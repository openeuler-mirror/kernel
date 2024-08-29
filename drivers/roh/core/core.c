// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2022 Hisilicon Limited.

#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_macvlan.h>

#include "core_priv.h"
#include "core.h"

static DEFINE_XARRAY_FLAGS(devices, XA_FLAGS_ALLOC);
static DECLARE_RWSEM(devices_rwsem);
#define DEVICE_REGISTERED XA_MARK_1

static u32 highest_client_id;
#define CLIENT_REGISTERED XA_MARK_1
static DEFINE_XARRAY_FLAGS(clients, XA_FLAGS_ALLOC);
static DECLARE_RWSEM(clients_rwsem);

static void roh_client_put(struct roh_client *client)
{
	if (refcount_dec_and_test(&client->uses))
		complete(&client->uses_zero);
}

#define CLIENT_DATA_REGISTERED XA_MARK_1

static int add_client_context(struct roh_device *device,
			      struct roh_client *client);
static void remove_client_context(struct roh_device *device,
				  unsigned int client_id);
static void __roh_unregister_device(struct roh_device *device);

static void roh_device_release(struct device *device)
{
	struct roh_device *dev = container_of(device, struct roh_device, dev);

	WARN_ON(refcount_read(&dev->refcount));

	mutex_destroy(&dev->unregistration_lock);
	xa_destroy(&dev->client_data);
	kfree(dev);
}

static int roh_device_uevent(const struct device *device, struct kobj_uevent_env *env)
{
	struct roh_device *dev = container_of(device, struct roh_device, dev);

	if (add_uevent_var(env, "NAME=%s", dev->name)) {
		pr_err("failed to do add_uevent_var.\n");
		return -ENOMEM;
	}

	return 0;
}

static struct class roh_class = {
	.name = "roh",
	.dev_release = roh_device_release,
	.dev_uevent = roh_device_uevent,
};

struct roh_device *roh_alloc_device(size_t size)
{
	struct roh_device *device;

	if (WARN_ON(size < sizeof(struct roh_device)))
		return NULL;

	device = kzalloc(size, GFP_KERNEL);
	if (!device)
		return NULL;

	device->dev.class = &roh_class;

	device_initialize(&device->dev);
	dev_set_drvdata(&device->dev, device);

	mutex_init(&device->unregistration_lock);

	mutex_init(&device->eid_mutex);

	xa_init_flags(&device->client_data, XA_FLAGS_ALLOC);
	init_rwsem(&device->client_data_rwsem);
	init_completion(&device->unreg_completion);

	return device;
}
EXPORT_SYMBOL(roh_alloc_device);

void roh_dealloc_device(struct roh_device *device)
{
	down_write(&devices_rwsem);
	if (xa_load(&devices, device->index) == device)
		xa_erase(&devices, device->index);
	up_write(&devices_rwsem);

	WARN_ON(!xa_empty(&device->client_data));
	WARN_ON(refcount_read(&device->refcount));

	put_device(&device->dev);
}
EXPORT_SYMBOL(roh_dealloc_device);

static int alloc_name(struct roh_device *device)
{
	struct roh_device *dev;
	unsigned long index;
	struct ida inuse;
	int rc;
	int i;

	lockdep_assert_held_write(&devices_rwsem);

	ida_init(&inuse);
	xa_for_each(&devices, index, dev) {
		char buf[ROH_DEVICE_NAME_MAX];

		if (sscanf(dev_name(&dev->dev), device->name, &i) != 1)
			continue;
		if (i < 0 || i >= INT_MAX)
			continue;
		rc = snprintf(buf, sizeof(buf), device->name, i);
		if (rc >= sizeof(buf) || rc < 0) {
			ida_destroy(&inuse);
			pr_err("device name is too long.\n");
			return -EINVAL;
		}

		if (strcmp(buf, dev_name(&dev->dev)) != 0)
			continue;

		rc = ida_alloc_range(&inuse, i, i, GFP_KERNEL);
		if (rc < 0)
			goto out;
	}

	rc = ida_alloc(&inuse, GFP_KERNEL);
	if (rc < 0)
		goto out;

	rc = dev_set_name(&device->dev, device->name, rc);

out:
	ida_destroy(&inuse);
	return rc;
}

static void roh_device_put(struct roh_device *device)
{
	if (refcount_dec_and_test(&device->refcount))
		complete(&device->unreg_completion);
}

struct roh_device *__roh_device_get_by_name(const char *name)
{
	struct roh_device *device;
	unsigned long index;

	xa_for_each(&devices, index, device)
		if (!strcmp(name, dev_name(&device->dev)))
			return device;

	return NULL;
}

static int assign_name(struct roh_device *device)
{
	static u32 last_id;
	int ret;

	down_write(&devices_rwsem);
	if (strchr(device->name, '%'))
		ret = alloc_name(device);
	else
		ret = dev_set_name(&device->dev, device->name);

	if (ret)
		goto out;

	if (__roh_device_get_by_name(dev_name(&device->dev))) {
		ret = -ENFILE;
		goto out;
	}

	strscpy(device->name, dev_name(&device->dev), ROH_DEVICE_NAME_MAX);
	ret = xa_alloc_cyclic(&devices, &device->index, device, xa_limit_31b,
			      &last_id, GFP_KERNEL);
	if (ret > 0)
		ret = 0;

out:
	up_write(&devices_rwsem);
	return ret;
}

static void disable_device(struct roh_device *device)
{
	u32 cid;

	WARN_ON(!refcount_read(&device->refcount));

	down_write(&devices_rwsem);
	xa_clear_mark(&devices, device->index, DEVICE_REGISTERED);
	up_write(&devices_rwsem);

	down_read(&clients_rwsem);
	cid = highest_client_id;
	up_read(&clients_rwsem);
	while (cid) {
		cid--;
		remove_client_context(device, cid);
	}

	roh_device_put(device);
	wait_for_completion(&device->unreg_completion);
}

static int enable_device_and_get(struct roh_device *device)
{
	struct roh_client *client;
	unsigned long index;
	int ret = 0;

	refcount_set(&device->refcount, MAX_DEVICE_REFCOUNT);
	down_write(&devices_rwsem);
	xa_set_mark(&devices, device->index, DEVICE_REGISTERED);

	downgrade_write(&devices_rwsem);
	down_read(&clients_rwsem);
	xa_for_each_marked(&clients, index, client, CLIENT_REGISTERED) {
		ret = add_client_context(device, client);
		if (ret)
			break;
	}
	up_read(&clients_rwsem);

	up_read(&devices_rwsem);

	return ret;
}

static int roh_ipv4_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct roh_eid_attr eid_attr;
	struct in_ifaddr *ifa = ptr;
	struct roh_device *device;
	struct net_device *ndev;
	struct sockaddr s_addr;
	struct sockaddr_in in;
	int ret;

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	device = container_of(this, struct roh_device, nb);
	ndev = ifa->ifa_dev->dev;

	if (is_vlan_dev(ndev)) {
		if (vlan_dev_real_dev(ndev) == device->netdev) {
			s_addr.sa_family = ndev->type;
			u64_to_ether_addr(be32_to_cpu(ifa->ifa_address) & 0xffffff, s_addr.sa_data);
			dev_set_mac_address(ndev, &s_addr, NULL);
		}
		return NOTIFY_DONE;
	}

	if (netif_is_macvlan(ndev)) {
		if (macvlan_dev_real_dev(ndev) == device->netdev) {
			s_addr.sa_family = ndev->type;
			u64_to_ether_addr(be32_to_cpu(ifa->ifa_address) & 0xffffff, s_addr.sa_data);
			dev_set_mac_address(ndev, &s_addr, NULL);
		}
		return NOTIFY_DONE;
	}

	if (device->netdev != ndev)
		return NOTIFY_DONE;

	in.sin_addr.s_addr = ifa->ifa_address;

	eid_attr.base = be32_to_cpu(in.sin_addr.s_addr) & 0xffffff; /* lower 3B as src eid */
	eid_attr.num = 1;
	ret = roh_device_set_eid(device, &eid_attr);
	if (ret) {
		pr_err("failed to set eid by IP, ret = %d\n", ret);
		return ret;
	}

	return NOTIFY_DONE;
}

static int roh_register_inetaddr_event(struct roh_device *device)
{
	int ret;

	device->nb.notifier_call = roh_ipv4_event;
	ret = register_inetaddr_notifier(&device->nb);
	if (ret) {
		pr_err("roh_core: failed to register inetaddr notifier, ret = %d\n", ret);
		device->nb.notifier_call = NULL;
	}

	return ret;
}

static void roh_unregister_inetaddr_event(struct roh_device *device)
{
	int ret;

	if (device->nb.notifier_call) {
		ret = unregister_inetaddr_notifier(&device->nb);
		if (ret)
			pr_err("roh_core: failed to unregister inetaddr notifier, ret = %d\n", ret);
		device->nb.notifier_call = NULL;
	}
}

int roh_register_device(struct roh_device *device)
{
	int ret;

	ret = assign_name(device);
	if (ret) {
		pr_err("roh_core: failed to assigne name, ret = %d\n", ret);
		return ret;
	}

	dev_set_uevent_suppress(&device->dev, true);
	ret = device_add(&device->dev);
	if (ret) {
		pr_err("roh_core: failed to add device, ret = %d\n", ret);
		goto out;
	}

	ret = roh_device_register_sysfs(device);
	if (ret)
		goto err_dev_cleanup;

	ret = roh_register_inetaddr_event(device);
	if (ret) {
		pr_err("roh_core: failed to register inetaddr event, ret = %d\n", ret);
		goto err_unregister_sysfs;
	}

	ret = enable_device_and_get(device);
	dev_set_uevent_suppress(&device->dev, false);
	kobject_uevent(&device->dev.kobj, KOBJ_ADD);
	if (ret) {
		roh_device_put(device);
		__roh_unregister_device(device);
		return ret;
	}

	roh_device_put(device);

	return 0;

err_unregister_sysfs:
	roh_device_unregister_sysfs(device);
err_dev_cleanup:
	device_del(&device->dev);
out:
	dev_set_uevent_suppress(&device->dev, false);
	return ret;
}
EXPORT_SYMBOL(roh_register_device);

static void __roh_unregister_device(struct roh_device *device)
{
	mutex_lock(&device->unregistration_lock);
	if (!refcount_read(&device->refcount))
		goto out;

	disable_device(device);
	roh_unregister_inetaddr_event(device);
	roh_device_unregister_sysfs(device);
	device_del(&device->dev);

out:
	mutex_unlock(&device->unregistration_lock);
}

void roh_unregister_device(struct roh_device *device)
{
	get_device(&device->dev);

	__roh_unregister_device(device);
	put_device(&device->dev);
}
EXPORT_SYMBOL(roh_unregister_device);

void roh_set_client_data(struct roh_device *device, struct roh_client *client,
			 void *data)
{
	void *rc;

	if (WARN_ON(IS_ERR(data)))
		data = NULL;

	rc = xa_store(&device->client_data, client->client_id, data,
		      GFP_KERNEL);
	WARN_ON(xa_is_err(rc));
}

static void remove_client_context(struct roh_device *device,
				  unsigned int client_id)
{
	struct roh_client *client;
	void *client_data;

	down_write(&device->client_data_rwsem);
	if (!xa_get_mark(&device->client_data, client_id,
			 CLIENT_DATA_REGISTERED)) {
		up_write(&device->client_data_rwsem);
		return;
	}
	client_data = xa_load(&device->client_data, client_id);
	xa_clear_mark(&device->client_data, client_id, CLIENT_DATA_REGISTERED);
	client = xa_load(&clients, client_id);
	up_write(&device->client_data_rwsem);

	if (client->remove)
		client->remove(device, client_data);

	xa_erase(&device->client_data, client_id);
	roh_device_put(device);
	roh_client_put(client);
}

static int add_client_context(struct roh_device *device,
			      struct roh_client *client)
{
	int ret = 0;

	down_write(&device->client_data_rwsem);
	if (!refcount_inc_not_zero(&client->uses))
		goto out_unlock;
	refcount_inc(&device->refcount);

	if (xa_get_mark(&device->client_data, client->client_id,
			CLIENT_DATA_REGISTERED))
		goto out;

	ret = xa_err(xa_store(&device->client_data, client->client_id, NULL,
			      GFP_KERNEL));
	if (ret)
		goto out;

	downgrade_write(&device->client_data_rwsem);
	if (client->add) {
		if (client->add(device)) {
			xa_erase(&device->client_data, client->client_id);
			up_read(&device->client_data_rwsem);
			roh_device_put(device);
			roh_client_put(client);
			return 0;
		}
	}

	xa_set_mark(&device->client_data, client->client_id,
		    CLIENT_DATA_REGISTERED);
	up_read(&device->client_data_rwsem);

	return 0;

out:
	roh_device_put(device);
	roh_client_put(client);
out_unlock:
	up_write(&device->client_data_rwsem);
	return ret;
}

static int assign_client_id(struct roh_client *client)
{
	int ret;

	down_write(&clients_rwsem);

	client->client_id = highest_client_id;
	ret = xa_insert(&clients, client->client_id, client, GFP_KERNEL);
	if (ret)
		goto out;

	highest_client_id++;
	xa_set_mark(&clients, client->client_id, CLIENT_REGISTERED);

out:
	up_write(&clients_rwsem);
	return ret;
}

static void remove_client_id(struct roh_client *client)
{
	down_write(&clients_rwsem);
	xa_erase(&clients, client->client_id);
	for (; highest_client_id; highest_client_id--)
		if (xa_load(&clients, highest_client_id - 1))
			break;
	up_write(&clients_rwsem);
}

int roh_register_client(struct roh_client *client)
{
	struct roh_device *device;
	unsigned long index;
	int ret;

	refcount_set(&client->uses, 1);
	init_completion(&client->uses_zero);
	ret = assign_client_id(client);
	if (ret)
		return ret;

	down_read(&devices_rwsem);
	xa_for_each_marked(&devices, index, device, DEVICE_REGISTERED) {
		ret = add_client_context(device, client);
		if (ret) {
			up_read(&devices_rwsem);
			roh_unregister_client(client);
			return ret;
		}
	}
	up_read(&devices_rwsem);

	return 0;
}

void roh_unregister_client(struct roh_client *client)
{
	struct roh_device *device;
	unsigned long index;

	down_write(&clients_rwsem);
	roh_client_put(client);
	xa_clear_mark(&clients, client->client_id, CLIENT_REGISTERED);
	up_write(&clients_rwsem);

	rcu_read_lock();
	xa_for_each(&devices, index, device) {
		if (!roh_device_try_get(device))
			continue;
		rcu_read_unlock();

		remove_client_context(device, client->client_id);

		roh_device_put(device);
		rcu_read_lock();
	}
	rcu_read_unlock();

	wait_for_completion(&client->uses_zero);
	remove_client_id(client);
}

static int roh_set_pf_mac_by_eid(struct roh_device *device,
				 struct roh_eid_attr *eid_attr)
{
	const struct net_device_ops *ndev_ops;
	u32 eid = eid_attr->base;
	struct net_device *ndev;
	struct sockaddr s_addr;
	u8 mac[ETH_ALEN] = {0};
	int ret;

	ndev = device->netdev;
	if (!ndev)
		return -EINVAL;

	ndev_ops = ndev->netdev_ops;
	if (!ndev_ops->ndo_set_mac_address)
		return -EOPNOTSUPP;

	convert_eid_to_mac(mac, eid);

	s_addr.sa_family = ndev->type;
	memcpy(s_addr.sa_data, mac, ndev->addr_len);

	ret = dev_set_mac_address(ndev, &s_addr, NULL);
	if (ret) {
		netdev_err(ndev, "failed to set dev %s mac, ret = %d\n",
			   ndev->name, ret);
		return ret;
	}

	return 0;
}

static int roh_set_mac_by_eid(struct roh_device *device,
			      struct roh_eid_attr *eid_attr)
{
	int ret;

	ret = roh_set_pf_mac_by_eid(device, eid_attr);
	if (ret) {
		pr_err("failed to set pf mac, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

int roh_device_set_eid(struct roh_device *device, struct roh_eid_attr *attr)
{
	int ret;

	if (!device->ops.set_eid)
		return -EPROTONOSUPPORT;

	mutex_lock(&device->eid_mutex);
	/* Update current EID */
	ret = device->ops.set_eid(device, attr);
	if (ret) {
		mutex_unlock(&device->eid_mutex);
		return ret;
	}

	memcpy(&device->eid, attr, sizeof(device->eid));
	ret = roh_set_mac_by_eid(device, attr);
	mutex_unlock(&device->eid_mutex);

	return ret;
}

void roh_device_get_eid(struct roh_device *device, struct roh_eid_attr *attr)
{
	mutex_lock(&device->eid_mutex);
	memcpy(attr, &device->eid, sizeof(*attr));
	mutex_unlock(&device->eid_mutex);
}

enum roh_link_status roh_device_query_link_status(struct roh_device *device)
{
	return device->link_status;
}

static void roh_update_link_status(struct roh_device *device, u32 ls)
{
	device->link_status = ls;
}

void roh_event_notify(struct roh_event *event)
{
	struct roh_device *device = event->device;

	switch (event->type) {
	case ROH_EVENT_LINK_UP:
		roh_update_link_status(device, ROH_LINK_UP);
		break;
	case ROH_EVENT_LINK_DOWN:
		roh_update_link_status(device, ROH_LINK_DOWN);
		break;
	default:
		pr_err("roh_core: not support event type(%d).\n", event->type);
		break;
	}
}
EXPORT_SYMBOL(roh_event_notify);

int roh_core_init(void)
{
	int ret;

	ret = class_register(&roh_class);
	if (ret) {
		pr_err("roh_core: couldn't create roh device class, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

void roh_core_cleanup(void)
{
	class_unregister(&roh_class);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("ROH Core Driver");
