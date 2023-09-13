// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore kernel module
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: create file
 */

#include <net/addrconf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/version.h>
#include <linux/list.h>

#include "ubcore_cmd.h"
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"

/* ubcore create independent cdev and ioctl channels
 * to handle public work.
 */
#define UBCORE_DEVICE_NAME "ubcore"
#define UBCORE_CLASS_NAME "ubus"
#define UBCORE_IPV4_MAP_IPV6_PREFIX 0x0000ffff

struct ubcore_ctx {
	dev_t ubcore_devno;
	struct cdev ubcore_cdev;
	struct class *ubcore_class;
	struct device *ubcore_dev;
};

static struct ubcore_ctx g_ubcore_ctx;
#define UBCORE_MAX_UASID (1 << 24)
static DECLARE_BITMAP(g_uasid_bitmap, UBCORE_MAX_UASID);
static DEFINE_SPINLOCK(g_uasid_spinlock);

struct ubcore_net_addr_node {
	struct list_head node;
	struct ubcore_net_addr addr;
};

int ubcore_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static uint32_t ubcore_uasid_alloc(uint32_t uasid)
{
	spin_lock(&g_uasid_spinlock);
	if (uasid > 0) {
		uint32_t ret = 0;

		if (test_bit(uasid, g_uasid_bitmap) == 0) {
			set_bit(uasid, g_uasid_bitmap);
			spin_unlock(&g_uasid_spinlock);
			ret = uasid;
		} else {
			spin_unlock(&g_uasid_spinlock);
			ubcore_log_err("uasid allocation failed.\n");
			return 0;
		}
		if (ret != 0)
			return ret;
	}
	uasid = (uint32_t)find_first_zero_bit(g_uasid_bitmap, UBCORE_MAX_UASID);
	if (uasid >= UBCORE_MAX_UASID) {
		ubcore_log_err("uasid allocation failed.\n");
		spin_unlock(&g_uasid_spinlock);
		return 0;
	}
	set_bit(uasid, g_uasid_bitmap);
	spin_unlock(&g_uasid_spinlock);
	return uasid;
}

static int ubcore_uasid_free(uint32_t uasid)
{
	spin_lock(&g_uasid_spinlock);
	if (uasid == 0) {
		spin_unlock(&g_uasid_spinlock);
		ubcore_log_err("uasid is zero.\n");
		return -EINVAL;
	}
	if (test_bit(uasid, g_uasid_bitmap) == false) {
		spin_unlock(&g_uasid_spinlock);
		ubcore_log_err("uasid is used.\n");
		return -EINVAL;
	}
	clear_bit(uasid, g_uasid_bitmap);
	spin_unlock(&g_uasid_spinlock);
	return 0;
}

static int ubcore_cmd_set_uasid(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_uasid arg;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_set_uasid));
	if (ret != 0)
		return -EPERM;

	arg.out.uasid = ubcore_uasid_alloc(arg.in.uasid);
	if (arg.out.uasid == 0) {
		ubcore_log_err("set uasid allocation failed, in_uasid: %u.\n", arg.in.uasid);
		return -ENOMEM;
	}
	ubcore_log_info("set uasid allocation success, uasid: %u.\n", arg.out.uasid);

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				  sizeof(struct ubcore_cmd_set_uasid));
	if (ret != 0)
		return -EPERM;

	return 0;
}

static int ubcore_cmd_put_uasid(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_put_uasid arg;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_put_uasid));
	if (ret != 0)
		return -EPERM;

	if (ubcore_uasid_free(arg.in.uasid) != 0)
		return -EINVAL;

	ubcore_log_info("put uasid free success, uasid: %u.\n", arg.in.uasid);
	return 0;
}

static int ubcore_cmd_query_stats(struct ubcore_cmd_hdr *hdr)
{
	enum ubcore_transport_type trans_type;
	struct ubcore_cmd_query_stats arg = { 0 };
	struct ubcore_stats_com_val com_val;
	struct ubcore_stats_key key = { 0 };
	struct ubcore_stats_val val;
	struct ubcore_device *dev;
	union ubcore_eid eid;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_query_stats));
	if (ret != 0)
		return ret;

	(void)memcpy(eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	trans_type = (enum ubcore_transport_type)arg.in.tp_type;
	dev = ubcore_find_device(&eid, trans_type);
	if (dev == NULL || ubcore_check_dev_name_invalid(dev, arg.in.dev_name)) {
		ubcore_log_err("find dev failed, dev:%s, arg_in: %s.\n",
			       dev == NULL ? "NULL" : dev->dev_name, arg.in.dev_name);
		return -EINVAL;
	}

	key.type = (uint8_t)arg.in.type;
	key.key = arg.in.key;
	val.addr = (uint64_t)&com_val;
	val.len = sizeof(struct ubcore_stats_com_val);

	ret = ubcore_query_stats(dev, &key, &val);
	if (ret != 0) {
		ubcore_put_device(dev);
		return ret;
	}

	ubcore_put_device(dev);
	(void)memcpy(&arg.out, &com_val, sizeof(struct ubcore_stats_com_val));
	return ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct ubcore_cmd_query_stats));
}

static uint32_t ubcore_get_query_res_len(uint32_t type)
{
	return 0;
}

static void ubcore_dealloc_res_dev(struct ubcore_res_dev_val *ubcore_addr)
{
}

static int ubcore_fill_res_addr(struct ubcore_res_dev_val *ubcore_addr)
{
	return 0;
}

static int ubcore_fill_user_res_dev(struct ubcore_res_dev_val *dev_val,
				    struct ubcore_res_dev_val *ubcore_addr)
{
	return 0;
}

static int ubcore_query_res_dev(const struct ubcore_device *dev, struct ubcore_res_key *key,
				struct ubcore_res_dev_val *dev_val)
{
	struct ubcore_res_dev_val ubcore_addr = { 0 };
	struct ubcore_res_val val = { 0 };
	int ret = 0;

	(void)memcpy(&ubcore_addr, dev_val,
		     sizeof(struct ubcore_res_dev_val)); // save

	if (ubcore_fill_res_addr(&ubcore_addr) != 0) {
		ubcore_log_err("Failed to fill dev dev_val.\n");
		return -ENOMEM;
	}

	val.addr = (uint64_t)&ubcore_addr;
	val.len = sizeof(struct ubcore_res_dev_val);

	ret = ubcore_query_resource(dev, key, &val);
	if (ret != 0)
		goto ubcore_free_dev;

	ret = ubcore_fill_user_res_dev(dev_val, &ubcore_addr);
ubcore_free_dev:
	ubcore_dealloc_res_dev(&ubcore_addr);
	return ret;
}

static int ubcore_query_res_arg(const struct ubcore_device *dev, struct ubcore_cmd_query_res *arg,
				uint32_t res_len)
{
	struct ubcore_res_key key = { 0 };
	struct ubcore_res_val val = { 0 };
	void *addr;
	int ret;

	addr = kzalloc(res_len, GFP_KERNEL);
	if (addr == NULL)
		return -1;

	ret = ubcore_copy_from_user(addr, (void __user *)(uintptr_t)arg->out.addr, res_len);
	if (ret != 0)
		goto kfree_addr;

	key.type = (uint8_t)arg->in.type;
	key.key = arg->in.key;
	val.addr = (uint64_t)addr;
	val.len = res_len;

	if (arg->in.type == UBCORE_RES_KEY_URMA_DEV)
		ret = ubcore_query_res_dev(dev, &key, (struct ubcore_res_dev_val *)addr);
	else
		ret = ubcore_query_resource(dev, &key, &val);

	if (ret != 0)
		goto kfree_addr;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)arg->out.addr, addr, res_len);

kfree_addr:
	kfree(addr);
	return ret;
}

static int ubcore_cmd_query_res(struct ubcore_cmd_hdr *hdr)
{
	enum ubcore_transport_type trans_type;
	struct ubcore_cmd_query_res arg = { 0 };
	struct ubcore_device *dev;
	union ubcore_eid eid;
	uint32_t res_len;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
				    sizeof(struct ubcore_cmd_query_res));
	if (ret != 0)
		return ret;

	res_len = ubcore_get_query_res_len((uint32_t)arg.in.type);
	if (res_len != arg.out.len) {
		ubcore_log_err("Failed to check res len, type: %u, res_len: %u, len: %u.\n",
			       (uint32_t)arg.in.type, res_len, arg.out.len);
		return -1;
	}
	(void)memcpy(eid.raw, arg.in.eid, UBCORE_EID_SIZE);
	trans_type = (enum ubcore_transport_type)arg.in.tp_type;

	dev = ubcore_find_device(&eid, trans_type);
	if (dev == NULL || ubcore_check_dev_name_invalid(dev, arg.in.dev_name)) {
		ubcore_log_err("find dev failed, dev:%s, arg_in: %s.\n",
			       dev == NULL ? "NULL" : dev->dev_name, arg.in.dev_name);
		return -EINVAL;
	}

	ret = ubcore_query_res_arg(dev, &arg, res_len);
	if (ret != 0) {
		ubcore_put_device(dev);
		ubcore_log_err("Failed to query res by arg, tp_type: %d.\n", (int)trans_type);
		return -1;
	}

	ubcore_put_device(dev);
	return ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
				   sizeof(struct ubcore_cmd_query_res));
}

static int ubcore_cmd_parse(struct ubcore_cmd_hdr *hdr)
{
	switch (hdr->command) {
	case UBCORE_CMD_SET_UASID:
		return ubcore_cmd_set_uasid(hdr);
	case UBCORE_CMD_PUT_UASID:
		return ubcore_cmd_put_uasid(hdr);
	case UBCORE_CMD_QUERY_STATS:
		return ubcore_cmd_query_stats(hdr);
	case UBCORE_CMD_QUERY_RES:
		return ubcore_cmd_query_res(hdr);
	default:
		ubcore_log_err("bad ubcore command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
}

static long ubcore_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ubcore_cmd_hdr hdr;
	int ret;

	if (cmd == UBCORE_CMD) {
		ret = ubcore_copy_from_user(&hdr, (void *)arg, sizeof(struct ubcore_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBCORE_MAX_CMD_SIZE)) {
			ubcore_log_err("length of ioctl input parameter is out of range.\n");
			return -EINVAL;
		}
	} else {
		ubcore_log_err("bad ioctl command.\n");
		return -ENOIOCTLCMD;
	}
	return ubcore_cmd_parse(&hdr);
}

static int ubcore_close(struct inode *i_node, struct file *filp)
{
	return 0;
}

static const struct file_operations g_ubcore_ops = {
	.owner = THIS_MODULE,
	.open = ubcore_open,
	.release = ubcore_close,
	.unlocked_ioctl = ubcore_ioctl,
	.compat_ioctl = ubcore_ioctl,
};

static int ubcore_register_sysfs(void)
{
	int ret;

	ret = alloc_chrdev_region(&g_ubcore_ctx.ubcore_devno, 0, 1, UBCORE_DEVICE_NAME);
	if (ret != 0) {
		ubcore_log_err("alloc chrdev region failed, ret:%d.\n", ret);
		return ret;
	}

	cdev_init(&g_ubcore_ctx.ubcore_cdev, &g_ubcore_ops);
	ret = cdev_add(&g_ubcore_ctx.ubcore_cdev, g_ubcore_ctx.ubcore_devno, 1);
	if (ret != 0) {
		ubcore_log_err("chrdev add failed, ret:%d.\n", ret);
		goto unreg_cdev_region;
	}

	/* /sys/class/ubus/ubcore */
	g_ubcore_ctx.ubcore_class = class_create(THIS_MODULE, UBCORE_CLASS_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_class)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_class);
		ubcore_log_err("couldn't create class %s, ret:%d.\n", UBCORE_CLASS_NAME, ret);
		goto del_cdev;
	}

	/* /dev/ubcore */
	g_ubcore_ctx.ubcore_dev =
		device_create(g_ubcore_ctx.ubcore_class, NULL, g_ubcore_ctx.ubcore_devno, NULL,
			      UBCORE_DEVICE_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_dev)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_dev);
		ubcore_log_err("couldn't create device %s, ret:%d.\n", UBCORE_DEVICE_NAME, ret);
		goto destroy_class;
	}
	ubcore_log_info("ubcore device created success.\n");
	return 0;

destroy_class:
	class_destroy(g_ubcore_ctx.ubcore_class);
del_cdev:
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
unreg_cdev_region:
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	return ret;
}

static void ubcore_unregister_sysfs(void)
{
	device_destroy(g_ubcore_ctx.ubcore_class, g_ubcore_ctx.ubcore_cdev.dev);
	class_destroy(g_ubcore_ctx.ubcore_class);
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	ubcore_log_info("ubcore device destroyed success.\n");
}

static void ubcore_ipv4_to_netaddr(struct ubcore_net_addr *netaddr, __be32 ipv4)
{
	netaddr->net_addr.in4.resv1 = 0;
	netaddr->net_addr.in4.resv2 = htonl(UBCORE_IPV4_MAP_IPV6_PREFIX);
	netaddr->net_addr.in4.addr = ipv4;
}

static void ubcore_set_net_addr(struct ubcore_device *dev, const struct ubcore_net_addr *netaddr)
{
	if (dev->ops->set_net_addr != NULL && dev->ops->set_net_addr(dev, netaddr) != 0)
		ubcore_log_err("Failed to set net addr");
}

static void ubcore_unset_net_addr(struct ubcore_device *dev, const struct ubcore_net_addr *netaddr)
{
	if (dev->ops->unset_net_addr != NULL && dev->ops->unset_net_addr(dev, netaddr) != 0)
		ubcore_log_err("Failed to unset net addr");
}

static void ubcore_update_eid(struct ubcore_device *dev, struct ubcore_net_addr *netaddr)
{
	if (dev->transport_type <= UBCORE_TRANSPORT_INVALID ||
	    dev->transport_type >= UBCORE_TRANSPORT_MAX)
		return;

	if (ubcore_set_eid(dev, (union ubcore_eid *)(void *)&netaddr->net_addr) != 0)
		ubcore_log_warn("Failed to update eid");
}

static int ubcore_handle_inetaddr_event(struct net_device *netdev, unsigned long event,
					struct ubcore_net_addr *netaddr)
{
	struct ubcore_device **devices;
	struct ubcore_device *dev;
	uint32_t num_devices = 0;
	uint32_t i;

	if (netdev == NULL || netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	devices = ubcore_get_devices_from_netdev(netdev, &num_devices);
	if (devices == NULL)
		return NOTIFY_DONE;

	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		switch (event) {
		case NETDEV_UP:
			ubcore_set_net_addr(dev, netaddr);
			ubcore_update_eid(dev, netaddr);
			break;
		case NETDEV_DOWN:
			ubcore_unset_net_addr(dev, netaddr);
			break;
		default:
			break;
		}
	}

	ubcore_put_devices(devices, num_devices);
	return NOTIFY_OK;
}

static int ubcore_ipv6_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->idev == NULL || ifa->idev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->idev->dev;
	ubcore_log_info("Get a ipv6 event %s from netdev %s%s ip %pI6c", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev), &ifa->addr);

	(void)memcpy(&netaddr.net_addr, &ifa->addr, sizeof(struct in6_addr));
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr);
}

static int ubcore_ipv4_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->ifa_dev == NULL || ifa->ifa_dev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	ubcore_log_info("Get a ipv4 event %s netdev %s%s ip %pI4", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev), &ifa->ifa_address);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	ubcore_ipv4_to_netaddr(&netaddr, ifa->ifa_address);
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr);
}

static void ubcore_add_ipv4_entry(struct list_head *list, __be32 ipv4)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);

	ubcore_ipv4_to_netaddr(&na_entry->addr, ipv4);
	list_add_tail(&na_entry->node, list);
}

static void ubcore_add_ipv6_entry(struct list_head *list, const struct in6_addr *ipv6)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	(void)memcpy(&na_entry->addr.net_addr, ipv6, sizeof(struct in6_addr));
	list_add_tail(&na_entry->node, list);
}

static void ubcore_netdev_get_ipv4(struct net_device *netdev, struct list_head *list)
{
	const struct in_ifaddr *ifa;
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (in_dev == NULL) {
		rcu_read_unlock();
		return;
	}

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		if (ifa->ifa_flags & IFA_F_SECONDARY)
			continue;
		ubcore_add_ipv4_entry(list, ifa->ifa_address);
	}
	rcu_read_unlock();
}

static void ubcore_netdev_get_ipv6(struct net_device *netdev, struct list_head *list)
{
	const struct inet6_ifaddr *ifa;
	struct inet6_dev *in_dev;

	in_dev = in6_dev_get(netdev);
	if (in_dev == NULL)
		return;

	read_lock_bh(&in_dev->lock);
	list_for_each_entry(ifa, &in_dev->addr_list, if_list) {
		if (ifa->flags & IFA_F_SECONDARY)
			continue;
		ubcore_add_ipv6_entry(list, (const struct in6_addr *)&ifa->addr);
	}
	read_unlock_bh(&in_dev->lock);
	in6_dev_put(in_dev);
}

void ubcore_set_default_eid(struct ubcore_device *dev)
{
	struct net_device *netdev = dev->netdev;
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	/* Do not modify eid if the driver already set default eid other than 0 */
	if (netdev == NULL ||
	    !(dev->attr.eid.in6.interface_id == 0 && dev->attr.eid.in6.subnet_prefix == 0))
		return;

	ubcore_netdev_get_ipv4(netdev, &na_list);
	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		ubcore_update_eid(dev, &na_entry->addr);
		list_del(&na_entry->node);
		kfree(na_entry);
	}
}

static void ubcore_update_netaddr(struct ubcore_device *dev, struct net_device *netdev, bool add)
{
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	/* ipv4 */
	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);

	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (add)
			ubcore_set_net_addr(dev, &na_entry->addr);
		else
			ubcore_unset_net_addr(dev, &na_entry->addr);

		list_del(&na_entry->node);
		kfree(na_entry);
	}
}

static int ubcore_add_netaddr(struct ubcore_device *dev, struct net_device *netdev)
{
	if (netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	ubcore_update_netaddr(dev, netdev, true);
	return NOTIFY_OK;
}

static int ubcore_remove_netaddr(struct ubcore_device *dev, struct net_device *netdev)
{
	if (netdev->reg_state >= NETREG_UNREGISTERED)
		return NOTIFY_DONE;

	ubcore_update_netaddr(dev, netdev, false);
	return NOTIFY_OK;
}

static int ubcore_net_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct ubcore_device **devices;
	struct ubcore_device *dev;
	uint32_t num_devices = 0;
	uint32_t i;

	if (netdev == NULL)
		return NOTIFY_DONE;

	devices = ubcore_get_devices_from_netdev(netdev, &num_devices);
	if (devices == NULL)
		return NOTIFY_DONE;

	ubcore_log_info("Get a net event %s from ubcore_dev %s%s", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev));

	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		switch (event) {
		case NETDEV_REGISTER:
		case NETDEV_UP:
			ubcore_add_netaddr(dev, netdev);
			break;
		case NETDEV_UNREGISTER:
		case NETDEV_DOWN:
			ubcore_remove_netaddr(dev, netdev);
			break;
		default:
			break;
		}
	}
	ubcore_put_devices(devices, num_devices);
	return NOTIFY_OK;
}

static struct notifier_block ubcore_ipv6_notifier = {
	.notifier_call = ubcore_ipv6_notifier_call,
};

static struct notifier_block ubcore_ipv4_notifier = {
	.notifier_call = ubcore_ipv4_notifier_call,
};

static struct notifier_block ubcore_net_notifier = { .notifier_call = ubcore_net_notifier_call };

static int ubcore_register_notifiers(void)
{
	int ret;

	ret = register_netdevice_notifier(&ubcore_net_notifier);
	if (ret != 0) {
		pr_err("Failed to register netdev notifier, ret = %d\n", ret);
		return ret;
	}
	ret = register_inetaddr_notifier(&ubcore_ipv4_notifier);
	if (ret != 0) {
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inetaddr notifier, ret = %d\n", ret);
		return -1;
	}
	ret = register_inet6addr_notifier(&ubcore_ipv6_notifier);
	if (ret != 0) {
		(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inet6addr notifier, ret = %d\n", ret);
		return -1;
	}
	return 0;
}

static void ubcore_unregister_notifiers(void)
{
	(void)unregister_inet6addr_notifier(&ubcore_ipv6_notifier);
	(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
	(void)unregister_netdevice_notifier(&ubcore_net_notifier);
}

static int __init ubcore_init(void)
{
	int ret;

	ret = ubcore_register_sysfs();
	if (ret != 0)
		return ret;

	/* uasid is assigned from 1, and 0 means random value.
	 * so 0 consumed here first.
	 */
	bitmap_zero(g_uasid_bitmap, UBCORE_MAX_UASID);
	set_bit(0, g_uasid_bitmap);

	if (ubcore_netlink_init() != 0) {
		ubcore_unregister_sysfs();
		return -1;
	}

	ret = ubcore_register_notifiers();
	if (ret != 0) {
		pr_err("Failed to register notifiers\n");
		ubcore_unregister_sysfs();
		ubcore_netlink_exit();
		return -1;
	}
	ubcore_log_info("ubcore module init success.\n");
	return 0;
}

static void __exit ubcore_exit(void)
{
	ubcore_unregister_notifiers();
	ubcore_netlink_exit();
	ubcore_unregister_sysfs();
	ubcore_log_info("ubcore module exits.\n");
}

module_init(ubcore_init);
module_exit(ubcore_exit);

MODULE_DESCRIPTION("Kernel module for ubus");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
