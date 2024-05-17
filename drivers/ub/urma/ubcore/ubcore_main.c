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
#include <linux/if_vlan.h>
#include <linux/types.h>

#include "ubcore_cmd.h"
#include "ubcore_uvs_cmd.h"
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include <urma/ubcore_types.h>
#include <urma/ubcore_api.h>
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"
#include "ubcore_netdev.h"
#include "ubcore_msg.h"
#include "ubcore_genl.h"
#include "ubcore_workqueue.h"
#include "ubcore_device.h"

#define UBCORE_LOG_FILE_PERMISSION (0644)

module_param(g_ubcore_log_level, uint, UBCORE_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(g_ubcore_log_level, " 3: ERR, 4: WARNING, 6: INFO, 7: DEBUG");

/* ubcore create independent cdev and ioctl channels
 * to handle public work.
 */
#define UBCORE_DEVICE_NAME "ubcore"
#define UBCORE_IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define UBCORE_LOCAL_SHUNET (0xfe80000000000000ULL)
#define SIP_MTU_BITS_BASE_SHIFT 7


struct ubcore_ctx {
	dev_t ubcore_devno;
	struct cdev ubcore_cdev;
	struct class *ubcore_class;
	struct device *ubcore_dev;
};

static struct ubcore_ctx g_ubcore_ctx;

struct ubcore_net_addr_node {
	struct list_head node;
	struct ubcore_net_addr addr;
	uint32_t prefix_len;
};

enum ubcore_bond_op_type {
	UBCORE_BOND_ADD = 0,
	UBCORE_BOND_REMOVE,
	UBCORE_BOND_SLAVE_UPDATE
};

struct ubcore_bond_event_work {
	struct work_struct work;
	struct netdev_lag_upper_info info_upper;
	struct netdev_lag_lower_state_info info_lower;
	enum ubcore_bond_op_type bond_op_type;
	struct net_device *slave;
	struct net_device *bond;
	int (*bond_add)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_upper_info *upper_info);
	int (*bond_remove)(struct net_device *bond, struct net_device *slave);
	int (*slave_update)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_lower_state_info *lower_info);
};

enum ubcore_sip_op_type {
	UBCORE_SIP_DEL = 0,
	UBCORE_SIP_ADD,
	UBCORE_SIP_UPDATE
};

struct ubcore_notify_uvs_sip_event_work {
	struct work_struct work;
	struct ubcore_device *tpf_dev;
	struct ubcore_sip_info new_sip;
	struct ubcore_sip_info old_sip;
	enum ubcore_sip_op_type sip_op;
	uint32_t index;
};

int ubcore_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static void ubcore_update_pattern1_eid(struct ubcore_device *dev,
	union ubcore_eid *eid, uint32_t eid_idx, bool is_add)
{
	struct ubcore_ueid_cfg cfg;

	cfg.eid = *eid;
	cfg.eid_index = eid_idx;
	cfg.upi = 0;
	if (is_add)
		(void)ubcore_add_ueid(dev, dev->attr.fe_idx, &cfg);
	else
		(void)ubcore_delete_ueid(dev, dev->attr.fe_idx, &cfg);
}

static void ubcore_update_pattern3_eid(struct ubcore_device *dev,
	union ubcore_eid *eid, uint32_t eid_idx, bool is_add)
{
	uint32_t pattern3_upi = 0;
	struct ubcore_ueid_cfg cfg;

	if (dev->attr.virtualization ||
		ubcore_find_upi_with_dev_name(dev->dev_name, &pattern3_upi) == NULL)
		return;

	if (pattern3_upi != (uint32_t)UCBORE_INVALID_UPI) {
		cfg.eid = *eid;
		cfg.eid_index = eid_idx;
		cfg.upi = pattern3_upi;
		if (is_add)
			(void)ubcore_add_ueid(dev, dev->attr.fe_idx, &cfg);
		else
			(void)ubcore_delete_ueid(dev, dev->attr.fe_idx, &cfg);
	} else {
		ubcore_log_err("upi not configured\n");
	}
}

static long ubcore_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ubcore_cmd_hdr hdr;
	int ret;

	if (cmd == UBCORE_UVS_CMD) {
		ret = ubcore_copy_from_user(&hdr, (void *)arg, sizeof(struct ubcore_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBCORE_MAX_CMD_SIZE)) {
			ubcore_log_err("length of ioctl input parameter is out of range.\n");
			return -EINVAL;
		}
		return ubcore_uvs_cmd_parse(&hdr);
	}

	ubcore_log_err("bad ioctl command.\n");
	return -ENOIOCTLCMD;
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

	/* /sys/class/ubus/ubcore */
	ret = ubcore_class_register(&g_ubcore_ctx.ubcore_class);
	if (ret) {
		ubcore_log_err("couldn't create class\n");
		return ret;
	}

	ret = alloc_chrdev_region(&g_ubcore_ctx.ubcore_devno, 0, 1, UBCORE_DEVICE_NAME);
	if (ret != 0) {
		ubcore_log_err("alloc chrdev region failed, ret:%d.\n", ret);
		goto unreg_class;
	}

	cdev_init(&g_ubcore_ctx.ubcore_cdev, &g_ubcore_ops);
	ret = cdev_add(&g_ubcore_ctx.ubcore_cdev, g_ubcore_ctx.ubcore_devno, 1);
	if (ret != 0) {
		ubcore_log_err("chrdev add failed, ret:%d.\n", ret);
		goto unreg_cdev_region;
	}

	/* /dev/ubcore */
	g_ubcore_ctx.ubcore_dev =
		device_create(g_ubcore_ctx.ubcore_class, NULL, g_ubcore_ctx.ubcore_devno, NULL,
			      UBCORE_DEVICE_NAME);
	if (IS_ERR(g_ubcore_ctx.ubcore_dev)) {
		ret = (int)PTR_ERR(g_ubcore_ctx.ubcore_dev);
		ubcore_log_err("couldn't create device %s, ret:%d.\n", UBCORE_DEVICE_NAME, ret);
		goto del_cdev;
	}
	ubcore_log_info("ubcore device created success.\n");
	return 0;

del_cdev:
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
unreg_cdev_region:
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
unreg_class:
	ubcore_class_unregister(g_ubcore_ctx.ubcore_class);
	return ret;
}

static void ubcore_unregister_sysfs(void)
{
	device_destroy(g_ubcore_ctx.ubcore_class, g_ubcore_ctx.ubcore_cdev.dev);
	cdev_del(&g_ubcore_ctx.ubcore_cdev);
	unregister_chrdev_region(g_ubcore_ctx.ubcore_devno, 1);
	ubcore_class_unregister(g_ubcore_ctx.ubcore_class);
	ubcore_log_info("ubcore device destroyed success.\n");
}

static void ubcore_ipv4_to_netaddr(struct ubcore_net_addr *netaddr, __be32 ipv4)
{
	netaddr->net_addr.in4.reserved1 = 0;
	netaddr->net_addr.in4.reserved2 = htonl(UBCORE_IPV4_MAP_IPV6_PREFIX);
	netaddr->net_addr.in4.addr = ipv4;
}

static inline uint32_t sip_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return (uint32_t)(1 << ((uint32_t)mtu + SIP_MTU_BITS_BASE_SHIFT));
}

static enum ubcore_mtu sip_get_mtu(uint32_t mtu)
{
	if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return (enum ubcore_mtu)0;
}

static void ubcore_sip_init(struct ubcore_sip_info *sip, struct ubcore_device *tpf_dev,
	const struct ubcore_net_addr *netaddr, uint8_t *port_list,
	uint8_t port_cnt, uint32_t prefix_len, struct net_device *netdev)
{
	(void)memcpy(sip->dev_name, tpf_dev->dev_name, UBCORE_MAX_DEV_NAME);
	(void)memcpy(&sip->addr, netaddr, sizeof(struct ubcore_net_addr));
	if (port_list != NULL)
		(void)memcpy(sip->port_id, port_list, UBCORE_MAX_PORT_CNT);
	sip->port_cnt = port_cnt;
	sip->prefix_len = prefix_len;
	sip->mtu = (uint32_t)sip_get_mtu(netdev->mtu);
	(void)memcpy(sip->netdev_name, netdev_name(netdev),
		UBCORE_MAX_DEV_NAME);
}

static void ubcore_notify_uvs_update_sip(
	struct ubcore_device *tpf_dev, struct ubcore_sip_info *new_sip,
	struct ubcore_sip_info *old_sip, uint32_t index)
{
	(void)ubcore_notify_uvs_del_sip(tpf_dev, old_sip, index);
	(void)ubcore_notify_uvs_add_sip(tpf_dev, new_sip, index);
}

static bool ubcore_notify_uvs_update_sip_sync(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index)
{
	if (ubcore_get_netlink_valid() != true)
		return true;

	switch (sip_op) {
	case UBCORE_SIP_DEL:
		(void)ubcore_notify_uvs_del_sip(tpf_dev, old_sip, index);
		return true;
	case UBCORE_SIP_ADD:
		(void)ubcore_notify_uvs_add_sip(tpf_dev, new_sip, index);
		return true;
	case UBCORE_SIP_UPDATE:
		ubcore_notify_uvs_update_sip(tpf_dev, new_sip, old_sip, index);
		return true;
	default:
		ubcore_log_err("sip_op_type out of range");
		return false;
	}
}

static void ubcore_notify_uvs_update_sip_task(struct work_struct *work)
{
	struct ubcore_notify_uvs_sip_event_work *l_work = container_of(
		work, struct ubcore_notify_uvs_sip_event_work, work);

	(void)ubcore_notify_uvs_update_sip_sync(
		l_work->tpf_dev, &l_work->new_sip, &l_work->old_sip, l_work->sip_op, l_work->index);
	kfree(l_work);
}

static int ubcore_notify_uvs_update_sip_async(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index)
{
	struct ubcore_notify_uvs_sip_event_work *work;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return -ENOMEM;

	INIT_WORK(&work->work, ubcore_notify_uvs_update_sip_task);
	work->tpf_dev = tpf_dev;
	if (new_sip != NULL)
		work->new_sip = *(new_sip);
	if (old_sip != NULL)
		work->old_sip = *(old_sip);
	work->index = index;
	work->sip_op = sip_op;
	if (ubcore_queue_work((int)UBCORE_SIP_NOTIFY_WQ, &work->work) != 0) {
		kfree(work);
		ubcore_log_err("Queue work failed");
		return -1;
	}
	return 0;
}

static int ubcore_notify_uvs_update_sip_manage(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index, bool async)
{
	int ret = 0;

	if (!async) {
		(void)ubcore_notify_uvs_update_sip_sync(tpf_dev, new_sip, old_sip, sip_op, index);
		return 0;
	}

	ret = ubcore_notify_uvs_update_sip_async(tpf_dev, new_sip, old_sip, sip_op, index);
	if (ret != 0)
		ubcore_log_err("kzalloc failed or queue type err");
	return ret;
}

static void ubcore_add_net_addr(struct ubcore_device *tpf_dev, struct ubcore_device *pf_dev,
	struct ubcore_net_addr *netaddr, struct net_device *netdev, uint32_t prefix_len, bool async)
{
	struct ubcore_sip_info sip = {0};
	uint8_t *port_list = NULL;
	uint8_t port_cnt = 0;
	uint32_t index;
	int ret;

	/* get driver set nedev port */
	ubcore_find_port_netdev(pf_dev, netdev, &port_list, &port_cnt);
	ubcore_sip_init(&sip, tpf_dev,
		netaddr, port_list, port_cnt, prefix_len, netdev);

	ret = ubcore_lookup_sip_idx(&tpf_dev->sip_table, &sip, &index);
	if (ret == 0) {
		ubcore_log_err("sip already exists\n");
		return;
	}
	index = (uint32_t)ubcore_sip_idx_alloc(&tpf_dev->sip_table);

	if (tpf_dev->ops != NULL && tpf_dev->ops->add_net_addr != NULL &&
		tpf_dev->ops->add_net_addr(tpf_dev, netaddr, index) != 0)
		ubcore_log_err("Failed to set net addr");

	/* add net_addr entry, record idx -> netaddr mapping */
	(void)ubcore_add_sip_entry(&tpf_dev->sip_table, &sip, index);

	/* nodify uvs add sip info */
	if (ubcore_notify_uvs_update_sip_manage(tpf_dev, &sip, NULL,
		UBCORE_SIP_ADD, index, async) != 0)
		ubcore_log_err("kzalloc failed or queue type err");

	/* The ubcore sip table and up/down events are updated synchronously, and the uvs
	 * is abnormally disconnected. After waiting for the pull-up,
	 * the sip table in the kernel state is actively synchronized.
	 */
}

static void ubcore_delete_net_addr(struct ubcore_device *tpf_dev, struct ubcore_device *pf_dev,
	struct ubcore_net_addr *netaddr, struct net_device *netdev, uint32_t prefix_len, bool async)
{
	struct ubcore_sip_info sip = {0};
	uint8_t *port_list = NULL;
	uint8_t port_cnt = 0;
	uint32_t index;

	ubcore_find_port_netdev(pf_dev, netdev, &port_list, &port_cnt);

	ubcore_sip_init(&sip, tpf_dev,
		netaddr, port_list, port_cnt, prefix_len, netdev);
	if (ubcore_lookup_sip_idx(&tpf_dev->sip_table, &sip, &index) != 0)
		return;

	if (tpf_dev->ops != NULL && tpf_dev->ops->delete_net_addr != NULL &&
		tpf_dev->ops->delete_net_addr(tpf_dev, index) != 0)
		ubcore_log_err("Failed to delete net addr");

	(void)ubcore_del_sip_entry(&tpf_dev->sip_table, index);
	(void)ubcore_sip_idx_free(&tpf_dev->sip_table, index);
	/* nodify uvs delete sip info */
	if (ubcore_notify_uvs_update_sip_manage(tpf_dev, NULL, &sip,
		UBCORE_SIP_DEL, index, async) != 0)
		ubcore_log_err("kzalloc failed or queue type err");

	/* The ubcore sip table and up/down events are updated synchronously,
	 * and the uvs is abnormally disconnected. After waiting for the pull-up,
	 * the sip table in the kernel state is actively synchronized
	 */
}

static void ubcore_update_eid(struct ubcore_device *dev,
	struct ubcore_net_addr *netaddr, bool is_add)
{
	union ubcore_eid *eid;
	uint32_t eid_idx = 0;

	if (dev->transport_type <= UBCORE_TRANSPORT_INVALID ||
		dev->transport_type >= UBCORE_TRANSPORT_MAX)
		return;

	if (!dev->dynamic_eid) {
		ubcore_log_err("static mode does not allow modify of eid\n");
		return;
	}
	eid = (union ubcore_eid *)(void *)&netaddr->net_addr;
	if (ubcore_update_eidtbl_by_eid(dev, eid, &eid_idx, is_add) != 0)
		return;
	if (dev->cfg.pattern == (uint8_t)UBCORE_PATTERN_1)
		ubcore_update_pattern1_eid(dev, eid, eid_idx, is_add);
	else
		ubcore_update_pattern3_eid(dev, eid, eid_idx, is_add);
}

static int ubcore_handle_inetaddr_event(struct net_device *netdev, unsigned long event,
					struct ubcore_net_addr *netaddr, uint32_t prefix_len)
{
	struct net_device *real_netdev;
	struct ubcore_net_addr real_netaddr;
	struct ubcore_device **devices;
	uint32_t num_devices = 0;
	struct ubcore_device *tpf_dev;
	struct ubcore_device *dev;

	uint32_t i;

	if (netdev == NULL || netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	if (is_vlan_dev(netdev)) {
		real_netdev = vlan_dev_real_dev(netdev);
		(void)ubcore_fill_netaddr_macvlan(&real_netaddr, real_netdev, netaddr->type);
	} else {
		real_netdev = netdev;
		real_netaddr = *netaddr;
	}

	devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
	if (devices == NULL)
		return NOTIFY_DONE;

	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		if (dev->attr.virtualization)
			continue;

		tpf_dev = ubcore_find_tpf_by_dev(dev, UBCORE_TRANSPORT_UB);
		switch (event) {
		case NETDEV_UP:
			if (tpf_dev)
				ubcore_add_net_addr(
					tpf_dev, dev, netaddr, netdev, prefix_len, true);
			ubcore_update_eid(dev, netaddr, true);
			break;
		case NETDEV_DOWN:
			if (tpf_dev)
				ubcore_delete_net_addr(
					tpf_dev, dev, netaddr, netdev, prefix_len, true);
			ubcore_update_eid(dev, netaddr, false);
			break;
		default:
			break;
		}
		if (tpf_dev)
			ubcore_put_device(tpf_dev);
	}
	ubcore_put_devices(devices, num_devices);
	return NOTIFY_OK;
}

static int ubcore_ipv6_notifier_call(struct notifier_block *nb,
	unsigned long event, void *arg)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->idev == NULL || ifa->idev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->idev->dev;
	ubcore_log_info("Get a ipv6 event %s from netdev %s%s ip %pI6c prefixlen %u\n",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->addr, ifa->prefix_len);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	(void)memcpy(&netaddr.net_addr, &ifa->addr, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);

	if (netaddr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
		/* When mtu changes, intercept the ipv6 address up/down that triggers fe80 */
		return NOTIFY_DONE;
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr, ifa->prefix_len);
}

static int ubcore_ipv4_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->ifa_dev == NULL || ifa->ifa_dev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	ubcore_log_info("Get a ipv4 event %s netdev %s%s ip %pI4 prefixlen %hhu",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->ifa_address, ifa->ifa_prefixlen);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	ubcore_ipv4_to_netaddr(&netaddr, ifa->ifa_address);
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr, (uint32_t)ifa->ifa_prefixlen);
}

static void ubcore_add_ipv4_entry(struct list_head *list, __be32 ipv4, uint32_t prefix_len,
	struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	ubcore_ipv4_to_netaddr(&na_entry->addr, ipv4);
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	na_entry->prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_add_ipv6_entry(struct list_head *list, struct in6_addr *ipv6,
	uint32_t prefix_len, struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	(void)memcpy(&na_entry->addr.net_addr, ipv6, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);
	na_entry->prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_netdev_get_ipv4(struct net_device *netdev, struct list_head *list)
{
	struct in_ifaddr *ifa;
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (in_dev == NULL) {
		rcu_read_unlock();
		return;
	}

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		ubcore_add_ipv4_entry(list, ifa->ifa_address, ifa->ifa_prefixlen, netdev);
	}
	rcu_read_unlock();
}

static void ubcore_netdev_get_ipv6(struct net_device *netdev, struct list_head *list)
{
	struct inet6_ifaddr *ifa;
	struct inet6_dev *in_dev;

	in_dev = in6_dev_get(netdev);
	if (in_dev == NULL)
		return;

	read_lock_bh(&in_dev->lock);
	list_for_each_entry(ifa, &in_dev->addr_list, if_list) {
		ubcore_add_ipv6_entry(list, (struct in6_addr *)&ifa->addr, ifa->prefix_len, netdev);
	}
	read_unlock_bh(&in_dev->lock);
	in6_dev_put(in_dev);
}

void ubcore_update_default_eid(struct ubcore_device *dev, bool is_add)
{
	struct net_device *netdev = dev->netdev;
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_device *tpf_dev = NULL;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	if (netdev == NULL)
		return;

	/* In virtualization situation sip and eid are not from net_dev */
	if (dev->attr.virtualization)
		return;

	tpf_dev = ubcore_find_tpf_by_dev(dev, UBCORE_TRANSPORT_UB);

	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);
	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (na_entry->addr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
			continue;
		if (tpf_dev)
			is_add == true ?
				ubcore_add_net_addr(tpf_dev, dev, &na_entry->addr,
					netdev, na_entry->prefix_len, false) :
				ubcore_delete_net_addr(tpf_dev, dev, &na_entry->addr,
					netdev, na_entry->prefix_len, false);
		ubcore_update_eid(dev, &na_entry->addr, is_add);
		list_del(&na_entry->node);
		kfree(na_entry);
	}
	if (tpf_dev)
		ubcore_put_device(tpf_dev);
}

void ubcore_update_netaddr(struct ubcore_device *dev, struct net_device *netdev, bool add)
{
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	/* ipv4 */
	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);

	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (add) {
			if (dev != NULL && dev->ops != NULL && dev->ops->add_net_addr != NULL &&
				dev->ops->add_net_addr(dev, &na_entry->addr, 0) != 0)
				ubcore_log_err("Failed to add net addr");
		} else {
			if (dev != NULL && dev->ops != NULL && dev->ops->delete_net_addr != NULL &&
				dev->ops->delete_net_addr(dev, 0) != 0)
				ubcore_log_err("Failed to delete net addr");
		}
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

static void ubcore_change_mtu(struct ubcore_device *dev, struct net_device *netdev)
{
	struct ubcore_device *tpf_dev;
	struct ubcore_sip_info *new_sip;
	struct ubcore_sip_info old_sip;
	uint32_t max_cnt;
	uint32_t i;

	tpf_dev = ubcore_find_tpf_by_dev(dev, UBCORE_TRANSPORT_UB);
	if (tpf_dev == NULL)
		return;

	mutex_lock(&tpf_dev->sip_table.lock);
	max_cnt = ubcore_get_sip_max_cnt(&tpf_dev->sip_table);
	for (i = 0; i < max_cnt; i++) {
		new_sip = ubcore_lookup_sip_info(&tpf_dev->sip_table, i);
		if (new_sip == NULL || memcmp(new_sip->netdev_name, netdev_name(netdev),
			UBCORE_MAX_DEV_NAME) != 0)
			continue;
		old_sip = *new_sip;
		new_sip->mtu = (uint32_t)sip_get_mtu(netdev->mtu);
		(void)ubcore_notify_uvs_update_sip_manage(
			tpf_dev, new_sip, &old_sip, UBCORE_SIP_UPDATE, i, true);
	}
	mutex_unlock(&tpf_dev->sip_table.lock);
	ubcore_put_device(tpf_dev);
}

static void ubcore_do_bond(struct ubcore_bond_event_work *l_bond_event)
{
	int ret = -1;

	switch (l_bond_event->bond_op_type) {
	case UBCORE_BOND_ADD:
		ret = l_bond_event->bond_add(
			l_bond_event->bond, l_bond_event->slave, &l_bond_event->info_upper);
		if (ret != 0)
			ubcore_log_err("Failed to bond_add and ret value is %d", ret);
		break;
	case UBCORE_BOND_REMOVE:
		ret = l_bond_event->bond_remove(l_bond_event->bond, l_bond_event->slave);
		if (ret != 0)
			ubcore_log_err("Failed to bond_remove and ret value is %d", ret);
		break;
	case UBCORE_BOND_SLAVE_UPDATE:
		ret = l_bond_event->slave_update(
			l_bond_event->bond, l_bond_event->slave, &l_bond_event->info_lower);
		if (ret != 0)
			ubcore_log_err("Failed to slave_update and ret value is %d", ret);
		break;
	default:
		break;
	}
	if (l_bond_event->bond)
		dev_put(l_bond_event->bond);
	dev_put(l_bond_event->slave);
	if (ret == 0)
		ubcore_log_info("Success running bond_event with type %d",
			(int)l_bond_event->bond_op_type);
	kfree(l_bond_event);
}

static void ubcore_do_bond_work(struct work_struct *work)
{
	struct ubcore_bond_event_work *l_bond_event =
		container_of(work, struct ubcore_bond_event_work, work);

	ubcore_do_bond(l_bond_event);
}

static void ubcore_queue_bond_work(struct ubcore_bond_event_work *l_bond_event)
{
	if (ubcore_queue_work((int)UBCORE_BOND_EVENT_WQ, &l_bond_event->work) != 0) {
		dev_put(l_bond_event->slave);
		if (l_bond_event->bond)
			dev_put(l_bond_event->bond);
		ubcore_log_err("Queue work type %d, op type %d failed",
			(int)UBCORE_BOND_EVENT_WQ,
			(int)l_bond_event->bond_op_type);
		kfree(l_bond_event);
	}
}

static int ubcore_netdev_event_change_upper(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	struct ubcore_bond_event_work *l_bond_event;
	struct net_device *bond = info->upper_dev;

	if (dev == NULL || dev->ops == NULL || dev->ops->bond_add == NULL ||
		dev->ops->bond_remove == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		ubcore_put_device(dev);
		return -EINVAL;
	}

	ubcore_log_info("Event with master netdev %s and slave netdev %s",
		netdev_name(bond), netdev_name(slave));

	l_bond_event = kzalloc(sizeof(*l_bond_event), GFP_KERNEL);
	if (!l_bond_event) {
		ubcore_put_device(dev);
		return -ENOMEM;
	}

	dev_hold(bond);
	l_bond_event->bond = bond;
	dev_hold(slave);
	l_bond_event->slave = slave;
	if (info->linking) {
		lag_upper_info = info->upper_info;
		l_bond_event->info_upper = *lag_upper_info;
		l_bond_event->bond_add = dev->ops->bond_add;
		l_bond_event->bond_op_type = UBCORE_BOND_ADD;
	} else {
		l_bond_event->bond_op_type = UBCORE_BOND_REMOVE;
		l_bond_event->bond_remove = dev->ops->bond_remove;
	}

	/* dev may be unregistered so it has to be put_device here */
	ubcore_put_device(dev);

	INIT_WORK(&l_bond_event->work, ubcore_do_bond_work);
	ubcore_queue_bond_work(l_bond_event);
	ubcore_log_info("Success to deal with event NETDEV_CHANGEUPPER");
	return 0;
}

static int ubcore_netdev_event_change_lower_state(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info = NULL;
	struct net_device *bond = NULL;
	struct ubcore_bond_event_work *l_bond_event;

	if (dev == NULL || dev->ops == NULL || dev->ops->slave_update == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}
	l_bond_event = kzalloc(sizeof(*l_bond_event), GFP_KERNEL);
	if (!l_bond_event)
		return false;
	bond = netdev_master_upper_dev_get_rcu(slave);
	if (bond) {
		dev_hold(bond);
		l_bond_event->bond = bond;
		ubcore_log_info("Event with master netdev %s and slave netdev %s",
			netdev_name(bond), netdev_name(slave));
	} else {
		l_bond_event->bond = NULL;
		ubcore_log_info("Event with master netdev NULL and slave netdev %s",
			netdev_name(slave));
	}
	lag_lower_info = info->lower_state_info;
	l_bond_event->info_lower = *lag_lower_info;
	dev_hold(slave);
	l_bond_event->slave = slave;
	l_bond_event->slave_update = dev->ops->slave_update;
	l_bond_event->bond_op_type = UBCORE_BOND_SLAVE_UPDATE;
	INIT_WORK(&l_bond_event->work, ubcore_do_bond_work);
	ubcore_queue_bond_work(l_bond_event);
	ubcore_log_info("Success to deal with event NETDEV_CHANGELOWERSTATE");
	return 0;
}

static struct net_device *ubcore_find_master_netdev(unsigned long event,
	struct netdev_notifier_changeupper_info *info,
	struct net_device *slave)
{
	/* When we need to remove slaves from the bond device,
	 * we cannot find the ubcore dev by the netdev provided by unlink NETDEV_CHANGEUPPER.
	 * It has been unregistered. We need to find ubcore dev by the master netdev
	 */
	struct net_device *bond = NULL;

	if (event == NETDEV_CHANGEUPPER && !info->linking)
		bond = info->upper_dev;
	else if (event == NETDEV_CHANGELOWERSTATE)
		bond = netdev_master_upper_dev_get_rcu(slave);

	return bond;
}

static void ubcore_do_netdev_notify(unsigned long event, struct ubcore_device *dev,
	struct net_device *netdev, void *arg)
{
	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_UP:
		if (dev->transport_type != UBCORE_TRANSPORT_UB)
			ubcore_add_netaddr(dev, netdev);
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		if (dev->transport_type != UBCORE_TRANSPORT_UB)
			ubcore_remove_netaddr(dev, netdev);
		break;
	case NETDEV_CHANGEADDR:
		if (dev->transport_type != UBCORE_TRANSPORT_UB) {
			ubcore_remove_netaddr(dev, netdev);
			ubcore_add_netaddr(dev, netdev);
		}
		break;
	case NETDEV_CHANGEMTU:
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			ubcore_change_mtu(dev, netdev);
		break;
	case NETDEV_CHANGEUPPER:
		/* NETDEV_CHANGEUPPER event need to put_device ahead due to unregister dev */
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			(void)ubcore_netdev_event_change_upper(dev, netdev, arg);
		else
			ubcore_put_device(dev);

		break;
	case NETDEV_CHANGELOWERSTATE:
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			(void)ubcore_netdev_event_change_lower_state(dev, netdev, arg);
		break;
	default:
		break;
	}
}

static int ubcore_net_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct ubcore_device **devices;
	struct net_device *real_netdev;
	uint32_t num_devices = 0;
	uint32_t i;

	if (netdev == NULL)
		return NOTIFY_DONE;

	if (is_vlan_dev(netdev))
		real_netdev = vlan_dev_real_dev(netdev);
	else
		real_netdev = netdev;

	ubcore_log_info("Get a net event %s from ubcore_dev %s%s", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev));

	devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
	if (devices == NULL) {
		if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
			return NOTIFY_DONE;
		real_netdev = ubcore_find_master_netdev(event, arg, netdev);
		if (real_netdev == NULL) {
			ubcore_log_warn("Can not find master netdev by slave netdev %s",
				netdev_name(netdev));
			return NOTIFY_DONE;
		}
		ubcore_log_info("Success to find master netdev %s",
			netdev_name(real_netdev));
		devices = ubcore_get_devices_from_netdev(real_netdev, &num_devices);
		if (devices == NULL) {
			ubcore_log_warn("Can not find devices from master netdev %s",
				netdev_name(real_netdev));
			return NOTIFY_DONE;
		}
	}

	for (i = 0; i < num_devices; i++)
		ubcore_do_netdev_notify(event, devices[i], netdev, arg);

	if (event != NETDEV_CHANGEUPPER)
		ubcore_put_devices(devices, num_devices);
	else
		kfree(devices);

	return NOTIFY_OK;
}

static struct notifier_block ubcore_ipv6_notifier = {
	.notifier_call = ubcore_ipv6_notifier_call,
};

static struct notifier_block ubcore_ipv4_notifier = {
	.notifier_call = ubcore_ipv4_notifier_call,
};

static struct notifier_block ubcore_net_notifier = {
	.notifier_call = ubcore_net_notifier_call,
};

static int ubcore_register_notifiers(void)
{
	int ret;

	ret = ubcore_alloc_workqueue((int)UBCORE_SIP_NOTIFY_WQ);
	if (ret != 0) {
		pr_err("Failed to alloc workqueue for sip notify, ret = %d\n", ret);
		return -ENOMEM;
	}

	ret = ubcore_alloc_workqueue((int)UBCORE_BOND_EVENT_WQ);
	if (ret != 0) {
		(void)ubcore_destroy_workqueue((int)UBCORE_SIP_NOTIFY_WQ);
		pr_err("Failed to alloc workqueue for bond event, ret = %d\n", ret);
		return -ENOMEM;
	}

	ret = register_netdevice_notifier(&ubcore_net_notifier);
	if (ret != 0) {
		(void)ubcore_destroy_workqueue((int)UBCORE_BOND_EVENT_WQ);
		(void)ubcore_destroy_workqueue((int)UBCORE_SIP_NOTIFY_WQ);
		pr_err("Failed to register netdev notifier, ret = %d\n", ret);
		return ret;
	}
	ret = register_inetaddr_notifier(&ubcore_ipv4_notifier);
	if (ret != 0) {
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		(void)ubcore_destroy_workqueue((int)UBCORE_BOND_EVENT_WQ);
		(void)ubcore_destroy_workqueue((int)UBCORE_SIP_NOTIFY_WQ);
		pr_err("Failed to register inetaddr notifier, ret = %d\n", ret);
		return -1;
	}
	ret = register_inet6addr_notifier(&ubcore_ipv6_notifier);
	if (ret != 0) {
		(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		(void)ubcore_destroy_workqueue((int)UBCORE_BOND_EVENT_WQ);
		(void)ubcore_destroy_workqueue((int)UBCORE_SIP_NOTIFY_WQ);
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
	(void)ubcore_destroy_workqueue((int)UBCORE_BOND_EVENT_WQ);
	(void)ubcore_destroy_workqueue((int)UBCORE_DISPATCH_EVENT_WQ);
}

static int __init ubcore_init(void)
{
	int ret;

	ret = ubcore_register_sysfs();
	if (ret != 0)
		return ret;

	ret = ubcore_genl_init();
	if (ret != 0) {
		(void)pr_err("Failed to ubcore genl init\n");
		ubcore_unregister_sysfs();
		return -1;
	}

	if (ubcore_netlink_init() != 0) {
		ubcore_genl_exit();
		ubcore_unregister_sysfs();
		return -1;
	}

	ret = ubcore_register_notifiers();
	if (ret != 0) {
		pr_err("Failed to register notifiers\n");
		ubcore_netlink_exit();
		ubcore_genl_exit();
		ubcore_unregister_sysfs();
		return -1;
	}

	ret = ubcore_register_pnet_ops();
	if (ret != 0) {
		ubcore_unregister_notifiers();
		ubcore_netlink_exit();
		ubcore_genl_exit();
		ubcore_unregister_sysfs();
	}

	ret = ubcore_alloc_workqueue((int)UBCORE_DISPATCH_EVENT_WQ);
	if (ret != 0) {
		pr_err("Failed to alloc workqueue, ret = %d\n", ret);
		ubcore_unregister_pnet_ops();
		ubcore_unregister_notifiers();
		ubcore_netlink_exit();
		ubcore_genl_exit();
		ubcore_unregister_sysfs();
		return ret;
	}
	ubcore_log_info("ubcore module init success.\n");
	return 0;
}

static void __exit ubcore_exit(void)
{
	ubcore_unregister_pnet_ops();
	ubcore_unregister_notifiers();
	ubcore_netlink_exit();
	ubcore_genl_exit();
	ubcore_unregister_sysfs();
	ubcore_log_info("ubcore module exits.\n");
}

module_init(ubcore_init);
module_exit(ubcore_exit);

MODULE_DESCRIPTION("Kernel module for ubus");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
