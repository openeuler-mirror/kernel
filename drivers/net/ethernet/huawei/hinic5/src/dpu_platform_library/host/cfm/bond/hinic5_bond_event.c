/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bond_event.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [BOND]" fmt

#include <net/sock.h>
#include <net/bonding.h>
#include <net/netlink.h>
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include <linux/net.h>
#include <linux/netdevice.h>

#include "hinic5_hw.h"
#include "hinic5_lld.h"
#include "cfg_mgmt_mpu_cmd_defs.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"
#include "bond_common_defs.h"
#include "hinic5_bond.h"
#include "hinic5_bond_inner.h"

static u8 bond_get_slaves_bitmap(struct hinic5_bond_dev *bdev, struct bonding *bond)
{
	struct slave *slave = NULL;
	struct list_head *iter = NULL;
	struct hinic5_lld_dev *lld_dev = NULL;
	u8 bitmap = 0;
	u8 port_id;

	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		lld_dev = hinic5_get_lld_dev_by_netdev(slave->dev);
		if (lld_dev == NULL || hinic5_func_type(lld_dev->hwdev) == TYPE_VF)
			continue;

		port_id = hinic5_physical_port_id(lld_dev->hwdev);
		BITMAP_SET(bitmap, port_id);
		(void)iter;
	}
	rcu_read_unlock();

	return bitmap;
}

static void bond_update_attr(struct hinic5_bond_dev *bdev, struct bonding *bond)
{
	spin_lock(&bdev->lock);
	bdev->new_attr.bond_mode = (u16)bond->params.mode;
	bdev->new_attr.bond_id = bdev->bond_attr.bond_id;
	bdev->new_attr.up_delay = (u16)bond->params.updelay;
	bdev->new_attr.down_delay = (u16)bond->params.downdelay;
	bdev->new_attr.slaves = 0;
	bdev->new_attr.active_slaves = 0;
	bdev->new_attr.lacp_collect_slaves = 0;
	bdev->new_attr.first_roce_func = BOND_DEFAULT_ROCE_FUNC;

	/* Only support L2/L34/L23 three policy */
	if (bond->params.xmit_policy <= BOND_XMIT_POLICY_LAYER23) {
		bdev->new_attr.xmit_hash_policy = (u8)bond->params.xmit_policy;
	} else {
		bond_master_warn(bdev->bond->dev, "Invalid hash policy %u (not layer2/34/23), defaulting to layer2\n",
				 (u8)bond->params.xmit_policy);
		bdev->new_attr.xmit_hash_policy = BOND_XMIT_POLICY_LAYER2;
	}

	bdev->new_attr.slaves = bond_get_slaves_bitmap(bdev, bond);
	spin_unlock(&bdev->lock);
}

static u8 bond_get_netdev_idx(const struct hinic5_bond_dev *bdev,
				  const struct net_device *ndev)
{
	u8 i;

	for (i = 0; i < BOND_PORT_MAX_NUM; i++) {
		if (bdev->tracker.ndev[i] == ndev)
			return i;
	}

	return PORT_INVALID_ID;
}

static void bond_pf_bitmap_set(struct hinic5_bond_dev *bdev, struct bond_attr *attr, u8 port_id)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	u8 pf_id;

	lld_dev = hinic5_get_lld_dev_by_netdev(bdev->tracker.ndev[port_id]);
	if (!lld_dev) {
		pr_err("hinic5_bond: Failed to get lld dev by netdev\n");
		return;
	}

	pf_id = hinic5_pf_id_of_vf(lld_dev->hwdev);
	BITMAP_SET(attr->bond_pf_bitmap, pf_id);
}

static void bond_dev_untrack_port(struct hinic5_bond_dev *bdev, u8 port_id)
{
	u32 track_cnt = 0;
	const struct net_device *untrack_ndev = NULL;

	spin_lock(&bdev->lock);
	if (bdev->tracker.ndev[port_id] != NULL) {
		untrack_ndev = bdev->tracker.ndev[port_id];
		track_cnt = --bdev->tracker.cnt;
		bdev->tracker.ndev[port_id] = NULL;
	}
	spin_unlock(&bdev->lock);
	if (track_cnt == 0)
		bond_dev_free_chip_bond_id(bdev);
	if (untrack_ndev)
		bond_master_info(bdev->bond->dev, "untrack port:%u, untrack ndev: %s, tracker cnt: %u\n",
				 port_id, untrack_ndev->name, track_cnt);
}

static void bond_slave_event(struct hinic5_bond_dev *bdev, struct slave *slave)
{
	/* Compatible with low version kernel socket listen event dynamically adding slave PF */
	u8 port_id = bond_get_netdev_idx(bdev, slave->dev);
	if (port_id == PORT_INVALID_ID)
		port_id = bond_dev_track_port(bdev, slave->dev);
	if (port_id == PORT_INVALID_ID)
		return;

	spin_lock(&bdev->lock);
	bdev->tracker.netdev_state[port_id].link_up = bond_slave_is_up(slave);
	bdev->tracker.netdev_state[port_id].tx_enabled = bond_slave_is_up(slave) && bond_is_active_slave(slave);
	spin_unlock(&bdev->lock);
	/* If bdev is dead, terminate the flow */
	if (unlikely(READ_ONCE(bdev->dead)))
		return;
	queue_delayed_work(bdev->wq, &bdev->bond_work, 0);
}

static bool bond_eval_bonding_stats(const struct hinic5_bond_dev *bdev, struct bonding *bond)
{
	return bdev->tracker.cnt > 0;
}

static void bond_master_event(struct hinic5_bond_dev *bdev, struct bonding *bond)
{
	u8 port_id = 0;
	int i = 0, cnt = 0;
	struct slave *slave = NULL;
	struct list_head *iter = NULL;

	bool slave_is_up[BOND_PORT_MAX_NUM] = {false};
	bool slave_is_active[BOND_PORT_MAX_NUM] = {false};
	struct net_device *slave_ndev[BOND_PORT_MAX_NUM]; /* Temporarily store network device pointers*/

	/* No mutex allowed within rcu lock */
	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		if (cnt >= BOND_PORT_MAX_NUM)
			break;
		slave_is_up[cnt] = bond_slave_is_up(slave);
		slave_is_active[cnt] = bond_is_active_slave(slave);
		slave_ndev[cnt] = slave->dev;
		dev_hold(slave_ndev[cnt++]);
		(void)iter;
	}
	rcu_read_unlock();

	/* Dynamic add Slave PF scenario */
	for (i = 0; i < cnt; ++i) {
		port_id = bond_get_netdev_idx(bdev, slave_ndev[i]);
		if (port_id == PORT_INVALID_ID) {
			port_id = bond_dev_track_port(bdev, slave_ndev[i]);
			if (port_id == PORT_INVALID_ID)
				continue;

			spin_lock(&bdev->lock);
			bdev->tracker.netdev_state[port_id].link_up = slave_is_up[i];
			bdev->tracker.netdev_state[port_id].tx_enabled =
				slave_is_up[i] && slave_is_active[i];
			spin_unlock(&bdev->lock);
		}
	}
	while (cnt != 0)
		dev_put(slave_ndev[--cnt]);
	/* TODO: For logic completeness, spinlock modify bdev needs to check bdev->dead status,
	   This issue will be uniformly modified when attach/detach new solution is modified */
	spin_lock(&bdev->lock);
	bdev->tracker.is_bonded = bond_eval_bonding_stats(bdev, bond);
	spin_unlock(&bdev->lock);

	/* Dynamic delete Slave PF scenario */
	for (port_id = 0; port_id < BOND_PORT_MAX_NUM; port_id++) {
		/* If new bond_attr has no slave pf but old bond_attr has slave pf,
		   need to delete old bond_attr's slave PF */
		if (BITMAP_JUDGE(bdev->new_attr.slaves, port_id) == 0) {
			if (BITMAP_JUDGE(bdev->bond_attr.slaves, port_id) != 0) {
				bond_dev_untrack_port(bdev, port_id);
			}
			continue;
		}
		bond_pf_bitmap_set(bdev, &bdev->new_attr, port_id);
	}
	/* Terminate the flow if bdev is dead */
	if (unlikely(READ_ONCE(bdev->dead)))
		return;
	queue_delayed_work(bdev->wq, &bdev->bond_work, 0);
}

void bond_handle_rtnl_event(struct net_device *ndev)
{
	struct hinic5_bond_dev *bdev = NULL;
	struct bonding *bond = NULL;
	struct slave *slave = NULL;
	struct hinic5_lld_dev *lld_dev = NULL;
	int srcu_idx = 0;

	if (netif_is_bond_master(ndev)) {
		bond = netdev_priv(ndev);
		bdev = bond_get_bdev(bond);
	} else if (netif_is_bond_slave(ndev)) {
		lld_dev = hinic5_get_lld_dev_by_netdev(ndev);
		if (!lld_dev || hinic5_func_type(lld_dev->hwdev) == TYPE_VF)
			return;
		slave = bond_slave_get_rtnl(ndev);
		if (slave) {
			bond = bond_get_bond_by_slave(slave);
			bdev = bond_get_bdev(bond);
		}
	}
	if (bond == NULL || bdev == NULL)
		return;

	/* TODO: Temporarily solve bdev async timing issue */
	srcu_idx = srcu_read_lock(&bdev_srcu);
	if (!bdev || unlikely(READ_ONCE(bdev->dead))) {
		srcu_read_unlock(&bdev_srcu, srcu_idx);

		return;
	}

	bond_update_attr(bdev, bond);
	if (slave)
		bond_slave_event(bdev, slave);
	else
		bond_master_event(bdev, bond);

	srcu_read_unlock(&bdev_srcu, srcu_idx);
}

/* If service registers attach_func, it will try to bind bond */
void bond_try_attach_user(struct net_device *ndev)
{
	u32 user;
	struct bonding *bond = NULL;
	struct hinic5_bond_dev *bdev = NULL;

	if (!netif_is_bond_master(ndev))
		return;

	bond = netdev_priv(ndev);
	/* if slave invalid or not exist, don't alloc bdev */
	if (!hinic5_bond_slave_is_match(bond)) {
		bond_master_warn(ndev, "Bond try attach user slaves invalid or not exist\n");
		return;
	}

	if (bond->params.mode != BOND_MODE_ACTIVEBACKUP &&
		bond->params.mode != BOND_MODE_XOR &&
		bond->params.mode != BOND_MODE_8023AD) {
		return;
	}
	bdev = bond_get_bdev(bond);
	for (user = HINIC5_BOND_USER_OVS; user < HINIC5_BOND_USER_NUM; user++) {
		if (bdev && bdev->slot_used[user] != 0)
			continue;
		if (bond_call_srv_attach_func(user, bond)) {
			bond_master_info(bond->dev, "bond try attach user:%d name %s\n",
				user, bond->dev->name);
			hinic5_bond_event_attach(bond, user);
		}
	}
}

#if defined(HAVE_NETDEV_CHANGEUPPER)

int bond_notifier_netdev_event(struct notifier_block *self, unsigned long event, void *ptr)
{
	struct net_device *ndev = NULL;
	struct netdev_notifier_changeupper_info *info = NULL;
	struct net_device *upper_dev = NULL;

	switch ((u32)event) {
	case NETDEV_CHANGEUPPER:
		info = (struct netdev_notifier_changeupper_info *)ptr;

		upper_dev = info->upper_dev;
		if (!virt_addr_valid((void *)upper_dev)) /* Low kernel version register callback but dev may not have completed registration scenario */
			break;

		bond_try_attach_user(upper_dev);
		bond_handle_rtnl_event(upper_dev);
		break;
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGEINFODATA:
	case NETDEV_CHANGELOWERSTATE:
		ndev = netdev_notifier_info_to_dev(ptr);
		if (!virt_addr_valid((void *)ndev))
			break;

		bond_handle_rtnl_event(ndev);
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_DONE;
}

struct notifier_block g_bond_nb = {
	.notifier_call = bond_notifier_netdev_event,
};

int bond_enable_netdev_event(void)
{
	int ret;

	ret = register_netdevice_notifier(&g_bond_nb);
	if (ret != 0) {
		pr_err("bond register_netdevice_notifier failed\n");
		return ret;
	}

	return 0;
}

void bond_disable_netdev_event(void)
{
	(void)unregister_netdevice_notifier(&g_bond_nb);
}

#else

#if defined(HAVE_SK_DATE_READY_BYTES)
void bond_rtnl_data_ready(struct sock *sk, int bytes)
#else
void bond_rtnl_data_ready(struct sock *sk)
#endif
{
	struct net_device *ndev = NULL;
	struct ifinfomsg *ifinfo = NULL;
	struct nlmsghdr *hdr = NULL;
	struct sk_buff *skb = NULL;
	int err = 0;

	skb = skb_recv_datagram(sk, 0, 0, &err);
	if (err != 0 || !skb)
		return;

	hdr = (struct nlmsghdr *)skb->data;
	if (!hdr || !((skb->len > (sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg))) &&
		hdr->nlmsg_len >= sizeof(struct nlmsghdr) && hdr->nlmsg_len <= skb->len) ||
		hdr->nlmsg_type != RTM_NEWLINK || rtnl_is_locked() == 0) {
		goto free_skb;
	}

	ifinfo = nlmsg_data(hdr);
	ndev = dev_get_by_index(&init_net, ifinfo->ifi_index);
	if (ndev) {
		bond_try_attach_user(ndev);
		bond_handle_rtnl_event(ndev);
		dev_put(ndev);
	}

free_skb:
	kfree_skb(skb);
}

int bond_enable_netdev_event(void)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTNLGRP_LINK,
	};
	int err;
	struct socket **rtnl_sock = hinic5_get_bond_mngr_sock_addr();

#if defined (HAVE_SOCK_CREATE_KERN_NET)
	err = sock_create_kern(&init_net, AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE,
			rtnl_sock);
#else
	err = sock_create_kern(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE,
			rtnl_sock);
#endif
	if (err != 0) {
		pr_err("hinic5_bond: Couldn't create rtnl socket.\n");
		*rtnl_sock = NULL;
		return err;
	}

	(*rtnl_sock)->sk->sk_data_ready = bond_rtnl_data_ready;
	(*rtnl_sock)->sk->sk_allocation = GFP_KERNEL;

	err = kernel_bind(*rtnl_sock, (struct sockaddr *)(u8 *)&addr, sizeof(addr));
	if (err != 0) {
		pr_err("hinic5_bond: Couldn't bind rtnl socket.\n");
		sock_release(*rtnl_sock);
		*rtnl_sock = NULL;
	}

	return err;
}

void bond_disable_netdev_event(void)
{
	struct socket *rtnl_sock = NULL;

	rtnl_sock = hinic5_get_bond_mngr_sock();
	if (rtnl_sock != NULL)
		sock_release(rtnl_sock);
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) */