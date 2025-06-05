// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth.h"
#include "common/vport.h"
#include "common/xsc_fs.h"

static int xsc_vport_context_update_vlans(struct xsc_adapter *adapter,
					  enum xsc_vlan_rule_type rule_type,
					  u16 vid, bool add)
{
	struct net_device *ndev = adapter->netdev;
	struct xsc_core_device *xdev = adapter->xdev;
	int err;

	err = xsc_modify_nic_vport_vlans(xdev, vid, add);
	if (err)
		netdev_err(ndev, "Failed to modify vport vid:%d rule_type:%d err:%d\n",
			   vid, rule_type, err);
	return err;
}

static int  xsc_add_vlan_rule(struct xsc_adapter *adapter,
			      enum xsc_vlan_rule_type rule_type, u16 vid)
{
	return xsc_vport_context_update_vlans(adapter, rule_type, vid, true);
}

static void xsc_del_vlan_rule(struct xsc_adapter *adapter,
			      enum xsc_vlan_rule_type rule_type, u16 vid)
{
	xsc_vport_context_update_vlans(adapter, rule_type, vid, false);
}

static int xsc_vlan_rx_add_cvid(struct xsc_adapter *adapter, u16 vid)
{
	int err;

	set_bit(vid, adapter->fs.vlan.active_cvlans);

	err = xsc_add_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID, vid);
	if (err)
		clear_bit(vid, adapter->vlan_params.active_cvlans);

	return err;
}

static int xsc_vlan_rx_add_svid(struct xsc_adapter *adapter, u16 vid)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	set_bit(vid, adapter->fs.vlan.active_svlans);

	err = xsc_add_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_STAG_VID, vid);
	if (err) {
		clear_bit(vid, adapter->fs.vlan.active_svlans);
		return err;
	}

	/* Need to fix some features.. */
	netdev_update_features(netdev);
	return err;
}

int xsc_vlan_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	if (!vid)
		return 0;

	if (be16_to_cpu(proto) == ETH_P_8021Q)
		return xsc_vlan_rx_add_cvid(adapter, vid);
	else if (be16_to_cpu(proto) == ETH_P_8021AD)
		return xsc_vlan_rx_add_svid(adapter, vid);

	return -EOPNOTSUPP;
}

int xsc_vlan_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct xsc_adapter *adapter = netdev_priv(dev);

	if (!vid)
		return 0;

	if (be16_to_cpu(proto) == ETH_P_8021Q) {
		clear_bit(vid, adapter->fs.vlan.active_cvlans);
		xsc_del_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID, vid);
	} else if (be16_to_cpu(proto) == ETH_P_8021AD) {
		clear_bit(vid, adapter->fs.vlan.active_svlans);
		xsc_del_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_STAG_VID, vid);
		netdev_update_features(dev);
	}

	return 0;
}

static inline int xsc_hash_l2(const u8 *addr)
{
	return addr[5];
}

static void xsc_add_l2_to_hash(struct hlist_head *hash, const u8 *addr)
{
	struct xsc_l2_hash_node *hn;
	int ix = xsc_hash_l2(addr);
	int found = 0;

	hlist_for_each_entry(hn, &hash[ix], hlist)
		if (ether_addr_equal(hn->mac_addr, addr)) {
			found = 1;
			break;
		}

	if (found) {
		hn->action = XSC_ACTION_NONE;
		return;
	}

	hn = kzalloc(sizeof(*hn), GFP_ATOMIC);
	if (!hn)
		return;

	ether_addr_copy(hn->mac_addr, addr);
	hn->action = XSC_ACTION_ADD;

	hlist_add_head(&hn->hlist, &hash[ix]);
}

static void xsc_del_l2_from_hash(struct xsc_l2_hash_node *hn)
{
	hlist_del(&hn->hlist);
	kfree(hn);
}

static void xsc_sync_netdev_uc_addr(struct xsc_core_device *xdev,
				    struct net_device *netdev,
				    struct xsc_flow_steering *fs)
{
	struct netdev_hw_addr *ha;

	netif_addr_lock_bh(netdev);

	netdev_for_each_uc_addr(ha, netdev) {
		xsc_add_l2_to_hash(fs->l2.netdev_uc, ha->addr);
	}

	netif_addr_unlock_bh(netdev);
}

static void xsc_vport_context_update_uc_mac(struct xsc_core_device *xdev,
					    struct xsc_flow_steering *fs,
					    struct xsc_l2_hash_node *hn)
{
	int err = 0;
	u16 pct_prio;

	switch (hn->action) {
	case XSC_ACTION_ADD:
		err = xsc_nic_vport_add_uc_mac(xdev, hn->mac_addr, &pct_prio);
		if (err) {
			xsc_core_err(xdev, "failed to add pct entry for uc mac %pM\n",
				     hn->mac_addr);
			xsc_del_l2_from_hash(hn);
		} else {
			hn->action = XSC_ACTION_NONE;
			hn->pct_prio = pct_prio;
		}
		xsc_core_info(xdev, "pct add for uc mac %pM, priority: %d\n",
			      hn->mac_addr, pct_prio);
		break;
	case XSC_ACTION_DEL:
		xsc_core_info(xdev, "pct del for uc mac %pM, priority: %d\n",
			      hn->mac_addr, hn->pct_prio);
		err = xsc_nic_vport_del_uc_mac(xdev, hn->pct_prio);
		if (err)
			xsc_core_err(xdev, "failed to del pct entry for uc mac %pM\n",
				     hn->mac_addr);
		xsc_del_l2_from_hash(hn);
		break;
	}
}

static void xsc_apply_netdev_uc_addr(struct xsc_core_device *xdev,
				     struct xsc_flow_steering *fs)
{
	struct xsc_l2_hash_node *hn;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < XSC_L2_ADDR_HASH_SIZE; i++)
		hlist_for_each_entry_safe(hn, tmp, &fs->l2.netdev_uc[i], hlist)
			xsc_vport_context_update_uc_mac(xdev, fs, hn);
}

static void xsc_vport_context_update_mc_mac(struct xsc_core_device *xdev,
					    struct xsc_flow_steering *fs,
					    struct xsc_l2_hash_node *hn)
{
	int err = 0;

	switch (hn->action) {
	case XSC_ACTION_ADD:
		err = xsc_nic_vport_modify_mc_mac(xdev, hn->mac_addr, XSC_JOIN);
		if (err) {
			xsc_core_err(xdev, "failed to join mcg\n");
			xsc_del_l2_from_hash(hn);
		} else {
			hn->action = XSC_ACTION_NONE;
		}
		break;
	case XSC_ACTION_DEL:
		xsc_del_l2_from_hash(hn);
		err = xsc_nic_vport_modify_mc_mac(xdev, hn->mac_addr, XSC_LEAVE);
		if (err) {
			xsc_core_err(xdev, "failed to leave mcg\n");
			xsc_add_l2_to_hash(fs->l2.netdev_mc, hn->mac_addr);
		}
		break;
	default:
		break;
	}

	if (err)
		xsc_core_info(xdev, "action=%u, mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
			      hn->action, hn->mac_addr[0], hn->mac_addr[1], hn->mac_addr[2],
			      hn->mac_addr[3], hn->mac_addr[4], hn->mac_addr[5]);
}

static void xsc_sync_netdev_mc_addr(struct xsc_core_device *xdev,
				    struct net_device *netdev,
				    struct xsc_flow_steering *fs)
{
	struct netdev_hw_addr *ha;

	netif_addr_lock_bh(netdev);

	netdev_for_each_mc_addr(ha, netdev) {
		xsc_add_l2_to_hash(fs->l2.netdev_mc, ha->addr);
	}

	netif_addr_unlock_bh(netdev);
}

static void xsc_apply_netdev_mc_addr(struct xsc_core_device *xdev,
				     struct xsc_flow_steering *fs)
{
	struct xsc_l2_hash_node *hn;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < XSC_L2_ADDR_HASH_SIZE; i++)
		hlist_for_each_entry_safe(hn, tmp, &fs->l2.netdev_mc[i], hlist)
			xsc_vport_context_update_mc_mac(xdev, fs, hn);
}

static void xsc_handle_netdev_addr(struct xsc_core_device *xdev,
				   struct net_device *netdev,
				   struct xsc_flow_steering *fs)
{
	struct xsc_l2_hash_node *hn;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < XSC_L2_ADDR_HASH_SIZE; i++)
		hlist_for_each_entry_safe(hn, tmp, &fs->l2.netdev_uc[i], hlist)
			hn->action = XSC_ACTION_DEL;

	xsc_sync_netdev_uc_addr(xdev, netdev, fs);

	xsc_apply_netdev_uc_addr(xdev, fs);

	for (i = 0; i < XSC_L2_ADDR_HASH_SIZE; i++)
		hlist_for_each_entry_safe(hn, tmp, &fs->l2.netdev_mc[i], hlist)
			hn->action = XSC_ACTION_DEL;

	xsc_sync_netdev_mc_addr(xdev, netdev, fs);

	xsc_apply_netdev_mc_addr(xdev, fs);
}

void xsc_set_rx_mode_work(struct work_struct *work)
{
	int err = 0;
	struct xsc_adapter *adapter = container_of(work, struct xsc_adapter,
					       set_rx_mode_work);
	struct net_device *dev = adapter->netdev;
	struct xsc_l2_table *l2 = &adapter->fs.l2;

	bool rx_mode_enable   = (adapter->status == XSCALE_ETH_DRIVER_OK);
	bool promisc_enabled   = rx_mode_enable && (dev->flags & IFF_PROMISC);
	bool allmulti_enabled  = rx_mode_enable && (dev->flags & IFF_ALLMULTI);

	bool enable_promisc    = !l2->promisc_enabled   &&  promisc_enabled;
	bool disable_promisc   =  l2->promisc_enabled   && !promisc_enabled;
	bool enable_allmulti   = !l2->allmulti_enabled  &&  allmulti_enabled;
	bool disable_allmulti  =  l2->allmulti_enabled  && !allmulti_enabled;
	bool change = enable_promisc | disable_promisc | enable_allmulti | disable_allmulti;

	if (change)
		err = xsc_modify_nic_vport_promisc(adapter->xdev,
						   (enable_allmulti | disable_allmulti),
						   (enable_promisc | disable_promisc),
						   allmulti_enabled, promisc_enabled);
	if (err) {
		xsc_core_err(adapter->xdev, "failed to set rx mode, err = %d\n", err);

		return;
	}

	l2->promisc_enabled   = promisc_enabled;
	l2->allmulti_enabled  = allmulti_enabled;

	xsc_handle_netdev_addr(adapter->xdev, dev, &adapter->fs);
}

