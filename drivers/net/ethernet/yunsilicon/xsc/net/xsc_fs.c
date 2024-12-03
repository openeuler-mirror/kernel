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
}

