// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_eth.h"
#include "common/vport.h"
#include "common/xsc_fs.h"

enum xsc_vlan_rule_type {
	XSC_VLAN_RULE_TYPE_UNTAGGED,
	XSC_VLAN_RULE_TYPE_ANY_CTAG_VID,
	XSC_VLAN_RULE_TYPE_ANY_STAG_VID,
	XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID,
	XSC_VLAN_RULE_TYPE_MATCH_STAG_VID,
};

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

	set_bit(vid, adapter->vlan_params.active_cvlans);

	err = xsc_add_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID, vid);
	if (err)
		clear_bit(vid, adapter->vlan_params.active_cvlans);

	return err;
}

static int xsc_vlan_rx_add_svid(struct xsc_adapter *adapter, u16 vid)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	set_bit(vid, adapter->vlan_params.active_svlans);

	err = xsc_add_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_STAG_VID, vid);
	if (err) {
		clear_bit(vid, adapter->vlan_params.active_svlans);
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
		clear_bit(vid, adapter->vlan_params.active_cvlans);
		xsc_del_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID, vid);
	} else if (be16_to_cpu(proto) == ETH_P_8021AD) {
		clear_bit(vid, adapter->vlan_params.active_svlans);
		xsc_del_vlan_rule(adapter, XSC_VLAN_RULE_TYPE_MATCH_STAG_VID, vid);
		netdev_update_features(dev);
	}

	return 0;
}
