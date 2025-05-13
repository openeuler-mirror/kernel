/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FS_H
#define XSC_FS_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>


enum xsc_list_type {
	XSC_NVPRT_LIST_TYPE_UC   = 0x0,
	XSC_NVPRT_LIST_TYPE_MC   = 0x1,
	XSC_NVPRT_LIST_TYPE_VLAN = 0x2,
	XSC_NVPRT_LIST_TYPE_VLAN_OFFLOAD = 0x03,
};

enum xsc_vlan_rule_type {
	XSC_VLAN_RULE_TYPE_UNTAGGED,
	XSC_VLAN_RULE_TYPE_ANY_CTAG_VID,
	XSC_VLAN_RULE_TYPE_ANY_STAG_VID,
	XSC_VLAN_RULE_TYPE_MATCH_CTAG_VID,
	XSC_VLAN_RULE_TYPE_MATCH_STAG_VID,
};

enum {
	XSC_ACTION_NONE = 0,
	XSC_ACTION_ADD  = 1,
	XSC_ACTION_DEL  = 2,
};

struct xsc_l2_hash_node {
	struct hlist_node	hlist;
	u8			action;
	u8			mac_addr[ETH_ALEN];
	u16			pct_prio;
};

struct xsc_vlan_table {
	DECLARE_BITMAP(active_cvlans, VLAN_N_VID);
	DECLARE_BITMAP(active_svlans, VLAN_N_VID);
	DECLARE_BITMAP(active_outer_cvlans, VLAN_N_VID);
	DECLARE_BITMAP(active_outer_svlans, VLAN_N_VID);
	u8	cvlan_filter_disabled;
};

struct xsc_l2_table {
	struct hlist_head          netdev_uc[XSC_L2_ADDR_HASH_SIZE];
	struct hlist_head          netdev_mc[XSC_L2_ADDR_HASH_SIZE];
	u8	broadcast_enabled;
	u8	allmulti_enabled;
	u8	promisc_enabled;
};

struct xsc_flow_steering {
	struct xsc_vlan_table         vlan;
	struct xsc_l2_table           l2;
};

int xsc_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			u16 vid);
int xsc_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			 u16 vid);
void xsc_set_rx_mode_work(struct work_struct *work);
#endif
