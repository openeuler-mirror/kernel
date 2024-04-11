/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FS_H
#define XSC_FS_H

#include <linux/types.h>
#include <linux/netdevice.h>

enum xsc_list_type {
	XSC_NVPRT_LIST_TYPE_UC   = 0x0,
	XSC_NVPRT_LIST_TYPE_MC   = 0x1,
	XSC_NVPRT_LIST_TYPE_VLAN = 0x2,
};

int xsc_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			u16 vid);
int xsc_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			 u16 vid);

#endif
