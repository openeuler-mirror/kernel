/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZXDH_RDMA_OPS_H
#define ZXDH_RDMA_OPS_H

#include <linux/dinghai/driver.h>
#include <linux/netdevice.h>

struct zxdh_rdma_hb_if {
	s32 (*cfg_rdma_hb_master)(struct net_device *primary_netdev,
				  struct net_device *linux_bond_netdev, bool hb_enable);
	s32 (*cfg_rdma_hb_speed)(struct net_device *netdev, u32 bps);
};

s32 zxdh_set_rdma_hwbond_master(struct net_device *primary_netdev,
				struct net_device *linux_bond_netdev, bool hb_enable);
s32 zxdh_set_rdma_hwbond_speed(struct net_device *netdev, u32 bps);

extern void zxdh_update_rdma_hwbond_master(void);

#endif
