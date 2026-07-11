// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "rdma_ops.h"

static struct zxdh_rdma_hb_if *zxdh_rdma_hb_ops;

void zxdh_hwbond_register_rdma_ops(struct zxdh_rdma_hb_if *ops)
{
	if (!zxdh_rdma_hb_ops)
		zxdh_rdma_hb_ops = ops;
	LOG_INFO("enter\n");
	zxdh_update_rdma_hwbond_master();
}
EXPORT_SYMBOL(zxdh_hwbond_register_rdma_ops);

void zxdh_hwbond_unregister_rdma_ops(void)
{
	zxdh_rdma_hb_ops = NULL;
}
EXPORT_SYMBOL(zxdh_hwbond_unregister_rdma_ops);

s32 zxdh_set_rdma_hwbond_master(struct net_device *primary_netdev,
				struct net_device *linux_bond_netdev, bool hb_enable)
{
	if (!zxdh_rdma_hb_ops) {
		LOG_DEBUG("zxdh_rdma_hb_ops unregister\n");
		return -1;
	}
	if (!zxdh_rdma_hb_ops->cfg_rdma_hb_master) {
		LOG_ERR("cfg_rdma_hb_master unregister\n");
		return -1;
	}
	if (!primary_netdev || !linux_bond_netdev) {
		LOG_ERR("primary_netdev or linux_bond_netdev is null\n");
		return -1;
	}
	LOG_INFO("primary_netdev %s linux_bond_netdev %s hb_enable %d\n", primary_netdev->name,
		 linux_bond_netdev->name, hb_enable);
	return zxdh_rdma_hb_ops->cfg_rdma_hb_master(primary_netdev, linux_bond_netdev, hb_enable);
}

s32 zxdh_set_rdma_hwbond_speed(struct net_device *netdev, u32 bps)
{
	if (!zxdh_rdma_hb_ops) {
		LOG_DEBUG("zxdh_rdma_hb_ops unregister\n");
		return -1;
	}
	if (!zxdh_rdma_hb_ops->cfg_rdma_hb_speed) {
		LOG_ERR("cfg_rdma_hb_speed unregister\n");
		return -1;
	}
	if (bps == 0 || bps == SPEED_UNKNOWN) {
		LOG_ERR("speed invalid\n");
		return -1;
	}
	return zxdh_rdma_hb_ops->cfg_rdma_hb_speed(netdev, bps);
}
