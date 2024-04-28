// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"


struct rdma_comp_priv *get_rdma_comp_priv(void *hwdev)
{
	struct rdma_comp_priv *comp_private = NULL;

	comp_private = (struct rdma_comp_priv *)hinic3_get_service_adapter(hwdev, SERVICE_T_ROCE);
	return comp_private;
}

void rdma_cleanup_pd_table(struct rdma_comp_priv *comp_priv)
{
	rdma_bitmap_cleanup(&comp_priv->pd_bitmap);
}
