/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FLOW_POOL_H
#define XSC_FLOW_POOL_H

#include "common/xsc_core.h"

#define XSC_FLOW_POOL_BLOCK_NUM		8192
#define XSC_FLOW_POOL_BLOCK_SIZE	4096

#define XSC_FLOW_GRP_POOL_BLOCK_NUM	8
#define XSC_FLOW_GRP_POOL_BLOCK_SIZE	1024

struct xsc_flow_pool_entry {
	spinlock_t lock; /* protect xsc_flow_pool_entry */
	struct xsc_hw_flow *hw_flow;
};

struct xsc_flow_pool_block {
	unsigned long *bitmap;
	struct xsc_flow_pool_entry *entry_array;
	spinlock_t lock; /* protect block */
};

struct xsc_flow_pool {
	struct xsc_flow_pool_block *blocks[XSC_FLOW_POOL_BLOCK_NUM];
};

struct xsc_flow_grp_pool_entry {
	struct xsc_ifc_flow_group *grp;
};

struct xsc_flow_grp_pool_block {
	unsigned long *bitmap;
	struct xsc_flow_grp_pool_entry *entry_array;
	spinlock_t lock; /* protect grp pool block */
};

struct xsc_flow_grp_pool {
	struct xsc_flow_grp_pool_block *blocks[XSC_FLOW_GRP_POOL_BLOCK_NUM];
};

struct xsc_flow_pool *xsc_flow_pool_alloc(struct xsc_core_device *dev);
void xsc_flow_pool_free(struct xsc_flow_pool *pool);
struct xsc_hw_flow *xsc_flow_free_idx(struct xsc_core_device *dev,
				      struct xsc_flow_pool *pool, u32 flow_id);
int xsc_flow_alloc_idx(struct xsc_core_device *dev,
		       struct xsc_flow_pool *pool,
		       struct xsc_hw_flow *flow, u32 *idx);

struct xsc_flow_grp_pool *xsc_flow_grp_pool_alloc(struct xsc_core_device *dev);
void xsc_flow_grp_pool_free(struct xsc_flow_grp_pool *pool);
int xsc_flow_grp_alloc_idx(struct xsc_core_device *dev,
			   struct xsc_flow_grp_pool *pool,
			   struct xsc_ifc_flow_group *grp);
void xsc_flow_grp_free_idx(struct xsc_core_device *dev,
			   struct xsc_flow_grp_pool *pool, u32 grp_id);
struct xsc_ifc_flow_group *xsc_flow_grp_find_with_idx(struct xsc_core_device *dev,
						      struct xsc_flow_grp_pool *pool,
						      u32 grp_id);
#endif
