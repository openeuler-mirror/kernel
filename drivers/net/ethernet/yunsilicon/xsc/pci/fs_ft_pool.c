// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "fs_ft_pool.h"
#include "common/xsc_eswitch.h"

/* Firmware currently has 4 pool of 4 sizes that it supports (FT_POOLS),
 * and a virtual memory region of 16M (XSC_FT_SIZE), this region is duplicated
 * for each flow table pool. We can allocate up to 16M of each pool,
 * and we keep track of how much we used via xsc_ft_pool_get_avail_sz.
 * Firmware doesn't report any of this for now.
 * ESW_POOL is expected to be sorted from large to small and match firmware
 * pools.
 */
#define FT_SIZE (32 * 1024)
static const unsigned int FT_POOLS[] = { 32 * 1024,
					 4 * 1024,
					 1 * 1024,
					 128,
					 1 /* size for termination tables */ };
struct xsc_ft_pool {
	int ft_left[ARRAY_SIZE(FT_POOLS)];
};

int xsc_ft_pool_init(struct xsc_core_device *dev)
{
	struct xsc_ft_pool *ft_pool;
	int i;

	ft_pool = kzalloc(sizeof(*ft_pool), GFP_KERNEL);
	if (!ft_pool)
		return -ENOMEM;

	for (i = ARRAY_SIZE(FT_POOLS) - 1; i >= 0; i--)
		ft_pool->ft_left[i] = FT_SIZE / FT_POOLS[i];

	dev->priv.ft_pool = ft_pool;
	return 0;
}

void xsc_ft_pool_destroy(struct xsc_core_device *dev)
{
	kfree(dev->priv.ft_pool);
}

int xsc_ft_pool_get_avail_sz(struct xsc_core_device *dev,
			     enum fs_flow_table_type table_type,
			     int desired_size)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 max_ft_size = 1 << esw->esw_caps.log_max_ft_size;
	int i, found_i = -1;

	for (i = ARRAY_SIZE(FT_POOLS) - 1; i >= 0; i--) {
		if (dev->priv.ft_pool->ft_left[i] && FT_POOLS[i] >= desired_size &&
		    FT_POOLS[i] <= max_ft_size) {
			found_i = i;
			if (desired_size != POOL_NEXT_SIZE)
				break;
		}
	}

	if (found_i != -1) {
		--dev->priv.ft_pool->ft_left[found_i];
		return FT_POOLS[found_i];
	}

	return 0;
}

void xsc_ft_pool_put_sz(struct xsc_core_device *dev, int sz)
{
	int i;

	if (!sz)
		return;

	for (i = ARRAY_SIZE(FT_POOLS) - 1; i >= 0; i--) {
		if (sz == FT_POOLS[i]) {
			++dev->priv.ft_pool->ft_left[i];
			return;
		}
	}

	WARN_ONCE(1, "Couldn't find size %d in flow table size pool", sz);
}
