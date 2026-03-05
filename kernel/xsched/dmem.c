// SPDX-License-Identifier: GPL-2.0+
/*
 * Core kernel scheduler code for XPU device
 *
 * Copyright (C) 2025 Huawei Technologies Co., Ltd
 *
 * Author: Alexander Pavlenko <pavlenko.alexander@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/err.h>
#include <linux/list.h>
#include <linux/xsched.h>
#include <linux/types.h>
#include <linux/cgroup_dmem.h>

static struct dmem_cgroup_region *hbm_regions[XSCHED_NR_CUS];

struct xsched_dmem_pool {
	uint64_t id;
	struct dmem_cgroup_pool_state *pool;
	struct list_head pool_node;
};

int xsched_dmem_init(void)
{
	// TODO: get max memory capacity from driver info or CONFIG
	const size_t hbm_size_gb = 32;
	const size_t hardcoded_hbm_size = hbm_size_gb * SZ_1G;
	int dev_id, retval;

	// register HBM region for each device
	for (dev_id = 0; dev_id < XSCHED_NR_CUS; dev_id++) {
		hbm_regions[dev_id] = dmem_cgroup_register_region(
			hardcoded_hbm_size, "HBM%d", dev_id);

		if (IS_ERR_OR_NULL(hbm_regions[dev_id])) {
			XSCHED_ERR("Fail to register HBM region for xcu %d\n", dev_id);
			retval = PTR_ERR(hbm_regions[dev_id]);
			goto err_out;
		}
		XSCHED_INFO("register HBM%d %zuGB region(s) in dmem\n", dev_id, hbm_size_gb);
	}

	return 0;

err_out:
	for (dev_id--; dev_id >= 0; dev_id--) {
		dmem_cgroup_unregister_region(hbm_regions[dev_id]);
		hbm_regions[dev_id] = NULL;
	}
	return retval;
}

int xsched_dmem_alloc(struct xsched_context *ctx, struct vstream_args *args)
{
	struct dmem_cgroup_pool_state *ret_pool, *ret_limit_pool;
	struct xsched_dmem_pool *new_pool;
	int ret;
	struct dmem_cgroup_region *hbm_region;

	hbm_region = hbm_regions[args->dev_id];
	if (!hbm_region) {
		XSCHED_ERR("Try to charge memory when region is not registered (region HBM%u)\n",
			args->dev_id);
		goto error_out;
	}

	ret = dmem_cgroup_try_charge(hbm_region, args->vh_args.size, &ret_pool, &ret_limit_pool);
	if (ret != 0) {
		XSCHED_ERR("Fail to charge a new allocation to a HBM region\n");
		goto error_out;
	}

	new_pool = kzalloc(sizeof(*new_pool), GFP_KERNEL);
	if (!new_pool) {
		XSCHED_ERR("Fail to alloc xsched dmem alloc @ %s\n", __func__);
		ret = -ENOMEM;
		goto error_charge;
	}

	new_pool->pool = ret_pool;

	/* protect list using ctx_lock */
	spin_lock(&ctx->ctx_lock);
	new_pool->id = ctx->next_pool_id++;
	list_add_tail(&new_pool->pool_node, &ctx->pool_list);
	spin_unlock(&ctx->ctx_lock);

	args->vh_args.pool_id = new_pool->id;
	XSCHED_DEBUG("charged %llu bytes, new_alloc = %p with id %llu",
		args->vh_args.size, new_pool, new_pool->id);

	return 0;

error_charge:
	dmem_cgroup_uncharge(ret_pool, args->vh_args.size);
error_out:
	args->vh_args.pool_id = ULLONG_MAX;
	return ret;
}

int xsched_dmem_free(struct xsched_context *ctx, struct vstream_args *args)
{
	struct xsched_dmem_pool *pool, *target = NULL;

	spin_lock(&ctx->ctx_lock);
	list_for_each_entry(pool, &ctx->pool_list, pool_node) {
		if (pool->id == args->vh_args.pool_id) {
			list_del(&pool->pool_node);
			target = pool;
			break;
		}
	}
	spin_unlock(&ctx->ctx_lock);

	if (!target) {
		XSCHED_ERR("pool with id %llu is not found\n", args->vh_args.pool_id);
		return -EINVAL;
	}

	XSCHED_DEBUG("uncharged %llu bytes for pool = %p with id %llu\n",
		args->vh_args.size, target, target->id);
	dmem_cgroup_uncharge(target->pool, args->vh_args.size);
	kfree(target);

	return 0;
}
