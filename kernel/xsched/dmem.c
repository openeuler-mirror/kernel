// SPDX-License-Identifier: GPL-2.0+
/*
 * Core kernel scheduler code for XPU device
 *
 * Copyright (C) 2026 Huawei Technologies Co., Ltd
 *
 * Author: Liu Kai <liukai284@huawei.com>
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
#include <linux/kref.h>
#include <linux/xsched.h>
#include <linux/types.h>
#include <linux/cgroup_dmem.h>

static LIST_HEAD(xsched_dmem_regions);
static int xsched_dmem_region_num;
static DEFINE_SPINLOCK(xsched_dmem_lock);

struct xsched_dmem_region {
	int dev_id;
	struct dmem_cgroup_region *cgroup_region;
	struct list_head node;
	struct kref kref;
};

struct xsched_dmem_pool {
	uint64_t addr;
	uint64_t size;
	struct dmem_cgroup_pool_state *pool;
	struct list_head pool_node;
};

static void xsched_dmem_region_release(struct kref *kref)
{
	struct xsched_dmem_region *region = container_of(kref,
		struct xsched_dmem_region, kref);

	dmem_cgroup_unregister_region(region->cgroup_region);
	kfree(region);
}

static void xsched_dmem_region_get(struct xsched_dmem_region *region)
{
	kref_get(&region->kref);
}

static void xsched_dmem_region_put(struct xsched_dmem_region *region)
{
	kref_put(&region->kref, xsched_dmem_region_release);
}

struct xsched_dmem_region *find_dmem_region_by_devid(int dev_id)
{
	struct xsched_dmem_region *region, *found = NULL;

	lockdep_assert_held(&xsched_dmem_lock);

	list_for_each_entry(region, &xsched_dmem_regions, node) {
		if (region->dev_id == dev_id) {
			found = region;
			break;
		}
	}

	return found;
}

static struct xsched_dmem_region *get_dmem_region_by_devid(int dev_id)
{
	struct xsched_dmem_region *region;

	spin_lock(&xsched_dmem_lock);
	region = find_dmem_region_by_devid(dev_id);
	if (region)
		xsched_dmem_region_get(region);
	spin_unlock(&xsched_dmem_lock);

	return region;
}

bool xsched_dmem_used(void)
{
	return READ_ONCE(xsched_dmem_region_num) > 0;
}

int xsched_dmem_register_region(uint64_t size, int dev_id)
{
	struct xsched_dmem_region *region, *found;
	struct dmem_cgroup_region *cg_region;
	int ret;

	if (size == 0 || dev_id < 0)
		return -EINVAL;

	region = kmalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	cg_region = dmem_cgroup_register_region(size, "HBM%d", dev_id);
	if (IS_ERR(cg_region)) {
		kfree(region);
		return PTR_ERR(cg_region);
	}

	spin_lock(&xsched_dmem_lock);
	if (xsched_dmem_region_num >= XSCHED_NR_CUS) {
		ret = -ENOSPC;
		goto unlock_out;
	}

	found = find_dmem_region_by_devid(dev_id);
	if (found) {
		ret = -EEXIST;
		goto unlock_out;
	}

	region->cgroup_region = cg_region;
	region->dev_id = dev_id;
	kref_init(&region->kref);
	xsched_dmem_region_num++;
	list_add_tail(&region->node, &xsched_dmem_regions);
	spin_unlock(&xsched_dmem_lock);

	XSCHED_INFO("register HBM%d %llu region(s) in dmem\n", dev_id, size);

	return 0;

unlock_out:
	spin_unlock(&xsched_dmem_lock);
	dmem_cgroup_unregister_region(cg_region);
	kfree(region);
	return ret;
}
EXPORT_SYMBOL(xsched_dmem_register_region);

void xsched_dmem_unregister_region(int dev_id)
{
	struct xsched_dmem_region *found;

	spin_lock(&xsched_dmem_lock);
	found = find_dmem_region_by_devid(dev_id);
	if (!found) {
		spin_unlock(&xsched_dmem_lock);
		return;
	}

	list_del(&found->node);
	xsched_dmem_region_num--;
	spin_unlock(&xsched_dmem_lock);

	xsched_dmem_region_put(found);

	XSCHED_INFO("unregister HBM%d region(s) in dmem\n", dev_id);
}
EXPORT_SYMBOL(xsched_dmem_unregister_region);

int xsched_dmem_alloc(struct xsched_context *ctx, struct vstream_args *args)
{
	struct dmem_cgroup_pool_state *ret_pool, *ret_limit_pool;
	struct xsched_dmem_pool *new_pool;
	struct xsched_dmem_region *found;
	int ret;

	if (!xsched_dmem_used())
		return -EPERM;

	found = get_dmem_region_by_devid(args->dev_id);
	if (!found) {
		XSCHED_ERR("Try to charge memory when region is not registered (region HBM%u)\n",
			args->dev_id);
		return -ENOENT;
	}

	ret = dmem_cgroup_try_charge(found->cgroup_region, args->vm_args.size,
			&ret_pool, &ret_limit_pool);
	if (ret != 0) {
		XSCHED_ERR("Fail to charge a new allocation to a HBM region\n");
		dmem_cgroup_pool_state_put(ret_limit_pool);
		xsched_dmem_region_put(found);
		return ret;
	}

	new_pool = kzalloc(sizeof(*new_pool), GFP_KERNEL);
	if (!new_pool) {
		XSCHED_ERR("Fail to alloc xsched dmem alloc @ %s\n", __func__);
		dmem_cgroup_uncharge(ret_pool, args->vm_args.size);
		xsched_dmem_region_put(found);
		return -ENOMEM;
	}

	new_pool->pool = ret_pool;
	new_pool->addr = args->vm_args.addr;
	new_pool->size = args->vm_args.size;

	spin_lock(&ctx->ctx_lock);
	list_add_tail(&new_pool->pool_node, &ctx->pool_list);
	spin_unlock(&ctx->ctx_lock);

	xsched_dmem_region_put(found);

	XSCHED_DEBUG("charged %llu bytes, new_alloc = %p with addr %llu",
		new_pool->size, new_pool, new_pool->addr);

	return 0;
}
