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
