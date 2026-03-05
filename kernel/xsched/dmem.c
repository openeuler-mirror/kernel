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
