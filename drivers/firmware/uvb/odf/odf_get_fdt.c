// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ODF get fdt info
 * Author: mengkanglai
 * Create: 2025-04-18
 */
#include <linux/of.h>
#include <linux/printk.h>

int odf_get_fdt_ubiostbl(u64 *phys_addr, char *tbl)
{
	struct device_node *node;
	u64 val;
	int ret;

	node = of_find_node_by_path("/chosen");
	if (!node) {
		pr_err("failed to get device tree chosen node\n");
		return -EINVAL;
	}

	ret = of_property_read_u64(node, tbl, &val);
	if (ret) {
		pr_err("failed to get property %s, ret=%d\n", tbl, ret);
		of_node_put(node);
		return -EINVAL;
	}
	of_node_put(node);

	*phys_addr = val;
	return 0;
}
EXPORT_SYMBOL(odf_get_fdt_ubiostbl);
