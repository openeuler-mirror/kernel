// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 * Description:
 * This file implements the parsing of the ub reserved memory node in the UBRT table.
 */

#include <linux/errno.h>
#include <linux/iommu.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <ub/ubfi/ubfi.h>

#include "ubrt.h"
#include "ub_fi.h"
#include "ubc.h"

#define UBRT_RMR_DIRECT_REMAP BIT(0)

struct ubrt_resv_mem_range {
	u8 flags;
	u8 reserved[7];
	u64 memory_base;
	u64 memory_size;
};

struct ubrt_resv_mem_node {
	struct ub_table_header header;
	u16 count;
	u8 reserved[6];
	u8 ranges[] __counted_by(count);
};

static void parse_ummu_reserved_memory(void *info_node, struct list_head *list)
{
	struct ubrt_resv_mem_node *sub_table = info_node;
	struct ubrt_resv_mem_range *mem_range;
	struct iommu_resv_region *region;
	int prot = IOMMU_READ | IOMMU_WRITE;
	u32 i;

	if (!sub_table->count) {
		pr_warn("resv mem table has no node.\n");
		return;
	}

	mem_range = (struct ubrt_resv_mem_range *)sub_table->ranges;
	for (i = 0; i < sub_table->count; i++) {
		if (!(mem_range[i].flags & UBRT_RMR_DIRECT_REMAP))
			continue;

		prot |= IOMMU_MMIO;
		region = iommu_alloc_resv_region(mem_range[i].memory_base, mem_range[i].memory_size,
						 prot, IOMMU_RESV_DIRECT, GFP_KERNEL);
		if (!region) {
			pr_err("Failed to allocate resv region for ummu.\n");
			return;
		}

		list_add_tail(&region->list, list);
	}
}

static void reserved_memory_parse(u64 pointer, struct list_head *list)
{
	void *info_node = ub_table_get(pointer);

	if (!info_node)
		return;

	parse_ummu_reserved_memory(info_node, list);
	ub_table_put(info_node);
}

void ubrt_iommu_get_resv_regions(struct device *dev, struct list_head *list)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct ubrt_sub_table *sub_table;
	u32 i;

	if (!fwspec || !acpi_table)
		return;

	for (i = 0; i < acpi_table->count; i++) {
		sub_table = &acpi_table->sub_table[i];
		if (sub_table->type == UB_RESERVED_MEMORY_TABLE)
			reserved_memory_parse(sub_table->pointer, list);
	}
}
EXPORT_SYMBOL_GPL(ubrt_iommu_get_resv_regions);
