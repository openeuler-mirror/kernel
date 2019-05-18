// SPDX-License-Identifier: GPL-2.0
/*
 * PASID table management for the IOMMU
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/kernel.h>

#include "iommu-pasid-table.h"

static const struct iommu_pasid_init_fns *
pasid_table_init_fns[PASID_TABLE_NUM_FMTS] = {
	[PASID_TABLE_ARM_SMMU_V3] = &arm_smmu_v3_pasid_init_fns,
};

struct iommu_pasid_table_ops *
iommu_alloc_pasid_ops(enum iommu_pasid_table_fmt fmt,
		      struct iommu_pasid_table_cfg *cfg, void *cookie)
{
	struct iommu_pasid_table *table;
	const struct iommu_pasid_init_fns *fns;

	if (fmt >= PASID_TABLE_NUM_FMTS)
		return NULL;

	fns = pasid_table_init_fns[fmt];
	if (!fns)
		return NULL;

	table = fns->alloc(cfg, cookie);
	if (!table)
		return NULL;

	table->fmt = fmt;
	table->cookie = cookie;
	table->cfg = *cfg;

	return &table->ops;
}

void iommu_free_pasid_ops(struct iommu_pasid_table_ops *ops)
{
	struct iommu_pasid_table *table;

	if (!ops)
		return;

	table = container_of(ops, struct iommu_pasid_table, ops);
	iommu_pasid_flush_all(table);
	pasid_table_init_fns[table->fmt]->free(table);
}
