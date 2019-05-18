// SPDX-License-Identifier: GPL-2.0
/*
 * Context descriptor table driver for SMMUv3
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "iommu-pasid-table.h"

#define CTXDESC_CD_DWORDS		8
#define CTXDESC_CD_0_TCR_T0SZ		GENMASK_ULL(5, 0)
#define ARM64_TCR_T0SZ			GENMASK_ULL(5, 0)
#define CTXDESC_CD_0_TCR_TG0		GENMASK_ULL(7, 6)
#define ARM64_TCR_TG0			GENMASK_ULL(15, 14)
#define CTXDESC_CD_0_TCR_IRGN0		GENMASK_ULL(9, 8)
#define ARM64_TCR_IRGN0			GENMASK_ULL(9, 8)
#define CTXDESC_CD_0_TCR_ORGN0		GENMASK_ULL(11, 10)
#define ARM64_TCR_ORGN0			GENMASK_ULL(11, 10)
#define CTXDESC_CD_0_TCR_SH0		GENMASK_ULL(13, 12)
#define ARM64_TCR_SH0			GENMASK_ULL(13, 12)
#define CTXDESC_CD_0_TCR_EPD0		(1ULL << 14)
#define ARM64_TCR_EPD0			(1ULL << 7)
#define CTXDESC_CD_0_TCR_EPD1		(1ULL << 30)
#define ARM64_TCR_EPD1			(1ULL << 23)

#define CTXDESC_CD_0_ENDI		(1UL << 15)
#define CTXDESC_CD_0_V			(1UL << 31)

#define CTXDESC_CD_0_TCR_IPS		GENMASK_ULL(34, 32)
#define ARM64_TCR_IPS			GENMASK_ULL(34, 32)
#define CTXDESC_CD_0_TCR_TBI0		(1ULL << 38)
#define ARM64_TCR_TBI0			(1ULL << 37)

#define CTXDESC_CD_0_AA64		(1UL << 41)
#define CTXDESC_CD_0_S			(1UL << 44)
#define CTXDESC_CD_0_R			(1UL << 45)
#define CTXDESC_CD_0_A			(1UL << 46)
#define CTXDESC_CD_0_ASET		(1UL << 47)
#define CTXDESC_CD_0_ASID		GENMASK_ULL(63, 48)

#define CTXDESC_CD_1_TTB0_MASK		GENMASK_ULL(51, 4)

/* Convert between AArch64 (CPU) TCR format and SMMU CD format */
#define ARM_SMMU_TCR2CD(tcr, fld)	FIELD_PREP(CTXDESC_CD_0_TCR_##fld, \
					FIELD_GET(ARM64_TCR_##fld, tcr))

struct arm_smmu_cd {
	struct iommu_pasid_entry	entry;

	u64				ttbr;
	u64				tcr;
	u64				mair;
};

#define pasid_entry_to_cd(entry) \
	container_of((entry), struct arm_smmu_cd, entry)

struct arm_smmu_cd_tables {
	struct iommu_pasid_table	pasid;

	void				*ptr;
	dma_addr_t			ptr_dma;
};

#define pasid_to_cd_tables(pasid_table) \
	container_of((pasid_table), struct arm_smmu_cd_tables, pasid)

#define pasid_ops_to_tables(ops) \
	pasid_to_cd_tables(iommu_pasid_table_ops_to_table(ops))

static DEFINE_IDA(asid_ida);

static u64 arm_smmu_cpu_tcr_to_cd(u64 tcr)
{
	u64 val = 0;

	/* Repack the TCR. Just care about TTBR0 for now */
	val |= ARM_SMMU_TCR2CD(tcr, T0SZ);
	val |= ARM_SMMU_TCR2CD(tcr, TG0);
	val |= ARM_SMMU_TCR2CD(tcr, IRGN0);
	val |= ARM_SMMU_TCR2CD(tcr, ORGN0);
	val |= ARM_SMMU_TCR2CD(tcr, SH0);
	val |= ARM_SMMU_TCR2CD(tcr, EPD0);
	val |= ARM_SMMU_TCR2CD(tcr, EPD1);
	val |= ARM_SMMU_TCR2CD(tcr, IPS);
	val |= ARM_SMMU_TCR2CD(tcr, TBI0);

	return val;
}

static void arm_smmu_write_ctx_desc(struct arm_smmu_cd_tables *tbl,
				    struct arm_smmu_cd *cd)
{
	u64 val;
	__u64 *cdptr = tbl->ptr;
	struct arm_smmu_context_cfg *cfg = &tbl->pasid.cfg.arm_smmu;

	/*
	 * We don't need to issue any invalidation here, as we'll invalidate
	 * the STE when installing the new entry anyway.
	 */
	val = arm_smmu_cpu_tcr_to_cd(cd->tcr) |
#ifdef __BIG_ENDIAN
	      CTXDESC_CD_0_ENDI |
#endif
	      CTXDESC_CD_0_R | CTXDESC_CD_0_A | CTXDESC_CD_0_ASET |
	      CTXDESC_CD_0_AA64 | FIELD_PREP(CTXDESC_CD_0_ASID, cd->entry.tag) |
	      CTXDESC_CD_0_V;

	if (cfg->stall)
		val |= CTXDESC_CD_0_S;

	cdptr[0] = cpu_to_le64(val);

	val = cd->ttbr & CTXDESC_CD_1_TTB0_MASK;
	cdptr[1] = cpu_to_le64(val);

	cdptr[3] = cpu_to_le64(cd->mair);
}

static void arm_smmu_free_cd(struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd *cd = pasid_entry_to_cd(entry);

	ida_simple_remove(&asid_ida, (u16)entry->tag);
	kfree(cd);
}

static struct iommu_pasid_entry *
arm_smmu_alloc_shared_cd(struct iommu_pasid_table_ops *ops,
			 struct mm_struct *mm)
{
	return ERR_PTR(-ENODEV);
}

static struct iommu_pasid_entry *
arm_smmu_alloc_priv_cd(struct iommu_pasid_table_ops *ops,
		       enum io_pgtable_fmt fmt,
		       struct io_pgtable_cfg *cfg)
{
	int ret;
	int asid;
	struct arm_smmu_cd *cd;
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);
	struct arm_smmu_context_cfg *ctx_cfg = &tbl->pasid.cfg.arm_smmu;

	cd = kzalloc(sizeof(*cd), GFP_KERNEL);
	if (!cd)
		return ERR_PTR(-ENOMEM);

	asid = ida_simple_get(&asid_ida, 0, 1 << ctx_cfg->asid_bits,
			      GFP_KERNEL);
	if (asid < 0) {
		kfree(cd);
		return ERR_PTR(asid);
	}

	cd->entry.tag = asid;
	cd->entry.release = arm_smmu_free_cd;

	switch (fmt) {
	case ARM_64_LPAE_S1:
		cd->ttbr	= cfg->arm_lpae_s1_cfg.ttbr[0];
		cd->tcr		= cfg->arm_lpae_s1_cfg.tcr;
		cd->mair	= cfg->arm_lpae_s1_cfg.mair[0];
		break;
	default:
		pr_err("Unsupported pgtable format 0x%x\n", fmt);
		ret = -EINVAL;
		goto err_free_cd;
	}

	return &cd->entry;

err_free_cd:
	arm_smmu_free_cd(&cd->entry);

	return ERR_PTR(ret);
}

static int arm_smmu_set_cd(struct iommu_pasid_table_ops *ops, int pasid,
			   struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);
	struct arm_smmu_cd *cd = pasid_entry_to_cd(entry);

	arm_smmu_write_ctx_desc(tbl, cd);
	return 0;
}

static void arm_smmu_clear_cd(struct iommu_pasid_table_ops *ops, int pasid,
			      struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);

	arm_smmu_write_ctx_desc(tbl, NULL);
}

static struct iommu_pasid_table *
arm_smmu_alloc_cd_tables(struct iommu_pasid_table_cfg *cfg, void *cookie)
{
	struct arm_smmu_cd_tables *tbl;
	struct device *dev = cfg->iommu_dev;

	if (cfg->order) {
		/* TODO: support SSID */
		return NULL;
	}

	tbl = devm_kzalloc(dev, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return NULL;

	tbl->ptr = dmam_alloc_coherent(dev, CTXDESC_CD_DWORDS << 3,
				       &tbl->ptr_dma, GFP_KERNEL | __GFP_ZERO);
	if (!tbl->ptr) {
		dev_warn(dev, "failed to allocate context descriptor\n");
		goto err_free_tbl;
	}

	tbl->pasid.ops = (struct iommu_pasid_table_ops) {
		.alloc_priv_entry	= arm_smmu_alloc_priv_cd,
		.alloc_shared_entry	= arm_smmu_alloc_shared_cd,
		.set_entry		= arm_smmu_set_cd,
		.clear_entry		= arm_smmu_clear_cd,
	};
	cfg->base = tbl->ptr_dma;

	return &tbl->pasid;

err_free_tbl:
	devm_kfree(dev, tbl);

	return NULL;
}

static void arm_smmu_free_cd_tables(struct iommu_pasid_table *pasid_table)
{
	struct iommu_pasid_table_cfg *cfg = &pasid_table->cfg;
	struct device *dev = cfg->iommu_dev;
	struct arm_smmu_cd_tables *tbl = pasid_to_cd_tables(pasid_table);

	dmam_free_coherent(dev, CTXDESC_CD_DWORDS << 3,
			   tbl->ptr, tbl->ptr_dma);
	devm_kfree(dev, tbl);
}

struct iommu_pasid_init_fns arm_smmu_v3_pasid_init_fns = {
	.alloc	= arm_smmu_alloc_cd_tables,
	.free	= arm_smmu_free_cd_tables,
};
