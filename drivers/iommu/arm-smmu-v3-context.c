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

struct arm_smmu_cd_table {
	__le64				*ptr;
	dma_addr_t			ptr_dma;
};

struct arm_smmu_cd_tables {
	struct iommu_pasid_table	pasid;
	struct arm_smmu_cd_table	table;
};

#define pasid_to_cd_tables(pasid_table) \
	container_of((pasid_table), struct arm_smmu_cd_tables, pasid)

#define pasid_ops_to_tables(ops) \
	pasid_to_cd_tables(iommu_pasid_table_ops_to_table(ops))

static DEFINE_IDA(asid_ida);

static int arm_smmu_alloc_cd_leaf_table(struct device *dev,
					struct arm_smmu_cd_table *desc,
					size_t num_entries)
{
	size_t size = num_entries * (CTXDESC_CD_DWORDS << 3);

	desc->ptr = dmam_alloc_coherent(dev, size, &desc->ptr_dma,
					GFP_ATOMIC | __GFP_ZERO);
	if (!desc->ptr) {
		dev_warn(dev, "failed to allocate context descriptor table\n");
		return -ENOMEM;
	}

	return 0;
}

static void arm_smmu_free_cd_leaf_table(struct device *dev,
					struct arm_smmu_cd_table *desc,
					size_t num_entries)
{
	size_t size = num_entries * (CTXDESC_CD_DWORDS << 3);

	dmam_free_coherent(dev, size, desc->ptr, desc->ptr_dma);
}

static __le64 *arm_smmu_get_cd_ptr(struct arm_smmu_cd_tables *tbl, u32 ssid)
{
	return tbl->table.ptr + ssid * CTXDESC_CD_DWORDS;
}

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

static int arm_smmu_write_ctx_desc(struct arm_smmu_cd_tables *tbl, int ssid,
				   struct arm_smmu_cd *cd)
{
	u64 val;
	bool cd_live;
	__le64 *cdptr = arm_smmu_get_cd_ptr(tbl, ssid);
	struct arm_smmu_context_cfg *cfg = &tbl->pasid.cfg.arm_smmu;

	/*
	 * This function handles the following cases:
	 *
	 * (1) Install primary CD, for normal DMA traffic (SSID = 0).
	 * (2) Install a secondary CD, for SID+SSID traffic, followed by an
	 *     invalidation.
	 * (3) Update ASID of primary CD. This is allowed by atomically writing
	 *     the first 64 bits of the CD, followed by invalidation of the old
	 *     entry and mappings.
	 * (4) Remove a secondary CD and invalidate it.
	 */

	if (!cdptr)
		return -ENOMEM;

	val = le64_to_cpu(cdptr[0]);
	cd_live = !!(val & CTXDESC_CD_0_V);

	if (!cd) { /* (4) */
		cdptr[0] = 0;
	} else if (cd_live) { /* (3) */
		val &= ~CTXDESC_CD_0_ASID;
		val |= FIELD_PREP(CTXDESC_CD_0_ASID, cd->entry.tag);

		cdptr[0] = cpu_to_le64(val);
		/*
		 * Until CD+TLB invalidation, both ASIDs may be used for tagging
		 * this substream's traffic
		 */
	} else { /* (1) and (2) */
		cdptr[1] = cpu_to_le64(cd->ttbr & CTXDESC_CD_1_TTB0_MASK);
		cdptr[2] = 0;
		cdptr[3] = cpu_to_le64(cd->mair);

		/*
		 * STE is live, and the SMMU might fetch this CD at any
		 * time. Ensure it observes the rest of the CD before we
		 * enable it.
		 */
		iommu_pasid_flush(&tbl->pasid, ssid, true);


		val = arm_smmu_cpu_tcr_to_cd(cd->tcr) |
#ifdef __BIG_ENDIAN
		      CTXDESC_CD_0_ENDI |
#endif
		      CTXDESC_CD_0_R | CTXDESC_CD_0_A | CTXDESC_CD_0_ASET |
		      CTXDESC_CD_0_AA64 |
		      FIELD_PREP(CTXDESC_CD_0_ASID, cd->entry.tag) |
		      CTXDESC_CD_0_V;

		if (cfg->stall)
			val |= CTXDESC_CD_0_S;

		cdptr[0] = cpu_to_le64(val);
	}

	iommu_pasid_flush(&tbl->pasid, ssid, true);

	return 0;
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

	if (WARN_ON(pasid > (1 << tbl->pasid.cfg.order)))
		return -EINVAL;

	return arm_smmu_write_ctx_desc(tbl, pasid, cd);
}

static void arm_smmu_clear_cd(struct iommu_pasid_table_ops *ops, int pasid,
			      struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);

	if (WARN_ON(pasid > (1 << tbl->pasid.cfg.order)))
		return;

	arm_smmu_write_ctx_desc(tbl, pasid, NULL);
}

static struct iommu_pasid_table *
arm_smmu_alloc_cd_tables(struct iommu_pasid_table_cfg *cfg, void *cookie)
{
	int ret;
	struct arm_smmu_cd_tables *tbl;
	struct device *dev = cfg->iommu_dev;

	tbl = devm_kzalloc(dev, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return NULL;

	ret = arm_smmu_alloc_cd_leaf_table(dev, &tbl->table, 1 << cfg->order);
	if (ret)
		goto err_free_tbl;

	tbl->pasid.ops = (struct iommu_pasid_table_ops) {
		.alloc_priv_entry	= arm_smmu_alloc_priv_cd,
		.alloc_shared_entry	= arm_smmu_alloc_shared_cd,
		.set_entry		= arm_smmu_set_cd,
		.clear_entry		= arm_smmu_clear_cd,
	};
	cfg->base			= tbl->table.ptr_dma;
	cfg->arm_smmu.s1fmt		= ARM_SMMU_S1FMT_LINEAR;

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

	arm_smmu_free_cd_leaf_table(dev, &tbl->table, 1 << cfg->order);
	devm_kfree(dev, tbl);
}

struct iommu_pasid_init_fns arm_smmu_v3_pasid_init_fns = {
	.alloc	= arm_smmu_alloc_cd_tables,
	.free	= arm_smmu_free_cd_tables,
};
