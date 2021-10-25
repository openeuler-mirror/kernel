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
#include <linux/mmu_context.h>
#include <linux/slab.h>

#include "io-pgtable-arm.h"
#include "iommu-pasid-table.h"

/*
 * Linear: when less than 1024 SSIDs are supported
 * 2lvl: at most 1024 L1 entrie,
 *	 1024 lazy entries per table.
 */
#define CTXDESC_SPLIT			10
#define CTXDESC_NUM_L2_ENTRIES		(1 << CTXDESC_SPLIT)

#define CTXDESC_L1_DESC_DWORD		1
#define CTXDESC_L1_DESC_VALID		1
#define CTXDESC_L1_DESC_L2PTR_MASK	GENMASK_ULL(51, 12)

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

#define CTXDESC_CD_0_TCR_HA		(1UL << 43)
#define ARM64_TCR_HA			(1ULL << 39)
#define CTXDESC_CD_0_TCR_HD		(1UL << 42)
#define ARM64_TCR_HD			(1ULL << 40)

#define CTXDESC_CD_0_AA64		(1UL << 41)
#define CTXDESC_CD_0_S			(1UL << 44)
#define CTXDESC_CD_0_R			(1UL << 45)
#define CTXDESC_CD_0_A			(1UL << 46)
#define CTXDESC_CD_0_ASET		(1UL << 47)
#define CTXDESC_CD_0_ASID		GENMASK_ULL(63, 48)

#define CTXDESC_CD_1_TTB0_MASK		GENMASK_ULL(51, 4)

#define CTXDESC_CD_5_PARTID_MASK	GENMASK_ULL(47, 32)
#define CTXDESC_CD_5_PMG_MASK		GENMASK_ULL(55, 48)

/* Convert between AArch64 (CPU) TCR format and SMMU CD format */
#define ARM_SMMU_TCR2CD(tcr, fld)	FIELD_PREP(CTXDESC_CD_0_TCR_##fld, \
					FIELD_GET(ARM64_TCR_##fld, tcr))

#define ARM_SMMU_NO_PASID		(-1)

struct arm_smmu_cd {
	struct iommu_pasid_entry	entry;

	u64				ttbr;
	u64				tcr;
	u64				mair;

	int				pasid;

	/* 'refs' tracks alloc/free */
	refcount_t			refs;
	/* 'users' tracks attach/detach, and is only used for sanity checking */
	unsigned int			users;
	struct mm_struct		*mm;
	struct arm_smmu_cd_tables	*tbl;
};

#define pasid_entry_to_cd(entry) \
	container_of((entry), struct arm_smmu_cd, entry)

struct arm_smmu_cd_table {
	__le64				*ptr;
	dma_addr_t			ptr_dma;
};

struct arm_smmu_cd_tables {
	struct iommu_pasid_table	pasid;
	bool				linear;
	union {
		struct arm_smmu_cd_table table;
		struct {
			__le64		*ptr;
			dma_addr_t	ptr_dma;
			size_t		num_entries;

			struct arm_smmu_cd_table *tables;
		} l1;
	};
};

#define pasid_to_cd_tables(pasid_table) \
	container_of((pasid_table), struct arm_smmu_cd_tables, pasid)

#define pasid_ops_to_tables(ops) \
	pasid_to_cd_tables(iommu_pasid_table_ops_to_table(ops))

static DEFINE_SPINLOCK(contexts_lock);
static DEFINE_SPINLOCK(asid_lock);
static DEFINE_IDR(asid_idr);

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

static void arm_smmu_write_cd_l1_desc(__le64 *dst,
				      struct arm_smmu_cd_table *desc)
{
	u64 val = (desc->ptr_dma & CTXDESC_L1_DESC_L2PTR_MASK) |
		CTXDESC_L1_DESC_VALID;

	*dst = cpu_to_le64(val);
}

static __le64 *arm_smmu_get_cd_ptr(struct arm_smmu_cd_tables *tbl, u32 ssid)
{
	unsigned long idx;
	struct arm_smmu_cd_table *l1_desc;
	struct iommu_pasid_table_cfg *cfg = &tbl->pasid.cfg;

	if (tbl->linear)
		return tbl->table.ptr + ssid * CTXDESC_CD_DWORDS;

	idx = ssid >> CTXDESC_SPLIT;
	if (idx >= tbl->l1.num_entries)
		return NULL;

	l1_desc = &tbl->l1.tables[idx];
	if (!l1_desc->ptr) {
		__le64 *l1ptr = tbl->l1.ptr + idx * CTXDESC_L1_DESC_DWORD;

		if (arm_smmu_alloc_cd_leaf_table(cfg->iommu_dev, l1_desc,
						 CTXDESC_NUM_L2_ENTRIES))
			return NULL;

		arm_smmu_write_cd_l1_desc(l1ptr, l1_desc);
		/* An invalid L1 entry is allowed to be cached */
		iommu_pasid_flush(&tbl->pasid, idx << CTXDESC_SPLIT, false);
	}

	idx = ssid & (CTXDESC_NUM_L2_ENTRIES - 1);

	return l1_desc->ptr + idx * CTXDESC_CD_DWORDS;
}

static u64 arm_smmu_cpu_tcr_to_cd(struct arm_smmu_context_cfg *cfg, u64 tcr)
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

	if (cfg->hw_access)
		val |= ARM_SMMU_TCR2CD(tcr, HA);

	if (cfg->hw_dirty)
		val |= ARM_SMMU_TCR2CD(tcr, HD);

	return val;
}

static int __arm_smmu_write_ctx_desc(struct arm_smmu_cd_tables *tbl, int ssid,
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


		val = arm_smmu_cpu_tcr_to_cd(cfg, cd->tcr) |
#ifdef __BIG_ENDIAN
		      CTXDESC_CD_0_ENDI |
#endif
		      CTXDESC_CD_0_R | CTXDESC_CD_0_A |
		      (cd->mm ? 0 : CTXDESC_CD_0_ASET) |
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

static int arm_smmu_write_ctx_desc(struct arm_smmu_cd_tables *tbl, int ssid,
				   struct arm_smmu_cd *cd)
{
	int ret;

	spin_lock(&contexts_lock);
	ret = __arm_smmu_write_ctx_desc(tbl, ssid, cd);
	spin_unlock(&contexts_lock);

	return ret;
}

static bool arm_smmu_free_asid(struct arm_smmu_cd *cd)
{
	bool free;
	struct arm_smmu_cd *old_cd;

	spin_lock(&asid_lock);
	free = refcount_dec_and_test(&cd->refs);
	if (free) {
		old_cd = idr_remove(&asid_idr, (u16)cd->entry.tag);
		WARN_ON(old_cd != cd);
	}
	spin_unlock(&asid_lock);

	return free;
}

static void arm_smmu_free_cd(struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd *cd = pasid_entry_to_cd(entry);

	if (!arm_smmu_free_asid(cd))
		return;

	if (cd->mm) {
		/* Unpin ASID */
		mm_context_put(cd->mm);
	}

	kfree(cd);
}

static struct arm_smmu_cd *arm_smmu_alloc_cd(struct arm_smmu_cd_tables *tbl)
{
	struct arm_smmu_cd *cd;

	cd = kzalloc(sizeof(*cd), GFP_KERNEL);
	if (!cd)
		return NULL;

	cd->pasid		= ARM_SMMU_NO_PASID;
	cd->tbl			= tbl;
	cd->entry.release	= arm_smmu_free_cd;
	refcount_set(&cd->refs, 1);

	return cd;
}

/*
 * Try to reserve this ASID in the SMMU. If it is in use, try to steal it from
 * the private entry. Careful here, we may be modifying the context tables of
 * another SMMU!
 */
static struct arm_smmu_cd *arm_smmu_share_asid(u16 asid)
{
	int ret;
	struct arm_smmu_cd *cd;
	struct arm_smmu_cd_tables *tbl;
	struct arm_smmu_context_cfg *cfg;
	struct iommu_pasid_entry old_entry;

	cd = idr_find(&asid_idr, asid);
	if (!cd)
		return NULL;

	if (cd->mm) {
		/*
		 * It's pretty common to find a stale CD when doing unbind-bind,
		 * given that the release happens after a RCU grace period.
		 * Simply reuse it, but check that it isn't active, because it's
		 * going to be assigned a different PASID.
		 */
		if (WARN_ON(cd->users))
			return ERR_PTR(-EINVAL);

		refcount_inc(&cd->refs);
		return cd;
	}

	tbl = cd->tbl;
	cfg = &tbl->pasid.cfg.arm_smmu;

	ret = idr_alloc_cyclic(&asid_idr, cd, 0, 1 << cfg->asid_bits,
			       GFP_ATOMIC);
	if (ret < 0)
		return ERR_PTR(-ENOSPC);

	/* Save the previous ASID */
	old_entry = cd->entry;

	/*
	 * Race with unmap; TLB invalidations will start targeting the new ASID,
	 * which isn't assigned yet. We'll do an invalidate-all on the old ASID
	 * later, so it doesn't matter.
	 */
	cd->entry.tag = ret;

	/*
	 * Update ASID and invalidate CD in all associated masters. There will
	 * be some overlap between use of both ASIDs, until we invalidate the
	 * TLB.
	 */
	arm_smmu_write_ctx_desc(tbl, cd->pasid, cd);

	/* Invalidate TLB entries previously associated with that context */
	iommu_pasid_flush_tlbs(&tbl->pasid, cd->pasid, &old_entry);

	idr_remove(&asid_idr, asid);

	return NULL;
}

static struct iommu_pasid_entry *
arm_smmu_alloc_shared_cd(struct iommu_pasid_table_ops *ops,
			 struct mm_struct *mm)
{
	u16 asid;
	u64 tcr, par, reg;
	int ret = -ENOMEM;
	struct arm_smmu_cd *cd;
	struct arm_smmu_cd *old_cd = NULL;
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);

	asid = mm_context_get(mm);
	if (!asid)
		return ERR_PTR(-ESRCH);

	cd = arm_smmu_alloc_cd(tbl);
	if (!cd)
		goto err_put_context;

	idr_preload(GFP_KERNEL);
	spin_lock(&asid_lock);
	old_cd = arm_smmu_share_asid(asid);
	if (!old_cd)
		ret = idr_alloc(&asid_idr, cd, asid, asid + 1, GFP_ATOMIC);
	spin_unlock(&asid_lock);
	idr_preload_end();

	if (!IS_ERR_OR_NULL(old_cd)) {
		if (WARN_ON(old_cd->mm != mm)) {
			ret = -EINVAL;
			goto err_free_cd;
		}
		kfree(cd);
		mm_context_put(mm);
		return &old_cd->entry;
	} else if (old_cd) {
		ret = PTR_ERR(old_cd);
		goto err_free_cd;
	}

	tcr = TCR_T0SZ(VA_BITS) | TCR_IRGN0_WBWA | TCR_ORGN0_WBWA |
		TCR_SH0_INNER | ARM_LPAE_TCR_EPD1;

	switch (PAGE_SIZE) {
	case SZ_4K:
		tcr |= TCR_TG0_4K;
		break;
	case SZ_16K:
		tcr |= TCR_TG0_16K;
		break;
	case SZ_64K:
		tcr |= TCR_TG0_64K;
		break;
	default:
		WARN_ON(1);
		ret = -EINVAL;
		goto err_free_asid;
	}

	reg = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	par = cpuid_feature_extract_unsigned_field(reg,
				ID_AA64MMFR0_PARANGE_SHIFT);
	tcr |= par << ARM_LPAE_TCR_IPS_SHIFT;
	tcr |= TCR_HA | TCR_HD;

	cd->ttbr	= virt_to_phys(mm->pgd);
	cd->tcr		= tcr;
	/*
	 * MAIR value is pretty much constant and global, so we can just get it
	 * from the current CPU register
	 */
	cd->mair	= read_sysreg(mair_el1);

	cd->mm		= mm;
	cd->entry.tag	= asid;

	return &cd->entry;

err_free_asid:
	arm_smmu_free_asid(cd);

err_free_cd:
	kfree(cd);

err_put_context:
	mm_context_put(mm);

	return ERR_PTR(ret);
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

	cd = arm_smmu_alloc_cd(tbl);
	if (!cd)
		return ERR_PTR(-ENOMEM);

	idr_preload(GFP_KERNEL);
	spin_lock(&asid_lock);
	asid = idr_alloc_cyclic(&asid_idr, cd, 0, 1 << ctx_cfg->asid_bits,
				GFP_ATOMIC);
	cd->entry.tag = asid;
	spin_unlock(&asid_lock);
	idr_preload_end();

	if (asid < 0) {
		kfree(cd);
		return ERR_PTR(asid);
	}

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

	if (WARN_ON(cd->pasid != ARM_SMMU_NO_PASID && cd->pasid != pasid))
		return -EEXIST;

	/*
	 * There is a single cd structure for each address space, multiple
	 * devices may use the same in different tables.
	 */
	cd->users++;
	cd->pasid = pasid;
	return arm_smmu_write_ctx_desc(tbl, pasid, cd);
}

int arm_smmu_set_cd_mpam(struct iommu_pasid_table_ops *ops,
			 int ssid, int partid, int pmg)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);
	u64 val;
	__le64 *cdptr = arm_smmu_get_cd_ptr(tbl, ssid);

	if (!cdptr)
		return -ENOMEM;

	val = le64_to_cpu(cdptr[5]);
	val &= ~CTXDESC_CD_5_PARTID_MASK;
	val |= FIELD_PREP(CTXDESC_CD_5_PARTID_MASK, partid);
	val &= ~CTXDESC_CD_5_PMG_MASK;
	val |= FIELD_PREP(CTXDESC_CD_5_PMG_MASK, pmg);
	WRITE_ONCE(cdptr[5], cpu_to_le64(val));

	iommu_pasid_flush(&tbl->pasid, ssid, true);

	return 0;
}

int arm_smmu_get_cd_mpam(struct iommu_pasid_table_ops *ops,
		int ssid, int *partid, int *pmg)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);
	u64 val;
	__le64 *cdptr = arm_smmu_get_cd_ptr(tbl, ssid);

	if (!cdptr)
		return -ENOMEM;

	val = le64_to_cpu(cdptr[5]);
	*partid = FIELD_GET(CTXDESC_CD_5_PARTID_MASK, val);
	*pmg = FIELD_GET(CTXDESC_CD_5_PMG_MASK, val);

	return 0;
}

static void arm_smmu_clear_cd(struct iommu_pasid_table_ops *ops, int pasid,
			      struct iommu_pasid_entry *entry)
{
	struct arm_smmu_cd_tables *tbl = pasid_ops_to_tables(ops);
	struct arm_smmu_cd *cd = pasid_entry_to_cd(entry);

	if (WARN_ON(pasid > (1 << tbl->pasid.cfg.order)))
		return;

	WARN_ON(cd->pasid != pasid);

	if (!(--cd->users))
		cd->pasid = ARM_SMMU_NO_PASID;

	arm_smmu_write_ctx_desc(tbl, pasid, NULL);

	/*
	 * The ASID allocator won't broadcast the final TLB invalidations for
	 * this ASID, so we need to do it manually. For private contexts,
	 * freeing io-pgtable ops performs the invalidation.
	 */
	if (cd->mm)
		iommu_pasid_flush_tlbs(&tbl->pasid, pasid, entry);
}

static struct iommu_pasid_table *
arm_smmu_alloc_cd_tables(struct iommu_pasid_table_cfg *cfg, void *cookie)
{
	int ret;
	size_t size = 0;
	struct arm_smmu_cd_tables *tbl;
	struct device *dev = cfg->iommu_dev;
	struct arm_smmu_cd_table *leaf_table;
	size_t num_contexts, num_leaf_entries;

	tbl = devm_kzalloc(dev, sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return NULL;

	num_contexts = 1 << cfg->order;
	if (num_contexts <= CTXDESC_NUM_L2_ENTRIES) {
		/* Fits in a single table */
		tbl->linear = true;
		num_leaf_entries = num_contexts;
		leaf_table = &tbl->table;
	} else {
		/*
		 * SSID[S1CDmax-1:10] indexes 1st-level table, SSID[9:0] indexes
		 * 2nd-level
		 */
		tbl->l1.num_entries = num_contexts / CTXDESC_NUM_L2_ENTRIES;

		tbl->l1.tables = devm_kzalloc(dev,
					      sizeof(struct arm_smmu_cd_table) *
					      tbl->l1.num_entries, GFP_KERNEL);
		if (!tbl->l1.tables)
			goto err_free_tbl;

		size = tbl->l1.num_entries * (CTXDESC_L1_DESC_DWORD << 3);
		tbl->l1.ptr = dmam_alloc_coherent(dev, size, &tbl->l1.ptr_dma,
						  GFP_KERNEL | __GFP_ZERO);
		if (!tbl->l1.ptr) {
			dev_warn(dev, "failed to allocate L1 context table\n");
			devm_kfree(dev, tbl->l1.tables);
			goto err_free_tbl;
		}

		num_leaf_entries = CTXDESC_NUM_L2_ENTRIES;
		leaf_table = tbl->l1.tables;
	}

	ret = arm_smmu_alloc_cd_leaf_table(dev, leaf_table, num_leaf_entries);
	if (ret)
		goto err_free_l1;

	tbl->pasid.ops = (struct iommu_pasid_table_ops) {
		.alloc_priv_entry	= arm_smmu_alloc_priv_cd,
		.alloc_shared_entry	= arm_smmu_alloc_shared_cd,
		.set_entry		= arm_smmu_set_cd,
		.clear_entry		= arm_smmu_clear_cd,
	};

	if (tbl->linear) {
		cfg->base		= leaf_table->ptr_dma;
		cfg->arm_smmu.s1fmt	= ARM_SMMU_S1FMT_LINEAR;
	} else {
		cfg->base		= tbl->l1.ptr_dma;
		cfg->arm_smmu.s1fmt	= ARM_SMMU_S1FMT_64K_L2;
		arm_smmu_write_cd_l1_desc(tbl->l1.ptr, leaf_table);
	}

	return &tbl->pasid;

err_free_l1:
	if (!tbl->linear) {
		dmam_free_coherent(dev, size, tbl->l1.ptr, tbl->l1.ptr_dma);
		devm_kfree(dev, tbl->l1.tables);
	}
err_free_tbl:
	devm_kfree(dev, tbl);

	return NULL;
}

static void arm_smmu_free_cd_tables(struct iommu_pasid_table *pasid_table)
{
	struct iommu_pasid_table_cfg *cfg = &pasid_table->cfg;
	struct device *dev = cfg->iommu_dev;
	struct arm_smmu_cd_tables *tbl = pasid_to_cd_tables(pasid_table);

	if (tbl->linear) {
		arm_smmu_free_cd_leaf_table(dev, &tbl->table, 1 << cfg->order);
	} else {
		size_t i, size;

		for (i = 0; i < tbl->l1.num_entries; i++) {
			struct arm_smmu_cd_table *table = &tbl->l1.tables[i];

			if (!table->ptr)
				continue;

			arm_smmu_free_cd_leaf_table(dev, table,
						    CTXDESC_NUM_L2_ENTRIES);
		}

		size = tbl->l1.num_entries * (CTXDESC_L1_DESC_DWORD << 3);
		dmam_free_coherent(dev, size, tbl->l1.ptr, tbl->l1.ptr_dma);
		devm_kfree(dev, tbl->l1.tables);
	}

	devm_kfree(dev, tbl);
}

struct iommu_pasid_init_fns arm_smmu_v3_pasid_init_fns = {
	.alloc	= arm_smmu_alloc_cd_tables,
	.free	= arm_smmu_free_cd_tables,
};
