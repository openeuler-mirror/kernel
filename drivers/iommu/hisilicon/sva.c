// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: Implementation of the IOMMU SVA API for the UMMU
 */

#define pr_fmt(fmt) "UMMU: " fmt
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>

#include "iommu.h"
#include "ummu.h"
#include "page_table.h"
#include "perm_table.h"
#include "perm_queue.h"
#include "cfg_table.h"
#include "queue.h"
#include "flush.h"
#include "sva.h"

static DEFINE_MUTEX(ummu_sva_mutex);

bool ummu_sva_supported(struct ummu_device *ummu)
{
	u32 feat_mask = UMMU_FEAT_COHERENCY;
	unsigned long asid_bits;
	unsigned long reg, fld;
	unsigned long oas;

	if ((ummu->cap.features & feat_mask) != feat_mask)
		return false;

	if (!(ummu->cap.pgsize_bitmap & PAGE_SIZE))
		return false;

	/*
	 * Get the smallest PA size of all CPUs (sanitized by cpufeature). We're
	 * not even pretending to support AArch32 here. Abort if the MMU outputs
	 * addresses larger than what we support.
	 */
	reg = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	fld = cpuid_feature_extract_unsigned_field(
		reg, ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	oas = id_aa64mmfr0_parange_to_phys_shift(fld);
	if (ummu->cap.oas < oas)
		return false;

	/* We can support bigger ASIDs than the CPU, but not smaller */
	fld = cpuid_feature_extract_unsigned_field(
		reg, ID_AA64MMFR0_EL1_ASIDBITS_SHIFT);
	/* 16: aaid shift 16 bits, 8: asid shift 8 bits. */
	asid_bits = fld ? 16 : 8;
	if (ummu->cap.asid_bits < asid_bits)
		return false;

	return true;
}

static bool ummu_master_sva_supported(struct ummu_master *master)
{
	return master->ummu->cap.features & UMMU_FEAT_SVA;
}

static bool ummu_master_iopf_supported(struct ummu_master *master)
{
	return master->ummu->cap.features & UMMU_FEAT_STALLS;
}

bool ummu_master_sva_enabled(struct ummu_master *master)
{
	bool enabled;

	mutex_lock(&ummu_sva_mutex);
	enabled = master->sva_enabled;
	mutex_unlock(&ummu_sva_mutex);
	return enabled;
}

static int ummu_master_sva_enable_iopf(struct ummu_master *master)
{
	struct device *dev = master->dev;
	struct iopf_queue *iopfq;
	int ret;

	if (master->iopf_enabled)
		return -EBUSY;

	/* bus controller support stall as default. */
	iopfq = master->ummu->evtq.iopf;
	if (!iopfq) {
		pr_debug("has no iopf queue, check evetq support\n");
		return -ENODEV;
	}

	ret = iopf_queue_add_device(iopfq, dev);
	if (ret)
		return ret;

	master->iopf_enabled = true;

	return 0;
}

bool ummu_master_iopf_enabled(struct ummu_master *master)
{
	bool enabled;

	mutex_lock(&ummu_sva_mutex);
	enabled = master->iopf_enabled;
	mutex_unlock(&ummu_sva_mutex);
	return enabled;
}

static void ummu_master_sva_disable_iopf(struct ummu_master *master)
{
	struct device *dev = master->dev;

	if (!master->iopf_enabled)
		return;

	iopf_queue_remove_device(master->ummu->evtq.iopf, dev);
	master->iopf_enabled = false;
}

int ummu_master_enable_sva(struct ummu_master *master,
			   enum iommu_dev_features feat)
{
	int ret = 0;

	if (!ummu_master_sva_supported(master)) {
		pr_err("doesn't support sva!\n");
		return -ENODEV;
	}

	guard(mutex)(&ummu_sva_mutex);
	if (feat == IOMMU_DEV_FEAT_SVA) {
		if (master->sva_enabled) {
			pr_err("%s SVA already enabled.\n", dev_name(master->dev));
			return -EBUSY;
		}

		if (ummu_master_iopf_supported(master)) {
			ret = ummu_master_sva_enable_iopf(master);
			if (ret) {
				pr_err("enable iopf failed!\n");
				return ret;
			}
		}

		master->sva_enabled = true;
	} else {
		if (master->ksva_enabled) {
			pr_err("%s KSVA already enabled.\n", dev_name(master->dev));
			return -EBUSY;
		}
		master->ksva_enabled = true;
	}

	return 0;
}

int ummu_master_disable_sva(struct ummu_master *master,
			    enum iommu_dev_features feat)
{
	guard(mutex)(&ummu_sva_mutex);

	if (feat == IOMMU_DEV_FEAT_SVA) {
		if (!master->sva_enabled)
			goto err_out;

		if (refcount_read(&master->sva_ref) > 1) {
			dev_err(master->dev,
				"cannot disable SVA, device is shared\n");
			return -EBUSY;
		}

		if (ummu_master_iopf_supported(master))
			ummu_master_sva_disable_iopf(master);

		master->sva_enabled = false;
	} else {
		if (!master->ksva_enabled)
			goto err_out;

		if (refcount_read(&master->ksva_ref) > 1) {
			dev_err(master->dev,
				"cannot disable KSVA, device is shared\n");
			return -EBUSY;
		}
		master->ksva_enabled = false;
	}

err_out:
	return 0;
}

int ummu_master_enable_iopf(struct ummu_master *master)
{
	int ret;

	if (!ummu_master_iopf_supported(master))
		return 0;

	guard(mutex)(&ummu_sva_mutex);
	ret = ummu_master_sva_enable_iopf(master);
	return ret;
}

int ummu_master_disable_iopf(struct ummu_master *master)
{
	if (!ummu_master_iopf_supported(master))
		return 0;

	guard(mutex)(&ummu_sva_mutex);
	if (master->sva_enabled)
		return -EBUSY;

	ummu_master_sva_disable_iopf(master);

	return 0;
}

static int ummu_sva_get_translation_granule(void)
{
	switch (PAGE_SIZE) {
	case SZ_4K:
		return TCT_TCR_TGS_4K;
	case SZ_16K:
		return TCT_TCR_TGS_16K;
	case SZ_64K:
		return TCT_TCR_TGS_64K;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

static int ummu_sva_domain_collect_tct_info(struct ummu_device *ummu,
					    struct ummu_domain *domain,
					    u32 asid)
{
	struct ummu_tct_desc *tct_desc = &domain->cfgs.s1_cfg.tct;
	u64 reg, gpas;
	int tgs;

	tgs = ummu_sva_get_translation_granule();
	if (unlikely(tgs < 0)) {
		pr_err("SVA get invalid page_size = %lu\n", PAGE_SIZE);
		return tgs;
	}

	reg = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	gpas = cpuid_feature_extract_unsigned_field(
		reg, ID_AA64MMFR0_EL1_PARANGE_SHIFT);

	tct_desc->tcr0 |= FIELD_PREP(TCT_ENT0_GPAS, gpas) |
			  ((ummu->cap.features & UMMU_FEAT_STALLS) ? TCT_ENT0_FBS : 0) |
			  TCT_ENT0_FBR | TCT_ENT0_FBA | TCT_ENT0_AA64;

	tct_desc->tcr1 |= FIELD_PREP(TCT_ENT1_SZ, 64ULL - vabits_actual) |
			  FIELD_PREP(TCT_ENT1_MD0, TCT_TCR_RGN_WBWA) |
			  FIELD_PREP(TCT_ENT1_MD1, TCT_TCR_RGN_WBWA) |
			  FIELD_PREP(TCT_ENT1_MSD, TCT_MSD_IS) |
			  FIELD_PREP(TCT_ENT1_TGS, tgs);

	tct_desc->asid = asid;
	tct_desc->mair = read_sysreg(mair_el1);
	tct_desc->ttbr = virt_to_phys(domain->base_domain.domain.mm->pgd);
	return 0;
}

static struct ummu_master *ummu_sva_master_get(struct device *dev, bool is_ksva)
{
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);

	if (!is_ksva)
		refcount_inc(&master->sva_ref);
	else
		refcount_inc(&master->ksva_ref);

	return master;
}

static void ummu_sva_master_put(struct ummu_master *master, bool is_ksva)
{
	if (!is_ksva)
		refcount_dec(&master->sva_ref);
	else
		refcount_dec(&master->ksva_ref);
}

static int ummu_sva_collect_domain_cfg(struct ummu_domain *domain, ioasid_t id)
{
	struct ummu_device *ummu = core_to_ummu_device(
					domain->base_domain.core_dev);
	bool ksva = iommu_is_ksva_domain(&domain->base_domain.domain);
	enum ummu_mapt_mode mode;
	int ret;

	if (ummu->cap.features & UMMU_FEAT_BTM)
		domain->cfgs.btm_enabled = true;

	domain->base_domain.tid = id;
	domain->cfgs.s1_cfg.tct_cfg = ummu->local_tct_cfg;
	domain->cfgs.s1_cfg.io_pt_cfg.mode = MAPT_MODE_END;

	mode = ummu_core_get_mapt_mode(&ummu->core_dev, id);

	if (ksva) {
		domain->cfgs.sva_mode = UMMU_MODE_KSVA;
	} else {
		if (mode == MAPT_MODE_END)
			domain->cfgs.sva_mode = UMMU_MODE_SVA_DISABLE_PTB;
		else
			domain->cfgs.sva_mode = UMMU_MODE_SVA;
	}

	if ((ummu->cap.features & UMMU_FEAT_MAPT) &&
	    domain->cfgs.sva_mode != UMMU_MODE_SVA_DISABLE_PTB) {
		domain->cfgs.s1_cfg.io_pt_cfg.mode = mode;
		if (!ksva) {
			ret = ummu_init_sva_mapt_context(domain, mode);
			if (ret)
				goto out_cfg;
		} else {
			if (ummu->cap.features & UMMU_FEAT_PPLBI)
				domain->cfgs.s1_cfg.io_pt_cfg.positive_plbi = 1;
			if (ummu->cap.features & UMMU_FEAT_FREE_BIT)
				domain->cfgs.s1_cfg.io_pt_cfg.free_bit = 1;
			domain->cfgs.s1_cfg.io_pt_cfg.domain =
						&domain->base_domain.domain;
			ret = ummu_init_ksva_mapt(domain, mode);
			if (ret)
				goto out_cfg;
		}
	}
	return 0;

out_cfg:
	domain->base_domain.tid = UMMU_INVALID_TID;
	return ret;
}

static int ummu_sva_asid_get(struct iommu_domain *iommu_domain, bool is_ksva,
			     u32 *asid)
{
	if (!is_ksva) {
		*asid = arm64_mm_context_get(iommu_domain->mm);
		if (!(*asid))
			return -EFAULT;
	} else {
		*asid = ASID(iommu_domain->mm);
	}

	return 0;
}

static void ummu_sva_asid_put(struct iommu_domain *iommu_domain, bool is_ksva)
{
	if (!is_ksva)
		arm64_mm_context_put(iommu_domain->mm);
}

static int ummu_sva_set_dev_pasid(struct iommu_domain *domain,
				  struct device *dev, ioasid_t id)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_device *ummu = core_to_ummu_device(
					u_domain->base_domain.core_dev);
	bool is_ksva = iommu_is_ksva_domain(domain);
	struct ummu_master *master;
	u32 asid;
	int ret;

	guard(mutex)(&ummu_sva_mutex);
	ret = ummu_sva_asid_get(domain, is_ksva, &asid);
	if (ret)
		return ret;

	ret = ummu_sva_domain_collect_tct_info(ummu, u_domain, asid);
	if (ret)
		goto out_asid_put;

	master = ummu_sva_master_get(dev, is_ksva);
	if (!master) {
		ret = -ENODEV;
		goto out_asid_put;
	}

	ret = ummu_sva_collect_domain_cfg(u_domain, id);
	if (ret)
		goto out_master_put;

	(void)ummu_write_tct_desc(ummu, &u_domain->cfgs, false);
	return 0;

out_master_put:
	ummu_sva_master_put(master, is_ksva);
out_asid_put:
	ummu_sva_asid_put(domain, is_ksva);
	return ret;
}

static void ummu_sva_domain_free(struct iommu_domain *domain)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);

	if (u_domain->qid != UMMU_INVALID_QID) {
		pr_warn("qid %u still valid when free sva domain 0x%pK, forgot put resource?\n",
			u_domain->qid, domain);
		ummu_release_permq_resource(u_domain);
	}

	ummu_release_domain_mapt_mem(u_domain);
	kfree(u_domain);
}

static void ummu_invalidate_plb(struct iommu_domain *domain,
				struct iommu_plb_gather *plb_gather)
{
	struct ummu_base_domain *base_domain = to_ummu_base_domain(domain);
	struct ummu_device *ummu = core_to_ummu_device(base_domain->core_dev);
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	u32 tid = u_domain->base_domain.tid;
	u32 tag = u_domain->cfgs.tecte_tag;
	u64 addr;
	int ret;

	if (plb_gather->size == 0)
		return;

	addr = (u64)(uintptr_t)plb_gather->va & GENMASK_ULL(ummu->cap.ias - 1, 0U);
	ret = ummu_device_flush_plb(ummu, tag, tid, addr, plb_gather->size);
	if (ret)
		pr_warn("failed to plbi by va!\n");
}

const struct iommu_perm_ops ummu_sva_perm_ops = {
	.grant = ummu_perm_grant,
	.ungrant = ummu_perm_ungrant,
	.plb_sync = ummu_invalidate_plb,
	.plb_sync_all = ummu_device_flush_plb_all,
};

static const struct iommu_domain_ops ummu_sva_domain_ops = {
	.set_dev_pasid = ummu_sva_set_dev_pasid,
	.free = ummu_sva_domain_free,
};

struct iommu_domain *ummu_domain_alloc_sva(struct device *dev,
					   struct mm_struct *mm)
{
	struct ummu_domain *u_domain;

	u_domain = ummu_domain_alloc_helper();
	if (!u_domain)
		return ERR_PTR(-ENOMEM);

	u_domain->base_domain.domain.type = IOMMU_DOMAIN_SVA;
	u_domain->base_domain.domain.ops = &ummu_sva_domain_ops;
	u_domain->base_domain.domain.perm_ops = &ummu_sva_perm_ops;
	return &u_domain->base_domain.domain;
}

void ummu_sva_domain_remove_tid(struct ummu_domain *domain,
				struct ummu_master *master, u32 tid)
{
	bool is_ksva = iommu_is_ksva_domain(&domain->base_domain.domain);

	guard(mutex)(&ummu_sva_mutex);
	ummu_sva_master_put(master, is_ksva);
	ummu_sva_asid_put(&domain->base_domain.domain, is_ksva);

	if (is_ksva) {
		ummu_release_ksva_mapt(domain);
	} else {
		if (domain->cfgs.sva_mode == UMMU_MODE_SVA_DISABLE_PTB)
			ummu_write_tct_desc(master->ummu, &domain->cfgs, true);
		else
			ummu_release_domain_mapt_mem(domain);
	}
}

int ummu_iopf_queue_alloc(struct ummu_device *ummu)
{
	ummu->evtq.iopf = iopf_queue_alloc(dev_name(ummu->dev));
	if (!ummu->evtq.iopf)
		return -ENOMEM;

	return 0;
}

void ummu_iopf_queue_free(struct ummu_device *ummu)
{
	iopf_queue_free(ummu->evtq.iopf);
}

void ummu_sva_tcte_invalidate(struct ummu_domain *u_domain)
{
	struct ummu_device *ummu =
		core_to_ummu_device(u_domain->base_domain.core_dev);
	struct ummu_tct_desc *tct_desc = &u_domain->cfgs.s1_cfg.tct;

	guard(mutex)(&ummu_sva_mutex);
	tct_desc->tcr0 &= ~TCT_ENT0_FBR;
	tct_desc->tcr1 |= TCT_ENT1_TTWD;
	ummu_write_tct_desc(ummu, &u_domain->cfgs, false);
	ummu_flush_iotlb_all(&u_domain->base_domain.domain);
}
