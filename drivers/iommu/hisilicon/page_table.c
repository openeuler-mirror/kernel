// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU matt allocator.
 */

#define pr_fmt(fmt) "UMMU: " fmt
#include <linux/dma-mapping.h>
#include <linux/io-pgtable.h>
#include <linux/errno.h>
#include <linux/kvm_host.h>

#include "flush.h"
#include "cfg_table.h"
#include "page_table.h"

struct ummu_pgtable_cfg {
	enum io_pgtable_fmt fmt;
	struct io_pgtable_cfg pgtbl_cfg;
	struct io_pgtable_ops *pgtbl_ops;
};

static const struct iommu_flush_ops ummu_flush_ops = {
	.tlb_flush_all = ummu_tlbi_context,
	.tlb_flush_walk = ummu_tlbi_walk,
	.tlb_add_page = ummu_tlbi_page,
};

struct ummu_domain identity_u_domain = {};

static int ummu_get_pgtable_cfg(struct ummu_domain *u_domain,
				struct ummu_pgtable_cfg *cfg)
{
	struct ummu_device *ummu = core_to_ummu_device(
					u_domain->base_domain.core_dev);

	if (u_domain->cfgs.stage == UMMU_DOMAIN_S1) {
		cfg->fmt = ARM_64_LPAE_S1;
		cfg->pgtbl_cfg.ias = (ummu->cap.features & UMMU_FEAT_VAX) ? 52 : 48;
		cfg->pgtbl_cfg.ias = min(cfg->pgtbl_cfg.ias, VA_BITS);
		cfg->pgtbl_cfg.oas = ummu->cap.ias;

		if (ummu->cap.features & UMMU_FEAT_HD)
			cfg->pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_HD;

		if (ummu->cap.features & UMMU_FEAT_BBML1)
			cfg->pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_BBML1;

		if (ummu->cap.features & UMMU_FEAT_BBML2)
			cfg->pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_BBML2;
	} else {
		cfg->fmt = ARM_64_LPAE_S2;
		cfg->pgtbl_cfg.ias = ummu->cap.ias;
		cfg->pgtbl_cfg.oas = ummu->cap.oas;
	}

	cfg->pgtbl_cfg.coherent_walk = ummu->cap.features & UMMU_FEAT_COHERENCY;
	cfg->pgtbl_cfg.pgsize_bitmap = ummu->cap.pgsize_bitmap;

	if (u_domain->base_domain.domain.type != IOMMU_DOMAIN_IDENTITY)
		cfg->pgtbl_cfg.tlb = &ummu_flush_ops;

	cfg->pgtbl_cfg.iommu_dev = ummu->dev;

	cfg->pgtbl_ops =
		alloc_io_pgtable_ops(cfg->fmt, &cfg->pgtbl_cfg, u_domain);
	if (!cfg->pgtbl_ops) {
		pr_err("alloc page table failed, check page table config!\n");
		return -ENOMEM;
	}

	return 0;
}

static int ummu_domain_collect_pgtable_s1(struct ummu_domain *u_domain,
					  struct io_pgtable_cfg *pgtbl_cfg)
{
	typeof(&pgtbl_cfg->arm_lpae_s1_cfg.tcr) tcr =
		&pgtbl_cfg->arm_lpae_s1_cfg.tcr;
	struct ummu_s1_cfg *cfg = &u_domain->cfgs.s1_cfg;

	cfg->tct.ttbr = pgtbl_cfg->arm_lpae_s1_cfg.ttbr;
	cfg->tct.mair = pgtbl_cfg->arm_lpae_s1_cfg.mair;
	cfg->tct.tcr0 |= FIELD_PREP(TCT_ENT0_GPAS, tcr->ips) |
			 TCT_ENT0_FBR | TCT_ENT0_FBA | TCT_ENT0_AA64;

	cfg->tct.tcr1 |= FIELD_PREP(TCT_ENT1_MD0, tcr->irgn) |
			 FIELD_PREP(TCT_ENT1_MD1, tcr->orgn) |
			 FIELD_PREP(TCT_ENT1_SZ, tcr->tsz) |
			 FIELD_PREP(TCT_ENT1_TGS, tcr->tg) |
			 FIELD_PREP(TCT_ENT1_MSD, tcr->sh);

	return 0;
}

static int ummu_domain_collect_pgtable_s2(struct ummu_domain *u_domain,
					  struct io_pgtable_cfg *pgtbl_cfg)
{
	typeof(&pgtbl_cfg->arm_lpae_s2_cfg.vtcr) vtcr =
		&pgtbl_cfg->arm_lpae_s2_cfg.vtcr;
	struct ummu_s2_cfg *cfg = &u_domain->cfgs.s2_cfg;
	int vmid = 0;

	if (u_domain->kvm)
		vmid = kvm_pinned_vmid_get(u_domain->kvm);
	if (vmid < 0)
		return vmid;

	cfg->vmid = (u16)vmid;
	cfg->vttbr = pgtbl_cfg->arm_lpae_s2_cfg.vttbr;
	cfg->vtcr = FIELD_PREP(TECT_ENT2_NS_S2_TSZ, vtcr->tsz) |
		    FIELD_PREP(TECT_ENT2_NS_S2_SL, vtcr->sl) |
		    FIELD_PREP(TECT_ENT2_S2_MD0, vtcr->irgn) |
		    FIELD_PREP(TECT_ENT2_S2_MD1, vtcr->orgn) |
		    FIELD_PREP(TECT_ENT2_NS_S2_TG, vtcr->tg) |
		    FIELD_PREP(TECT_ENT2_S2_MSD, vtcr->sh) |
		    FIELD_PREP(TECT_ENT2_S2_PAS, vtcr->ps);

	return 0;
}

int ummu_domain_collect_pgtable(struct ummu_domain *u_domain)
{
	struct ummu_pgtable_cfg cfg;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	ret = ummu_get_pgtable_cfg(u_domain, &cfg);
	if (ret) {
		pr_err("get ummu pagetable configuration failed!\n");
		return ret;
	}

	if (u_domain->cfgs.stage == UMMU_DOMAIN_S1)
		ret = ummu_domain_collect_pgtable_s1(u_domain,
						     &cfg.pgtbl_cfg);
	else
		ret = ummu_domain_collect_pgtable_s2(u_domain,
						     &cfg.pgtbl_cfg);

	if (ret) {
		free_io_pgtable_ops(cfg.pgtbl_ops);
		return ret;
	}

	u_domain->cfgs.pgtbl_ops = cfg.pgtbl_ops;
	u_domain->base_domain.domain.pgsize_bitmap =
				cfg.pgtbl_cfg.pgsize_bitmap;
	u_domain->base_domain.domain.geometry.aperture_start = 0;
	u_domain->base_domain.domain.geometry.aperture_end =
		(dma_addr_t)DMA_BIT_MASK(cfg.pgtbl_cfg.ias);
	u_domain->base_domain.domain.geometry.force_aperture = true;
	return 0;
}

static int ummu_map_identity_pages(void)
{
	struct io_pgtable_ops *pgtbl_ops = identity_u_domain.cfgs.pgtbl_ops;
	size_t pgcount = 0;
	size_t pgsize = 0;
	size_t mapped = 0;
	size_t step = 0;
	u64 start;
	u64 end;
	int ret = 0;

	switch (PAGE_SIZE) {
	case SZ_4K:
		pgcount = SZ_512;
		pgsize = SZ_1G;
		break;
	case SZ_64K:
		pgcount = SZ_8K;
		pgsize = SZ_512M;
		break;
	default:
		pr_err("PAGE_SIZE not supported: %lu\n", PAGE_SIZE);
		return -EINVAL;
	}

	if (!pgtbl_ops)
		return -EOPNOTSUPP;
	end = ALIGN(identity_u_domain.base_domain.domain.geometry.aperture_end +
		1, pgsize);
	step = pgsize * pgcount;
	for (start = 0; start < end; start += step) {
		ret = pgtbl_ops->map_pages(pgtbl_ops, start, start, pgsize,
					   pgcount, (IOMMU_READ | IOMMU_WRITE),
					   GFP_KERNEL, &mapped);
		if (ret) {
			pr_err("map failed, ret = %d!\n", ret);
			return ret;
		}
	}

	return 0;
}

int ummu_global_identity_pgtbl_init(struct ummu_device *ummu)
{
	int ret;

	if (identity_u_domain.cfgs.pgtbl_ops)
		return 0;

	identity_u_domain.base_domain.domain.type = IOMMU_DOMAIN_IDENTITY;
	identity_u_domain.base_domain.core_dev = &ummu->core_dev;
	identity_u_domain.base_domain.tid = UMMU_INVALID_TID;
	identity_u_domain.cfgs.stage = UMMU_DOMAIN_S1;
	mutex_init(&identity_u_domain.init_mutex);

	ret = ummu_domain_collect_pgtable(&identity_u_domain);
	if (ret) {
		pr_err("init global identity page table failed, ret = %d\n", ret);
		return ret;
	}

	ret = ummu_map_identity_pages();
	if (ret) {
		ummu_global_identity_pgtbl_free();
		return ret;
	}

	identity_u_domain.cfgs.s1_cfg.tct_cfg = ummu->local_tct_cfg;
	return 0;
}

void ummu_global_identity_pgtbl_free(void)
{
	free_io_pgtable_ops(identity_u_domain.cfgs.pgtbl_ops);
	identity_u_domain.cfgs.pgtbl_ops = NULL;
}

struct ummu_domain *ummu_get_global_identity_domain(void)
{
	return &identity_u_domain;
}
