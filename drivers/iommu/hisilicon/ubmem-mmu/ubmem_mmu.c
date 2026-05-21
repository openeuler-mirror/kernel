// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UBMEM-MMU Device's Implementation
 */
#define pr_fmt(fmt) "UBMEM-MMU: " fmt

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/iopoll.h>
#include <linux/dma-map-ops.h>
#include <linux/refcount.h>
#include <linux/iommu.h>
#include <linux/xarray.h>
#include <linux/bitmap.h>
#include <linux/ummu_core.h>
#include <linux/delay.h>
#include <linux/maple_tree.h>
#include <linux/interrupt.h>
#include <ub/ubfi/ubfi.h>
#include <linux/hisi_ummu.h>

#include "../regs.h"
#include "ubmem_mmu.h"

#define UMMU_MEM_MAX_GRANULE 8
#define UMMU_VENDOR_INFO_RESERVED 48
static LIST_HEAD(ubmem_device_list);

static ulong ubm_granule;
module_param(ubm_granule, ulong, 0444);
MODULE_PARM_DESC(ubm_granule,
	"UB memory page table granule; range [0,7], default(0), addr|size must be aligned to 2M * 2^ubm_granule.");

static unsigned long ummu_get_ubm_granule(void)
{
	return (ubm_granule >= UMMU_MEM_MAX_GRANULE) ? 0 : ubm_granule;
}

/* REG DEFINE */
#define UBMEM_REG_SHIFT 16
#define UBMEM_VALID_VALUE 7
#define UBMEM_VALID_MASK GENMASK_ULL(2, 0)
#define UBMEM_REG_BASE 0x800000
#define UMMU_MEM_START_ADDR 0x0
#define START_PTE_ADDR_MASK GENMASK(26, 0)
#define START_ATE_ADDR_MASK GENMASK(22, 0)

#define UMMU_MEM_LEN_GRANU 0x4
#define MEM_GRANU_MASK GENMASK(19, 17)
#define MEM_LEN_MASK GENMASK(16, 0)

#define UMMU_MEM_BTE 0x8
#define MEM_BTE_MASK GENMASK(16, 0)

#define UMMU_MEM_INDEX 0xC
#define MEM_WR_MASK (1UL << 19)
#define MEM_TYPE_MASK (1UL << 18)
#define MEM_VLD_MASK (1UL << 17)
#define MEM_PTE_INDEX_MASK GENMASK(9, 0)
#define MEM_ATE_INDEX_MASK GENMASK(16, 0)

#define UMMU_MEM_DTLB_INVLD 0x10
#define MEM_DTLB_INVLD_MASK (1UL)

#define SZ_2M_SHIFT (21UL)
#define PHYS_ADDR_MASK GENMASK_ULL(43, 21)
#define IOVA_MASK GENMASK_ULL(47, 21)

#define UMMU_UBIF_MEM_SZ 0x8000

#define UBIF_MEM_CHK_FAULT_VLD (1UL)
#define UBIF_MEM_CHK_FAULT_RECORD_MODE (1UL << 8)
#define UBIF_MEM_CHK_FAULT_STAGE (1UL << 1)
#define UBIF_MEM_CHK_FAULT_LENGTH GENMASK(5, 2)
#define UBIF_MEM_CHK_FAULT_TOKENID GENMASK(25, 6)
#define UBIF_MEM_CHK_FAULT_ERR_CODE GENMASK(30, 26)
#define UBIF_MEM_CHK_FAULT_END_ADDR GENMASK(8, 0)
#define UBIF_MEM_CHK_FAULT_CLEAR (1UL << 31)
#define UBIF_MEM_CHK_FAULT_VA_H GENMASK(15, 0)
#define UBIF_MEM_CHK_FAULT_VA_L GENMASK(31, 0)
#define UBIF_MEM_CHK_FAULT_VA_H_SHIFT 32

#define UBMEM_MMU_INT_MASK 0x3404
#define UBIF_USI_MASK (1UL << 1)
#define UIEQ_USI_MASK (1UL << 0)

#define RESERVED_MSI_ADDR 0x4D90
#define RESERVED_MSI_ADDR_MASK GENMASK_ULL(51, 2)
#define RESERVED_MSI_DATA 0x4D98
#define RESERVED_MSI_ATTR 0x4D9C
#define RESERVED_MSI_ATTR_DEVICE_nGnRE 0x1
#define RESERVED_MSI_ADDR_H_SHIFT 32

#define UMAU_MEM_DTLB_INVLD 0x2030
#define UMAU_MEM_START_ADDR 0x2000
#define UMAU_MEM_LEN_GRANU 0x2004
#define UMAU_MEM_BTE 0x2008
#define UMAU_MEM_INDEX 0x200C

#define UMAU_MEM_TAB_INIT_EN_TRANS 0x2020
#define TTB_INTI_EN BIT(0)
#define UMAU_MEM_TAB_INIT_EN_PROT 0x2024
#define PTB_INIT_EN BIT(0)
#define UMAU_MEM_TAB_INIT_DONE_TRANS 0x2010
#define TTB_INIT_DONE BIT(0)
#define UMAU_MEM_TAB_INIT_DONE_PROT 0x2014
#define PTB_INIT_DONE BIT(0)

enum ummu_ubif_reg_enum {
	UBIF_MEM_CFG,
	UBIF_MEM_DFX0,
	UBIF_MEM_DFX1,
	UBIF_MEM_DFX2,
	UBIF_MEM_DFX3,
	UMMU_UBIF_MEM_MAX,
};

static u32 ummu_ubif_reg[UMMU_UBIF_MEM_MAX] = {
	[UBIF_MEM_CFG] = 0x6430,
	[UBIF_MEM_DFX0] = 0x6434,
	[UBIF_MEM_DFX1] = 0x6438,
	[UBIF_MEM_DFX2] = 0x643C,
	[UBIF_MEM_DFX3] = 0x6444,
};

static u32 umau_ubif_reg[UMMU_UBIF_MEM_MAX] = {
	[UBIF_MEM_CFG] = 0x1030,
	[UBIF_MEM_DFX0] = 0x1034,
	[UBIF_MEM_DFX1] = 0x1038,
	[UBIF_MEM_DFX2] = 0x103C,
	[UBIF_MEM_DFX3] = 0x1044,
};

struct ubmem_reg_offset {
	u32 mem_dtlb_invld;
	u32 mem_start_addr;
	u32 mem_len_granu;
	u32 mem_bte;
	u32 mem_index;
	const u32 *ubif_reg;
};

static const struct ubmem_reg_offset reg_v1 = {
	.mem_dtlb_invld = UMMU_MEM_DTLB_INVLD,
	.mem_start_addr = UMMU_MEM_START_ADDR,
	.mem_len_granu = UMMU_MEM_LEN_GRANU,
	.mem_bte = UMMU_MEM_BTE,
	.mem_index = UMMU_MEM_INDEX,
	.ubif_reg = ummu_ubif_reg
};

static const struct ubmem_reg_offset reg_umau_v2 = {
	.mem_dtlb_invld = UMAU_MEM_DTLB_INVLD,
	.mem_start_addr = UMAU_MEM_START_ADDR,
	.mem_len_granu = UMAU_MEM_LEN_GRANU,
	.mem_bte = UMAU_MEM_BTE,
	.mem_index = UMAU_MEM_INDEX,
	.ubif_reg = umau_ubif_reg
};

enum ubmem_err_type {
	BAD_REQUEST = 1,
	BAD_TOKENID,
	PT_ECC_2BITS,
	PT_INVALID,
	PT_BAD_ADDR,
	ATT_ECC_2BITS,
	ATT_INVALID,
};

struct ubmem_mmu_info {
	u64 valid;
	u32 cap0;
	u32 cap1;
	u64 reg_base;
	u64 reg_size;
	u8 reserved[UMMU_VENDOR_INFO_RESERVED];
};

struct ubmem_mmu_device {
	struct ummu_device ummu;
	struct list_head list;
	struct device *dev;
	void __iomem *base;
	void __iomem *dfx_base;
	unsigned long *ate_bitmap;
	spinlock_t pte_lock;
	u32 ate_bits;
	u32 token_id_bits;
	const struct ubmem_reg_offset *reg_offset;
	struct ummu_core_device ummu_core;
};

struct ubmem_mmu_domain {
	struct mutex map_lock;
	void *cached_pa_list;
	bool pte_valid;
	unsigned long iova_start;
	unsigned long iova_len;
	unsigned long ate_index_start;
	unsigned long ate_count;
	unsigned long granule;
	struct ubmem_mmu_device *mmu;
	struct ummu_base_domain base_domain;
};

struct ubmem_master {
	struct ubmem_mmu_device *ubmem_dev;
};

struct pa_info {
	phys_addr_t paddr;
	size_t size;
};

static inline
struct ubmem_mmu_device *to_ubmem_mmu_dev(struct ummu_device *ummu)
{
	return container_of(ummu, struct ubmem_mmu_device, ummu);
}

static inline
struct ubmem_mmu_device *core_to_ubmem_mmu_dev(struct ummu_core_device *core)
{
	return container_of(core, struct ubmem_mmu_device, ummu_core);
}

static inline struct ubmem_mmu_domain *
to_ubmem_mmu_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_domain =
		container_of(dom, struct ummu_base_domain, domain);
	return container_of(base_domain, struct ubmem_mmu_domain, base_domain);
}

static irqreturn_t ubmem_error_handler(int irq, void *ummu)
{
	struct ubmem_mmu_device *mmu =
				to_ubmem_mmu_dev((struct ummu_device *)ummu);
	void __iomem *dfx_base = mmu->dfx_base == NULL ? mmu->base : mmu->dfx_base;
	u32 regs[UMMU_UBIF_MEM_MAX];
	u8 code;
	int i;

	for (i = 0; i < UMMU_UBIF_MEM_MAX; i++)
		regs[i] = readl_relaxed(dfx_base + mmu->reg_offset->ubif_reg[i]);

	if (!(regs[UBIF_MEM_DFX2] & UBIF_MEM_CHK_FAULT_VLD)) {
		dev_info_ratelimited(mmu->dev, "received a unknown fault.\n");
		return IRQ_HANDLED;
	}
	code = FIELD_GET(UBIF_MEM_CHK_FAULT_ERR_CODE, regs[UBIF_MEM_DFX2]);
	dev_info(mmu->dev, "event 0x%x received.\n", code);
	dev_info(mmu->dev, "fault stage: 0x%lx.\n",
		 regs[UBIF_MEM_DFX2] & UBIF_MEM_CHK_FAULT_STAGE);
	dev_info(mmu->dev, "fault mode: 0x%lx.\n",
		 regs[UBIF_MEM_CFG] & UBIF_MEM_CHK_FAULT_RECORD_MODE);
	dev_info(mmu->dev, "fault tid: 0x%lx.\n",
		 FIELD_GET(UBIF_MEM_CHK_FAULT_TOKENID, regs[UBIF_MEM_DFX2]));
	dev_info(mmu->dev, "fault length: 0x%lx.\n",
		 FIELD_GET(UBIF_MEM_CHK_FAULT_END_ADDR, regs[UBIF_MEM_DFX3]) -
		 FIELD_GET(UBIF_MEM_CHK_FAULT_END_ADDR, regs[UBIF_MEM_DFX0]));

	writel_relaxed(UBIF_MEM_CHK_FAULT_CLEAR,
		       dfx_base + mmu->reg_offset->ubif_reg[UBIF_MEM_DFX2]);
	return IRQ_HANDLED;
}

static void ubmem_mmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct device *dev = msi_desc_to_dev(desc);
	struct ummu_device *ummu = (struct ummu_device *)dev_get_drvdata(dev);
	phys_addr_t msi_addr;

	if (desc->msi_index != RESERVED_MSI_INDEX) {
		dev_err(dev, "Unsupport msi_index = %u\n", desc->msi_index);
		return;
	}

	msi_addr = (((u64)msg->address_hi) << RESERVED_MSI_ADDR_H_SHIFT) |
		    msg->address_lo;
	msi_addr &= RESERVED_MSI_ADDR_MASK;

	writeq_relaxed(msi_addr, ummu->base + RESERVED_MSI_ADDR);
	writel_relaxed(msg->data, ummu->base + RESERVED_MSI_DATA);
	writel_relaxed(RESERVED_MSI_ATTR_DEVICE_nGnRE,
		       ummu->base + RESERVED_MSI_ATTR);
}

static void ubmem_mmu_set_usi_mask(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UBMEM_MMU_INT_MASK);

	reg &= ~UBIF_USI_MASK;
	writel_relaxed(reg, ummu->base + UBMEM_MMU_INT_MASK);
}

static void ubmem_mmu_setup_irq(struct ummu_device *ummu)
{
	u32 reserved_irq;
	int ret;

	reserved_irq = msi_get_virq(ummu->dev, RESERVED_MSI_INDEX);
	if (reserved_irq == 0) {
		dev_warn(ummu->dev,
			 "no ubmem-mmu irq - events will not be reported!\n");
		return;
	}
	ubmem_mmu_set_usi_mask(ummu);
	ret = devm_request_threaded_irq(ummu->dev, reserved_irq, NULL,
					ubmem_error_handler, IRQF_ONESHOT,
					"ubmem-error", ummu);
	if (ret < 0)
		dev_warn(ummu->dev, "failed to enable ubmem-error irq\n");
}

static void ubmem_mmu_setup_msis(struct ummu_device *ummu)
{
	struct device *dev = ummu->dev;

	if (!(ummu->cap.features & UMMU_FEAT_MSI))
		return;

	if (!dev->msi.domain)
		return;

	/* Clear the MSI address regs */
	writeq_relaxed(0, ummu->base + RESERVED_MSI_ADDR);
}

static struct ubmem_mmu_device *get_ubmem_mmu_from_fwnode(struct fwnode_handle *handle)
{
	struct ubmem_mmu_device *entry, *ubmem_mmu = NULL;

	list_for_each_entry(entry, &ubmem_device_list, list) {
		if (entry->ummu_core.iommu.fwnode == handle) {
			ubmem_mmu = entry;
			break;
		}
	}

	if (!ubmem_mmu)
		pr_err("can not find ubmem_mmu from fwnode\n");

	return ubmem_mmu;
}

static void mmu_domain_cfg_clear(struct ubmem_mmu_domain *dom)
{
	dom->granule = ummu_get_ubm_granule();
	dom->iova_start = 0;
	dom->iova_len = 0;
	dom->ate_count = 0;
	dom->ate_index_start = 0;
}

static int ubmem_mmu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct ubmem_mmu_domain *mmu_domain = to_ubmem_mmu_domain(domain);
	struct ubmem_mmu_device *mmu_device =
		((struct ubmem_master *)dev_iommu_priv_get(dev))->ubmem_dev;
	struct maple_tree *mtree;
	struct ummu_tid_param param;
	u32 tid;
	int ret;

	if (mmu_domain->mmu) {
		dev_err(dev, "attach failed, the domain has been occupied.\n");
		return -EEXIST;
	}
	if (!mmu_device) {
		dev_err(dev, "attach failed, can't find the ubmem device.\n");
		return -ENODEV;
	}

	mtree = kzalloc(sizeof(*mtree), GFP_KERNEL);
	if (!mtree)
		return -ENOMEM;
	param.device = dev;
	ret = ummu_core_alloc_tid(&mmu_device->ummu_core, &param, &tid);
	if (ret) {
		dev_err(dev, "alloc tid failed, ret = %d.", ret);
		kfree(mtree);
		return ret;
	}

	mt_init_flags(mtree, MT_FLAGS_ALLOC_RANGE);
	mmu_domain->cached_pa_list = mtree;
	mmu_domain->base_domain.tid = tid;
	mmu_domain->mmu = mmu_device;
	mmu_domain_cfg_clear(mmu_domain);

	return 0;
}

static void write_ate_entries(struct ubmem_mmu_domain *dom,
			      struct ubmem_mmu_device *mdev)
{
	struct maple_tree *mt = (struct maple_tree *)dom->cached_pa_list;
	unsigned long granule_size;
	u32 cnt, reg, i, index;
	phys_addr_t start_addr;
	struct pa_info *info;

	MA_STATE(mas, mt, 0, 0);
	index = dom->ate_index_start;
	granule_size = 1UL << (dom->granule + SZ_2M_SHIFT);
	mas_for_each(&mas, info, ULONG_MAX) {
		start_addr = info->paddr;
		cnt = info->size / granule_size;
		for (i = 0; i < cnt; i++) {
			reg = (start_addr & PHYS_ADDR_MASK) >> SZ_2M_SHIFT;
			writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_start_addr);

			reg = MEM_TYPE_MASK | MEM_WR_MASK | MEM_VLD_MASK;
			reg |= (index++) & MEM_ATE_INDEX_MASK;
			writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_index);
			start_addr += granule_size;
		}
	}
}

static void write_pte_entry(struct ubmem_mmu_domain *dom,
			    struct ubmem_mmu_device *mdev)
{
	u32 reg;

	reg = (dom->iova_start & IOVA_MASK) >> SZ_2M_SHIFT;
	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_start_addr);

	reg = FIELD_PREP(MEM_GRANU_MASK, dom->granule);
	reg |= FIELD_PREP(MEM_LEN_MASK, dom->ate_count - 1);
	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_len_granu);

	reg = FIELD_PREP(MEM_BTE_MASK, dom->ate_index_start);
	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_bte);

	reg = MEM_WR_MASK | MEM_VLD_MASK;
	reg |= FIELD_PREP(MEM_PTE_INDEX_MASK, dom->base_domain.tid);
	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_index);
}

static void clear_pte_entry(struct ubmem_mmu_domain *dom,
			    struct ubmem_mmu_device *mdev)
{
	u32 reg = MEM_WR_MASK;

	reg |= FIELD_PREP(MEM_PTE_INDEX_MASK, dom->base_domain.tid);
	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_index);
}

static void ubmem_mmu_flush_dtlb(struct ubmem_mmu_device *mdev)
{
	u32 reg = MEM_DTLB_INVLD_MASK;

	writel_relaxed(reg, mdev->base + mdev->reg_offset->mem_dtlb_invld);
}

static int alloc_and_fill_entry(struct ubmem_mmu_domain *dom)
{
	struct ubmem_mmu_device *mdev = dom->mmu;
	unsigned long start;

	guard(spinlock)(&mdev->pte_lock);
	start = bitmap_find_next_zero_area(
		mdev->ate_bitmap, 1UL << mdev->ate_bits, 0, dom->ate_count, 0);
	if (start > (1UL << mdev->ate_bits)) {
		pr_err("find space in bitmap failed.\n");
		return -ENOSPC;
	}
	bitmap_set(mdev->ate_bitmap, start, dom->ate_count);
	dom->ate_index_start = start;

	write_ate_entries(dom, mdev);
	write_pte_entry(dom, mdev);

	return 0;
}

static void free_and_inv_entry(struct ubmem_mmu_domain *dom)
{
	struct ubmem_mmu_device *mdev = dom->mmu;

	spin_lock(&mdev->pte_lock);
	clear_pte_entry(dom, mdev);
	spin_unlock(&mdev->pte_lock);

	/* need sleep 10us before flush DTLB, worst 15us. */
	usleep_range(10, 15);

	spin_lock(&mdev->pte_lock);
	ubmem_mmu_flush_dtlb(mdev);
	bitmap_clear(mdev->ate_bitmap, dom->ate_index_start, dom->ate_count);
	spin_unlock(&mdev->pte_lock);
}

static int ubmem_mmu_map_pages(struct iommu_domain *domain, unsigned long iova,
			       phys_addr_t paddr, size_t pgsize, size_t pgcount,
			       int prot, gfp_t gfp, size_t *mapped)
{
	struct ubmem_mmu_domain *mdom = to_ubmem_mmu_domain(domain);
	struct maple_tree *mt;
	struct pa_info *info;
	unsigned long size;
	int ret;

	guard(mutex)(&mdom->map_lock);
	if (mdom->pte_valid) {
		pr_err("unexpected map pages when pte is valid!\n");
		return -EEXIST;
	}

	size = pgsize * pgcount;
	if (!IS_ALIGNED(paddr | size, (1UL << mdom->granule) * SZ_2M)) {
		pr_err("paddr size unaligned: pgsize = 0x%zx, pgcount = 0x%zx, granule = 0x%lx.\n",
		       pgsize, pgcount, mdom->granule);
		return -EINVAL;
	}

	/* if no access, then nothing to do */
	if (!((u32)prot & (IOMMU_READ | IOMMU_WRITE))) {
		pr_err("map_pages without permission failed.\n");
		return -EACCES;
	}

	info = kzalloc(sizeof(struct pa_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->paddr = paddr;
	info->size = size;
	mt = (struct maple_tree *)mdom->cached_pa_list;
	ret = mtree_insert_range(mt, iova, iova + size - 1, info, gfp);
	if (ret) {
		pr_err("insert phys addr info failed, ret = %d.\n", ret);
		kfree(info);
		return ret;
	}

	mdom->iova_len += size;
	*mapped = size;

	return ret;
}

static void clear_cached_pa_list(struct maple_tree *mt)
{
	MA_STATE(mas, mt, 0, 0);
	struct pa_info *info;

	if (mtree_empty(mt))
		goto destroy;

	mas_for_each(&mas, info, ULONG_MAX)
		kfree(info);

destroy:
	mtree_destroy(mt);
}

static size_t ubmem_mmu_unmap_pages(struct iommu_domain *domain,
				    unsigned long iova, size_t pgsize,
				    size_t pgcount,
				    struct iommu_iotlb_gather *gather)
{
	struct ubmem_mmu_domain *mdom = to_ubmem_mmu_domain(domain);
	struct maple_tree *mt = (struct maple_tree *)mdom->cached_pa_list;
	unsigned long unmapped = 0;
	struct pa_info *info;

	MA_STATE(mas, mt, 0, 0);
	guard(mutex)(&mdom->map_lock);
	if (!mdom->pte_valid && mdom->iova_len == 0) {
		pr_err("unmap_pages without map_pages failed.\n");
		return 0;
	}

	info = (struct pa_info *)mas_find_range(&mas, ULONG_MAX);
	if (!info) {
		pr_err("unmap_pages with empty cached_pa_list failed.\n");
		return 0;
	} else if (iova != mas.index) {
		pr_err("find same iova range to unmap_pages failed.\n");
		return 0;
	}

	if (mdom->pte_valid) {
		free_and_inv_entry(mdom);
		mdom->pte_valid = false;
	}

	unmapped = mdom->iova_len;
	clear_cached_pa_list(mt);
	mmu_domain_cfg_clear(mdom);

	return unmapped;
}

static int ubmem_mmu_iotlb_sync_map(struct iommu_domain *domain,
				    unsigned long iova, size_t size)
{
	struct ubmem_mmu_domain *mdom = to_ubmem_mmu_domain(domain);
	struct maple_tree *mt = (struct maple_tree *)mdom->cached_pa_list;
	struct pa_info *info;
	int ret;

	MA_STATE(mas, mt, 0, 0);
	guard(mutex)(&mdom->map_lock);
	if (mdom->pte_valid) {
		pr_err("sync_map with protection entry valid failed!\n");
		return -EBUSY;
	}

	info = (struct pa_info *)mas_find_range(&mas, ULONG_MAX);
	if (!info) {
		pr_err("sync_map with empty cached_pa_list failed.\n");
		return -EINVAL;
	}
	mdom->iova_start = mas.index;

	/* make sure the iova in the cached_pa_list is strictly continuous. */
	mas_reset(&mas);
	ret = mas_empty_area(&mas, mdom->iova_start,
			     mdom->iova_start + mdom->iova_len - 1, 1);
	if (iova != mdom->iova_start || size != mdom->iova_len || !ret) {
		pr_err("match the iova with cached_pa_list failed.\n");
		return -EINVAL;
	}

	mdom->ate_count = mdom->iova_len >> (mdom->granule + SZ_2M_SHIFT);
	ret = alloc_and_fill_entry(mdom);
	if (ret)
		return ret;

	mdom->pte_valid = true;

	return 0;
}

static void ubmem_mmu_domain_free(struct iommu_domain *domain)
{
	struct ubmem_mmu_domain *mmu_domain = to_ubmem_mmu_domain(domain);
	struct maple_tree *mt = (struct maple_tree *)mmu_domain->cached_pa_list;
	struct ubmem_mmu_device *mmu_device = mmu_domain->mmu;

	if (!mmu_device) {
		pr_err("cannot find domain related ubmem-mmu.\n");
		goto free_domain;
	}
	if (mmu_domain->pte_valid)
		free_and_inv_entry(mmu_domain);

	ummu_core_free_tid(&mmu_device->ummu_core,
					mmu_domain->base_domain.tid);

free_domain:
	if (mt) {
		clear_cached_pa_list(mt);
		kfree(mt);
	}
	mmu_domain->pte_valid = false;
	kfree(mmu_domain);
}

static struct ubmem_mmu_domain *ubmem_mmu_domain_alloc_helper(unsigned int type)
{
	struct ubmem_mmu_domain *ubmem_dom;

	ubmem_dom = kzalloc(sizeof(*ubmem_dom), GFP_KERNEL);
	if (!ubmem_dom)
		return NULL;

	mutex_init(&ubmem_dom->map_lock);
	ubmem_dom->base_domain.tid = UMMU_INVALID_TID;
	ubmem_dom->pte_valid = false;
	return ubmem_dom;
}

static struct iommu_domain *ubmem_mmu_domain_alloc(unsigned int type)
{
	struct ubmem_mmu_domain *ubmem_dom;

	switch (type) {
	case IOMMU_DOMAIN_DMA:
	case IOMMU_DOMAIN_DMA_FQ:
		ubmem_dom = ubmem_mmu_domain_alloc_helper(type);
		if (!ubmem_dom)
			return ERR_PTR(-ENOMEM);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return &ubmem_dom->base_domain.domain;
}

static struct iommu_device *ubmem_mmu_probe_device(struct device *dev)
{
	struct fwnode_handle *iommu_fwnode =
		dev_iommu_fwspec_get(dev)->iommu_fwnode;
	struct ubmem_mmu_device *ubmem_dev;
	struct ubmem_master *master;

	if (!iommu_fwnode)
		return ERR_PTR(-ENODEV);

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	ubmem_dev = get_ubmem_mmu_from_fwnode(iommu_fwnode);
	if (!ubmem_dev)
		goto free;

	master->ubmem_dev = ubmem_dev;
	dev_iommu_priv_set(dev, master);
	pr_debug("ubmem probe device %s successful!\n", dev_name(dev));
	return &ubmem_dev->ummu_core.iommu;

free:
	kfree(master);
	return NULL;
}

static void ubmem_mmu_release_device(struct device *dev)
{
	struct ubmem_master *master =
		(struct ubmem_master *)dev_iommu_priv_get(dev);

	dev_iommu_priv_set(dev, NULL);
	kfree(master);
}

static bool ubmem_mmu_tdev_support_attr(struct ummu_core_device *core_device,
					struct tdev_attr *attr)
{
	struct ubmem_mmu_device *ubmem_dev = core_to_ubmem_mmu_dev(core_device);
	struct hisi_ummu_tdev_info *info;
	struct ubrt_fwnode *ubrt_fw;
	u32 index;

	if (!attr || !attr->priv ||
		attr->priv_len < sizeof(struct hisi_ummu_tdev_info))
		return false;

	info = (struct hisi_ummu_tdev_info *)attr->priv;
	if (!info->v1.on_chip || !info->v1.ummu_idx_mask) {
		dev_err(ubmem_dev->ummu.dev, "tdev_info is invalid.\n");
		return false;
	}

	index = __ffs(info->v1.ummu_idx_mask);
	ubrt_fw = ubrt_fwnode_get_by_idx(index, UBRT_UMMU);
	if (!ubrt_fw) {
		dev_err(ubmem_dev->ummu.dev, "get ubrt fw failed, index = %u.\n",
			index);
		return false;
	}

	return (ubrt_fw == ubrt_fwnode_get(ubmem_dev->ummu.dev->fwnode));
}

static struct ummu_core_ops ubmm_mmu_core_ops = {
	.tdev_support_attr = ubmem_mmu_tdev_support_attr,
};

static struct iommu_group *ubmem_mmu_device_group(struct device *dev)
{
	return generic_device_group(dev);
}

static struct iommu_domain_ops ubmm_mmu_domain_ops = {
	.attach_dev = ubmem_mmu_attach_dev,
	.map_pages = ubmem_mmu_map_pages,
	.unmap_pages = ubmem_mmu_unmap_pages,
	.iotlb_sync_map = ubmem_mmu_iotlb_sync_map,
	.free = ubmem_mmu_domain_free,
};

static struct iommu_ops ubmm_mmu_iommu_ops = {
	.domain_alloc = ubmem_mmu_domain_alloc,
	.probe_device = ubmem_mmu_probe_device,
	.release_device = ubmem_mmu_release_device,
	.device_group = ubmem_mmu_device_group,
	.default_domain_ops = &ubmm_mmu_domain_ops,
	.pgsize_bitmap = -1UL,
	.owner = THIS_MODULE,
};

static int umau_tab_init(struct ubmem_mmu_device *mmu)
{
	u32 reg_PTB, reg_TTB;
	int ret;

	writel_relaxed(PTB_INIT_EN, mmu->base + UMAU_MEM_TAB_INIT_EN_PROT);
	writel_relaxed(TTB_INTI_EN, mmu->base + UMAU_MEM_TAB_INIT_EN_TRANS);

	ret = readl_relaxed_poll_timeout(mmu->base + UMAU_MEM_TAB_INIT_DONE_PROT, reg_PTB,
					 reg_PTB & PTB_INIT_DONE, 1, UMMU_QUE_POLL_TIMEOUT_US);
	if (ret)
		return -EBUSY;

	ret = readl_relaxed_poll_timeout(mmu->base + UMAU_MEM_TAB_INIT_DONE_TRANS, reg_TTB,
					 reg_TTB & TTB_INIT_DONE, 1, UMMU_QUE_POLL_TIMEOUT_US);
	if (ret)
		return -EBUSY;

	return 0;
}

static int ubmem_mmu_init(struct platform_device *pdev,
			  struct ubmem_mmu_info *info,
			  struct ubmem_mmu_device *mmu)
{
	struct resource *res;
	int ret;

	mmu->base = devm_ioremap(&pdev->dev, info->reg_base, info->reg_size);
	if (!mmu->base)
		return -ENOMEM;

	if (mmu->ummu.cap.options & UMMU_OPT_UMAU) {
		mmu->dfx_base = NULL;
		mmu->reg_offset = &reg_umau_v2;
		ret = umau_tab_init(mmu);
		if (ret)
			return ret;
	} else {
		res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
		if (res == NULL)
			return -ENODEV;

		mmu->dfx_base = devm_ioremap(&pdev->dev, res->start, UMMU_UBIF_MEM_SZ);
		if (!mmu->dfx_base) {
			dev_err(&pdev->dev, "dfx resources map failed.\n");
			return -ENOMEM;
		}
		mmu->reg_offset = &reg_v1;
	}

	mmu->ate_bits = info->cap1;
	mmu->ate_bitmap = bitmap_zalloc(1UL << mmu->ate_bits, GFP_KERNEL);
	if (!mmu->ate_bitmap) {
		dev_err(&pdev->dev, "allocate ate bitmap failed.\n");
		return -ENOMEM;
	}

	mmu->token_id_bits = info->cap0;

	return 0;
}

static int register_to_ummu_core(struct platform_device *pdev, struct ubmem_mmu_device *mmu)
{
	struct ummu_core_init_args args = {0};
	int ret;

	args.iommu_ops = &ubmm_mmu_iommu_ops;
	args.hwdev = &pdev->dev;
	args.tid_args.tid_ops = ummu_core_tid_ops[DEFAULT_OPS];
	args.tid_args.max_tid = (1 << (mmu->token_id_bits)) - 1;
	args.tid_args.min_tid = 0;
	args.core_ops = &ubmm_mmu_core_ops;

	ret = ummu_core_device_init(&mmu->ummu_core, &args);
	if (ret) {
		pr_err("init ummu core device failed, ret=%d\n", ret);
		return ret;
	}
	ret = ummu_core_device_register(&mmu->ummu_core, REGISTER_TYPE_NORMAL);
	if (ret) {
		pr_err("register to ummu core failed, ret=%d\n", ret);
		ummu_core_device_deinit(&mmu->ummu_core);
	} else {
		list_add_tail(&mmu->list, &ubmem_device_list);
	}
	return ret;
}

static int ubmem_mmu_device_probe(struct ummu_device *ummu)
{
	struct platform_device *pdev = to_platform_device(ummu->dev);
	struct ubmem_mmu_info *info;
	struct ubmem_mmu_device *mmu;
	struct iommu_device *iommu;
	int ret;

	info = (struct ubmem_mmu_info *)pdev->dev.platform_data;
	mmu = (struct ubmem_mmu_device *)to_ubmem_mmu_dev(ummu);
	ret = ubmem_mmu_init(pdev, info, mmu);
	if (ret)
		goto exit_err;

	iommu = &mmu->ummu_core.iommu;
	ret = iommu_device_sysfs_add(iommu, &pdev->dev, NULL, "ubmem-mmu.%s",
				     dev_name(&pdev->dev));
	if (ret)
		goto exit_mmu_init;

	ret = register_to_ummu_core(pdev, mmu);
	if (ret)
		goto remove_sysfs;

	mmu->dev = &pdev->dev;
	ubmm_mmu_iommu_ops.pgsize_bitmap = SZ_4K | SZ_2M | SZ_4M | SZ_8M |
					   SZ_16M | SZ_32M | SZ_64M | SZ_128M |
					   SZ_256M;

	return 0;

remove_sysfs:
	iommu_device_sysfs_remove(iommu);
exit_mmu_init:
	bitmap_free(mmu->ate_bitmap);
exit_err:
	return -ENODEV;
}

static void ubmem_mmu_device_remove(struct ummu_device *ummu)
{
	struct ubmem_mmu_device *mmu = to_ubmem_mmu_dev(ummu);

	if (!mmu->ate_bitmap)
		return;

	ummu_core_device_unregister(&mmu->ummu_core);
	ummu_core_device_deinit(&mmu->ummu_core);
	iommu_device_sysfs_remove(&mmu->ummu_core.iommu);
	bitmap_free(mmu->ate_bitmap);
}

struct ummu_device *ubmem_mmu_impl_init(struct ummu_device *ummu)
{
	struct platform_device *pdev = to_platform_device(ummu->dev);
	struct ubmem_mmu_device *ubmem_mmu;
	struct device *dev = ummu->dev;
	struct ubmem_mmu_info *info;

	/* bit0: protection table, bit1: translation table, bit2:ubmem reg base */
	info = (struct ubmem_mmu_info *)pdev->dev.platform_data;
	if (!info || (info->valid & UBMEM_VALID_MASK) != UBMEM_VALID_VALUE)
		return ummu;

	pr_info("valid = 0x%llx, cap0 = 0x%x, cap1 = 0x%x.\n",
		info->valid, info->cap0, info->cap1);
	ubmem_mmu = devm_krealloc(dev, ummu, sizeof(*ubmem_mmu), GFP_KERNEL | __GFP_ZERO);
	if (!ubmem_mmu)
		return ERR_PTR(-ENOMEM);

	ubmem_mmu->ummu.impl_ops->write_msi_msg = ubmem_mmu_write_msi_msg;
	ubmem_mmu->ummu.impl_ops->set_msis = ubmem_mmu_setup_msis;
	ubmem_mmu->ummu.impl_ops->setup_irqs = ubmem_mmu_setup_irq;
	ubmem_mmu->ummu.impl_ops->dev_probe = ubmem_mmu_device_probe;
	ubmem_mmu->ummu.impl_ops->dev_remove = ubmem_mmu_device_remove;

	return &ubmem_mmu->ummu;
}
