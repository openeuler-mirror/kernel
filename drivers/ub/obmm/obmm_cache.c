// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 */

#include <linux/pgtable.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/pagewalk.h>
#include <linux/hugetlb.h>
#include <linux/jiffies.h>

#include <ub/ubus/ub-mem-decoder.h>

#include "obmm_core.h"
#include "obmm_export_region_ops.h"
#include "obmm_import.h"
#include "obmm_cache.h"

static bool skip_cache_maintain;
module_param(skip_cache_maintain, bool, 0444);
MODULE_PARM_DESC(skip_cache_maintain,
		 "Whether to skip cache maintain operation (to suppress errors in simulations).");

#define UB_MEM_DRAIN_TMOUT_MSEC 1000

int ub_write_queue_flush(uint32_t scna)
{
	unsigned long ub_mem_drain_timeout = jiffies + msecs_to_jiffies(UB_MEM_DRAIN_TMOUT_MSEC);

	pr_debug("call external: ub_mem_drain(scna=%#x)\n", scna);

	ub_mem_drain_start(scna);
	while (!ub_mem_drain_state(scna)) {
		if (time_after(jiffies, ub_mem_drain_timeout)) {
			pr_err("ub_mem_drain not completed within %d msecs\n",
			       UB_MEM_DRAIN_TMOUT_MSEC);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}

	pr_debug("external called: ub_mem_drain\n");
	return 0;
}

#define MAX_FLUSH_SIZE (1UL << 30)
/* the flush_cache_by_pa will yield CPU */
#define MAX_RESCHED_ROUND 10
#define CACHE_FLUSH_RETRY_MS 10
int flush_cache_by_pa(phys_addr_t addr, size_t size, unsigned long cache_ops)
{
	static DEFINE_SEMAPHORE(sem, 1);
	static const enum hisi_soc_cache_maint_type hisi_maint_type[] = {
		/* OBMM_SHM_CACHE_NONE does not have a maintenance type */
		[OBMM_SHM_CACHE_NONE] = HISI_CACHE_MAINT_MAX,
		[OBMM_SHM_CACHE_INVAL] = HISI_CACHE_MAINT_MAKEINVALID,
		[OBMM_SHM_CACHE_WB_INVAL] = HISI_CACHE_MAINT_CLEANINVALID,
		[OBMM_SHM_CACHE_WB_ONLY] = HISI_CACHE_MAINT_CLEANSHARED,
	};

	phys_addr_t curr_addr = addr;
	size_t remain_size = size;
	int ret = 0, round_to_resched = MAX_RESCHED_ROUND;
	enum hisi_soc_cache_maint_type maint_type = hisi_maint_type[cache_ops];

	if (skip_cache_maintain) {
		pr_debug_ratelimited("cache maintenance request {cache_ops=%lu}.\n", cache_ops);
		return 0;
	}

	if (!obmm_is_valid_cache_ops(cache_ops))
		return -EINVAL;

	down(&sem);
	while (remain_size != 0) {
		size_t flush_size;

		flush_size = remain_size <= MAX_FLUSH_SIZE ? remain_size : MAX_FLUSH_SIZE;

		/* retry if there is contention over hardware */
		while (true) {
			pr_debug("call external: hisi_soc_cache_maintain(0x%llx, 0x%zx, %u)\n",
				 curr_addr, flush_size, maint_type);
			ret = hisi_soc_cache_maintain(curr_addr, flush_size, maint_type);
			pr_debug("external called: hisi_soc_cache_maintain(), ret=%pe\n",
				 ERR_PTR(ret));

			if (ret != -EBUSY)
				break;
			pr_warn_once("Racing access of cache flushing hardware identified. The performance of UB memory may significantly degrade.\n");
			msleep(CACHE_FLUSH_RETRY_MS);
		}
		if (ret)
			break;

		curr_addr += flush_size;
		remain_size -= flush_size;
		if (--round_to_resched == 0) {
			cond_resched();
			round_to_resched = MAX_RESCHED_ROUND;
		}
	}
	up(&sem);

	if (remain_size != 0)
		pr_warn("%s: 0x%zx@0x%llx not flushed due to unexpected error; ret=%pe.\n",
			__func__, remain_size, curr_addr, ERR_PTR(ret));

	return ret;
}

int obmm_region_flush_range(struct obmm_region *reg, unsigned long offset, unsigned long length,
			    uint8_t cache_ops)
{
	int ret;
	struct obmm_import_region *i_reg;
	struct obmm_export_region *e_reg;

	/* validation */
	if (!obmm_is_valid_cache_ops(cache_ops))
		return -EINVAL;
	if (offset >= reg->mem_size || length > reg->mem_size - offset ||
		!IS_ALIGNED(offset, PAGE_SIZE) || !IS_ALIGNED(length, PAGE_SIZE)) {
		pr_err("invalid flush range for region=%d: offset=0x%lx, flush_length=0x%lx, region_length=0x%llx\n",
			reg->regionid, offset, length, reg->mem_size);
		return -EINVAL;
	}

	if (cache_ops == OBMM_SHM_CACHE_NONE)
		return 0;
	pr_debug("flush cache: region=%d, offset=0x%lx, length=0x%lx, cache_ops=%u\n",
		 reg->regionid, offset, length, cache_ops);
	/* clear cache and ubus queue */
	if (reg->type == OBMM_IMPORT_REGION) {
		i_reg = container_of(reg, struct obmm_import_region, region);
		ret = flush_import_region(i_reg, offset, length, cache_ops);
	} else {
		e_reg = container_of(reg, struct obmm_export_region, region);
		ret = flush_export_region(e_reg, offset, length, cache_ops);
	}

	if (ret)
		pr_err("flush failed: region=%d, offset=0x%lx, length=0x%lx, cache_ops=%u\n",
			reg->regionid, offset, length, cache_ops);
	else
		pr_debug("cache successfully flushed.\n");
	return ret;
}

/* flush the entire process address space */
void obmm_flush_tlb(struct mm_struct *mm)
{
	unsigned long asid;

	dsb(ishst);
	asid = __TLBI_VADDR(0, ASID(mm));
	__tlbi(aside1is, asid);
	__tlbi_user(aside1is, asid);
	dsb(ish);
}

struct modify_info {
	int pmd_cnt;
	int pte_cnt;
	int pmd_leaf_cnt;
	int hugetlb_cnt;
	bool cacheable;
};

static int modify_hugetlb_prot(pte_t *pte, unsigned long hmask __always_unused,
			       unsigned long addr __always_unused,
			       unsigned long next __always_unused, struct mm_walk *walk)
{
	struct modify_info *info = (struct modify_info *)walk->private;
	bool cacheable = info->cacheable;
	struct vm_area_struct *vma = walk->vma;
	spinlock_t *ptl;
	pgprot_t prot;
	pte_t entry;

	ptl = huge_pte_lock(hstate_vma(vma), walk->mm, pte);
	entry = ptep_get(pte);
	if (unlikely(!pte_present(entry))) {
		pr_warn("%s: addr = 0x%lx, pte not present\n", __func__, addr);
		spin_unlock(ptl);
		return 0;
	}

	info->hugetlb_cnt++;

	prot = cacheable ? pgprot_tagged(pte_pgprot(entry)) :
			   pgprot_writecombine(pte_pgprot(entry));
	entry = pte_modify(entry, prot);
	__set_pte(pte, entry);

	spin_unlock(ptl);
	return 0;
}

int modify_pgtable_prot(struct mm_struct *mm, void *va, size_t size, bool cacheable)
{
	struct modify_info info = { 0 };
	struct mm_walk_ops walk_ops = {
		.hugetlb_entry = modify_hugetlb_prot,
	};

	info.cacheable = cacheable;
	unsigned long start = (uintptr_t)va;
	unsigned long end = start + size;

	mmap_read_lock(mm);
	walk_page_range(mm, start, end, &walk_ops, &info);
	mmap_read_unlock(mm);
	obmm_flush_tlb(mm);

	return 0;
}
