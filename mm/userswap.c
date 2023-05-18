// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * userswap core file include swap-in and swap-out core function
 */

#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>

#include "internal.h"

int enable_userswap;

static void uswap_unmap_anon_page(struct mm_struct *mm,
				  struct vm_area_struct *vma,
				  unsigned long addr, struct page *page,
				  pmd_t *pmd, pte_t *old_pte)
{
	struct mmu_notifier_range range;
	spinlock_t *ptl;
	pte_t *pte;

	mmu_notifier_range_init(&range, MMU_NOTIFY_UNMAP, 0, vma,
				vma->vm_mm, addr, addr + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);
	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (pte_none(*pte))
		goto out_release_unlock;
	flush_cache_page(vma, addr, pte_pfn(*pte));
	*old_pte = ptep_clear_flush(vma, addr, pte);

	dec_mm_counter(mm, MM_ANONPAGES);
	reliable_page_counter(page, mm, -1);
	page_remove_rmap(page, false);

out_release_unlock:
	pte_unmap_unlock(pte, ptl);
	mmu_notifier_invalidate_range_end(&range);
	page->mapping = NULL;
}

static void uswap_map_anon_page(struct mm_struct *mm,
				struct vm_area_struct *vma,
				unsigned long addr,
				struct page *page,
				pmd_t *pmd,
				pte_t old_pte)
{
	spinlock_t *ptl;
	pte_t *pte;

	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	flush_cache_page(vma, addr, pte_pfn(*pte));
	set_pte_at(mm, addr, pte, old_pte);
	inc_mm_counter(mm, MM_ANONPAGES);
	reliable_page_counter(page, mm, 1);
	page_add_new_anon_rmap(page, vma, addr, false);
	pte_unmap_unlock(pte, ptl);
}

int mfill_atomic_pte_nocopy(struct mm_struct *mm,
			    pmd_t *dst_pmd,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr,
			    unsigned long src_addr)
{
	struct vm_area_struct *src_vma;
	pte_t dst_pte, *pte, src_pte;
	pmd_t *src_pmd;
	spinlock_t *ptl;
	int ret = 0;
	struct page *page;

	src_vma = find_vma(mm, src_addr);
	if (!src_vma || src_addr < src_vma->vm_start)
		return -ENOENT;

	if (src_vma->vm_flags & VM_LOCKED)
		return -EINVAL;

	page = follow_page(src_vma, src_addr, FOLL_GET | FOLL_MIGRATION);
	if (!page)
		return -ENODEV;

	src_pmd = mm_find_pmd(mm, src_addr);
	if (!src_pmd) {
		ret = -ENXIO;
		goto out_put_page;
	}
	uswap_unmap_anon_page(mm, src_vma, src_addr, page, src_pmd, &src_pte);

	if (dst_vma->vm_flags & VM_USWAP)
		ClearPageDirty(page);
	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__SetPageUptodate(page);

	dst_pte = mk_pte(page, dst_vma->vm_page_prot);
	if (dst_vma->vm_flags & VM_WRITE)
		dst_pte = pte_mkwrite(pte_mkdirty(dst_pte));
	if (dst_vma->vm_flags & VM_USWAP)
		dst_pte = pte_mkclean(dst_pte);

	pte = pte_offset_map_lock(mm, dst_pmd, dst_addr, &ptl);

	/*
	 * The userspace may swap in a large area. Part of the area is not
	 * swapped out. If concurrent execution, PTE may be present. Skip those
	 * pages (pte_present).
	 * No other scenes should be handled except first pagefault (pte_none)
	 * and after userswap out (SWP_USERSWAP_ENTRY).
	 */
	if (pte_present(*pte) || (!pte_none(*pte) &&
	    swp_type(pte_to_swp_entry(*pte)) != SWP_USERSWAP_ENTRY)) {
		pte_unmap_unlock(pte, ptl);
		uswap_map_anon_page(mm, src_vma, src_addr, page, src_pmd,
				    src_pte);
		ret = -EEXIST;
		goto out_put_page;
	}

	inc_mm_counter(mm, MM_ANONPAGES);
	reliable_page_counter(page, mm, 1);
	page_add_new_anon_rmap(page, dst_vma, dst_addr, false);
	set_pte_at(mm, dst_addr, pte, dst_pte);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(dst_vma, dst_addr, pte);
	pte_unmap_unlock(pte, ptl);

out_put_page:
	put_page(page);
	return ret;
}
