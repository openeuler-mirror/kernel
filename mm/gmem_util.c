// SPDX-License-Identifier: GPL-2.0-only
/*
 * GMEM physical memory management.
 *
 * Copyright (C) 2025- Huawei, Inc.
 * Author: Ni Cunshu, Wang bin
 *
 */

#include <linux/err.h>
#include <linux/khugepaged.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/pgalloc.h>
#include <linux/security.h>
#include <linux/vm_object.h>

#include "internal.h"
#include "gmem-internal.h"

#define GMEM_MMAP_RETRY_TIMES 10 /* gmem retry times before OOM */

static struct folio *__vma_alloc_anon_folio_pmd(struct vm_area_struct *vma,
		unsigned long addr, gfp_t gfp)
{
	const int order = HPAGE_PMD_ORDER;
	struct folio *folio;

	folio = vma_alloc_folio(gfp, order, vma, addr & HPAGE_PMD_MASK, true);

	if (unlikely(!folio)) {
		count_vm_event(THP_FAULT_FALLBACK);
		count_mthp_stat(order, MTHP_STAT_ANON_FAULT_FALLBACK);
		return NULL;
	}

	VM_BUG_ON_FOLIO(!folio_test_large(folio), folio);
	if (mem_cgroup_charge(folio, vma->vm_mm, gfp)) {
		folio_put(folio);
		count_vm_event(THP_FAULT_FALLBACK);
		count_vm_event(THP_FAULT_FALLBACK_CHARGE);
		count_mthp_stat(order, MTHP_STAT_ANON_FAULT_FALLBACK);
		count_mthp_stat(order, MTHP_STAT_ANON_FAULT_FALLBACK_CHARGE);
		return NULL;
	}
	folio_throttle_swaprate(folio, gfp);

	clear_huge_page(&folio->page, addr, HPAGE_PMD_NR);
	/*
	 * The memory barrier inside __folio_mark_uptodate makes sure that
	 * clear_huge_page writes become visible before the set_pmd_at()
	 * write.
	 */
	__folio_mark_uptodate(folio);
	return folio;
}

static void map_anon_folio_pmd(struct folio *folio, pmd_t *pmd,
		struct vm_area_struct *vma, unsigned long haddr)
{
	pmd_t entry;

	entry = mk_huge_pmd(&folio->page, vma->vm_page_prot);
	entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
	folio_add_new_anon_rmap(folio, vma, haddr, RMAP_EXCLUSIVE);
	folio_add_lru_vma(folio, vma);
	set_pmd_at(vma->vm_mm, haddr, pmd, entry);
	update_mmu_cache_pmd(vma, haddr, pmd);
	add_mm_counter(vma->vm_mm, MM_ANONPAGES, HPAGE_PMD_NR);
	count_vm_event(THP_FAULT_ALLOC);
	count_mthp_stat(HPAGE_PMD_ORDER, MTHP_STAT_ANON_FAULT_ALLOC);
	count_memcg_event_mm(vma->vm_mm, THP_FAULT_ALLOC);
}

vm_fault_t do_peer_shared_anonymous_page(struct vm_fault *vmf)
{
	unsigned long haddr = vmf->address & HPAGE_PMD_MASK;
	struct vm_area_struct *vma = vmf->vma;
	struct folio *folio = NULL;
	bool is_new_folio = false;
	pgtable_t pgtable = NULL;
	struct gm_mapping *gm_mapping;
	vm_fault_t ret = 0;

	if (!thp_vma_suitable_order(vma, haddr, PMD_ORDER))
		return VM_FAULT_FALLBACK;

	ret = vmf_anon_prepare(vmf);
	if (ret)
		return ret;

	gm_mapping = vma_prepare_gm_mapping(vma, haddr);
	if (!gm_mapping)
		return VM_FAULT_OOM;

	mutex_lock(&gm_mapping->lock);

	if (gm_mapping_device(gm_mapping) && gm_page_pinned(gm_mapping->gm_page)) {
		pr_err("page is pinned! addr is %lx\n", gm_mapping->gm_page->va);
		ret = VM_FAULT_SIGBUS;
		goto release;
	}

	if (gm_mapping_cpu(gm_mapping))
		folio = page_folio(gm_mapping->page);
	if (!folio) {
		folio = __vma_alloc_anon_folio_pmd(vma, haddr, GFP_TRANSHUGE);
		is_new_folio = true;
	}

	if (unlikely(!folio)) {
		ret = VM_FAULT_FALLBACK;
		goto release;
	}

	pgtable = pte_alloc_one(vma->vm_mm);
	if (unlikely(!pgtable)) {
		ret = VM_FAULT_OOM;
		goto release;
	}

	/**
	 * if page is mapped in device, release device mapping and
	 * deliver the page content to host.
	 */
	if (gm_mapping_device(gm_mapping)) {
		vmf->page = &folio->page;
		ret = gm_host_fault_locked(vmf, PMD_ORDER);
		if (ret)
			goto release;
	}

	/* map page in pgtable */
	vmf->ptl = pmd_lock(vma->vm_mm, vmf->pmd);

	if (!pmd_none(*vmf->pmd))
		goto unlock_release;
	ret = check_stable_address_space(vma->vm_mm);
	if (ret)
		goto unlock_release;
	pgtable_trans_huge_deposit(vma->vm_mm, vmf->pmd, pgtable);
	map_anon_folio_pmd(folio, vmf->pmd, vma, haddr);
	mm_inc_nr_ptes(vma->vm_mm);
	spin_unlock(vmf->ptl);

	/* finally setup cpu mapping */
	gm_mapping_flags_set(gm_mapping, GM_MAPPING_CPU);
	gm_mapping->page = &folio->page;
	mutex_unlock(&gm_mapping->lock);

	return 0;
unlock_release:
	spin_unlock(vmf->ptl);
release:
	if (pgtable)
		pte_free(vma->vm_mm, pgtable);
	if (is_new_folio)
		folio_put(folio);
	mutex_unlock(&gm_mapping->lock);
	return ret;
}

static int alloc_va_in_peer_devices(unsigned long addr, unsigned long len,
						unsigned long flag)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct gm_context *ctx, *tmp;
	unsigned long prot = VM_NONE;
	enum gm_ret gm_ret;
	int ret;

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start >= addr + len) {
		gmem_err("vma for addr %lx is NULL, should not happen\n", addr);
		return -EINVAL;
	}

	if (thp_disabled_by_hw() || vma_thp_disabled(vma, vma->vm_flags)) {
		gmem_err("transparent hugepage is not enabled\n");
		return -EINVAL;
	}

	prot |= vma->vm_flags;

	if (!mm->gm_as) {
		ret = gm_as_create(0, ULONG_MAX, GM_AS_ALLOC_DEFAULT, HPAGE_SIZE, &mm->gm_as);
		if (ret) {
			gmem_err("gm_as_create failed\n");
			return ret;
		}
	}

	ret = -ENODEV;
	list_for_each_entry_safe(ctx, tmp, &mm->gm_as->gm_ctx_list, gm_as_link) {
		struct gm_fault_t gmf = {
			.mm = mm,
			.dev = ctx->dev,
			.va = addr,
			.size = len,
			.prot = prot,
		};

		if (!ctx->dev->mmu->peer_va_alloc_fixed) {
			gmem_err("gmem: mmu ops has no alloc_vma\n");
			continue;
		}

		gm_ret = ctx->dev->mmu->peer_va_alloc_fixed(&gmf);
		if (gm_ret != GM_RET_SUCCESS) {
			gmem_err("device mmap failed\n");
			if (gm_ret == GM_RET_NOMEM)
				ret = -ENOMEM;
			return ret;
		}
		ret = 0;
	}

	if (ret == 0 && !vma->vm_obj) {
		vma->vm_obj = vm_object_create(vma);
		if (!vma->vm_obj)
			return -ENOMEM;
	}

	return ret;
}

struct gmem_vma_list {
	unsigned long start;
	size_t len;
	struct list_head list;
};

static void gmem_reserve_vma(struct mm_struct *mm, unsigned long start,
				size_t len, struct list_head *head)
{
	struct vm_area_struct *vma;
	struct gmem_vma_list *node = kmalloc(sizeof(struct gmem_vma_list), GFP_KERNEL);

	vma = find_vma(mm, start);
	if (!vma || vma->vm_start >= start + len) {
		kfree(node);
		return;
	}
	vm_flags_clear(vma, VM_PEER_SHARED);

	node->start = start;
	node->len = round_up(len, SZ_2M);
	list_add_tail(&node->list, head);
}

static void gmem_release_vma(struct mm_struct *mm, struct list_head *head)
{
	struct gmem_vma_list *node, *next;

	list_for_each_entry_safe(node, next, head, list) {
		unsigned long start = node->start;
		size_t len = node->len;

		if (len)
			vm_munmap(start, len);

		list_del(&node->list);
		kfree(node);
	}
}

unsigned long gm_vm_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;
	unsigned long populate;
	LIST_HEAD(uf);
	int error = 0;
	LIST_HEAD(reserve_list);
	unsigned int retry_times = 0;

retry:
	ret = security_mmap_file(file, prot, flag);
	if (!ret) {
		if (mmap_write_lock_killable(mm)) {
			gmem_release_vma(mm, &reserve_list);
			return -EINTR;
		}
		ret = do_mmap(file, addr, len, prot, flag, 0, pgoff, &populate, &uf);
		mmap_write_unlock(mm);

		if (populate)
			mm_populate(ret, populate);
	}

	if (!IS_ERR_VALUE(ret)) {
		error = alloc_va_in_peer_devices(ret, len, flag);
		/**
		 * if alloc_va_in_peer_devices failed
		 * add vma to reserve_list and release after find a proper vma
		 */
		if (error == -ENOMEM && retry_times < GMEM_MMAP_RETRY_TIMES) {
			retry_times++;
			gmem_reserve_vma(mm, ret, len, &reserve_list);
			goto retry;
		} else if (error != 0) {
			gmem_err("alloc vma ret %d\n", error);
			gmem_reserve_vma(mm, ret, len, &reserve_list);
			ret = -ENOMEM;
		}
		gmem_release_vma(mm, &reserve_list);
	}

	return ret;
}

static void munmap_single_vma_in_peer_devices(struct mm_struct *mm, struct vm_area_struct *vma,
					      unsigned long start_addr, unsigned long end_addr)
{
	unsigned long start, end, addr;
	struct vm_object *obj = vma->vm_obj;
	enum gm_ret ret;
	struct gm_context *ctx, *tmp;
	struct gm_mapping *gm_mapping;
	struct hnode *hnode;
	struct gm_fault_t gmf = {
		.mm = mm,
		.copy = false,
	};

	start = max(vma->vm_start, start_addr);
	if (start >= vma->vm_end)
		return;
	addr = start;
	end = min(vma->vm_end, end_addr);
	if (end <= vma->vm_start)
		return;

	if (!obj)
		return;

	if (!mm->gm_as)
		return;

	do {
		xa_lock(obj->logical_page_table);
		gm_mapping = vm_object_lookup(obj, addr);
		if (!gm_mapping) {
			xa_unlock(obj->logical_page_table);
			continue;
		}
		xa_unlock(obj->logical_page_table);

		mutex_lock(&gm_mapping->lock);
		if (!gm_mapping_device(gm_mapping)) {
			mutex_unlock(&gm_mapping->lock);
			continue;
		}

		gmf.va = addr;
		gmf.size = HPAGE_SIZE;
		gmf.pfn = gm_mapping->gm_page->dev_pfn;
		gmf.dev = gm_mapping->dev;
		ret = gm_mapping->dev->mmu->peer_unmap(&gmf);
		if (ret != GM_RET_SUCCESS)
			gmem_err("%s: call dev peer_unmap error %d", __func__, ret);

		/*
		 * Regardless of whether the gm_page is unmapped, we should release it.
		 */
		hnode = get_hnode(gm_mapping->gm_page->hnid);
		if (!hnode) {
			mutex_unlock(&gm_mapping->lock);
			continue;
		}
		gm_page_remove_rmap(gm_mapping->gm_page);
		hnode_activelist_del(hnode, gm_mapping->gm_page);
		hnode_active_pages_dec(hnode);
		put_gm_page(gm_mapping->gm_page);
		gm_mapping_flags_set(gm_mapping, GM_MAPPING_NOMAP);
		gm_mapping->gm_page = NULL;
		mutex_unlock(&gm_mapping->lock);
	} while (addr += HPAGE_SIZE, addr != end);

	list_for_each_entry_safe(ctx, tmp, &mm->gm_as->gm_ctx_list, gm_as_link) {
		if (!ctx->dev->mmu->peer_va_free)
			continue;

		gmf.va = start;
		gmf.size = end - start;
		gmf.dev = ctx->dev;

		ret = ctx->dev->mmu->peer_va_free(&gmf);
		if (ret != GM_RET_SUCCESS)
			gmem_err("gmem: free_vma failed, ret %d\n", ret);
	}
}

static void munmap_in_peer_devices(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct vm_area_struct *vma;

	VMA_ITERATOR(vmi, mm, start);
	for_each_vma_range(vmi, vma, end) {
		if (vma_is_peer_shared(vma))
			munmap_single_vma_in_peer_devices(mm, vma, start, end);
	}
}

unsigned long gmem_unmap_align(struct mm_struct *mm,
				unsigned long start, size_t len)
{
	struct vm_area_struct *vma, *vma_end;

	vma = find_vma_intersection(mm, start, start + len);
	vma_end = find_vma(mm, start + len);
	if (!vma || !vma_is_peer_shared(vma))
		return 0;
	if (vma_is_peer_shared(vma)) {
		if (!IS_ALIGNED(start, HPAGE_SIZE))
			return -EINVAL;
	}

	/* Prevents partial release of the peer_share page. */
	if (vma_end && vma_end->vm_start < (start + len) && vma_is_peer_shared(vma_end))
		len = round_up(len, SZ_2M);
	return len;
}

void gmem_unmap_region(struct mm_struct *mm, unsigned long start, size_t len)
{
	unsigned long end, ret;

	ret = gmem_unmap_align(mm, start, len);

	if (!ret || IS_ERR_VALUE(ret))
		return;

	end = start + ret;
	munmap_in_peer_devices(mm, start, end);
}

bool gm_mmap_check_flags(unsigned long flags)
{
	if (gmem_is_enabled()) {
		if ((flags & MAP_SHARED) && (flags & MAP_PEER_SHARED)) {
			gmem_err(" MAP_PEER_SHARED and MAP_SHARE cannot be used together.\n");
			return false;
		} else if ((flags & MAP_HUGETLB) && (flags & MAP_PEER_SHARED)) {
			gmem_err(" MAP_PEER_SHARED and MAP_HUGETLB cannot be used together.\n");
			return false;
		} else if (!(flags & MAP_ANONYMOUS) && (flags & MAP_PEER_SHARED)) {
			gmem_err(" MAP_PEER_SHARED cannot map file page.\n");
			return false;
		}
	}
	return true;
}

unsigned long
gm_get_unmapped_area_aligned(struct file *file, unsigned long addr, unsigned long len,
			  unsigned long pgoff, unsigned long flags)
{
	unsigned long align = HPAGE_SIZE;

	len = round_up(len, align);
	if (len > TASK_SIZE)
		return -ENOMEM;

	addr = current->mm->get_unmapped_area(file, addr, len + align, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = round_up(addr, align);
	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (!IS_ALIGNED(addr, align))
		return -EINVAL;

	return addr;
}

void destroy_gm_as(struct mm_struct *mm)
{
	if (mm->gm_as)
		gm_as_destroy(mm->gm_as);
}
