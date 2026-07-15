// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <linux/huge_mm.h>
#include <linux/mm_types.h>
#include <linux/mm_types_task.h>
#include <linux/rmap.h>
#include <linux/pgalloc.h>
#include <asm-generic/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable-hwdef.h>

#define CREATE_TRACE_POINTS
#include <trace/events/attach.h>

#ifndef PUD_SHIFT
#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n) ((PAGE_SHIFT - 3) * (4 - (n)) + 3)
#define PUD_SHIFT               ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
#endif

enum pgt_entry {
	NORMAL_PMD,
	HPAGE_PMD,
};

enum {
	IO_ATTACH	= 1,
	IO_MAX
};

struct zcopy_ioctl_pswap {
	unsigned long src_addr;
	unsigned long dst_addr;
	int src_pid;
	int dst_pid;
	unsigned long size;
};

struct zcopy_cdev {
	struct cdev chrdev;
	dev_t dev;
	int major;
	struct class *dev_class;
	struct device *dev_device;
};

static struct zcopy_cdev z_cdev;

static pte_t *(*__zcopy_pte_offset_map)(pmd_t *, unsigned long, pmd_t *);
static int (*__zcopy_pte_alloc)(struct mm_struct *, pmd_t *);
static int (*__zcopy_pmd_alloc)(struct mm_struct *, pud_t *, unsigned long);
static int (*__zcopy_pud_alloc)(struct mm_struct *, p4d_t *, unsigned long);
static unsigned long (*kallsyms_lookup_name_funcp)(const char *);
static void (*__zcopy_mmu_notifier_arch_invalidate_secondary_tlbs)(struct mm_struct *,
					unsigned long, unsigned long);

static struct kretprobe __kretprobe;

#if defined(CONFIG_SPLIT_PTE_PTLOCKS) && ALLOC_SPLIT_PTLOCKS
static struct kmem_cache *zcopy_page_ptl_cachep;
bool ptlock_alloc(struct ptdesc *ptdesc)
{
	spinlock_t *ptl;

	ptl = kmem_cache_alloc(zcopy_page_ptl_cachep, GFP_KERNEL);
	if (!ptl)
		return false;
	ptdesc->ptl = ptl;
	return true;
}

void ptlock_free(struct ptdesc *ptdesc)
{
	kmem_cache_free(zcopy_page_ptl_cachep, ptdesc->ptl);
}
#endif

static unsigned long __kprobe_lookup_name(const char *symbol_name)
{
	int ret;
	void *addr;

	__kretprobe.kp.symbol_name = symbol_name;
	ret = register_kretprobe(&__kretprobe);
	if (ret < 0)
		return 0;

	addr = __kretprobe.kp.addr;
	unregister_kretprobe(&__kretprobe);
	return (unsigned long)addr;
}

static inline unsigned long __kallsyms_lookup_name(const char *symbol_name)
{
	if (kallsyms_lookup_name_funcp == NULL)
		return 0;
	return kallsyms_lookup_name_funcp(symbol_name);
}

static inline pud_t *zcopy_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
									unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) &&
		__zcopy_pud_alloc(mm, p4d, address)) ? NULL : pud_offset(p4d, address);
}

static inline pmd_t *zcopy_pmd_alloc(struct mm_struct *mm, pud_t *pud,
						unsigned long address)
{
	return (unlikely(pud_none(*pud)) &&
		__zcopy_pmd_alloc(mm, pud, address)) ? NULL : pmd_offset(pud, address);
}

static inline bool zcopy_pte_alloc(struct mm_struct *mm, pmd_t *pmd)
{
	return unlikely(pmd_none(*pmd)) && __zcopy_pte_alloc(mm, pmd);
}

static inline pte_t *zcopy_pte_offset_map(pmd_t *pmd, unsigned long addr)
{
	return __zcopy_pte_offset_map(pmd, addr, NULL);
}

static inline void zcopy_flush_tlb_mm_range(struct mm_struct *mm,
				     unsigned long start, unsigned long end)
{
	unsigned long asid, pages;

	start = round_down(start, PAGE_SIZE);
	end = round_up(end, PAGE_SIZE);
	pages = (end - start) >> PAGE_SHIFT;

	if (__flush_tlb_range_limit_excess(start, end, pages, PAGE_SIZE)) {
		dsb(ishst);
		asid = __TLBI_VADDR(0, ASID(mm));
		__tlbi(aside1is, asid);
		__tlbi_user(aside1is, asid);
		dsb(ish);
		start = 0;
		end = -1UL;
		goto notifier;
	}

	dsb(ishst);
	asid = ASID(mm);

	__flush_tlb_range_op(vae1is, start, pages, PAGE_SIZE, asid, 0, true);

notifier:
	if (mm_has_notifiers(mm))
		__zcopy_mmu_notifier_arch_invalidate_secondary_tlbs(mm, start, end);
	dsb(ish);
}

static pud_t *zcopy_get_pud(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	if (!pud_table(*pud))
		return NULL;

	return pud;
}

static pmd_t *zcopy_get_pmd(struct mm_struct *mm, unsigned long addr)
{
	pud_t *pud;
	pmd_t *pmd;

	pud = zcopy_get_pud(mm, addr);
	if (!pud)
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static pud_t *zcopy_alloc_new_pud(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return NULL;

	return zcopy_pud_alloc(mm, p4d, addr);
}

static pmd_t *zcopy_alloc_pmd(struct mm_struct *mm, unsigned long addr, int *rc)
{
	pud_t *pud;
	pmd_t *pmd;

	*rc = -ENOMEM;
	pud = zcopy_alloc_new_pud(mm, addr);
	if (!pud)
		return NULL;

	pmd = zcopy_pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	if (pmd_trans_huge(*pmd)) {
		pr_warn_once("va mapped to hugepage, please free it and realloc va\n");
		*rc = -EAGAIN;
		return NULL;
	}

	return pmd;
}

static inline void zcopy_add_mm_counter(struct mm_struct *mm, int member, long value)
{
	struct percpu_counter *fbc = &mm->rss_stat[member];

	if (percpu_counter_initialized(fbc))
		percpu_counter_add(fbc, value);
	else
		percpu_counter_atomic_add(fbc, value);
}

static inline void zcopy_add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
	int i;

	if (current->mm == mm)
		sync_mm_rss(mm);
	for (i = 0; i < NR_MM_COUNTERS; i++)
		if (rss[i])
			zcopy_add_mm_counter(mm, i, rss[i]);
}

typedef int __bitwise fpb_t;
#define FPB_IGNORE_DIRTY		((__force fpb_t)BIT(0))
#define FPB_IGNORE_SOFT_DIRTY		((__force fpb_t)BIT(1))

static inline pte_t __pte_batch_clear_ignored(pte_t pte, fpb_t flags)
{
	if (flags & FPB_IGNORE_DIRTY)
		pte = pte_mkclean(pte);
	if (likely(flags & FPB_IGNORE_SOFT_DIRTY))
		pte = pte_clear_soft_dirty(pte);
	return pte_wrprotect(pte_mkold(pte));
}

static inline bool vma_soft_dirty_enabled(struct vm_area_struct *vma)
{
	if (!IS_ENABLED(CONFIG_MEM_SOFT_DIRTY))
		return false;

	return !(vma->vm_flags & VM_SOFTDIRTY);
}

static inline int folio_pte_batch(struct folio *folio, unsigned long addr,
		pte_t *start_ptep, pte_t pte, int max_nr, fpb_t flags)
{
	unsigned long folio_end_pfn = folio_pfn(folio) + folio_nr_pages(folio);
	const pte_t *end_ptep = start_ptep + max_nr;
	pte_t expected_pte, *ptep;
	int nr;

	VM_WARN_ON_FOLIO(!pte_present(pte), folio);
	VM_WARN_ON_FOLIO(!folio_test_large(folio) || max_nr < 1, folio);
	VM_WARN_ON_FOLIO(page_folio(pfn_to_page(pte_pfn(pte))) != folio, folio);

	nr = pte_batch_hint(start_ptep, pte);
	expected_pte = __pte_batch_clear_ignored(pte_advance_pfn(pte, nr), flags);
	ptep = start_ptep + nr;

	while (ptep < end_ptep) {
		pte = ptep_get(ptep);
		pte = __pte_batch_clear_ignored(pte, flags);

		if (!pte_same(pte, expected_pte))
			break;

		/*
		 * Stop immediately once we reached the end of the folio. In
		 * corner cases the next PFN might fall into a different folio.
		 */
		if (pte_pfn(pte) >= folio_end_pfn)
			break;

		nr = pte_batch_hint(ptep, pte);
		expected_pte = pte_advance_pfn(expected_pte, nr);
		ptep += nr;
	}

	return min(ptep - start_ptep, max_nr);
}

static __always_inline int zcopy_folio_try_dup_anon_rmap(struct folio *folio,
		struct page *page, int nr_pages, struct vm_area_struct *src_vma,
		enum rmap_level level)
{
	VM_WARN_ON_FOLIO(!folio_test_anon(folio), folio);
	__folio_rmap_sanity_checks(folio, page, nr_pages, level);

	switch (level) {
	case RMAP_LEVEL_PTE:
		if (!folio_test_large(folio)) {
			atomic_inc(&page->_mapcount);
			break;
		}

		do {
			atomic_inc(&page->_mapcount);
		} while (page++, --nr_pages > 0);
		break;
	case RMAP_LEVEL_PMD:
		atomic_inc(&folio->_entire_mapcount);
		break;
	}
	return 0;
}

static inline void zcopy_set_ptes(struct mm_struct *mm,
			      unsigned long __always_unused addr,
			      pte_t *ptep, pte_t pte, unsigned int nr)
{
	page_table_check_ptes_set(mm, ptep, pte, nr);
	if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
		__sync_icache_dcache(pte);

	for (;;) {
		__set_pte(ptep, pte);
		if (--nr == 0)
			break;
		ptep++;
		pte = pte_advance_pfn(pte, 1);
	}
}

static int attach_ptes(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
			pte_t *dst_ptep, pte_t *src_ptep, pte_t pte, unsigned long dst_addr,
			unsigned long src_addr, int max_nr, int *rss)
{
	struct page *src_page;
	struct folio *src_folio;
	fpb_t flags = 0;
	int nr;

	src_page = pte_page(pte);
	src_folio = page_folio(src_page);

	if (unlikely(folio_test_large(src_folio) && max_nr != 1)) {
		if (src_vma->vm_flags & VM_SHARED)
			flags |= FPB_IGNORE_DIRTY;
		if (!vma_soft_dirty_enabled(src_vma))
			flags |= FPB_IGNORE_SOFT_DIRTY;

		nr = folio_pte_batch(src_folio, src_addr, src_ptep, pte, max_nr, flags);

		folio_ref_add(src_folio, nr);
		if (unlikely(zcopy_folio_try_dup_anon_rmap(src_folio, src_page,
							  nr, src_vma, RMAP_LEVEL_PTE))) {
			folio_ref_sub(src_folio, nr);
			return -EAGAIN;
		}
		rss[MM_ANONPAGES] += nr;

		zcopy_set_ptes(dst_vma->vm_mm, dst_addr, dst_ptep, pte, nr);
		return nr;
	}

	folio_get(src_folio);
	if (unlikely(zcopy_folio_try_dup_anon_rmap(src_folio, src_page,
							1, src_vma, RMAP_LEVEL_PTE))) {
		folio_put(src_folio);
		return -EAGAIN;
	}
	rss[MM_ANONPAGES]++;

	zcopy_set_ptes(dst_vma->vm_mm, dst_addr, dst_ptep, pte, 1);
	return 1;
}

static int attach_pte_range(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
			unsigned long dst_addr, unsigned long src_addr, pmd_t *dst_pmdp,
			pmd_t *src_pmdp, unsigned long len)
{
	struct mm_struct *dst_mm = dst_vma->vm_mm;
	pte_t *src_ptep, *dst_ptep, pte, dst_pte;
	pte_t *orig_src_ptep, *orig_dst_ptep;
	spinlock_t *dst_ptl;
	int max_nr, ret, nr, i;
	int rss[NR_MM_COUNTERS];
	unsigned long src_addr_end = src_addr + len;

	if (!vma_is_anonymous(dst_vma) || !vma_is_anonymous(src_vma))
		return -EINVAL;

	memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);

	src_ptep = zcopy_pte_offset_map(src_pmdp, src_addr);
	dst_ptep = zcopy_pte_offset_map(dst_pmdp, dst_addr);
	dst_ptl = pte_lockptr(dst_mm, dst_pmdp);
	orig_src_ptep = src_ptep;
	orig_dst_ptep = dst_ptep;
	spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);

	do {
		nr = 1;

		/*
		 * For special pte, there may not be corresponding page. Hence,
		 * we skip this situation.
		 */
		pte = ptep_get(src_ptep);
		if (pte_none(pte) || pte_special(pte) || !pte_present(pte))
			continue;

		max_nr = (src_addr_end - src_addr) / PAGE_SIZE;
		/* check if there exists old mappings. */
		for (i = 0; i < max_nr; i++) {
			dst_pte = ptep_get(dst_ptep + i);
			if (!pte_none(dst_pte)) {
				ret = -EAGAIN;
				goto out;
			}
		}

		ret = attach_ptes(dst_vma, src_vma, dst_ptep, src_ptep, pte, dst_addr,
							src_addr, max_nr, rss);
		if (unlikely(ret == -EAGAIN))
			goto out;

		nr = ret;
	} while (src_ptep += nr, src_addr += PAGE_SIZE * nr, dst_ptep += nr,
		dst_addr += PAGE_SIZE * nr, src_addr != src_addr_end);

	zcopy_flush_tlb_mm_range(dst_vma->vm_mm, dst_addr, dst_addr + len);
	ret = 0;
out:
	zcopy_add_mm_rss_vec(dst_mm, rss);
	spin_unlock(dst_ptl);
	pte_unmap(orig_dst_ptep);
	pte_unmap(orig_src_ptep);
	return ret;
}

static __always_inline unsigned long get_extent(enum pgt_entry entry,
			unsigned long old_addr, unsigned long old_end,
			unsigned long new_addr)
{
	unsigned long next, extent, mask, size;

	switch (entry) {
	case HPAGE_PMD:
	case NORMAL_PMD:
		mask = PMD_MASK;
		size = PMD_SIZE;
		break;
	default:
		BUILD_BUG();
		break;
	}

	next = (old_addr + size) & mask;
	/* even if next overflowed, extent below will be ok */
	extent = next - old_addr;
	if (extent > old_end - old_addr)
		extent = old_end - old_addr;
	next = (new_addr + size) & mask;
	if (extent > next - new_addr)
		extent = next - new_addr;
	return extent;
}

static void zcopy_pgtable_trans_huge_deposit(struct mm_struct *mm, pmd_t *pmdp,
				pgtable_t pgtable)
{
	assert_spin_locked(pmd_lockptr(mm, pmdp));

	/* FIFO */
	if (!pmd_huge_pte(mm, pmdp))
		INIT_LIST_HEAD(&pgtable->lru);
	else
		list_add(&pgtable->lru, &pmd_huge_pte(mm, pmdp)->lru);
	pmd_huge_pte(mm, pmdp) = pgtable;
}

static int attach_huge_pmd(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
		unsigned long dst_addr, unsigned long src_addr, pmd_t *dst_pmdp, pmd_t *src_pmdp)
{
	struct mm_struct *dst_mm, *src_mm;
	spinlock_t *src_ptl, *dst_ptl;
	struct page *src_thp_page;
	struct folio *src_thp_folio;
	pmd_t pmd, orig_pmd;
	pgtable_t pgtable;
	int ret = 0;

	if (!vma_is_anonymous(dst_vma))
		return -EINVAL;

	dst_mm = dst_vma->vm_mm;
	src_mm = src_vma->vm_mm;

	/* alloc a pgtable for new pmdp */
	pgtable = pte_alloc_one(dst_mm);
	if (unlikely(!pgtable))
		return -ENOMEM;

	dst_ptl = pmd_lockptr(dst_mm, dst_pmdp);
	spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);
	orig_pmd = *dst_pmdp;
	/* check if exists old mappings */
	if (!pmd_none(orig_pmd)) {
		pte_free(dst_mm, pgtable);
		spin_unlock(dst_ptl);
		return -EAGAIN;
	}
	spin_unlock(dst_ptl);

	src_ptl = pmd_lockptr(src_mm, src_pmdp);
	spin_lock(src_ptl);
	pmd = *src_pmdp;
	src_thp_page = pmd_page(pmd);
	if (unlikely(!PageHead(src_thp_page))) {
		pr_err("VM assertion failed: it is not a head page\n");
		spin_unlock(src_ptl);
		return -EINVAL;
	}

	src_thp_folio = page_folio(src_thp_page);
	folio_get(src_thp_folio);
	if (unlikely(zcopy_folio_try_dup_anon_rmap(src_thp_folio, src_thp_page,
							HPAGE_PMD_NR, src_vma, RMAP_LEVEL_PMD))) {
		folio_put(src_thp_folio);
		pte_free(src_mm, pgtable);
		spin_unlock(src_ptl);
		return -EAGAIN;
	}
	spin_unlock(src_ptl);

	spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);
	zcopy_add_mm_counter(dst_mm, MM_ANONPAGES, HPAGE_PMD_NR);
	mm_inc_nr_ptes(dst_mm);
	zcopy_pgtable_trans_huge_deposit(dst_mm, dst_pmdp, pgtable);
	__set_pte((pte_t *)dst_pmdp, pmd_pte(pmd));
	zcopy_flush_tlb_mm_range(dst_vma->vm_mm, dst_addr, dst_addr + HPAGE_PMD_SIZE);
	spin_unlock(dst_ptl);
	return ret;
}

static int attach_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			unsigned long dst_addr, unsigned long src_addr, unsigned long size)
{
	struct vm_area_struct *src_vma, *dst_vma;
	unsigned long extent, src_addr_end;
	pmd_t *src_pmd, *dst_pmd;
	int ret = 0;

	src_addr_end = src_addr + size;
	src_vma = find_vma(src_mm, src_addr);
	dst_vma   = find_vma(dst_mm, dst_addr);
	/* Check the vma has not been freed again.*/
	if (!src_vma || !dst_vma)
		return -ENOENT;

	for (; src_addr < src_addr_end; src_addr += extent, dst_addr += extent) {
		cond_resched();

		extent = get_extent(NORMAL_PMD, src_addr, src_addr_end, dst_addr);
		src_pmd = zcopy_get_pmd(src_mm, src_addr);
		if (!src_pmd)
			continue;

		dst_pmd = zcopy_alloc_pmd(dst_mm, dst_addr, &ret);
		if (!dst_pmd)
			break;

		if (pmd_trans_huge(*src_pmd)) {
			if (extent == HPAGE_PMD_SIZE) {
				trace_attach_extent_start(dst_mm, src_mm, dst_addr, src_addr,
						dst_pmd, src_pmd, extent);
				ret = attach_huge_pmd(dst_vma, src_vma, dst_addr, src_addr,
							dst_pmd, src_pmd);
				trace_attach_extent_end(dst_mm, src_mm, dst_addr, src_addr,
						dst_pmd, src_pmd, ret);
				if (ret)
					return ret;
				continue;
			} else {
				ret = -EOPNOTSUPP;
				break;
			}
		} else if (is_swap_pmd(*src_pmd) || pmd_devmap(*src_pmd)) {
			ret = -EOPNOTSUPP;
			break;
		}

		if (zcopy_pte_alloc(dst_mm, dst_pmd)) {
			ret = -ENOMEM;
			break;
		}

		trace_attach_extent_start(dst_mm, src_mm, dst_addr, src_addr, dst_pmd,
					src_pmd, extent);
		ret = attach_pte_range(dst_vma, src_vma, dst_addr, src_addr, dst_pmd,
					src_pmd, extent);
		trace_attach_extent_end(dst_mm, src_mm, dst_addr, src_addr, dst_pmd,
					src_pmd, ret);
		if (ret < 0)
			break;
	}

	return ret;
}

static int attach_pages(unsigned long dst_addr, unsigned long src_addr,
					int dst_pid, int src_pid, unsigned long size)
{
	struct mm_struct *dst_mm, *src_mm;
	struct task_struct *src_task, *dst_task;
	struct page **process_pages;
	unsigned long nr_pages;
	unsigned int flags = FOLL_NOFAULT;
	int pinned_pages;
	int locked = 1;
	int ret;

	ret = -EINVAL;
	if (size <= 0)
		goto out;

	if ((src_addr & (PAGE_SIZE-1)) != 0 ||
	    (dst_addr & (PAGE_SIZE-1)) != 0 ||
	    (size & (PAGE_SIZE-1)) != 0)
		goto out;

	/* check the addr is in userspace. wo do not allow */
	if (!is_ttbr0_addr(dst_addr) || !is_ttbr0_addr(src_addr))
		goto out;

	ret = -ESRCH;
	src_task = find_get_task_by_vpid(src_pid);
	if (!src_task)
		goto out;

	src_mm = mm_access(src_task, PTRACE_MODE_ATTACH_REALCREDS);
	if (!src_mm || IS_ERR(src_mm)) {
		ret = IS_ERR(src_mm) ? PTR_ERR(src_mm) : -ESRCH;
		if (ret == -EACCES)
			ret = -EPERM;
		goto put_src_task;
	}

	dst_task = find_get_task_by_vpid(dst_pid);
	if (!dst_task)
		goto put_src_mm;

	dst_mm = mm_access(dst_task, PTRACE_MODE_ATTACH_REALCREDS);
	if (!dst_mm || IS_ERR(dst_mm)) {
		ret = IS_ERR(dst_mm) ? PTR_ERR(dst_mm) : -ESRCH;
		if (ret == -EACCES)
			ret = -EPERM;
		goto put_dst_task;
	}

	if (src_mm == dst_mm) {
		ret = -EINVAL;
		goto put_dst_mm;
	}

	nr_pages = (src_addr + size - 1) / PAGE_SIZE - src_addr / PAGE_SIZE + 1;
	process_pages = kvmalloc_array(nr_pages, sizeof(struct pages *), GFP_KERNEL);
	if (!process_pages) {
		ret = -ENOMEM;
		goto put_dst_mm;
	}

	mmap_read_lock(src_mm);
	pinned_pages = pin_user_pages_remote(src_mm, src_addr, nr_pages,
					     flags, process_pages,
					     &locked);
	if (locked)
		mmap_read_unlock(src_mm);

	if (pinned_pages <= 0) {
		ret = -EFAULT;
		goto free_pages_array;
	}

	trace_attach_page_range_start(dst_mm, src_mm, dst_addr, src_addr, size);
	mmap_read_lock(src_mm);
	ret = attach_page_range(dst_mm, src_mm, dst_addr, src_addr, size);
	mmap_read_unlock(src_mm);
	trace_attach_page_range_end(dst_mm, src_mm, dst_addr, src_addr, ret);

	unpin_user_pages_dirty_lock(process_pages, pinned_pages, 0);

free_pages_array:
	kvfree(process_pages);
put_dst_mm:
	mmput(dst_mm);
put_dst_task:
	put_task_struct(dst_task);
put_src_mm:
	mmput(src_mm);
put_src_task:
	put_task_struct(src_task);
out:
	return ret;
}

static long zcopy_ioctl(struct file *file, unsigned int type, unsigned long ptr)
{
	long ret = 0;

	switch (type) {
	case IO_ATTACH:
	{
		struct zcopy_ioctl_pswap ctx;

		if (copy_from_user((void *)&ctx, (void *)ptr,
								sizeof(struct zcopy_ioctl_pswap))) {
			ret = -EFAULT;
			break;
		}
		ret = attach_pages(ctx.dst_addr, ctx.src_addr, ctx.dst_pid,
					ctx.src_pid, ctx.size);
		break;
	}
	default:
		break;
	}

	return ret;
}

static const struct file_operations zcopy_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = zcopy_ioctl,
};

#define REGISTER_CHECK(_var, _errstr) ({ \
	int __ret = 0; \
	if (!(_var)) { \
		pr_warn("Not found %s\n", _errstr); \
		__ret = -ENOENT; \
	} \
	__ret; \
})

static int register_unexport_func(void)
{
	int ret;

#if defined(CONFIG_SPLIT_PTE_PTLOCKS) && ALLOC_SPLIT_PTLOCKS
	zcopy_page_ptl_cachep
		= (struct kmem_cache *)__kallsyms_lookup_name("page_ptl_cachep");
	ret = REGISTER_CHECK(__zcopy_pud_alloc, "__pud_alloc");
	if (ret)
		goto out;
#endif

	kallsyms_lookup_name_funcp
		= (unsigned long (*)(const char *))__kprobe_lookup_name("kallsyms_lookup_name");
	ret = REGISTER_CHECK(kallsyms_lookup_name_funcp, "kallsyms_lookup_name");
	if (ret)
		goto out;

	__zcopy_pte_offset_map
		= (pte_t *(*)(pmd_t *, unsigned long, pmd_t *))
			__kallsyms_lookup_name("__pte_offset_map");
	ret = REGISTER_CHECK(__zcopy_pte_offset_map, "__pte_offset_map");
	if (ret)
		goto out;

	__zcopy_pte_alloc
		= (int (*)(struct mm_struct *, pmd_t *))__kallsyms_lookup_name("__pte_alloc");
	ret = REGISTER_CHECK(__zcopy_pte_alloc, "__pte_alloc");
	if (ret)
		goto out;

	__zcopy_pmd_alloc
		= (int (*)(struct mm_struct *, pud_t *, unsigned long))
			__kallsyms_lookup_name("__pmd_alloc");
	ret = REGISTER_CHECK(__zcopy_pmd_alloc, "__pmd_alloc");
	if (ret)
		goto out;

	__zcopy_pud_alloc
		= (int (*)(struct mm_struct *, p4d_t *, unsigned long))
			__kallsyms_lookup_name("__pud_alloc");
	ret = REGISTER_CHECK(__zcopy_pud_alloc, "__pud_alloc");
	if (ret)
		goto out;

	__zcopy_mmu_notifier_arch_invalidate_secondary_tlbs
		= (void (*)(struct mm_struct *, unsigned long, unsigned long))
			__kallsyms_lookup_name("__mmu_notifier_arch_invalidate_secondary_tlbs");
	ret = REGISTER_CHECK(__zcopy_mmu_notifier_arch_invalidate_secondary_tlbs,
			"__mmu_notifier_arch_invalidate_secondary_tlbs");

out:
	return ret;
}

static int register_device_zcopy(void)
{
	int ret;

	ret = alloc_chrdev_region(&z_cdev.dev, 0, 1, "zcopy");
	if (ret < 0)
		goto err_out;

	z_cdev.major = MAJOR(z_cdev.dev);

	cdev_init(&z_cdev.chrdev, &zcopy_fops);
	ret = cdev_add(&z_cdev.chrdev, z_cdev.dev, 1);
	if (ret < 0)
		goto err_unregister_chrdev;

	z_cdev.dev_class = class_create("zcopy");
	if (IS_ERR(z_cdev.dev_class)) {
		ret = PTR_ERR(z_cdev.dev_class);
		goto err_cdev_del;
	}

	z_cdev.dev_device = device_create(z_cdev.dev_class, NULL,
						MKDEV(z_cdev.major, 0), NULL, "zdax");
	if (IS_ERR(z_cdev.dev_device)) {
		ret = PTR_ERR(z_cdev.dev_device);
		goto err_class_destroy;
	}

	return 0;

err_class_destroy:
	class_destroy(z_cdev.dev_class);
err_cdev_del:
	cdev_del(&z_cdev.chrdev);
err_unregister_chrdev:
	unregister_chrdev_region(z_cdev.dev, 1);
err_out:
	return ret;
}

static void unregister_device_zcopy(void)
{
	device_destroy(z_cdev.dev_class, MKDEV(z_cdev.major, 0));
	class_destroy(z_cdev.dev_class);
	cdev_del(&z_cdev.chrdev);
	unregister_chrdev_region(z_cdev.dev, 1);
}

static int __init zcopy_init(void)
{
	int ret;

	ret = register_unexport_func();
	if (ret)
		return ret;

	ret = register_device_zcopy();
	if (ret)
		return ret;

	return 0;
}

static void __exit zcopy_exit(void)
{
	unregister_device_zcopy();
}

module_init(zcopy_init);
module_exit(zcopy_exit);

MODULE_AUTHOR("liumingrui <liumingrui@huawei.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PAGEATTACH: A zero-copy data transfer mechanism");
