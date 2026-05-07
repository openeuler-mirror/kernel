// SPDX-License-Identifier: GPL-2.0-only
/*
 * Contiguous pfn range allocator
 *
 * Copyright (C) 2025 Huawei Limited.
 */

#define pr_fmt(fmt) "pfn_range_alloc: " fmt

#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/page-isolation.h>
#include <linux/set_memory.h>
#include <trace/events/kmem.h>
#include <linux/pagewalk.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/numa_remote.h>
#include "internal.h"
#include "../../../mm/internal.h"

struct pmd_lm_range {
	unsigned long start_pfn;
	unsigned long end_pfn;
	spinlock_t	lock;
	unsigned long *bitmap;
	unsigned long bitmap_maxno;
};

unsigned long contig_mem_pool_percent __ro_after_init;
EXPORT_SYMBOL_GPL(contig_mem_pool_percent);
static unsigned long nr_reserved_pages[MAX_NUMNODES] __initdata;
static struct pmd_lm_range reserved_range[MAX_NUMNODES];
DEFINE_STATIC_KEY_FALSE(pmd_mapping_initialized);
static atomic_long_t num_poisoned_pfn __read_mostly = ATOMIC_LONG_INIT(0);

static inline bool pmd_linear_mapping_enabled(void)
{
	return static_branch_unlikely(&pmd_mapping_initialized);
}

static __init int cmdline_parse_pmd_mapping(char *p)
{
	unsigned long percent;
	char *endptr;

	if (IS_ENABLED(CONFIG_ARM64_64K_PAGES)) {
		pr_warn("page size is 64KB, don't use pmd_mapping, use rodata=full instead\n");
		return -EINVAL;
	}

	if (!p)
		return -EINVAL;

	percent = simple_strtoul(p, &endptr, 0);
	if (*endptr != '%' || *(endptr + 1) != '\0')
		return -EINVAL;

	if (percent > 100)
		return -EINVAL;

	contig_mem_pool_percent = percent;

	return 0;
}
early_param("pmd_mapping", cmdline_parse_pmd_mapping);

static __init void calculate_node_nr_reserved_pages(void)
{
	unsigned long start_pfn, end_pfn;
	int i, nid;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid)
		nr_reserved_pages[nid] += end_pfn - start_pfn;

	for_each_online_node(nid) {
		nr_reserved_pages[nid] = nr_reserved_pages[nid] * contig_mem_pool_percent / 100;
		nr_reserved_pages[nid] = ALIGN_DOWN(nr_reserved_pages[nid],
							PUD_SIZE / PAGE_SIZE);
	}
}

static __init unsigned long calculate_reserve_base(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone;
	unsigned long base = 0;

#ifdef CONFIG_ZONE_DMA
	zone = &pgdat->node_zones[ZONE_DMA];
	if (managed_zone(zone))
		base = max(base, PFN_PHYS(zone_end_pfn(zone)));
#endif

#ifdef CONFIG_ZONE_DMA32
	zone = &pgdat->node_zones[ZONE_DMA32];
	if (managed_zone(zone))
		base = max(base, PFN_PHYS(zone_end_pfn(zone)));
#endif

	return base;
}

static __init int __get_suitable_reserved_range(int nid)
{
	unsigned long base, size, start;

	base = calculate_reserve_base(nid);
retry:
	size = nr_reserved_pages[nid] * PAGE_SIZE;
	start = memblock_alloc_range_nid(size, PUD_SIZE, base, 0, nid, true);
	/*
	 * If reservation fails, try to fallback to reserve
	 * smaller size. Fallback is at PUD_SIZE granularity.
	 */
	if (!start) {
		nr_reserved_pages[nid] -= PUD_SIZE / PAGE_SIZE;
		if (!nr_reserved_pages[nid])
			return -ENOMEM;
		goto retry;
	}

	reserved_range[nid].start_pfn = PHYS_PFN(start);
	reserved_range[nid].end_pfn = PHYS_PFN(start) + nr_reserved_pages[nid];

	return 0;
}

static __init int get_suitable_reserved_range(void)
{
	bool restore_bottom_up = false;
	unsigned long start, end;
	bool resved = false;
	int nid, ret;

	if (memblock_bottom_up()) {
		memblock_set_bottom_up(false);
		restore_bottom_up = true;
	}

	calculate_node_nr_reserved_pages();
	for_each_online_node(nid) {
		if (!nr_reserved_pages[nid])
			continue;

		ret = __get_suitable_reserved_range(nid);
		if (ret) {
			pr_warn("reservation failed for node %d\n", nid);
			continue;
		}

		start = PFN_PHYS(reserved_range[nid].start_pfn);
		end = PFN_PHYS(reserved_range[nid].end_pfn);
		pmd_mapping_reserved_remap(start, end);
		resved = true;
		pr_info("reserved %lu MiB on node %d\n", (end - start) / SZ_1M, nid);
	}

	if (restore_bottom_up)
		memblock_set_bottom_up(true);

	return resved;
}

static __init void put_suitable_reserved_range(void)
{
	unsigned long start, end;
	int ret, nid;

	for_each_online_node(nid) {
		start = PFN_PHYS(reserved_range[nid].start_pfn);
		end = PFN_PHYS(reserved_range[nid].end_pfn);

		if (start == end)
			continue;

		ret = memblock_phys_free(start, end - start);
		if (ret)
			pr_warn("put reserved memory [%lx, %lx) failed(%d) for node %d\n",
					start, end, ret, nid);
	}
}

void __init pmd_mapping_reserve_and_remap(void)
{
	bool resved;

	if (!contig_mem_pool_percent)
		return;

	if (should_pmd_linear_mapping())
		goto out;

	if (can_set_direct_map()) {
		pr_info("linear mapping is mapped at PTE level, all memory can be borrowed\n");
		goto out;
	}

	resved = get_suitable_reserved_range();
	if (!resved)
		return;

	put_suitable_reserved_range();
out:
	static_branch_enable(&pmd_mapping_initialized);
}

static int __init activate_reserved_range(void)
{
	int nid;
	unsigned long pfn, end_pfn;
	unsigned long bitmap_maxno;

	if (!pmd_linear_mapping_enabled())
		return 0;

	for_each_online_node(nid) {
		pfn = reserved_range[nid].start_pfn;
		end_pfn = reserved_range[nid].end_pfn;

		if (pfn == end_pfn)
			continue;

		bitmap_maxno = (end_pfn - pfn) / (PFN_RANGE_ALLOC_SIZE / PAGE_SIZE);
		reserved_range[nid].bitmap_maxno = bitmap_maxno;
		reserved_range[nid].bitmap = bitmap_zalloc(bitmap_maxno, GFP_KERNEL);
		if (!reserved_range[nid].bitmap) {
			reserved_range[nid].start_pfn = 0;
			reserved_range[nid].end_pfn = 0;
			pr_warn("reserved_range %d fails to be initialized\n", nid);
			continue;
		}
		spin_lock_init(&reserved_range[nid].lock);
	}

	return 0;
}
core_initcall(activate_reserved_range);

struct folio *pfn_range_alloc(unsigned int nr_pages, int nid)
{
	unsigned long min_align = PFN_RANGE_ALLOC_NR_PAGES;
	gfp_t gfp_mask = (GFP_KERNEL | __GFP_COMP) & ~__GFP_RECLAIM;
	unsigned long start, bitmap_no, bitmap_count, mask, offset;
	struct pmd_lm_range *mem_range;
	struct folio *folio = ERR_PTR(-EINVAL);
	unsigned long pfn;
	int ret;

	if (in_interrupt())
		goto out;

	if (nid < 0 || nid >= MAX_NUMNODES)
		goto out;

#ifdef CONFIG_ARM64_4K_PAGES
	if (!IS_ALIGNED(nr_pages, min_align))
		goto out;
#endif

#ifdef CONFIG_ARM64_64K_PAGES
	if (!can_set_direct_map())
		goto out;
	if (!is_power_of_2(nr_pages))
		goto out;
#endif

	if (can_set_direct_map() || should_pmd_linear_mapping()) {
		int order = ilog2(nr_pages);

		gfp_mask |= __GFP_THISNODE;
		if (nr_pages <= MAX_ORDER_NR_PAGES) {
			gfp_mask |= __GFP_RECLAIM | __GFP_NOWARN | __GFP_NORETRY;
			folio = __folio_alloc_node(gfp_mask, order, nid);
		} else {
			folio = folio_alloc_gigantic(order, gfp_mask, nid, NULL);
		}

		if (!folio)
			folio = ERR_PTR(-ENOMEM);
		goto out;
	}

	mem_range = &reserved_range[nid];
	if (!mem_range->bitmap) {
		folio = ERR_PTR(-ENOMEM);
		goto out;
	}

	start = 0;
	bitmap_count = nr_pages / min_align;
	mask = bitmap_count - 1;
	offset = (mem_range->start_pfn & (nr_pages - 1)) / min_align;
	for (;;) {
		spin_lock(&mem_range->lock);
		bitmap_no = bitmap_find_next_zero_area_off(mem_range->bitmap,
				mem_range->bitmap_maxno, start, bitmap_count, mask, offset);
		if (bitmap_no >= mem_range->bitmap_maxno) {
			spin_unlock(&mem_range->lock);
			break;
		}
		bitmap_set(mem_range->bitmap, bitmap_no, bitmap_count);
		spin_unlock(&mem_range->lock);
		pfn = mem_range->start_pfn + bitmap_no * min_align;
		ret = alloc_contig_range(pfn, pfn + nr_pages, MIGRATE_MOVABLE, gfp_mask);
		if (!ret) {
			folio = pfn_folio(pfn);
			goto out;
		}

		spin_lock(&mem_range->lock);
		bitmap_clear(mem_range->bitmap, bitmap_no, bitmap_count);
		spin_unlock(&mem_range->lock);
		start = bitmap_no + bitmap_count;
	}

	folio = ERR_PTR(-ENOMEM);
out:
	trace_pfn_range_alloc(folio, nr_pages, nid);
	return folio;
}
EXPORT_SYMBOL_GPL(pfn_range_alloc);

static void pfn_range_folio_dissolve(struct folio *folio)
{
	int nr_pages = folio_nr_pages(folio);
	struct page *page;
	int i;

	VM_WARN_ON_FOLIO(folio_ref_count(folio) != 1, folio);

	for (i = 1; i < nr_pages; i++) {
		page = folio_page(folio, i);
		page->flags &= ~PAGE_FLAGS_CHECK_AT_FREE;
		page->mapping = NULL;
		clear_compound_head(page);
		set_page_refcounted(page);
	}

	__folio_clear_head(folio);

	page = &folio->page;
	for (i = 0; i < nr_pages; i++, page++) {
		if (PageHWPoison(page)) {
			atomic_long_inc(&num_poisoned_pfn);
			continue;
		}

		__free_page(page);
	}
}

static inline bool pfn_range_free_prepare(struct folio *folio)
{
	int nr_pages = folio_nr_pages(folio);
	struct page *page = &folio->page;
	int i;

	for (i = 0; i < nr_pages; i++, page++)
		if (PageHWPoison(page)) {
			pfn_range_folio_dissolve(folio);
			return false;
		}

	return true;
}

int pfn_range_free(struct folio *folio)
{
	struct pmd_lm_range *mem_range;
	unsigned long start_pfn, end_pfn;
	unsigned long bitmap_no, bitmap_count;
	unsigned long nr_pages = folio_nr_pages(folio);
	unsigned long min_align = PFN_RANGE_ALLOC_NR_PAGES;
	int ret = 0;

	if (in_interrupt()) {
		ret = -EINVAL;
		goto out;
	}

	if (!pfn_range_free_prepare(folio))
		goto out;

	if (can_set_direct_map() || should_pmd_linear_mapping()) {
		folio_put(folio);
		goto out;
	}

	mem_range = &reserved_range[folio_nid(folio)];
	start_pfn = folio_pfn(folio);
	end_pfn = start_pfn + nr_pages;

	if (start_pfn < mem_range->start_pfn || end_pfn > mem_range->end_pfn) {
		ret = -EINVAL;
		goto out;
	}

	free_contig_range(start_pfn, nr_pages);
	bitmap_no = (start_pfn - mem_range->start_pfn) / min_align;
	bitmap_count = nr_pages / min_align;
	spin_lock(&mem_range->lock);
	bitmap_clear(mem_range->bitmap, bitmap_no, bitmap_count);
	spin_unlock(&mem_range->lock);

out:
	trace_pfn_range_free(folio, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(pfn_range_free);

static inline int check_update_lm_arg(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long start, end;
	struct page *start_page;
	int nid;

	if (can_set_direct_map())
		return 0;

	start_page = pfn_to_page(start_pfn);
	nid = page_to_nid(start_page);
	start = (unsigned long)page_to_virt(start_page);
	end = start + (end_pfn - start_pfn) * PAGE_SIZE;
	if ((start_pfn >= reserved_range[nid].start_pfn &&
	    end_pfn <= reserved_range[nid].end_pfn)
	    || should_pmd_linear_mapping()) {
		if (!IS_ALIGNED(start, PFN_RANGE_ALLOC_SIZE) ||
			!IS_ALIGNED(end, PFN_RANGE_ALLOC_SIZE)) {
			return -EINVAL;
		}
	} else if (!IS_ALIGNED(start, PUD_SIZE) || !IS_ALIGNED(end, PUD_SIZE)) {
		return -EINVAL;
	}

	return 0;
}

static int invalid_pud_entry(pud_t *pudp, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_invalid = (bool)walk->private;
	pud_t pud;

	pud = pudp_get(pudp);
	if (pud_table(pud))
		return 0;

	if (set_invalid)
		pud_val(pud) &= ~PTE_VALID;
	else
		pud_val(pud) |= PTE_VALID;
	set_pud(pudp, pud);

	return 0;
}

static int invalid_pmd_entry(pmd_t *pmdp, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_invalid = (bool)walk->private;
	pmd_t pmd;

	pmd = pmdp_get(pmdp);
	if (pmd_table(pmd))
		return 0;

	if (set_invalid)
		pmd_val(pmd) &= ~PTE_VALID;
	else
		pmd_val(pmd) |= PTE_VALID;
	set_pmd(pmdp, pmd);

	return 0;
}

static int invalid_pte_entry(pte_t *ptep, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_invalid = (bool)walk->private;
	pte_t pte;

	pte = ptep_get(ptep);

	if (set_invalid)
		pte_val(pte) &= ~PTE_VALID;
	else
		pte_val(pte) |= PTE_VALID;
	set_pte(ptep, pte);

	return 0;
}

static const struct mm_walk_ops invalid_ops = {
	.pud_entry = invalid_pud_entry,
	.pmd_entry = invalid_pmd_entry,
	.pte_entry = invalid_pte_entry,
};

int set_linear_mapping_invalid(unsigned long start_pfn, unsigned long end_pfn,
										bool set_invalid)
{
	unsigned long start, end;
	int ret;

	ret = check_update_lm_arg(start_pfn, end_pfn);
	if (ret)
		return ret;

	start = (unsigned long)page_to_virt(pfn_to_page(start_pfn));
	end = start + (end_pfn - start_pfn) * PAGE_SIZE;
	mmap_write_lock(&init_mm);
	walk_page_range_novma(&init_mm, start, end,
				&invalid_ops, NULL, (void *)set_invalid);
	mmap_write_unlock(&init_mm);
	if (set_invalid)
		flush_tlb_kernel_range(start, end);

	return 0;
}
EXPORT_SYMBOL_GPL(set_linear_mapping_invalid);

static inline void update_entry_nc(unsigned long long *val, bool set_nc)
{
	*val &= ~PTE_ATTRINDX_MASK;
	if (set_nc)
		*val |= PTE_ATTRINDX(MT_NORMAL_NC);
	else
		*val |= PTE_ATTRINDX(MT_NORMAL_TAGGED);
	*val |= PTE_VALID;
}

static int nc_pud_entry(pud_t *pudp, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_nc = (bool)walk->private;
	pud_t pud;

	if (pud_table(*pudp))
		return 0;

	pud = pudp_huge_get_and_clear(walk->mm, addr, pudp);
	update_entry_nc(&pud_val(pud), set_nc);
	set_pud(pudp, pud);

	return 0;
}

static int nc_pmd_entry(pmd_t *pmdp, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_nc = (bool)walk->private;
	pmd_t pmd;

	if (pmd_table(*pmdp))
		return 0;

	pmd = pmdp_huge_get_and_clear(walk->mm, addr, pmdp);
	update_entry_nc(&pmd_val(pmd), set_nc);
	set_pmd(pmdp, pmd);

	return 0;
}

static int nc_pte_entry(pte_t *ptep, unsigned long addr,
				unsigned long next, struct mm_walk *walk)
{
	bool set_nc = (bool)walk->private;
	pte_t pte;

	pte = ptep_get_and_clear(walk->mm, addr, ptep);
	update_entry_nc(&pte_val(pte), set_nc);
	set_pte(ptep, pte);

	return 0;
}

static const struct mm_walk_ops nc_ops = {
	.pud_entry = nc_pud_entry,
	.pmd_entry = nc_pmd_entry,
	.pte_entry = nc_pte_entry,
};

int set_linear_mapping_nc(unsigned long start_pfn, unsigned long end_pfn, bool set_nc)
{
	unsigned long start, end;
	int ret;

	start = (unsigned long)page_to_virt(pfn_to_page(start_pfn));
	end = start + (end_pfn - start_pfn) * PAGE_SIZE;
	ret = check_update_lm_arg(start_pfn, end_pfn);
	if (ret)
		return ret;

	mmap_write_lock(&init_mm);
	walk_page_range_novma(&init_mm, start, end,
				&invalid_ops, NULL, (void *)true);
	flush_tlb_kernel_range(start, end);
	walk_page_range_novma(&init_mm, start, end,
				&nc_ops, NULL, (void *)set_nc);
	mmap_write_unlock(&init_mm);

	return 0;
}
EXPORT_SYMBOL_GPL(set_linear_mapping_nc);

#ifdef CONFIG_DEBUG_FS
static int reserved_range_show(struct seq_file *m, void *v)
{
	int nid;

	for_each_online_node(nid) {
		if (numa_is_remote_node(nid))
			continue;

		seq_printf(m, "%d, %llx-%llx\n", nid,
				PFN_PHYS(reserved_range[nid].start_pfn),
				PFN_PHYS(reserved_range[nid].end_pfn));
	}

	seq_printf(m, "\nHardwareCorrupted: %lu kB\n",
		   atomic_long_read(&num_poisoned_pfn) << (PAGE_SHIFT - 10));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(reserved_range);

static int __init reserved_range_debug_init(void)
{
	if (!pmd_linear_mapping_enabled())
		return 0;

	if (can_set_direct_map() || should_pmd_linear_mapping())
		return 0;

	debugfs_create_file("pmd_mapping_reserved_range", 0400, NULL,
			    NULL, &reserved_range_fops);
	return 0;
}
late_initcall(reserved_range_debug_init);
#endif
