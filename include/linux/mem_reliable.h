/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_MEM_RELIABLE__
#define __MM_MEM_RELIABLE__

#ifdef CONFIG_MEMORY_RELIABLE

#include <linux/stddef.h>
#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/oom.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/percpu_counter.h>

DECLARE_STATIC_KEY_FALSE(mem_reliable);

extern bool reliable_enabled;
extern struct file_operations proc_reliable_operations;
extern bool shmem_reliable;
extern bool reliable_allow_fallback;
extern bool pagecache_reliable;
extern struct percpu_counter pagecache_reliable_pages;
extern struct percpu_counter anon_reliable_pages;
extern struct percpu_counter shmem_reliable_pages;
extern unsigned long task_reliable_limit __read_mostly;
extern unsigned long shmem_reliable_limit __read_mostly;
extern unsigned long pagecache_reliable_limit __read_mostly;

void mem_reliable_init(bool has_unmirrored_mem, unsigned long mirrored_sz);
bool mem_reliable_status(void);
bool mem_reliable_hide_file(const char *name);
void shmem_reliable_init(void);
void reliable_lru_add(enum lru_list lru, struct folio *folio, int val);
void reliable_lru_add_batch(int zid, enum lru_list lru, int val);
bool mem_reliable_counter_initialized(void);
void reliable_report_meminfo(struct seq_file *m);
void mem_reliable_out_of_memory(gfp_t gfp_mask, unsigned int order,
				int preferred_nid, nodemask_t *nodemask);
void reliable_report_usage(struct seq_file *m, struct mm_struct *mm);

static inline bool mem_reliable_is_enabled(void)
{
	return static_branch_likely(&mem_reliable);
}

static inline bool page_reliable(struct page *page)
{
	if (!mem_reliable_is_enabled())
		return false;

	if (!page)
		return false;

	if (PagePool(page))
		return false;

	return page_zonenum(page) < ZONE_MOVABLE;
}

static inline bool folio_reliable(struct folio *folio)
{
	if (!mem_reliable_is_enabled())
		return false;

	if (!folio)
		return false;

	return folio_zonenum(folio) < ZONE_MOVABLE;
}

static inline bool shmem_reliable_is_enabled(void)
{
	return shmem_reliable;
}

static inline bool filemap_reliable_is_enabled(void)
{
	return pagecache_reliable;
}

static inline bool skip_non_mirrored_zone(gfp_t gfp, struct zoneref *z)
{
	if (!mem_reliable_is_enabled())
		return false;

	if (!current->mm || (current->flags & PF_KTHREAD))
		return false;

	/* user tasks can only alloc memory from non-mirrored region */
	if (!(gfp & GFP_RELIABLE) && (gfp & __GFP_HIGHMEM) &&
	    (gfp & __GFP_MOVABLE)) {
		if (zonelist_zone_idx(z) < ZONE_MOVABLE)
			return true;
	}

	return false;
}

static inline bool reliable_allow_fb_enabled(void)
{
	return reliable_allow_fallback;
}

static inline bool mem_reliable_shmem_limit_check(void)
{
	return percpu_counter_read_positive(&shmem_reliable_pages) <
	       (shmem_reliable_limit >> PAGE_SHIFT);
}

/*
 * Check if this memory allocation for shmem is allowed.
 * Return false if limit is triggered.
 */
static inline bool shmem_prepare_alloc(gfp_t *gfp_mask)
{
	if (!mem_reliable_is_enabled())
		return true;

	if (!shmem_reliable_is_enabled()) {
		*gfp_mask &= ~GFP_RELIABLE;
		return true;
	}

	if (mem_reliable_shmem_limit_check()) {
		*gfp_mask |= GFP_RELIABLE;
		return true;
	}

	if (reliable_allow_fb_enabled())
		return true;

	return false;
}

static inline void filemap_prepare_alloc(gfp_t *gfp_mask)
{
	s64 nr_reliable = 0;

	if (!mem_reliable_is_enabled())
		return;

	if (!filemap_reliable_is_enabled()) {
		*gfp_mask &= ~GFP_RELIABLE;
		return;
	}

	nr_reliable = percpu_counter_read_positive(&pagecache_reliable_pages);
	if (nr_reliable > pagecache_reliable_limit >> PAGE_SHIFT) {
		*gfp_mask &= ~GFP_RELIABLE;
		return;
	}

	*gfp_mask |= GFP_RELIABLE;
}

static inline unsigned long task_reliable_used_pages(void)
{
	s64 nr_pages;

	nr_pages = percpu_counter_read_positive(&pagecache_reliable_pages);
	nr_pages += percpu_counter_read_positive(&anon_reliable_pages);

	return nr_pages;
}

static inline void shmem_reliable_folio_add(struct folio *folio, int nr_page)
{
	if (shmem_reliable_is_enabled() && folio_reliable(folio))
		percpu_counter_add(&shmem_reliable_pages, nr_page);
}


static inline bool reliable_mem_limit_check(unsigned long nr_page)
{
	return (task_reliable_used_pages() + nr_page) <=
	       (task_reliable_limit >> PAGE_SHIFT);
}

static inline bool mem_reliable_should_reclaim(void)
{
	if (percpu_counter_sum_positive(&pagecache_reliable_pages) >=
	    MAX_ORDER_NR_PAGES)
		return true;

	return false;
}

static inline void reliable_page_counter_inner(struct mm_struct *mm, int val)
{
	atomic_long_add(val, &mm->reliable_nr_page);

	/*
	 * Update reliable page counter to zero if underflows.
	 *
	 * Since reliable page counter is used for debug purpose only,
	 * there is no real function problem by doing this.
	 */
	if (unlikely(atomic_long_read(&mm->reliable_nr_page) < 0))
		atomic_long_set(&mm->reliable_nr_page, 0);
}

static inline void add_reliable_folio_counter(struct folio *folio,
		struct mm_struct *mm, int val)
{
	if (!folio_reliable(folio))
		return;

	reliable_page_counter_inner(mm, val);
}

static inline void add_reliable_page_counter(struct page *page,
		struct mm_struct *mm, int val)
{
	if (!page_reliable(page))
		return;

	reliable_page_counter_inner(mm, val);
}

static inline void reliable_clear_page_counter(struct mm_struct *mm)
{
	if (!mem_reliable_is_enabled())
		return;

	atomic_long_set(&mm->reliable_nr_page, 0);
}
#else
#define reliable_enabled 0

static inline bool mem_reliable_is_enabled(void) { return false; }
static inline bool filemap_reliable_is_enabled(void) { return false; }
static inline void mem_reliable_init(bool has_unmirrored_mem,
				     unsigned long mirrored_sz) {}
static inline bool page_reliable(struct page *page) { return false; }
static inline bool folio_reliable(struct folio *folio) { return false; }
static inline bool skip_non_mirrored_zone(gfp_t gfp, struct zoneref *z)
{
	return false;
}
static inline bool mem_reliable_status(void) { return false; }
static inline bool mem_reliable_hide_file(const char *name) { return false; }
static inline bool shmem_prepare_alloc(gfp_t *gfp_mask) { return true; }
static inline void filemap_prepare_alloc(gfp_t *gfp_mask) {}
static inline void shmem_reliable_init(void) {}
static inline void reliable_lru_add(enum lru_list lru, struct folio *folio,
				    int val) {}
static inline void reliable_lru_add_batch(int zid, enum lru_list lru,
					  int val) {}
static inline bool mem_reliable_counter_initialized(void) { return false; }
static inline void shmem_reliable_folio_add(struct folio *folio,
					    int nr_page) {}
static inline void reliable_report_meminfo(struct seq_file *m) {}
static inline bool mem_reliable_shmem_limit_check(void) { return true; }
static inline bool reliable_mem_limit_check(unsigned long nr_page)
{
	return false;
}
static inline bool mem_reliable_should_reclaim(void) { return false; }
static inline void mem_reliable_out_of_memory(gfp_t gfp_mask,
					      unsigned int order,
					      int preferred_nid,
					      nodemask_t *nodemask) {}
static inline bool reliable_allow_fb_enabled(void) { return false; }
static inline void add_reliable_page_counter(struct page *page,
		struct mm_struct *mm, int val) {}
static inline void add_reliable_folio_counter(struct folio *folio,
		struct mm_struct *mm, int val) {}
static inline void reliable_report_usage(struct seq_file *m,
		struct mm_struct *mm) {}
static inline void reliable_clear_page_counter(struct mm_struct *mm) {}
#endif

#endif
