/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_MEM_RELIABLE__
#define __MM_MEM_RELIABLE__

#include <linux/stddef.h>
#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/oom.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/percpu_counter.h>

#ifdef CONFIG_MEMORY_RELIABLE

DECLARE_STATIC_KEY_FALSE(mem_reliable);

extern bool reliable_enabled;
extern bool shmem_reliable;
extern struct percpu_counter reliable_shmem_used_nr_page;
extern long shmem_reliable_nr_page __read_mostly;
extern bool reliable_allow_fallback;
extern bool pagecache_use_reliable_mem;
extern struct percpu_counter pagecache_reliable_pages;
extern struct percpu_counter anon_reliable_pages;
extern unsigned long task_reliable_limit __read_mostly;
extern atomic_long_t reliable_user_used_nr_page;

extern void mem_reliable_init(bool has_unmirrored_mem,
			      unsigned long *zone_movable_pfn,
			      unsigned long mirrored_sz);
extern void shmem_reliable_init(void);
extern void reliable_report_meminfo(struct seq_file *m);
extern void page_cache_prepare_alloc(gfp_t *gfp);
extern bool mem_reliable_status(void);
extern void reliable_lru_add(enum lru_list lru, struct page *page,
					int val);
extern void reliable_lru_add_batch(int zid, enum lru_list lru,
					      int val);
extern bool mem_reliable_counter_initialized(void);
extern void mem_reliable_out_of_memory(gfp_t gfp_mask, unsigned int order,
				       int preferred_nid, nodemask_t *nodemask);
extern void reliable_show_mem_info(void);
extern void reliable_report_usage(struct seq_file *m,
		struct mm_struct *mm);

static inline bool mem_reliable_is_enabled(void)
{
	return static_branch_likely(&mem_reliable);
}

static inline bool pagecache_reliable_is_enabled(void)
{
	return pagecache_use_reliable_mem;
}

static inline bool skip_none_movable_zone(gfp_t gfp, struct zoneref *z)
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

static inline bool shmem_reliable_is_enabled(void)
{
	return shmem_reliable;
}

static inline bool page_reliable(struct page *page)
{
	if (!mem_reliable_is_enabled())
		return false;

	if (!page)
		return false;

	return page_zonenum(page) < ZONE_MOVABLE;
}

static inline void shmem_reliable_page_counter(struct page *page, int nr_page)
{
	if (shmem_reliable_is_enabled() && page_reliable(page))
		percpu_counter_add(&reliable_shmem_used_nr_page, nr_page);
}

static inline bool mem_reliable_shmem_limit_check(void)
{
	return percpu_counter_read_positive(&reliable_shmem_used_nr_page) <
		shmem_reliable_nr_page;
}

static inline u64 task_reliable_used_pages(void)
{
	s64 nr_pages;

	nr_pages = percpu_counter_read_positive(&pagecache_reliable_pages);
	nr_pages += percpu_counter_read_positive(&anon_reliable_pages);

	return nr_pages;
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

static inline bool reliable_allow_fb_enabled(void)
{
	return reliable_allow_fallback;
}

static inline void reliable_page_counter(struct page *page,
		struct mm_struct *mm, int val)
{
	if (!page_reliable(page))
		return;

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

static inline void reliable_clear_page_counter(struct mm_struct *mm)
{
	if (!mem_reliable_is_enabled())
		return;

	atomic_long_set(&mm->reliable_nr_page, 0);
}
#else
#define reliable_enabled 0
#define pagecache_use_reliable_mem 0

static inline bool mem_reliable_is_enabled(void) { return false; }
static inline bool pagecache_reliable_is_enabled(void) { return false; }
static inline void mem_reliable_init(bool has_unmirrored_mem,
				     unsigned long *zone_movable_pfn,
				     unsigned long mirrored_sz) {}
static inline void shmem_reliable_init(void) {}
static inline bool skip_none_movable_zone(gfp_t gfp, struct zoneref *z)
{
	return false;
}
static inline void reliable_report_meminfo(struct seq_file *m) {}
static inline bool shmem_reliable_is_enabled(void) { return false; }
static inline void shmem_reliable_page_counter(struct page *page,
					       int nr_page) {}
static inline bool mem_reliable_shmem_limit_check(void) { return true; }
static inline void page_cache_prepare_alloc(gfp_t *gfp) {}
static inline bool mem_reliable_status(void) { return false; }
static inline bool page_reliable(struct page *page) { return false; }
static inline void reliable_lru_add(enum lru_list lru, struct page *page,
				    int val) {}
static inline void reliable_lru_add_batch(int zid, enum lru_list lru,
					  int val) {}
static inline bool mem_reliable_counter_initialized(void) { return false; }
static inline u64 task_reliable_used_pages(void) { return 0; }
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
static inline void reliable_show_mem_info(void) {}
static inline void reliable_page_counter(struct page *page,
		struct mm_struct *mm, int val) {}
static inline void reliable_report_usage(struct seq_file *m,
		struct mm_struct *mm) {}
static inline void reliable_clear_page_counter(struct mm_struct *mm) {}
#endif

#endif
