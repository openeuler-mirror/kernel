/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_MEM_RELIABLE__
#define __MM_MEM_RELIABLE__

#include <linux/stddef.h>
#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <linux/sched.h>

#ifdef CONFIG_MEMORY_RELIABLE

DECLARE_STATIC_KEY_FALSE(mem_reliable);

extern bool reliable_enabled;
extern bool shmem_reliable;

extern void mem_reliable_init(bool has_unmirrored_mem,
			      unsigned long *zone_movable_pfn,
			      unsigned long mirrored_sz);
extern void shmem_reliable_init(void);
extern void reliable_report_meminfo(struct seq_file *m);
extern void page_cache_prepare_alloc(gfp_t *gfp);
extern bool mem_reliable_status(void);

static inline bool mem_reliable_is_enabled(void)
{
	return static_branch_likely(&mem_reliable);
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
#else
#define reliable_enabled 0

static inline bool mem_reliable_is_enabled(void) { return false; }
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
static inline void page_cache_prepare_alloc(gfp_t *gfp) {}
static inline bool mem_reliable_status(void) { return false; }
#endif

#endif
