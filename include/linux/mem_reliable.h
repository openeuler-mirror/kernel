/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_MEM_RELIABLE__
#define __MM_MEM_RELIABLE__

#ifdef CONFIG_MEMORY_RELIABLE

#include <linux/stddef.h>
#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/mm_types.h>
#include <linux/sched.h>

DECLARE_STATIC_KEY_FALSE(mem_reliable);

extern bool reliable_enabled;
extern struct file_operations proc_reliable_operations;

void mem_reliable_init(bool has_unmirrored_mem, unsigned long mirrored_sz);
bool mem_reliable_status(void);
bool mem_reliable_hide_file(const char *name);

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
#else
#define reliable_enabled 0

static inline bool mem_reliable_is_enabled(void) { return false; }
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
#endif

#endif
