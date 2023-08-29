/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _GMEM_AS_H
#define _GMEM_AS_H

typedef struct gm_as gm_as_t;
typedef unsigned long gm_va_t;
typedef unsigned long gm_pa_t;
typedef enum gm_as_alloc gm_as_alloc_t;

#define GMEM_MMAP_RETRY_TIMES 10 /* gmem retry times before OOM */

/**
 * enum gm_as_alloc - defines different allocation policy for virtual addresses.
 *
 * @GM_AS_ALLOC_DEFAULT:		An object cache is applied to accelerate VA allocations.
 * @GM_AS_ALLOC_FIRSTFIT:		Prefer allocation efficiency.
 * @GM_AS_ALLOC_BESTFIT:		Prefer space efficiency.
 * @GM_AS_ALLOC_NEXTFIT:		Perform an address-ordered search for free addresses,
 * beginning where the previous search ended.
 */
enum gm_as_alloc {
	GM_AS_ALLOC_DEFAULT = 0,
	GM_AS_ALLOC_FIRSTFIT,
	GM_AS_ALLOC_BESTFIT,
	GM_AS_ALLOC_NEXTFIT,
};

/* Defines an address space. */
struct gm_as {
	spinlock_t rbtree_lock; /* spinlock of gm_as_t */
	struct rb_root rbroot; /*root of gm_region_t */
	gm_as_alloc_t policy;
	gm_va_t start_va;
	gm_va_t end_va;
	gm_va_t cache_quantum; /* defines the VA unit size if an object cache is applied */

	struct list_head gm_ctx_list; /* tracks device contexts attached to this va space, using gm_as_link */
};

#endif
