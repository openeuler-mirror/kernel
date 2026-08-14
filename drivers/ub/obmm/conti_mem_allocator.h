/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#ifndef CONTI_MEM_ALLOC
#define CONTI_MEM_ALLOC

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/atmioc.h>
#include <linux/kobject.h>

struct memseg_node {
	phys_addr_t addr;
	size_t size;
	struct list_head list;
};

struct conti_mem_allocator;

/**
 * struct conti_mempool_ops - Memory pool operation callbacks for the allocator
 *
 * This structure defines a set of callback functions that customize the
 * behavior of the memory allocator for different memory management strategies.
 * Each function pointer implements specific operations required for memory
 * allocation, deallocation, and pool management.
 *
 * @clear_memseg: Clear the memory segment's data (e.g., zeroing or secure erase)
 *   @allocator: Pointer to the memory allocator instance
 *   @memseg: Memory segment to be cleared
 *   Return: 0 for success, or an error on failure
 *
 * @pool_free_memseg: Return a memory segment to the pool for reuse
 *   @allocator: Pointer to the memory allocator instance
 *   @memseg: Memory segment to be freed back to the pool
 *
 * @pool_alloc_memseg: Allocate a new memory segment from the underlying memory source
 *   @allocator: Pointer to the memory allocator instance
 *   Return: A newly allocated memory segment, or NULL on failure
 *
 * @need_contract: Check if the memory pool should be shrunk
 *   @allocator: Pointer to the memory allocator instance
 *   Return: true if contraction is needed, false otherwise
 *
 * @contract_size: Calculate the size to contract the memory pool
 *   @allocator: Pointer to the memory allocator instance
 *   Return: The size (in bytes) to reduce the pool, or 0 if no contraction
 *
 * @need_expand: Check if the memory pool should be expanded
 *   @allocator: Pointer to the memory allocator instance
 *   Return: true if expansion is needed, false otherwise
 *
 * @expand_size: Calculate the size to expand the memory pool
 *   @allocator: Pointer to the memory allocator instance
 *   Return: The size (in bytes) to increase the pool, or 0 if no expansion
 */
struct conti_mempool_ops {
	int (*clear_memseg)(struct conti_mem_allocator *allocator, struct memseg_node *node);
	void (*pool_free_memseg)(struct conti_mem_allocator *allocator, struct memseg_node *node);
	struct memseg_node *(*pool_alloc_memseg)(struct conti_mem_allocator *allocator);
	bool (*need_contract)(struct conti_mem_allocator *allocator);
	size_t (*contract_size)(struct conti_mem_allocator *allocator);
	bool (*need_expand)(struct conti_mem_allocator *allocator);
	size_t (*expand_size)(struct conti_mem_allocator *allocator);
};

struct conti_mem_allocator {
	bool initialized;
	bool sysfs_initialized;

	int nid;
	size_t granu;

	atomic64_t pooled_mem_size;
	atomic64_t used_mem_size;
	atomic64_t ready_mem_size;      /* cleared but not used (memseg_ready) */
	atomic64_t uncleared_mem_size;  /* allocated but not cleared */
					/* (memseg_uncleared + memseg_clearing) */
	atomic64_t max_total;		/* cap on pooled_mem_size; LLONG_MAX = uncapped */

	spinlock_t lock;
	struct list_head memseg_ready;
	struct list_head memseg_uncleared;
	struct memseg_node *memseg_clearing;
	struct list_head memseg_poisoned;

	struct task_struct *clear_work;
	struct wait_queue_head clear_wq;

	struct task_struct *pool_work;
	struct wait_queue_head pool_wq;

	const struct conti_mempool_ops *ops;
	const char *name;

	/* sysfs support */
	struct kobject kobj;
};

static inline size_t conti_get_total(struct conti_mem_allocator *a)
{
	return atomic64_read(&a->pooled_mem_size);
}

static inline size_t conti_get_avail(struct conti_mem_allocator *a)
{
	return atomic64_read(&a->pooled_mem_size) - atomic64_read(&a->used_mem_size);
}

static inline u64 conti_get_max_total(struct conti_mem_allocator *a)
{
	return (u64)atomic64_read(&a->max_total);
}

static inline u64 conti_get_used(struct conti_mem_allocator *a)
{
	return (u64)atomic64_read(&a->used_mem_size);
}

/*
 * True if pooled_mem_size may still grow by @bytes without exceeding max_total.
 * Lock-free and best-effort: concurrent growers may transiently overshoot
 * max_total by at most (number of growers) * granu.
 */
static inline bool conti_can_grow_pooled(struct conti_mem_allocator *a, u64 bytes)
{
	return conti_get_total(a) + bytes <= conti_get_max_total(a);
}

/*
 * Parse a max_total value written to the sysfs store.
 *
 * Returns 0 and stores the parsed value in *@val on success, -EINVAL on:
 *  - no digits consumed (empty write such as "\n", or a leading '-');
 *  - trailing garbage (a single trailing '\n' from sysfs echo is tolerated);
 *  - values above LLONG_MAX (max_total is stored as s64).
 */
static inline int conti_parse_max_total(const char *str, u64 *val)
{
	u64 v;
	char *endp;

	v = memparse(str, &endp);
	if (endp == str || (*endp != '\0' && *endp != '\n'))
		return -EINVAL;
	if (v > (u64)LLONG_MAX)
		return -EINVAL;

	*val = v;
	return 0;
}

int conti_mem_allocator_init(struct conti_mem_allocator *allocator, int nid, size_t granu,
			     const struct conti_mempool_ops *ops,
			     struct kobject *parent, const char *fmt, ...);
void conti_mem_allocator_deinit(struct conti_mem_allocator *allocator);

void conti_free_memory(struct conti_mem_allocator *allocator, struct list_head *head);

size_t conti_alloc_memory(struct conti_mem_allocator *allocator, size_t size,
			  struct list_head *head, bool zero, bool allow_slow);

size_t conti_mem_allocator_expand(struct conti_mem_allocator *allocator, size_t size);

size_t conti_mem_allocator_contract(struct conti_mem_allocator *allocator, size_t size);

bool conti_mem_allocator_isolate_memseg(struct conti_mem_allocator *allocator, unsigned long addr);

#endif
