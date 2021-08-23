/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef EUFS_DEF_H
#define EUFS_DEF_H

#ifndef EUFS_H
#error "Do not include euler_def.h directly. Include euler.h instead."
#endif

#include <linux/cpufeature.h>
#include <linux/processor.h>
#include <linux/types.h>
#include <linux/magic.h>
#include <linux/delay.h>

struct alloc_batch {
	/* both in slots */
	long size;
	long n_used;
	void **batch;
	long n_pending;
	struct list_head list;
};

struct v_dict;

enum { I_TRANS_NONE = 0, I_TRANS_AVAIL, I_TRANS_LOCKED };

struct eufs_inode_info {
	struct list_head i_dep_list; /* A list of struct op_node to persist */
	/* protect operations on i_dep_list */
	struct mutex i_dep_lock;

	struct llist_node i_persistee_node;

	u32 i_next_dep_seq;
	u32 i_persisted_dep_seq;
	spinlock_t i_owner_lock;
	struct list_head i_owner_list;

	/* regular file: pmem pointer */
	void __pmem *i_volatile_root;
	struct v_dict *i_volatile_dict;
	/*
	 * serialize the insertion of dependency nodes into the same
	 * directory by different processes or CPUs
	 */
	struct mutex i_header_lock;

	struct mutex i_urgent_mutex;

	int i_volatile_height;
	u64 i_volatile_tree_blocks;

	u64 i_dotdot;
	/*
	 * a inode can only be added into a persistence list once,
	 * so use i_is_persisting & inode_lock to ensure that.
	 */
	bool i_is_persisting;
	/* whether or not the inode need persistence */
	bool i_is_dirty;

	int i_lock_transferred;

	bool hole_at_sta; /* the 0th data block is a hole */

	u64 i_ext;
	u16 i_version;

	struct alloc_batch page_batch;
	/* serialize mmap with truncate/fallocate/write/unlink */
	struct rw_semaphore mmap_rwsem;
	/* Protect pointers to leaf nodes (data pages) */
	struct mutex i_leaf_lock;

	spinlock_t i_dentry_persist_lock;
	struct inode vfs_inode;
};

typedef u8 page_info_t;
struct page_wear;

/*
 * EulerFS super-block data in memory
 */
struct eufs_sb_info {
	struct block_device *s_bdev;
	struct dax_device *s_dax_dev;
	phys_addr_t phys_addr;
	void __pmem *virt_addr;
	struct vm_struct *vm;
	unsigned long block_start;
	unsigned long block_end;

	void __pmem *renamej;

	u64 s_crash_ver;

	/* protects the SB's buffer-head */
	struct mutex s_lock;

	unsigned long blocksize;
	unsigned long initsize;
	unsigned long s_mount_opt;
	atomic_t next_generation;

	/* Begin of Allocator */
	/*  DRAM pools:
	 *   - a single global pool
	 *     - potected by page_lock and line_lock
	 *   - a local pool per cpu
	 *     - allocate/free from global pool in batch
	 *     - no locks needed
	 *   - a single (global) rest pool
	 *     - when a page is used too many times, it is put into rest pool
	 *     - cache lines are never put in rest pool
	 */
	spinlock_t large_lock;
	spinlock_t page_lock;
	spinlock_t line_lock;
	struct mem_pool *gpool;
	struct mem_pool *ppool; /* percpu variable */

	spinlock_t rest_lock;
	struct mem_pool *rest_pool;

	page_info_t __pmem *page_map;
	void __pmem *data_start;
	u64 npages;

	/* Other DRAM structures for the allcoator:
	 *
	 *  - struct ptr_list_node: an unit for allocation (i.e., a page
	 *    or a cacheline).
	 *
	 *  - cached nodes: preallocated ptr_list_node for all pages, indexed by
	 *    the page number. If the page is free, its ptr_list_node should
	 *    be in some mem_pool.
	 *
	 *  - line_node_ptrs: preallocated pointers for all pages. For each
	 *    page, the pointer may point to an array of
	 *    (PAGE_SIZE/CACHELINE_SIZE) ptr_list_nodes, each of which presents
	 *    the allocation status of the corresponding cache line in the page.
	 *    The array is dynamically allocated for memory conservation.
	 *
	 *  - line_indicators: preallocated u8s for all pages. Each of the u8s
	 *    records the number of cache lines available in global pool. This
	 *    is used for cacheline coalescence.
	 *
	 *  - page_wears: preallocated ints for all pages. Each of the ints
	 *    records the number of writes to the page. This is used to
	 *    coarse-grainedly show the degree of wear.
	 *
	 */
	struct ptr_list_node *cached_nodes;
	struct ptr_list_node **line_node_ptrs;
	u8 *line_indicators; /* Number of lines used per page! */

	struct page_wear *page_wears;

	/* End of Allocator  */

	/* Begin of Persister */
	/* kmem cache for dep_node is universal defined in super.c */
	struct llist_head *persistee_list; /* percpu variable */
	struct task_struct **persisters;
	bool *need_sync; /* for fssync */
	wait_queue_head_t sync_wq; /* for fssync's thread */
	struct mutex sync_mutex; /* serialize fssync request */
	/* End of Persister */

	/* The word `draining` is reserved for volatility quota limitation */
	bool s_draining;
	wait_queue_head_t s_draining_wq;

	atomic_t s_nr_dirty_inodes;
	atomic_t s_nr_dep_nodes;

	struct mutex gather_mutex;
};

struct dir_scan_data {
	struct super_block *sb;
	struct dir_context *ctx;
};

typedef u64 hashlen_t;

#endif /* EUFS_DEF_H */
