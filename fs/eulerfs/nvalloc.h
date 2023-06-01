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

#ifndef EUFS_NVALLOC_H
#define EUFS_NVALLOC_H

#include "euler.h"
#include "euler_common.h"
#include <linux/sort.h>
#include <linux/vmalloc.h>

/*
 * The design of the allocator is hybrid, and the in-dram allocators are
 * per-cpu to accelerate the zalloc/zfree process.
 *
 * This allocator supports only 4K and 64B (one cache line) so no chunks
 * are involved in the design.
 */
/*
 * In NVM                     +---> 0/1: 4K/64B
 * +-----------------+        |
 * | page-map       *+-->+----+---1B-in-size+-
 * | (page-info)     |   | type | birth_gen |
 * +-----------------+   +------------------+
 * | pages           |   | type2| check_gen |
 * | (actual data)* *|   +------------------+
 * +--------------+-++
 *                | |
 *                | +---> +-------------------------+
 *                v       | gen x 63 + lock/cpu x 1 |
 *       +-----------+    +-------------------------+
 *       |           |    | cache line data 1       |
 *       | 4K page   |    +-------------------------+
 *       |  data     |    | cache line data 2       |
 *       |           |    +-------------------------+
 *       +-----------+    | ...                     |
 *                        +-------------------------+
 *                        | cache line data 63      |
 *                        +-------------------------+
 */

/*
 * In DRAM, percpu
 * +----------------+
 * | free-page-list +----->...
 * +----------------+
 * | free-line-list   +----->...
 * +----------------+
 *
 * global
 * +----------------+
 * | free-page-lists+----> free-page-list --> free-page-list
 * +----------------+
 * | free-line-lists  +----> free-line-list --> free-line-list
 * +----------------+
 */

extern int wear_control;
extern int wear_alloc_threshold;

struct ptr_list_node {
	struct list_head node; /* points to next list node */
	void __pmem *ptr;
	bool busy; /* whether it is allocated in the volatile allocator */
	bool solid; /* whether it is allocated in the bitmap */
	bool multiple; /* whther it is a linex4/large-page */
	u8 tag;
	int counter; /* How many times has it been allocated? */
};

struct mem_pool {
	struct list_head page_list; /* points to ptr_lists_node */
	struct list_head line_list; /* points to ptr_lists_node */
	struct list_head line4_list;
	struct list_head large_list;
	u64 npages;
	u64 nlines;
	u64 nline4s;
	u64 nlarges;
	int fetch_count;
};

#define _SET_NON_BUSY(node, fmt, args...)                                      \
	do {                                                                   \
		if (node->busy == false) {                                     \
			eufs_info(fmt, ##args);                               \
			BUG();                                                 \
		}                                                              \
		node->busy = false;                                            \
	} while (0)

#define _SET_BUSY(node, fmt, args...)                                          \
	do {                                                                   \
		if (node->busy == true) {                                      \
			eufs_info(fmt, ##args);                               \
			BUG();                                                 \
		}                                                              \
		node->busy = true;                                             \
	} while (0)

#define EUFS_PAGE_FREE (0)
#define EUFS_PAGE_USED (1)
#define EUFS_PAGE_LINE_USED (2)
#define EUFS_PAGE_LARGE_USED (3)
#define EUFS_PAGE_RESERVED (5)

#define EUFS_LINE_FREE (0)
#define EUFS_LINE_USED (1)
#define EUFS_LINE4_USED (2)

#define EUFS_PAGE_FILE_DATA (8)
#define EUFS_PAGE_FILE_INDEX (9)
#define EUFS_PAGE_HTABLE (10)
#define EUFS_PAGE_SYMLINK (11)
#define EUFS_PAGE_INODE_EXT (12)

#define EUFS_LINE4_INODE (4)
#define EUFS_LINE_DENTRY (5)
#define EUFS_LINE_NAME_EXT (6)

void *nvmalloc_pre_get_from_list(struct super_block *sb, struct list_head *list,
				 u8 tag);
int nvmalloc_pre(struct super_block *sb, struct alloc_batch *ab, size_t count,
		 size_t size);
void *nvmalloc(struct super_block *sb, size_t size, u8 tag, bool nonblocking);
void nvfree(struct super_block *sb, void *ptr, bool rest);
int nv_init(struct super_block *sb, bool init);
void nv_fini(struct super_block *sb);
void eufs_get_layout(struct super_block *sb, bool init);

#define FETCH_COUNT 64
#define EUFS_PRE_PAGES_PERCPU (4096)

#define LOCAL_PAGE_MAX (4096 * 8)
#define LOCAL_LINE_MAX (4096)

#define NR_RESERVED_PAGES (64)

static __always_inline void print_line_map(line_info_t *line_map, u8 line_num)
{
	int i;

	eufs_info("line_map[line_num]: %px[%u]=%u\n", line_map, line_num,
		   line_map[line_num]);
	eufs_info("line_map=%px ===>\n", line_map);
	for (i = 0; i < 8; ++i) {
		int i8 = i * 8;

		eufs_info("%d: %u %u %u %u %u %u %u %u\n", i, line_map[i8 + 0],
			   line_map[i8 + 1], line_map[i8 + 2], line_map[i8 + 3],
			   line_map[i8 + 4], line_map[i8 + 5], line_map[i8 + 6],
			   line_map[i8 + 7]);
	}
}

static __always_inline void nv_stat(struct eufs_sb_info *sbi, u64 *page,
				    u64 *line)
{
	struct mem_pool *ppool;
	u64 nlarges = sbi->gpool->nlarges;
	u64 npages = sbi->gpool->npages;
	u64 nline4s = 0;
	u64 nlines = sbi->gpool->nlines;
	int cpu;

	for_each_online_cpu(cpu) {
		ppool = per_cpu_ptr(sbi->ppool, cpu);

		nlarges += ppool->nlarges;
		npages += ppool->npages;
		nline4s += ppool->nline4s;
		nlines += ppool->nlines;
	}
	*page = npages + (nlarges << 9);
	*line = nlines + (nline4s << 2);
}

static __always_inline void print_stats(struct eufs_sb_info *sbi)
{
	struct mem_pool *ppool;
	int cpu;
	u64 nlarges = sbi->gpool->nlarges;
	u64 npages = sbi->gpool->npages;
	u64 nline4s = 0;
	u64 nlines = sbi->gpool->nlines;

	eufs_info("Stat: (g,%lld,%lld), ", sbi->gpool->npages,
		  sbi->gpool->nlines);
	for_each_online_cpu(cpu) {
		ppool = per_cpu_ptr(sbi->ppool, cpu);

		nlarges += ppool->nlarges;
		npages += ppool->npages;
		nline4s += ppool->nline4s;
		nlines += ppool->nlines;

		eufs_info("(@%d,%lld,%lld,%lld,%lld) ", cpu, ppool->nlarges,
			  ppool->npages, ppool->nline4s, ppool->nlines);
	}
	eufs_info("= (summary: larges=%lld pages=%lld line4s=%lld lines=%lld)\n",
		  nlarges, npages, nline4s, nlines);
}

#endif /* EUFS_NVALLOC_H */
