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

#ifndef EUFS_PBATCH_H
#define EUFS_PBATCH_H

/**
 * To prevent data races, only two cases are allowed:
 * 1) nvmalloc -> alloc_batch_persist -> nvfree
 * 2) nvmalloc -> nvfree
 */

/**
 * eufs_alloc_batch_* API usage:
 *
 * struct alloc_batch batch;
 * [ eufs_alloc_batch_init(&batch, estimated_size); ]
 * eufs_alloc_batch_hint(&batch, estimated_size);
 * eufs_alloc_batch_add(&batch, the_page_pointer);
 * eufs_alloc_batch_add(&batch, the_page_pointer);
 * ...
 * eufs_alloc_batch_add(&batch, the_page_pointer);
 * eufs_alloc_batch_persist_reset(&batch);
 *
 * eufs_alloc_batch_fini(&batch);
 *
 */
/* TODO: consider using list? */

#define EUFS_AB_MAX_SIZE (KMALLOC_MAX_SIZE / 8)

/* log2(cache_line size / page_info_t size) */
#define EUFS_PMAP_CNT_SHIFT_PER_CACHELINE 6

static __always_inline void eufs_alloc_batch_hint(struct alloc_batch *pb,
						   ssize_t size);
static __always_inline void
eufs_alloc_batch_persist_reset(struct super_block *sb, struct alloc_batch *pb);
static __always_inline void eufs_alloc_batch_init(struct alloc_batch *pb,
						   ssize_t size)
{
	pb->n_used = 0;
	pb->batch = NULL;
	pb->size = 0;
	pb->n_pending = 0;
	eufs_alloc_batch_hint(pb, size);
	BUG_ON(!pb->batch);
}

/* This gives only hints, no guarantees. */
static __always_inline void eufs_alloc_batch_hint(struct alloc_batch *pb,
						   ssize_t size)
{
	ssize_t realsize;
	void **batch;

	realsize = round_up(size * sizeof(void *), PAGE_SIZE);
	if (realsize > KMALLOC_MAX_SIZE)
		realsize = KMALLOC_MAX_SIZE;
	size = realsize / sizeof(void *);

	if (pb->size >= size)
		return;
	batch = krealloc(pb->batch, realsize, GFP_KERNEL | __GFP_NOFAIL);
	BUG_ON(batch == NULL);
	pb->batch = batch;
	pb->size = size;
	eufs_dbg("! eufs_alloc_batch_hint ; ab=%px size=%ld\n", pb, size);
}

static __always_inline void eufs_alloc_batch_hint_off(struct alloc_batch *pb,
						       ssize_t off_size)
{
	eufs_alloc_batch_hint(pb, pb->size + pb->n_pending + off_size);
}

static __always_inline void eufs_alloc_batch_fini(struct alloc_batch *pb)
{
	kfree(pb->batch);
	pb->batch = NULL;
	pb->size = pb->n_used = 0;
}
/* Add an already allocated address */
static __always_inline void eufs_alloc_batch_add(struct super_block *sb,
						  struct alloc_batch *pb,
						  void *page)
{
	if (pb->n_used == pb->size) {
		/* Enlarge */
		if (pb->size == EUFS_AB_MAX_SIZE)
			eufs_alloc_batch_persist_reset(sb, pb);
		else
			eufs_alloc_batch_hint(pb, pb->size * 2);
		BUG_ON(pb->n_used >= pb->size);
	}
	BUG_ON(pb->n_used >= pb->size);
	pb->batch[pb->n_used] = page;
	pb->n_used++;
}

/*
 * With the following four functions, alloc_batch can be used as a pool of
 * preallocation.
 */
static __always_inline int
eufs_alloc_batch_pre_allocate_begin(struct super_block *sb,
				     struct alloc_batch *ab, size_t need_blocks)
{
	long r;
	BUG_ON(ab->n_pending);
	eufs_alloc_batch_hint_off(ab, need_blocks);
	ab->n_pending = need_blocks;
	r = nvmalloc_pre(sb, ab, need_blocks, PAGE_SIZE);
	if (r)
		ab->n_pending = 0;
	return r;
}
static __always_inline void
eufs_alloc_batch_pre_allocate_end(struct super_block *sb,
				   struct alloc_batch *ab)
{
	WARN((ab->n_pending != 0),
	     "Some pre-allocated pages are not used in %px!\n", ab);
	BUG_ON(!list_empty(&ab->list));
}

/* Allocate from the pre-allocated addresses */
static __always_inline void *eufs_alloc_batch_allocate(struct super_block *sb,
							struct alloc_batch *ab,
							u8 tag)
{
	void *page = NULL;
	/* used up */
	BUG_ON(ab->n_pending <= 0);
	page = nvmalloc_pre_get_from_list(sb, &ab->list, tag);
	BUG_ON(!page);
	ab->n_pending--;
	eufs_alloc_batch_add(sb, ab, page);
	return page;
}
static __always_inline void *
eufs_alloc_batch_allocate_file_index(struct super_block *sb,
				      struct alloc_batch *ab)
{
	return eufs_alloc_batch_allocate(sb, ab, EUFS_PAGE_FILE_INDEX);
}
static __always_inline void *
eufs_alloc_batch_allocate_file_data(struct super_block *sb,
				     struct alloc_batch *ab)
{
	return eufs_alloc_batch_allocate(sb, ab, EUFS_PAGE_FILE_DATA);
}

static int cmp_func(const void *a, const void *b)
{
	const void **_a = (const void **)a;
	const void **_b = (const void **)b;

	if (*_a > *_b)
		return 1;
	if (*_a < *_b)
		return -1;
	return 0;
}
#define _PAGE_NO(ptr) (((u64)ptr - (u64)sbi->data_start) / PAGE_SIZE)
#define _LINE_MAP(addr) ((line_info_t *)((u64)(addr)&PAGE_MASK))
#define _IS_LINE(addr) ((u64)addr % PAGE_SIZE)
static __always_inline void _set_bitmap(struct eufs_sb_info *sbi, u64 addr,
					bool forced)
{
	u64 page_no = _PAGE_NO(addr);
	u64 rem = addr % PAGE_SIZE;
	line_info_t __pmem *line_map;
	/* no one can free this address now, so no race will happen */
	struct ptr_list_node *node;
	int line_no;

	if (rem == 0) {
		/* page */
		node = sbi->cached_nodes + (page_no);
		if (!forced) {
			BUG_ON(node->solid);
			BUG_ON(sbi->page_map[page_no] != EUFS_PAGE_FREE);
		}
		WARN(node->tag == 0,
		     "unexpected page node tag %u (addr 0x%llx)\n", node->tag,
		     addr);
		sbi->page_map[page_no] = node->tag;
		node->solid = true;
	} else {
		/* line */
		BUG_ON(rem % CACHELINE_SIZE != 0);

		line_map = (void *)(addr - rem);
		line_no = rem / CACHELINE_SIZE;

		BUG_ON(sbi->page_map[page_no] != EUFS_PAGE_FREE &&
		       sbi->page_map[page_no] != EUFS_PAGE_LINE_USED);
		/*   \        _set        _unset
		 * _set    idempotent
		 * _unset
		 */
		if (sbi->page_map[page_no] == EUFS_PAGE_FREE) {
			/* idempotent */
			sbi->page_map[page_no] = EUFS_PAGE_LINE_USED;
			node = sbi->cached_nodes + (page_no);
			BUG_ON(!node->busy);
			node->solid = true;
		}

		node = &sbi->line_node_ptrs[page_no][line_no];
		if (!forced) {
			BUG_ON(node->solid);
			if (line_map[line_no]) {
				eufs_info(
					"!line_map[line_no] = %px[%d] = %d\n",
					line_map, line_no, line_map[line_no]);
				BUG();
			}
			BUG_ON(line_map[line_no]);
		}
		WARN(node->tag == 0,
		     "unexpected line node tag %u (addr 0x%llx)\n", node->tag,
		     addr);
		line_map[line_no] = node->tag;
		eufs_dbg("set %px[%d] = %d forced=%d\n", line_map, line_no,
			  line_map[line_no], forced);
		node->solid = true;
		BUG_ON(!node->busy);
	}
}

static __always_inline void
eufs_alloc_batch_persist_reset(struct super_block *sb, struct alloc_batch *pb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	u64 page_no, page_no0;
	int i;

	if (pb->n_used == 0)
		goto reset;
	if (pb->size == 0)
		goto reset;

	BUG_ON(!pb->batch);

	sort(pb->batch, pb->n_used, sizeof(void *), cmp_func, NULL);

	for (i = 0; i < pb->n_used; ++i) {
		if (i > 0 && pb->batch[i] == pb->batch[i - 1]) {
			pr_info("!pb->batch[i]=%px [i-1]=%px i=%d\n",
				pb->batch[i], pb->batch[i - 1], i);
			BUG();
		}
		_set_bitmap(sbi, (u64)pb->batch[i], false);
	}

	page_no0 = _PAGE_NO(pb->batch[0]);
	if (_IS_LINE(pb->batch[0]))
		eufs_flush_cacheline(_LINE_MAP(pb->batch[0]));
	eufs_flush_cacheline(&sbi->page_map[page_no0]);

	for (i = 1; i < pb->n_used; ++i) {
		page_no = _PAGE_NO(pb->batch[i]);
		if (page_no == page_no0)
			/* same page, must be allocation of two cache lines */
			continue;

		/* different page */
		if (_IS_LINE(pb->batch[i]))
			eufs_flush_cacheline(_LINE_MAP(pb->batch[i]));

		/* not in a single cache line */
		if ((page_no >> EUFS_PMAP_CNT_SHIFT_PER_CACHELINE) !=
		    (page_no0 >> EUFS_PMAP_CNT_SHIFT_PER_CACHELINE))
			eufs_flush_cacheline(&sbi->page_map[page_no]);
		page_no0 = page_no;
	}

	eufs_dbg("!persistallocation: pb=%px sorted %px~%px %ld\n", pb,
		  pb->batch[0], pb->batch[pb->n_used - 1], pb->n_used);
reset:
	pb->n_used = 0;
}

static __always_inline void eufs_alloc_persist(struct super_block *sb,
						void *ptr, bool forced)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	u64 page_no = _PAGE_NO(ptr);

	_set_bitmap(sbi, (u64)ptr, forced);

	if (_IS_LINE(ptr))
		eufs_flush_cacheline(_LINE_MAP(ptr));

	eufs_flush_cacheline(&sbi->page_map[page_no]);
}

#undef _PAGE_NO
#undef _LINE_MAP
#undef _IS_LINE

#endif /* EUFS_PBATCH_H */
