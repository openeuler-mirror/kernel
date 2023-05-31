// SPDX-License-Identifier: GPL-2.0
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

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/ratelimit.h>
#include "nvalloc.h"
#include "euler.h"

static __always_inline void print_ptr_list_node(struct ptr_list_node *node)
{
	eufs_info("========> &ptr_list_node = %px <==========\n", node);
	eufs_info("= node => .prev=%px  .next=%px\n", node->node.prev,
		  node->node.next);
	eufs_info("= ptr =%px\n", node->ptr);
	eufs_info("======== reported @cpu=%d =============\n",
		  smp_processor_id());
}

static __always_inline void memclr(void *ptr, size_t len)
{
	memset(ptr, 0, len);
}

static __always_inline void *eufs_get_page(struct super_block *sb, int page_no)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	return sbi->data_start + page_no * PAGE_SIZE;
}

void eufs_get_layout(struct super_block *sb, bool init)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	unsigned long start_addr = (u64)sbi->virt_addr;
	ssize_t len = sbi->initsize;

	unsigned long ptr;
	ssize_t page_map_size;

	/* only support 4K page now */
	BUG_ON(PAGE_SIZE != 4096);
	BUILD_BUG_ON(sizeof(unsigned long) != sizeof(void *));

	/* align the start to 4K */
	ptr = round_up(start_addr, PAGE_SIZE);
	len -= (ptr - start_addr);

	sbi->npages = len / PAGE_SIZE; /* round down */
	sbi->data_start = (void *)((uintptr_t) ptr);

	/* skip the first 4K, reserved for super blocks */
	ptr += PAGE_SIZE;
	len -= PAGE_SIZE;

	/* get page-map */
	if (init)
		sbi->page_map = (page_info_t *)ptr;
	page_map_size = round_up(sbi->npages * sizeof(page_info_t), PAGE_SIZE);

	ptr += page_map_size;
	len -= page_map_size;

	/* skip for renamej */
	sbi->renamej = (void *)ptr;
	ptr += EUFS_RENAMEJ_SIZE;
	len -= EUFS_RENAMEJ_SIZE;
	if (init) {
		/* clear the pagemap */
		memclr(sbi->page_map, page_map_size);
		memclr(sbi->renamej, EUFS_RENAMEJ_SIZE);
		eufs_flush_buffer(sbi->renamej, EUFS_RENAMEJ_SIZE, true);
	}
}

static void partition_page(struct eufs_sb_info *sbi, int page_no,
			   line_info_t *gens, int *line4_cpu,
			   int *line4_countdown)
{
	struct ptr_list_node *node;
	int i = page_no;
	int j;

	/* no cache line is in global pool */
	sbi->line_indicators[i] = 0;
	for (j = 1; j < 64; ++j) {
		node = &sbi->line_node_ptrs[i][j];
		node->ptr = ((void *)gens) + CACHELINE_SIZE * j;
		if (gens[j] == EUFS_LINE_DENTRY ||
		    gens[j] == EUFS_LINE_NAME_EXT) {
			/* line used */
			node->busy = true;
			node->solid = true;
			node->multiple = false;
			node->tag = gens[j];
			continue;
		}
		if (gens[j] == EUFS_LINE4_INODE) {
			int k;
			/* linex4 used */
			node->busy = true;
			node->solid = true;
			node->multiple = true;
			node->tag = gens[j];
			for (k = 1; k < 4; ++k) {
				sbi->line_node_ptrs[i][j + k].ptr =
					((void *)gens) +
					CACHELINE_SIZE * (j + k);
				sbi->line_node_ptrs[i][j + k].busy = false;
				sbi->line_node_ptrs[i][j + k].solid = false;
				sbi->line_node_ptrs[i][j + k].multiple = false;
			}
			j += 3;
			continue;
		}
		/* EUFS_LINE_FREE */
		if ((j & 3) == 0 &&
		    /* probe */
		    (gens[j + 1] == EUFS_LINE_FREE &&
		     gens[j + 2] == EUFS_LINE_FREE &&
		     gens[j + 3] == EUFS_LINE_FREE)) {
			struct mem_pool *line4_ppool;
			int k;

			node->busy = false;
			node->solid = false;
			node->multiple = true;
			for (k = 1; k < 4; ++k) {
				sbi->line_node_ptrs[i][j + k].ptr =
					((void *)gens) +
					CACHELINE_SIZE * (j + k);
				sbi->line_node_ptrs[i][j + k].busy = false;
				sbi->line_node_ptrs[i][j + k].solid = false;
				sbi->line_node_ptrs[i][j + k].multiple = false;
			}
			if (*line4_countdown == 0) {
				/* switch to next cpu */
				*line4_cpu = cpumask_next(*line4_cpu,
							  cpu_possible_mask);
				if (*line4_cpu >= nr_cpu_ids)
					*line4_cpu = cpumask_next(
						-1, cpu_possible_mask);
				*line4_countdown = EUFS_PRE_PAGES_PERCPU;
			}
			line4_ppool = per_cpu_ptr(sbi->ppool, *line4_cpu);
			list_add(&node->node, &line4_ppool->line4_list);
			line4_ppool->nline4s++;
			(*line4_countdown)--;
			j += 3;
			continue;
		}
		node->busy = false;
		node->solid = false;
		node->multiple = false;
		++sbi->line_indicators[i];
		list_add(&node->node, &sbi->gpool->line_list);
		sbi->gpool->nlines++;
	}
}

static bool probe_large_page(struct eufs_sb_info *sbi, long page_no)
{
	long i = page_no;
	int k;

	for (k = 1; k < 512; ++k) {
		if (sbi->page_map[i + k] != EUFS_PAGE_FREE)
			return false;
	}
	return true;
}

/* Partition the area into multiple zones */
static void partition(struct super_block *sb, bool init)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	u64 start_addr = (u64)sbi->virt_addr;
	u64 len = sbi->initsize;
	u64 npages_percpu;
	u64 cpu_page_left;
	u64 start_page;
	int cpu;
	int i;
	int k;
	struct mem_pool *pool;
	struct ptr_list_node *node;
	ssize_t page_map_size;
	int line4_cpu;
	int line4_countdown;

	/*
	 * The status of 64 cache-lines in a pmem page are tracked by
	 * 64 ptr_list_node in volatile page, so check whether or not
	 * the size of ptr_list_node is too large.
	 */
	BUILD_BUG_ON(64 * sizeof(struct ptr_list_node) > PAGE_SIZE);

	eufs_get_layout(sb, init);
	page_map_size = round_up(sbi->npages * sizeof(page_info_t), PAGE_SIZE);

	/* allocate space for volatile allocator */
	sbi->cached_nodes = vmalloc(sizeof(struct ptr_list_node) * sbi->npages);
	memclr(sbi->cached_nodes, sizeof(struct ptr_list_node) * sbi->npages);

	/* pointers reserved for cache line nodes for a page (64 lines) */
	sbi->line_node_ptrs =
		vmalloc(sizeof(struct ptr_list_node *) * sbi->npages);
	memclr(sbi->line_node_ptrs,
	       sizeof(struct ptr_list_node *) * sbi->npages);

	sbi->line_indicators =
		vmalloc(sizeof(*sbi->line_indicators) * sbi->npages);
	memclr(sbi->line_indicators,
	       sizeof(*sbi->line_indicators) * sbi->npages);

	i = 0;
	if (init) {
		unsigned int reserved_pages;

		eufs_info("start: %llx, len=%llu\n", start_addr, len);

		/* +1 for super block */
		reserved_pages =
			1 + page_map_size / PAGE_SIZE +
			round_up(EUFS_RENAMEJ_SIZE, PAGE_SIZE) / PAGE_SIZE;
		while (reserved_pages-- > 0)
			sbi->page_map[i++] = EUFS_PAGE_RESERVED;

		eufs_flush_buffer(sbi->page_map, page_map_size, true);
	}

	npages_percpu = EUFS_PRE_PAGES_PERCPU;

	cpu = -1;
	cpu_page_left = 0;
	start_page = 0;

	/* init spinlock for gpool */
	spin_lock_init(&sbi->large_lock);
	spin_lock_init(&sbi->page_lock);
	spin_lock_init(&sbi->line_lock);
	spin_lock_init(&sbi->rest_lock);

	sbi->gpool->nlarges = 0;
	sbi->gpool->npages = 0;
	sbi->gpool->nlines = 0;

	line4_cpu = cpumask_next(-1, cpu_possible_mask);
	line4_countdown = npages_percpu;

	for (; i < sbi->npages; ++i) {
		if (cpu_page_left == 0) {
			eufs_info(
				"%s for cpu=%d, page=[%llu~%llu) [%px~%px)\n",
				__func__, cpu, (u64)start_page, (u64)i,
				eufs_get_page(sb, start_page),
				eufs_get_page(sb, i));
			if (cpu < (int)nr_cpu_ids)
				cpu = cpumask_next(cpu, cpu_possible_mask);
			if (cpu >= nr_cpu_ids) {
				pool = sbi->gpool;
				cpu_page_left =
					sbi->npages; /* never exhausted */
			} else {
				pool = per_cpu_ptr(sbi->ppool, cpu);
				cpu_page_left = npages_percpu;
			}
			start_page = i;
		}
		node = sbi->cached_nodes + (i);
		node->ptr = eufs_get_page(sb, i);
		switch (sbi->page_map[i]) {
		case EUFS_PAGE_LARGE_USED:
			node->busy = true;
			node->solid = true;
			node->multiple = true;
			node->tag = sbi->page_map[i];
			WARN(((u64)node->ptr) & ((2 << 20) - 1),
			     "EulerFS unalinged large page!");
			for (k = 1; k < 512; ++k) {
				sbi->cached_nodes[i + k].ptr =
					eufs_get_page(sb, i + k);
				sbi->cached_nodes[i + k].busy = false;
				sbi->cached_nodes[i + k].solid = false;
				sbi->cached_nodes[i + k].multiple = false;
			}
			i += 511;
			continue;
		/* case EUFS_PAGE_USED: */
		case EUFS_PAGE_RESERVED:
		case EUFS_PAGE_FILE_DATA:
		case EUFS_PAGE_FILE_INDEX:
		case EUFS_PAGE_HTABLE:
		case EUFS_PAGE_SYMLINK:
		case EUFS_PAGE_INODE_EXT:
			BUG_ON(init);
			node->busy = true;
			node->solid = true;
			node->multiple = false;
			node->tag = sbi->page_map[i];
			/* page used */
			continue;
		case EUFS_PAGE_LINE_USED:
			BUG_ON(init);
			/* page used as cache lines */
			node->busy = true;
			node->solid = true;
			node->multiple = false;
			node->tag = sbi->page_map[i];

			/* TODO: add cache lines */
			BUG_ON(sbi->line_node_ptrs[i]);
			sbi->line_node_ptrs[i] = eufs_zalloc_page();

			partition_page(sbi, i, node->ptr, &line4_cpu,
				       &line4_countdown);

			break;
		case EUFS_PAGE_FREE:
			/* allocate and fill the node */
			node->busy = false;
			node->solid = false;

			if ((((u64)node->ptr) & ((2 << 20) - 1)) == 0 &&
			    probe_large_page(sbi, i)) {
				/* insert as large page */
				node->multiple = true;

				list_add(&node->node, &pool->large_list);
				pool->nlarges++;

				cpu_page_left--;

				for (k = 1; k < 512; ++k) {
					sbi->cached_nodes[i + k].ptr =
						eufs_get_page(sb, i + k);
					sbi->cached_nodes[i + k].busy = false;
					sbi->cached_nodes[i + k].solid = false;
					sbi->cached_nodes[i + k].multiple =
						false;
				}
				i += 511;
			} else {
				/* insert to ppool */
				node->multiple = false;
				list_add(&node->node, &pool->page_list);
				pool->npages++;

				cpu_page_left--;
			}
			break;
		default:
			eufs_warn(
				"Invalid value 0x%x in pagemap[%d] is detected!\n",
				sbi->page_map[i], i);
			continue;
		}
	}
	if (cpu < nr_cpu_ids)
		eufs_info("%s for cpu=%d, page=[%llu~%llu) [%px~%px)\n",
			  __func__, cpu, (u64)start_page, (u64)i,
			  eufs_get_page(sb, start_page), eufs_get_page(sb, i));
	else
		eufs_info("%s for global pool, page=[%llu~%llu)\n",
			  __func__, start_page, (u64)i);
}

static void return_page(struct eufs_sb_info *sbi, struct mem_pool *ppool,
			struct ptr_list_node *node, bool rest)
{
	unsigned long flags;
	u64 page_num = (node->ptr - sbi->data_start) / PAGE_SIZE;

	sbi->page_map[page_num] = EUFS_PAGE_FREE;
	eufs_flush_cacheline(&sbi->page_map[page_num]);
	eufs_pbarrier();
	if (wear_control &&
	    (node->counter++ % wear_alloc_threshold == 0 || rest)) {
		spin_lock_irqsave(&sbi->rest_lock, flags);
		list_add(&node->node, &sbi->rest_pool->page_list);
		sbi->rest_pool->npages++;
		spin_unlock_irqrestore(&sbi->rest_lock, flags);
	} else if (ppool->npages >= LOCAL_PAGE_MAX) {
		spin_lock_irqsave(&sbi->page_lock, flags);
		list_add(&node->node, &sbi->gpool->page_list);
		sbi->gpool->npages++;
		spin_unlock_irqrestore(&sbi->page_lock, flags);
	} else {
		local_irq_save(flags);

		list_add(&node->node, &ppool->page_list);
		ppool->npages++;

		local_irq_restore(flags);
	}
}

static void _unset_bitmap(struct eufs_sb_info *sbi, u64 addr, bool flush);
static void return_cl(struct eufs_sb_info *sbi, struct mem_pool *ppool,
		      struct ptr_list_node *node, bool rest)
{
	unsigned long flags, flags2;
	u64 page_no;
	u64 page_off;
	int i;
	struct ptr_list_node *tmp;

	if (wear_control &&
	    (node->counter++ % wear_alloc_threshold == 0 || rest)) {
		spin_lock_irqsave(&sbi->rest_lock, flags);
		list_add(&node->node, &sbi->rest_pool->line_list);
		sbi->rest_pool->nlines++;
		spin_unlock_irqrestore(&sbi->rest_lock, flags);
	} else if (ppool->nlines >= LOCAL_LINE_MAX) {
		page_off = (node->ptr - sbi->data_start);
		page_no = page_off / PAGE_SIZE;
		page_off = page_off % PAGE_SIZE;

		spin_lock_irqsave(&sbi->line_lock, flags2);
		/* line_indicators are protected by sbi->line_lock */
		if (++sbi->line_indicators[page_no] == 63) {
			/* Remove all cache lines */
			for (i = 1; i < 64; ++i) {
				tmp = &sbi->line_node_ptrs[page_no][i];
				if (tmp == node)
					continue;
				list_del(&tmp->node);
				/* It must be !solid since we ensure it during nvfree */
				BUG_ON(tmp->solid);
				--sbi->gpool->nlines;
			}
			spin_unlock_irqrestore(&sbi->line_lock, flags2);
			eufs_dbg("! cacheline coalescence !\n");

			/* Add back a whole page */
			tmp = &sbi->cached_nodes[page_no];
			BUG_ON(!tmp->solid);
			_unset_bitmap(sbi, (u64)tmp->ptr, true);
			_SET_NON_BUSY(tmp, "fault addr %px", tmp->ptr);

			spin_lock_irqsave(&sbi->page_lock, flags);
			list_add(&tmp->node, &sbi->gpool->page_list);
			sbi->gpool->npages++;
			sbi->page_map[page_no] = EUFS_PAGE_FREE;

			spin_unlock_irqrestore(&sbi->page_lock, flags);

			return;
		}

		list_add(&node->node, &sbi->gpool->line_list);
		sbi->gpool->nlines++;
		spin_unlock_irqrestore(&sbi->line_lock, flags2);

	} else {
		list_add(&node->node, &ppool->line_list);
		ppool->nlines++;
	}
}

static void return_line4(struct eufs_sb_info *sbi, struct mem_pool *ppool,
			 struct ptr_list_node *node, bool rest)
{
	if (wear_control &&
	    (node->counter++ % wear_alloc_threshold == 0 || rest)) {
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);

	} else if (ppool->nlines >= LOCAL_LINE_MAX) {
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);
		node->multiple = false;
		return_cl(sbi, ppool, node++, rest);

	} else {
		list_add(&node->node, &ppool->line4_list);
		ppool->nline4s++;
	}
}

void nv_fini(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	int i;

	vfree(sbi->cached_nodes);
	for (i = 0; i < sbi->npages; ++i)
		if (sbi->line_node_ptrs[i])
			eufs_free_page(sbi->line_node_ptrs[i]);
	vfree(sbi->line_node_ptrs);
	vfree(sbi->line_indicators);

	free_percpu(sbi->ppool);
	kfree(sbi->rest_pool);
	kfree(sbi->gpool);
}

int nv_init(struct super_block *sb, bool init)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct mem_pool *ppool;
	int cpu;

	/* allocate pools */
	sbi->gpool = kmalloc(sizeof(struct mem_pool), GFP_KERNEL);
	if (!sbi->gpool)
		return -ENOMEM;

	INIT_LIST_HEAD(&sbi->gpool->large_list);
	INIT_LIST_HEAD(&sbi->gpool->page_list);
	INIT_LIST_HEAD(&sbi->gpool->line4_list);
	INIT_LIST_HEAD(&sbi->gpool->line_list);
	sbi->gpool->nlarges = 0;
	sbi->gpool->npages = 0;
	sbi->gpool->nline4s = 0;
	sbi->gpool->nlines = 0;

	sbi->rest_pool = kmalloc(sizeof(struct mem_pool), GFP_KERNEL);
	if (!sbi->rest_pool)
		goto err_rest_pool;

	INIT_LIST_HEAD(&sbi->rest_pool->large_list);
	INIT_LIST_HEAD(&sbi->rest_pool->page_list);
	INIT_LIST_HEAD(&sbi->rest_pool->line4_list);
	INIT_LIST_HEAD(&sbi->rest_pool->line_list);

	sbi->rest_pool->nlarges = 0;
	sbi->rest_pool->npages = 0;
	sbi->rest_pool->nline4s = 0;
	sbi->rest_pool->nlines = 0;

	sbi->ppool = alloc_percpu(struct mem_pool);
	if (!sbi->ppool)
		goto err_ppool;

	for_each_online_cpu(cpu) {
		ppool = per_cpu_ptr(sbi->ppool, cpu);
		INIT_LIST_HEAD(&ppool->large_list);
		INIT_LIST_HEAD(&ppool->page_list);
		INIT_LIST_HEAD(&ppool->line4_list);
		INIT_LIST_HEAD(&ppool->line_list);
		ppool->nlarges = 0;
		ppool->npages = 0;
		ppool->nline4s = 0;
		ppool->nlines = 0;
		ppool->fetch_count = FETCH_COUNT;
	}

	partition(sb, init);
	return 0;

err_ppool:
	kfree(sbi->rest_pool);
	sbi->rest_pool = NULL;
err_rest_pool:
	kfree(sbi->gpool);
	sbi->gpool = NULL;
	return -ENOMEM;
}

static int cut_from_list_remaining(struct list_head *head, int remaining,
				   struct list_head *tmp)
{
	int i = 0;
	struct list_head *end;
	struct list_head *sentry;

	if (list_empty(head))
		return 0;
	end = head;
	sentry = head;
	for (i = 0; i < remaining; ++i) {
		if (sentry->next == head)
			/* too few */
			return 0;
		sentry = sentry->next;
	}

	for (i = 0; sentry->next != head; ++i) {
		end = end->next;
		sentry = sentry->next;
	}

	INIT_LIST_HEAD(tmp);
	list_cut_position(tmp, head, end);
	return i;
}

static void give_up_pages(void *info)
{
	struct eufs_sb_info *sbi = info;
	unsigned long flags, flags2;
	LIST_HEAD(tmp);
	struct mem_pool *ppool;
	int i = 0;
	int cpu;

	cpu = get_cpu();
	local_irq_save(flags2);
	/* Need a way to get it back */
	ppool = per_cpu_ptr(sbi->ppool, cpu);
	ppool->fetch_count = 10;

	i = cut_from_list_remaining(&ppool->page_list, ppool->fetch_count,
				    &tmp);

	if (i) {
		spin_lock_irqsave(&sbi->page_lock, flags);
		list_splice_tail(&tmp, &sbi->gpool->page_list);
		sbi->gpool->npages += i;
		spin_unlock_irqrestore(&sbi->page_lock, flags);

		ppool->npages -= i;
	}

	i = cut_from_list_remaining(&ppool->large_list, 1, &tmp);
	if (i) {
		spin_lock_irqsave(&sbi->large_lock, flags);
		list_splice_tail(&tmp, &sbi->gpool->large_list);
		sbi->gpool->nlarges += i;
		spin_unlock_irqrestore(&sbi->large_lock, flags);

		ppool->nlarges -= i;
	}

	local_irq_restore(flags2);
	put_cpu();
}

void revive_rest_pool(struct eufs_sb_info *sbi);

static void gather_pages(struct eufs_sb_info *sbi)
{
	smp_call_func_t func = give_up_pages;
	unsigned long flags;

	/* Gather from other CPUs */
	mutex_lock(&sbi->gather_mutex);

	smp_call_function(func, sbi, true);

	mutex_unlock(&sbi->gather_mutex);

	/* Gather from rest pool, if necessary */
	spin_lock_irqsave(&sbi->page_lock, flags);
	if (!list_empty(&sbi->gpool->page_list)) {
		spin_unlock_irqrestore(&sbi->page_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&sbi->page_lock, flags);

	revive_rest_pool(sbi);
	/* I've tried the best */
}

static bool reload_lines_from_gpool(struct eufs_sb_info *sbi,
				    struct mem_pool *ppool)
{
	struct ptr_list_node *node;
	struct list_head *head;
	struct list_head *end;
	unsigned long flags;
	LIST_HEAD(tmp);
	int i;

	spin_lock_irqsave(&sbi->line_lock, flags);
	head = &sbi->gpool->line_list;
	if (list_empty(head)) {
		spin_unlock_irqrestore(&sbi->line_lock, flags);
		return false;
	}
	end = head;

	/* head is not a legal node */
	for (i = 0; i < ppool->fetch_count && end->next != head; ++i) {
		end = end->next;
		node = list_entry(end, struct ptr_list_node, node);
		/* move out of global pool */
		--sbi->line_indicators[(node->ptr - sbi->data_start) /
				       PAGE_SIZE];
	}
	list_cut_position(&tmp, head, end);
	list_splice_tail(&tmp, &ppool->line_list);

	sbi->gpool->nlines -= i;
	ppool->nlines += i;
	spin_unlock_irqrestore(&sbi->line_lock, flags);

	return true;
}

static bool reload_large_from_gpool(struct eufs_sb_info *sbi,
				    struct mem_pool *ppool, bool nonblocking)
{
	struct list_head *head;
	struct list_head *end;
	LIST_HEAD(tmp);
	int i;
	unsigned long flags;

	spin_lock_irqsave(&sbi->large_lock, flags);

	if (nonblocking) {
		if (sbi->gpool->nlarges == 0) {
			spin_unlock_irqrestore(&sbi->large_lock, flags);
			return false;
		}
	} else {
		/* blocking is okay */
		if (sbi->gpool->nlarges <= NR_RESERVED_PAGES) {
			spin_unlock_irqrestore(&sbi->large_lock, flags);
			return false;
		}
	}
	head = &sbi->gpool->large_list;
	end = head;

	for (i = 0; i < ppool->fetch_count && end->next != head; ++i)
		end = end->next;
	list_cut_position(&tmp, head, end);
	list_splice_tail(&tmp, &ppool->large_list);

	sbi->gpool->nlarges -= i;
	ppool->nlarges += i;

	spin_unlock_irqrestore(&sbi->large_lock, flags);

	return true;
}

static bool reload_page_from_gpool(struct eufs_sb_info *sbi,
				   struct mem_pool *ppool, bool nonblocking)
{
	struct list_head *head;
	struct list_head *end;
	LIST_HEAD(tmp);
	int i;
	unsigned long flags;

	spin_lock_irqsave(&sbi->page_lock, flags);

	if (nonblocking) {
		if (sbi->gpool->npages == 0) {
			spin_unlock_irqrestore(&sbi->page_lock, flags);
			return false;
		}
	} else {
		/* blocking is okay */
		if (sbi->gpool->npages <= NR_RESERVED_PAGES) {
			spin_unlock_irqrestore(&sbi->page_lock, flags);
			return false;
		}
	}
	head = &sbi->gpool->page_list;
	end = head;

	for (i = 0; i < ppool->fetch_count && end->next != head; ++i)
		end = end->next;
	list_cut_position(&tmp, head, end);
	list_splice_tail(&tmp, &ppool->page_list);

	sbi->gpool->npages -= i;
	ppool->npages += i;

	spin_unlock_irqrestore(&sbi->page_lock, flags);

	return true;
}

void revive_rest_pool(struct eufs_sb_info *sbi)
{
	unsigned long flags;

	spin_lock_irqsave(&sbi->page_lock, flags);
	spin_lock(&sbi->large_lock);
	spin_lock(&sbi->line_lock);
	spin_lock(&sbi->rest_lock);

	list_splice_init(&sbi->rest_pool->large_list, &sbi->gpool->large_list);
	list_splice_init(&sbi->rest_pool->page_list, &sbi->gpool->page_list);
	list_splice_init(&sbi->rest_pool->line_list, &sbi->gpool->line_list);
	sbi->gpool->nlarges += sbi->rest_pool->nlarges;
	sbi->gpool->npages += sbi->rest_pool->npages;
	sbi->gpool->nlines += sbi->rest_pool->nlines;
	sbi->rest_pool->nlarges = 0;
	sbi->rest_pool->npages = 0;
	sbi->rest_pool->nlines = 0;

	spin_unlock(&sbi->rest_lock);
	spin_unlock(&sbi->line_lock);
	spin_unlock(&sbi->large_lock);
	spin_unlock_irqrestore(&sbi->page_lock, flags);
}

static __always_inline int cut_from_list(struct list_head *head,
					 struct list_head *list, int count)
{
	struct list_head *end = head;
	int i;

	for (i = 0; i < count && end->next != head; ++i)
		end = end->next;
	list_cut_position(list, head, end);
	return i;
}

static void preallocate_pages_from_larges_and_pages(struct eufs_sb_info *sbi,
						    struct alloc_batch *ab,
						    size_t count,
						    struct mem_pool *pool)
{
	struct ptr_list_node *list_node;
	long nlarges_needed;
	size_t r = 0;
	int i;

	WARN(!irqs_disabled(), "Interrupt is not disabled!");

	WARN(count > pool->nlarges * 512 + pool->npages,
	     "Invarients violated!");

	if (count <= pool->npages) {
		r = cut_from_list(&pool->page_list, &ab->list, count);
		pool->npages -= r;
		WARN_ON(r != count);
		return;
	}

	nlarges_needed = DIV_ROUND_UP(count - pool->npages, 512);
	if ((nlarges_needed * 512) < count) {
		r = cut_from_list(&pool->page_list, &ab->list,
				  count - (nlarges_needed * 512));
		WARN_ON(r != count - (nlarges_needed * 512));
		pool->npages -= r;
	}
	while (nlarges_needed--) {
		list_node = list_first_entry(&pool->large_list,
					     struct ptr_list_node, node);
		list_del(&list_node->node);
		pool->nlarges--;
		list_node->multiple = false;
		/* split the large page */
		for (i = 0; i < 512; ++i) {
			if (r < count) {
				list_add(&list_node->node, &ab->list);
			} else {
				/*
				 * When all requested pages come from splitting of
				 * large pages, the remaining pages needs to add
				 * the list of normal page
				 */
				list_add(&list_node->node, &pool->page_list);
				pool->npages++;
			}

			r++;
			list_node++;
		}
	}
}

static int preallocate_page_from_pool(struct eufs_sb_info *sbi,
				      struct alloc_batch *ab, size_t count,
				      struct mem_pool *ppool)
{
	BUG_ON(!list_empty(&ab->list));
	BUG_ON(count > ppool->nlarges * 512 + ppool->npages);

	/* get locally with large pages and pages */
	preallocate_pages_from_larges_and_pages(sbi, ab, count, ppool);

	return 0;
}

static int preallocate_page_from_gpool(struct eufs_sb_info *sbi,
				       struct alloc_batch *ab, size_t count)
{
	unsigned long flags;
	u64 nlarges_avail = 0;
	u64 npages_avail = 0;

	BUG_ON(!list_empty(&ab->list));

	spin_lock_irqsave(&sbi->page_lock, flags);
	spin_lock(&sbi->large_lock);
	/* enough pages are available? */
	/*
	 * We have NR_RESERVED_PAGES pages reserved for allocation in page fault
	 * handlers, so do not use reserved pages if we can gather from other
	 * CPUs.
	 * NOTICE: We'd better not to use minus here since sbi->gpool->npages is
	 * unsigned.
	 */
	if (sbi->gpool->nlarges > NR_RESERVED_PAGES)
		nlarges_avail = sbi->gpool->nlarges - NR_RESERVED_PAGES;
	if (sbi->gpool->npages > NR_RESERVED_PAGES)
		npages_avail = sbi->gpool->npages - NR_RESERVED_PAGES;

	if (count > nlarges_avail * 512 + npages_avail) {
		spin_unlock(&sbi->large_lock);
		spin_unlock_irqrestore(&sbi->page_lock, flags);
		/* unlock and gather page */
		gather_pages(sbi);
		/* relock after the gathering */
		spin_lock_irqsave(&sbi->page_lock, flags);
		spin_lock(&sbi->large_lock);
		/* enough pages this time? */
		if (count > sbi->gpool->nlarges * 512 + sbi->gpool->npages) {
			spin_unlock(&sbi->large_lock);
			spin_unlock_irqrestore(&sbi->page_lock, flags);
			return -ENOSPC;
		}
	}

	/* get locally with large pages and pages */
	preallocate_pages_from_larges_and_pages(sbi, ab, count, sbi->gpool);

	spin_unlock(&sbi->large_lock);
	spin_unlock_irqrestore(&sbi->page_lock, flags);

	return 0;
}

void *nvmalloc_pre_get_from_list(struct super_block *sb, struct list_head *list,
				 u8 tag)
{
	struct ptr_list_node *list_node =
		list_first_entry(list, struct ptr_list_node, node);
	void __pmem *page = list_node->ptr;

	list_del(&list_node->node);
	list_node->tag = tag;
	/* list_node->solid is unchanged. */
	_SET_BUSY(list_node, "set_busy addr=%px", page);

	eufs_dbg("nvallocate pre-from-list: %px bitmap=%d busy=%d\n", page,
		 EUFS_SB(sb)->page_map[(page - EUFS_SB(sb)->data_start) /
				       PAGE_SIZE],
		 EUFS_SB(sb)
			 ->cached_nodes[(page - EUFS_SB(sb)->data_start) /
					PAGE_SIZE]
			 .busy);
	return page;
}

int nvmalloc_pre(struct super_block *sb, struct alloc_batch *ab, size_t count,
		 size_t size)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct mem_pool *ppool;
	unsigned long flags;
	int cpu;
	int r;
	/* size other than PAGE_SIZE not supported currently */
	if (size != PAGE_SIZE)
		return -EOPNOTSUPP;

	cpu = get_cpu();
	local_irq_save(flags);

	ppool = per_cpu_ptr(sbi->ppool, cpu);
	if (count <= ppool->nlarges * 512 + ppool->npages) {
		/* get locally */
		r = preallocate_page_from_pool(sbi, ab, count, ppool);
		local_irq_restore(flags);
		put_cpu();
		return r;
	}

	/* get from global pool */
	local_irq_restore(flags);
	put_cpu();
	r = preallocate_page_from_gpool(sbi, ab, count);
	return r;
}

/*
 * Large: 2M
 * Page: 4K
 * Line4: 256B
 * Line: 64B
 */

#define LARGE_PAGE_SIZE (2 << 20)

/*
 * get from ppool list, then from the global list if present,
 * if failed, break larger units.
 */
static void *try_get_large_page(struct eufs_sb_info *sbi,
				struct mem_pool *ppool, u8 tag,
				bool nonblocking)
{
	struct ptr_list_node *list_node;
	void *ret;
	unsigned long flags;

retry:
	if (list_empty(&ppool->large_list) &&
	    !reload_large_from_gpool(sbi, ppool, nonblocking))
		return NULL;

	local_irq_save(flags);
	if (list_empty(&ppool->large_list)) {
		local_irq_restore(flags);
		goto retry;
	}

	list_node = list_first_entry(&ppool->large_list, struct ptr_list_node,
				     node);
	ret = list_node->ptr;
	list_del(&list_node->node);
	ppool->nlarges--;
	list_node->tag = tag;

	local_irq_restore(flags);

	/* list_node->solid is unchanged. */
	_SET_BUSY(list_node, "set_busy addr=%px", ret);

	BUG_ON(((u64)ret % LARGE_PAGE_SIZE));

	return ret;
}

static void *eufs_try_get_page(struct eufs_sb_info *sbi, struct mem_pool *ppool,
			       u8 tag, bool use_reserved)
{
	struct ptr_list_node *list_node;
	struct ptr_list_node *node;
	void *ret;
	unsigned long flags;
	void *large;
	int i;
	u64 page_no;

retry:
	if (list_empty(&ppool->page_list)) {
		/* slow path */
		if (!reload_page_from_gpool(sbi, ppool, use_reserved)) {
			/* TODO: merge pages back to large pages? */
			large = try_get_large_page(sbi, ppool, 0, use_reserved);
			if (!large)
				return NULL;
			page_no = (large - sbi->data_start) / PAGE_SIZE;
			for (i = 1; i < 512; ++i) {
				node = &sbi->cached_nodes[page_no + i];
				node->multiple = false;
				return_page(sbi, ppool, node, false);
			}
			sbi->cached_nodes[page_no].multiple = false;
			sbi->cached_nodes[page_no].tag = tag;
			return large;
		}
	}
	local_irq_save(flags);
	if (list_empty(&ppool->page_list)) {
		local_irq_restore(flags);
		goto retry;
	}
	list_node =
		list_first_entry(&ppool->page_list, struct ptr_list_node, node);

	ret = list_node->ptr;
	list_del(&list_node->node);
	ppool->npages--;
	list_node->tag = tag;

	local_irq_restore(flags);

	/* list_node->solid is unchanged. */
	_SET_BUSY(list_node, "set_busy addr=%px", ret);

	BUG_ON(((u64)ret % PAGE_SIZE));

	return ret;
}

/* NOTICE: cpu changes in this function */
static struct ptr_list_node *split_page_to_lines(struct eufs_sb_info *sbi,
						 struct mem_pool *ppool,
						 void *page, bool use_line4)
{
	struct ptr_list_node *node, *ret = NULL;
	u64 page_no;
	int cpu;
	int i;
	/* Release the cpu since may need to allocate a page. */
	put_cpu();

	/* Split the page */
	page_no = (page - sbi->data_start) / PAGE_SIZE;
	sbi->line_indicators[page_no] = 0;

	if (sbi->line_node_ptrs[page_no]) {
		memclr(sbi->line_node_ptrs[page_no], PAGE_SIZE);
	} else {
		sbi->line_node_ptrs[page_no] = eufs_zalloc_page();
		BUG_ON(!sbi->line_node_ptrs[page_no]);
	}
	memclr(page, CACHELINE_SIZE);

	/* cache line 0: bitmap */
	/* cache line 1~3: insert to line_list */
	/* cache line >4: insert to line4_list */

	/*
	 * Reget the cpu. The cpu might be different from the
	 * one we previously got, but it doesn't matter.
	 */
	cpu = get_cpu();
	ppool = per_cpu_ptr(sbi->ppool, cpu);
	for (i = 1; i < 64; ++i) {
		node = &sbi->line_node_ptrs[page_no][i];
		node->ptr = page + i * CACHELINE_SIZE;
		node->busy = false;
		node->solid = false;
		node->multiple = false;
	}
	for (i = 1; i < 4; ++i) {
		node = &sbi->line_node_ptrs[page_no][i];
		if (!use_line4 && i == 1) {
			ret = node;
			continue;
		}
		return_cl(sbi, ppool, node, false);
	}
	for (i = 4; i < 64; i += 4) {
		node = &sbi->line_node_ptrs[page_no][i];
		node->multiple = true;
		if (use_line4 && i == 4) {
			ret = node;
			continue;
		}
		return_line4(sbi, ppool, node, false);
	}
	return ret;
}

static void *try_get_line4(struct eufs_sb_info *sbi, struct mem_pool *ppool,
			   u8 tag, bool use_reserved)
{
	struct ptr_list_node *list_node;
	unsigned long flags;
	void *ret;

retry:
	/* cache line x 4 */
	if (list_empty(&ppool->line4_list)) {
		/* Cannot fetch cache lines from gpool, get from page  */
		ret = eufs_try_get_page(sbi, ppool, 0, use_reserved);
		if (ret == NULL)
			return NULL;

		list_node = split_page_to_lines(sbi, ppool, ret, true);
		ret = list_node->ptr;
		list_node->tag = tag;
		goto out;
	}

	local_irq_save(flags);
	if (list_empty(&ppool->line4_list)) {
		local_irq_restore(flags);
		goto retry;
	}

	list_node = list_first_entry(&ppool->line4_list, struct ptr_list_node,
				     node);
	ret = list_node->ptr;
	list_del(&list_node->node);

	ppool->nline4s--;
	list_node->tag = tag;

	local_irq_restore(flags);
out:

	_SET_BUSY(list_node, "error cacheline addr=%px", ret);

	return ret;
}

static void *try_get_line(struct eufs_sb_info *sbi, struct mem_pool *ppool,
			  u8 tag, bool use_reserved)
{
	struct ptr_list_node *list_node;
	struct ptr_list_node *node;
	unsigned long flags;
	void *ret;
	int k;

retry:
	/* cache line x 1 */
	if (list_empty(&ppool->line_list)) {
		/* Fetch cache lines from gpool */
		if (!reload_lines_from_gpool(sbi, ppool) /* slow path */) {
			if (list_empty(&ppool->line4_list)) {
				ret = eufs_try_get_page(sbi, ppool, 0,
							use_reserved);
				if (ret == NULL)
					return NULL;

				list_node = split_page_to_lines(sbi, ppool, ret,
								false);
				ret = list_node->ptr;
				list_node->tag = tag;
				goto out;
			} else {
				local_irq_save(flags);
				if (list_empty(&ppool->line4_list)) {
					local_irq_restore(flags);
					goto retry;
				}
				list_node =
					list_first_entry(&ppool->line4_list,
							 struct ptr_list_node,
							 node);
				ret = list_node->ptr;
				list_del(&list_node->node);
				ppool->nline4s--;
				list_node->tag = tag;

				list_node->multiple = false;

				for (k = 1; k < 4; ++k) {
					node = list_node + k;
					node->multiple = false;
					list_add(&node->node,
						 &ppool->line_list);
					ppool->nlines++;
				}
				local_irq_restore(flags);
				goto out;
			}
		}
	}

	local_irq_save(flags);
	if (list_empty(&ppool->line_list)) {
		local_irq_restore(flags);
		goto retry;
	}

	list_node =
		list_first_entry(&ppool->line_list, struct ptr_list_node, node);
	ret = list_node->ptr;
	list_del(&list_node->node);

	ppool->nlines--;
	list_node->tag = tag;

	local_irq_restore(flags);
out:

	_SET_BUSY(list_node, "error cacheline addr=%px", ret);

	return ret;
}

/*
 * If nonblocking is set, we will skip the gather phase and allocate from the
 * reserved pages (in gpool)
 */
void *nvmalloc(struct super_block *sb, size_t size, u8 tag, bool nonblocking)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct mem_pool *ppool;
	void __pmem *ret;
	int cpu;
	u64 npages;
	u64 nlines;
	bool once_gathered = false;
	void *(*try_get_)(struct eufs_sb_info *sbi, struct mem_pool *mp, u8 tag,
			  bool use_reserved);

	if (size == PAGE_SIZE << 9) {
		try_get_ = try_get_large_page;
	} else if (size == PAGE_SIZE) {
		try_get_ = eufs_try_get_page;
	} else if (size == CACHELINE_SIZE << 2) {
		try_get_ = try_get_line4;
	} else if (size == CACHELINE_SIZE) {
		try_get_ = try_get_line;
	} else {
		WARN(1, "EulerFS: INVALID allocation size!");
		return NULL;
	}

gathered_retry:
	cpu = get_cpu();
	ppool = per_cpu_ptr(sbi->ppool, cpu);
	/*
	 * If we have gathered, we must try our best to allocate, so
	 * even the reserved pages can be used
	 */
	ret = try_get_(sbi, ppool, tag, nonblocking || once_gathered);

	if (ret == NULL) {
		if (once_gathered || nonblocking)
			/* Really full */
			goto full_out;
		/* Maybe full. Try gather from other CPUs. */
		put_cpu();
		gather_pages(sbi);
		once_gathered = true;
		goto gathered_retry;
	}
	put_cpu();

	eufs_dbg("nvallocate: %px bitmap=%d busy=%d @cpu=%d\n", ret,
		 sbi->page_map[(ret - sbi->data_start) / PAGE_SIZE],
		 sbi->cached_nodes[(ret - sbi->data_start) / PAGE_SIZE].busy,
		 cpu);

	WARN_ON(ret == NULL);
	return ret;
full_out:
	put_cpu();
	nv_stat(sbi, &npages, &nlines);
	pr_warn_ratelimited("EulerFS is FULL! @%d (%lld pages, %lld lines)\n",
			    smp_processor_id(), npages, nlines);
	return NULL;
}

static void _unset_bitmap(struct eufs_sb_info *sbi, u64 addr, bool flush)
{
	u64 page_no = (addr - (u64)sbi->data_start) / PAGE_SIZE;
	u64 rem = addr % PAGE_SIZE;
	line_info_t __pmem *line_map;
	struct ptr_list_node *node;
	int line_no;

	node = sbi->cached_nodes + (page_no);
	if (rem == 0) {
		/*
		 * the nvmalloc->nvfree case should be handled when nolde->solid
		 * is false if the allocation is implemented. Same as below.
		 */
		if (node->solid) {
			BUG_ON(sbi->page_map[page_no] == EUFS_PAGE_FREE);
			sbi->page_map[page_no] = EUFS_PAGE_FREE;
			if (flush)
				eufs_flush_cacheline(&sbi->page_map[page_no]);
		}

		BUG_ON(sbi->page_map[page_no] != EUFS_PAGE_FREE);
		node->solid = false;
	} else {
		/* line */
		BUG_ON(rem % CACHELINE_SIZE != 0);

		BUG_ON(sbi->page_map[page_no] != EUFS_PAGE_FREE &&
		       sbi->page_map[page_no] != EUFS_PAGE_LINE_USED);

		if (!node->solid) {
			/* the allocation is not written yet */
			/* HACK: idempotent */
			if (sbi->page_map[page_no] != EUFS_PAGE_LINE_USED) {
				sbi->page_map[page_no] = EUFS_PAGE_LINE_USED;
				eufs_flush_cacheline(&sbi->page_map[page_no]);
			}
			node->solid = true;
		}

		node = &sbi->line_node_ptrs[page_no][rem / CACHELINE_SIZE];
		line_map = (void *)(addr - rem);
		line_no = rem / CACHELINE_SIZE;

		if (node->solid) {
			BUG_ON(line_map[line_no] == EUFS_LINE_FREE);
			line_map[line_no] = EUFS_LINE_FREE;
			eufs_dbg("unset %px[%d] = 0\n", line_map, line_no);

			if (flush)
				eufs_flush_cacheline(&line_map[line_no]);
		}

		node->solid = false;
		BUG_ON(line_map[line_no] != EUFS_LINE_FREE);
	}
}

void nvfree(struct super_block *sb, void *ptr, bool rest)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct mem_pool *ppool;
	struct ptr_list_node *node;
	s64 offset;
	int cpu;
	u64 end = sbi->npages * PAGE_SIZE;

	if (ptr == NULL_ADDR_PTR)
		return;

	offset = ptr - sbi->data_start;
	BUG_ON(offset < 0);
	BUG_ON(offset >= end);

	eufs_dbg("%s: %px bitmap=%d busy=%d\n", __func__, ptr,
		 sbi->page_map[(ptr - sbi->data_start) / PAGE_SIZE],
		 sbi->cached_nodes[(ptr - sbi->data_start) / PAGE_SIZE].busy);

	_unset_bitmap(sbi, (u64)ptr, true);

	cpu = get_cpu();
	ppool = per_cpu_ptr(sbi->ppool, cpu);
	if ((u64)ptr % PAGE_SIZE == 0) {
		/* page */

		/* get node */
		node = sbi->cached_nodes + offset / PAGE_SIZE;
		node->ptr = ptr;
		_SET_NON_BUSY(node, "fault addr %px", ptr);
		/* add to page-to-free list */
		if (node->multiple)
			WARN_ON_ONCE(1);
		else
			return_page(sbi, ppool, node, rest);
	} else if ((u64)ptr % CACHELINE_SIZE == 0) {
		/* cache line */

		/* get node */
		node = &sbi->line_node_ptrs[offset / PAGE_SIZE]
					   [offset % PAGE_SIZE / CACHELINE_SIZE];
		_SET_NON_BUSY(node, "fault addr %px", ptr);
		/* add to local cl pool */
		if (node->multiple)
			return_line4(sbi, ppool, node, rest);
		else
			return_cl(sbi, ppool, node, rest);
	} else {
		/* error */
		eufs_warn("!err allocation type!\n");
	}
	put_cpu();
	eufs_dbg("%s done: %px bitmap=%d busy=%d\n", __func__, ptr,
		 sbi->page_map[(ptr - sbi->data_start) / PAGE_SIZE],
		 sbi->cached_nodes[(ptr - sbi->data_start) / PAGE_SIZE].busy);
}
