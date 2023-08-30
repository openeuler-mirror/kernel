// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Chen Jun
 *
 */
#include "swap_policy.h"

#include <linux/list_lru.h>
#include <linux/mm.h>

static struct list_lru swap_list_lru;

static int add_page(struct page *page)
{
	struct list_lru *lru = &swap_list_lru;
	int nid = page_to_nid(page);
	struct list_head *item = &page->lru;
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;

	spin_lock(&nlru->lock);
	if (list_empty(item)) {
		l = &nlru->lru;
		list_move_tail(item, &l->list);
		SetPageLRU(page);
		spin_unlock(&nlru->lock);
		return 0;
	}
	spin_unlock(&nlru->lock);
	return -EINVAL;
}

static int del_page(struct page *page)
{
	struct list_lru *lru = &swap_list_lru;
	int nid = page_to_nid(page);
	struct list_head *item = &page->lru;
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;

	spin_lock(&nlru->lock);
	if (PageLRU(page) && !list_empty(item)) {
		l = &nlru->lru;
		list_del_init(item);
		__ClearPageLRU(page);
		spin_unlock(&nlru->lock);
		return 0;
	}
	spin_unlock(&nlru->lock);
	return -EINVAL;
}

static int update_page(struct page *page)
{
	struct list_lru *lru = &swap_list_lru;
	int nid = page_to_nid(page);
	struct list_head *item = &page->lru;
	struct list_lru_node *nlru = &lru->node[nid];
	struct list_lru_one *l;
	int page_isolate;

	spin_lock(&nlru->lock);
	l = &nlru->lru;
	list_move_tail(item, &l->list);
	page_isolate = PageIsolated(page);
	__ClearPageIsolated(page);
	SetPageLRU(page);
	spin_unlock(&nlru->lock);

	return 0;
}

static enum lru_status lru_isolate_shrink(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct list_head *victim_list = arg;
	struct page *page = list_entry(item, struct page, lru);

	list_lru_isolate_move(lru, item, victim_list);
	__ClearPageLRU(page);
	__SetPageIsolated(page);
	return LRU_REMOVED;
}

static int pick_victim_pages(struct list_head *page_list, int nid, unsigned long *nr)
{
	list_lru_walk_node(&swap_list_lru, nid, lru_isolate_shrink, page_list, nr);

	return 0;
}

static int init(void)
{
	list_lru_init(&swap_list_lru);

	return 0;
}

struct swap_policy swap_policy_list_lru = {
	.init = init,
	.add_page = add_page,
	.del_page = del_page,
	.update_page = update_page,
	.pick_victim_pages = pick_victim_pages,
};
