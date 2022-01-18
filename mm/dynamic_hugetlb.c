// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dynamic hugetlb core file
 */

#include <linux/rmap.h>
#include <linux/migrate.h>
#include <linux/memory_hotplug.h>
#include <linux/dynamic_hugetlb.h>

#include "internal.h"

static bool enable_dhugetlb = false;
DEFINE_STATIC_KEY_FALSE(dhugetlb_enabled_key);

#define hugepage_index(pfn)	((pfn) >> (PUD_SHIFT - PAGE_SHIFT))
static void add_new_page_to_pool(struct dhugetlb_pool *hpool, struct page *page, int hpages_pool_idx)
{
	struct huge_pages_pool *hpages_pool = &hpool->hpages_pool[hpages_pool_idx];

	lockdep_assert_held(&hpool->lock);
	VM_BUG_ON_PAGE(page_mapcount(page), page);
	INIT_LIST_HEAD(&page->lru);

	switch (hpages_pool_idx) {
		case HUGE_PAGES_POOL_1G:
			prep_compound_gigantic_page(page, PUD_SHIFT - PAGE_SHIFT);
			set_compound_page_dtor(page, HUGETLB_PAGE_DTOR);
			set_hugetlb_cgroup(page, NULL);
			break;
		case HUGE_PAGES_POOL_2M:
			prep_compound_page(page, PMD_SHIFT - PAGE_SHIFT);
			set_compound_page_dtor(page, HUGETLB_PAGE_DTOR);
			set_hugetlb_cgroup(page, NULL);
			break;
	}
	list_add_tail(&page->lru, &hpages_pool->hugepage_freelists);
	hpages_pool->free_normal_pages++;
}

static void __hpool_split_gigantic_page(struct dhugetlb_pool *hpool, struct page *page)
{
	int nr_pages = 1 << (PUD_SHIFT - PAGE_SHIFT);
	int nr_blocks = 1 << (PMD_SHIFT - PAGE_SHIFT);
	int i;

	lockdep_assert_held(&hpool->lock);
	atomic_set(compound_mapcount_ptr(page), 0);
	atomic_set(compound_pincount_ptr(page), 0);

	for (i = 1; i < nr_pages; i++)
		clear_compound_head(&page[i]);
	set_compound_order(page, 0);
	page[1].compound_nr = 0;
	__ClearPageHead(page);

	for (i = 0; i < nr_pages; i+= nr_blocks)
		add_new_page_to_pool(hpool, &page[i], HUGE_PAGES_POOL_2M);
}

static void __hpool_split_huge_page(struct dhugetlb_pool *hpool, struct page *page)
{
	int nr_pages = 1 << (PMD_SHIFT - PAGE_SHIFT);
	int i;

	lockdep_assert_held(&hpool->lock);
	set_compound_page_dtor(page, NULL_COMPOUND_DTOR);
	set_compound_order(page, 0);

	__ClearPageHead(page);
	for (i = 0; i < nr_pages; i++) {
		page[i].flags &= ~(1 << PG_locked | 1 << PG_error |
				1 << PG_referenced | 1 << PG_dirty |
				1 << PG_active | 1 << PG_private |
				1 << PG_writeback);
		if (i != 0) {
			page[i].mapping = NULL;
			clear_compound_head(&page[i]);
		}
		add_new_page_to_pool(hpool, &page[i], HUGE_PAGES_POOL_4K);
	}
}

static int hpool_split_page(struct dhugetlb_pool *hpool, int hpages_pool_idx)
{
	struct huge_pages_pool *hpages_pool;
	struct split_hugepage *split_page;
	struct page *page;

	lockdep_assert_held(&hpool->lock);

	if (hpages_pool_idx < 0 || hpages_pool_idx >= HUGE_PAGES_POOL_MAX - 1)
		return -EINVAL;

	hpages_pool = &hpool->hpages_pool[hpages_pool_idx];

	/* If hpages_pool has no pages to split, try higher hpages_pool */
	if (!hpages_pool->free_normal_pages &&
	    hpool_split_page(hpool, hpages_pool_idx - 1))
		return -ENOMEM;

	split_page = kzalloc(sizeof(struct split_hugepage), GFP_ATOMIC);
	if (!split_page)
		return -ENOMEM;

	page = list_entry(hpages_pool->hugepage_freelists.next, struct page, lru);
	list_del(&page->lru);
	hpages_pool->free_normal_pages--;

	split_page->start_pfn = page_to_pfn(page);
	list_add(&split_page->head_pages, &hpages_pool->hugepage_splitlists);
	hpages_pool->split_normal_pages++;

	switch (hpages_pool_idx) {
		case HUGE_PAGES_POOL_1G:
			__hpool_split_gigantic_page(hpool, page);
			break;
		case HUGE_PAGES_POOL_2M:
			__hpool_split_huge_page(hpool, page);
			break;
	}
	return 0;
}

static int add_pages_to_percpu_pool(struct dhugetlb_pool *hpool,
				    struct percpu_pages_pool *percpu_pool,
				    unsigned long nr_pages)
{
	struct huge_pages_pool *hpages_pool = &hpool->hpages_pool[HUGE_PAGES_POOL_4K];
	struct page *page, *next;
	int ret, i = 0;

	while (hpages_pool->free_normal_pages < nr_pages) {
		ret = hpool_split_page(hpool, HUGE_PAGES_POOL_2M);
		if (ret)
			break;
	}

	list_for_each_entry_safe(page, next, &hpages_pool->hugepage_freelists, lru) {
		list_del(&page->lru);
		hpages_pool->free_normal_pages--;
		list_add_tail(&page->lru, &percpu_pool->head_page);
		percpu_pool->free_pages++;
		if (++i == nr_pages)
			break;
	}

	if (percpu_pool->free_pages == 0)
		return -ENOMEM;
	return 0;
}

static void reclaim_pages_from_percpu_pool(struct dhugetlb_pool *hpool,
					struct percpu_pages_pool *percpu_pool,
					unsigned long nr_pages)
{
	struct huge_pages_pool *hpages_pool = &hpool->hpages_pool[HUGE_PAGES_POOL_4K];
	struct page *page, *next;
	int i = 0;

	list_for_each_entry_safe(page, next, &percpu_pool->head_page, lru) {
		list_del(&page->lru);
		percpu_pool->free_pages--;
		list_add(&page->lru, &hpages_pool->hugepage_freelists);
		hpages_pool->free_normal_pages++;
		if (++i == nr_pages)
			break;
	}
}

static void clear_percpu_pools(struct dhugetlb_pool *hpool)
{
	struct percpu_pages_pool *percpu_pool;
	int i;

	lockdep_assert_held(&hpool->lock);

	spin_unlock(&hpool->lock);
	for (i = 0; i < NR_PERCPU_POOL; i++)
		spin_lock(&hpool->percpu_pool[i].lock);
	spin_lock(&hpool->lock);
	for (i = 0; i < NR_PERCPU_POOL; i++) {
		percpu_pool = &hpool->percpu_pool[i];
		reclaim_pages_from_percpu_pool(hpool, percpu_pool, percpu_pool->free_pages);
	}
	for (i = 0; i < NR_PERCPU_POOL; i++)
		spin_unlock(&hpool->percpu_pool[i].lock);
}

/* We only try 5 times to reclaim pages */
#define	HPOOL_RECLAIM_RETRIES	5

static int hpool_merge_page(struct dhugetlb_pool *hpool, int hpages_pool_idx, bool force_merge)
{
	struct huge_pages_pool *hpages_pool, *src_hpages_pool;
	struct split_hugepage *split_page, *split_next;
	unsigned long nr_pages, block_size;
	struct page *page, *next;
	bool need_migrate = false;
	int i, try;
	LIST_HEAD(wait_page_list);

	lockdep_assert_held(&hpool->lock);

	if (hpages_pool_idx < 0 || hpages_pool_idx >= HUGE_PAGES_POOL_MAX - 1)
		return -EINVAL;

	switch (hpages_pool_idx) {
		case HUGE_PAGES_POOL_1G:
			nr_pages = 1 << (PUD_SHIFT - PMD_SHIFT);
			block_size = 1 << (PMD_SHIFT - PAGE_SHIFT);
			break;
		case HUGE_PAGES_POOL_2M:
			nr_pages = 1 << (PMD_SHIFT - PAGE_SHIFT);
			block_size = 1;
			need_migrate |= force_merge;
			break;
	}

	hpages_pool = &hpool->hpages_pool[hpages_pool_idx];
	src_hpages_pool = &hpool->hpages_pool[hpages_pool_idx + 1];
	if (!hpages_pool->split_normal_pages)
		return -ENOMEM;

	list_for_each_entry_safe(split_page, split_next, &hpages_pool->hugepage_splitlists, head_pages) {
		try = 0;

merge:
		clear_percpu_pools(hpool);
		page = pfn_to_page(split_page->start_pfn);
		for (i = 0; i < nr_pages; i+= block_size) {
			if (PagePool(&page[i])) {
				if (!need_migrate)
					goto next;
				else
					goto migrate;
			}
		}

		list_del(&split_page->head_pages);
		hpages_pool->split_normal_pages--;
		kfree(split_page);
		for (i = 0; i < nr_pages; i+= block_size) {
			list_del(&page[i].lru);
			src_hpages_pool->free_normal_pages--;
		}
		add_new_page_to_pool(hpool, page, hpages_pool_idx);
		return 0;
next:
		continue;
migrate:
		if (try++ >= HPOOL_RECLAIM_RETRIES)
			goto next;

		/* Isolate free page first. */
		INIT_LIST_HEAD(&wait_page_list);
		for (i = 0; i < nr_pages; i+= block_size) {
			if (!PagePool(&page[i])) {
				list_move(&page[i].lru, &wait_page_list);
				src_hpages_pool->free_normal_pages--;
			}
		}

		/* Unlock and try migration. */
		spin_unlock(&hpool->lock);
		for (i = 0; i < nr_pages; i+= block_size) {
			if (PagePool(&page[i]))
				/*
				 * TODO: fatal migration failures should bail
				 * out
				 */
				do_migrate_range(page_to_pfn(&page[i]), page_to_pfn(&page[i]) + block_size);
		}
		spin_lock(&hpool->lock);

		list_for_each_entry_safe(page, next, &wait_page_list, lru) {
			list_move_tail(&page->lru, &src_hpages_pool->hugepage_freelists);
			src_hpages_pool->free_normal_pages++;
		}
		goto merge;
	}
	return -ENOMEM;
}

static int hugetlb_pool_merge_all_pages(struct dhugetlb_pool *hpool)
{
	int ret = 0;

	spin_lock(&hpool->lock);
	while (hpool->hpages_pool[HUGE_PAGES_POOL_2M].split_normal_pages) {
		ret = hpool_merge_page(hpool, HUGE_PAGES_POOL_2M, true);
		if (ret) {
			pr_err("dynamic_hugetlb: some 4K pages are still in use, delete memcg: %s failed!\n",
				hpool->attach_memcg->css.cgroup->kn->name);
			goto out;
		}
	}
	while (hpool->hpages_pool[HUGE_PAGES_POOL_1G].split_normal_pages) {
		ret = hpool_merge_page(hpool, HUGE_PAGES_POOL_1G, true);
		if (ret) {
			pr_err("dynamic_hugetlb: some 2M pages are still in use, delete memcg: %s failed!\n",
				hpool->attach_memcg->css.cgroup->kn->name);
			goto out;
		}
	}
	if (hpool->hpages_pool[HUGE_PAGES_POOL_1G].used_huge_pages) {
		ret = -ENOMEM;
		pr_err("dynamic_hugetlb: some 1G pages are still in use, delete memcg: %s failed!\n",
			hpool->attach_memcg->css.cgroup->kn->name);
		goto out;
	}
out:
	spin_unlock(&hpool->lock);
	return ret;
}

static bool get_hpool_unless_zero(struct dhugetlb_pool *hpool)
{
	if (!dhugetlb_enabled || !hpool)
		return false;
	return atomic_inc_not_zero(&hpool->refcnt);
}

static void put_hpool(struct dhugetlb_pool *hpool)
{
	if (!dhugetlb_enabled || !hpool)
		return;
	if (atomic_dec_and_test(&hpool->refcnt)) {
		css_put(&hpool->attach_memcg->css);
		kfree(hpool);
	}
}

struct dhugetlb_pagelist {
	unsigned long count;
	struct dhugetlb_pool *hpool[0];
};

static struct dhugetlb_pagelist *dhugetlb_pagelist_t;
static DEFINE_RWLOCK(dhugetlb_pagelist_rwlock);

static int set_hpool_in_dhugetlb_pagelist(unsigned long idx, struct dhugetlb_pool *hpool)
{
	/*
	 * There is not conflit when write to dhugetlb_pagelist_t->hpool, so just
	 * need read_lock here.
	 */
	read_lock(&dhugetlb_pagelist_rwlock);

	/*
	 * If page's pfn is greater than dhugetlb_pagelist_t->count (which may
	 * occurs due to memory hotplug) then dhugetlb_pagelist_t need to be
	 * reallocated, so need write_lock here.
	 */
	if (idx >= dhugetlb_pagelist_t->count) {
		unsigned long size;
		struct dhugetlb_pagelist *tmp;

		read_unlock(&dhugetlb_pagelist_rwlock);
		write_lock(&dhugetlb_pagelist_rwlock);

		size = sizeof(struct dhugetlb_pagelist) +
			(idx + 1) * sizeof(struct dhugetlb_pool *);
		tmp = krealloc(dhugetlb_pagelist_t, size, GFP_ATOMIC);
		if (!tmp) {
			write_unlock(&dhugetlb_pagelist_rwlock);
			return -ENOMEM;
		}
		tmp->count = idx + 1;
		dhugetlb_pagelist_t = tmp;

		write_unlock(&dhugetlb_pagelist_rwlock);
		read_lock(&dhugetlb_pagelist_rwlock);
	}
	dhugetlb_pagelist_t->hpool[idx] = hpool;
	read_unlock(&dhugetlb_pagelist_rwlock);

	return 0;
}

static struct dhugetlb_pool *find_hpool_by_task(struct task_struct *tsk)
{
	struct mem_cgroup *memcg;

	if (!dhugetlb_enabled)
		return NULL;

	rcu_read_lock();
	memcg = mem_cgroup_from_task(tsk);
	rcu_read_unlock();

	if (!memcg)
		return NULL;

	return memcg->hpool;
}

int task_has_mem_in_hpool(struct task_struct *tsk)
{
	struct dhugetlb_pool *hpool;

	if (!dhugetlb_enabled)
		return 0;

	hpool = find_hpool_by_task(tsk);

	return hpool ? -EPERM : 0;
}

static bool should_allocate_from_dhugetlb_pool(gfp_t gfp_mask)
{
	gfp_t gfp = gfp_mask & GFP_HIGHUSER_MOVABLE;

	if (current->flags & PF_KTHREAD)
		return false;

	/*
	 * The cgroup only charges anonymous and file pages from usespage.
	 * some filesystem maybe has masked out the __GFP_IO | __GFP_FS
	 * to avoid recursive memory request. eg: loop device, xfs.
	 */
	if ((gfp | __GFP_IO | __GFP_FS) != GFP_HIGHUSER_MOVABLE)
		return false;

	return true;
}

static struct page *__alloc_page_from_dhugetlb_pool(void)
{
	struct percpu_pages_pool *percpu_pool;
	struct dhugetlb_pool *hpool;
	struct page *page = NULL;
	unsigned long flags;

	hpool = find_hpool_by_task(current);

	if (!get_hpool_unless_zero(hpool))
		return NULL;

	percpu_pool = &hpool->percpu_pool[smp_processor_id()];
	/*
	 * Before we lock percpu_pool, must be sure hpool is unlocked.
	 */
	spin_lock_irqsave(&percpu_pool->lock, flags);

	if (percpu_pool->free_pages == 0) {
		int ret;

		spin_lock(&hpool->lock);
		ret = add_pages_to_percpu_pool(hpool, percpu_pool,
						PERCPU_POOL_PAGE_BATCH);
		spin_unlock(&hpool->lock);
		if (ret)
			goto unlock;
	}

	page = list_entry(percpu_pool->head_page.next, struct page, lru);
	list_del(&page->lru);
	percpu_pool->free_pages--;
	percpu_pool->used_pages++;
	SetPagePool(page);

unlock:
	spin_unlock_irqrestore(&percpu_pool->lock, flags);
	put_hpool(hpool);
	return page;
}

struct page *alloc_page_from_dhugetlb_pool(gfp_t gfp, unsigned int order,
					   unsigned int flags)
{
	struct page *page = NULL;

	if (!dhugetlb_enabled)
		return NULL;

	if (order != 0)
		return NULL;

	if (should_allocate_from_dhugetlb_pool(gfp))
		page = __alloc_page_from_dhugetlb_pool();

	if (page)
		prep_new_page(page, order, gfp, flags);
	return page;
}

static int alloc_hugepage_from_hugetlb(struct dhugetlb_pool *hpool,
				       unsigned long nid, unsigned long nr_pages)
{
	struct hstate *h = size_to_hstate(PUD_SIZE);
	struct huge_pages_pool *hpages_pool = &hpool->hpages_pool[HUGE_PAGES_POOL_1G];
	struct page *page, *next;
	unsigned long count = 0, idx;
	int ret = 0;

	if (!h)
		return -ENOMEM;

	spin_lock(&hpool->lock);
	spin_lock(&hugetlb_lock);
	if (h->free_huge_pages_node[nid] - h->resv_huge_pages_node[nid] < nr_pages) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	list_for_each_entry_safe(page, next, &h->hugepage_freelists[nid], lru) {
		idx = hugepage_index(page_to_pfn(page));
		ret = set_hpool_in_dhugetlb_pagelist(idx, hpool);
		if (ret)
			continue;

		list_move_tail(&page->lru, &hpages_pool->hugepage_freelists);
		h->free_huge_pages--;
		h->free_huge_pages_node[nid]--;
		hpool->total_huge_pages++;
		hpages_pool->free_normal_pages++;

		if (++count == nr_pages)
			break;
	}

out_unlock:
	spin_unlock(&hugetlb_lock);
	spin_unlock(&hpool->lock);
	return ret;
}

static int free_hugepage_to_hugetlb(struct dhugetlb_pool *hpool)
{
	struct hstate *h = size_to_hstate(PUD_SIZE);
	struct huge_pages_pool *hpages_pool = &hpool->hpages_pool[HUGE_PAGES_POOL_1G];
	struct page *page, *next, *p;
	unsigned long pfn, idx;
	unsigned int nr_pages;
	int nid, ret = 0;

	spin_lock(&hpool->lock);
	spin_lock(&hugetlb_lock);
	list_for_each_entry_safe(page, next, &hpages_pool->hugepage_freelists, lru) {
		nr_pages = 1 << huge_page_order(h);
		pfn = page_to_pfn(page);
		for (; nr_pages--; pfn++) {
			p = pfn_to_page(pfn);
			p->mapping = NULL;
		}
		set_compound_page_dtor(page, HUGETLB_PAGE_DTOR);

		nid = page_to_nid(page);
		list_move(&page->lru, &h->hugepage_freelists[nid]);
		hpool->total_huge_pages--;
		hpages_pool->free_normal_pages--;
		h->free_huge_pages++;
		h->free_huge_pages_node[nid]++;

		idx = hugepage_index(page_to_pfn(page));
		ret = set_hpool_in_dhugetlb_pagelist(idx, NULL);
		if (ret)
			break;
	}
	spin_unlock(&hugetlb_lock);
	spin_unlock(&hpool->lock);
	return ret;
}

void hugetlb_pool_inherit(struct mem_cgroup *memcg, struct mem_cgroup *parent)
{
	if (!dhugetlb_enabled || !memcg || !parent)
		return;
	memcg->hpool = parent->hpool;
}

static int hugetlb_pool_create(struct mem_cgroup *memcg, unsigned long nid)
{
	struct dhugetlb_pool *hpool;
	int i;

	if (memcg_has_children(memcg))
		return -EINVAL;

	hpool = kzalloc(sizeof(struct dhugetlb_pool) +
			NR_PERCPU_POOL * sizeof(struct percpu_pages_pool), GFP_KERNEL);
	if (!hpool)
		return -ENOMEM;

	spin_lock_init(&hpool->lock);
	spin_lock_init(&hpool->reserved_lock);
	hpool->nid = nid;
	atomic_set(&hpool->refcnt, 1);

	for (i = 0; i < HUGE_PAGES_POOL_MAX; i++) {
		INIT_LIST_HEAD(&hpool->hpages_pool[i].hugepage_freelists);
		INIT_LIST_HEAD(&hpool->hpages_pool[i].hugepage_splitlists);
	}
	for (i = 0; i < NR_PERCPU_POOL; i++) {
		spin_lock_init(&hpool->percpu_pool[i].lock);
		INIT_LIST_HEAD(&hpool->percpu_pool[i].head_page);
	}

	hpool->attach_memcg = memcg;
	css_get(&memcg->css);
	memcg->hpool = hpool;

	return 0;
}

int hugetlb_pool_destroy(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *css = cgrp->subsys[memory_cgrp_id];
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	struct dhugetlb_pool *hpool = memcg ? memcg->hpool : NULL;
	int ret = 0;

	if (!dhugetlb_enabled)
		return 0;

	if (!hpool || hpool->attach_memcg != memcg)
		return 0;

	ret = hugetlb_pool_merge_all_pages(hpool);
	if (ret)
		return -ENOMEM;
	ret = free_hugepage_to_hugetlb(hpool);
	memcg->hpool = NULL;

	put_hpool(hpool);
	return ret;
}

static int hugetlb_pool_update(struct mem_cgroup *memcg,
			       unsigned long nid, unsigned long size)
{
	struct dhugetlb_pool *hpool;
	bool new_create = false;
	int ret = -EINVAL;

again:
	hpool = memcg->hpool;
	if (!hpool) {
		ret = hugetlb_pool_create(memcg, nid);
		if (ret)
			return ret;
		new_create = true;
		goto again;
	}
	if (!get_hpool_unless_zero(hpool))
		return -EINVAL;

	if (hpool->attach_memcg != memcg || hpool->nid != nid)
		goto out;
	ret = alloc_hugepage_from_hugetlb(hpool, nid, size);
	/*
	 * if create a new hpool here but alloc hugepages failed,
	 * destroy it directly here.
	 */
	if (ret && new_create) {
		memcg->hpool = NULL;
		put_hpool(hpool);
	}
out:
	put_hpool(hpool);
	return ret;
}

bool dhugetlb_hide_files(struct cftype *cft)
{
	if (!dhugetlb_enabled && strstr(cft->name, "dhugetlb"))
		return true;
	return false;
}

static ssize_t update_reserved_pages(struct mem_cgroup *memcg, char *buf, int hpages_pool_idx)
{
	struct dhugetlb_pool *hpool = memcg->hpool;
	struct huge_pages_pool *hpages_pool;
	unsigned long nr_pages;
	unsigned long delta;
	char *endp;

	if (!dhugetlb_enabled)
		return -EINVAL;

	buf = strstrip(buf);
	nr_pages = memparse(buf, &endp);
	if (*endp != '\0')
		return -EINVAL;

	if (!get_hpool_unless_zero(hpool))
		return -EINVAL;

	spin_lock(&hpool->reserved_lock);
	spin_lock(&hpool->lock);
	hpages_pool = &hpool->hpages_pool[hpages_pool_idx];
	if (nr_pages > hpages_pool->nr_huge_pages) {
		delta = nr_pages - hpages_pool->nr_huge_pages;
		while (delta > hpages_pool->free_normal_pages) {
			if (hpool_split_page(hpool, hpages_pool_idx - 1))
				break;
		}
		/*
		 * First try to merge pages without migration, If this can not meet
		 * the requirements, then try to merge pages with migration.
		 */
		while (delta > hpages_pool->free_normal_pages) {
			if (hpool_merge_page(hpool, hpages_pool_idx, false))
				break;
		}
		while (delta > hpages_pool->free_normal_pages) {
			if (hpool_merge_page(hpool, hpages_pool_idx, true))
				break;
		}
		delta = min(nr_pages - hpages_pool->nr_huge_pages, hpages_pool->free_normal_pages);
		hpages_pool->nr_huge_pages += delta;
		hpages_pool->free_huge_pages += delta;
		hpages_pool->free_normal_pages -= delta;
	} else {
		delta = min(hpages_pool->nr_huge_pages - nr_pages,
			    hpages_pool->free_huge_pages - hpages_pool->resv_huge_pages);
		hpages_pool->nr_huge_pages -= delta;
		hpages_pool->free_huge_pages -= delta;
		hpages_pool->free_normal_pages += delta;
	}
	spin_unlock(&hpool->lock);
	spin_unlock(&hpool->reserved_lock);
	put_hpool(hpool);
	return 0;
}

ssize_t write_2M_reserved_pages(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));

	return update_reserved_pages(memcg, buf, HUGE_PAGES_POOL_2M) ?: nbytes;
}

ssize_t write_1G_reserved_pages(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));

	return update_reserved_pages(memcg, buf, HUGE_PAGES_POOL_1G) ?: nbytes;
}

ssize_t write_hugepage_to_hpool(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	unsigned long nid, size;
	char *endp;
	int ret;

	if (!dhugetlb_enabled || !memcg)
		return -EINVAL;

	buf = strstrip(buf);
	nid = memparse(buf, &endp);
	if (*endp != ' ' || nid < 0 || nid >= MAX_NUMNODES)
		return -EINVAL;

	buf = endp + 1;
	size = memparse(buf, &endp);
	if (*endp != '\0' || size == 0)
		return -EINVAL;

	ret = hugetlb_pool_update(memcg, nid, size);

	return ret ? : nbytes;
}

int hugetlb_pool_info_show(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct dhugetlb_pool *hpool = memcg ? memcg->hpool : NULL;
	unsigned long free_pages;
	long used_pages = 0;
	int i;

	if (!dhugetlb_enabled)
		return 0;

	if (!hpool) {
		seq_printf(m, "Curent hierarchial have not memory pool.\n");
		return 0;
	}

	if (!get_hpool_unless_zero(hpool))
		return 0;

	for (i = 0; i < NR_PERCPU_POOL; i++)
		spin_lock(&hpool->percpu_pool[i].lock);
	spin_lock(&hpool->lock);

	free_pages = hpool->hpages_pool[HUGE_PAGES_POOL_4K].free_normal_pages;
	for (i = 0; i < NR_PERCPU_POOL; i++) {
		free_pages += hpool->percpu_pool[i].free_pages;
		used_pages += hpool->percpu_pool[i].used_pages;
	}

	seq_printf(m,
		   "dhugetlb_total_pages %ld\n"
		   "1G_total_reserved_pages %ld\n"
		   "1G_free_reserved_pages %ld\n"
		   "1G_mmap_reserved_pages %ld\n"
		   "1G_used_pages %ld\n"
		   "2M_total_reserved_pages %ld\n"
		   "2M_free_reserved_pages %ld\n"
		   "2M_mmap_reserved_pages %ld\n"
		   "2M_used_pages %ld\n"
		   "1G_free_unreserved_pages %ld\n"
		   "2M_free_unreserved_pages %ld\n"
		   "4K_free_pages %ld\n"
		   "4K_used_pages %ld\n",
		   hpool->total_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_1G].nr_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_1G].free_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_1G].resv_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_1G].used_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_2M].nr_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_2M].free_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_2M].resv_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_2M].used_huge_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_1G].free_normal_pages,
		   hpool->hpages_pool[HUGE_PAGES_POOL_2M].free_normal_pages,
		   free_pages,
		   used_pages);

	spin_unlock(&hpool->lock);
	for (i = NR_PERCPU_POOL - 1; i >= 0; i--)
		spin_unlock(&hpool->percpu_pool[i].lock);
	put_hpool(hpool);
	return 0;
}

#define	DEFAULT_PAGELIST_COUNT	4096
void __init dynamic_hugetlb_init(void)
{
	unsigned long count, size;

	if (!enable_dhugetlb)
		return;

	count = max(hugepage_index(max_pfn), (unsigned long)DEFAULT_PAGELIST_COUNT);
	size = sizeof(struct dhugetlb_pagelist) + count * sizeof(struct dhugetlb_pool *);
	dhugetlb_pagelist_t = kzalloc(size, GFP_KERNEL);
	if (!dhugetlb_pagelist_t) {
		pr_info("Dynamic hugetlb init failed, need %lu memory\n", size);
		return;
	}

	dhugetlb_pagelist_t->count = count;
	static_branch_enable(&dhugetlb_enabled_key);
	pr_info("Dynamic hugetlb is enabled\n");
}

static int __init dynamic_hugetlb_setup(char *s)
{
	if (!strcmp(s, "on"))
		enable_dhugetlb = true;
	return 1;
}
__setup("dynamic_hugetlb=", dynamic_hugetlb_setup);
