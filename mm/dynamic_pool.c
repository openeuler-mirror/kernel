// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dynamic pool core file
 *
 * Copyright (C) 2024 Huawei Limited.
 */

#define pr_fmt(fmt) "Dynamic pool: " fmt

#include <linux/memblock.h>
#include <linux/dynamic_pool.h>
#include "internal.h"

static bool enable_dhugetlb;

/* Indicate the enabled of dynamic pool */
DEFINE_STATIC_KEY_FALSE(dynamic_pool_key);

/* Protect the operation of dynamic pool */
static DEFINE_MUTEX(dpool_mutex);

/* Introduce the special opeartion. */
struct dynamic_pool_ops {
	int (*fill_pool)(struct dynamic_pool *dpool, void *arg);
	int (*drain_pool)(struct dynamic_pool *dpool);
	int (*restore_pool)(struct dynamic_pool *dpool);
};

/* Used to record the mapping of page and dpool */
struct dpool_page_array {
	unsigned long count;
	struct dynamic_pool *dpool[];
};

#define DEFAULT_PAGE_ARRAY_COUNT	4096
#define hugepage_index(pfn)	((pfn) >> PUD_ORDER)
static struct dpool_page_array *dpool_page_array;
static DEFINE_RWLOCK(dpool_page_array_rwlock);

/* === reference function ============================================= */

static bool dpool_get_unless_zero(struct dynamic_pool *dpool)
{
	if (!dpool)
		return false;

	return refcount_inc_not_zero(&dpool->refcnt);
}

static void dpool_put(struct dynamic_pool *dpool)
{
	if (!dpool)
		return;

	if (refcount_dec_and_test(&dpool->refcnt)) {
		dpool->memcg->dpool = NULL;
		css_put(&dpool->memcg->css);
		synchronize_rcu();
		kfree(dpool);
	}
}

static struct dynamic_pool *dpool_get_from_memcg(struct mem_cgroup *memcg)
{
	struct dynamic_pool *dpool;

	rcu_read_lock();
	dpool = memcg->dpool;
	if (!dpool_get_unless_zero(dpool))
		dpool = NULL;
	rcu_read_unlock();

	return dpool;
}

/* === demote and promote function ==================================== */

/*
 * Clear compound structure which is inverse of prep_compound_page,
 * For detail, see destroy_compound_hugetlb_folio_for_demote.
 */
static void clear_compound_page(struct folio *folio, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;
	struct page *p;

	atomic_set(&folio->_entire_mapcount, 0);
	atomic_set(&folio->_nr_pages_mapped, 0);
	atomic_set(&folio->_pincount, 0);

	for (i = 0; i < nr_pages; i++) {
		p = folio_page(folio, i);
		p->flags &= ~PAGE_FLAGS_CHECK_AT_FREE;
		p->mapping = NULL;
		if (!i)
			__ClearPageHead(p);
		else
			clear_compound_head(p);
		set_page_private(p, 0);
	}
}

static int dpool_demote_gigantic_page(struct pages_pool *src_pool,
				       struct pages_pool *dst_pool,
				       struct page *page)
{
	struct folio *folio = page_folio(page);
	struct hstate *h = size_to_hstate(PMD_SIZE);
	int nr_pages = 1 << PUD_ORDER;
	int block_size = 1 << PMD_ORDER;
	struct page *subpage;
	int i;

	if (PageHWPoison(page))
		return -EHWPOISON;

	list_del(&page->lru);
	__ClearPageDpool(page);
	src_pool->free_pages--;

	destroy_compound_hugetlb_folio_for_demote(folio, PUD_ORDER);

	for (i = 0; i < nr_pages; i += block_size) {
		subpage = folio_page(folio, i);
		prep_compound_page(subpage, PMD_ORDER);
		folio_change_private(page_folio(subpage), NULL);
		__SetPageDpool(subpage);
		__prep_new_hugetlb_folio(h, page_folio(subpage));
		list_add_tail(&subpage->lru, &dst_pool->freelist);
		dst_pool->free_pages++;
	}

	return 0;
}

static int dpool_demote_huge_page(struct pages_pool *src_pool,
				  struct pages_pool *dst_pool,
				  struct page *page)
{
	struct folio *folio = page_folio(page);
	int nr_pages = 1 << PMD_ORDER;
	struct page *subpage;
	int i;

	if (PageHWPoison(page))
		return -EHWPOISON;

	list_del(&page->lru);
	__ClearPageDpool(page);
	src_pool->free_pages--;

	clear_compound_page(page_folio(page), PMD_ORDER);
	for (i = 0; i < nr_pages; i++) {
		subpage = folio_page(folio, i);
		free_pages_prepare(subpage, 0, 0);
		__SetPageDpool(subpage);
		list_add_tail(&subpage->lru, &dst_pool->freelist);
		dst_pool->free_pages++;
	}

	return 0;
}

static int dpool_demote_pool_locked(struct dynamic_pool *dpool, int type)
{
	struct pages_pool *src_pool, *dst_pool;
	struct split_page *spage = NULL;
	struct page *page;
	int ret = -ENOMEM;

	lockdep_assert_held(&dpool->lock);

	if (type < 0 || type >= PAGES_POOL_MAX - 1)
		return -EINVAL;

	src_pool = &dpool->pool[type];
	dst_pool = &dpool->pool[type + 1];

	spage = kzalloc(sizeof(struct split_page), GFP_ATOMIC);
	if (!spage)
		goto out;

	if (!src_pool->free_pages && dpool_demote_pool_locked(dpool, type - 1))
		goto out;

	list_for_each_entry(page, &src_pool->freelist, lru) {
		switch (type) {
		case PAGES_POOL_1G:
			ret = dpool_demote_gigantic_page(src_pool, dst_pool, page);
			break;
		case PAGES_POOL_2M:
			ret = dpool_demote_huge_page(src_pool, dst_pool, page);
			break;
		default:
			BUG();
		}
		if (!ret)
			break;
	}

out:
	if (!ret) {
		spage->start_pfn = page_to_pfn(page);
		list_add(&spage->entry, &src_pool->splitlist);
		src_pool->split_pages++;
	} else {
		kfree(spage);
	}

	return ret;
}

static int dpool_promote_gigantic_page(struct pages_pool *src_pool,
				       struct pages_pool *dst_pool,
				       struct split_page *spage)
{
	struct hstate *h = size_to_hstate(PUD_SIZE);
	int nr_pages = 1 << PUD_ORDER;
	int block_size = 1 << PMD_ORDER;
	struct page *page, *subpage;
	int i;

	for (i = 0; i < nr_pages; i += block_size) {
		subpage = pfn_to_page(spage->start_pfn + i);
		if (!PageDpool(subpage))
			return -EBUSY;

		if (PageHWPoison(subpage))
			return -EHWPOISON;
	}

	for (i = 0; i < nr_pages; i += block_size) {
		subpage = pfn_to_page(spage->start_pfn + i);
		clear_compound_page(page_folio(subpage), PMD_ORDER);
		__ClearPageDpool(subpage);
		list_del(&subpage->lru);
		src_pool->free_pages--;
	}

	page = pfn_to_page(spage->start_pfn);
	prep_compound_gigantic_folio_for_demote(page_folio(page), PUD_ORDER);
	folio_change_private(page_folio(page), NULL);
	__SetPageDpool(page);
	__prep_new_hugetlb_folio(h, page_folio(page));
	list_add_tail(&page->lru, &dst_pool->freelist);
	dst_pool->free_pages++;

	return 0;
}

static int dpool_promote_huge_page(struct pages_pool *src_pool,
				   struct pages_pool *dst_pool,
				   struct split_page *spage)
{
	struct hstate *h = size_to_hstate(PMD_SIZE);
	int nr_pages = 1 << PMD_ORDER;
	struct page *page, *subpage;
	int i;

	for (i = 0; i < nr_pages; i++) {
		subpage = pfn_to_page(spage->start_pfn + i);
		if (!PageDpool(subpage))
			return -EBUSY;

		if (PageHWPoison(subpage))
			return -EHWPOISON;
	}

	for (i = 0; i < nr_pages; i++) {
		subpage = pfn_to_page(spage->start_pfn + i);
		__ClearPageDpool(subpage);
		list_del(&subpage->lru);
		src_pool->free_pages--;
	}

	page = pfn_to_page(spage->start_pfn);
	prep_new_page(page, PMD_ORDER, __GFP_COMP, 0);
	set_page_count(page, 0);
	folio_change_private(page_folio(page), NULL);
	__SetPageDpool(page);
	__prep_new_hugetlb_folio(h, page_folio(page));
	list_add_tail(&page->lru, &dst_pool->freelist);
	dst_pool->free_pages++;

	return 0;
}

static int dpool_promote_pool(struct dynamic_pool *dpool, int type)
{
	struct pages_pool *src_pool, *dst_pool;
	struct split_page *spage, *spage_next;
	int ret = -ENOMEM;


	if (type < 0 || type >= PAGES_POOL_MAX - 1)
		return -EINVAL;

	src_pool = &dpool->pool[type + 1];
	dst_pool = &dpool->pool[type];

	spin_lock(&dpool->lock);

	if (!dst_pool->split_pages)
		goto unlock;

	list_for_each_entry_safe(spage, spage_next, &dst_pool->splitlist, entry) {
		switch (type) {
		case PAGES_POOL_1G:
			ret = dpool_promote_gigantic_page(src_pool, dst_pool, spage);
			break;
		case PAGES_POOL_2M: {
			unsigned long nr_pages = 1 << PMD_ORDER;

			/*
			 * Since the dpool_mutex is already locked,
			 * there is no way to free spage_next, so
			 * it is safe to unlock here.
			 */
			spin_unlock(&dpool->lock);
			cond_resched();
			lru_add_drain_all();
			do_migrate_range(spage->start_pfn,
					 spage->start_pfn + nr_pages);
			spin_lock(&dpool->lock);
			ret = dpool_promote_huge_page(src_pool, dst_pool, spage);
			break;
		}
		default:
			BUG();
		}
		if (!ret)
			break;
	}

	if (!ret) {
		list_del(&spage->entry);
		dst_pool->split_pages--;
	}

unlock:
	spin_unlock(&dpool->lock);
	if (!ret)
		kfree(spage);

	return ret;
}

/* === dynamic pool function ========================================== */

static void dpool_dump_child_memcg(struct mem_cgroup *memcg, void *message)
{
	struct mem_cgroup *root = (struct mem_cgroup *)message;
	struct cgroup *cgrp;

	if (root == memcg)
		return;

	cgrp = memcg->css.cgroup;
	pr_err("child memcg exists: ");
	pr_cont_cgroup_name(cgrp);
	pr_cont("\n");
}

static struct dynamic_pool *dpool_create(struct mem_cgroup *memcg,
					 struct dynamic_pool_ops *ops)
{
	struct dynamic_pool *dpool;
	int i;

	if (memcg_has_children(memcg)) {
		pr_err("create failed, memcg has children\n");
		mem_cgroup_scan_cgroups(memcg, dpool_dump_child_memcg, memcg);
		return NULL;
	}

	dpool = kzalloc(sizeof(struct dynamic_pool), GFP_KERNEL);
	if (!dpool)
		return NULL;

	spin_lock_init(&dpool->lock);
	refcount_set(&dpool->refcnt, 1);
	dpool->memcg = memcg;
	dpool->ops = ops;

	for (i = 0; i < PAGES_POOL_MAX; i++) {
		INIT_LIST_HEAD(&dpool->pool[i].freelist);
		INIT_LIST_HEAD(&dpool->pool[i].splitlist);
	}

	css_get(&memcg->css);
	memcg->dpool = dpool;
	dpool->online = true;

	return dpool;
}

void dynamic_pool_inherit(struct mem_cgroup *memcg)
{
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);
	struct dynamic_pool *dpool;

	if (!dpool_enabled || !parent || !memcg)
		return;

	mutex_lock(&dpool_mutex);
	dpool = dpool_get_from_memcg(parent);
	memcg->dpool = dpool;

	/* Don't increase refcount for child memcg */
	dpool_put(dpool);
	mutex_unlock(&dpool_mutex);
}

int dynamic_pool_destroy(struct cgroup *cgrp, bool *clear_css_online)
{
	struct cgroup_subsys_state *css = cgrp->subsys[memory_cgrp_id];
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);
	struct dynamic_pool *dpool;
	int ret = 0;

	if (!dpool_enabled || !memcg)
		return 0;

	mutex_lock(&dpool_mutex);
	dpool = dpool_get_from_memcg(memcg);
	if (!dpool)
		goto unlock;

	if (dpool->memcg != memcg) {
		memcg->dpool = NULL;
		goto put;
	}

	/* A offline dpool is not allowed for allocation */
	dpool->online = false;

	BUG_ON(!dpool->ops->restore_pool);
	ret = dpool->ops->restore_pool(dpool);
	if (ret) {
		pr_err("restore pool failed\n");
		goto put;
	}

	BUG_ON(!dpool->ops->drain_pool);
	ret = dpool->ops->drain_pool(dpool);
	if (ret) {
		pr_err("drain pool failed\n");
		goto put;
	}

	memcg->dpool = NULL;

	/* Release the initial reference count */
	dpool_put(dpool);

	/*
	 * Since dpool is destroyed and the memcg will be freed then,
	 * clear CSS_ONLINE immediately to prevent race with create.
	 */
	if (cgrp->self.flags & CSS_ONLINE) {
		cgrp->self.flags &= ~CSS_ONLINE;
		*clear_css_online = true;
	}

put:
	dpool_put(dpool);
unlock:
	mutex_unlock(&dpool_mutex);

	return ret;
}

static int __init dynamic_pool_init(void)
{
	if (!enable_dhugetlb)
		return 0;

	if (enable_dhugetlb) {
		unsigned long count, size;

		count = max_t(unsigned long, hugepage_index(max_pfn),
				DEFAULT_PAGE_ARRAY_COUNT);
		size = sizeof(struct dpool_page_array) +
			count * sizeof(struct dynamic_pool *);
		dpool_page_array = kzalloc(size, GFP_KERNEL);
		if (!dpool_page_array) {
			pr_err("init failed\n");
			return -ENOMEM;
		}

		dpool_page_array->count = count;
	}

	static_branch_enable(&dynamic_pool_key);
	pr_info("enabled\n");

	return 0;
}
subsys_initcall(dynamic_pool_init);

/* === Dynamic hugetlb interface ====================================== */

static int __init dynamic_hugetlb_setup(char *buf)
{
	return kstrtobool(buf, &enable_dhugetlb);
}
early_param("dynamic_hugetlb", dynamic_hugetlb_setup);

static int dpool_record_page(struct dynamic_pool *dpool, unsigned long idx)
{
	read_lock(&dpool_page_array_rwlock);

	/*
	 * If page's pfn is greater than dhugetlb_pagelist_t->count (which
	 * may occurs due to memory hotplug) then dhugetlb_pagelist_t need
	 * to be reallocated, so need write_lock here.
	 */
	if (idx >= dpool_page_array->count) {
		unsigned long size;
		struct dpool_page_array *tmp;

		read_unlock(&dpool_page_array_rwlock);
		write_lock(&dpool_page_array_rwlock);

		size = sizeof(struct dpool_page_array) +
			(idx + 1) * sizeof(struct dynamic_pool *);
		tmp = krealloc(dpool_page_array, size, GFP_ATOMIC);
		if (!tmp) {
			write_unlock(&dpool_page_array_rwlock);
			return -ENOMEM;
		}

		tmp->count = idx + 1;
		dpool_page_array = tmp;

		write_unlock(&dpool_page_array_rwlock);
		read_lock(&dpool_page_array_rwlock);
	}
	dpool_page_array->dpool[idx] = dpool;
	read_unlock(&dpool_page_array_rwlock);

	return 0;
}

static int dpool_fill_from_hugetlb(struct dynamic_pool *dpool, void *arg)
{
	struct hstate *h = size_to_hstate(PUD_SIZE);
	unsigned long nr_pages = *(unsigned long *)arg;
	int nid = dpool->nid;
	unsigned long count = 0;
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_1G];
	struct page *page, *next;
	struct folio *folio;
	unsigned long idx;
	LIST_HEAD(page_list);

	if (!h)
		return -EINVAL;

	spin_lock(&hugetlb_lock);
	if ((h->free_huge_pages_node[nid] < nr_pages) ||
	     (h->free_huge_pages - h->resv_huge_pages < nr_pages)) {
		spin_unlock(&hugetlb_lock);
		return -ENOMEM;
	}

	while (count < nr_pages) {
		folio = dequeue_hugetlb_folio_node_exact(h, nid);
		if (!folio)
			break;
		page = folio_page(folio, 0);
		/* dequeue will unfreeze the page, refreeze it. */
		page_ref_freeze(page, 1);
		idx = hugepage_index(page_to_pfn(page));
		if (dpool_record_page(dpool, idx)) {
			enqueue_hugetlb_folio(h, folio);
			pr_err("dpool_page_array can't record page 0x%px\n",
				page);
			continue;
		}
		list_move(&page->lru, &page_list);
		count++;
	}
	spin_unlock(&hugetlb_lock);

	list_for_each_entry_safe(page, next, &page_list, lru) {
		__SetPageDpool(page);
		spin_lock(&dpool->lock);
		list_move(&page->lru, &pool->freelist);
		pool->free_pages++;
		dpool->total_pages++;
		spin_unlock(&dpool->lock);
	}

	return 0;
}

static int dpool_drain_to_hugetlb(struct dynamic_pool *dpool)
{
	struct hstate *h = size_to_hstate(PUD_SIZE);
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_1G];
	struct page *page, *next;
	unsigned long idx;
	LIST_HEAD(page_list);

	if (!h)
		return -EINVAL;

	spin_lock(&dpool->lock);
	list_for_each_entry_safe(page, next, &pool->freelist, lru) {
		WARN_ON(PageHWPoison(page));
		idx = hugepage_index(page_to_pfn(page));
		WARN_ON(dpool_record_page(NULL, idx));

		list_move(&page->lru, &page_list);
		__ClearPageDpool(page);
		pool->free_pages--;
		dpool->total_pages--;
	}
	spin_unlock(&dpool->lock);

	list_for_each_entry_safe(page, next, &page_list, lru) {
		spin_lock(&hugetlb_lock);
		enqueue_hugetlb_folio(h, page_folio(page));
		spin_unlock(&hugetlb_lock);
	}

	return dpool->total_pages ? -ENOMEM : 0;
}

static int dpool_merge_all(struct dynamic_pool *dpool)
{
	struct pages_pool *pool;
	int ret = -ENOMEM;

	pool = &dpool->pool[PAGES_POOL_2M];
	while (pool->split_pages) {
		cond_resched();
		ret = dpool_promote_pool(dpool, PAGES_POOL_2M);
		if (ret) {
			pr_err("some 4K pages can't merge ret: %d, delete failed: \n",
				ret);
			pr_cont_cgroup_name(dpool->memcg->css.cgroup);
			pr_cont("\n");
			goto out;
		}
	}

	spin_lock(&dpool->lock);
	if (pool->split_pages || pool->used_huge_pages || pool->resv_huge_pages) {
		ret = -ENOMEM;
		pr_err("some 2M pages are still in use or mmap, delete failed: ");
		pr_cont_cgroup_name(dpool->memcg->css.cgroup);
		pr_cont("\n");
		spin_unlock(&dpool->lock);
		goto out;
	}

	pool->free_pages += pool->nr_huge_pages;
	pool->nr_huge_pages = 0;
	pool->free_huge_pages = 0;
	spin_unlock(&dpool->lock);

	pool = &dpool->pool[PAGES_POOL_1G];
	while (pool->split_pages) {
		cond_resched();
		ret = dpool_promote_pool(dpool, PAGES_POOL_1G);
		if (ret) {
			pr_err("some 2M pages can't merge ret: %d, delete failed: \n",
				ret);
			pr_cont_cgroup_name(dpool->memcg->css.cgroup);
			pr_cont("\n");
			goto out;
		}
	}

	spin_lock(&dpool->lock);
	if (pool->split_pages || pool->used_huge_pages || pool->resv_huge_pages) {
		ret = -ENOMEM;
		pr_err("some 1G pages are still in use or mmap, delete failed: ");
		pr_cont_cgroup_name(dpool->memcg->css.cgroup);
		pr_cont("\n");
		spin_unlock(&dpool->lock);
		goto out;
	}

	pool->free_pages += pool->nr_huge_pages;
	pool->nr_huge_pages = 0;
	pool->free_huge_pages = 0;
	spin_unlock(&dpool->lock);
	ret = 0;

out:
	return ret;
}

static struct dynamic_pool_ops hugetlb_dpool_ops = {
	.fill_pool = dpool_fill_from_hugetlb,
	.drain_pool = dpool_drain_to_hugetlb,
	.restore_pool = dpool_merge_all,
};

/* If dynamic pool is disabled, hide the interface */
bool dynamic_pool_hide_files(struct cftype *cft)
{
	if (dpool_enabled && enable_dhugetlb)
		return false;

	return !!strstr(cft->name, "dhugetlb");
}

int dynamic_pool_add_memory(struct mem_cgroup *memcg, int nid,
			    unsigned long size)
{
	struct dynamic_pool *dpool;
	int ret = -EINVAL;
	bool new_create = false;

	if (!dpool_enabled)
		return -EINVAL;

	mutex_lock(&dpool_mutex);

	if (!(memcg->css.cgroup->self.flags & CSS_ONLINE)) {
		pr_err("add memory failed, memcg is going offline\n");
		goto unlock;
	}

	dpool = memcg->dpool;
	if (!dpool) {
		dpool = dpool_create(memcg, &hugetlb_dpool_ops);
		if (!dpool)
			goto unlock;

		dpool->nid = nid;
		new_create = true;
	} else if (dpool->memcg != memcg) {
		pr_err("add memory failed, not parent memcg\n");
		goto unlock;
	} else if (dpool->nid != nid) {
		pr_err("add memory failed, not target nid(%d)\n",
			dpool->nid);
		goto unlock;
	}

	BUG_ON(!dpool->ops->fill_pool);
	ret = dpool->ops->fill_pool(dpool, &size);
	if (ret) {
		pr_err("fill pool failed\n");
		/*
		 * If create a new hpool here but add memory failed,
		 * release it directly here.
		 */
		if (new_create) {
			memcg->dpool = NULL;
			dpool_put(dpool);
		}
	}

unlock:
	mutex_unlock(&dpool_mutex);

	return ret;
}

void dynamic_pool_show(struct mem_cgroup *memcg, struct seq_file *m)
{
	struct dynamic_pool *dpool;

	if (!dpool_enabled || !memcg)
		return;

	dpool = dpool_get_from_memcg(memcg);
	if (!dpool) {
		seq_puts(m, "Current hierarchial have not memory pool.\n");
		return;
	}

	spin_lock(&dpool->lock);

	seq_printf(m, "nid %d\n", dpool->nid);
	seq_printf(m, "dhugetlb_total_pages %lu\n", dpool->total_pages);
	seq_printf(m, "1G_total_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_1G].nr_huge_pages);
	seq_printf(m, "1G_free_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_1G].free_huge_pages);
	seq_printf(m, "1G_mmap_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_1G].resv_huge_pages);
	seq_printf(m, "1G_used_pages %lu\n",
		   dpool->pool[PAGES_POOL_1G].used_huge_pages);
	seq_printf(m, "2M_total_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_2M].nr_huge_pages);
	seq_printf(m, "2M_free_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_2M].free_huge_pages);
	seq_printf(m, "2M_mmap_reserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_2M].resv_huge_pages);
	seq_printf(m, "2M_used_pages %lu\n",
		   dpool->pool[PAGES_POOL_2M].used_huge_pages);
	seq_printf(m, "1G_free_unreserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_1G].free_pages);
	seq_printf(m, "2M_free_unreserved_pages %lu\n",
		   dpool->pool[PAGES_POOL_2M].free_pages);
	seq_printf(m, "4K_free_pages %lu\n",
		   dpool->pool[PAGES_POOL_4K].free_pages);
	seq_printf(m, "4K_used_pages %lu\n",
		   dpool->pool[PAGES_POOL_4K].used_pages);

	spin_unlock(&dpool->lock);
	dpool_put(dpool);
}

int dynamic_pool_reserve_hugepage(struct mem_cgroup *memcg,
				  unsigned long nr_pages, int type)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	unsigned long delta;
	int ret = -EINVAL;

	if (!dpool_enabled)
		return -EINVAL;

	mutex_lock(&dpool_mutex);

	dpool = dpool_get_from_memcg(memcg);
	if (!dpool)
		goto unlock;

	pool = &dpool->pool[type];
	spin_lock(&dpool->lock);
	if (nr_pages > pool->nr_huge_pages) {
		delta = nr_pages - pool->nr_huge_pages;
		while (delta > pool->free_pages &&
		       !dpool_demote_pool_locked(dpool, type - 1))
			cond_resched_lock(&dpool->lock);
		/* Only try merge pages for 2M pages */
		if (type == PAGES_POOL_2M) {
			while (delta > pool->free_pages) {
				spin_unlock(&dpool->lock);
				cond_resched();
				if (dpool_promote_pool(dpool, type)) {
					spin_lock(&dpool->lock);
					break;
				}
				spin_lock(&dpool->lock);
			}
		}
		delta = min(delta, pool->free_pages);
		pool->nr_huge_pages += delta;
		pool->free_huge_pages += delta;
		pool->free_pages -= delta;
	} else {
		delta = min(pool->nr_huge_pages - nr_pages,
			    pool->free_huge_pages - pool->resv_huge_pages);
		pool->nr_huge_pages -= delta;
		pool->free_huge_pages -= delta;
		pool->free_pages += delta;
	}
	spin_unlock(&dpool->lock);
	dpool_put(dpool);
	ret = 0;

unlock:
	mutex_unlock(&dpool_mutex);

	return ret;
}
