// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dynamic pool core file
 *
 * Copyright (C) 2024 Huawei Limited.
 */

#define pr_fmt(fmt) "Dynamic pool: " fmt

#include <linux/memblock.h>
#include <linux/dynamic_pool.h>

static bool enable_dhugetlb;

/* Indicate the enabled of dynamic pool */
DEFINE_STATIC_KEY_FALSE(dynamic_pool_key);

/* Protect the operation of dynamic pool */
static DEFINE_MUTEX(dpool_mutex);

/* Introduce the special opeartion. */
struct dynamic_pool_ops {
	int (*fill_pool)(struct dynamic_pool *dpool, void *arg);
	int (*drain_pool)(struct dynamic_pool *dpool);
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

	for (i = 0; i < PAGES_POOL_MAX; i++)
		INIT_LIST_HEAD(&dpool->pool[i].freelist);

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

static struct dynamic_pool_ops hugetlb_dpool_ops = {
	.fill_pool = dpool_fill_from_hugetlb,
	.drain_pool = dpool_drain_to_hugetlb,
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
		delta = min(nr_pages - pool->nr_huge_pages, pool->free_pages);
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
