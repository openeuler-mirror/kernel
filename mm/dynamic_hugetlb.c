// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dynamic hugetlb core file
 */

#include <linux/dynamic_hugetlb.h>

static bool enable_dhugetlb = false;
DEFINE_STATIC_KEY_FALSE(dhugetlb_enabled_key);

#define hugepage_index(pfn)	((pfn) >> (PUD_SHIFT - PAGE_SHIFT))

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
