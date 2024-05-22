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
#include "hugetlb_vmemmap.h"

#define CREATE_TRACE_POINTS
#include <trace/events/dynamic_pool.h>

static bool enable_dhugetlb;
static bool enable_dpagelist;

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

/* For dpagelist, there are only one dpool */
static struct dynamic_pool *dpool_global_pool;

/* Used for percpu pages pool */
#define PCP_PAGE_MAX	1024
#define PCP_PAGE_BATCH	(PCP_PAGE_MAX >> 2)

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
		dpool_global_pool = NULL;
		synchronize_rcu();
		free_percpu(dpool->pcp_pool);
		kfree(dpool->pfn_ranges);
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

static struct dynamic_pool *dpool_get_from_task(struct task_struct *tsk)
{
	struct dynamic_pool *dpool = NULL;
	struct mem_cgroup *memcg;

	if (!dpool_enabled)
		return NULL;

	rcu_read_lock();
	do {
		memcg = mem_cgroup_from_task(tsk);
	} while (memcg && !css_tryget(&memcg->css));
	rcu_read_unlock();
	if (!memcg)
		return NULL;

	dpool = dpool_get_from_memcg(memcg);
	css_put(&memcg->css);

	return dpool;
}

static struct dynamic_pool *dpool_get_from_page(struct page *page)
{
	struct dynamic_pool *dpool = NULL;
	unsigned long idx;

	rcu_read_lock();
	if (enable_dhugetlb) {
		idx = hugepage_index(page_to_pfn(page));
		read_lock(&dpool_page_array_rwlock);
		if (idx < dpool_page_array->count)
			dpool = dpool_page_array->dpool[idx];
		read_unlock(&dpool_page_array_rwlock);
	} else if (enable_dpagelist) {
		/*
		 * Attention: dpool_global_pool return for any page,
		 * so need other check to make sure it is from dpool.
		 */
		dpool = dpool_global_pool;
	}

	if (!dpool_get_unless_zero(dpool))
		dpool = NULL;
	rcu_read_unlock();

	return dpool;
}

bool __task_in_dynamic_pool(struct task_struct *tsk)
{
	struct dynamic_pool *dpool;

	if (!dpool_enabled)
		return false;

	dpool = dpool_get_from_task(tsk);
	dpool_put(dpool);

	return !!dpool;
}

bool page_in_dynamic_pool(struct page *page)
{
	struct dynamic_pool *dpool;
	bool ret;

	if (!dpool_enabled)
		return false;

	if (PageDpool(page))
		return true;

	/*
	 * If the page don't have the flags, it may be in pcp list.
	 * Check it using the page range.
	 */
	dpool = dpool_get_from_page(page);
	if (enable_dpagelist && dpool) {
		unsigned long pfn = page_to_pfn(page);
		int range_cnt = dpool->range_cnt;
		struct range *range;
		int i;

		for (i = 0; i < range_cnt; i++) {
			range = &dpool->pfn_ranges[i];
			if (pfn >= range->start && pfn <= range->end)
				goto out;
		}

		/* The pfn is not in the range, set dpool to NULL */
		dpool = NULL;
	}

out:
	ret = dpool ? !PagePool(page) : false;
	dpool_put(dpool);

	return ret;
}

/* === demote and promote function ==================================== */

static void dpool_disable_pcp_pool(struct dynamic_pool *dpool, bool drain);
static void dpool_enable_pcp_pool(struct dynamic_pool *dpool);

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

	__folio_clear_hugetlb(page_folio(page));
	clear_compound_page(page_folio(page), PMD_ORDER);
	for (i = 0; i < nr_pages; i++) {
		subpage = folio_page(folio, i);
		dpool_free_page_prepare(subpage);
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
	struct page *page = NULL;
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
	trace_dpool_demote(dpool, type, page, ret);

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
	dpool_prep_new_page(page, PMD_ORDER, __GFP_COMP, 0);
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
	struct page *page = NULL;
	int ret = -ENOMEM;


	if (type < 0 || type >= PAGES_POOL_MAX - 1)
		return -EINVAL;

	src_pool = &dpool->pool[type + 1];
	dst_pool = &dpool->pool[type];

	spin_lock_irq(&dpool->lock);

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
			spin_unlock_irq(&dpool->lock);
			cond_resched();
			lru_add_drain_all();
			dpool_disable_pcp_pool(dpool, true);
			do_migrate_range(spage->start_pfn,
					 spage->start_pfn + nr_pages);
			spin_lock_irq(&dpool->lock);
			dpool_enable_pcp_pool(dpool);
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
		page = pfn_to_page(spage->start_pfn);
		list_del(&spage->entry);
		dst_pool->split_pages--;
	}

unlock:
	spin_unlock_irq(&dpool->lock);
	if (!ret)
		kfree(spage);
	trace_dpool_promote(dpool, type, page, ret);

	return ret;
}

/* === percpu pool function =========================================== */

static void dpool_refill_pcp_pool(struct dynamic_pool *dpool,
				  struct pcp_pages_pool *pcp_pool,
				  unsigned long count)
{
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_4K];
	struct page *page, *next;
	unsigned long flags;
	int i = 0;

	lockdep_assert_held(&pcp_pool->lock);

	spin_lock_irqsave(&dpool->lock, flags);

	if (!pool->free_pages && dpool_demote_pool_locked(dpool, PAGES_POOL_2M))
		goto unlock;

	list_for_each_entry_safe(page, next, &pool->freelist, lru) {
		list_move_tail(&page->lru, &pcp_pool->freelist);
		__ClearPageDpool(page);
		pool->free_pages--;
		pcp_pool->free_pages++;
		if (++i == count)
			break;
	}

unlock:
	spin_unlock_irqrestore(&dpool->lock, flags);
}

static void dpool_drain_pcp_pool(struct dynamic_pool *dpool,
				 struct pcp_pages_pool *pcp_pool,
				 unsigned long count)
{
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_4K];
	struct page *page, *next;
	unsigned long flags;
	int i = 0;

	lockdep_assert_held(&pcp_pool->lock);

	spin_lock_irqsave(&dpool->lock, flags);
	list_for_each_entry_safe(page, next, &pcp_pool->freelist, lru) {
		list_move_tail(&page->lru, &pool->freelist);
		__SetPageDpool(page);
		pcp_pool->free_pages--;
		pool->free_pages++;
		if (++i == count)
			break;
	}

	pool->used_pages += pcp_pool->used_pages;
	pcp_pool->used_pages = 0;
	spin_unlock_irqrestore(&dpool->lock, flags);
}

static void dpool_drain_all_pcp_pool(struct dynamic_pool *dpool)
{
	struct pcp_pages_pool *pcp_pool;
	unsigned long flags;
	int cpu;

	for_each_possible_cpu(cpu) {
		pcp_pool = per_cpu_ptr(dpool->pcp_pool, cpu);
		spin_lock_irqsave(&pcp_pool->lock, flags);
		dpool_drain_pcp_pool(dpool, pcp_pool, pcp_pool->free_pages);
		spin_unlock_irqrestore(&pcp_pool->lock, flags);
	}
}

static void dpool_wait_all_pcp_pool_unlock(struct dynamic_pool *dpool)
{
	struct pcp_pages_pool *pcp_pool;
	unsigned long flags;
	int cpu;

	for_each_possible_cpu(cpu) {
		pcp_pool = per_cpu_ptr(dpool->pcp_pool, cpu);
		spin_lock_irqsave(&pcp_pool->lock, flags);
		spin_unlock_irqrestore(&pcp_pool->lock, flags);
	}
}


/* The caller have to make sure no others write the count */
static void dpool_sum_pcp_pool(struct dynamic_pool *dpool,
			       unsigned long *free_pages, long *used_pages)
{
	struct pcp_pages_pool *pcp_pool;
	int cpu;

	*free_pages = 0;
	*used_pages = 0;
	for_each_possible_cpu(cpu) {
		pcp_pool = per_cpu_ptr(dpool->pcp_pool, cpu);
		*free_pages += pcp_pool->free_pages;
		*used_pages += pcp_pool->used_pages;
	}
}

static void dpool_disable_pcp_pool(struct dynamic_pool *dpool, bool drain)
{
	atomic_inc(&dpool->pcp_refcnt);
	/* After increase refcount, wait for other user to unlock. */
	if (drain)
		dpool_drain_all_pcp_pool(dpool);
	else
		dpool_wait_all_pcp_pool_unlock(dpool);
}

static void dpool_enable_pcp_pool(struct dynamic_pool *dpool)
{
	atomic_dec(&dpool->pcp_refcnt);
}

static bool dpool_pcp_enabled(struct dynamic_pool *dpool)
{
	return !atomic_read(&dpool->pcp_refcnt);
}

static struct page *dpool_alloc_pcp_page(struct dynamic_pool *dpool)
{
	struct pcp_pages_pool *pcp_pool;
	struct page *page = NULL;
	unsigned long flags;

	pcp_pool = this_cpu_ptr(dpool->pcp_pool);
	spin_lock_irqsave(&pcp_pool->lock, flags);
	if (!dpool->online || !dpool_pcp_enabled(dpool))
		goto unlock;

retry:
	page = NULL;
	if (!pcp_pool->free_pages)
		dpool_refill_pcp_pool(dpool, pcp_pool, PCP_PAGE_BATCH);

	page = list_first_entry_or_null(&pcp_pool->freelist, struct page, lru);
	if (!page)
		goto unlock;

	list_del(&page->lru);
	pcp_pool->free_pages--;
	pcp_pool->used_pages++;

	if (dpool_check_new_page(page)) {
		SetPagePool(page);
		goto retry;
	}

	SetPagePool(page);

unlock:
	spin_unlock_irqrestore(&pcp_pool->lock, flags);

	return page;
}

static int dpool_free_pcp_page(struct dynamic_pool *dpool, struct page *page)
{
	struct pcp_pages_pool *pcp_pool;
	unsigned long flags;
	int ret = 0;

	pcp_pool = this_cpu_ptr(dpool->pcp_pool);
	spin_lock_irqsave(&pcp_pool->lock, flags);
	if (!dpool_pcp_enabled(dpool)) {
		ret = -EINVAL;
		goto unlock;
	}

	ClearPagePool(page);
	if (!dpool_free_page_prepare(page)) {
		SetPagePool(page);
		goto unlock;
	}

	list_add(&page->lru, &pcp_pool->freelist);
	pcp_pool->free_pages++;
	pcp_pool->used_pages--;
	if (pcp_pool->free_pages > PCP_PAGE_MAX)
		dpool_drain_pcp_pool(dpool, pcp_pool, PCP_PAGE_BATCH);

unlock:
	spin_unlock_irqrestore(&pcp_pool->lock, flags);

	return ret;
}

/* === allocation interface =========================================== */

int dynamic_pool_can_attach(struct task_struct *tsk, struct mem_cgroup *memcg)
{
	struct dynamic_pool *src_dpool, *dst_dpool;
	int ret = 0;

	if (!dpool_enabled)
		return 0;

	src_dpool = dpool_get_from_task(tsk);
	if (!src_dpool)
		return 0;

	dst_dpool = dpool_get_from_memcg(memcg);
	if (dst_dpool != src_dpool)
		ret = -EPERM;

	dpool_put(src_dpool);
	dpool_put(dst_dpool);

	return ret;
}

bool dynamic_pool_should_alloc(gfp_t gfp_mask, unsigned int order)
{
	gfp_t gfp = gfp_mask & GFP_HIGHUSER_MOVABLE;

	if (current->flags & PF_KTHREAD)
		return false;

	if (order != 0)
		return false;

	/*
	 * The cgroup only charges anonymous and file pages from usespage.
	 * some filesystem maybe has masked out the __GFP_IO | __GFP_FS
	 * to avoid recursive memory request. eg: loop device, xfs.
	 */
	if ((gfp | __GFP_IO | __GFP_FS) != GFP_HIGHUSER_MOVABLE)
		return false;

#ifdef CONFIG_MEMORY_RELIABLE
	if (mem_reliable_is_enabled() && (gfp_mask & GFP_RELIABLE))
		return false;
#endif

	return true;
}

struct page *dynamic_pool_alloc_page(gfp_t gfp, unsigned int order,
				     unsigned int alloc_flags)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	struct page *page = NULL;
	unsigned long flags;

	if (!dpool_enabled)
		return NULL;

	if (!dynamic_pool_should_alloc(gfp, order))
		return NULL;

	dpool = dpool_get_from_task(current);
	if (!dpool)
		return NULL;

	page = dpool_alloc_pcp_page(dpool);
	if (page)
		goto put;

	pool = &dpool->pool[PAGES_POOL_4K];
	spin_lock_irqsave(&dpool->lock, flags);
	if (!dpool->online)
		goto unlock;

retry:
	page = NULL;
	if (!pool->free_pages && dpool_demote_pool_locked(dpool, PAGES_POOL_2M)) {
		spin_unlock_irqrestore(&dpool->lock, flags);
		dpool_drain_all_pcp_pool(dpool);
		spin_lock_irqsave(&dpool->lock, flags);
		if (!dpool->online || !pool->free_pages)
			goto unlock;
	}

	page = list_first_entry_or_null(&pool->freelist, struct page, lru);
	if (!page)
		goto unlock;

	__ClearPageDpool(page);
	list_del(&page->lru);
	pool->free_pages--;
	pool->used_pages++;

	if (dpool_check_new_page(page)) {
		/* This is a bad page, treat it as a used pages */
		SetPagePool(page);
		goto retry;
	}

	SetPagePool(page);

unlock:
	spin_unlock_irqrestore(&dpool->lock, flags);
put:
	dpool_put(dpool);
	if (page)
		dpool_prep_new_page(page, order, gfp, alloc_flags);

	return page;
}

void dynamic_pool_free_page(struct page *page)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	unsigned long flags;

	if (!dpool_enabled)
		return;

	dpool = dpool_get_from_page(page);
	if (!dpool) {
		pr_err("get dpool failed when free page 0x%px\n", page);
		return;
	}

	if (!dpool_free_pcp_page(dpool, page))
		goto put;

	pool = &dpool->pool[PAGES_POOL_4K];
	spin_lock_irqsave(&dpool->lock, flags);

	ClearPagePool(page);
	if (!dpool_free_page_prepare(page)) {
		SetPagePool(page);
		goto unlock;
	}

	__SetPageDpool(page);
	list_add(&page->lru, &pool->freelist);
	pool->free_pages++;
	pool->used_pages--;

unlock:
	spin_unlock_irqrestore(&dpool->lock, flags);
put:
	dpool_put(dpool);
}

void dynamic_pool_bind_file(struct hugetlbfs_inode_info *p, struct hstate *h)
{
	unsigned long size;

	if (!dpool_enabled || !p)
		return;

	size = huge_page_size(h);
	if (size == PMD_SIZE || size == PUD_SIZE)
		p->dpool = dpool_get_from_task(current);
	else
		p->dpool = NULL;
}

void dynamic_pool_unbind_file(struct hugetlbfs_inode_info *p)
{
	struct dynamic_pool *dpool;

	if (!dpool_enabled || !p || !p->dpool)
		return;

	dpool = p->dpool;
	p->dpool = NULL;
	dpool_put(dpool);
}

int dynamic_pool_hugetlb_acct_memory(struct hstate *h, long delta,
				     struct hugetlbfs_inode_info *p)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	unsigned long flags;
	int type;
	int ret = -ENOMEM;

	if (!dpool_enabled || !p || !p->dpool)
		return 0;

	dpool = p->dpool;
	spin_lock_irqsave(&dpool->lock, flags);

	if (hstate_is_gigantic(h))
		type = PAGES_POOL_1G;
	else
		type = PAGES_POOL_2M;
	pool = &dpool->pool[type];

	if (delta > 0) {
		if (delta <= pool->free_huge_pages - pool->resv_huge_pages) {
			pool->resv_huge_pages += delta;
			ret = 0;
		}
	} else {
		pool->resv_huge_pages -= (unsigned long)(-delta);
		WARN_ON(pool->resv_huge_pages < 0);
		ret = 0;
	}
	spin_unlock_irqrestore(&dpool->lock, flags);
	trace_dpool_acct_memory(dpool, type, delta, pool->resv_huge_pages,
				ret);

	return ret;
}

struct folio *dynamic_pool_alloc_hugepage(struct hugetlbfs_inode_info *p,
					  struct hstate *h, bool reserved)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	struct folio *folio = NULL;
	unsigned long flags;
	int type;

	if (!dpool_enabled)
		return NULL;

	dpool = p->dpool;
	if (!dpool)
		return NULL;

	if (hstate_is_gigantic(h))
		type = PAGES_POOL_1G;
	else
		type = PAGES_POOL_2M;
	pool = &dpool->pool[type];

	spin_lock_irqsave(&dpool->lock, flags);
	if (!dpool->online)
		goto unlock;

	list_for_each_entry(folio, &pool->freelist, lru) {
		if (folio_test_hwpoison(folio))
			continue;

		list_del(&folio->lru);
		__folio_clear_dpool(folio);
		folio_ref_unfreeze(folio, 1);
		pool->free_huge_pages--;
		pool->used_huge_pages++;
		if (reserved) {
			folio_set_hugetlb_restore_reserve(folio);
			pool->resv_huge_pages--;
		}
		folio_set_pool(folio);
		goto unlock;
	}
	folio = NULL;

unlock:
	spin_unlock_irqrestore(&dpool->lock, flags);
	trace_dpool_alloc_hugepage(dpool, type, folio, pool->free_huge_pages,
				   pool->resv_huge_pages);

	return folio;
}

void dynamic_pool_free_hugepage(struct folio *folio, bool restore_reserve)
{
	struct hstate *h = folio_hstate(folio);
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	unsigned long flags;
	int type;

	if (!dpool_enabled)
		return;

	dpool = dpool_get_from_page(folio_page(folio, 0));
	if (!dpool) {
		pr_err("get dpool failed when free hugepage 0x%px\n", folio);
		return;
	}

	if (hstate_is_gigantic(h))
		type = PAGES_POOL_1G;
	else
		type = PAGES_POOL_2M;
	pool = &dpool->pool[type];

	spin_lock_irqsave(&dpool->lock, flags);

	if (folio_test_hwpoison(folio))
		goto unlock;

	folio_clear_pool(folio);
	__folio_set_dpool(folio);
	list_add(&folio->lru, &pool->freelist);
	pool->free_huge_pages++;
	pool->used_huge_pages--;
	if (restore_reserve)
		pool->resv_huge_pages++;

unlock:
	spin_unlock_irqrestore(&dpool->lock, flags);
	dpool_put(dpool);
	trace_dpool_free_hugepage(dpool, type, folio, pool->free_huge_pages,
				  pool->resv_huge_pages);
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
	int cpu;
	int i;

	if (memcg_has_children(memcg)) {
		pr_err("create failed, memcg has children\n");
		mem_cgroup_scan_cgroups(memcg, dpool_dump_child_memcg, memcg);
		return NULL;
	}

	dpool = kzalloc(sizeof(struct dynamic_pool), GFP_KERNEL);
	if (!dpool)
		return NULL;

	dpool->pcp_pool = alloc_percpu(struct pcp_pages_pool);
	if (!dpool->pcp_pool) {
		kfree(dpool);
		return NULL;
	}

	spin_lock_init(&dpool->lock);
	refcount_set(&dpool->refcnt, 1);
	dpool->memcg = memcg;
	dpool->ops = ops;
	atomic_set(&dpool->pcp_refcnt, 0);

	for (i = 0; i < PAGES_POOL_MAX; i++) {
		INIT_LIST_HEAD(&dpool->pool[i].freelist);
		INIT_LIST_HEAD(&dpool->pool[i].splitlist);
	}

	for_each_possible_cpu(cpu) {
		struct pcp_pages_pool *pcp_pool;

		pcp_pool = per_cpu_ptr(dpool->pcp_pool, cpu);
		spin_lock_init(&pcp_pool->lock);
		INIT_LIST_HEAD(&pcp_pool->freelist);
		pcp_pool->free_pages = 0;
		pcp_pool->used_pages = 0;
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
	/* Disable pcp pool forever */
	dpool_disable_pcp_pool(dpool, true);

	/*
	 * Even if no process exists in the memory cgroup, some pages may
	 * still be occupied. Release these pages before restore pool.
	 */
	mem_cgroup_force_empty(dpool->memcg);

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
	if (!enable_dhugetlb && !enable_dpagelist)
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
	if (enable_dpagelist)
		return 0;

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

	spin_lock_irq(&hugetlb_lock);
	if ((h->free_huge_pages_node[nid] < nr_pages) ||
	     (h->free_huge_pages - h->resv_huge_pages < nr_pages)) {
		spin_unlock_irq(&hugetlb_lock);
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
	spin_unlock_irq(&hugetlb_lock);

	list_for_each_entry_safe(page, next, &page_list, lru) {
		if (hugetlb_vmemmap_restore(h, page)) {
			spin_lock_irq(&hugetlb_lock);
			enqueue_hugetlb_folio(h, folio);
			spin_unlock_irq(&hugetlb_lock);
			pr_err("restore hugetlb_vmemmap failed page 0x%px\n",
				page);
			continue;
		}

		__SetPageDpool(page);
		spin_lock_irq(&dpool->lock);
		list_move(&page->lru, &pool->freelist);
		pool->free_pages++;
		dpool->total_pages++;
		spin_unlock_irq(&dpool->lock);
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

	spin_lock_irq(&dpool->lock);
	list_for_each_entry_safe(page, next, &pool->freelist, lru) {
		WARN_ON(PageHWPoison(page));
		idx = hugepage_index(page_to_pfn(page));
		WARN_ON(dpool_record_page(NULL, idx));

		list_move(&page->lru, &page_list);
		__ClearPageDpool(page);
		pool->free_pages--;
		dpool->total_pages--;
	}
	spin_unlock_irq(&dpool->lock);

	list_for_each_entry_safe(page, next, &page_list, lru) {
		hugetlb_vmemmap_optimize(h, page);
		spin_lock_irq(&hugetlb_lock);
		enqueue_hugetlb_folio(h, page_folio(page));
		spin_unlock_irq(&hugetlb_lock);
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

	spin_lock_irq(&dpool->lock);
	if (pool->split_pages || pool->used_huge_pages || pool->resv_huge_pages) {
		ret = -ENOMEM;
		pr_err("some 2M pages are still in use or mmap, delete failed: ");
		pr_cont_cgroup_name(dpool->memcg->css.cgroup);
		pr_cont("\n");
		spin_unlock_irq(&dpool->lock);
		goto out;
	}

	pool->free_pages += pool->nr_huge_pages;
	pool->nr_huge_pages = 0;
	pool->free_huge_pages = 0;
	spin_unlock_irq(&dpool->lock);

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

	spin_lock_irq(&dpool->lock);
	if (pool->split_pages || pool->used_huge_pages || pool->resv_huge_pages) {
		ret = -ENOMEM;
		pr_err("some 1G pages are still in use or mmap, delete failed: ");
		pr_cont_cgroup_name(dpool->memcg->css.cgroup);
		pr_cont("\n");
		spin_unlock_irq(&dpool->lock);
		goto out;
	}

	pool->free_pages += pool->nr_huge_pages;
	pool->nr_huge_pages = 0;
	pool->free_huge_pages = 0;
	spin_unlock_irq(&dpool->lock);
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
	unsigned long free_pages;
	long used_pages;

	if (!dpool_enabled || !memcg)
		return;

	dpool = dpool_get_from_memcg(memcg);
	if (!dpool) {
		seq_puts(m, "Current hierarchial have not memory pool.\n");
		return;
	}

	dpool_disable_pcp_pool(dpool, false);
	spin_lock_irq(&dpool->lock);

	/*
	 * no others can modify the count because pcp pool is disabled and
	 * dpool->lock is locked.
	 */
	dpool_sum_pcp_pool(dpool, &free_pages, &used_pages);
	free_pages += dpool->pool[PAGES_POOL_4K].free_pages;
	used_pages += dpool->pool[PAGES_POOL_4K].used_pages;

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
	seq_printf(m, "4K_free_pages %lu\n", free_pages);
	seq_printf(m, "4K_used_pages %ld\n", used_pages);

	spin_unlock_irq(&dpool->lock);
	dpool_enable_pcp_pool(dpool);
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
	spin_lock_irq(&dpool->lock);
	if (nr_pages > pool->nr_huge_pages) {
		delta = nr_pages - pool->nr_huge_pages;
		while (delta > pool->free_pages &&
		       !dpool_demote_pool_locked(dpool, type - 1)) {
			spin_unlock_irq(&dpool->lock);
			cond_resched();
			spin_lock_irq(&dpool->lock);
		}
		/* Only try merge pages for 2M pages */
		if (type == PAGES_POOL_2M) {
			while (delta > pool->free_pages) {
				spin_unlock_irq(&dpool->lock);
				cond_resched();
				if (dpool_promote_pool(dpool, type)) {
					spin_lock_irq(&dpool->lock);
					break;
				}
				spin_lock_irq(&dpool->lock);
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
	spin_unlock_irq(&dpool->lock);
	dpool_put(dpool);
	ret = 0;

unlock:
	mutex_unlock(&dpool_mutex);

	return ret;
}

/* === Dynamic pagelist interface ===================================== */

static int __init dynamic_pagelist_setup(char *buf)
{
	if (enable_dhugetlb)
		return 0;

	return kstrtobool(buf, &enable_dpagelist);
}
early_param("dpool", dynamic_pagelist_setup);

static int dpool_fill_from_pagelist(struct dynamic_pool *dpool, void *arg)
{
	struct dpool_info *info = (struct dpool_info *)arg;
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_4K];
	int i, ret = -EINVAL;

	dpool->range_cnt = info->range_cnt;
	dpool->pfn_ranges =
		kmalloc_array(info->range_cnt, sizeof(struct range), GFP_KERNEL);
	if (!dpool->pfn_ranges)
		return -ENOMEM;

	memcpy(dpool->pfn_ranges, info->pfn_ranges,
		sizeof(struct range) * dpool->range_cnt);

	spin_lock_irq(&dpool->lock);

	for (i = 0; i < dpool->range_cnt; i++) {
		struct range *range = &dpool->pfn_ranges[i];
		u64 pfn;

		for (pfn = range->start; pfn <= range->end; pfn++) {
			struct page *page = pfn_to_page(pfn);

			set_page_count(page, 0);
			page_mapcount_reset(page);

			if (!dpool_free_page_prepare(page)) {
				pr_err("fill pool failed, check pages failed\n");
				goto unlock;
			}

			__SetPageDpool(page);
			list_add_tail(&page->lru, &pool->freelist);
			pool->free_pages++;

			cond_resched_lock(&dpool->lock);
		}
	}
	ret = 0;

unlock:
	spin_unlock_irq(&dpool->lock);

	return ret;
}

static int dpool_drain_to_pagelist(struct dynamic_pool *dpool)
{
	struct pages_pool *pool = &dpool->pool[PAGES_POOL_4K];

	/* check poisoned pages */
	return (pool->used_pages == dpool->nr_poisoned_pages) ? 0 : -ENOMEM;
}

static int dpool_migrate_used_pages(struct dynamic_pool *dpool)
{
	int range_cnt = dpool->range_cnt;
	int i;

	spin_lock_irq(&dpool->lock);

	dpool->nr_poisoned_pages = 0;
	for (i = 0; i < range_cnt; i++) {
		struct range *range = &dpool->pfn_ranges[i];
		u64 pfn;

		for (pfn = range->start; pfn <= range->end; pfn++) {
			struct page *page = pfn_to_page(pfn);

			/* Unlock and try migration. */
			spin_unlock_irq(&dpool->lock);
			cond_resched();

			if (PageDpool(page)) {
				spin_lock_irq(&dpool->lock);
				continue;
			}

			if (PageHWPoison(page))
				dpool->nr_poisoned_pages++;

			lru_add_drain_all();
			do_migrate_range(pfn, pfn + 1);
			spin_lock_irq(&dpool->lock);
		}
	}

	spin_unlock_irq(&dpool->lock);

	return 0;
}

struct dynamic_pool_ops pagelist_dpool_ops = {
	.fill_pool = dpool_fill_from_pagelist,
	.drain_pool = dpool_drain_to_pagelist,
	.restore_pool = dpool_migrate_used_pages,
};

int dpool_init(struct dpool_info *arg)
{
	struct dynamic_pool *dpool;
	int ret;

	if (!dpool_enabled)
		return -EINVAL;

	if (!arg || !arg->memcg || arg->range_cnt <= 0) {
		pr_err("init failed, arg is invalid\n");
		return -EINVAL;
	}

	mutex_lock(&dpool_mutex);

	if (dpool_global_pool || arg->memcg->dpool) {
		pr_err("init failed, dpool is already exist\n");
		ret = -EINVAL;
		goto unlock;
	}

	if (!(arg->memcg->css.cgroup->self.flags & CSS_ONLINE)) {
		pr_err("init failed, memcg is not online\n");
		ret = -EINVAL;
		goto unlock;
	}

	dpool = dpool_create(arg->memcg, &pagelist_dpool_ops);
	if (!dpool) {
		pr_err("init failed, create failed. ret: %d\n", ret);
		ret = -ENOMEM;
		goto unlock;
	}

	dpool_global_pool = dpool;

	BUG_ON(!dpool->ops->fill_pool);
	ret = dpool->ops->fill_pool(dpool, arg);
	if (ret)
		dpool_put(dpool);

unlock:
	mutex_unlock(&dpool_mutex);

	return ret;
}

void dynamic_pool_show_meminfo(struct seq_file *m)
{
	struct dynamic_pool *dpool;
	struct pages_pool *pool;
	unsigned long free_pages = 0;
	long used_pages = 0;
	unsigned long flags;

	if (!dpool_enabled || !enable_dpagelist)
		return;

	dpool = dpool_get_from_page(NULL);
	if (!dpool)
		goto out;

	pool = &dpool->pool[PAGES_POOL_4K];
	dpool_disable_pcp_pool(dpool, false);
	spin_lock_irqsave(&dpool->lock, flags);
	dpool_sum_pcp_pool(dpool, &free_pages, &used_pages);
	free_pages += pool->free_pages;
	used_pages += pool->used_pages;
	spin_unlock_irqrestore(&dpool->lock, flags);
	dpool_enable_pcp_pool(dpool);

out:
	if (m) {
		seq_printf(m,
			   "DPoolTotal:     %8lu kB\n"
			   "DPoolFree:      %8ld kB\n",
			   (free_pages + used_pages) << (PAGE_SHIFT - 10),
			   free_pages << (PAGE_SHIFT - 10));
	} else {
		pr_info("DPoolTotal: %lu kB\n",
			(free_pages + used_pages) << (PAGE_SHIFT - 10));
		pr_info("DPoolFree: %ld kB\n", free_pages << (PAGE_SHIFT - 10));
	}

	dpool_put(dpool);
}
