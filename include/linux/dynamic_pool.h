/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __LINUX_DYNAMIC_POOL_H
#define __LINUX_DYNAMIC_POOL_H

#include <linux/memcontrol.h>
#include <linux/hugetlb.h>
#include <linux/kabi.h>

#ifdef CONFIG_DYNAMIC_POOL

DECLARE_STATIC_KEY_FALSE(dynamic_pool_key);
#define dpool_enabled (static_branch_unlikely(&dynamic_pool_key))

enum pages_pool_type {
	PAGES_POOL_1G,
	PAGES_POOL_2M,
	PAGES_POOL_4K,
	PAGES_POOL_MAX,
};

struct split_page {
	struct list_head entry;
	unsigned long start_pfn;
};

struct pages_pool {
	unsigned long free_pages;
	long used_pages;
	struct list_head freelist;

	/* Used for hugepage allocation */
	unsigned long nr_huge_pages;
	unsigned long free_huge_pages;
	unsigned long resv_huge_pages;
	unsigned long used_huge_pages;

	/* Used for split page */
	unsigned long split_pages;
	struct list_head splitlist;
};

struct pcp_pages_pool {
	spinlock_t lock;
	unsigned long free_pages;
	long used_pages;
	struct list_head freelist;
};

struct dynamic_pool_ops;

struct dynamic_pool {
	refcount_t refcnt;
	bool online;
	struct mem_cgroup *memcg;
	struct dynamic_pool_ops *ops;

	spinlock_t lock;
	struct pages_pool pool[PAGES_POOL_MAX];
	atomic_t pcp_refcnt;
	struct pcp_pages_pool __percpu *pcp_pool;

	/* Used for dynamic hugetlb */
	int nid;
	unsigned long total_pages;

	KABI_RESERVE(1)
};

static inline bool page_from_dynamic_pool(struct page *page)
{
	if (!dpool_enabled)
		return false;

	return PagePool(page);
}

int dynamic_pool_can_attach(struct task_struct *tsk, struct mem_cgroup *memcg);
struct page *dynamic_pool_alloc_page(gfp_t gfp, unsigned int order,
				     unsigned int alloc_flags);
void dynamic_pool_free_page(struct page *page);

void dynamic_pool_inherit(struct mem_cgroup *memcg);
int dynamic_pool_destroy(struct cgroup *cgrp, bool *clear_css_online);

bool dynamic_pool_hide_files(struct cftype *cft);
int dynamic_pool_add_memory(struct mem_cgroup *memcg, int nid,
			    unsigned long size);
void dynamic_pool_show(struct mem_cgroup *memcg, struct seq_file *m);
int dynamic_pool_reserve_hugepage(struct mem_cgroup *memcg,
				  unsigned long nr_pages, int type);

#else
#define dpool_enabled	0

struct dynamic_pool {};

static inline bool page_from_dynamic_pool(struct page *page)
{
	return false;
}

static inline int dynamic_pool_can_attach(struct task_struct *tsk,
					  struct mem_cgroup *memcg)
{
	return 0;
}

static inline struct page *dynamic_pool_alloc_page(gfp_t gfp, unsigned int order,
						   unsigned int alloc_flags)
{
	return NULL;
}

static inline void dynamic_pool_free_page(struct page *page)
{
}

static inline void dynamic_pool_inherit(struct mem_cgroup *memcg)
{
}

static inline int dynamic_pool_destroy(struct cgroup *cgrp,
				       bool *clear_css_online)
{
	return 0;
}

#ifdef CONFIG_CGROUPS
static inline bool dynamic_pool_hide_files(struct cftype *cft)
{
	return false;
}
#endif
#endif /* CONFIG_DYNAMIC_POOL */
#endif /* __LINUX_DYNAMIC_POOL_H */
