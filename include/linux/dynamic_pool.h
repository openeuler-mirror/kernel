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

struct pages_pool {
	unsigned long free_pages;
	unsigned long used_pages;
	struct list_head freelist;
};

struct dynamic_pool {
	refcount_t refcnt;
	bool online;
	struct mem_cgroup *memcg;

	spinlock_t lock;
	struct pages_pool pool[PAGES_POOL_MAX];

	KABI_RESERVE(1)
};

void dynamic_pool_inherit(struct mem_cgroup *memcg);
int dynamic_pool_destroy(struct cgroup *cgrp, bool *clear_css_online);

#else
struct dynamic_pool {};

static inline void dynamic_pool_inherit(struct mem_cgroup *memcg)
{
}

static inline int dynamic_pool_destroy(struct cgroup *cgrp,
				       bool *clear_css_online)
{
	return 0;
}
#endif /* CONFIG_DYNAMIC_POOL */
#endif /* __LINUX_DYNAMIC_POOL_H */
