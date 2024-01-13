// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dynamic pool core file
 *
 * Copyright (C) 2024 Huawei Limited.
 */

#define pr_fmt(fmt) "Dynamic pool: " fmt

#include <linux/dynamic_pool.h>

/* Indicate the enabled of dynamic pool */
DEFINE_STATIC_KEY_FALSE(dynamic_pool_key);

/* Protect the operation of dynamic pool */
static DEFINE_MUTEX(dpool_mutex);

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

static struct dynamic_pool *dpool_create(struct mem_cgroup *memcg)
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
	static_branch_enable(&dynamic_pool_key);
	pr_info("enabled\n");

	return 0;
}
subsys_initcall(dynamic_pool_init);
