// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for Soft Domain Scheduling
 *
 * Copyright (C) 2025-2025 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/sort.h>

#define NR_MAX_CLUSTER 32

static DEFINE_STATIC_KEY_TRUE(__soft_domain_switch);

static int __init soft_domain_switch_setup(char *str)
{
	int val = 0;

	if (kstrtoint(str, 0, &val))
		pr_warn("sched_soft_domain parameter is error: %s\n", str);
	else {
		if (val == 1)
			static_branch_enable(&__soft_domain_switch);
		else if (val == 0)
			static_branch_disable(&__soft_domain_switch);
	}

	return 1;
}
__setup("sched_soft_domain=", soft_domain_switch_setup);

bool soft_domain_enabled(void)
{
	return static_branch_likely(&__soft_domain_switch);
}

static DEFINE_PER_CPU(struct soft_domain *, g_sf_d);

static void free_sub_soft_domain(struct soft_domain *sf_d);

static int build_soft_sub_domain(int nid, struct cpumask *cpus)
{
	const struct cpumask *span = cpumask_of_node(nid);
	struct soft_domain *sf_d = NULL;
	int i;
	int cls_cnt = 0;

	sf_d = kzalloc_node(sizeof(struct soft_domain) + cpumask_size(),
			    GFP_KERNEL, nid);
	if (!sf_d)
		return -ENOMEM;

	INIT_LIST_HEAD(&sf_d->child_domain);
	sf_d->nr_available_cpus = cpumask_weight(span);
	cpumask_copy(to_cpumask(sf_d->span), span);

	for_each_cpu_and(i, span, cpus) {
		struct soft_subdomain *sub_d = NULL;

		cls_cnt++;
		if (cls_cnt > NR_MAX_CLUSTER) {
			pr_info("clsuter number > %d, unsupport soft domain.\n", NR_MAX_CLUSTER);
			return -EINVAL;
		}

		sub_d = kzalloc_node(sizeof(struct soft_subdomain) + cpumask_size(),
				     GFP_KERNEL, nid);
		if (!sub_d) {
			free_sub_soft_domain(sf_d);
			return -ENOMEM;
		}
		list_add_tail(&sub_d->node, &sf_d->child_domain);
		cpumask_and(soft_domain_span(sub_d->span), span, topology_cluster_cpumask(i));
		cpumask_andnot(cpus, cpus, topology_cluster_cpumask(i));
	}

	for_each_cpu(i, span) {
		rcu_assign_pointer(per_cpu(g_sf_d, i), sf_d);
	}

	return 0;
}

static void free_sub_soft_domain(struct soft_domain *sf_d)
{
	struct list_head *children = &sf_d->child_domain;
	struct soft_subdomain *entry = NULL, *next = NULL;
	int i;

	list_for_each_entry_safe(entry, next, children, node) {
		list_del(&entry->node);
		kfree(entry);
	}

	for_each_cpu(i, to_cpumask(sf_d->span)) {
		rcu_assign_pointer(per_cpu(g_sf_d, i), NULL);
	}

	kfree(sf_d);
}

static void free_soft_domain(void)
{
	struct soft_domain *sf_d = NULL;
	int i;

	for_each_cpu(i, cpu_active_mask) {
		sf_d = rcu_dereference(per_cpu(g_sf_d, i));
		if (sf_d)
			free_sub_soft_domain(sf_d);
	}

	static_branch_disable(&__soft_domain_switch);
}

void build_soft_domain(void)
{
	static struct cpumask cpus;
	int i, ret;

	if (!soft_domain_enabled())
		return;

	cpumask_copy(&cpus, cpu_active_mask);
	for (i = 0; i < nr_node_ids; i++) {
		/* build soft domain for each numa domain. */
		ret = build_soft_sub_domain(i, &cpus);
		if (ret) {
			free_soft_domain();
			return;
		}
	}
}

static DEFINE_MUTEX(soft_domain_mutex);

struct domain_node {
	struct soft_subdomain *sud_d;
	unsigned int attached;
	unsigned long util;
};

static int subdomain_cmp(const void *a, const void *b)
{
	struct domain_node *ca = (struct domain_node *)a;
	struct domain_node *cb = (struct domain_node *)b;

	if (ca->attached < cb->attached ||
	    (ca->attached == cb->attached && ca->util < cb->util))
		return -1;

	return 1;
}

struct soft_domain_args {
	int policy;
	int nr_cpu;
	struct cpumask *cpus;
};

static int tg_set_soft_domain(struct task_group *tg, void *data)
{
	struct soft_domain_args *args = (struct soft_domain_args *)data;

	tg->sf_ctx->policy = args->policy;
	if (args->policy) {
		cpumask_copy(to_cpumask(tg->sf_ctx->span), args->cpus);
		tg->sf_ctx->nr_cpus = args->nr_cpu;
	} else
		cpumask_clear(to_cpumask(tg->sf_ctx->span));

	return 0;
}

static int __calc_cpu(struct task_group *tg)
{
	int nr_cpu = 1;

	if (tg->sf_ctx->nr_cpus)
		nr_cpu = tg->sf_ctx->nr_cpus;
#ifdef CONFIG_CFS_BANDWIDTH
	else if (tg->cfs_bandwidth.quota != RUNTIME_INF)
		nr_cpu = DIV_ROUND_UP_ULL(tg->cfs_bandwidth.quota, tg->cfs_bandwidth.period);
#endif

	return nr_cpu;
}

static unsigned long sum_util(struct cpumask *mask)
{
	unsigned long sum = 0;
	int cpu;

	for_each_cpu(cpu, mask)
		sum += cpu_util_cfs(cpu);

	return sum;
}

static int __check_policy(struct task_group *tg, void *data)
{
	return !!tg->sf_ctx->policy;
}

static int check_policy(struct task_group *tg, long policy)
{
	int ret;

	rcu_read_lock();
	ret = walk_tg_tree_from(tg, __check_policy, tg_nop, NULL);
	rcu_read_unlock();

	return ret;
}

static struct soft_domain *find_idlest_llc(long policy,
					    int nr_cpu, cpumask_var_t cpus)
{
	int cpu;
	int max_cpu = 0;
	struct soft_domain *idlest = NULL;
	unsigned long min_util = ULONG_MAX;

	/* The user has specified the llc. */
	if (policy > 0) {
		for_each_cpu(cpu, cpumask_of_node(policy-1)) {
			idlest = rcu_dereference(per_cpu(g_sf_d, cpu));
			if (idlest != NULL)
				break;
		}

		if (idlest && nr_cpu <= cpumask_weight(to_cpumask(idlest->span)))
			return idlest;

		return NULL;
	}

	cpumask_copy(cpus, cpu_active_mask);
	for_each_cpu(cpu, cpus) {
		struct soft_domain *sf_d = NULL;
		struct cpumask *mask;

		sf_d = rcu_dereference(per_cpu(g_sf_d, cpu));
		if (sf_d == NULL)
			continue;

		mask = to_cpumask(sf_d->span);
		cpumask_andnot(cpus, cpus, mask);
		if (nr_cpu > cpumask_weight(mask))
			continue;

		/*
		 * LLC selection order:
		 * 1. When the number of idle cpus meet the requirements,
		 *    the one with more idles cpus is better;
		 * 2. Under the condition of insufficient idle cpus, util
		 *    is lower, the better.
		 */
		if (sf_d->nr_available_cpus > max_cpu &&
			nr_cpu <= sf_d->nr_available_cpus) {
			max_cpu = sf_d->nr_available_cpus;
			idlest = sf_d;
		} else if (max_cpu == 0) {   /* No llc meets the demand */
			unsigned long util = sum_util(mask);

			if (idlest == NULL || util < min_util) {
				idlest = sf_d;
				min_util = util;
			}
		}
	}

	return idlest;
}

static int __sched_group_set_soft_domain(struct task_group *tg, long policy)
{
	int cpu;
	int ret = 0;
	cpumask_var_t cpus;
	struct soft_domain_args args;
	struct domain_node nodes[NR_MAX_CLUSTER] = {0};
	int nr_cpu = __calc_cpu(tg);

	if (check_policy(tg, policy))
		return -EINVAL;

	if (!zalloc_cpumask_var(&cpus, GFP_KERNEL))
		return -EINVAL;

	scoped_guard (cpus_read_lock) {
		struct soft_domain *sf_d = NULL;

		rcu_read_lock();
		/* 1. Find a idlest llc. */
		sf_d = find_idlest_llc(policy, nr_cpu, cpus);
		if (sf_d != NULL) {
			/* 2. select idlest clusters. */
			struct list_head *children = &sf_d->child_domain;
			struct soft_subdomain *sub_d = NULL;
			int nr = 0, i;
			struct cpumask *tmpmask = NULL;
			int tmp_cpu = nr_cpu;

			list_for_each_entry(sub_d, children, node) {
				nodes[nr].sud_d = sub_d;
				nodes[nr].attached = sub_d->attached;
				tmpmask = to_cpumask(sub_d->span);
				cpu = cpumask_first(tmpmask);
				nodes[nr].util = sum_util(tmpmask);
				nr++;
			}

			cpumask_clear(cpus);

			sort(nodes, nr, sizeof(struct domain_node), subdomain_cmp, NULL);
			sf_d->nr_available_cpus -= tmp_cpu;
			for (i = 0; i < nr; i++) {
				sub_d = nodes[i].sud_d;
				tmpmask = to_cpumask(sub_d->span);
				cpumask_or(cpus, cpus, tmpmask);
				sub_d->attached++;
				nr_cpu -= cpumask_weight(tmpmask);
				if (nr_cpu <= 0)
					break;
			}

			/* 3. attach task group to softdomain. */
			args.policy = policy;
			args.cpus = cpus;
			args.nr_cpu = tmp_cpu;
			walk_tg_tree_from(tg, tg_set_soft_domain, tg_nop, &args);

			/*
			 * 4. TODO
			 * add tg to llc domain task_groups list for load balance.
			 */
			tg->sf_ctx->nr_cpus = tmp_cpu;
			tg->sf_ctx->sf_d = sf_d;
		} else {
			ret = -EINVAL;
		}
		rcu_read_unlock();
	}

	free_cpumask_var(cpus);

	return ret;
}

static int __sched_group_unset_soft_domain(struct task_group *tg)
{
	struct soft_domain_args args = {
		.policy = 0,
	};
	struct soft_domain *sf_d = NULL;
	struct soft_subdomain *sub_d = NULL;
	struct list_head *children = NULL;

	/* If parent has set soft domain, child group can't unset itself. */
	if (tg->parent->sf_ctx != NULL && tg->parent->sf_ctx->policy != 0)
		return -EINVAL;

	sf_d = tg->sf_ctx->sf_d;
	sf_d->nr_available_cpus += __calc_cpu(tg);
	children = &sf_d->child_domain;

	list_for_each_entry(sub_d, children, node) {
		if (cpumask_intersects(to_cpumask(tg->sf_ctx->span), to_cpumask(sub_d->span)))
			sub_d->attached--;
	}

	walk_tg_tree_from(tg, tg_set_soft_domain, tg_nop, &args);

	return 0;
}

int sched_group_set_soft_domain(struct task_group *tg, long val)
{
	int ret = 0;

	if (!soft_domain_enabled())
		return -EPERM;

	if (val < -1 || val > nr_node_ids)
		return -EINVAL;

	mutex_lock(&soft_domain_mutex);

	/* If enable or disable is repeated, directly return. */
	if (!!tg->sf_ctx->policy == !!val)
		goto out;

	if (val == 0)
		ret = __sched_group_unset_soft_domain(tg);
	else
		ret = __sched_group_set_soft_domain(tg, val);

	if (!ret)
		tg->sf_ctx->policy = val;

out:
	mutex_unlock(&soft_domain_mutex);

	return ret;
}

int sched_group_set_soft_domain_quota(struct task_group *tg, long val)
{
	int ret = 0;

	if (!soft_domain_enabled())
		return -EPERM;

	mutex_lock(&soft_domain_mutex);
	if (tg->sf_ctx->policy != 0) {
		ret = -EINVAL;
		goto out;
	} else
		tg->sf_ctx->nr_cpus = (int)val;

out:
	mutex_unlock(&soft_domain_mutex);

	return ret;
}

int init_soft_domain(struct task_group *tg, struct task_group *parent)
{
	struct soft_domain_ctx *sf_ctx = NULL;
	struct soft_domain_ctx *psf_ctx = NULL;

	if (!soft_domain_enabled())
		return 0;

	sf_ctx = kzalloc(sizeof(*sf_ctx) + cpumask_size(), GFP_KERNEL);
	if (!sf_ctx)
		return -ENOMEM;

	mutex_lock(&soft_domain_mutex);
	psf_ctx = parent->sf_ctx;
	if (psf_ctx) {
		sf_ctx->policy = psf_ctx->policy;
		sf_ctx->nr_cpus = psf_ctx->nr_cpus;
		cpumask_copy(to_cpumask(sf_ctx->span), to_cpumask(psf_ctx->span));
	}

	tg->sf_ctx = sf_ctx;
	mutex_unlock(&soft_domain_mutex);

	return 0;
}

void offline_soft_domain(struct task_group *tg)
{
	struct soft_domain_ctx *sf_ctx = NULL;
	struct soft_domain_ctx *psf_ctx = NULL;

	if (!soft_domain_enabled())
		return;

	sf_ctx = tg->sf_ctx;
	psf_ctx = tg->parent->sf_ctx;

	if (!sf_ctx)
		return;

	mutex_lock(&soft_domain_mutex);
	if (sf_ctx->policy != 0) {
		/*
		 * parent group is not set, this group set
		 * soft domain by user.
		 */
		if (psf_ctx == NULL || psf_ctx->policy == 0)
			__sched_group_unset_soft_domain(tg);
	}
	mutex_unlock(&soft_domain_mutex);
}

int destroy_soft_domain(struct task_group *tg)
{
	if (!soft_domain_enabled())
		return 0;

	kfree(tg->sf_ctx);

	return 0;
}
