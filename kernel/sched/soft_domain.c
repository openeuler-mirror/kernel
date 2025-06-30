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

#include "sched.h"

static DEFINE_PER_CPU(struct soft_domain *, g_sf_d);

static void free_sub_soft_domain(struct soft_domain *sf_d);

static int build_soft_sub_domain(struct sched_domain *sd, struct cpumask *cpus)
{
	struct cpumask *span = sched_domain_span(sd);
	int nid = cpu_to_node(cpumask_first(span));
	struct soft_domain *sf_d = NULL;
	int i;

	sf_d = kzalloc_node(sizeof(struct soft_domain) + cpumask_size(),
			    GFP_KERNEL, nid);
	if (!sf_d)
		return -ENOMEM;

	INIT_LIST_HEAD(&sf_d->child_domain);
	sf_d->nr_available_cpus = cpumask_weight(span);
	cpumask_copy(to_cpumask(sf_d->span), span);

	for_each_cpu_and(i, sched_domain_span(sd), cpus) {
		struct soft_subdomain *sub_d = NULL;

		sub_d = kzalloc_node(sizeof(struct soft_subdomain) + cpumask_size(),
				     GFP_KERNEL, nid);
		if (!sub_d) {
			free_sub_soft_domain(sf_d);
			return -ENOMEM;
		}

		list_add_tail(&sub_d->node, &sf_d->child_domain);
		cpumask_copy(soft_domain_span(sub_d->span), cpu_clustergroup_mask(i));
		cpumask_andnot(cpus, cpus, cpu_clustergroup_mask(i));
	}

	for_each_cpu(i, sched_domain_span(sd)) {
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
}

void build_soft_domain(void)
{
	struct sched_domain *sd;
	static struct cpumask cpus;
	int i, ret;

	cpumask_copy(&cpus, cpu_active_mask);
	rcu_read_lock();
	for_each_cpu(i, &cpus) {
		/* build soft domain for each llc domain. */
		sd = rcu_dereference(per_cpu(sd_llc, i));
		if (sd) {
			ret = build_soft_sub_domain(sd, &cpus);
			if (ret) {
				free_soft_domain();
				goto out;
			}
		}
	}

out:
	rcu_read_unlock();
}
