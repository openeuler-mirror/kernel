// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for Smart Grid Scheduling
 *
 * Copyright (C) 2023-2024 Huawei Technologies Co., Ltd
 *
 * Author: Wang Shaobo <bobo.shaobowang@huawei.com>
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
#include <linux/nodemask.h>
#include <linux/mempolicy.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/grid_qos.h>
#include "internal.h"

static inline int qos_affinity_set(struct task_struct *p)
{
	int n;
	struct sched_grid_qos_affinity *affinity = &p->_resvd->grid_qos->affinity;

	if (likely(affinity->prefer_cpus == p->select_cpus))
		return 0;

	/*
	 * We want the memory allocation to be as close to the CPU
	 * as possible, and adjust after getting memory bandwidth usage.
	 */
	for (n = 0; n < nr_node_ids; n++) {
		if (cpumask_intersects(cpumask_of_node(n), p->select_cpus))
			node_set(n, affinity->mem_preferred_node_mask);
		else
			node_clear(n, affinity->mem_preferred_node_mask);
	}

	affinity->prefer_cpus = p->select_cpus;
	return 0;
}

int sched_grid_qos_fork(struct task_struct *p, struct task_struct *orig)
{
	struct sched_grid_qos *qos;

	qos = kzalloc(sizeof(*qos), GFP_KERNEL);
	if (!qos)
		return -ENOMEM;

	qos_power_init(&qos->power);
	qos_stat_init(&qos->stat);

	nodes_clear(qos->affinity.mem_preferred_node_mask);
	if (likely(orig->_resvd->grid_qos))
		qos->affinity = orig->_resvd->grid_qos->affinity;
	qos->affinity_set = qos_affinity_set;
	p->_resvd->grid_qos = qos;

	return 0;
}

void sched_grid_qos_free(struct task_struct *p)
{
	kfree(p->_resvd->grid_qos);
	p->_resvd->grid_qos = NULL;
}

/* dynamic select a more appropriate preferred interleave nid for process */
int sched_grid_preferred_interleave_nid(struct mempolicy *policy)
{
	nodemask_t nmask;
	unsigned int next;
	struct task_struct *me = current;
	nodemask_t *preferred_nmask = NULL;

	if (likely(me->_resvd->grid_qos))
		preferred_nmask =
			&me->_resvd->grid_qos->affinity.mem_preferred_node_mask;

	if (!preferred_nmask || !policy)
		return NUMA_NO_NODE;

	if (nodes_equal(policy->v.nodes, *preferred_nmask))
		return NUMA_NO_NODE;
	/*
	 * We perceive the actual consumption of memory bandwidth
	 * in each node and post a preferred interleave nid in
	 * more appropriate range.
	 */
	nodes_and(nmask, policy->v.nodes, *preferred_nmask);
	if (nodes_empty(nmask))
		return NUMA_NO_NODE;

	next = next_node_in(me->il_prev, nmask);
	if (next < MAX_NUMNODES)
		me->il_prev = next;
	return next;
}

/* dynamic select a more appropriate preferred nid for process */
int sched_grid_preferred_nid(int preferred_nid, nodemask_t *nodemask)
{
	int nd = preferred_nid;
	nodemask_t nmask, ndmask;
	nodemask_t *preferred_nmask = NULL;

	if (likely(current->_resvd->grid_qos))
		preferred_nmask =
			&current->_resvd->grid_qos->affinity.mem_preferred_node_mask;

	if (!preferred_nmask)
		return preferred_nid;

	/*
	 * We perceive the actual consumption of memory bandwidth
	 * in each node and post a preferred nid in more appropriate
	 * range.
	 */
	nmask = *preferred_nmask;
	if (nodemask) {
		if (nodes_equal(*nodemask, nmask))
			return preferred_nid;

		nodes_and(nmask, nmask, *nodemask);
	}

	if (node_isset(preferred_nid, nmask))
		return preferred_nid;

	/*
	 * We prefer the numa node we're running, if there is no limit
	 * to nodemask, we select preferred nid in preferred range or
	 * in restriced range if not.
	 */
	init_nodemask_of_node(&ndmask, numa_node_id());
	nodes_and(ndmask, nmask, ndmask);
	if (!nodes_empty(ndmask))
		nd = first_node(ndmask);
	else if (!nodes_empty(nmask))
		nd = first_node(nmask);

	return nd;
}
