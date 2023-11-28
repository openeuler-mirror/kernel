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
#include <linux/numa.h>
#include <linux/sched/grid_qos.h>
#include "internal.h"
#include <../kernel/sched/sched.h>

static inline int qos_affinity_set(struct task_struct *p)
{
	int n;
	struct sched_grid_qos_affinity *affinity = &p->grid_qos->affinity;

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
	if (likely(orig->grid_qos))
		qos->affinity = orig->grid_qos->affinity;
	qos->affinity_set = qos_affinity_set;
	p->grid_qos = qos;

	return 0;
}

void sched_grid_qos_free(struct task_struct *p)
{
	kfree(p->grid_qos);
	p->grid_qos = NULL;
}

/* dynamic select a more appropriate preferred interleave nid for process */
int sched_grid_preferred_interleave_nid(struct mempolicy *policy)
{
#ifndef CONFIG_NUMA
	return NUMA_NO_NODE;
#else
	nodemask_t nmask;
	unsigned int next;
	struct task_struct *me = current;
	nodemask_t *preferred_nmask = NULL;

	if (likely(me->grid_qos))
		preferred_nmask =
			&me->grid_qos->affinity.mem_preferred_node_mask;

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
#endif
}

/* dynamic select a more appropriate preferred nid for process */
int sched_grid_preferred_nid(int preferred_nid, nodemask_t *nodemask)
{
	int nd = preferred_nid;
	nodemask_t nmask, ndmask;
	nodemask_t *preferred_nmask = NULL;

	if (likely(current->grid_qos))
		preferred_nmask =
			&current->grid_qos->affinity.mem_preferred_node_mask;

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

static struct sched_grid_zone sg_zone;

int __init sched_grid_zone_init(void)
{
	int index;

	for (index = 0; index < SMART_GRID_ZONE_NR; index++)
		cpumask_clear(&sg_zone.cpus[index]);

	raw_spin_lock_init(&sg_zone.lock);
	INIT_LIST_HEAD(&sg_zone.af_list_head);
	return 0;
}

int sched_grid_zone_update(bool is_locked)
{
	struct list_head *pos;
	struct auto_affinity *af_pos;
	unsigned long flags;

	if (!is_locked)
		raw_spin_lock_irqsave(&sg_zone.lock, flags);

	cpumask_clear(&sg_zone.cpus[SMART_GRID_ZONE_HOT]);

	list_for_each(pos, &sg_zone.af_list_head) {
		af_pos = list_entry(pos, struct auto_affinity, af_list);

		/* when smart_grid not used we need calculate all task_group */
		/* when smart_grid used we only calculate enabled task_group */
		if (smart_grid_used() && af_pos->mode == 0)
			continue;

		cpumask_or(&sg_zone.cpus[SMART_GRID_ZONE_HOT], &sg_zone.cpus[SMART_GRID_ZONE_HOT],
			   af_pos->ad.domains[af_pos->ad.curr_level]);
	}

	cpumask_complement(&sg_zone.cpus[SMART_GRID_ZONE_WARM],
			   &sg_zone.cpus[SMART_GRID_ZONE_HOT]);

	if (!is_locked)
		raw_spin_unlock_irqrestore(&sg_zone.lock, flags);

	cpufreq_smart_grid_start_sync();
	return 0;
}

int sched_grid_zone_add_af(struct auto_affinity *af)
{
	unsigned long flags;

	if (af == NULL)
		return -1;

	raw_spin_lock_irqsave(&sg_zone.lock, flags);
	list_add_tail(&af->af_list, &sg_zone.af_list_head);
	sched_grid_zone_update(true);
	raw_spin_unlock_irqrestore(&sg_zone.lock, flags);
	return 0;
}

int sched_grid_zone_del_af(struct auto_affinity *af)
{
	unsigned long flags;

	if (af == NULL)
		return -1;

	raw_spin_lock_irqsave(&sg_zone.lock, flags);
	list_del(&af->af_list);
	sched_grid_zone_update(true);
	raw_spin_unlock_irqrestore(&sg_zone.lock, flags);
	return 0;
}

struct cpumask *sched_grid_zone_cpumask(enum sg_zone_type zone)
{
	if (zone >= SMART_GRID_ZONE_NR)
		return NULL;

	return &sg_zone.cpus[zone];
}

/*
 * Default smart_grid strategy was disable (=0).
 * But, considering for inheritance of the pre-verion code.
 * We make all the task to the highest qos_level (class_lvl = 0),
 * when smart_grid strategy was disabled.
 * Otherwise, When smart_grid strategy was enabled, we use the task's
 * actually class_lvl.
 */
unsigned int sysctl_smart_grid_strategy_ctrl;

struct cpumask *sched_grid_prefer_cpus(struct task_struct *p)
{
	struct affinity_domain *ad;
	enum sg_zone_type current_zone;

	ad = &task_group(p)->auto_affinity->ad;
	/*
	 * when smart_grid strategy was disabled,
	 * We make all the task to the highest qos_level (class_lvl = 0)
	 */
	if (sysctl_smart_grid_strategy_ctrl == 0)
		return ad->domains[ad->curr_level];

	/* Only place the highest level task into hot zone */
	current_zone = p->grid_qos->stat.class_lvl == SCHED_GRID_QOS_TASK_LEVEL_HIGHEST ?
		       SMART_GRID_ZONE_HOT : SMART_GRID_ZONE_WARM;

	/* Place the highest level task in current domain level itself */
	if (current_zone == SMART_GRID_ZONE_HOT)
		return ad->domains[ad->curr_level];

	return &sg_zone.cpus[current_zone];
}
