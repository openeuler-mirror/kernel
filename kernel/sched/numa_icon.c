// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for task numa isolation consolidation
 *
 * Copyright (C) 2023-2024 Huawei Technologies Co., Ltd
 *
 * Author: Hui Tang <tanghui20@huawei.com>
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

static bool __sched_numa_icon_switch __initdata;
DEFINE_STATIC_KEY_FALSE(sched_numa_icon_switch);

struct node_load_info *node_load_ptr;

static void set_numa_icon_switch(bool enabled)
{
	if (enabled) {
		static_branch_enable(&sched_numa_icon_switch);
		task_relationship_enable();
	} else {
		static_branch_disable(&sched_numa_icon_switch);
		task_relationship_disable();
	}
}

static int __init numa_icon_switch_setup(char *str)
{
	int ret = 0;

	if (!str)
		goto out;

	/*
	 * This code is called before jump labels have been set up, so we can't
	 * change the static branch directly just yet.  Instead set a temporary
	 * variable so init_numa_icon_switch() can do it later.
	 */
	if (!strcmp(str, "enable")) {
		__sched_numa_icon_switch = true;
		ret = 1;
	} else if (!strcmp(str, "disable")) {
		__sched_numa_icon_switch = false;
		ret = 1;
	}
out:
	if (!ret)
		pr_warn("Unable to parse numa_icon=\n");

	return ret;
}
__setup("numa_icon=", numa_icon_switch_setup);

__init void init_sched_numa_icon(void)
{
	int i;

	set_numa_icon_switch(__sched_numa_icon_switch);

	if (!sched_numa_icon_enabled())
		return;

	node_load_ptr = kcalloc(nr_node_ids, sizeof(struct node_load_info),
		GFP_KERNEL);

	for (i = 0; i < nr_node_ids; i++) {
		raw_spin_lock_init(&node_load_ptr[i].lock);
		node_load_ptr[i].util_avg_last =
			kcalloc(nr_cpu_ids, sizeof(struct sched_avg), GFP_KERNEL);
	}

	for_each_possible_cpu(i) {
		node_load_ptr[cpu_to_node(i)].compute_capacity +=
			SCHED_CAPACITY_SCALE;
	}
}

void print_node_load_info(struct seq_file *m, int node)
{
	if (!sched_numa_icon_enabled())
		return;

	seq_printf(m, "node %d capacity=%lu util_avg=%lu\n", node,
		node_load_ptr[node].compute_capacity,
		atomic_long_read(&node_load_ptr[node].util_avg));
}

void numa_load_change(struct cfs_rq *cfs_rq)
{
	struct rq *rq = rq_of(cfs_rq);
	int cpu = cpu_of(rq);
	int nid = cpu_to_node(cpu);
	struct sched_avg *avg_old;
	long delta;

	if (!sched_numa_icon_enabled())
		return;

	avg_old = &node_load_ptr[nid].util_avg_last[cpu];

	if (&rq->cfs != cfs_rq)
		return;

	delta = cfs_rq->avg.util_avg - avg_old->util_avg;
	atomic_long_add(delta, &node_load_ptr[nid].util_avg);
	avg_old->util_avg = cfs_rq->avg.util_avg;
}

void update_numa_capacity(struct rq *rq)
{
	int cpu = cpu_of(rq);
	int nid = cpu_to_node(cpu);
	unsigned long capacity = 0;

	if (!sched_numa_icon_enabled())
		return;

	if (cpu != cpumask_first(cpumask_of_node(nid)))
		return;

	for_each_cpu(cpu, cpumask_of_node(nid)) {
		capacity += cpu_rq(cpu)->cpu_capacity;
	}
	node_load_ptr[nid].compute_capacity = capacity;
}

#ifdef CONFIG_BPF_SCHED
void sched_get_node_load(int nid, struct bpf_node_stats *ctx)
{
	ctx->util = atomic_long_read(&node_load_ptr[nid].util_avg);
	ctx->compute_capacity = node_load_ptr[nid].compute_capacity;
	ctx->weight = cpumask_weight(cpumask_of_node(nid));
}
#endif
