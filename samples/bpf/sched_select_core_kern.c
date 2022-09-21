// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Sample select core BPF program.
 * 'cfs_select_rq'
 *       Replace the original core selection policy or
 *       implement dynamic CPU affinity.
 *
 * 'cfs_select_rq_exit'
 *       Restoring the CPU affinity of the task before exiting of
 *       'select_task_rq_fair'.
 *
 *       To be used with 'cfs_select_rq' hook to implement
 *       dynamic CPU affinity.
 *
 * 'cfs_wake_affine'
 *       Determine on which CPU task can run soonest. Allow user to
 *       implement deferent policies.
 */
#include <linux/version.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/libbpf_sched.h>
#include <linux/cpumask.h>

#define STR_MAX				(32)
#define SELECT_RQ_RANGE			(-1)
#define SELECT_RQ_EXIT_CPU_VALID	(-2)

/* From kernel/sched/sched.h */
#define WF_SYNC			0x01		/* Waker goes to sleep after wakeup */
#define WF_FORK			0x02		/* Child wakeup after fork */
#define WF_MIGRATED		0x04		/* Internal use, task got migrated */
#define WF_ON_CPU		0x08		/* Wakee is on_cpu */

#define TAG_ID(id) TAG_##id

enum tag_id {
	TAG_NONE,
	TAG_ID(1),
	TAG_ID(2),
	TAG_MAX
};

struct tag_info {
	long tag;
	char buf[STR_MAX];
};

struct tag_info tag_tbl[] = {
	{TAG_NONE, ""},
	{TAG_ID(1), "0-1"},
	{TAG_ID(2), "4-7"},
	{TAG_MAX, ""},
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, int);
	__uint(max_entries, 1);
} map_idlest_cpu SEC(".maps");

int sysctl_sched_util_low_pct = 85;

static inline bool prefer_cpus_valid(struct cpumask *prefer_cpus,
				     struct cpumask *cpus_allowed)
{
	return !libbpf_cpumask_empty(prefer_cpus) &&
	       !libbpf_cpumask_equal(prefer_cpus, cpus_allowed) &&
	       libbpf_cpumask_subset(prefer_cpus, cpus_allowed);
}

static struct cpumask *select_better_cpus(struct task_struct *p,
					  struct cpumask *prefer_cpus,
					  int *idlest_cpu)
{
	unsigned long util_avg_sum = 0;
	unsigned long tg_capacity = 0;
	unsigned int weight;
	long min_util = INT_MIN;
	struct task_group *tg;
	long spare;
	int cpu, i;

	if (!prefer_cpus_valid(prefer_cpus, (void *)getVal(p->cpus_ptr)))
		return (void *)getVal(p->cpus_ptr);

	tg = p->sched_task_group;
	for (i = 0, cpu = -1; i < BPF_SCHED_LOOP_MAX; i++) {
		cpu = libbpf_cpumask_next(cpu, (void *)getVal(prefer_cpus));
		if (cpu >= libbpf_nr_cpus_ids())
			break;

		if (idlest_cpu && libbpf_available_idle_cpu(cpu)) {
			*idlest_cpu = cpu;
		} else if (idlest_cpu) {
			spare = (long)(libbpf_capacity_of(cpu) - libbpf_cfs_util_avg_of(cpu));
			if (spare > min_util) {
				min_util = spare;
				*idlest_cpu = cpu;
			}
		}

		if (libbpf_available_idle_cpu(cpu))
			return getVal(prefer_cpus);

		util_avg_sum += libbpf_cfs_util_avg_of(cpu);
		tg_capacity += libbpf_capacity_of(cpu);
	}

	weight = libbpf_cpumask_weight(prefer_cpus);
	if (tg_capacity > weight &&
	    util_avg_sum * 100 <= tg_capacity * sysctl_sched_util_low_pct) {
		return getVal(prefer_cpus);
	}

	return (void *)getVal(p->cpus_ptr);
}

SEC("sched/cfs_select_rq")
int BPF_PROG(cfs_select_cpu_range, struct sched_migrate_ctx *h_ctx)
{
	struct cpumask *prefer_cpus = getVal(h_ctx->select_idle_mask);
	struct task_struct *p = getVal(h_ctx->task);
	struct cpumask *cpus_ptr;
	int type = SELECT_RQ_RANGE;
	long tag = getVal(p->tag);
	int *idlest_cpu = 0;
	int key = 0;
	int ret;

	if (tag <= TAG_NONE || tag >= TAG_MAX)
		return type;

	ret = libbpf_cpumask_cpulist_parse(tag_tbl[tag].buf, prefer_cpus);
	if (ret)
		return type;

	idlest_cpu = bpf_map_lookup_elem(&map_idlest_cpu, &key);
	if (!idlest_cpu)
		return type;

	cpus_ptr = select_better_cpus(p, prefer_cpus, idlest_cpu);
	libbpf_sched_set_task_cpus_ptr((void *)h_ctx, getVal(cpus_ptr));

	return type;
}

SEC("sched/cfs_select_rq_exit")
int BPF_PROG(cfs_select_cpu_range_exit, struct sched_migrate_ctx *h_ctx)
{
	struct task_struct *p = getVal(h_ctx->task);
	long tag = getVal(p->tag);
	int *idlest_cpu;
	int key = 0;

	if (tag <= TAG_NONE || tag >= TAG_MAX)
		return SELECT_RQ_EXIT_CPU_VALID;

	idlest_cpu = bpf_map_lookup_elem(&map_idlest_cpu, &key);
	if (!idlest_cpu) {
		libbpf_sched_set_task_cpus_ptr(h_ctx, (void *)getVal(h_ctx->cpus_allowed));
		return SELECT_RQ_EXIT_CPU_VALID;
	}

	if (!libbpf_cpumask_test_cpu(getVal(h_ctx->new_cpu),
	    (void *)getVal(h_ctx->task->cpus_ptr))) {
		libbpf_sched_set_task_cpus_ptr(h_ctx, (void *)getVal(h_ctx->cpus_allowed));
		return *idlest_cpu;
	}

	libbpf_sched_set_task_cpus_ptr(h_ctx, (void *)getVal(h_ctx->cpus_allowed));
	return SELECT_RQ_EXIT_CPU_VALID;
}

static int find_idlest_cpu(struct task_struct *p, int parent)
{
	unsigned long min = INT_MAX;
	int min_load_cpu = 0;
	unsigned long load;
	int cpu;
	int i;

	for (i = 0, cpu = -1; i < BPF_SCHED_LOOP_MAX; i++) {
		cpu = libbpf_cpumask_next(cpu, (void *)getVal(p->cpus_ptr));
		if (cpu >= libbpf_nr_cpus_ids())
			break;

		load = libbpf_cfs_load_avg_of(cpu);
		if (load < min) {
			min = load;
			min_load_cpu = cpu;
		}
	}

	return min_load_cpu;
}

static int select_idle_cpu(struct task_struct *p, int parent, int prev_cpu)
{
	int cpu, i;

	if (libbpf_available_idle_cpu(prev_cpu))
		return prev_cpu;

	if (libbpf_available_idle_cpu(parent))
		return parent;

	cpu = libbpf_cpumask_next_wrap(prev_cpu - 1,
				       (void *)getVal(p->cpus_ptr),
				       prev_cpu, false);
	for (i = 0; i < BPF_SCHED_LOOP_MAX; i++) {
		if (cpu >= libbpf_nr_cpumask_bits())
			break;

		if (libbpf_available_idle_cpu(cpu))
			return cpu;

		cpu = libbpf_cpumask_next_wrap(cpu, (void *)getVal(p->cpus_ptr),
					       prev_cpu, true);
	}

	return prev_cpu;
}

SEC("sched/cfs_select_rq")
int BPF_PROG(cfs_select_cpu, struct sched_migrate_ctx *h_ctx)
{
	struct task_struct *p = getVal(h_ctx->task);
	int wake_flags = getVal(h_ctx->wake_flags);
	int prev_cpu = getVal(h_ctx->prev_cpu);
	int cpu = getVal(h_ctx->curr_cpu);
	int new_cpu;

	if (wake_flags == WF_FORK) {
		/* Slow path */
		new_cpu = find_idlest_cpu(p, cpu);
	} else {
		/* Fast path */
		new_cpu = select_idle_cpu(p, cpu, prev_cpu);
	}

	return new_cpu;
}

SEC("sched/cfs_wake_affine")
int BPF_PROG(cfs_wake_affine, struct sched_affine_ctx *h_ctx)
{
	int prev_cpu = getVal(h_ctx->prev_cpu);
	int curr_cpu = getVal(h_ctx->curr_cpu);
	int sync = getVal(h_ctx->is_sync);

	if (libbpf_available_idle_cpu(curr_cpu) &&
	    libbpf_cpus_share_cache(curr_cpu, prev_cpu))
		return libbpf_available_idle_cpu(prev_cpu) ? prev_cpu : curr_cpu;

	if (sync && libbpf_nr_running_of(curr_cpu) == 1)
		return curr_cpu;

	return prev_cpu;
}

char _license[] SEC("license") = "GPL";
