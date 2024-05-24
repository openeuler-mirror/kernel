/* SPDX-License-Identifier: GPL-2.0 */

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
 */
#ifndef __LIBBPF_LIBSCHED_H
#define __LIBBPF_LIBSCHED_H

#include <linux/bpf_topology.h>
#include <linux/numa.h>
#include <linux/sched/relationship.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* set bigger value may lead verifier failed */
#define BPF_SCHED_LOOP_MAX	1024
#define INVALID_PTR		((void *)(0UL))
#define getVal(P)							\
	({								\
		typeof(P) val;						\
		bpf_probe_read_kernel(&val, sizeof(val), &(P));		\
		val;							\
	})

static __always_inline long libbpf_cpumask_next(int n, struct cpumask *mask);
static __always_inline long libbpf_cpumask_next_wrap(int n,
						     struct cpumask *mask,
						     int start, int wrap);
static __always_inline long libbpf_cpumask_next_and(int n,
						    struct cpumask *mask1,
						    struct cpumask *mask2);
static __always_inline int libbpf_nr_cpus_ids(void);
static __always_inline int libbpf_nr_cpumask_bits(void);

#if NR_CPUS == 1

#define libbpf_for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define libbpf_for_each_cpu_wrap(cpu, mask, start)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)(start))
#define libbpf_for_each_cpu_and(cpu, mask1, mask2)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask1, (void)mask2)

#else

#define libbpf_for_each_cpu(cpu, mask)				\
	for (int __i = 0, (cpu) = -1;				\
		(cpu) = libbpf_cpumask_next((cpu), (mask)),	\
		(cpu) < libbpf_nr_cpus_ids() && __i < NR_CPUS; __i++)

#define libbpf_for_each_cpu_wrap(cpu, mask, start)			\
	for (int __i = 0, (cpu) = libbpf_cpumask_next_wrap((start) - 1,\
		(mask), (start), false);				\
		(cpu) < libbpf_nr_cpumask_bits() && __i < NR_CPUS;	\
		(cpu) = libbpf_cpumask_next_wrap((cpu), (mask), (start),\
						 true), __i++)

#define libbpf_for_each_cpu_and(cpu, mask1, mask2)			\
	for (int __i = 0, (cpu) = -1;					\
		(cpu) = libbpf_cpumask_next_and((cpu), (mask1), (mask2)),\
		(cpu) < libbpf_nr_cpus_ids() && __i < NR_CPUS; __i++)

#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct bpf_cpumask_info);
	__uint(max_entries, 1);
} map_cpumask_info SEC(".maps");

static struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct bpf_relationship_get_args);
	__uint(max_entries, 1);
} map_rship_stats SEC(".maps");

static __always_inline void
libbpf_nodes_and(nodemask_t *dst, nodemask_t *src1, nodemask_t *src2)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODES_AND;
	op.arg1 = dst;
	op.arg2 = src1;
	op.arg3 = src2;
	bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline void
libbpf_nodes_andnot(nodemask_t *dst, nodemask_t *src1, nodemask_t *src2)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODES_ANDNOT;
	op.arg1 = dst;
	op.arg2 = src1;
	op.arg3 = src2;
	bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline void
libbpf_nodes_or(nodemask_t *dst, nodemask_t *src1, nodemask_t *src2)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODES_OR;
	op.arg1 = dst;
	op.arg2 = src1;
	op.arg3 = src2;
	bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline void libbpf_node_set(int nid,
					    nodemask_t *nodes)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODE_SET;
	op.arg1 = &nid;
	op.arg2 = nodes;
	op.arg3 = INVALID_PTR;
	bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline void libbpf_node_clear(int nid,
					      nodemask_t *nodes)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODE_CLEAR;
	op.arg1 = &nid;
	op.arg2 = nodes;
	op.arg3 = INVALID_PTR;
	bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline long libbpf_node_isset(int nid,
					      nodemask_t *nodes)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_NODE_ISSET;
	op.arg1 = &nid;
	op.arg2 = nodes;
	op.arg3 = INVALID_PTR;
	return bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline long libbpf_nodemask_empty(nodemask_t *nodes)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_EMPTY;
	op.arg1 = nodes;
	op.arg2 = INVALID_PTR;
	op.arg3 = INVALID_PTR;
	return bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline long libbpf_nodemask_to_cpumask(nodemask_t *nodes,
						       struct cpumask *cpus)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_TO_CPUMASK;
	op.arg1 = nodes;
	op.arg2 = cpus;
	op.arg3 = INVALID_PTR;
	return bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline long libbpf_nodes_online(nodemask_t *nodes)
{
	struct nodemask_op_args op = {0};

	op.op_type = NODEMASK_ONLINE;
	op.arg1 = nodes;
	op.arg2 = INVALID_PTR;
	op.arg3 = INVALID_PTR;
	return bpf_nodemask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_copy(struct cpumask *dst,
						struct cpumask *src)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_COPY;
	op.arg1 = dst;
	op.arg2 = src;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_empty(struct cpumask *mask)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_EMPTY;
	op.arg1 = mask;
	op.arg2 = INVALID_PTR;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_and(struct cpumask *dst,
					       struct cpumask *src1,
					       struct cpumask *src2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_AND;
	op.arg1 = dst;
	op.arg2 = src1;
	op.arg3 = src2;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_andnot(struct cpumask *dst,
						  struct cpumask *src1,
						  struct cpumask *src2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_ANDNOT;
	op.arg1 = dst;
	op.arg2 = src1;
	op.arg3 = src2;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_subset(struct cpumask *src1,
						  struct cpumask *src2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_SUBSET;
	op.arg1 = src1;
	op.arg2 = src2;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_equal(struct cpumask *src1,
						 struct cpumask *src2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_EQUAL;
	op.arg1 = src1;
	op.arg2 = src2;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_weight(struct cpumask *src1)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_WEIGHT;
	op.arg1 = src1;
	op.arg2 = INVALID_PTR;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_test_cpu(int cpu,
						    struct cpumask *mask)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_TEST_CPU;
	op.arg1 = &cpu;
	op.arg2 = mask;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_next(int n, struct cpumask *mask)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_NEXT;
	op.arg1 = &n;
	op.arg2 = mask;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_next_wrap(int n,
						     struct cpumask *mask,
						     int start, int wrap)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_NEXT_WRAP;
	op.arg1 = &n;
	op.arg2 = mask;
	op.arg3 = &start;
	op.arg4 = &wrap;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_next_and(int n,
						    struct cpumask *mask1,
						    struct cpumask *mask2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_NEXT_AND;
	op.arg1 = &n;
	op.arg2 = mask1;
	op.arg3 = mask2;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline long libbpf_cpumask_cpulist_parse(char *src1,
							 struct cpumask *src2)
{
	struct cpumask_op_args op;

	op.op_type = CPUMASK_CPULIST_PARSE;
	op.arg1 = src1;
	op.arg2 = src2;
	op.arg3 = INVALID_PTR;
	op.arg4 = INVALID_PTR;
	return bpf_cpumask_op(&op, sizeof(op));
}

static __always_inline int libbpf_num_active_cpus(void)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return -1;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	return getVal(cpus->nums_active_cpus);
}

static __always_inline int libbpf_num_possible_cpus(void)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return -1;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	return getVal(cpus->nums_possible_cpus);
}

static __always_inline void libbpf_possible_cpus_mask(struct cpumask *mask)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	libbpf_cpumask_copy(mask, &cpus->cpu_possible_cpumask);
}

static __always_inline void libbpf_active_cpus_mask(struct cpumask *mask)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	libbpf_cpumask_copy(mask, &cpus->cpu_active_cpumask);
}

static __always_inline void libbpf_isolate_cpus_mask(struct cpumask *mask)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	libbpf_cpumask_copy(mask, &cpus->cpu_isolate_cpumask);
}

static __always_inline int libbpf_nr_cpus_ids(void)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return -1;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	return getVal(cpus->bpf_nr_cpu_ids);
}

static __always_inline int libbpf_nr_cpumask_bits(void)
{
	struct bpf_cpumask_info *cpus;
	int key = 0;

	cpus = bpf_map_lookup_elem(&map_cpumask_info, &key);
	if (!cpus)
		return -1;

	bpf_get_cpumask_info(&map_cpumask_info, cpus);
	return getVal(cpus->bpf_nr_cpumask_bits);
}

static __always_inline unsigned long libbpf_cfs_load_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return getVal(load.cfs_load_avg);
}

static __always_inline unsigned long libbpf_cfs_runnable_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return getVal(load.cfs_runnable_avg);
}

static __always_inline unsigned long libbpf_cfs_util_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return getVal(load.cfs_util_avg);
}

static __always_inline unsigned long libbpf_rt_load_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return load.rt_load_avg;
}

static __always_inline unsigned long libbpf_rt_runnable_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return load.rt_runnable_avg;
}

static __always_inline unsigned long libbpf_rt_util_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return load.rt_util_avg;
}

static __always_inline unsigned long libbpf_irq_load_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return load.irq_load_avg;
}

static __always_inline unsigned long libbpf_irq_util_avg_of(int cpu)
{
	struct bpf_sched_cpu_stats load;

	bpf_sched_cpu_stats_of(cpu, &load, sizeof(load));
	return load.irq_util_avg;
}

static __always_inline unsigned int libbpf_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return getVal(running.nr_running);
}

static __always_inline unsigned int libbpf_cfs_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return getVal(running.cfs_nr_running);
}

static __always_inline unsigned int libbpf_cfs_h_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return getVal(running.cfs_h_nr_running);
}

static __always_inline unsigned int libbpf_cfs_idle_h_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return running.cfs_idle_h_nr_running;
}

static __always_inline unsigned int libbpf_rt_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return getVal(running.rt_nr_running);
}

static __always_inline unsigned int libbpf_rr_nr_running_of(int cpu)
{
	struct bpf_sched_cpu_stats running;

	bpf_sched_cpu_stats_of(cpu, &running, sizeof(running));
	return running.rr_nr_running;
}

static __always_inline unsigned int libbpf_exit_latency_of(int cpu)
{
	struct bpf_sched_cpu_stats stat;

	bpf_sched_cpu_stats_of(cpu, &stat, sizeof(stat));
	return stat.exit_latency;
}

static __always_inline unsigned long libbpf_idle_stamp_of(int cpu)
{
	struct bpf_sched_cpu_stats stat;

	bpf_sched_cpu_stats_of(cpu, &stat, sizeof(stat));
	return stat.idle_stamp;
}

static __always_inline unsigned long libbpf_avg_idle_of(int cpu)
{
	struct bpf_sched_cpu_stats stat;

	bpf_sched_cpu_stats_of(cpu, &stat, sizeof(stat));
	return stat.avg_idle;
}

static __always_inline unsigned long libbpf_available_idle_cpu(int cpu)
{
	struct bpf_sched_cpu_stats stat;

	bpf_sched_cpu_stats_of(cpu, &stat, sizeof(stat));
	return getVal(stat.available_idle);
}

static __always_inline unsigned long libbpf_capacity_of(int cpu)
{
	struct bpf_sched_cpu_stats cap;

	bpf_sched_cpu_stats_of(cpu, &cap, sizeof(cap));
	return getVal(cap.capacity);
}

static __always_inline unsigned long libbpf_capacity_orig_of(int cpu)
{
	struct bpf_sched_cpu_stats cap;

	bpf_sched_cpu_stats_of(cpu, &cap, sizeof(cap));
	return cap.capacity_orig;
}

static __always_inline int libbpf_cpus_share_cache(int src_cpu, int dst_cpu)
{
	return bpf_cpus_share_cache(src_cpu, dst_cpu);
}

static __always_inline  int libbpf_sched_se_tag_of(struct sched_entity *se)
{
	int se_tag = 0;

	if (bpf_sched_entity_is_task(se)) {
		struct task_struct *task = bpf_sched_entity_to_task(se);

		se_tag = bpf_sched_task_tag_of(task);
	} else {
		struct task_group *tg = bpf_sched_entity_to_tg(se);

		se_tag = bpf_sched_tg_tag_of(tg);
	}

	return se_tag;
}

static __always_inline unsigned long libbpf_node_cfs_util_of(int nid)
{
	struct bpf_node_stats stats = {0};

	bpf_get_node_stats(nid, &stats, sizeof(stats));
	return getVal(stats.util);
}

static __always_inline unsigned long libbpf_node_cfs_capacity_of(int nid)
{
	struct bpf_node_stats stats = {0};

	bpf_get_node_stats(nid, &stats, sizeof(stats));
	return getVal(stats.compute_capacity);
}

static __always_inline unsigned int libbpf_node_weight_of(int nid)
{
	struct bpf_node_stats stats = {0};

	bpf_get_node_stats(nid, &stats, sizeof(stats));
	return getVal(stats.weight);
}

static __always_inline int
libbpf_mem_preferred_nid(struct task_struct *tsk, nodemask_t *preferred_node)
{
	struct bpf_relationship_get_args *stats;
	int key = 0;
	int ret;

	stats = bpf_map_lookup_elem(&map_rship_stats, &key);
	if (!stats)
		return NUMA_NO_NODE;

	ret = bpf_get_task_relationship_stats(tsk, &map_rship_stats, stats);
	if (ret)
		return NUMA_NO_NODE;

	*preferred_node = getVal(stats->mm.comm.preferred_node);
	return 0;
}
#endif
