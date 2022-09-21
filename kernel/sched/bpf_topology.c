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
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/bpf_verifier.h>
#include <linux/topology.h>
#include <linux/cpumask.h>
#include <linux/bpf_topology.h>
#include <linux/sched/isolation.h>

static void bpf_update_cpu_topology(struct bpf_cpu_topology *cpu_topology, int cpu)
{
	cpu_topology->cpu = cpu;
	cpu_topology->core_id = topology_core_id(cpu);
	cpu_topology->cluster_id = topology_cluster_id(cpu);
	cpu_topology->die_id = topology_die_id(cpu);
	cpu_topology->physical_package_id = topology_physical_package_id(cpu);
	cpu_topology->numa_node = cpu_to_node(cpu);
	cpumask_copy(&cpu_topology->thread_siblings, topology_sibling_cpumask(cpu));
	cpumask_copy(&cpu_topology->core_siblings, topology_core_cpumask(cpu));
	cpumask_copy(&cpu_topology->cluster_cpus, topology_cluster_cpumask(cpu));
	cpumask_copy(&cpu_topology->die_cpus, topology_die_cpumask(cpu));
	cpumask_copy(&cpu_topology->package_cpus, topology_core_cpumask(cpu));
	cpumask_copy(&cpu_topology->node_cpu_lists, cpumask_of_node(cpu_to_node(cpu)));
}

BPF_CALL_2(bpf_init_cpu_topology, struct bpf_map *, map, u64, flags)
{
	const struct cpumask *cpu_map = cpu_active_mask;
	int ret = 0;
	int i = -1;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());
	for_each_cpu(i, cpu_map) {
		struct bpf_cpu_topology topo;

		bpf_update_cpu_topology(&topo, i);
		ret = map->ops->map_update_elem(map, &i, &topo, flags);
		if (ret) {
			int idx = i;

			for (; idx >= 0; idx--)
				map->ops->map_delete_elem(map, &idx);
			break;
		}
	}

	return ret;
}

BTF_ID_LIST_SINGLE(bpf_cpu_topology_ids, struct, bpf_cpu_topology)

const struct bpf_func_proto bpf_init_cpu_topology_proto = {
	.func		= bpf_init_cpu_topology,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_get_cpumask_info, struct bpf_map *, map, struct bpf_cpumask_info *, cpus)
{
	if (!cpus)
		return -EINVAL;

	cpumask_copy(&cpus->cpu_possible_cpumask, cpu_possible_mask);
	cpumask_copy(&cpus->cpu_active_cpumask, cpu_active_mask);
	cpumask_copy(&cpus->cpu_isolate_cpumask, housekeeping_cpumask(HK_FLAG_DOMAIN));
	cpus->nums_possible_cpus = num_possible_cpus();
	cpus->nums_active_cpus = num_active_cpus();
	cpus->nums_isolate_cpus = cpumask_weight(&cpus->cpu_isolate_cpumask);
	cpus->nr_cpu_ids = nr_cpu_ids;
	cpus->bpf_nr_cpumask_bits = nr_cpumask_bits;

	return 0;
}

const struct bpf_func_proto bpf_get_cpumask_info_proto = {
	.func		= bpf_get_cpumask_info,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
};
