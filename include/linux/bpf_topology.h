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
 */

#ifndef _LINUX_BPF_TOPOLOGY_H
#define _LINUX_BPF_TOPOLOGY_H

#include <linux/cpumask.h>

struct bpf_cpu_topology {
		int cpu;
		int core_id;
		int cluster_id;
		int die_id;
		int physical_package_id;
		int numa_node;
		struct cpumask thread_siblings;
		struct cpumask core_siblings;
		struct cpumask cluster_cpus;
		struct cpumask die_cpus;
		struct cpumask package_cpus;
		struct cpumask node_cpu_lists;
};

struct bpf_cpumask_info {
	unsigned int nums_possible_cpus;
	unsigned int nums_active_cpus;
	unsigned int nums_isolate_cpus;
	unsigned int nr_cpu_ids;
	unsigned int bpf_nr_cpumask_bits;
	struct cpumask cpu_possible_cpumask;
	struct cpumask cpu_active_cpumask;
	struct cpumask cpu_isolate_cpumask;
};

#endif /* _LINUX_BPF_TOPOLOGY_H */
