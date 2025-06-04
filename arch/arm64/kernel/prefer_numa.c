// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * choose a prefer numa node
 *
 * Copyright (C) 2025 Huawei Limited.
 */
#include <linux/perf_event.h>
#include <asm/prefer_numa.h>

static atomic_t paral_nid_last = ATOMIC_INIT(-1);

int probe_pmu_numa_event(void)
{
	struct perf_event *event;
	struct perf_event_attr attr = {};
	int type = perf_pmu_type_of_name(PROBE_NUMA_PMU_NAME);

	if (type == -1)
		return -EINVAL;

	attr.type = type;
	attr.config = PROBE_NUMA_PMU_EVENT;
	attr.size = sizeof(struct perf_event_attr);
	attr.pinned = 1;
	attr.disabled = 1;
	attr.sample_period = 0;

	event = perf_event_create_kernel_counter(&attr, smp_processor_id(),
							NULL, NULL, NULL);
	if (IS_ERR(event))
		return PTR_ERR(event);

	perf_event_release_kernel(event);

	return 0;
}

static inline unsigned int update_sched_paral_nid(void)
{
	return (unsigned int)atomic_inc_return(&paral_nid_last);
}

void set_task_paral_node(struct task_struct *p)
{
	int nid;
	int i = 0;
	const cpumask_t *cpus_mask;

	if (is_global_init(current))
		return;

	if (p->flags & PF_KTHREAD || p->tgid != p->pid)
		return;

	while (i < nr_node_ids) {
		nid = update_sched_paral_nid() % nr_node_ids;
		cpus_mask = cpumask_of_node(nid);

		if (cpumask_empty(cpus_mask) ||
			!cpumask_subset(cpus_mask, p->cpus_ptr)) {
			i++;
			continue;
		}

		cpumask_copy(p->prefer_cpus, cpus_mask);
		break;
	}
}
