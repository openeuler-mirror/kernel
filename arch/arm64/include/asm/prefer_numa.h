/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_PREFER_NUMA_H
#define __ASM_PREFER_NUMA_H

#include <linux/sched.h>

#define PROBE_NUMA_PMU_NAME  "hisi_sccl3_hha0"
#define PROBE_NUMA_PMU_EVENT 0x02

void set_task_paral_node(struct task_struct *p);
int probe_pmu_numa_event(void);

#endif	/* __ASM_PREFER_NUMA_H */
