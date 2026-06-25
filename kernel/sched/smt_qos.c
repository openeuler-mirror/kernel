// SPDX-License-Identifier: GPL-2.0
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/numa.h>
#include <linux/percpu.h>
#include <linux/sched/cputime.h>
#include <linux/sched/smt.h>
#include <linux/sched/topology.h>
#include <linux/sysctl.h>

#include <asm/xint.h>
#include "sched.h"

static DEFINE_PER_CPU_ALIGNED(cpumask_t, smt_prefer_cpus);
static unsigned long numa_smt_util[MAX_NUMNODES];
/*
 * Target SMT sibling CPU utilization watermark.
 * Default range: 0-100.
 */
static unsigned int sched_smt_offline_util_pct = 50;
static cpumask_t slave_smt_cpumask;
cpumask_t master_smt_cpumask;

static struct ctl_table smt_util_pct_sysctl_table[] = {
	{
		.procname	= "sched_smt_offline_util_pct",
		.data		= &sched_smt_offline_util_pct,
		.maxlen		= sizeof(sched_smt_offline_util_pct),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{}
};

static int __init sched_init_smt_qos(void)
{
	int cpu;

	if (!sched_smt_active())
		return 0;

	register_sysctl_init("kernel", smt_util_pct_sysctl_table);

	cpumask_copy(&master_smt_cpumask, cpu_possible_mask);
	for_each_possible_cpu(cpu) {
		if (cpu != cpumask_first(cpu_smt_mask(cpu)))
			cpumask_clear_cpu(cpu, &master_smt_cpumask);
	}

	cpumask_andnot(&slave_smt_cpumask, cpu_possible_mask, &master_smt_cpumask);
	pr_info("Master SMT mask: %*pbl\n", cpumask_pr_args(&master_smt_cpumask));
	pr_info("Slave SMT mask: %*pbl\n", cpumask_pr_args(&slave_smt_cpumask));

	return 0;
}
late_initcall(sched_init_smt_qos);

void set_qos_task_select_cpus(struct task_struct *p, int *idlest_cpu, int prev_cpu,
			      const cpumask_t **backup_select_cpus)
{
	cpumask_t *prefer_cpus = this_cpu_ptr(&smt_prefer_cpus);
	cpumask_t *prefer_cpumask = &master_smt_cpumask;

	if (!smt_qos_enabled())
		return;

	if (task_group(p)->qos_level < QOS_LEVEL_ONLINE) {
		unsigned long smt_util = numa_smt_util[cpu_to_node(prev_cpu)];

		if (smt_util < sched_smt_offline_util_pct)
			prefer_cpumask = &slave_smt_cpumask;
	}

	if (unlikely(prefer_cpus_valid(p)))
		cpumask_and(prefer_cpus, task_prefer_cpus(p), prefer_cpumask);
	else
		cpumask_and(prefer_cpus, p->cpus_ptr, prefer_cpumask);

	if (!cpumask_empty(prefer_cpus)) {
		*backup_select_cpus = p->select_cpus;
		p->select_cpus = prefer_cpus;
	}

	if (*idlest_cpu == -1 || !cpumask_test_cpu(*idlest_cpu, p->select_cpus))
		*idlest_cpu = cpumask_first(p->select_cpus);
}

void restore_qos_task_select_cpus(struct task_struct *p, const cpumask_t *backup_select_cpus)
{
	if (!backup_select_cpus)
		return;

	p->select_cpus = backup_select_cpus;
}

bool should_restrict(void)
{
	int this_cpu = smp_processor_id();
	int cpu;

	if (idle_cpu(this_cpu))
		return false;

	for_each_cpu(cpu, cpu_smt_mask(this_cpu)) {
		if (cpu == this_cpu)
			continue;

		/* SMT master CPU is idle, need not throttle */
		if (idle_cpu(cpu))
			return false;

		/* SMT master CPU has finished online task */
		if (per_cpu(qos_smt_status, cpu) < QOS_LEVEL_ONLINE)
			return false;
	}

	return true;
}

static inline void send_ipi_throttle_smt(int this_cpu)
{
	int cpu;

	if (!system_uses_xint() || !sysctl_sched_wfi_timeout)
		return;

	for_each_cpu(cpu, cpu_smt_mask(this_cpu)) {
		if (cpu == this_cpu)
			continue;

		arch_smp_send_ipi_user(cpu);
	}
}

void smt_qos_update_qos_level(int cpu, struct task_struct *p)
{
	int new_status;

	if (!smt_qos_enabled())
		return;

	new_status = p ? task_group(p)->qos_level : QOS_LEVEL_OFFLINE;

	if (likely(new_status == __this_cpu_read(qos_smt_status)))
		return;

	__this_cpu_write(qos_smt_status, new_status);

	if (cpumask_test_cpu(cpu, &master_smt_cpumask))
		send_ipi_throttle_smt(cpu);
}

static __always_inline bool is_slave_to_master(int src_cpu, int dst_cpu)
{
	return !cpumask_test_cpu(src_cpu, &master_smt_cpumask) &&
		cpumask_test_cpu(dst_cpu, &master_smt_cpumask);
}

bool smt_qos_should_not_busiest(int src_cpu, int dst_cpu)
{
	if (!smt_qos_enabled())
		return false;

	/*
	 * Migration of tasks from SMT siblings to
	 * the primary SMT CPU is restricted.
	 */
	return is_slave_to_master(src_cpu, dst_cpu);
}

bool smt_qos_can_migrate_task(struct task_struct *p, int src_cpu, int dst_cpu)
{
	if (!smt_qos_enabled())
		return 1;

	/*
	 * Only offline tasks are allowed to be migrated from
	 * primary SMT CPUs to SMT siblings.
	 */
	if (cpumask_test_cpu(src_cpu, &master_smt_cpumask) &&
	    !cpumask_test_cpu(dst_cpu, &master_smt_cpumask)) {
		unsigned long smt_util;

		if (task_group(p)->qos_level >= QOS_LEVEL_ONLINE)
			return 0;

		smt_util = numa_smt_util[cpu_to_node(dst_cpu)];
		if (smt_util >= sched_smt_offline_util_pct)
			return 0;
	}

	/*
	 * Migration of tasks from SMT siblings to
	 * the primary SMT CPU is restricted.
	 */
	return !is_slave_to_master(src_cpu, dst_cpu);
}

void update_sd_ld_qos_stats(struct sched_domain *sd, int dst_cpu,
			    unsigned long smt_capacity, unsigned long smt_util)
{
	if (!smt_qos_enabled() || !smt_capacity)
		return;

	if (!(sd->flags & SD_NUMA) && (sd->parent && (sd->parent->flags & SD_NUMA)))
		numa_smt_util[cpu_to_node(dst_cpu)] = (smt_util * 100) / smt_capacity;
}
