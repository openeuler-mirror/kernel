/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SYSCTL_H
#define _LINUX_SCHED_SYSCTL_H

#include <linux/types.h>

struct ctl_table;

#ifdef CONFIG_DETECT_HUNG_TASK

#ifdef CONFIG_SMP
extern unsigned int sysctl_hung_task_all_cpu_backtrace;
#else
#define sysctl_hung_task_all_cpu_backtrace 0
#endif /* CONFIG_SMP */

extern int	     sysctl_hung_task_check_count;
extern unsigned int  sysctl_hung_task_panic;
extern unsigned long sysctl_hung_task_timeout_secs;
extern unsigned long sysctl_hung_task_check_interval_secs;
extern int sysctl_hung_task_warnings;
int proc_dohung_task_timeout_secs(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
#else
/* Avoid need for ifdefs elsewhere in the code */
enum { sysctl_hung_task_timeout_secs = 0 };
#endif

extern unsigned int sysctl_sched_latency;
extern unsigned int sysctl_sched_min_granularity;
extern unsigned int sysctl_sched_wakeup_granularity;
extern unsigned int sysctl_sched_child_runs_first;

#ifdef CONFIG_QOS_SCHED_DYNAMIC_AFFINITY
extern int sysctl_sched_util_low_pct;
#endif

#ifdef CONFIG_SCHED_KEEP_ON_CORE
extern int sysctl_sched_util_ratio;
#endif

#ifdef CONFIG_SCHED_STEAL
extern int sysctl_sched_max_steal_count;
#endif

#ifdef CONFIG_QOS_SCHED_SMART_GRID
extern unsigned int sysctl_smart_grid_strategy_ctrl;
extern int sysctl_affinity_adjust_delay_ms;
#endif

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE,
	SCHED_TUNABLESCALING_LOG,
	SCHED_TUNABLESCALING_LINEAR,
	SCHED_TUNABLESCALING_END,
};
extern enum sched_tunable_scaling sysctl_sched_tunable_scaling;

extern unsigned int sysctl_numa_balancing_scan_delay;
extern unsigned int sysctl_numa_balancing_scan_period_min;
extern unsigned int sysctl_numa_balancing_scan_period_max;
extern unsigned int sysctl_numa_balancing_scan_size;

#ifdef CONFIG_SCHED_DEBUG
extern __read_mostly unsigned int sysctl_sched_migration_cost;
extern __read_mostly unsigned int sysctl_sched_nr_migrate;

int sched_proc_update_handler(struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos);
#endif

/*
 *  control realtime throttling:
 *
 *  /proc/sys/kernel/sched_rt_period_us
 *  /proc/sys/kernel/sched_rt_runtime_us
 */
extern unsigned int sysctl_sched_rt_period;
extern int sysctl_sched_rt_runtime;

extern unsigned int sysctl_sched_dl_period_max;
extern unsigned int sysctl_sched_dl_period_min;

#ifdef CONFIG_UCLAMP_TASK
extern unsigned int sysctl_sched_uclamp_util_min;
extern unsigned int sysctl_sched_uclamp_util_max;
extern unsigned int sysctl_sched_uclamp_util_min_rt_default;
#endif

#ifdef CONFIG_CFS_BANDWIDTH
extern unsigned int sysctl_sched_cfs_bandwidth_slice;
#endif

#ifdef CONFIG_QOS_SCHED
extern unsigned int sysctl_overload_detect_period;
extern unsigned int sysctl_offline_wait_interval;
#endif

#ifdef CONFIG_QOS_SCHED_MULTILEVEL
extern unsigned int sysctl_qos_level_weights[];
#endif

#ifdef CONFIG_QOS_SCHED_PRIO_LB
extern unsigned int sysctl_sched_prio_load_balance_enabled;
#endif

#ifdef CONFIG_SCHED_AUTOGROUP
extern unsigned int sysctl_sched_autogroup_enabled;
#endif

extern int sysctl_sched_rr_timeslice;
extern int sched_rr_timeslice;

int sched_rr_handler(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
int sched_rt_handler(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
int sysctl_sched_uclamp_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
int sysctl_numa_balancing(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);
int sysctl_schedstats(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);

#if defined(CONFIG_ENERGY_MODEL) && defined(CONFIG_CPU_FREQ_GOV_SCHEDUTIL)
extern unsigned int sysctl_sched_energy_aware;
int sched_energy_aware_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
#endif

#ifdef CONFIG_SCHED_CLUSTER
extern unsigned int sysctl_sched_cluster;
int sched_cluster_handler(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos);
#endif

#endif /* _LINUX_SCHED_SYSCTL_H */
