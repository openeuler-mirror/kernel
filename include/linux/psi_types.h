#ifndef _LINUX_PSI_TYPES_H
#define _LINUX_PSI_TYPES_H

#include <linux/kthread.h>
#include <linux/seqlock.h>
#include <linux/types.h>
#include <linux/kref.h>
#include <linux/wait.h>

#ifdef CONFIG_PSI

/* Tracked task states */
#ifdef __GENKSYMS__
/*
 * This definition is used to keep kabi unchanged,
 * and **should not changed**
 */
enum psi_task_count {
	NR_IOWAIT,
	NR_MEMSTALL,
	NR_RUNNING,
	/*
	 * This can't have values other than 0 or 1 and could be
	 * implemented as a bit flag. But for now we still have room
	 * in the first cacheline of psi_group_cpu, and this way we
	 * don't have to special case any state tracking for it.
	 */
	NR_ONCPU,
	NR_PSI_TASK_COUNTS = 4,
};
#else
/*
 * All modification to psi_task_count should apply to here.
 */
enum psi_task_count {
	NR_IOWAIT,
	NR_MEMSTALL,
	NR_RUNNING,
	/*
	 * For IO and CPU stalls the presence of running/oncpu tasks
	 * in the domain means a partial rather than a full stall.
	 * For memory it's not so simple because of page reclaimers:
	 * they are running/oncpu while representing a stall. To tell
	 * whether a domain has productivity left or not, we need to
	 * distinguish between regular running (i.e. productive)
	 * threads and memstall ones.
	 */
	NR_MEMSTALL_RUNNING,
	NR_PSI_TASK_COUNTS = 4,
};
#endif

/* Task state bitmasks */
#define TSK_IOWAIT	(1 << NR_IOWAIT)
#define TSK_MEMSTALL	(1 << NR_MEMSTALL)
#define TSK_RUNNING	(1 << NR_RUNNING)
#define TSK_MEMSTALL_RUNNING	(1 << NR_MEMSTALL_RUNNING)
/* Only one task can be scheduled, no corresponding task count */
#define TSK_ONCPU	(1 << NR_PSI_TASK_COUNTS)

/* Resources that workloads could be stalled on */
enum psi_res {
	PSI_IO,
	PSI_MEM,
	PSI_CPU,
#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	PSI_IRQ,
#endif
	NR_PSI_RESOURCES,
};

/*
 * Pressure states for each resource:
 *
 * SOME: Stalled tasks & working tasks
 * FULL: Stalled tasks & no working tasks
 */
#ifdef __GENKSYMS__
/*
 * This definition is used to keep kabi unchanged,
 * and **should not changed**
 */
enum psi_states {
	PSI_IO_SOME,
	PSI_IO_FULL,
	PSI_MEM_SOME,
	PSI_MEM_FULL,
	PSI_CPU_SOME,
	/* Only per-CPU, to weigh the CPU in the global average: */
	PSI_NONIDLE,
	NR_PSI_STATES = 6,
};
#else
/*
 * All modification to psi_states should apply to here.
 */
enum psi_states {
	PSI_IO_SOME,
	PSI_IO_FULL,
	PSI_MEM_SOME,
	PSI_MEM_FULL,
	PSI_CPU_SOME,
	PSI_CPU_FULL,
#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	PSI_IRQ_FULL,
#endif
	/* Only per-CPU, to weigh the CPU in the global average: */
	PSI_NONIDLE,
	NR_PSI_STATES,
};
#endif

/* Use one bit in the state mask to track TSK_ONCPU */
#define PSI_ONCPU	(1 << NR_PSI_STATES)

enum psi_aggregators {
	PSI_AVGS = 0,
	PSI_POLL,
	NR_PSI_AGGREGATORS,
};

struct psi_group_cpu {
	/* 1st cacheline updated by the scheduler */

	/* Aggregator needs to know of concurrent changes */
	seqcount_t seq ____cacheline_aligned_in_smp;

	/* States of the tasks belonging to this group */
	unsigned int tasks[NR_PSI_TASK_COUNTS];

	/* Aggregate pressure state derived from the tasks */
	u32 state_mask;

	/* Period time sampling buckets for each state of interest (ns) */
	u32 times[NR_PSI_STATES];

	/* Time of last task change in this group (rq_clock) */
	u64 state_start;

	/* 2nd cacheline updated by the aggregator */

	/* Delta detection against the sampling buckets */
	u32 times_prev[NR_PSI_AGGREGATORS][NR_PSI_STATES]
			____cacheline_aligned_in_smp;
};

/* PSI growth tracking window */
struct psi_window {
	/* Window size in ns */
	u64 size;

	/* Start time of the current window in ns */
	u64 start_time;

	/* Value at the start of the window */
	u64 start_value;

	/* Value growth in the previous window */
	u64 prev_growth;
};

struct psi_trigger {
	/* PSI state being monitored by the trigger */
	enum psi_states state;

	/* User-spacified threshold in ns */
	u64 threshold;

	/* List node inside triggers list */
	struct list_head node;

	/* Backpointer needed during trigger destruction */
	struct psi_group *group;

	/* Wait queue for polling */
	wait_queue_head_t event_wait;

	/* Kernfs file for cgroup triggers */
	struct kernfs_open_file *of;

	/* Pending event flag */
	int event;

	/* Tracking window */
	struct psi_window win;

	/*
	 * Time last event was generated. Used for rate-limiting
	 * events to one per window
	 */
	u64 last_event_time;
};

struct psi_group {
	/* Protects data used by the aggregator */
	struct mutex avgs_lock;

	/* Per-cpu task state & time tracking */
	struct psi_group_cpu __percpu *pcpu;

	/* Running pressure averages */
	u64 avg_total[NR_PSI_STATES - 1];
	u64 avg_last_update;
	u64 avg_next_update;

	/* Aggregator work control */
	struct delayed_work avgs_work;

	/* Total stall times and sampled pressure averages */
	u64 total[NR_PSI_AGGREGATORS][NR_PSI_STATES - 1];
	unsigned long avg[NR_PSI_STATES - 1][3];

	/* Monitor work control */
	struct task_struct __rcu *poll_task;
	struct timer_list poll_timer;
	wait_queue_head_t poll_wait;
	atomic_t poll_wakeup;

	/* Protects data used by the monitor */
	struct mutex trigger_lock;

	/* Configured polling triggers */
	struct list_head triggers;
	u32 nr_triggers[NR_PSI_STATES - 1];
	u32 poll_states;
	u64 poll_min_period;

	/* Total stall times at the start of monitor activation */
	u64 polling_total[NR_PSI_STATES - 1];
	u64 polling_next_update;
	u64 polling_until;
};

#ifdef CONFIG_PSI_FINE_GRAINED

enum psi_stat_states {
	PSI_MEMCG_RECLAIM_SOME,
	PSI_MEMCG_RECLAIM_FULL,
	PSI_GLOBAL_RECLAIM_SOME,
	PSI_GLOBAL_RECLAIM_FULL,
	PSI_COMPACT_SOME,
	PSI_COMPACT_FULL,
	PSI_ASYNC_MEMCG_RECLAIM_SOME,
	PSI_ASYNC_MEMCG_RECLAIM_FULL,
	PSI_SWAP_SOME,
	PSI_SWAP_FULL,
	PSI_CPU_CFS_BANDWIDTH_FULL,
#ifdef CONFIG_QOS_SCHED
	PSI_CPU_QOS_FULL,
#endif
	NR_PSI_STAT_STATES,
};

enum psi_stat_task_count {
	NR_MEMCG_RECLAIM,
	NR_MEMCG_RECLAIM_RUNNING,
	NR_GLOBAL_RECLAIM,
	NR_GLOBAL_RECLAIM_RUNNING,
	NR_COMPACT,
	NR_COMPACT_RUNNING,
	NR_ASYNC_MEMCG_RECLAIM,
	NR_ASYNC_MEMCG_RECLAIM_RUNNING,
	NR_SWAP,
	NR_SWAP_RUNNING,
	NR_PSI_STAT_TASK_COUNTS,
};

#define CPU_CFS_BANDWIDTH		1

struct psi_group_stat_cpu {
	u32 state_mask;
	u32 times[NR_PSI_STAT_STATES];
	u32 psi_delta;
	unsigned int tasks[NR_PSI_STAT_TASK_COUNTS];
	u32 times_delta;
	u32 times_prev[NR_PSI_AGGREGATORS][NR_PSI_STAT_STATES];
	int prev_throttle;
	int cur_throttle;
};

struct psi_group_ext {
	struct psi_group psi;
	struct psi_group_stat_cpu __percpu *pcpu;
	/* Running fine grained pressure averages */
	u64 avg_total[NR_PSI_STAT_STATES];
	/* Total fine grained stall times and sampled pressure averages */
	u64 total[NR_PSI_AGGREGATORS][NR_PSI_STAT_STATES];
	unsigned long avg[NR_PSI_STAT_STATES][3];
};
#else
struct psi_group_ext { };
#endif /* CONFIG_PSI_FINE_GRAINED */

#else /* CONFIG_PSI */

struct psi_group { };

#endif /* CONFIG_PSI */

/*
 * one type should have two task stats: regular running and memstall
 * threads. The reason is the same as NR_MEMSTALL_RUNNING.
 * Because of the psi_memstall_type is start with 1, the correspondence
 * between psi_memstall_type and psi_stat_task_count should be as below:
 *
 * memstall : psi_memstall_type * 2 - 2;
 * running  : psi_memstall_type * 2 - 1;
 */
enum psi_memstall_type {
	PSI_MEMCG_RECLAIM = 1,
	PSI_GLOBAL_RECLAIM,
	PSI_COMPACT,
	PSI_ASYNC_MEMCG_RECLAIM,
	PSI_SWAP,
};

#endif /* _LINUX_PSI_TYPES_H */
