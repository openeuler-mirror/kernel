/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PSI_TYPES_H
#define _LINUX_PSI_TYPES_H

#include <linux/kthread.h>
#include <linux/seqlock.h>
#include <linux/types.h>
#include <linux/kref.h>
#include <linux/wait.h>
#include <linux/kabi.h>

#ifdef CONFIG_PSI

/* Tracked task states */
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

/* Use one bit in the state mask to track TSK_ONCPU */
#define PSI_ONCPU	(1 << NR_PSI_STATES)

/* Flag whether to re-arm avgs_work, see details in get_recent_times() */
#define PSI_STATE_RESCHEDULE	(1 << (NR_PSI_STATES + 1))

enum psi_aggregators {
	PSI_AVGS = 0,
	PSI_POLL,
	NR_PSI_AGGREGATORS,
};

#ifdef CONFIG_PSI_FINE_GRAINED
#define CPU_CFS_BANDWIDTH		1

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
	/* reserve for KABI start */
	PSI_STATE_LAST,
	PSI_STATE_RESERVE1,
	PSI_STATE_RESERVE2,
	PSI_STATE_RESERVE3,
	PSI_STATE_RESERVE4,
	PSI_STATE_RESERVE5,
	/* reserve for KABI end */

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
	NR_PSI_ST_RESERVE1,
	NR_PSI_ST_RESERVE2,
	NR_PSI_ST_RESERVE3,
	NR_PSI_ST_RESERVE4,
	NR_PSI_ST_RESERVE5,
	NR_PSI_ST_RESERVE6,
	NR_PSI_STAT_TASK_COUNTS,
};
#endif /* CONFIG_PSI_FINE_GRAINED */

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

#ifdef CONFIG_PSI_FINE_GRAINED
	CACHELINE_PADDING(_pad1_);
	u32 fine_grained_state_mask;
	u32 fine_grained_times[NR_PSI_STAT_STATES];
	unsigned int fine_grained_tasks[NR_PSI_STAT_TASK_COUNTS];
	u32 fine_grained_times_delta;
	u32 fine_grained_times_prev[NR_PSI_AGGREGATORS][NR_PSI_STAT_STATES];
	int prev_throttle;
	int cur_throttle;
#endif
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
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
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
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

	/* Deferred event(s) from previous ratelimit window */
	bool pending_event;

	/* Trigger type - PSI_AVGS for unprivileged, PSI_POLL for RT */
	enum psi_aggregators aggregator;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
};

struct psi_group {
	struct psi_group *parent;
	bool enabled;

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

	/* Unprivileged triggers against N*PSI_FREQ windows */
	struct list_head avg_triggers;
	u32 avg_nr_triggers[NR_PSI_STATES - 1];

	/* Total stall times and sampled pressure averages */
	u64 total[NR_PSI_AGGREGATORS][NR_PSI_STATES - 1];
	unsigned long avg[NR_PSI_STATES - 1][3];

	/* Monitor RT polling work control */
	struct task_struct __rcu *rtpoll_task;
	struct timer_list rtpoll_timer;
	wait_queue_head_t rtpoll_wait;
	atomic_t rtpoll_wakeup;
	atomic_t rtpoll_scheduled;

	/* Protects data used by the monitor */
	struct mutex rtpoll_trigger_lock;

	/* Configured RT polling triggers */
	struct list_head rtpoll_triggers;
	u32 rtpoll_nr_triggers[NR_PSI_STATES - 1];
	u32 rtpoll_states;
	u64 rtpoll_min_period;

	/* Total stall times at the start of RT polling monitor activation */
	u64 rtpoll_total[NR_PSI_STATES - 1];
	u64 rtpoll_next_update;
	u64 rtpoll_until;
#ifdef CONFIG_PSI_FINE_GRAINED
	/* Running fine grained pressure averages */
	u64 fine_grained_avg_total[NR_PSI_STAT_STATES];
	/* Total fine grained stall times and sampled pressure averages */
	u64 fine_grained_total[NR_PSI_AGGREGATORS][NR_PSI_STAT_STATES];
	unsigned long fine_grained_avg[NR_PSI_STAT_STATES][3];
#endif
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};
#else /* CONFIG_PSI */

#define NR_PSI_RESOURCES	0

struct psi_group { };

#endif /* CONFIG_PSI */

#ifdef CONFIG_PSI_FINE_GRAINED
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
#else
#define PSI_MEMCG_RECLAIM		0
#define PSI_GLOBAL_RECLAIM		0
#define PSI_COMPACT			0
#define PSI_ASYNC_MEMCG_RECLAIM		0
#define PSI_SWAP			0
#endif /* CONFIG_PSI_FINE_GRAINED */

#endif /* _LINUX_PSI_TYPES_H */
