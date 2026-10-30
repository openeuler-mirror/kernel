/* SPDX-License-Identifier: GPL-2.0-only */
/* Internal definitions of the dynamic threaded NAPI scheduler */

#ifndef _NET_DYNTHREAD_H
#define _NET_DYNTHREAD_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/netdevice.h>

#define ONE_HUNDRED			100
#define SCHED_MAX_NETDEV_NUM		8
#define MAX_DEV_RXQ_NUM			256
#define DYN_THREAD_INTERVAL		(dyn_threaded_interval * NSEC_PER_MSEC)

/**
 * struct sched_netdev_queue_info - IRQ information of one RX queue
 * @irq: Linux IRQ number of the queue
 * @affinity_cpu: CPU the IRQ was affined to when the module was loaded
 */
struct sched_netdev_queue_info {
	int irq;
	int affinity_cpu;
};

/**
 * struct sched_netdev - net device to monitor
 * @dev_name: interface name
 * @netdev: net device with a reference held by this module
 * @dev_tracker: tracker of the net device reference
 * @parent: parent device, with a reference held by this module
 * @rxq_num: number of RX queue IRQs recorded
 * @node_num: number of NUMA nodes the RX queue IRQs span
 * @rxq: IRQ information of the RX queues
 */
struct sched_netdev {
	char				dev_name[IFNAMSIZ];
	struct net_device		*netdev;
	netdevice_tracker		dev_tracker;
	struct device			*parent;
	int				rxq_num;
	int				node_num;
	struct sched_netdev_queue_info	rxq[MAX_DEV_RXQ_NUM];
};

/**
 * enum task_status - scheduling state of the target tasks
 * @DATA_LOSS: the counters moved backwards, the sample is not usable
 * @NO_TASK: no task with the target name exists
 * @NOT_RUNNING: the tasks hardly get the CPU
 * @FRAGMENTATION: the tasks are scheduled out quickly, softirq mode is fine
 * @LONG_RUNNING_WITH_INTERRUPTS: the tasks run long between context
 *	switches and should not be disturbed by softirq activity
 */
enum task_status {
	DATA_LOSS,
	NO_TASK,
	NOT_RUNNING,
	FRAGMENTATION,
	LONG_RUNNING_WITH_INTERRUPTS,
};

/**
 * struct sched_task_runtime_avg_info - scheduling statistics of the target tasks
 * @total_switches: total context switches since boot
 * @total_runtime_ns: total runtime in ns since boot
 * @total_nvcsw: total voluntary context switches since boot
 * @total_nivcsw: total involuntary context switches since boot
 * @avg_runtime: avg runtime of the sample in ns, per context switch
 * @nvcsw_per: percent of voluntary context switches of the sample
 * @cpuload: total load of the sample in percent, over all allowed CPUs
 * @thread_cnt: number of matching threads
 * @status: task status judged for this sample
 * @last_status: task status of the previous sample
 * @comm: name of the target tasks
 */
struct sched_task_runtime_avg_info {
	u64 total_switches;
	u64 total_runtime_ns;
	u64 total_nvcsw;
	u64 total_nivcsw;
	u64 avg_runtime;
	u64 nvcsw_per;
	u64 cpuload;
	u32 thread_cnt;
	enum task_status status;
	enum task_status last_status;
	char comm[TASK_COMM_LEN];
};

#endif /* _NET_DYNTHREAD_H */
