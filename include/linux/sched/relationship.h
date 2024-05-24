/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_RELATIONSHIP_H
#define _LINUX_SCHED_RELATIONSHIP_H

#include <linux/nodemask.h>
#include <linux/jump_label.h>
#include <linux/refcount.h>

#define FAULT_NODES_MAX 4

struct task_struct;
struct rq;

#ifdef CONFIG_SCHED_DEBUG
struct seq_file;
#endif

struct fault_array_info {
	int nid;
	unsigned long val;
};

struct relationship_hdr {
	refcount_t refcount;
	spinlock_t lock;
	int nr_tasks;
	int gid;
	nodemask_t preferred_nid;
};

enum net_req_type {
	NET_RS_TYPE_INVALID = 0,
	NET_RS_TYPE_LOCAL,
	NET_RS_TYPE_RX,
	NET_RS_TYPE_TX,
	NET_RS_TYPE_MAX
};

struct net_relationship_req {
	enum net_req_type net_rship_type;
	pid_t rx_pid;
	pid_t tx_pid;
	int nic_nid;
	int rx_dev_idx;
	int rx_dev_queue_idx;
	u64 rx_dev_netns_cookie;
	unsigned long rxtx_bytes;

	/* reserved */
	unsigned long rxtx_cnt;
};

struct net_relationship_callback {
	struct callback_head twork;
	atomic_t active;
	pid_t src_pid;
	struct net_relationship_req req;
};

struct net_group {
	struct rcu_head rcu;
	struct relationship_hdr hdr;
	unsigned long rxtx_bytes;

	/* reserved */
	unsigned long rxtx_cnt;
};

struct numa_fault_ext {
	struct fault_array_info faults_ordered[FAULT_NODES_MAX];
};

struct task_relationship {
	/* network relationship */
	struct net_group __rcu *net_group;
	spinlock_t net_lock;
	int nic_nid;
	int rx_dev_idx;
	int rx_dev_queue_idx;
	unsigned long rx_dev_netns_cookie;
	unsigned long rxtx_remote_bytes;
	unsigned long rxtx_remote_update_next;
	unsigned long rxtx_remote_buffer;
	unsigned long rxtx_bytes;
	unsigned long rxtx_buffer;
	unsigned long rxtx_update_next;
	struct net_relationship_callback cb;

	/* extras numa fault data */
	struct numa_fault_ext faults;
};

extern void task_relationship_enable(void);
extern void task_relationship_disable(void);

#ifdef CONFIG_SCHED_DEBUG
extern void sched_show_relationship(struct task_struct *p, struct seq_file *m);
#endif

#ifdef CONFIG_SCHED_TASK_RELATIONSHIP
extern int sched_relationship_fork(struct task_struct *p);
extern void sched_relationship_free(struct task_struct *p);
void task_relationship_free(struct task_struct *tsk, bool reset);
extern bool task_relationship_supported(struct task_struct *tsk);
extern int sched_net_relationship_submit(struct net_relationship_req *req);
extern void numa_faults_update_and_sort(int nid, int new,
					  struct fault_array_info *stats);

DECLARE_STATIC_KEY_FALSE(__relationship_switch);
static inline bool task_relationship_used(void)
{
	return static_branch_unlikely(&__relationship_switch);
}
#else
static inline bool task_relationship_used(void)
{
	return false;
}

static inline int sched_relationship_fork(struct task_struct *p)
{
	return 0;
}

static inline void sched_relationship_free(struct task_struct *p) {}

static inline void
task_relationship_free(struct task_struct *tsk, bool reset) {}

static inline int
sched_net_relationship_submit(struct net_relationship_req *req)
{
	return 0;
}
#endif

#endif
