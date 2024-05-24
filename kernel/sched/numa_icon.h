/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_NUMA_ICON_H
#include <linux/sched.h>

struct node_load_info {
	raw_spinlock_t		lock ____cacheline_aligned;
	atomic_long_t		util_avg;
	unsigned long		compute_capacity;
	struct sched_avg	*util_avg_last;
};

#ifdef CONFIG_QOS_SCHED_NUMA_ICON
extern struct static_key_false sched_numa_icon_switch;
static __always_inline bool sched_numa_icon_enabled(void)
{
	return static_branch_unlikely(&sched_numa_icon_switch);
}

extern void print_node_load_info(struct seq_file *m, int node);
extern __init void init_sched_numa_icon(void);
extern void sched_get_node_load(int nid, struct bpf_node_stats *ctx);
extern void init_node_load(struct rq *rq);
extern void numa_load_change(struct cfs_rq *cfs_rq);
extern void update_numa_capacity(struct rq *rq);

#else /* !CONFIG_QOS_SCHED_NUMA_ICON */
static inline void init_sched_numa_icon(void) {}

static inline void init_node_load(struct rq *rq) {}

static inline void numa_load_change(struct cfs_rq *cfs_rq) {}

static inline void update_numa_capacity(struct rq *rq) {}

static inline void print_node_load_info(struct seq_file *m, int node) {}

static __always_inline bool sched_numa_icon_enabled(void)
{
	return false;
}
#endif /* CONFIG_QOS_SCHED_NUMA_ICON */

#endif
