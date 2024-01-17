/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_GRID_QOS_H
#define _LINUX_SCHED_GRID_QOS_H
#include <linux/nodemask.h>
#include <linux/sched.h>

#ifdef CONFIG_QOS_SCHED_SMART_GRID
enum sched_grid_qos_class {
	SCHED_GRID_QOS_CLASS_LEVEL_1 = 0,
	SCHED_GRID_QOS_CLASS_LEVEL_2 = 1,
	SCHED_GRID_QOS_CLASS_LEVEL_3 = 2,
	SCHED_GRID_QOS_CLASS_LEVEL_4 = 3,
	SCHED_GRID_QOS_CLASS_LEVEL_5 = 4,
	SCHED_GRID_QOS_CLASS_LEVEL_6 = 5,
	SCHED_GRID_QOS_CLASS_LEVEL_7 = 6,
	SCHED_GRID_QOS_CLASS_LEVEL_8 = 7,
	SCHED_GRID_QOS_CLASS_LEVEL_NR
};

/*
 * SCHED_GRID_QOS_TASK_LEVEL was defined different QoS level.
 * The lower number has the higher priority. (E.g. 0 was the highest)
 * The enum sched_grid_qos_class defined the max level, the lowest level.
 */
#define SCHED_GRID_QOS_TASK_LEVEL_HIGHEST SCHED_GRID_QOS_CLASS_LEVEL_1
#define SCHED_GRID_QOS_TASK_LEVEL_MAX	(SCHED_GRID_QOS_CLASS_LEVEL_NR)
#define SCHED_GRID_QOS_TASK_LEVEL_DEFAULT (SCHED_GRID_QOS_CLASS_LEVEL_NR - 1)

enum {
	SCHED_GRID_QOS_IPS_INDEX = 0,
	SCHED_GRID_QOS_MEMBOUND_RATIO_INDEX = 1,
	SCHED_GRID_QOS_MEMBANDWIDTH_INDEX = 2,
	SCHED_GRID_QOS_SAMPLE_NR
};

#define SCHED_GRID_QOS_RING_BUFFER_MAXLEN 100

struct sched_grid_qos_ring_buffer {
	u64 vecs[SCHED_GRID_QOS_RING_BUFFER_MAXLEN];
	unsigned int head;
	void (*push)(u64 *data, int stepsize,
		struct sched_grid_qos_ring_buffer *ring_buffer);
};

struct sched_grid_qos_sample {
	const char *name;
	int index;
	int sample_bypass;
	int sample_times;
	struct sched_grid_qos_ring_buffer ring_buffer;
	u64 pred_target[MAX_NUMNODES];
	void (*cal_target)(int stepsize,
		struct sched_grid_qos_ring_buffer *ring_buffer);

	int account_ready;
	int (*start)(void *arg);
	int (*account)(void *arg);
};

struct sched_grid_qos_stat {
	enum sched_grid_qos_class class_lvl;
	int (*set_class_lvl)(struct sched_grid_qos_stat *qos_stat, int level);
	struct sched_grid_qos_sample sample[SCHED_GRID_QOS_SAMPLE_NR];
};

struct sched_grid_qos_power {
	int cpufreq_sense_ratio;
	int target_cpufreq;
	int cstate_sense_ratio;
};

struct sched_grid_qos_affinity {
	nodemask_t mem_preferred_node_mask;
	const struct cpumask *prefer_cpus;
};

struct task_struct;
struct sched_grid_qos {
	struct sched_grid_qos_stat stat;
	struct sched_grid_qos_power power;
	struct sched_grid_qos_affinity affinity;

	int (*affinity_set)(struct task_struct *p);
};

static inline int sched_qos_affinity_set(struct task_struct *p)
{
	return p->grid_qos->affinity_set(p);
}

int sched_grid_qos_fork(struct task_struct *p, struct task_struct *orig);
void sched_grid_qos_free(struct task_struct *p);

int sched_grid_preferred_interleave_nid(struct mempolicy *policy);
int sched_grid_preferred_nid(int preferred_nid, nodemask_t *nodemask);

enum sg_zone_type {
	SMART_GRID_ZONE_HOT = 0,
	SMART_GRID_ZONE_WARM,
	SMART_GRID_ZONE_NR
};

struct auto_affinity;
struct sched_grid_zone {
	raw_spinlock_t lock;
	struct cpumask cpus[SMART_GRID_ZONE_NR];
	struct list_head af_list_head;	/* struct auto_affinity list head */
};

int __init sched_grid_zone_init(void);
int sched_grid_zone_update(bool is_locked);
int sched_grid_zone_add_af(struct auto_affinity *af);
int sched_grid_zone_del_af(struct auto_affinity *af);
struct cpumask *sched_grid_zone_cpumask(enum sg_zone_type zone);
struct cpumask *sched_grid_prefer_cpus(struct task_struct *p);
#else
static inline int __init sched_grid_zone_init(void) { return 0; }

static inline int
sched_grid_preferred_interleave_nid(struct mempolicy *policy)
{
	return NUMA_NO_NODE;
}
static inline int
sched_grid_preferred_nid(int preferred_nid, nodemask_t *nodemask)
{
	return preferred_nid;
}

static inline int sched_qos_affinity_set(struct task_struct *p)
{
	return 0;
}
#endif
#endif
