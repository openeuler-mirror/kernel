/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_XSCHED_H__
#define __LINUX_XSCHED_H__

#include <linux/cgroup.h>
#include <linux/kref.h>
#include <linux/vstream.h>
#include <linux/xcu_group.h>
#include <linux/xsched_types.h>

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define XSCHED_LOG_PREFIX "XSched"
#define XSCHED_INFO(fmt, ...)                                                  \
	pr_info(pr_fmt(XSCHED_LOG_PREFIX " [INFO]: " fmt), ##__VA_ARGS__)

#define XSCHED_ERR(fmt, ...)                                                   \
	pr_err(pr_fmt(XSCHED_LOG_PREFIX " [ERROR]: " fmt), ##__VA_ARGS__)

#define XSCHED_WARN(fmt, ...)                                                  \
	pr_warn(pr_fmt(XSCHED_LOG_PREFIX " [WARNING]: " fmt), ##__VA_ARGS__)

/*
 * Debug specific prints for XSched
 */

#define XSCHED_DEBUG(fmt, ...)                                                 \
	pr_debug(pr_fmt(XSCHED_LOG_PREFIX " [DEBUG]: " fmt), ##__VA_ARGS__)

#define XSCHED_CALL_STUB()                                                     \
	XSCHED_DEBUG(" -----* %s @ %s called *-----\n", __func__, __FILE__)

#define XSCHED_EXIT_STUB()                                                     \
	XSCHED_DEBUG(" -----* %s @ %s exited *-----\n", __func__, __FILE__)

#define MAX_VSTREAM_NUM 512

#define RUNTIME_INF ((u64)~0ULL)
#define XSCHED_TIME_INF RUNTIME_INF
#define XSCHED_CFS_WEIGHT_DFLT 1
#define XSCHED_CFS_QUOTA_PERIOD_MS (100 * NSEC_PER_MSEC)
#define XSCHED_CFG_SHARE_DFLT 1024

/*
 * A default kick slice for RT class XSEs.
 */
#define XSCHED_RT_KICK_SLICE 2
/*
 * A default kick slice for CFS class XSEs.
 */
#define XSCHED_CFS_KICK_SLICE 10

extern struct xsched_cu *xsched_cu_mgr[XSCHED_NR_CUS];

extern struct xsched_class rt_xsched_class;
extern struct xsched_class fair_xsched_class;

#define xsched_first_class \
	list_first_entry(&(xsched_class_list), struct xsched_class, node)

#define for_each_xsched_class(class)                                           \
	list_for_each_entry((class), &(xsched_class_list), node)

#define for_each_xse_prio(prio)                                                \
	for (prio = XSE_PRIO_HIGH; prio < NR_XSE_PRIO; prio++)
#define for_each_vstream_in_ctx(vs, ctx)                                       \
	list_for_each_entry((vs), &((ctx)->vstream_list), ctx_node)


/* Manages xsched RT-like class linked list based runqueue.
 *
 * Now RT-like class runqueue structs is identical
 * but will most likely grow different in the
 * future as the Xsched evolves.
 */
struct xsched_rq_rt {
	struct list_head rq[NR_XSE_PRIO];
	unsigned int nr_running;
};

/* Manages xsched CFS-like class rbtree based runqueue. */
struct xsched_rq_cfs {
	unsigned int nr_running;
	unsigned int load;
	u64 min_xruntime;
	struct rb_root_cached ctx_timeline;
};

/* Base XSched runqueue object structure that contains both mutual and
 * individual parameters for different scheduling classes.
 */
struct xsched_rq {
	struct xsched_entity *curr_xse;
	const struct xsched_class *class;

	int state;
	int nr_running;
	/* RT class run queue.*/
	struct xsched_rq_rt rt;
	/* CFS class run queue.*/
	struct xsched_rq_cfs cfs;
};

enum xsched_cu_status {
	/* Worker not initialized. */
	XSCHED_XCU_NONE,

	/* Worker is sleeping in idle state. */
	XSCHED_XCU_WAIT_IDLE,

	/* Worker is sleeping in running state. */
	XSCHED_XCU_WAIT_RUNNING,

	/* Worker is active but not processing anything. */
	XSCHED_XCU_ACTIVE,

	NR_XSCHED_XCU_STATUS,
};

/* This is the abstraction object of the xcu computing unit. */
struct xsched_cu {
	uint32_t id;
	uint32_t state;

	atomic_t pending_kicks;
	struct task_struct *worker;

	/* Storage list for contexts associated with this xcu */
	uint32_t nr_ctx;
	struct list_head ctx_list;
	struct mutex ctx_list_lock;

	vstream_info_t *vs_array[MAX_VSTREAM_NUM];
	struct mutex vs_array_lock;

	struct xsched_rq xrq;
	struct list_head vsm_list;

	struct xcu_group *group;
	struct mutex xcu_lock;
	wait_queue_head_t wq_xcu_idle;
};

extern int num_active_xcu;
#define for_each_active_xcu(xcu, id)                                           \
	for ((id) = 0, xcu = xsched_cu_mgr[(id)];                                  \
	     (id) < num_active_xcu && (xcu = xsched_cu_mgr[(id)]); (id)++)

struct xsched_entity_rt {
	struct list_head list_node;
	enum xse_prio prio;

	ktime_t timeslice;
};

struct xsched_entity_cfs {
	struct rb_node run_node;

	/* Rq on which this entity is (to be) queued. */
	struct xsched_rq_cfs *cfs_rq;

	/* Value of "virtual" runtime to sort entities in rbtree */
	u64 xruntime;
	u32 weight;

	/* Execution time of scheduling entity */
	u64 exec_start;
	u64 sum_exec_runtime;
};

struct xsched_entity {
	uint32_t task_type;

	bool on_rq;

	pid_t owner_pid;
	pid_t tgid;

	/* Amount of pending kicks currently sitting on this context. */
	atomic_t kicks_pending_cnt;

	/* Amount of submitted kicks context, used for resched decision. */
	atomic_t submitted_one_kick;

	size_t total_scheduled;
	size_t total_submitted;

	/* File descriptor coming from an associated context
	 * used for identifying a given xsched entity in
	 * info and error prints.
	 */
	uint32_t fd;

	/* Xsched class for this xse. */
	const struct xsched_class *class;

	/* RT class entity. */
	struct xsched_entity_rt rt;
	/* CFS class entity. */
	struct xsched_entity_cfs cfs;

	/* Pointer to context object. */
	struct xsched_context *ctx;

	/* Xsched entity execution statistics */
	u64 last_exec_runtime;

	/* Pointer to an XCU object that represents an XCU
	 * on which this xse is to be processed or is being
	 * processed currently.
	 */
	struct xsched_cu *xcu;

#ifdef CONFIG_CGROUP_XCU
	/* Link to list of xsched_group items */
	struct list_head group_node;
	struct xsched_group *parent_grp;
	bool is_group;
#endif /* CONFIG_CGROUP_XCU */

	/* General purpose xse lock. */
	spinlock_t xse_lock;
};

struct xcg_attach_entry {
	struct task_struct *task;
	struct xsched_group *old_xcg;
	struct xsched_group *new_xcg;

	struct list_head node;
};

#ifdef CONFIG_CGROUP_XCU
/* xsched_group's xcu related stuff */
struct xsched_group_xcu_priv {
	/* Owner of this group */
	struct xsched_group *self;

	/* xcu id */
	int xcu_id;

	/* Link to scheduler */
	struct xsched_entity xse; /* xse of this group on runqueue */
	struct xsched_rq_cfs *cfs_rq; /* cfs runqueue "owned" by this group */
	struct xsched_rq_rt *rt_rq; /* rt runqueue "owned" by this group */
	/* Statistics */
	int nr_throttled;
	u64 throttled_time;
};

enum xcu_file_type {
	XCU_FILE_PERIOD_MS,
	XCU_FILE_QUOTA_MS,
	XCU_FILE_SHARES,
	NR_XCU_FILE_TYPES,
};

/* Xsched scheduling control group */
struct xsched_group {
	/* Cgroups controller structure */
	struct cgroup_subsys_state css;

	/* Control group settings: */
	int sched_class;
	int prio;

	/* Bandwidth setting: shares value set by user */
	u64 shares_cfg;
	u64 shares_cfg_red;
	u32 weight;
	u64 children_shares_sum;

	/* Bandwidth setting: maximal quota in period */
	s64 quota;
	/* record the runtime of operators during the period */
	s64 runtime;
	s64 period;
	struct hrtimer quota_timeout;
	struct work_struct refill_work;

	struct xsched_group_xcu_priv perxcu_priv[XSCHED_NR_CUS];

	/* Groups hierarchcy */
	struct xsched_group *parent;
	struct list_head children_groups;
	struct list_head group_node;

	spinlock_t lock;

	/* for XSE to move in perxcu */
	struct list_head members;

	/* to control the xcu.{period, quota, shares} files shown or not */
	struct cgroup_file xcu_file[NR_XCU_FILE_TYPES];
	struct work_struct file_show_work;
};
#endif /* CONFIG_CGROUP_XCU */

#define XSCHED_SE_OF(cfs_xse)                                                  \
	(container_of((cfs_xse), struct xsched_entity, cfs))

#ifdef CONFIG_CGROUP_XCU
#define xcg_parent_grp_xcu(xcg)                                                \
	((xcg)->self->parent->perxcu_priv[(xcg)->xcu_id])

#define xse_parent_grp_xcu(xse_cfs)                                            \
	(&((XSCHED_SE_OF(xse_cfs)                                                  \
			->parent_grp->perxcu_priv[(XSCHED_SE_OF(xse_cfs))->xcu->id])))

static inline struct xsched_group_xcu_priv *
xse_this_grp_xcu(struct xsched_entity_cfs *xse_cfs)
{
	struct xsched_entity *xse;

	xse = xse_cfs ? container_of(xse_cfs, struct xsched_entity, cfs) : NULL;
	return xse ? container_of(xse, struct xsched_group_xcu_priv, xse) : NULL;
}

static inline struct xsched_group *
xse_this_grp(struct xsched_entity_cfs *xse_cfs)
{
	return xse_cfs ? xse_this_grp_xcu(xse_cfs)->self : NULL;
}
#endif /* CONFIG_CGROUP_XCU */

static inline int xse_integrity_check(const struct xsched_entity *xse)
{
	if (!xse) {
		XSCHED_ERR("xse is null @ %s\n", __func__);
		return -EINVAL;
	}

	if (!xse->class) {
		XSCHED_ERR("xse->class is null @ %s\n", __func__);
		return -EINVAL;
	}

	return 0;
}

struct xsched_context {
	uint32_t fd;
	uint32_t dev_id;
	pid_t tgid;

	struct list_head vstream_list;
	struct list_head ctx_node;

	struct xsched_entity xse;

	spinlock_t ctx_lock;
	struct mutex ctx_mutex;
	struct kref kref;
};

extern struct list_head xsched_ctx_list;
extern struct mutex xsched_ctx_list_mutex;

/* Returns a pointer to xsched_context object corresponding to a given
 * tgid and xcu.
 */
static inline struct xsched_context *
ctx_find_by_tgid_and_xcu(pid_t tgid, struct xsched_cu *xcu)
{
	struct xsched_context *ctx;
	struct xsched_context *ret = NULL;

	list_for_each_entry(ctx, &xcu->ctx_list, ctx_node) {
		if (ctx->tgid == tgid) {
			ret = ctx;
			break;
		}
	}
	return ret;
}

static inline u64 gcd(u64 a, u64 b)
{
	u64 rem;

	while (a != 0 && b != 0) {
		if (a > b) {
			div64_u64_rem(a, b, &rem);
			a = rem;
		} else {
			div64_u64_rem(b, a, &rem);
			b = rem;
		}
	}
	return (a) ? a : b;
}

struct xsched_class {
	enum xcu_sched_class class_id;
	size_t kick_slice;
	struct list_head node;

	/* Initialize a new xsched entity */
	void (*xse_init)(struct xsched_entity *xse);

	/* Destroy XSE scheduler-specific data */
	void (*xse_deinit)(struct xsched_entity *xse);

	/* Initialize a new runqueue per xcu */
	void (*rq_init)(struct xsched_cu *xcu);

	/* Removes a given XSE from it's runqueue. */
	void (*dequeue_ctx)(struct xsched_entity *xse);

	/* Places a given XSE on a runqueue on a given XCU. */
	void (*enqueue_ctx)(struct xsched_entity *xse, struct xsched_cu *xcu);

	/* Returns a next XSE to be submitted on a given XCU. */
	struct xsched_entity *(*pick_next_ctx)(struct xsched_cu *xcu);

	/* Put a XSE back into rq during preemption. */
	void (*put_prev_ctx)(struct xsched_entity *xse);

	/* Check context preemption. */
	bool (*check_preempt)(struct xsched_entity *xse);

	/* Select jobs from XSE to submit on XCU */
	size_t (*select_work)(struct xsched_cu *xcu, struct xsched_entity *xse);
};

static inline void xsched_init_vsm(struct vstream_metadata *vsm,
				struct vstream_info *vs, vstream_args_t *arg)
{
	vsm->sq_id = arg->sq_id;
	vsm->exec_time = arg->vk_args.exec_time;
	vsm->sqe_num = arg->vk_args.sqe_num;
	vsm->timeout = arg->vk_args.timeout;
	memcpy(vsm->sqe, arg->vk_args.sqe, XCU_SQE_SIZE_MAX);
	vsm->parent = vs;
	INIT_LIST_HEAD(&vsm->node);
}

int xsched_xcu_init(struct xsched_cu *xcu, struct xcu_group *group, int xcu_id);
int xsched_schedule(void *input_xcu);
int xsched_init_entity(struct xsched_context *ctx, struct vstream_info *vs);
int ctx_bind_to_xcu(vstream_info_t *vstream_info, struct xsched_context *ctx);
int xsched_vsm_add_tail(struct vstream_info *vs, vstream_args_t *arg);
struct vstream_metadata *xsched_vsm_fetch_first(struct vstream_info *vs);
void xsched_rt_prio_set(pid_t tgid, unsigned int prio);
void enqueue_ctx(struct xsched_entity *xse, struct xsched_cu *xcu);
void dequeue_ctx(struct xsched_entity *xse, struct xsched_cu *xcu);
int delete_ctx(struct xsched_context *ctx);

#ifdef CONFIG_CGROUP_XCU
/* Xsched group manage functions */
void xsched_group_inherit(struct task_struct *tsk, struct xsched_entity *xse);
void xcu_cg_subsys_init(void);
void xcu_cfs_root_cg_init(struct xsched_cu *xcu);
void xcu_grp_shares_update(struct xsched_group *parent);
void xsched_group_xse_detach(struct xsched_entity *xse);

void xsched_quota_init(void);
void xsched_quota_timeout_init(struct xsched_group *xg);
void xsched_quota_timeout_update(struct xsched_group *xg);
void xsched_quota_account(struct xsched_group *xg, s64 exec_time);
bool xsched_quota_exceed(struct xsched_group *xg);
void xsched_quota_refill(struct work_struct *work);

#define XCU_PERIOD_MIN_MS 1
#define XCU_QUOTA_RUNTIME_INF -1
#define XCU_SHARES_MIN 1

#define XCUCG_SET_FILE_RETRY_COUNT 50
#define XCUCG_SET_FILE_DELAY_MS 10

#define SCHED_CLASS_MAX_LENGTH 4

#endif

#ifdef CONFIG_CGROUP_DMEM
/* Dmem interface */
int xsched_dmem_init(void);
#endif /* CONFIG_CGROUP_DMEM */

#endif /* !__LINUX_XSCHED_H__ */
