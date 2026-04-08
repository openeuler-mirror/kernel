// SPDX-License-Identifier: GPL-2.0+
/*
 * Support cgroup for xpu device
 *
 * Copyright (C) 2025-2026 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/err.h>
#include <linux/cgroup.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/xsched.h>
#include <linux/delay.h>

#ifdef CONFIG_CGROUP_FREEZER
#include <linux/freezer.h>
#endif

static struct xsched_group root_xsched_group;
struct xsched_group *root_xcg = &root_xsched_group;

/*
 * Cacheline aligned slab cache for xsched_group,
 * to replace kzalloc with kmem_cache_alloc.
 */
static struct kmem_cache *xsched_group_cache __read_mostly;
static struct kmem_cache *xcg_attach_entry_cache __read_mostly;
static LIST_HEAD(xcg_attach_list);
static DEFINE_MUTEX(xcg_mutex);
static DEFINE_MUTEX(xcu_file_show_mutex);

static const char xcu_sched_name[XSCHED_TYPE_NUM][SCHED_CLASS_MAX_LENGTH] = {
	[XSCHED_TYPE_RT] = "rt",
	[XSCHED_TYPE_CFS] = "cfs"
};

/**
 * Parse the "xcu=" kernel command line parameter.
 *
 * Usage:
 *   xcu=enable → enable xcu_cgrp_subsys
 *   Otherwise  → enable freezer_cgrp_subsys
 *
 * Returns:
 *   1 (handled), 0 (not handled)
 */
static DEFINE_STATIC_KEY_FALSE(xcu_cgroup_key);

static int __init xcu_setup(char *str)
{
	if (!str)
		return 0;

	if (strcmp(str, "enable") == 0)
		static_branch_enable(&xcu_cgroup_key);

	return 1;
}
__setup("xcu=", xcu_setup);

static bool xcu_cgroup_enabled(void)
{
	return static_branch_unlikely(&xcu_cgroup_key);
}

/**
 * xcu_cgroup_check_compat - Verify XCU mode matches the cgroup hierarchy version.
 *
 * Validates that the XCU enablement state matches the active cgroup hierarchy
 * version. The compatibility rules are strictly defined as:
 *
 * 1. XCU Enabled (xcu=enable): Requires cgroup v2.
 * 2. XCU Disabled (default):   Requires cgroup v1.
 *
 * IMPORTANT: cgroup_subsys_on_dfl() only returns a valid version indicator
 * after the cgroup filesystem has been mounted at the root node. Calling
 * this function prior to mount may yield incorrect results.
 *
 * Return: true if compatible, false otherwise (with a warning logged).
 */
static bool xcu_cgroup_check_compat(void)
{
	bool xcu_mode = xcu_cgroup_enabled();

	if (xcu_mode != cgroup_subsys_on_dfl(xcu_cgrp_subsys)) {
		XSCHED_WARN("XCU cgrp is incompatible with the cgroup version\n");
		return false;
	}
	return true;
}

static int xcu_cg_set_file_show(struct xsched_group *xg, int sched_class)
{
	if (!xg) {
		XSCHED_ERR("xsched_group is NULL.\n");
		return -EINVAL;
	}

	mutex_lock(&xcu_file_show_mutex);
	/* Update visibility of related files based on sched_class */
	for (int type_name = XCU_FILE_PERIOD_MS; type_name < NR_XCU_FILE_TYPES; type_name++) {
		if (unlikely(!xg->xcu_file[type_name].kn)) {
			mutex_unlock(&xcu_file_show_mutex);
			return -EBUSY;
		}

		cgroup_file_show(&xg->xcu_file[type_name], sched_class == XSCHED_TYPE_CFS);
	}

	mutex_unlock(&xcu_file_show_mutex);
	return 0;
}

/**
 * @brief Initialize the core components of an xsched_group.
 *
 * This function initializes the essential components of an xsched_group,
 * including the spin lock, member list, children groups list, quota timeout
 * mechanism, and refill work queue. These components are necessary for the
 * proper functioning of the xsched_group.
 *
 * @param xcg Pointer to the xsched_group to be initialized.
 * @param parent_xcg Pointer to the parent xsched_group to be inherited.
 */
static void init_xsched_group(
	struct xsched_group *xcg, struct xsched_group *parent_xcg)
{
	spin_lock_init(&xcg->lock);
	INIT_LIST_HEAD(&xcg->members);
	INIT_LIST_HEAD(&xcg->children_groups);
	xsched_quota_timeout_init(xcg);
	INIT_WORK(&xcg->refill_work, xsched_quota_refill);

	xcg->sched_class = parent_xcg ? parent_xcg->sched_class : XSCHED_TYPE_DFLT;
	xcg->parent = parent_xcg;
	xcg->runtime = 0;
}

void xcu_cg_subsys_init(void)
{
	init_xsched_group(root_xcg, NULL);

	xsched_quota_init();

	xsched_group_cache = KMEM_CACHE(xsched_group, 0);
	xcg_attach_entry_cache = KMEM_CACHE(xcg_attach_entry, 0);
}

void init_fair_xsched_group(struct xsched_group *xg,
	struct xsched_cu *xcu, struct xsched_rq_cfs *cfs_rq)
{
	int id = xcu->id;

	/* Ensure non-root group has a valid parent */
	if (xg != root_xcg && WARN_ON(!xg->parent))
		return;

	xg->perxcu_priv[id].xcu_id = id;
	xg->perxcu_priv[id].self = xg;
	xg->perxcu_priv[id].cfs_rq = cfs_rq;
	xg->perxcu_priv[id].xse.xcu = xcu;
	xg->perxcu_priv[id].xse.is_group = true;
	xg->perxcu_priv[id].xse.parent_grp = xg->parent;

	/* Put new empty groups to the right in parent's rbtree */
	fair_xsched_class.xse_init(&xg->perxcu_priv[id].xse);
}

static void xcg_perxcu_cfs_rq_deinit(struct xsched_group *xcg, int max_id)
{
	struct xsched_cu *xcu;
	int i;

	for (i = 0; i < max_id; i++) {
		xcu = xsched_cu_mgr[i];
		mutex_lock(&xcu->xcu_lock);
		dequeue_ctx(&xcg->perxcu_priv[i].xse);
		kfree(xcg->perxcu_priv[i].cfs_rq);
		xcg->perxcu_priv[i].cfs_rq = NULL;
		mutex_unlock(&xcu->xcu_lock);
	}
}

/**
 * xcu_cfs_cg_init() - Initialize xsched_group cfs runqueues and bw control.
 * @xcg: new xsched_cgroup
 * @parent_xg: parent's group
 *
 * One xsched_group can host many processes with contexts on different devices.
 * Function creates xsched_entity for every XCU, and places it in runqueue
 * of parent group. Create new cfs rq for xse inside group.
 */
static int xcu_cfs_cg_init(struct xsched_group *xcg,
				struct xsched_group *parent_xg)
{
	int id = 0;
	struct xsched_cu *xcu;
	struct xsched_rq_cfs *sub_cfs_rq;

	for_each_active_xcu(xcu, id) {
		sub_cfs_rq = kzalloc(sizeof(*sub_cfs_rq), GFP_KERNEL);
		if (!sub_cfs_rq) {
			XSCHED_ERR("Fail to alloc cfs runqueue on xcu %d\n", id);
			xcg_perxcu_cfs_rq_deinit(xcg, id);
			return -ENOMEM;
		}
		init_xsched_cfs_rq(sub_cfs_rq);

		/* call init_fair_xsched_group() after init_xsched_group() */
		init_fair_xsched_group(xcg, xcu, sub_cfs_rq);
	}

	xcg->period = XSCHED_CFS_QUOTA_PERIOD_MS;
	xcg->quota = XSCHED_TIME_INF;
	xcg->shares_cfg = XSCHED_CFG_SHARE_DFLT;
	xcu_grp_shares_add(parent_xg, xcg);

	return 0;
}

/**
 * xcu_cg_init() - Initialize non-root xsched_group structure.
 * @xcg: new xsched_cgroup
 * @parent_xg: parent's group
 */
static int xcu_cg_init(struct xsched_group *xcg,
				struct xsched_group *parent_xg)
{
	init_xsched_group(xcg, parent_xg);
	list_add_tail(&xcg->group_node, &parent_xg->children_groups);

	switch (xcg->sched_class) {
	case XSCHED_TYPE_CFS:
		return xcu_cfs_cg_init(xcg, parent_xg);
	default:
		XSCHED_INFO("xcu_cgroup: init RT group css=0x%lx\n",
					(uintptr_t)&xcg->css);
		break;
	}

	return 0;
}

inline struct xsched_group *xcu_cg_from_css(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct xsched_group, css) : NULL;
}

/**
 * xcu_css_alloc() - Allocate and init xcu cgroup.
 * @parent_css: css of parent xcu cgroup
 *
 * Called from kernel/cgroup.c with cgroup_lock() held.
 * First called in subsys initialization to create root xcu cgroup, when
 * XCUs haven't been initialized yet. Func used on every new cgroup creation,
 * on second call to set root xsched_group runqueue.
 *
 * Return: pointer of new xcu cgroup css on success, -ENOMEM otherwise.
 */
static struct cgroup_subsys_state *
xcu_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct xsched_group *xg;

	if (!parent_css)
		return &root_xsched_group.css;

	xg = kmem_cache_zalloc(xsched_group_cache, GFP_KERNEL);
	if (!xg)
		return ERR_PTR(-ENOMEM);

	return &xg->css;
}

static void xcu_css_free(struct cgroup_subsys_state *css)
{
	struct xsched_group *xcg = xcu_cg_from_css(css);

	hrtimer_cancel(&xcg->quota_timeout);
	cancel_work_sync(&xcg->refill_work);
	cancel_work_sync(&xcg->file_show_work);

	if (xcg->sched_class == XSCHED_TYPE_CFS)
		xcg_perxcu_cfs_rq_deinit(xcg, num_active_xcu);

	kmem_cache_free(xsched_group_cache, xcg);
}

static void delay_xcu_cg_set_file_show_workfn(struct work_struct *work)
{
	struct xsched_group *xg = container_of(work, struct xsched_group, file_show_work);

	for (int i = 0; i < XCUCG_SET_FILE_RETRY_COUNT; i++) {
		if (!xcu_cg_set_file_show(xg, xg->sched_class))
			return;

		mdelay(XCUCG_SET_FILE_DELAY_MS);
	}

	XSCHED_ERR("Failed to control the files xcu.{quota, period, shares} visibility after\n"
				"%d retries, sched_class=%d, css=0x%lx\n",
				XCUCG_SET_FILE_RETRY_COUNT, xg->sched_class, (uintptr_t)&xg->css);
}

static int xcu_css_online(struct cgroup_subsys_state *css)
{
	struct xsched_group *xg = xcu_cg_from_css(css);
	struct cgroup_subsys_state *parent_css = css->parent;
	struct xsched_group *parent_xg;
	int err;

	if (!parent_css)
		return 0;

	parent_xg = xcu_cg_from_css(parent_css);
	err = xcu_cg_init(xg, parent_xg);
	if (err) {
		kmem_cache_free(xsched_group_cache, xg);
		XSCHED_ERR("Failed to initialize new xsched_group @ %s.\n", __func__);
		return err;
	}

	INIT_WORK(&xg->file_show_work, delay_xcu_cg_set_file_show_workfn);
	schedule_work(&xg->file_show_work);

	return 0;
}

static void xcu_css_offline(struct cgroup_subsys_state *css)
{
	struct xsched_group *xcg;

	xcg = xcu_cg_from_css(css);

	if (xcg == root_xcg)
		return;

	switch (xcg->sched_class) {
	case XSCHED_TYPE_CFS:
		xcu_grp_shares_sub(xcg->parent, xcg);
		break;
	default:
		XSCHED_INFO("xcu_cgroup: deinit RT group css=0x%lx\n",
					(uintptr_t)&xcg->css);
		break;
	}
}

static void xcu_css_released(struct cgroup_subsys_state *css)
{
	struct xsched_group *xcg = xcu_cg_from_css(css);

	list_del(&xcg->group_node);
}

static void xsched_group_xse_attach(struct xsched_group *xg,
				struct xsched_entity *xse)
{
	spin_lock(&xg->lock);
	list_add_tail(&xse->group_node, &xg->members);
	spin_unlock(&xg->lock);
	xse->parent_grp = xg;
}

void xsched_group_xse_detach(struct xsched_entity *xse)
{
	struct xsched_group *xcg = xse->parent_grp;

	spin_lock(&xcg->lock);
	list_del(&xse->group_node);
	spin_unlock(&xcg->lock);
}

static int xcu_task_can_attach(struct task_struct *task,
			struct xsched_group *old)
{
	struct xsched_entity *xse;
	bool has_xse = false;

	spin_lock(&old->lock);
	list_for_each_entry(xse, &old->members, group_node) {
		if (xse->owner_pid == task_pid_nr(task)) {
			has_xse = true;
			break;
		}
	}
	spin_unlock(&old->lock);

	return has_xse ? -EINVAL : 0;
}

static int xcu_can_attach(struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cgroup_subsys_state *dst_css, *old_css;
	struct xsched_group *old_xcg, *dst_xcg;
	struct xcg_attach_entry *entry;
	int ret = 0;

	cgroup_taskset_for_each(task, dst_css, tset) {
		rcu_read_lock();
		old_css = task_css(task, xcu_cgrp_id);
		rcu_read_unlock();
		dst_xcg = xcu_cg_from_css(dst_css);
		old_xcg = xcu_cg_from_css(old_css);

		ret = xcu_task_can_attach(task, old_xcg);
		if (ret < 0)
			return ret;

		/* record entry for this task */
		entry = kmem_cache_zalloc(xcg_attach_entry_cache, GFP_KERNEL);
		if (!entry)
			return -ENOMEM;
		entry->task = task;
		entry->old_xcg = old_xcg;
		entry->new_xcg = dst_xcg;
		list_add_tail(&entry->node, &xcg_attach_list);
	}

	return 0;
}

static void xcu_cancel_attach(struct cgroup_taskset *tset)
{
	struct xcg_attach_entry *entry, *tmp;

	/* error: clear all entries */
	list_for_each_entry_safe(entry, tmp, &xcg_attach_list, node) {
		list_del(&entry->node);
		kmem_cache_free(xcg_attach_entry_cache, entry);
	}
}

void xcu_move_task(struct task_struct *task, struct xsched_group *old_xcg,
			struct xsched_group *new_xcg)
{
	struct xsched_entity *xse;
	struct xsched_cu *xcu;

	if (!old_xcg || !new_xcg)
		return;

	spin_lock(&old_xcg->lock);

	list_for_each_entry(xse, &old_xcg->members, group_node) {
		if (xse->owner_pid == task_pid_nr(task)) {
			if (WARN_ON_ONCE(xse->parent_grp != old_xcg))
				break;

			/* delete from the old_xcg */
			list_del(&xse->group_node);
			xse->parent_grp = NULL;
			break;
		}
	}

	spin_unlock(&old_xcg->lock);

	/* xse not found */
	if (list_entry_is_head(xse, &old_xcg->members, group_node))
		return;

	xcu = xse->xcu;

	mutex_lock(&xcu->xcu_lock);
	/* dequeue from the current runqueue */
	dequeue_ctx(xse);
	/* attach to the new_xcg */
	xsched_group_xse_attach(new_xcg, xse);
	/* enqueue to the runqueue in new_xcg */
	enqueue_ctx(xse, xcu);
	wake_up_interruptible(&xcu->wq_xcu_idle);
	mutex_unlock(&xcu->xcu_lock);
}

static void xcu_attach(struct cgroup_taskset *tset)
{
	struct xcg_attach_entry *entry, *tmp;

	list_for_each_entry(entry, &xcg_attach_list, node) {
		xcu_move_task(entry->task, entry->old_xcg, entry->new_xcg);
	}

	/* cleanup */
	list_for_each_entry_safe(entry, tmp, &xcg_attach_list, node) {
		list_del(&entry->node);
		kmem_cache_free(xcg_attach_entry_cache, entry);
	}
}

/**
 * xsched_group_inherit() - Attach new entity to task's xsched_group.
 * @task: task_struct
 * @xse: xsched entity
 *
 * Called in xsched context initialization to attach xse to task's group
 * and inherit its xse scheduling class and bandwidth control policy.
 *
 * Return: Zero on success.
 */
void xsched_group_inherit(struct task_struct *task, struct xsched_entity *xse)
{
	struct cgroup_subsys_state *css;
	struct xsched_group *xg;

	xse->owner_pid = task_pid_nr(task);
	css = task_get_css(task, xcu_cgrp_id);
	xg = xcu_cg_from_css(css);
	xsched_group_xse_attach(xg, xse);
	css_put(css);
}

static int xcu_sched_class_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct xsched_group *xg = xcu_cg_from_css(css);

	seq_printf(sf, "%s\n", xcu_sched_name[xg->sched_class]);
	return 0;
}

/**
 * xcu_cg_set_sched_class() - Set scheduling type for group.
 * @xg: xsched group
 * @type: scheduler type
 *
 * Scheduler type can be changed if task is child of root group
 * and haven't got scheduling entities.
 *
 * Return: Zero on success or -EINVAL
 */
static int xcu_cg_set_sched_class(struct xsched_group *xg, int type)
{
	if (type == xg->sched_class)
		return 0;

	/* can't change scheduler when there are running members */
	if (!list_empty(&xg->members))
		return -EBUSY;

	/* deinit old type if necessary */
	switch (xg->sched_class) {
	case XSCHED_TYPE_CFS:
		xcu_grp_shares_sub(xg->parent, xg);
		xcg_perxcu_cfs_rq_deinit(xg, num_active_xcu);
		break;
	default:
		break;
	}

	/* update type */
	xg->sched_class = type;

	/* init new type if necessary */
	switch (type) {
	case XSCHED_TYPE_CFS:
		return xcu_cfs_cg_init(xg, xg->parent);
	default:
		return 0;
	}
}

static ssize_t xcu_sched_class_write(struct kernfs_open_file *of, char *buf,
				size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct xsched_group *xg;
	char type_name[SCHED_CLASS_MAX_LENGTH];
	int type;

	ssize_t ret = sscanf(buf, "%3s", type_name);

	if (ret < 1)
		return -EINVAL;

	for (type = 0; type < XSCHED_TYPE_NUM; type++) {
		if (!strcmp(type_name, xcu_sched_name[type]))
			break;
	}
	if (type == XSCHED_TYPE_NUM)
		return -EINVAL;

	if (!list_empty(&css->children))
		return -EBUSY;

	css_get(css);
	xg = xcu_cg_from_css(css);

	/* only the first level of root can switch scheduler type */
	if (xg->parent != root_xcg) {
		css_put(css);
		return -EINVAL;
	}

	mutex_lock(&xcg_mutex);
	ret = xcu_cg_set_sched_class(xg, type);
	mutex_unlock(&xcg_mutex);

	if (!ret)
		xcu_cg_set_file_show(xg, type);

	css_put(css);

	return ret ? ret : nbytes;
}

static s64 xcu_read_s64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	s64 ret = 0;
	struct xsched_group *xcucg = xcu_cg_from_css(css);

	switch (cft->private) {
	case XCU_FILE_PERIOD_MS:
		ret = div_s64(xcucg->period, NSEC_PER_MSEC);
		break;
	case XCU_FILE_QUOTA_MS:
		ret = (xcucg->quota > 0) ? div_s64(xcucg->quota, NSEC_PER_MSEC)
						: xcucg->quota;
		break;
	case XCU_FILE_SHARES:
		ret = xcucg->shares_cfg;
		break;
	default:
		XSCHED_ERR("invalid operation %lu @ %s\n", cft->private, __func__);
		break;
	}

	return ret;
}

void xcu_grp_shares_update(struct xsched_group *parent, struct xsched_group *child, u32 shares_cfg)
{
	if (child->sched_class != XSCHED_TYPE_CFS)
		return;

	xcu_grp_shares_sub(parent, child);
	child->shares_cfg = shares_cfg;
	xcu_grp_shares_add(parent, child);
}

void xcu_grp_shares_add(struct xsched_group *parent, struct xsched_group *child)
{
	int id;
	struct xsched_cu *xcu;

	if (child->sched_class != XSCHED_TYPE_CFS)
		return;

	child->weight = child->shares_cfg;
	for_each_active_xcu(xcu, id) {
		mutex_lock(&xcu->xcu_lock);
		child->perxcu_priv[id].xse.cfs.weight = child->weight;
		mutex_unlock(&xcu->xcu_lock);
	}

	parent->children_shares_sum += child->shares_cfg;
}

void xcu_grp_shares_sub(struct xsched_group *parent, struct xsched_group *child)
{
	if (child->sched_class != XSCHED_TYPE_CFS)
		return;

	parent->children_shares_sum -= child->shares_cfg;
}

static int xcu_write_s64(struct cgroup_subsys_state *css, struct cftype *cft,
			s64 val)
{
	int ret = 0;
	struct xsched_group *xcucg;
	s64 quota_ns;

	css_get(css);
	xcucg = xcu_cg_from_css(css);

	if (xcucg->sched_class == XSCHED_TYPE_RT) {
		css_put(css);
		return -EINVAL;
	}

	switch (cft->private) {
	case XCU_FILE_PERIOD_MS:
		if (val < XCU_PERIOD_MIN_MS || val > (S64_MAX / NSEC_PER_MSEC)) {
			ret = -EINVAL;
			break;
		}
		xcucg->period = val * NSEC_PER_MSEC;
		xsched_quota_timeout_update(xcucg);
		break;
	case XCU_FILE_QUOTA_MS:
		if (val < XCU_QUOTA_RUNTIME_INF || val > (S64_MAX / NSEC_PER_MSEC)) {
			ret = -EINVAL;
			break;
		}
		/* Runtime should be updated when modifying quota_ms configuration */
		quota_ns = (val > 0) ? val * NSEC_PER_MSEC : val;
		if (xcucg->quota > 0 && quota_ns > 0)
			xcucg->runtime = max((xcucg->runtime - quota_ns), (s64)0);
		else
			xcucg->runtime = 0;
		xcucg->quota = quota_ns;
		xsched_quota_timeout_update(xcucg);
		break;
	case XCU_FILE_SHARES:
		if (val < XCU_SHARES_MIN || val > U32_MAX) {
			ret = -EINVAL;
			break;
		}
		xcu_grp_shares_update(xcucg->parent, xcucg, val);
		break;
	default:
		XSCHED_ERR("invalid operation %lu @ %s\n", cft->private, __func__);
		ret = -EINVAL;
		break;
	}

	css_put(css);

	return ret;
}

static int xcu_stat(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct xsched_group *xcucg = xcu_cg_from_css(css);
	struct xsched_rq_cfs *cfs_rq;
	struct xsched_cu *xcu;
	u64 nr_throttled = 0;
	u64 throttled_time = 0;
	u64 exec_runtime = 0;
	int id;

	if (xcucg->sched_class == XSCHED_TYPE_RT) {
		seq_printf(sf, "RT group stat is not supported @ %s.\n", __func__);
		return 0;
	}

	for_each_active_xcu(xcu, id) {
		mutex_lock(&xcu->xcu_lock);

		cfs_rq = xsched_group_cfs_rq(xcucg, id);
		if (!cfs_rq) {
			mutex_unlock(&xcu->xcu_lock);
			continue;
		}
		nr_throttled += cfs_rq->nr_throttled;
		throttled_time += cfs_rq->throttled_time;
		exec_runtime +=
			xcucg->perxcu_priv[id].xse.cfs.sum_exec_runtime;

		mutex_unlock(&xcu->xcu_lock);
	}

	seq_printf(sf, "exec_runtime:	%llu\n", exec_runtime);
	seq_printf(sf, "shares cfg:	%u/%llu x%u\n", xcucg->shares_cfg,
		   xcucg->parent->children_shares_sum, xcucg->weight);
	seq_printf(sf, "quota:	%lld\n", xcucg->quota);
	seq_printf(sf, "used:	%lld\n", xcucg->runtime);
	seq_printf(sf, "period:	%lld\n", xcucg->period);
	seq_printf(sf, "nr_throttled:	%lld\n", nr_throttled);
	seq_printf(sf, "throttled_time:	%lld\n", throttled_time);

	return 0;
}

static struct cftype xcu_cg_files[] = {
	{
		.name = "period_ms",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = xcu_read_s64,
		.write_s64 = xcu_write_s64,
		.private = XCU_FILE_PERIOD_MS,
		.file_offset = offsetof(struct xsched_group, xcu_file[XCU_FILE_PERIOD_MS]),
	},
	{
		.name = "quota_ms",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = xcu_read_s64,
		.write_s64 = xcu_write_s64,
		.private = XCU_FILE_QUOTA_MS,
		.file_offset = offsetof(struct xsched_group, xcu_file[XCU_FILE_QUOTA_MS]),
	},
	{
		.name = "shares",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = xcu_read_s64,
		.write_s64 = xcu_write_s64,
		.private = XCU_FILE_SHARES,
		.file_offset = offsetof(struct xsched_group, xcu_file[XCU_FILE_SHARES]),
	},
	{
		.name = "stat",
		.seq_show = xcu_stat,
	},
	{
		.name = "sched_class",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = xcu_sched_class_show,
		.write = xcu_sched_class_write,
	},
	{} /* terminate */
};

/*
 * The hooks of a cgroup_subsys are only invoked after a successful allocation.
 * Therefore, we must handle all error conditions during the alloc phase to
 * prevent invalid usage later.
 *
 * 1. If both CONFIG_CGROUP_XCU and CONFIG_CGROUP_FREEZER are enabled:
 *    We verify that the xcu cmdline and cgroup version are compatible.
 *    If they do not match, return -EPERM.
 *
 * 2. If only CONFIG_CGROUP_XCU is enabled:
 *    We verify the cgroup version. If the system is using cgroup v1,
 *    return -EPERM as it is unsupported.
 */
static struct cgroup_subsys_state *
xcu_freezer_compat_css_alloc(struct cgroup_subsys_state *parent_css)
{
	/* Skip allocation if XCU cmdline mismatches the cgroup version. */
	if (parent_css && !xcu_cgroup_check_compat())
		return ERR_PTR(-EPERM);

	if (xcu_cgroup_enabled())
		return xcu_css_alloc(parent_css);

#ifdef CONFIG_CGROUP_FREEZER
	return freezer_css_alloc(parent_css);
#else /* CONFIG_CGROUP_FREEZER=n xcu=disable cgroup=v1 */
	if (!parent_css)
		return &root_xsched_group.css;
	else
		return ERR_PTR(-EPERM);
#endif
}

static int xcu_freezer_compat_css_online(struct cgroup_subsys_state *css)
{
	if (xcu_cgroup_enabled())
		return xcu_css_online(css);

#ifdef CONFIG_CGROUP_FREEZER
	return freezer_css_online(css);
#else
	return 0;
#endif
}

static void xcu_freezer_compat_css_offline(struct cgroup_subsys_state *css)
{
	if (xcu_cgroup_enabled())
		return xcu_css_offline(css);

#ifdef CONFIG_CGROUP_FREEZER
	return freezer_css_offline(css);
#endif
}

static void xcu_freezer_compat_css_released(struct cgroup_subsys_state *css)
{
	if (xcu_cgroup_enabled())
		return xcu_css_released(css);
}

static void xcu_freezer_compat_css_free(struct cgroup_subsys_state *css)
{
	if (xcu_cgroup_enabled())
		return xcu_css_free(css);

#ifdef CONFIG_CGROUP_FREEZER
	return freezer_css_free(css);
#endif
}

static int xcu_freezer_compat_can_attach(struct cgroup_taskset *tset)
{
	if (xcu_cgroup_enabled())
		return xcu_can_attach(tset);

	return 0;
}

static void xcu_freezer_compat_cancel_attach(struct cgroup_taskset *tset)
{
	if (xcu_cgroup_enabled())
		return xcu_cancel_attach(tset);
}

static void xcu_freezer_compat_attach(struct cgroup_taskset *tset)
{
	if (xcu_cgroup_enabled())
		return xcu_attach(tset);

#ifdef CONFIG_CGROUP_FREEZER
	return freezer_attach(tset);
#endif
}

static void xcu_freezer_compat_fork(struct task_struct *task)
{
#ifdef CONFIG_CGROUP_FREEZER
	if (!xcu_cgroup_enabled())
		return freezer_fork(task);
#endif
}

struct cgroup_subsys xcu_cgrp_subsys = {
	.css_alloc = xcu_freezer_compat_css_alloc,
	.css_online = xcu_freezer_compat_css_online,
	.css_offline = xcu_freezer_compat_css_offline,
	.css_released = xcu_freezer_compat_css_released,
	.css_free = xcu_freezer_compat_css_free,
	.can_attach = xcu_freezer_compat_can_attach,
	.cancel_attach = xcu_freezer_compat_cancel_attach,
	.attach = xcu_freezer_compat_attach,
	.fork = xcu_freezer_compat_fork,
	.dfl_cftypes = xcu_cg_files,
#ifdef CONFIG_CGROUP_FREEZER
	.legacy_cftypes = files,
	.legacy_name = "freezer",
#else
	.legacy_cftypes = xcu_cg_files,
#endif
};
