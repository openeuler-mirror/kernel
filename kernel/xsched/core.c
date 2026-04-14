// SPDX-License-Identifier: GPL-2.0+
/*
 * Core kernel scheduler code for XPU device
 *
 * Copyright (C) 2025-2026 Huawei Technologies Co., Ltd
 *
 * Author: Konstantin Meskhidze <konstantin.meskhidze@huawei.com>
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
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/xsched.h>

/* List of scheduling classes available */
struct list_head xsched_class_list;

static void put_prev_ctx(struct xsched_entity *xse)
{
	struct xsched_cu *xcu = xse->xcu;

	lockdep_assert_held(&xcu->xcu_lock);
	xse->class->put_prev_ctx(xse);
	xse->last_exec_runtime = 0;
	atomic_set(&xse->submitted_one_kick, 0);
	XSCHED_DEBUG("Put current xse %d @ %s\n", xse->tgid, __func__);
}

static size_t select_work_def(struct xsched_cu *xcu, struct xsched_entity *xse)
{
	int scheduled = 0, not_empty;
	struct vstream_info *vs;
	struct xcu_op_handler_params params;
	struct vstream_metadata *vsm;
	size_t kick_slice = xse->class->kick_slice;

	if (atomic_read(&xse->kicks_pending_cnt) == 0) {
		XSCHED_WARN("Try to select xse that has 0 kicks @ %s\n",
			__func__);
		return 0;
	}

	do {
		not_empty = 0;
		for_each_vstream_in_ctx(vs, xse->ctx) {
			vsm = xsched_vsm_fetch_first(vs);

			if (!vsm)
				continue;

			list_add_tail(&vsm->node, &xcu->vsm_list);
			scheduled++;
			not_empty++;
		}
	} while ((scheduled < kick_slice) && (not_empty));

	if (scheduled == 0)
		return 0;

	atomic_sub(scheduled, &xse->kicks_pending_cnt);
	atomic_add(scheduled, &xcu->pending_kicks);

	/*
	 * Iterate over all vstreams in context:
	 * Set wr_cqe bit in last computing task in vsm_list
	 */
	for_each_vstream_in_ctx(vs, xse->ctx) {
		list_for_each_entry_reverse(vsm, &xcu->vsm_list, node) {
			if (vsm->parent == vs) {
				params.group = vsm->parent->xcu->group;
				params.param_1 = &(int){SQE_SET_NOTIFY};
				params.param_2 = &vsm->sqe;
				xcu_sqe_op(&params);
				break;
			}
		}
	}

	xse->total_scheduled += scheduled;
	return scheduled;
}

static struct xsched_entity *__raw_pick_next_ctx(struct xsched_cu *xcu)
{
	const struct xsched_class *class;
	struct xsched_entity *next = NULL;
	size_t scheduled;

	lockdep_assert_held(&xcu->xcu_lock);
	for_each_xsched_class(class) {
		next = class->pick_next_ctx(xcu);
		if (next) {
			scheduled = class->select_work ?
				class->select_work(xcu, next) : select_work_def(xcu, next);

			if (scheduled == 0) {
				dequeue_ctx(next);
				return NULL;
			}

			break;
		}
	}

	return next;
}

void enqueue_ctx(struct xsched_entity *xse, struct xsched_cu *xcu)
{
	lockdep_assert_held(&xcu->xcu_lock);

	if (xse_integrity_check(xse)) {
		XSCHED_ERR("Fail to check xse integrity @ %s\n", __func__);
		return;
	}

	if (!xse->on_rq) {
		xse->xcu = xcu;
		xse->class->enqueue_ctx(xse, xcu);
		XSCHED_DEBUG("Enqueue xse %d @ %s\n", xse->tgid, __func__);
	}
}

void dequeue_ctx(struct xsched_entity *xse)
{
	if (xse_integrity_check(xse)) {
		XSCHED_ERR("Fail to check xse integrity @ %s\n", __func__);
		return;
	}

	lockdep_assert_held(&xse->xcu->xcu_lock);

	if (xse->on_rq) {
		xse->class->dequeue_ctx(xse);
		XSCHED_DEBUG("Dequeue xse %d @ %s\n", xse->tgid, __func__);
	}
}

int delete_ctx(struct xsched_context *ctx)
{
	struct xsched_cu *xcu = ctx->xse.xcu;
	struct xsched_entity *curr_xse = xcu->xrq.curr_xse;
	struct xsched_entity *xse = &ctx->xse;
	int pending;

	if (xse_integrity_check(xse))
		return -EINVAL;

	pending = atomic_read(&xse->kicks_pending_cnt);
	if (pending > 0)
		XSCHED_WARN("Delete xse %d on xcu %u with pending %d kicks\n",
			xse->tgid, xcu->id, pending);

	mutex_lock(&xcu->xcu_lock);
	if (curr_xse == xse)
		xcu->xrq.curr_xse = NULL;
	dequeue_ctx(xse);

#ifdef CONFIG_CGROUP_XCU
	xsched_group_xse_detach(xse);
#endif

	mutex_unlock(&xcu->xcu_lock);

	xse->class->xse_deinit(xse);
	return 0;
}

const struct xsched_class *find_xsched_class(int class_id)
{
	struct xsched_class *sched;

	if (class_id >= XSCHED_TYPE_NUM)
		return NULL;

	for_each_xsched_class(sched) {
		if (sched->class_id == class_id)
			return sched;
	}

	return NULL;
}

static void submit_kick(struct vstream_metadata *vsm)
{
	struct vstream_info *vs = vsm->parent;
	struct xcu_op_handler_params params;

	params.group = vs->xcu->group;
	params.fd = vs->fd;
	params.param_1 = &vs->sq_id;
	params.param_2 = &vs->channel_id;
	params.param_3 = vsm->sqe;
	params.param_4 = &vsm->sqe_num;
	params.param_5 = &vsm->timeout;
	params.param_6 = &vs->sqcq_type;
	params.param_7 = vs->drv_ctx;
	params.param_8 = &vs->logic_vcq_id;

	/* Send vstream on a device for processing. */
	if (xcu_run(&params) != 0)
		XSCHED_ERR(
			"Fail to send Vstream id %u tasks to a device for processing.\n",
			vs->id);
}

static void submit_wait(struct vstream_metadata *vsm)
{
	struct vstream_info *vs = vsm->parent;
	struct xcu_op_handler_params params;
	/* Wait timeout in ms. */
	int32_t timeout = 500;

	params.group = vs->xcu->group;
	params.param_1 = &vs->channel_id;
	params.param_2 = &vs->logic_vcq_id;
	params.param_3 = &vs->id;
	params.param_4 = &vsm->sqe;
	params.param_5 = vsm->cqe;
	params.param_6 = vs->drv_ctx;
	params.param_7 = &timeout;

	/* Wait for a device to complete processing. */
	if (xcu_wait(&params)) {
		XSCHED_ERR("Fail to wait Vstream id %u tasks, logic_cq_id %u.\n",
			vs->id, vs->logic_vcq_id);
	}
}

static int __xsched_submit(struct xsched_cu *xcu, struct xsched_entity *xse)
{
	struct vstream_metadata *vsm, *tmp;
	int submitted = 0;
	long submit_exec_time = 0;
	ktime_t t_start = 0;
	struct xcu_op_handler_params params;

	list_for_each_entry_safe(vsm, tmp, &xcu->vsm_list, node) {
		submit_kick(vsm);
		XSCHED_DEBUG("Xse %d vsm %u sched_delay: %lld ns\n",
			xse->tgid, vsm->sq_id, ktime_to_ns(ktime_sub(ktime_get(), vsm->add_time)));

		params.group = vsm->parent->xcu->group;
		params.param_1 = &(int){SQE_IS_NOTIFY};
		params.param_2 = &vsm->sqe;
		if (xcu_sqe_op(&params)) {
			mutex_unlock(&xcu->xcu_lock);
			t_start = ktime_get();
			submit_wait(vsm);
			submit_exec_time += ktime_to_ns(ktime_sub(ktime_get(), t_start));
			mutex_lock(&xcu->xcu_lock);
		}
		submitted++;
		list_del(&vsm->node);
		kfree(vsm);
	}

	if (submitted == 0)
		return 0;

	xse->last_exec_runtime += submit_exec_time;
	xse->total_submitted += submitted;
	atomic_sub(submitted, &xcu->pending_kicks);
	atomic_add(submitted, &xse->submitted_one_kick);
	INIT_LIST_HEAD(&xcu->vsm_list);
	XSCHED_DEBUG("Xse %d submitted=%d total=%zu, exec_time=%ld @ %s\n",
		xse->tgid, submitted, xse->total_submitted,
		submit_exec_time, __func__);

	return submitted;
}

static inline bool should_preempt(struct xsched_entity *xse)
{
	return xse->class->check_preempt(xse);
}

int xsched_vsm_add_tail(struct vstream_info *vs, vstream_args_t *arg)
{
	struct vstream_metadata *new_vsm;

	new_vsm = kmalloc(sizeof(struct vstream_metadata), GFP_KERNEL);
	if (!new_vsm) {
		XSCHED_ERR("Fail to alloc kick metadata for vs %u @ %s\n",
			vs->id, __func__);
		return -ENOMEM;
	}

	spin_lock(&vs->stream_lock);

	if (vs->kicks_count > MAX_VSTREAM_SIZE) {
		spin_unlock(&vs->stream_lock);
		kfree(new_vsm);
		return -EBUSY;
	}

	xsched_init_vsm(new_vsm, vs, arg);
	list_add_tail(&new_vsm->node, &vs->metadata_list);
	new_vsm->add_time = ktime_get();
	vs->kicks_count++;

	spin_unlock(&vs->stream_lock);

	/* Increasing a total amount of kicks on an CU to which this
	 * context is attached to based on sched_class.
	 */
	atomic_inc(&vs->ctx->xse.kicks_pending_cnt);

	return 0;
}

/* Fetch the first vstream metadata from vstream metadata list
 * and removes it from that list. Returned vstream metadata pointer
 * to be freed after.
 */
struct vstream_metadata *xsched_vsm_fetch_first(struct vstream_info *vs)
{
	struct vstream_metadata *vsm;

	if (!vs || list_empty(&vs->metadata_list))
		return NULL;

	spin_lock(&vs->stream_lock);
	vsm = list_first_entry(&vs->metadata_list, struct vstream_metadata, node);
	if (!vsm) {
		XSCHED_ERR("Corrupted metadata list in vs %u @ %s\n",
			vs->id, __func__);
		goto out_unlock;
	}

	list_del(&vsm->node);
	if (vs->kicks_count == 0)
		XSCHED_WARN("kicks_count underflow in vs %u @ %s\n",
			vs->id, __func__);
	else
		vs->kicks_count -= 1;

out_unlock:
	spin_unlock(&vs->stream_lock);

	return vsm;
}

static bool xcu_has_running(struct xsched_cu *xcu)
{
	bool ret = false;
	struct xsched_class *sched;

	mutex_lock(&xcu->xcu_lock);
	for_each_xsched_class(sched)
		ret |= sched->has_running(xcu);
	mutex_unlock(&xcu->xcu_lock);

	return ret;
}

int xsched_schedule(void *input_xcu)
{
	struct xsched_cu *xcu = input_xcu;
	struct xsched_entity *curr_xse = NULL;
	struct xsched_entity *next_xse = NULL;

	while (!kthread_should_stop()) {
		mutex_unlock(&xcu->xcu_lock);
		wait_event_interruptible(xcu->wq_xcu_idle,
			xcu_has_running(xcu) || kthread_should_stop());

		mutex_lock(&xcu->xcu_lock);
		if (kthread_should_stop()) {
			mutex_unlock(&xcu->xcu_lock);
			break;
		}

		next_xse = __raw_pick_next_ctx(xcu);
		if (!next_xse) {
			XSCHED_WARN("%s: Couldn't find next xse on xcu %u\n", __func__, xcu->id);
			continue;
		}

		xcu->xrq.curr_xse = next_xse;
		if (__xsched_submit(xcu, next_xse) == 0)
			continue;

		curr_xse = xcu->xrq.curr_xse;
		if (!curr_xse)
			continue;

		/* if not deleted yet */
		put_prev_ctx(curr_xse);
		if (!atomic_read(&curr_xse->kicks_pending_cnt))
			dequeue_ctx(curr_xse);

		xcu->xrq.curr_xse = NULL;
	}

	return 0;
}

/* Initializes all xsched XCU objects.
 * Should only be called from xsched_xcu_register function.
 */
int xsched_xcu_init(struct xsched_cu *xcu, struct xcu_group *group, int xcu_id)
{
	struct xsched_class *sched;
	int err;

	xcu->id = xcu_id;
	xcu->state = XSCHED_XCU_NONE;
	xcu->group = group;

	xcu->nr_ctx = 0;
	xcu->xrq.curr_xse = NULL;

	atomic_set(&xcu->pending_kicks, 0);
	INIT_LIST_HEAD(&xcu->vsm_list);
	INIT_LIST_HEAD(&xcu->ctx_list);
	init_waitqueue_head(&xcu->wq_xcu_idle);
	mutex_init(&xcu->ctx_list_lock);
	mutex_init(&xcu->vs_array_lock);
	mutex_init(&xcu->xcu_lock);

	/* Initialize current XCU's runqueue. */
	for_each_xsched_class(sched)
		sched->rq_init(&xcu->xrq);

	/* This worker should set XCU to XSCHED_XCU_WAIT_IDLE.
	 * If after initialization XCU still has XSCHED_XCU_NONE
	 * status then we can assume that there was a problem
	 * with XCU kthread job.
	 */
	xcu->worker = kthread_run(xsched_schedule, xcu, "xcu_%u", xcu->id);

	if (IS_ERR(xcu->worker)) {
		err = PTR_ERR(xcu->worker);
		xcu->worker = NULL;
		XSCHED_DEBUG("Fail to run the worker to schedule for xcu[%u].", xcu->id);
		return err;
	}
	return 0;
}

int init_xsched_entity(struct xsched_context *ctx, struct vstream_info *vs)
{
	int err = 0, class_id = XSCHED_TYPE_DFLT;
	struct xsched_entity *xse;
	const struct xsched_class *sched;

	if (!ctx || !vs || WARN_ON(vs->xcu == NULL))
		return -EINVAL;

	xse = &ctx->xse;

#ifdef CONFIG_CGROUP_XCU
	if (!xcu_cgroup_enabled())
		return -EPERM;

	xsched_group_inherit(current, xse);
	/* inherit the scheduler class from the parent group */
	class_id = xse->parent_grp->sched_class;
#endif

	sched = find_xsched_class(class_id);
	if (!sched)
		return -ENOENT;

	atomic_set(&xse->kicks_pending_cnt, 0);
	atomic_set(&xse->submitted_one_kick, 0);

	xse->total_scheduled = 0;
	xse->total_submitted = 0;
	xse->last_exec_runtime = 0;

	xse->fd = ctx->fd;
	xse->tgid = ctx->tgid;

	err = ctx_bind_to_xcu(vs, ctx);
	if (err) {
		XSCHED_ERR(
			"Couldn't find valid xcu for vstream %u dev_id %u @ %s\n",
			vs->id, vs->dev_id, __func__);
		return err;
	}

	xse->ctx = ctx;
	xse->xcu = vs->xcu;

	WRITE_ONCE(xse->on_rq, false);
	spin_lock_init(&xse->xse_lock);
	sched->xse_init(xse);

	return err;
}

static void xsched_register_sched_class(struct xsched_class *sched)
{
	list_add_tail(&sched->node, &xsched_class_list);
}

__init int xsched_sched_init(void)
{
	INIT_LIST_HEAD(&xsched_class_list);
#ifdef CONFIG_XCU_SCHED_RT
	xsched_register_sched_class(&rt_xsched_class);
#endif

#ifdef CONFIG_XCU_SCHED_CFS
	xsched_register_sched_class(&fair_xsched_class);
#endif

#ifdef CONFIG_CGROUP_XCU
	xcu_cg_subsys_init();
#endif

	return 0;
}
late_initcall(xsched_sched_init);

static int xsched_setattr(struct task_struct *p, const struct xsched_attr *attr)
{
	struct xsched_attr *old_attr = &p->_resvd->xse_attr;

	if (old_attr->xsched_class == attr->xsched_class &&
		old_attr->xsched_priority == attr->xsched_priority)
		return 0;

	old_attr->xsched_class = attr->xsched_class;
	old_attr->xsched_priority = attr->xsched_priority;
	xsched_rt_prio_set(p->pid, old_attr->xsched_priority);

	return 0;
}

SYSCALL_DEFINE2(xsched_setattr, pid_t, pid, struct xsched_attr __user *, arg)
{
	struct xsched_attr kattr;
	struct task_struct *p;
	int rt_prio, retval;

	if (pid < 0 || !arg)
		return -EINVAL;

	if (copy_from_user(&kattr, arg, sizeof(*arg))) {
		XSCHED_ERR("Fail to copy_from_user @ %s\n", __func__);
		return -EFAULT;
	}

	rt_prio = NR_XSE_PRIO - kattr.xsched_priority;
	/* Only support RT */
	if (rt_prio < XSE_PRIO_HIGH || rt_prio > XSE_PRIO_LOW ||
		kattr.xsched_class != XSCHED_TYPE_RT)
		return -EINVAL;

	kattr.xsched_priority = rt_prio;

	rcu_read_lock();
	retval = -ESRCH;
	p = pid ? find_task_by_vpid(pid) : current;
	if (likely(p))
		get_task_struct(p);
	rcu_read_unlock();

	if (likely(p)) {
		retval = xsched_setattr(p, &kattr);
		put_task_struct(p);
	}

	return retval;
}

SYSCALL_DEFINE2(xsched_getattr, pid_t, pid, struct xsched_attr __user *, arg)
{
	struct xsched_attr kattr = { };
	struct task_struct *p;

	if (pid < 0 || !arg)
		return -EINVAL;

	rcu_read_lock();
	p = pid ? find_task_by_vpid(pid) : current;
	if (!p) {
		rcu_read_unlock();
		return -ESRCH;
	}
	kattr = p->_resvd->xse_attr;
	rcu_read_unlock();

	kattr.xsched_priority = NR_XSE_PRIO - kattr.xsched_priority;

	if (copy_to_user(arg, &kattr, sizeof(kattr))) {
		XSCHED_ERR("Fail to copy_to_user @ %s\n", __func__);
		return -EFAULT;
	}

	return 0;
}
