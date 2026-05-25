// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2026. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus task: " fmt

#include "ubus.h"
#include "link.h"
#include "msg.h"
#include "ubus_entity.h"
#include "task.h"

static DEFINE_SPINLOCK(retry_lock);
static LIST_HEAD(retry_list);

static struct workqueue_struct *delay_task_wq;
struct workqueue_struct *ub_get_delay_task_wq(void)
{
	return delay_task_wq;
}
EXPORT_SYMBOL_GPL(ub_get_delay_task_wq);

int ub_delay_task_wq_init(void)
{
	struct workqueue_struct *q;

	q = alloc_ordered_workqueue("ub_delay_task_wq", 0);
	if (!q) {
		pr_err("alloc delay task wq failed\n");
		return -ENOMEM;
	}

	delay_task_wq = q;

	return 0;
}

void ub_delay_task_wq_uninit(void)
{
	if (!delay_task_wq)
		return;

	flush_workqueue(delay_task_wq);
	destroy_workqueue(delay_task_wq);
	delay_task_wq = NULL;
}

static void ub_delay_task_device_attach(struct ub_entity *uent, bool retry)
{
	int ret;

	if (!uent->is_mue)
		device_lock(&uent->pue->dev);

	ret = device_attach(&uent->dev);
	if (ret < 0 && ret != -EPROBE_DEFER)
		ub_warn(uent, "device attach failed, ret=%d\n", ret);

	if (!uent->is_mue)
		device_unlock(&uent->pue->dev);

	if (!retry)
		atomic_set(&uent->ent_mgmt_state, MGMT_STATE_IDLE);
}

static void ub_delay_task_reinit(struct ub_entity *uent, bool retry)
{
	(void)ub_reinit_ent(uent);

	if (!retry)
		atomic_set(&uent->ent_mgmt_state, MGMT_STATE_IDLE);
}

static void ub_delay_task_disable(struct ub_entity *uent)
{
	struct ub_entity *mue = uent->pue;
	u8 is_mue = uent->is_mue;
	int lock;

	if (!is_mue) {
		lock = device_trylock(&mue->dev);
		if (!lock) {
			ub_warn(uent, "disable ue, get mue lock busy\n");
			atomic_set(&uent->ent_mgmt_state, MGMT_STATE_IDLE);
			return;
		}
	}

	ub_disable_ent(uent);

	if (!is_mue) {
		mue->num_ues -= 1;
		device_unlock(&mue->dev);
	}
}

static void ub_retry_task_assign(struct ub_entity *uent, int task_type,
				 bool flag)
{
	if (task_type == TASK_TYPE_ATTACH_RETRY)
		ub_entity_assign_task_src(uent, TASK_SRC_RETRY_ATTACH, flag);
	else
		ub_entity_assign_task_src(uent, TASK_SRC_RETRY_REINIT, flag);
}

static void ub_delay_task_work(struct work_struct *work)
{
	struct ub_delay_task *task = container_of(work, struct ub_delay_task,
						  work);
	const struct ub_manage_subsystem_ops *ops = get_ub_manage_subsystem_ops();
	struct ub_entity *uent = task->uent;
	struct ub_port *port = task->port;
	int task_type = task->task_type;
	u32 task_src = uent->task_src;

	ub_info(uent, "delay task work coming, type[%d], src[%#x]\n",
		task_type, task_src);

	switch (task_type) {
	case TASK_TYPE_START:
		if (!uent->is_mue)
			device_lock(&uent->pue->dev);
		ub_start_ent(uent);
		if (!uent->is_mue)
			device_unlock(&uent->pue->dev);

		atomic_set(&uent->ent_mgmt_state, MGMT_STATE_IDLE);
		break;
	case TASK_TYPE_ATTACH:
		ub_delay_task_device_attach(uent, false);
		break;
	case TASK_TYPE_REINIT:
		ub_delay_task_reinit(uent, false);
		break;
	case TASK_TYPE_LINKDOWN:
		device_lock(&port->uent->dev);
		ublc_handle_all_link_down(port, uent);
		device_unlock(&port->uent->dev);
		break;
	case TASK_TYPE_DISABLE:
		ub_delay_task_disable(uent);
		break;
	case TASK_TYPE_ATTACH_RETRY:
		ub_retry_task_assign(uent, TASK_TYPE_ATTACH_RETRY, false);
		ub_delay_task_device_attach(uent, true);
		break;
	case TASK_TYPE_REINIT_RETRY:
		ub_retry_task_assign(uent, TASK_TYPE_REINIT_RETRY, false);
		ub_delay_task_reinit(uent, true);
		break;
	default:
		goto out;
	}

	/* Attention, here uent maybe has been freed */
	if (!!(task_src & TASK_SRC_VDM_MASK) && ops && ops->vdm_delay_work)
		ops->vdm_delay_work(work);
out:
	ub_delay_task_free(task);
}

struct ub_delay_task *
ub_delay_task_alloc_and_init(struct ub_entity *uent, struct ub_port *port,
			     int type)
{
	struct ub_delay_task *task;

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return (struct ub_delay_task *)ERR_PTR(-ENOMEM);

	task->uent = uent;
	task->port = port;
	task->task_type = type;
	INIT_WORK(&task->work, ub_delay_task_work);

	return task;
}
EXPORT_SYMBOL_GPL(ub_delay_task_alloc_and_init);

void ub_delay_task_free(struct ub_delay_task *task)
{
	kfree(task);
}
EXPORT_SYMBOL_GPL(ub_delay_task_free);

int ub_add_delay_task(struct ub_entity *uent, struct ub_port *port, int type)
{
	struct ub_delay_task *task;

	task = ub_delay_task_alloc_and_init(uent, port, type);
	if (IS_ERR(task))
		return PTR_ERR(task);

	queue_work(delay_task_wq, &task->work);
	return 0;
}
EXPORT_SYMBOL_GPL(ub_add_delay_task);

static void ub_retry_task_release(struct kref *kref)
{
	struct ub_retry_task *task = container_of(kref, struct ub_retry_task,
						  kref);

	kfree(task);
}

static int ub_attach_reinit_self(struct ub_entity *uent, int task_type);
static void ub_retry_task_work(struct work_struct *work)
{
	struct ub_retry_task *task = container_of(work, struct ub_retry_task,
						  work.work);
	int ret, task_type = task->task_type;
	struct ub_entity *uent;

	uent = ub_get_ent_by_guid(&task->guid);
	if (!uent)
		goto out;

	if (uent->eid != task->eid)
		goto put;

	if (atomic_read(&uent->ent_mgmt_state) == MGMT_STATE_UNREGISTERING)
		goto put;

	if (ub_entity_test_task_src(uent, TASK_SRC_SELF)) {
		(void)ub_attach_reinit_self(uent, task_type);
	} else {
		ret = ub_add_delay_task(uent, NULL, task_type);
		if (ret) {
			ub_warn(uent, "retry[%d] add delay work failed\n",
				task_type);
			ub_retry_task_assign(uent, task_type, false);
		}
	}
put:
	ub_entity_put(uent);
out:
	spin_lock(&retry_lock);
	list_del(&task->node);
	spin_unlock(&retry_lock);
	kref_put(&task->kref, ub_retry_task_release);
}

static struct ub_retry_task *
ub_retry_task_alloc_and_init(u32 eid, struct ub_guid guid, int task_type)
{
	struct ub_retry_task *task;

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return (struct ub_retry_task *)ERR_PTR(-ENOMEM);

	task->eid = eid;
	task->guid = guid;
	INIT_DELAYED_WORK(&task->work, ub_retry_task_work);
	INIT_LIST_HEAD(&task->node);
	kref_init(&task->kref);
	task->task_type = task_type;

	return task;
}

void ub_add_retry_task(struct ub_entity *uent, int task_type)
{
	struct ub_retry_task *task;
	struct workqueue_struct *q;

	if (!get_msg_rx_flag())
		return;

	task = ub_retry_task_alloc_and_init(uent->eid, uent->guid, task_type);
	if (IS_ERR(task)) {
		ub_err(uent, "alloc retry[%d] task failed\n", task_type);
		return;
	}

	if (uent->task_src & TASK_SRC_VDM_MASK)
		q = get_rx_msg_wq(UB_MSG_CODE_VDM);
	else if (ub_entity_test_task_src(uent, TASK_SRC_SELF))
		q = get_rx_msg_wq(UB_MSG_CODE_LINK);
	else
		q = get_rx_msg_wq(UB_MSG_CODE_POOL);

	if (!q) {
		kref_put(&task->kref, ub_retry_task_release);
		ub_err(uent, "retry[%d] task queue is null\n", task_type);
		return;
	}

	if ((task_type == TASK_TYPE_ATTACH_RETRY &&
	    ub_entity_test_task_src(uent, TASK_SRC_RETRY_ATTACH)) ||
	    (task_type == TASK_TYPE_REINIT_RETRY &&
	    ub_entity_test_task_src(uent, TASK_SRC_RETRY_REINIT))) {
		ub_info(uent, "retry[%d] existed\n", task_type);
		kref_put(&task->kref, ub_retry_task_release);
		return;
	}

	ub_retry_task_assign(uent, task_type, true);

	spin_lock(&retry_lock);
	list_add_tail(&task->node, &retry_list);
	queue_delayed_work(q, &task->work, 5 * HZ); /* delay 5 seconds to retry */
	spin_unlock(&retry_lock);
}

void ub_cancel_retry_work_sync(void)
{
	struct ub_retry_task *task, *tmp;
	bool ret;

	spin_lock(&retry_lock);
	list_for_each_entry_safe(task, tmp, &retry_list, node) {
		list_del_init(&task->node);
		kref_get(&task->kref);
		spin_unlock(&retry_lock);

		ret = cancel_delayed_work_sync(&task->work);
		if (ret)
			kref_put(&task->kref, ub_retry_task_release);

		kref_put(&task->kref, ub_retry_task_release);

		spin_lock(&retry_lock);
	}
	spin_unlock(&retry_lock);
}

static int ub_attach_reinit_self(struct ub_entity *uent, int task_type)
{
	int ret;

	if (task_type == TASK_TYPE_ATTACH_RETRY ||
	    task_type == TASK_TYPE_REINIT_RETRY)
		ub_retry_task_assign(uent, task_type, false);

	if (task_type == TASK_TYPE_ATTACH ||
	    task_type == TASK_TYPE_ATTACH_RETRY) {
		ret = device_attach(&uent->dev);
		if (ret < 0 && ret != -EPROBE_DEFER)
			ub_warn(uent, "device attach failed, ret=%d\n", ret);
	} else {
		ret = ub_reinit_ent(uent);
	}

	return ret;
}

int ub_create_existed_entity_handler(struct ub_entity *uent)
{
	int task_type = TASK_TYPE_ATTACH;
	struct ub_delay_task *task;

	switch (atomic_read(&uent->ent_mgmt_state)) {
	case MGMT_STATE_REGISTERING:
		return 0;
	case MGMT_STATE_UNREGISTERING:
		return -EBUSY;
	case MGMT_STATE_IDLE:
	default:
		if (ub_entity_test_priv_flag(uent, UB_ENTITY_PROBED))
			task_type = TASK_TYPE_REINIT;

		if (ub_entity_test_task_src(uent, TASK_SRC_SELF))
			return ub_attach_reinit_self(uent, task_type);

		task = ub_delay_task_alloc_and_init(uent, NULL, task_type);
		if (IS_ERR(task))
			return PTR_ERR(task);

		atomic_set(&uent->ent_mgmt_state, MGMT_STATE_REGISTERING);
		queue_work(delay_task_wq, &task->work);
		return 0;
	}
}
EXPORT_SYMBOL_GPL(ub_create_existed_entity_handler);

int ub_destroy_existed_entity_handler(struct ub_entity *uent)
{
	struct ub_delay_task *task;

	switch (atomic_read(&uent->ent_mgmt_state)) {
	case MGMT_STATE_REGISTERING:
		return -EBUSY;
	case MGMT_STATE_UNREGISTERING:
		return 0;
	case MGMT_STATE_IDLE:
	default:
		task = ub_delay_task_alloc_and_init(uent, NULL,
						    TASK_TYPE_DISABLE);
		if (IS_ERR(task))
			return PTR_ERR(task);

		atomic_set(&uent->ent_mgmt_state, MGMT_STATE_UNREGISTERING);
		queue_work(delay_task_wq, &task->work);
		return 0;
	}
}
EXPORT_SYMBOL_GPL(ub_destroy_existed_entity_handler);
