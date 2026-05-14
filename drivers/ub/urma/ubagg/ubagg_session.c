// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg session implementation
 * Author: Chen Chongyu
 * Create: 2026-05-13
 * Note:
 * History: 2026-05-13: Create file
 */

#include <linux/atomic.h>
#include <linux/random.h>
#include "ubagg_log.h"
#include "ubagg_session.h"

struct ubagg_session {
	struct ubcore_device *dev;
	uint32_t session_id;
	void *session_data;
	struct kref ref;
	struct list_head list_entry;
	struct delayed_work delayed_work;
	struct completion completion;
	atomic_t cb_called;
	ubagg_session_callback complete_cb;
	ubagg_session_free_callback free_cb;
};

struct ubagg_session_context {
	atomic_t next_id;
	struct list_head list;
	spinlock_t lock;
	struct workqueue_struct *wq;
};

struct ubagg_session_context session_ctx = { 0 };

void ubagg_session_ref_acquire(struct ubagg_session *session)
{
	kref_get(&session->ref);
}

static void ubagg_session_free(struct kref *kref)
{
	struct ubagg_session *session =
		container_of(kref, struct ubagg_session, ref);

	if (session->session_data) {
		if (!session->free_cb)
			session->free_cb = kfree;
		(session->free_cb)(session->session_data);
	}
	kfree(session);
}

static inline void ubagg_session_add_to_list(struct ubagg_session *session)
{
	unsigned long flags;

	ubagg_session_ref_acquire(session);
	spin_lock_irqsave(&session_ctx.lock, flags);
	list_add_tail(&session->list_entry, &session_ctx.list);
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	ubagg_log_info("Session %u add to list", session->session_id);
}

static inline void
ubagg_session_remove_from_list(struct ubagg_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_del(&session->list_entry);
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	ubagg_session_ref_release(session);
	ubagg_log_info("Session %u remove from list", session->session_id);
}

static void ubagg_session_timeout(struct work_struct *work)
{
	struct ubagg_session *session =
		container_of(work, struct ubagg_session, delayed_work.work);

	if (atomic_cmpxchg(&session->cb_called, 0, 1) == 1)
		return;

	ubagg_log_err("Session %u timeout\n", session->session_id);

	if (session->complete_cb)
		session->complete_cb(session->dev, session->session_data);
	complete(&session->completion);
	ubagg_session_remove_from_list(session);
}

struct ubagg_session *
ubagg_session_create(struct ubcore_device *dev, void *session_data,
		      uint32_t timeout, ubagg_session_callback complete_cb,
		      ubagg_session_free_callback free_cb)
{
	struct ubagg_session *s;
	uint32_t timeout_limited;

	if (timeout == 0 || timeout > UBAGG_CONN_MAX_TIMEOUT)
		timeout_limited = UBAGG_CONN_MAX_TIMEOUT;
	else
		timeout_limited = timeout;

	s = kzalloc(sizeof(struct ubagg_session), GFP_KERNEL);
	if (!s)
		return NULL;

	s->dev = dev;
	s->session_id = (uint32_t)atomic_inc_return(&session_ctx.next_id);
	s->session_data = session_data;
	INIT_DELAYED_WORK(&s->delayed_work, ubagg_session_timeout);
	kref_init(&s->ref);
	init_completion(&s->completion);
	atomic_set(&s->cb_called, 0);
	s->complete_cb = complete_cb;
	s->free_cb = free_cb;
	ubagg_session_add_to_list(s);

	if (!queue_delayed_work(session_ctx.wq, &s->delayed_work,
				msecs_to_jiffies(timeout_limited)))
		goto delete_session;

	return s;

delete_session:
	ubagg_session_remove_from_list(s);
	return NULL;
}

struct ubagg_session *ubagg_session_find(uint32_t session_id)
{
	struct ubagg_session *cur, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_for_each_entry(cur, &session_ctx.list, list_entry) {
		if (cur->session_id == session_id) {
			target = cur;
			ubagg_session_ref_acquire(target);
			break;
		}
	}
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	return target;
}

uint32_t ubagg_session_get_id(struct ubagg_session *session)
{
	return session->session_id;
}

void *ubagg_session_get_data(struct ubagg_session *session)
{
	return session->session_data;
}

void ubagg_session_complete(struct ubagg_session *session)
{
	if (atomic_cmpxchg(&session->cb_called, 0, 1) == 1)
		return;

	ubagg_log_info("Session %u complete\n", session->session_id);
	cancel_delayed_work_sync(&session->delayed_work);

	if (session->complete_cb)
		session->complete_cb(session->dev, session->session_data);
	complete(&session->completion);
	ubagg_session_remove_from_list(session);
}

void ubagg_session_wait(struct ubagg_session *session)
{
	wait_for_completion(&session->completion);
}

void ubagg_session_ref_release(struct ubagg_session *session)
{
	kref_put(&session->ref, ubagg_session_free);
}

int ubagg_session_init(void)
{
	atomic_set(&session_ctx.next_id, 0);
	INIT_LIST_HEAD(&session_ctx.list);
	spin_lock_init(&session_ctx.lock);

	session_ctx.wq = alloc_workqueue("%s",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM, 1, "ubagg-session");
	if (!session_ctx.wq) {
		ubagg_log_err("Fail to alloc session workqueue.");
		return -EINVAL;
	}
	return 0;
}

void ubagg_session_uninit(void)
{
	struct ubagg_session *session = NULL;
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_for_each_entry(session, &session_ctx.list, list_entry) {
		mod_delayed_work(session_ctx.wq, &session->delayed_work, 0);
	}
	spin_unlock_irqrestore(&session_ctx.lock, flags);

	drain_workqueue(session_ctx.wq);
	destroy_workqueue(session_ctx.wq);
}
