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
	struct ubagg_device *dev;
	uint32_t session_id;
	void *session_data;
	struct kref ref;
	struct delayed_work delayed_work;
	struct completion completion;
	atomic_t cb_called;
	ubagg_session_callback complete_cb;
	ubagg_session_free_callback free_cb;
};

struct ubagg_session_context {
	atomic_t next_id;
	struct xarray sessions;
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

static inline int ubagg_session_add(struct ubagg_session *session)
{
	int ret;

	ubagg_session_ref_acquire(session);
	ret = xa_insert_irq(&session_ctx.sessions, session->session_id,
			    session, GFP_KERNEL);
	if (ret) {
		ubagg_log_err_rl("Failed to add session %u.\n", session->session_id);
		ubagg_session_ref_release(session);
		return ret;
	}
	ubagg_log_info_rl("Session %u add to xarray.\n", session->session_id);
	return 0;
}

static inline void ubagg_session_remove(struct ubagg_session *session)
{
	xa_erase_irq(&session_ctx.sessions, session->session_id);
	ubagg_session_ref_release(session);
	ubagg_log_info_rl("Session %u remove from xarray", session->session_id);
}

static void ubagg_session_timeout(struct work_struct *work)
{
	struct ubagg_session *session =
		container_of(work, struct ubagg_session, delayed_work.work);

	if (atomic_cmpxchg(&session->cb_called, 0, 1) == 1)
		return;

	ubagg_log_err_rl("Session %u timeout\n", session->session_id);

	if (session->complete_cb)
		session->complete_cb(session->dev, session->session_data);
	complete(&session->completion);
	ubagg_session_remove(session);
}

struct ubagg_session *ubagg_session_create(struct ubagg_device *dev,
					   void *session_data, uint32_t timeout,
					   ubagg_session_callback complete_cb,
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
	if (ubagg_session_add(s))
		goto free_session;

	if (!queue_delayed_work(session_ctx.wq, &s->delayed_work,
				msecs_to_jiffies(timeout_limited)))
		goto delete_session;

	return s;

free_session:
	ubagg_session_ref_release(s);
	return NULL;

delete_session:
	ubagg_session_remove(s);
	return NULL;
}

struct ubagg_session *ubagg_session_find(uint32_t session_id)
{
	struct ubagg_session *target;
	unsigned long flags;

	xa_lock_irqsave(&session_ctx.sessions, flags);
	target = xa_load(&session_ctx.sessions, session_id);
	if (target)
		ubagg_session_ref_acquire(target);
	xa_unlock_irqrestore(&session_ctx.sessions, flags);
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
	ubagg_session_remove(session);
}

void ubagg_session_wait(struct ubagg_session *session)
{
	wait_for_completion(&session->completion);
}

void ubagg_session_ref_release(struct ubagg_session *session)
{
	kref_put(&session->ref, ubagg_session_free);
}

void ubagg_session_flush(struct ubagg_device *dev)
{
	struct ubagg_session *session;
	unsigned long flags;
	unsigned long index;

	xa_lock_irqsave(&session_ctx.sessions, flags);
	xa_for_each(&session_ctx.sessions, index, session) {
		if (dev != NULL && session->dev != dev)
			continue;
		mod_delayed_work(session_ctx.wq, &session->delayed_work, 0);
	}
	xa_unlock_irqrestore(&session_ctx.sessions, flags);

	flush_workqueue(session_ctx.wq);
}

int ubagg_session_init(void)
{
	atomic_set(&session_ctx.next_id, 0);
	xa_init_flags(&session_ctx.sessions, XA_FLAGS_LOCK_IRQ);

	session_ctx.wq =
		alloc_workqueue("%s", WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM,
				1, "ubagg-session");
	if (!session_ctx.wq) {
		ubagg_log_err("Fail to alloc session workqueue.");
		return -EINVAL;
	}
	return 0;
}

void ubagg_session_uninit(void)
{
	ubagg_session_flush(NULL);
	drain_workqueue(session_ctx.wq);
	destroy_workqueue(session_ctx.wq);
	xa_destroy(&session_ctx.sessions);
}
