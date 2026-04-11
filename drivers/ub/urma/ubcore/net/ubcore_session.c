// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubcore session implementation
 * Author: Wang Hang
 * Create: 2025-04-11
 * Note:
 * History: 2025-04-11: Create file
 */

#include <linux/atomic.h>
#include <linux/random.h>
#include "ubcore_log.h"
#include "ubcore_session.h"

struct ubcore_session {
	struct ubcore_device *dev;
	uint32_t session_id;
	void *session_data;
	struct kref ref;
	struct list_head list_entry;
	struct delayed_work delayed_work;
	struct completion completion;
	atomic_t cb_called;
	ubcore_session_callback complete_cb;
	ubcore_session_free_callback free_cb;
};

struct ubcore_session_context {
	atomic_t next_id;
	struct list_head list;
	spinlock_t lock;
	struct workqueue_struct *wq;
};

struct ubcore_session_context session_ctx = { 0 };

static inline void ubcore_session_add_to_list(struct ubcore_session *session)
{
	unsigned long flags;

	ubcore_session_ref_acquire(session);
	spin_lock_irqsave(&session_ctx.lock, flags);
	list_add_tail(&session->list_entry, &session_ctx.list);
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	ubcore_log_info("Session %u add to list", session->session_id);
}

static inline void
ubcore_session_remove_from_list(struct ubcore_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_del(&session->list_entry);
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	ubcore_session_ref_release(session);
	ubcore_log_info("Session %u remove from list", session->session_id);
}

static void ubcore_session_timeout(struct work_struct *work);

struct ubcore_session *
ubcore_session_create(struct ubcore_device *dev, void *session_data,
		      uint32_t timeout, ubcore_session_callback complete_cb,
		      ubcore_session_free_callback free_cb)
{
	struct ubcore_session *s;
	uint32_t timeout_limited;

	if (timeout == 0 || timeout > UBCORE_CONN_MAX_TIMEOUT)
		timeout_limited = UBCORE_CONN_MAX_TIMEOUT;
	else
		timeout_limited = timeout;

	s = kzalloc(sizeof(struct ubcore_session), GFP_KERNEL);
	if (!s)
		return NULL;

	s->dev = dev;
	s->session_id = (uint32_t)atomic_inc_return(&session_ctx.next_id);
	s->session_data = session_data;
	INIT_DELAYED_WORK(&s->delayed_work, ubcore_session_timeout);
	kref_init(&s->ref);
	init_completion(&s->completion);
	atomic_set(&s->cb_called, 0);
	s->complete_cb = complete_cb;
	s->free_cb = free_cb;
	ubcore_session_add_to_list(s);

	if (!queue_delayed_work(session_ctx.wq, &s->delayed_work,
				msecs_to_jiffies(timeout_limited)))
		goto delete_session;

	return s;

delete_session:
	ubcore_session_remove_from_list(s);
	return NULL;
}

struct ubcore_session *ubcore_session_find(uint32_t session_id)
{
	struct ubcore_session *cur, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_for_each_entry(cur, &session_ctx.list, list_entry) {
		if (cur->session_id == session_id) {
			target = cur;
			ubcore_session_ref_acquire(target);
			break;
		}
	}
	spin_unlock_irqrestore(&session_ctx.lock, flags);
	return target;
}

static void ubcore_session_timeout(struct work_struct *work)
{
	struct ubcore_session *session =
		container_of(work, struct ubcore_session, delayed_work.work);

	if (atomic_cmpxchg(&session->cb_called, 0, 1) == 1)
		return;

	ubcore_log_err("Session %u timeout\n", session->session_id);

	if (session->complete_cb)
		session->complete_cb(session->dev, session->session_data);
	complete(&session->completion);
	ubcore_session_remove_from_list(session);
}

void ubcore_session_complete(struct ubcore_session *session)
{
	if (atomic_cmpxchg(&session->cb_called, 0, 1) == 1)
		return;

	ubcore_log_info("Session %u complete\n", session->session_id);
	cancel_delayed_work_sync(&session->delayed_work);

	if (session->complete_cb)
		session->complete_cb(session->dev, session->session_data);
	complete(&session->completion);
	ubcore_session_remove_from_list(session);
}

void ubcore_session_wait(struct ubcore_session *session)
{
	wait_for_completion(&session->completion);
}

static void ubcore_session_free(struct kref *kref)
{
	struct ubcore_session *session =
		container_of(kref, struct ubcore_session, ref);

	if (session->session_data) {
		if (!session->free_cb)
			session->free_cb = kfree;
		(session->free_cb)(session->session_data);
	}
	kfree(session);
}

void ubcore_session_ref_acquire(struct ubcore_session *session)
{
	kref_get(&session->ref);
}

void ubcore_session_ref_release(struct ubcore_session *session)
{
	kref_put(&session->ref, ubcore_session_free);
}

uint32_t ubcore_session_get_id(struct ubcore_session *session)
{
	return session->session_id;
}

void *ubcore_session_get_data(struct ubcore_session *session)
{
	return session->session_data;
}

void ubcore_session_flush(struct ubcore_device *dev)
{
	struct ubcore_session *session = NULL;
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_for_each_entry(session, &session_ctx.list, list_entry) {
		mod_delayed_work(session_ctx.wq, &session->delayed_work, 0);
	}
	spin_unlock_irqrestore(&session_ctx.lock, flags);

	flush_workqueue(session_ctx.wq);
}

int ubcore_session_init(void)
{
	atomic_set(&session_ctx.next_id, 0);
	INIT_LIST_HEAD(&session_ctx.list);
	spin_lock_init(&session_ctx.lock);

	session_ctx.wq = alloc_workqueue("%s", 0, 1, "ubcore-session");
	if (!session_ctx.wq) {
		ubcore_log_err("Fail to alloc session workqueue.");
		return -EINVAL;
	}
	return 0;
}

void ubcore_session_uninit(void)
{
	struct ubcore_session *session = NULL;
	unsigned long flags;

	spin_lock_irqsave(&session_ctx.lock, flags);
	list_for_each_entry(session, &session_ctx.list, list_entry) {
		mod_delayed_work(session_ctx.wq, &session->delayed_work, 0);
	}
	spin_unlock_irqrestore(&session_ctx.lock, flags);

	drain_workqueue(session_ctx.wq);
	destroy_workqueue(session_ctx.wq);
}
