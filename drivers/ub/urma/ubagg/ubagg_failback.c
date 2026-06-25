// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg failback implementation file
 */

#include <linux/err.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "ubagg_log.h"
#include "ubagg_msg.h"
#include "ubagg_netlink.h"
#include "ubagg_session.h"
#include "ubagg_device.h"
#include "ubagg_ioctl.h"

#include "ubagg_failback.h"

struct fb_task {
	uint32_t request_id;
	uint32_t peer_node_id;
	struct ubagg_jetty_id vjetty_id;
	uint32_t pjetty_idx;
	struct ubagg_jetty_id new_pjetty_id;
};

struct fb_result {
	uint32_t request_id;
	uint32_t peer_node_id;
	struct ubagg_jetty_id vjetty_id;
	uint32_t pjetty_idx;
	struct ubagg_jetty_id new_pjetty_id;
	int32_t result;
};

struct fb_req_ctx {
	struct fb_result completion;
	bool notify_user;
};

struct fb_collect_ctx {
	struct list_head list_node;
	struct ubagg_session *session;
	struct fb_task task;
	uint32_t src_id;
	uint32_t need_cnt;
	uint32_t done_cnt;
	int result;
};

static LIST_HEAD(fb_list);
static DEFINE_SPINLOCK(fb_lock);

static int nl_send_notify(const struct fb_task *task)
{
	return ubagg_nl_broadcast(UBAGG_NL_CMD_FAILBACK_NOTIFY,
				  UBAGG_ATTR_PAYLOAD, task, sizeof(*task));
}

static int nl_send_done(const struct fb_result *result)
{
	return ubagg_nl_broadcast(UBAGG_NL_CMD_FAILBACK_DONE,
				  UBAGG_ATTR_PAYLOAD, result, sizeof(*result));
}

static bool eid_equal(const union ubcore_eid *left,
		      const union ubcore_eid *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

#define jetty_id_equal(left, right) \
	(eid_equal(&(left)->eid, &(right)->eid) && (left)->id == (right)->id)

static bool fb_key_equal(const struct fb_task *left,
			 const struct fb_task *right)
{
	return left->request_id == right->request_id &&
	       left->peer_node_id == right->peer_node_id &&
	       left->pjetty_idx == right->pjetty_idx &&
	       jetty_id_equal(&left->vjetty_id, &right->vjetty_id) &&
	       jetty_id_equal(&left->new_pjetty_id, &right->new_pjetty_id);
}

static void fb_del_locked(struct fb_collect_ctx *ctx)
{
	if (!list_empty(&ctx->list_node))
		list_del_init(&ctx->list_node);
}

static struct fb_collect_ctx *fb_find_locked(const struct fb_task *key)
{
	struct fb_collect_ctx *entry;

	list_for_each_entry(entry, &fb_list, list_node) {
		if (fb_key_equal(&entry->task, key))
			return entry;
	}
	return NULL;
}

static void fb_req_complete(struct ubcore_device *dev, const void *session_data)
{
	const struct fb_req_ctx *data = session_data;
	int ret;

	if (data != NULL && data->notify_user) {
		ret = nl_send_done(&data->completion);
		if (ret != 0)
			ubagg_log_err(
				"Failed to send failback done to user, ret:%d.\n",
				ret);
	}

	ubagg_put_ubcore_device(dev);
}

static int fb_send_req(struct ubcore_device *dev, uint32_t session_id,
		       const struct fb_task *task)
{
	struct ubcore_comm_msg msg = { 0 };

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_FAILBACK_REQ;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(*task);
	msg.session_id = session_id;
	msg.data = (void *)task;
	return ubcore_send_comm_msg_to(dev, &msg, task->vjetty_id.eid);
}

static int fb_send_resp(struct ubcore_device *dev,
			const struct fb_result *result, uint32_t session_id)
{
	struct ubcore_comm_msg msg = { 0 };

	msg.protocol_id = UBAGG_COMM_PROTOCOL;
	msg.type = UBAGG_COMM_MSG_FAILBACK_RESP;
	msg.version = UBAGG_BONDING_MSG_CUR_VERSION;
	msg.len = sizeof(*result);
	msg.session_id = session_id;
	msg.data = (void *)result;
	return ubcore_send_comm_msg_to(dev, &msg, result->new_pjetty_id.eid);
}

static void fb_complete(struct ubcore_device *dev, const void *session_data)
{
	struct fb_collect_ctx *data = (struct fb_collect_ctx *)session_data;
	struct fb_result result = { 0 };
	unsigned long flags;
	int ret;

	if (data == NULL) {
		ubagg_put_ubcore_device(dev);
		return;
	}

	spin_lock_irqsave(&fb_lock, flags);
	fb_del_locked(data);
	spin_unlock_irqrestore(&fb_lock, flags);

	result.peer_node_id = data->task.peer_node_id;
	result.request_id = data->task.request_id;
	result.vjetty_id = data->task.vjetty_id;
	result.pjetty_idx = data->task.pjetty_idx;
	result.new_pjetty_id = data->task.new_pjetty_id;
	result.result = data->done_cnt == data->need_cnt ? data->result :
							   -ETIMEDOUT;
	ret = fb_send_resp(dev, &result, data->src_id);
	if (ret != 0)
		ubagg_log_err("Failed to send failback resp, ret:%d.\n", ret);

	ubagg_put_ubcore_device(dev);
}

static struct ubagg_session *fb_create(struct ubcore_device *dev,
				       struct fb_collect_ctx *ctx)
{
	struct ubagg_session *session;
	unsigned long flags;

	INIT_LIST_HEAD(&ctx->list_node);

	spin_lock_irqsave(&fb_lock, flags);
	if (fb_find_locked(&ctx->task) != NULL) {
		spin_unlock_irqrestore(&fb_lock, flags);
		return ERR_PTR(-EALREADY);
	}
	list_add_tail(&ctx->list_node, &fb_list);
	spin_unlock_irqrestore(&fb_lock, flags);

	session = ubagg_session_create(dev, ctx, UBAGG_CONN_MAX_TIMEOUT,
				       fb_complete, NULL);
	if (session == NULL) {
		spin_lock_irqsave(&fb_lock, flags);
		fb_del_locked(ctx);
		spin_unlock_irqrestore(&fb_lock, flags);
		return ERR_PTR(-ENOMEM);
	}

	ctx->session = session;
	return session;
}

static int fb_handle_start(const struct fb_task *task)
{
	struct fb_req_ctx *ctx;
	struct fb_task req;
	struct ubcore_device *bonding_dev;
	struct ubagg_session *session;
	int ret;

	if (task == NULL) {
		ubagg_log_err("Invalid failback start param.\n");
		return -EINVAL;
	}

	bonding_dev = ubagg_find_bonding_device(&task->new_pjetty_id.eid);
	if (bonding_dev == NULL) {
		ubagg_log_err(
			"Failed to find bonding device for failback start.\n");
		return -ENODEV;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		ubagg_put_ubcore_device(bonding_dev);
		return -ENOMEM;
	}

	ctx->completion.peer_node_id = task->peer_node_id;
	ctx->completion.vjetty_id = task->vjetty_id;
	ctx->completion.pjetty_idx = task->pjetty_idx;
	ctx->completion.new_pjetty_id = task->new_pjetty_id;
	ctx->completion.result = -ETIMEDOUT;
	ctx->notify_user = true;

	session = ubagg_session_create(bonding_dev, ctx, UBAGG_CONN_MAX_TIMEOUT,
				       fb_req_complete, NULL);
	if (session == NULL) {
		kfree(ctx);
		ubagg_put_ubcore_device(bonding_dev);
		return -ENOMEM;
	}

	req = *task;
	req.request_id = ubagg_session_get_id(session);
	ctx->completion.request_id = req.request_id;

	ret = fb_send_req(bonding_dev, req.request_id, &req);
	if (ret != 0) {
		ctx->notify_user = false;
		ubagg_session_complete(session);
		ubagg_session_ref_release(session);
		return ret;
	}

	ubagg_session_ref_release(session);
	return 0;
}

static int fb_handle_result(const struct fb_result *result)
{
	struct fb_collect_ctx *entry;
	struct fb_task key = { 0 };
	struct ubagg_session *session = NULL;
	unsigned long flags;

	if (result == NULL) {
		ubagg_log_err("Invalid failback result param.\n");
		return -EINVAL;
	}

	key.peer_node_id = result->peer_node_id;
	key.request_id = result->request_id;
	key.vjetty_id = result->vjetty_id;
	key.pjetty_idx = result->pjetty_idx;
	key.new_pjetty_id = result->new_pjetty_id;

	spin_lock_irqsave(&fb_lock, flags);
	entry = fb_find_locked(&key);
	if (entry == NULL) {
		spin_unlock_irqrestore(&fb_lock, flags);
		ubagg_log_warn(
			"No active failback collection for vjetty_id:%u.\n",
			result->vjetty_id.id);
		return -ENOENT;
	}

	if (entry->done_cnt >= entry->need_cnt) {
		spin_unlock_irqrestore(&fb_lock, flags);
		ubagg_log_warn(
			"Ignore stale failback result for vjetty_id:%u.\n",
			result->vjetty_id.id);
		return -EALREADY;
	}

	if (entry->result == 0 && result->result != 0)
		entry->result = result->result;
	entry->done_cnt++;
	if (entry->done_cnt == entry->need_cnt) {
		session = entry->session;
		ubagg_session_ref_acquire(session);
	}
	spin_unlock_irqrestore(&fb_lock, flags);

	if (session != NULL) {
		ubagg_session_complete(session);
		ubagg_session_ref_release(session);
	}

	return 0;
}

int ubagg_fb_nl_start(struct sk_buff *skb, struct genl_info *info)
{
	struct fb_task task = { 0 };
	int ret;

	ret = ubagg_nl_parse_attr(info, UBAGG_ATTR_PAYLOAD, &task,
				  sizeof(task));
	if (ret != 0)
		return ret;

	return fb_handle_start(&task);
}

int ubagg_fb_nl_result(struct sk_buff *skb, struct genl_info *info)
{
	struct fb_result result = { 0 };
	int ret;

	ret = ubagg_nl_parse_attr(info, UBAGG_ATTR_PAYLOAD, &result,
				  sizeof(result));
	if (ret != 0)
		return ret;

	return fb_handle_result(&result);
}

static void fb_req_msg(struct ubcore_device *dev, struct ubcore_comm_msg *msg,
		       void *conn)
{
	const struct fb_task *task = (const struct fb_task *)msg->data;
	struct fb_collect_ctx *ctx;
	struct ubcore_device *bonding_dev;
	struct ubagg_session *session;
	struct fb_result result = { 0 };
	uint32_t match_count;
	int ret;

	result.peer_node_id = task->peer_node_id;
	result.request_id = task->request_id;
	result.vjetty_id = task->vjetty_id;
	result.pjetty_idx = task->pjetty_idx;
	result.new_pjetty_id = task->new_pjetty_id;

	bonding_dev = ubagg_find_bonding_device(&task->vjetty_id.eid);
	if (bonding_dev == NULL) {
		result.result = -ENODEV;
		(void)fb_send_resp(dev, &result, msg->session_id);
		return;
	}

	match_count = ubagg_get_ucontext_count();
	if (match_count == 0) {
		result.result = -ENOENT;
		(void)fb_send_resp(bonding_dev, &result, msg->session_id);
		ubagg_put_ubcore_device(bonding_dev);
		return;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		result.result = -ENOMEM;
		(void)fb_send_resp(bonding_dev, &result, msg->session_id);
		ubagg_put_ubcore_device(bonding_dev);
		return;
	}

	ctx->task = *task;
	ctx->src_id = msg->session_id;
	ctx->need_cnt = match_count;
	ctx->done_cnt = 0;
	ctx->result = 0;
	session = fb_create(bonding_dev, ctx);
	if (IS_ERR(session)) {
		result.result = PTR_ERR(session);
		kfree(ctx);
		(void)fb_send_resp(bonding_dev, &result, msg->session_id);
		ubagg_put_ubcore_device(bonding_dev);
		return;
	}

	ret = nl_send_notify(task);
	if (ret != 0) {
		ctx->result = ret;
		ctx->done_cnt = ctx->need_cnt;
		ubagg_session_complete(session);
		ubagg_session_ref_release(session);
		return;
	}

	ubagg_session_ref_release(session);
}

static void fb_resp_msg(struct ubcore_device *dev, struct ubcore_comm_msg *msg,
			void *conn)
{
	const struct fb_result *result = (const struct fb_result *)msg->data;
	struct fb_req_ctx *ctx;
	struct fb_task key = { 0 };
	struct fb_task expected = { 0 };
	struct ubagg_session *session;

	session = ubagg_session_find(msg->session_id);
	if (session == NULL) {
		ubagg_log_warn("Failed to find failback session %u.\n",
			       msg->session_id);
		return;
	}

	ctx = ubagg_session_get_data(session);
	key.peer_node_id = result->peer_node_id;
	key.request_id = result->request_id;
	key.vjetty_id = result->vjetty_id;
	key.pjetty_idx = result->pjetty_idx;
	key.new_pjetty_id = result->new_pjetty_id;
	expected.request_id = ctx->completion.request_id;
	expected.peer_node_id = ctx->completion.peer_node_id;
	expected.vjetty_id = ctx->completion.vjetty_id;
	expected.pjetty_idx = ctx->completion.pjetty_idx;
	expected.new_pjetty_id = ctx->completion.new_pjetty_id;
	if (!fb_key_equal(&key, &expected)) {
		ubagg_log_err("Unexpected failback resp for session %u.\n",
			      msg->session_id);
		ubagg_session_ref_release(session);
		return;
	}

	ctx->completion.result = result->result;
	ubagg_session_complete(session);
	ubagg_session_ref_release(session);
}

static const struct ubagg_msg_desc fb_msg_descs[] = {
	{
		.type = UBAGG_COMM_MSG_FAILBACK_REQ,
		.handler = fb_req_msg,
		.expected_len = sizeof(struct fb_task),
	},
	{
		.type = UBAGG_COMM_MSG_FAILBACK_RESP,
		.handler = fb_resp_msg,
		.expected_len = sizeof(struct fb_result),
	},
};

int ubagg_fb_init(void)
{
	return ubagg_msg_register_handlers(fb_msg_descs,
					   ARRAY_SIZE(fb_msg_descs));
}

void ubagg_fb_exit(void)
{
	ubagg_msg_unregister_handlers(fb_msg_descs, ARRAY_SIZE(fb_msg_descs));
}
