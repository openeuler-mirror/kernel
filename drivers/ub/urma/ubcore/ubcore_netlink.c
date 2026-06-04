// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore netlink module
 * Author: Chen Wen, Yan Fangfang
 * Create: 2022-08-27
 * Note:
 * History: 2022-08-27: create file
 */

#include <net/sock.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/list.h>
#include "ubcore_log.h"
#include "ubcore_tp.h"
#include "ubcore_vtp.h"
#include "ubcore_priv.h"
#include "ubcore_device.h"
#include "ubcore_genl_define.h"
#include "ubcore_workqueue.h"
#include "ubcore_priv.h"
#include "ubcore_netlink.h"

#define UBCORE_NL_INVALID_PORT 0
#define CB_ARGS_DEV_LIST 0
#define CB_ARGS_DEV_CNT 1
#define CB_ARGS_DEV_IDX 2
#define CB_ARGS_SIP_IDX 3
#define CB_ARGS_INFO_TYPE 4

#define UBCORE_MAX_NL_MSG_BUF_LEN 2048

static LIST_HEAD(g_nl_session_list);
static DEFINE_SPINLOCK(g_nl_session_lock);
static atomic_t g_nlmsg_seq;
static atomic_t g_nl_buffer_size = ATOMIC_INIT(208 * 1024);
static int ubcore_genl_unicast(struct ubcore_nlmsg *req, uint32_t len,
			       struct ubcore_uvs_instance *uvs);
static int ubcore_insert_nl_msg_queue_pop_task(uint32_t wait_time);

static LIST_HEAD(g_nl_msg_list);
static DEFINE_SPINLOCK(g_nl_msg_lock);

static uint32_t ubcore_get_nlmsg_seq(void)
{
	return atomic_inc_return(&g_nlmsg_seq);
}

struct ubcore_nlmsg *ubcore_alloc_nlmsg(size_t payload_len,
					const union ubcore_eid *src_eid,
					const union ubcore_eid *dst_eid)
{
	struct ubcore_nlmsg *msg;

	msg = kzalloc(sizeof(struct ubcore_nlmsg) + payload_len, GFP_KERNEL);
	if (msg == NULL)
		return NULL;

	if (src_eid != NULL)
		msg->src_eid = *src_eid;

	if (dst_eid != NULL)
		msg->dst_eid = *dst_eid;

	msg->payload_len = payload_len;
	return msg;
}

static void ubcore_free_nl_session(struct kref *kref)
{
	struct ubcore_nl_session *s =
		container_of(kref, struct ubcore_nl_session, kref);

	if (s->dev)
		ubcore_put_device(s->dev);
	kfree(s->resp);
	kfree(s);
}

static inline void ubcore_get_nl_session(struct ubcore_nl_session *s)
{
	kref_get(&s->kref);
}

static inline void ubcore_put_nl_session(struct ubcore_nl_session *s)
{
	(void)kref_put(&s->kref, ubcore_free_nl_session);
}

static struct ubcore_nl_session *
ubcore_create_get_nl_session(struct ubcore_device *dev,
			     struct ubcore_nlmsg *req,
			     struct ubcore_nl_resp_cb *cb)
{
	struct ubcore_nl_session *s;
	unsigned long flags;

	s = kzalloc(sizeof(struct ubcore_nl_session), GFP_KERNEL);
	if (s == NULL)
		return NULL;

	ubcore_get_device(dev);
	s->dev = dev;
	s->cb = *cb;
	s->nlmsg_seq = req->nlmsg_seq;
	kref_init(&s->kref);
	init_completion(&s->comp);

	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_add_tail(&s->node, &g_nl_session_list);
	ubcore_get_nl_session(s);
	spin_unlock_irqrestore(&g_nl_session_lock, flags);

	return s;
}

static inline void ubcore_rmv_nl_session(struct ubcore_nl_session *s)
{
	unsigned long flags;
	bool rmv = false;

	spin_lock_irqsave(&g_nl_session_lock, flags);
	if (!list_empty(&s->node)) {
		list_del_init(&s->node);
		rmv = true;
	}
	spin_unlock_irqrestore(&g_nl_session_lock, flags);

	if (rmv)
		ubcore_put_nl_session(s);
}

static struct ubcore_nl_session *ubcore_find_get_nl_session(uint32_t nlmsg_seq)
{
	struct ubcore_nl_session *tmp, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_for_each_entry(tmp, &g_nl_session_list, node) {
		if (tmp->nlmsg_seq == nlmsg_seq) {
			target = tmp;
			ubcore_get_nl_session(target);
			break;
		}
	}
	spin_unlock_irqrestore(&g_nl_session_lock, flags);
	return target;
}

void ubcore_free_dev_nl_sessions(struct ubcore_device *dev)
{
	struct ubcore_nl_session *s = NULL;
	struct list_head *p, *next;
	unsigned long flags;

	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_for_each_safe(p, next, &g_nl_session_list) {
		s = list_entry(p, struct ubcore_nl_session, node);
		if (s->dev != dev)
			continue;

		list_del_init(&s->node);
		ubcore_put_nl_session(s);
	}
	spin_unlock_irqrestore(&g_nl_session_lock, flags);
}

static struct ubcore_nlmsg *ubcore_get_genlmsg_data(struct genl_info *info)
{
	struct ubcore_nlmsg *msg;
	uint32_t payload_len = 0;

	if (!info->attrs[UBCORE_MSG_SEQ])
		return NULL;

	payload_len = (uint32_t)nla_len(info->attrs[UBCORE_PAYLOAD_DATA]);
	if (payload_len > UBCORE_MAX_NL_MSG_BUF_LEN) {
		ubcore_log_err("Invalid payload len: %d", payload_len);
		return NULL;
	}

	msg = kzalloc((size_t)(sizeof(struct ubcore_nlmsg) + payload_len),
		      GFP_KERNEL);
	if (msg == NULL)
		return NULL;

	msg->payload_len = payload_len;
	msg->nlmsg_seq = nla_get_u32(info->attrs[UBCORE_MSG_SEQ]);
	if (info->attrs[UBCORE_MSG_TYPE])
		msg->msg_type = nla_get_u32(info->attrs[UBCORE_MSG_TYPE]);

	if (info->attrs[UBCORE_TRANSPORT_TYPE])
		msg->transport_type = (enum ubcore_transport_type)nla_get_u32(
			info->attrs[UBCORE_TRANSPORT_TYPE]);

	if (info->attrs[UBORE_SRC_ID])
		(void)memcpy(&msg->src_eid, nla_data(info->attrs[UBORE_SRC_ID]),
			     UBCORE_EID_SIZE);

	if (info->attrs[UBORE_DST_ID])
		(void)memcpy(&msg->dst_eid, nla_data(info->attrs[UBORE_DST_ID]),
			     UBCORE_EID_SIZE);

	if (info->attrs[UBCORE_PAYLOAD_DATA]) {
		(void)memcpy(msg->payload,
			     nla_data(info->attrs[UBCORE_PAYLOAD_DATA]),
			     payload_len);
	}

	return msg;
}

int ubcore_tp_resp_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;

	resp = ubcore_get_genlmsg_data(info);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return 0;
	}
	s = ubcore_find_get_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u",
			       resp->nlmsg_seq);
		kfree(resp);
		return 0;
	}
	s->resp = resp;
	complete(&s->comp);
	ubcore_put_nl_session(s);
	return 0;
}

static int ubcore_genl_unicast(struct ubcore_nlmsg *req, uint32_t len,
			       struct ubcore_uvs_instance *uvs)
{
	int ret = 0;
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	struct ubcore_nl_message *nl_messages;
	unsigned long flags;

	if (req == NULL || uvs->genl_sock == NULL ||
	    uvs->genl_port == UBCORE_NL_INVALID_PORT) {
		ubcore_log_err("There are illegal parameters.\n");
		return -1;
	}

	/* create sk_buff */
	nl_skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (nl_skb == NULL) {
		ubcore_log_err("failed to alloc.\n");
		return -1;
	}
	/* set genl head */
	nlh = genlmsg_put(nl_skb, uvs->genl_port, req->nlmsg_seq,
			  &ubcore_genl_family, NLM_F_ACK,
			  (uint8_t)req->msg_type);
	if (nlh == NULL) {
		ubcore_log_err("Failed to nlmsg put.\n");
		nlmsg_free(nl_skb);
		return -1;
	}
	if (nla_put_u32(nl_skb, UBCORE_MSG_SEQ, req->nlmsg_seq) ||
	    nla_put_u32(nl_skb, UBCORE_MSG_TYPE, (uint32_t)req->msg_type) ||
	    nla_put_u32(nl_skb, UBCORE_TRANSPORT_TYPE,
			(uint32_t)req->transport_type) ||
	    nla_put(nl_skb, UBCORE_PAYLOAD_DATA, (int)req->payload_len,
		    req->payload)) {
		nlmsg_free(nl_skb);
		return -1;
	}

	genlmsg_end(nl_skb, nlh);
	ubcore_log_debug("send genl msg type %d seq:%u payload_len %u",
			 (int)req->msg_type, req->nlmsg_seq, req->payload_len);

	nl_messages = kzalloc(sizeof(struct ubcore_nl_message), GFP_ATOMIC);
	if (nl_messages == NULL)
		return -1;
	nl_messages->nl_skb = nl_skb;
	nl_messages->uvs_genl_port = uvs->genl_port;

	spin_lock_irqsave(&g_nl_msg_lock, flags);
	list_add_tail(&nl_messages->node, &g_nl_msg_list);
	spin_unlock_irqrestore(&g_nl_msg_lock, flags);
	ret = ubcore_insert_nl_msg_queue_pop_task(0);
	if (ret != 0) {
		ubcore_log_err("Failed to insert_nl_msg_queue_pop_task\n");
		return -1;
	}

	return ret;
}

int ubcore_nl_msg_ack_ops(struct sk_buff *skb, struct genl_info *info)
{
	int ack_size;

	ack_size = NLMSG_DEFAULT_SIZE;
	atomic_add(ack_size, &g_nl_buffer_size);
	if (ubcore_insert_nl_msg_queue_pop_task(0) != 0)
		ubcore_log_err("Failed to insert_nl_msg_queue_pop_task\n");

	return 0;
}

int ubcore_mue2ue_resp_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;
	struct ubcore_device *dev;

	resp = ubcore_get_genlmsg_data(info);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return 0;
	}
	s = ubcore_find_get_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u",
			       resp->nlmsg_seq);
		kfree(resp);
		return 0;
	}
	s->resp = resp;

	dev = s->dev;
	if (dev != NULL && s->cb.callback != NULL) {
		s->cb.user_arg = (void *)dev;
		s->cb.callback(resp, s->cb.user_arg);
	} else {
		ubcore_log_err("Invalid param");
	}

	ubcore_rmv_nl_session(s);
	ubcore_put_nl_session(s);
	return 0;
}

int ubcore_tp2ue_vtp_status_notify_ops(struct sk_buff *skb,
				       struct genl_info *info)
{
	struct ubcore_vtp_status_notify *notify;
	struct ubcore_resp_host *resp_host;
	struct ubcore_nlmsg *nlmsg;
	struct ubcore_device *dev;

	nlmsg = ubcore_get_genlmsg_data(info);
	if (nlmsg == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return 0;
	}
	if (nlmsg->payload_len <
	    sizeof(struct ubcore_resp_host) +
		    sizeof(struct ubcore_vtp_status_notify)) {
		ubcore_log_err("Netlink msg payload length not match, len:%u",
			       nlmsg->payload_len);
		goto free_msg;
	}

	resp_host = (struct ubcore_resp_host *)nlmsg->payload;
	if (resp_host->resp.len < sizeof(struct ubcore_vtp_status_notify)) {
		ubcore_log_err("wrong msg size:%u", resp_host->resp.len);
		goto free_msg;
	}

	notify = (struct ubcore_vtp_status_notify *)resp_host->resp.data;
	if (strnlen(notify->mue_name, UBCORE_MAX_DEV_NAME) >=
	    UBCORE_MAX_DEV_NAME)
		goto free_msg;

	dev = ubcore_find_mue_device_by_name(notify->mue_name);
	if (!dev) {
		ubcore_log_err("Failed to find dev %s", notify->mue_name);
		goto free_msg;
	}

	(void)ubcore_send_resp(dev, resp_host);
	ubcore_put_device(dev);

free_msg:
	kfree(nlmsg);
	return 0;
}

int ubcore_update_mue_dev_info_resp_ops(struct sk_buff *skb,
					struct genl_info *info)
{
	struct ubcore_update_mue_dev_info_resp *resp;
	struct ubcore_nlmsg *nlmsg;

	nlmsg = ubcore_get_genlmsg_data(info);
	if (nlmsg == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return 0;
	}
	if (nlmsg->payload_len <
	    sizeof(struct ubcore_update_mue_dev_info_resp)) {
		ubcore_log_err("Netlink msg payload length not match, len:%u",
			       nlmsg->payload_len);
		goto free_msg;
	}

	resp = (struct ubcore_update_mue_dev_info_resp *)(void *)nlmsg->payload;
	if (resp->ret != UBCORE_NL_RESP_SUCCESS)
		ubcore_log_err("Failed to get mue dev info resp");

free_msg:
	kfree(nlmsg);
	return 0;
}

struct ubcore_nlmsg *ubcore_nl_send_wait(struct ubcore_device *dev,
					 struct ubcore_nlmsg *req,
					 struct ubcore_uvs_instance *uvs)
{
	struct ubcore_nl_resp_cb cb = {};
	struct ubcore_nlmsg *resp = NULL;
	struct ubcore_nl_session *s;
	unsigned long leavetime;
	int ret;

	if (uvs->genl_sock == NULL ||
	    uvs->genl_port == UBCORE_NL_INVALID_PORT) {
		ubcore_log_err("genl_port or genl_sock is invalid for uvs %s",
			       uvs->name);
		return NULL;
	}

	req->nlmsg_seq = ubcore_get_nlmsg_seq();
	s = ubcore_create_get_nl_session(dev, req, &cb);
	if (s == NULL) {
		ubcore_log_err("Failed to create nl session");
		return NULL;
	}

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req), uvs);
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		goto exit;
	}

	leavetime = wait_for_completion_timeout(
		&s->comp, msecs_to_jiffies(UBCORE_TYPICAL_TIMEOUT));
	if (leavetime == 0) {
		ubcore_log_err(
			"Failed to wait reply, ret: %d, leavetime: %lu\n", ret,
			leavetime);
		goto exit;
	}

	resp = s->resp;
	s->resp = NULL; /* resp memory is managed by caller  */

exit:
	ubcore_rmv_nl_session(s);
	ubcore_put_nl_session(s);
	return resp;
}

int ubcore_nl_send_nowait(struct ubcore_device *dev, struct ubcore_nlmsg *req,
			  struct ubcore_nl_resp_cb *cb,
			  struct ubcore_uvs_instance *uvs)
{
	struct ubcore_nl_session *s;
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();
	s = ubcore_create_get_nl_session(dev, req, cb);
	if (s == NULL) {
		ubcore_log_err("Failed to create nl session");
		return -ENOMEM;
	}

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req), uvs);
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		ubcore_rmv_nl_session(s);
		ubcore_put_nl_session(s);
		return -EIO;
	}

	ubcore_put_nl_session(s);
	return 0;
}

int ubcore_nl_send_nowait_without_cb(struct ubcore_nlmsg *req,
				     struct ubcore_uvs_instance *uvs)
{
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();

	if (uvs->genl_sock == NULL ||
	    uvs->genl_port == UBCORE_NL_INVALID_PORT) {
		ubcore_log_err("genl_port or genl_sock is invalid for uvs %s",
			       uvs->name);
		return -EINVAL;
	}

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req), uvs);
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg to uvs %s, return %d",
			       uvs->name, ret);
		return -EIO;
	}

	return 0;
}

static int ubcore_set_genl_nla(struct sk_buff *skb,
			       struct ubcore_nlmsg *req_msg)
{
	if (nla_put_u32(skb, UBCORE_MSG_SEQ, req_msg->nlmsg_seq) ||
	    nla_put_u32(skb, UBCORE_MSG_TYPE, (uint32_t)req_msg->msg_type) ||
	    nla_put_u32(skb, UBCORE_TRANSPORT_TYPE,
			(uint32_t)req_msg->transport_type) ||
	    nla_put(skb, UBCORE_PAYLOAD_DATA, (int)req_msg->payload_len,
		    req_msg->payload))
		return -1;

	return 0;
}

static int ubcore_dump_genl_info(struct sk_buff *skb,
				 struct netlink_callback *cb,
				 struct ubcore_nlmsg *req_msg)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &ubcore_genl_family, NLM_F_MULTI,
			  (uint8_t)req_msg->msg_type);
	if (!hdr)
		return -ENOMEM;

	if (ubcore_set_genl_nla(skb, req_msg)) {
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, hdr);
	return 0;
}

static int ubcore_get_mue_dev_dump(struct sk_buff *skb,
				   struct netlink_callback *cb)
{
	struct ubcore_device **dev_list =
		(struct ubcore_device **)cb->args[CB_ARGS_DEV_LIST];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	long i = cb->args[CB_ARGS_DEV_IDX];
	struct ubcore_nlmsg *req_msg;
	int ret;

	for (; i < dev_cnt; ++i) {
		req_msg = ubcore_new_mue_dev_msg(dev_list[i]);
		if (req_msg == NULL) {
			ubcore_log_warn("failed to get mue dev info %s",
					dev_list[i]->dev_name);
			continue;
		}
		ret = ubcore_dump_genl_info(skb, cb, req_msg);
		kfree(req_msg);
		if (ret != 0)
			break;
		ubcore_log_info("dump dev :%s success.\n",
				dev_list[i]->dev_name);
	}
	if (i == dev_cnt) {
		cb->args[CB_ARGS_INFO_TYPE] = 1;
		cb->args[CB_ARGS_DEV_IDX] = 0;
	} else {
		cb->args[CB_ARGS_DEV_IDX] = i;
	}
	return (int)skb->len;
}

int ubcore_get_uvs_init_res_start(struct netlink_callback *cb)
{
	struct ubcore_device **dev_list = NULL;
	uint32_t dev_cnt;

	dev_list = ubcore_get_all_mue_device(UBCORE_TRANSPORT_UB, &dev_cnt);
	ubcore_log_info("init_res :%u start.\n", dev_cnt);

	cb->args[CB_ARGS_DEV_LIST] = (long)dev_list;
	cb->args[CB_ARGS_DEV_CNT] = dev_cnt;
	cb->args[CB_ARGS_DEV_IDX] = 0;
	cb->args[CB_ARGS_SIP_IDX] = 0;
	cb->args[CB_ARGS_INFO_TYPE] = 0;
	cb->args[CB_ARGS_SIP_IDX] = 0;
	return 0;
}

int ubcore_get_uvs_init_res_dump(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	long info_type = cb->args[CB_ARGS_INFO_TYPE];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	int ret = 0;

	if (dev_cnt <= 0)
		return 0;
	if (info_type == 0)
		ret = ubcore_get_mue_dev_dump(skb, cb);

	ubcore_log_info("init_res ret:%d.\n", ret);
	return ret;
}

int ubcore_get_uvs_init_res_done(struct netlink_callback *cb)
{
	struct ubcore_device **dev_list =
		(struct ubcore_device **)cb->args[CB_ARGS_DEV_LIST];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	long i;

	for (i = 0; i < dev_cnt; ++i)
		if (dev_list[i] != NULL)
			ubcore_put_device(dev_list[i]);

	kfree(dev_list);
	ubcore_log_info("init_res done.\n");
	return 0;
}

static void ubcore_nl_msg_queue_pop_task(struct work_struct *work)
{
	struct delayed_work *delay_work =
		container_of(work, struct delayed_work, work);

	kfree(delay_work);
}

static int ubcore_insert_nl_msg_queue_pop_task(uint32_t wait_time)
{
	struct delayed_work *delay_work =
		kzalloc(sizeof(struct delayed_work), GFP_ATOMIC);

	if (delay_work == NULL)
		return -ENOMEM;

	INIT_DELAYED_WORK(delay_work, ubcore_nl_msg_queue_pop_task);
	if (ubcore_queue_delayed_work((int)UBCORE_NLMSG_WQ, delay_work,
				      wait_time) != 0) {
		ubcore_log_err("Fail to insert nl msg queue pop task.\n");
		kfree(delay_work);
		return -1;
	}
	return 0;
}

