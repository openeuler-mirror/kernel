// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
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
#include "ubcore_netdev.h"
#include "ubcore_device.h"
#include "ubcore_genl_define.h"
#include "ubcore_netlink.h"

#define UBCORE_NL_INVALID_PORT 0
#define CB_ARGS_DEV_LIST  0
#define CB_ARGS_DEV_CNT 1
#define CB_ARGS_DEV_IDX 2
#define CB_ARGS_SIP_IDX 3
#define CB_ARGS_INFO_TYPE 4

static LIST_HEAD(g_nl_session_list);
static DEFINE_SPINLOCK(g_nl_session_lock);
static atomic_t g_nlmsg_seq;
static uint32_t g_genl_port = UBCORE_NL_INVALID_PORT; /* get genl pid */
static struct sock *g_genl_sock;

static uint32_t ubcore_get_nlmsg_seq(void)
{
	return atomic_inc_return(&g_nlmsg_seq);
}

struct ubcore_nlmsg *ubcore_alloc_nlmsg(size_t payload_len,
	const union ubcore_eid *src_eid, const union ubcore_eid *dst_eid)
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

static struct ubcore_nl_session *ubcore_create_nl_session(struct ubcore_device *dev,
	struct ubcore_nlmsg *req)
{
	struct ubcore_nl_session *s;
	unsigned long flags;

	s = kzalloc(sizeof(struct ubcore_nl_session), GFP_KERNEL);
	if (s == NULL)
		return NULL;

	s->req = req;
	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_add_tail(&s->node, &g_nl_session_list);
	spin_unlock_irqrestore(&g_nl_session_lock, flags);
	kref_init(&s->kref);
	init_completion(&s->comp);
	(void)strncpy(s->dev_name, dev->dev_name, strlen(dev->dev_name));

	return s;
}

static void ubcore_free_nl_session(struct kref *kref)
{
	struct ubcore_nl_session *s = container_of(kref, struct ubcore_nl_session, kref);
	unsigned long flags;

	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_del(&s->node);
	spin_unlock_irqrestore(&g_nl_session_lock, flags);
	kfree(s);
}

static inline void ubcore_destroy_nl_session(struct ubcore_nl_session *s)
{
	(void)kref_put(&s->kref, ubcore_free_nl_session);
}

static struct ubcore_nl_session *ubcore_find_nl_session(uint32_t nlmsg_seq)
{
	struct ubcore_nl_session *tmp, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_nl_session_lock, flags);
	list_for_each_entry(tmp, &g_nl_session_list, node) {
		if (tmp->req->nlmsg_seq == nlmsg_seq) {
			target = tmp;
			kref_get(&target->kref);
			break;
		}
	}
	spin_unlock_irqrestore(&g_nl_session_lock, flags);
	return target;
}

static struct ubcore_nlmsg *ubcore_get_genlmsg_data(struct genl_info *info)
{
	struct ubcore_nlmsg *msg;
	uint32_t payload_len = 0;

	if (!info->attrs[UBCORE_MSG_SEQ] || !info->attrs[UBCORE_PAYLOAD_LEN])
		return NULL;

	payload_len = nla_get_u32(info->attrs[UBCORE_PAYLOAD_LEN]);
	msg = kzalloc((size_t)(sizeof(struct ubcore_nlmsg) + payload_len), GFP_KERNEL);
	if (msg == NULL)
		return NULL;

	msg->payload_len = payload_len;
	msg->nlmsg_seq = nla_get_u32(info->attrs[UBCORE_MSG_SEQ]);
	if (info->attrs[UBCORE_MSG_TYPE])
		msg->msg_type = nla_get_u32(info->attrs[UBCORE_MSG_TYPE]);

	if (info->attrs[UBCORE_TRANSPORT_TYPE])
		msg->transport_type = (enum ubcore_transport_type)
		nla_get_u32(info->attrs[UBCORE_TRANSPORT_TYPE]);

	if (info->attrs[UBORE_SRC_ID])
		(void)memcpy(&msg->src_eid,
		nla_data(info->attrs[UBORE_SRC_ID]), UBCORE_EID_SIZE);

	if (info->attrs[UBORE_DST_ID])
		(void)memcpy(&msg->dst_eid,
		nla_data(info->attrs[UBORE_DST_ID]), UBCORE_EID_SIZE);

	if (info->attrs[UBCORE_PAYLOAD_DATA]) {
		(void)memcpy(msg->payload,
		nla_data(info->attrs[UBCORE_PAYLOAD_DATA]), payload_len);
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
		return -1;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return -1;
	}
	s->resp = resp;
	(void)kref_put(&s->kref, ubcore_free_nl_session);
	complete(&s->comp);
	return 0;
}

int ubcore_genl_unicast(struct ubcore_nlmsg *req, uint32_t len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;

	if (req == NULL || g_genl_port == UBCORE_NL_INVALID_PORT) {
		ubcore_log_err("There are illegal parameters.\n");
		return -1;
	}

	/* create sk_buff */
	nl_skb = genlmsg_new(NLMSG_DEFAULT_SIZE,  GFP_KERNEL);
	if (nl_skb == NULL) {
		ubcore_log_err("failed to alloc.\n");
		return -1;
	}
	/* set genl head */
	nlh = genlmsg_put(nl_skb, g_genl_port, req->nlmsg_seq, &ubcore_genl_family, 0,
		(uint8_t)req->msg_type);
	if (nlh == NULL) {
		ubcore_log_err("Failed to nlmsg put.\n");
		nlmsg_free(nl_skb);
		return -1;
	}
	if (nla_put_u32(nl_skb, UBCORE_MSG_SEQ, req->nlmsg_seq) ||
		nla_put_u32(nl_skb, UBCORE_MSG_TYPE, (uint32_t)req->msg_type) ||
		nla_put_u32(nl_skb, UBCORE_TRANSPORT_TYPE, (uint32_t)req->transport_type) ||
		nla_put_u32(nl_skb, UBCORE_PAYLOAD_LEN, req->payload_len) ||
		nla_put(nl_skb, UBCORE_PAYLOAD_DATA, (int)req->payload_len, req->payload)) {
		nlmsg_free(nl_skb);
		return -1;
	}

	genlmsg_end(nl_skb, nlh);
	ubcore_log_info("send genl msg type %d seq:%u payload_len %u",
		(int)req->msg_type, req->nlmsg_seq, req->payload_len);
	return nlmsg_unicast(g_genl_sock, nl_skb, g_genl_port);
}

int ubcore_tp_req_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_nlmsg *resp = NULL;
	struct ubcore_nlmsg *req;

	req = ubcore_get_genlmsg_data(info);
	if (req == NULL) {
		ubcore_log_err("Failed to calloc and copy req");
		return -1;
	}
	if (req->msg_type == UBCORE_CMD_RESTORE_TP_REQ)
		resp = ubcore_handle_restore_tp_req(req);

	if (resp == NULL) {
		ubcore_log_err("Failed to handle tp req");
		kfree(req);
		return -1;
	}
	if (ubcore_genl_unicast(resp, ubcore_nlmsg_len(resp)) != 0)
		ubcore_log_err("Failed to send response");

	kfree(req);
	kfree(resp);
	return 0;
}

int ubcore_tpf2fe_resp_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;
	struct ubcore_device *dev;

	resp = ubcore_get_genlmsg_data(info);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return -1;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return -1;
	}
	s->resp = resp;
	(void)kref_put(&s->kref, ubcore_free_nl_session);

	dev = ubcore_find_device_with_name(s->dev_name);
	if (dev != NULL) {
		s->cb.user_arg = (void *)dev;
		s->cb.callback(resp, s->cb.user_arg);
	}
	ubcore_put_device(dev);

	kfree(s->req);
	kfree(s->resp);
	ubcore_destroy_nl_session(s);
	return 0;
}

int ubcore_update_tpf_dev_info_resp_ops(struct sk_buff *skb, struct genl_info *info)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;

	resp = ubcore_get_genlmsg_data(info);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return -1;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return -1;
	}
	s->resp = resp;
	(void)kref_put(&s->kref, ubcore_free_nl_session);
	complete(&s->comp);
	return 0;
}

static struct ubcore_nlmsg *ubcore_get_migrate_vtp_req(struct ubcore_vtp *vtp,
	enum ubcore_event_type event_type, struct ubcore_device *dev)
{
	uint32_t payload_len = (uint32_t)sizeof(struct ubcore_migrate_vtp_req);
	struct ubcore_migrate_vtp_req *mig_req;
	struct ubcore_nlmsg *req;

	req = ubcore_alloc_nlmsg(payload_len, &vtp->cfg.local_eid, &vtp->cfg.peer_eid);
	if (req == NULL)
		return NULL;

	req->transport_type = UBCORE_TRANSPORT_UB;
	if (event_type == UBCORE_EVENT_MIGRATE_VTP_SWITCH) {
		req->msg_type = UBCORE_CMD_MIGRATE_VTP_SWITCH;
	} else if (event_type == UBCORE_EVENT_MIGRATE_VTP_ROLLBACK) {
		req->msg_type = UBCORE_CMD_MIGRATE_VTP_ROLLBACK;
	} else {
		kfree(req);
		ubcore_log_err("wrong event msg type");
		return NULL;
	}
	mig_req = (struct ubcore_migrate_vtp_req *)(void *)req->payload;
	(void)memcpy(mig_req->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);

	mig_req->vtp_cfg.fe_idx = vtp->cfg.fe_idx;
	mig_req->vtp_cfg.vtpn = vtp->cfg.vtpn;
	mig_req->vtp_cfg.local_jetty = vtp->cfg.local_jetty;
	mig_req->vtp_cfg.local_eid = vtp->cfg.local_eid;
	mig_req->vtp_cfg.peer_eid = vtp->cfg.peer_eid;
	mig_req->vtp_cfg.peer_jetty = vtp->cfg.peer_jetty;
	mig_req->vtp_cfg.flag = vtp->cfg.flag;
	mig_req->vtp_cfg.trans_mode = vtp->cfg.trans_mode;

	return req;
}

void ubcore_report_migrate_vtp(struct ubcore_device *dev, struct ubcore_vtp *vtp,
	enum ubcore_event_type event_type)
{
	struct ubcore_nlmsg *req_msg;
	int ret;

	req_msg = ubcore_get_migrate_vtp_req(vtp, event_type, dev);
	if (req_msg == NULL) {
		ubcore_log_err("Failed to get migrate vtp switch req");
		return;
	}

	ret = ubcore_nl_send_nowait_without_cb(req_msg);
	if (ret)
		ubcore_log_err("Failed to nowait send migrate vtp request");
	else
		ubcore_log_info("Success to nowait send migrate vtp request");

	kfree(req_msg);
}

struct ubcore_nlmsg *ubcore_nl_send_wait(struct ubcore_device *dev, struct ubcore_nlmsg *req)
{
	unsigned long leavetime;
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();
	s = ubcore_create_nl_session(dev, req);
	if (s == NULL) {
		ubcore_log_err("Failed to create nl session");
		return NULL;
	}

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req));
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		ubcore_destroy_nl_session(s);
		return NULL;
	}

	leavetime = wait_for_completion_timeout(&s->comp, msecs_to_jiffies(UBCORE_TIMEOUT));
	if (leavetime == 0) {
		ubcore_log_err("Failed to wait reply, ret: %d, leavetime: %lu\n", ret, leavetime);
		ubcore_destroy_nl_session(s);
		return NULL;
	}
	resp = s->resp;
	ubcore_destroy_nl_session(s);
	return resp;
}

int ubcore_nl_send_nowait(struct ubcore_device *dev, struct ubcore_nlmsg *req,
	struct ubcore_nl_resp_cb *cb)
{
	struct ubcore_nl_session *s;
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();
	s = ubcore_create_nl_session(dev, req);
	if (s == NULL) {
		ubcore_log_err("Failed to create nl session");
		return -ENOMEM;
	}
	s->cb = *cb;

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req));
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		ubcore_destroy_nl_session(s);
		return -EIO;
	}

	return 0;
}

int ubcore_nl_send_nowait_without_cb(struct ubcore_nlmsg *req)
{
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();

	ret = ubcore_genl_unicast(req, ubcore_nlmsg_len(req));
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		return -EIO;
	}

	return 0;
}

bool ubcore_get_netlink_valid(void)
{
	if (g_genl_port == UBCORE_NL_INVALID_PORT)
		ubcore_log_warn("The nelink service is not established well");
	return g_genl_port != UBCORE_NL_INVALID_PORT;
}

static int ubcore_set_genl_nla(struct sk_buff *skb, struct ubcore_nlmsg *req_msg)
{
	if (nla_put_u32(skb, UBCORE_MSG_SEQ, req_msg->nlmsg_seq) ||
		nla_put_u32(skb, UBCORE_MSG_TYPE, (uint32_t)req_msg->msg_type) ||
		nla_put_u32(skb, UBCORE_TRANSPORT_TYPE, (uint32_t)req_msg->transport_type) ||
		nla_put_u32(skb, UBCORE_PAYLOAD_LEN, req_msg->payload_len) ||
		nla_put(skb, UBCORE_PAYLOAD_DATA, (int)req_msg->payload_len, req_msg->payload))
		return -1;

	return 0;
}

static int ubcore_dump_genl_info(struct sk_buff *skb, struct netlink_callback *cb,
	struct ubcore_nlmsg *req_msg)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, &ubcore_genl_family,
			  NLM_F_MULTI, (uint8_t)req_msg->msg_type);
	if (!hdr)
		return -ENOMEM;

	if (ubcore_set_genl_nla(skb, req_msg)) {
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, hdr);
	return 0;
}

static int ubcore_dev_sip_info(struct sk_buff *skb, struct netlink_callback *cb,
	struct ubcore_device *dev)
{
	long i = cb->args[CB_ARGS_SIP_IDX];
	struct ubcore_sip_table *sip_table;
	struct ubcore_nlmsg *req_msg;
	struct ubcore_sip_info *sip;
	uint32_t max_cnt;
	int ret;

	sip_table = &dev->sip_table;
	mutex_lock(&sip_table->lock);
	max_cnt = sip_table->max_sip_cnt;
	for (; i < max_cnt; i++) {
		sip = &sip_table->entry[i];
		if (!sip->is_active)
			continue;
		req_msg = ubcore_new_sip_req_msg(dev, sip, (uint32_t)(unsigned long)i);
		if (req_msg == NULL) {
			ubcore_log_warn("failed to get sip info %s", dev->dev_name);
			continue;
		}
		ret = ubcore_dump_genl_info(skb, cb, req_msg);
		kfree(req_msg);
		if (ret != 0) {
			mutex_unlock(&sip_table->lock);
			return -1;
		}
		cb->args[CB_ARGS_SIP_IDX] = i;
	}
	mutex_unlock(&sip_table->lock);

	if (i == max_cnt)
		cb->args[CB_ARGS_SIP_IDX] = 0;
	return 0;
}

static int ubcore_get_sip_info_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ubcore_device **dev_list = (struct ubcore_device **)cb->args[CB_ARGS_DEV_LIST];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	long i = cb->args[CB_ARGS_DEV_IDX];

	for (; i < dev_cnt; ++i) {
		if (ubcore_dev_sip_info(skb, cb, dev_list[i])) {
			--i;
			break;
		}
	}
	cb->args[CB_ARGS_DEV_IDX] = i;
	return (int)skb->len;
}

static int ubcore_get_tpf_dev_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ubcore_device **dev_list = (struct ubcore_device **)cb->args[CB_ARGS_DEV_LIST];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	long i = cb->args[CB_ARGS_DEV_IDX];
	struct ubcore_nlmsg *req_msg;
	int ret;

	for (; i < dev_cnt; ++i) {
		req_msg = ubcore_new_tpf_dev_msg(dev_list[i]);
		if (req_msg == NULL) {
			ubcore_log_warn("failed to get tpf dev info %s", dev_list[i]->dev_name);
			continue;
		}
		ret = ubcore_dump_genl_info(skb, cb, req_msg);
		kfree(req_msg);
		if (ret != 0) {
			--i;
			break;
		}
		ubcore_log_info("dump dev :%s success.\n", dev_list[i]->dev_name);
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

	dev_list = ubcore_get_all_tpf_device(UBCORE_TRANSPORT_UB, &dev_cnt);
	ubcore_log_info("init_res :%u start.\n", dev_cnt);

	cb->args[CB_ARGS_DEV_LIST] = (long)dev_list;
	cb->args[CB_ARGS_DEV_CNT] = dev_cnt;
	cb->args[CB_ARGS_DEV_IDX] = 0;
	cb->args[CB_ARGS_SIP_IDX] = 0;
	cb->args[CB_ARGS_INFO_TYPE] = 0;
	cb->args[CB_ARGS_SIP_IDX] = 0;
	return 0;
}

int ubcore_get_uvs_init_res_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	long info_type = cb->args[CB_ARGS_INFO_TYPE];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	int ret;

	if (dev_cnt <= 0)
		return 0;
	if (info_type == 0)
		ret = ubcore_get_tpf_dev_dump(skb, cb);
	else
		ret = ubcore_get_sip_info_dump(skb, cb);
	ubcore_log_info("init_res ret:%d.\n", ret);
	return ret;
}

int ubcore_get_uvs_init_res_done(struct netlink_callback *cb)
{
	struct ubcore_device **dev_list = (struct ubcore_device **)cb->args[CB_ARGS_DEV_LIST];
	long dev_cnt = cb->args[CB_ARGS_DEV_CNT];
	long i;

	for (i = 0; i < dev_cnt; ++i)
		if (dev_list[i] != NULL)
			ubcore_put_device(dev_list[i]);

	kfree(dev_list);
	ubcore_log_info("init_res done.\n");
	return 0;
}

int ubcore_set_genl_pid_ops(struct sk_buff *skb, struct genl_info *info)
{
	g_genl_port = info->snd_portid;
	g_genl_sock = genl_info_net(info)->genl_sock;
	ubcore_log_info("set_port :%u success.\n", g_genl_port);
	return 0;
}
