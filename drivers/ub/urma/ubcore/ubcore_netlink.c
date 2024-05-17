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
#include "ubcore_netlink.h"

#define UBCORE_NL_TYPE 24 /* same with agent netlink type */
#define UBCORE_NL_INVALID_PORT 0

static struct sock *nl_sock;
static LIST_HEAD(g_nl_session_list);
static DEFINE_SPINLOCK(g_nl_session_lock);
static atomic_t g_nlmsg_seq;
static uint32_t g_agent_port = UBCORE_NL_INVALID_PORT; /* get agent pid */

static int ubcore_nl_unicast(struct ubcore_nlmsg *pbuf, uint32_t len);

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
	kref_put(&s->kref, ubcore_free_nl_session);
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

static struct ubcore_nlmsg *ubcore_get_nlmsg_data(struct nlmsghdr *nlh)
{
	struct ubcore_nlmsg *msg;

	msg = kzalloc(nlmsg_len(nlh), GFP_KERNEL);
	if (msg == NULL)
		return NULL;

	(void)memcpy(msg, nlmsg_data(nlh), nlmsg_len(nlh));
	return msg;
}

static void ubcore_nl_handle_tp_resp(struct nlmsghdr *nlh)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;

	resp = ubcore_get_nlmsg_data(nlh);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return;
	}
	s->resp = resp;
	kref_put(&s->kref, ubcore_free_nl_session);
	complete(&s->comp);
}

static void ubcore_nl_handle_tp_req(struct nlmsghdr *nlh)
{
	struct ubcore_nlmsg *resp = NULL;
	struct ubcore_nlmsg *req;

	req = ubcore_get_nlmsg_data(nlh);
	if (req == NULL) {
		ubcore_log_err("Failed to calloc and copy req");
		return;
	}
	if (nlh->nlmsg_type == UBCORE_NL_CREATE_TP_REQ)
		resp = ubcore_handle_create_tp_req(req);
	else if (nlh->nlmsg_type == UBCORE_NL_DESTROY_TP_REQ)
		resp = ubcore_handle_destroy_tp_req(req);
	else if (nlh->nlmsg_type == UBCORE_NL_RESTORE_TP_REQ)
		resp = ubcore_handle_restore_tp_req(req);

	if (resp == NULL) {
		ubcore_log_err("Failed to handle tp req");
		kfree(req);
		return;
	}
	if (ubcore_nl_unicast(resp, ubcore_nlmsg_len(resp)) != 0)
		ubcore_log_err("Failed to send response");

	kfree(req);
	kfree(resp);
}

static void ubcore_nl_handle_tpf2fe_resp(struct nlmsghdr *nlh)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;
	struct ubcore_device *dev;

	resp = ubcore_get_nlmsg_data(nlh);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return;
	}
	s->resp = resp;
	kref_put(&s->kref, ubcore_free_nl_session);

	dev = ubcore_find_device_with_name(s->dev_name);
	if (dev != NULL) {
		s->cb.user_arg = (void *)dev;
		s->cb.callback(resp, s->cb.user_arg);
	}
	ubcore_put_device(dev);

	kfree(s->req);
	kfree(s->resp);
	ubcore_destroy_nl_session(s);
}

static void ubcore_nl_handle_update_tpf_dev_info_resp(struct nlmsghdr *nlh)
{
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;

	resp = ubcore_get_nlmsg_data(nlh);
	if (resp == NULL) {
		ubcore_log_err("Failed to calloc and copy response");
		return;
	}
	s = ubcore_find_nl_session(resp->nlmsg_seq);
	if (s == NULL) {
		ubcore_log_err("Failed to find nl session with seq %u", resp->nlmsg_seq);
		kfree(resp);
		return;
	}
	s->resp = resp;
	kref_put(&s->kref, ubcore_free_nl_session);
	complete(&s->comp);
}

static void ubcore_sync_tpf_dev_info(void)
{
	if (ubcore_query_all_device_tpf_dev_info() != 0)
		ubcore_log_warn("Failed update tpf dev info after tpsa ready");
}

static void ubcore_nl_sync_table(void)
{
	ubcore_sync_tpf_dev_info();
	ubcore_sync_sip_table();
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
		req->msg_type = UBCORE_NL_MIGRATE_VTP_SWITCH;
	} else if (event_type == UBCORE_EVENT_MIGRATE_VTP_ROLLBACK) {
		req->msg_type = UBCORE_NL_MIGRATE_VTP_ROLLBACK;
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

static void ubcore_nl_cb_func(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);
	if (nlmsg_len(nlh) < (int)sizeof(struct ubcore_nlmsg) || skb->len < nlh->nlmsg_len) {
		ubcore_log_err("Invalid nl msg received");
		return;
	}

	switch (nlh->nlmsg_type) {
	case UBCORE_NL_CREATE_TP_REQ:
	case UBCORE_NL_DESTROY_TP_REQ:
	case UBCORE_NL_RESTORE_TP_REQ:
		ubcore_nl_handle_tp_req(nlh);
		break;
	case UBCORE_NL_CREATE_TP_RESP:
	case UBCORE_NL_DESTROY_TP_RESP:
	case UBCORE_NL_QUERY_TP_RESP:
	case UBCORE_NL_RESTORE_TP_RESP:
	case UBCORE_NL_ADD_SIP_RESP:
	case UBCORE_NL_DEL_SIP_RESP:
		ubcore_nl_handle_tp_resp(nlh);
		break;
	case UBCORE_NL_SET_AGENT_PID:
		g_agent_port = nlh->nlmsg_pid;
		ubcore_nl_sync_table();
		break;
	case UBCORE_NL_UPDATE_TPF_DEV_INFO_RESP:
		ubcore_nl_handle_update_tpf_dev_info_resp(nlh);
		break;
	case UBCORE_NL_TPF2FE_RESP:
		ubcore_nl_handle_tpf2fe_resp(nlh);
		break;
	case UBCORE_NL_FE2TPF_REQ:
	case UBCORE_NL_QUERY_TP_REQ:
	case UBCORE_NL_ADD_SIP_REQ:
	case UBCORE_NL_DEL_SIP_REQ:
	case UBCORE_NL_UPDATE_TPF_DEV_INFO_REQ:
	default:
		ubcore_log_err("Unexpected nl msg type: %d received\n", nlh->nlmsg_type);
		break;
	}
}

static int ubcore_nl_unicast(struct ubcore_nlmsg *pbuf, uint32_t len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	int ret;

	if (pbuf == NULL || g_agent_port == UBCORE_NL_INVALID_PORT) {
		ubcore_log_err("There are illegal parameters.\n");
		return -1;
	}

	/* create sk_buff */
	nl_skb = nlmsg_new(len, GFP_ATOMIC);
	if (nl_skb == NULL) {
		ubcore_log_err("failed to alloc.\n");
		return -1;
	}
	/* set netlink head */
	nlh = nlmsg_put(nl_skb, 0, pbuf->nlmsg_seq, pbuf->msg_type, len, 0);
	if (nlh == NULL) {
		ubcore_log_err("Failed to nlmsg put.\n");
		nlmsg_free(nl_skb);
		return -1;
	}
	/* copy msg */
	(void)memcpy(nlmsg_data(nlh), pbuf, len);
	ret = netlink_unicast(nl_sock, nl_skb, g_agent_port, 0);
	return ret < 0 ? ret : 0;
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

	ret = ubcore_nl_unicast(req, ubcore_nlmsg_len(req));
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

	ret = ubcore_nl_unicast(req, ubcore_nlmsg_len(req));
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

	ret = ubcore_nl_unicast(req, ubcore_nlmsg_len(req));
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		return -EIO;
	}

	return 0;
}

bool ubcore_get_netlink_valid(void)
{
	if (g_agent_port == UBCORE_NL_INVALID_PORT)
		ubcore_log_warn("The nelink service is not established well");
	return g_agent_port != UBCORE_NL_INVALID_PORT;
}


static int ubcore_netlink_notify(struct notifier_block *nb, unsigned long event, void *_notify)
{
	struct netlink_notify *notify = _notify;

	if (event != NETLINK_URELEASE || notify->protocol != UBCORE_NL_TYPE)
		return NOTIFY_DONE;

	ubcore_log_info("netlink release.\n");
	g_agent_port = UBCORE_NL_INVALID_PORT;

	return NOTIFY_OK;
}

static struct notifier_block ubcore_netlink_notifier = {
	.notifier_call = ubcore_netlink_notify,
};

int ubcore_netlink_init(void)
{
	/* create netlink socket */
	struct netlink_kernel_cfg cfg = {0};

	cfg.input = ubcore_nl_cb_func;

	nl_sock = (struct sock *)netlink_kernel_create(&init_net, UBCORE_NL_TYPE, &cfg);
	if (nl_sock == NULL) {
		ubcore_log_err("Netlink_kernel_create error.\n");
		return -1;
	}
	if (netlink_register_notifier(&ubcore_netlink_notifier) != 0) {
		ubcore_log_err("netlink_register_notifier error.\n");
		netlink_kernel_release(nl_sock);
		nl_sock = NULL;
		return -1;
	}
	return 0;
}

void ubcore_netlink_exit(void)
{
	(void)netlink_unregister_notifier(&ubcore_netlink_notifier);
	if (nl_sock != NULL) {
		netlink_kernel_release(nl_sock);
		nl_sock = NULL;
	}
}
