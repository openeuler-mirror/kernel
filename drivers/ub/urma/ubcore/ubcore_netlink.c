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
#include "ubcore_netlink.h"

#define UBCORE_NL_TYPE 24 /* same with agent netlink type */
#define UBCORE_NL_TIMEOUT 10000 /* 10s */
#define UBCORE_NL_INVALID_PORT 0

struct sock *nl_sock;
static LIST_HEAD(g_nl_session_list);
static DEFINE_SPINLOCK(g_nl_session_lock);
atomic_t g_nlmsg_seq;
static uint32_t g_agent_port = UBCORE_NL_INVALID_PORT; /* get agent pid */

static int ubcore_nl_send(struct ubcore_nlmsg *pbuf, uint16_t len);

static uint32_t ubcore_get_nlmsg_seq(void)
{
	return atomic_inc_return(&g_nlmsg_seq);
}

static struct ubcore_nl_session *ubcore_create_nl_session(struct ubcore_nlmsg *req)
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
	if (ubcore_nl_send(resp, ubcore_nlmsg_len(resp)) != 0)
		ubcore_log_err("Failed to send response");

	kfree(req);
	kfree(resp);
}

static void ubcore_nl_cb_func(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);
	if (nlmsg_len(nlh) < sizeof(struct ubcore_nlmsg) || skb->len < nlh->nlmsg_len) {
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
		ubcore_nl_handle_tp_resp(nlh);
		break;
	case UBCORE_NL_SET_AGENT_PID:
		g_agent_port = nlh->nlmsg_pid;
		break;
	case UBCORE_NL_QUERY_TP_REQ:
	default:
		ubcore_log_err("Unexpected nl msg type: %d received\n", nlh->nlmsg_type);
		break;
	}
}

static int ubcore_nl_send(struct ubcore_nlmsg *pbuf, uint16_t len)
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

struct ubcore_nlmsg *ubcore_nl_send_wait(struct ubcore_nlmsg *req)
{
	unsigned long leavetime;
	struct ubcore_nl_session *s;
	struct ubcore_nlmsg *resp;
	int ret;

	req->nlmsg_seq = ubcore_get_nlmsg_seq();
	s = ubcore_create_nl_session(req);
	if (s == NULL) {
		ubcore_log_err("Failed to create nl session");
		return NULL;
	}

	ret = ubcore_nl_send(req, ubcore_nlmsg_len(req));
	if (ret != 0) {
		ubcore_log_err("Failed to send nl msg %d", ret);
		ubcore_destroy_nl_session(s);
		return NULL;
	}

	leavetime = wait_for_completion_timeout(&s->comp, msecs_to_jiffies(UBCORE_NL_TIMEOUT));
	if (leavetime == 0) {
		ubcore_log_err("Failed to wait reply, ret: %d, leavetime: %lu\n", ret, leavetime);
		ubcore_destroy_nl_session(s);
		return NULL;
	}
	resp = s->resp;
	ubcore_destroy_nl_session(s);
	return resp;
}

int ubcore_netlink_init(void)
{
	/* create netlink socket */
	struct netlink_kernel_cfg cfg = { .input = ubcore_nl_cb_func };

	nl_sock = (struct sock *)netlink_kernel_create(&init_net, UBCORE_NL_TYPE, &cfg);
	if (nl_sock == NULL) {
		ubcore_log_err("Netlink_kernel_create error.\n");
		return -1;
	}
	return 0;
}

void ubcore_netlink_exit(void)
{
	if (nl_sock != NULL) {
		netlink_kernel_release(nl_sock);
		nl_sock = NULL;
	}
}
