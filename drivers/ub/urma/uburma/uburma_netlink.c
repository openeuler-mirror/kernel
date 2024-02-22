// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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
 * Description: uburma netlink implementation
 * Author: Yan Fangfang
 * Create: 2023-12-06
 * Note:
 * History: 2023-12-06: create file
 */

#include <net/sock.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/list.h>
#include "uburma_log.h"
#include "uburma_main.h"
#include "uburma_netlink.h"

#define UBURMA_NL_TYPE 25 /* same with urma admin netlink type */

static struct sock *g_uburma_nl_sock;

static int uburma_nl_reply(struct nlmsghdr *req, struct uburma_nl_resp *resp, uint32_t pid)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	int ret;

	nl_skb = nlmsg_new(NLMSG_ALIGN(sizeof(struct uburma_nl_resp)), GFP_ATOMIC);
	if (nl_skb == NULL) {
		uburma_log_err("failed to alloc.\n");
		return -1;
	}

	nlh = nlmsg_put(nl_skb, pid, req->nlmsg_seq, req->nlmsg_type,
		sizeof(struct uburma_nl_resp), 0);
	if (nlh == NULL) {
		nlmsg_free(nl_skb);
		uburma_log_err("Failed to nlmsg put.\n");
		return -1;
	}

	memcpy(nlmsg_data(nlh), resp, sizeof(struct uburma_nl_resp));
	ret = netlink_unicast(g_uburma_nl_sock, nl_skb, pid, 0);
	return ret < 0 ? ret : 0;
}

static void uburma_nl_handle_set_ns_mode(struct nlmsghdr *nlh, uint32_t pid)
{
	struct uburma_nl_set_ns_mode *msg = nlmsg_data(nlh);
	bool ns_mode = (msg->ns_mode == 0 ? false : true);
	struct uburma_nl_resp resp = {0};

	if (nlmsg_len(nlh) < sizeof(struct uburma_nl_set_ns_mode)) {
		resp.ret = -1;
		(void)uburma_nl_reply(nlh, &resp, pid);
		uburma_log_err("Invalid nl msg received");
		return;
	}
	resp.ret = uburma_set_ns_mode(ns_mode);
	(void)uburma_nl_reply(nlh, &resp, pid);
}

static void uburma_nl_handle_set_dev_ns(struct nlmsghdr *nlh, uint32_t pid)
{
	struct uburma_nl_set_dev_ns *msg = nlmsg_data(nlh);
	struct uburma_nl_resp resp = {0};

	if (nlmsg_len(nlh) < sizeof(struct uburma_nl_set_dev_ns)) {
		resp.ret = -1;
		(void)uburma_nl_reply(nlh, &resp, pid);
		uburma_log_err("Invalid nl msg received");
		return;
	}
	resp.ret = uburma_set_dev_ns(msg->dev_name, msg->ns_fd);
	(void)uburma_nl_reply(nlh, &resp, pid);
}

static void uburma_nl_cb_func(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	uint32_t pid; /* portid */

	nlh = nlmsg_hdr(skb);
	if (skb->len < nlh->nlmsg_len) {
		uburma_log_err("Invalid nl msg received");
		return;
	}

	pid = NETLINK_CB(skb).portid;
	switch (nlh->nlmsg_type) {
	case UBURMA_NL_SET_NS_MODE:
		uburma_nl_handle_set_ns_mode(nlh, pid);
		break;
	case UBURMA_NL_SET_DEV_NS:
		uburma_nl_handle_set_dev_ns(nlh, pid);
		break;
	default:
		uburma_log_err("Unexpected nl msg type: %d received\n", nlh->nlmsg_type);
		break;
	}
}

int uburma_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {0};

	cfg.input = uburma_nl_cb_func;
	g_uburma_nl_sock = (struct sock *)netlink_kernel_create(&init_net, UBURMA_NL_TYPE, &cfg);
	if (g_uburma_nl_sock == NULL) {
		uburma_log_err("Netlink_kernel_create error.\n");
		return -1;
	}
	return 0;
}

void uburma_netlink_exit(void)
{
	if (g_uburma_nl_sock != NULL) {
		netlink_kernel_release(g_uburma_nl_sock);
		g_uburma_nl_sock = NULL;
	}
}
