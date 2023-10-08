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
#include "ubcore_netlink.h"

#define UBCORE_NL_TYPE 24 /* same with agent netlink type */
#define UBCORE_NL_TIMEOUT 10000 /* 10s */
#define UBCORE_NL_INVALID_PORT 0

struct sock *nl_sock;
static uint32_t g_agent_port = UBCORE_NL_INVALID_PORT; /* get agent pid */

static void ubcore_nl_cb_func(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);
	if (nlmsg_len(nlh) < sizeof(struct ubcore_nlmsg) || skb->len < nlh->nlmsg_len) {
		ubcore_log_err("Invalid nl msg received");
		return;
	}

	switch (nlh->nlmsg_type) {
	case UBCORE_NL_SET_AGENT_PID:
		g_agent_port = nlh->nlmsg_pid;
		break;
	default:
		ubcore_log_err("Unexpected nl msg type: %d received\n", nlh->nlmsg_type);
		break;
	}
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
