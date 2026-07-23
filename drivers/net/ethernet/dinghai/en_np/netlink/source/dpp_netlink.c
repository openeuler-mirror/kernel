// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <asm/types.h>
#include "dpp_netlink.h"

#define DPP_NETLINK_PROTOCOL ((u32)(29))
#define DPP_NETLINK_GROUP_ID ((u32)(1))
#define DPP_NETLINK_MAX_PROC ((u32)(2048))

typedef DPP_STATUS (*DPP_NETLINK_PROC_PTR)(void *msg_body, u32 msg_len, void **resp, u32 *reps_len);

static struct sock *dpp_netlink_sk;
static DPP_NETLINK_PROC_PTR dpp_netlink_proc_ptr[DPP_NETLINK_MAX_PROC] = { 0 };

static DPP_STATUS dpp_netlink_send_ack_msg(void *data, u32 len)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	s32 rtn = DPP_OK;

	if (!data) {
		ZXIC_COMM_PRINT("%s: data invalid.\n", __func__);
		return DPP_ERR;
	}

	skb = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
	if (!skb) {
		ZXIC_COMM_PRINT("%s: alloc_skb failed.\n", __func__);
		return DPP_ERR;
	}

	nlh = nlmsg_put(skb, 0, 0, 0, len, 0);
	if (!nlh) {
		ZXIC_COMM_PRINT("%s: nlmsg_put failed.\n", __func__);
		return DPP_ERR;
	}

	nlh->nlmsg_flags = NLM_F_ACK;
	memcpy(NLMSG_DATA(nlh), data, len);

	rtn = nlmsg_multicast(dpp_netlink_sk, skb, 0, DPP_NETLINK_GROUP_ID, 0);
	if (rtn < 0) {
		ZXIC_COMM_PRINT("%s: nlmsg_multicast failed, rtn %d.\n", __func__, rtn);
		return DPP_ERR;
	}
	return DPP_OK;
}

static DPP_STATUS dpp_netlink_dispach_msg(struct nlmsghdr *nlh)
{
	u8 *data = NULL;
	u32 id = 0;
	u32 len = 0;
	u8 *req = NULL;
	void *resp = NULL;
	u32 resp_len = 0;
	u32 rtn = DPP_OK;

	DPP_NETLINK_PROC_PTR ptr = NULL;

	if (!nlh) {
		ZXIC_COMM_PRINT("%s: nlh invalid.\n", __func__);
		return DPP_ERR;
	}

	id = *(u32 *)NLMSG_DATA(nlh);
	len = nlh->nlmsg_len - NLMSG_HDRLEN;
	req = (u8 *)NLMSG_DATA(nlh);
	if (id > (DPP_NETLINK_MAX_PROC - 1)) {
		ZXIC_COMM_PRINT("%s: id %u invalid.\n", __func__, id);
		return DPP_ERR;
	}

	ptr = dpp_netlink_proc_ptr[id];
	if (!ptr) {
		ZXIC_COMM_PRINT("%s: ptr invalid.\n", __func__);
		return DPP_ERR;
	}

	rtn = ptr(req, len, &resp, &resp_len);
	if (rtn != DPP_OK) {
		ZXIC_COMM_FREE(resp);
		ZXIC_COMM_PRINT("%s: proc id %u failed.\n", __func__, id);
		return rtn;
	}

	data = (u8 *)ZXIC_COMM_MALLOC(NLMSG_ALIGN(resp_len) + sizeof(u32));
	if (!data) {
		ZXIC_COMM_FREE(resp);
		ZXIC_COMM_PRINT("%s: ZXIC_COMM_MALLOC failed.\n", __func__);
		return DPP_ERR;
	}
	memcpy(data, &rtn, sizeof(u32));

	if (resp)
		memcpy(data + sizeof(u32), resp, resp_len);

	dpp_netlink_send_ack_msg(data, NLMSG_ALIGN(resp_len) + sizeof(u32));

	ZXIC_COMM_FREE(data);
	ZXIC_COMM_FREE(resp);

	return DPP_OK;
}

static void dpp_netlink_recv_msg(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	u32 rtn = DPP_ERR;

	skb = skb_get(__skb);
	if (!skb) {
		ZXIC_COMM_PRINT("%s: get skb failed.\n", __func__);
		return;
	}

	nlh = nlmsg_hdr(skb);
	if ((!nlh) || !NLMSG_OK(nlh, skb->len)) {
		kfree_skb(skb);
		ZXIC_COMM_PRINT("%s: skb format invalid.\n", __func__);
		return;
	}

	if ((nlh->nlmsg_flags & NLM_F_REQUEST) != 0) {
		if (dpp_netlink_dispach_msg(nlh) != DPP_OK) {
			dpp_netlink_send_ack_msg((u8 *)&rtn, sizeof(u32));
			ZXIC_COMM_PRINT("%s: dpp_netlink_dispach_msg failed.\n", __func__);
		}
		kfree_skb(skb);
		return;
	}

	kfree_skb(skb);
	ZXIC_COMM_PRINT("%s: nlmsg_flags 0x%04x invalid.\n", __func__, nlh->nlmsg_flags);
}

DPP_STATUS dpp_netlink_regist_msg_proc_fun(u32 id, void *ptr)
{
	if (!ptr) {
		ZXIC_COMM_PRINT("%s: ptr invalid.\n", __func__);
		return DPP_ERR;
	}
	if (id > (DPP_NETLINK_MAX_PROC - 1)) {
		ZXIC_COMM_PRINT("%s: id %u invalid.\n", __func__, id);
		return DPP_ERR;
	}
	dpp_netlink_proc_ptr[id] = ptr;
	return DPP_OK;
}

s32 dpp_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = dpp_netlink_recv_msg,
	};

	ZXIC_COMM_TRACE_NOTICE("[%s] start.\n", __func__);

	// dpp_netlink_sk = netlink_kernel_create(get_net_ns_by_pid(1), DPP_NETLINK_PROTOCOL, &cfg);
	dpp_netlink_sk = netlink_kernel_create(&init_net, DPP_NETLINK_PROTOCOL, &cfg);
	if (!dpp_netlink_sk) {
		ZXIC_COMM_PRINT("%s: create socket failed.\n", __func__);
		return DPP_ERR;
	}

	ZXIC_COMM_PRINT("[%s] success.\n", __func__);

	return DPP_OK;
}

void dpp_netlink_exit(void)
{
	ZXIC_COMM_TRACE_NOTICE("[%s] start.\n", __func__);
	netlink_kernel_release(dpp_netlink_sk);
	ZXIC_COMM_PRINT("[%s] success.\n", __func__);
}
