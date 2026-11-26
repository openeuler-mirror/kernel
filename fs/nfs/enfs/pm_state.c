// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include "pm_state.h"
#include <linux/sunrpc/xprt.h>

#include "enfs.h"
#include "enfs_log.h"

enum enfs_path_state pm_get_path_state(struct rpc_xprt *xprt)
{
	struct enfs_xprt_context *ctx = NULL;
	enum enfs_path_state state;

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return PM_STATE_UNDEFINED;
	}

	xprt_get(xprt);

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		xprt_put(xprt);
		return PM_STATE_UNDEFINED;
	}

	state = atomic_read(&ctx->path_state);

	xprt_put(xprt);

	return state;
}

static int sockaddr_ip_to_str(struct sockaddr *addr, char *buf, int len)
{
	if (!addr)
		return 0;
	switch (addr->sa_family) {
	case AF_INET:{
			struct sockaddr_in *sin = (struct sockaddr_in *)addr;

			snprintf(buf, len, "%pI4", &sin->sin_addr);
			return 0;
		}
	case AF_INET6:{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

			snprintf(buf, len, "%pI6", &sin6->sin6_addr);
			return 0;
		}
	default:
		break;
	}
	return 1;
}

static bool is_valid_ip_address(const char *ip_str)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (in4_pton(ip_str, -1, (u8 *) &addr4, '\0', NULL) == 1)
		return true;

	if (in6_pton(ip_str, -1, (u8 *) &addr6, '\0', NULL) == 1)
		return true;

	return false;
}

void pm_set_path_state(struct rpc_xprt *xprt, enum enfs_path_state state)
{
	struct enfs_xprt_context *ctx = NULL;
	enum enfs_path_state cur_state;
	char localip[64] = { "*" };
	char remoteip[64] = { "*" };
	struct sockaddr_storage srcaddr = {};
	char local_name[INET6_ADDRSTRLEN] = {};
	const char *local = local_name;
	int ret;

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return;
	}

	xprt_get(xprt);

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		goto out;
	}

	cur_state = atomic_read(&ctx->path_state);
	if (cur_state == state)
		goto out;

	atomic_set(&ctx->path_state, state);
	ret =
		sockaddr_ip_to_str((struct sockaddr *)&xprt->addr, remoteip,
				   sizeof(remoteip));

	sockaddr_ip_to_str((struct sockaddr *)&ctx->srcaddr, local_name,
			   sizeof(local_name));
	if (!is_valid_ip_address(local)) {
		ret =
			rpc_localalladdr(xprt, (struct sockaddr *)&srcaddr,
					 sizeof(srcaddr));

		if (!ret)
			sockaddr_ip_to_str((struct sockaddr *)&srcaddr, localip,
					   sizeof(localip));
	} else {
		sockaddr_ip_to_str((struct sockaddr *)&ctx->srcaddr, localip,
				   sizeof(localip));
	}
	enfs_log_info
		("The xprt localip{%s} remoteip{%s} path state change from {%d} to {%d}.\n",
		 localip, remoteip, cur_state, state);

out:
	xprt_put(xprt);
}

void pm_get_path_state_desc(struct rpc_xprt *xprt, char *buf, int len)
{
	enum enfs_path_state state;

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return;
	}

	if ((buf == NULL) || (len <= 0)) {
		enfs_log_error("Buffer is not valid, len=%d.\n", len);
		return;
	}

	state = pm_get_path_state(xprt);

	switch (state) {
	case PM_STATE_INIT:
		(void)snprintf(buf, len, "Init");
		break;
	case PM_STATE_NORMAL:
		(void)snprintf(buf, len, "Normal");
		break;
	case PM_STATE_UNSTABLE:
		(void)snprintf(buf, len, "Unstable");
		break;
	case PM_STATE_FAULT:
		(void)snprintf(buf, len, "Fault");
		break;
	default:
		(void)snprintf(buf, len, "Unknown");
		break;
	}

}

void pm_get_xprt_state_desc(struct rpc_xprt *xprt, char *buf, int len)
{
	int i;
	unsigned long state;
	static unsigned long xprt_mask[] = { XPRT_LOCKED,     XPRT_CONNECTED,
					     XPRT_CONNECTING, XPRT_CLOSE_WAIT,
					     XPRT_BOUND,      XPRT_BINDING,
					     XPRT_CLOSING,    XPRT_CONGESTED };
	static const char * const xprt_state_desc[] = { "LOCKED",     "CONNECTED",
						 "CONNECTING", "CLOSE_WAIT",
						 "BOUND",      "BINDING",
						 "CLOSING",    "CONGESTED" };
	int pos = 0;
	int ret = 0;

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return;
	}

	if ((buf == NULL) || (len <= 0)) {
		enfs_log_error("Xprt state buffer is not valid, len=%d.\n",
				   len);
		return;
	}

	xprt_get(xprt);
	state = READ_ONCE(xprt->state);
	xprt_put(xprt);

	for (i = 0; i < ARRAY_SIZE(xprt_mask); ++i) {
		if (pos >= len)
			break;

		if (!test_bit(xprt_mask[i], &state))
			continue;

		if (pos == 0)
			ret = snprintf(buf, len, "%s", xprt_state_desc[i]);
		else
			ret =
				snprintf(buf + pos, len - pos, "|%s",
					 xprt_state_desc[i]);

		if (ret < 0) {
			enfs_log_error("format state failed, ret %d.\n", ret);
			break;
		}

		pos += ret;
	}

}
