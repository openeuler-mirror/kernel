/* SPDX-License-Identifier: GPL-2.0 */
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
 * Description: ubcore netlink head file
 * Author: Chen Wen
 * Create: 2022-08-27
 * Note:
 * History: 2022-08-27: Create file
 */

#ifndef UBCORE_NETLINK_H
#define UBCORE_NETLINK_H

#include <linux/netlink.h>
#include <urma/ubcore_types.h>

enum ubcore_nl_resp_status { UBCORE_NL_RESP_FAIL = -1, UBCORE_NL_RESP_SUCCESS = 0 };

enum ubcore_nlmsg_type {
	UBCORE_NL_CREATE_TP_REQ = NLMSG_MIN_TYPE, /* 0x10 */
	UBCORE_NL_CREATE_TP_RESP,
	UBCORE_NL_DESTROY_TP_REQ,
	UBCORE_NL_DESTROY_TP_RESP,
	UBCORE_NL_QUERY_TP_REQ,
	UBCORE_NL_QUERY_TP_RESP,
	UBCORE_NL_RESTORE_TP_REQ,
	UBCORE_NL_RESTORE_TP_RESP,
	UBCORE_NL_SET_AGENT_PID
};

struct ubcore_nlmsg {
	uint32_t nlmsg_seq;
	enum ubcore_nlmsg_type msg_type;
	enum ubcore_transport_type transport_type;
	union ubcore_eid src_eid;
	union ubcore_eid dst_eid;
	uint32_t payload_len;
	uint8_t payload[0];
} __packed;

struct ubcore_ta_data {
	enum ubcore_ta_type type;
	struct ubcore_jetty_id jetty_id; /* local jetty id */
	struct ubcore_jetty_id tjetty_id; /* peer jetty id */
};

struct ubcore_multipath_tp_cfg {
	union ubcore_tp_flag flag;
	uint16_t data_rctp_start;
	uint16_t ack_rctp_start;
	uint16_t data_rmtp_start;
	uint16_t ack_rmtp_start;
	uint8_t tp_range;
	uint16_t congestion_alg;
};

struct ubcore_nl_create_tp_req {
	uint32_t tpn;
	struct ubcore_net_addr local_net_addr;
	struct ubcore_net_addr peer_net_addr;
	enum ubcore_transport_mode trans_mode;
	struct ubcore_multipath_tp_cfg cfg;
	uint32_t rx_psn;
	enum ubcore_mtu mtu;
	struct ubcore_ta_data ta;
	uint32_t ext_len;
	uint32_t udrv_in_len;
	uint8_t ext_udrv[0]; /* struct ubcore_tp_ext->len + struct ubcore_udrv_priv->in_len */
};

struct ubcore_nl_create_tp_resp {
	enum ubcore_nl_resp_status ret;
	union ubcore_tp_flag flag;
	uint32_t peer_tpn;
	uint32_t peer_rx_psn;
	enum ubcore_mtu peer_mtu;
	uint32_t peer_ext_len;
	uint8_t peer_ext[0]; /* struct ubcore_tp_ext->len */
};

struct ubcore_nl_query_tp_req {
	enum ubcore_transport_mode trans_mode;
};

struct ubcore_nl_query_tp_resp {
	enum ubcore_nl_resp_status ret;
	bool tp_exist;
	uint32_t tpn; /* must set if tp exist is true */
	union ubcore_eid dst_eid; /* underlay */
	struct ubcore_net_addr src_addr; /* underlay */
	struct ubcore_net_addr dst_addr; /* underlay */
	struct ubcore_multipath_tp_cfg cfg;
};

struct ubcore_nl_session {
	struct ubcore_nlmsg *req;
	struct ubcore_nlmsg *resp;
	struct list_head node;
	struct kref kref;
	struct completion comp; /* Synchronization event of timeout sleep and thread wakeup */
};

static inline uint32_t ubcore_nlmsg_len(struct ubcore_nlmsg *msg)
{
	return sizeof(struct ubcore_nlmsg) + msg->payload_len;
}

int ubcore_netlink_init(void);
void ubcore_netlink_exit(void);

/* return response msg pointer, caller must release it */
struct ubcore_nlmsg *ubcore_nl_send_wait(struct ubcore_nlmsg *req);
#endif
