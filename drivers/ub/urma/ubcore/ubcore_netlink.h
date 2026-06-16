/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore netlink head file
 * Author: Chen Wen
 * Create: 2022-08-27
 * Note:
 * History: 2022-08-27: Create file
 */

#ifndef UBCORE_NETLINK_H
#define UBCORE_NETLINK_H

#include <net/genetlink.h>
#include <linux/netlink.h>
#include <ub/urma/ubcore_types.h>
#include "ubcore_cmd.h"

struct ubcore_uvs_instance;

enum ubcore_nl_resp_status {
	UBCORE_NL_RESP_IN_PROGRESS = -2,
	UBCORE_NL_RESP_FAIL = -1,
	UBCORE_NL_RESP_SUCCESS = 0
};

struct ubcore_nlmsg {
	uint32_t nlmsg_seq;
	enum ubcore_cmd msg_type;
	union ubcore_eid src_eid; /* todo: delete */
	union ubcore_eid dst_eid; /* todo: delete */
	enum ubcore_transport_type transport_type;
	uint32_t payload_len;
	uint8_t payload[0]; // limited by tpsa_nl_msg_t's payload len
};

struct ubcore_ta_data {
	enum ubcore_transport_type trans_type;
	enum ubcore_ta_type ta_type;
	struct ubcore_jetty_id jetty_id; /* local jetty id */
	struct ubcore_jetty_id tjetty_id; /* peer jetty id */
	bool is_target;
};

struct ubcore_msg_ack {
	uint32_t payload_len;
};

struct ubcore_nl_query_tp_req {
	enum ubcore_transport_mode trans_mode;
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint16_t ue_idx;
};

struct ubcore_nl_query_tp_resp {
	enum ubcore_nl_resp_status ret;
	uint8_t retry_num;
	uint8_t retry_factor;
	uint8_t ack_timeout;
	uint8_t dscp;
	uint32_t oor_cnt;
};

struct ubcore_nl_restore_tp_req {
	enum ubcore_transport_mode trans_mode;
	uint32_t tpn;
	uint32_t peer_tpn;
	uint32_t rx_psn;
	struct ubcore_ta_data ta;
};

struct ubcore_nl_restore_tp_resp {
	enum ubcore_nl_resp_status ret;
	uint32_t peer_rx_psn;
};

struct ubcore_nl_resp_cb {
	void *user_arg;
	int (*callback)(struct ubcore_nlmsg *resp, void *user_arg);
};

struct ubcore_nl_session {
	uint32_t nlmsg_seq;
	struct ubcore_nlmsg *resp; /* memory is managed by session */
	struct list_head node;
	struct kref kref;
	struct ubcore_nl_resp_cb cb;
	struct completion
		comp; /* Synchronization event of timeout sleep and thread wakeup */
	struct ubcore_device *dev;
};

struct ubcore_nl_message {
	struct list_head node;
	struct sk_buff *nl_skb;
	uint32_t uvs_genl_port;
};

struct ubcore_add_sip_req {
	struct ubcore_net_addr netaddr;
	uint32_t prefix_len;
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint8_t port_cnt;
	uint8_t port_id[UBCORE_MAX_PORT_CNT];
	uint32_t index;
	uint32_t mtu;
	char netdev_name[UBCORE_MAX_DEV_NAME]; /* for change mtu */
};

struct ubcore_add_sip_resp {
	enum ubcore_nl_resp_status ret;
};

struct ubcore_del_sip_req {
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint32_t index;
};

struct ubcore_del_sip_resp {
	enum ubcore_nl_resp_status ret;
};

struct ubcore_tp_suspend_req {
	uint32_t tpgn;
	uint32_t tpn;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint32_t sip_idx;
	char mue_dev_name[UBCORE_MAX_DEV_NAME];
};

struct ubcore_tp_flush_done_req {
	uint32_t tpgn;
	uint32_t tpn;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint32_t tx_psn;
	uint32_t peer_tpn;
	enum ubcore_transport_mode trans_mode;
	uint32_t sip_idx;
	struct ubcore_net_addr sip;
	union ubcore_eid local_eid;
	uint32_t local_jetty_id;
	union ubcore_eid peer_eid;
	uint32_t peer_jetty_id;
	char mue_dev_name[UBCORE_MAX_DEV_NAME];
};

struct ubcore_nl_function_mig_req {
	uint16_t mig_ue_idx;
	char dev_name[UBCORE_MAX_DEV_NAME];
};

enum ubcore_update_mue_opcode {
	UBCORE_UPDATE_MUE_ADD = 0,
	UBCORE_UPDATE_MUE_DEL
};

struct ubcore_update_mue_dev_info_req {
	char dev_name[UBCORE_MAX_DEV_NAME];
	char netdev_name[UBCORE_MAX_DEV_NAME];
	union ubcore_device_feat dev_fea;
	uint32_t cc_entry_cnt;
	enum ubcore_update_mue_opcode opcode;
	uint8_t data[];
}; // same as tpsa_nl_update_mue_dev_info_req

struct ubcore_update_mue_dev_info_resp {
	enum ubcore_nl_resp_status ret;
}; // same as tpsa_nl_update_mue_dev_info_resp

static inline uint32_t ubcore_nlmsg_len(struct ubcore_nlmsg *msg)
{
	return sizeof(struct ubcore_nlmsg) + msg->payload_len;
}

struct ubcore_nlmsg_delay_work {
	struct delayed_work delay_work;
	struct ubcore_uvs_instance *uvs;
	struct ubcore_nlmsg *req;
	uint32_t len;
};

bool ubcore_get_netlink_valid(void);
/* return response msg pointer, caller must release it */
struct ubcore_nlmsg *ubcore_nl_send_wait(struct ubcore_device *dev,
					 struct ubcore_nlmsg *req,
					 struct ubcore_uvs_instance *uvs);

int ubcore_nl_send_nowait(struct ubcore_device *dev, struct ubcore_nlmsg *req,
			  struct ubcore_nl_resp_cb *cb,
			  struct ubcore_uvs_instance *uvs);
int ubcore_nl_send_nowait_without_cb(struct ubcore_nlmsg *req,
				     struct ubcore_uvs_instance *uvs);

struct ubcore_nlmsg *ubcore_alloc_nlmsg(size_t payload_len,
					const union ubcore_eid *src_eid,
					const union ubcore_eid *dst_eid);

int ubcore_get_uvs_init_res_done(struct netlink_callback *cb);
int ubcore_get_uvs_init_res_dump(struct sk_buff *skb,
				 struct netlink_callback *cb);
int ubcore_get_uvs_init_res_start(struct netlink_callback *cb);
extern struct genl_family ubcore_genl_family;
int ubcore_set_genl_pid_ops(struct sk_buff *skb, struct genl_info *info);
void ubcore_unset_genl_pid_ops(uint32_t genl_port);
int ubcore_mue2ue_resp_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_tp_resp_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_tp_req_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_update_mue_dev_info_resp_ops(struct sk_buff *skb,
					struct genl_info *info);
int ubcore_tp2ue_vtp_status_notify_ops(struct sk_buff *skb,
				       struct genl_info *info);
int ubcore_nl_msg_ack_ops(struct sk_buff *skb, struct genl_info *info);
void ubcore_free_dev_nl_sessions(struct ubcore_device *dev);
void ubcore_uvs_release_nl_buffer(struct ubcore_uvs_instance *uvs);
#endif
