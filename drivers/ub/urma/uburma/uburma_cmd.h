/* SPDX-License-Identifier: GPL-2.0 */
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
 * Description: uburma cmd header file
 * Author: Qian Guoxin
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBURMA_CMD_H
#define UBURMA_CMD_H
#include <linux/types.h>
#include <linux/uaccess.h>
#include "urma/ubcore_types.h"
#include "uburma_types.h"

struct uburma_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBURMA_CMD_MAX_ARGS_SIZE 25600

/* only for uburma device ioctl */
#define UBURMA_CMD_MAGIC 'U'
#define UBURMA_CMD _IOWR(UBURMA_CMD_MAGIC, 1, struct uburma_cmd_hdr)

enum uburma_cmd {
	UBURMA_CMD_CREATE_CTX = 1,
	UBURMA_CMD_ALLOC_TOKEN_ID,
	UBURMA_CMD_FREE_TOKEN_ID,
	UBURMA_CMD_REGISTER_SEG,
	UBURMA_CMD_UNREGISTER_SEG,
	UBURMA_CMD_IMPORT_SEG,
	UBURMA_CMD_UNIMPORT_SEG,
	UBURMA_CMD_CREATE_JFS,
	UBURMA_CMD_MODIFY_JFS,
	UBURMA_CMD_QUERY_JFS,
	UBURMA_CMD_DELETE_JFS,
	UBURMA_CMD_CREATE_JFR,
	UBURMA_CMD_MODIFY_JFR,
	UBURMA_CMD_QUERY_JFR,
	UBURMA_CMD_DELETE_JFR,
	UBURMA_CMD_CREATE_JFC,
	UBURMA_CMD_MODIFY_JFC,
	UBURMA_CMD_DELETE_JFC,
	UBURMA_CMD_CREATE_JFCE,
	UBURMA_CMD_IMPORT_JFR,
	UBURMA_CMD_UNIMPORT_JFR,
	UBURMA_CMD_CREATE_JETTY,
	UBURMA_CMD_MODIFY_JETTY,
	UBURMA_CMD_QUERY_JETTY,
	UBURMA_CMD_DELETE_JETTY,
	UBURMA_CMD_IMPORT_JETTY,
	UBURMA_CMD_UNIMPORT_JETTY,
	UBURMA_CMD_ADVISE_JFR,
	UBURMA_CMD_UNADVISE_JFR,
	UBURMA_CMD_ADVISE_JETTY,
	UBURMA_CMD_UNADVISE_JETTY,
	UBURMA_CMD_BIND_JETTY,
	UBURMA_CMD_UNBIND_JETTY,
	UBURMA_CMD_CREATE_JETTY_GRP,
	UBURMA_CMD_DESTROY_JETTY_GRP,
	UBURMA_CMD_USER_CTL,
	UBURMA_CMD_GET_EID_LIST,
	UBURMA_CMD_GET_NETADDR_LIST,
	UBURMA_CMD_MODIFY_TP,
	UBURMA_CMD_MAX
};

struct uburma_cmd_udrv_priv {
	uint64_t in_addr;
	uint32_t in_len;
	uint64_t out_addr;
	uint32_t out_len;
};

struct uburma_cmd_create_ctx {
	struct {
		uint8_t eid[UBCORE_EID_SIZE];
		uint32_t eid_index;
	} in;
	struct {
		int async_fd;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_alloc_token_id {
	struct {
		uint32_t token_id;
		uint64_t handle; /* handle of the allocated token_id obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_free_token_id {
	struct {
		uint64_t handle; /* handle of the allocated token_id obj in kernel */
		uint32_t token_id;
	} in;
};

struct uburma_cmd_register_seg {
	struct {
		uint64_t va;
		uint64_t len;
		uint32_t token_id;
		uint64_t token_id_handle;
		uint32_t token;
		uint32_t flag;
	} in;
	struct {
		uint32_t token_id;
		uint64_t handle; /* handle of the allocated seg obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unregister_seg {
	struct {
		uint64_t handle; /* handle of seg, used to find seg obj in kernel */
	} in;
};

struct uburma_cmd_import_seg {
	struct {
		uint8_t eid[UBCORE_EID_SIZE];
		uint64_t va;
		uint64_t len;
		uint32_t flag;
		uint32_t token;
		uint32_t token_id;
		uint64_t mva;
	} in;
	struct {
		uint64_t handle; /* handle of the allocated tseg obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unimport_seg {
	struct {
		uint64_t handle; /* handle of the seg to be unimported */
	} in;
};

struct uburma_cmd_create_jfr {
	struct {
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t max_sge;
		uint8_t min_rnr_timer;
		uint32_t jfc_id;
		uint64_t jfc_handle;
		uint32_t token;
		uint32_t id;
		uint64_t urma_jfr; /* urma jfr pointer */
	} in;
	struct {
		uint32_t id;
		uint32_t depth;
		uint8_t max_sge;
		uint64_t handle; /* handle of the allocated jfr obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_modify_jfr {
	struct {
		uint64_t handle; /* handle of jfr, used to find jfr obj in kernel */
		uint32_t mask; /* see urma_jfr_attr_mask_t */
		uint32_t rx_threshold;
		uint32_t state;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct unurma_cmd_query_jfr {
	struct {
		uint64_t handle; /* handle of the allocated jfr obj in kernel */
	} in;
	struct {
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t max_sge;
		uint8_t min_rnr_timer;
		uint32_t token;
		uint32_t id;

		uint32_t rx_threshold;
		uint32_t state;
	} out;
};

struct uburma_cmd_delete_jfr {
	struct {
		uint64_t handle; /* handle of jfr, used to find jfr obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
};

struct uburma_cmd_create_jfs {
	struct {
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t priority;
		uint8_t max_sge;
		uint8_t max_rsge;
		uint32_t max_inline_data;
		uint8_t retry_cnt;
		uint8_t rnr_retry;
		uint8_t err_timeout;
		uint32_t jfc_id;
		uint64_t jfc_handle;
		uint64_t urma_jfs; /* urma jfs pointer */
	} in;
	struct {
		uint32_t id;
		uint32_t depth;
		uint8_t max_sge;
		uint8_t max_rsge;
		uint32_t max_inline_data;
		uint64_t handle; /* handle of the allocated jfs obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_modify_jfs {
	struct {
		uint64_t handle;          /* handle of jfs, used to find jfs obj in kernel */
		uint32_t mask;            /* see urma_jfs_attr_mask_t */
		uint32_t state;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_query_jfs {
	struct {
		uint64_t handle; /* handle of the allocated jfs obj in kernel */
	} in;
	struct {
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t priority;
		uint8_t max_sge;
		uint8_t max_rsge;
		uint32_t max_inline_data;
		uint8_t retry_cnt;
		uint8_t rnr_retry;
		uint8_t err_timeout;

		uint32_t state;
	} out;
};

struct uburma_cmd_delete_jfs {
	struct {
		uint64_t handle; /* handle of jfs, used to find jfs obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
};

struct uburma_cmd_create_jfc {
	struct {
		uint32_t depth; /* in terms of CQEBB */
		uint32_t flag;
		int jfce_fd;
		uint64_t urma_jfc; /* urma jfc pointer */
		uint32_t ceqn;     /* [Optional] event queue id */
	} in;
	struct {
		uint32_t id;
		uint32_t depth;
		uint64_t handle; /* handle of the allocated jfc obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_modify_jfc {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
		uint32_t mask; /* see urma_jfc_attr_mask_t */
		uint16_t moderate_count;
		uint16_t moderate_period; /* in micro seconds */
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_delete_jfc {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
	} in;
	struct {
		uint32_t comp_events_reported;
		uint32_t async_events_reported;
	} out;
};

struct uburma_cmd_create_jfce {
	struct {
		int fd;
	} out;
};

struct uburma_cmd_import_jfr {
	struct {
		/* correspond to urma_jfr_id */
		uint8_t eid[UBCORE_EID_SIZE];
		uint32_t id;
		uint32_t flag;
		/* correspond to urma_token_t */
		uint32_t token;
		uint32_t trans_mode;
	} in;
	struct {
		uint32_t tpn;
		uint64_t handle; /* handle of the allocated tjfr obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unimport_jfr {
	struct {
		uint64_t handle; /* handle of tjfr, used to find tjfr obj in kernel */
	} in;
};

struct uburma_cmd_create_jetty {
	struct {
		uint32_t id; /* user may assign id */
		uint32_t jetty_flag;

		uint32_t jfs_depth;
		uint32_t jfs_flag;
		uint32_t trans_mode;
		uint8_t priority;
		uint8_t max_send_sge;
		uint8_t max_send_rsge;
		uint32_t max_inline_data;
		uint8_t rnr_retry;
		uint8_t err_timeout;
		uint32_t send_jfc_id;
		uint64_t send_jfc_handle; /* handle of the related send jfc */

		uint32_t jfr_depth;
		uint32_t jfr_flag;
		uint8_t max_recv_sge;
		uint8_t min_rnr_timer;

		uint32_t recv_jfc_id;
		uint64_t recv_jfc_handle; /* handle of the related recv jfc */
		uint32_t token;

		uint32_t jfr_id; /* shared jfr */
		uint64_t jfr_handle; /* handle of the shared jfr */

		uint64_t jetty_grp_handle; /* handle of the jetty_grp */
		uint8_t  is_jetty_grp;

		uint64_t urma_jetty; /* urma jetty pointer */
	} in;
	struct {
		uint32_t id; /* jetty id allocated by ubcore */
		uint64_t handle; /* handle of the allocated jetty obj in kernel */
		uint32_t jfs_depth;
		uint32_t jfr_depth;
		uint8_t max_send_sge;
		uint8_t max_send_rsge;
		uint8_t max_recv_sge;
		uint32_t max_inline_data;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_modify_jetty {
	struct {
		uint64_t handle; /* handle of jetty, used to find jetty obj in kernel */
		uint32_t mask; /* see urma_jetty_attr_mask_t */
		uint32_t rx_threshold;
		uint32_t state;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_query_jetty {
	struct {
		uint64_t handle; /* handle of the allocated jetty obj in kernel */
	} in;
	struct {
		uint32_t id; /* user may assign id */
		uint32_t jetty_flag;

		uint32_t jfs_depth;
		uint32_t jfr_depth;
		uint32_t jfs_flag;
		uint32_t jfr_flag;
		uint32_t trans_mode;
		uint8_t max_send_sge;
		uint8_t max_send_rsge;
		uint8_t max_recv_sge;
		uint32_t max_inline_data;
		uint8_t priority;
		uint8_t retry_cnt;
		uint8_t rnr_retry;
		uint8_t err_timeout;
		uint8_t min_rnr_timer;
		uint32_t jfr_id;
		uint32_t token;

		uint32_t rx_threshold;
		uint32_t state;
	} out;
};

struct uburma_cmd_delete_jetty {
	struct {
		uint64_t handle; /* handle of jetty, used to find jetty obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
};

struct uburma_cmd_import_jetty {
	struct {
		/* correspond to urma_jetty_id */
		uint8_t eid[UBCORE_EID_SIZE];
		uint32_t id;
		uint32_t flag;
		/* correspond to urma_token_t */
		uint32_t token;
		uint32_t trans_mode;
		uint32_t policy;
		uint32_t type;
	} in;
	struct {
		uint32_t tpn;
		uint64_t handle; /* handle of the allocated tjetty obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unimport_jetty {
	struct {
		uint64_t handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
};

struct uburma_cmd_advise_jetty {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unadvise_jetty {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
};

struct uburma_cmd_bind_jetty {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
	struct {
		uint32_t tpn;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unbind_jetty {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
	} in;
};

struct uburma_cmd_create_jetty_grp {
	struct {
		char name[UBCORE_JETTY_GRP_MAX_NAME];
		uint32_t token;
		uint32_t id;
		uint32_t policy;
		uint32_t flag;
		uint64_t urma_jetty_grp; /* urma jetty group pointer */
	} in;
	struct {
		uint32_t id; /* jetty group id allocated by ubcore */
		uint64_t handle; /* handle of the allocated jetty group obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_delete_jetty_grp {
	struct {
		uint64_t handle; /* handle of jetty group, used to find jetty group obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
};

struct uburma_cmd_get_eid_list {
	struct {
		uint32_t max_eid_cnt;
	} in;
	struct {
		uint32_t eid_cnt;
		struct ubcore_eid_info eid_list[UBCORE_MAX_EID_CNT];
	} out;
};

struct uburma_cmd_user_ctl {
	struct {
		uint64_t addr;
		uint32_t len;
		uint32_t opcode;
	} in; /* struct [in] should be consistent with [urma_user_ctl_in_t] */
	struct {
		uint64_t addr;
		uint32_t len;
		uint32_t rsv;
	} out; /* struct [out] should be consistent with [urma_user_ctl_out_t] */
	struct {
		uint64_t in_addr;
		uint32_t in_len;
		uint64_t out_addr;
		uint32_t out_len;
	} udrv; /* struct [udrv] should be consistent with [urma_udrv_t] */
};

union uburma_cmd_tp_cfg_flag {
	struct {
		uint32_t target : 1;          /* 0: initiator, 1: target */
		uint32_t loopback : 1;
		uint32_t dca_enable : 1;
		/* for the bonding case, the hardware selects the port
		 * ignoring the port of the tp context and
		 * selects the port based on the hash value
		 * along with the information in the bonding group table.
		 */
		uint32_t bonding : 1;
		uint32_t reserved : 28;
	} bs;
	uint32_t value;
};

struct uburma_cmd_user_tp_cfg {
	union uburma_cmd_tp_cfg_flag flag;          /* flag of initial tp */
	enum ubcore_transport_mode trans_mode;      /* tranport layer attributes */
	uint8_t retry_num;
	uint8_t retry_factor;                       /* for calculate the time slot to retry */
	uint8_t ack_timeout;
	uint8_t dscp;                               /* priority */
	uint32_t oor_cnt;                           /* OOR window size: by packet */
};

struct uburma_cmd_tp_attr {
	union ubcore_tp_mod_flag flag;  /* consistend with urma_tp_mod_flag */
	uint32_t peer_tpn;
	enum ubcore_tp_state state;
	uint32_t tx_psn;
	uint32_t rx_psn;
	enum ubcore_mtu mtu;
	uint8_t cc_pattern_idx;
	uint32_t oos_cnt;               /* out of standing packet cnt */
	uint32_t local_net_addr_idx;
	struct ubcore_net_addr peer_net_addr;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint8_t udp_range;
	uint8_t hop_limit;
	uint32_t flow_label;
	uint8_t port_id;
	uint8_t mn;                     /* 0~15, a packet contains only one msg if mn is set as 0 */
	enum ubcore_transport_type peer_trans_type;
};

union uburma_cmd_tp_attr_mask {
	struct {
		uint32_t flag : 1;
		uint32_t peer_tpn : 1;
		uint32_t state : 1;
		uint32_t tx_psn : 1;
		uint32_t rx_psn : 1; /* modify both rx psn and tx psn when restore tp */
		uint32_t mtu : 1;
		uint32_t cc_pattern_idx : 1;
		uint32_t oos_cnt : 1;
		uint32_t local_net_addr_idx : 1;
		uint32_t peer_net_addr : 1;
		uint32_t data_udp_start : 1;
		uint32_t ack_udp_start : 1;
		uint32_t udp_range : 1;
		uint32_t hop_limit : 1;
		uint32_t flow_label : 1;
		uint32_t port_id : 1;
		uint32_t mn : 1;
		uint32_t peer_trans_type : 1; /* Only for user tp connection */
		uint32_t reserved : 13;
	} bs;
	uint32_t value;
};

struct uburma_cmd_net_addr_info {
	struct ubcore_net_addr netaddr;
	uint32_t index;
};

struct uburma_cmd_get_net_addr_list {
	struct {
		uint32_t max_netaddr_cnt;
	} in;
	struct {
		uint32_t netaddr_cnt;
		struct uburma_cmd_net_addr_info netaddr_info[UBCORE_MAX_SIP];
	} out;
};

struct uburma_cmd_modify_tp {
	struct {
		uint32_t tpn;
		struct uburma_cmd_user_tp_cfg tp_cfg;
		struct uburma_cmd_tp_attr attr;
		union uburma_cmd_tp_attr_mask mask;
	} in;
}; /* this struct should be consistent [urma_cmd_modify_tp_t] */

/* only for event ioctl */
#define MAX_JFCE_EVENT_CNT 16
#define UBURMA_EVENT_CMD_MAGIC 'E'
#define JFCE_CMD_WAIT_EVENT 0
#define JFAE_CMD_GET_ASYNC_EVENT 0
#define UBURMA_CMD_WAIT_JFC	\
	_IOWR(UBURMA_EVENT_CMD_MAGIC, JFCE_CMD_WAIT_EVENT, struct uburma_cmd_jfce_wait)
#define UBURMA_CMD_GET_ASYNC_EVENT	\
	_IOWR(UBURMA_EVENT_CMD_MAGIC, JFAE_CMD_GET_ASYNC_EVENT, struct uburma_cmd_async_event)

struct uburma_cmd_jfce_wait {
	struct {
		uint32_t max_event_cnt;
		int time_out;
	} in;
	struct {
		uint32_t event_cnt;
		uint64_t event_data[MAX_JFCE_EVENT_CNT];
	} out;
};

struct uburma_cmd_async_event {
	uint32_t event_type;
	uint64_t event_data;
	uint32_t pad;
};

/* copy from user_space addr to kernel args */
static inline int uburma_copy_from_user(void *args, const void *args_addr,
	unsigned long args_size)
{
	int ret;

	ret = (int)copy_from_user(args, args_addr, args_size);
	if (ret != 0) {
		uburma_log_err("copy from user failed, ret:%d.\n", ret);
		return -EFAULT;
	}
	return 0;
}

/* copy kernel args to user_space addr */
static inline int uburma_copy_to_user(void *args_addr, const void *args,
	unsigned long args_size)
{
	int ret;

	ret = (int)copy_to_user(args_addr, args, args_size);
	if (ret != 0) {
		uburma_log_err("copy to user failed ret:%d.\n", ret);
		return -EFAULT;
	}
	return 0;
}

void uburma_cmd_inc(struct uburma_device *ubu_dev);
void uburma_cmd_dec(struct uburma_device *ubu_dev);
void uburma_cmd_flush(struct uburma_device *ubu_dev);

#endif /* UBURMA_CMD_H */
