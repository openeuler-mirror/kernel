/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: ubcore cmd header file
 * Author: Qian Guoxin
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBCORE_CMD_H
#define UBCORE_CMD_H

#include <linux/types.h>
#include <linux/uaccess.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_perf.h>

#include "ubcore_log.h"
#include "ubcore_topo_info.h"

struct ubcore_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBCORE_CMD_MAGIC 'C'
#define UBCORE_CMD _IOWR(UBCORE_CMD_MAGIC, 1, struct ubcore_cmd_hdr)
#define UBCORE_MAX_CMD_SIZE 0x4000
#define UBCORE_MAIN_UE_EID_BATCH_EID_MAX 128

/* only for ubcore device ioctl */
enum ubcore_cmd {
	UBCORE_CMD_QUERY_STATS = 1,
	UBCORE_CMD_QUERY_RES,
	UBCORE_CMD_ADD_EID,
	UBCORE_CMD_DEL_EID,
	UBCORE_CMD_SET_EID_MODE,
	UBCORE_CMD_SET_DEV_NS_MODE,
	UBCORE_CMD_SET_DEV_NS,
	UBCORE_CMD_EXPOSE_DEV_NS,
	UBCORE_CMD_UNEXPOSE_DEV_NS,
	UBCORE_CMD_SET_DEV_EID_NS,
	UBCORE_CMD_GET_TOPO_INFO,
	UBCORE_CMD_SET_GENL_PID,
	UBCORE_CMD_SET_SL,
	UBCORE_CMD_UVS_INIT_RES,
	/* alpha netlink ops begin: */
	UBCORE_CMD_QUERY_TP_REQ,
	UBCORE_CMD_QUERY_TP_RESP,
	UBCORE_CMD_RESTORE_TP_REQ,
	UBCORE_CMD_RESTORE_TP_RESP,
	/* alpha netlink ops end: */
	UBCORE_CMD_UE2MUE_REQ,
	UBCORE_CMD_MUE2UE_RESP,
	UBCORE_CMD_ADD_SIP_REQ,
	UBCORE_CMD_ADD_SIP_RESP,
	UBCORE_CMD_DEL_SIP_REQ,
	UBCORE_CMD_DEL_SIP_RESP,
	UBCORE_CMD_TP_FLUSH_DONE_REQ,
	UBCORE_CMD_TP_SUSPEND_REQ,
	UBCORE_CMD_MIGRATE_VTP_SWITCH,
	UBCORE_CMD_MIGRATE_VTP_ROLLBACK,
	UBCORE_CMD_UPDATE_MUE_DEV_INFO_REQ,
	UBCORE_CMD_UPDATE_MUE_DEV_INFO_RESP,
	UBCORE_CMD_VTP_STATUS_NOTIFY,
	UBCORE_CMD_MSG_ACK,
	/* 33 and 34 are used by user-space admin command definitions. */
	UBCORE_CMD_ADMIN_INSERT_MAIN_UE_EID = 35,
	UBCORE_CMD_ADMIN_DELETE_MAIN_UE_EID,
	UBCORE_CMD_ADMIN_LOOKUP_MAIN_UE_EID,
	UBCORE_CMD_ADMIN_FLUSH_MAIN_UE_EID,
	UBCORE_CMD_ADMIN_INSERT_MAIN_UE_EID_BATCH,
	UBCORE_CMD_PERF_START,
	UBCORE_CMD_PERF_STOP,
	UBCORE_CMD_PERF_SHOW,
	UBCORE_CMD_GET_V2P_RES,
	UBCORE_CMD_SET_EID_NS_MODE,
	UBCORE_CMD_SHOW_TPID_LIST,
	UBCORE_CMD_SHOW_TPID_REUSE,
	UBCORE_CMD_SHOW_SYSTEM,
	UBCORE_CMD_MAX
};

struct ubcore_cmd_query_stats {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
	} in;
	struct {
		uint64_t tx_pkt;
		uint64_t rx_pkt;
		uint64_t tx_bytes;
		uint64_t rx_bytes;
		uint64_t tx_pkt_err;
		uint64_t rx_pkt_err;
	} out;
};

struct ubcore_cmd_query_res {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
		uint32_t key_ext;
		uint32_t key_cnt;
		bool query_cnt;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
		uint64_t save_ptr; /* save ubcore address for second ioctl */
	} out;
};

struct ubcore_cmd_show_res {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
		uint32_t key_cnt;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
		uint64_t save_ptr; /* save ubcore address for second ioctl */
	} out;
};

struct ubcore_cmd_show_utp {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t utpn;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
	} out;
};

struct ubcore_cmd_update_ueid {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t eid_index;
		int ns_fd;
	} in;
};

struct ubcore_cmd_set_eid_mode {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		bool eid_mode;
	} in;
};

struct ubcore_cmd_topo_info {
	struct {
		int node_idx;
	} in;
	struct {
		uint32_t node_num;
		struct ubcore_topo_node topo_info;
	} out;
};

/* record types streamed back during a tpid show dumpit */
enum ubcore_tpid_show_rec_type {
	UBCORE_TPID_SHOW_REC_LIST_HDR = 0,
	UBCORE_TPID_SHOW_REC_AWARE_NODE,
	UBCORE_TPID_SHOW_REC_UNAWARE_NODE,
	UBCORE_TPID_SHOW_REC_TPID_STATE,
	UBCORE_TPID_SHOW_REC_REUSE_ENTRY,
};

/* netlink attributes used by the tpid show dumpit messages */
enum {
	UBCORE_TPID_SHOW_ATTR_UNSPEC = 0,
	UBCORE_TPID_SHOW_ATTR_REC_TYPE,
	UBCORE_TPID_SHOW_ATTR_REC_DATA,
	UBCORE_TPID_SHOW_ATTR_MAX_PLUS,
};
#define UBCORE_TPID_SHOW_ATTR_MAX (UBCORE_TPID_SHOW_ATTR_MAX_PLUS - 1)

/* one transport point id node, mirror of ubcore_tpid_list node + state */
struct ubcore_show_tpid_node {
	uint64_t tp_handle;
};

/* tpid_list header (no node arrays, nodes are streamed separately) */
struct ubcore_show_tpid_list_hdr {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t trans_mode;
	uint32_t share_mode;
	uint32_t tp_type;
	uint32_t link_type;
	uint32_t acnt;
	uint32_t ucnt;
	uint32_t capacity;
	uint32_t ref_cnt;
	uint32_t aware_node_cnt;
	uint32_t unaware_node_cnt;
};

/* single tpid state query result */
struct ubcore_show_tpid_state {
	uint8_t found;
	uint32_t status;
	uint32_t owner_type;
	uint8_t alloced;
	uint32_t ref_cnt;
};

struct ubcore_cmd_show_tpid_list {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint8_t query_tpid; /* 1: only query a single tpid state */
		uint64_t tpid; /* valid when query_tpid is 1 */
	} in;
};

/* one tpid_reuse entry, mirror of struct ubcore_tpid_reuse */
struct ubcore_show_tpid_reuse_entry {
	union ubcore_eid local_eid;
	union ubcore_eid peer_eid;
	uint32_t trans_mode;
	uint32_t share_mode;
	uint32_t tp_type;
	uint32_t link_type;
	uint64_t stag;
	uint64_t dtag;
	uint64_t tp_handle;
	uint32_t reuse_state;
	uint32_t ref_cnt;
	int32_t use_cnt;
};

struct ubcore_cmd_show_tpid_reuse {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
	} in;
};

struct ubcore_cmd_set_sl {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t SL;

		uint32_t priority;
	} in;
};

struct ubcore_cmd_perf_show {
	struct {
		struct ubcore_latency_stat stat;
	} out;
};

/* copy from user_space addr to kernel args */
static inline int ubcore_copy_from_user(void *args, const void *args_addr,
					unsigned long args_size)
{
	int ret;

	ret = (int)copy_from_user(args, args_addr, args_size);
	if (ret != 0)
		ubcore_log_err("copy from user failed, ret:%d.\n", ret);
	return ret;
}

/* copy kernel args to user_space addr */
static inline int ubcore_copy_to_user(void *args_addr, const void *args,
				      unsigned long args_size)
{
	int ret;

	ret = (int)copy_to_user(args_addr, args, args_size);
	if (ret != 0)
		ubcore_log_err("copy to user failed ret:%d.\n", ret);
	return ret;
}
#endif
