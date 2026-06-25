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
	UBCORE_CMD_GET_TOPO_INFO_RESERVE,
	UBCORE_CMD_SET_SL,
	UBCORE_CMD_SET_GENL_PID,
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
	UBCORE_CMD_SET_EID_NS_MODE,
	UBCORE_CMD_SHOW_TPID_LIST,
	UBCORE_CMD_SHOW_TPID_REUSE,
	UBCORE_CMD_SHOW_SYSTEM,
	UBCORE_CMD_MAX
};

struct ubcore_stats {
	uint64_t tx_pkt;
	uint64_t rx_pkt;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_pkt_err;
	uint64_t rx_pkt_err;
};

struct ubcore_cmd_query_stats {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
	} in;
	struct ubcore_stats out;
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

/* record types streamed back during a tpid show dumpit */
enum ubcore_tpid_show_rec_type {
	UBCORE_TPID_SHOW_REC_LIST_HDR = 0,
	UBCORE_TPID_SHOW_REC_TP_LIST,
	UBCORE_TPID_SHOW_REC_TPID_STATE,
	UBCORE_TPID_SHOW_REC_REUSE_ENTRY,
};

/* netlink attributes used by the tpid show dumpit messages */
enum {
	UBCORE_TPID_SHOW_ATTR_UNSPEC = 0,
	UBCORE_TPID_SHOW_ATTR_REC_TYPE,      /* u32: ubcore_tpid_show_rec_type */
	/* common fields (shared across multiple record types) */
	UBCORE_TPID_SHOW_ATTR_LOCAL_EID,     /* binary, UBCORE_EID_SIZE */
	UBCORE_TPID_SHOW_ATTR_PEER_EID,      /* binary, UBCORE_EID_SIZE */
	UBCORE_TPID_SHOW_ATTR_TRANS_MODE,    /* u32 */
	UBCORE_TPID_SHOW_ATTR_SHARE_MODE,    /* u32 */
	UBCORE_TPID_SHOW_ATTR_TP_TYPE,       /* u32 */
	UBCORE_TPID_SHOW_ATTR_LINK_TYPE,     /* u32 */
	UBCORE_TPID_SHOW_ATTR_REF_CNT,       /* u32 */
	UBCORE_TPID_SHOW_ATTR_TP_HANDLE,     /* u64 */
	/* LIST_HDR specific */
	UBCORE_TPID_SHOW_ATTR_TP_LIST_CNT,   /* u32 */
	/* TPID_STATE specific */
	UBCORE_TPID_SHOW_ATTR_FOUND,         /* u8 */
	UBCORE_TPID_SHOW_ATTR_STATUS,        /* u32 */
	UBCORE_TPID_SHOW_ATTR_ALLOCED,       /* u8 */
	/* REUSE_ENTRY specific */
	UBCORE_TPID_SHOW_ATTR_STAG,          /* u64 */
	UBCORE_TPID_SHOW_ATTR_DTAG,          /* u64 */
	UBCORE_TPID_SHOW_ATTR_REUSE_STATE,   /* u32 */
	UBCORE_TPID_SHOW_ATTR_USE_CNT,       /* s32 */
	UBCORE_TPID_SHOW_ATTR_PEER_TP_HANDLE, /* u64 */
	UBCORE_TPID_SHOW_ATTR_TX_PSN,        /* u32 */
	UBCORE_TPID_SHOW_ATTR_IS_REF,        /* u8 */
	UBCORE_TPID_SHOW_ATTR_MAX_PLUS,
};
#define UBCORE_TPID_SHOW_ATTR_MAX (UBCORE_TPID_SHOW_ATTR_MAX_PLUS - 1)

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
