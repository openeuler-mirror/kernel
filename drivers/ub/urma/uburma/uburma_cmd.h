/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 *
 * Description: uburma cmd header file
 * Author: Qian Guoxin
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBURMA_CMD_H
#define UBURMA_CMD_H

#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/socket.h>

#include "ub/urma/ubcore_types.h"
#include "uburma_types.h"

struct uburma_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBURMA_CMD_MAX_ARGS_SIZE 25600
#define UBURMA_CMD_MAX_PORT_CNT 8
#define UBURMA_CMD_TP_ATTR_BYTES 128

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
	UBURMA_CMD_QUERY_DEV_ATTR,
	UBURMA_CMD_IMPORT_JETTY_ASYNC,
	UBURMA_CMD_UNIMPORT_JETTY_ASYNC,
	UBURMA_CMD_BIND_JETTY_ASYNC,
	UBURMA_CMD_UNBIND_JETTY_ASYNC,
	UBURMA_CMD_CREATE_NOTIFIER,
	UBURMA_CMD_GET_TP_LIST,
	UBURMA_CMD_IMPORT_JETTY_EX,
	UBURMA_CMD_IMPORT_JFR_EX,
	UBURMA_CMD_BIND_JETTY_EX,
	UBURMA_CMD_DELETE_JFS_BATCH,
	UBURMA_CMD_DELETE_JFR_BATCH,
	UBURMA_CMD_DELETE_JFC_BATCH,
	UBURMA_CMD_DELETE_JETTY_BATCH,
	UBURMA_CMD_SET_TP_ATTR,
	UBURMA_CMD_GET_TP_ATTR,
	UBURMA_CMD_EXCHANGE_TP_INFO,
	UBURMA_CMD_GET_EID_BY_IP,
	UBURMA_CMD_GET_IP_BY_EID,
	UBURMA_CMD_GET_SMAC,
	UBURMA_CMD_GET_DMAC,
	UBURMA_CMD_ALLOC_JFC,
	UBURMA_CMD_FREE_JFC,
	UBURMA_CMD_SET_JFC_OPT,
	UBURMA_CMD_GET_JFC_OPT,
	UBURMA_CMD_ACTIVE_JFC,
	UBURMA_CMD_DEACTIVE_JFC,
	UBURMA_CMD_ALLOC_JFR,
	UBURMA_CMD_FREE_JFR,
	UBURMA_CMD_SET_JFR_OPT,
	UBURMA_CMD_GET_JFR_OPT,
	UBURMA_CMD_ACTIVE_JFR,
	UBURMA_CMD_DEACTIVE_JFR,
	UBURMA_CMD_ALLOC_JFS,
	UBURMA_CMD_FREE_JFS,
	UBURMA_CMD_SET_JFS_OPT,
	UBURMA_CMD_GET_JFS_OPT,
	UBURMA_CMD_ACTIVE_JFS,
	UBURMA_CMD_DEACTIVE_JFS,
	UBURMA_CMD_ALLOC_JETTY,
	UBURMA_CMD_FREE_JETTY,
	UBURMA_CMD_SET_JETTY_OPT,
	UBURMA_CMD_GET_JETTY_OPT,
	UBURMA_CMD_ACTIVE_JETTY,
	UBURMA_CMD_DEACTIVE_JETTY,
	UBURMA_CMD_MAX
};

struct uburma_cmd_udrv_priv {
	uint64_t in_addr;
	uint32_t in_len;
	uint64_t out_addr;
	uint32_t out_len;
};

union uburma_cmd_token_id_flag {
	struct {
		uint32_t multi_seg : 1;
		uint32_t reserved : 31;
	} bs;
	uint32_t value;
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
	union uburma_cmd_token_id_flag flag;
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

struct uburma_cmd_query_jfr {
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

struct uburma_cmd_delete_jfr_batch {
	struct {
		uint32_t async_events_reported;
		uint32_t bad_jfr_index;
	} out;
	struct {
		uint32_t jfr_num;
		uint64_t jfr_ptr;
	} in;
};

struct uburma_cmd_alloc_jfr {
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
		uint64_t handle; /* handle of the allocated jfr obj in kernel */
		uint8_t max_sge;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_free_jfr {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_set_jfr_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_get_jfr_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct {
		uint64_t buf;
		uint32_t len;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_active_jfr {
	struct {
		uint64_t handle;          /* handle of jfr, used to find jfr obj in kernel */
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t max_sge;
		uint8_t min_rnr_timer;
		uint32_t jfc_id;
		uint64_t jfc_handle;
		uint32_t token_value;
		uint64_t urma_jfr_opt;
	} in;
	struct {
		uint32_t id;
		uint32_t depth;
		uint64_t handle; /* handle of the allocated jfr obj in kernel */
		uint8_t max_sge;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_deactive_jfr {
	struct {
	uint64_t handle;          /* handle of jfr, used to find jfr obj in kernel */
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_alloc_jfs {
	struct {
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t priority;
		uint8_t max_sge;
		uint8_t max_rsge;
		uint32_t max_inline_data;
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

struct uburma_cmd_free_jfs {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_set_jfs_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_get_jfs_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct {
		uint64_t buf;
		uint32_t len;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_active_jfs {
	struct {
		uint64_t handle;          /* handle of jfs, used to find jfs obj in kernel */
		uint32_t depth;
		uint32_t flag;
		uint32_t trans_mode;
		uint32_t priority;
		uint8_t max_sge;
		uint8_t max_rsge;
		uint32_t max_inline_data;
		uint8_t rnr_retry;
		uint8_t err_timeout;
		uint32_t jfc_id;
		uint64_t jfc_handle;
		uint64_t jfs_opt;
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

struct uburma_cmd_deactive_jfs {
	struct {
	uint64_t handle;          /* handle of jfr, used to find jfr obj in kernel */
	} in;
	struct uburma_cmd_udrv_priv udata;
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
		uint64_t handle; /* handle of jfs, used to find jfs obj in kernel */
		uint32_t mask; /* see urma_jfs_attr_mask_t */
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

struct uburma_cmd_delete_jfs_batch {
	struct {
		uint32_t async_events_reported;
		uint32_t bad_jfs_index;
	} out;
	struct {
		uint32_t jfs_num;
		uint64_t jfs_ptr;
	} in;
};

struct uburma_cmd_create_jfc {
	struct {
		uint32_t depth; /* in terms of CQEBB */
		uint32_t flag;
		int jfce_fd;
		uint64_t urma_jfc; /* urma jfc pointer */
		uint32_t ceqn; /* [Optional] event queue id */
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

struct uburma_cmd_delete_jfc_batch {
	struct {
		uint32_t comp_events_reported;
		uint32_t async_events_reported;
		uint32_t bad_jfc_index;
	} out;
	struct {
		uint32_t jfc_num;
		uint64_t jfc_ptr;
	} in;
};

struct uburma_cmd_alloc_jfc {
	struct {
		uint32_t depth;
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

struct uburma_cmd_free_jfc {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
	} in;
	struct {
		uint32_t comp_events_reported;
		uint32_t async_events_reported;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_set_jfc_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_get_jfc_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct {
		uint64_t buf;
		uint32_t len;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_active_jfc {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
		uint32_t depth;
		uint32_t flag;
		uint32_t ceqn;
		uint64_t urma_jfc_opt;
	} in;
		struct {
		uint32_t id;
		uint32_t depth;
		uint64_t handle; /* handle of the allocated jfc obj in kernel */
		} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_deactive_jfc {
	struct {
		uint64_t handle; /* handle of jfc, used to find jfc obj in kernel */
	} in;
	struct uburma_cmd_udrv_priv udata;
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
		uint32_t tp_type;
	} in;
	struct {
		uint32_t tpn;
		uint64_t handle; /* handle of the allocated tjfr obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_import_jfr_ex {
	struct {
		/* correspond to ubcore_jfr_id */
		uint8_t eid[UBCORE_EID_SIZE];
		uint32_t id;
		uint32_t flag;
		/* correspond to ubcore_token */
		uint32_t token;
		uint32_t trans_mode;
		uint32_t tp_type;
		/* correspond to struct ubcore_active_tp_cfg */
		uint64_t tp_handle;
		uint64_t peer_tp_handle;
		uint64_t tag;
		uint32_t tx_psn;
		uint32_t rx_psn;
		uint64_t stag;
		uint64_t dtag;
	} in;
	struct {
		uint32_t tpn;
		uint32_t reserved;
		uint64_t handle; /* handle of the allocated tjfr obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_import_jfr_ex_t] */

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
		uint8_t is_jetty_grp;

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

struct uburma_cmd_delete_jetty_batch {
	struct {
		uint32_t async_events_reported;
		uint32_t bad_jetty_index;
	} out;
	struct {
		uint32_t jetty_num;
		uint64_t jetty_ptr;
	} in;
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
		uint32_t tp_type;
	} in;
	struct {
		uint32_t tpn;
		uint64_t handle; /* handle of the allocated tjetty obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_import_jetty_ex {
	struct {
		/* correspond to ubcore_jetty_id */
		uint8_t eid[UBCORE_EID_SIZE];
		uint32_t id;
		uint32_t flag;
		/* correspond to ubcore_token */
		uint32_t token;
		uint32_t trans_mode;
		uint32_t policy;
		uint32_t type;
		uint32_t tp_type;
		/* correspond to struct ubcore_active_tp_cfg */
		uint64_t tp_handle;
		uint64_t peer_tp_handle;
		uint64_t tag;
		uint32_t tx_psn;
		uint32_t rx_psn;
		/* correspond to upper layer business */
		uint64_t stag;
		uint64_t dtag;
	} in;
	struct {
		uint32_t tpn;
		uint32_t reserved;
		uint64_t handle; /* handle of the allocated tjetty obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_import_jetty_ex_t] */

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

struct uburma_cmd_bind_jetty_ex {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
		/* correspond to ubcore_active_tp_cfg */
		uint64_t tp_handle;
		uint64_t peer_tp_handle;
		uint64_t tag;
		uint32_t tx_psn;
		uint32_t rx_psn;
	} in;
	struct {
		uint32_t tpn;
		uint32_t reserved;
	} out;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_bind_jetty_ex_t] */

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

struct uburma_cmd_alloc_jetty {
	struct uburma_cmd_create_jetty create_jetty;
};

struct uburma_cmd_free_jetty {
	struct {
		uint64_t handle; /* handle of jetty, used to find jetty obj in kernel */
	} in;
	struct {
		uint32_t async_events_reported;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_set_jetty_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_get_jetty_opt {
	struct {
		uint64_t handle;
		uint64_t opt;
		uint64_t buf;
		uint32_t len;
	} in;
	struct {
		uint64_t buf;
		uint32_t len;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_active_jetty {
	struct {
		uint32_t flag;
		uint64_t handle;
		uint64_t send_jfc_handle; /* handle of the related send jfc */
		uint64_t recv_jfc_handle; /* handle of the related recv jfc */
		uint64_t urma_jetty; /* urma jetty pointer */
		uint64_t jetty_opt;
	} in;
	struct {
		uint32_t jetty_id;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_deactive_jetty {
	struct {
		uint64_t handle;          /* handle of jetty, used to find jetty obj in kernel */
	} in;
	struct uburma_cmd_udrv_priv udata;
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
		uint32_t target : 1; /* 0: initiator, 1: target */
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
	union uburma_cmd_tp_cfg_flag flag; /* flag of initial tp */
	enum ubcore_transport_mode trans_mode; /* tranport layer attributes */
	uint8_t retry_num;
	uint8_t retry_factor; /* for calculate the time slot to retry */
	uint8_t ack_timeout;
	uint8_t dscp; /* priority */
	uint32_t oor_cnt; /* OOR window size: by packet */
};

struct uburma_cmd_net_addr {
	sa_family_t sin_family; /* AF_INET/AF_INET6 */
	union {
		struct in_addr in4;
		struct in6_addr in6;
	};
	uint64_t vlan;
	uint8_t mac[UBCORE_MAC_BYTES];
	uint32_t prefix_len;
};

struct uburma_cmd_tp_attr {
	union ubcore_tp_mod_flag flag; /* consistend with urma_tp_mod_flag */
	uint32_t peer_tpn;
	enum ubcore_tp_state state;
	uint32_t tx_psn;
	uint32_t rx_psn;
	enum ubcore_mtu mtu;
	uint8_t cc_pattern_idx;
	uint32_t oos_cnt; /* out of standing packet cnt */
	uint32_t local_net_addr_idx;
	struct uburma_cmd_net_addr peer_net_addr;
	uint16_t data_udp_start;
	uint16_t ack_udp_start;
	uint8_t udp_range;
	uint8_t hop_limit;
	uint32_t flow_label;
	uint8_t port_id;
	uint8_t mn; /* 0~15, a packet contains only one msg if mn is set as 0 */
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
		uint32_t reserved : 14;
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
		uint64_t addr; /* containing array of struct uburma_cmd_net_addr_info */
		uint64_t len;
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

struct uburma_cmd_device_cap {
	union ubcore_device_feat feature; /* refer to urma_device_feature_t */
	uint32_t max_jfc;
	uint32_t max_jfs;
	uint32_t max_jfr;
	uint32_t max_jetty;
	uint32_t max_jetty_grp;
	uint32_t max_jetty_in_jetty_grp;
	uint32_t max_jfc_depth;
	uint32_t max_jfs_depth;
	uint32_t max_jfr_depth;
	uint32_t max_jfs_inline_len;
	uint32_t max_jfs_sge;
	uint32_t max_jfs_rsge;
	uint32_t max_jfr_sge;
	uint64_t max_msg_size;
	uint32_t max_read_size;
	uint32_t max_write_size;
	uint32_t max_cas_size;
	uint32_t max_swap_size;
	uint32_t max_fetch_and_add_size;
	uint32_t max_fetch_and_sub_size;
	uint32_t max_fetch_and_and_size;
	uint32_t max_fetch_and_or_size;
	uint32_t max_fetch_and_xor_size;
	union ubcore_atomic_feat atomic_feat; /* refer to urma_atomic_feature_t */
	uint16_t trans_mode;
	uint16_t congestion_ctrl_alg;
	uint32_t ceq_cnt;
	uint32_t max_tp_in_tpg;
	uint32_t max_eid_cnt;
	uint64_t page_size_cap;
	uint32_t max_oor_cnt;
	uint32_t mn;
	uint32_t max_netaddr_cnt;
	union ubcore_order_type_cap rm_order_cap;
	union ubcore_order_type_cap rc_order_cap;
	union urma_tp_type_cap rm_tp_cap;
	union urma_tp_type_cap rc_tp_cap;
	union urma_tp_type_cap um_tp_cap;
	union urma_tp_feature tp_feature;
	struct ubcore_sl_info priority_info[UBCORE_MAX_PRIORITY_CNT];
}; /* this struct should be consistent [urma_device_cap_t] */

struct uburma_cmd_port_attr {
	enum ubcore_mtu max_mtu; /* MTU_256, MTU_512, MTU_1024 */
	enum ubcore_port_state state; /* PORT_DOWN, PORT_INIT, PORT_ACTIVE */
	enum ubcore_link_width active_width; /* link width: X1, X2, X4 */
	enum ubcore_speed active_speed; /* bandwidth */
	enum ubcore_mtu active_mtu;
}; /* this struct should be consistent [struct urma_port_attr] */

struct uburma_cmd_device_attr {
	struct ubcore_guid guid; /* [Public] */
	struct uburma_cmd_device_cap
		dev_cap; /* [Public] capabilities of device. */
	uint8_t port_cnt; /* [Public] port number of device. */
	struct uburma_cmd_port_attr port_attr[UBURMA_CMD_MAX_PORT_CNT];
	uint32_t reserved_jetty_id_min;
	uint32_t reserved_jetty_id_max;
}; /* this struct should be consistent [urma_device_attr_t] */

struct uburma_cmd_query_device_attr {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
	} in;
	struct {
		struct uburma_cmd_device_attr attr;
	} out;
}; /* this struct should be consistent [urma_cmd_query_device_attr_t] */

struct uburma_cmd_import_jetty_async {
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
		uint64_t urma_tjetty; /* urma tjetty pointer */
		uint64_t user_ctx;
		int fd;
		int timeout;
	} in;
	struct {
		uint32_t tpn;
		uint64_t handle; /* handle of the allocated tjetty obj in kernel */
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unimport_jetty_async {
	struct {
		uint64_t handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
};

struct uburma_cmd_bind_jetty_async {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
		uint64_t urma_tjetty; /* urma tjetty pointer */
		uint64_t urma_jetty; /* urma jetty pointer */
		int fd;
		uint64_t user_ctx;
		int timeout;
	} in;
	struct {
		uint32_t tpn;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

struct uburma_cmd_unbind_jetty_async {
	struct {
		uint64_t jetty_handle; /* handle of jetty, used to find jetty obj in kernel */
		uint64_t tjetty_handle; /* handle of tjetty, used to find tjetty obj in kernel */
	} in;
};

struct uburma_cmd_create_notifier {
	struct {
		int fd;
	} out;
};

#define UBURMA_CMD_MAX_TP_NUM 128

struct uburma_cmd_get_tp_list {
	struct {
		uint32_t flag;
		uint32_t trans_mode;
		uint8_t local_eid[UBCORE_EID_SIZE];
		uint8_t peer_eid[UBCORE_EID_SIZE];
		uint32_t tp_cnt;
		uint32_t reserved;
	} in;
	struct {
		uint32_t tp_cnt;
		uint32_t reserved;
		uint64_t tp_handle[UBURMA_CMD_MAX_TP_NUM];
	} out;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_get_tp_list_t] */

struct uburma_cmd_set_tp_attr {
	struct {
		uint64_t tp_handle;
		uint8_t tp_attr_cnt;
		uint32_t tp_attr_bitmap;
		uint8_t tp_attr[UBURMA_CMD_TP_ATTR_BYTES];
	} in;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_set_tp_attr_t] */

struct uburma_cmd_get_tp_attr {
	struct {
		uint64_t tp_handle;
	} in;
	struct {
		uint8_t tp_attr_cnt;
		uint32_t tp_attr_bitmap;
		uint8_t tp_attr[UBURMA_CMD_TP_ATTR_BYTES];
	} out;
	struct uburma_cmd_udrv_priv udata;
}; /* this struct should be consistent [urma_cmd_get_tp_attr_t] */

struct uburma_cmd_exchange_tp_info {
	struct {
		struct ubcore_get_tp_cfg get_tp_cfg;
		uint64_t tp_handle;
		uint32_t tx_psn;
	} in;
	struct {
		uint64_t peer_tp_handle;
		uint32_t rx_psn;
	} out;
}; /* this struct should be consistent [urma_cmd_exchange_tp_info_t] */

struct uburma_cmd_get_eid_by_ip {
	struct {
		struct uburma_cmd_net_addr net_addr;
	} in;
	struct {
		union ubcore_eid eid;
	} out;
};

struct uburma_cmd_get_ip_by_eid {
	struct {
		union ubcore_eid eid;
	} in;
	struct {
		struct uburma_cmd_net_addr net_addr;
	} out;
};

struct uburma_cmd_get_smac {
	struct {
		uint8_t mac[UBCORE_MAC_BYTES];
	} out;
};

struct uburma_cmd_get_dmac {
	struct {
		struct uburma_cmd_net_addr net_addr;
	} in;
	struct {
		uint8_t mac[UBCORE_MAC_BYTES];
	} out;
};

/* only for event ioctl */
#define MAX_JFCE_EVENT_CNT 16
#define MAX_NOTIFY_CNT 16
#define UBURMA_EVENT_CMD_MAGIC 'E'
#define JFCE_CMD_WAIT_EVENT 0
#define JFAE_CMD_GET_ASYNC_EVENT 0
#define NOTIFY_CMD_WAIT_NOTIFY 0
#define UBURMA_CMD_WAIT_JFC                                \
	_IOWR(UBURMA_EVENT_CMD_MAGIC, JFCE_CMD_WAIT_EVENT, \
	      struct uburma_cmd_hdr)
#define UBURMA_CMD_GET_ASYNC_EVENT                              \
	_IOWR(UBURMA_EVENT_CMD_MAGIC, JFAE_CMD_GET_ASYNC_EVENT, \
	      struct uburma_cmd_hdr)
#define UBURMA_CMD_WAIT_NOTIFY                                \
	_IOWR(UBURMA_EVENT_CMD_MAGIC, NOTIFY_CMD_WAIT_NOTIFY, \
	      struct uburma_cmd_hdr)
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

enum uburma_notify_type {
	UBURMA_IMPORT_JETTY_NOTIFY = 0,
	UBURMA_BIND_JETTY_NOTIFY
};

struct uburma_notify {
	enum uburma_notify_type type;
	int status;
	uint64_t user_ctx;
	uint64_t urma_jetty;
	uint32_t vtpn;
};

struct uburma_notify_event {
	struct uburma_notify notify;
	int jetty_handle;
	int tjetty_handle;
};

struct uburma_cmd_wait_notify {
	struct {
		uint32_t cnt;
		int timeout;
	} in;
	struct {
		uint32_t cnt;
		struct uburma_notify notify[MAX_NOTIFY_CNT];
	} out;
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

int uburma_unimport_jetty(struct uburma_file *file, bool async,
			  int tjetty_handle);
int uburma_unbind_jetty(struct uburma_file *file, bool async, int jetty_handle,
			int tjetty_handle);

void uburma_cmd_inc(struct uburma_device *ubu_dev);
void uburma_cmd_dec(struct uburma_device *ubu_dev);
void uburma_cmd_flush(struct uburma_device *ubu_dev);

#endif /* UBURMA_CMD_H */
