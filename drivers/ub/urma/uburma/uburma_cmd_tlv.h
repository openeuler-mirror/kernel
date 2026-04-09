/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: uburma cmd tlv parse header, uburma cmd struct consists of
 * type/length/value, ioctl operations are copyed and parsed by tlv form
 * Author: Wang Hang
 * Create: 2024-08-27
 * Note:
 * History: 2024-08-27: create file
 */

#ifndef UBURMA_CMD_TLV_H
#define UBURMA_CMD_TLV_H

#include <linux/types.h>

#include "uburma_cmd.h"

#define UBURMA_CMD_OUT_TYPE_INIT 0x80

enum uburma_event_cmd {
	UBURMA_EVENT_CMD_WAIT_JFCE = 1,
	UBURMA_EVENT_CMD_GET_ASYNC_EVENT,
	UBURMA_EVENT_CMD_WAIT_NOTIFY,
	UBURMA_EVENT_CMD_MAX,
};

struct uburma_cmd_attr {
	uint8_t type; /* See enum uburma_cmd_xxx_type */
	uint8_t flag;
	uint16_t field_size;
	union {
		struct {
			uint32_t el_num : 12; /* Array element number if field is in an array */
			uint32_t el_size : 12; /* Array element size if field is in an array */
			uint32_t reserved : 8;
		} bs;
		uint32_t value;
	} attr_data;
	uint64_t data;
};

struct uburma_cmd_spec {
	uint8_t type; /* See uburma_cmd_xxx_type_t */
	union {
		struct {
			uint8_t mandatory : 1;
		} bs;
		uint8_t value;
	} flag;
	uint16_t field_size;
	union {
		struct {
			uint32_t el_num : 12; /* Array element number if field is in an array */
			uint32_t el_size : 12; /* Array element size if field is in an array */
			uint32_t reserved : 8;
		} bs;
		uint32_t value;
	} attr_data;
	uint64_t data;
};

/* See struct uburma_cmd_create_ctx, in/out type should be continuous */
enum uburma_cmd_create_ctx_type {
	/* In type */
	CREATE_CTX_IN_EID,
	CREATE_CTX_IN_EID_INDEX,
	CREATE_CTX_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	CREATE_CTX_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_CTX_OUT_ASYNC_FD = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_CTX_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	CREATE_CTX_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_alloc_token_id, in/out type should be continuous */
enum uburma_cmd_alloc_token_id_type {
	/* In type */
	ALLOC_TOKEN_ID_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	ALLOC_TOKEN_ID_IN_FLAG, /* For multi seg per token id stand */
	ALLOC_TOKEN_ID_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ALLOC_TOKEN_ID_OUT_TOKEN_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ALLOC_TOKEN_ID_OUT_HANDLE,
	ALLOC_TOKEN_ID_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	ALLOC_TOKEN_ID_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_free_token_id */
/* udata is not required in out/in type */
enum uburma_cmd_free_token_id_type {
	/* In type */
	FREE_TOKEN_ID_IN_HANDLE,
	FREE_TOKEN_ID_IN_TOKEN_ID,
	FREE_TOKEN_ID_IN_NUM /* Only for calculating number of types */
};

/* See struct uburma_cmd_register_seg, in/out type should be continuous */
enum uburma_cmd_register_seg_type {
	/* In type */
	REGISTER_SEG_IN_VA,
	REGISTER_SEG_IN_LEN,
	REGISTER_SEG_IN_TOKEN_ID,
	REGISTER_SEG_IN_TOKEN_ID_HANDLE,
	REGISTER_SEG_IN_TOKEN,
	REGISTER_SEG_IN_FLAG,
	REGISTER_SEG_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	REGISTER_SEG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	REGISTER_SEG_OUT_TOKEN_ID = UBURMA_CMD_OUT_TYPE_INIT,
	REGISTER_SEG_OUT_HANDLE,
	REGISTER_SEG_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	REGISTER_SEG_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unregister_seg, in/out type should be continuous */
enum uburma_cmd_unregister_seg_type {
	/* In type */
	UNREGISTER_SEG_IN_HANDLE,
	UNREGISTER_SEG_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_import_seg, in/out type should be continuous */
enum uburma_cmd_import_seg_type {
	/* In type */
	IMPORT_SEG_IN_EID,
	IMPORT_SEG_IN_VA,
	IMPORT_SEG_IN_LEN,
	IMPORT_SEG_IN_FLAG,
	IMPORT_SEG_IN_TOKEN,
	IMPORT_SEG_IN_TOKEN_ID,
	IMPORT_SEG_IN_MVA,
	IMPORT_SEG_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	IMPORT_SEG_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_SEG_OUT_HANDLE = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_SEG_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	IMPORT_SEG_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unimport_seg */
enum uburma_cmd_unimport_seg_type {
	/* In type */
	UNIMPORT_SEG_IN_HANDLE,
	UNIMPORT_SEG_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jfs, in/out type should be continuous */
enum uburma_cmd_create_jfs_type {
	/* In type */
	CREATE_JFS_IN_DEPTH,
	CREATE_JFS_IN_FLAG,
	CREATE_JFS_IN_TRANS_MODE,
	CREATE_JFS_IN_PRIORITY,
	CREATE_JFS_IN_MAX_SGE,
	CREATE_JFS_IN_MAX_RSGE,
	CREATE_JFS_IN_MAX_INLINE_DATA,
	CREATE_JFS_IN_RETRY_CNT,
	CREATE_JFS_IN_RNR_RETRY,
	CREATE_JFS_IN_ERR_TIMEOUT,
	CREATE_JFS_IN_JFC_ID,
	CREATE_JFS_IN_JFC_HANDLE,
	CREATE_JFS_IN_URMA_JFS,
	CREATE_JFS_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	CREATE_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_JFS_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JFS_OUT_DEPTH,
	CREATE_JFS_OUT_MAX_SGE,
	CREATE_JFS_OUT_MAX_RSGE,
	CREATE_JFS_OUT_MAX_INLINE_DATA,
	CREATE_JFS_OUT_HANDLE,
	CREATE_JFS_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	CREATE_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_modify_jfs, in/out type should be continuous */
enum uburma_cmd_modify_jfs_type {
	/* In type */
	MODIFY_JFS_IN_HANDLE,
	MODIFY_JFS_IN_MASK,
	MODIFY_JFS_IN_STATE,
	MODIFY_JFS_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	MODIFY_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	/* Consider udata as an ordinary member of out specs */
	MODIFY_JFS_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	MODIFY_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_query_jfs, in/out type should be continuous */
enum uburma_cmd_query_jfs_type {
	/* In type */
	QUERY_JFS_IN_HANDLE,
	QUERY_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	QUERY_JFS_OUT_DEPTH = UBURMA_CMD_OUT_TYPE_INIT,
	QUERY_JFS_OUT_FLAG,
	QUERY_JFS_OUT_TRANS_MODE,
	QUERY_JFS_OUT_PRIORITY,
	QUERY_JFS_OUT_MAX_SGE,
	QUERY_JFS_OUT_MAX_RSGE,
	QUERY_JFS_OUT_MAX_INLINE_DATA,
	QUERY_JFS_OUT_RETRY_CNT,
	QUERY_JFS_OUT_RNR_RETRY,
	QUERY_JFS_OUT_ERR_TIMEOUT,
	QUERY_JFS_OUT_STATE,
	QUERY_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfs, in/out type should be continuous */
enum uburma_cmd_delete_jfs_type {
	/* In type */
	DELETE_JFS_IN_HANDLE,
	DELETE_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFS_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfs_batch, in/out type should be continuous */
enum uburma_cmd_delete_jfs_batch_type {
	/* In type */
	DELETE_JFS_BATCH_IN_JFS_COUNT,
	DELETE_JFS_BATCH_IN_JFS_PTR,
	DELETE_JFS_BATCH_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFS_BATCH_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFS_BATCH_OUT_BAD_JFS_INDEX,
	DELETE_JFS_BATCH_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_alloc_jfs_t, consistent with enum urma_cmd_alloc_jfs_type */
enum uburma_cmd_alloc_jfs_type {
	/* In type */
	ALLOC_JFS_IN_DEPTH,
	ALLOC_JFS_IN_FLAG,
	ALLOC_JFS_IN_TRANS_MODE,
	ALLOC_JFS_IN_PRIORITY,
	ALLOC_JFS_IN_MAX_SGE,
	ALLOC_JFS_IN_MAX_RSGE,
	ALLOC_JFS_IN_MAX_INLINE_DATA,
	ALLOC_JFS_IN_RNR_RETRY,
	ALLOC_JFS_IN_ERR_TIMEOUT,
	ALLOC_JFS_IN_JFC_ID,
	ALLOC_JFS_IN_JFC_HANDLE,
	ALLOC_JFS_IN_URMA_JFS,
	ALLOC_JFS_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	ALLOC_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ALLOC_JFS_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ALLOC_JFS_OUT_DEPTH,
	ALLOC_JFS_OUT_MAX_SGE,
	ALLOC_JFS_OUT_MAX_RSGE,
	ALLOC_JFS_OUT_MAX_INLINE_DATA,
	ALLOC_JFS_OUT_HANDLE,
	ALLOC_JFS_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	ALLOC_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_free_jfs_t, consistent with enum urma_cmd_free_jfs_type */
enum uburma_cmd_free_jfs_type {
	/* In type */
	FREE_JFS_IN_HANDLE,
	FREE_JFS_IN_UDATA,
	FREE_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	FREE_JFS_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	FREE_JFS_OUT_UDATA,
	FREE_JFS_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_set_jfs_opt_type {
	/* In type */
	SET_JFS_OPT_IN_HANDLE,
	SET_JFS_OPT_IN_OPT,
	SET_JFS_OPT_IN_BUF,
	SET_JFS_OPT_IN_LEN,
	SET_JFS_OPT_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	SET_JFS_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SET_JFS_OPT_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	SET_JFS_OPT_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_jfs_opt_type {
	/* In type */
	GET_JFS_OPT_IN_HANDLE,
	GET_JFS_OPT_IN_OPT,
	GET_JFS_OPT_IN_BUF,
	GET_JFS_OPT_IN_LEN,
	GET_JFS_OPT_IN_UDATA,
	GET_JFS_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_JFS_OPT_OUT_BUF = UBURMA_CMD_OUT_TYPE_INIT,
	GET_JFS_OPT_OUT_LEN,
	GET_JFS_OPT_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	GET_JFS_OPT_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_active_jfs_t, consistent with enum urma_cmd_active_jfs_type */
enum uburma_cmd_active_jfs_type {
	/* In type */
	ACTIVE_JFS_IN_HANDLE,
	ACTIVE_JFS_IN_DEPTH,
	ACTIVE_JFS_IN_FLAG,
	ACTIVE_JFS_IN_TRANS_MODE,
	ACTIVE_JFS_IN_PRIORITY,
	ACTIVE_JFS_IN_MAX_SGE,
	ACTIVE_JFS_IN_MAX_RSGE,
	ACTIVE_JFS_IN_MAX_INLINE_DATA,
	ACTIVE_JFS_IN_RNR_RETRY,
	ACTIVE_JFS_IN_ERR_TIMEOUT,
	ACTIVE_JFS_IN_JFC_ID,
	ACTIVE_JFS_IN_JFC_HANDLE,
	ACTIVE_JFS_IN_JFS_OPT,
	ACTIVE_JFS_IN_UDATA,
	ACTIVE_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ACTIVE_JFS_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ACTIVE_JFS_OUT_DEPTH,
	ACTIVE_JFS_OUT_MAX_SGE,
	ACTIVE_JFS_OUT_MAX_RSGE,
	ACTIVE_JFS_OUT_MAX_INLINE_DATA,
	ACTIVE_JFS_OUT_HANDLE,
	ACTIVE_JFS_OUT_UDATA,
	ACTIVE_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_deactive_jfs_t, consistent with enum uburma_cmd_deactive_jfs_type */
enum uburma_cmd_deactive_jfs_type {
	/* In type */
	DEACTIVE_JFS_IN_HANDLE,
	DEACTIVE_JFS_IN_UDATA,
	DEACTIVE_JFS_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DEACTIVE_JFS_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	DEACTIVE_JFS_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jfr, in/out type should be continuous */
enum uburma_cmd_create_jfr_type {
	/* In type */
	CREATE_JFR_IN_DEPTH,
	CREATE_JFR_IN_FLAG,
	CREATE_JFR_IN_TRANS_MODE,
	CREATE_JFR_IN_MAX_SGE,
	CREATE_JFR_IN_MIN_RNR_TIMER,
	CREATE_JFR_IN_JFC_ID,
	CREATE_JFR_IN_JFC_HANDLE,
	CREATE_JFR_IN_TOKEN,
	CREATE_JFR_IN_ID,
	CREATE_JFR_IN_URMA_JFR,
	CREATE_JFR_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	CREATE_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_JFR_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JFR_OUT_DEPTH,
	CREATE_JFR_OUT_MAX_SGE,
	CREATE_JFR_OUT_HANDLE,
	CREATE_JFR_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	CREATE_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_modify_jfr, in/out type should be continuous */
enum uburma_cmd_modify_jfr_type {
	/* In type */
	MODIFY_JFR_IN_HANDLE,
	MODIFY_JFR_IN_MASK,
	MODIFY_JFR_IN_RX_THRESHOLD,
	MODIFY_JFR_IN_STATE,
	MODIFY_JFR_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	MODIFY_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	/* Consider udata as an ordinary member of out specs */
	MODIFY_JFR_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	MODIFY_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_query_jfr, in/out type should be continuous */
enum uburma_cmd_query_jfr_type {
	/* In type */
	QUERY_JFR_IN_HANDLE,
	QUERY_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	QUERY_JFR_OUT_DEPTH = UBURMA_CMD_OUT_TYPE_INIT,
	QUERY_JFR_OUT_FLAG,
	QUERY_JFR_OUT_TRANS_MODE,
	QUERY_JFR_OUT_MAX_SGE,
	QUERY_JFR_OUT_MIN_RNR_TIMER,
	QUERY_JFR_OUT_TOKEN,
	QUERY_JFR_OUT_ID,
	QUERY_JFR_OUT_RX_THRESHOLD,
	QUERY_JFR_OUT_STATE,
	QUERY_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfr, in/out type should be continuous */
enum uburma_cmd_delete_jfr_type {
	/* In type */
	DELETE_JFR_IN_HANDLE,
	DELETE_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFR_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfr_batch, in/out type should be continuous */
enum uburma_cmd_delete_jfr_batch_type {
	/* In type */
	DELETE_JFR_BATCH_IN_JFR_COUNT,
	DELETE_JFR_BATCH_IN_JFR_PTR,
	DELETE_JFR_BATCH_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFR_BATCH_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFR_BATCH_OUT_BAD_JFR_INDEX,
	DELETE_JFR_BATCH_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_alloc_jfr_t, consistent with enum urma_cmd_alloc_jfr_type */
enum uburma_cmd_alloc_jfr_type {
	/* In type */
	ALLOC_JFR_IN_DEPTH,
	ALLOC_JFR_IN_FLAG,
	ALLOC_JFR_IN_TRANS_MODE,
	ALLOC_JFR_IN_MAX_SGE,
	ALLOC_JFR_IN_MIN_RNR_TIMER,
	ALLOC_JFR_IN_JFC_ID,
	ALLOC_JFR_IN_JFC_HANDLE,
	ALLOC_JFR_IN_TOKEN,
	ALLOC_JFR_IN_ID,
	ALLOC_JFR_IN_URMA_JFR,
	ALLOC_JFR_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	ALLOC_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ALLOC_JFR_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ALLOC_JFR_OUT_DEPTH,
	ALLOC_JFR_OUT_HANDLE,
	ALLOC_JFR_OUT_MAX_SGE,
	ALLOC_JFR_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	ALLOC_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_free_jfr_t, consistent with enum urma_cmd_free_jfr_type */
enum uburma_cmd_free_jfr_type {
	/* In type */
	FREE_JFR_IN_HANDLE,
	FREE_JFR_IN_UDATA,
	FREE_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	FREE_JFR_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	FREE_JFR_OUT_UDATA,
	FREE_JFR_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_set_jfr_opt_type {
	/* In type */
	SET_JFR_OPT_IN_HANDLE,
	SET_JFR_OPT_IN_OPT,
	SET_JFR_OPT_IN_BUF,
	SET_JFR_OPT_IN_LEN,
	SET_JFR_OPT_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	SET_JFR_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SET_JFR_OPT_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	SET_JFR_OPT_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_jfr_opt_type {
	/* In type */
	GET_JFR_OPT_IN_HANDLE,
	GET_JFR_OPT_IN_OPT,
	GET_JFR_OPT_IN_BUF,
	GET_JFR_OPT_IN_LEN,
	GET_JFR_OPT_IN_UDATA,
	GET_JFR_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_JFR_OPT_OUT_BUF = UBURMA_CMD_OUT_TYPE_INIT,
	GET_JFR_OPT_OUT_LEN,
	GET_JFR_OPT_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	GET_JFR_OPT_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_active_jfr_t, consistent with enum urma_cmd_active_jfr_type */
enum uburma_cmd_active_jfr_type {
	/* In type */
	ACTIVE_JFR_IN_HANDLE,
	ACTIVE_JFR_IN_DEPTH,
	ACTIVE_JFR_IN_FLAG,
	ACTIVE_JFR_IN_TRANS_MODE,
	ACTIVE_JFR_IN_MAX_SGE,
	ACTIVE_JFR_IN_MIN_RNR_TIMER,
	ACTIVE_JFR_IN_JFC_ID,
	ACTIVE_JFR_IN_JFC_HANDLE,
	ACTIVE_JFR_IN_TOKEN,
	ACTIVE_JFR_IN_JFR_OPT,
	ACTIVE_JFR_IN_UDATA,
	ACTIVE_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ACTIVE_JFR_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ACTIVE_JFR_OUT_DEPTH,
	ACTIVE_JFR_OUT_HANDLE,
	ACTIVE_JFR_OUT_MAX_SGE,
	ACTIVE_JFR_OUT_UDATA,
	ACTIVE_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_deactive_jfr_t, consistent with enum urma_cmd_deactive_jfr_type */
enum uburma_cmd_deactive_jfr_type {
	/* In type */
	DEACTIVE_JFR_IN_HANDLE,
	DEACTIVE_JFR_IN_UDATA,
	DEACTIVE_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DEACTIVE_JFR_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	DEACTIVE_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jfc, in/out type should be continuous */
enum uburma_cmd_create_jfc_type {
	/* In type */
	CREATE_JFC_IN_DEPTH,
	CREATE_JFC_IN_FLAG,
	CREATE_JFC_IN_JFCE_FD,
	CREATE_JFC_IN_URMA_JFC,
	CREATE_JFC_IN_CEQN,
	CREATE_JFC_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	CREATE_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_JFC_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JFC_OUT_DEPTH,
	CREATE_JFC_OUT_HANDLE,
	CREATE_JFC_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	CREATE_JFC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_modify_jfc, in/out type should be continuous */
enum uburma_cmd_modify_jfc_type {
	/* In type */
	MODIFY_JFC_IN_HANDLE,
	MODIFY_JFC_IN_MASK,
	MODIFY_JFC_IN_MODERATE_COUNT,
	MODIFY_JFC_IN_MODERATE_PERIOD,
	MODIFY_JFC_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	MODIFY_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	/* Consider udata as an ordinary member of out specs */
	MODIFY_JFC_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	MODIFY_JFC_OUT_NUM /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfc, in/out type should be continuous */
enum uburma_cmd_delete_jfc_type {
	/* In type */
	DELETE_JFC_IN_HANDLE,
	DELETE_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFC_OUT_COMP_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFC_OUT_ASYNC_EVENTS_REPORTED,
	DELETE_JFC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jfc_batch, in/out type should be continuous */
enum uburma_cmd_delete_jfc_batch_type {
	/* In type */
	DELETE_JFC_BATCH_IN_JFC_COUNT,
	DELETE_JFC_BATCH_IN_JFC_PTR,
	DELETE_JFC_BATCH_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JFC_BATCH_OUT_COMP_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JFC_BATCH_OUT_ASYNC_EVENTS_REPORTED,
	DELETE_JFC_BATCH_OUT_BAD_JFC_INDEX,
	DELETE_JFC_BATCH_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_alloc_jfc, in/out type should be continuous */
/* See urma_cmd_create_jfc_t, consistent with enum uburma_cmd_create_jfc_type */
enum uburma_cmd_alloc_jfc_type {
	/* In type */
	ALLOC_JFC_IN_DEPTH,
	ALLOC_JFC_IN_FLAG,
	ALLOC_JFC_IN_JFCE_FD,
	ALLOC_JFC_IN_URMA_JFC,
	ALLOC_JFC_IN_CEQN,
	ALLOC_JFC_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	ALLOC_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ALLOC_JFC_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ALLOC_JFC_OUT_DEPTH,
	ALLOC_JFC_OUT_HANDLE,
	ALLOC_JFC_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	ALLOC_JFC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_free_jfc, in/out type should be continuous */
enum uburma_cmd_free_jfc_type {
	/* In type */
	FREE_JFC_IN_HANDLE,
	FREE_JFC_IN_UDATA,
	FREE_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	FREE_JFC_OUT_COMP_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	FREE_JFC_OUT_ASYNC_EVENTS_REPORTED,
	FREE_JFC_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	FREE_JFC_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_set_jfc_opt_type {
	/* In type */
	SET_JFC_OPT_IN_HANDLE,
	SET_JFC_OPT_IN_OPT,
	SET_JFC_OPT_IN_BUF,
	SET_JFC_OPT_IN_LEN,
	SET_JFC_OPT_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	SET_JFC_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SET_JFC_OPT_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	SET_JFC_OPT_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_jfc_opt_type {
	/* In type */
	GET_JFC_OPT_IN_HANDLE,
	GET_JFC_OPT_IN_OPT,
	GET_JFC_OPT_IN_BUF,
	GET_JFC_OPT_IN_LEN,
	GET_JFC_OPT_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	GET_JFC_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_JFC_OPT_OUT_BUF = UBURMA_CMD_OUT_TYPE_INIT,
	GET_JFC_OPT_OUT_LEN,
	GET_JFC_OPT_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	GET_JFC_OPT_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_active_jfc_t, consistent with enum uburma_cmd_active_jfc_type */
enum uburma_cmd_active_jfc_type {
	/* In type */
	ACTIVE_JFC_IN_HANDLE,
	ACTIVE_JFC_IN_DEPTH,
	ACTIVE_JFC_IN_FLAG,
	ACTIVE_JFC_IN_CEQN,
	ACTIVE_JFC_IN_JFC_OPT,
	ACTIVE_JFC_IN_UDATA,
	ACTIVE_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ACTIVE_JFC_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ACTIVE_JFC_OUT_DEPTH,
	ACTIVE_JFC_OUT_HANDLE,
	ACTIVE_JFC_OUT_UDATA,
	ACTIVE_JFC_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_deactive_jfc_t, consistent with enum uburma_cmd_deactive_jfc_type */
enum uburma_cmd_deactive_jfc_type {
	/* In type */
	DEACTIVE_JFC_IN_HANDLE,
	DEACTIVE_JFC_IN_UDATA,
	DEACTIVE_JFC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DEACTIVE_JFC_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	DEACTIVE_JFC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jfce, in/out type should be continuous */
enum uburma_cmd_create_jfce_type {
	/* Out type */
	CREATE_JFCE_OUT_FD = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JFCE_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_import_jfr, in/out type should be continuous */
enum uburma_cmd_import_jfr_type {
	/* In type */
	IMPORT_JFR_IN_EID,
	IMPORT_JFR_IN_ID,
	IMPORT_JFR_IN_FLAG,
	IMPORT_JFR_IN_TOKEN,
	IMPORT_JFR_IN_TRANS_MODE,
	IMPORT_JFR_IN_TP_TYPE,
	IMPORT_JFR_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	IMPORT_JFR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_JFR_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_JFR_OUT_HANDLE,
	IMPORT_JFR_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	IMPORT_JFR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_import_jfr_ex, in/out type should be continuous */
enum uburma_cmd_import_jfr_ex_type {
	/* In type */
	IMPORT_JFR_EX_IN_EID,
	IMPORT_JFR_EX_IN_ID,
	IMPORT_JFR_EX_IN_FLAG,
	IMPORT_JFR_EX_IN_TOKEN,
	IMPORT_JFR_EX_IN_TRANS_MODE,
	IMPORT_JFR_EX_IN_TP_TYPE,
	IMPORT_JFR_EX_IN_TP_HANDLE,
	IMPORT_JFR_EX_IN_PEER_TP_HANDLE,
	IMPORT_JFR_EX_IN_TAG,
	IMPORT_JFR_EX_IN_TX_PSN,
	IMPORT_JFR_EX_IN_RX_PSN,
	IMPORT_JFR_EX_IN_UDATA, /* Consider udata as an ordinary member of in specs */
	IMPORT_JFR_EX_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_JFR_EX_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_JFR_EX_OUT_HANDLE,
	IMPORT_JFR_EX_OUT_UDATA, /* Consider udata as an ordinary member of out specs */
	IMPORT_JFR_EX_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unimport_jfr, in/out type should be continuous */
enum uburma_cmd_unimport_jfr_type {
	/* In type */
	UNIMPORT_JFR_IN_HANDLE,
	UNIMPORT_JFR_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jetty, in/out type should be continuous */
enum uburma_cmd_create_jetty_type {
	/* In type */
	CREATE_JETTY_IN_ID,
	CREATE_JETTY_IN_JETTY_FLAG,
	CREATE_JETTY_IN_JFS_DEPTH,
	CREATE_JETTY_IN_JFS_FLAG,
	CREATE_JETTY_IN_TRANS_MODE,
	CREATE_JETTY_IN_PRIORITY,
	CREATE_JETTY_IN_MAX_SEND_SGE,
	CREATE_JETTY_IN_MAX_SEND_RSGE,
	CREATE_JETTY_IN_MAX_INLINE_DATA,
	CREATE_JETTY_IN_RNR_RETRY,
	CREATE_JETTY_IN_ERR_TIMEOUT,
	CREATE_JETTY_IN_SEND_JFC_ID,
	CREATE_JETTY_IN_SEND_JFC_HANDLE,
	CREATE_JETTY_IN_JFR_DEPTH,
	CREATE_JETTY_IN_JFR_FLAG,
	CREATE_JETTY_IN_MAX_RECV_SGE,
	CREATE_JETTY_IN_MIN_RNR_TIMER,
	CREATE_JETTY_IN_RECV_JFC_ID,
	CREATE_JETTY_IN_RECV_JFC_HANDLE,
	CREATE_JETTY_IN_TOKEN,
	CREATE_JETTY_IN_JFR_ID,
	CREATE_JETTY_IN_JFR_HANDLE,
	CREATE_JETTY_IN_JETTY_GRP_HANDLE,
	CREATE_JETTY_IN_IS_JETTY_GRP,
	CREATE_JETTY_IN_URMA_JETTY,
	CREATE_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	CREATE_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_JETTY_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JETTY_OUT_HANDLE,
	CREATE_JETTY_OUT_JFS_DEPTH,
	CREATE_JETTY_OUT_JFR_DEPTH,
	CREATE_JETTY_OUT_MAX_SEND_SGE,
	CREATE_JETTY_OUT_MAX_SEND_RSGE,
	CREATE_JETTY_OUT_MAX_RECV_SGE,
	CREATE_JETTY_OUT_MAX_INLINE_DATA,
	CREATE_JETTY_OUT_UDATA, /* Consider udata as an in/out attr */
	CREATE_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_modify_jetty, in/out type should be continuous */
enum uburma_cmd_modify_jetty_type {
	/* In type */
	MODIFY_JETTY_IN_HANDLE,
	MODIFY_JETTY_IN_MASK,
	MODIFY_JETTY_IN_RX_THRESHOLD,
	MODIFY_JETTY_IN_STATE,
	MODIFY_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	MODIFY_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	MODIFY_JETTY_OUT_UDATA =
		UBURMA_CMD_OUT_TYPE_INIT, /* Consider udata as an in/out attr */
	MODIFY_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_query_jetty, in/out type should be continuous */
enum uburma_cmd_query_jetty_type {
	/* In type */
	QUERY_JETTY_IN_HANDLE,
	QUERY_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	QUERY_JETTY_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	QUERY_JETTY_OUT_JETTY_FLAG,
	QUERY_JETTY_OUT_JFS_DEPTH,
	QUERY_JETTY_OUT_JFR_DEPTH,
	QUERY_JETTY_OUT_JFS_FLAG,
	QUERY_JETTY_OUT_JFR_FLAG,
	QUERY_JETTY_OUT_TRANS_MODE,
	QUERY_JETTY_OUT_MAX_SEND_SGE,
	QUERY_JETTY_OUT_MAX_SEND_RSGE,
	QUERY_JETTY_OUT_MAX_RECV_SGE,
	QUERY_JETTY_OUT_MAX_INLINE_DATA,
	QUERY_JETTY_OUT_PRIORITY,
	QUERY_JETTY_OUT_RETRY_CNT,
	QUERY_JETTY_OUT_RNR_RETRY,
	QUERY_JETTY_OUT_ERR_TIMEOUT,
	QUERY_JETTY_OUT_MIN_RNR_TIMER,
	QUERY_JETTY_OUT_JFR_ID,
	QUERY_JETTY_OUT_TOKEN,
	QUERY_JETTY_OUT_RX_THRESHOLD,
	QUERY_JETTY_OUT_STATE,
	QUERY_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jetty, in/out type should be continuous */
enum uburma_cmd_delete_jetty_type {
	/* In type */
	DELETE_JETTY_IN_HANDLE,
	DELETE_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JETTY_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jetty_batch, in/out type should be continuous */
enum uburma_cmd_delete_jetty_batch_type {
	/* In type */
	DELETE_JETTY_BATCH_IN_JETTY_COUNT,
	DELETE_JETTY_BATCH_IN_JETTY_PTR,
	DELETE_JETTY_BATCH_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JETTY_BATCH_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JETTY_BATCH_OUT_BAD_JETTY_INDEX,
	DELETE_JETTY_BATCH_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_import_jetty, in/out type should be continuous */
enum uburma_cmd_import_jetty_type {
	/* In type */
	IMPORT_JETTY_IN_EID,
	IMPORT_JETTY_IN_ID,
	IMPORT_JETTY_IN_FLAG,
	IMPORT_JETTY_IN_TOKEN,
	IMPORT_JETTY_IN_TRANS_MODE,
	IMPORT_JETTY_IN_POLICY,
	IMPORT_JETTY_IN_TYPE,
	IMPORT_JETTY_IN_TP_TYPE,
	IMPORT_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_JETTY_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_JETTY_OUT_HANDLE,
	IMPORT_JETTY_OUT_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_import_jetty_ex, in/out type should be continuous */
enum uburma_cmd_import_jetty_ex_type {
	/* In type */
	IMPORT_JETTY_EX_IN_EID,
	IMPORT_JETTY_EX_IN_ID,
	IMPORT_JETTY_EX_IN_FLAG,
	IMPORT_JETTY_EX_IN_TOKEN,
	IMPORT_JETTY_EX_IN_TRANS_MODE,
	IMPORT_JETTY_EX_IN_POLICY,
	IMPORT_JETTY_EX_IN_TYPE,
	IMPORT_JETTY_EX_IN_TP_TYPE,
	IMPORT_JETTY_EX_IN_TP_HANDLE,
	IMPORT_JETTY_EX_IN_PEER_TP_HANDLE,
	IMPORT_JETTY_EX_IN_TAG,
	IMPORT_JETTY_EX_IN_TX_PSN,
	IMPORT_JETTY_EX_IN_RX_PSN,
	IMPORT_JETTY_EX_IN_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_EX_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_JETTY_EX_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_JETTY_EX_OUT_HANDLE,
	IMPORT_JETTY_EX_OUT_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_EX_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unimport_jetty, in/out type should be continuous */
enum uburma_cmd_unimport_jetty_type {
	/* In type */
	UNIMPORT_JETTY_IN_HANDLE,
	UNIMPORT_JETTY_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_advise_jetty, in/out type should be continuous */
enum uburma_cmd_advise_jetty_type {
	/* In type */
	ADVISE_JETTY_IN_JETTY_HANDLE,
	ADVISE_JETTY_IN_TJETTY_HANDLE,
	ADVISE_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	ADVISE_JETTY_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unadvise_jetty, in/out type should be continuous */
enum uburma_cmd_unadvise_jetty_type {
	/* In type */
	UNADVISE_JETTY_IN_JETTY_HANDLE,
	UNADVISE_JETTY_IN_TJETTY_HANDLE,
	UNADVISE_JETTY_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_bind_jetty, in/out type should be continuous */
enum uburma_cmd_bind_jetty_type {
	/* In type */
	BIND_JETTY_IN_JETTY_HANDLE,
	BIND_JETTY_IN_TJETTY_HANDLE,
	BIND_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	BIND_JETTY_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	BIND_JETTY_OUT_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_bind_jetty_ex, in/out type should be continuous */
enum uburma_cmd_bind_jetty_ex_type {
	/* In type */
	BIND_JETTY_EX_IN_JETTY_HANDLE,
	BIND_JETTY_EX_IN_TJETTY_HANDLE,
	BIND_JETTY_EX_IN_TP_HANDLE,
	BIND_JETTY_EX_IN_PEER_TP_HANDLE,
	BIND_JETTY_EX_IN_TAG,
	BIND_JETTY_EX_IN_TX_PSN,
	BIND_JETTY_EX_IN_RX_PSN,
	BIND_JETTY_EX_IN_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_EX_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	BIND_JETTY_EX_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	BIND_JETTY_EX_OUT_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_EX_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_jetty_grp, in/out type should be continuous */
enum uburma_cmd_create_jetty_grp_type {
	/* In type */
	CREATE_JETTY_GRP_IN_NAME,
	CREATE_JETTY_GRP_IN_TOKEN,
	CREATE_JETTY_GRP_IN_ID,
	CREATE_JETTY_GRP_IN_POLICY,
	CREATE_JETTY_GRP_IN_FLAG,
	CREATE_JETTY_GRP_IN_URMA_JETTY_GRP,
	CREATE_JETTY_GRP_IN_UDATA, /* Consider udata as an in/out attr */
	CREATE_JETTY_GRP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	CREATE_JETTY_GRP_OUT_ID = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_JETTY_GRP_OUT_HANDLE,
	CREATE_JETTY_GRP_OUT_UDATA, /* Consider udata as an in/out attr */
	CREATE_JETTY_GRP_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_delete_jetty_grp, in/out type should be continuous */
enum uburma_cmd_delete_jetty_grp_type {
	/* In type */
	DELETE_JETTY_GRP_IN_HANDLE,
	DELETE_JETTY_GRP_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DELETE_JETTY_GRP_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	DELETE_JETTY_GRP_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_alloc_jetty_type {
	/* In type */
	ALLOC_JETTY_IN_CFG,
	ALLOC_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	ALLOC_JETTY_OUT_CFG = UBURMA_CMD_OUT_TYPE_INIT,
	ALLOC_JETTY_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_free_jetty_type {
	/* In type */
	FREE_JETTY_IN_HANDLE,
	FREE_JETTY_IN_UDATA,
	FREE_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	FREE_JETTY_OUT_ASYNC_EVENTS_REPORTED = UBURMA_CMD_OUT_TYPE_INIT,
	FREE_JETTY_OUT_UDATA,
	FREE_JETTY_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_set_jetty_opt_type {
	/* In type */
	SET_JETTY_OPT_IN_HANDLE,
	SET_JETTY_OPT_IN_OPT,
	SET_JETTY_OPT_IN_BUF,
	SET_JETTY_OPT_IN_LEN,
	SET_JETTY_OPT_IN_UDATA, /* Consider udata as an ordinary member of in attrs */
	SET_JETTY_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SET_JETTY_OPT_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	SET_JETTY_OPT_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_jetty_opt_type {
	/* In type */
	GET_JETTY_OPT_IN_HANDLE,
	GET_JETTY_OPT_IN_OPT,
	GET_JETTY_OPT_IN_BUF,
	GET_JETTY_OPT_IN_LEN,
	GET_JETTY_OPT_IN_UDATA,
	GET_JETTY_OPT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_JETTY_OPT_OUT_BUF = UBURMA_CMD_OUT_TYPE_INIT,
	GET_JETTY_OPT_OUT_LEN,
	GET_JETTY_OPT_OUT_UDATA, /* Consider udata as an ordinary member of out attrs */
	GET_JETTY_OPT_OUT_NUM, /* Only for calculating number of types */
};

/* See urma_cmd_active_jetty_t, consistent with enum uburma_cmd_active_jetty_type */
enum uburma_cmd_active_jetty_type {
	/* In type */
	ACTIVE_JETTY_IN_FLAG,
	ACTIVE_JETTY_IN_HANDLE,
	ACTIVE_JETTY_IN_SEND_JFC_HANDLE,
	ACTIVE_JETTY_IN_RECV_JFC_HANDLE,
	ACTIVE_JETTY_IN_URMA_JETTY,
	ACTIVE_JETTY_IN_JETTY_OPT,
	ACTIVE_JETTY_IN_UDATA, /* Consider udata as an in/out attr */
	ACTIVE_JETTY_IN_NUM,   /* Only for calculating number of types */
	/* Out type */
	ACTIVE_JETTY_OUT_JETTY_ID = UBURMA_CMD_OUT_TYPE_INIT,
	ACTIVE_JETTY_OUT_UDATA, /* Consider udata as an in/out attr */
	ACTIVE_JETTY_OUT_NUM,   /* Only for calculating number of types */
};

/* See urma_cmd_deactive_jetty_t, consistent with enum uburma_cmd_deactive_jetty_type */
enum uburma_cmd_deactive_jetty_type {
	/* In type */
	DEACTIVE_JETTY_IN_HANDLE,
	DEACTIVE_JETTY_IN_UDATA,
	DEACTIVE_JETTY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	DEACTIVE_JETTY_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	DEACTIVE_JETTY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_user_ctl, in/out type should be continuous */
enum uburma_cmd_user_ctl_type {
	/* In type */
	USER_CTL_IN_IN_ADDR,
	USER_CTL_IN_IN_LEN,
	USER_CTL_IN_OPCODE,
	USER_CTL_IN_OUT_ADDR,
	USER_CTL_IN_OUT_LEN,
	USER_CTL_IN_UDATA,
	USER_CTL_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_get_eid_list, in/out type should be continuous */
enum uburma_cmd_get_eid_list_type {
	/* In type */
	GET_EID_LIST_IN_MAX_EID_CNT,
	GET_EID_LIST_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_EID_LIST_OUT_EID_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	GET_EID_LIST_OUT_EID_LIST, /* This array is considered as a whole */
	GET_EID_LIST_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_get_net_addr_list, in/out type should be continuous */
enum uburma_cmd_get_net_addr_list_type {
	/* In type */
	GET_NET_ADDR_LIST_IN_MAX_NETADDR_CNT,
	GET_NET_ADDR_LIST_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_NET_ADDR_LIST_OUT_NETADDR_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	GET_NET_ADDR_LIST_OUT_NETADDR_LIST, /* This array is considered as a whole */
	GET_NET_ADDR_LIST_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_modify_tp, in/out type should be continuous */
enum uburma_cmd_modify_tp_type {
	/* In type */
	MODIFY_TP_IN_TPN,
	MODIFY_TP_IN_TP_CFG_FLAG,
	MODIFY_TP_IN_TP_CFG_TRANS_MODE,
	MODIFY_TP_IN_TP_CFG_RETRY_NUM,
	MODIFY_TP_IN_TP_CFG_RETRY_FACTOR,
	MODIFY_TP_IN_TP_CFG_ACK_TIMEOUT,
	MODIFY_TP_IN_TP_CFG_DSCP,
	MODIFY_TP_IN_TP_CFG_OOR_CNT,
	MODIFY_TP_IN_ATTR_FLAG,
	MODIFY_TP_IN_ATTR_PEER_TPN,
	MODIFY_TP_IN_ATTR_STATE,
	MODIFY_TP_IN_ATTR_TX_PSN,
	MODIFY_TP_IN_ATTR_RX_PSN,
	MODIFY_TP_IN_ATTR_MTU,
	MODIFY_TP_IN_ATTR_CC_PATTERN_IDX,
	MODIFY_TP_IN_ATTR_OOS_CNT,
	MODIFY_TP_IN_ATTR_LOCAL_NET_ADDR_IDX,
	MODIFY_TP_IN_ATTR_PEER_NET_ADDR,
	MODIFY_TP_IN_ATTR_DATA_UDP_START,
	MODIFY_TP_IN_ATTR_ACK_UDP_START,
	MODIFY_TP_IN_ATTR_UDP_RANGE,
	MODIFY_TP_IN_ATTR_HOP_LIMIT,
	MODIFY_TP_IN_ATTR_FLOW_LABEL,
	MODIFY_TP_IN_ATTR_PORT_ID,
	MODIFY_TP_IN_ATTR_MN,
	MODIFY_TP_IN_ATTR_PEER_TRANS_TYPE,
	MODIFY_TP_IN_MASK,
	MODIFY_TP_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_query_device_attr, in/out type should be continuous */
enum uburma_cmd_query_device_attr_type {
	/* In type */
	QUERY_DEVICE_IN_DEV_NAME,
	QUERY_DEVICE_IN_NUM,
	/* Out type */
	QUERY_DEVICE_OUT_GUID = UBURMA_CMD_OUT_TYPE_INIT,
	QUERY_DEVICE_OUT_DEV_CAP_FEATURE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_GRP,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_IN_JETTY_GRP,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC_DEPTH,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_DEPTH,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_DEPTH,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_INLINE_LEN,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_SGE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_RSGE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_SGE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_MSG_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_READ_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_WRITE_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_CAS_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_SWAP_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_ADD_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_SUB_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_AND_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_OR_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_XOR_SIZE,
	QUERY_DEVICE_OUT_DEV_CAP_ATOMIC_FEAT,
	QUERY_DEVICE_OUT_DEV_CAP_TRANS_MODE,
	QUERY_DEVICE_OUT_DEV_CAP_CONGESTION_CTRL_ALG,
	QUERY_DEVICE_OUT_DEV_CAP_CEQ_CNT,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_TP_IN_TPG,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_EID_CNT,
	QUERY_DEVICE_OUT_DEV_CAP_PAGE_SIZE_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_OOR_CNT,
	QUERY_DEVICE_OUT_DEV_CAP_MN,
	QUERY_DEVICE_OUT_DEV_CAP_MAX_NETADDR_CN,
	QUERY_DEVICE_OUT_PORT_CNT,
	QUERY_DEVICE_OUT_PORT_ATTR_MAX_MTU,
	QUERY_DEVICE_OUT_PORT_ATTR_STATE,
	QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_WIDTH,
	QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_SPEED,
	QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_MTU,
	QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MIN,
	QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MAX,
	QUERY_DEVICE_OUT_DEV_CAP_RM_ORDER_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_RC_ORDER_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_RM_TP_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_RC_TP_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_UM_TP_CAP,
	QUERY_DEVICE_OUT_DEV_CAP_TP_FEATURE,
	QUERY_DEVICE_OUT_DEV_CAP_PRIORITY_INFO,
	QUERY_DEVICE_OUT_NUM,
};

/* See struct uburma_cmd_import_jetty_async, in/out type should be continuous */
enum uburma_cmd_import_jetty_async_type {
	/* In type */
	IMPORT_JETTY_ASYNC_IN_EID,
	IMPORT_JETTY_ASYNC_IN_ID,
	IMPORT_JETTY_ASYNC_IN_FLAG,
	IMPORT_JETTY_ASYNC_IN_TOKEN,
	IMPORT_JETTY_ASYNC_IN_TRANS_MODE,
	IMPORT_JETTY_ASYNC_IN_POLICY,
	IMPORT_JETTY_ASYNC_IN_TYPE,
	IMPORT_JETTY_ASYNC_IN_URMA_TJETTY,
	IMPORT_JETTY_ASYNC_IN_USER_CTX,
	IMPORT_JETTY_ASYNC_IN_FD,
	IMPORT_JETTY_ASYNC_IN_TIMEOUT,
	IMPORT_JETTY_ASYNC_IN_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_ASYNC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	IMPORT_JETTY_ASYNC_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	IMPORT_JETTY_ASYNC_OUT_HANDLE,
	IMPORT_JETTY_ASYNC_OUT_UDATA, /* Consider udata as an in/out attr */
	IMPORT_JETTY_ASYNC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unimport_jetty_async, in/out type should be continuous */
enum uburma_cmd_unimport_jetty_async_type {
	/* In type */
	UNIMPORT_JETTY_ASYNC_IN_HANDLE,
	UNIMPORT_JETTY_ASYNC_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_bind_jetty_async, in/out type should be continuous */
enum uburma_cmd_bind_jetty_async_type {
	/* In type */
	BIND_JETTY_ASYNC_IN_JETTY_HANDLE,
	BIND_JETTY_ASYNC_IN_TJETTY_HANDLE,
	BIND_JETTY_ASYNC_IN_URMA_TJETTY,
	BIND_JETTY_ASYNC_IN_URMA_JETTY,
	BIND_JETTY_ASYNC_IN_FD,
	BIND_JETTY_ASYNC_IN_USER_CTX,
	BIND_JETTY_ASYNC_IN_TIMEOUT,
	BIND_JETTY_ASYNC_IN_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_ASYNC_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	BIND_JETTY_ASYNC_OUT_TPN = UBURMA_CMD_OUT_TYPE_INIT,
	BIND_JETTY_ASYNC_OUT_UDATA, /* Consider udata as an in/out attr */
	BIND_JETTY_ASYNC_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_unbind_jetty_async, in/out type should be continuous */
enum uburma_cmd_unbind_jetty_async_type {
	/* In type */
	UNBIND_JETTY_ASYNC_IN_JETTY_HANDLE,
	UNBIND_JETTY_ASYNC_IN_TJETTY_HANDLE,
	UNBIND_JETTY_ASYNC_IN_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_create_notifier, in/out type should be continuous */
enum uburma_cmd_create_notifier_type {
	/* Out type */
	CREATE_NOTIFIER_OUT_FD = UBURMA_CMD_OUT_TYPE_INIT,
	CREATE_NOTIFIER_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_get_tp_list, in/out type should be continuous */
enum uburma_cmd_get_tp_list_type {
	/* In type */
	GET_TP_LIST_IN_FLAG,
	GET_TP_LIST_IN_TRANS_MODE,
	GET_TP_LIST_IN_LOCAL_EID,
	GET_TP_LIST_IN_PEER_EID,
	GET_TP_LIST_IN_TP_CNT,
	GET_TP_LIST_IN_UDATA,
	GET_TP_LIST_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_TP_LIST_OUT_TP_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	GET_TP_LIST_OUT_TP_HANDLE,
	GET_TP_LIST_OUT_UDATA,
	GET_TP_LIST_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_set_tp_attr, in/out type should be continuous */
enum uburma_cmd_set_tp_attr_type {
	/* In type */
	SET_TP_ATTR_IN_TP_HANLDE,
	SET_TP_ATTR_IN_TP_ATTR_CNT,
	SET_TP_ATTR_IN_TP_ATTR_BITMAP,
	SET_TP_ATTR_IN_TP_ATTR,
	SET_TP_ATTR_IN_UDATA,
	SET_TP_ATTR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	SET_TP_ATTR_OUT_UDATA = UBURMA_CMD_OUT_TYPE_INIT,
	SET_TP_ATTR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_get_tp_attr, in/out type should be continuous */
enum uburma_cmd_get_tp_attr_type {
	/* In type */
	GET_TP_ATTR_IN_TP_HANDLE,
	GET_TP_ATTR_IN_UDATA,
	GET_TP_ATTR_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	GET_TP_ATTR_OUT_TP_ATTR_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	GET_TP_ATTR_OUT_TP_ATTR_BITMAP,
	GET_TP_ATTR_OUT_TP_ATTR,
	GET_TP_ATTR_OUT_UDATA,
	GET_TP_ATTR_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_jfce_wait, in/out type should be continuous */
enum uburma_cmd_jfce_wait_type {
	/* In type */
	JFCE_WAIT_IN_MAX_EVENT_CNT,
	JFCE_WAIT_IN_TIME_OUT,
	JFCE_WAIT_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	JFCE_WAIT_OUT_EVENT_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	JFCE_WAIT_OUT_EVENT_DATA,
	JFCE_WAIT_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_async_event, in/out type should be continuous */
enum uburma_cmd_async_event_type {
	/* Out type */
	GET_ASYNC_EVENT_OUT_EVENT_TYPE = UBURMA_CMD_OUT_TYPE_INIT,
	GET_ASYNC_EVENT_OUT_EVENT_DATA,
	GET_ASYNC_EVENT_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_wait_notify, in/out type should be continuous */
enum uburma_cmd_wait_notify_type {
	/* In type */
	WAIT_NOTIFY_IN_CNT,
	WAIT_NOTIFY_IN_TIMEOUT,
	WAIT_NOTIFY_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	WAIT_NOTIFY_OUT_CNT = UBURMA_CMD_OUT_TYPE_INIT,
	WAIT_NOTIFY_OUT_NOTIFY,
	WAIT_NOTIFY_OUT_NUM, /* Only for calculating number of types */
};

/* See struct uburma_cmd_exchange_tp_info, in/out type should be continuous */
enum uburma_cmd_exchange_tp_info_type {
	/* In type */
	EXCHANGE_TP_INFO_IN_FLAG,
	EXCHANGE_TP_INFO_IN_TRANS_MODE,
	EXCHANGE_TP_INFO_IN_LOCAL_EID,
	EXCHANGE_TP_INFO_IN_PEER_EID,
	EXCHANGE_TP_INFO_IN_TP_HANDLE,
	EXCHANGE_TP_INFO_IN_TX_PSN,
	EXCHANGE_TP_INFO_IN_NUM, /* Only for calculating number of types */
	/* Out type */
	EXCHANGE_TP_INFO_OUT_PEER_TP_HANDLE = UBURMA_CMD_OUT_TYPE_INIT,
	EXCHANGE_TP_INFO_OUT_RX_PSN,
	EXCHANGE_TP_INFO_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_eid_by_ip_type {
	/* In type */
	GET_EID_BY_IP_INFO_IN_NET_ADDR,
	GET_EID_BY_IP_INFO_IN_NUM,
	/* Out type */
	GET_EID_BY_IP_INFO_OUT_EID = UBURMA_CMD_OUT_TYPE_INIT,
	GET_EID_BY_IP_INFO_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_ip_by_eid_type {
	/* In type */
	GET_IP_BY_EID_INFO_IN_EID,
	GET_IP_BY_EID_INFO_IN_NUM,
	/* Out type */
	GET_IP_BY_EID_INFO_OUT_NET_ADDR = UBURMA_CMD_OUT_TYPE_INIT,
	GET_IP_BY_EID_INFO_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_smac_type {
	/* Out type */
	GET_SMAC_OUT_MAC = UBURMA_CMD_OUT_TYPE_INIT,
	GET_SMAC_OUT_NUM, /* Only for calculating number of types */
};

enum uburma_cmd_get_dmac_type {
	/* In type */
	GET_DMAC_IN_NET_ADDR,
	GET_DMAC_IN_NUM,
	/* Out type */
	GET_DMAC_OUT_MAC = UBURMA_CMD_OUT_TYPE_INIT,
	GET_DMAC_OUT_NUM, /* Only for calculating number of types */
};

int uburma_tlv_parse(struct uburma_cmd_hdr *hdr, void *arg);
int uburma_tlv_append(struct uburma_cmd_hdr *hdr, void *arg);

int uburma_event_tlv_parse(struct uburma_cmd_hdr *hdr, void *arg);
int uburma_event_tlv_append(struct uburma_cmd_hdr *hdr, void *arg);

#endif /* UBURMA_CMD_TLV_H */
