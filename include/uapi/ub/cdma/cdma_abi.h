/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef _UAPI_UB_CDMA_CDMA_ABI_H_
#define _UAPI_UB_CDMA_CDMA_ABI_H_

#include <linux/types.h>

/* cdma ioctl cmd */
#define CDMA_IOC_MAGIC 'C'
#define CDMA_SYNC _IOWR(CDMA_IOC_MAGIC, 0, struct cdma_ioctl_hdr)

/* cdma event ioctl cmd */
#define CDMA_EVENT_CMD_MAGIC 'F'
#define JFAE_CMD_GET_ASYNC_EVENT 0
#define JFCE_CMD_WAIT_EVENT 0

#define CDMA_CMD_GET_ASYNC_EVENT	\
	_IOWR(CDMA_EVENT_CMD_MAGIC, JFAE_CMD_GET_ASYNC_EVENT, struct cdma_cmd_async_event)
#define CDMA_CMD_WAIT_JFC \
	_IOWR(CDMA_EVENT_CMD_MAGIC, JFCE_CMD_WAIT_EVENT, struct cdma_cmd_jfce_wait_args)

#define CDMA_ADDR_SHIFT 32
#define CDMA_DOORBELL_OFFSET 0x80

#define CDMA_JFC_DB_CI_IDX_M GENMASK(21, 0)
#define CDMA_JFC_DB_VALID_OWNER_M 1
#define CDMA_INTER_ERR 1
#define CDMA_SRC_IDX_SHIFT 16
#define CDMA_MAX_JFCE_EVENT_CNT 72

#define MAP_COMMAND_MASK 0xff
#define MAP_INDEX_MASK 0xffffff
#define MAP_INDEX_SHIFT 8

/* cdma queue cfg deault value */
#define CDMA_TYPICAL_RNR_RETRY 7
#define CDMA_TYPICAL_ERR_TIMEOUT 2 /* 0:128ms 1:1s 2:8s 3:64s */

#define CDMA_CQE_STATUS_NUM 7
#define CDMA_CQE_SUB_STATUS_NUM 5

/* rsv_bitmap bits for cdma_create_context_args.out */
#define CDMA_CTX_RSP_ST64B_EN 0x1

enum dma_cr_status {
	DMA_CR_SUCCESS = 0,
	DMA_CR_UNSUPPORTED_OPCODE_ERR,
	DMA_CR_LOC_LEN_ERR,
	DMA_CR_LOC_OPERATION_ERR,
	DMA_CR_LOC_ACCESS_ERR,
	DMA_CR_REM_RESP_LEN_ERR,
	DMA_CR_REM_UNSUPPORTED_REQ_ERR,
	DMA_CR_REM_OPERATION_ERR,
	DMA_CR_REM_ACCESS_ABORT_ERR,
	DMA_CR_ACK_TIMEOUT_ERR,
	DMA_CR_RNR_RETRY_CNT_EXC_ERR,
	DMA_CR_WR_FLUSH_ERR,
	DMA_CR_WR_SUSPEND_DONE,
	DMA_CR_WR_FLUSH_ERR_DONE,
	DMA_CR_WR_UNHANDLED,
	DMA_CR_LOC_DATA_POISON,
	DMA_CR_REM_DATA_POISON,
};

enum db_mmap_type {
	CDMA_MMAP_JFC_PAGE,
	CDMA_MMAP_JETTY_DSQE,
};

enum cdma_cmd {
	CDMA_CMD_QUERY_DEV_INFO,
	CDMA_CMD_CREATE_CTX,
	CDMA_CMD_DELETE_CTX,
	CDMA_CMD_CREATE_CTP,
	CDMA_CMD_DELETE_CTP,
	CDMA_CMD_CREATE_JFS,
	CDMA_CMD_DELETE_JFS,
	CDMA_CMD_REGISTER_SEG,
	CDMA_CMD_UNREGISTER_SEG,
	CDMA_CMD_CREATE_QUEUE,
	CDMA_CMD_DELETE_QUEUE,
	CDMA_CMD_CREATE_JFC,
	CDMA_CMD_DELETE_JFC,
	CDMA_CMD_CREATE_JFCE,
	CDMA_CMD_MAX,
};

enum {
	CQE_FOR_SEND,
	CQE_FOR_RECEIVE
};

enum hw_cqe_opcode {
	HW_CQE_OPC_SEND				= 0x00,
	HW_CQE_OPC_SEND_WITH_IMM		= 0x01,
	HW_CQE_OPC_SEND_WITH_INV		= 0x02,
	HW_CQE_OPC_WRITE_WITH_IMM		= 0x03,
	HW_CQE_OPC_ERR				= 0xff
};

struct cdma_ioctl_hdr {
	__u32 command;
	__u32 args_len;
	__u64 args_addr;
};

struct cdma_create_jfs_ucmd {
	__u64 buf_addr;
	__u32 buf_len;
	__u64 db_addr;
	__u64 idx_addr;
	__u32 idx_len;
	__u64 jetty_addr;
	__u32 sqe_bb_cnt;
	__u32 jetty_type;
	__u32 non_pin;
	__u32 jfs_id;
	__u32 queue_id;
	__u32 tid;
};

struct cdma_cmd_udrv_priv {
	__u64 in_addr;
	__u32 in_len;
	__u64 out_addr;
	__u32 out_len;
};

struct cdma_cmd_create_jfs_args {
	struct {
		__u32 depth;
		__u32 flag;
		__u32 eid_idx;
		__u8 priority;
		__u8 max_sge;
		__u8 max_rsge;
		__u8 retry_cnt;
		__u8 rnr_retry;
		__u8 err_timeout;
		__u32 jfc_id;
		__u32 queue_id;
		__u32 rmt_eid;
		__u32 pld_token_id;
		__u32 tpn;
		__u64 dma_jfs; /* dma jfs pointer */
		__u32 trans_mode;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 id;
		__u32 depth;
		__u8 max_sge;
		__u8 max_rsge;
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
	struct cdma_cmd_udrv_priv udata;
};

struct cdma_cmd_async_event {
	__u64 event_data;
	__u32 event_type;
};

struct cdma_cmd_delete_jfs_args {
	struct {
		__u32 jfs_id;
		__u64 handle;
		__u32 queue_id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_create_ctp_args {
	struct {
		__u32 scna;
		__u32 dcna;
		__u32 eid_idx;
		__u32 upi;
		__u64 dma_tp;
		__u32 seid;
		__u32 deid;
		__u32 queue_id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 tpn;
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_delete_ctp_args {
	struct {
		__u32 tpn;
		__u64 handle;
		__u32 queue_id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_create_jfce_args {
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		int fd;
		int id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_create_jfc_args {
	struct {
		__u32 depth; /* in terms of CQEBB */
		int jfce_fd;
		int jfce_id;
		__u32 ceqn;
		__u32 queue_id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 id;
		__u32 depth;
		__u64 handle; /* handle of the allocated jfc obj in kernel */
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
	struct cdma_cmd_udrv_priv udata;
};

struct cdma_cmd_delete_jfc_args {
	struct {
		__u32 jfcn;
		__u64 handle; /* handle of jfc */
		__u32 queue_id;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 comp_events_reported;
		__u32 async_events_reported;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_register_seg_args {
	struct {
		__u64 addr;
		__u64 len;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_unregister_seg_args {
	struct {
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct dev_eid {
	__u32 dw0;
	__u32 dw1;
	__u32 dw2;
	__u32 dw3;
};

struct eu_info {
	__u32 eid_idx;
	struct dev_eid eid;
	__u32 upi;
};

struct cdma_device_cap {
	__u32 max_jfc;
	__u32 max_jfs;
	__u32 max_jfc_depth;
	__u32 max_jfs_depth;
	__u32 max_jfs_inline_len;
	__u32 max_jfs_sge;
	__u32 max_jfs_rsge;
	__u64 max_msg_size;
	__u32 max_atomic_size;
	__u16 trans_mode;
	__u32 ceq_cnt;
	__u32 max_eid_cnt;
	__u64 page_size_cap;
};

struct cdma_device_attr {
#define CDMA_MAX_EU_NUM 64
	__u8 eu_num;
	struct dev_eid eid;
	struct eu_info eu;
	struct eu_info eus[CDMA_MAX_EU_NUM];
	struct cdma_device_cap dev_cap;
};

struct cdma_cmd_query_device_attr_args {
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		struct cdma_device_attr attr;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_create_context_args {
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u8 cqe_size;
		__u8 dwqe_enable;
		int async_fd;
		__u32 rsv_bitmap;
		__u8 st64b_en;
		__u8 pad[3];
		__u32 rsvd[3];
	} out;
};

struct cdma_jfc_db {
	__u32 ci : 24;
	__u32 notify : 1;
	__u32 arm_sn : 2;
	__u32 type : 1;
	__u32 rsv1 : 4;
	__u32 jfcn : 20;
	__u32 rsv2 : 12;
};

struct cdma_create_jfc_ucmd {
	__u64 buf_addr;
	__u32 buf_len;
	__u64 db_addr;
	__u32 mode;
	__u32 tid;
};

struct cdma_cmd_create_queue_args {
	struct {
		__u32 queue_depth;
		__u32 dcna;
		__u32 rmt_eid;
		__u8  priority;
		__u64 user_ctx;
		__u32 trans_mode;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		int queue_id;
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_delete_queue_args {
	struct {
		__u32 queue_id;
		__u64 handle;
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} in;
	struct {
		__u32 rsv_bitmap;
		__u32 rsvd[4];
	} out;
};

struct cdma_cmd_jfce_wait_args {
	struct {
		__u32 max_event_cnt;
		int time_out;
	} in;
	struct {
		__u32 event_cnt;
		__u64 event_data[CDMA_MAX_JFCE_EVENT_CNT];
	} out;
};

enum jfc_poll_state {
	JFC_OK,
	JFC_EMPTY,
	JFC_POLL_ERR,
};

#endif /* _UAPI_UB_CDMA_CDMA_ABI_H_ */
