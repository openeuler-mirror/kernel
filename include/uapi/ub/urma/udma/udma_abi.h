/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef _UAPI_UB_UMDK_URMA_UDMA_UDMA_ABI_H_
#define _UAPI_UB_UMDK_URMA_UDMA_UDMA_ABI_H_

#include <linux/types.h>

#define MAP_COMMAND_MASK 0xf
#define MAP_INDEX_MASK 0xfffffff
#define MAP_INDEX_SHIFT 4

#define UDMA_SEGMENT_ACCESS_GUARD (1UL << 5)

#define UDMA_CQE_COALESCE_SHIFT 10
#define UDMA_CQE_COALESCE_CNT_MAX (1 << UDMA_CQE_COALESCE_SHIFT)

#define UDMA_CQE_PERIOD_0 0
#define UDMA_CQE_PERIOD_4 4
#define UDMA_CQE_PERIOD_16 16
#define UDMA_CQE_PERIOD_64 64
#define UDMA_CQE_PERIOD_256 256
#define UDMA_CQE_PERIOD_1024 1024
#define UDMA_CQE_PERIOD_4096 4096
#define UDMA_CQE_PERIOD_16384 16384

#define UDMA_JFC_HW_DB_OFFSET 0x40

#define UDMA_DOORBELL_OFFSET 0x80

#define UDMA_JETTY_DSQE_OFFSET 0x1000

#define UDMA_DB_SIZE 64U

#define UDMA_SRC_IDX_SHIFT 16
#define UDMA_IMM_DATA_SHIFT 32
#define UDMA_JFC_DB_VALID_OWNER_M 1
#define UDMA_ADDR_SHIFT 32

#define UDMA_INTER_ERR 1
#define UDMA_CQE_DEFAULT_SUBSTATUS 0

#define UDMA_MAX_GRANT_SIZE 0xFFFFFFFFF000

#define UDMA_TID_SHIFT 8U
#define UDMA_MAX_TID 0xFFFFFU

enum udma_jetty_type {
	UDMA_CACHE_LOCK_DWQE_JETTY_TYPE,
	UDMA_CCU_JETTY_TYPE,
	UDMA_NORMAL_JETTY_TYPE,
	UDMA_URMA_NORMAL_JETTY_TYPE,
	UDMA_URMA_EX_JETTY_TYPE,
	UDMA_JETTY_TYPE_MAX
};

enum cr_direct {
	CR_SEND,
	CR_RECV,
};

enum cr_jetty {
	CR_IS_NOT_JETTY,
	CR_IS_JETTY,
};

struct udma_create_jetty_ucmd {
	__aligned_u64 buf_addr;
	__u32 buf_len;
	__u32 jfr_id;
	__aligned_u64 db_addr;
	__aligned_u64 idx_addr;
	__u32 idx_len;
	__u32 sqe_bb_cnt;
	__aligned_u64 jetty_addr;
	__u32 pi_type : 1;
	__u32 non_pin : 1;
	__u32 is_hugepage : 1;
	__u32 dtu_en : 1;
	__u32 rsv : 28;
	__u32 jetty_type;
	__aligned_u64 jfr_sleep_buf;
	__u32 jfs_id;
	__u32 rsv1;
};

struct udma_create_jetty_resp {
	__aligned_u64 buf_addr;
};

struct udma_create_jfc_resp {
	__aligned_u64 buf_addr;
};

struct udma_create_jfc_ucmd {
	__aligned_u64 buf_addr;
	__u32 buf_len;
	__u32 mode; /* 0: normal, 1: user stars, 2: kernel stars */
	__aligned_u64 db_addr;
	__u32 is_hugepage : 1;
	__u32 dtu_en : 1;
	__u32 rsv : 30;
	__u32 rsv1;
};

struct udma_create_ctx_resp {
	__u32 cqe_size : 8;
	__u32 dwqe_enable : 1;
	__u32 reduce_enable : 1;
	__u32 dump_aux_info : 1;
	__u32 sq_reserved : 1;
	__u32 atomic_add_en : 1;
	__u32 hugepage_enable : 1;
	__u32 sva_sep_mode_en : 1;
	__u32 u_dtu_enable : 1;
	__u32 rsv : 16;
	__u32 ue_id;
	__u32 chip_id;
	__u32 die_id;
	__u32 jfr_sge;
	__u32 ccu_jetty_start_id;
	__u32 ccu_jetty_max_cnt;
	__u32 rsv1;
	__aligned_u64 sq_reserved_va;
	__aligned_u64 sq_reserved_len;
	__aligned_u64 dtu_va_base;
	__aligned_u64 dtu_va_size;
};

struct udma_create_jfr_resp {
	__u32 jfr_caps;
	__u32 rsv;
};

enum db_mmap_type {
	UDMA_MMAP_HUGEPAGE,
	UDMA_MMAP_JFC_PAGE,
	UDMA_MMAP_JETTY_DSQE,
	UDMA_MMAP_RESERVED_SQ,
	UDMA_MMAP_KERNEL_BUF,
};

enum {
	UDMA_CQ_DB,
	UDMA_CQ_ARM_DB,
};

struct udma_jfc_db {
	__u32 ci	: 24;
	__u32 notify	: 1;
	__u32 arm_sn	: 2;
	__u32 type	: 1;
	__u32 rsv1	: 4;
	__u32 jfcn	: 20;
	__u32 rsv2	: 12;
};

enum udma_db_type {
	UDMA_JFR_TYPE_DB,
	UDMA_JFC_TYPE_DB,
	UDMA_JFR_PAYLOAD,
	UDMA_DB_TYPE_NUM,
};

enum jfc_poll_state {
	JFC_OK,
	JFC_EMPTY,
	JFC_POLL_ERR,
};

enum {
	CQE_FOR_SEND,
	CQE_FOR_RECEIVE,
};

enum {
	UDMA_CQE_SUCCESS			= 0x00,
	UDMA_CQE_UNSUPPORTED_OPCODE		= 0x01,
	UDMA_CQE_LOCAL_OP_ERR			= 0x02,
	UDMA_CQE_REMOTE_OP_ERR			= 0x03,
	UDMA_CQE_TRANSACTION_RETRY_COUNTER_ERR	= 0x04,
	UDMA_CQE_TRANSACTION_ACK_TIMEOUT_ERR	= 0x05,
	UDMA_JETTY_WORK_REQUEST_FLUSH		= 0x06,
};

enum {
	UDMA_CQE_LOCAL_LENGTH_ERR		= 0x01,
	UDMA_CQE_LOCAL_ACCESS_ERR		= 0x02,
	UDMA_CQE_REM_RSP_LENGTH_ERR		= 0x03,
	UDMA_CQE_LOCAL_DATA_POISON		= 0x04,
};

enum {
	UDMA_CQE_REM_UNSUPPORTED_REQ_ERR	= 0x01,
	UDMA_CQE_REM_ACCESS_ERR			= 0x02,
	UDMA_CQE_REM_DATA_POISON		= 0x04,
};

enum hw_cqe_opcode {
	HW_CQE_OPC_SEND				= 0x00,
	HW_CQE_OPC_SEND_WITH_IMM		= 0x01,
	HW_CQE_OPC_SEND_WITH_INV		= 0x02,
	HW_CQE_OPC_WRITE_WITH_IMM		= 0x03,
	HW_CQE_OPC_ERR				= 0xff,
};

#endif /* _UAPI_UB_UMDK_URMA_UDMA_UDMA_ABI_H_ */
