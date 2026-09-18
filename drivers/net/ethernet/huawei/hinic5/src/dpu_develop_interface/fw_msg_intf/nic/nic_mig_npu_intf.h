/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mig_npu_intf.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : NIC migration NPU interface
 */

#ifndef NIC_MIG_INTF_H
#define NIC_MIG_INTF_H

#include "nic_cfg_comm.h"

/**
 * @brief enum nic_mig_q_type
 * @details  migrate queue type info for nic migration
 */
enum nic_mig_q_type {
	NIC_MIG_SQ, /**< Send Queue */
	NIC_MIG_RQ, /**< Receive Queue */
	NIC_MIG_CMDQ, /**< Command Queue */
	NIC_MIG_MAX,  /**< Max Queue Type */
};

/**< if sq num < 30, one cmdq is enough, is sq is 30~60, need to read 2 rounds */
#define MAX_SQ_NUM 0x40  /**< max sq num */
#define MAX_RQ_NUM 0x40  /**< max rq num */
#define MAX_CMDQ_NUM 0x4    /**< max cmdq num */

#define SQ_RQ_CTX_SIZE 0x40  /**< sq/rq context size */

#define CTX_BUF_LEN 0x400   /**< context buffer length */

#define MAX_CTX_NUM (CTX_BUF_LEN / SQ_RQ_CTX_SIZE)  /**< max context number */

/**
 * @brief struct nic_mig_q_ctx
 * @details  migrate queue ctx for nic migration
 */
struct nic_mig_q_ctx {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 16;  /**< reserved */
		u32 queue_type : 2;  /**< queue type */
		u32 opcode : 1;  /**< opcode */
		u32 func_id : 13;   /**< function id */
#else
		u32 func_id : 13;   /**< function id */
		u32 opcode : 1;  /**< opcode */
		u32 queue_type : 2;  /**< queue type */
		u32 rsvd : 16;  /**< reserved */
#endif
	} bs;
	u32 value;  /**< context value */
	} dw0;

	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 16;  /**< reserved */
		u32 queue_num : 8;  /**< queue number */
		u32 start_queue_id : 8;  /**< start queue id */
#else
		u32 start_queue_id : 8;  /**< start queue id */
		u32 queue_num : 8;  /**< queue number */
		u32 rsvd : 16;  /**< reserved */
#endif
	} bs;
	u32 value;  /**< context value */
	} dw1;
	u8 queue_ctx[CTX_BUF_LEN];  /**< queue context */
};

/**
 * @brief struct nic_mig_rq_stop
 * @details  stop rq info for nic migration
 */
struct nic_mig_rq_stop {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 11;  /**< reserved */
		u32 rq_num : 8;  /**< receive queue number */
		u32 func_id : 13;   /**< function id */
#else
		u32 func_id : 13;   /**< function id */
		u32 rq_num : 8;  /**< receive queue number */
		u32 rsvd : 11;  /**< reserved */
#endif
	} bs;
	u32 value;  /**< context value */
	} dw;
	u32 is_empty;   /**< is empty */
};

/**
 * @brief struct nic_mig_rq_empty_type
 * @details  rq drain type for nic migration
 */
enum nic_mig_rq_empty_type {
	NIC_MIG_RQ_CHK_INIT,    /**< rq init check type*/
	NIC_MIG_RQ_CHK_EMPTY,   /**< rq empty check type*/
	NIC_MIG_RQ_CHECK_ERR,   /**< rq error check type*/
};

/**
 * @brief struct nic_mig_cmdq_stop
 * @details  stop cmdq info for nic migration
 */
struct nic_mig_cmdq_stop {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 10;  /**< reserved */
		u32 cmdq_num : 8;   /**< cmdq number */
		u32 is_stop : 1;    /**< is stop */
		u32 func_id : 13;   /**< function id */
#else
		u32 func_id : 13;   /**< function id */
		u32 is_stop : 1;    /**< is stop */
		u32 cmdq_num : 8;   /**< cmdq number */
		u32 rsvd : 10;  /**< reserved */
#endif
	} bs;
	u32 value;  /**< context value */
	} dw;
};

#define BAT_ARR_LEN 0x100  /**< bat array length */

/**
 * @brief struct nic_mig_update_bat
 * @details  update bat table info for nic migration
 */
struct nic_mig_update_bat {
	u32 opcode;   /**< opcode */
	u32 func_id;    /**< function id */
	u32 size;   /**< size */
	u8 data[BAT_ARR_LEN];   /**< data */
};

/**
 * @brief struct nic_mig_compensate_intr
 * @details compensate interrupt info for nic migration
 */
struct nic_mig_compensate_intr {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd1 : 10;  /**< reserved */
		u32 intr_num : 9;   /**< interrupt number */
		u32 func_id : 13;   /**< function id */
#else
		u32 func_id : 13;   /**< function id */
		u32 intr_num : 9;   /**< interrupt number */
		u32 rsvd1 : 10;  /**< reserved */
#endif
	} bs;
	u32 value;  /**< context value */
	} dw;
};

#define MIG_FAST_MSG_BHEAP_SIZE 64
struct mig_nic_fast_msg_bheap {
	union {
	struct {
#if defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
		u32 rsvd : 8;
		u32 opcode : 8;
		u32 func_id : 16;
#else
		u32 func_id : 16;
		u32 opcode : 8;
		u32 rsvd : 8;
#endif
	} bs;
	u32 value;
	} dw;
	u8 bheap[MIG_FAST_MSG_BHEAP_SIZE];
};

#endif
