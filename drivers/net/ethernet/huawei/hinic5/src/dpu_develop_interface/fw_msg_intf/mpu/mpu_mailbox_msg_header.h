/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_mailbox_msg_header.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : The message header if in-band commands between the driver and the MPU
 */
#ifndef MPU_MAILBOX_MSG_HEADER_H
#define MPU_MAILBOX_MSG_HEADER_H

#include "base_type.h"

#define MPU_MAILBOX_HEADER_VER_0 0 /**< mailbox message version 0 */
#define MPU_MAILBOX_HEADER_VER_1 1 /**< mailbox message version 1 */

#define MPU_MAILBOX_HEADER_VER1_LEN_UNIT 4 /**< mailbox message length unit 4 bytes */

typedef union {
	struct {
		u32 func_id : 13; /**< indicates function id of this message */
		u32 status : 1; /**< indicates the status of this message */
		u32 rsvd : 1; /**< reserved field */
		u32 source : 1;   /* indicates the source of this message.
				   * 0--mailbox   1--api cmd
				   */
		u32 aeq_id : 2;   /**< indicates message response aeq id */
		u32 msg_id : 4;   /**< indicates the ID of this message */
		u32 cmd : 10;     /**< user defined command */
		u32 msg_len : 11; /**< total message length, maximum (2 << 11) - 1 */
		u32 module : 5;   /**< module id */
		u32 seg_len : 6;  /**< current segment length */
		u32 no_ack : 1; /**< no_ack flag */
		u32 tlp : 1;       /**< this bit indicates the message is tlp format */
		u32 seg_id : 6;    /**< segment sequence id */
		u32 last_flg : 1;  /**< the last segment flag */
		u32 direction : 1; /**< 0 send, 1 receive */
	} v0;

	struct {
		u32 func_id : 13; /**< indicates function id of this message */
		u32 status : 1; /**< indicates the status of this message */
		u32 version : 1; /**< indicates the version of this message */
		u32 source : 1;   /* indicates the source of this message.
				   * 0--mailbox   1--api cmd
				   */
		u32 aeq_id : 2;   /**< indicates message response aeq id */
		u32 msg_id : 4;   /**< indicates the ID of this message */
		u32 cmd : 10;     /**< user defined command */
		u32 msg_len : 9; /**< total message length, maximum (2 << 11) - 1 */
		u32 rsvd0 : 2; /**< reserved field */
		u32 module : 6;   /**< module id */
		u32 rsvd1 : 1; /**< reserved field */
		u32 seg_len : 4;  /**< current segment length */
		u32 no_ack : 1; /**< no_ack flag */
		u32 tlp : 1;       /**< this bit indicates the message is tlp format */
		u32 seg_id : 6;    /**< segment sequence id */
		u32 last_flg : 1;  /**< the last segment flag */
		u32 direction : 1; /**< 0 send, 1 receive */
	} v1;
} mpu_mbx_header;

#endif