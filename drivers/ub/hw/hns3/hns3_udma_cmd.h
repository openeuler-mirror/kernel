/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _UDMA_CMD_H
#define _UDMA_CMD_H

#include "hns3_udma_device.h"

#define CMD_MAX_NUM		32
#define UDMA_MAILBOX_SIZE	4096
#define UDMA_CMD_TIMEOUT_MSECS	10000
#define CMD_POLL_TOKEN		0xffff
#define SUB_OPCODE_IDX		4

enum {
	/* QPC BT commands */
	UDMA_CMD_WRITE_QPC_BT0		= 0x0,
	UDMA_CMD_WRITE_QPC_BT1		= 0x1,
	UDMA_CMD_WRITE_QPC_BT2		= 0x2,
	UDMA_CMD_READ_QPC_BT0		= 0x4,
	UDMA_CMD_READ_QPC_BT1		= 0x5,
	UDMA_CMD_READ_QPC_BT2		= 0x6,
	UDMA_CMD_DESTROY_QPC_BT0	= 0x8,
	UDMA_CMD_DESTROY_QPC_BT1	= 0x9,
	UDMA_CMD_DESTROY_QPC_BT2	= 0xa,

	/* QPC operation */
	UDMA_CMD_MODIFY_QPC		= 0x41,
	UDMA_CMD_QUERY_QPC		= 0x42,

	UDMA_CMD_MODIFY_CQC		= 0x52,
	UDMA_CMD_QUERY_CQC		= 0x53,
	/* CQC BT commands */
	UDMA_CMD_WRITE_CQC_BT0		= 0x10,
	UDMA_CMD_WRITE_CQC_BT1		= 0x11,
	UDMA_CMD_WRITE_CQC_BT2		= 0x12,
	UDMA_CMD_READ_CQC_BT0		= 0x14,
	UDMA_CMD_READ_CQC_BT1		= 0x15,
	UDMA_CMD_READ_CQC_BT2		= 0x1b,
	UDMA_CMD_DESTROY_CQC_BT0	= 0x18,
	UDMA_CMD_DESTROY_CQC_BT1	= 0x19,
	UDMA_CMD_DESTROY_CQC_BT2	= 0x1a,

	/* MPT BT commands */
	UDMA_CMD_WRITE_MPT_BT0		= 0x20,
	UDMA_CMD_WRITE_MPT_BT1		= 0x21,
	UDMA_CMD_WRITE_MPT_BT2		= 0x22,
	UDMA_CMD_READ_MPT_BT0		= 0x24,
	UDMA_CMD_READ_MPT_BT1		= 0x25,
	UDMA_CMD_READ_MPT_BT2		= 0x26,
	UDMA_CMD_DESTROY_MPT_BT0	= 0x28,
	UDMA_CMD_DESTROY_MPT_BT1	= 0x29,
	UDMA_CMD_DESTROY_MPT_BT2	= 0x2a,

	/* CQC TIMER commands */
	UDMA_CMD_WRITE_CQC_TIMER_BT0	= 0x23,
	UDMA_CMD_READ_CQC_TIMER_BT0	= 0x27,

	/* MPT commands */
	UDMA_CMD_CREATE_MPT		= 0xd,
	UDMA_CMD_DESTROY_MPT		= 0xf,
	UDMA_CMD_QUERY_MPT		= 0x62,

	/* SRQC BT commands */
	UDMA_CMD_WRITE_SRQC_BT0		= 0x30,
	UDMA_CMD_WRITE_SRQC_BT1		= 0x31,
	UDMA_CMD_WRITE_SRQC_BT2		= 0x32,
	UDMA_CMD_READ_SRQC_BT0		= 0x34,
	UDMA_CMD_READ_SRQC_BT1		= 0x35,
	UDMA_CMD_READ_SRQC_BT2		= 0x36,
	UDMA_CMD_DESTROY_SRQC_BT0	= 0x38,
	UDMA_CMD_DESTROY_SRQC_BT1	= 0x39,
	UDMA_CMD_DESTROY_SRQC_BT2	= 0x3a,

	/* QPC TIMER commands */
	UDMA_CMD_WRITE_QPC_TIMER_BT0	= 0x33,
	UDMA_CMD_READ_QPC_TIMER_BT0	= 0x37,

	/* QP/EE commands */
	UDMA_CMD_CREATE_SRQ		= 0x70,
	UDMA_CMD_MODIFY_SRQC		= 0x72,
	UDMA_CMD_QUERY_SRQC		= 0x73,
	UDMA_CMD_DESTROY_SRQ		= 0x74,

	/* EQC commands */
	UDMA_CMD_CREATE_AEQC		= 0x80,
	UDMA_CMD_DESTROY_AEQC		= 0x83,
	UDMA_CMD_CREATE_CEQC		= 0x90,
	UDMA_CMD_DESTROY_CEQC		= 0x93,

	/* SCC CTX BT commands */
	UDMA_CMD_QUERY_SCCC		= 0xa2,
	UDMA_CMD_READ_SCCC_BT0		= 0xa4,
	UDMA_CMD_WRITE_SCCC_BT0		= 0xa5,

	/* CQ commands */
	UDMA_CMD_CREATE_CQC		= 0x16,
	UDMA_CMD_DESTROY_CQC		= 0x17,
	UDMA_CMD_RESERVED		= 0xff,
};

enum {
	CMD_RST_PRC_OTHERS,
	CMD_RST_PRC_SUCCESS,
	CMD_RST_PRC_EBUSY,
};

struct udma_mbox {
	uint32_t	in_param_l;
	uint32_t	in_param_h;
	uint32_t	out_param_l;
	uint32_t	out_param_h;
	uint32_t	cmd_tag;
	uint32_t	token_event_en;
};

struct udma_mbox_status {
	uint32_t	mb_status_hw_run;
	uint32_t	rsv[5];
};

#define UDMA_GO_BIT_TIMEOUT_MSECS 10000

#define MB_ST_HW_RUN_M BIT(31)
#define MB_ST_COMPLETE_M GENMASK(7, 0)

#define MB_ST_COMPLETE_SUCC 1
#define UDMA_MB_EVENT_EN_SHIFT 16

void dump_desc(struct udma_dev *dev, struct udma_cmq_desc *desc);
struct udma_cmd_mailbox *udma_alloc_cmd_mailbox(struct udma_dev *dev);
void udma_free_cmd_mailbox(struct udma_dev *dev,
			   struct udma_cmd_mailbox *mailbox);
int udma_post_mbox(struct udma_dev *dev, struct udma_cmq_desc *desc,
		   uint16_t token, int vfid_event);
int udma_poll_mbox_done(struct udma_dev *dev, uint32_t timeout);
bool udma_chk_mbox_is_avail(struct udma_dev *dev, bool *busy);
void udma_cmq_setup_basic_desc(struct udma_cmq_desc *desc,
			       enum udma_opcode_type opcode,
			       bool is_read);
int udma_cmq_send(struct udma_dev *dev, struct udma_cmq_desc *desc, int num);
int udma_cmd_mbox(struct udma_dev *dev, struct udma_cmq_desc *desc,
		  uint32_t timeout, int vfid);
void udma_cmd_event(struct udma_dev *udma_dev, uint16_t token, uint8_t status,
		    uint64_t out_param);
static inline void mbox_desc_init(struct udma_mbox *mb, uint64_t in_param,
				  uint64_t out_param, uint32_t in_modifier,
				  uint16_t op)
{
	mb->in_param_l = cpu_to_le32(in_param);
	mb->in_param_h = cpu_to_le32(in_param >> 32);
	mb->out_param_l = cpu_to_le32(out_param);
	mb->out_param_h = cpu_to_le32(out_param >> 32);
	mb->cmd_tag = cpu_to_le32(in_modifier << 8 | op);
}

#endif /* _UDMA_CMD_H */
