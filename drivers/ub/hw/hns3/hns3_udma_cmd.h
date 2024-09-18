/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef _HNS3_UDMA_CMD_H
#define _HNS3_UDMA_CMD_H

#include "hns3_udma_device.h"

#define CMD_MAX_NUM		32
#define HNS3_UDMA_MAILBOX_SIZE	4096
#define HNS3_UDMA_CMD_TIMEOUT_MSECS	10000
#define CMD_POLL_TOKEN		0xffff
#define SUB_OPCODE_IDX		4
#define HNS3_UDMA_CMQ_DESC_SIZE	2

enum {
	/* QPC BT commands */
	HNS3_UDMA_CMD_WRITE_QPC_BT0		= 0x0,
	HNS3_UDMA_CMD_WRITE_QPC_BT1		= 0x1,
	HNS3_UDMA_CMD_WRITE_QPC_BT2		= 0x2,
	HNS3_UDMA_CMD_READ_QPC_BT0		= 0x4,
	HNS3_UDMA_CMD_READ_QPC_BT1		= 0x5,
	HNS3_UDMA_CMD_READ_QPC_BT2		= 0x6,
	HNS3_UDMA_CMD_DESTROY_QPC_BT0		= 0x8,
	HNS3_UDMA_CMD_DESTROY_QPC_BT1		= 0x9,
	HNS3_UDMA_CMD_DESTROY_QPC_BT2		= 0xa,

	/* QPC operation */
	HNS3_UDMA_CMD_MODIFY_QPC		= 0x41,
	HNS3_UDMA_CMD_QUERY_QPC			= 0x42,

	HNS3_UDMA_CMD_MODIFY_CQC		= 0x52,
	HNS3_UDMA_CMD_QUERY_CQC			= 0x53,
	/* CQC BT commands */
	HNS3_UDMA_CMD_WRITE_CQC_BT0		= 0x10,
	HNS3_UDMA_CMD_WRITE_CQC_BT1		= 0x11,
	HNS3_UDMA_CMD_WRITE_CQC_BT2		= 0x12,
	HNS3_UDMA_CMD_READ_CQC_BT0		= 0x14,
	HNS3_UDMA_CMD_READ_CQC_BT1		= 0x15,
	HNS3_UDMA_CMD_READ_CQC_BT2		= 0x1b,
	HNS3_UDMA_CMD_DESTROY_CQC_BT0		= 0x18,
	HNS3_UDMA_CMD_DESTROY_CQC_BT1		= 0x19,
	HNS3_UDMA_CMD_DESTROY_CQC_BT2		= 0x1a,

	/* MPT BT commands */
	HNS3_UDMA_CMD_WRITE_MPT_BT0		= 0x20,
	HNS3_UDMA_CMD_WRITE_MPT_BT1		= 0x21,
	HNS3_UDMA_CMD_WRITE_MPT_BT2		= 0x22,
	HNS3_UDMA_CMD_READ_MPT_BT0		= 0x24,
	HNS3_UDMA_CMD_READ_MPT_BT1		= 0x25,
	HNS3_UDMA_CMD_READ_MPT_BT2		= 0x26,
	HNS3_UDMA_CMD_DESTROY_MPT_BT0		= 0x28,
	HNS3_UDMA_CMD_DESTROY_MPT_BT1		= 0x29,
	HNS3_UDMA_CMD_DESTROY_MPT_BT2		= 0x2a,

	/* CQC TIMER commands */
	HNS3_UDMA_CMD_WRITE_CQC_TIMER_BT0	= 0x23,
	HNS3_UDMA_CMD_READ_CQC_TIMER_BT0	= 0x27,

	/* MPT commands */
	HNS3_UDMA_CMD_CREATE_MPT		= 0xd,
	HNS3_UDMA_CMD_DESTROY_MPT		= 0xf,
	HNS3_UDMA_CMD_QUERY_MPT			= 0x62,

	/* SRQC BT commands */
	HNS3_UDMA_CMD_WRITE_SRQC_BT0		= 0x30,
	HNS3_UDMA_CMD_WRITE_SRQC_BT1		= 0x31,
	HNS3_UDMA_CMD_WRITE_SRQC_BT2		= 0x32,
	HNS3_UDMA_CMD_READ_SRQC_BT0		= 0x34,
	HNS3_UDMA_CMD_READ_SRQC_BT1		= 0x35,
	HNS3_UDMA_CMD_READ_SRQC_BT2		= 0x36,
	HNS3_UDMA_CMD_DESTROY_SRQC_BT0		= 0x38,
	HNS3_UDMA_CMD_DESTROY_SRQC_BT1		= 0x39,
	HNS3_UDMA_CMD_DESTROY_SRQC_BT2		= 0x3a,

	/* QPC TIMER commands */
	HNS3_UDMA_CMD_WRITE_QPC_TIMER_BT0	= 0x33,
	HNS3_UDMA_CMD_READ_QPC_TIMER_BT0	= 0x37,

	/* QP/EE commands */
	HNS3_UDMA_CMD_CREATE_SRQ		= 0x70,
	HNS3_UDMA_CMD_MODIFY_SRQC		= 0x72,
	HNS3_UDMA_CMD_QUERY_SRQC		= 0x73,
	HNS3_UDMA_CMD_DESTROY_SRQ		= 0x74,

	/* EQC commands */
	HNS3_UDMA_CMD_CREATE_AEQC		= 0x80,
	HNS3_UDMA_CMD_DESTROY_AEQC		= 0x83,
	HNS3_UDMA_CMD_CREATE_CEQC		= 0x90,
	HNS3_UDMA_CMD_DESTROY_CEQC		= 0x93,

	/* SCC CTX BT commands */
	HNS3_UDMA_CMD_QUERY_SCCC		= 0xa2,
	HNS3_UDMA_CMD_READ_SCCC_BT0		= 0xa4,
	HNS3_UDMA_CMD_WRITE_SCCC_BT0		= 0xa5,

	/* CQ commands */
	HNS3_UDMA_CMD_CREATE_CQC		= 0x16,
	HNS3_UDMA_CMD_DESTROY_CQC		= 0x17,
	HNS3_UDMA_CMD_RESERVED			= 0xff,
};

enum {
	CMD_RST_PRC_OTHERS,
	CMD_RST_PRC_SUCCESS,
	CMD_RST_PRC_EBUSY,
};

struct hns3_udma_mbox {
	uint32_t	in_param_l;
	uint32_t	in_param_h;
	uint32_t	out_param_l;
	uint32_t	out_param_h;
	uint32_t	cmd_tag;
	uint32_t	token_event_en;
};

struct hns3_udma_mbox_status {
	uint32_t	mb_status_hw_run;
	uint32_t	rsv[5];
};

#define HNS3_UDMA_GO_BIT_TIMEOUT_MSECS 10000

#define MB_ST_HW_RUN_M BIT(31)
#define MB_ST_COMPLETE_M GENMASK(7, 0)

#define MB_ST_COMPLETE_SUCC 1
#define HNS3_UDMA_MB_EVENT_EN_SHIFT 16

#define MBOX_PARAM_H_SHIFT 32
#define MBOX_CMD_TAG_OP_SHIFT 8

struct hns3_udma_cmd_mailbox *hns3_udma_alloc_cmd_mailbox(struct hns3_udma_dev *dev);
void hns3_udma_free_cmd_mailbox(struct hns3_udma_dev *dev,
				struct hns3_udma_cmd_mailbox *mailbox);
int hns3_udma_post_mbox(struct hns3_udma_dev *dev, struct hns3_udma_cmq_desc *desc,
			uint16_t token, int vfid_event);
int hns3_udma_poll_mbox_done(struct hns3_udma_dev *dev, uint32_t timeout);
bool hns3_udma_chk_mbox_is_avail(struct hns3_udma_dev *dev, bool *busy);
void hns3_udma_cmq_setup_basic_desc(struct hns3_udma_cmq_desc *desc,
				    enum hns3_udma_opcode_type opcode,
				    bool is_read);
int hns3_udma_cmq_send(struct hns3_udma_dev *dev, struct hns3_udma_cmq_desc *desc, int num);
int hns3_udma_cmd_mbox(struct hns3_udma_dev *dev, struct hns3_udma_cmq_desc *desc,
		       uint32_t timeout, int vfid);
void hns3_udma_cmd_event(struct hns3_udma_dev *udma_dev, uint16_t token, uint8_t status,
			 uint64_t out_param);
static inline void mbox_desc_init(struct hns3_udma_mbox *mb, uint64_t in_param,
				  uint64_t out_param, uint32_t in_modifier,
				  uint16_t op)
{
	mb->in_param_l = cpu_to_le32(in_param);
	mb->in_param_h = cpu_to_le32(in_param >> MBOX_PARAM_H_SHIFT);
	mb->out_param_l = cpu_to_le32(out_param);
	mb->out_param_h = cpu_to_le32(out_param >> MBOX_PARAM_H_SHIFT);
	mb->cmd_tag = cpu_to_le32(in_modifier << MBOX_CMD_TAG_OP_SHIFT | op);
}

#endif /* _HNS3_UDMA_CMD_H */
