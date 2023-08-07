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
	/* CQC TIMER commands */
	UDMA_CMD_WRITE_CQC_TIMER_BT0	= 0x23,

	/* QPC TIMER commands */
	UDMA_CMD_WRITE_QPC_TIMER_BT0 = 0x33,
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
