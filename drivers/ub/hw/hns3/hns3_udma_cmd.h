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

void udma_cmq_setup_basic_desc(struct udma_cmq_desc *desc,
			       enum udma_opcode_type opcode,
			       bool is_read);
int udma_cmq_send(struct udma_dev *dev, struct udma_cmq_desc *desc, int num);
#endif /* _UDMA_CMD_H */
