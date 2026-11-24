/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu IMP command queue protocol definitions.
 */

#ifndef __UMMU_DTU_CMD_H__
#define __UMMU_DTU_CMD_H__

#include "dtu.h"

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/io.h>
#include <linux/types.h>

/* BD flag byte bits */
#define DTU_CMD_FLAG_IN		BIT(0) /* driver → IMP has payload */
#define DTU_CMD_FLAG_OUT	BIT(1) /* IMP → driver has response */
#define DTU_CMD_FLAG_NEXT	BIT(2) /* next BD follows (chaining) */
#define DTU_CMD_FLAG_WR		BIT(3) /* read command (IMP reads and writes back) */
#define DTU_CMD_FLAG_NO_INTR	BIT(4) /* no interrupt on completion */
#define DTU_CMD_FLAG_ERR_INTR	BIT(5) /* interrupt on error */
#define DTU_CMD_FLAG_GET_BD_NUM	BIT(6) /* get BD number command */

/* Aggregate config command (configures a complete window in one cmd) */
#define DTU_OPC_CONFIG_CMD		0x0009

/* Single-register commands (reserved, currently unused) */
#define DTU_OPC_CONFIG_CONTROL_1	0xA001
#define DTU_OPC_CONFIG_CONTROL_2	0xA002
#define DTU_OPC_CONFIG_CONTROL_3	0xA003
#define DTU_OPC_CONFIG_TOKENVAL_0	0xA004
#define DTU_OPC_CONFIG_TOKENVAL_1	0xA005
#define DTU_OPC_CONFIG_BASE_ADDR_H	0xA006
#define DTU_OPC_CONFIG_BASE_ADDR_L	0xA007
#define DTU_OPC_CONFIG_LIMIT_ADDR_H	0xA008
#define DTU_OPC_CONFIG_LIMIT_ADDR_L	0xA009
#define DTU_OPC_CONFIG_TARGET_ADDR_H	0xA00A
#define DTU_OPC_CONFIG_TARGET_ADDR_L	0xA00B

/* CSQ register offsets */
#define UMMU_CSQ_BASEADDR_L_REG		0x000
#define UMMU_CSQ_BASEADDR_H_REG		0x004
#define UMMU_CSQ_DEPTH_REG		0x008
#define UMMU_CSQ_TAIL_REG		0x010
#define UMMU_CSQ_HEAD_REG		0x014

#define UMMU_CMDQ_DESC_NUM_S		3

#define UB_DTU_CMDQ_TX_TIMEOUT_US	100000
#define UB_DTU_CMDQ_TX_DELAY_US		1000

#define DTU_CMD_HEADER_LENGTH		8
#define DTU_CMD_DATA_LENGTH		(UMMU_DESC_DATA_LEN * sizeof(__le32))
#define DTU_CMD_MAX_DESC_SIZE		\
	(UMMU_CMDQ_DESC_NUM * sizeof(struct dtu_cmdq_desc))

/* Driver-side command buffer */
struct dtu_cmd_buf {
	u16	opcode;
	bool	is_read;
	u32	data_size;
	void	*data;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/* 0x0009 aggregate config command payload */
struct dtu_cfg_tbl {
	u8	en;
	u8	resv0;
	__le16	win_num;
	u8	exclusive : 1;
	u8	resv1 : 7;
	u8	perm_read : 1;
	u8	perm_write : 1;
	u8	perm_atomic : 1;
	u8	resv2 : 5;
	u8	bufferable : 1;
	u8	modified : 1;
	u8	read_allocate : 1;
	u8	write_allocate : 1;
	u8	resv3 : 4;
	u8	snoop : 1;
	u8	resv4 : 7;
	__le32	resv5;
	__le32	tid;
	__le32	base_addr_l;
	__le32	base_addr_h;
	__le32	limit_addr_l;
	__le32	limit_addr_h;
	__le32	target_addr_l;
	__le32	target_addr_h;
	__le32	dsteid;
	__le32	dsteid_type;
	__le32	resv6[2];
} __packed;

static inline void ub_dtu_fill_cmd_buf(struct dtu_cmd_buf *buf, u16 opcode,
					 bool is_read, u32 data_size,
					 void *data)
{
	buf->opcode = opcode;
	buf->is_read = is_read;
	buf->data_size = data_size;
	buf->data = data;
}

void ub_dtu_write_reg(void __iomem *base, u32 reg, u32 value);
u32  ub_dtu_read_reg(void __iomem *base, u32 reg);

int  ub_dtu_cmdq_init(struct ub_dtu_device *dtu);
void ub_dtu_cmdq_uninit(struct ub_dtu_device *dtu);
int  ub_dtu_cmd_send_inout(struct ub_dtu_device *dtu_dev,
			   struct dtu_cmd_buf *in,
			   struct dtu_cmdq_desc *out_desc);

#endif /* __UMMU_DTU_CMD_H__ */
