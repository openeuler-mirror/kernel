/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_COMMON_H
#define __HNS3_CAE_COMMON_H

#define REG_RDATA_NUM		2

#define CMDQ_32_COM_CMD_OPCODE 0xfffd
#define CMDQ_64_COM_CMD_OPCODE 0xffff

struct reg_param {
	u32 addr;
	u32 data[REG_RDATA_NUM];
	u8 bits_width;
	u8 is_read;
};

struct reg_ret_param {
	u32 value[REG_RDATA_NUM];
};

struct cmd_desc {
	u16 opcode;
	u16 flag;
	u16 retval;
	u16 rsv;
	u32 data[6];
};

struct com_reg_param {
	struct cmd_desc reg_desc;
	u32 fw_dw_opcode;
	u32 is_read;
};

int hns3_test_reg_cfg(struct hns3_nic_priv *net_priv, void *buf_in, u32 in_size,
		      void *buf_out, u32 out_size);

int hns3_reg_cfg(struct hns3_nic_priv *net_priv, void *buf_in, u32 in_size,
		 void *buf_out, u32 out_size);

#endif
