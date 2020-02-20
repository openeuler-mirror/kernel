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

int hns3_cae_reg_cfg(const struct hns3_nic_priv *net_priv, void *buf_in,
		     u32 in_size, void *buf_out, u32 out_size);
#endif
