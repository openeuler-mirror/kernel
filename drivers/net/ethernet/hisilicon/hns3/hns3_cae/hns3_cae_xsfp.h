/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_XSFP_H__
#define __HNS3_CAE_XSFP_H__

#define STD_XSFP_INFO_A0_SIZE	256
#define STD_XSFP_INFO_A2_SIZE	256
#define STD_XSFP_INFO_MAX_SIZE	640
#define HCLGE_SFP_INFO_LEN		6
#define HCLGE_SFP_INFO_SIZE		140
/* SFP command */
#define XSFP_OPC_SFP_GET_INFO		0x7100
#define XSFP_OPC_SFP_GET_PRESENT	0x7101
#define XSFP_OPC_SFP_SET_STATUS		0x7102

struct hclge_sfp_info {
	u32 sfpinfo[6];
};

struct hclge_sfp_enable_cmd {
	u32 set_sfp_enable_flag;
	u32 rsv[5];
};

struct hclge_sfp_present_cmd {
	u32 sfp_present;
	u32 rsv[5];
};

enum hns3_xsfp_opcode_type {
	OPC_QUERY_XSFP_INFO = 0,
	OPC_QUERY_ALL_XSFP_INFO,
	OPC_CONFIG_XSFP_TX_STATUS
};

struct hns3_cfg_xsfp {
	u32 cfg_optype;
	u8 status;		/* 1: enable 0: disable */
};

struct hns3_xsfp_info {
	u8 light_module_status;
	u16 eeprom_len;
	u8 sfp_info[STD_XSFP_INFO_MAX_SIZE];
};

int hns3_xsfp_cfg(struct hns3_nic_priv *net_priv, void *buf_in,
		  u32 in_size, void *buf_out, u32 out_size);

#endif
