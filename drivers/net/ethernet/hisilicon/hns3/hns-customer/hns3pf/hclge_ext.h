/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HCLGE_EXT_H
#define __HCLGE_EXT_H
#include <linux/types.h>
#include "hnae3.h"

#ifdef CONFIG_IT_VALIDATION
#define HCLGE_SFP_INFO_LEN		6
#define HCLGE_SFP_INFO_SIZE		140
#define HCLGE_8211_PHY_INDIRECT_PAGE	0xa43
#define HCLGE_8211_PHY_INDIRECT_REG	0x1b
#define HCLGE_8211_PHY_INDIRECT_DATA	0x1c
#define HCLGE_8211_PHY_INDIRECT_RANGE1_S	0xDC0
#define HCLGE_8211_PHY_INDIRECT_RANGE1_E	0xDCF
#define HCLGE_8211_PHY_INDIRECT_RANGE2_S	0xDE0
#define HCLGE_8211_PHY_INDIRECT_RANGE2_E	0xDF0

#define HCLGE_OPC_CONFIG_NIC_CLOCK	0x0060

struct hclge_chip_id_cmd {
	u32 chip_id;
	u32 rsv[5];
};

struct hclge_sfp_info_para {
	u8 *buff;
	u16 offset;
	u16 size;
	u16 *outlen;
};

struct hclge_sfp_info {
	u32 sfpinfo[6];
};

struct hclge_led_state {
	u32 type;
	u32 status;
};

struct hclge_pfc_storm_para {
	u32 dir;
	u32 enable;
	u32 period_ms;
	u32 times;
	u32 recovery_period_ms;
};

struct hclge_phy_para {
	u32 page_select_addr;
	u32 reg_addr;
	u16 page;
	u16 data;
};

struct hclge_sfp_enable_cmd {
	u32 set_sfp_enable_flag;
	u32 rsv[5];
};

struct hclge_sfp_present_cmd {
	u32 sfp_present;
	u32 rsv[5];
};

struct hclge_lamp_signal {
	u8 error;
	u8 locate;
	u8 activity;
};

struct hclge_mac_table_para {
	u8 op_cmd;
	u8 mac_addr[ETH_ALEN];
};

enum hclge_ext_op_code {
	HCLGE_EXT_OPC_CLEAN_STATS64 = 0,
	HCLGE_EXT_OPC_GET_CHIPID,
	HCLGE_EXT_OPC_GET_SFPINFO,
	HCLGE_EXT_OPC_SET_SFP_STATE,
	HCLGE_EXT_OPC_GET_CHIP_NUM,
	HCLGE_EXT_OPC_GET_PORT_NUM,
	HCLGE_EXT_OPC_SET_LED,
	HCLGE_EXT_OPC_GET_PRESENT,
	HCLGE_EXT_OPC_DISABLE_LANE,
	HCLGE_EXT_OPC_GET_LANE_STATUS,
	HCLGE_EXT_OPC_GET_LED_SIGNAL,
	HCLGE_EXT_OPC_SET_MAC_STATE,
	HCLGE_EXT_OPC_CONFIG_CLOCK,
	HCLGE_EXT_OPC_GET_PFC_STORM_PARA,
	HCLGE_EXT_OPC_SET_PFC_STORM_PARA,
	HCLGE_EXT_OPC_GET_PHY_REG,
	HCLGE_EXT_OPC_SET_PHY_REG,
	HCLGE_EXT_OPC_GET_MAC_ID,
	HCLGE_EXT_OPC_OPT_MAC_TABLE,
	HCLGE_EXT_OPC_RESET,
	HCLGE_EXT_OPC_GET_HILINK_REF_LOS,
	HCLGE_EXT_OPC_GET_8211_PHY_REG,
	HCLGE_EXT_OPC_SET_8211_PHY_REG,
};

enum hclge_opt_table_code {
	HCLGE_OPT_TABLE_LOOKUP,
	HCLGE_OPT_TABLE_ADD,
	HCLGE_OPT_TABLE_DEL,
};

struct hclge_ext_func {
	int opcode;
	int (*priv_ops)(struct hnae3_handle *handle, int opcode,
			void *data, int length);
};

enum hclge_ext_opcode_type {
	/* misc command */
	HCLGE_OPC_CHIP_ID_GET = 0x7003,
	HCLGE_OPC_IMP_COMMIT_ID_GET = 0x7004,
	HCLGE_OPC_GET_CHIP_NUM = 0x7005,
	HCLGE_OPC_GET_PORT_NUM = 0x7006,
	HCLGE_OPC_SET_LED = 0x7007,
	HCLGE_OPC_DISABLE_NET_LANE = 0x7008,
	HCLGE_OPC_CFG_PAUSE_STORM_PARA = 0x7019,
	HCLGE_OPC_CFG_GET_HILINK_REF_LOS = 0x701B,
	/*SFP command */
	HCLGE_OPC_SFP_GET_INFO = 0x7100,
	HCLGE_OPC_SFP_GET_PRESENT = 0x7101,
	HCLGE_OPC_SFP_SET_STATUS = 0x7102,
};

int hclge_ext_ops_handle(struct hnae3_handle *handle, int opcode,
			 void *data, int length);
void hclge_reset_task_schedule_it(struct hclge_dev *hdev);
#endif
#endif

