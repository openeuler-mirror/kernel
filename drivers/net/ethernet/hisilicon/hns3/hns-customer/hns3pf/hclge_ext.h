/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2017 Hisilicon Limited. */

#ifndef __HCLGE_EXT_H
#define __HCLGE_EXT_H
#include <linux/types.h>
#include "../../hnae3.h"

#define HCLGE_SFP_INFO_LEN		6
#define HCLGE_SFP_INFO_SIZE		140

#define HCLGE_OPC_CONFIG_NIC_CLOCK	0x0060

struct hclge_chip_id_cmd {
	u32 chip_id;
	u32 rsv[5];
};

struct hclge_commit_id_cmd {
	u8 commit_id[8];
	u32 ncl_version;
	u32 rsv[3];
};

struct hclge_sfp_info {
	u32 sfpinfo[6];
};

struct hclge_sfp_enable_cmd {
	u32  set_sfp_enable_flag;
	u32  rsv[5];
};

struct hclge_sfp_present_cmd {
	u32  sfp_present;
	u32  rsv[5];
};

struct hns3_lamp_signal {
	u8 error;
	u8 locate;
	u8 activity;
};

enum hclge_ext_opcode_type {
	/* misc command */
	HCLGE_OPC_CHIP_ID_GET		= 0x7003,
	HCLGE_OPC_IMP_COMMIT_ID_GET	= 0x7004,
	HCLGE_OPC_GET_CHIP_NUM		= 0x7005,
	HCLGE_OPC_GET_PORT_NUM		= 0x7006,
	HCLGE_OPC_SET_LED		= 0x7007,
	HCLGE_OPC_DISABLE_NET_LANE	= 0x7008,
	/*SFP command*/
	HCLGE_OPC_SFP_GET_INFO		= 0x7100,
	HCLGE_OPC_SFP_GET_PRESENT	= 0x7101,
	HCLGE_OPC_SFP_SET_STATUS	= 0x7102,
};

void hclge_clean_stats64(struct hnae3_handle *handle);
int hclge_get_chipid(struct hnae3_handle *handle, u32 *chip_id);
int hclge_get_commit_id(struct hnae3_handle *handle, u8 *commit_id,
			u32 *ncl_version);
int hclge_get_sfpinfo(struct hnae3_handle *handle, u8 *buff, u16 offset,
		      u16 size, u16 *outlen);
int hclge_set_sfp_state(struct hnae3_handle *handle, bool en);
int hclge_get_chip_num(struct hnae3_handle *handle, u32 *chip_num);
int hclge_get_port_num(struct hnae3_handle *handle, u32 *port_num);
int hclge_set_led(struct hnae3_handle *handle, u32 type, u32 status);
int hclge_get_sfp_present(struct hnae3_handle *handle, u32 *present);
int hclge_disable_net_lane(struct hnae3_handle *handle);
int hclge_get_net_lane_status(struct hnae3_handle *handle, u32 *status);
int hclge_ext_get_sfp_speed(struct hnae3_handle *handle, u32 *speed);
int hclge_get_led_signal(struct hnae3_handle *handle,
			 struct hns3_lamp_signal *signal);
int hclge_set_mac_state(struct hnae3_handle *handle, bool enable);
int hclge_config_nic_clock(struct hnae3_handle *handle, bool enable);

#endif

