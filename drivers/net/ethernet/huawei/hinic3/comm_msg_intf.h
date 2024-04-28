/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * File Name     : comm_msg_intf.h
 * Version       : Initial Draft
 * Created       : 2021/6/28
 * Last Modified :
 * Description   : COMM Command interfaces between Driver and MPU
 * Function List :
 */

#ifndef COMM_MSG_INTF_H
#define COMM_MSG_INTF_H

#include "comm_defs.h"
#include "mgmt_msg_base.h"
#include "mpu_cmd_base_defs.h"
#include "mpu_inband_cmd_defs.h"

struct spu_cmd_freq_operation {
	struct comm_info_head head;

	u8 op_code; /* 0: get  1: set 2: check */
	u8 rsvd[3];
	u32 freq;
};

struct spu_cmd_power_operation {
	struct comm_info_head head;

	u8 op_code; /* 0: get  1: set 2: init */
	u8 slave_addr;
	u8 cmd_id;
	u8 size;
	u32 value;
};

struct spu_cmd_tsensor_operation {
	struct comm_info_head head;

	u8 op_code;
	u8 rsvd[3];
	s16 fabric_tsensor_temp_avg;
	s16 fabric_tsensor_temp;
	s16 sys_tsensor_temp_avg;
	s16 sys_tsensor_temp;
};

enum cfg_msix_operation {
	CFG_MSIX_OPERATION_FREE = 0,
	CFG_MSIX_OPERATION_ALLOC = 1,
};

struct comm_cmd_ffm_info {
	struct mgmt_msg_head head;

	u8 node_id;
	/* error level of the interrupt source */
	u8 err_level;
	/* Classification by interrupt source properties */
	u16 err_type;
	u32 err_csr_addr;
	u32 err_csr_value;
	u32 rsvd1;
};

struct hinic3_cmd_update_firmware {
	struct mgmt_msg_head msg_head;

	struct {
		u32 sl : 1;
		u32 sf : 1;
		u32 flag : 1;
		u32 bit_signed : 1;
		u32 reserved : 12;
		u32 fragment_len : 16;
	} ctl_info;

	struct {
		u32 section_crc;
		u32 section_type;
	} section_info;

	u32 total_len;
	u32 section_len;
	u32 section_version;
	u32 section_offset;
	u32 data[384];
};

struct hinic3_cmd_activate_firmware {
	struct mgmt_msg_head msg_head;
	u8 index; /* 0 ~ 7 */
	u8 data[7];
};

struct hinic3_cmd_switch_config {
	struct mgmt_msg_head msg_head;
	u8 index; /* 0 ~ 7 */
	u8 data[7];
};

#endif
