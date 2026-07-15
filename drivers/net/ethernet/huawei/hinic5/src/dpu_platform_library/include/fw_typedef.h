/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : fw_typedef.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef FW_TYPEDEF_H
#define FW_TYPEDEF_H

#include "base_type.h"

typedef enum up_fw_update_type_e {
	UP_FW_UPDATE_UP_TEXT = 0x0,
	UP_FW_UPDATE_UP_DATA = 0x1,
	UP_FW_UPDATE_UP_DICT = 0x2,
	UP_FW_UPDATE_TILE_PCPTR = 0x3,
	UP_FW_UPDATE_TILE_TEXT = 0x4,
	UP_FW_UPDATE_TILE_DATA = 0x5,
	UP_FW_UPDATE_TILE_DICT = 0x6,
	UP_FW_UPDATE_PPE_STATE = 0x7,
	UP_FW_UPDATE_PPE_BRANCH = 0x8,
	UP_FW_UPDATE_PPE_EXTACT = 0x9,
	UP_FW_UPDATE_CFG0 = 0xa,
	UP_FW_UPDATE_CFG1 = 0xb,
	UP_FW_UPDATE_MPU_CNT_DICT = 0xc,
	UP_FW_UPDATE_NPU_CNT_DICT = 0xd,
	UP_FW_UPDATE_PHY = 0x18,
	UP_FW_UPDATE_BIOS = 0x19,
	UP_FW_UPDATE_HLINK_ONE = 0x1a,
	UP_FW_UPDATE_HLINK_TWO = 0x1b,
	UP_FW_UPDATE_HLINK_THR = 0x1c,
	UP_FW_UPDATE_VERIFY_TYPE = 0x1d,
	UP_FW_UPDATE_RESVD_FW_TWO = 0x1e,
	UP_FW_UPDATE_L0FW = 0x20,
	UP_FW_UPDATE_L1FW = 0x21,
	UP_FW_UPDATE_BOOT = 0x22,
	UP_FW_UPDATE_SEC_DICT = 0x23,
	UP_FW_UPDATE_HOT_PATCH0 = 0x24,
	UP_FW_UPDATE_PSM_ROM = 0x2a,
	UP_FW_UPDATE_UB_SCC = 0x2b,
	UP_FW_UPDATE_UB_SCC_DICT = 0x2c,
	UP_FW_UPDATE_UBC_IMP = 0x2d,
	UP_FW_UPDATE_UBC_IMP_DICT = 0x2e,
	UP_FW_UPDATE_UBG_IMP = 0x2f,
	UP_FW_UPDATE_UBG_IMP_DICT = 0x30,
	UP_FW_UPDATE_ROCE_IMP = 0x31,
	UP_FW_UPDATE_ROCE_IMP_DICT = 0x32,
	UP_FW_UPDATE_ROCE_SCC = 0x33,
	UP_FW_UPDATE_ROCE_SCC_DICT = 0x34,
	UP_FW_UPDATE_OPTION_ROM = 0x3a,
	UP_FW_UPDATE_EXTEND_BIN = 0x3e,
} up_fw_update_type_e;

#define UP_MAX_FW_TYPE_CNT 0x40

/* uP image context could not be the same since the flash address the
 * checksum are different. It is needed to keep two different fw information.
 */
#define FINAL_SUM(sum) (~(sum))

typedef struct fw_section_info_s {
	u32 invalid;
	u32 fw_ver;
	u32 fw_len;
	u32 fw_crc;
	u32 fw_info_csum;
} fw_section_info_s;

typedef struct fw_info_s {
	u32 invalid;	// Non-zero means state machine does not exist, 0 means exists
	u32 cfg_index;	// Configuration file index, 0~7
	u8 image_state[UP_MAX_FW_TYPE_CNT];	// Primary/standby state, 0 is primary, 1 is standby
	fw_section_info_s fw_attr[UP_MAX_FW_TYPE_CNT];	// Sub-firmware information
	u32 csum;
} fw_info_s;

#endif
