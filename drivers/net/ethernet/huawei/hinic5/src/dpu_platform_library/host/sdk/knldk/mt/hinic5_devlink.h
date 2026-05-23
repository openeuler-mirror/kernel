/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_devlink.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_DEVLINK_H
#define HINIC5_DEVLINK_H

#include "ossl_knl.h"
#include "hinic5_hwdev.h"

#define FW_MAGIC_NUM           0x5a5a1100
#define FW_IMAGE_HEAD_SIZE     4096
#define FW_FRAGMENT_MAX_LEN    1536
#define FW_CFG_DEFAULT_INDEX   0xFF
#define FW_TYPE_MAX_NUM        0x40
#define FW_CFG_MAX_INDEX       7
#define FW_DEFAULT_TYPE_COLD_UPDATE 0

#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
enum hinic5_devlink_param_id {
	HINIC5_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	HINIC5_DEVLINK_PARAM_ID_ACTIVATE_FW,
	HINIC5_DEVLINK_PARAM_ID_SWITCH_CFG,
};
#endif

#define IMAGE_MPU_ALL_IN (BIT_ULL(UP_FW_UPDATE_UP_TEXT) | \
			  BIT_ULL(UP_FW_UPDATE_UP_DATA) | \
			  BIT_ULL(UP_FW_UPDATE_UP_DICT))
// BIT_ULL(UP_FW_UPDATE_MPU_CNT_DICT)),
// cnt index file integrity check needs consideration, temporarily not added for compatibility

#define IMAGE_NPU_ALL_IN (BIT_ULL(UP_FW_UPDATE_TILE_PCPTR) | \
			  BIT_ULL(UP_FW_UPDATE_TILE_TEXT) |  \
			  BIT_ULL(UP_FW_UPDATE_TILE_DATA) |  \
			  BIT_ULL(UP_FW_UPDATE_TILE_DICT) |  \
			  BIT_ULL(UP_FW_UPDATE_PPE_STATE) |  \
			  BIT_ULL(UP_FW_UPDATE_PPE_BRANCH) | \
			  BIT_ULL(UP_FW_UPDATE_PPE_EXTACT))
// BIT_ULL(UP_FW_UPDATE_NPU_CNT_DICT)),
// cnt index file integrity check needs consideration, temporarily not added for compatibility

#define IMAGE_COLD_SUB_MODULES_MUST_IN (IMAGE_MPU_ALL_IN | IMAGE_NPU_ALL_IN)

#define IMAGE_CFG_SUB_MODULES_MUST_IN (BIT_ULL(UP_FW_UPDATE_CFG0) | \
				       BIT_ULL(UP_FW_UPDATE_CFG1))

struct firmware_section {
	u32 section_len;
	u32 section_offset;
	u32 section_version;
	u32 section_type;
	u32 section_crc;
	u32 section_flag;
};

struct firmware_image {
	u32 fw_version;
	u32 fw_len;
	u32 fw_magic;
	struct {
		u32 section_cnt : 16;
		u32 rsvd : 16;
	} fw_info;
	struct firmware_section section_info[FW_TYPE_MAX_NUM];
	u32 device_id;   /* cfg fw board_type value */
	u32 rsvd0[101];  /* device_id and rsvd0[101] is update_head_extend_info */
	u32 rsvd1[534];  /* big bin file total size 4096B */
	u32 bin_data;    /* obtain the address for use */
};

struct host_image {
	struct firmware_section section_info[FW_TYPE_MAX_NUM];
	struct {
		u32 total_len;
		u32 fw_version;
	} image_info;
	u32 type_num;
	u32 device_id;
};

int hinic5_init_devlink(struct hinic5_hwdev *hwdev);
void hinic5_uninit_devlink(struct hinic5_hwdev *hwdev);

#endif
