/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_187x_cmdq_ops.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef _HINIC5_CQM_187X_CMDQ_PRIVATE_H_
#define _HINIC5_CQM_187X_CMDQ_PRIVATE_H_

#include "ossl_knl.h"
#include "hinic5_cqm_npu_cmd_defs.h"

struct hinic5_cqm_187x_bat_update_cmd {
	u32 rsv[2];
	u32 smf_id : 4; /* set as 0xffff, HTN_CMDQ use func_id in metadata */
	u32 byte_len : 10; /* max size: 256byte, min size: 16byte, 16Byte aligned */
	u32 offset : 18; /* byte offset, 16Byte aligned */
	u16 rsv1;
	u16 func_id;
	u8 data[HINIC5_CQM_BAT_MAX_SIZE];
};

struct hinic5_cqm_187x_cla_update_cmd {
	u32 rsv[2];
	u32 smf_id : 4;
	u32 rsv1 : 28;
	u16 rsv2;
	u16 func_id; /* set as 0xffff, HTN_CMDQ use func_id in metadata */

	/* Gpa address to be updated */
	u32 gpa_h; /* byte addr */
	u32 gpa_l;

	/* Updated Value */
	u32 value_h;
	u32 value_l;
};

struct hinic5_cqm_187x_cla_cache_invalid_cmd {
	u32 gpa_h;
	u32 gpa_l;

	u32 smf_id : 4;
	u32 cache_size : 19; /* CLA cache size=4096B */
	u32 rsv : 9;
	u16 rsv2;
	u16 func_id; /* set as 0xffff, HTN_CMDQ use func_id in metadata */
};

/* HINIC5_CQM HTN CMD */
enum hinic5_cqm_htn_cmd {
	HINIC5_CQM_HTN_CMD_T_CLA_CACHE_INVALID = 0x20,
	HINIC5_CQM_HTN_CMD_T_BAT_UPDATE,
	HINIC5_CQM_HTN_CMD_T_CLA_UPDATE
};

#endif
