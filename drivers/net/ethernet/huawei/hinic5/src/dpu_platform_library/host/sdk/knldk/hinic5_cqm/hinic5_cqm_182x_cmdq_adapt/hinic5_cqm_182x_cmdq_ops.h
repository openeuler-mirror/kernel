/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_182x_cmdq_ops.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef _HINIC5_CQM_182X_CMDQ_PRIVATE_H_
#define _HINIC5_CQM_182X_CMDQ_PRIVATE_H_

#include "ossl_knl.h"
#include "hinic5_cqm_npu_cmd_defs.h"

struct hinic5_cqm_182x_bat_update_cmd {
	u32 offset;   /* byte offset,16Byte aligned */
	u32 byte_len; /* max size: 256byte */
	u8 data[HINIC5_CQM_BAT_MAX_SIZE];
	u32 smf_id;
	u32 func_id;
};

struct hinic5_cqm_182x_cla_update_cmd {
	/* Gpa address to be updated */
	u32 gpa_h; /* byte addr */
	u32 gpa_l; /* byte addr */

	/* Updated Value */
	u32 value_h;
	u32 value_l;

	u32 smf_id;
	u32 func_id;
};

struct hinic5_cqm_182x_cla_cache_invalid_cmd {
	u32 gpa_h;
	u32 gpa_l;

	u32 cache_size; /* CLA cache size=4096B */

	u32 smf_id;
	u32 func_id;
};

#endif
