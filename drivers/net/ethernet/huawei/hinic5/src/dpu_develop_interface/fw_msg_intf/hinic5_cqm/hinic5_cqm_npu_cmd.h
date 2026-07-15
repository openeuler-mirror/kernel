/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_npu_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : hinic5_cqm common command interface define.
 */
#ifndef HINIC5_CQM_NPU_CMD_H
#define HINIC5_CQM_NPU_CMD_H

typedef enum {
	HINIC5_CQM_CMD_T_INVALID			= 0,
	HINIC5_CQM_CMD_T_BAT_UPDATE		= 1,
	HINIC5_CQM_CMD_T_CLA_UPDATE		= 2,
	HINIC5_CQM_CMD_T_BLOOMFILTER_SET		= 3,
	HINIC5_CQM_CMD_T_BLOOMFILTER_CLEAR		= 4,
	HINIC5_CQM_CMD_T_COMPACT_SRQ_UPDATE	= 5,
	HINIC5_CQM_CMD_T_CLA_CACHE_INVALID		= 6,
	HINIC5_CQM_CMD_T_BLOOMFILTER_INIT		= 7,
	HINIC5_CQM_CMD_T_CLA_RESET			= 8, /* Reset VF's CLA */
	HINIC5_CQM_CMD_T_MAX
} hinic5_cqm_cmd_type_e;

#endif /* HINIC5_CQM_NPU_CMD_H */
