/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_npu_cmd.h
 * Version       : Initial Draft
 * Created       : 2015/11/13
 * Last Modified : 2026/09/16
 * Description   : cqm common command interface define.
 */

#ifndef CQM_NPU_CMD_H
#define CQM_NPU_CMD_H

typedef enum {
	CQM_CMD_T_INVALID			= 0,
	CQM_CMD_T_BAT_UPDATE		= 1,
	CQM_CMD_T_CLA_UPDATE		= 2,
	CQM_CMD_T_BLOOMFILTER_SET		= 3,
	CQM_CMD_T_BLOOMFILTER_CLEAR		= 4,
	CQM_CMD_T_COMPACT_SRQ_UPDATE	= 5,
	CQM_CMD_T_CLA_CACHE_INVALID		= 6,
	CQM_CMD_T_BLOOMFILTER_INIT		= 7,
	CQM_CMD_T_CLA_RESET			= 8, /* Reset VF's CLA */
	CQM_CMD_T_MAX
} cqm_cmd_type_e;

#endif /* CQM_NPU_CMD_H */
