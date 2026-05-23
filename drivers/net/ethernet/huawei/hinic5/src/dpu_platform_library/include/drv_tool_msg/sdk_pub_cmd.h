/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : sdk_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef SDK_PUB_CMD_H
#define SDK_PUB_CMD_H

#include "base_type.h"
#include "hinic5_mt.h"

/**
 * @brief struct wqe_info
 * @details Structure for storing work queue related information
 */
struct cmdq_wqe_info {
	int q_id;               /* Queue ID */
	void *rsvd;
	unsigned int wqebb_id;    /* Work queue element ID */
};

#define CMDQ_WQE_DW_NUMBER (16)

struct sdk_cmdq_wqe_desc {
	u32 data[CMDQ_WQE_DW_NUMBER];
	u32 wqebb_size;
};

enum sdk_cmd_type {
	SDK_CMD_SET_FREQ_REDUCE_RATIO = SERVICE_DRV_BASE_CMD,   /* Set chip time
								 * frequency reduction ratio
								 */
	SDK_CMD_SET_TIME_DIFF_ENABLE,    /* Enable chip time difference statistics */
	SDK_CMD_GET_TIME_DIFF,           /* Get chip time difference statistics value */
	SDK_CMD_GET_CMDQ_INFO,           /* Get cmdq queue metadata information */
	SDK_CMD_GET_CMDQ_WQE_DESC,       /* Get cmdq queue wqe information */
	SDK_CMD_CMDQ_CHANNEL_DETECT,     /* cmdq channel connectivity test */
	SDK_CMD_ATTACK_TEST,             /* SDK attack test */

	SDK_CMD_EXTEND_RSV_START = 0x200,
	/* SDK tool reserved command codes, products use command codes in this range */
	SDK_CMD_EXTEND_RSV_END = 0x2FF,
};
#endif
