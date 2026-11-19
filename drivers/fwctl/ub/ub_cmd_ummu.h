/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#ifndef __UB_CMD_UMMU_H__
#define __UB_CMD_UMMU_H__

#include "ub_common.h"

int ubctl_ummu_process_data(struct ubctl_dev *ucdev,
			    struct ubctl_query_cmd_param *query_cmd_param,
			    struct ubctl_func_dispatch *query_func);
#endif
