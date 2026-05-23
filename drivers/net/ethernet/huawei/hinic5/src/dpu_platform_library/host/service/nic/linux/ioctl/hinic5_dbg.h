/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_dbg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_DBG_H
#define HINIC5_DBG_H

#include "hinic5_nic_dev.h"
#include "hinic5_mt.h"

#define HINIC5_CAR_INFO_INDEX (0x4)

typedef int (*nic_driv_module)(struct hinic5_nic_dev *nic_dev,
			       const void *buf_in, u32 in_size,
			       void *buf_out, u32 *out_size);

struct nic_drv_module_handle {
	u32	driv_cmd_name;
	nic_driv_module		driv_func;
};

#endif
