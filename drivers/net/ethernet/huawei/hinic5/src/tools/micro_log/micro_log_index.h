/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_index.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Micro log index header
 */

#ifndef MICRO_LOG_INDEX_H_
#define MICRO_LOG_INDEX_H_

#include "micro_log_comm.h"

#define FW_TILE_DATA_INDEX 0x5
int mirco_log_get_sim_data_from_flash(void *hwdev, struct micro_log_info *log_info);

#endif
