/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_micro_log.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Micro log header file
 */

#ifndef __NIC_MICRO_LOG_H__
#define __NIC_MICRO_LOG_H__

#define MAX_PATH_NAME 256

#define MAX_LEN_MICRO_LOG_DATA (64 * 1024)

#define MAX_NUM_OF_ONE_TIME_ULOG (16 * 1024)

#define MAX_SIZE_OF_LOG_FILE (512 * 1024 * 1024)

#define MICRO_LOG_ITEM_LEN 64

#define MICRO_LOG_MAX_RECV_NUM_ONE_TIME 20

#define MICRO_LOG_MEM_TAG MEM_TAG("MICRO_LOG_INIT")

#define LINE_CHAR_NUM (20)

#define MICRO_LOG_POLLING_TIME 1

#define MICRO_LOG_Q_CI_MASK (0x000F)
#define MICRO_LOG_D2_CI_MASK (0x00FF)
#define MICRO_LOG_ALL_MASK (0xFFFF)

/* This must be fixed at 0, the tool auto-generated TBL_ID_DFX_LOG_POINTER is fixed at position 0 */
#define TBL_ID_DFX_LOG_POINTER 0

/* Type */
#define ULOG_ERR 0
#define ULOG_WARN 1
#define ULOG_INFO 2
#define ULOG_DEBUG 3

int hinic5_comm_micro_log_init(struct hinic5_hwdev *hwdev);

int hinic5_micro_log_func_en(void *hwdev, u8 is_en);

int hinic5_micro_log_init(void *hwdev);

void hinic5_micro_log_uninit(void *hwdev);

void hinic5_micro_log_reset(void *hwdev);

#define BEIJING_TIMEZONE 8
#define SECONDS_OF_HOUR 3600
#define TIMEZONE_ADJUSTMENT(unix_time) \
	(unix_time + (BEIJING_TIMEZONE * SECONDS_OF_HOUR))

#endif
