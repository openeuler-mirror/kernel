/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_fast_msg_init.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_FAST_MSG_INIT
#define HINIC5_FAST_MSG_INIT

#include <linux/types.h>

typedef struct hisdk5_fast_msg_caps {
	u32 depth;
	u32 page_size;
} hisdk5_fast_msg_caps;

#define HINIC5_FAST_MSG_WQ_NAME	"hinic5_fast_msg"

int hinic5_fast_msg_init(void *hwdev);
void hinic5_fast_msg_deinit(void *hwdev);

#endif