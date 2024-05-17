/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma log head file
 * Author: Qian Guoxin
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 */

#ifndef UBURMA_LOG_H
#define UBURMA_LOG_H

#include <linux/types.h>
#include <linux/printk.h>

enum uburma_log_level {
	UBURMA_LOG_LEVEL_EMERG = 0,
	UBURMA_LOG_LEVEL_ALERT = 1,
	UBURMA_LOG_LEVEL_CRIT = 2,
	UBURMA_LOG_LEVEL_ERR = 3,
	UBURMA_LOG_LEVEL_WARNING = 4,
	UBURMA_LOG_LEVEL_NOTICE = 5,
	UBURMA_LOG_LEVEL_INFO = 6,
	UBURMA_LOG_LEVEL_DEBUG = 7,
	UBURMA_LOG_LEVEL_MAX = 8,
};

/* add log head info, "LogTag_UBURMA|function|[line]| */
#define UBURMA_LOG_TAG "LogTag_UBURMA"
#define uburma_log(l, format, args...)	\
	pr_##l("%s|%s:[%d]|" format, UBURMA_LOG_TAG, __func__, __LINE__, ##args)

extern uint32_t g_uburma_log_level;

#define uburma_log_info(...) do {   \
	if (g_uburma_log_level >= UBURMA_LOG_LEVEL_INFO) \
		uburma_log(info, __VA_ARGS__);   \
} while (0)

#define uburma_log_err(...) do {   \
	if (g_uburma_log_level >= UBURMA_LOG_LEVEL_ERR) \
		uburma_log(err, __VA_ARGS__);   \
} while (0)

#define uburma_log_warn(...) do {   \
	if (g_uburma_log_level >= UBURMA_LOG_LEVEL_WARNING) \
		uburma_log(warn, __VA_ARGS__);   \
} while (0)

#define uburma_log_debug(...) do {   \
	if (g_uburma_log_level >= UBURMA_LOG_LEVEL_DEBUG) \
		uburma_log(debug, __VA_ARGS__);   \
} while (0)

#endif /* UBURMA_LOG_H */
