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

/* add log head info, "LogTag_UBURMA|function|[line]| */
#define UBURMA_LOG_TAG "LogTag_UBURMA"
#define uburma_log(l, format, args...)	\
	((void)pr_##l("%s|%s:[%d]|" format, UBURMA_LOG_TAG, __func__, __LINE__, ##args))

#define uburma_log_info(...) uburma_log(info, __VA_ARGS__)

#define uburma_log_err(...) uburma_log(err, __VA_ARGS__)

#define uburma_log_warn(...) uburma_log(warn, __VA_ARGS__)

#define uburma_log_debug(...) uburma_log(debug, __VA_ARGS__)

#endif /* UBURMA_LOG_H */
