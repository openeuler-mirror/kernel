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
 * Description: ubcore log head file
 * Author: Qian Guoxin
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 */

#ifndef UBCORE_LOG_H
#define UBCORE_LOG_H

/* add log head info, "LogTag_UBCORE|function|[line]| */
#define UBCORE_LOG_TAG "LogTag_UBCORE"
#define ubcore_log(l, format, args...)	\
	((void)pr_##l("%s|%s:[%d]|" format, UBCORE_LOG_TAG, __func__, __LINE__, ##args))

#define ubcore_log_info(...) ubcore_log(info, __VA_ARGS__)

#define ubcore_log_err(...) ubcore_log(err, __VA_ARGS__)

#define ubcore_log_warn(...) ubcore_log(warn, __VA_ARGS__)

#define ubcore_log_debug(...) ubcore_log(debug, __VA_ARGS__)
#endif
