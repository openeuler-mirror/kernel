// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: ubcore log file
 * Author: Qian Guoxin
 * Create: 2024-2-5
 * Note:
 * History: 2024-2-5: Create file
 */

#include <linux/types.h>
#include "ubcore_log.h"

uint32_t g_ubcore_log_level = UBCORE_LOG_LEVEL_INFO;
