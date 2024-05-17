/* SPDX-License-Identifier: GPL-2.0 */
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
 * Description: ubcore jetty find header file
 * Author: Zhang jiayu
 * Create: 2024-3-12
 * Note:
 * History: 2024-3-12: Create file
 */

#ifndef UBCORE_JETTY_H
#define UBCORE_JETTY_H

#include "ubcore_types.h"

/* The APIs below are deprecated, should not be called by driver or ubcore client */
struct ubcore_jfc *ubcore_find_jfc(struct ubcore_device *dev, uint32_t jfc_id);

struct ubcore_jfs *ubcore_find_jfs(struct ubcore_device *dev, uint32_t jfs_id);

struct ubcore_jfr *ubcore_find_jfr(struct ubcore_device *dev, uint32_t jfr_id);

struct ubcore_jetty *ubcore_find_jetty(struct ubcore_device *dev, uint32_t jetty_id);

#endif
