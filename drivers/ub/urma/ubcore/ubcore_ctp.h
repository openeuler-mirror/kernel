/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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
 * Description: ubcore ctp header
 * Author: Xu Zhicong
 * Create: 2023-10-12
 * Note:
 * History: 2023-10-12: Create file
 */
#ifndef UBCORE_CTP_H
#define UBCORE_CTP_H

#include <urma/ubcore_types.h>

struct ubcore_ctp *ubcore_create_ctp(struct ubcore_device *dev, struct ubcore_ctp_cfg *cfg);
int ubcore_destroy_ctp(struct ubcore_ctp *ctp);
struct ubcore_ctp *ubcore_find_ctp(struct ubcore_device *dev, uint32_t idx);
struct ubcore_ctp *ubcore_find_get_ctp(struct ubcore_device *dev, uint32_t idx);
struct ubcore_ctp *ubcore_find_remove_ctp(struct ubcore_device *dev, uint32_t idx);
void ubcore_ctp_get(void *obj);
void ubcore_ctp_kref_put(struct ubcore_ctp *ctp);
#endif
