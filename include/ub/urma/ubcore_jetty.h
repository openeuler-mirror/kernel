/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: ubcore jetty header file
 * Author: Zhang jiayu
 * Create: 2024-3-12
 * Note:
 * History: 2024-3-12: Create file
 */

#ifndef UBCORE_JETTY_H
#define UBCORE_JETTY_H

#include "ubcore_types.h"

struct ubcore_jfc *ubcore_find_jfc(struct ubcore_device *dev, uint32_t jfc_id);
void ubcore_put_jfc(struct ubcore_jfc *jfc);
void ubcore_jfc_get(void *obj);

struct ubcore_jfs *ubcore_find_jfs(struct ubcore_device *dev, uint32_t jfs_id);
void ubcore_put_jfs(struct ubcore_jfs *jfs);
void ubcore_jfs_get(void *obj);

struct ubcore_jfr *ubcore_find_jfr(struct ubcore_device *dev, uint32_t jfr_id);
void ubcore_put_jfr(struct ubcore_jfr *jfr);
void ubcore_jfr_get(void *obj);

struct ubcore_jetty *ubcore_find_jetty(struct ubcore_device *dev,
					   uint32_t jetty_id);
void ubcore_put_jetty(struct ubcore_jetty *jetty);
void ubcore_jetty_get(void *obj);

struct ubcore_jfc *ubcore_find_get_jfc(struct ubcore_device *dev, uint32_t jfc_id);
struct ubcore_jfs *ubcore_find_get_jfs(struct ubcore_device *dev, uint32_t jfs_id);
struct ubcore_jfr *ubcore_find_get_jfr(struct ubcore_device *dev, uint32_t jfr_id);
struct ubcore_jetty *ubcore_find_get_jetty(struct ubcore_device *dev, uint32_t jetty_id);

#endif

