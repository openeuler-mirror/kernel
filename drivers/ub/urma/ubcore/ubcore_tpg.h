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
 * Description: ubcore tpg header
 * Author: Yan Fangfang
 * Create: 2023-07-17
 * Note:
 * History: 2023-07-17: Create file
 */
#ifndef UBCORE_TPG_H
#define UBCORE_TPG_H

#include <urma/ubcore_types.h>

struct ubcore_tpg *ubcore_create_tpg(struct ubcore_device *dev, struct ubcore_tpg_cfg *cfg);
struct ubcore_tpg *ubcore_find_get_tpg(struct ubcore_device *dev, uint32_t tpgn);
int ubcore_create_multi_tp(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	struct ubcore_tp_cfg *cfg);
uint32_t ubcore_destroy_multi_tp(struct ubcore_device *dev, struct ubcore_tpg *tpg);
uint32_t ubcore_destroy_multi_tp_from_index(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	uint32_t from_index);
uint32_t ubcore_modify_tp_in_tpg(struct ubcore_device *dev, struct ubcore_tpg *tpg,
	struct ubcore_tp_attr *attr, union ubcore_tp_attr_mask *mask, struct ubcore_tp **failed_tp);
struct ubcore_tp *ubcore_find_tp_in_tpg(struct ubcore_tpg *tpg, uint32_t tpn);
struct ubcore_tp *ubcore_find_get_tp_in_tpg(struct ubcore_tpg *tpg, uint32_t tpn);
int ubcore_find_remove_tpg(struct ubcore_device *dev, uint32_t tpgn);
void ubcore_tpg_get(void *obj);
void ubcore_tpg_kref_put(struct ubcore_tpg *tpg);
int ubcore_add_tp(struct ubcore_device *dev, struct ubcore_tp *tp);
struct ubcore_tp *ubcore_find_get_tp(struct ubcore_device *dev, uint32_t tpn);
struct ubcore_tp *ubcore_find_remove_tp_node(struct ubcore_device *dev, uint32_t tpn);
int ubcore_find_add_tpg(struct ubcore_device *dev, struct ubcore_tpg *tpg);
#endif
