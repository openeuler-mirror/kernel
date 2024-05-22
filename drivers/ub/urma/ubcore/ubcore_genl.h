/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: define hash table ops
 * Author: Zhao Yanchao
 * Create: 2024-01-18
 * Note:
 * History: 2024-01-18  Zhao Yanchao  Add base code
 */

#ifndef UBCORE_GENL_H
#define UBCORE_GENL_H

#include "urma/ubcore_types.h"
int ubcore_genl_init(void) __init;
void ubcore_genl_exit(void);

#endif
