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
 * Description: uburma main header
 * Author: Yan Fangfang
 * Create: 2023-12-12
 * Note:
 * History: 2023-12-12: Create file
 */

#ifndef UBURMA_MAIN_H
#define UBURMA_MAIN_H

#include "uburma_types.h"

int uburma_set_ns_mode(bool shared);
int uburma_set_dev_ns(char *device_name, int ns_fd);
bool uburma_dev_accessible_by_ns(struct uburma_device *ubu_dev, struct net *net);
#endif
