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
 * Description: uburma device file ops file
 * Author: Qian Guoxin
 * Create: 2022-8-16
 * Note:
 * History: 2022-8-16: Create file
 */

#ifndef UBURMA_CDEV_FILE_H
#define UBURMA_CDEV_FILE_H

#include "uburma_types.h"

int uburma_create_dev_attr_files(struct uburma_device *ubu_dev);
void uburma_remove_dev_attr_files(struct uburma_device *ubu_dev);

#endif /* UBURMA_CDEV_FILE_H */
