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
 * Description: uburma device file ops file
 * Author: Qian Guoxin
 * Create: 2021-8-4
 * Note:
 * History: 2021-8-4: Create file
 */

#ifndef UBURMA_FILE_OPS_H
#define UBURMA_FILE_OPS_H

#include <linux/kref.h>
#include <linux/fs.h>
#include <linux/mm_types.h>

long uburma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

#endif /* UBURMA_FILE_OPS_H */
