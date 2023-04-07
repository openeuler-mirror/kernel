/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef BLK_EXTRA_API_H
#define BLK_EXTRA_API_H

/*
 * Include blk.h will cause kabi broken in some contexts because it will expose
 * definitions for some data structure. This file is used for the apis that
 * can't be placed in blk.h.
 */

#include <linux/genhd.h>

int disk_scan_partitions(struct gendisk *disk, fmode_t mode);

#endif /* BLK_EXTRA_API_H */
