/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _HNS3_UDMA_DB_H
#define _HNS3_UDMA_DB_H

#include "hns3_udma_device.h"

int hns3_udma_db_map_user(struct hns3_udma_ucontext *udma_ctx, uint64_t virt,
			  struct hns3_udma_db *db);

void hns3_udma_db_unmap_user(struct hns3_udma_ucontext *udma_ctx, struct hns3_udma_db *db);

#endif /* _HNS3_UDMA_DB_H */
