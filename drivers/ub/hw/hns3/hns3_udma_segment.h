/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
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

#ifndef _UDMA_SEGMENT_H
#define _UDMA_SEGMENT_H

#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include "urma/ubcore_opcode.h"
#include "hns3_udma_device.h"
#include "hns3_udma_common.h"

#define SEG_KEY_OFFSET		8
#define MPT_PAGE_OFFSET		3
#define PA_PAGE_SHIFT		6
#define MPT_VA_H_SHIFT		32
#define MPT_LEN_H_SHIFT		32
#define UDMA_PAGE_SIZE_1G	0x40000 // 1GB page size

enum {
	MPT_ST_VALID = 0x1,
};

struct udma_mpt_entry {
	uint32_t	mpt_context1[4];
	uint32_t	len_l;
	uint32_t	len_h;
	uint32_t	lkey;
	uint32_t	va_l;
	uint32_t	va_h;
	uint32_t	pbl_size;
	uint32_t	pbl_ba_l;
	uint32_t	mpt_context2;
	uint32_t	pa0_l;
	uint32_t	mpt_context3;
	uint32_t	pa1_l;
	uint32_t	mpt_context4;
};

#define MPT_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define MPT_ST MPT_FIELD_LOC(1, 0)
#define MPT_PBL_HOP_NUM MPT_FIELD_LOC(3, 2)
#define MPT_PBL_BA_PG_SZ MPT_FIELD_LOC(7, 4)
#define MPT_PD MPT_FIELD_LOC(31, 8)
#define MPT_R_INV_EN MPT_FIELD_LOC(33, 33)
#define MPT_L_INV_EN MPT_FIELD_LOC(34, 34)
#define MPT_RW_EN MPT_FIELD_LOC(38, 38)
#define MPT_LW_EN MPT_FIELD_LOC(39, 39)
#define MPT_PA MPT_FIELD_LOC(65, 65)
#define MPT_INNER_PA_VLD MPT_FIELD_LOC(71, 71)
#define MPT_LEN_L MPT_FIELD_LOC(159, 128)
#define MPT_LEN_H MPT_FIELD_LOC(191, 160)
#define MPT_LKEY MPT_FIELD_LOC(223, 192)
#define MPT_VA_L MPT_FIELD_LOC(255, 224)
#define MPT_VA_H MPT_FIELD_LOC(287, 256)
#define MPT_PBL_BA_H MPT_FIELD_LOC(380, 352)
#define MPT_PA0_H MPT_FIELD_LOC(441, 416)
#define MPT_PA1_L MPT_FIELD_LOC(579, 448)
#define MPT_PA1_H MPT_FIELD_LOC(505, 480)
#define MPT_PERSIST_EN MPT_FIELD_LOC(506, 506)
#define MPT_PBL_BUF_PG_SZ MPT_FIELD_LOC(511, 508)

#define UDMA_MAX_INNER_MTPT_NUM 2

struct ubcore_target_seg *udma_register_seg(struct ubcore_device *dev,
					    struct ubcore_seg_cfg *cfg,
					    struct ubcore_udata *udata);
int udma_unregister_seg(struct ubcore_target_seg *seg);
struct ubcore_target_seg *udma_import_seg(struct ubcore_device *dev,
					  struct ubcore_target_seg_cfg *cfg,
					  struct ubcore_udata *udata);
int udma_unimport_seg(struct ubcore_target_seg *tseg);
uint64_t key_to_hw_index(uint32_t key);

#endif /* _UDMA_SEGMENT_H */
