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

#ifndef _HNS3_UDMA_JFC_H
#define _HNS3_UDMA_JFC_H

#include "hns3_udma_device.h"
#include "hns3_udma_abi.h"

struct hns3_udma_jfc {
	struct ubcore_jfc		ubcore_jfc;
	struct hns3_udma_mtr		mtr;
	uint32_t			jfc_caps;
	uint32_t			jfc_depth;
	uint64_t			cqn;
	uint32_t			arm_sn;
	struct hns3_udma_db		db;
	spinlock_t			lock;
	refcount_t			refcount;
	struct completion		free;
	struct list_head		sq_list;
	struct list_head		rq_list;
	struct hns3_udma_ucontext	*hns3_udma_uctx;
	struct hns3_udma_jfc_attr_ex	jfc_attr_ex;
};

#define HNS3_UDMA_JFC_CONTEXT_SIZE 16
struct hns3_udma_jfc_context {
	uint32_t jfc_data[HNS3_UDMA_JFC_CONTEXT_SIZE];
};

#define HNS3_UDMA_NOTIFY_MODE_4B 1UL

enum hns3_udma_notify_device_en {
	HNS3_UDMA_NOTIFY_DEV,
	HNS3_UDMA_NOTIFY_DDR,
};

#define CQC_NOTIFY_ADDR_0_S 12
#define CQC_NOTIFY_ADDR_0_M GENMASK(19, 12)
#define CQC_NOTIFY_ADDR_1_S 20
#define CQC_NOTIFY_ADDR_1_M GENMASK(29, 20)
#define CQC_NOTIFY_ADDR_2_S 30
#define CQC_NOTIFY_ADDR_2_M GENMASK(33, 30)
#define CQC_NOTIFY_ADDR_3_S 34
#define CQC_NOTIFY_ADDR_3_M GENMASK(41, 34)
#define CQC_NOTIFY_ADDR_4_S 42
#define CQC_NOTIFY_ADDR_4_M GENMASK(49, 42)
#define CQC_NOTIFY_ADDR_5_S 50
#define CQC_NOTIFY_ADDR_5_M GENMASK(57, 50)
#define CQC_NOTIFY_ADDR_6_S 58
#define CQC_NOTIFY_ADDR_6_M GENMASK(63, 58)

#define CQC_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define CQC_CQE_BA_L_OFFSET 3
#define CQC_CQE_BA_H_OFFSET 35

#define CQC_CQ_ST CQC_FIELD_LOC(1, 0)
#define CQC_NOTIFY_MODE CQC_FIELD_LOC(4, 4)
#define CQC_ARM_ST CQC_FIELD_LOC(7, 6)
#define CQC_SHIFT CQC_FIELD_LOC(12, 8)
#define CQC_CEQN CQC_FIELD_LOC(23, 15)
#define CQC_NOTIFY_ADDR_0 CQC_FIELD_LOC(31, 24)
#define CQC_CQN CQC_FIELD_LOC(55, 32)
#define CQC_POE_EN CQC_FIELD_LOC(56, 56)
#define CQC_POE_NUM CQC_FIELD_LOC(58, 57)
#define CQC_CQE_SIZE CQC_FIELD_LOC(60, 59)
#define CQC_NOTIFY_DEVICE_EN CQC_FIELD_LOC(62, 62)
#define CQC_CQE_CUR_BLK_ADDR_L CQC_FIELD_LOC(95, 64)
#define CQC_CQE_CUR_BLK_ADDR_H CQC_FIELD_LOC(115, 96)
#define CQC_POE_QID CQC_FIELD_LOC(125, 116)
#define CQC_CQE_HOP_NUM CQC_FIELD_LOC(127, 126)
#define CQC_CQE_NEX_BLK_ADDR_L CQC_FIELD_LOC(159, 128)
#define CQC_CQE_NEX_BLK_ADDR_H CQC_FIELD_LOC(179, 160)
#define CQC_NOTIFY_ADDR_2 CQC_FIELD_LOC(183, 180)
#define CQC_CQE_BAR_PG_SZ CQC_FIELD_LOC(187, 184)
#define CQC_CQE_BUF_PG_SZ CQC_FIELD_LOC(191, 188)
#define CQC_NOTIFY_ADDR_3 CQC_FIELD_LOC(223, 216)
#define CQC_NOTIFY_ADDR_4 CQC_FIELD_LOC(255, 248)
#define CQC_CQE_BA_L CQC_FIELD_LOC(287, 256)
#define CQC_CQE_BA_H CQC_FIELD_LOC(316, 288)
#define CQC_DB_RECORD_EN CQC_FIELD_LOC(320, 320)
#define CQC_CQE_DB_RECORD_ADDR_L CQC_FIELD_LOC(351, 321)
#define CQC_CQE_DB_RECORD_ADDR_H CQC_FIELD_LOC(383, 352)
#define CQC_CQE_CNT CQC_FIELD_LOC(407, 384)
#define CQC_NOTIFY_ADDR_5 CQC_FIELD_LOC(415, 408)
#define CQC_CQ_MAX_CNT CQC_FIELD_LOC(431, 416)
#define CQC_CQ_PERIOD CQC_FIELD_LOC(447, 432)
#define CQC_NOTIFY_ADDR_6 CQC_FIELD_LOC(509, 504)
#define CQC_NOTIFY_EN CQC_FIELD_LOC(510, 510)

static inline struct hns3_udma_jfc *to_hns3_udma_jfc(struct ubcore_jfc *jfc)
{
	return container_of(jfc, struct hns3_udma_jfc, ubcore_jfc);
}

struct ubcore_jfc *hns3_udma_create_jfc(struct ubcore_device *dev, struct ubcore_jfc_cfg *cfg,
					struct ubcore_udata *udata);
int hns3_udma_destroy_jfc(struct ubcore_jfc *jfc);
int hns3_udma_modify_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_jfc_attr *attr,
			 struct ubcore_udata *udata);
void hns3_udma_jfc_completion(struct hns3_udma_dev *udma_dev, uint32_t cqn);
void hns3_udma_jfc_event(struct hns3_udma_dev *udma_dev, uint32_t cqn, int event_type);
uint8_t hns3_udma_get_cq_bankid_for_uctx(struct hns3_udma_dev *ub_dev);
void hns3_udma_put_cq_bankid_for_uctx(struct hns3_udma_ucontext *uctx);
static inline uint8_t get_jfc_bankid(uint64_t cqn)
{
	/* The lower 2 bits of CQN are used to hash to different banks */
	return (uint8_t)(cqn & GENMASK(1, 0));
}

#endif /* _HNS3_UDMA_JFC_H */
