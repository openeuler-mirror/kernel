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

#ifndef _UDMA_JFC_H
#define _UDMA_JFC_H

#include "hns3_udma_device.h"
#include "hns3_udma_abi.h"

struct udma_jfc {
	struct ubcore_jfc	ubcore_jfc;
	struct udma_mtr		mtr;
	uint32_t		jfc_caps;
	uint32_t		jfc_depth;
	uint64_t		cqn;
	uint32_t		arm_sn;
	struct udma_db		db;
	spinlock_t		lock;
	refcount_t		refcount;
	struct completion	free;
	struct list_head	sq_list;
	struct list_head	rq_list;
	struct udma_jfc_attr_ex	jfc_attr_ex;
};

#define UDMA_JFC_CONTEXT_SIZE 16
struct udma_jfc_context {
	uint32_t jfc_data[UDMA_JFC_CONTEXT_SIZE];
};

#define UDMA_NOTIFY_MODE_4B 1UL

enum udma_notify_device_en {
	UDMA_NOTIFY_DEV,
	UDMA_NOTIFY_DDR,
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

static inline struct udma_jfc *to_udma_jfc(struct ubcore_jfc *jfc)
{
	return container_of(jfc, struct udma_jfc, ubcore_jfc);
}

struct ubcore_jfc *udma_create_jfc(struct ubcore_device *dev, struct ubcore_jfc_cfg *cfg,
				   struct ubcore_udata *udata);
int udma_destroy_jfc(struct ubcore_jfc *jfc);
int udma_modify_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_jfc_attr *attr,
		    struct ubcore_udata *udata);
void udma_jfc_completion(struct udma_dev *udma_dev, uint32_t cqn);
void udma_jfc_event(struct udma_dev *udma_dev, uint32_t cqn, int event_type);
static inline uint8_t get_jfc_bankid(uint64_t cqn)
{
	/* The lower 2 bits of CQN are used to hash to different banks */
	return (uint8_t)(cqn & GENMASK(1, 0));
}

#endif /* _UDMA_JFC_H */
