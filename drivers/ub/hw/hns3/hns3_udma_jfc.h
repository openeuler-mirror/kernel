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
	struct ubcore_jfc		ubcore_jfc;
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
};

#define UDMA_JFC_CONTEXT_SIZE 16
struct udma_jfc_context {
	uint32_t jfc_data[UDMA_JFC_CONTEXT_SIZE];
};

static inline struct udma_jfc *to_udma_jfc(struct ubcore_jfc *jfc)
{
	return container_of(jfc, struct udma_jfc, ubcore_jfc);
}

struct ubcore_jfc *udma_create_jfc(struct ubcore_device *dev, const struct ubcore_jfc_cfg *cfg,
			      struct ubcore_udata *udata);
int udma_destroy_jfc(struct ubcore_jfc *jfc);
static inline uint8_t get_jfc_bankid(uint64_t cqn)
{
	/* The lower 2 bits of CQN are used to hash to different banks */
	return (uint8_t)(cqn & GENMASK(1, 0));
}

#endif /* _UDMA_JFC_H */
