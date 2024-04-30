/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef RDMA_BITMAP_H
#define RDMA_BITMAP_H

#include <linux/spinlock.h>

#ifndef RDMA_INVALID_INDEX
#define RDMA_INVALID_INDEX 0xFFFFFFFF
#endif

#define ROCE_BITMAP_ROUNDUP_POW_OF_TWO(n) (roundup_pow_of_two(n))

struct rdma_bitmap {
	u32 last;		/* bottom of available id  */
	u32 top;		/* top value of non zone of id  */
	u32 max_num;		/* max id num */
	u32 reserved_top;	/* unavailable top num */
	u32 mask;		/* mask of id */
	u32 avail;		/* num of available id */
	spinlock_t lock;	/* spinlock of bitmap */
	unsigned long *table;	/* memory of bitmap */
};

u32 rdma_bitmap_alloc(struct rdma_bitmap *bitmap);

void rdma_bitmap_free(struct rdma_bitmap *bitmap, u32 index);

int rdma_bitmap_init(struct rdma_bitmap *bitmap, u32 num, u32 mask,
	u32 reserved_bot, u32 reserved_top);

void rdma_bitmap_cleanup(struct rdma_bitmap *bitmap);

#endif // __RDMA_BITMAP_H__

