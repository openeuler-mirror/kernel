/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HMM_BUDDY_H
#define HMM_BUDDY_H

#include <linux/spinlock.h>
#include <linux/mm.h>

#if defined(__i386__)
#include <linux/highmem.h>
#endif

#ifndef HMM_INVALID_INDEX
#define HMM_INVALID_INDEX 0xFFFFFFFF
#endif

struct hmm_buddy {
	unsigned long **bits;   /* 指向多级bitmap的内存 */
	unsigned int *num_free; /* 指示各级bitmap中可用的索引个数 */
	u32 max_order;		  /* 指bitmap的级数 */
	spinlock_t lock;		/* buddy的自旋锁 */
};

u32 hmm_buddy_alloc(struct hmm_buddy *buddy, u32 order);
void hmm_buddy_free(struct hmm_buddy *buddy, u32 first_index, u32 order);

int hmm_buddy_init(struct hmm_buddy *buddy, u32 max_order);
void hmm_buddy_cleanup(struct hmm_buddy *buddy);


#endif // HMM_BUDDY_H
