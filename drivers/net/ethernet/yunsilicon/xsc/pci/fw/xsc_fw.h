/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FW_H
#define XSC_FW_H

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"

struct xsc_free_list {
	struct list_head list;
	int start;
	int end;
};

struct xsc_free_list_wl {
	struct xsc_free_list head;
	spinlock_t lock;	/* lock for free list */
};

struct xsc_mpt_info {
	u64 va;
	u32 mtt_base;
	u32 page_num;
};

#define XSC_RES_IAE_GRP_MASK (XSC_RES_NUM_IAE_GRP - 1)
struct xsc_resources {
	atomic_t iae_grp;
	int iae_idx[XSC_RES_NUM_IAE_GRP];
	spinlock_t iae_lock[XSC_RES_NUM_IAE_GRP];	/* iae group lock */
	struct xsc_mpt_info *mpt_entry;
	int max_mpt_num;
	u8 *mpt_tbl;
	int max_mtt_num;
	struct xsc_free_list_wl mtt_list;
	spinlock_t lock; /* lock for mpt_tbl */
};

struct xsc_resources *get_xsc_res(struct xsc_core_device *dev);

int alloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx);

int dealloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx);

int alloc_mtt_entry(struct xsc_core_device *dev, u32 pages_num, u32 *mtt_base);

int dealloc_mtt_entry(struct xsc_core_device *dev, int pages_num, u32 mtt_base);

void save_mtt_to_free_list(struct xsc_core_device *dev, u32 base, u32 num);
void xsc_sync_mr_to_fw(struct xsc_core_device *dev);
void xsc_sync_mr_from_fw(struct xsc_core_device *dev);

#endif
