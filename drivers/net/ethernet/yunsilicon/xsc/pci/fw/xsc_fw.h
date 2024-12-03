/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FW_H
#define XSC_FW_H

#include "osdep.h"

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"

struct xsc_free_list {
	struct list_head list;
	int start;
	int end;
};

struct xsc_free_list_wl {
	struct xsc_free_list head;
	struct xsc_lock lock;
};

struct xsc_mpt_info {
	u64 va;
	u32 mtt_base;
	u32 page_num;
};

#define XSC_RES_IAE_GRP_MASK (XSC_RES_NUM_IAE_GRP - 1)
struct xsc_resources {
	int refcnt;
	atomic_t iae_grp;
	int iae_idx[XSC_RES_NUM_IAE_GRP];
	spinlock_t iae_lock[XSC_RES_NUM_IAE_GRP];	/* iae group lock */
#define XSC_MAX_MPT_NUM MMC_MPT_TBL_MEM_DEPTH
	struct xsc_mpt_info mpt_entry[XSC_MAX_MPT_NUM];
	int max_mpt_num;
	u64 mpt_tbl[XSC_MAX_MPT_NUM >> 6];
#define XSC_MAX_MTT_NUM MMC_MTT_TBL_MEM_DEPTH
	int max_mtt_num;
	struct xsc_free_list_wl mtt_list;
	struct xsc_lock lock;
};

struct xsc_resources *get_xsc_res(struct xsc_core_device *dev);

int xsc_alloc_res(u32 *res, u64 *res_tbl, u32 max);

int xsc_dealloc_res(u32 *res, u64 *res_tbl);

int alloc_from_free_list(struct xsc_free_list_wl *list, int required, u32 *alloc,
			 u32 base_align);

int release_to_free_list(struct xsc_free_list_wl *list, u32 release,
			 u32 num_released);

int alloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx);

int dealloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx);

int alloc_mtt_entry(struct xsc_core_device *dev, u32 pages_num, u32 *mtt_base);

int dealloc_mtt_entry(struct xsc_core_device *dev, int pages_num, u32 mtt_base);
#endif /* XSC_FW_H */
