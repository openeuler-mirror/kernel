/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu address window slot manager.
 */

#ifndef __UMMU_DTU_ADDR_WINDOW_H__
#define __UMMU_DTU_ADDR_WINDOW_H__

#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>

#define DTU_WIN_MAX	16
#define DTU_WIN_BASE	8 /* driver starts at slot 8 */
#define DTU_WIN_USABLE	7 /* slots 8..14 */

/* An IOVA-to-PA address window */
struct dtu_addr_window {
	unsigned long base_iova;
	phys_addr_t   base_paddr;
	size_t        size;
};

/* Global window slot manager (one per logic device) */
struct dtu_win_mgr {
	struct dtu_addr_window windows[DTU_WIN_MAX];
	unsigned long          bitmap;
	struct mutex           lock;
};

static inline void dtu_win_mgr_init(struct dtu_win_mgr *mgr)
{
	memset(mgr->windows, 0, sizeof(mgr->windows));
	mgr->bitmap = 0;
	mutex_init(&mgr->lock);
}

static inline bool range_overlap(u64 sa, u64 la, u64 sb, u64 lb)
{
	return (sa < sb + lb) && (sa + la > sb);
}

static inline bool dtu_win_iova_overlap(const struct dtu_addr_window *a,
					const struct dtu_addr_window *b)
{
	if (a->size == 0 || b->size == 0)
		return false;
	return range_overlap((u64)a->base_iova, (u64)a->size,
			     (u64)b->base_iova, (u64)b->size);
}

static inline bool dtu_win_pa_overlap(const struct dtu_addr_window *a,
				      const struct dtu_addr_window *b)
{
	if (a->size == 0 || b->size == 0)
		return false;
	return range_overlap((u64)a->base_paddr, (u64)a->size,
			     (u64)b->base_paddr, (u64)b->size);
}

int dtu_win_remove_by_id(struct dtu_win_mgr *mgr, u8 id);
int dtu_win_check(struct dtu_win_mgr *mgr, const struct dtu_addr_window *win,
		  struct list_head *domain_win_list);
int dtu_win_save(struct dtu_win_mgr *mgr, u8 win_num,
		 const struct dtu_addr_window *win);

#endif /* __UMMU_DTU_ADDR_WINDOW_H__ */
