// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu address window slot manager.
 */

#define pr_fmt(fmt) "[ub dtu]: " fmt

#include <linux/errno.h>
#include <linux/bitops.h>

#include "dtu_addr_window.h"
#include "dtu.h"

static int find_free_slot(unsigned long used)
{
	unsigned long avail = ~used & GENMASK(DTU_WIN_BASE + DTU_WIN_USABLE - 1,
					      DTU_WIN_BASE);
	if (avail == 0)
		return -ENOSPC;
	return __ffs(avail);
}

int dtu_win_remove_by_id(struct dtu_win_mgr *mgr, u8 id)
{
	if (id < DTU_WIN_BASE || id >= DTU_WIN_BASE + DTU_WIN_USABLE)
		return -EINVAL;

	guard(mutex)(&mgr->lock);

	if (!(mgr->bitmap & BIT(id)))
		return -EINVAL;

	memset(&mgr->windows[id], 0, sizeof(mgr->windows[id]));
	mgr->bitmap &= ~BIT(id);
	return 0;
}

int dtu_win_check(struct dtu_win_mgr *mgr, const struct dtu_addr_window *win,
		  struct list_head *domain_win_list)
{
	struct ub_dtu_win *existing;
	int i;

	list_for_each_entry(existing, domain_win_list, node) {
		struct dtu_addr_window cur = {
			.base_iova = existing->iova,
			.size = existing->size,
		};
		if (dtu_win_iova_overlap(win, &cur))
			return -EBUSY;
	}

	guard(mutex)(&mgr->lock);

	if (find_free_slot(mgr->bitmap) < 0)
		return -ENOSPC;

	for (i = DTU_WIN_BASE; i < DTU_WIN_BASE + DTU_WIN_USABLE; i++) {
		if (!(mgr->bitmap & BIT(i)))
			continue;
		if (dtu_win_pa_overlap(win, &mgr->windows[i]))
			return -EBUSY;
	}

	return 0;
}

int dtu_win_save(struct dtu_win_mgr *mgr, u8 win_num,
		 const struct dtu_addr_window *win)
{
	if (win_num < DTU_WIN_BASE || win_num >= DTU_WIN_BASE + DTU_WIN_USABLE)
		return -EINVAL;

	guard(mutex)(&mgr->lock);

	if (mgr->bitmap & BIT(win_num))
		return -EBUSY;

	mgr->windows[win_num] = *win;
	mgr->bitmap |= BIT(win_num);
	return 0;
}
