// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "wear.h"
#include <linux/vmalloc.h>
#include "euler.h"

void wear_init(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	if (!wear_control)
		return;
	sbi->page_wears = vmalloc(sizeof(struct page_wear) * sbi->npages);
	memset(sbi->page_wears, 0, sizeof(struct page_wear) * sbi->npages);
}

void wear_fini(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	if (!wear_control)
		return;
	if (sbi->page_wears)
		vfree(sbi->page_wears);
	sbi->page_wears = NULL;
}

/* Return whether it's in a good state */
bool wear_inc(struct super_block *sb, void *page)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	if (!wear_control)
		return true;
	return sbi->page_wears[(page - sbi->data_start) / PAGE_SIZE].wear++ <=
	       wear_threshold;
}
