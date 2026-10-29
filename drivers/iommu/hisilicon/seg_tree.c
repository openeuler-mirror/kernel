// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU segment tree
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/maple_tree.h>
#include <linux/slab.h>

#include "seg_tree.h"

struct maple_tree *ummu_create_seg_tree(void)
{
	struct maple_tree *mtree;

	mtree = kzalloc(sizeof(*mtree), GFP_KERNEL);
	if (!mtree)
		return NULL;
	mt_init_flags(mtree, MT_FLAGS_ALLOC_RANGE);

	return mtree;
}

int ummu_insert_seg(void *data, struct maple_tree *seg_tree, u64 left, u64 size)
{
	int ret;

	ret = mtree_insert_range(seg_tree, left, left + size, data, GFP_KERNEL);
	if (ret) {
		pr_err("insert segment failed, ret = %d.\n", ret);
		return -EINVAL;
	}

	return 0;
}

void *ummu_find_seg(u64 left, u64 size, struct maple_tree *seg_tree, range_compare func, int *comp)
{
	void *data;

	MA_STATE(mas, seg_tree, left, left + size);
	data = mas_find(&mas, ULONG_MAX);
	if (!data) {
		*comp = RANGE_NOT_EXIST;
		return NULL;
	}

	*comp = func(left, size, data);
	return data;
}

int ummu_delete_seg(u64 left, u64 size, struct maple_tree *seg_tree, range_compare func,
		    clear_seg_node cleaner)
{
	int comp_ret;
	void *data;

	data = ummu_find_seg(left, size, seg_tree, func, &comp_ret);
	if (comp_ret == RANGE_NOT_EXIST)
		return -ENXIO;
	else if (comp_ret == RANGE_OVERLAP)
		return -ERANGE;

	data = mtree_erase(seg_tree, left);
	if (!data)
		return -EINVAL;

	if (cleaner)
		cleaner(data);
	kfree(data);
	return 0;
}

void ummu_destroy_seg_tree(struct maple_tree *seg_tree, clear_seg_node cleaner)
{
	void *data;

	if (!mtree_empty(seg_tree)) {
		MA_STATE(mas, seg_tree, 0, 0);
		mas_for_each(&mas, data, ULONG_MAX) {
			if (cleaner)
				cleaner(data);
			kfree(data);
		}
	}

	mtree_destroy(seg_tree);
	kfree(seg_tree);
}
