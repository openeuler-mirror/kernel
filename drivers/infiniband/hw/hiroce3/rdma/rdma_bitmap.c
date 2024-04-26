// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>

#include "rdma_comp.h"
#include "rdma_bitmap.h"

u32 rdma_bitmap_alloc(struct rdma_bitmap *bitmap)
{
	u32 index = 0;

	if (bitmap == NULL) {
		pr_err("%s: Bitmap is null\n", __func__);
		return RDMA_INVALID_INDEX;
	}

	spin_lock(&bitmap->lock);

	index = (u32)find_next_zero_bit(bitmap->table,
		(unsigned long)bitmap->max_num, (unsigned long)bitmap->last);
	if (index >= bitmap->max_num) {
		bitmap->top = (bitmap->top + bitmap->max_num + bitmap->reserved_top) & bitmap->mask;
		index = (u32)find_first_zero_bit(bitmap->table, (unsigned long)bitmap->max_num);
	}

	if (index < bitmap->max_num) {
		set_bit(index, bitmap->table);
		bitmap->last = index + 1;
		if (bitmap->last == bitmap->max_num)
			bitmap->last = 0;

		index |= bitmap->top;
		--bitmap->avail;
	} else {
		pr_err("%s: Get a invalid index\n", __func__);
		spin_unlock(&bitmap->lock);
		return RDMA_INVALID_INDEX;
	}

	spin_unlock(&bitmap->lock);

	return index;
}

void rdma_bitmap_free(struct rdma_bitmap *bitmap, u32 index)
{
	u32 index_tmp = index;

	if (bitmap == NULL) {
		pr_err("%s: Bitmap is null\n", __func__);
		return;
	}

	if (index_tmp >= bitmap->max_num) {
		pr_err("%s: Index(%d) is bigger or equal than max(%d)\n",
			__func__, index_tmp, bitmap->max_num);
		return;
	}

	index_tmp &= bitmap->max_num + bitmap->reserved_top - 1;

	spin_lock(&bitmap->lock);

	bitmap->last = min(bitmap->last, index_tmp);
	bitmap->top = (bitmap->top + bitmap->max_num + bitmap->reserved_top) & bitmap->mask;

	bitmap_clear(bitmap->table, (int)index_tmp, 1);
	++bitmap->avail;
	spin_unlock(&bitmap->lock);
}

int rdma_bitmap_init(struct rdma_bitmap *bitmap, u32 num, u32 mask,
	u32 reserved_bot, u32 reserved_top)
{
	if (bitmap == NULL) {
		pr_err("%s: Bitmap is null\n", __func__);
		return -EINVAL;
	}

	/*lint -e587 */
	if (num != (u32)(ROCE_BITMAP_ROUNDUP_POW_OF_TWO(num) & 0xffffffff)) {
		pr_err("%s: Num(%d) isn't pow of two, err(%d)\n", __func__, num, -EINVAL);
		return -EINVAL;
	}
	/*lint +e587 */

	if (num <= (reserved_bot + reserved_top)) {
		pr_err("%s: Reserved num is bigger than total num, err(%d)\n",
			__func__, -EINVAL);
		return -EINVAL;
	}

	bitmap->last = 0;
	bitmap->top = 0;
	bitmap->max_num = num - reserved_top;
	bitmap->mask = mask;
	bitmap->reserved_top = reserved_top;
	bitmap->avail = (num - reserved_top) - reserved_bot;

	/*lint -e708*/
	spin_lock_init(&bitmap->lock);
	/*lint +e708*/
	bitmap->table = kcalloc(BITS_TO_LONGS(bitmap->max_num), sizeof(long), GFP_KERNEL);
	if (bitmap->table == NULL) {
		bitmap->table = vzalloc((size_t)(BITS_TO_LONGS(bitmap->max_num) * sizeof(long)));
		if (bitmap->table == NULL)
			return -ENOMEM;
	}

	bitmap_set(bitmap->table, 0, (int)reserved_bot);

	return 0;
}

void rdma_bitmap_cleanup(struct rdma_bitmap *bitmap)
{
	if (bitmap == NULL) {
		pr_err("%s: Bitmap is null\n", __func__);
		return;
	}

	if (is_vmalloc_addr(bitmap->table))
		vfree(bitmap->table);
	else
		kfree(bitmap->table);

	bitmap->table = NULL;
}
