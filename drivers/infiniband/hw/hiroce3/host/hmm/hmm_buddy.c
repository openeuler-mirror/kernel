// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "hinic3_hw.h"
#include "hmm_comp.h"
#include "hmm_buddy.h"


u32 hmm_buddy_alloc(struct hmm_buddy *buddy, u32 order)
{
	u32 first_index = 0;
	u32 cur_order = 0;
	u32 cur_bit_num = 0;

	if (buddy == NULL) {
		pr_err("%s: Buddy is null\n", __func__);
		return HMM_INVALID_INDEX;
	}
	if (order > buddy->max_order) {
		pr_err("%s: Order(%d) is bigger than max order(%d)\n",
			__func__, order, buddy->max_order);
		return HMM_INVALID_INDEX;
	}
	spin_lock(&buddy->lock);

	for (cur_order = order; cur_order <= buddy->max_order; ++cur_order) {
		if (buddy->num_free[cur_order] != 0) {
			cur_bit_num = 1U << (buddy->max_order - cur_order);
			first_index = (u32)find_first_bit(buddy->bits[cur_order],
				(unsigned long)cur_bit_num);
			if (first_index < cur_bit_num)
				goto found;
		}
	}
	spin_unlock(&buddy->lock);
	pr_err("%s: Get a invalid index\n", __func__);
	return HMM_INVALID_INDEX;

found:
	clear_bit((int)first_index, buddy->bits[cur_order]);
	--buddy->num_free[cur_order];

	while (cur_order > order) {
		--cur_order;
		first_index <<= 1;
		set_bit(first_index ^ 1, buddy->bits[cur_order]);
		++buddy->num_free[cur_order];
	}
	first_index <<= order;
	spin_unlock(&buddy->lock);
	return first_index;
}

void hmm_buddy_free(struct hmm_buddy *buddy, u32 first_index, u32 order)
{
	u32 tmp_first_index = first_index;
	u32 tmp_order = order;

	if (buddy == NULL) {
		pr_err("%s: Buddy is null\n", __func__);
		return;
	}
	if (tmp_order > buddy->max_order) {
		pr_err("%s: Order(%d) is bigger than max order(%d)\n",
			__func__, tmp_order, buddy->max_order);
		return;
	}
	tmp_first_index >>= tmp_order;
	spin_lock(&buddy->lock);
	while (test_bit((int)(tmp_first_index ^ 1), buddy->bits[tmp_order]) != 0) {
		clear_bit((int)(tmp_first_index ^ 1), buddy->bits[tmp_order]);
		--buddy->num_free[tmp_order];
		tmp_first_index >>= 1;
		++tmp_order;
	}
	set_bit(tmp_first_index, buddy->bits[tmp_order]);
	++buddy->num_free[tmp_order];
	spin_unlock(&buddy->lock);
}

static void hmm_buddy_alloc_bitmap_fail(struct hmm_buddy *buddy, u32 i)
{
	u32 j = 0;

	for (j = 0; j < i; j++) {
		if (is_vmalloc_addr(buddy->bits[j]))
			vfree(buddy->bits[j]);
		else
			kfree(buddy->bits[j]);
		buddy->bits[j] = NULL;
	}
	kfree(buddy->bits);
	buddy->bits = NULL;
}

int hmm_buddy_init(struct hmm_buddy *buddy, u32 max_order)
{
	u32 i = 0;
	u32 bit_num = 0;

	if (buddy == NULL) {
		pr_err("%s: Buddy is null\n", __func__);
		return -EINVAL;
	}
	buddy->max_order = max_order;
	/*lint -e708*/
	spin_lock_init(&buddy->lock);
	/*lint +e708*/
	buddy->num_free = kcalloc(
		(unsigned long)(buddy->max_order + 1UL), sizeof(int), GFP_KERNEL);
	if (buddy->num_free == NULL)
		return -ENOMEM;
	buddy->bits = kcalloc(
		(unsigned long)(buddy->max_order + 1UL), sizeof(long *), GFP_KERNEL);
	if (buddy->bits == NULL)
		goto alloc_bits_fail;

	for (i = 0; i <= buddy->max_order; i++) {
		bit_num = (u32)BITS_TO_LONGS(1UL << (buddy->max_order - i));
		buddy->bits[i] = kcalloc(
			(unsigned long)bit_num, sizeof(long), GFP_KERNEL | __GFP_NOWARN);
		if (buddy->bits[i] == NULL) {
			buddy->bits[i] = vzalloc((unsigned long)bit_num * sizeof(long));
			if (buddy->bits[i] == NULL)
				goto alloc_bitmap_fail;
		}
	}
	set_bit(0, buddy->bits[buddy->max_order]);
	buddy->num_free[buddy->max_order] = 1;
	return 0;

alloc_bitmap_fail:
	hmm_buddy_alloc_bitmap_fail(buddy, i);
alloc_bits_fail:
	kfree(buddy->num_free);
	buddy->num_free = NULL;
	return -ENOMEM;
}

void hmm_buddy_cleanup(struct hmm_buddy *buddy)
{
	u32 i;

	if (buddy == NULL) {
		pr_err("%s: Buddy is null\n", __func__);
		return;
	}
	for (i = 0; i <= buddy->max_order; i++) {
		if (is_vmalloc_addr(buddy->bits[i]))
			vfree(buddy->bits[i]);
		else
			kfree(buddy->bits[i]);
		buddy->bits[i] = NULL;
	}
	kfree(buddy->bits);
	buddy->bits = NULL;
	kfree(buddy->num_free);
	buddy->num_free = NULL;
}
