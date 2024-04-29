// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_fw.h"

struct xsc_resources g_xres[MAX_BOARD_NUM];

static int xsc_alloc_free_list_res(struct xsc_free_list_wl *list, int max_num)
{
	struct xsc_free_list *free_node;

	xsc_lock_init(&list->lock);
	INIT_LIST_HEAD(&list->head.list);

	free_node = xsc_malloc(sizeof(struct xsc_free_list));
	if (!free_node)
		return -ENOMEM;

	free_node->start = 0;
	free_node->end = free_node->start + max_num - 1;
	list_add(&free_node->list, &list->head.list);

	return 0;
}

static void xsc_destroy_free_list_res(struct xsc_free_list_wl *list)
{
	struct xsc_free_list *pos;
	struct xsc_free_list *next;

	list_for_each_entry_safe(pos, next, &list->head.list, list) {
		list_del(&pos->list);
		xsc_free(pos);
	}
}

static int xsc_alloc_msix_res_tbl(unsigned long **res_tbl, u32 max)
{
	u32 bytes;

	bytes = max >> 3;
	if (!bytes)
		bytes = 1;
	*res_tbl = kmalloc(bytes, GFP_KERNEL);
	if (!*res_tbl)
		return -ENOMEM;
	memset((u8 *)(*res_tbl), 0xFF, bytes);
	return 0;
}

static void xsc_free_msix_res_tbl(unsigned long **res)
{
	if (*res)
		kfree(*res);
	*res = 0;
}

int xsc_alloc_continuous_msix_vec(struct xsc_core_device *dev, u16 vec_num)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	int i, j, start, end;
	int vec_base = 0;
	int avail_vec = 0;

	start = xres->msix_vec_base;
	end = xres->msix_vec_end;

	vec_base = -1;
	for (i = start; i <= end; i++) {
		if (test_bit(i, xres->msix_vec_tbl)) {
			avail_vec++;
			if (vec_base == -1)
				vec_base = i;
		} else {
			avail_vec = 0;
			vec_base = -1;
		}

		if (avail_vec == vec_num) {
			for (j = 0; j < vec_num; j++)
				clear_bit(vec_base + j, xres->msix_vec_tbl);

			dev->msix_vec_base = vec_base;
			return 0;
		}
	}
	xsc_core_warn(dev,
		      "failed to alloc msix vec, vec_range=%d~%d, vec_num=%d\n",
		      start, end, vec_num);
	return -EINVAL;
}

int xsc_free_continuous_msix_vec(struct xsc_core_device *dev)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	struct xsc_eq_table *table = &dev->dev_res->eq_table;
	u32 vec_base, vec_num;
	int i, start, end;

	vec_base = dev->msix_vec_base;
	vec_num = table->num_comp_vectors + table->eq_vec_comp_base;

	start = xres->msix_vec_base;
	end = xres->msix_vec_end;

	if (vec_base < start || vec_base > end ||
	    (vec_base + vec_num - 1) > end) {
		xsc_core_warn(dev,
			      "failed to free msix vec, vec_base=%d, vec_num=%d, range=%d~%d\n",
			      vec_base, vec_num, start, end);
		return -EINVAL;
	}

	for (i = 0; i < vec_num; i++)
		set_bit(vec_base + i, xres->msix_vec_tbl);

	return 0;
}

int xsc_create_res(struct xsc_core_device *dev)
{
	int ret = 0;
	struct xsc_resources *xres = get_xsc_res(dev);

	xres->refcnt++;
	if (xres->refcnt > 1)
		return 0;

	xsc_lock_init(&xres->lock);
	xres->max_mpt_num = XSC_MAX_MPT_NUM;
	memset(xres->mpt_tbl, 0xFF, XSC_MAX_MPT_NUM >> 3);
	/* reserved for local dma lkey */
	clear_bit(0, (unsigned long *)xres->mpt_tbl);

	ret = xsc_alloc_iae_idx(dev, &xres->iae_idx);
	if (ret)
		return -EINVAL;

	xres->msix_max_num = 1 << dev->caps.log_max_msix;
	xres->msix_vec_base = 0;
	xres->msix_vec_end = (xres->msix_max_num - 1);
	ret = xsc_alloc_msix_res_tbl(&xres->msix_vec_tbl, xres->msix_max_num);
	if (ret)
		goto err_msix;

	xres->max_mtt_num = XSC_MAX_MTT_NUM;
	ret = xsc_alloc_free_list_res(&xres->mtt_list, xres->max_mtt_num);
	if (ret)
		goto err_mtt;

	return ret;

err_mtt:
	xsc_free_msix_res_tbl(&xres->msix_vec_tbl);
err_msix:
	xsc_release_iae_idx(dev, &xres->iae_idx);
	return ret;
}

void xsc_destroy_res(struct xsc_core_device *dev)
{
	struct xsc_resources *xres = get_xsc_res(dev);

	xres->refcnt--;
	if (xres->refcnt)
		return;

	xsc_destroy_free_list_res(&xres->mtt_list);
	xsc_free_msix_res_tbl(&xres->msix_vec_tbl);
	xsc_release_iae_idx(dev, &xres->iae_idx);
}

struct xsc_resources *get_xsc_res(struct xsc_core_device *dev)
{
	return &g_xres[dev->board_id];
}

int xsc_alloc_res(u32 *res, u64 *res_tbl, u32 max)
{
	u32 bit_num;

	bit_num = find_first_bit((unsigned long *)res_tbl, max);
	if (bit_num == max)
		return -ENOMEM;
	clear_bit(bit_num, (unsigned long *)res_tbl);
	*res = bit_num;
	return 0;
}

int xsc_dealloc_res(u32 *res, u64 *res_tbl)
{
	if (test_and_set_bit(*res, (unsigned long *)res_tbl))
		return -EINVAL;

	*res = 0;
	return 0;
}

int alloc_from_free_list(struct xsc_free_list_wl *list, int required, u32 *alloc,
			 u32 base_align)
{
	struct xsc_free_list *free_node;
	struct xsc_free_list *next;
	struct xsc_free_list *new_node;
	unsigned long flags;

	*alloc = -1;
	xsc_acquire_lock(&list->lock, &flags);
	list_for_each_entry_safe(free_node, next, &list->head.list, list) {
		int start = round_up(free_node->start, base_align);
		int avail_num = free_node->end - start + 1;

		if (required < avail_num) {
			if (start > free_node->start) {
				new_node = xsc_malloc(sizeof(struct xsc_free_list));
				if (!new_node) {
					xsc_release_lock(&list->lock, flags);
					return -ENOMEM;
				}
				new_node->start = free_node->start;
				new_node->end = start - 1;
				__list_add(&new_node->list, free_node->list.prev,
					   &free_node->list);
			}
			*alloc = start;
			free_node->start = start + required;
			break;
		} else if (required == avail_num) {
			*alloc = start;
			if (start > free_node->start) {
				free_node->end = start - 1;
			} else {
				list_del(&free_node->list);
				xsc_free(free_node);
			}
			break;
		}
	}
	xsc_release_lock(&list->lock, flags);

	if (*alloc == -1)
		return -EINVAL;

	return 0;
}

int release_to_free_list(struct xsc_free_list_wl *list, uint32_t release,
			 uint32_t num_released)
{
	struct xsc_free_list *free_node = NULL;
	struct xsc_free_list *next, *prev;
	struct xsc_free_list *new_node;
	unsigned long flags;
	bool new_flag = false;
	bool end_merge = false;
	int ret = 0;

	xsc_acquire_lock(&list->lock, &flags);
	list_for_each_entry_safe(free_node, next, &list->head.list, list) {
		if (release + num_released < free_node->start) {
			new_flag = true;
		} else if (release + num_released == free_node->start) {
			/* backward merge */
			end_merge = true;
			free_node->start = release;
		}

		if (new_flag || end_merge) {
			/* forward merge, and backward merge if possible */
			if (free_node->list.prev == &list->head.list)
				goto create_node;

			prev = list_entry(free_node->list.prev, struct xsc_free_list, list);
			if (release == prev->end + 1) {
				if (end_merge) {
					prev->end = free_node->end;
					list_del(&free_node->list);
					xsc_free(free_node);
					free_node = NULL;
				} else {
					prev->end = release + num_released - 1;
					new_flag = false;
				}
			}

			break;
		}
	}

	if (list_empty(&list->head.list)) {
		new_flag = true;
		free_node = &list->head;
	}

create_node:
	if (new_flag && free_node) {
		new_node = xsc_malloc(sizeof(struct xsc_free_list));
		if (!new_node) {
			ret = -ENOMEM;
			goto ret;
		}
		new_node->start = release;
		new_node->end = release + num_released - 1;
		__list_add(&new_node->list, free_node->list.prev,
			   &free_node->list);
	}
ret:
	xsc_release_lock(&list->lock, flags);
	return ret;
}

int alloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx)
{
	struct xsc_resources *xres = get_xsc_res(dev);

	if (xsc_alloc_res(mpt_idx, xres->mpt_tbl, xres->max_mpt_num))
		return -EINVAL;

	return 0;
}

int dealloc_mpt_entry(struct xsc_core_device *dev, u32 *mpt_idx)
{
	struct xsc_resources *xres = get_xsc_res(dev);

	if (xsc_dealloc_res(mpt_idx, xres->mpt_tbl))
		return -EINVAL;

	return 0;
}

int alloc_mtt_entry(struct xsc_core_device *dev, u32 pages_num, u32 *mtt_base)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	int ret = alloc_from_free_list(&xres->mtt_list, pages_num, mtt_base, 1);

	xsc_core_dbg(dev, "alloc mtt for %d pages start from %d\n",
		     pages_num, *mtt_base);

	return ret;
}

int dealloc_mtt_entry(struct xsc_core_device *dev, int pages_num, u32 mtt_base)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	int ret = release_to_free_list(&xres->mtt_list, mtt_base, pages_num);

	xsc_core_dbg(dev, "mtt release %d pages start from %d\n",
		     pages_num, mtt_base);

	return ret;
}

