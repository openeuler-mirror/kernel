// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "xsc_fw.h"

struct xsc_resources *g_xres[MAX_BOARD_NUM];

static int xsc_alloc_free_list_res(struct xsc_free_list_wl *list, int max_num)
{
	struct xsc_free_list *free_node;

	spin_lock_init(&list->lock);
	INIT_LIST_HEAD(&list->head.list);

	free_node = kmalloc(sizeof(*free_node), GFP_ATOMIC);
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
		kfree(pos);
	}
}

static int xsc_res_iae_init(struct xsc_core_device *dev)
{
	int i = 0;
	int ret = 0;
	struct xsc_resources *res = get_xsc_res(dev);
	struct xsc_alloc_ia_lock_mbox_in in;
	struct xsc_alloc_ia_lock_mbox_out out;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ALLOC_IA_LOCK);
	in.lock_num = XSC_RES_NUM_IAE_GRP;

	ret = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(dev, "failed to alloc ia lock from fw, ret = %d\n", ret);
		return -EINVAL;
	}

	for (i = 0; i < XSC_RES_NUM_IAE_GRP; i++) {
		res->iae_idx[i] = out.lock_idx[i];
		spin_lock_init(&res->iae_lock[i]);
	}

	atomic_set(&res->iae_grp, 0);

	xsc_core_info(dev, "allocated %d iae groups", i);

	return 0;
}

static void xsc_res_iae_release(struct xsc_core_device *dev)
{
	int ret = 0;
	int i = 0;
	struct xsc_resources *res = get_xsc_res(dev);
	struct xsc_release_ia_lock_mbox_in in;
	struct xsc_release_ia_lock_mbox_out out;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_RELEASE_IA_LOCK);
	for (i = 0; i < XSC_RES_NUM_IAE_GRP; i++)
		in.lock_idx[i] = res->iae_idx[i];

	ret = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (ret)
		xsc_core_err(dev, "failed to release ia lock, ret = %d\n", ret);

	return;
}

int xsc_create_res(struct xsc_core_device *dev)
{
	int ret = 0;
	u32 board_id = dev->board_info->board_id;
	struct xsc_resources *xres = get_xsc_res(dev);

	g_xres[board_id] = vmalloc(sizeof(*g_xres[board_id]));
	if (!g_xres[board_id])
		return -ENOMEM;
	xres = g_xres[board_id];

	spin_lock_init(&xres->lock);
	xres->max_mpt_num = xsc_get_max_mpt_num(dev);
	xres->mpt_tbl = kmalloc(xres->max_mpt_num >> 3, GFP_KERNEL);
	if (!xres->mpt_tbl)
		goto err_mpt_tbl;
	memset(xres->mpt_tbl, 0xFF, xres->max_mpt_num >> 3);
	/* reserved for local dma lkey */
	clear_bit(0, (unsigned long *)xres->mpt_tbl);
	xres->mpt_entry = vmalloc(xres->max_mpt_num * sizeof(struct xsc_mpt_info));
	if (!xres->mpt_entry)
		goto err_mpt_entry;

	ret = xsc_res_iae_init(dev);
	if (ret)
		goto err_iae_init;

	xres->max_mtt_num = xsc_get_max_mtt_num(dev);
	ret = xsc_alloc_free_list_res(&xres->mtt_list, xres->max_mtt_num);
	if (ret)
		goto err_mtt;

	return ret;

err_mtt:
	xsc_res_iae_release(dev);
err_iae_init:
	vfree(xres->mpt_entry);
err_mpt_entry:
	kfree(xres->mpt_tbl);
err_mpt_tbl:
	vfree(g_xres[board_id]);
	g_xres[board_id] = NULL;
	return ret;
}

void xsc_destroy_res(struct xsc_core_device *dev)
{
	struct xsc_resources *xres = get_xsc_res(dev);

	xsc_destroy_free_list_res(&xres->mtt_list);
	xsc_res_iae_release(dev);
	vfree(xres->mpt_entry);
	kfree(xres->mpt_tbl);
	vfree(g_xres[dev->board_info->board_id]);
	g_xres[dev->board_info->board_id] = NULL;
}

struct xsc_resources *get_xsc_res(struct xsc_core_device *dev)
{
	return g_xres[dev->board_info->board_id];
}

static int xsc_alloc_res(u32 *res, u8 *res_tbl, u32 max)
{
	u32 bit_num;

	bit_num = find_first_bit((unsigned long *)res_tbl, max);
	if (bit_num == max)
		return -ENOMEM;
	clear_bit(bit_num, (unsigned long *)res_tbl);
	*res = bit_num;
	return 0;
}

static int xsc_dealloc_res(u32 *res, u8 *res_tbl)
{
	if (test_and_set_bit(*res, (unsigned long *)res_tbl))
		return -EINVAL;

	*res = 0;
	return 0;
}

static int alloc_from_free_list(struct xsc_free_list_wl *list, int required, u32 *alloc,
				u32 base_align)
{
	struct xsc_free_list *free_node;
	struct xsc_free_list *next;
	struct xsc_free_list *new_node;

	*alloc = -1;
	list_for_each_entry_safe(free_node, next, &list->head.list, list) {
		int start = round_up(free_node->start, base_align);
		int avail_num = free_node->end - start + 1;

		if (required < avail_num) {
			if (start > free_node->start) {
				new_node = kmalloc(sizeof(*new_node), GFP_ATOMIC);
				if (!new_node)
					return -ENOMEM;
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
				kfree(free_node);
			}
			break;
		}
	}

	if (*alloc == -1)
		return -EINVAL;

	return 0;
}

void save_mtt_to_free_list(struct xsc_core_device *dev, u32 base, u32 num)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	struct list_head *h = &xres->mtt_list.head.list;
	struct xsc_free_list *pos, *new;
	unsigned long flags;

	spin_lock_irqsave(&xres->mtt_list.lock, flags);
	list_for_each_entry(pos, h, list) {
		if (base >= pos->start && base + num - 1 <= pos->end)
			break;
	}

	if (base == pos->start) {
		if (base + num - 1 == pos->end) {
			list_del(&pos->list);
			kfree(pos);
		} else {
			pos->start = base + num;
		}
	} else if (base > pos->start) {
		if (base + num - 1 < pos->end) {
			new = kmalloc(sizeof(*new), GFP_KERNEL);
			if (new) {
				new->start = base + num;
				new->end = pos->end;
				__list_add(&new->list, &pos->list, pos->list.next);
			}
		}
		pos->end = base - 1;
	}
	spin_unlock_irqrestore(&xres->mtt_list.lock, flags);
}

static int release_to_free_list(struct xsc_free_list_wl *list, uint32_t release_base,
				uint32_t num_released)
{
	struct list_head *head = &list->head.list;
	struct xsc_free_list *pos;
	struct xsc_free_list *n;
	struct xsc_free_list *prev;
	struct xsc_free_list *new;
	struct list_head *prev_node, *next_node;

	/* find the position to insert, don't Do merge here */
	list_for_each_entry_safe(pos, n, head, list) {
		if (release_base < pos->start)
			break;
	}

	/* merge */
	if (&pos->list == head) {
		/* list is empty or release_base is great than last node */
		if (!list_empty(head)) {
			prev = list_entry(head->prev, struct xsc_free_list, list);
			/* merge to last node */
			if (prev->end + 1 == release_base) {
				prev->end = release_base + num_released - 1;
				return 0;
			}
			prev_node = head->prev;
			next_node = head;
		} else {
			prev_node = head;
			next_node = head;
		}

		goto create_new_node;
	} else {
		/* release_base is little than first node of free list */
		if (pos->list.prev == head) {
			/* merge to first node */
			if (release_base + num_released == pos->start) {
				pos->start = release_base;
				return 0;
			}

			prev_node = head;
			next_node = &pos->list;
			goto create_new_node;
		} else { /* release pos in the middle of free list */
			prev = list_prev_entry(pos, list);

			if (prev->end + 1 == release_base &&
			    release_base + num_released == pos->start) {
				prev->end = pos->end;
				list_del(&pos->list);
				kfree(pos);

				return 0;
			}
			if (prev->end + 1 == release_base) {
				prev->end = release_base + num_released - 1;
				return 0;
			}

			if (release_base + num_released == pos->start) {
				pos->start = release_base;
				return 0;
			}

			prev_node = &prev->list;
			next_node = &pos->list;
			goto create_new_node;
		}
	}

create_new_node:
	new = kmalloc(sizeof(*new), GFP_ATOMIC);
	if (!new)
		return -ENOMEM;
	new->start = release_base;
	new->end = release_base + num_released - 1;
	__list_add(&new->list, prev_node, next_node);
	return 0;
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
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&xres->mtt_list.lock, flags);
	ret = alloc_from_free_list(&xres->mtt_list, pages_num, mtt_base, 1);
	spin_unlock_irqrestore(&xres->mtt_list.lock, flags);

	xsc_core_dbg(dev, "alloc mtt for %d pages start from %d\n",
		     pages_num, *mtt_base);

	return ret;
}

int dealloc_mtt_entry(struct xsc_core_device *dev, int pages_num, u32 mtt_base)
{
	struct xsc_resources *xres = get_xsc_res(dev);
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&xres->mtt_list.lock, flags);
	ret = release_to_free_list(&xres->mtt_list, mtt_base, pages_num);
	spin_unlock_irqrestore(&xres->mtt_list.lock, flags);

	xsc_core_dbg(dev, "mtt release %d pages start from %d\n",
		     pages_num, mtt_base);

	return ret;
}

