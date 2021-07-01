/*
 * Copyright (c) 2016 Hisilicon Limited.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "roce_k_compat.h"

#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <rdma/ib_umem.h>
#include "hns_roce_device.h"
#include "hns_roce_cmd.h"
#include "hns_roce_hem.h"

u32 hw_index_to_key(unsigned long ind)
{
	return (u32)(ind >> 24) | (ind << 8);
}
EXPORT_SYMBOL_GPL(hw_index_to_key);

unsigned long key_to_hw_index(u32 key)
{
	return (key << 24) | (key >> 8);
}
EXPORT_SYMBOL_GPL(key_to_hw_index);

static int hns_roce_hw_create_mpt(struct hns_roce_dev *hr_dev,
				  struct hns_roce_cmd_mailbox *mailbox,
				  unsigned long mpt_index)
{
	return hns_roce_cmd_mbox(hr_dev, mailbox->dma, 0, mpt_index, 0,
				 HNS_ROCE_CMD_CREATE_MPT,
				 HNS_ROCE_CMD_TIMEOUT_MSECS);
}

int hns_roce_hw_destroy_mpt(struct hns_roce_dev *hr_dev,
			    struct hns_roce_cmd_mailbox *mailbox,
			    unsigned long mpt_index)
{
	return hns_roce_cmd_mbox(hr_dev, 0, mailbox ? mailbox->dma : 0,
				 mpt_index, !mailbox, HNS_ROCE_CMD_DESTROY_MPT,
				 HNS_ROCE_CMD_TIMEOUT_MSECS);
}
EXPORT_SYMBOL_GPL(hns_roce_hw_destroy_mpt);

static int hns_roce_buddy_alloc(struct hns_roce_buddy *buddy, int order,
				unsigned long *seg)
{
	int o;
	u32 m;

	spin_lock(&buddy->lock);

	for (o = order; o <= buddy->max_order; ++o) {
		if (buddy->num_free[o]) {
			m = 1 << (buddy->max_order - o);
			*seg = find_first_bit(buddy->bits[o], m);
			if (*seg < m)
				goto found;
		}
	}
	spin_unlock(&buddy->lock);
	return -1;

 found:
	clear_bit(*seg, buddy->bits[o]);
	--buddy->num_free[o];

	while (o > order) {
		--o;
		*seg <<= 1;
		set_bit(*seg ^ 1, buddy->bits[o]);
		++buddy->num_free[o];
	}

	spin_unlock(&buddy->lock);

	*seg <<= order;
	return 0;
}

static void hns_roce_buddy_free(struct hns_roce_buddy *buddy, unsigned long seg,
				int order)
{
	seg >>= order;

	spin_lock(&buddy->lock);

	while (test_bit(seg ^ 1, buddy->bits[order])) {
		clear_bit(seg ^ 1, buddy->bits[order]);
		--buddy->num_free[order];
		seg >>= 1;
		++order;
	}

	set_bit(seg, buddy->bits[order]);
	++buddy->num_free[order];

	spin_unlock(&buddy->lock);
}

static int hns_roce_buddy_init(struct hns_roce_buddy *buddy, int max_order)
{
	int i, s;

	buddy->max_order = max_order;
	spin_lock_init(&buddy->lock);
	buddy->bits = kcalloc(buddy->max_order + 1,
			      sizeof(*buddy->bits),
			      GFP_KERNEL);
	buddy->num_free = kcalloc(buddy->max_order + 1,
				  sizeof(*buddy->num_free),
				  GFP_KERNEL);
	if (!buddy->bits || !buddy->num_free)
		goto err_out;

	for (i = 0; i <= buddy->max_order; ++i) {
		s = BITS_TO_LONGS(1 << (buddy->max_order - i));
		buddy->bits[i] = kcalloc(s, sizeof(long), GFP_KERNEL |
					 __GFP_NOWARN);
		if (!buddy->bits[i]) {
			buddy->bits[i] = vzalloc(array_size(s, sizeof(long)));
			if (!buddy->bits[i])
				goto err_out_free;
		}
	}

	set_bit(0, buddy->bits[buddy->max_order]);
	buddy->num_free[buddy->max_order] = 1;

	return 0;

err_out_free:
	for (i = 0; i <= buddy->max_order; ++i)
		kvfree(buddy->bits[i]);

err_out:
	kfree(buddy->bits);
	kfree(buddy->num_free);
	return -ENOMEM;
}

static void hns_roce_buddy_cleanup(struct hns_roce_buddy *buddy)
{
	int i;

	for (i = 0; i <= buddy->max_order; ++i)
		kvfree(buddy->bits[i]);

	kfree(buddy->bits);
	kfree(buddy->num_free);
}

static int hns_roce_alloc_mtt_range(struct hns_roce_dev *hr_dev, int order,
				    unsigned long *seg, u32 mtt_type)
{
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;
	struct hns_roce_hem_table *table;
	struct hns_roce_buddy *buddy;
	int ret;

	switch (mtt_type) {
	case MTT_TYPE_WQE:
		buddy = &mr_table->mtt_buddy;
		table = &mr_table->mtt_table;
		break;
	case MTT_TYPE_CQE:
		buddy = &mr_table->mtt_cqe_buddy;
		table = &mr_table->mtt_cqe_table;
		break;
	case MTT_TYPE_SRQWQE:
		buddy = &mr_table->mtt_srqwqe_buddy;
		table = &mr_table->mtt_srqwqe_table;
		break;
	case MTT_TYPE_IDX:
		buddy = &mr_table->mtt_idx_buddy;
		table = &mr_table->mtt_idx_table;
		break;
	default:
		dev_err(hr_dev->dev, "Unsupport MTT table type: %d\n",
			mtt_type);
		return -EINVAL;
	}

	ret = hns_roce_buddy_alloc(buddy, order, seg);
	if (ret == -1)
		return -1;

	if (hns_roce_table_get_range(hr_dev, table, *seg,
				     *seg + (1 << order) - 1)) {
		hns_roce_buddy_free(buddy, *seg, order);
		return -1;
	}

	return 0;
}

int hns_roce_mtt_init(struct hns_roce_dev *hr_dev, int npages, int page_shift,
		      struct hns_roce_mtt *mtt)
{
	int ret;
	int i;

	/* Page num is zero, correspond to DMA memory register */
	if (!npages) {
		mtt->order = -1;
		mtt->page_shift = HNS_ROCE_HEM_PAGE_SHIFT;
		return 0;
	}

	/* Note: if page_shift is zero, FAST memory register */
	mtt->page_shift = page_shift;

	/* Compute MTT entry necessary */
	for (mtt->order = 0, i = HNS_ROCE_MTT_ENTRY_PER_SEG; i < npages;
	     i <<= 1)
		++mtt->order;

	/* Allocate MTT entry */
	ret = hns_roce_alloc_mtt_range(hr_dev, mtt->order, &mtt->first_seg,
				       mtt->mtt_type);
	if (ret != 0)
		return -ENOMEM;

	return 0;
}

void hns_roce_mtt_cleanup(struct hns_roce_dev *hr_dev, struct hns_roce_mtt *mtt)
{
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;

	if (mtt->order < 0)
		return;

	switch (mtt->mtt_type) {
	case MTT_TYPE_WQE:
		hns_roce_buddy_free(&mr_table->mtt_buddy, mtt->first_seg,
				    mtt->order);
		hns_roce_table_put_range(hr_dev, &mr_table->mtt_table,
					mtt->first_seg,
					mtt->first_seg + (1 << mtt->order) - 1);
		break;
	case MTT_TYPE_CQE:
		hns_roce_buddy_free(&mr_table->mtt_cqe_buddy, mtt->first_seg,
				    mtt->order);
		hns_roce_table_put_range(hr_dev, &mr_table->mtt_cqe_table,
					mtt->first_seg,
					mtt->first_seg + (1 << mtt->order) - 1);
		break;
	case MTT_TYPE_SRQWQE:
		hns_roce_buddy_free(&mr_table->mtt_srqwqe_buddy, mtt->first_seg,
				    mtt->order);
		hns_roce_table_put_range(hr_dev, &mr_table->mtt_srqwqe_table,
					mtt->first_seg,
					mtt->first_seg + (1 << mtt->order) - 1);
		break;
	case MTT_TYPE_IDX:
		hns_roce_buddy_free(&mr_table->mtt_idx_buddy, mtt->first_seg,
				    mtt->order);
		hns_roce_table_put_range(hr_dev, &mr_table->mtt_idx_table,
					mtt->first_seg,
					mtt->first_seg + (1 << mtt->order) - 1);
		break;
	default:
		dev_err(hr_dev->dev,
			"Unsupport mtt type %d, clean mtt failed\n",
			mtt->mtt_type);
		break;
	}
}
EXPORT_SYMBOL_GPL(hns_roce_mtt_cleanup);

static void hns_roce_loop_free(struct hns_roce_dev *hr_dev,
			       struct hns_roce_mr *mr, int err_loop_index,
			       int loop_i, int loop_j)
{
	struct device *dev = hr_dev->dev;
	u32 mhop_num;
	u32 pbl_bt_sz;
	u64 bt_idx;
	int i, j;

	pbl_bt_sz = 1 << (hr_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT);
	mhop_num = hr_dev->caps.pbl_hop_num;

	i = loop_i;
	if (mhop_num == 3 && err_loop_index == 2) {
		for (; i >= 0; i--) {
			dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l1[i],
					  mr->pbl_l1_dma_addr[i]);

			for (j = 0; j < pbl_bt_sz / BA_BYTE_LEN; j++) {
				if (i == loop_i && j >= loop_j)
					break;

				bt_idx = i * (pbl_bt_sz / BA_BYTE_LEN) + j;
				dma_free_coherent(dev, pbl_bt_sz,
						  mr->pbl_bt_l2[bt_idx],
						  mr->pbl_l2_dma_addr[bt_idx]);
			}
		}
	} else if (mhop_num == 3 && err_loop_index == 1) {
		for (i -= 1; i >= 0; i--) {
			dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l1[i],
					  mr->pbl_l1_dma_addr[i]);

			for (j = 0; j < pbl_bt_sz / BA_BYTE_LEN; j++) {
				bt_idx = i * (pbl_bt_sz / BA_BYTE_LEN) + j;
				dma_free_coherent(dev, pbl_bt_sz,
						  mr->pbl_bt_l2[bt_idx],
						  mr->pbl_l2_dma_addr[bt_idx]);
			}
		}
	} else if (mhop_num == 2 && err_loop_index == 1) {
		for (i -= 1; i >= 0; i--)
			dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l1[i],
					  mr->pbl_l1_dma_addr[i]);
	} else {
		dev_warn(dev, "not support: mhop_num=%d, err_loop_index=%d.",
			 mhop_num, err_loop_index);
		return;
	}

	dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l0, mr->pbl_l0_dma_addr);
	mr->pbl_bt_l0 = NULL;
	mr->pbl_l0_dma_addr = 0;
}
static int pbl_1hop_alloc(struct hns_roce_dev *hr_dev, int npages,
			       struct hns_roce_mr *mr, u32 pbl_bt_sz)
{
	struct device *dev = hr_dev->dev;

	if (npages > pbl_bt_sz / BA_BYTE_LEN) {
		dev_err(dev, "Npages %d is larger than buf_pg_sz!", npages);
		return -EINVAL;
	}
	mr->pbl_buf = dma_alloc_coherent(dev, npages * BA_BYTE_LEN,
					 &(mr->pbl_dma_addr),
					 GFP_KERNEL);
	if (!mr->pbl_buf)
		return -ENOMEM;

	mr->pbl_size = npages;
	mr->pbl_ba = mr->pbl_dma_addr;
	mr->pbl_hop_num = 1;
	mr->pbl_ba_pg_sz = hr_dev->caps.pbl_ba_pg_sz;
	mr->pbl_buf_pg_sz = hr_dev->caps.pbl_buf_pg_sz;
	return 0;

}


static int pbl_2hop_alloc(struct hns_roce_dev *hr_dev, int npages,
			       struct hns_roce_mr *mr, u32 pbl_bt_sz)
{
	struct device *dev = hr_dev->dev;
	int npages_alloced;
	u64 pbl_last_bt_num;
	u64 pbl_bt_cnt = 0;
	u64 size;
	int i;

	pbl_last_bt_num = DIV_ROUND_UP(npages, pbl_bt_sz / BA_BYTE_LEN);

	/* alloc L1 BT */
	for (i = 0; i < pbl_bt_sz / BA_BYTE_LEN; i++) {
		if (pbl_bt_cnt + 1 < pbl_last_bt_num) {
			size = pbl_bt_sz;
		} else {
			npages_alloced = i * (pbl_bt_sz / BA_BYTE_LEN);
			size = (npages - npages_alloced) * BA_BYTE_LEN;
		}
		mr->pbl_bt_l1[i] = dma_alloc_coherent(dev, size,
					    &(mr->pbl_l1_dma_addr[i]),
					    GFP_KERNEL);
		if (!mr->pbl_bt_l1[i]) {
			hns_roce_loop_free(hr_dev, mr, 1, i, 0);
			return -ENOMEM;
		}

		*(mr->pbl_bt_l0 + i) = mr->pbl_l1_dma_addr[i];

		pbl_bt_cnt++;
		if (pbl_bt_cnt >= pbl_last_bt_num)
			break;
	}

	mr->l0_chunk_last_num = i + 1;

	return 0;
}

static int pbl_3hop_alloc(struct hns_roce_dev *hr_dev, int npages,
			       struct hns_roce_mr *mr, u32 pbl_bt_sz)
{
	struct device *dev = hr_dev->dev;
	int mr_alloc_done = 0;
	int npages_alloced;
	u64 pbl_last_bt_num;
	u64 pbl_bt_cnt = 0;
	u64 bt_idx;
	u64 size;
	int i;
	int j = 0;

	pbl_last_bt_num = DIV_ROUND_UP(npages, pbl_bt_sz / BA_BYTE_LEN);

	mr->pbl_l2_dma_addr = kcalloc(pbl_last_bt_num,
				      sizeof(*mr->pbl_l2_dma_addr),
				      GFP_KERNEL);
	if (!mr->pbl_l2_dma_addr)
		return -ENOMEM;

	mr->pbl_bt_l2 = kcalloc(pbl_last_bt_num,
				sizeof(*mr->pbl_bt_l2),
				GFP_KERNEL);
	if (!mr->pbl_bt_l2)
		goto err_kcalloc_bt_l2;

	/* alloc L1, L2 BT */
	for (i = 0; i < pbl_bt_sz / BA_BYTE_LEN; i++) {
		mr->pbl_bt_l1[i] = dma_alloc_coherent(dev, pbl_bt_sz,
					    &(mr->pbl_l1_dma_addr[i]),
					    GFP_KERNEL);
		if (!mr->pbl_bt_l1[i]) {
			hns_roce_loop_free(hr_dev, mr, 1, i, 0);
			goto err_dma_alloc_l0;
		}

		*(mr->pbl_bt_l0 + i) = mr->pbl_l1_dma_addr[i];

		for (j = 0; j < pbl_bt_sz / BA_BYTE_LEN; j++) {
			bt_idx = i * (pbl_bt_sz / BA_BYTE_LEN) + j;

			if (pbl_bt_cnt + 1 < pbl_last_bt_num) {
				size = pbl_bt_sz;
			} else {
				npages_alloced = bt_idx *
						 (pbl_bt_sz / BA_BYTE_LEN);
			       size = (npages - npages_alloced) * BA_BYTE_LEN;
			}
			mr->pbl_bt_l2[bt_idx] = dma_alloc_coherent(
				      dev, size,
				      &(mr->pbl_l2_dma_addr[bt_idx]),
				      GFP_KERNEL);
			if (!mr->pbl_bt_l2[bt_idx]) {
				hns_roce_loop_free(hr_dev, mr, 2, i, j);
				goto err_dma_alloc_l0;
			}

			*(mr->pbl_bt_l1[i] + j) =
					mr->pbl_l2_dma_addr[bt_idx];

			pbl_bt_cnt++;
			if (pbl_bt_cnt >= pbl_last_bt_num) {
				mr_alloc_done = 1;
				break;
			}
		}

		if (mr_alloc_done)
			break;
	}

	mr->l0_chunk_last_num = i + 1;
	mr->l1_chunk_last_num = j + 1;


	return 0;

err_dma_alloc_l0:
	kfree(mr->pbl_bt_l2);
	mr->pbl_bt_l2 = NULL;

err_kcalloc_bt_l2:
	kfree(mr->pbl_l2_dma_addr);
	mr->pbl_l2_dma_addr = NULL;

	return -ENOMEM;
}


/* PBL multi hop addressing */
static int hns_roce_mhop_alloc(struct hns_roce_dev *hr_dev, int npages,
			       struct hns_roce_mr *mr)
{
	struct device *dev = hr_dev->dev;
	u32 pbl_bt_sz;
	u32 mhop_num;

	mhop_num = (mr->type == MR_TYPE_FRMR ? 1 : hr_dev->caps.pbl_hop_num);
	pbl_bt_sz = 1 << (hr_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT);

	if (mhop_num == HNS_ROCE_HOP_NUM_0)
		return 0;

	if (mhop_num == 1)
		return pbl_1hop_alloc(hr_dev, npages, mr, pbl_bt_sz);

	mr->pbl_l1_dma_addr = kcalloc(pbl_bt_sz / BA_BYTE_LEN,
				      sizeof(*mr->pbl_l1_dma_addr),
				      GFP_KERNEL);
	if (!mr->pbl_l1_dma_addr)
		return -ENOMEM;

	mr->pbl_bt_l1 = kcalloc(pbl_bt_sz / BA_BYTE_LEN, sizeof(*mr->pbl_bt_l1),
				GFP_KERNEL);
	if (!mr->pbl_bt_l1)
		goto err_kcalloc_bt_l1;

	/* alloc L0 BT */
	mr->pbl_bt_l0 = dma_alloc_coherent(dev, pbl_bt_sz,
					   &(mr->pbl_l0_dma_addr),
					   GFP_KERNEL);
	if (!mr->pbl_bt_l0)
		goto err_kcalloc_l2_dma;

	if (mhop_num == 2) {
		if (pbl_2hop_alloc(hr_dev, npages, mr, pbl_bt_sz))
			goto err_kcalloc_l2_dma;
	}

	if (mhop_num == 3) {
		if (pbl_3hop_alloc(hr_dev, npages, mr, pbl_bt_sz))
			goto err_kcalloc_l2_dma;
	}

	mr->pbl_size = npages;
	mr->pbl_ba = mr->pbl_l0_dma_addr;
	mr->pbl_hop_num = hr_dev->caps.pbl_hop_num;
	mr->pbl_ba_pg_sz = hr_dev->caps.pbl_ba_pg_sz;
	mr->pbl_buf_pg_sz = hr_dev->caps.pbl_buf_pg_sz;

	return 0;

err_kcalloc_l2_dma:
	kfree(mr->pbl_bt_l1);
	mr->pbl_bt_l1 = NULL;

err_kcalloc_bt_l1:
	kfree(mr->pbl_l1_dma_addr);
	mr->pbl_l1_dma_addr = NULL;

	return -ENOMEM;
}

int hns_roce_mr_alloc(struct hns_roce_dev *hr_dev, u32 pd, u64 iova,
			     u64 size, u32 access, int npages,
			     struct hns_roce_mr *mr)
{
	struct device *dev = hr_dev->dev;
	unsigned long index = 0;
	int ret;

	/* Allocate a key for mr from mr_table */
	ret = hns_roce_bitmap_alloc(&hr_dev->mr_table.mtpt_bitmap, &index);
	if (ret == -1)
		return -ENOMEM;

	mr->iova = iova;			/* MR va starting addr */
	mr->size = size;			/* MR addr range */
	mr->pd = pd;				/* MR num */
	mr->access = access;			/* MR access permit */
	mr->enabled = 0;			/* MR active status */
	mr->key = hw_index_to_key(index);	/* MR key */

	if (size == ~0ull) {
		mr->pbl_buf = NULL;
		mr->pbl_dma_addr = 0;
		/* PBL multi-hop addressing parameters */
		mr->pbl_bt_l2 = NULL;
		mr->pbl_bt_l1 = NULL;
		mr->pbl_bt_l0 = NULL;
		mr->pbl_l2_dma_addr = NULL;
		mr->pbl_l1_dma_addr = NULL;
		mr->pbl_l0_dma_addr = 0;
	} else {
		if (!hr_dev->caps.pbl_hop_num) {
			mr->pbl_buf = dma_alloc_coherent(dev,
							 npages * BA_BYTE_LEN,
							 &(mr->pbl_dma_addr),
							 GFP_KERNEL);
			if (!mr->pbl_buf)
				return -ENOMEM;
		} else {
			ret = hns_roce_mhop_alloc(hr_dev, npages, mr);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(hns_roce_mr_alloc);

static void hns_roce_mhop_free(struct hns_roce_dev *hr_dev,
			       struct hns_roce_mr *mr)
{
	struct device *dev = hr_dev->dev;
	int npages_alloced;
	int npages;
	int i, j;
	u32 pbl_bt_sz;
	u32 mhop_num;
	u64 bt_idx;

	npages = mr->pbl_size;
	pbl_bt_sz = 1 << (hr_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT);
	mhop_num = (mr->type == MR_TYPE_FRMR) ? 1 : hr_dev->caps.pbl_hop_num;

	if (mhop_num == HNS_ROCE_HOP_NUM_0)
		return;

	if (mhop_num == 1) {
		dma_free_coherent(dev, (unsigned int)(npages * BA_BYTE_LEN),
				  mr->pbl_buf, mr->pbl_dma_addr);
		return;
	}

	dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l0,
			  mr->pbl_l0_dma_addr);

	if (mhop_num == 2) {
		for (i = 0; i < mr->l0_chunk_last_num; i++) {
			if (i == mr->l0_chunk_last_num - 1) {
				npages_alloced = i * (pbl_bt_sz / BA_BYTE_LEN);

				dma_free_coherent(dev,
					(npages - npages_alloced) * BA_BYTE_LEN,
				      mr->pbl_bt_l1[i], mr->pbl_l1_dma_addr[i]);

				break;
			}

			dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l1[i],
					  mr->pbl_l1_dma_addr[i]);
		}
	} else if (mhop_num == 3) {
		for (i = 0; i < mr->l0_chunk_last_num; i++) {
			dma_free_coherent(dev, pbl_bt_sz, mr->pbl_bt_l1[i],
					  mr->pbl_l1_dma_addr[i]);

			for (j = 0; j < pbl_bt_sz / BA_BYTE_LEN; j++) {
				bt_idx = i * (pbl_bt_sz / BA_BYTE_LEN) + j;

				if ((i == mr->l0_chunk_last_num - 1)
				    && j == mr->l1_chunk_last_num - 1) {
					npages_alloced = bt_idx *
						      (pbl_bt_sz / BA_BYTE_LEN);

					dma_free_coherent(dev,
					(npages - npages_alloced) * BA_BYTE_LEN,
					      mr->pbl_bt_l2[bt_idx],
					      mr->pbl_l2_dma_addr[bt_idx]);

					break;
				}

				dma_free_coherent(dev, pbl_bt_sz,
						mr->pbl_bt_l2[bt_idx],
						mr->pbl_l2_dma_addr[bt_idx]);
			}
		}
	}

	kfree(mr->pbl_bt_l1);
	kfree(mr->pbl_l1_dma_addr);
	mr->pbl_bt_l1 = NULL;
	mr->pbl_l1_dma_addr = NULL;
	if (mhop_num == 3) {
		kfree(mr->pbl_bt_l2);
		kfree(mr->pbl_l2_dma_addr);
		mr->pbl_bt_l2 = NULL;
		mr->pbl_l2_dma_addr = NULL;
	}
}

void hns_roce_mr_free(struct hns_roce_dev *hr_dev,
			     struct hns_roce_mr *mr)
{
	struct device *dev = hr_dev->dev;
	int npages = 0;
	int ret;

	if (mr->enabled) {
		ret = hns_roce_hw_destroy_mpt(hr_dev, NULL,
					      key_to_hw_index(mr->key) &
					      (hr_dev->caps.num_mtpts - 1));
		if (ret)
			dev_warn(dev, "DESTROY_MPT failed (%d)\n", ret);
	}

	if (mr->size != ~0ULL) {
		if (mr->type == MR_TYPE_MR)
			npages = ib_umem_page_count(mr->umem);

		if (!hr_dev->caps.pbl_hop_num)
			dma_free_coherent(dev,
					  (unsigned int)(npages * BA_BYTE_LEN),
					  mr->pbl_buf, mr->pbl_dma_addr);
		else
			hns_roce_mhop_free(hr_dev, mr);
	}

	if (mr->enabled)
		hns_roce_table_put(hr_dev, &hr_dev->mr_table.mtpt_table,
				   key_to_hw_index(mr->key));

	hns_roce_bitmap_free(&hr_dev->mr_table.mtpt_bitmap,
			     key_to_hw_index(mr->key), BITMAP_NO_RR);
}
EXPORT_SYMBOL_GPL(hns_roce_mr_free);

int hns_roce_mr_enable(struct hns_roce_dev *hr_dev,
			      struct hns_roce_mr *mr)
{
	int ret;
	unsigned long mtpt_idx = key_to_hw_index(mr->key);
	struct device *dev = hr_dev->dev;
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;

	/* Prepare HEM entry memory */
	ret = hns_roce_table_get(hr_dev, &mr_table->mtpt_table, mtpt_idx);
	if (ret) {
		dev_err(dev, "Get mtpt table(0x%lx) failed(%d).",
			mtpt_idx, ret);
		return ret;
	}
	/* Allocate mailbox memory */
	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox)) {
		ret = PTR_ERR(mailbox);
		goto err_table;
	}

	if (mr->type != MR_TYPE_FRMR)
		ret = hr_dev->hw->write_mtpt(mailbox->buf, mr, mtpt_idx);
	else
		ret = hr_dev->hw->frmr_write_mtpt(mailbox->buf, mr);
	if (ret) {
		dev_err(dev, "Write mtpt fail(%d)!\n", ret);
		goto err_page;
	}

	ret = hns_roce_hw_create_mpt(hr_dev, mailbox,
				     mtpt_idx & (hr_dev->caps.num_mtpts - 1));
	if (ret) {
		dev_err(dev, "CREATE_MPT(0x%lx) failed(%d) for mr_enable.\n",
			mtpt_idx, ret);
		goto err_page;
	}

	mr->enabled = 1;
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return 0;

err_page:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

err_table:
	hns_roce_table_put(hr_dev, &mr_table->mtpt_table, mtpt_idx);
	return ret;
}
EXPORT_SYMBOL_GPL(hns_roce_mr_enable);

static int hns_roce_write_mtt_chunk(struct hns_roce_dev *hr_dev,
				    struct hns_roce_mtt *mtt, u32 start_index,
				    u32 npages, u64 *page_list)
{
	struct hns_roce_hem_table *table;
	dma_addr_t dma_handle;
	__le64 *mtts;
	u32 bt_page_size;
	u32 i;

	switch (mtt->mtt_type) {
	case MTT_TYPE_WQE:
		table = &hr_dev->mr_table.mtt_table;
		bt_page_size = 1 << (hr_dev->caps.mtt_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_CQE:
		table = &hr_dev->mr_table.mtt_cqe_table;
		bt_page_size = 1 << (hr_dev->caps.cqe_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_SRQWQE:
		table = &hr_dev->mr_table.mtt_srqwqe_table;
		bt_page_size = 1 << (hr_dev->caps.srqwqe_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_IDX:
		table = &hr_dev->mr_table.mtt_idx_table;
		bt_page_size = 1 << (hr_dev->caps.idx_ba_pg_sz + PAGE_SHIFT);
		break;
	default:
		dev_err(hr_dev->dev,
			"Unsupport mtt type %d, write mtt chunk failed\n",
			mtt->mtt_type);
		return -EINVAL;
	}

	/* All MTTs must fit in the same page */
	if (start_index / (bt_page_size / sizeof(u64)) !=
		(start_index + npages - 1) / (bt_page_size / sizeof(u64)))
		return -EINVAL;

	if (start_index & (HNS_ROCE_MTT_ENTRY_PER_SEG - 1))
		return -EINVAL;

	mtts = hns_roce_table_find(hr_dev, table,
				   mtt->first_seg +
				   start_index / HNS_ROCE_MTT_ENTRY_PER_SEG,
				   &dma_handle);
	if (!mtts)
		return -ENOMEM;

	/* Save page addr, low 12 bits : 0 */
	for (i = 0; i < npages; ++i) {
		if (!hr_dev->caps.mtt_hop_num)
			mtts[i] = cpu_to_le64(page_list[i] >> PAGE_ADDR_SHIFT);
		else
			mtts[i] = cpu_to_le64(page_list[i]);
	}

	return 0;
}

static int hns_roce_write_mtt(struct hns_roce_dev *hr_dev,
			      struct hns_roce_mtt *mtt, u32 start_index,
			      u32 npages, u64 *page_list)
{
	int chunk;
	int ret;
	u32 bt_page_size;

	if (mtt->order < 0)
		return -EINVAL;

	switch (mtt->mtt_type) {
	case MTT_TYPE_WQE:
		bt_page_size = 1 << (hr_dev->caps.mtt_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_CQE:
		bt_page_size = 1 << (hr_dev->caps.cqe_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_SRQWQE:
		bt_page_size = 1 << (hr_dev->caps.srqwqe_ba_pg_sz + PAGE_SHIFT);
		break;
	case MTT_TYPE_IDX:
		bt_page_size = 1 << (hr_dev->caps.idx_ba_pg_sz + PAGE_SHIFT);
		break;
	default:
		dev_err(hr_dev->dev,
			"Unsupport mtt type %d, write mtt failed\n",
			mtt->mtt_type);
		return -EINVAL;
	}

	while (npages > 0) {
		chunk = min_t(int, bt_page_size / sizeof(u64), npages);

		ret = hns_roce_write_mtt_chunk(hr_dev, mtt, start_index, chunk,
					       page_list);
		if (ret)
			return ret;

		npages -= chunk;
		start_index += chunk;
		page_list += chunk;
	}

	return 0;
}

int hns_roce_buf_write_mtt(struct hns_roce_dev *hr_dev,
			   struct hns_roce_mtt *mtt, struct hns_roce_buf *buf)
{
	u64 *page_list;
	int ret;
	u32 i;

	page_list = kmalloc_array(buf->npages, sizeof(*page_list), GFP_KERNEL);
	if (!page_list)
		return -ENOMEM;

	for (i = 0; i < buf->npages; ++i)
		page_list[i] = hns_roce_buf_page(buf, i);

	ret = hns_roce_write_mtt(hr_dev, mtt, 0, buf->npages, page_list);

	kfree(page_list);

	return ret;
}

int hns_roce_init_mr_table(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;
	int ret;

	ret = hns_roce_bitmap_init(&mr_table->mtpt_bitmap,
				   hr_dev->caps.num_mtpts,
				   hr_dev->caps.num_mtpts - 1,
				   hr_dev->caps.reserved_mrws, 0);
	if (ret) {
		dev_err(hr_dev->dev,
			"mtpt bitmap init failed, ret = %d\n", ret);
		return ret;
	}
	ret = hns_roce_buddy_init(&mr_table->mtt_buddy,
				  ilog2(hr_dev->caps.num_mtt_segs));
	if (ret)
		goto err_buddy;

	if (hns_roce_check_whether_mhop(hr_dev, HEM_TYPE_CQE)) {
		ret = hns_roce_buddy_init(&mr_table->mtt_cqe_buddy,
					  ilog2(hr_dev->caps.num_cqe_segs));
		if (ret)
			goto err_buddy_cqe;
	}

	ret = hns_roce_buddy_init(&mr_table->mtt_srqwqe_buddy,
				  ilog2(hr_dev->caps.num_srqwqe_segs));
	if (ret)
		goto err_buddy_srqwqe;

	ret = hns_roce_buddy_init(&mr_table->mtt_idx_buddy,
				  ilog2(hr_dev->caps.num_idx_segs));
	if (ret)
		goto err_buddy_idx;

	return 0;

err_buddy_idx:
	hns_roce_buddy_cleanup(&mr_table->mtt_srqwqe_buddy);

err_buddy_srqwqe:
	if (hns_roce_check_whether_mhop(hr_dev, HEM_TYPE_CQE))
		hns_roce_buddy_cleanup(&mr_table->mtt_cqe_buddy);

err_buddy_cqe:
	hns_roce_buddy_cleanup(&mr_table->mtt_buddy);

err_buddy:
	hns_roce_bitmap_cleanup(&mr_table->mtpt_bitmap);
	return ret;
}

void hns_roce_cleanup_mr_table(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;

	hns_roce_buddy_cleanup(&mr_table->mtt_idx_buddy);
	hns_roce_buddy_cleanup(&mr_table->mtt_srqwqe_buddy);
	hns_roce_buddy_cleanup(&mr_table->mtt_buddy);
	if (hns_roce_check_whether_mhop(hr_dev, HEM_TYPE_CQE))
		hns_roce_buddy_cleanup(&mr_table->mtt_cqe_buddy);
	hns_roce_bitmap_cleanup(&mr_table->mtpt_bitmap);
}

struct ib_mr *hns_roce_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct hns_roce_mr *mr;
	int ret;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (mr == NULL)
		return  ERR_PTR(-ENOMEM);

	mr->type = MR_TYPE_DMA;

	/* Allocate memory region key */
	ret = hns_roce_mr_alloc(to_hr_dev(pd->device), to_hr_pd(pd)->pdn, 0,
				~0ULL, acc, 0, mr);
	if (ret) {
		dev_err(to_hr_dev(pd->device)->dev,
			"alloc mr failed(%d), pd is 0x%lx , access is 0x%x.\n",
			ret, to_hr_pd(pd)->pdn, acc);
		goto err_free;
	}

	ret = hns_roce_mr_enable(to_hr_dev(pd->device), mr);
	if (ret)
		goto err_mr;

	mr->ibmr.rkey = mr->ibmr.lkey = mr->key;
	mr->umem = NULL;

	rdfx_func_cnt(to_hr_dev(pd->device), RDFX_FUNC_GET_DMA_MR);
	rdfx_alloc_rdfx_mr(to_hr_dev(pd->device), mr);

	return &mr->ibmr;

err_mr:
	hns_roce_mr_free(to_hr_dev(pd->device), mr);

err_free:
	kfree(mr);
	return ERR_PTR(ret);
}

int hns_roce_ib_umem_write_mtt(struct hns_roce_dev *hr_dev,
			       struct hns_roce_mtt *mtt, struct ib_umem *umem)
{
	struct device *dev = hr_dev->dev;
	struct scatterlist *sg;
	unsigned int order;
	int i, k, entry;
	int npage = 0;
	int ret = 0;
	int len;
	u64 page_addr;
	u64 *pages;
	u32 bt_page_size;
	u32 n;

	switch (mtt->mtt_type) {
	case MTT_TYPE_WQE:
		order = hr_dev->caps.mtt_ba_pg_sz;
		break;
	case MTT_TYPE_CQE:
		order = hr_dev->caps.cqe_ba_pg_sz;
		break;
	case MTT_TYPE_SRQWQE:
		order = hr_dev->caps.srqwqe_ba_pg_sz;
		break;
	case MTT_TYPE_IDX:
		order = hr_dev->caps.idx_ba_pg_sz;
		break;
	default:
		dev_err(dev, "Unsupport mtt type %d, umem write mtt failed\n",
			mtt->mtt_type);
		return -EINVAL;
	}

	bt_page_size = 1 << (order + PAGE_SHIFT);

	pages = (u64 *) __get_free_pages(GFP_KERNEL, order);
	if (!pages)
		return -ENOMEM;

	i = n = 0;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		len = sg_dma_len(sg) >> PAGE_SHIFT;
		for (k = 0; k < len; ++k) {
			page_addr =
				sg_dma_address(sg) + (k << umem->page_shift);
			if (!(npage % (1 << (mtt->page_shift - PAGE_SHIFT)))) {
				if (page_addr & ((1 << mtt->page_shift) - 1)) {
					dev_err(dev, "page_addr 0x%llx is not page_shift %d alignment!\n",
						page_addr, mtt->page_shift);
					ret = -EINVAL;
					goto out;
				}
				pages[i++] = page_addr;
			}
			npage++;
			if (i == bt_page_size / sizeof(u64)) {
				ret = hns_roce_write_mtt(hr_dev, mtt, n, i,
							 pages);
				if (ret)
					goto out;
				n += i;
				i = 0;
			}
		}
	}

	if (i)
		ret = hns_roce_write_mtt(hr_dev, mtt, n, i, pages);

out:
	free_pages((unsigned long) pages, order);
	return ret;
}

int hns_roce_ib_umem_write_mr(struct hns_roce_dev *hr_dev,
				     struct hns_roce_mr *mr,
				     struct ib_umem *umem)
{
	struct scatterlist *sg;
	int i = 0, j = 0, k;
	int entry;
	int len;
	u64 page_addr;
	u32 pbl_bt_sz;

	if (hr_dev->caps.pbl_hop_num == HNS_ROCE_HOP_NUM_0)
		return 0;

	pbl_bt_sz = 1 << (hr_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT);
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		len = sg_dma_len(sg) >> umem->page_shift;
		for (k = 0; k < len; ++k) {
			page_addr = sg_dma_address(sg) +
				    (k << umem->page_shift);

			if (!hr_dev->caps.pbl_hop_num) {
				/* for hip06, page addr is aligned to 4K */
				mr->pbl_buf[i++] = page_addr >> 12;
			} else if (hr_dev->caps.pbl_hop_num == 1) {
				mr->pbl_buf[i++] = page_addr;
			} else {
				if (hr_dev->caps.pbl_hop_num == 2)
					mr->pbl_bt_l1[i][j] = page_addr;
				else if (hr_dev->caps.pbl_hop_num == 3)
					mr->pbl_bt_l2[i][j] = page_addr;

				j++;
				if (j >= (pbl_bt_sz / BA_BYTE_LEN)) {
					i++;
					j = 0;
				}
			}
		}
	}

	/* Memory barrier */
	mb();

	return 0;
}
EXPORT_SYMBOL_GPL(hns_roce_ib_umem_write_mr);

struct ib_mr *hns_roce_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				   u64 virt_addr, int access_flags,
				   struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	struct device *dev = hr_dev->dev;
	struct hns_roce_mr *mr;
	int bt_size;
	int ret;
	int n;
	int i;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->umem = ib_umem_get(pd->uobject->context, start, length,
			       access_flags, 0);
	if (IS_ERR(mr->umem)) {
		ret = PTR_ERR(mr->umem);
		dev_err(dev, " ib_umem_get failed, ret = %d\n", ret);
		goto err_free;
	}

	n = ib_umem_page_count(mr->umem);

	if (!hr_dev->caps.pbl_hop_num) {
		if (n > HNS_ROCE_MAX_MTPT_PBL_NUM) {
			dev_err(dev,
			     " MR len %lld err. MR is limited to 4G at most!\n",
			     length);
			ret = -EINVAL;
			goto err_umem;
		}
	} else {
		u64 pbl_size = 1;

		bt_size = (1 << (hr_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT)) /
			  BA_BYTE_LEN;
		for (i = 0; i < hr_dev->caps.pbl_hop_num; i++)
			pbl_size *= bt_size;
		if (n > pbl_size) {
			dev_err(dev,
			    " MR len %lld err. MR page num is limited to %lld!\n",
			    length, pbl_size);
			ret = -EINVAL;
			goto err_umem;
		}
	}

	mr->type = MR_TYPE_MR;

	ret = hns_roce_mr_alloc(hr_dev, to_hr_pd(pd)->pdn, virt_addr, length,
				access_flags, n, mr);
	if (ret)
		goto err_umem;

	ret = hns_roce_ib_umem_write_mr(hr_dev, mr, mr->umem);
	if (ret)
		goto err_mr;

	ret = hns_roce_mr_enable(hr_dev, mr);
	if (ret)
		goto err_mr;

	mr->ibmr.rkey = mr->ibmr.lkey = mr->key;

	rdfx_func_cnt(to_hr_dev(pd->device), RDFX_FUNC_REG_USER_MR);
	rdfx_alloc_rdfx_mr(to_hr_dev(pd->device), mr);
	hns_roce_inc_rdma_hw_stats(pd->device, HW_STATS_MR_ALLOC);

	return &mr->ibmr;

err_mr:
	hns_roce_mr_free(hr_dev, mr);

err_umem:
	ib_umem_release(mr->umem);

err_free:
	kfree(mr);
	return ERR_PTR(ret);
}

static int rereg_mr_trans(struct ib_mr *ibmr, int flags,
			  u64 start, u64 length,
			  u64 virt_addr, int mr_access_flags,
			  struct hns_roce_cmd_mailbox *mailbox,
			  u32 pdn)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibmr->device);
	struct hns_roce_mr *mr = to_hr_mr(ibmr);
	struct device *dev = hr_dev->dev;
	int npages;
	int ret;

	if (mr->size != ~0ULL) {
		npages = ib_umem_page_count(mr->umem);

		if (hr_dev->caps.pbl_hop_num)
			hns_roce_mhop_free(hr_dev, mr);
		else
			dma_free_coherent(dev, npages * BA_BYTE_LEN,
					  mr->pbl_buf, mr->pbl_dma_addr);
	}
	ib_umem_release(mr->umem);

	mr->umem = ib_umem_get(ibmr->uobject->context, start, length,
			       mr_access_flags, 0);
	if (IS_ERR(mr->umem)) {
		ret = PTR_ERR(mr->umem);
		mr->umem = NULL;
		return -ENOMEM;
	}
	npages = ib_umem_page_count(mr->umem);

	if (hr_dev->caps.pbl_hop_num) {
		ret = hns_roce_mhop_alloc(hr_dev, npages, mr);
		if (ret)
			goto release_umem;
	} else {
		mr->pbl_buf = dma_alloc_coherent(dev, npages * BA_BYTE_LEN,
						 &(mr->pbl_dma_addr),
						 GFP_KERNEL);
		if (!mr->pbl_buf) {
			ret = -ENOMEM;
			goto release_umem;
		}
	}

	ret = hr_dev->hw->rereg_write_mtpt(hr_dev, mr, flags, pdn,
					   mr_access_flags, virt_addr,
					   length, mailbox->buf);
	if (ret)
		goto release_umem;

	ret = hns_roce_ib_umem_write_mr(hr_dev, mr, mr->umem);
	if (ret) {
		if (mr->size != ~0ULL) {
			npages = ib_umem_page_count(mr->umem);

			if (hr_dev->caps.pbl_hop_num)
				hns_roce_mhop_free(hr_dev, mr);
			else
				dma_free_coherent(dev, npages * BA_BYTE_LEN,
						  mr->pbl_buf,
						  mr->pbl_dma_addr);
		}

		goto release_umem;
	}

	return 0;
release_umem:
	ib_umem_release(mr->umem);
	return ret;
}

int hns_roce_rereg_user_mr(struct ib_mr *ibmr, int flags, u64 start, u64 length,
			   u64 virt_addr, int mr_access_flags, struct ib_pd *pd,
			   struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibmr->device);
	struct hns_roce_mr *mr = to_hr_mr(ibmr);
	struct hns_roce_cmd_mailbox *mailbox;
	struct device *dev = hr_dev->dev;
	unsigned long mtpt_idx;
	u32 pdn = 0;
	int ret;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_REREG_USER_MR);
	hns_roce_inc_rdma_hw_stats(ibmr->device, HW_STATS_MR_REREG);

	if (!mr->enabled)
		return -EINVAL;

	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	mtpt_idx = key_to_hw_index(mr->key) & (hr_dev->caps.num_mtpts - 1);
	ret = hns_roce_cmd_mbox(hr_dev, 0, mailbox->dma, mtpt_idx, 0,
				HNS_ROCE_CMD_QUERY_MPT,
				HNS_ROCE_CMD_TIMEOUT_MSECS);
	if (ret)
		goto free_cmd_mbox;

	ret = hns_roce_hw_destroy_mpt(hr_dev, NULL, mtpt_idx);
	if (ret)
		dev_warn(dev, "DESTROY_MPT failed (%d)\n", ret);

	mr->enabled = 0;

	if (flags & IB_MR_REREG_PD)
		pdn = to_hr_pd(pd)->pdn;

	if (flags & IB_MR_REREG_TRANS) {
		ret = rereg_mr_trans(ibmr, flags,
				     start, length,
				     virt_addr, mr_access_flags,
				     mailbox, pdn);
		if (ret)
			goto free_cmd_mbox;
	} else {
		ret = hr_dev->hw->rereg_write_mtpt(hr_dev, mr, flags, pdn,
						   mr_access_flags, virt_addr,
						   length, mailbox->buf);
		if (ret)
			goto free_cmd_mbox;
	}

	ret = hns_roce_hw_create_mpt(hr_dev, mailbox, mtpt_idx);
	if (ret) {
		dev_err(dev, "CREATE_MPT failed(%d) for rereg_usr_mr\n", ret);
		ib_umem_release(mr->umem);
		goto free_cmd_mbox;
	}

	mr->enabled = 1;
	if (flags & IB_MR_REREG_ACCESS)
		mr->access = mr_access_flags;

	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return 0;

free_cmd_mbox:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return ret;
}

int hns_roce_dereg_mr(struct ib_mr *ibmr)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibmr->device);
	struct hns_roce_mr *mr = to_hr_mr(ibmr);
	int ret = 0;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_DEREG_MR);
	rdfx_inc_dereg_mr_cnt(hr_dev);
	rdfx_release_rdfx_mr(hr_dev, mr->key);
	hns_roce_inc_rdma_hw_stats(ibmr->device, HW_STATS_MR_DEALLOC);

	if (hr_dev->hw->dereg_mr) {
		ret = hr_dev->hw->dereg_mr(hr_dev, mr);
	} else {
		hns_roce_mr_free(hr_dev, mr);

		if (mr->umem)
			ib_umem_release(mr->umem);

		kfree(mr);
	}

	return ret;
}

struct ib_mr *hns_roce_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
				u32 max_num_sg)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(pd->device);
	struct device *dev = hr_dev->dev;
	struct hns_roce_mr *mr;
	u64 length;
	u32 page_size;
	int ret;

	page_size = 1 << (hr_dev->caps.pbl_buf_pg_sz + PAGE_SHIFT);
	length = max_num_sg * page_size;

	if (mr_type != IB_MR_TYPE_MEM_REG)
		return ERR_PTR(-EINVAL);

	if (max_num_sg > HNS_ROCE_FRMR_MAX_PA) {
		dev_err(dev, "max_num_sg larger than %d\n",
			HNS_ROCE_FRMR_MAX_PA);
		return ERR_PTR(-EINVAL);
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->type = MR_TYPE_FRMR;

	/* Allocate memory region key */
	ret = hns_roce_mr_alloc(hr_dev, to_hr_pd(pd)->pdn, 0, length,
				0, max_num_sg, mr);
	if (ret)
		goto err_free;

	ret = hns_roce_mr_enable(hr_dev, mr);
	if (ret)
		goto err_free_mr;

	mr->ibmr.rkey = mr->ibmr.lkey = mr->key;
	mr->umem = NULL;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_REG_USER_MR);
	rdfx_alloc_rdfx_mr(hr_dev, mr);
	hns_roce_inc_rdma_hw_stats(pd->device, HW_STATS_MR_ALLOC);

	return &mr->ibmr;

err_free_mr:
	hns_roce_mr_free(to_hr_dev(pd->device), mr);

err_free:
	kfree(mr);
	return ERR_PTR(ret);
}

static int hns_roce_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct hns_roce_mr *mr = to_hr_mr(ibmr);

	mr->pbl_buf[mr->npages++] = addr;

	return 0;
}

int hns_roce_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		       unsigned int *sg_offset)
{
	struct hns_roce_mr *mr = to_hr_mr(ibmr);

	mr->npages = 0;

	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, hns_roce_set_page);
}

static void hns_roce_mw_free(struct hns_roce_dev *hr_dev,
			     struct hns_roce_mw *mw)
{
	struct device *dev = hr_dev->dev;
	int ret;

	if (mw->enabled) {
		ret = hns_roce_hw_destroy_mpt(hr_dev, NULL,
					      key_to_hw_index(mw->rkey) &
					      (hr_dev->caps.num_mtpts - 1));
		if (ret)
			dev_warn(dev, "MW DESTROY_MPT failed (%d)\n", ret);

		hns_roce_table_put(hr_dev, &hr_dev->mr_table.mtpt_table,
				   key_to_hw_index(mw->rkey));
	}

	hns_roce_bitmap_free(&hr_dev->mr_table.mtpt_bitmap,
			     key_to_hw_index(mw->rkey), BITMAP_NO_RR);
}

static int hns_roce_mw_enable(struct hns_roce_dev *hr_dev,
			      struct hns_roce_mw *mw)
{
	unsigned long mtpt_idx = key_to_hw_index(mw->rkey);
	struct device *dev = hr_dev->dev;
	struct hns_roce_cmd_mailbox *mailbox;
	struct hns_roce_mr_table *mr_table = &hr_dev->mr_table;
	int ret;

	/* prepare HEM entry memory */
	ret = hns_roce_table_get(hr_dev, &mr_table->mtpt_table, mtpt_idx);
	if (ret)
		return ret;

	/* allocate mailbox memory */
	mailbox = hns_roce_alloc_cmd_mailbox(hr_dev);
	if (IS_ERR(mailbox)) {
		ret = PTR_ERR(mailbox);
		goto err_table;
	}

	ret = hr_dev->hw->mw_write_mtpt(mailbox->buf, mw);
	if (ret) {
		dev_err(dev, "MW write mtpt failed(%d)!\n", ret);
		goto err_page;
	}

	ret = hns_roce_hw_create_mpt(hr_dev, mailbox,
				     mtpt_idx & (hr_dev->caps.num_mtpts - 1));
	if (ret) {
		dev_err(dev, "MW CREATE_MPT failed (%d).\n", ret);
		goto err_page;
	}

	mw->enabled = 1;

	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

	return 0;

err_page:
	hns_roce_free_cmd_mailbox(hr_dev, mailbox);

err_table:
	hns_roce_table_put(hr_dev, &mr_table->mtpt_table, mtpt_idx);

	return ret;
}

struct ib_mw *hns_roce_alloc_mw(struct ib_pd *ib_pd, enum ib_mw_type type,
				struct ib_udata *udata)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_pd->device);
	struct hns_roce_mw *mw;
	unsigned long index = 0;
	int ret;

	mw = kzalloc(sizeof(*mw), GFP_KERNEL);
	if (!mw)
		return ERR_PTR(-ENOMEM);

	/* Allocate a key for mw from bitmap */
	ret = hns_roce_bitmap_alloc(&hr_dev->mr_table.mtpt_bitmap, &index);
	if (ret)
		goto err_bitmap;

	mw->rkey = hw_index_to_key(index);

	mw->ibmw.rkey = mw->rkey;
	mw->ibmw.type = type;
	mw->pdn = to_hr_pd(ib_pd)->pdn;
	mw->pbl_hop_num = hr_dev->caps.pbl_hop_num;
	mw->pbl_ba_pg_sz = hr_dev->caps.pbl_ba_pg_sz;
	mw->pbl_buf_pg_sz = hr_dev->caps.pbl_buf_pg_sz;

	ret = hns_roce_mw_enable(hr_dev, mw);
	if (ret)
		goto err_mw;

	return &mw->ibmw;

err_mw:
	hns_roce_mw_free(hr_dev, mw);

err_bitmap:
	kfree(mw);

	return ERR_PTR(ret);
}

int hns_roce_dealloc_mw(struct ib_mw *ibmw)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ibmw->device);
	struct hns_roce_mw *mw = to_hr_mw(ibmw);

	hns_roce_mw_free(hr_dev, mw);
	kfree(mw);

	return 0;
}

static int mtr_map_region(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
			  struct hns_roce_buf_region *region, dma_addr_t *pages,
			  int max_count)
{
	int count, npage;
	int offset, end;
	__le64 *mtts;
	u64 addr;
	int i;

	offset = region->offset;
	end = offset + region->count;
	npage = 0;
	while (offset < end && npage < max_count) {
		count = 0;
		mtts = hns_roce_hem_list_find_mtt(hr_dev, &mtr->hem_list,
						  offset, &count, NULL);
		if (!mtts)
			return -ENOBUFS;

		for (i = 0; i < count && npage < max_count; i++) {
			if (hr_dev->hw_rev == HNS_ROCE_HW_VER1)
				addr = to_hr_hw_page_addr(pages[npage]);
			else
				addr = pages[npage];

			mtts[i] = cpu_to_le64(addr);
			npage++;
		}
		offset += count;
	}

	return npage;
}

static inline bool mtr_has_mtt(struct hns_roce_buf_attr *attr)
{
	int i;

	for (i = 0; i < attr->region_count; i++)
		if (attr->region[i].hopnum != HNS_ROCE_HOP_NUM_0 &&
		    attr->region[i].hopnum > 0)
			return true;

	/* because the mtr only one root base address, when hopnum is 0 means
	 * root base address equals the first buffer address, thus all alloced
	 * memory must in a continuous space accessed by direct mode.
	 */
	return false;
}

static inline size_t mtr_bufs_size(struct hns_roce_buf_attr *attr)
{
	size_t size = 0;
	int i;

	for (i = 0; i < attr->region_count; i++)
		size += attr->region[i].size;

	return size;
}

/*
 * check the given pages in continuous address space
 * Returns 0 on success, or the error page num.
 */
static inline int mtr_check_direct_pages(dma_addr_t *pages, int page_count,
					 unsigned int page_shift)
{
	size_t page_size = 1 << page_shift;
	int i;

	for (i = 1; i < page_count; i++)
		if (pages[i] - pages[i - 1] != page_size)
			return i;

	return 0;
}

static void mtr_free_bufs(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr)
{
	/* release user buffers */
	if (mtr->umem) {
		ib_umem_release(mtr->umem);
		mtr->umem = NULL;
	}

	/* release kernel buffers */
	if (mtr->kmem) {
		hns_roce_buf_free(hr_dev, mtr->kmem);
		mtr->kmem = NULL;
	}
}

static struct ib_umem *
mtr_get_umem(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
	     struct hns_roce_buf_attr *buf_attr, size_t buf_size,
	     struct ib_ucontext *ucontext, unsigned long user_addr)
{
	return ib_umem_get(ucontext, user_addr, buf_size,
			   buf_attr->user_access,
			   buf_attr->user_dmasync);
}

static struct hns_roce_buf *
mtr_get_kmem(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
	     struct hns_roce_buf_attr *buf_attr, int pg_shift, size_t buf_size,
	     bool is_direct)
{
	struct device *dev = hr_dev->dev;
	struct hns_roce_buf *hr_buf;

	hr_buf = hns_roce_buf_alloc(hr_dev, buf_size, pg_shift,
				    is_direct ? HNS_ROCE_BUF_DIRECT : 0);
	if (IS_ERR_OR_NULL(hr_buf)) {
		dev_err(dev, "Failed to alloc kmem, ret %ld\n",
			PTR_ERR(hr_buf));
		return NULL;
	}

	return hr_buf;
}

static int mtr_alloc_bufs(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
			  struct hns_roce_buf_attr *buf_attr,
			  struct ib_ucontext *ucontext, unsigned long user_addr)
{
	struct device *dev = hr_dev->dev;
	size_t total_size;

	total_size = mtr_bufs_size(buf_attr);
	if (ucontext) {
		mtr->kmem = NULL;
		mtr->umem = mtr_get_umem(hr_dev, mtr, buf_attr, total_size,
					 ucontext, user_addr);
		if (IS_ERR_OR_NULL(mtr->umem)) {
			dev_err(dev, "Failed to get umem, ret %ld\n",
				PTR_ERR(mtr->umem));
			return -ENOMEM;
		}
	} else {
		mtr->umem = NULL;
		mtr->kmem = mtr_get_kmem(hr_dev, mtr, buf_attr,
					 buf_attr->page_shift, total_size,
					 mtr->hem_cfg.is_direct);
		if (!mtr->kmem) {
			dev_err(dev, "Failed to alloc kmem\n");
			return -ENOMEM;
		}
	}

	return 0;
}

static int mtr_map_bufs(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
			 int page_count, unsigned int page_shift)
{
	struct device *dev = hr_dev->dev;
	dma_addr_t *pages;
	int npage;
	int ret;

	/* alloc a tmp array to store buffer's dma address */
	pages = kvcalloc(page_count, sizeof(dma_addr_t), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	if (mtr->umem)
		npage = hns_roce_get_umem_bufs(hr_dev, pages, page_count,
					       mtr->umem, page_shift);
	else
		npage = hns_roce_get_kmem_bufs(hr_dev, pages, page_count,
					       mtr->kmem, page_shift);

	if (npage != page_count) {
		dev_err(dev, "failed to get mtr page %d != %d.\n", npage,
			page_count);
		ret = -ENOBUFS;
		goto err_alloc_list;
	}

	if (mtr->hem_cfg.is_direct && npage > 1) {
		ret = mtr_check_direct_pages(pages, npage, page_shift);
		if (ret) {
			dev_err(dev, "failed to check %s page: %d / %d.\n",
				mtr->umem ? "umtr" : "kmtr", ret, npage);
			ret = -ENOBUFS;
			goto err_alloc_list;
		}
	}

	ret = hns_roce_mtr_map(hr_dev, mtr, pages, page_count);
	if (ret)
		dev_err(dev, "failed to map mtr pages, ret = %d.\n", ret);

err_alloc_list:
	/* drop tmp array */
	kvfree(pages);

	return ret;
}

int hns_roce_mtr_map(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
		     dma_addr_t *pages, unsigned int page_cnt)
{
	struct device *dev = hr_dev->dev;
	struct hns_roce_buf_region *r;
	unsigned int i, mapped_cnt;
	int ret;

	/*
	 * Only use the first page address as root ba when hopnum is 0, this
	 * is because the addresses of all pages are consecutive in this case.
	 */
	if (mtr->hem_cfg.is_direct) {
		mtr->hem_cfg.root_ba = pages[0];
		return 0;
	}

	for (i = 0, mapped_cnt = 0; i < mtr->hem_cfg.region_count &&
				mapped_cnt < page_cnt; i++) {
		r = &mtr->hem_cfg.region[i];
		/* if hopnum is 0, no need to map pages in this region */
		if (!r->hopnum) {
			mapped_cnt += r->count;
			continue;
		}

		if (r->offset + r->count > page_cnt) {
			ret = -EINVAL;
			dev_err(dev,
				"failed to check mtr%u count %u + %u > %u\n",
				i, r->offset, r->count, page_cnt);
			return ret;
		}

		ret = mtr_map_region(hr_dev, mtr, r, &pages[r->offset],
				     page_cnt - mapped_cnt);
		if (ret < 0) {
			dev_err(dev, "failed to map mtr%u offset %u, ret = %d.\n",
				i, r->offset, ret);
			return ret;
		}
		mapped_cnt += ret;
		ret = 0;
	}

	if (mapped_cnt < page_cnt) {
		ret = -ENOBUFS;
		dev_err(dev, "failed to map mtr pages count: %u < %u.\n",
			mapped_cnt, page_cnt);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(hns_roce_mtr_map);

int hns_roce_mtr_find(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
		      int offset, u64 *mtt_buf, int mtt_max, u64 *base_addr)
{
	struct hns_roce_hem_cfg *cfg = &mtr->hem_cfg;
	int mtt_count, left;
	int start_index;
	int total = 0;
	__le64 *mtts;
	u32 npage;
	u64 addr;

	if (!mtt_buf || mtt_max < 1)
		goto done;

	/* no mtt memory in direct mode, so just return the buffer address */
	if (cfg->is_direct) {
		start_index = offset >> HNS_HW_PAGE_SHIFT;
		for (mtt_count = 0; mtt_count < cfg->region_count &&
		     total < mtt_max; mtt_count++) {
			npage = cfg->region[mtt_count].offset;
			if (npage < start_index)
				continue;

			addr = cfg->root_ba + (npage << HNS_HW_PAGE_SHIFT);
			if (hr_dev->hw_rev == HNS_ROCE_HW_VER1)
				mtt_buf[total] = to_hr_hw_page_addr(addr);
			else
				mtt_buf[total] = addr;

			total++;
		}

		goto done;
	}

	start_index = offset >> cfg->buf_pg_shift;
	left = mtt_max;
	while (left > 0) {
		mtt_count = 0;
		mtts = hns_roce_hem_list_find_mtt(hr_dev, &mtr->hem_list,
						  start_index + total,
						  &mtt_count, NULL);
		if (!mtts || !mtt_count)
			goto done;

		npage = min(mtt_count, left);
		left -= npage;
		for (mtt_count = 0; mtt_count < npage; mtt_count++)
			mtt_buf[total++] = le64_to_cpu(mtts[mtt_count]);
	}

done:
	if (base_addr)
		*base_addr = cfg->root_ba;

	return total;
}
EXPORT_SYMBOL_GPL(hns_roce_mtr_find);

static int mtr_init_buf_cfg(struct hns_roce_dev *hr_dev,
			    struct hns_roce_buf_attr *attr,
			    struct hns_roce_hem_cfg *cfg,
			    unsigned int *buf_page_shift, int unalinged_size)
{
	struct hns_roce_buf_region *r;
	int first_region_padding;
	int page_cnt, region_cnt;
	unsigned int page_shift;
	size_t buf_size;

	/* if disable mtt, all pages must in a continuous address range */
	cfg->is_direct = !mtr_has_mtt(attr);
	buf_size = mtr_bufs_size(attr);
	if (cfg->is_direct) {
		/* When HEM buffer use level-0 addressing, the page size is
		 * equal the whole buffer size, and we split whole buffer as
		 * small pages which is used to check whether the adjacent units
		 * are in the continuous space and the size is fixed as 4K for
		 * the hns ROCEE required.
		 */
		page_shift = HNS_HW_PAGE_SHIFT;
		/* The ROCEE requires the page size is 4K * 2^N. */
		cfg->buf_pg_count = 1;
		cfg->buf_pg_shift = HNS_HW_PAGE_SHIFT +
			order_base_2(DIV_ROUND_UP(buf_size, HNS_HW_PAGE_SIZE));
		first_region_padding = 0;
	} else {
		page_shift = attr->page_shift;
		cfg->buf_pg_count = DIV_ROUND_UP(buf_size + unalinged_size,
						 1 << page_shift);
		cfg->buf_pg_shift = page_shift;
		first_region_padding = unalinged_size;
	}

	/* Convert buffer size to page index and page count for each region and
	 * the buffer's offset need append to the first region.
	 */
	for (page_cnt = 0, region_cnt = 0; region_cnt < attr->region_count &&
	     region_cnt < ARRAY_SIZE(cfg->region); region_cnt++) {
		r = &cfg->region[region_cnt];
		r->offset = page_cnt;
		buf_size = hr_hw_page_align(attr->region[region_cnt].size +
					    first_region_padding);
		r->count = DIV_ROUND_UP(buf_size, 1 << page_shift);
		first_region_padding = 0;
		page_cnt += r->count;
		r->hopnum = to_hr_hem_hopnum(attr->region[region_cnt].hopnum,
					     r->count);
	}

	cfg->region_count = region_cnt;
	*buf_page_shift = page_shift;

	return page_cnt;
}

static int mtr_alloc_mtt(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
			 unsigned int ba_page_shift)
{
	struct hns_roce_hem_cfg *cfg = &mtr->hem_cfg;
	int ret;

	hns_roce_hem_list_init(&mtr->hem_list);
	if (!cfg->is_direct) {
		ret = hns_roce_hem_list_request(hr_dev, &mtr->hem_list,
						cfg->region, cfg->region_count,
						ba_page_shift);
		if (ret)
			return ret;
		cfg->root_ba = mtr->hem_list.root_ba;
		cfg->ba_pg_shift = ba_page_shift;
	} else {
		cfg->ba_pg_shift = cfg->buf_pg_shift;
	}

	return 0;
}

static void mtr_free_mtt(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr)
{
	hns_roce_hem_list_release(hr_dev, &mtr->hem_list);
}

/**
 * hns_roce_mtr_create - Create hns memory translate region.
 *
 * @mtr: memory translate region
 * @buf_attr: buffer attribute for creating mtr
 * @ba_page_shift: page shift for multi-hop base address table
 * @ucontext: user space context, if it's NULL, means kernel space
 * @user_addr: userspace virtual address to start at
 */
int hns_roce_mtr_create(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr,
			struct hns_roce_buf_attr *buf_attr,
			unsigned int ba_page_shift,
			struct ib_ucontext *ucontext, unsigned long user_addr)
{
	struct device *dev = hr_dev->dev;
	unsigned int buf_page_shift = 0;
	int buf_page_cnt;
	int ret;

	buf_page_cnt = mtr_init_buf_cfg(hr_dev, buf_attr, &mtr->hem_cfg,
					&buf_page_shift,
					ucontext ? user_addr & ~PAGE_MASK : 0);
	if (buf_page_cnt < 1 || buf_page_shift < HNS_HW_PAGE_SHIFT) {
		dev_err(dev, "failed to init mtr cfg, count %d shift %u.\n",
			buf_page_cnt, buf_page_shift);
		return -EINVAL;
	}

	ret = mtr_alloc_mtt(hr_dev, mtr, ba_page_shift);
	if (ret) {
		dev_err(dev, "failed to alloc mtr mtt, ret = %d.\n", ret);
		return ret;
	}

	/* The caller has its own buffer list and invokes the hns_roce_mtr_map()
	 * to finish the MTT configure.
	 */
	if (buf_attr->mtt_only) {
		mtr->umem = NULL;
		mtr->kmem = NULL;
		return 0;
	}

	ret = mtr_alloc_bufs(hr_dev, mtr, buf_attr, ucontext, user_addr);
	if (ret) {
		dev_err(dev, "failed to alloc mtr bufs, ret = %d.\n", ret);
		goto err_alloc_mtt;
	}

	/* Write buffer's dma address to MTT */
	ret = mtr_map_bufs(hr_dev, mtr, buf_page_cnt, buf_page_shift);
	if (ret)
		dev_err(dev, "failed to map mtr bufs, ret = %d.\n", ret);
	else
		return 0;

	mtr_free_bufs(hr_dev, mtr);
err_alloc_mtt:
	mtr_free_mtt(hr_dev, mtr);
	return ret;
}
EXPORT_SYMBOL_GPL(hns_roce_mtr_create);

void hns_roce_mtr_destroy(struct hns_roce_dev *hr_dev, struct hns_roce_mtr *mtr)
{
	/* release multi-hop addressing resource */
	hns_roce_hem_list_release(hr_dev, &mtr->hem_list);

	/* free buffers */
	mtr_free_bufs(hr_dev, mtr);
}
EXPORT_SYMBOL_GPL(hns_roce_mtr_destroy);
