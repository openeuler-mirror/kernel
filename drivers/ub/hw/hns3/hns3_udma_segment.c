// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include "urma/ubcore_types.h"
#include "hns3_udma_abi.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_eid.h"
#include "hns3_udma_segment.h"

static uint32_t hw_index_to_key(int ind)
{
	return ((uint32_t)ind << SEG_KEY_OFFSET);
}

uint64_t key_to_hw_index(uint32_t key)
{
	return (key >> SEG_KEY_OFFSET);
}

static int udma_hw_create_mpt(struct udma_dev *udma_dev,
			      struct udma_cmd_mailbox *mailbox,
			      uint64_t mpt_index)
{
	struct udma_cmq_desc desc;
	struct udma_mbox *mb;

	mb = (struct udma_mbox *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, mpt_index, UDMA_CMD_CREATE_MPT);

	return udma_cmd_mbox(udma_dev, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);
}

static int udma_hw_destroy_mpt(struct udma_dev *udma_dev,
			struct udma_cmd_mailbox *mailbox,
			uint64_t mpt_index)
{
	struct udma_cmq_desc desc;
	struct udma_mbox *mb;

	mb = (struct udma_mbox *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, 0, 0, mpt_index, UDMA_CMD_DESTROY_MPT);

	return udma_cmd_mbox(udma_dev, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);
}

static int alloc_seg_key(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	struct udma_ida *seg_ida = &udma_dev->seg_table.seg_ida;
	int err;
	int id;

	id = ida_alloc_range(&seg_ida->ida, seg_ida->min, seg_ida->max,
			     GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc id for MR key, id(%d).\n",
			id);
		return -ENOMEM;
	}

	seg->key = hw_index_to_key(id);

	err = udma_table_get(udma_dev, &udma_dev->seg_table.table,
			     (uint64_t)id);
	if (err) {
		dev_err(udma_dev->dev,
			"failed to alloc mtpt, ret = %d.\n", err);
		goto err_free_bitmap;
	}

	return 0;

err_free_bitmap:
	ida_free(&seg_ida->ida, id);

	return err;
}

static uint64_t get_continuos_mem_size(uint64_t seg_addr)
{
#define HNS3_DOUBLE 2
	return seg_addr / HNS3_UDMA_KB * HNS3_DOUBLE;
}

static void get_pbl_addr_level(struct udma_seg *seg, struct udma_dev *udma_dev)
{
	uint64_t cont_mem_size;
	uint64_t seg_size;
	uint64_t page_num;

	if (seg->size <= SEG_MEM_SIZE_1G) {
		seg->pbl_hop_num = UDMA_PBL_HOP_NUM - 1U;
		seg_size = roundup_pow_of_two(seg->size);
		cont_mem_size = get_continuos_mem_size(seg_size);
		page_num = cont_mem_size / PAGE_SIZE;
		udma_dev->caps.pbl_ba_pg_sz = ilog2(roundup_pow_of_two(page_num));
	} else {
		seg->pbl_hop_num = udma_dev->caps.pbl_hop_num;
		udma_dev->caps.pbl_ba_pg_sz = UDMA_BA_PG_SZ_SUPPORTED_16K;
	}
}


static int alloc_seg_pbl(struct udma_dev *udma_dev, struct udma_seg *seg,
			 bool is_user)
{
	struct udma_buf_attr buf_attr = {};
	int err;

	get_pbl_addr_level(seg, udma_dev);

	buf_attr.page_shift = PAGE_SHIFT;
	buf_attr.region[0].size = seg->size;
	buf_attr.region[0].hopnum = seg->pbl_hop_num;
	buf_attr.region_count = 1;
	buf_attr.mtt_only = false;

	err = udma_mtr_create(udma_dev, &seg->pbl_mtr, &buf_attr,
			      udma_dev->caps.pbl_ba_pg_sz + PAGE_SHIFT,
			      seg->iova, is_user);
	if (err)
		dev_err(udma_dev->dev, "failed to alloc pbl mtr, ret = %d.\n",
			err);
	else
		seg->npages = seg->pbl_mtr.hem_cfg.buf_pg_count;

	return err;
}

static int set_mtpt_pbl(struct udma_dev *udma_dev,
			struct udma_mpt_entry *mpt_entry,
			struct udma_seg *seg)
{
	uint64_t pages[UDMA_MAX_INNER_MTPT_NUM] = {};
	uint64_t pbl_ba;
	int i, count;

	count = udma_mtr_find(udma_dev, &seg->pbl_mtr, 0, pages,
			      min_t(int, ARRAY_SIZE(pages), seg->npages),
			      &pbl_ba);
	if (count < 1) {
		dev_err(udma_dev->dev, "failed to find PBL mtr, count = %d.\n",
			count);
		return -ENOBUFS;
	}

	/* Aligned to the hardware address access unit */
	for (i = 0; i < count; i++)
		pages[i] >>= PA_PAGE_SHIFT;

	mpt_entry->pbl_size = cpu_to_le32(seg->npages);
	mpt_entry->pbl_ba_l = cpu_to_le32(pbl_ba >> MPT_PAGE_OFFSET);
	udma_reg_write(mpt_entry, MPT_PBL_BA_H,
		       upper_32_bits(pbl_ba >> MPT_PAGE_OFFSET));
	mpt_entry->pa0_l = cpu_to_le32(lower_32_bits(pages[0]));
	udma_reg_write(mpt_entry, MPT_PA0_H, upper_32_bits(pages[0]));
	mpt_entry->pa1_l = cpu_to_le32(lower_32_bits(pages[1]));
	udma_reg_write(mpt_entry, MPT_PA1_H, upper_32_bits(pages[1]));
	udma_reg_write(mpt_entry, MPT_PBL_BUF_PG_SZ,
		       to_hr_hw_page_shift(seg->pbl_mtr.hem_cfg.buf_pg_shift));

	return 0;
}

static int udma_write_seg_mpt(struct udma_dev *udma_dev,
			      void *mb_buf, struct udma_seg *seg)
{
	struct udma_mpt_entry *mpt_entry;
	int ret = 0;

	mpt_entry = (struct udma_mpt_entry *)mb_buf;
	memset(mpt_entry, 0, sizeof(*mpt_entry));

	udma_reg_write(mpt_entry, MPT_ST, MPT_ST_VALID);
	udma_reg_write(mpt_entry, MPT_PD, seg->pd);
	udma_reg_enable(mpt_entry, MPT_L_INV_EN);

	udma_reg_write(mpt_entry, MPT_RW_EN,
		       !!(seg->access & UBCORE_ACCESS_REMOTE_WRITE));
	udma_reg_write(mpt_entry, MPT_LW_EN,
		       !!(seg->access & UBCORE_ACCESS_LOCAL_WRITE));
	udma_reg_write(mpt_entry, MPT_R_INV_EN,
		       !!(seg->access & UBCORE_ACCESS_REMOTE_INVALIDATE));

	mpt_entry->len_l = cpu_to_le32(lower_32_bits(seg->size));
	mpt_entry->len_h = cpu_to_le32(upper_32_bits(seg->size));
	mpt_entry->lkey = cpu_to_le32(seg->key);
	mpt_entry->va_l = cpu_to_le32(lower_32_bits(seg->iova));
	mpt_entry->va_h = cpu_to_le32(upper_32_bits(seg->iova));

	udma_reg_write(mpt_entry, MPT_PERSIST_EN, 1);

	if (seg->pbl_hop_num != UDMA_HOP_NUM_0)
		udma_reg_write(mpt_entry, MPT_PBL_HOP_NUM, seg->pbl_hop_num);

	udma_reg_write(mpt_entry, MPT_PBL_BA_PG_SZ,
		       to_hr_hw_page_shift(seg->pbl_mtr.hem_cfg.ba_pg_shift));
	udma_reg_enable(mpt_entry, MPT_INNER_PA_VLD);

	ret = set_mtpt_pbl(udma_dev, mpt_entry, seg);

	return ret;
}

static int udma_seg_enable(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	uint64_t seg_idx = key_to_hw_index(seg->key);
	struct device *dev = udma_dev->dev;
	struct udma_cmd_mailbox *mailbox;
	int ret;

	/* Allocate mailbox memory */
	mailbox = udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox)) {
		ret = PTR_ERR(mailbox);
		return ret;
	}

	ret = udma_write_seg_mpt(udma_dev, mailbox->buf, seg);
	if (ret) {
		dev_err(dev, "failed to write mtpt, ret = %d.\n", ret);
		goto err_page;
	}

	ret = udma_hw_create_mpt(udma_dev, mailbox,
				 seg_idx & (udma_dev->caps.num_mtpts - 1));
	if (ret) {
		dev_err(dev, "failed to create mpt, ret = %d.\n", ret);
		goto err_page;
	}

err_page:
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static void free_seg_pbl(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	udma_mtr_destroy(udma_dev, &seg->pbl_mtr);
}

static void free_seg_key(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	uint64_t obj = key_to_hw_index(seg->key);

	udma_table_put(udma_dev, &udma_dev->seg_table.table, obj);
	ida_free(&udma_dev->seg_table.seg_ida.ida, (int)obj);
}

static void store_seg_id(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	struct udma_eid *udma_eid;
	struct seg_list *seg_new;
	struct seg_list *seg_now;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	udma_eid = (struct udma_eid *)xa_load(&udma_dev->eid_table, seg->ctx->eid_index);
	if (IS_ERR_OR_NULL(udma_eid)) {
		dev_err(udma_dev->dev, "failed to find eid, index = %d.\n",
			seg->ctx->eid_index);
		return;
	}

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	seg_new = kzalloc(sizeof(struct seg_list), GFP_KERNEL);
	if (!seg_new) {
		read_unlock(&g_udma_dfx_list[i].rwlock);
		return;
	}

	lock = &g_udma_dfx_list[i].dfx->seg_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(seg_now, &g_udma_dfx_list[i].dfx->seg_list->node, node) {
		if (seg_now->key_id == seg->key) {
			memcpy(&seg_now->eid, &udma_eid->eid,
			       sizeof(union ubcore_eid));
			seg_now->pd = seg->pd;
			seg_now->iova = seg->iova;
			seg_now->len = seg->size;
			goto found;
		}
	}

	memcpy(&seg_new->eid, &udma_eid->eid, sizeof(union ubcore_eid));
	seg_new->pd = seg->pd;
	seg_new->iova = seg->iova;
	seg_new->len = seg->size;
	seg_new->key_id = seg->key;
	list_add(&seg_new->node, &g_udma_dfx_list[i].dfx->seg_list->node);
	++g_udma_dfx_list[i].dfx->seg_cnt;
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);

	return;

found:
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
	kfree(seg_new);
}

static void delete_seg_id(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	struct seg_list *seg_now, *seg_tmp;
	unsigned long flags;
	spinlock_t *lock;
	int ret;
	int i;

	ret = udma_find_dfx_dev(udma_dev, &i);
	if (ret)
		return;

	lock = &g_udma_dfx_list[i].dfx->seg_list->node_lock;
	spin_lock_irqsave(lock, flags);
	list_for_each_entry_safe(seg_now, seg_tmp,
				 &g_udma_dfx_list[i].dfx->seg_list->node,
				 node) {
		if (seg_now->key_id == seg->key) {
			list_del(&seg_now->node);
			--g_udma_dfx_list[i].dfx->seg_cnt;
			kfree(seg_now);
			break;
		}
	}
	spin_unlock_irqrestore(lock, flags);
	read_unlock(&g_udma_dfx_list[i].rwlock);
}

struct ubcore_target_seg *udma_register_seg(struct ubcore_device *dev,
					    struct ubcore_seg_cfg *cfg,
					    struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_ucontext *udma_ctx;
	struct udma_seg *seg;
	int ret;

	if (cfg->flag.bs.access >= HNS3_URMA_SEG_ACCESS_GUARD) {
		dev_err(udma_dev->dev, "invalid segment access 0x%x.\n",
			cfg->flag.bs.access);
		return NULL;
	}

	seg = kcalloc(1, sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return NULL;

	udma_ctx = to_udma_ucontext(udata->uctx);
	seg->iova = cfg->va;
	seg->size = cfg->len;
	seg->pd = udma_ctx->pdn;
	seg->access = cfg->flag.bs.access;
	seg->ctx = udma_ctx;

	ret = alloc_seg_key(udma_dev, seg);
	if (ret)
		goto err_alloc_key;

	ret = alloc_seg_pbl(udma_dev, seg, !!udata);
	if (ret)
		goto err_alloc_pbl;

	ret = udma_seg_enable(udma_dev, seg);
	if (ret)
		goto err_enable_seg;
	seg->enabled = 1;
	seg->ubcore_seg.seg.token_id = seg->key;

	if (dfx_switch)
		store_seg_id(udma_dev, seg);

	return &seg->ubcore_seg;

err_enable_seg:
	free_seg_pbl(udma_dev, seg);
err_alloc_pbl:
	free_seg_key(udma_dev, seg);
err_alloc_key:
	kfree(seg);

	return NULL;
}

static void udma_seg_free(struct udma_dev *udma_dev, struct udma_seg *seg)
{
	int ret;

	if (seg->enabled) {
		ret = udma_hw_destroy_mpt(udma_dev, NULL,
					  key_to_hw_index(seg->key) &
					  (udma_dev->caps.num_mtpts - 1));
		if (ret)
			dev_err(udma_dev->dev, "failed to destroy mpt, ret = %d.\n",
				ret);
	}

	free_seg_pbl(udma_dev, seg);
	free_seg_key(udma_dev, seg);
}

int udma_unregister_seg(struct ubcore_target_seg *seg)
{
	struct udma_dev *udma_dev = to_udma_dev(seg->ub_dev);
	struct udma_seg *udma_seg = to_udma_seg(seg);

	if (dfx_switch)
		delete_seg_id(udma_dev, udma_seg);

	udma_seg_free(udma_dev, udma_seg);
	kfree(udma_seg);

	return 0;
}

struct ubcore_target_seg *udma_import_seg(struct ubcore_device *dev,
					  struct ubcore_target_seg_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct ubcore_target_seg *tseg;

	tseg = kcalloc(1, sizeof(*tseg), GFP_KERNEL);
	if (!tseg)
		return NULL;

	return tseg;
}

int udma_unimport_seg(struct ubcore_target_seg *tseg)
{
	kfree(tseg);

	return 0;
}
