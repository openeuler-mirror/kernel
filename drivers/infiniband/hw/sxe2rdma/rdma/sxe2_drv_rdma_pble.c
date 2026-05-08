// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_pble.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/bitmap.h>

static int sxe2_pbl_buddy_init(struct sxe2_pbl_buddy *buddy, u32 max_order)
{
	int ret = SXE2_OK;
	u32 i;
	u32 num				  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(buddy->dev);

	buddy->max_order = max_order;
	spin_lock_init(&buddy->buddy_lock);
	buddy->bits = kzalloc(
		(buddy->max_order + 1) * sizeof(unsigned long *), GFP_KERNEL);
	if (!buddy->bits) {
		DRV_RDMA_LOG_DEV_ERR("pbl:buddy init bits alloc mem err\n");
		ret = -ENOMEM;
		goto end;
	}
	buddy->num_free = kzalloc((buddy->max_order + 1) * sizeof(u32 *),
					 GFP_KERNEL);
	if (!buddy->num_free) {
		DRV_RDMA_LOG_DEV_ERR("pbl:buddy init num free alloc mem err\n");
		ret = -ENOMEM;
		goto num_free_err_out;
	}

	for (i = 0; i <= buddy->max_order; ++i) {
		num = (u32)BITS_TO_LONGS(1ul << (buddy->max_order - i));
		buddy->bits[i] = kvmalloc_array(
			num, sizeof(unsigned long), GFP_KERNEL | __GFP_ZERO);
		if (!buddy->bits[i]) {
			DRV_RDMA_LOG_DEV_ERR(
				"pbl:buddy init bits %u alloc mem err\n", i);
			ret = -ENOMEM;
			goto err_out_free;
		}
		memset(buddy->bits[i], 0x0, sizeof(unsigned long));
	}

	set_bit(0, buddy->bits[buddy->max_order]);
	buddy->num_free[buddy->max_order] = 1;
	goto end;

err_out_free:
	for (i = 0; i <= buddy->max_order; ++i) {
		if (buddy->bits[i]) {
			kvfree(buddy->bits[i]);
			buddy->bits[i] = NULL;
		}
	}
	kfree(buddy->num_free);
	buddy->num_free = NULL;
num_free_err_out:
	kfree(buddy->bits);
	buddy->bits = NULL;
end:
	return ret;
}

int sxe2_pbl_buddy_alloc(struct sxe2_pbl_buddy *buddy, u32 order,
			 u64 *pbl_seg_index, u32 *total_pble_cnt)
{
	int ret				  = SXE2_OK;
	u32 cur_order			  = 0;
	u32 max_bits			  = 0;
	int seg				  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(buddy->dev);

	spin_lock(&buddy->buddy_lock);
	for (cur_order = order; cur_order <= buddy->max_order; ++cur_order) {
		if (buddy->num_free[cur_order]) {
			max_bits = (u32)(1UL << (buddy->max_order - cur_order));
			seg = (int)find_first_bit(buddy->bits[cur_order],
						  max_bits);
			if (seg < (int)max_bits)
				goto found;
		}
	}

	spin_unlock(&buddy->buddy_lock);
	*pbl_seg_index = SXE2_PBL_IDX_VALID_VAL;
	DRV_RDMA_LOG_DEV_ERR(
		"pbl:buddy alloc not find enough pble err order=%u\n", order);
	ret = -ENOMEM;
	goto end;

found:
	clear_bit(seg, buddy->bits[cur_order]);
	--buddy->num_free[cur_order];
	while (cur_order > order) {
		--cur_order;
		seg <<= 1;
		set_bit(seg ^ 1, buddy->bits[cur_order]);
		++buddy->num_free[cur_order];
	}

	spin_unlock(&buddy->buddy_lock);
	*total_pble_cnt = 1 << order;
	*pbl_seg_index	= (u64)seg << order;

end:
	return ret;
}

static void sxe2_pbl_buddy_free(struct sxe2_pbl_buddy *buddy, u64 pbl_seg_index,
				u32 order)
{
	int seg;

	seg = (int)(pbl_seg_index >> order);
	spin_lock(&buddy->buddy_lock);

	while (test_bit(seg ^ 1, buddy->bits[order])) {
		clear_bit(seg ^ 1, buddy->bits[order]);
		--buddy->num_free[order];
		seg >>= 1;
		++order;
	}
	set_bit(seg, buddy->bits[order]);
	++buddy->num_free[order];
	spin_unlock(&buddy->buddy_lock);

}

static void sxe2_pbl_buddy_cleanup(struct sxe2_pbl_buddy *buddy)
{
	u32 i;

	for (i = 0; i <= buddy->max_order; ++i) {
		if (buddy->bits && buddy->bits[i]) {
			kvfree(buddy->bits[i]);
			buddy->bits[i] = NULL;
		}
	}

	kfree(buddy->bits);
	buddy->bits = NULL;

	kfree(buddy->num_free);
	buddy->num_free = NULL;
}

static int sxe2_pbl_first_page_bitmap_init(
	struct sxe2_pbl_first_page_bitmap *first_page_bitmap)
{
	int ret				  = SXE2_OK;
	struct sxe2_rcms_info *rcms_info  = first_page_bitmap->dev->rcms_info;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(first_page_bitmap->dev);

	first_page_bitmap->max_fpte_cnt	  = rcms_info->first_page_fpte;
	first_page_bitmap->first_fpte_idx = rcms_info->max_fpte_index + 1;
	spin_lock_init(&first_page_bitmap->bitmap_lock);
	first_page_bitmap->fpte_bits = kzalloc(
		(first_page_bitmap->max_fpte_cnt) * sizeof(unsigned long *),
		GFP_KERNEL);
	if (!first_page_bitmap->fpte_bits) {
		DRV_RDMA_LOG_DEV_ERR(
			"pbl:first page bitmap init alloc mem err\n");
		ret = -ENOMEM;
	}

	return ret;
}

static int sxe2_pbl_first_page_bitmap_alloc(
	struct sxe2_pbl_first_page_bitmap *first_page_bitmap, u32 bit_cnt,
	u32 *bit_idx)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(first_page_bitmap->dev);

	*bit_idx = SXE2_FIRST_PAGE_INVALID_IDX;
	spin_lock(&first_page_bitmap->bitmap_lock);

	*bit_idx =
		(u32)bitmap_find_next_zero_area(first_page_bitmap->fpte_bits,
						first_page_bitmap->max_fpte_cnt,
						0, bit_cnt, 0);
	if (*bit_idx >= first_page_bitmap->max_fpte_cnt) {
		DRV_RDMA_LOG_DEV_ERR("pbl:first page fpte not enough\n");
		ret = -ENOMEM;
		goto end;
	}
	bitmap_set(first_page_bitmap->fpte_bits, *bit_idx, bit_cnt);

end:
	spin_unlock(&first_page_bitmap->bitmap_lock);
	return ret;
}

static void sxe2_pbl_first_page_bitmap_free(
	struct sxe2_pbl_first_page_bitmap *first_page_bitmap, u32 bit_idx,
	u32 bit_cnt)
{
	spin_lock(&first_page_bitmap->bitmap_lock);
	bitmap_clear(first_page_bitmap->fpte_bits, bit_idx, bit_cnt);
	spin_unlock(&first_page_bitmap->bitmap_lock);
}

int sxe2_pbl_liner_addr_to_pble_pa(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				   u64 liner_addr, u64 *pa)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rcms_info *rcms_info  = dev->rcms_info;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_spt_entry *spte;
	u32 fpte_idx;
	u32 rel_spte_idx;
	u64 page_offset;

	fpte_idx = FPT_INDEX_GET(liner_addr);
	fpte	 = &rcms_info->fpt.fpte[fpte_idx];
	if (!fpte->valid) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:liner addr to pble pa fpte is invalid\n");
		ret = -EINVAL;
		goto end;
	}
	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		if (!fpte->u.cp.use_cnt || !fpte->u.cp.page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa cp is invalid\n");
			ret = -EINVAL;
			goto end;
		}
		page_offset = liner_addr & SXE2_PBL_2MB_PAGE_OFFSET;
		*pa = fpte->u.cp.page_addr.pa + page_offset;
	} else if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND) {
		if (!fpte->u.spt.use_cnt || !fpte->u.spt.spt_page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa spt is invalid\n");
			ret = -EINVAL;
			goto end;
		}
		rel_spte_idx = LINER_ADDR_TO_REL_SPTE_IDX(liner_addr);
		spte	     = &fpte->u.spt.spte[rel_spte_idx];
		if (!spte->valid || !spte->cp.page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa spte is invalid\n");
			ret = -EINVAL;
			goto end;
		}
		page_offset = liner_addr & SXE2_PBL_4KB_PAGE_OFFSET;
		*pa = spte->cp.page_addr.pa + page_offset;
	}

end:
	return ret;
}

static int sxe2_pbl_liner_addr_to_pble_va(struct sxe2_pbl_pble_rsrc *pble_rsrc,
					  u64 liner_addr, u64 **va)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rcms_info *rcms_info  = dev->rcms_info;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_spt_entry *spte;
	u32 fpte_idx;
	u32 rel_spte_idx;
	u64 page_offset;
	char *pble_va = NULL;

	fpte_idx = FPT_INDEX_GET(liner_addr);
	fpte	 = &rcms_info->fpt.fpte[fpte_idx];
	if (!fpte->valid) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:liner addr to pble pa fpte is invalid\n");
		ret = -EINVAL;
		goto end;
	}
	if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		if (!fpte->u.cp.use_cnt || !fpte->u.cp.page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa cp is invalid\n");
			ret = -EINVAL;
			goto end;
		}

		page_offset = liner_addr & SXE2_PBL_2MB_PAGE_OFFSET;
		pble_va = (char *)fpte->u.cp.page_addr.va;
		pble_va += page_offset;
	} else if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND) {
		if (!fpte->u.spt.use_cnt || !fpte->u.spt.spt_page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa spt is invalid\n");
			ret = -EINVAL;
			goto end;
		}
		rel_spte_idx = LINER_ADDR_TO_REL_SPTE_IDX(liner_addr);
		spte	     = &fpte->u.spt.spte[rel_spte_idx];
		if (!spte->valid || !spte->cp.page_addr.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa spte is invalid\n");
			ret = -EINVAL;
			goto end;
		}
		page_offset = liner_addr & SXE2_PBL_4KB_PAGE_OFFSET;
		pble_va = (char *)spte->cp.page_addr.va;
		pble_va += page_offset;
	}
	*va = (u64 *)pble_va;
end:
	return ret;
}

static u32 sxe2_pbl_liner_addr_to_idx(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				      u64 liner_addr)
{
	u64 idx;

	idx = (liner_addr - pble_rsrc->pble_base_addr) >>
	      SXE2_PBL_PBLE_SIZE_SHIFT;
	return (u32)idx;
}

static void sxe2_pbl_get_index_info(u64 liner_addr,
				    struct sxe2_pbl_table_idx_info *idx_info)
{
	idx_info->fpte_idx     = (u32)FPT_INDEX_GET(liner_addr);
	idx_info->spte_idx     = (u32)SPT_INDEX_GET(liner_addr);
	idx_info->rel_spte_idx = REL_SPTE_INDEX_GET(idx_info->spte_idx);

}

static enum sxe2_rcms_fpt_entry_type
sxe2_pbl_get_type(struct sxe2_pbl_pble_rsrc *pble_rsrc)
{
	enum sxe2_rcms_fpt_entry_type entry_type = SXE2_RCMS_FPT_TYPE_FIRST;

	if (!pble_rsrc->dev->privileged) {
		entry_type = SXE2_RCMS_FPT_TYPE_SECOND;
		goto end;
	}

	if (pble_rsrc->init_mode == PBL_SECOND_PAGE_TABLE)
		entry_type = SXE2_RCMS_FPT_TYPE_FIRST;
	else if (pble_rsrc->init_mode == PBL_THIRD_PAGE_TABLE)
		entry_type = SXE2_RCMS_FPT_TYPE_SECOND;

end:
	return entry_type;
}

int sxe2_pbl_manage_pble_cp_cmd(struct sxe2_mq_ctx *mq,
				struct sxe2_pbl_manage_pble_info *info,
				u64 scratch, bool post_sq)
{
	int ret = SXE2_OK;
	__le64 *wqe;
	struct sxe2_rcms_manage_vf_pble_cp_wqe *manage_cp_wqe;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR("pble: query fpm kget next mq wqe err\n");
		ret = -ENOMEM;
		goto end;
	}
	manage_cp_wqe		= (struct sxe2_rcms_manage_vf_pble_cp_wqe *)wqe;
	manage_cp_wqe->spte_cnt = info->spte_cnt;
	manage_cp_wqe->first_spte_idx  = info->first_spte_idx;
	manage_cp_wqe->fpte_idx	       = info->fpte_idx;
	manage_cp_wqe->op	       = SXE2_MQ_OP_MANAGE_PBLE_BP;
	manage_cp_wqe->invalidate_spte = info->invalidate_spte_cnt;
	manage_cp_wqe->spt_pagelist_buf_pa =
		info->first_spte_pa >> SXE2_PBL_MANAGE_CP_WQE_PA_SHIFT;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_pbl_err", manage_cp_wqe,
		     &rdma_dev->rdma_func->mq.err_cqe_val);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_pbl_err");
#endif

	dma_wmb();
	manage_cp_wqe->wqe_valid = mq->polarity;

	if (post_sq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}

int sxe2_pbl_build_second_type_table(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				     struct sxe2_pbl_add_page_info *info)
{
	int ret				    = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	    = pble_rsrc->dev;
	struct sxe2_pbl_table_idx_info *idx = &info->idx_info;
	struct sxe2_rcms_info *rcms_info    = info->rcms_info;
	struct sxe2_rcms_fpt_entry *fpte    = info->fpte;
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);

	if (!fpte->valid) {
		ret = sxe2_rcms_add_fpt_entry(dev, rcms_info, idx->fpte_idx,
					      SXE2_RCMS_FPT_TYPE_FIRST);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pbl:build second type table add fpte %u err ret=%d\n",
				idx->fpte_idx, ret);
			goto end;
		}
		pble_rsrc->fpte_indexes[pble_rsrc->add_fpte_cnt] =
			(u16)idx->fpte_idx;
		pble_rsrc->add_fpte_cnt++;
		fpte->valid = true;
		pble_rsrc->second_type_fpte_cnt++;
	}

end:
	return ret;
}

int sxe2_pbl_build_third_type_table(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				    struct sxe2_pbl_add_page_info *info)
{
	int ret				 = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	 = pble_rsrc->dev;
	struct sxe2_rcms_fpt_entry *fpte = info->fpte;
	struct sxe2_rcms_spt_entry *spte;
	struct sxe2_rcms_info *rcms_info = info->rcms_info;
	u32 fpte_idx			 = info->idx_info.fpte_idx;
	u32 rel_spte_idx		 = info->idx_info.rel_spte_idx;
	u32 spte_idx			 = info->idx_info.spte_idx;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!fpte->valid) {
		ret = sxe2_rcms_add_fpt_entry(dev, rcms_info, fpte_idx,
					      SXE2_RCMS_FPT_TYPE_SECOND);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pbl:build third type table add fpte err ret=%d\n",
				ret);
			goto end;
		}
	}

	info->start_liner_addr += (info->pages << SXE2_PBL_CP_PBLE_CNT_SHIFT)
				  << SXE2_PBL_PBLE_SIZE_SHIFT;

	for (i = 0; i < info->pages; i++) {
		spte = &fpte->u.spt.spte[rel_spte_idx];
		if (!spte->valid) {
			ret = sxe2_rcms_add_spt_entry(dev, rcms_info, spte_idx);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"pbl:build third type table add fpte err ret=%d\n",
					ret);
				goto add_spte_err;
			}
			pble_rsrc->spte_indexes[pble_rsrc->add_spte_cnt] =
				spte_idx;
			pble_rsrc->add_spte_cnt++;
		}
		rel_spte_idx++;
		spte_idx++;
	}

	if (!fpte->valid) {
		pble_rsrc->fpte_indexes[pble_rsrc->add_fpte_cnt] =
			(u16)fpte_idx;
		pble_rsrc->add_fpte_cnt++;
		fpte->valid = true;
		pble_rsrc->third_type_fpte_cnt++;
	}
	goto end;
add_spte_err:
	for (i = 0; i < pble_rsrc->add_spte_cnt; i++) {
		spte_idx = pble_rsrc->spte_indexes[i];
		sxe2_rcms_remove_spt_entry(dev, rcms_info, spte_idx);
	}
	pble_rsrc->add_spte_cnt = 0;
	sxe2_rcms_remove_fpt_entry(dev, rcms_info, fpte_idx,
				   SXE2_RCMS_FPT_TYPE_SECOND);
end:
	return ret;
}

int sxe2_pbl_add_pble_prm(struct sxe2_pbl_pble_rsrc *pble_rsrc)
{
	int ret			      = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev = pble_rsrc->dev;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_pbl_add_page_info info;
	enum sxe2_rcms_fpt_entry_type fpte_type	 = SXE2_RCMS_FPT_TYPE_FIRST;
	struct sxe2_pbl_table_idx_info *idx_info = &info.idx_info;
	u32 pages;
	u32 spte_idx;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (pble_rsrc->unallocated_pble < SXE2_PBL_PBLE_CNT_IN_4K) {
		DRV_RDMA_LOG_DEV_ERR("pble:unallocated pble is not enough\n");
		ret = -ENOMEM;
		goto end;
	}
	rcms_info = dev->rcms_info;
	sxe2_pbl_get_index_info(pble_rsrc->alloc_pble_base_addr, idx_info);
	fpte = &rcms_info->fpt.fpte[idx_info->fpte_idx];
	pages = (idx_info->rel_spte_idx) ?
			(SXE2_RCMS_SPT_ENTRY_CNT - idx_info->rel_spte_idx) :
			SXE2_RCMS_SPT_ENTRY_CNT;
	pages		      = min(pages,
		    pble_rsrc->unallocated_pble / SXE2_PBL_PBLE_CNT_IN_4K);
	info.fpte	      = fpte;
	info.rcms_info	      = rcms_info;
	info.pages	      = pages;
	info.start_liner_addr = pble_rsrc->alloc_pble_base_addr;
	if (!fpte->valid)
		fpte_type = sxe2_pbl_get_type(pble_rsrc);
	else
		fpte_type = fpte->entry_type;

	DRV_RDMA_LOG_DEV_DEBUG("pbl:fpte index %u entry type=%u\n",
			       idx_info->fpte_idx, fpte_type);
	if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		ret = sxe2_pbl_build_second_type_table(pble_rsrc, &info);
		if (ret != SXE2_OK)
			goto end;
		else
			pble_rsrc->second_type_fpte_cnt++;
	} else {
		ret = sxe2_pbl_build_third_type_table(pble_rsrc, &info);
		if (ret != SXE2_OK)
			goto end;
		else
			pble_rsrc->third_type_fpte_cnt++;
	}

	if (dev->privileged && pble_rsrc->add_fpte_cnt) {
		ret = sxe2_rcms_update_fptes(dev, info.rcms_info,
					     &pble_rsrc->fpte_indexes[0],
					     pble_rsrc->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble:update fpte %u err ret=%d\n",
					     idx_info->fpte_idx, ret);
			goto update_fpte_err;
		}
	} else if (!dev->privileged && pble_rsrc->add_fpte_cnt) {
		ret = sxe2_rcms_vf_update_fptes(dev, info.rcms_info,
						&pble_rsrc->fpte_indexes[0],
						pble_rsrc->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"pble:vf update fpte %u err ret=%d\n",
				idx_info->fpte_idx, ret);
			goto update_fpte_err;
		}
	}

	pble_rsrc->add_fpte_cnt = 0;
	pble_rsrc->add_spte_cnt = 0;

	goto end;
update_fpte_err:
	if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		fpte = &rcms_info->fpt.fpte[idx_info->fpte_idx];
		fpte->u.cp.use_cnt--;
		sxe2_rcms_remove_fpt_entry(dev, rcms_info, idx_info->fpte_idx,
					   SXE2_RCMS_FPT_TYPE_FIRST);
		pble_rsrc->add_fpte_cnt = 0;
	} else if (fpte_type == SXE2_RCMS_FPT_TYPE_SECOND) {
		for (i = 0; i < pble_rsrc->add_spte_cnt; i++) {
			spte_idx = pble_rsrc->spte_indexes[i];
			sxe2_rcms_remove_spt_entry(dev, rcms_info, spte_idx);
		}
		pble_rsrc->add_spte_cnt = 0;
		sxe2_rcms_remove_fpt_entry(dev, rcms_info, idx_info->fpte_idx,
					   SXE2_RCMS_FPT_TYPE_SECOND);
		pble_rsrc->add_fpte_cnt = 0;
	}
end:
	return ret;
}

static void sxe2_pbl_get_pble_fpte_range(u64 pble_liner_addr, u32 pble_cnt,
					 u32 *fpte_idx, u32 *fpte_lmt)
{
	u64 liner_addr_lmt;

	*fpte_idx      = (u32)FPT_INDEX_GET(pble_liner_addr);
	liner_addr_lmt = pble_liner_addr + pble_cnt * SXE2_PBL_PBLE_SIZE;
	*fpte_lmt      = (u32)FPT_INDEX_GET((liner_addr_lmt - 1));
	*fpte_lmt += 1;

}

static void sxe2_pbl_get_pble_spte_range(u64 pble_liner_addr, u32 pble_cnt,
					 u32 *spte_idx, u32 *spte_lmt)
{
	u64 liner_addr_lmt;

	*spte_idx      = (u32)SPT_INDEX_GET(pble_liner_addr);
	liner_addr_lmt = pble_liner_addr + pble_cnt * SXE2_PBL_PBLE_SIZE;
	*spte_lmt      = (u32)SPT_INDEX_GET((liner_addr_lmt - 1));
	*spte_lmt += 1;

}

int sxe2_pbl_add_second_type_table(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info)
{
	int ret				 = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	 = pble_rsrc->dev;
	struct sxe2_rcms_info *rcms_info = dev->rcms_info;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_pbl_add_page_info info = {};
	u32 fpte_idx;
	u32 fpte_lmt;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	sxe2_pbl_get_pble_fpte_range(pble_alloc_info->pble_info.liner_addr,
				     pble_alloc_info->total_pble_cnt, &fpte_idx,
				     &fpte_lmt);
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:add second table fpte idx=%u fpte lmt=%u\n", fpte_idx,
		fpte_lmt);
	for (i = fpte_idx; i < fpte_lmt; i++) {
		fpte		       = &rcms_info->fpt.fpte[i];
		info.fpte	       = fpte;
		info.rcms_info	       = rcms_info;
		info.idx_info.fpte_idx = i;
		ret = sxe2_pbl_build_second_type_table(pble_rsrc, &info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:fpte %u build second type table err ret=%d\n",
				i, ret);
			goto end;
		}
	}
	if (pble_rsrc->add_fpte_cnt > 0) {
		ret = sxe2_rcms_update_fptes(dev, info.rcms_info,
					     &pble_rsrc->fpte_indexes[0],
					     pble_rsrc->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble:update fpte err ret=%d\n",
					     ret);
			goto update_fpte_err;
		}
		pble_rsrc->add_fpte_cnt = 0;
	}
	goto end;

update_fpte_err:
	while (pble_rsrc->add_fpte_cnt) {
		pble_rsrc->add_fpte_cnt--;
		fpte = &rcms_info->fpt.fpte[pble_rsrc->fpte_indexes
						    [pble_rsrc->add_fpte_cnt]];
		fpte->u.cp.use_cnt--;
		sxe2_rcms_remove_fpt_entry(
			dev, rcms_info,
			pble_rsrc->fpte_indexes[pble_rsrc->add_fpte_cnt],
			SXE2_RCMS_FPT_TYPE_FIRST);
	}

end:
	return ret;
}

int sxe2_pbl_add_third_type_table(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info)
{
	int ret				 = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	 = pble_rsrc->dev;
	struct sxe2_rcms_info *rcms_info = dev->rcms_info;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_pbl_add_page_info info = {};
	u32 fpte_idx, fpte_lmt;
	u32 spte_idx, spte_lmt;
	u32 spte_idx_range = 0;
	u32 spte_lmt_range = 0;
	u32 i, j;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	sxe2_pbl_get_pble_fpte_range(pble_alloc_info->pble_info.liner_addr,
				     pble_alloc_info->total_pble_cnt, &fpte_idx,
				     &fpte_lmt);
	sxe2_pbl_get_pble_spte_range(pble_alloc_info->pble_info.liner_addr,
				     pble_alloc_info->total_pble_cnt, &spte_idx,
				     &spte_lmt);
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:add third type table fpte idx=%u fpte lmt=%u spte idx=%u spte lmt=%u\n",
		fpte_idx, fpte_lmt, spte_idx, spte_lmt);

	info.start_liner_addr = pble_alloc_info->pble_info.liner_addr;
	for (i = fpte_idx; i < fpte_lmt; i++) {
		fpte = &rcms_info->fpt.fpte[i];
		if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST)
			continue;
		info.fpte	       = fpte;
		info.rcms_info	       = rcms_info;
		info.idx_info.fpte_idx = i;
		spte_idx_range = max(spte_idx, i * SXE2_RCMS_SPT_ENTRY_CNT);
		spte_lmt_range =
			min(spte_lmt, (i + 1) * SXE2_RCMS_SPT_ENTRY_CNT);
		info.idx_info.spte_idx = spte_idx_range;
		info.idx_info.rel_spte_idx =
			REL_SPTE_INDEX_GET(info.idx_info.spte_idx);
		info.pages = spte_lmt_range - spte_idx_range;
		ret = sxe2_pbl_build_third_type_table(pble_rsrc, &info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:fpte %u build third type table err ret=%d\n",
				i, ret);
			goto end;
		}
		pble_rsrc->add_spte_cnt = 0;
	}

	if (dev->privileged && pble_rsrc->add_fpte_cnt) {
		ret = sxe2_rcms_update_fptes(dev, info.rcms_info,
					     &pble_rsrc->fpte_indexes[0],
					     pble_rsrc->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble:update fpte err ret=%d\n",
					     ret);
			goto update_fpte_err;
		}
	} else if (!dev->privileged && pble_rsrc->add_fpte_cnt) {
		ret = sxe2_rcms_vf_update_fptes(dev, info.rcms_info,
						&pble_rsrc->fpte_indexes[0],
						pble_rsrc->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"pble:vf update fpte err ret=%d\n", ret);
			goto update_fpte_err;
		}
	}

	pble_rsrc->add_fpte_cnt = 0;

	goto end;

update_fpte_err:
	for (j = 0; j < pble_rsrc->add_fpte_cnt; j++) {
		i	       = (u32)pble_rsrc->fpte_indexes[j];
		fpte	       = &rcms_info->fpt.fpte[i];
		fpte->valid    = false;
		spte_idx_range = max(spte_idx, i * SXE2_RCMS_SPT_ENTRY_CNT);
		spte_lmt_range =
			min(spte_lmt, (i + 1) * SXE2_RCMS_SPT_ENTRY_CNT);
		j = spte_lmt_range;
		while (j > spte_idx_range) {
			j--;
			sxe2_rcms_remove_spt_entry(dev, rcms_info, j);
		}
		sxe2_rcms_remove_fpt_entry(dev, rcms_info, i,
					   SXE2_RCMS_FPT_TYPE_SECOND);
	}
	pble_rsrc->add_fpte_cnt = 0;
end:
	return ret;
}

int sxe2_pbl_alloc_pble_idx(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			    struct sxe2_pbl_pble_alloc_info *pble_alloc_info,
			    u32 pble_cnt)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 order			  = 0;
	u32 real_pble_cnt;
	u64 pbl_seg_idx;
	u64 pbl_liner_addr;
	u32 i;

	pbl_liner_addr = pble_rsrc->alloc_pble_base_addr;
	for (order = 0, i = SXE2_PBL_MIN_ALLOC_PBLE; i < pble_cnt; i <<= 1)
		order++;

	ret = sxe2_pbl_buddy_alloc(&pble_rsrc->buddy, order, &pbl_seg_idx,
				   &real_pble_cnt);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("pble:buddy alloc pble %u err ret=%d\n",
				     pble_cnt, ret);
		goto end;
	}
	pbl_liner_addr +=
		pbl_seg_idx * SXE2_PBL_MIN_ALLOC_PBLE * SXE2_PBL_PBLE_SIZE;
	pble_alloc_info->pble_info.liner_addr = pbl_liner_addr;
	pble_alloc_info->pble_info.pble_idx =
		sxe2_pbl_liner_addr_to_idx(pble_rsrc, pbl_liner_addr);
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:buddy alloc pble needed cnt=%u\n"
		"\trel cnt=%u pble liner addr=0x%llx pble idx=%u\n",
		pble_cnt, real_pble_cnt, pbl_liner_addr,
		pble_alloc_info->pble_info.pble_idx);
	pble_alloc_info->total_pble_cnt = real_pble_cnt;

end:
	return ret;
}

static int
sxe2_pbl_alloc_first_type_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			       struct sxe2_pbl_pble_alloc_info *pble_alloc_info,
			       u32 pble_cnt)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 bit_idx;
	u64 start_fpte_idx;

	mutex_lock(&pble_rsrc->pble_mutex_lock);
	if (pble_cnt > pble_rsrc->unallocated_first_type_fpte_cnt) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:need first type pble not enough pble cnt=%u unallocated cnt=%u\n",
			pble_cnt, pble_rsrc->unallocated_first_type_fpte_cnt);
		ret = -ENOMEM;
		goto end;
	}

	ret = sxe2_pbl_first_page_bitmap_alloc(&pble_rsrc->first_page_bitmap,
					       pble_cnt, &bit_idx);
	if (ret != SXE2_OK)
		goto end;

	start_fpte_idx = bit_idx + pble_rsrc->first_page_bitmap.first_fpte_idx;
	pble_alloc_info->total_pble_cnt	  = pble_cnt;
	pble_alloc_info->pbl_mode.mr_mode = MR_TABLE_FIRST_MODE;
	pble_alloc_info->pbl_index =
		SXE2_PBL_FPTE_IDX_TO_PBL_IDX(start_fpte_idx);
	pble_alloc_info->pble_info.liner_addr = pble_alloc_info->pbl_index;
	pble_alloc_info->pble_info.pble_idx   = (u32)start_fpte_idx;
	pble_rsrc->unallocated_first_type_fpte_cnt -= pble_cnt;
	pble_rsrc->allocated_first_type_fpte_cnt += pble_cnt;
end:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
	return ret;
}

int sxe2_pbl_alloc_second_type_pble(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info, u32 pble_cnt,
	enum sxe2_pbl_obj_type obj_type)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if ((obj_type == PBL_OBJ_QP || obj_type == PBL_OBJ_SRQ) &&
	    (pble_cnt > SXE2_PBL_2MB_PAGE_PBLE_CNT)) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:obj %u alloc pble cross page pble cnt=%u\n",
			obj_type, pble_cnt);
		ret = -EINVAL;
		goto end;
	}
	mutex_lock(&pble_rsrc->pble_mutex_lock);
	ret = sxe2_pbl_alloc_pble_idx(pble_rsrc, pble_alloc_info, pble_cnt);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:obj %u pble %u alloc pble idx err ret=%d\n",
			obj_type, pble_cnt, ret);
		goto end;
	}
	ret = sxe2_pbl_add_second_type_table(pble_rsrc, pble_alloc_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("pble:obj %u add second type err ret=%d\n",
				     obj_type, ret);
		goto end;
	}
	pble_rsrc->unallocated_pble -= pble_alloc_info->total_pble_cnt;
	pble_rsrc->allocated_pbles += pble_alloc_info->total_pble_cnt;
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:obj %u needed pble cnt=%u rel alloc pble cnt=%u unallocated pble cnt=%u\n",
		obj_type, pble_cnt, pble_alloc_info->total_pble_cnt,
		pble_rsrc->unallocated_pble);
	if ((obj_type == PBL_OBJ_QP || obj_type == PBL_OBJ_SRQ ||
	     obj_type == PBL_OBJ_CQ || obj_type == PBL_OBJ_EQ) &&
	    pble_cnt <= SXE2_PBL_2MB_PAGE_PBLE_CNT) {
		pble_alloc_info->pbl_mode.mode = QP_SRQ_PA_SECOND_MODE;
		ret			       = sxe2_pbl_liner_addr_to_pble_pa(
			   pble_rsrc, pble_alloc_info->pble_info.liner_addr,
			   &pble_alloc_info->pbl_index);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa err ret=%d\n", ret);
			goto liner_to_pa_err;
		}
	} else if (obj_type == PBL_OBJ_CQ || obj_type == PBL_OBJ_EQ) {
		pble_alloc_info->pbl_mode.cq_eq_mode = CQ_EQ_TABLE_SECOND_MODE;
		pble_alloc_info->pbl_index =
			pble_alloc_info->pble_info.liner_addr;
	} else if (obj_type == PBL_OBJ_MR) {
		pble_alloc_info->pbl_mode.mr_mode = MR_TABLE_SECOND_MODE;
		pble_alloc_info->pbl_index =
			pble_alloc_info->pble_info.liner_addr;
	}
	DRV_RDMA_LOG_DEV_DEBUG("pble:obj %u pbl mode %u pbl index 0x%llx\n",
			       obj_type, pble_alloc_info->pbl_mode.mode,
			       pble_alloc_info->pbl_index);
	goto end;
liner_to_pa_err:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
	sxe2_pbl_free_pble(pble_rsrc, pble_alloc_info->pble_info.liner_addr,
			   pble_cnt, false);
	return ret;
end:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
	return ret;
}

int sxe2_pbl_alloc_third_type_pble(
	struct sxe2_pbl_pble_rsrc *pble_rsrc,
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info, u32 pble_cnt,
	enum sxe2_pbl_obj_type obj_type)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if ((obj_type == PBL_OBJ_QP || obj_type == PBL_OBJ_SRQ) &&
	    (pble_cnt > SXE2_PBL_4KB_PAGE_PBLE_CNT)) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:obj %u alloc pble cross page pble cnt=%u\n",
			obj_type, pble_cnt);
		ret = -EINVAL;
		goto end;
	}
	mutex_lock(&pble_rsrc->pble_mutex_lock);
	ret = sxe2_pbl_alloc_pble_idx(pble_rsrc, pble_alloc_info, pble_cnt);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:obj %u pble %u alloc pble idx err ret=%d\n",
			obj_type, pble_cnt, ret);
		goto end;
	}
	ret = sxe2_pbl_add_third_type_table(pble_rsrc, pble_alloc_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("pble:obj %u add second type err ret=%d\n",
				     obj_type, ret);
		goto end;
	}

	pble_rsrc->unallocated_pble -= pble_alloc_info->total_pble_cnt;
	pble_rsrc->allocated_pbles += pble_alloc_info->total_pble_cnt;

	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:obj %u needed pble=%u rel alloc pble=%u\n"
		"\talloced pble=%u unallocated pble=%u\n",
		obj_type, pble_cnt, pble_alloc_info->total_pble_cnt,
		pble_rsrc->allocated_pbles, pble_rsrc->unallocated_pble);
	if ((obj_type == PBL_OBJ_QP || obj_type == PBL_OBJ_SRQ ||
	     obj_type == PBL_OBJ_CQ || obj_type == PBL_OBJ_EQ) &&
	    pble_cnt <= SXE2_PBL_4KB_PAGE_PBLE_CNT) {
		pble_alloc_info->pbl_mode.mode = QP_SRQ_PA_SECOND_MODE;
		ret = sxe2_pbl_liner_addr_to_pble_pa(
			pble_rsrc, pble_alloc_info->pble_info.liner_addr,
			&pble_alloc_info->pbl_index);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:liner addr to pble pa err ret=%d\n", ret);
			goto liner_to_pa_err;
		}
	} else if (obj_type == PBL_OBJ_CQ || obj_type == PBL_OBJ_EQ) {
		pble_alloc_info->pbl_mode.cq_eq_mode = CQ_EQ_TABLE_THIRD_MODE;
		pble_alloc_info->pbl_index =
			pble_alloc_info->pble_info.liner_addr;
	} else if (obj_type == PBL_OBJ_MR) {
		pble_alloc_info->pbl_mode.mr_mode = MR_TABLE_THIRD_MODE;
		pble_alloc_info->pbl_index =
			pble_alloc_info->pble_info.liner_addr;
	}
	DRV_RDMA_LOG_DEV_DEBUG("pble:obj %u pbl mode %u pbl index 0x%llx\n",
			       obj_type, pble_alloc_info->pbl_mode.mode,
			       pble_alloc_info->pbl_index);
	goto end;
liner_to_pa_err:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
	sxe2_pbl_free_pble(pble_rsrc, pble_alloc_info->pble_info.liner_addr,
			   pble_cnt, false);
	return ret;
end:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
	return ret;
}

int sxe2_pbl_set_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx, u64 page_pa,
		      u16 fn_id)
{
	int ret						     = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev		     = to_rdmadev(dev);
	struct sxe2_rcms_update_fptes_info *update_fpte_info = NULL;

	update_fpte_info = kzalloc(
		sizeof(*update_fpte_info), GFP_KERNEL);
	if (!update_fpte_info) {
		DRV_RDMA_LOG_DEV_ERR("pble:update fpte info alloc err\n");
		ret = -ENOMEM;
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:func id %u set pble fpte idx=%u page pa=%llx\n", fn_id,
		fpte_idx, page_pa);
	update_fpte_info->cnt	     = 1;
	update_fpte_info->rcms_fn_id = fn_id;
	update_fpte_info->entry[0].data =
		page_pa | FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_TYPE, (s64)1) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_VALID, (s64)1);
	update_fpte_info->entry[0].cmd = fpte_idx;

	ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"pble:func id %u mq update fpte err ret=%d\n", fn_id,
			ret);
	}

	kfree(update_fpte_info);
end:
	return ret;
}

int sxe2_pbl_clear_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
			u32 pble_cnt, u16 fn_id)
{
	int ret						     = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev		     = to_rdmadev(dev);
	struct sxe2_rcms_update_fptes_info *update_fpte_info = NULL;
	u32 i;

	update_fpte_info = kzalloc(
		sizeof(*update_fpte_info), GFP_KERNEL);
	if (!update_fpte_info) {
		DRV_RDMA_LOG_DEV_ERR("pble:update fpte info alloc err\n");
		ret = -ENOMEM;
		goto end;
	}

	update_fpte_info->cnt	     = 0;
	update_fpte_info->rcms_fn_id = fn_id;

	for (i = 0; i < pble_cnt; i++) {
		update_fpte_info->entry[update_fpte_info->cnt].data =
			FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_TYPE, (s64)1) |
			FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_VALID, (s64)0);
		update_fpte_info->entry[update_fpte_info->cnt].cmd =
			fpte_idx + i;
		DRV_RDMA_LOG_DEV_DEBUG("pble:func id %u clear fpte idx=%u\n",
				       fn_id, fpte_idx + i);
		update_fpte_info->cnt++;

		if (update_fpte_info->cnt ==
		    SXE2_RCMS_MAX_UPDATE_FPTE_ENTRIES) {
			ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"pble:func id %u mq update fpte err ret=%d\n",
					fn_id, ret);
				goto end;
			}
			update_fpte_info->cnt = 0;
		}
	}

	if (update_fpte_info->cnt) {
		ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:func id %u mq update fpte err ret=%d\n",
				fn_id, ret);
		}
	}

	kfree(update_fpte_info);
end:
	return ret;
}

static int sxe2_pbl_first_type_set_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
					u64 pble_liner_addr, u64 page_pa)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 fpte_idx;

	fpte_idx = SXE2_PBL_PBL_IDX_TO_FPTE_IDX(pble_liner_addr);
	if (fpte_idx < pble_rsrc->first_page_bitmap.first_fpte_idx ||
	    fpte_idx > (pble_rsrc->first_page_bitmap.first_fpte_idx +
			pble_rsrc->first_page_bitmap.max_fpte_cnt)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"pble:first type set pble fpte idx err fpte idx=%u\n",
			fpte_idx);
		goto end;
	}

	if (!dev->privileged) {
		ret = sxe2_vchnl_req_set_pbl_fpte(dev, fpte_idx, page_pa);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble: vf set fpte err ret=%d\n",
					     ret);
		}
		goto end;
	}

	ret = sxe2_pbl_set_fpte(dev, fpte_idx, page_pa,
				dev->rcms_info->rcms_fn_id);
	if (ret != SXE2_OK)
		DRV_RDMA_LOG_DEV_ERR("pble: set fpte err ret=%d\n", ret);

end:
	return ret;
}

static void sxe2_pbl_first_type_free_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
					  u64 pble_liner_addr, u32 pble_cnt)
{
	int ret = SXE2_OK;
	u32 fpte_idx;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	fpte_idx = SXE2_PBL_PBL_IDX_TO_FPTE_IDX(pble_liner_addr);

	if (!dev->privileged) {
		ret = sxe2_vchnl_req_clear_pbl_fpte(dev, fpte_idx, pble_cnt);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble: vf clear fpte err ret=%d\n",
					     ret);
		}
	} else {
		ret = sxe2_pbl_clear_fpte(dev, fpte_idx, pble_cnt,
					  dev->rcms_info->rcms_fn_id);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("pble: clear fpte err ret=%d\n",
					     ret);
		}
	}
	sxe2_pbl_first_page_bitmap_free(
		&pble_rsrc->first_page_bitmap,
		(fpte_idx - pble_rsrc->first_page_bitmap.first_fpte_idx),
		pble_cnt);

	pble_rsrc->allocated_first_type_fpte_cnt -= pble_cnt;
	pble_rsrc->unallocated_first_type_fpte_cnt += pble_cnt;

}

int sxe2_pbl_set_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc, u64 pble_liner_addr,
		      u64 page_pa, bool firt_type_flag)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u64 *pble_va;

	if (firt_type_flag) {
		ret = sxe2_pbl_first_type_set_pble(pble_rsrc, pble_liner_addr,
						   page_pa);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:set first type pble err ret=%d\n",
				ret);
		}
		goto end;
	}

	ret = sxe2_pbl_liner_addr_to_pble_va(pble_rsrc, pble_liner_addr,
					     &pble_va);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("pble:liner addr to pble pa err ret=%d\n",
				     ret);
		goto end;
	}
	memcpy(pble_va, &page_pa, sizeof(*pble_va));
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:set pble liner addr=0x%llx pble va=%p page pa=0x%llx\n",
		pble_liner_addr, pble_va, *pble_va);
end:
	return ret;
}

int sxe2_pbl_get_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
		      struct sxe2_pbl_pble_alloc_info *pble_alloc_info,
		      u32 pble_cnt, enum sxe2_pbl_obj_type obj_type)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	if (pble_cnt == 0) {
		DRV_RDMA_LOG_DEV_ERR("pble:obj %u alloc pble cnt is 0\n",
				     obj_type);
		goto end;
	}
	pble_alloc_info->needed_pble_cnt = pble_cnt;

	if (obj_type == PBL_OBJ_MR && pble_alloc_info->mr_first_page_flags) {
		ret = sxe2_pbl_alloc_first_type_pble(pble_rsrc, pble_alloc_info,
						     pble_cnt);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pble:obj %u alloc first type pble err ret=%d\n",
				obj_type, ret);
		}
		goto end;
	}

	if (pble_rsrc->init_mode == PBL_SECOND_PAGE_TABLE) {
		ret = sxe2_pbl_alloc_second_type_pble(
			pble_rsrc, pble_alloc_info, pble_cnt, obj_type);
		if (ret != SXE2_OK && rdma_func->rcms_mode.pbl_mode ==
					      SXE2_PBL_SECOND_INIT_MODE) {
			goto end;
		}
	} else {
		ret = sxe2_pbl_alloc_third_type_pble(pble_rsrc, pble_alloc_info,
						     pble_cnt, obj_type);
	}
end:
	return ret;
}

void sxe2_pbl_free_pble(struct sxe2_pbl_pble_rsrc *pble_rsrc,
			u64 pble_liner_addr, u32 pble_cnt, bool firt_type_flag)
{
	struct sxe2_rdma_ctx_dev *dev	  = pble_rsrc->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 order			  = 0;
	u64 i;
	u64 pble_seg_idx;
	u32 total_free_pble_cnt;

	if (pble_cnt == 0) {
		DRV_RDMA_LOG_DEV_ERR("pble:free pble cnt is 0\n");
		return;
	}
	mutex_lock(&pble_rsrc->pble_mutex_lock);
	if (firt_type_flag) {
		sxe2_pbl_first_type_free_pble(pble_rsrc, pble_liner_addr,
					      pble_cnt);
		goto end;
	}

	pble_seg_idx = ((pble_liner_addr - pble_rsrc->alloc_pble_base_addr) /
			SXE2_PBL_MIN_ALLOC_PBLE) /
		       SXE2_PBL_PBLE_SIZE;
	for (order = 0, i = SXE2_PBL_MIN_ALLOC_PBLE; i < pble_cnt; i <<= 1)
		++order;

	sxe2_pbl_buddy_free(&pble_rsrc->buddy, pble_seg_idx, order);

	total_free_pble_cnt = 1 << order;
	pble_rsrc->unallocated_pble += total_free_pble_cnt;
	pble_rsrc->allocated_pbles -= total_free_pble_cnt;
	DRV_RDMA_LOG_DEV_DEBUG(
		"pble:free pble liner addr=0x%llx pble cnt=%u total free cnt = 0x%x\n",
		pble_liner_addr, pble_cnt, total_free_pble_cnt);

end:
	mutex_unlock(&pble_rsrc->pble_mutex_lock);
}

int sxe2_pbl_init(struct sxe2_rdma_device *rdma_dev)
{
	s32 ret				     = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func    = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	     = &rdma_func->ctx_dev;
	struct sxe2_pbl_pble_rsrc *pble_rsrc = rdma_func->pble_rsrc;
	struct sxe2_rcms_info *rcms_info;
	u32 fpm_idx   = 0;
	u32 max_order = 0;
	u32 powerof2  = 1;

	DRV_RDMA_LOG_DEV_DEBUG("pbl:pbl init start\n");
	rcms_info = dev->rcms_info;
	if (rdma_func->rcms_mode.pbl_mode >= SXE2_PBL_INIT_MODE_MAX) {
		DRV_RDMA_LOG_DEV_ERR("pbl: init mode err init mode=%u\n",
				     rdma_func->rcms_mode.pbl_mode);
		ret = -EINVAL;
		goto end;
	}

	if (dev->privileged &&
	    rdma_func->rcms_mode.pbl_mode == SXE2_PBL_SECOND_INIT_MODE) {
		pble_rsrc->init_mode = PBL_SECOND_PAGE_TABLE;
	} else {
		pble_rsrc->init_mode = PBL_THIRD_PAGE_TABLE;
	}
	pble_rsrc->dev = dev;
	pble_rsrc->pble_base_addr =
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_PBLE].base;
	if (pble_rsrc->pble_base_addr & SXE2_PBL_4KB_PAGE_OFFSET) {
		fpm_idx =
			(SXE2_PBL_SPTE_CP_SIZE - ((pble_rsrc->pble_base_addr &
						   SXE2_PBL_4KB_PAGE_OFFSET) >>
						  SXE2_PBL_PBLE_SIZE_SHIFT));
	}

	pble_rsrc->unallocated_pble =
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt - fpm_idx;
	pble_rsrc->allocated_pbles	= 0;
	pble_rsrc->alloc_pble_base_addr = pble_rsrc->pble_base_addr +
					  (fpm_idx << SXE2_PBL_PBLE_SIZE_SHIFT);
	while (powerof2 <= pble_rsrc->unallocated_pble) {
		powerof2 *= 2;
		max_order++;
	}
	pble_rsrc->unallocated_pble = powerof2 / 2;
	max_order--;

	pble_rsrc->buddy.dev = dev;
	ret = sxe2_pbl_buddy_init(&pble_rsrc->buddy, max_order);
	if (ret != SXE2_OK)
		goto end;

	if (rcms_info->first_page_fpte) {
		pble_rsrc->first_page_en = true;
		pble_rsrc->unallocated_first_type_fpte_cnt =
			rcms_info->first_page_fpte;
		pble_rsrc->first_page_bitmap.dev = dev;
		ret = sxe2_pbl_first_page_bitmap_init(
			&pble_rsrc->first_page_bitmap);
		if (ret != SXE2_OK)
			goto end;
	} else {
		pble_rsrc->first_page_en = false;
	}

	mutex_init(&pble_rsrc->pble_mutex_lock);
	ret = sxe2_pbl_add_pble_prm(pble_rsrc);
	if (ret != SXE2_OK)
		goto add_pble_prm_err;

	DRV_RDMA_LOG_DEV_DEBUG("pbl:pbl init finish\n");
	goto end;

add_pble_prm_err:
	sxe2_pbl_buddy_cleanup(&pble_rsrc->buddy);
	kvfree(pble_rsrc->first_page_bitmap.fpte_bits);
	pble_rsrc->first_page_bitmap.fpte_bits = NULL;
end:
	return ret;
}

void sxe2_pbl_exit(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_pbl_pble_rsrc *pble_rsrc = rdma_dev->rdma_func->pble_rsrc;

	sxe2_pbl_buddy_cleanup(&pble_rsrc->buddy);
	kvfree(pble_rsrc->first_page_bitmap.fpte_bits);
	pble_rsrc->first_page_bitmap.fpte_bits = NULL;
}
