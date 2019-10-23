// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/sched.h>
#include "rde_data.h"
#include "rde.h"

static u32 rde_matrix_len(u8 alg_type, u8 cm_len)
{
	u32 len = 0;

	switch (alg_type) {
	case PQ_FLEXEC:
		len = RDE_PER_SRC_COEF_SIZE * cm_len;
		break;
	case MPCC:
		len = (RDE_PER_SRC_COEF_SIZE *
				RDE_PER_SRC_COEF_TIMES * cm_len);
		break;
	default:
		pr_err("[%s] err alg type.\n", __func__);
		break;
	}

	return len;
}

static int rde_sgl_src_scatterlist_release(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u32 num)
{
	u32 i;
	int ret;

	for (i = 0; i < num; i++) {
		if (req->src_record[i]) {
			ret = acc_sgl_phys_to_virt(pdev,
				(void *)req->src_record[i],
				rde_ctx->smmu_state);
			if (ret) {
				dev_err(&pdev->dev,
					"[%s]src[%d] fail.\n", __func__, i);
				return ret;
			}
		}
	}

	return 0;
}

static int rde_sgl_dst_scatterlist_release(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u32 num)
{
	u32 i;
	int ret;

	for (i = 0; i < num; i++) {
		if (req->dst_record[i]) {
			ret = acc_sgl_phys_to_virt(pdev,
				(void *)req->dst_record[i],
				rde_ctx->smmu_state);
			if (ret) {
				dev_err(&pdev->dev,
					"[%s]dst[%d] fail.\n", __func__, i);
				return ret;
			}
		}
	}

	return 0;
}

static void rde_pbuf_src_addr_unmap(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u32 num)
{
	u32 i;
	u32 gn_cnt;
	struct raid_ec_ctrl *udata = req->udata;

	if (!rde_ctx->smmu_state)
		return;

	for (i = 0; i < num; i++) {
		gn_cnt = RDE_GN_CNT(i) + i;
		if (req->src_addr->content[gn_cnt]) {
			acc_phys_to_virt(pdev,
				(dma_addr_t)req->src_addr->content[gn_cnt],
				(size_t)udata->data_len, rde_ctx->smmu_state);
		}
	}
}

static void rde_pbuf_dst_addr_unmap(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u32 num)
{
	u32 i;
	u32 gn_cnt;
	struct raid_ec_ctrl *udata = req->udata;

	if (!rde_ctx->smmu_state)
		return;

	for (i = 0; i < num; i++) {
		gn_cnt = RDE_GN_CNT(i) + i;
		if (req->dst_addr->content[gn_cnt]) {
			acc_phys_to_virt(pdev,
				(dma_addr_t)req->dst_addr->content[gn_cnt],
				(size_t)udata->data_len, rde_ctx->smmu_state);
		}
	}
}

static void rde_cm_addr_unmap(struct pci_dev *pdev,
	struct hisi_rde_sqe *bd, u8 alg_type,
	struct hisi_rde_ctx *rde_ctx)
{
	u32 matrix_len;

	if (!rde_ctx->smmu_state)
		return;

	matrix_len = rde_matrix_len(alg_type, (u8)bd->cm_len);
	if (bd->coef_matrix_addr && matrix_len)
		acc_phys_to_virt(pdev, (dma_addr_t)bd->coef_matrix_addr,
			(size_t)matrix_len, rde_ctx->smmu_state);
}

static void rde_bd_addr_release(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u8 buf_mode)
{
	int ret = 0;
	struct raid_ec_ctrl *udata = req->udata;
	u32 src_num = udata->src_num;
	u32 dst_num = udata->dst_num;

	if (buf_mode ==  PBUF) {
		rde_pbuf_src_addr_unmap(pdev, rde_ctx, req, src_num);
		rde_pbuf_dst_addr_unmap(pdev, rde_ctx, req, dst_num);
	} else if (buf_mode == SGL) {
		ret = rde_sgl_src_scatterlist_release(pdev,
			rde_ctx, req, src_num);
		if (ret)
			dev_err(&pdev->dev,
				"[%s]src release fail.\n", __func__);

		ret = rde_sgl_dst_scatterlist_release(pdev,
			rde_ctx, req, dst_num);
		if (ret)
			dev_err(&pdev->dev,
				"[%s]dst release fail.\n", __func__);
	}
}

static int rde_cm_len_check(struct device *dev, u8 alg_type, u8 cm_len)
{
	if (alg_type == MPCC) {
		if (unlikely(cm_len > RDE_MPCC_MAX_SRC_NUM)) {
			dev_err(dev,
				"error!mpcc cmlen should smaller than 17.\n");
			return -EINVAL;
		}
	} else if (alg_type == PQ_FLEXEC) {
		if (unlikely(cm_len > RDE_FLEXEC_MAX_SRC_NUM)) {
			dev_err(dev,
				"error!flexec cmlen should smaller than 32.\n");
			return -EINVAL;
		}
	} else {
		dev_err(dev, "no support alg_type.\n");
		return -EINVAL;
	}

	return 0;
}

static int rde_io_para_check(struct acc_ctx *ctx,
		struct raid_ec_ctrl *req,
		u8 op_type, u8 alg_type)
{
	struct hisi_rde_ctx *rde_ctx;

	if (unlikely(!ctx || !req || op_type >= ACC_OPT_RAID_BUTT)) {
		pr_err("[%s]invalid input para.\n", __func__);
		return -EINVAL;
	}

	rde_ctx = (struct hisi_rde_ctx *)ctx->inner;
	if (unlikely(!rde_ctx)) {
		pr_err("[%s]rde_ctx without init.\n", __func__);
		return -EIO;
	}

	if ((rde_ctx->addr_type == VA_FROM_HIGHMEM_ZONE &&
		req->buf_type != ACC_BUF_TYPE_PBUFFER) ||
		(rde_ctx->addr_type == VA_FROM_HIGHMEM_ZONE &&
		rde_ctx->smmu_state)) {
		dev_err(rde_ctx->dev, "error!invalid addr & buf type.\n");
		return -EINVAL;
	}

	if (unlikely(!req->input_block || !req->data_len)) {
		dev_err(rde_ctx->dev, "error!invalid input_block.\n");
		return -EINVAL;
	}

	if (unlikely(!req->src_data || !req->dst_data || !req->coe_matrix)) {
		dev_err(rde_ctx->dev, "error!input addr is NULL.\n");
		return -EFAULT;
	}

	return rde_cm_len_check(rde_ctx->dev, alg_type, req->cm_len);
}

static void src_dif_package(struct hisi_rde_msg *req)
{
	u32 i;
	u32 lba_info_cnt = 0;
	u32 chk_info_cnt = 0;
	u32 cur_cnt1 = 0;
	u32 cur_cnt2 = 0;
	struct raid_ec_ctrl *udata = req->udata;
	u8 grd = udata->src_dif.ctrl.verify.grd_verify_type;
	u8 ref = udata->src_dif.ctrl.verify.ref_verify_type;
	u32 num = udata->src_num;

	for (i = 0; i < num; i++) {
		chk_info_cnt = i / RDE_LBA_BLK + 1;
		lba_info_cnt = RDE_LBA_INFO_CNT(i);
		cur_cnt1 = (i / RDE_LBA_BLK) * RDE_LBA_DWORD_CNT;
		cur_cnt2 = chk_info_cnt + lba_info_cnt;
		req->src_tag_addr->content[cur_cnt1] |=
			((u64)(grd << DIF_CHK_GRD_CTRL_SHIFT | ref) <<
			(RDE_LBA_BLK * (i % RDE_LBA_BLK)));
		req->src_tag_addr->content[cur_cnt2] |=
			((u64)udata->src_dif.priv <<
			(DIF_LBA_SHIFT * RDE_LBA_SHIFT_MSK(i)));
	}
}

static void dst_dif_package(struct hisi_rde_msg *req)
{
	u32 i;
	struct dif_ctrl ctrl;
	struct raid_ec_ctrl *udata = req->udata;
	u32 num = udata->dst_num;

	ctrl = udata->dst_dif.ctrl;
	for (i = 0; i < num; i++) {
		req->dst_tag_addr->content[i] |=
			((u64)(ctrl.gen.page_layout_gen_type) <<
			DIF_GEN_PAD_CTRL_SHIFT);
		req->dst_tag_addr->content[i] |=
			((u64)(ctrl.gen.ref_gen_type) <<
			DIF_GEN_REF_CTRL_SHIFT);
		req->dst_tag_addr->content[i] |=
			((u64)(ctrl.gen.app_gen_type) <<
			DIF_GEN_APP_CTRL_SHIFT);
		req->dst_tag_addr->content[i] |=
			((u64)(ctrl.gen.ver_gen_type) <<
			DIF_GEN_VER_CTRL_SHIFT);
		req->dst_tag_addr->content[i] |=
			((u64)(ctrl.gen.grd_gen_type) <<
			DIF_GEN_GRD_CTRL_SHIFT);
		req->dst_tag_addr->content[i] |= (u64)udata->dst_dif.priv;
		req->dst_tag_addr->content[i] |=
			((u64)(udata->dst_dif.app) <<
			DIF_APP_TAG_SHIFT);
		req->dst_tag_addr->content[i] |=
			((u64)(udata->dst_dif.ver) <<
			DIF_VERSION_SHIFT);
	}
}

static int rde_disk_sgl_addr_translation(struct pci_dev *pdev,
	struct hisi_rde_ctx *rde_ctx, struct sgl_hw *sgl_addr,
	u64 *content, u64 *record)
{
	int ret;
	void *sg_head = NULL;

	switch (rde_ctx->addr_type) {
	case VA_FROM_NORMAL_DMA_ZONE:
		ret = acc_sgl_virt_to_phys(pdev, sgl_addr, &sg_head,
			rde_ctx->smmu_state);
		if (unlikely(ret))
			return ret;
		break;
	case PA_PASS_THROUGH:
		*content = (u64)sgl_addr;
		return 0;
	default:
		dev_err(rde_ctx->dev, "[%s] invalid addr type.\n", __func__);
		return -EINVAL;
	}

	*content = sg_dma_address((struct scatterlist *)sg_head);
	*record = (u64)sg_head;

	return 0;
}

static int sgl_src_addr_package(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u8 mode)
{
	int ret, r_ret;
	u32 i;
	u8 gn;
	u32 sgl_data;
	u32 gn_cnt, gn_flag, cur_cnt;
	struct raid_ec_ctrl *ctrl = req->udata;
	u32 num = ctrl->src_num;
	struct rde_sgl *sgl_src = (struct rde_sgl *)(ctrl->src_data);

	if (unlikely(!sgl_src->ctrl)) {
		dev_err(rde_ctx->dev, "[%s]sg_hw is NULL\n", __func__);
		return -EFAULT;
	}

	memset(&req->src_record[0], 0, num * sizeof(u64));
	for (i = 0; i < num; i++) {
		gn = (u8)(sgl_src->column) +
			((ACC_OPT_UPD ^ mode) ? 0 : (RDE_UPD_GN_FLAG &
			(sgl_src->parity << RDE_UPD_PARITY_SHIFT)));
		sgl_data = (sgl_src->buf_offset <<
			SGL_DATA_OFFSET_SHIFT) | (u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		req->src_addr->content[cur_cnt] |=
			((u64)sgl_data << RDE_GN_SHIFT(gn_flag));
		ret = rde_disk_sgl_addr_translation(pdev, rde_ctx,
			sgl_src->ctrl, &req->src_addr->content[gn_cnt],
			&req->src_record[i]);
		if (ret) {
			r_ret = rde_sgl_src_scatterlist_release(pdev,
				rde_ctx, req, i);
			if (r_ret)
				return r_ret;
			return ret;
		}

		sgl_src++;
	}

	return 0;
}

static int sgl_dst_addr_package(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req)
{
	int ret, r_ret;
	u32 i;
	u8 gn;
	u32 sgl_data;
	u32 gn_cnt, gn_flag, cur_cnt;
	struct raid_ec_ctrl *ctrl = req->udata;
	u32 num = ctrl->dst_num;
	struct rde_sgl *sgl_dst = (struct rde_sgl *)(ctrl->dst_data);

	if (unlikely(!sgl_dst->ctrl)) {
		dev_err(rde_ctx->dev, "[%s]dst sgl_addr->ctrl is NULL\n",
			__func__);
		return -EFAULT;
	}

	memset(&req->dst_record[0], 0, num * sizeof(u64));
	for (i = 0; i < num; i++) {
		gn = (u8)(sgl_dst->column);
		sgl_data = (sgl_dst->buf_offset <<
			SGL_DATA_OFFSET_SHIFT) | (u32)gn;
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		req->dst_addr->content[cur_cnt] |= ((u64)sgl_data <<
			RDE_GN_SHIFT(gn_flag));
		ret = rde_disk_sgl_addr_translation(pdev, rde_ctx,
			sgl_dst->ctrl, &req->dst_addr->content[gn_cnt],
			&req->dst_record[i]);
		if (ret) {
			r_ret = rde_sgl_dst_scatterlist_release(pdev,
				rde_ctx, req, i);
			if (r_ret)
				return r_ret;
			return ret;
		}

		sgl_dst++;
	}

	return 0;
}

static int rde_disk_pbuf_addr_translation(struct pci_dev *pdev,
	struct hisi_rde_ctx *rde_ctx, u64 *content, char *addr, u32 data_len)
{
	dma_addr_t pa = 0;

	switch (rde_ctx->addr_type) {
	case VA_FROM_NORMAL_DMA_ZONE:
		pa = acc_virt_to_phys(pdev, addr, (size_t)data_len,
				rde_ctx->smmu_state);
		break;
	case VA_FROM_HIGHMEM_ZONE:
		pa = acc_pfn_to_phys(addr);
		break;
	case PA_PASS_THROUGH:
		*content = (u64)addr;
		return 0;
	default:
		dev_err(rde_ctx->dev, "[%s] invalid addr type.\n", __func__);
		return -EINVAL;
	}

	if (unlikely(!pa)) {
		dev_err(rde_ctx->dev, "[%s] addr map fail.\n", __func__);
		return -EFAULT;
	}

	*content = pa;

	return 0;
}

static int pbuf_src_addr_package(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		u8 mode)
{
	u32 i;
	int ret;
	u8 gn;
	u32 gn_cnt, gn_flag, cur_cnt;
	struct raid_ec_ctrl *ctrl = req->udata;
	u32 data_len_nbytes = ctrl->data_len;
	u32 num = ctrl->src_num;
	struct rde_pbuf *pbuf_src = (struct rde_pbuf *)(ctrl->src_data);

	for (i = 0; i < num; i++) {
		gn = (u8)pbuf_src->column +
			((ACC_OPT_UPD ^ mode) ? 0 : (RDE_UPD_GN_FLAG &
			(pbuf_src->parity << RDE_UPD_PARITY_SHIFT)));
		gn_cnt = RDE_GN_CNT(i) + i;
		gn_flag = RDE_GN_FLAG(i);
		cur_cnt = gn_cnt - gn_flag;
		req->src_addr->content[cur_cnt] |= ((u64)gn <<
			RDE_GN_SHIFT(gn_flag));
		ret = rde_disk_pbuf_addr_translation(pdev, rde_ctx,
			&req->src_addr->content[gn_cnt],
			pbuf_src->pbuf, data_len_nbytes);
		if (ret) {
			rde_pbuf_src_addr_unmap(pdev, rde_ctx, req, i);
			return ret;
		}

		pbuf_src++;
	}

	return 0;
}

static int pbuf_dst_addr_package(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req)
{
	u32 i;
	int ret;
	u8  gf_coef;
	u32 gf_cnt, gf_flag, cur_cnt;
	struct raid_ec_ctrl *ctrl = req->udata;
	u32 num = ctrl->dst_num;
	u32 data_len_nbytes = ctrl->data_len;
	struct rde_pbuf *pbuf_dst = (struct rde_pbuf *)(ctrl->dst_data);

	for (i = 0; i < num; i++) {
		gf_coef = (u8)pbuf_dst->column;
		gf_cnt = RDE_GN_CNT(i) + i;
		gf_flag = RDE_GN_FLAG(i);
		cur_cnt = gf_cnt - gf_flag;
		req->dst_addr->content[cur_cnt] |= ((u64)gf_coef <<
			RDE_GN_SHIFT(gf_flag));
		ret = rde_disk_pbuf_addr_translation(pdev, rde_ctx,
			&req->dst_addr->content[gf_cnt],
			pbuf_dst->pbuf, data_len_nbytes);
		if (ret) {
			rde_pbuf_dst_addr_unmap(pdev, rde_ctx, req, i);
			return ret;
		}

		pbuf_dst++;
	}

	return 0;
}

static int hisi_rde_fill_addr_tlb(struct pci_dev *pdev,
		struct hisi_rde_ctx *rde_ctx,
		struct hisi_rde_msg *req,
		struct rde_type *type)
{
	int ret, r_ret;

	if (type->buf_mode == PBUF) {
		ret = pbuf_src_addr_package(pdev, rde_ctx, req, type->alg_mode);
		if (ret) {
			dev_err(&pdev->dev, "pbuf src addr package fail.\n");
			return ret;
		}
		ret = pbuf_dst_addr_package(pdev, rde_ctx, req);
		if (ret) {
			dev_err(&pdev->dev, "pbuf dst addr package fail.\n");
			rde_pbuf_src_addr_unmap(pdev, rde_ctx, req,
				req->udata->src_num);
			return ret;
		}
	} else if (type->buf_mode == SGL) {
		ret = sgl_src_addr_package(pdev, rde_ctx, req, type->alg_mode);
		if (ret) {
			dev_err(&pdev->dev, "sgl src addr package fail.\n");
			return ret;
		}
		ret = sgl_dst_addr_package(pdev, rde_ctx, req);
		if (ret) {
			dev_err(&pdev->dev, "sgl dst addr package fail.\n");
			r_ret = rde_sgl_src_scatterlist_release(pdev, rde_ctx,
				req, req->udata->src_num);
			if (r_ret)
				return r_ret;
			return ret;
		}
	} else {
		dev_err(&pdev->dev, "[%s] invalid buf type.\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int rde_cm_addr_translation(struct pci_dev *pdev,
	struct hisi_rde_ctx *rde_ctx, struct raid_ec_ctrl *ctrl,
	struct hisi_rde_sqe *bd, u8 alg_type)
{
	u32 matrix_len = 0;
	dma_addr_t pa = 0;

	if (rde_ctx->addr_type != PA_PASS_THROUGH) {
		matrix_len = rde_matrix_len(alg_type, ctrl->cm_len);
		pa = acc_virt_to_phys(pdev, ctrl->coe_matrix,
			(size_t)matrix_len, rde_ctx->smmu_state);
		if (unlikely(!pa)) {
			dev_err(rde_ctx->dev,
				"[%s]coe_matrix virt to phys fail.\n",
				__func__);
			return -EFAULT;
		}
		bd->coef_matrix_addr = pa;
	} else
		bd->coef_matrix_addr = (u64)ctrl->coe_matrix;

	return 0;
}

int hisi_rde_fill_sqe(struct hisi_rde_ctx *rde_ctx, struct hisi_rde_msg *req,
	struct rde_type *type)
{
	int ret;
	struct raid_ec_ctrl *ctrl = req->udata;
	struct hisi_rde_sqe *bd = &req->sqe;
	struct pci_dev *pdev = rde_ctx->qp->qm->pdev;
	u32 q_id = rde_ctx->qp->qp_id;

	memset(bd, 0, sizeof(struct hisi_rde_sqe));
	bd->op_tag = q_id * rde_ctx->session_num + req->req_id;
	bd->alg_blk_size = ctrl->alg_blk_size;
	bd->cm_type = (type->alg_mode ==
		ACC_OPT_RCT) ? CM_DECODE : CM_ENCODE;
	bd->cm_le =  ctrl->cm_load;
	bd->abort = NO_ABORT;
	bd->src_nblks = ctrl->src_num;
	bd->dst_nblks = ctrl->dst_num;
	if (type->alg_mode == ACC_OPT_VLD) {
		bd->chk_dst_ref_ctrl =
			ctrl->dst_dif.ctrl.verify.ref_verify_type;
		bd->chk_dst_grd_ctrl =
			ctrl->dst_dif.ctrl.verify.grd_verify_type;
	}
	bd->op_type = type->alg_mode | type->mem_mode |
			type->buf_mode | type->alg_type;
	bd->block_size = ctrl->block_size;
	bd->page_pad_type = ctrl->dst_dif.ctrl.gen.page_layout_pad_type;
	bd->dif_type = (ctrl->dst_dif.ctrl.gen.grd_gen_type) ?
		RDE_DIF : NO_RDE_DIF;
	bd->crciv_sel = CRCIV1;
	bd->crciv_en = CRCIV;
	bd->cm_len = ctrl->cm_len;
	bd->transfer_size = ctrl->input_block - 1;

	ret = rde_cm_addr_translation(pdev, rde_ctx, ctrl,
		bd, type->alg_type);
	if (ret)
		return ret;
	bd->src_addr = req->src_dma_addr;
	bd->dst_addr = req->dst_dma_addr;
	bd->src_tag_addr = req->src_tag_dma_addr;
	bd->dst_tag_addr = req->dst_tag_dma_addr;
	memset(req->src_addr, 0, sizeof(struct rde_src_tbl));
	memset(req->dst_addr, 0, sizeof(struct rde_dst_tbl));
	ret = hisi_rde_fill_addr_tlb(pdev, rde_ctx, req, type);
	if (ret) {
		if (rde_ctx->addr_type != PA_PASS_THROUGH)
			rde_cm_addr_unmap(pdev, bd, type->alg_type, rde_ctx);
		return ret;
	}

	memset(req->src_tag_addr, 0, sizeof(struct rde_src_tag_tbl));
	memset(req->dst_tag_addr, 0, sizeof(struct rde_dst_tag_tbl));
	if (bd->dif_type) {
		src_dif_package(req);
		dst_dif_package(req);
	}
#ifdef DEBUG
	rde_bd_dump(bd);
	rde_table_dump(req);
#endif
	return 0;
}

static int hisi_rde_alloc_req_id(struct hisi_rde_ctx *rde_ctx)
{
	int req_id;
	unsigned long flags;
	struct device *dev = rde_ctx->dev;

	spin_lock_irqsave(&rde_ctx->req_lock, flags);
	req_id = find_first_zero_bit(rde_ctx->req_bitmap, rde_ctx->session_num);
	if ((u32)req_id >= rde_ctx->session_num) {
		spin_unlock_irqrestore(&rde_ctx->req_lock, flags);
		dev_err(dev, "[%s]no free req id.\n", __func__);
		return -EBUSY;
	}
	set_bit(req_id, rde_ctx->req_bitmap);
	spin_unlock_irqrestore(&rde_ctx->req_lock, flags);
	dev_dbg(dev, "alloc_id is %d.\n", req_id);

	return req_id;
}

static void hisi_rde_free_req_id(struct hisi_rde_ctx *rde_ctx, int req_id)
{
	unsigned long flags;

	dev_dbg(rde_ctx->dev, "free_id is %d.\n", req_id);
	spin_lock_irqsave(&rde_ctx->req_lock, flags);
	clear_bit(req_id, rde_ctx->req_bitmap);
	spin_unlock_irqrestore(&rde_ctx->req_lock, flags);
}

static void rde_cb(struct hisi_qp *qp, void *resp)
{
	struct hisi_rde_sqe *wb_sqe = (struct hisi_rde_sqe *)resp;
	struct acc_ctx *ctx = qp->qp_ctx;
	struct hisi_rde_ctx *rde_ctx = (struct hisi_rde_ctx *)ctx->inner;
	u16 req_id = wb_sqe->op_tag % (rde_ctx->session_num);
	struct pci_dev *pdev = qp->qm->pdev;
	u8 alg_type = wb_sqe->op_type & RDE_ALG_TYPE_MSK;
	u8 buf_mode = wb_sqe->op_type & RDE_BUF_TYPE_MSK;
	struct raid_ec_ctrl *ctrl;
	u8 result;

	ctrl = rde_ctx->req_list[req_id].udata;
	result = wb_sqe->status;
	if (wb_sqe->status != RDE_TASK_DONE_STATUS) {
		dev_err(&pdev->dev, "task done flag is 0x%x, err status is 0x%x.\n",
			(wb_sqe->status >> RDE_DONE_SHIFT) & RDE_DONE_MSK,
			(wb_sqe->status) & RDE_STATUS_MSK);
		rde_bd_dump(wb_sqe);
	}

	if (ctx->cb) {
		if (rde_ctx->addr_type != PA_PASS_THROUGH) {
			rde_cm_addr_unmap(pdev, wb_sqe, alg_type, rde_ctx);
			rde_bd_addr_release(pdev, rde_ctx,
				&rde_ctx->req_list[req_id], buf_mode);
		}
		hisi_rde_free_req_id(rde_ctx, (int)req_id);

		ctx->cb((void *)ctx, (void *)ctrl,
			(int)(result & RDE_STATUS_MSK), ctrl->data_len);
	} else
		complete(&rde_ctx->req_list[req_id].completion);
}

int hisi_rde_io_proc(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
		u8 op_type, u8 alg_type, bool sync)
{
	int ret, id;
	struct hisi_rde_ctx *rde_ctx;
	struct hisi_qp *qp;
	struct pci_dev *pdev;
	struct hisi_rde_msg *req;
	struct rde_type type;
	unsigned long flags;

	ret = rde_io_para_check(ctx, ctrl, op_type, alg_type);
	if (ret)
		return ret;
	rde_ctx = (struct hisi_rde_ctx *)ctx->inner;
	qp = rde_ctx->qp;
	qp->req_cb = rde_cb;
	pdev = qp->qm->pdev;
	type.alg_mode = op_type;
	type.mem_mode = ctrl->mem_saving << RDE_MEM_SAVE_SHIFT;
	type.buf_mode = (u8)(ctrl->buf_type) << RDE_BUF_TYPE_SHIFT;
	type.alg_type = alg_type;

	id = hisi_rde_alloc_req_id(rde_ctx);
	if (id < 0)
		return id;
	req = &rde_ctx->req_list[id];
	req->req_id = (u32)id;
	req->udata = ctrl;
	init_completion(&req->completion);

	ret = hisi_rde_fill_sqe(rde_ctx, req, &type);
	if (ret) {
		dev_err(rde_ctx->dev, "[%s]bd package fail.\n", __func__);
		goto req_free;
	}

	spin_lock_irqsave(&rde_ctx->req_lock, flags);
	ret = hisi_qp_send(qp, &req->sqe);
	if (ret < 0) {
		spin_unlock_irqrestore(&rde_ctx->req_lock, flags);
		goto addr_unmap;
	}
	spin_unlock_irqrestore(&rde_ctx->req_lock, flags);

	if (!sync)
		return ret;

	if (wait_for_completion_timeout(&req->completion,
		msecs_to_jiffies(RDE_TASK_TMOUT_MS)) == 0) {
		dev_err(rde_ctx->dev, "sync mode task timeout.\n");
		ret = -ETIME;
	}

addr_unmap:
	if (rde_ctx->addr_type != PA_PASS_THROUGH) {
		rde_cm_addr_unmap(pdev, &req->sqe, type.alg_type, rde_ctx);
		rde_bd_addr_release(pdev, rde_ctx, req, type.buf_mode);
	}
req_free:
	hisi_rde_free_req_id(rde_ctx, id);
	return ret;
}

static int hisi_rde_create_qp(struct hisi_qm *qm, struct acc_ctx *ctx,
			      int alg_type, int req_type)
{
	struct hisi_qp *qp;
	struct hisi_rde_ctx *rde_ctx;
	int ret;

	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	qp->req_type = req_type;
	qp->qp_ctx = ctx;

	rde_ctx = (struct hisi_rde_ctx *)ctx->inner;
	rde_ctx->qp = qp;

	ret = hisi_qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_release_qp;

	return 0;

err_release_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static void hisi_rde_release_qp(struct hisi_rde_ctx *rde_ctx)
{
	hisi_qm_stop_qp(rde_ctx->qp);
	hisi_qm_release_qp(rde_ctx->qp);
}

static int hisi_rde_tbl_init(struct device *dev, struct hisi_rde_msg *req)
{
	req->src_addr = dma_alloc_coherent(dev,
		(size_t)sizeof(struct rde_src_tbl),
		&req->src_dma_addr, GFP_KERNEL);
	if (!req->src_addr) {
		dev_err(dev, "[%s]Fail to alloc rde_src_tlb.\n", __func__);
		return -ENOMEM;
	}

	req->dst_addr = dma_alloc_coherent(dev,
		(size_t)sizeof(struct rde_dst_tbl),
		&req->dst_dma_addr, GFP_KERNEL);
	if (!req->dst_addr) {
		dev_err(dev, "[%s]Fail to alloc rde_dst_tlb.\n", __func__);
		return -ENOMEM;
	}

	req->src_tag_addr = dma_alloc_coherent(dev,
		(size_t)sizeof(struct rde_src_tag_tbl),
		&req->src_tag_dma_addr, GFP_KERNEL);
	if (!req->src_tag_addr) {
		dev_err(dev, "[%s]Fail to alloc rde_src_tag_tlb.\n", __func__);
		return -ENOMEM;
	}

	req->dst_tag_addr = dma_alloc_coherent(dev,
		(size_t)sizeof(struct rde_dst_tag_tbl),
		&req->dst_tag_dma_addr, GFP_KERNEL);
	if (!req->dst_tag_addr) {
		dev_err(dev, "[%s]Fail to alloc rde_dst_tag_tlb.\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static void hisi_rde_tbl_deinit(struct device *dev, struct hisi_rde_msg *req)
{
	if (!dev || !req) {
		pr_info("[%s][%d] invalid para.\n", __func__, __LINE__);
		return;
	}

	if (req->src_addr) {
		dma_free_coherent(dev, (size_t)sizeof(struct rde_src_tbl),
			req->src_addr, req->src_dma_addr);
		req->src_addr = NULL;
	}

	if (req->dst_addr) {
		dma_free_coherent(dev, (size_t)sizeof(struct rde_dst_tbl),
			req->dst_addr, req->dst_dma_addr);
		req->dst_addr = NULL;
	}

	if (req->src_tag_addr) {
		dma_free_coherent(dev, (size_t)sizeof(struct rde_src_tag_tbl),
			req->src_tag_addr, req->src_tag_dma_addr);
		req->src_tag_addr = NULL;
	}

	if (req->dst_tag_addr) {
		dma_free_coherent(dev, (size_t)sizeof(struct rde_dst_tag_tbl),
			req->dst_tag_addr, req->dst_tag_dma_addr);
		req->dst_tag_addr = NULL;
	}

}

static void hisi_rde_session_init(struct hisi_rde_ctx *rde_ctx)
{
	u32 num = rde_ctx->qp->qm->qp_num;

	if (num <= QNUM_64)
		rde_ctx->session_num = QDEPTH_1024;
	else if (num > QNUM_64 && num <= QNUM_128)
		rde_ctx->session_num = QDEPTH_512;
	else if (num > QNUM_128 && num <= QNUM_256)
		rde_ctx->session_num = QDEPTH_256;
	else if (num > QNUM_256 && num <= QNUM_512)
		rde_ctx->session_num = QDEPTH_128;
	else
		rde_ctx->session_num = QDEPTH_64;
}

static int hisi_rde_ctx_init(struct hisi_rde_ctx *rde_ctx, int qlen)
{
	struct device *dev = rde_ctx->dev;
	int i, j;
	int ret;

	spin_lock_init(&rde_ctx->req_lock);
	rde_ctx->req_bitmap = kcalloc(BITS_TO_LONGS(qlen),
		sizeof(long), GFP_KERNEL);
	if (!rde_ctx->req_bitmap)
		return -ENOMEM;

	rde_ctx->req_list = kcalloc(qlen, sizeof(struct hisi_rde_msg),
			GFP_KERNEL);
	if (!rde_ctx->req_list) {
		kfree(rde_ctx->req_bitmap);
		rde_ctx->req_bitmap = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < qlen; i++) {
		ret = hisi_rde_tbl_init(dev,  &rde_ctx->req_list[i]);
		if (ret)
			goto err_proc;
	}

	return 0;

err_proc:
	for (j = 0; j <= i; j++)
		hisi_rde_tbl_deinit(dev, &rde_ctx->req_list[j]);
	kfree(rde_ctx->req_list);
	rde_ctx->req_list = NULL;
	kfree(rde_ctx->req_bitmap);
	rde_ctx->req_bitmap = NULL;
	return ret;
}

int acc_init(struct acc_ctx *ctx)
{
	struct hisi_rde *hisi_rde;
	struct hisi_qm *qm;
	struct hisi_rde_ctx *rde_ctx;
	int ret;

	if (unlikely(!ctx)) {
		pr_err("[%s]acc_ctx is NULL.\n", __func__);
		return -EINVAL;
	}

	hisi_rde = find_rde_device(cpu_to_node(smp_processor_id()));
	if (unlikely(!hisi_rde)) {
		pr_err("[%s]Fail to find proper RDE device.\n", __func__);
		return -ENODEV;
	}
	/* alloc inner private struct */
	rde_ctx =  kzalloc(sizeof(*rde_ctx), GFP_KERNEL);
	if (unlikely(!rde_ctx)) {
		pr_err("[%s]Fail to alloc rde_ctx.\n", __func__);
		return -ENOMEM;
	}
	ctx->inner = (void *)rde_ctx;

	qm = &hisi_rde->qm;
	if (unlikely(!qm->pdev)) {
		pr_err("[%s]pdev is NULL.\n", __func__);
		return -ENODEV;
	}
	rde_ctx->dev = &qm->pdev->dev;

	ret = hisi_rde_create_qp(qm, ctx, 0, 0);
	if (ret) {
		dev_err(rde_ctx->dev, "[%s]Fail to create qp.\n", __func__);
		goto qp_err;
	}

	rde_ctx->rde_dev = hisi_rde;
	rde_ctx->smmu_state = hisi_rde->smmu_state;
	rde_ctx->addr_type = ctx->addr_type;
	hisi_rde_session_init(rde_ctx);
	ret = hisi_rde_ctx_init(rde_ctx, (int)rde_ctx->session_num);
	if (ret) {
		dev_err(rde_ctx->dev, "[%s]Fail to init rde ctx.\n", __func__);
		goto ctx_err;
	}

	dev_info_ratelimited(rde_ctx->dev, "[%s]smmu state is %d, addr_type is %d.\n",
		__func__, rde_ctx->smmu_state, rde_ctx->addr_type);
	return 0;

ctx_err:
	hisi_rde_release_qp(rde_ctx);
qp_err:
	kfree(rde_ctx);
	ctx->inner = NULL;
	return ret;
}
EXPORT_SYMBOL(acc_init);

int acc_clear(struct acc_ctx *ctx)
{
	struct hisi_rde_ctx *rde_ctx;
	u32 i;

	if (unlikely(!ctx)) {
		pr_err("[%s]acc_ctx is NULL.\n", __func__);
		return -EINVAL;
	}

	rde_ctx = (struct hisi_rde_ctx *)ctx->inner;
	if (unlikely(!rde_ctx)) {
		pr_err("[%s]rde ctx is NULL.\n", __func__);
		return -EIO;
	}

	if (unlikely(!rde_ctx->dev)) {
		pr_err("[%s] dev is NULL.\n", __func__);
		return -ENODEV;
	}

	for (i = 0;  i < rde_ctx->session_num; i++)
		hisi_rde_tbl_deinit(rde_ctx->dev, &rde_ctx->req_list[i]);

	kfree(rde_ctx->req_bitmap);
	rde_ctx->req_bitmap = NULL;
	kfree(rde_ctx->req_list);
	rde_ctx->req_list = NULL;
	hisi_rde_release_qp(rde_ctx);

	mutex_lock(rde_ctx->rde_dev->rde_list_lock);
	rde_ctx->rde_dev->q_ref = rde_ctx->rde_dev->q_ref - 1;
	mutex_unlock(rde_ctx->rde_dev->rde_list_lock);
	dev_dbg(rde_ctx->dev, "[%s] finish.\n", __func__);
	kfree(rde_ctx);
	ctx->inner = NULL;

	return 0;
}
EXPORT_SYMBOL(acc_clear);

int acc_setup_callback(struct acc_ctx *ctx, acc_callback cb)
{
	if (!ctx) {
		pr_err("[%s]hisi_rde acc_ctx is NULL.\n", __func__);
		return -EINVAL;
	}

	ctx->cb = cb;

	return 0;
}
EXPORT_SYMBOL(acc_setup_callback);

int acc_set_pi_crc_seed(uint16_t seed)
{
	struct hisi_rde *hisi_rde;

	hisi_rde = find_rde_device(cpu_to_node(smp_processor_id()));
	if (!hisi_rde) {
		pr_err("[%s]Fail to find proper RDE device!\n", __func__);
		return -ENODEV;
	}

	writel((u32)seed, hisi_rde->qm.io_base + RDE_CRC16_IV);

	return 0;
}
EXPORT_SYMBOL(acc_set_pi_crc_seed);

int acc_set_prp_mem_page_size(uint32_t page_size_byte)
{
	struct hisi_rde *hisi_rde;

	hisi_rde = find_rde_device(cpu_to_node(smp_processor_id()));
	if (!hisi_rde) {
		pr_err("[%s]Fail to find proper RDE device!\n", __func__);
		return -ENODEV;
	}

	writel(page_size_byte, hisi_rde->qm.io_base + RDE_PRP_PAGE_SIZE);

	return 0;
}
EXPORT_SYMBOL(acc_set_prp_mem_page_size);

int acc_set_sge_offset_from_sgl(uint32_t offset_byte)
{
	struct hisi_rde *hisi_rde;

	hisi_rde = find_rde_device(cpu_to_node(smp_processor_id()));
	if (!hisi_rde) {
		pr_err("[%s]Fail to find proper RDE device!\n", __func__);
		return -ENODEV;
	}

	writel(offset_byte, hisi_rde->qm.io_base + RDE_SGL_SGE_OFFSET);

	return 0;
}
EXPORT_SYMBOL(acc_set_sge_offset_from_sgl);

int acc_do_flexec_asyn(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	return hisi_rde_io_proc(ctx, ctrl, op_type, PQ_FLEXEC, false);
}
EXPORT_SYMBOL(acc_do_flexec_asyn);

int acc_do_flexec(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	return hisi_rde_io_proc(ctx, ctrl, op_type, PQ_FLEXEC, true);
}
EXPORT_SYMBOL(acc_do_flexec);

int acc_do_mpcc_asyn(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	return hisi_rde_io_proc(ctx, ctrl, op_type, MPCC, false);
}
EXPORT_SYMBOL(acc_do_mpcc_asyn);

int acc_do_mpcc(struct acc_ctx *ctx, struct raid_ec_ctrl *ctrl,
	uint8_t op_type)
{
	return hisi_rde_io_proc(ctx, ctrl, op_type, MPCC, true);
}
EXPORT_SYMBOL(acc_do_mpcc);

