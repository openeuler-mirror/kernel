// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_srq.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/stddef.h>
#include <linux/printk.h>
#include <linux/sysfs.h>
#include "sxe2_compat.h"
#include "sxe2-abi.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_srq.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_rcms.h"

#define SXE2_DRV_SRQC_PAGESZ_WIDTH_MAX	(21)
#define SXE2_DRV_SRQ_PAGE_NUM_MIN	(1)
#define SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA0 (0x0)
#define SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA1 (0x1)
#define SXE2_DRV_SRQE_MIN_SIZE		(32)
#define SXE2_DRV_SRQ_DB_NOTE_SIZE	(16)
#define SXE2_DRV_SRQ_POLARITY_INIT                                             \
	(0)
#define SXE2_DRV_SRQE_MAX_FRAG_CNT_SHIFT                                       \
	(2)
#define SXE2_DRV_SRQE_MAX_FRAG_CNT_SUB                                         \
	(1)
#define SXE2_DRV_SRQ_SIZE_MUL_SHIFT                                            \
	(1)
#define SXE2_DRV_SRQ_MIN_QUANTA	 (8)
#define SXE2_DRV_SRQ_MQ_OP_POST	 (1)
#define SXE2_DRV_SRQC_PA_OFFSET	 (8)
#define SXE2_DRV_SRQ_PAGE_OFFSET (256)

static int srq_kset_pble(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_rdma_srq *ksrq, int page_num,
			 int page_size)
{
	struct sxe2_umode_srq *usrq_rsc		    = &ksrq->srq_ctx.usrq_rsc;
	struct sxe2_pbl_pble_alloc_info *alloc_info = NULL;
	struct sxe2_pbl_pble_rsrc *pble_rsrc = rdma_dev->rdma_func->pble_rsrc;
	struct ib_block_iter biter;
	u64 pble_liner_index;
	u64 pgaddr;
	int ret = 0;

	if (page_num == SXE2_DRV_SRQ_PAGE_NUM_MIN) {
		rdma_umem_for_each_dma_block(usrq_rsc->srq_umem, &biter,
					      (ulong)page_size) {
			usrq_rsc->pbl_pointer =
				rdma_block_iter_dma_address(&biter);
		}
		usrq_rsc->wqe_access_mod = SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA0;
	} else {
		alloc_info = kzalloc(sizeof(*alloc_info), GFP_KERNEL);
		if (!alloc_info) {
			ret = -ENOMEM;
			goto end;
		}

		ret = sxe2_pbl_get_pble(pble_rsrc, alloc_info, (u32)page_num,
					PBL_OBJ_SRQ);
		if (ret) {
			ret = -EFAULT;
			DRV_RDMA_LOG_DEV_ERR(
				"SRQ:sxe2_pbl_get_pble failed, ret(%d)\n", ret);
			goto free_alloc_info;
		}

		usrq_rsc->pble_alloc_info = alloc_info;
		usrq_rsc->pbl_pointer	  = alloc_info->pbl_index;
		pble_liner_index	  = alloc_info->pble_info.liner_addr;
		usrq_rsc->wqe_access_mod  = SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA1;

		rdma_umem_for_each_dma_block(usrq_rsc->srq_umem, &biter,
					      (unsigned long)page_size) {
			pgaddr = rdma_block_iter_dma_address(&biter);
			ret    = sxe2_pbl_set_pble(pble_rsrc, pble_liner_index,
						   pgaddr, false);
			if (ret) {
				ret = -EFAULT;
				DRV_RDMA_LOG_DEV_ERR(
					"SRQ:sxe2_pbl_set_pble failed, ret(%d)\n",
					ret);
				goto free_pble;
			}
			pble_liner_index += sizeof(u64);
		}
	}
	goto end;

free_pble:
	sxe2_pbl_free_pble(pble_rsrc, alloc_info->pble_info.liner_addr,
			   (u32)page_num, false);
free_alloc_info:
	kfree(alloc_info);
	alloc_info = NULL;
end:
	return ret;
}

static int srq_ksetup_umode(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rdma_srq *ksrq,
			    struct sxe2_srq_init_info *info,
			    struct ib_udata *udata)
{
	struct sxe2_create_srq_req req = {};
	struct sxe2_srq_drv_init_info *drv_info;
	struct sxe2_umode_srq *usrq_rsc;
	int page_size;
	int page_num;
	int ret	     = 0;
	long ret_tmp = 0;

	if (udata->inlen <
	    offsetofend(struct sxe2_create_srq_req, max_wr_cal)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("SRQ:invalid udata inlen %zu, ret %d",
				     udata->inlen, ret);
		goto end;
	}

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR("SRQ:copy udata failed, ret %d", ret);
		goto end;
	}

	ksrq->srq_ctx.user_mode = true;
	ksrq->max_wr		= req.max_wr_cal;
	drv_info		= &info->srq_drv_init_info;
	drv_info->srq		= (struct sxe2_qp_quanta *)(&req.user_srq_buf);
	drv_info->db_note	= (__le64 *)(&req.user_srq_db_note);
	drv_info->srq_buf_size	= req.srq_buf_size;
	drv_info->srq_size	= req.srq_size;
	usrq_rsc		= &ksrq->srq_ctx.usrq_rsc;

	info->srq_cmpl_ctx = (u64)req.srq_cmpl_ctx;

#ifdef IB_UMEM_GET_V2
	usrq_rsc->srq_umem =
		ib_umem_get(udata, req.user_srq_buf, drv_info->srq_buf_size,
			    IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	usrq_rsc->srq_umem =
		ib_umem_get(udata, req.user_srq_buf, drv_info->srq_buf_size,
			    IB_ACCESS_LOCAL_WRITE, 0);
#elif defined IB_UMEM_GET_V3
	usrq_rsc->srq_umem = ib_umem_get(ksrq->pd->ibpd.uobject->context, req.user_srq_buf,
					 drv_info->srq_buf_size,
					 IB_ACCESS_LOCAL_WRITE, 0);
#else
	usrq_rsc->srq_umem =
		ib_umem_get(&rdma_dev->ibdev, req.user_srq_buf,
			    drv_info->srq_buf_size, IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(usrq_rsc->srq_umem)) {
		ret_tmp = PTR_ERR(usrq_rsc->srq_umem);
		DRV_RDMA_LOG_DEV_ERR("SRQ:umem ib_umem_get failed, ret %ld\n",
				     ret_tmp);
		ret = (int)ret_tmp;
		goto end;
	}

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	page_size = sxe2_set_best_pagesz(req.user_srq_buf, usrq_rsc->srq_umem,
						GENMASK(SXE2_DRV_SRQC_PAGESZ_WIDTH_MAX,
			PAGE_SHIFT));
#else
	page_size = (int)ib_umem_find_best_pgsz(
		usrq_rsc->srq_umem,
		GENMASK(SXE2_DRV_SRQC_PAGESZ_WIDTH_MAX,
			PAGE_SHIFT),
		0);
#endif
	if (!page_size) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:pin buf failed, bufaddr %#llx, ret %d\n",
			req.user_srq_buf, ret);
		goto free_srq_umem;
	}
	ksrq->srq_ctx.log_page_size = order_base_2(page_size);

#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
	page_num =
		sxe2_ib_umem_num_dma_blocks(usrq_rsc->srq_umem, page_size, 0);
#else
	page_num	       = (int)ib_umem_num_dma_blocks(usrq_rsc->srq_umem,
						     (unsigned long)page_size);
#endif

	ret = srq_kset_pble(rdma_dev, ksrq, page_num, page_size);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:sxe2_set_qp_pble failed, ret %d\n",
				     ret);
		goto free_srq_umem;
	}

#ifdef IB_UMEM_GET_V2
	usrq_rsc->db_note_umem =
		ib_umem_get(udata, req.user_srq_db_note,
			    SXE2_DRV_SRQ_DB_NOTE_SIZE, IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	usrq_rsc->db_note_umem = ib_umem_get(udata, req.user_srq_db_note,
					     SXE2_DRV_SRQ_DB_NOTE_SIZE,
					     IB_ACCESS_LOCAL_WRITE, 0);
#elif defined IB_UMEM_GET_V3
	usrq_rsc->db_note_umem = ib_umem_get(ksrq->pd->ibpd.uobject->context, req.user_srq_db_note,
				     SXE2_DRV_SRQ_DB_NOTE_SIZE,
				     IB_ACCESS_LOCAL_WRITE, 0);
#else
	usrq_rsc->db_note_umem =
		ib_umem_get(&rdma_dev->ibdev, req.user_srq_db_note,
			    SXE2_DRV_SRQ_DB_NOTE_SIZE, IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(usrq_rsc->db_note_umem)) {
		ret_tmp = PTR_ERR(usrq_rsc->db_note_umem);
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:dbnote umem ib_umem_get failed, ret %ld\n",
			ret_tmp);
		ret = (int)ret_tmp;
		goto free_pble;
	}
#ifdef HAVE_IB_UMEM_SG_HEAD
	info->db_note_pa = sg_dma_address(usrq_rsc->db_note_umem->sg_head.sgl) +
			   (req.user_srq_db_note & ~PAGE_MASK);
#else
	info->db_note_pa =
		sg_dma_address(usrq_rsc->db_note_umem->sgt_append.sgt.sgl) +
		(req.user_srq_db_note & ~PAGE_MASK);
#endif

	goto end;

free_pble:
	if (usrq_rsc->wqe_access_mod == SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA1) {
		sxe2_pbl_free_pble(
			rdma_dev->rdma_func->pble_rsrc,
			usrq_rsc->pble_alloc_info->pble_info.liner_addr,
			usrq_rsc->pble_alloc_info->needed_pble_cnt, false);
		kfree(usrq_rsc->pble_alloc_info);
		usrq_rsc->pble_alloc_info = NULL;
	}
free_srq_umem:
	ib_umem_release(usrq_rsc->srq_umem);
	usrq_rsc->srq_umem = NULL;
end:
	return ret;
}

static void srq_kcal_wqe_shift(u32 max_srq_sge, u8 *srqe_shift)
{
	*srqe_shift = WQE_SIZE_32BYTE;

	if (max_srq_sge > MAX_SGE_SIZE_1) {
		if (max_srq_sge < MAX_SGE_SIZE_4)
			*srqe_shift = WQE_SIZE_64BYTE;
		else if (max_srq_sge < MAX_SGE_SIZE_8)
			*srqe_shift = WQE_SIZE_128BYTE;
		else
			*srqe_shift = WQE_SIZE_256BYTE;
	}
}

static int srq_kget_depth(struct sxe2_common_attrs *common_attrs, u32 srq_size,
			  u8 shift, u32 *srq_depth)
{
	int ret = 0;

	*srq_depth = sxe2_round_up_pow_2((srq_size << shift) + SXE2_RQ_RSVD);

	if (*srq_depth > common_attrs->max_hw_srq_quanta)
		ret = -EINVAL;

	return ret;
}

static int srq_ksetup_kmode(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rdma_srq *ksrq,
			    struct sxe2_srq_init_info *info,
			    struct ib_srq_attr *attr)
{
	struct sxe2_rdma_ctx_dev *dev = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_srq_drv_init_info *drv_info;
	struct sxe2_rdma_dma_mem *srq_buf_mem =
		&ksrq->srq_ctx.ksrq_rsc.srq_buf_mem;
	struct sxe2_rdma_dma_mem *srq_db_note_mem =
		&ksrq->srq_ctx.ksrq_rsc.srq_db_note_mem;
	u32 depth;
	u8 shift;
	int ret = 0;

	drv_info = &info->srq_drv_init_info;

	srq_kcal_wqe_shift(drv_info->max_srq_frag_cnt, &shift);
	ret = srq_kget_depth(drv_info->common_attrs, attr->max_wr, shift,
			     &depth);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:calculate srq depth failed, ret:%d\n",
				     ret);
		goto end;
	}

	drv_info->srq_buf_size = depth * SXE2_DRV_SRQE_MIN_SIZE;

	drv_info->srq_size = depth >> shift;

	ksrq->srq_ctx.ksrq_rsc.srq_wrid_array =
		kcalloc(drv_info->srq_size,
			sizeof(*ksrq->srq_ctx.ksrq_rsc.srq_wrid_array),
			GFP_KERNEL);
	if (!ksrq->srq_ctx.ksrq_rsc.srq_wrid_array) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:kcalloc srq_wrid_array failed, ret: %d\n", ret);
		goto end;
	}

	ksrq->srq_ctx.ksrq_rsc.srqe_array =
		kcalloc(drv_info->srq_size,
			sizeof(*ksrq->srq_ctx.ksrq_rsc.srqe_array), GFP_KERNEL);
	if (!ksrq->srq_ctx.ksrq_rsc.srqe_array) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("SRQ:kcalloc srqe_array failed, ret: %d\n",
				     ret);
		goto free_srq_wrid;
	}

	srq_buf_mem->size = drv_info->srq_buf_size;
	srq_buf_mem->va = dma_alloc_coherent(dev->hw->device, srq_buf_mem->size,
					     &srq_buf_mem->pa, GFP_KERNEL);
	if (!srq_buf_mem->va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:Kernel Buf dma_alloc_coherent failed, ret %d\n",
			ret);
		goto free_srqe_array;
	}
	memset(srq_buf_mem->va, 0, srq_buf_mem->size);

	srq_db_note_mem->size = SXE2_DRV_SRQ_DB_NOTE_SIZE;
	srq_db_note_mem->va =
		dma_alloc_coherent(dev->hw->device, srq_db_note_mem->size,
				   &srq_db_note_mem->pa, GFP_KERNEL);
	if (!srq_db_note_mem->va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:Kernel DB Note Buf dma_alloc_coherent failed, ret %d\n",
			ret);
		goto free_srq_buf;
	}
	memset(srq_db_note_mem->va, 0, srq_db_note_mem->size);

	drv_info->srq	  = (struct sxe2_qp_quanta *)srq_buf_mem->va;
	info->srq_pa	  = (u64)srq_buf_mem->pa;
	drv_info->db_note = (__le64 *)srq_db_note_mem->va;
	info->db_note_pa  = (u64)srq_db_note_mem->pa;

	ksrq->srq_ctx.log_page_size = order_base_2(PAGE_SIZE);

	info->srq_cmpl_ctx = (u64)(&ksrq->srq_ctx);

	ksrq->max_wr = (depth - SXE2_RQ_RSVD) >> shift;

	goto end;

free_srq_buf:
	dma_free_coherent(dev->hw->device, srq_buf_mem->size, srq_buf_mem->va,
			  srq_buf_mem->pa);
	srq_buf_mem->va = NULL;
free_srqe_array:
	kfree(ksrq->srq_ctx.ksrq_rsc.srqe_array);
	ksrq->srq_ctx.ksrq_rsc.srqe_array = NULL;
free_srq_wrid:
	kfree(ksrq->srq_ctx.ksrq_rsc.srq_wrid_array);
	ksrq->srq_ctx.ksrq_rsc.srq_wrid_array = NULL;
end:
	return ret;
}

static int srq_kinit_drv_common(struct sxe2_srq_drv *srq,
				struct sxe2_srq_drv_init_info *info)
{
	u8 srqshift;
	int ret = 0;

	srq->common_attrs = info->common_attrs;

	if (info->max_srq_frag_cnt > srq->common_attrs->max_hw_wq_frags) {
		ret = -EINVAL;
		goto end;
	}

	srq_kcal_wqe_shift(info->max_srq_frag_cnt, &srqshift);

	srq->srq_base = info->srq;
	srq->db_note  = info->db_note;

	srq->srq_id = info->srq_id;

	srq->srq_polarity = SXE2_DRV_SRQ_POLARITY_INIT;

	srq->srq_size = info->srq_size;

	srq->wqe_size = srqshift;

	srq->max_srq_frag_cnt = info->max_srq_frag_cnt;

	SXE2_RING_INIT(srq->srq_ring, srq->srq_size);

	srq->wqe_size_multiplier = SXE2_DRV_SRQ_SIZE_MUL_SHIFT << srqshift;

	srq->srq_buf_size = info->srq_buf_size;

end:
	return ret;
}

static int srq_kinit_ctx(struct sxe2_rdma_srq_ctx *srq,
			 struct sxe2_srq_init_info *info)
{
	u32 srq_size_quanta = 0;
	int ret		    = 0;

	ret = srq_kinit_drv_common(&srq->srq_drv, &info->srq_drv_init_info);
	if (ret)
		goto end;

	srq->dev = info->pd->dev;
	srq->pd	 = info->pd;
	srq->vsi = info->vsi;

	srq->srq_pa = info->srq_pa;

	srq->db_note_pa = info->db_note_pa;

	srq->srq_cmpl_ctx = info->srq_cmpl_ctx;

	srq->srq_limit = info->srq_limit;

	srq_size_quanta =
		max((u32)SXE2_DRV_SRQ_MIN_QUANTA,
		    srq->srq_drv.srq_size * srq->srq_drv.wqe_size_multiplier);
	srq->hw_srq_size = sxe2_kget_encoded_wqe_size(srq_size_quanta,
						      SXE2_QUEUE_TYPE_SRQ);

end:
	return ret;
}

void sxe2_kadd_srq_ref(struct ib_srq *ib_srq)
{
	struct sxe2_rdma_srq *ksrq = to_srq(ib_srq);

	refcount_inc(&ksrq->refcnt);
}

void sxe2_krem_srq_ref(struct ib_srq *ib_srq)
{
	struct sxe2_rdma_srq *ksrq	  = to_srq(ib_srq);
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(ksrq->srq_ctx.dev);
	unsigned long flags		  = 0;

	spin_lock_irqsave(&rdma_func->srqtable_lock, flags);
	if (!refcount_dec_and_test(&ksrq->refcnt)) {
		spin_unlock_irqrestore(&rdma_func->srqtable_lock, flags);
		goto end;
	}

	rdma_func->srq_table[ksrq->srq_id] = NULL;
	spin_unlock_irqrestore(&rdma_func->srqtable_lock, flags);

	complete(&ksrq->free_srq);

end:
	return;
}

static void srq_kfree_mode(struct sxe2_rdma_srq *ksrq,
			   struct sxe2_rdma_ctx_dev *dev,
			   struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_umode_srq *usrq_rsc	  = &ksrq->srq_ctx.usrq_rsc;
	struct sxe2_kmode_srq *ksrq_rsc	  = &ksrq->srq_ctx.ksrq_rsc;

	if (udata) {
		ib_umem_release(usrq_rsc->db_note_umem);
		usrq_rsc->db_note_umem = NULL;
		if (usrq_rsc->wqe_access_mod ==
		    SXE2_DRV_SRQ_WQE_ACCESS_MOD_PA1) {
			sxe2_pbl_free_pble(
				rdma_dev->rdma_func->pble_rsrc,
				usrq_rsc->pble_alloc_info->pble_info.liner_addr,
				usrq_rsc->pble_alloc_info->needed_pble_cnt,
				false);
			kfree(usrq_rsc->pble_alloc_info);
			usrq_rsc->pble_alloc_info = NULL;
		}
		ib_umem_release(usrq_rsc->srq_umem);
		usrq_rsc->srq_umem = NULL;

	} else {
		dma_free_coherent(dev->hw->device,
				  ksrq_rsc->srq_db_note_mem.size,
				  ksrq_rsc->srq_db_note_mem.va,
				  ksrq_rsc->srq_db_note_mem.pa);
		ksrq_rsc->srq_db_note_mem.va = NULL;

		dma_free_coherent(dev->hw->device, ksrq_rsc->srq_buf_mem.size,
				  ksrq_rsc->srq_buf_mem.va,
				  ksrq_rsc->srq_buf_mem.pa);
		ksrq_rsc->srq_buf_mem.va = NULL;

		kfree(ksrq_rsc->srqe_array);
		ksrq_rsc->srqe_array = NULL;

		kfree(ksrq_rsc->srq_wrid_array);
		ksrq_rsc->srq_wrid_array = NULL;
	}
};

int sxe2_kdestroy_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 scratch,
			  bool post_mq)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(srq->dev);
	struct sxe2_mq_ctx *mq;
	struct mq_wqe_of_srq *wqe = NULL;
	int ret			  = 0;

	mq = srq->dev->mq;

	wqe = (struct mq_wqe_of_srq *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("SRQ: get destroy mq wqe failed, ret %d\n",
				     ret);
		goto end;
	}

	wqe->SRQ_Completion_Context = srq->srq_cmpl_ctx;
	wqe->srqn = srq->srq_drv.srq_id;
	wqe->op = SXE2_MQ_OP_DESTROY_SRQ;
	wqe->wqe_valid = mq->polarity;

	print_hex_dump_debug("WQE: SRQ_DESTROY WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, (__le64 *)wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);

	if (post_mq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}

void sxe2_kdestroy_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			      struct sxe2_rdma_srq_ctx *srq)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	int ret = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}

	mq_info				  = &mq_request->info;
	mq_info->mq_cmd			  = MQ_OP_DESTROY_SRQ;
	mq_info->post_mq		  = SXE2_DRV_SRQ_MQ_OP_POST;
	mq_info->in.u.srq_destroy.srq	  = srq;
	mq_info->in.u.srq_destroy.scratch = (uintptr_t)mq_request;
	mq_info->destroy		  = true;

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:mq handle destroy srq cmd failed, ret %d\n", ret);
	}

end:
	return;
}

#ifdef RDMA_DESTROY_SRQ_VER_2
void sxe2_kdestroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata)
#elif defined RDMA_DESTROY_SRQ_VER_3
int sxe2_kdestroy_srq(struct ib_srq *ib_srq)
#else
int sxe2_kdestroy_srq(struct ib_srq *ib_srq, struct ib_udata *udata)
#endif
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ib_srq->device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_rdma_srq *ksrq	  = to_srq(ib_srq);

	sxe2_krem_srq_ref(ib_srq);

	wait_for_completion(&ksrq->free_srq);

	drv_rdma_debug_srq_remove(rdma_dev, ksrq);

	sxe2_kdestroy_srq_mq_cmd(rdma_func, &ksrq->srq_ctx);

#ifndef RDMA_DESTROY_SRQ_VER_3
	srq_kfree_mode(ksrq, &rdma_func->ctx_dev, udata);
#endif

	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_srqs, ksrq->srq_id);
	DRV_RDMA_LOG_DEV_INFO("SRQ:Drstroy SRQ(%#x) over\n", ksrq->srq_id);
#ifdef RDMA_DESTROY_SRQ_VER_2
	return;
#else
	return 0;
#endif
}

static void sxe2_kfill_srq_wqe(struct mq_wqe_of_srq *wqe,
			       struct sxe2_rdma_srq_ctx *srq)
{
	wqe->pd = srq->pd->pd_id;
	wqe->log_srq_size = srq->hw_srq_size;
	wqe->srq_access_mode = srq->user_mode ? srq->usrq_rsc.wqe_access_mod :
						QP_SRQ_PA_FIRST_MODE;
	wqe->log_page_size = srq->log_page_size;
	wqe->dbr_addr = srq->db_note_pa;
	wqe->SRQ_Completion_Context = srq->srq_cmpl_ctx;
	wqe->srqn		    = srq->srq_drv.srq_id;
	wqe->op			    = SXE2_MQ_OP_CREATE_SRQ;
	wqe->Physical_Buffer_Address = 0;
	wqe->srq_pbl_pointer = srq->user_mode ?
				       srq->usrq_rsc.pbl_pointer :
				       (u64)srq->ksrq_rsc.srq_buf_mem.pa;
	wqe->lwm = srq->srq_limit;

}

int sxe2_kcreate_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 scratch,
			 bool post_mq)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(srq->dev);
	struct sxe2_mq_ctx *mq;
	struct mq_wqe_of_srq *wqe = NULL;
	int ret			  = 0;

	mq			  = srq->dev->mq;

	if (srq->srq_drv.srq_id < srq->dev->hw_attrs.min_hw_srq_id ||
	    srq->srq_drv.srq_id >
		    (srq->dev->rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt -
		     1)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ: srqn %#x invalid, srqn should in [%#x, %#x]\n",
			srq->srq_drv.srq_id, srq->dev->hw_attrs.min_hw_srq_id,
			(srq->dev->rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt -
			 1));
		goto end;
	}

	wqe = (struct mq_wqe_of_srq *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("SRQ: get create mq wqe failed, ret %d\n",
				     ret);
		goto end;
	}

	sxe2_kfill_srq_wqe(wqe, srq);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "srq_limit_flag",
				rdma_dev, wqe);
#endif
	wqe->log_rq_stride = srq->srq_drv.wqe_size;
	wqe->page_offset =
		srq->user_mode ? 0 :
				 (offset_in_page(srq->ksrq_rsc.srq_buf_mem.pa) /
				  SXE2_DRV_SRQ_PAGE_OFFSET);
	wqe->wqe_valid = mq->polarity;

	print_hex_dump_debug("WQE: SRQ_CREATE WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, (__le64 *)wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_size");
#endif

	if (post_mq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}

int sxe2_kcreate_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			    struct sxe2_rdma_srq_ctx *srq)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	int ret = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_CREATE_SRQ;
	mq_info->post_mq		 = SXE2_DRV_SRQ_MQ_OP_POST;
	mq_info->in.u.srq_create.srq	 = srq;
	mq_info->in.u.srq_create.scratch = (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:mq handle create srq cmd failed, ret %d\n", ret);
	}

end:
	return ret;
}

static int sxe2_creat_info_check(struct ib_srq_init_attr *init_attr,
				 struct ib_srq_attr *attr,
				 struct sxe2_common_attrs *common_attrs)
{
	int ret = 0;

	if (init_attr->srq_type != IB_SRQT_BASIC) {
		ret = -EOPNOTSUPP;
		DRV_RDMA_LOG_ERROR("SRQ:Type inv %d, ret %d\n",
				   init_attr->srq_type, ret);
		goto end;
	}

	if (attr->max_sge > common_attrs->max_hw_wq_frags ||
	    attr->max_wr > common_attrs->max_hw_srq_wr) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR(
			"SRQ:attr inv, max_sge %#x, max_wr %#x, ret %d\n",
			attr->max_sge, attr->max_wr, ret);
		goto end;
	}

end:
	return ret;
}

static void sxe2_creat_complete_info(struct sxe2_rdma_pci_f *rdma_func,
				     struct sxe2_rdma_srq *ksrq,
				     struct ib_srq_attr *attr)
{
	rdma_func->srq_table[ksrq->srq_id] = ksrq;

	init_completion(&ksrq->free_srq);

	ksrq->max_sge = ksrq->srq_ctx.srq_drv.max_srq_frag_cnt;
	attr->max_wr  = ksrq->max_wr;
	attr->max_sge = ksrq->max_sge;

	DRV_RDMA_LOG_INFO(
		"SRQ:Create SRQ(%#x) over, user_mode %d, srq_size %#x, srqe_size %#x\n",
		ksrq->srq_id, ksrq->srq_ctx.user_mode,
		ksrq->srq_ctx.srq_drv.srq_size, ksrq->srq_ctx.srq_drv.wqe_size);

}

 #ifdef CREATE_SRQ_V1
struct ib_srq *sxe2_kcreate_srq(struct ib_pd *ib_pd, struct ib_srq_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ib_pd->device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct ib_srq_attr *attr	  = &init_attr->attr;
	struct sxe2_rdma_pd *pd		  = to_kpd(ib_pd);
	struct sxe2_rdma_srq *ksrq	  = NULL;
	struct sxe2_common_attrs *common_attrs;
	struct sxe2_srq_init_info info = {};
	struct sxe2_srq_drv_init_info *drv_info;
	struct sxe2_create_srq_resp resp = {};
	int ret				 = 0;

	common_attrs = &rdma_func->ctx_dev.hw_attrs.uk_attrs;
	drv_info     = &info.srq_drv_init_info;

	ret = sxe2_creat_info_check(init_attr, attr, common_attrs);
	if (ret)
		goto end;

	ksrq =  kzalloc(sizeof(*ksrq), GFP_KERNEL);
	if (!ksrq) {
		DRV_RDMA_LOG_DEV_ERR("ksrq kzalloc failed\n");
		ret = -ENOMEM;
		goto end;
	}

	refcount_set(&ksrq->refcnt, 1);
	spin_lock_init(&ksrq->lock);
	ksrq->pd = pd;
	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_srqs,
			       rdma_func->max_srq, &ksrq->srq_id,
			       &rdma_func->next_srq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:alloc rsrc failed, ret %d\n", ret);
		goto free_ksrq;
	}

	drv_info->max_srq_frag_cnt = attr->max_sge;
	drv_info->common_attrs	   = common_attrs;
	drv_info->srq_id	   = ksrq->srq_id;

	if (udata)
		ret = srq_ksetup_umode(rdma_dev, ksrq, &info, udata);
	else
		ret = srq_ksetup_kmode(rdma_dev, ksrq, &info, attr);

	if (ret)
		goto free_rsrc;

	info.vsi = &rdma_dev->vsi;
	info.pd	 = &pd->pd_ctx;

	ret = srq_kinit_ctx(&ksrq->srq_ctx, &info);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:init ctx failed, ret %d\n", ret);
		goto free_mem;
	}

	ret = sxe2_kcreate_srq_mq_cmd(rdma_func, &ksrq->srq_ctx);
	if (ret)
		goto free_mem;

	ret = drv_rdma_debug_srq_add(rdma_dev, ksrq);
	if (unlikely(ret)) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding SRQ to debug file system, ret %d\n",
			ret);
		goto free_hw_srq;
	}

	if (udata) {
		resp.srq_id = ksrq->srq_id;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			ret = -EPROTO;
			DRV_RDMA_LOG_DEV_ERR(
				"SRQ:copy to udata failed, ret %d\n", ret);
			drv_rdma_debug_srq_remove(rdma_dev, ksrq);
			goto free_hw_srq;
		}
	}

	sxe2_creat_complete_info(rdma_func, ksrq, attr);
	goto end;

free_hw_srq:
	sxe2_kdestroy_srq_mq_cmd(rdma_func, &ksrq->srq_ctx);
free_mem:
	srq_kfree_mode(ksrq, &rdma_func->ctx_dev, udata);
free_rsrc:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_srqs, ksrq->srq_id);
free_ksrq:
	kfree(ksrq);
end:
	return ret ? ERR_PTR(ret) : &ksrq->ibsrq;
}
#else
int sxe2_kcreate_srq(struct ib_srq *ib_srq, struct ib_srq_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ib_srq->device);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct ib_srq_attr *attr	  = &init_attr->attr;
	struct sxe2_rdma_pd *pd		  = to_kpd(ib_srq->pd);
	struct sxe2_rdma_srq *ksrq	  = to_srq(ib_srq);
	struct sxe2_common_attrs *common_attrs;
	struct sxe2_srq_init_info info = {};
	struct sxe2_srq_drv_init_info *drv_info;
	struct sxe2_create_srq_resp resp = {};
	int ret				 = 0;

	common_attrs = &rdma_func->ctx_dev.hw_attrs.uk_attrs;
	drv_info     = &info.srq_drv_init_info;

	ret = sxe2_creat_info_check(init_attr, attr, common_attrs);
	if (ret)
		goto end;

	refcount_set(&ksrq->refcnt, 1);
	spin_lock_init(&ksrq->lock);

	ret = sxe2_kalloc_rsrc(rdma_func, rdma_func->allocated_srqs,
			       rdma_func->max_srq, &ksrq->srq_id,
			       &rdma_func->next_srq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:alloc rsrc failed, ret %d\n", ret);
		goto end;
	}

	drv_info->max_srq_frag_cnt = attr->max_sge;
	drv_info->common_attrs	   = common_attrs;
	drv_info->srq_id	   = ksrq->srq_id;

	if (udata)
		ret = srq_ksetup_umode(rdma_dev, ksrq, &info, udata);
	else
		ret = srq_ksetup_kmode(rdma_dev, ksrq, &info, attr);

	if (ret)
		goto free_rsrc;

	info.vsi = &rdma_dev->vsi;
	info.pd	 = &pd->pd_ctx;

	ret = srq_kinit_ctx(&ksrq->srq_ctx, &info);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("SRQ:init ctx failed, ret %d\n", ret);
		goto free_mem;
	}

	ret = sxe2_kcreate_srq_mq_cmd(rdma_func, &ksrq->srq_ctx);
	if (ret)
		goto free_mem;

	ret = drv_rdma_debug_srq_add(rdma_dev, ksrq);
	if (unlikely(ret)) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding SRQ to debug file system, ret %d\n",
			ret);
		goto free_hw_srq;
	}

	if (udata) {
		resp.srq_id = ksrq->srq_id;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			ret = -EPROTO;
			DRV_RDMA_LOG_DEV_ERR(
				"SRQ:copy to udata failed, ret %d\n", ret);
			drv_rdma_debug_srq_remove(rdma_dev, ksrq);
			goto free_hw_srq;
		}
	}

	sxe2_creat_complete_info(rdma_func, ksrq, attr);
	goto end;

free_hw_srq:
	sxe2_kdestroy_srq_mq_cmd(rdma_func, &ksrq->srq_ctx);
free_mem:
	srq_kfree_mode(ksrq, &rdma_func->ctx_dev, udata);
free_rsrc:
	sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_srqs, ksrq->srq_id);
end:
	return ret;
}
#endif

int sxe2_kquery_srq_ctx(struct sxe2_rdma_srq_ctx *srq, u64 query_pa,
			u64 scratch, bool post_mq)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(srq->dev);
	struct sxe2_mq_ctx *mq;
	struct mq_wqe_of_srq *wqe = NULL;
	int ret			  = 0;

	mq = srq->dev->mq;

	wqe = (struct mq_wqe_of_srq *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("SRQ: get destroy mq wqe failed, ret %d\n",
				     ret);
		goto end;
	}

	wqe->srqn = srq->srq_drv.srq_id;
	wqe->op = SXE2_MQ_OP_QUERY_SRQ;
	wqe->Physical_Buffer_Address = query_pa >> SXE2_DRV_SRQC_PA_OFFSET;
	wqe->wqe_valid = mq->polarity;

	print_hex_dump_debug("WQE: SRQ_QUERY WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, (__le64 *)wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srqn");
#endif

	if (post_mq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}

int sxe2_kquery_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			   struct sxe2_rdma_srq_ctx *srq, u64 query_pa)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	int ret = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_QUERY_SRQ;
	mq_info->post_mq		 = SXE2_DRV_SRQ_MQ_OP_POST;
	mq_info->in.u.srq_query.srq	 = srq;
	mq_info->in.u.srq_query.scratch	 = (uintptr_t)mq_request;
	mq_info->in.u.srq_query.query_pa = query_pa;

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:mq handle query srq cmd failed, ret %d\n", ret);
	}

end:
	return ret;
}

int sxe2_kquery_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ib_srq->device);
	struct sxe2_rdma_ctx_dev *dev_ctx;
	struct sxe2_rdma_srq *ksrq	   = to_srq(ib_srq);
	struct sxe2_rdma_dma_mem query_srq = {};
	struct sxe2_rdma_srqc *srqc;
	int ret = 0;

	dev_ctx	       = &rdma_dev->rdma_func->ctx_dev;
	query_srq.size = sizeof(struct sxe2_rdma_srqc);
	query_srq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_srq.size,
					    &query_srq.pa, GFP_KERNEL);
	if (!query_srq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:Query SRQC Buf Alloc failed, ret:%d\n", ret);
		goto end;
	}
	memset(query_srq.va, 0, query_srq.size);

	ret = sxe2_kquery_srq_mq_cmd(rdma_dev->rdma_func, &ksrq->srq_ctx,
				     (u64)query_srq.pa);
	if (ret)
		goto free_srqc;

	srqc		= (struct sxe2_rdma_srqc *)query_srq.va;
	attr->srq_limit = srqc->ssrqc.lwm;
	attr->max_wr	= ksrq->max_wr;
	attr->max_sge	= ksrq->max_sge;
	DRV_RDMA_LOG_DEV_DEBUG("SRQ:Query SRQC log_srq_size = [%d], log_rq_stride= [%d]\n",
		srqc->ssrqc.log_srq_size, srqc->ssrqc.log_rq_stride);
free_srqc:
	dma_free_coherent(dev_ctx->hw->device, query_srq.size, query_srq.va,
			  query_srq.pa);
	query_srq.va = NULL;
end:
	return ret;
}

int sxe2_kmodify_srq_ctx(struct sxe2_rdma_srq_ctx *srq,
			 struct sxe2_rdma_srqc *srqc, u64 scratch, bool post_mq)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(srq->dev);
	struct sxe2_mq_ctx *mq;
	struct mq_wqe_of_srq *wqe = NULL;
	int ret			  = 0;

	mq = srq->dev->mq;

	wqe = (struct mq_wqe_of_srq *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("SRQ: get destroy mq wqe failed, ret %d\n",
				     ret);
		goto end;
	}

	wqe->pd			    = srqc->ssrqc.pd;
	wqe->log_srq_size	    = srqc->ssrqc.log_srq_size;
	wqe->state		    = srqc->ssrqc.state;
	wqe->srq_access_mode	    = srqc->ssrqc.srq_access_mode;
	wqe->log_page_size	    = srqc->ssrqc.log_page_size;
	wqe->dbr_addr		    = srqc->ssrqc.dbr_addr;
	wqe->SRQ_Completion_Context = srqc->ssrqc.SRQ_Completion_Context;
	wqe->srq_pbl_pointer	    = srqc->ssrqc.srq_pbl_pointer;
	wqe->lwm		    = srqc->ssrqc.lwm;
	wqe->log_rq_stride	    = srqc->ssrqc.log_rq_stride;
	wqe->page_offset	    = srqc->ssrqc.page_offset;

	wqe->srqn = srq->srq_drv.srq_id;
	wqe->Physical_Buffer_Address = 0;
	wqe->op = SXE2_MQ_OP_MODIFY_SRQ;
	wqe->wqe_valid = mq->polarity;

	print_hex_dump_debug("WQE: SRQ_MODIFY WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, (__le64 *)wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_srq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, wqe, srq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_size");
#endif

	if (post_mq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}

int sxe2_kmodify_srq_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			    struct sxe2_rdma_srq_ctx *srq,
			    struct sxe2_rdma_srqc *srqc)
{
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	int ret = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_MODIFY_SRQ;
	mq_info->post_mq		 = SXE2_DRV_SRQ_MQ_OP_POST;
	mq_info->in.u.srq_modify.srq	 = srq;
	mq_info->in.u.srq_modify.scratch = (uintptr_t)mq_request;
	mq_info->in.u.srq_modify.srqc	 = srqc;

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:mq handle modify srq cmd failed, ret %d\n", ret);
	}

end:
	return ret;
}

int sxe2_kmodify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *attr,
		     enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ib_srq->device);
	struct sxe2_rdma_ctx_dev *dev_ctx;
	struct sxe2_rdma_srq *ksrq	   = to_srq(ib_srq);
	struct sxe2_rdma_dma_mem query_srq = {};
	struct sxe2_rdma_srqc *srqc;
	int ret = 0;

	if (attr_mask & IB_SRQ_MAX_WR) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:Modify SRQ Mask %#x is illegal(has max_wr), ret %d\n",
			attr_mask, ret);
		goto end;
	}

	if (attr_mask & IB_SRQ_LIMIT) {
		if (attr->srq_limit >= ksrq->srq_ctx.srq_drv.srq_size) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR(
				"SRQ:Modify SRQ limit %#x >= max_srqe %#x, ret %d\n",
				attr->srq_limit, ksrq->srq_ctx.srq_drv.srq_size,
				ret);
			goto end;
		}
	} else {
		DRV_RDMA_LOG_DEV_WARN(
			"SRQ:Modify SRQ Mask %#x is illegal(no limit)\n",
			attr_mask);
		goto end;
	}

	dev_ctx	       = &rdma_dev->rdma_func->ctx_dev;
	query_srq.size = sizeof(struct sxe2_rdma_srqc);
	query_srq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_srq.size,
					    &query_srq.pa, GFP_KERNEL);
	if (!query_srq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ:Query SRQC Buf Alloc failed, ret:%d\n", ret);
		goto end;
	}
	memset(query_srq.va, 0, query_srq.size);

	ret = sxe2_kquery_srq_mq_cmd(rdma_dev->rdma_func, &ksrq->srq_ctx,
				     query_srq.pa);
	if (ret)
		goto free_srqc;

	srqc		= (struct sxe2_rdma_srqc *)query_srq.va;
	srqc->ssrqc.lwm = attr->srq_limit;

	ret = sxe2_kmodify_srq_mq_cmd(rdma_dev->rdma_func, &ksrq->srq_ctx,
				      srqc);
	if (ret)
		goto free_srqc;

	ksrq->srq_ctx.srq_limit = srqc->ssrqc.lwm;

free_srqc:
	dma_free_coherent(dev_ctx->hw->device, query_srq.size, query_srq.va,
			  query_srq.pa);
	query_srq.va = NULL;
end:
	return ret;
}
