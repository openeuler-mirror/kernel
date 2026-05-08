// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qp.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/err.h>
#include <linux/if_vlan.h>
#include <linux/sizes.h>
#include <linux/rcupdate.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <net/route.h>

#include "sxe2_compat.h"
#include "sxe2-abi.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_main.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_rdma_device_port.h"
#include "sxe2_drv_aux.h"
#include "sxe2_drv_rdma_virtchnl.h"

void sxe2_qp_add_ref(struct ib_qp *ibqp)
{
	struct sxe2_rdma_qp *qp = to_qp(ibqp);

	refcount_inc(&qp->refcnt);
}

void sxe2_qp_rem_ref(struct ib_qp *ibqp)
{
	struct sxe2_rdma_qp *qp	     = to_qp(ibqp);
	struct sxe2_rdma_device *dev = qp->dev;
	unsigned long flags	     = 0;

	spin_lock_irqsave(&dev->rdma_func->qptable_lock, flags);
	if (!refcount_dec_and_test(&qp->refcnt)) {
		spin_unlock_irqrestore(&dev->rdma_func->qptable_lock, flags);
		goto end;
	}
	dev->rdma_func->qp_table[qp->ibqp.qp_num] = NULL;
	spin_unlock_irqrestore(&dev->rdma_func->qptable_lock, flags);
	complete(&qp->free_qp);
end:
	return;
}

static int sxe2_validate_qp_attrs(struct ib_qp_init_attr *init_attr,
				  struct sxe2_rdma_device *rdma_dev,
				  struct ib_udata *udata)
{
	struct sxe2_rdma_ctx_dev *ctx_dev      = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_common_attrs *common_attrs = &ctx_dev->hw_attrs.uk_attrs;
	int ret				       = 0;

	if (init_attr->create_flags) {
		DRV_RDMA_LOG_DEV_ERR(
			"create flags illegal , init_attr->create_flags(%d)\n",
			init_attr->create_flags);
		ret = -EOPNOTSUPP;
		goto end;
	}

	if (!udata) {
		if (init_attr->cap.max_inline_data >
			    common_attrs->max_hw_inline ||
		    init_attr->cap.max_send_sge >
			    common_attrs->max_hw_wq_frags ||
		    init_attr->cap.max_send_wr >
			    common_attrs->max_hw_wq_quanta ||
		    init_attr->cap.max_recv_wr >
			    common_attrs->max_hw_rq_quanta ||
		    init_attr->cap.max_recv_sge >
			    common_attrs->max_hw_wq_frags) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR(
				"qp request caps illegal, max_inline_data(%d) max_send_sge(%d)\n"
				"\tmax_send_wr(%d) max_recv_wr(%d) max_recv_sge(%d)\n"
				"\tdev hw_attrs: max_hw_inline(%d), max_hw_wq_frags(%d),\n"
				"\tmax_hw_wq_quanta(%d), max_hw_rq_quanta(%d),\n",
				init_attr->cap.max_inline_data,
				init_attr->cap.max_send_sge,
				init_attr->cap.max_send_wr,
				init_attr->cap.max_recv_wr,
				init_attr->cap.max_recv_sge,
				common_attrs->max_hw_inline,
				common_attrs->max_hw_wq_frags,
				common_attrs->max_hw_wq_quanta,
				common_attrs->max_hw_rq_quanta);
			goto end;
		}
	}

	if (init_attr->qp_type != IB_QPT_RC &&
	    init_attr->qp_type != IB_QPT_UD &&
	    init_attr->qp_type != IB_QPT_GSI) {
		DRV_RDMA_LOG_DEV_ERR("qp type illegal, qp_type(%d)",
				     init_attr->qp_type);
		ret = -EOPNOTSUPP;
	}
end:
	return ret;
}

static void sxe2_calc_sq_wqe_shift(u32 max_sq_sge, u32 max_inline_data,
				   u8 *wqe_shift)
{
	*wqe_shift = WQE_SIZE_32BYTE;

	if (max_sq_sge > MAX_SGE_SIZE_1 ||
	    max_inline_data > MAX_INLINE_DATA_8) {
		if (max_sq_sge < MAX_SGE_SIZE_4 &&
		    max_inline_data <= MAX_INLINE_DATA_39) {
			*wqe_shift = WQE_SIZE_64BYTE;
		} else if (max_sq_sge < MAX_SGE_SIZE_8 &&
			   max_inline_data <= MAX_INLINE_DATA_101) {
			*wqe_shift = WQE_SIZE_128BYTE;
		} else {
			*wqe_shift = WQE_SIZE_256BYTE;
		}
	}
}
static void sxe2_calc_rq_wqe_shift(u32 max_rq_sge, u8 *wqe_shift)
{
	*wqe_shift = WQE_SIZE_32BYTE;

	if (max_rq_sge > MAX_SGE_SIZE_1) {
		if (max_rq_sge < MAX_SGE_SIZE_4)
			*wqe_shift = WQE_SIZE_64BYTE;
		else if (max_rq_sge < MAX_SGE_SIZE_8)
			*wqe_shift = WQE_SIZE_128BYTE;
		else
			*wqe_shift = WQE_SIZE_256BYTE;
	}
}
static int sxe2_calc_sqdepth(struct sxe2_rdma_device *rdma_dev,
			     struct sxe2_common_attrs *common_attrs, u32 max_wr,
			     u8 wqe_shift, u32 *sq_depth)
{
	int ret = 0;
	u32 depth;

	depth = sxe2_round_up_pow_2((max_wr << wqe_shift) + SQ_RSV_SIZE);

	depth	  = max_t(u32, depth, (u32)MIN_SQ_SIZE);
	*sq_depth = depth;
	if (*sq_depth > common_attrs->max_hw_wq_quanta) {
		DRV_RDMA_LOG_DEV_ERR("sq depth illegal, sq_depth(%d)\n", depth);
		ret = -EINVAL;
	}
	return ret;
}
static int sxe2_calc_rqdepth(struct sxe2_rdma_device *rdma_dev,
			     struct sxe2_common_attrs *common_attrs, u32 max_wr,
			     u8 wqe_shift, u32 *rq_depth)
{
	int ret = 0;
	u32 depth;

	depth = sxe2_round_up_pow_2((max_wr << wqe_shift) + RQ_RSV_SIZE);

	depth	  = max_t(u32, depth, (u32)MIN_RQ_SIZE);
	*rq_depth = depth;
	if (*rq_depth > common_attrs->max_hw_rq_quanta) {
		DRV_RDMA_LOG_DEV_ERR("rq depth illegal, rq_depth(%d)\n", depth);
		ret = -EINVAL;
	}
	return ret;
}
static int sxe2_calc_sq_depth_shift(struct sxe2_rdma_device *rdma_dev,
				    struct sxe2_qp_common_init_info *init_info,
				    u32 *sq_depth, u8 *sq_shift)
{
	int ret = 0;

	sxe2_calc_sq_wqe_shift(init_info->max_sq_sge_cnt + 1,
			       init_info->max_inline_data, sq_shift);
	ret = sxe2_calc_sqdepth(rdma_dev, init_info->common_attrs,
				init_info->sq_size, *sq_shift, sq_depth);
	return ret;
}

static int sxe2_calc_rq_depth_shift(struct sxe2_rdma_device *rdma_dev,
				    struct sxe2_qp_common_init_info *init_info,
				    u32 *rq_depth, u8 *rq_shift)
{
	int ret = 0;

	if ((init_info->srq) || (init_info->rq_size == 0)) {
		*rq_depth = 0;
		*rq_shift = 0;
		ret	  = 0;
		goto end;
	}

	sxe2_calc_rq_wqe_shift(init_info->max_rq_sge_cnt, rq_shift);
	ret = sxe2_calc_rqdepth(rdma_dev, init_info->common_attrs,
				init_info->rq_size, *rq_shift, rq_depth);
end:
	return ret;
}
#ifdef NEED_RDMA_UMEM_BLOCK_ITER_NEXT
void kc__rdma_block_iter_start(struct kc_ib_block_iter *biter,
			       struct scatterlist *sglist, unsigned int nents,
			       unsigned long pgsz)
{
	memset(biter, 0, sizeof(*biter));
	biter->__sg	  = sglist;
	biter->__sg_nents = nents;

	biter->__pg_bit = __fls(pgsz);
}

bool kc__rdma_block_iter_next(struct kc_ib_block_iter *biter)
{
	unsigned int block_offset;
	unsigned int sg_delta;

	if (!biter->__sg_nents || !biter->__sg)
		return false;

	biter->__dma_addr = sg_dma_address(biter->__sg) + biter->__sg_advance;
	block_offset	  = biter->__dma_addr & (BIT_ULL(biter->__pg_bit) - 1);
	sg_delta	  = BIT_ULL(biter->__pg_bit) - block_offset;

	if (sg_dma_len(biter->__sg) - biter->__sg_advance > sg_delta) {
		biter->__sg_advance += sg_delta;
	} else {
		biter->__sg_advance = 0;
		biter->__sg	    = sg_next(biter->__sg);
		biter->__sg_nents--;
	}

	return true;
}
#endif

static int sxe2_set_qp_pble(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_rdma_qp *qp, u32 page_num,
			    unsigned long page_size)
{
	struct sxe2_pbl_pble_alloc_info *alloc_info = NULL;
	struct sxe2_pbl_pble_rsrc *pble_rsrc = rdma_dev->rdma_func->pble_rsrc;
	struct ib_block_iter biter;
	u64 pble_liner_index;
	u64 pgaddr;
	int ret = 0;

	if (page_num == 1) {
		rdma_umem_for_each_dma_block(qp->qp_umem, &biter, page_size) {
			qp->pbl_pointer = rdma_block_iter_dma_address(&biter);
		}
		qp->wqe_access_mod = SXE2_QP_WQE_ACCESS_MOD_0;
	} else {
		alloc_info = kzalloc(sizeof(*alloc_info), GFP_KERNEL);
		if (!alloc_info)
			goto end;
		ret = sxe2_pbl_get_pble(pble_rsrc, alloc_info, (u32)page_num,
					PBL_OBJ_QP);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"sxe2_pbl_get_pble failed, ret(%d)\n", ret);
			goto free_alloc_info;
		}
		qp->pble_alloc_info = alloc_info;
		qp->pbl_pointer	    = alloc_info->pbl_index;
		pble_liner_index    = alloc_info->pble_info.liner_addr;
		qp->wqe_access_mod  = SXE2_QP_WQE_ACCESS_MOD_1;
		rdma_umem_for_each_dma_block(qp->qp_umem, &biter, page_size) {
			pgaddr = rdma_block_iter_dma_address(&biter);
			ret    = sxe2_pbl_set_pble(pble_rsrc, pble_liner_index,
						   pgaddr, false);
			if (ret) {
				DRV_RDMA_LOG_DEV_ERR(
					"sxe2_pbl_set_pble failed, ret(%d)\n",
					ret);
				goto free_pble;
			}
			pble_liner_index += sizeof(u64);
		}
	}
	goto end;
free_pble:
	sxe2_pbl_free_pble(pble_rsrc, alloc_info->pble_info.liner_addr,
			   page_num, false);
free_alloc_info:
	kfree(alloc_info);
end:
	return ret;
}
static int sxe2_setup_umode_qp(struct ib_udata *udata,
			       struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_qp *qp,
			       struct sxe2_qp_init_info *info,
			       struct ib_qp_init_attr *init_attr)
{
	struct sxe2_qp_common_init_info *common_info =
		&info->qp_common_init_info;
	struct sxe2_create_qp_req req = {};
	size_t buf_size;
	unsigned long page_size;
	u32 page_num;
	int ret = 0;
#ifdef IB_UMEM_GET_V3
#endif

	ret = ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen));
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("copy fail len %zu , ret (%d)\n",
				     udata->inlen, ret);
		goto end;
	}
	qp->ctx_info.qp_compl_ctx = req.user_compl_ctx;
	qp->user_mod		  = 1;
	common_info->sq_depth	  = req.sq_depth;
	common_info->rq_depth	  = req.rq_depth;
	common_info->sq_shift	  = req.sq_shift;
	common_info->rq_shift	  = req.rq_shift;

	DRV_RDMA_LOG_DEV_INFO("rq depth %d shift:%d\n", req.rq_depth,
			      req.rq_shift);
	qp->max_send_wr =
		(common_info->sq_depth - SQ_RSV_SIZE) >> common_info->sq_shift;
	if (common_info->rq_depth != 0) {
		qp->max_recv_wr = (common_info->rq_depth - RQ_RSV_SIZE) >>
				  common_info->rq_shift;
	} else {
		qp->max_recv_wr = common_info->rq_depth;
	}
	common_info->sq_size = common_info->sq_depth >> common_info->sq_shift;
	common_info->rq_size = common_info->rq_depth >> common_info->rq_shift;
	buf_size	     = (common_info->rq_depth + common_info->sq_depth) *
		   QP_QUANTA_SIZE;
#ifdef IB_UMEM_GET_V2
	qp->qp_umem = ib_umem_get(udata, req.user_wqe_bufs, buf_size,
				  IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	qp->qp_umem	 = ib_umem_get(udata, req.user_wqe_bufs, buf_size,
				       IB_ACCESS_LOCAL_WRITE, 0);
#elif defined(IB_UMEM_GET_V3)
	qp->qp_umem = ib_umem_get(qp->pd->ibpd.uobject->context, req.user_wqe_bufs,
				  buf_size, IB_ACCESS_LOCAL_WRITE, 0);
#else
	qp->qp_umem = ib_umem_get(&rdma_dev->ibdev, req.user_wqe_bufs, buf_size,
				  IB_ACCESS_LOCAL_WRITE);
#endif
	if (!qp->qp_umem) {
		DRV_RDMA_LOG_DEV_ERR("qp umem ib_umem_get failed ret %ld\n", PTR_ERR(qp->qp_umem));
		ret = -EINVAL;
		goto end;
	}
#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	page_size = sxe2_set_best_pagesz(req.user_wqe_bufs, qp->qp_umem,
							GENMASK(21, PAGE_SHIFT));
#else
	page_size = ib_umem_find_best_pgsz(qp->qp_umem, GENMASK(21, PAGE_SHIFT), 0);
#endif
	qp->log_page_size = order_base_2(page_size);
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
	page_num = (u32)sxe2_ib_umem_num_dma_blocks(qp->qp_umem, page_size, 0);
#else
	page_num	 = (u32)ib_umem_num_dma_blocks(qp->qp_umem, page_size);
#endif
	ret = sxe2_set_qp_pble(rdma_dev, qp, page_num, page_size);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_set_qp_pble failed, ret(%d)\n", ret);
		goto free_umem;
	}
#ifdef IB_UMEM_GET_V2
	qp->db_note_umem = ib_umem_get(udata, req.doorbell_note, SZ_4K,
				       IB_ACCESS_LOCAL_WRITE);
#elif defined(IB_UMEM_GET_V1)
	qp->db_note_umem = ib_umem_get(udata, req.doorbell_note, SZ_4K,
				       IB_ACCESS_LOCAL_WRITE, 0);
#elif defined(IB_UMEM_GET_V3)

	qp->db_note_umem = ib_umem_get(qp->pd->ibpd.uobject->context, req.doorbell_note,
				  SZ_4K, IB_ACCESS_LOCAL_WRITE, 0);
#else
	qp->db_note_umem = ib_umem_get(&rdma_dev->ibdev, req.doorbell_note,
				       SZ_4K, IB_ACCESS_LOCAL_WRITE);
#endif

	if (!qp->db_note_umem) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("dbnote umem ib_umem_get failed\n");
		goto free_pble;
	}
	goto end;
free_pble:
	if (qp->wqe_access_mod == 0x1) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   qp->pble_alloc_info->pble_info.liner_addr,
				   page_num, false);
		kfree(qp->pble_alloc_info);
		qp->pble_alloc_info = NULL;
	}
free_umem:
	ib_umem_release(qp->qp_umem);
end:
	return ret;
}
static int sxe2_setup_kmode_qp(struct sxe2_rdma_ctx_dev *dev,
			       struct sxe2_rdma_qp *qp,
			       struct sxe2_qp_init_info *info,
			       struct ib_qp_init_attr *init_attr)
{
	struct sxe2_rdma_dma_mem *mem	  = &qp->kqp.dma_mem;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	int ret				  = 0;
	struct sxe2_qp_common_init_info *common_info =
		&info->qp_common_init_info;

	ret = sxe2_calc_sq_depth_shift(rdma_dev, common_info,
				       &common_info->sq_depth,
				       &common_info->sq_shift);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_calc_sq_depth_shift failed, ret(%d)\n", ret);
		goto end;
	}
	ret = sxe2_calc_rq_depth_shift(rdma_dev, common_info,
				       &common_info->rq_depth,
				       &common_info->rq_shift);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_calc_rq_depth_shift failed, ret(%d)\n", ret);
		goto end;
	}
	qp->kqp.sq_wrid_mem = kcalloc(common_info->sq_depth,
				      sizeof(*qp->kqp.sq_wrid_mem), GFP_KERNEL);
	if (!qp->kqp.sq_wrid_mem) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("kcalloc sq wrid mem failed\n");
		goto end;
	}
	common_info->sq_wrtrk_array = qp->kqp.sq_wrid_mem;

	if (common_info->rq_depth != 0) {
		qp->kqp.rq_wrid_mem =
			kcalloc(common_info->rq_depth,
				sizeof(*qp->kqp.rq_wrid_mem), GFP_KERNEL);
		if (!qp->kqp.rq_wrid_mem) {
			ret = -ENOMEM;
			DRV_RDMA_LOG_DEV_ERR("kcalloc rq wrid mem failed\n");
			goto free_sq_wrid;
		}
		common_info->rq_wrid_array = qp->kqp.rq_wrid_mem;
	}

	mem->size = (common_info->sq_depth + common_info->rq_depth) *
		    QP_QUANTA_SIZE;
	mem->va = dma_alloc_coherent(dev->hw->device, mem->size, &mem->pa,
				     GFP_KERNEL);
	if (!mem->va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("qp buffer dma_alloc_coherent failed\n");
		goto free_rq_wrid;
	}
	memset(mem->va, 0, mem->size);

	qp->log_page_size = order_base_2(PAGE_SIZE);
	common_info->rq	  = mem->va;
	info->rq_pa	  = mem->pa;
	common_info->sq	  = &common_info->rq[common_info->rq_depth];
	info->sq_pa	  = mem->pa + (common_info->rq_depth * QP_QUANTA_SIZE);

	common_info->sq_size = common_info->sq_depth >> common_info->sq_shift;
	common_info->rq_size = common_info->rq_depth >> common_info->rq_shift;
	qp->max_send_wr =
		(common_info->sq_depth - SQ_RSV_SIZE) >> common_info->sq_shift;
	if (common_info->rq_depth != 0) {
		qp->max_recv_wr = (common_info->rq_depth - RQ_RSV_SIZE) >>
				  common_info->rq_shift;
	} else {
		qp->max_recv_wr = common_info->rq_depth;
	}
	init_attr->cap.max_send_wr = qp->max_send_wr;
	init_attr->cap.max_recv_wr = qp->max_recv_wr;

	common_info->doorbell_note = dma_alloc_coherent(
		dev->hw->device, SZ_4K, &info->shadow_area_pa, GFP_KERNEL);
	if (!common_info->doorbell_note) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("shadow area dma_alloc_coherent failed\n");
		goto free_qp_dma_buf;
	}
	memset(common_info->doorbell_note, 0, SZ_4K);
	goto end;
free_qp_dma_buf:
	dma_free_coherent(dev->hw->device, mem->size, mem->va, mem->pa);
	mem->va = NULL;
free_rq_wrid:
	kfree(qp->kqp.rq_wrid_mem);
	qp->kqp.rq_wrid_mem = NULL;
free_sq_wrid:
	kfree(qp->kqp.sq_wrid_mem);
	qp->kqp.sq_wrid_mem = NULL;
end:
	return ret;
}
static void sxe2_common_qp_init(struct sxe2_qp_common *qp,
				struct sxe2_qp_common_init_info *info)
{
	u32 sq_ring_size;

	qp->qp_caps	   = info->qp_caps;
	qp->sq_base	   = info->sq;
	qp->rq_base	   = info->rq;
	qp->qp_type	   = info->qp_type;
	qp->doorbell_note  = info->doorbell_note;
	qp->sq_wrtrk_array = info->sq_wrtrk_array;
	qp->rq_wrid_array  = info->rq_wrid_array;
	qp->qp_db_no_llwqe = info->qp_db_no_llwqe;
	qp->qpn		   = info->qpn;
	qp->sq_size	   = info->sq_size;
	qp->llwqe_mode	   = false;
	qp->max_sq_sge_cnt = info->max_sq_sge_cnt;
	sq_ring_size	   = qp->sq_size << info->sq_shift;
	SXE2_RING_INIT(qp->sq_ring, sq_ring_size);
	SXE2_RING_INIT(qp->initial_ring, sq_ring_size);
	qp->swqe_polarity   = 0;
	qp->rwqe_polarity   = 0;
	qp->rq_size	    = info->rq_size;
	qp->max_rq_sge_cnt  = info->max_rq_sge_cnt;
	qp->max_inline_data = info->max_inline_data;
	qp->rq_wqe_size	    = info->rq_shift;
	SXE2_RING_INIT(qp->rq_ring, qp->rq_size);
	qp->rq_wqe_size_multiplier = 1 << info->rq_shift;
	qp->srq			   = info->srq;
	qp->common_attrs	   = info->common_attrs;
}

static void sxe2_rdma_ctx_qp_init(struct sxe2_rdma_ctx_qp *qp,
				  struct sxe2_qp_init_info *info)
{
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	qp->dev		   = info->pd->dev;
	qp->vsi		   = info->vsi;
	qp->sq_pa	   = info->sq_pa;
	qp->rq_pa	   = info->rq_pa;
	qp->hw_host_ctx	   = info->host_ctx;
	qp->hw_host_ctx_pa = info->host_ctx_pa;
	qp->shadow_area_va = info->qp_common_init_info.doorbell_note;
	qp->shadow_area_pa = info->shadow_area_pa;
	qp->pd		   = info->pd;
	info->qp_common_init_info.qp_db_no_llwqe =
		rdma_qp->dev->rdma_func->db->map;

	sxe2_common_qp_init(&qp->qp_common, &info->qp_common_init_info);
	qp->hw_sq_size = sxe2_kget_encoded_wqe_size(qp->qp_common.sq_ring.size,
						    SXE2_QUEUE_TYPE_SQ_RQ);
	qp->hw_rq_size = sxe2_kget_encoded_wqe_size(
		qp->qp_common.rq_size * qp->qp_common.rq_wqe_size_multiplier,
		SXE2_QUEUE_TYPE_SQ_RQ);
	qp->qp_state = IB_QPS_RESET;
}
static void sxe2_free_qp_buf(struct sxe2_rdma_qp *qp,
			     struct sxe2_rdma_ctx_dev *dev,
			     struct ib_udata *udata)
{
	struct sxe2_rdma_device *device = to_rdmadev(dev);

	if (udata) {
		ib_umem_release(qp->qp_umem);
		if (qp->wqe_access_mod == SXE2_QP_WQE_ACCESS_MOD_1) {
			sxe2_pbl_free_pble(
				device->rdma_func->pble_rsrc,
				qp->pble_alloc_info->pble_info.liner_addr,
				qp->pble_alloc_info->needed_pble_cnt, false);
			kfree(qp->pble_alloc_info);
			qp->pble_alloc_info = NULL;
		}
		ib_umem_release(qp->db_note_umem);
	} else {
		dma_free_coherent(dev->hw->device, qp->kqp.dma_mem.size,
				  qp->kqp.dma_mem.va, qp->kqp.dma_mem.pa);
		qp->kqp.dma_mem.va = NULL;
		dma_free_coherent(dev->hw->device, SZ_4K,
				  qp->qp_ctx.shadow_area_va,
				  qp->qp_ctx.shadow_area_pa);
		qp->qp_ctx.shadow_area_va = NULL;
		kfree(qp->kqp.rq_wrid_mem);
		qp->kqp.rq_wrid_mem = NULL;
		kfree(qp->kqp.sq_wrid_mem);
		qp->kqp.sq_wrid_mem = NULL;
	}
};
static void ether_addr_to_lmac_hmac(const u8 *eth_add, u32 *lmac, u16 *hmac)
{
	int i;

	for (i = 0, *hmac = 0; i < 2; i++)
		*hmac = (u16)((u32)(*hmac << 8) | eth_add[i]);
	for (*lmac = 0; i < ETH_ALEN; i++)
		*lmac = *lmac << 8 | eth_add[i];
}

static void sxe2_qpc_fill_tph(struct sxe2_rdma_device *rdma_dev,
			      bool tph_enable, struct sxe2_qpc *qpc)
{
	u32 st_mode = 0;
	s32 cpu_id  = 0;

	if (sxe2_drv_core_is_tph_enable(rdma_dev, tph_enable, &st_mode)) {
		if (st_mode != MODE_NO_ST)
			cpu_id = TPH_GET_CPU();
		qpc->sq_tph_en	  = true;
		qpc->sq_tph_value = (cpu_id & TPH_CPUID_MASK) | PH_HWDR << 8;
		qpc->rq_tph_en	  = true;
		qpc->rq_tph_value = (cpu_id & TPH_CPUID_MASK) | PH_DWHR << 8;
		qpc->xmit_tph_en  = true;
		qpc->rcv_tph_en	  = true;
	} else {
		qpc->sq_tph_en	  = false;
		qpc->sq_tph_value = 0;
		qpc->rq_tph_en	  = false;
		qpc->rq_tph_value = 0;
		qpc->xmit_tph_en  = false;
		qpc->rcv_tph_en	  = false;
	}
}

static void sxe2_ctx_qp_setctx_roce(struct sxe2_rdma_qp *qp, u64 *ctx_va)
{
	struct sxe2_qpc *qpc		  = (struct sxe2_qpc *)ctx_va;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	u32 lmac			  = 0;
	u16 hmac			  = 0;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;

	qpc->ack_timeout = qp->ctx_info.udp_info->ack_timeout;
	qpc->retry_mode	 = qp->ctx_info.retry_mode;
	qpc->credit_en	 = qp->ctx_info.credit_en;
	qpc->comm_est	       = 1;
	qpc->rqe_lwm	       = qp->ctx_info.rqe_lwm;
	qpc->retry_resp_op_sel = qp->ctx_info.retry_resp_op_sel;
	qpc->log_rtm	       = qp->ctx_info.log_rtm;
	qpc->qp_state	       = qp->qp_ctx.qp_state;
	qpc->dqpn	       = qp->ctx_info.roce_info->dest_qp;
	if (qp->qp_ctx.qp_common.qp_type == IB_QPT_RC) {
		qpc->qp_type = SXE2_QP_TYPE_RDMA_RC;
	} else {
		qpc->qp_type = SXE2_QP_TYPE_RDMA_UD;
		if (qp->gsi_flag == true)
			qpc->qp_type = SXE2_QP_TYPE_RDMA_QP1;
	}
	qpc->llwqe_page_index  = qp->ctx_info.llwqe_page_index;
	qpc->llwqe_mode_enable = qp->ctx_info.llwqe_mod_enable;
	qpc->log_msg_max       = qp->ctx_info.log_msg_max;
	qpc->pmtu	       = qp->ctx_info.udp_info->pmtu;
	qpc->page_offset       = qp->qp_ctx.qp_buff_page_offset;
	qpc->log_rq_size       = qp->qp_ctx.hw_rq_size;
	qpc->log_sq_size       = qp->qp_ctx.hw_sq_size;
	qpc->cqn_snd	       = qp->ctx_info.send_cq_num;
	qpc->cqn_rcv	       = qp->ctx_info.rcv_cq_num;
	qpc->log_rq_stride     = qp->qp_ctx.qp_common.rq_wqe_size;
	qpc->log_page_size     = qp->log_page_size;
	qpc->min_rnr_nak       = qp->ctx_info.udp_info->min_rnr_timer;
	qpc->fl		       = qp->ctx_info.fl;
	if (qp->qp_ctx.qp_common.srq)
		qpc->srqn = (__u64)qp->qp_ctx.qp_common.srq->srq_id;
	qpc->bucket_type = qp->ctx_info.qp_bucket_type;
	qpc->stat_rate	 = qp->ctx_info.roce_info->state_rate;

	if (qp->max_recv_wr == 0) {
		qpc->rq_type = qp->qp_ctx.qp_common.srq ? SXE2_SRQ : SXE2_NO_RQ;
		qpc->log_rq_size = 1;
	} else {
		qpc->rq_type = SXE2_REGULAR_RQ;
	}

	qpc->ipv4	      = qp->ctx_info.udp_info->ipv4;
	qpc->pd		      = qp->ctx_info.roce_info->pd_id;
	qpc->log_rra_max      = qp->ctx_info.roce_info->log_rra_max;
	qpc->log_sra_max      = qp->ctx_info.roce_info->log_sra_max;
	qpc->send_start_psn   = qp->ctx_info.udp_info->sq_psn;
	qpc->rcv_start_psn    = qp->ctx_info.udp_info->rq_psn;
	qpc->tmo_retry	      = qp->ctx_info.udp_info->retry_cnt;
	qpc->udpriv_cqenable  = qp->ctx_info.roce_info->udprivcq_en;
	qpc->rnr_retry	      = qp->ctx_info.udp_info->rnr_retry;
	qpc->ack_mode	      = qp->ctx_info.ack_mode;
	qpc->pkey_index	      = qp->ctx_info.roce_info->p_key;
	qpc->log_ack_req_freq = qp->ctx_info.log_ack_req_freq;
	qpc->hop_limit	      = qp->ctx_info.udp_info->ttl;
	qpc->q_key	      = qp->ctx_info.roce_info->qkey;
	qpc->src_port_num     = qp->ctx_info.udp_info->src_port;
	qpc->dest_port_num    = qp->ctx_info.udp_info->dst_port;
	ether_addr_to_lmac_hmac(qp->roce_info.mac_addr, &lmac, &hmac);
	qpc->smac_low  = lmac;
	qpc->smac_high = hmac;
	ether_addr_to_lmac_hmac(qp->roce_info.dest_mac_addr, &lmac, &hmac);
	qpc->rmac_low  = lmac;
	qpc->rmac_high = hmac;

	qpc->qp_completion_contex = qp->ctx_info.qp_compl_ctx;
	sxe2_qpc_fill_tph(rdma_dev, true, qpc);
	qpc->dest_ipaddr0 = qp->ctx_info.udp_info->dest_ip_addr[0];
	qpc->dest_ipaddr1 = qp->ctx_info.udp_info->dest_ip_addr[1];
	qpc->dest_ipaddr2 = qp->ctx_info.udp_info->dest_ip_addr[2];
	qpc->dest_ipaddr3 = qp->ctx_info.udp_info->dest_ip_addr[3];

	qpc->local_ipaddr_0 = qp->ctx_info.udp_info->local_ipaddr[0];
	qpc->local_ipaddr_1 = qp->ctx_info.udp_info->local_ipaddr[1];
	qpc->local_ipaddr_2 = qp->ctx_info.udp_info->local_ipaddr[2];
	qpc->local_ipaddr_3 = qp->ctx_info.udp_info->local_ipaddr[3];

	qpc->flow_label = qp->ctx_info.udp_info->flow_label;

	if (rf->cc_params.dcqcn_enable && qpc->qp_type == SXE2_QP_TYPE_RDMA_RC) {
		qpc->cnp_ecn = rdma_dev->rdma_func->cc_params.cnp_ecn;
		qpc->ecn     = rdma_dev->rdma_func->cc_params.ecn;
	} else {
		qpc->cnp_ecn = SXE2_QP_CC_CNP_ECN_DISABLE;
		qpc->ecn     = qp->udp_info.ecn;
	}
	DRV_RDMA_LOG_DEBUG_BDF("QP CC: qpc cnp_ecn=%u ecn=%u\n", qpc->cnp_ecn,
			       qpc->ecn);
	qpc->dscp     = qp->udp_info.dscp;
	qpc->cnp_dscp = qp->udp_info.dscp;

#ifdef HAVE_IB_UMEM_SG_HEAD
	qpc->dbr_addr = qp->user_mod ?
				sg_dma_address(qp->db_note_umem->sg_head.sgl) :
				qp->qp_ctx.shadow_area_pa;
#else
	qpc->dbr_addr =
		qp->user_mod ?
			sg_dma_address(qp->db_note_umem->sgt_append.sgt.sgl) :
			qp->qp_ctx.shadow_area_pa;
#endif
	qpc->pbl_pointer = qp->user_mod ? qp->pbl_pointer : qp->kqp.dma_mem.pa;
	qpc->wq_acces_mode	       = qp->wqe_access_mod;
	qpc->use_statistics_intance    = qp->ctx_info.stats_idx_valid;
	qpc->statistics_instance_index = qp->ctx_info.stats_idx;
	qpc->insert_vlan_tag	       = qp->ctx_info.udp_info->insert_vlan_tag;
	qpc->vlan_tag		       = qp->ctx_info.udp_info->vlan_tag;
	qpc->src_vsi		       = qp->ctx_info.src_vsi;
	qpc->dispatch_min_unit	       = qp->ctx_info.dispatch_min_unit;
	qpc->dispatch_mode	       = qp->ctx_info.dispatch_mode;

	if (qp->qp_ctx.flush_sq)
		qp->qp_ctx.sq_flush_polarity = !qp->qp_ctx.sq_flush_polarity;
	qpc->sq_flush_flag = qp->qp_ctx.sq_flush_polarity;
	qpc->rq_flush_flag = (qp->qp_ctx.flush_rq ? 1 : 0);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_srqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_srqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rcqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rcqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_type",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_type");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pmtu",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pmtu");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_sqSize",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_sqSize");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqType",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqType");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pageSize",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pageSize");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_scqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_scqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqSize",
		     &rdma_dev->rdma_func->mq.err_cqe_val, qpc, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqSize");

#endif
}

static void sxe2_print_qpc_info(struct sxe2_rdma_device *rdma_dev,
				struct sxe2_qpc *qpc)
{
	DRV_RDMA_LOG_DEV_DEBUG(
		"\nack_timeout(%llu) retry_mode(%llu) credit_en(%llu)\n"
		"\trqe_lwm(%llu)\n"
		"\tretry_resp_op_sel(%llu) log_rtm(%llu) qp_state(%llu) dqpn(%#llx)\n"
		"\tqp_type(%llu) llwqe_page_index(%llu)\n"
		"\tllwqe_mode_enable(%llu) log_msg_max(%llu) pmtu(%llu)\n"
		"\tpage_offset(%llu) log_rq_size(%llu)\n"
		"\tlog_sq_size(%llu) cqn_snd(%#llx) log_rq_stride(%llu)\n"
		"\tlog_page_size(%llu) cqn_rcv(%#llx)\n"
		"\tmin_rnr_nak(%llu) fl(%llu) srqn(%#llx) bucket_type(%llu)\n"
		"\ttat_rate(%llu) rq_type(%llu)\n"
		"\tipv4(%llu) pd(%llu) log_rra_max(%llu) log_sra_max(%llu)\n"
		"\tsend_start_psn(%llu)\n"
		"\ttmo_retry(%llu) udpriv_cqenable(%llu) rnr_retry(%llu)\n"
		"\trcv_start_psn(%llu) ack_mode(%llu)\n"
		"\tpkey_index(%llu) rq_flush_flag(%llu) sq_flush_flag(%llu)\n"
		"\tlog_ack_req_freq(%llu) hop_limit(%llu) q_key(%#llx) smac_low(%llu)\n"
		"\tsmac_high(%llu) src_port_num(%llu) rmac_low(%llu) rmac_high(%llu)\n"
		"\tdest_port_num(%llu)\n"
		"\tqp_completion_contex(%#llx) sq_tph_value(%llu) rq_tph_value(%llu)\n"
		"\tsq_tph_en(%llu) rq_tph_en(%llu)\n"
		"\txmit_tph_en(%llu) rcv_tph_en(%llu) cnp_dscp(%llu) cnp_ecn(%llu)\n"
		"\tflow_label(%llu)\n"
		"\tdscp(%llu) ecn(%llu) dest_ipaddr3(%llu) dest_ipaddr2(%llu)\n"
		"\tdest_ipaddr1(%llu)\n"
		"\tdest_ipaddr0(%llu) local_ipaddr_3(%llu) local_ipaddr_2(%llu)\n"
		"\tlocal_ipaddr_1(%llu) local_ipaddr_0(%llu)\n"
		"\tdbr_addr(%#llx) pbl_pointer(%#llx) tpid_index(%llu)\n"
		"\twq_acces_mode(%llu) use_statistics_intance(%llu)\n"
		"\tstatistics_instance_index(%llu) insert_vlan_tag(%llu) vlan_tag(%llu)\n"
		"\tsrc_vsi(%llu)\n"
		"\tdispatch_min_unit(%llu) dispatch_mode(%llu)\n",
		(u64)qpc->ack_timeout, (u64)qpc->retry_mode,
		(u64)qpc->credit_en, (u64)qpc->rqe_lwm,
		(u64)qpc->retry_resp_op_sel, (u64)qpc->log_rtm,
		(u64)qpc->qp_state, (u64)qpc->dqpn, (u64)qpc->qp_type,
		(u64)qpc->llwqe_page_index, (u64)qpc->llwqe_mode_enable,
		(u64)qpc->log_msg_max, (u64)qpc->pmtu, (u64)qpc->page_offset,
		(u64)qpc->log_rq_size, (u64)qpc->log_sq_size, (u64)qpc->cqn_snd,
		(u64)qpc->log_rq_stride, (u64)qpc->log_page_size,
		(u64)qpc->cqn_rcv, (u64)qpc->min_rnr_nak, (u64)qpc->fl,
		(u64)qpc->srqn, (u64)qpc->bucket_type, (u64)qpc->stat_rate,
		(u64)qpc->rq_type, (u64)qpc->ipv4, (u64)qpc->pd,
		(u64)qpc->log_rra_max, (u64)qpc->log_sra_max,
		(u64)qpc->send_start_psn, (u64)qpc->tmo_retry,
		(u64)qpc->udpriv_cqenable, (u64)qpc->rnr_retry,
		(u64)qpc->rcv_start_psn, (u64)qpc->ack_mode,
		(u64)qpc->pkey_index, (u64)qpc->rq_flush_flag,
		(u64)qpc->sq_flush_flag, (u64)qpc->log_ack_req_freq,
		(u64)qpc->hop_limit, (u64)qpc->q_key, (u64)qpc->smac_low,
		(u64)qpc->smac_high, (u64)qpc->src_port_num, (u64)qpc->rmac_low,
		(u64)qpc->rmac_high, (u64)qpc->dest_port_num,
		(u64)qpc->qp_completion_contex, (u64)qpc->sq_tph_value,
		(u64)qpc->rq_tph_value, (u64)qpc->sq_tph_en,
		(u64)qpc->rq_tph_en, (u64)qpc->xmit_tph_en,
		(u64)qpc->rcv_tph_en, (u64)qpc->cnp_dscp, (u64)qpc->cnp_ecn,
		(u64)qpc->flow_label, (u64)qpc->dscp, (u64)qpc->ecn,
		(u64)qpc->dest_ipaddr3, (u64)qpc->dest_ipaddr2,
		(u64)qpc->dest_ipaddr1, (u64)qpc->dest_ipaddr0,
		(u64)qpc->local_ipaddr_3, (u64)qpc->local_ipaddr_2,
		(u64)qpc->local_ipaddr_1, (u64)qpc->local_ipaddr_0,
		(u64)qpc->dbr_addr, (u64)qpc->pbl_pointer, (u64)qpc->tpid_index,
		(u64)qpc->wq_acces_mode, (u64)qpc->use_statistics_intance,
		(u64)qpc->statistics_instance_index, (u64)qpc->insert_vlan_tag,
		(u64)qpc->vlan_tag, (u64)qpc->src_vsi,
		(u64)qpc->dispatch_min_unit, (u64)qpc->dispatch_mode);
}

static void sxe2_fill_and_set_qpctx_info(struct sxe2_rdma_qp *qp,
					 struct sxe2_qp_host_ctx_info *ctx_info)
{
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_roce_offload_info *roce_info;
	struct sxe2_udp_offload_info *udp_info;
	u32 ib_mtu = (u32)sxe2_iboe_get_mtu(rdma_dev->vsi.mtu);

	udp_info = &qp->udp_info;
	udp_info->pmtu = min_t(u32, (u32)IB_MTU_4096, ib_mtu);

	if (qp->qp_ctx.qp_common.qp_type == IB_QPT_RC) {
		udp_info->retry_cnt = 2;
		udp_info->rnr_retry = 2;
	}
	udp_info->src_port = 0xc000;
	udp_info->dst_port = ROCE_V2_UDP_DPORT;
	roce_info	   = &qp->roce_info;
	ether_addr_copy(roce_info->mac_addr, rdma_dev->netdev->dev_addr);
	if (!qp->user_mod) {
		roce_info->udprivcq_en = true;
#ifdef SXE2_CFG_DEBUG
		if (rdma_dev->rdma_func->UDPriv_CQEnable)
			roce_info->udprivcq_en = false;
#endif
	}

	roce_info->log_rra_max = (u16)fls(dev->hw_attrs.max_rra - 1);
	roce_info->log_sra_max = (u16)fls(dev->hw_attrs.max_sra - 1);
	ctx_info->roce_info    = &qp->roce_info;
	ctx_info->udp_info     = &qp->udp_info;
	if (qp->qp_ctx.qp_common.qp_type == IB_QPT_RC) {
		ctx_info->retry_mode	    = SXE2_RETRY_MODE_GO_BACK_N;
		ctx_info->credit_en	    = 1;
		ctx_info->retry_resp_op_sel = 1;
		ctx_info->ack_mode	    = rdma_dev->rdma_func->ack_mode;
		ctx_info->log_ack_req_freq =
			rdma_dev->rdma_func->log_ack_req_freq;
		ctx_info->log_rtm = 1;
	}
	ctx_info->qp_bucket_type    = SXE2_QP_BUCKET_128K;
	ctx_info->dispatch_min_unit = 54;
	ctx_info->dispatch_mode	    = 1;
	ctx_info->udp_info->min_rnr_timer = SXE2_RDMA_MIN_RNR_NAK_DEFAULT;
	sxe2_ctx_qp_setctx_roce(qp, qp->host_ctx.va);
	DRV_RDMA_LOG_DEV_DEBUG("create qp%#x qpc print:\n", qp->ibqp.qp_num);
	sxe2_print_qpc_info(rdma_dev, qp->host_ctx.va);
}

static int sxe2_mq_create_qp_cmd(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_pci_f *rf = qp->dev->rdma_func;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_create_qp_info *qp_info;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	int ret				  = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);

	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kalloc_and_get_mq_request failed\n");
		goto end;
	}
	mq_info = &mq_request->info;
	qp_info = &mq_request->info.in.u.qp_create.info;
	memset(qp_info, 0, sizeof(*qp_info));

	mq_info->mq_cmd			= MQ_OP_CREATE_QP;
	mq_info->post_mq		= 1;
	mq_info->in.u.qp_create.qp	= &qp->qp_ctx;
	mq_info->in.u.qp_create.scratch = (uintptr_t)mq_request;
	ret				= sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
end:
	return ret;
}
int sxe2_mq_modify_qp_cmd(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_pci_f *rf = qp->dev->rdma_func;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_modify_qp_info *qp_info;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	int ret				  = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);

	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kalloc_and_get_mq_request failed\n");
		goto end;
	}
	mq_info = &mq_request->info;
	qp_info = &mq_request->info.in.u.qp_modify.info;
	memset(qp_info, 0, sizeof(*qp_info));

	mq_info->mq_cmd			= MQ_OP_MODIFY_QP;
	mq_info->post_mq		= 1;
	mq_info->in.u.qp_modify.qp	= &qp->qp_ctx;
	mq_info->in.u.qp_modify.scratch = (uintptr_t)mq_request;
	ret				= sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
end:
	return ret;
}
static int sxe2_mq_destroy_qp_cmd(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_pci_f *rf = qp->dev->rdma_func;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_destroy_qp_info *qp_info;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	int ret				  = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);

	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kalloc_and_get_mq_request failed\n");
		goto end;
	}
	mq_info = &mq_request->info;
	qp_info = &mq_request->info.in.u.qp_destroy.info;
	memset(qp_info, 0, sizeof(*qp_info));

	mq_info->mq_cmd			 = MQ_OP_DESTROY_QP;
	mq_info->post_mq		 = 1;
	mq_info->in.u.qp_destroy.qp	 = &qp->qp_ctx;
	mq_info->in.u.qp_destroy.scratch = (uintptr_t)mq_request;
	mq_info->destroy		 = true;
	ret				 = sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
end:
	return ret;
}

int sxe2_mq_query_qp_cmd(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_pci_f *rf = qp->dev->rdma_func;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_query_qp_info *qp_info;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	int ret				  = 0;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);

	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kalloc_and_get_mq_request failed\n");
		goto end;
	}
	mq_info = &mq_request->info;
	qp_info = &mq_request->info.in.u.qp_query.info;
	memset(qp_info, 0, sizeof(*qp_info));

	mq_info->mq_cmd		       = MQ_OP_QUERY_QP;
	mq_info->post_mq	       = 1;
	mq_info->in.u.qp_query.qp      = &qp->qp_ctx;
	mq_info->in.u.qp_query.scratch = (uintptr_t)mq_request;
	ret			       = sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
end:
	return ret;
}

void sxe2_ctx_qp_fill_cc_wqe(struct sxe2_rdma_ctx_qp *qp,
			     struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe)
{
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;
	struct sxe2_rdma_ctx_dev *ctx_dev = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_rdma_cc_dcqcn_params *dcqcn_params =
		&rdma_dev->rdma_func->cc_params.dcqcn_params;
	struct sxe2_rdma_cc_timely_params *timely_params =
		&rdma_dev->rdma_func->cc_params.timely_params;

	create_cc_qp_wqe->qp_id		     = qp->qp_common.qpn;
	create_cc_qp_wqe->op		     = SXE2_MQ_OP_CREATE_QP;
	create_cc_qp_wqe->qp_context_address = qp->hw_host_ctx_pa;
	create_cc_qp_wqe->sw_cc_enable	     = rdma_qp->sw_cc_enable;
	create_cc_qp_wqe->dcqcn_rc_l = dcqcn_params->rc & DCQCN_RC_L_MASK;
	create_cc_qp_wqe->dcqcn_rc_h = dcqcn_params->rc >> DCQCN_RC_H_SHIFT;
	if (ctx_dev->privileged)
		create_cc_qp_wqe->dcqcn_func_id = rdma_dev->rdma_func->pf_id;
	else
		create_cc_qp_wqe->dcqcn_func_id = ctx_dev->rcms_info->pmf_index;
	DRV_RDMA_LOG_DEBUG_BDF("qp cc:func id :%u\n",
			       create_cc_qp_wqe->dcqcn_func_id);
	if (rdma_qp->sw_cc_enable == SXE2_QP_ENABLE_DCQCN ||
	    rdma_qp->sw_cc_enable == SXE2_QP_ENABLE_DCQCN_TIMLEY) {
		DRV_RDMA_LOG_DEBUG_BDF(
			"qp cc:dcqcn params:\n"
			"T interval			: %u\n"
			"B					: %u\n"
			"rai				: %u\n"
			"rhai				: %u\n"
			"rreduce mperiod	: %u\n"
			"min dec factor		: %u\n"
			"min rate			: %u\n"
			"K					: %u\n"
			"BC					: %u\n"
			"TC					: %u\n"
			"g					: %u\n"
			"alpha				: %u\n",
			dcqcn_params->t_interval, dcqcn_params->b,
			dcqcn_params->rai_factor, dcqcn_params->rhai_factor,
			dcqcn_params->rreduce_mperiod,
			dcqcn_params->min_dec_factor, dcqcn_params->min_rate,
			dcqcn_params->k, dcqcn_params->bc, dcqcn_params->tc,
			dcqcn_params->g, dcqcn_params->alpha);

		create_cc_qp_wqe->dcqcn_b_l = dcqcn_params->b & DCQCN_B_L_MASK;
		create_cc_qp_wqe->dcqcn_b_h =
			dcqcn_params->b >> DCQCN_B_H_SHIFT;
		create_cc_qp_wqe->dcqcn_bc = dcqcn_params->bc;
		create_cc_qp_wqe->dcqcn_t_interval_h =
			dcqcn_params->t_interval >> DCQCN_T_INTERVAL_H_SHIFT;
		create_cc_qp_wqe->dcqcn_g = dcqcn_params->g;
		create_cc_qp_wqe->dcqcn_rhai_h =
			SXE2_USER_PARM_TO_HW_VAL(dcqcn_params->rhai_factor) >>
			DCQCN_RHAI_H_SHIFT;
		create_cc_qp_wqe->dcqcn_rai =
			SXE2_USER_PARM_TO_HW_VAL(dcqcn_params->rai_factor);
		create_cc_qp_wqe->dcqcn_f = dcqcn_params->f;
		create_cc_qp_wqe->dcqcn_t_interval_l =
			dcqcn_params->t_interval & DCQCN_T_INTERVAL_L_MASK;
		create_cc_qp_wqe->dcqcn_rreduce_mperiod_h =
			dcqcn_params->rreduce_mperiod >>
			DCQCN_RREDUCE_MPERIOD_H_SHIFT;
		create_cc_qp_wqe->dcqcn_k = dcqcn_params->k;
		create_cc_qp_wqe->dcqcn_rhai_l =
			SXE2_USER_PARM_TO_HW_VAL(dcqcn_params->rhai_factor) &
			DCQCN_RHAI_L_MASK;
		create_cc_qp_wqe->dcqcn_min_dec_factor =
			SXE2_USER_PARM_TO_HW_VAL(dcqcn_params->min_dec_factor);
		create_cc_qp_wqe->dcqcn_rreduce_next_node_info =
			dcqcn_params->rreduce_next_node_info;
		create_cc_qp_wqe->dcqcn_rreduce_mperiod_l =
			dcqcn_params->rreduce_mperiod &
			DCQCN_RREDUCE_MPERIOD_L_MASK;
		create_cc_qp_wqe->dcqcn_alpha = dcqcn_params->alpha;
		create_cc_qp_wqe->dcqcn_min_rate =
			SXE2_USER_PARM_TO_HW_VAL(dcqcn_params->min_rate);
		create_cc_qp_wqe->dcqcn_rt_h =
			dcqcn_params->rt >> DCQCN_RT_H_SHIFT;
		create_cc_qp_wqe->dcqcn_t_next_node_info =
			dcqcn_params->t_next_node_info;
		create_cc_qp_wqe->dcqcn_rt_l =
			dcqcn_params->rt & DCQCN_RT_L_MASK;
		create_cc_qp_wqe->dcqcn_t_counter = dcqcn_params->tc;
		create_cc_qp_wqe->dcqcn_byte_counter =
			dcqcn_params->byte_counter;
		create_cc_qp_wqe->dcqcn_decrease_rate_valid =
			dcqcn_params->decrease_rate_valid;
	}
	if (rdma_qp->sw_cc_enable == SXE2_QP_ENABLE_TIMELY ||
	    rdma_qp->sw_cc_enable == SXE2_QP_ENABLE_DCQCN_TIMLEY) {
		DRV_RDMA_LOG_DEBUG_BDF(
			"qp cc:timely params:\n"
			"min rtt		: %u\n"
			"tlow			: %u\n"
			"thigh			: %u\n"
			"rai			: %u\n"
			"beta			: %u\n"
			"alpha			: %u\n",
			timely_params->min_rtt, timely_params->tlow,
			timely_params->thigh, timely_params->rai_factor,
			timely_params->beta, timely_params->alpha);

		if (rdma_qp->sw_cc_enable == SXE2_QP_ENABLE_TIMELY) {
			create_cc_qp_wqe->dcqcn_rai = SXE2_USER_PARM_TO_HW_VAL(
				timely_params->rai_factor);
			create_cc_qp_wqe->dcqcn_b_l =
				SXE2_QP_DCQCN_MAX_B & DCQCN_B_L_MASK;
			create_cc_qp_wqe->dcqcn_b_h =
				SXE2_QP_DCQCN_MAX_B >> DCQCN_B_H_SHIFT;
		}
		create_cc_qp_wqe->timely_min_rtt_h =
			timely_params->min_rtt >> TIMELY_MIN_RTT_H_SHIFT;
		create_cc_qp_wqe->timely_alpha = timely_params->alpha;
		create_cc_qp_wqe->timely_thigh_h =
			timely_params->thigh >> TIMELY_THIGH_H_SHIFT;
		create_cc_qp_wqe->timely_tlow = timely_params->tlow;
		create_cc_qp_wqe->timely_min_rtt_l =
			timely_params->min_rtt & TIMELY_MIN_RTT_L_MASK;
		create_cc_qp_wqe->timely_pre_rtt_h =
			timely_params->pre_rtt >> TIMELY_PRE_RTT_H_SHIFT;
		create_cc_qp_wqe->timely_beta = timely_params->beta;
		create_cc_qp_wqe->timely_thigh_l =
			timely_params->thigh & TIMELY_THIGH_L_MASK;
		create_cc_qp_wqe->timely_rtt_diff = timely_params->rtt_diff;
		create_cc_qp_wqe->timely_pre_rtt_l =
			timely_params->pre_rtt & TIMELY_PRE_RTT_L_MASK;
	}
}

int sxe2_ctx_qp_create(struct sxe2_rdma_ctx_qp *qp,
		       struct sxe2_create_qp_info *info, u64 scratch,
		       bool post_sq)
{
	struct sxe2_mq_ctx *mq;
	void *mq_wqe;
	struct qp_mq_wqe *create_normal_qp_wqe		= NULL;
	struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe = NULL;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;
	int ret				  = 0;

	mq = qp->dev->mq;

	if (qp->qp_common.qpn < mq->dev->hw_attrs.min_hw_qp_id ||
	    qp->qp_common.qpn >
		    (mq->dev->rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].max_cnt -
		     1)) {
		DRV_RDMA_LOG_DEV_ERR("qpn illegal, qpn(%d)\n",
				     qp->qp_common.qpn);
		ret = -EINVAL;
		goto end;
	}
	mq_wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!mq_wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kget_next_mq_wqe fail\n");
		goto end;
	}

	memset(mq_wqe, 0, sizeof(struct qp_mq_wqe));
	if (!rdma_qp->sw_cc_enable) {
		create_normal_qp_wqe	  = (struct qp_mq_wqe *)mq_wqe;
		create_normal_qp_wqe->qpn = qp->qp_common.qpn;
		create_normal_qp_wqe->op  = SXE2_MQ_OP_CREATE_QP;
		create_normal_qp_wqe->qp_context_address = qp->hw_host_ctx_pa;
		create_normal_qp_wqe->sw_cc_enable = rdma_qp->sw_cc_enable;
	} else {
		sxe2_ctx_qp_fill_cc_wqe(
			qp, (struct qp_mq_create_cc_qp_wqe *)mq_wqe);
		create_cc_qp_wqe = (struct qp_mq_create_cc_qp_wqe *)mq_wqe;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (!rdma_qp->sw_cc_enable) {
		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpn",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_normal_qp_wqe, qp);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpn");

		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_normal_qp_wqe, qp);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx");

		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_createOp",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_normal_qp_wqe, qp);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_createOp");
	} else {
		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpn",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_cc_qp_wqe, qp);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpn");

		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_cc_qp_wqe, qp, SXE2_MQ_OP_CREATE_QP);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx");

		INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_createOp",
			     &rdma_dev->rdma_func->mq.err_cqe_val,
			     create_cc_qp_wqe, qp, SXE2_MQ_OP_CREATE_QP);
		INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_createOp");
	}

#endif

	if (post_sq)
		sxe2_kpost_mq(mq);

end:
	return ret;
}
int sxe2_ctx_qp_modify(struct sxe2_rdma_ctx_qp *qp,
		       struct sxe2_modify_qp_info *info, u64 scratch,
		       bool post_sq)
{
	struct sxe2_mq_ctx *mq;
	struct qp_mq_wqe *modify_qp_wqe;
	int ret = 0;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;

	mq = qp->dev->mq;

	if (qp->qp_common.qpn < mq->dev->hw_attrs.min_hw_qp_id ||
	    qp->qp_common.qpn >
		    (mq->dev->rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].max_cnt -
		     1)) {
		DRV_RDMA_LOG_DEV_ERR("qpn illegal, qpn(%d)\n",
				     qp->qp_common.qpn);
		ret = -EINVAL;
		goto end;
	}

	modify_qp_wqe = (struct qp_mq_wqe *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!modify_qp_wqe) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_kget_next_mq_wqe fail\n");
		ret = -ENOMEM;
		goto end;
	}
	memset(modify_qp_wqe, 0, sizeof(struct qp_mq_wqe));
	modify_qp_wqe->qpn		  = qp->qp_common.qpn;
	modify_qp_wqe->op		  = SXE2_MQ_OP_MODIFY_QP;
	modify_qp_wqe->qp_context_address = qp->hw_host_ctx_pa;
	modify_qp_wqe->modify_qp_mode	  = true;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, modify_qp_wqe, qp,
		     SXE2_MQ_OP_MODIFY_QP);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx",
		     &rdma_dev->rdma_func->mq.err_cqe_val, modify_qp_wqe, qp,
		     SXE2_MQ_OP_MODIFY_QP);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);
end:
	return ret;
}
int sxe2_ctx_qp_destroy(struct sxe2_rdma_ctx_qp *qp,
			struct sxe2_destroy_qp_info *info, u64 scratch,
			bool post_sq)
{
	struct sxe2_mq_ctx *mq;
	struct qp_mq_wqe *destroy_qp_wqe;
	int ret = 0;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;

	mq = qp->dev->mq;

	destroy_qp_wqe = (struct qp_mq_wqe *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!destroy_qp_wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kget_next_mq_wqe fail\n");
		goto end;
	}
	memset(destroy_qp_wqe, 0, sizeof(struct qp_mq_wqe));
	destroy_qp_wqe->qpn		   = qp->qp_common.qpn;
	destroy_qp_wqe->op		   = SXE2_MQ_OP_DESTROY_QP;
	destroy_qp_wqe->qp_context_address = qp->hw_host_ctx_pa;

	if (post_sq)
		sxe2_kpost_mq(mq);
end:
	return ret;
}
int sxe2_ctx_qp_query(struct sxe2_rdma_ctx_qp *qp,
		      struct sxe2_query_qp_info *info, u64 scratch,
		      bool post_sq)
{
	struct sxe2_mq_ctx *mq;
	struct qp_mq_wqe *query_qp_wqe;
	int ret = 0;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;

	mq = qp->dev->mq;

	query_qp_wqe = (struct qp_mq_wqe *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!query_qp_wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("sxe2_kget_next_mq_wqe fail\n");
		goto end;
	}
	memset(query_qp_wqe, 0, sizeof(struct qp_mq_wqe));
	query_qp_wqe->qpn		 = qp->qp_common.qpn;
	query_qp_wqe->op		 = SXE2_MQ_OP_QUERY_QP;
	query_qp_wqe->qp_context_address = qp->hw_host_ctx_pa;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, query_qp_wqe, qp,
		     SXE2_MQ_OP_QUERY_QP);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpn");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);
end:
	return ret;
}

int sxe2_qp_info_init(struct ib_qp_init_attr *init_attr,
		      struct sxe2_rdma_device *rdma_dev,
		      struct sxe2_rdma_ctx_dev *dev, struct sxe2_rdma_pd *pd,
		      u32 qpn, struct sxe2_qp_init_info *init_info)
{
	int ret				       = 0;
	struct sxe2_common_attrs *common_attrs = &dev->hw_attrs.uk_attrs;

	if (init_attr->srq)
		init_info->qp_common_init_info.srq =
			&(to_srq(init_attr->srq)->srq_ctx.srq_drv);

	init_info->vsi				    = &rdma_dev->vsi;
	init_info->qp_common_init_info.common_attrs = common_attrs;
	init_info->qp_common_init_info.sq_size = init_attr->cap.max_send_wr;
	init_info->qp_common_init_info.rq_size = init_attr->cap.max_recv_wr;
	init_info->qp_common_init_info.max_sq_sge_cnt =
		init_attr->cap.max_send_sge;
	init_info->qp_common_init_info.max_rq_sge_cnt =
		init_attr->cap.max_recv_sge;
	init_info->qp_common_init_info.max_inline_data =
		init_attr->cap.max_inline_data;
	init_info->pd			   = &pd->pd_ctx;
	init_info->qp_common_init_info.qpn = qpn;
	init_info->host_ctx =
		dma_alloc_coherent(dev->hw->device,
				   ALIGN(SXE2_QP_CTX_SIZE, 256),
				   &init_info->host_ctx_pa, GFP_KERNEL);
	if (!init_info->host_ctx) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("host ctx dma_alloc_coherent failed\n");
		goto end;
	}
	memset(init_info->host_ctx, 0, ALIGN(SXE2_QP_CTX_SIZE, 256));

	DRV_RDMA_LOG_DEV_DEBUG(
		"create qp%#x:qp_type(%d) max_inline_data(%d) max_send_sge(%d)\n"
		"\tmax_recv_sge(%d)\n"
		"\tmax_send_wr(%d) max_recv_wr(%d) qpc_va %p qpc_pa %#llx\n",
		qpn, init_attr->qp_type, init_attr->cap.max_inline_data,
		init_attr->cap.max_send_sge, init_attr->cap.max_recv_sge,
		init_attr->cap.max_send_wr, init_attr->cap.max_recv_wr,
		init_info->host_ctx, init_info->host_ctx_pa);
end:
	return ret;
}

int sxe2_rdma_qp_init(struct ib_qp_init_attr *init_attr, struct ib_udata *udata,
		      struct sxe2_rdma_device *rdma_dev,
		      struct sxe2_rdma_pd *pd, u32 qpn,
		      struct sxe2_qp_init_info *init_info,
		      struct sxe2_rdma_qp *qp)
{
	int ret				= 0;
	struct sxe2_rdma_pci_f *rf	= rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	= &rf->ctx_dev;
	struct sxe2_rdma_ctx_qp *qp_ctx = &qp->qp_ctx;

	qp_ctx->qp_common.back_qp	= qp;
	qp_ctx->qp_common.lock		= &qp->lock;
	qp_ctx->qp_common.rd_fence_rate = rdma_dev->rd_fence_rate;
	qp->dev				= rdma_dev;
	qp->pd				= pd;
	qp->ibqp.qp_num			= qpn;
	qp_ctx				= &qp->qp_ctx;
	qp->send_cq			= to_scq(init_attr->send_cq);
	qp->recv_cq			= to_scq(init_attr->recv_cq);
	qp->host_ctx.va			= init_info->host_ctx;
	qp->host_ctx.pa			= init_info->host_ctx_pa;
	qp->host_ctx.size		= ALIGN(SXE2_QP_CTX_SIZE, 256);
	qp->ctx_info.qp_compl_ctx	= (uintptr_t)qp_ctx;

	if (udata) {
		ret = sxe2_setup_umode_qp(udata, rdma_dev, qp, init_info,
					  init_attr);
		if (ret)
			goto end;
	} else {
		INIT_DELAYED_WORK(&qp->dwork_flush, sxe2_flush_wqe_worker);
		ret = sxe2_setup_kmode_qp(dev, qp, init_info, init_attr);
		if (ret)
			goto end;
		if (rdma_dev->kernel_llwqe_mode == 0) {
			qp->qp_ctx.qp_common.push_db  = NULL;
			qp->qp_ctx.qp_common.push_wqe = NULL;
			qp->qp_ctx.qp_common.llwqe    = NULL;
			DRV_RDMA_LOG_DEV_DEBUG(
				"QPC: kernel llwqe disable, llwqe NULL\n");
		} else {
			qp->qp_ctx.qp_common.push_db  = rf->llwqe.db_addr;
			qp->qp_ctx.qp_common.push_wqe = rf->llwqe.wqe_addr;
			qp->qp_ctx.qp_common.llwqe    = &rf->llwqe;
		}
	}

	if (init_attr->qp_type == IB_QPT_RC) {
		init_info->qp_common_init_info.qp_type = IB_QPT_RC;
		init_info->qp_common_init_info.qp_caps =
			SXE2_SEND_WITH_IMM | SXE2_WRITE_WITH_IMM;
	} else {
		init_info->qp_common_init_info.qp_type = IB_QPT_UD;
		init_info->qp_common_init_info.qp_caps = SXE2_SEND_WITH_IMM;

		if (init_attr->qp_type == IB_QPT_GSI)
			qp->gsi_flag = true;
		else
			qp->gsi_flag = false;
	}

	qp->sw_cc_enable = SXE2_QP_DISABLE_SW_CC;
	if ((rf->cc_params.dcqcn_enable || rf->cc_params.timely_enable) &&
	    init_attr->qp_type == IB_QPT_RC) {
		mutex_lock(&rf->cc_refcount.refcount_lock);
		if ((u32)atomic_read(&rf->cc_refcount.cc_qp_refcount) <
		    rf->max_cc_qp_cnt) {
			atomic_inc(&rf->cc_refcount.cc_qp_refcount);
			if (rf->cc_params.dcqcn_enable &&
			    rf->cc_params.timely_enable) {
				qp->sw_cc_enable = SXE2_QP_ENABLE_DCQCN_TIMLEY;
			} else {
				qp->sw_cc_enable =
					(rf->cc_params.dcqcn_enable == true) ?
						SXE2_QP_ENABLE_DCQCN :
						SXE2_QP_ENABLE_TIMELY;
			}

			DRV_RDMA_LOG_DEBUG_BDF(
				"create cc qp  refcount=%u enable algorithm=%u pf id=%u\n\n",
				atomic_read(&rf->cc_refcount.cc_qp_refcount),
				qp->sw_cc_enable, rf->pf_id);
		} else {
			DRV_RDMA_LOG_DEBUG_BDF(
				"failed to create cc qp refcount=%u max cc qp cnt=%u\n",
				atomic_read(&rf->cc_refcount.cc_qp_refcount),
				rf->max_cc_qp_cnt);
		}
		mutex_unlock(&rf->cc_refcount.refcount_lock);
	}

end:
	return ret;
}

int sxe2_qp_qset_init_and_resp(struct ib_udata *udata,
			       struct sxe2_rdma_device *rdma_dev, u32 qpn,
			       struct sxe2_rdma_ctx_qp *qp_ctx,
			       struct sxe2_rdma_qp *qp)
{
	int ret				 = 0;
	struct sxe2_create_qp_resp uresp = {};
	struct sxe2_qpc *qpc;

	if (rdma_dev->vsi.lag_aa)
		ret = sxe2_qos_register_qset_bond(&rdma_dev->vsi, 0);
	else
		ret = sxe2_qos_register_qset(&rdma_dev->vsi, 0);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_qos_register_qset failed , rdma_dev->vsi.lag_aa(%d) err(%d)\n",
			rdma_dev->vsi.lag_aa, ret);
		goto end;
	}
	if (rdma_dev->vsi.lag_aa) {
		if (atomic_read(&rdma_dev->vsi.port1_qp_cnt) <=
			atomic_read(&rdma_dev->vsi.port2_qp_cnt)) {
			qp->qp_ctx.qset_idx = QOS_QSET_IDX_0;
		} else {
			qp->qp_ctx.qset_idx = QOS_QSET_IDX_1;
		}
		ret = sxe2_qos_qp_add_qos_bond(&rdma_dev->vsi, qp_ctx);
	} else {
		ret = sxe2_qos_qp_add_qos(&rdma_dev->vsi, qp_ctx);
	}
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_qos_qp_add_qos failed , err(%d)\n",
				     ret);
		goto qp_unregist_qset;
	}

	if (udata) {
		uresp.qpn     = qpn;
		uresp.qp_caps = qp->qp_ctx.qp_common.qp_caps;
		ret	      = ib_copy_to_udata(udata, &uresp,
					 min(sizeof(uresp), udata->outlen));
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"ib_copy_to_udata failed , err(%d)\n", ret);
			goto qp_remove_qos;
		}
	}

	if (qp->sw_cc_enable) {
		ret = sxe2_mq_query_qp_cmd(qp);
		if (ret) {
			DRV_RDMA_LOG_ERROR_BDF("query qp failed , err(%d)\n",
					       ret);
			goto qp_remove_qos;
		}
		qpc	      = (struct sxe2_qpc *)qp->host_ctx.va;
		qp->sw_cc_idx = qpc->sw_cc_index;
		DRV_RDMA_LOG_DEV_DEBUG("create cc qp enable %u cc qp index %u\n",
				qpc->sw_cc_enable, qpc->sw_cc_index);
	}

end:
	return ret;
qp_remove_qos:
	(void)sxe2_qos_qp_rem_qos(&rdma_dev->vsi, qp_ctx);
qp_unregist_qset:
	if (rdma_dev->vsi.lag_aa)
		sxe2_qos_unregister_qset_bond(&rdma_dev->vsi, 0);
	else
		sxe2_qos_unregister_qset(&rdma_dev->vsi, 0);
	goto end;
}

#ifdef CREATE_QP_VER_1
struct ib_qp *sxe2_kcreate_qp(struct ib_pd *ibpd,
			      struct ib_qp_init_attr *init_attr,
			      struct ib_udata *udata)
{
	struct sxe2_rdma_pd *pd		  = to_pd(ibpd);
	struct sxe2_rdma_device *rdma_dev = to_dev(ibpd->device);
	struct sxe2_rdma_pci_f *rf	  = rdma_dev->rdma_func;
	struct sxe2_rdma_qp *qp		  = NULL;
	u32 qpn				  = 0;
	int ret;
	struct sxe2_rdma_ctx_qp *qp_ctx	   = NULL;
	struct sxe2_rdma_ctx_dev *dev	   = &rf->ctx_dev;
	struct sxe2_qp_init_info init_info = {};
	struct sxe2_qp_host_ctx_info *ctx_info;

	ret = sxe2_validate_qp_attrs(init_attr, rdma_dev, udata);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_validate_qp_attrs failed , err(%d)\n", ret);
		goto end;
	}
	if (udata && (udata->inlen < sizeof(struct sxe2_create_qp_req) ||
		      udata->outlen < sizeof(struct sxe2_create_qp_resp))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"udata illegal! , udata->inlen(%zu) udata->outlen(%zu)\n",
			udata->inlen, udata->outlen);
		goto end;
	}
	if (init_attr->qp_type == IB_QPT_GSI) {
		qpn = 1;
	} else {
		ret = sxe2_kalloc_rsrc(rf, rf->allocated_qps, rf->max_qp, &qpn,
				       &rf->next_qp);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"sxe2_kalloc_rsrc failed , err(%d)\n", ret);
			goto end;
		}
	}

	ret = sxe2_qp_info_init(init_attr, rdma_dev, dev, pd, qpn, &init_info);
	if (ret)
		goto free_qpn;

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("qp kzalloc failed\n");
		goto free_host_ctx;
	}

	qp_ctx = &qp->qp_ctx;

	ret = sxe2_rdma_qp_init(init_attr, udata, rdma_dev, pd, qpn, &init_info,
				qp);
	if (ret)
		goto free_qp;
	sxe2_rdma_ctx_qp_init(qp_ctx, &init_info);
	ctx_info	      = &qp->ctx_info;
	ctx_info->send_cq_num = qp->send_cq->cq_ctx.cq_uk.cq_id;
	ctx_info->rcv_cq_num  = qp->recv_cq->cq_ctx.cq_uk.cq_id;
	ctx_info->src_vsi     = rdma_dev->vsi.vsi_idx;
	sxe2_fill_and_set_qpctx_info(qp, ctx_info);
	ret = sxe2_mq_create_qp_cmd(qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_mq_create_qp_cmd failed , err(%d)\n",
				     ret);
		goto free_qp_buf;
	}
	ret = drv_rdma_debug_qp_add(rdma_dev, qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("drv_rdma_debug_qp_add failed , err(%d)\n",
				     ret);
		goto qp_destroy_cmd;
	}
	refcount_set(&qp->refcnt, 1);
	spin_lock_init(&qp->lock);
	qp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qpn] = qp;
	qp->ibqp_state	  = qp_ctx->qp_state;

	ret = sxe2_qp_qset_init_and_resp(udata, rdma_dev, qpn, qp_ctx, qp);
	if (ret)
		goto qp_debugfs_remove;
	init_completion(&qp->free_qp);
	goto end;

qp_debugfs_remove:
	drv_rdma_debug_qp_remove(rdma_dev, qp);
qp_destroy_cmd:
	sxe2_mq_destroy_qp_cmd(qp);
free_qp_buf:
	if (qp->sw_cc_enable != SXE2_QP_DISABLE_SW_CC) {
		mutex_lock(&rf->cc_refcount.refcount_lock);
		atomic_dec(&rf->cc_refcount.cc_qp_refcount);
		mutex_unlock(&rf->cc_refcount.refcount_lock);
	}
	sxe2_free_qp_buf(qp, dev, udata);
free_qp:
	kfree(qp);
free_host_ctx:
	dma_free_coherent(dev->hw->device, ALIGN(SXE2_QP_CTX_SIZE, 256),
			  init_info.host_ctx, init_info.host_ctx_pa);
	init_info.host_ctx = NULL;
free_qpn:
	if (init_attr->qp_type != IB_QPT_GSI)
		sxe2_kfree_rsrc(rf, rf->allocated_qps, qpn);
end:
	return ret ? ERR_PTR(ret) : &qp->ibqp;
}

#else
int sxe2_kcreate_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr,
		    struct ib_udata *udata)
{
	struct ib_pd *ibpd = ibqp->pd;
	struct sxe2_rdma_pd *pd = to_pd(ibpd);
	struct sxe2_rdma_device *rdma_dev = to_dev(ibpd->device);
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	struct sxe2_rdma_qp *qp = to_qp(ibqp);
	u32 qpn = 0;
	int ret = 0;
	struct sxe2_rdma_ctx_qp *qp_ctx = &qp->qp_ctx;
	struct sxe2_rdma_ctx_dev *dev = &rf->ctx_dev;
	struct sxe2_qp_init_info init_info = {};
	struct sxe2_qp_host_ctx_info *ctx_info;

	ret = sxe2_validate_qp_attrs(init_attr, rdma_dev, udata);
	if (ret)
		goto end;
	if (udata && (udata->inlen < sizeof(struct sxe2_create_qp_req) ||
		      udata->outlen < sizeof(struct sxe2_create_qp_resp))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"udata illegal! , udata->inlen(%zu) udata->outlen(%zu)\n",
			udata->inlen, udata->outlen);
		goto end;
	}
	if (init_attr->qp_type == IB_QPT_GSI) {
		qpn = 1;
	} else {
		ret = sxe2_kalloc_rsrc(rf, rf->allocated_qps, rf->max_qp, &qpn,
				       &rf->next_qp);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"sxe2_kalloc_rsrc failed , err(%d)\n", ret);
			goto end;
		}
	}

	ret = sxe2_qp_info_init(init_attr, rdma_dev, dev, pd, qpn, &init_info);
	if (ret)
		goto free_qpn;

	ret = sxe2_rdma_qp_init(init_attr, udata, rdma_dev, pd, qpn, &init_info,
				qp);
	if (ret)
		goto free_host_ctx;

	sxe2_rdma_ctx_qp_init(qp_ctx, &init_info);

	ctx_info = &qp->ctx_info;
	ctx_info->send_cq_num = qp->send_cq->cq_ctx.cq_uk.cq_id;
	ctx_info->rcv_cq_num = qp->recv_cq->cq_ctx.cq_uk.cq_id;
	ctx_info->src_vsi = rdma_dev->vsi.vsi_idx;
	sxe2_fill_and_set_qpctx_info(qp, ctx_info);
	ret = sxe2_mq_create_qp_cmd(qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_mq_create_qp_cmd failed , err(%d)\n",
				     ret);
		goto free_qp_buf;
	}
	ret = drv_rdma_debug_qp_add(rdma_dev, qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("drv_rdma_debug_qp_add failed , err(%d)\n",
				     ret);
		goto qp_destroy_cmd;
	}
	refcount_set(&qp->refcnt, 1);
	spin_lock_init(&qp->lock);
	qp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qpn] = qp;
	qp->ibqp_state = qp_ctx->qp_state;

	ret = sxe2_qp_qset_init_and_resp(udata, rdma_dev, qpn, qp_ctx, qp);
	if (ret)
		goto qp_debugfs_remove;

	init_completion(&qp->free_qp);
	goto end;

qp_debugfs_remove:
	drv_rdma_debug_qp_remove(rdma_dev, qp);
qp_destroy_cmd:
	sxe2_mq_destroy_qp_cmd(qp);
free_qp_buf:
	if (qp->sw_cc_enable != SXE2_QP_DISABLE_SW_CC) {
		mutex_lock(&rf->cc_refcount.refcount_lock);
		atomic_dec(&rf->cc_refcount.cc_qp_refcount);
		mutex_unlock(&rf->cc_refcount.refcount_lock);
	}
	sxe2_free_qp_buf(qp, dev, udata);
free_host_ctx:
	dma_free_coherent(dev->hw->device, ALIGN(SXE2_QP_CTX_SIZE, 256),
			  init_info.host_ctx, init_info.host_ctx_pa);
	init_info.host_ctx = NULL;
free_qpn:
	if (init_attr->qp_type != IB_QPT_GSI)
		sxe2_kfree_rsrc(rf, rf->allocated_qps, qpn);
end:
	return ret;
}
#endif

#ifdef QUERY_PKEY_V1
int sxe2_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey)
#else
int sxe2_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey)
#endif
{
	int ret = 0;

	if (index >= SXE2_PKEY_TBL_SZ) {
		ret = -EINVAL;
		goto end;
	}
	*pkey = SXE2_DEFAULT_PKEY;
end:
	return ret;
}

static u16 sxe2_rdma_flow_label_to_udp_sport(u32 fl)
{
	u32 fl_low  = fl & 0x03FFF;
	u32 fl_high = fl & 0xFC000;

	fl_low ^= fl_high >> 14;

	return (u16)(fl_low | 0xc000);
}
static u32 sxe2_rdma_calc_flow_label(u32 local_qpn, u32 remote_qpn)
{
	u64 fl = (u64)local_qpn * remote_qpn;

	fl ^= fl >> 20;
	fl ^= fl >> 40;

	return (u32)(fl & 0x000FFFFF);
}
static u16 sxe2_rdma_get_udp_sport(u32 flow_label, u32 local_qpn,
				   u32 remote_qpn)
{
	if (!flow_label)
		flow_label = sxe2_rdma_calc_flow_label(local_qpn, remote_qpn);

	return sxe2_rdma_flow_label_to_udp_sport(flow_label);
}
static u8 sxe2_roce_get_vlan_prio(struct net_device __rcu *ndev_rcu, u8 prio)
{
	struct net_device *ndev;

	rcu_read_lock();
	ndev = rcu_dereference(ndev_rcu);
	if (!ndev)
		goto end;
	if (is_vlan_dev(ndev)) {
		u16 vlan_qos = (u16)vlan_dev_get_egress_qos_mask(ndev, prio);

		prio = (vlan_qos & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	}
end:
	rcu_read_unlock();
	return prio;
}
static int sxe2_set_roce_cm_info(struct sxe2_rdma_qp *qp,
				 struct ib_qp_attr *attr, u16 *vlan_id)
{
	const struct ib_gid_attr *sgid_attr;
	int ret		   = 0;
	struct sxe2_av *av = &qp->roce_ah.av;

	sgid_attr = attr->ah_attr.grh.sgid_attr;
	if (sgid_attr->ndev) {
#ifdef HAVE_NO_FIELD_GID
		*vlan_id = rdma_vlan_dev_vlan_id(sgid_attr->ndev);
		ether_addr_copy(qp->ctx_info.roce_info->mac_addr,
				sgid_attr->ndev->dev_addr);
#else
		ret = rdma_read_gid_l2_fields(sgid_attr, vlan_id,
					      qp->ctx_info.roce_info->mac_addr);
#endif
		if (ret)
			goto end;
	}
	av->net_type = rdma_gid_attr_network_type(sgid_attr);
	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	qp->ctx_info.user_pri =
		sxe2_roce_get_vlan_prio(sgid_attr->ndev, qp->ctx_info.user_pri);
	qp->qp_ctx.user_pri = qp->ctx_info.user_pri;
end:
	return ret;
}

static int sxe2_wait_for_suspend(struct sxe2_rdma_qp *qp)
{
	int ret = 0;

	if (!wait_event_timeout(qp->dev->suspend_wq, !qp->suspend_pending,
				msecs_to_jiffies(SXE2_EVENT_TIMEOUT_MS))) {
		qp->suspend_pending = false;
		ret		    = -EBUSY;
	}
	return ret;
}

void sxe2_sched_qp_flush_work(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_device *rdma_dev = qp->dev;

	if (qp->qp_ctx.qp_common.destroy_pending) {
		DRV_RDMA_LOG_DEV_ERR("qp:%d is destroying\n", qp->ibqp.qp_num);
		goto end;
	}

	sxe2_qp_add_ref(&qp->ibqp);
	if (mod_delayed_work(qp->dev->cleanup_wq, &qp->dwork_flush,
			     msecs_to_jiffies(SXE2_FLUSH_DELAY_MS))) {
		sxe2_qp_rem_ref(&qp->ibqp);
	}

end:
	return;
}

void sxe2_flush_wqe_worker(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct sxe2_rdma_qp *rdma_qp =
		container_of(dwork, struct sxe2_rdma_qp, dwork_flush);

	sxe2_generate_flush_completions(rdma_qp);

	sxe2_qp_rem_ref(&rdma_qp->ibqp);
}

static int drv_rel_rate_to_stat_rate(u32 rel_rate)
{
	u8 state_rate = 0;

	if (rel_rate > 0 && rel_rate <= SXE2_RATE_2_5_GBPS)
		state_rate = SXE2_IB_RATE_TAG_1;
	else if (rel_rate > SXE2_RATE_2_5_GBPS && rel_rate <= SXE2_RATE_10_GBPS)
		state_rate = SXE2_IB_RATE_TAG_2;
	else if (rel_rate > SXE2_RATE_10_GBPS && rel_rate <= SXE2_RATE_25_GBPS)
		state_rate = SXE2_IB_RATE_TAG_3;
	else if (rel_rate > SXE2_RATE_25_GBPS && rel_rate <= SXE2_RATE_40_GBPS)
		state_rate = SXE2_IB_RATE_TAG_4;
	else if (rel_rate > SXE2_RATE_40_GBPS && rel_rate <= SXE2_RATE_50_GBPS)
		state_rate = SXE2_IB_RATE_TAG_5;
	else if (rel_rate > SXE2_RATE_50_GBPS && rel_rate <= SXE2_RATE_60_GBPS)
		state_rate = SXE2_IB_RATE_TAG_6;
	else if (rel_rate > SXE2_RATE_60_GBPS && rel_rate <= SXE2_RATE_80_GBPS)
		state_rate = SXE2_IB_RATE_TAG_7;
	else if (rel_rate > SXE2_RATE_80_GBPS && rel_rate <= SXE2_RATE_100_GBPS)
		state_rate = SXE2_IB_RATE_TAG_8;
	else if (rel_rate > SXE2_RATE_100_GBPS)
		state_rate = SXE2_IB_RATE_TAG_8;

	return state_rate;
}

static int drv_ib_rate_to_sxe2(struct sxe2_rdma_qp *qp, u8 rate)
{
	int ret = 0;
	u32 rel_rate = 0;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	struct aux_core_dev_info *cdev_info =
		(struct aux_core_dev_info *)(qp->dev->rdma_func->cdev);
	u32 port_active_speed;
	u32 ib_rate_to_real_rate[STATA_RATE_MAX_CNT];

	ib_rate_to_real_rate[SXE2_IB_RATE_2_5_GBPS] = SXE2_RATE_2_5_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_5_GBPS]   = SXE2_RATE_5_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_10_GBPS]  = SXE2_RATE_10_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_20_GBPS]  = SXE2_RATE_20_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_30_GBPS]  = SXE2_RATE_30_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_40_GBPS]  = SXE2_RATE_40_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_60_GBPS]  = SXE2_RATE_60_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_80_GBPS]  = SXE2_RATE_80_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_120_GBPS] = SXE2_RATE_120_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_14_GBPS]  = SXE2_RATE_14_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_56_GBPS]  = SXE2_RATE_56_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_112_GBPS] = SXE2_RATE_112_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_168_GBPS] = SXE2_RATE_168_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_25_GBPS]  = SXE2_RATE_25_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_100_GBPS] = SXE2_RATE_100_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_200_GBPS] = SXE2_RATE_200_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_300_GBPS] = SXE2_RATE_300_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_28_GBPS]  = SXE2_RATE_28_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_50_GBPS]  = SXE2_RATE_50_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_400_GBPS] = SXE2_RATE_400_GBPS;
	ib_rate_to_real_rate[SXE2_IB_RATE_600_GBPS] = SXE2_RATE_600_GBPS;
	if (rdma_dev->rdma_func->ctx_dev.privileged) {
		port_active_speed = cdev_info->ops->rdma_get_link_speed(cdev_info);
	} else {
		ret = sxe2_vchnl_req_get_port_active_speed(
			&rdma_dev->rdma_func->ctx_dev, &port_active_speed);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("qp:vchnl get port active speed err ret=%d\n", ret);
			goto end;
		}
	}
	if (port_active_speed == SXE2_LINK_SPEED_UNKNOWN) {
		ret = -EPERM;
		DRV_RDMA_LOG_DEV_ERR("qp:port active speed is unknown\n");
		goto end;
	}
	if (rate == IB_RATE_PORT_CURRENT) {
		rel_rate = port_active_speed;
		DRV_RDMA_LOG_DEV_DEBUG("qp:rate %u rel rate %u\n", rate, rel_rate);
	} else if (rate < SXE2_IB_RATE_2_5_GBPS || rate > SXE2_IB_RATE_600_GBPS) {
		ret = -EINVAL;
		goto end;
	} else {
		rel_rate = ib_rate_to_real_rate[rate];
		if (rel_rate > port_active_speed)
			rel_rate = port_active_speed;
	}
	qp->ctx_info.roce_info->state_rate = drv_rel_rate_to_stat_rate(rel_rate);
	DRV_RDMA_LOG_DEV_DEBUG("qp:user rate %u rel_rate %u state_rate:%u\n",
		rate, rel_rate, qp->ctx_info.roce_info->state_rate);
end:
	return ret;
}

static int sxe2_rdma_encoding_rd_atomic(u8 max_rd_atomic,
					struct sxe2_rdma_qp *qp, bool is_sra)
{
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	u16 log_val			  = 0;
	int ret				  = 0;

	if (max_rd_atomic > SXE2_MAX_RD_ATOMIC) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"max_rd_atomic must be [0,64], now is %u\n",
			max_rd_atomic);
		goto end;
	} else if (max_rd_atomic == SXE2_MIN_LOG_RD_ATOMIC) {
		log_val = SXE2_MIN_LOG_RD_ATOMIC;
	} else {
		log_val = (u16)fls((u32)(max_rd_atomic - 1));
	}

	if (is_sra)
		qp->ctx_info.roce_info->log_sra_max = log_val;
	else
		qp->ctx_info.roce_info->log_rra_max = log_val;

end:
	return ret;
}

static u8 sxe2_rdma_decoding_rd_atomic(u16 log_rd_atomic)
{
	u8 cal_val = 0;

	if (log_rd_atomic <= SXE2_ENCODING_READ_3)
		cal_val = SXE2_MIN_RD_ATOMIC;
	else if (log_rd_atomic >= SXE2_ENCODING_READ_7)
		cal_val = SXE2_MAX_RD_ATOMIC;
	else
		cal_val = (1 << log_rd_atomic);
	return cal_val;
}

static void sxe2_flush_wqes(struct sxe2_rdma_qp *qp, u32 flush_op)
{
	struct sxe2_rdma_pci_f *rdma_func = qp->dev->rdma_func;
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_qpc *qpc;
	unsigned long flags;

	if (!(flush_op & SXE2_FLUSH_SQ) && !(flush_op & SXE2_FLUSH_RQ)) {
		DRV_RDMA_LOG_DEV_DEBUG("SQ/RQ flush_op not valid\n");
		goto end;
	}

	if (flush_op & SXE2_REFLUSH) {
		if (qp->qp_ctx.flush_sq || qp->qp_ctx.flush_rq) {
			qp->qp_ctx.flush_sq = false;
			qp->qp_ctx.flush_rq = false;
		} else {
			DRV_RDMA_LOG_DEV_ERR(
				"reflush, but last sq/rq flush flag not valid\n");
			goto end;
		}
		if (flush_op & SXE2_FLUSH_SQ) {
			if (sxe2_mq_query_qp_cmd(qp)) {
				DRV_RDMA_LOG_DEV_ERR(
					"sxe2_mq_query_qp_cmd failed\n");
				goto end;
			}
			qpc = (struct sxe2_qpc *)qp->host_ctx.va;
			if (qpc->sq_flush_flag != qpc->txeng_sq_flush_flag) {
				DRV_RDMA_LOG_DEV_WARN(
					"reflush, but hw not finish last sq flush\n");
			} else {
				qp->qp_ctx.flush_sq = true;
			}
		}
		if (flush_op & SXE2_FLUSH_RQ)
			qp->qp_ctx.flush_rq = true;
	} else {
		if (flush_op & SXE2_FLUSH_SQ)
			qp->qp_ctx.flush_sq = true;
		if (flush_op & SXE2_FLUSH_RQ)
			qp->qp_ctx.flush_rq = true;
	}

	if (qp->qp_ctx.flush_sq || qp->qp_ctx.flush_rq) {
		spin_lock_irqsave(&qp->lock, flags);
		qp->flush_issued = true;
		spin_unlock_irqrestore(&qp->lock, flags);
	}

	DRV_RDMA_LOG_DEV_DEBUG(
		"flush out:qp %#x, op %u, sq_flush: %u, rq_flush: %u, flush_issued: %u\n",
		qp->qp_ctx.qp_common.qpn, flush_op, qp->qp_ctx.flush_sq,
		qp->qp_ctx.flush_rq, qp->flush_issued);
end:
	return;
}

static int sxe2_check_modify_qp_attrs(struct ib_qp_attr *attr, int attr_mask,
				      struct sxe2_rdma_device *rdma_dev,
				      struct ib_udata *udata)
{
	int ret = 0;

	if (udata && (udata->inlen < sizeof(struct sxe2_modify_qp_req) ||
		      udata->outlen < sizeof(struct sxe2_modify_qp_resp))) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"udata illegal! , udata->inlen(%zu) udata->outlen(%zu)\n",
			udata->inlen, udata->outlen);
		goto end;
	}

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS) {
		ret = -EOPNOTSUPP;
		DRV_RDMA_LOG_DEV_ERR("attr_mask illegal, attr_mask(%d)\n",
				     attr_mask);
		goto end;
	}

end:
	return ret;
}

static int sxe2_modify_qp_roce_info_set(struct ib_qp *ibqp,
					struct ib_qp_attr *attr, int attr_mask)
{
	int ret					 = 0;
	struct sxe2_rdma_qp *qp			 = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev	 = qp->dev;
	struct sxe2_roce_offload_info *roce_info = &qp->roce_info;

	if (attr_mask & IB_QP_DEST_QPN)
		roce_info->dest_qp = attr->dest_qp_num;
	if (attr_mask & IB_QP_PKEY_INDEX) {
		ret = sxe2_query_pkey(ibqp->device, 0, attr->pkey_index,
				      &roce_info->p_key);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"sxe2_query_pkey fail, pkey_index(%u) ret(%d)\n",
				attr->pkey_index, ret);
			goto end;
		}
		roce_info->p_key = attr->pkey_index;
	}
	if (attr_mask & IB_QP_QKEY)
		roce_info->qkey = attr->qkey;
end:
	return ret;
}

static void sxe2_modify_qp_ctx_info_set(struct sxe2_rdma_qp *qp,
					struct sxe2_rdma_pd *pd,
					struct sxe2_qp_host_ctx_info *ctx_info)
{
	if (qp->qp_ctx.qp_common.qp_type == IB_QPT_UD) {
		if (qp->gsi_flag)
			ctx_info->log_msg_max = SXE2_LOG_MSG_8;
		else
			ctx_info->log_msg_max = SXE2_LOG_MSG_12;
	} else {
		ctx_info->log_msg_max = SXE2_LOG_MSG_31;
	}
	ctx_info->roce_info->pd_id = pd->pd_ctx.pd_id;
}

static int sxe2_modify_qp_qset_and_vlan_set(struct ib_qp *ibqp,
					    struct ib_qp_attr *attr,
					    int attr_mask)
{
	int ret				       = 0;
	struct sxe2_rdma_qp *qp		       = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_qp_host_ctx_info *ctx_info = &qp->ctx_info;
	struct sxe2_udp_offload_info *udp_info = &qp->udp_info;
	u16 vlan_id			       = VLAN_N_VID;

	ret = sxe2_set_roce_cm_info(qp, attr, &vlan_id);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_set_roce_cm_info fail, ret(%d)\n",
				     ret);
		goto end;
	}
	if (rdma_dev->vsi.lag_aa)
		ret = sxe2_qos_register_qset_bond(&rdma_dev->vsi,
						  ctx_info->user_pri);
	else
		ret = sxe2_qos_register_qset(&rdma_dev->vsi,
					     ctx_info->user_pri);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_qos_register_qset fail, aa(%d), ret(%d)\n",
			rdma_dev->vsi.lag_aa, ret);
		goto end;
	}
	qp->qp_ctx.user_pri = ctx_info->user_pri;
	if (rdma_dev->vsi.lag_aa)
		ret = sxe2_qos_qp_add_qos_bond(&rdma_dev->vsi, &qp->qp_ctx);
	else
		ret = sxe2_qos_qp_add_qos(&rdma_dev->vsi, &qp->qp_ctx);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"sxe2_qos_qp_add_qos fail, aa(%d), ret(%d)\n",
			rdma_dev->vsi.lag_aa, ret);
		goto end;
	}
	if (vlan_id >= VLAN_N_VID && rdma_dev->dcb_vlan_mode)
		vlan_id = 0;
	if (vlan_id < VLAN_N_VID) {
		udp_info->insert_vlan_tag = true;
		udp_info->vlan_tag	  = vlan_id | ctx_info->user_pri
						       << VLAN_PRIO_SHIFT;
	} else {
		udp_info->insert_vlan_tag = false;
	}

end:
	return ret;
}

static int sxe2_rdma_gid_to_ip(struct sxe2_av *av, struct ib_qp_attr *attr,
			       struct sxe2_rdma_qp *qp)
{
	int ret				       = 0;
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_udp_offload_info *udp_info = &qp->udp_info;

	rdma_gid2ip((struct sockaddr *)&av->dgid_addr, &attr->ah_attr.grh.dgid);
	if (av->net_type == RDMA_NETWORK_IPV6) {
		__be32 *daddr =
			av->dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
		__be32 *saddr =
			av->sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32;
		sxe2_copy_ip_ntohl(&udp_info->dest_ip_addr[0], daddr);
		sxe2_copy_ip_ntohl(&udp_info->local_ipaddr[0], saddr);
		udp_info->ipv4 = false;
	} else if (av->net_type == RDMA_NETWORK_IPV4) {
		__be32 saddr = av->sgid_addr.saddr_in.sin_addr.s_addr;
		__be32 daddr = av->dgid_addr.saddr_in.sin_addr.s_addr;

		udp_info->ipv4		  = true;
		udp_info->dest_ip_addr[0] = 0;
		udp_info->dest_ip_addr[1] = 0;
		udp_info->dest_ip_addr[2] = 0;
		udp_info->dest_ip_addr[3] = ntohl(daddr);
		udp_info->local_ipaddr[0] = 0;
		udp_info->local_ipaddr[1] = 0;
		udp_info->local_ipaddr[2] = 0;
		udp_info->local_ipaddr[3] = ntohl(saddr);
	} else {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("net_type illegal, av->net_type(%d)\n",
				     av->net_type);
		goto end;
	}

end:
	return ret;
}

static int sxe2_modify_qp_udp_info_set(struct ib_qp *ibqp,
				       struct ib_qp_attr *attr, int attr_mask)
{
	int ret					 = 0;
	u32 active_mtu				 = 0;
	struct sxe2_rdma_qp *qp			 = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev	 = qp->dev;
	struct sxe2_qp_host_ctx_info *ctx_info	 = &qp->ctx_info;
	struct sxe2_udp_offload_info *udp_info	 = &qp->udp_info;
	struct sxe2_roce_offload_info *roce_info = &qp->roce_info;
	struct sxe2_av *av			 = &qp->roce_ah.av;
	u32 ib_mtu				 = 0;
	bool cur_dscp_mode       = 0;

	if (attr_mask & IB_QP_PATH_MTU) {
		if (attr->path_mtu < IB_MTU_256 ||
		    attr->path_mtu > IB_MTU_4096) {
			ret = -EINVAL;
			DRV_RDMA_LOG_DEV_ERR("path_mtu illegal, path_mtu(%d)\n",
					     attr->path_mtu);
			goto end;
		}
		ib_mtu	   = (u32)sxe2_iboe_get_mtu((int)rdma_dev->netdev->mtu);
		active_mtu = min_t(u32, (u32)IB_MTU_4096, ib_mtu);
		udp_info->pmtu = min_t(u32, active_mtu, (u32)attr->path_mtu);
	}

	if (attr_mask & IB_QP_SQ_PSN)
		udp_info->sq_psn = attr->sq_psn;
	if (attr_mask & IB_QP_RQ_PSN)
		udp_info->rq_psn = attr->rq_psn;
	if (attr_mask & IB_QP_RNR_RETRY)
		udp_info->rnr_retry = attr->rnr_retry;
	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		udp_info->min_rnr_timer = attr->min_rnr_timer;
	if (attr_mask & IB_QP_RETRY_CNT)
		udp_info->retry_cnt = attr->retry_cnt;

	if (attr_mask & IB_QP_TIMEOUT) {
		udp_info->ack_timeout =
			(attr->timeout > SXE2_MAX_ACK_TIMEOUT_VAL) ?
				SXE2_MAX_ACK_TIMEOUT_VAL :
				attr->timeout;
	} else {
		udp_info->ack_timeout =
			(rdma_dev->roce_rtomin > SXE2_MAX_ACK_TIMEOUT_VAL) ?
				SXE2_MAX_ACK_TIMEOUT_VAL :
				rdma_dev->roce_rtomin;
	}

	if (attr_mask & IB_QP_AV) {
		ether_addr_copy(roce_info->dest_mac_addr,
				ah_attr_to_dmac(attr->ah_attr));
		memset(&qp->roce_ah, 0, sizeof(qp->roce_ah));
		if (attr->ah_attr.ah_flags & IB_AH_GRH) {
			udp_info->ttl	     = attr->ah_attr.grh.hop_limit;
			udp_info->flow_label = attr->ah_attr.grh.flow_label;
			udp_info->dscp = attr->ah_attr.grh.traffic_class >> 2;
			udp_info->ecn  = attr->ah_attr.grh.traffic_class & 0x3;
			udp_info->src_port =
				sxe2_rdma_get_udp_sport(udp_info->flow_label,
							ibqp->qp_num,
							roce_info->dest_qp);
			ret = sxe2_qos_qp_rem_qos(&rdma_dev->vsi, &qp->qp_ctx);
			if (ret) {
				DRV_RDMA_LOG_DEV_ERR(
					"sxe2_qos_qp_rem_qos fail, ret(%d)\n",
					ret);
				goto end;
			}
			if (rdma_dev->vsi.lag_aa)
				sxe2_qos_unregister_qset_bond(
					&rdma_dev->vsi, qp->qp_ctx.user_pri);
			else
				sxe2_qos_unregister_qset(&rdma_dev->vsi,
							 qp->qp_ctx.user_pri);
			if (rdma_dev->vsi.lag_aa)
				cur_dscp_mode = qp->qp_ctx.vsi->dscp_mode[qp->qp_ctx.qset_idx];
			else
				cur_dscp_mode = qp->qp_ctx.vsi->dscp_mode[QOS_QSET_IDX_0];

			if (rdma_dev->vsi.lag_aa && cur_dscp_mode) {
				ctx_info->user_pri =
				qp->qp_ctx.vsi->dscp_map[qp->qp_ctx.qset_idx][udp_info->dscp];
			} else if (cur_dscp_mode) {
				ctx_info->user_pri =
				qp->qp_ctx.vsi->dscp_map[QOS_QSET_IDX_0][udp_info->dscp];

			} else {
				ctx_info->user_pri = (u8)rt_tos2priority(
					attr->ah_attr.grh.traffic_class);
			}
			if (ctx_info->user_pri >= SXE2_MAX_USER_PRIORITY) {
				DRV_RDMA_LOG_DEV_ERR("user pri error, val(%d)\n",
					ctx_info->user_pri);
				ctx_info->user_pri = 0;
			}
		}

		ret = drv_ib_rate_to_sxe2(qp,
				    rdma_ah_get_static_rate(&attr->ah_attr));
		if (ret)
			goto end;

		ret = sxe2_modify_qp_qset_and_vlan_set(ibqp, attr, attr_mask);
		if (ret)
			goto end;

		av->attrs = attr->ah_attr;
		ret = sxe2_rdma_gid_to_ip(av, attr, qp);
		if (ret)
			goto end;
	}
end:
	return ret;
}

static int sxe2_qp_state_info_set(struct sxe2_rdma_qp *qp,
				  struct ib_qp_attr *attr, int attr_mask,
				  struct ib_udata *udata, u8 *issue_modify_qp)
{
	int ret				  = 0;
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	unsigned long flags;

#ifdef NEED_LINK_LAYER
	if (!ib_modify_qp_is_ok(qp->ibqp_state, attr->qp_state,
				qp->ibqp.qp_type, attr_mask, IB_LINK_LAYER_ETHERNET)) {
#else
	if (!ib_modify_qp_is_ok(qp->ibqp_state, attr->qp_state,
				qp->ibqp.qp_type, attr_mask)) {
#endif

		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"modify qp illegal, cur_state(%d)\n"
			"\tnext_state(%d) qp_type(%d) attr_mask(%d)\n",
			qp->ibqp_state, attr->qp_state, qp->ibqp.qp_type,
			attr_mask);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG(
		"modify qp%#x cure_state(%d) next_state(%d) qp_type(%d) attr_mask(%d)\n",
		qp->ibqp.qp_num, qp->ibqp_state, attr->qp_state,
		qp->ibqp.qp_type, attr_mask);
	switch (attr->qp_state) {
	case IB_QPS_INIT:
		*issue_modify_qp = 1;
		break;
	case IB_QPS_RTR:
		*issue_modify_qp = 1;
		break;
	case IB_QPS_RTS:
		*issue_modify_qp = 1;
		break;
	case IB_QPS_SQD:
		if (qp->ibqp_state == IB_QPS_SQD) {
			DRV_RDMA_LOG_DEV_DEBUG("QP trans from SQD TO SQD\n");
			goto end;
		}

		*issue_modify_qp    = 1;
		qp->suspend_pending = true;
		break;
	case IB_QPS_ERR:
		*issue_modify_qp = 1;
		break;
	case IB_QPS_RESET:
		*issue_modify_qp = 1;
		spin_lock_irqsave(&qp->lock, flags);
		qp->flush_issued = 0;
		spin_unlock_irqrestore(&qp->lock, flags);
		qp->qp_ctx.flush_rq	     = 0;
		qp->qp_ctx.flush_sq	     = 0;
		qp->qp_ctx.sq_flush_polarity = 0;
		if (!udata) {
			if (qp->send_cq) {
				sxe2_clean_cqes(qp, qp->send_cq, SQ_CQ);
				if ((qp->recv_cq) &&
				    (qp->recv_cq != qp->send_cq))
					sxe2_clean_cqes(qp, qp->recv_cq, RQ_CQ);
			}
			qp->qp_ctx.qp_common.rq_ring.head      = 0;
			qp->qp_ctx.qp_common.rq_ring.tail      = 0;
			qp->qp_ctx.qp_common.sq_ring.head      = 0;
			qp->qp_ctx.qp_common.sq_ring.tail      = 0;
			qp->qp_ctx.qp_common.initial_ring.head = 0;
			qp->qp_ctx.qp_common.initial_ring.tail = 0;
			qp->qp_ctx.qp_common.rwqe_polarity     = 0;
			qp->qp_ctx.qp_common.swqe_polarity     = 0;
			qp->qp_ctx.qp_common.llwqe_mode	       = false;
			memset(qp->kqp.dma_mem.va, 0, qp->kqp.dma_mem.size);
		}
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"next qp state illegal, attr->qp_state(%d)\n",
			attr->qp_state);
		goto end;
	}
end:
	return ret;
}

static int sxe2_qp_state_change(struct sxe2_rdma_qp *qp,
				struct ib_qp_attr *attr, int attr_mask,
				struct ib_udata *udata, u8 *issue_modify_qp,
				struct sxe2_modify_qp_resp *uresp)
{
	int ret				       = 0;
	int tmp_ret				   = 0;
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_qp_host_ctx_info *ctx_info = &qp->ctx_info;
	struct sxe2_modify_qp_req ucmd;
	u32 db_page_id = 0;
	u8 new_llwqe_page_alloc = false;

	if (attr_mask & IB_QP_STATE) {
		ret = sxe2_qp_state_info_set(qp, attr, attr_mask, udata,
					     issue_modify_qp);
		if (ret)
			goto end;
	}
	ctx_info->send_cq_num = qp->send_cq->cq_ctx.cq_uk.cq_id;
	ctx_info->rcv_cq_num  = qp->recv_cq->cq_ctx.cq_uk.cq_id;
	qp->qp_ctx.qp_state   = attr->qp_state;

	if (udata) {
		memset(&ucmd, 0, sizeof(ucmd));
		if (ib_copy_from_udata(&ucmd, udata, udata->inlen)) {
			ret = -EFAULT;
			DRV_RDMA_LOG_DEV_ERR("copy fail len %zu , ret (%d)\n",
					     udata->inlen, ret);
			goto end;
		}
		db_page_id = ucmd.llwqe_page_index;
		new_llwqe_page_alloc = ucmd.new_page_alloc;
		ctx_info->llwqe_mod_enable = ucmd.llwqe_enable;
		if (attr->qp_state == IB_QPS_RTS) {
			if (new_llwqe_page_alloc) {
				tmp_ret = db_kalloc_llwqe_mmap_entry(
						rdma_dev, udata, qp,
						&uresp->db_page_id, &uresp->db_mmap_size,
						&uresp->db_mmap_offset);
				if (tmp_ret) {
					uresp->db_page_id = 0;
					uresp->db_mmap_size = 0;
					uresp->db_mmap_offset = 0;
					DRV_RDMA_LOG_DEV_WARN(
						"db_kalloc_llwqe_mmap_entry failed.\n");
				}
				if (!db_page_id) {
					ctx_info->llwqe_mod_enable = true;
					db_page_id = uresp->db_page_id;
				}
			}
			if (ctx_info->llwqe_mod_enable) {
				if (rdma_dev->rdma_func->ctx_dev.privileged) {
					ctx_info->llwqe_page_index =
						(SXE2_PF_DB_PAGE_BAR_OFFSET(
							db_page_id) >>
						SXE2_RDMA_DB_PAGE_SHIFT);
				} else {
					ctx_info->llwqe_page_index =
						(SXE2_VF_DB_PAGE_BAR_OFFSET(
						db_page_id) >>
						SXE2_RDMA_DB_PAGE_SHIFT);
				}
			}
		}
		if (qp->qp_ctx.qp_state == IB_QPS_ERR) {
			sxe2_flush_wqes(qp,
					(ucmd.sq_flush ? SXE2_FLUSH_SQ : 0) |
						(ucmd.rq_flush ? SXE2_FLUSH_RQ :
								 0) |
						SXE2_REFLUSH);
		}
	} else if (!qp->user_mod) {
		if (rdma_dev->kernel_llwqe_mode == 0) {
			ctx_info->llwqe_mod_enable	= false;
			ctx_info->llwqe_page_index	= 0;
			qp->qp_ctx.qp_common.llwqe_mode = false;
		} else {
			ctx_info->llwqe_mod_enable	= true;
			qp->qp_ctx.qp_common.llwqe_mode = true;
			if (rdma_dev->rdma_func->ctx_dev.privileged) {
				ctx_info->llwqe_page_index =
					(SXE2_PF_DB_PAGE_BAR_OFFSET(
						 qp->qp_ctx.qp_common.llwqe
							 ->index) >>
					 SXE2_RDMA_DB_PAGE_SHIFT);
			} else {
				ctx_info->llwqe_page_index =
					(SXE2_VF_DB_PAGE_BAR_OFFSET(
						 qp->qp_ctx.qp_common.llwqe
							 ->index) >>
					 SXE2_RDMA_DB_PAGE_SHIFT);
			}
		}
	}
	if ((attr_mask & IB_QP_STATE) && *issue_modify_qp &&
	    qp->qp_ctx.qp_state == IB_QPS_ERR && !qp->flush_issued) {
		if ((udata && !ucmd.sq_flush && !ucmd.rq_flush) || !udata)
			sxe2_flush_wqes(qp, SXE2_FLUSH_SQ | SXE2_FLUSH_RQ);
		else
			DRV_RDMA_LOG_DEV_DEBUG("data no flush condition\n");
	}
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_swState_jump",
		     &rdma_dev->rdma_func->mq.err_cqe_val, attr, qp);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_swState_jump");
#endif
	sxe2_ctx_qp_setctx_roce(qp, qp->host_ctx.va);
	DRV_RDMA_LOG_DEV_DEBUG("modify qp%#x qpc print:\n", qp->ibqp.qp_num);
	sxe2_print_qpc_info(rdma_dev, qp->host_ctx.va);
end:
	return ret;
}

int sxe2_kmodify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata)
{
	struct sxe2_rdma_pd *pd		       = to_pd(ibqp->pd);
	struct sxe2_rdma_qp *qp		       = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_qp_host_ctx_info *ctx_info = &qp->ctx_info;
	u8 issue_modify_qp		       = 0;
	int ret				       = 0;
	struct sxe2_modify_qp_resp uresp       = {0};
	unsigned long flags;

	ret = sxe2_check_modify_qp_attrs(attr, attr_mask, rdma_dev, udata);
	if (ret)
		goto end;

	ret = sxe2_modify_qp_roce_info_set(ibqp, attr, attr_mask);
	if (ret)
		goto end;

	sxe2_modify_qp_ctx_info_set(qp, pd, ctx_info);

	ret = sxe2_modify_qp_udp_info_set(ibqp, attr, attr_mask);
	if (ret)
		goto end;

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		ret = sxe2_rdma_encoding_rd_atomic(attr->max_rd_atomic, qp,
						   true);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("max_rd_atomic must be [0,64]\n");
			goto end;
		}
	}
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		ret = sxe2_rdma_encoding_rd_atomic(attr->max_dest_rd_atomic, qp,
						   false);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"max_dest_rd_atomic must be [0,64]\n");
			goto end;
		}
	}

	ret = sxe2_qp_state_change(qp, attr, attr_mask, udata,
				   &issue_modify_qp, &uresp);
	if (ret)
		goto end;

	if (attr_mask & IB_QP_STATE) {
		if (issue_modify_qp) {
			ret = sxe2_mq_modify_qp_cmd(qp);
			if (ret) {
				DRV_RDMA_LOG_DEV_ERR(
					"sxe2_mq_modify_qp_cmd fail\n");
				goto end;
			}
			if (attr->qp_state == IB_QPS_SQD) {
				ret = sxe2_wait_for_suspend(qp);
				if (ret) {
					DRV_RDMA_LOG_DEV_ERR(
						"sxe2_wait_for_suspend fail, ret(%d)\n",
						ret);
					goto end;
				}
			}
			spin_lock_irqsave(&qp->lock, flags);
			qp->ibqp_state = attr->qp_state;
			spin_unlock_irqrestore(&qp->lock, flags);

			if (qp->ibqp_state == IB_QPS_ERR && !qp->user_mod)
				sxe2_sched_qp_flush_work(qp);
		} else {
			spin_lock_irqsave(&qp->lock, flags);
			qp->ibqp_state = attr->qp_state;
			spin_unlock_irqrestore(&qp->lock, flags);
		}

		if (udata) {
			uresp.rd_fence_rate = rdma_dev->rd_fence_rate;
			ret		    = ib_copy_to_udata(udata, &uresp,
					       min(sizeof(uresp),
						   udata->outlen));
			if (ret) {
				DRV_RDMA_LOG_DEV_ERR(
					"ib_copy_to_udata failed , err(%d)\n",
					ret);
				goto end;
			}
		}
	}

end:
	return ret;
}

static u8 drv_sxe2_rate_to_ib(struct sxe2_rdma_qp *qp)
{
	u8 state_rate = 0;

	switch (qp->ctx_info.roce_info->state_rate) {
	case SXE2_IB_RATE_TAG_0:
		state_rate = IB_RATE_PORT_CURRENT;
		break;
	case SXE2_IB_RATE_TAG_1:
		state_rate = IB_RATE_2_5_GBPS;
		break;
	case SXE2_IB_RATE_TAG_2:
		state_rate = IB_RATE_10_GBPS;
		break;
	case SXE2_IB_RATE_TAG_3:
		state_rate = IB_RATE_25_GBPS;
		break;
	case SXE2_IB_RATE_TAG_4:
		state_rate = IB_RATE_40_GBPS;
		break;
#ifndef NOT_SURPORT_50_GBPS
	case SXE2_IB_RATE_TAG_5:
		state_rate = IB_RATE_50_GBPS;
		break;
#else
	case SXE2_IB_RATE_TAG_5:
		state_rate = IB_RATE_56_GBPS;
		break;
#endif

	case SXE2_IB_RATE_TAG_6:
		state_rate = IB_RATE_60_GBPS;
		break;
	case SXE2_IB_RATE_TAG_7:
		state_rate = IB_RATE_80_GBPS;
		break;
	case SXE2_IB_RATE_TAG_8:
		state_rate = IB_RATE_100_GBPS;
		break;
	default:
		break;
	}

	return state_rate;
}

int sxe2_kquery_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		   int qp_attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct sxe2_rdma_qp *qp		= to_qp(ibqp);
	struct sxe2_rdma_ctx_qp *qp_ctx = &qp->qp_ctx;

	memset(attr, 0, sizeof(*attr));
	memset(init_attr, 0, sizeof(*init_attr));

	attr->qp_state		  = qp->ibqp_state;
	attr->cur_qp_state	  = qp->ibqp_state;
	attr->cap.max_send_wr	  = qp->max_send_wr;
	attr->cap.max_recv_wr	  = qp->max_recv_wr;
	attr->cap.max_inline_data = qp_ctx->qp_common.max_inline_data;
	attr->cap.max_send_sge	  = qp_ctx->qp_common.max_sq_sge_cnt;
	attr->cap.max_recv_sge	  = qp_ctx->qp_common.max_rq_sge_cnt;

	attr->qp_access_flags =
		(IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE |
		 IB_ACCESS_REMOTE_READ);

	attr->port_num	  = 1;
	attr->path_mtu	  = qp->udp_info.pmtu;
	attr->qkey	  = qp->roce_info.qkey;
	attr->rq_psn	  = qp->udp_info.rq_psn;
	attr->sq_psn	  = qp->udp_info.sq_psn;
	attr->dest_qp_num = qp->roce_info.dest_qp;
	attr->pkey_index  = qp->roce_info.p_key;

	attr->retry_cnt	    = qp->udp_info.retry_cnt;
	attr->rnr_retry	    = qp->udp_info.rnr_retry;
	attr->min_rnr_timer = qp->udp_info.min_rnr_timer;

	attr->max_rd_atomic =
		sxe2_rdma_decoding_rd_atomic(qp->roce_info.log_sra_max);
	attr->max_dest_rd_atomic =
		sxe2_rdma_decoding_rd_atomic(qp->roce_info.log_rra_max);

	memcpy(&attr->ah_attr, &qp->roce_ah.av.attrs, sizeof(attr->ah_attr));
	attr->ah_attr.type	  = RDMA_AH_ATTR_TYPE_ROCE;
	attr->ah_attr.static_rate = drv_sxe2_rate_to_ib(qp);

	attr->timeout	   = qp->udp_info.ack_timeout;
	init_attr->qp_type = qp->ibqp.qp_type;

	init_attr->event_handler = qp->ibqp.event_handler;
	init_attr->qp_context	 = qp->ibqp.qp_context;
	init_attr->send_cq	 = qp->ibqp.send_cq;
	init_attr->recv_cq	 = qp->ibqp.recv_cq;
	init_attr->srq		 = qp->ibqp.srq;
	init_attr->cap		 = attr->cap;

	return 0;
}

static int sxe2_destroy_cc_qp(struct sxe2_rdma_device *rdma_dev, u32 cc_qp_idx)
{
	int ret				    = SXE2_OK;
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct sxe2_destroy_cc_qp_info info;

	if (cc_qp_idx >= SXE2_MAX_CC_QP_IDX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("qp:destroy cc qp idx err idx=%u\n",
				       cc_qp_idx);
		goto end;
	}
	DRV_RDMA_LOG_DEBUG_BDF("qp:destroy cc qp idx=%u\n", cc_qp_idx);
	info.cc_qp_idx = cpu_to_le32(cc_qp_idx);

	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_DESTROY_CC_QP,
					    (u8 *)&info, (u16)sizeof(info),
					    NULL, 0);
	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF("qp:aq send destroy cc qp err ret=%d\n",
				       ret);
		goto end;
	}

end:
	return ret;
}

 #ifdef DESTROY_QP_V1
int sxe2_kdestroy_qp(struct ib_qp *ibqp)
 #else
int sxe2_kdestroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
#endif
{
	struct sxe2_rdma_qp *qp		  = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	struct sxe2_rdma_pci_f *rf	  = rdma_dev->rdma_func;
	int ret				  = 0;
#ifndef HAVE_NO_REF_COUNT
	DRV_RDMA_LOG_DEV_DEBUG("qp:kdestroy qp start, ibdev refcount=%u\n",
			       refcount_read(&rdma_dev->ibdev.refcount));
#endif
	if (qp->qp_ctx.qp_common.destroy_pending)
		goto free_rsrc;
	qp->qp_ctx.qp_common.destroy_pending = true;

	if (!qp->user_mod) {
		if (qp->send_cq) {
			sxe2_clean_cqes(qp, qp->send_cq, SQ_CQ);
			if ((qp->recv_cq) && (qp->recv_cq != qp->send_cq))
				sxe2_clean_cqes(qp, qp->recv_cq, RQ_CQ);
		}
	}

	sxe2_qp_rem_ref(&qp->ibqp);
	wait_for_completion(&qp->free_qp);

	if (qp->sw_cc_enable) {
		DRV_RDMA_LOG_DEBUG_BDF("qp:destroy cc qp idx %u\n",
				       qp->sw_cc_idx);
		ret = sxe2_destroy_cc_qp(rdma_dev, qp->sw_cc_idx);
		if (ret)
			DRV_RDMA_LOG_ERROR_BDF("qp:%d destroy cc qp failed\n",
					       qp->qp_ctx.qp_common.qpn);
	}

	ret = sxe2_mq_destroy_qp_cmd(qp);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("qp:%d destroy failed\n",
				     qp->qp_ctx.qp_common.qpn);

free_rsrc:
	if (qp->sw_cc_enable) {
		mutex_lock(&rf->cc_refcount.refcount_lock);
		atomic_dec(&rf->cc_refcount.cc_qp_refcount);
		mutex_unlock(&rf->cc_refcount.refcount_lock);
	}
	drv_rdma_debug_qp_remove(rdma_dev, qp);
	if (qp->qp_ctx.vsi) {
		(void)sxe2_qos_qp_rem_qos(&rdma_dev->vsi, &qp->qp_ctx);
		if (rdma_dev->vsi.lag_aa)
			sxe2_qos_unregister_qset_bond(&rdma_dev->vsi,
						      qp->qp_ctx.user_pri);
		else
			sxe2_qos_unregister_qset(&rdma_dev->vsi,
						 qp->qp_ctx.user_pri);
	}
#ifndef DESTROY_QP_V1
	sxe2_free_qp_buf(qp, &rdma_dev->rdma_func->ctx_dev, udata);
#endif
	if (qp->ibqp.qp_type != IB_QPT_GSI) {
		sxe2_kfree_rsrc(rdma_dev->rdma_func,
				rdma_dev->rdma_func->allocated_qps,
				qp->ibqp.qp_num);
	}

	if (qp->qp_ctx.hw_host_ctx != NULL) {
		dma_free_coherent(rdma_dev->rdma_func->ctx_dev.hw->device,
				  ALIGN(SXE2_QP_CTX_SIZE, 256),
				  qp->qp_ctx.hw_host_ctx,
				  qp->qp_ctx.hw_host_ctx_pa);
		qp->qp_ctx.hw_host_ctx = NULL;
	}
#ifdef CREATE_QP_VER_1
	kfree(qp);
#endif
	return 0;
}

void sxe2_ib_qp_event(struct sxe2_rdma_qp *qp, enum sxe2_qp_event_type event)
{
	struct ib_event ibevent;

	if (!qp->ibqp.event_handler)
		goto out;

	switch (event) {
	case SXE2_QP_EVENT_CATASTROPHIC:
		ibevent.event = IB_EVENT_QP_FATAL;
		break;
	case SXE2_QP_EVENT_ACCESS_ERR:
		ibevent.event = IB_EVENT_QP_ACCESS_ERR;
		break;
	case SXE2_QP_EVENT_REQ_ERR:
		ibevent.event = IB_EVENT_QP_REQ_ERR;
		break;
	case SXE2_QP_EVENT_COMM_EST:
		ibevent.event = IB_EVENT_COMM_EST;
		break;
	case SXE2_QP_EVENT_QP_LASTWQE_REACHED:
		ibevent.event = IB_EVENT_QP_LAST_WQE_REACHED;
		break;
	default:
		break;
	}

	ibevent.device	   = qp->ibqp.device;
	ibevent.element.qp = &qp->ibqp;
	qp->ibqp.event_handler(&ibevent, qp->ibqp.qp_context);

out:
	return;
}

static void sxe2_qp_cm_disconn_true(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_qp *qp_ctx = &qp->qp_ctx;
	unsigned long flags		= 0;
	struct ib_qp_attr attr;

	rdma_dev = qp->dev;
	spin_lock_irqsave(&qp->lock, flags);

	if ((qp->flush_issued) || (qp_ctx->qp_common.destroy_pending)) {
		spin_unlock_irqrestore(&qp->lock, flags);
		goto out;
	}

	spin_unlock_irqrestore(&qp->lock, flags);
	attr.qp_state = IB_QPS_ERR;
	sxe2_kmodify_qp(&qp->ibqp, &attr, IB_QP_STATE, NULL);
	sxe2_ib_qp_event(qp, qp_ctx->event_type);

out:
	return;
}

static void sxe2_qp_disconnect_worker(struct work_struct *work)
{
	struct qp_disconn_work *dwork =
		container_of(work, struct qp_disconn_work, work);
	struct sxe2_rdma_qp *qp = dwork->qp;

	kfree(dwork);
	sxe2_qp_cm_disconn_true(qp);
	sxe2_qp_rem_ref(&qp->ibqp);
}

void sxe2_cm_disconn(struct sxe2_rdma_qp *qp)
{
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	struct qp_disconn_work *work;
	unsigned long flags = 0;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		DRV_RDMA_LOG_DEV_ERR("qp disconn work alloc failed.\n");
		goto out;
	}

	spin_lock_irqsave(&rdma_dev->rdma_func->qptable_lock, flags);
	if (!rdma_dev->rdma_func->qp_table[qp->ibqp.qp_num]) {
		spin_unlock_irqrestore(&rdma_dev->rdma_func->qptable_lock,
				       flags);
		DRV_RDMA_LOG_DEV_WARN("qp:%d is already freed.\n",
				      qp->ibqp.qp_num);
		kfree(work);
		goto out;
	}

	sxe2_qp_add_ref(&qp->ibqp);
	spin_unlock_irqrestore(&rdma_dev->rdma_func->qptable_lock, flags);

	work->qp = qp;
	INIT_WORK(&work->work, sxe2_qp_disconnect_worker);
	queue_work(rdma_dev->cleanup_wq, &work->work);

out:
	return;
}

static int sxe2_fragcnt_to_wqesize_rq(u32 frag_cnt, u16 *wqe_size)
{
	int ret = 0;

	switch (frag_cnt) {
	case MAX_SGE_SIZE_0:
	case MAX_SGE_SIZE_1:
		*wqe_size = RQE_SIZE_32BYTE;
		break;
	case MAX_SGE_SIZE_2:
	case MAX_SGE_SIZE_3:
		*wqe_size = RQE_SIZE_64BYTE;
		break;
	case MAX_SGE_SIZE_4:
	case MAX_SGE_SIZE_5:
	case MAX_SGE_SIZE_6:
	case MAX_SGE_SIZE_7:
		*wqe_size = RQE_SIZE_128BYTE;
		break;
	case MAX_SGE_SIZE_8:
	case MAX_SGE_SIZE_9:
	case MAX_SGE_SIZE_10:
	case MAX_SGE_SIZE_11:
	case MAX_SGE_SIZE_12:
	case MAX_SGE_SIZE_13:
	case MAX_SGE_SIZE_14:
		*wqe_size = RQE_SIZE_256BYTE;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

int sxe2_kset_attr_from_fragcnt(struct sxe2_rdma_device *rdma_dev)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_ctx_dev *ctx_dev = &rdma_dev->rdma_func->ctx_dev;
	u8 max_fragcnt			  = rdma_dev->rdma_func->fragcnt_limit;
	u32 max_inline;
	u16 max_wqesz, max_quanta_per_wr;

	ret = sxe2_fragcnt_to_wqesize_rq(max_fragcnt + 1, &max_wqesz);
	if (ret)
		goto end;

	max_inline = ctx_dev->hw_attrs.uk_attrs.max_hw_inline;
	switch (max_wqesz) {
	case RQE_SIZE_32BYTE:
		if (max_inline > MAX_INLINE_DATA_8)
			max_inline = MAX_INLINE_DATA_8;
		break;
	case RQE_SIZE_64BYTE:
		if (max_inline > MAX_INLINE_DATA_39)
			max_inline = MAX_INLINE_DATA_39;
		break;
	case RQE_SIZE_128BYTE:
		if (max_inline > MAX_INLINE_DATA_101)
			max_inline = MAX_INLINE_DATA_101;
		break;
	case RQE_SIZE_256BYTE:
	default:
		break;
	}

	max_quanta_per_wr = (max_wqesz / QP_QUANTA_SIZE);

	ctx_dev->hw_attrs.uk_attrs.max_hw_wq_frags  = max_fragcnt;
	ctx_dev->hw_attrs.uk_attrs.max_hw_read_sges = max_fragcnt;
	ctx_dev->hw_attrs.uk_attrs.max_hw_inline    = max_inline;
	ctx_dev->hw_attrs.max_qp_wr = SXE2_MAX_QP_WRS(max_quanta_per_wr);

end:
	return ret;
}
