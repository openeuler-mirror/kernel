// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>

#include <rdma/ib_verbs.h>

#include "roce_compat.h"

#include "roce.h"
#include "roce_mix.h"
#include "roce_mr.h"
#include "roce_user.h"
#include "roce_xrc.h"
#include "roce_pd.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#include "roce_pub_cmd.h"
#include "roce_qp_extension.h"
#include "roce_main_extension.h"

#include "hinic3_hmm.h"
#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif

/*
 ****************************************************************************
 Prototype	: roce3_check_rq_size
 Description  : roce3_check_rq_size
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
				struct ib_qp_cap *cap
				bool has_rq
 Output	   : None

  1.Date		 : 2017/4/27
	Modification : Created function
****************************************************************************
*/
static int roce3_check_rq_size(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_init_attr *init_attr, bool has_rq)
{
	u32 max_sge_num;
	struct ib_qp_cap *cap = &init_attr->cap;

	max_sge_num = (u32)ROCE_MIN(rdev->rdma_cap.max_sq_sg,
		rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_rq_sg);
	if ((cap->max_recv_wr > rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_wqes) ||
		(cap->max_recv_sge > max_sge_num)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to check rq size, over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	if (has_rq && ((cap->max_recv_wr == 0) || (cap->max_recv_sge == 0))) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Has rq, max_recv_wr(%d), max_recv_sge(%d), func_id(%d)\n",
			__func__, cap->max_recv_wr, cap->max_recv_sge, rdev->glb_func_id);
		return -EINVAL;
	}

	if ((!has_rq) && (cap->max_recv_wr != 0)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Not has rq, cap->max_recv_wr(%d), func_id(%d)\n",
			__func__, cap->max_recv_wr, rdev->glb_func_id);
		return -EINVAL;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_rq_size
 Description  : roce3_set_rq_size
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
				struct ib_qp_cap *cap
				bool is_user
				bool has_rq
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function
****************************************************************************
*/
/*
 ****************************************************************************
 *
 * 1 there is SQ or RQ
 *   SQ/RQ depth must be power of 2
 *   if max_send_wr=0, no need to alloc buf for SQ/RQ

 *   RQ WQE SIZE equals 64 or128
 *   SQ WQE SIZE equals multi of wqebb size

 *   SQ max_gs, max 8 and min 0
 *   RQ max_gs, can be 4 or 8, but can not be 0.

 * 2 there is no SQ or RQ
 *	 all related params should be 0
 *
 ****************************************************************************
 */
static int roce3_set_rq_size(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_init_attr *init_attr, bool is_user, bool has_rq)
{
	int ret;
	u32 wqebb_num = 0;
	u32 sge_total_len = 0;
	u32 sge_num = 0;
	struct ib_qp_cap *cap = &init_attr->cap;

	ret = roce3_check_rq_size(rdev, rqp, init_attr, has_rq);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to check rq size, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	if (has_rq) {
		wqebb_num = ROCE_MAX(2U, cap->max_recv_wr);
		/*lint -e587*/
		rqp->rq.wqebb_cnt = (u32)(ROCE_ROUNDUP_POW_OF_TWO(wqebb_num) & 0xffffffff);
		/*lint +e587*/

		/* RQ SGE range [0,4] select 4,[5,8] select 8 */
		rqp->rq.max_sge = (cap->max_recv_sge <= ROCE_RQ_MIN_SGE) ? ROCE_RQ_MIN_SGE :
			((cap->max_recv_sge <= ROCE_RQ_MID_SGE) ?
			ROCE_RQ_MID_SGE : ROCE_RQ_MAX_SGE);

		sge_total_len = (u32)((u32)rqp->rq.max_sge * sizeof(struct roce3_wqe_data_seg));
		rqp->rq.wqe_shift = (u32)ROCE_ILOG2(sge_total_len);

		if ((u32)((u32)rqp->rq.wqebb_cnt << (unsigned int)rqp->rq.wqe_shift) < PAGE_SIZE)
			rqp->rq.wqebb_cnt = (PAGE_SIZE >> (unsigned int)rqp->rq.wqe_shift);

		/* leave userspace return values as they were, so as not to break ABI */
		if (is_user) {
			rqp->rq.max_post = ROCE_MIN(
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_wqes,
				rqp->rq.wqebb_cnt);
			cap->max_recv_wr = (u32)rqp->rq.max_post;
			cap->max_recv_sge = (u32)rqp->rq.max_sge;
		} else {
			rqp->rq.max_post = ROCE_MIN(
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_wqes,
				rqp->rq.wqebb_cnt);
			cap->max_recv_wr = (u32)rqp->rq.max_post;
			sge_num = ROCE_MIN(rdev->rdma_cap.max_sq_sg,
				rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_rq_sg);
			cap->max_recv_sge = ROCE_MIN((u32)rqp->rq.max_sge, sge_num);
		}
	} else {
		rqp->rq.wqebb_cnt = 0;
		rqp->rq.max_sge = 0;
		rqp->rq.wqe_shift = ROCE_QP_DEFAULT_WQE_SHIFT;
		rqp->rq.max_post = 0;
		cap->max_recv_sge = 0;
	}

	rqp->rq.head = 0;
	rqp->rq.tail = 0;

	return 0;
}

static int roce3_set_user_sq_size_check(struct roce3_device *rdev, const struct ib_qp_cap *cap,
	const struct roce3_qp *rqp)
{
	u32 ud_max_inline_size;

	if (cap->max_send_wr > (rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_wqes)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Log_sq_bb_count over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	if (rqp->qp_type == IB_QPT_UD) {
		ud_max_inline_size =
			(rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz >
			ROCE_UD_MAX_INLINE_LEN_SUB) ?
			(rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz -
			ROCE_UD_MAX_INLINE_LEN_SUB) :
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz;
	} else {
		ud_max_inline_size =
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz;
	}

	/* RC:192B inline data, UD:176B */
	if (cap->max_inline_data > ud_max_inline_size) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SQ max inline data over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	return 0;
}
/*
 ****************************************************************************
 Prototype	: roce3_set_user_sq_size
 Description  : roce3_set_user_sq_size
 Input		: struct roce3_device *rdev
				struct ib_qp_cap *cap
				struct roce3_qp *rqp
				struct roce3_create_qp *ucmd
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
static int roce3_set_user_sq_size(struct roce3_device *rdev, struct ib_qp_cap *cap,
	struct roce3_qp *rqp, struct create_qp_cmd *ucmd)
{
	u32 tmp_max_sq_wqe_sz = 0;
	u32 sq_buf_sz = 0;
	int ret = 0;

	ret = roce3_set_user_sq_size_check(rdev, cap, rqp);
	if (ret != 0)
		return ret;

	if (rqp->qp_type != IB_QPT_XRC_TGT) {
		/* between max and min */
		/*lint -e587*/
		tmp_max_sq_wqe_sz = (u32)(
			ROCE_ROUNDUP_POW_OF_TWO(rdev->rdma_cap.max_sq_desc_sz) & 0xffffffff);
		/*lint +e587*/
		if ((ucmd->log_sq_stride > ROCE_ILOG2(tmp_max_sq_wqe_sz)) ||
			(ucmd->log_sq_stride < ROCE_ILOG2(rdev->rdma_cap.wqebb_size))) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: WQE err, func_id(%d) log_sq:%d wqebb:%d max:%d\n",
				__func__, rdev->glb_func_id, ucmd->log_sq_stride,
				rdev->rdma_cap.wqebb_size, tmp_max_sq_wqe_sz);
			return -EINVAL;
		}

		rqp->sq.wqebb_cnt = (u32)(1U << ucmd->log_sq_bb_count);
		rqp->sq.wqe_shift = ucmd->log_sq_stride;

		if ((u32)((u64)rqp->sq.wqebb_cnt << (unsigned int)rqp->sq.wqe_shift) < PAGE_SIZE)
			rqp->sq.wqebb_cnt = (PAGE_SIZE >> (unsigned int)rqp->sq.wqe_shift);

		sq_buf_sz = (u32)ROCE_ALIGN((u64)rqp->sq.wqebb_cnt <<
			(unsigned int)rqp->sq.wqe_shift, PAGE_SIZE);
		rqp->buf_size = (int)ROCE_ALIGN(
			((unsigned int)sq_buf_sz + ((unsigned int)rqp->rq.wqebb_cnt <<
			(unsigned int)rqp->rq.wqe_shift)), PAGE_SIZE);

		rqp->sq.offset = 0;
		rqp->rq.offset = sq_buf_sz;

		rqp->max_inline_data = cap->max_inline_data;
	} else {
		rqp->sq.wqebb_cnt = 0;
		rqp->sq.wqe_shift = ucmd->log_sq_stride;
		rqp->buf_size = 0;
		rqp->sq.offset = 0;
		rqp->rq.offset = 0;
		rqp->max_inline_data = 0;
		cap->max_inline_data = 0;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_send_wqe_overhead
 Description  : roce3_send_wqe_overhead
 Input		: enum ib_qp_type qp_type
 Output	   : None

  1.Date		 : 2015/5/7
	Modification : Created function

****************************************************************************
*/
static int roce3_send_wqe_overhead(enum ib_qp_type qp_type)
{
	switch (qp_type) {
	case IB_QPT_RC:
		return sizeof(struct roce3_wqe_ctrl_seg) +
			sizeof(struct roce3_wqe_mask_atomic_tsk_seg);

	case IB_QPT_UC:
		return sizeof(struct roce3_wqe_ctrl_seg) + sizeof(struct roce3_wqe_send_tsk_seg);

	case IB_QPT_UD:
		return sizeof(struct roce3_wqe_ctrl_seg) + sizeof(struct roce3_wqe_ud_tsk_seg);

	case IB_QPT_GSI:
		return sizeof(struct roce3_wqe_ctrl_seg) + sizeof(struct roce3_wqe_ud_tsk_seg);

	case IB_QPT_XRC_TGT:
		return 0;

	case IB_QPT_XRC_INI:
		return sizeof(struct roce3_wqe_ctrl_seg) +
			sizeof(struct roce3_wqe_mask_atomic_tsk_seg);

	default:
		pr_err("[ROCE, ERR] %s: Not supported this qp_type\n", __func__);
		return -1;
	}
}

static int roce3_set_kernel_sq_size_check(const struct roce3_device *rdev,
	const struct ib_qp_cap *cap, int *sq_max_wqe_size, enum ib_qp_type qp_type)
{
	int wqe_overhead = 0;
	int ret = 0;

	if (cap->max_send_wr > (u32)rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_wqes) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SQ WR over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	if (cap->max_send_sge >
		(u32)ROCE_MIN(rdev->rdma_cap.max_sq_sg,
		rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_rq_sg)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SQ SGE over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	if (cap->max_inline_data >
	    rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SQ max inline data over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	wqe_overhead = roce3_send_wqe_overhead(qp_type);
	if (wqe_overhead < 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Invalid service type(%d), func_id(%d)\n",
			__func__, (int)qp_type, rdev->glb_func_id);
		return -EINVAL;
	}

	*sq_max_wqe_size =
		ROCE_MAX((int)(cap->max_send_sge * sizeof(struct roce3_wqe_data_seg)),
		(int)cap->max_inline_data) + wqe_overhead;
	if (*sq_max_wqe_size > (int)rdev->rdma_cap.max_sq_desc_sz) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: SQ WQE size over range, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	return ret;
}
/*
 ****************************************************************************
 Prototype	: roce3_set_kernel_sq_size
 Description  : roce3_set_kernel_sq_size
 Input		: struct roce3_device *rdev
				struct ib_qp_cap *cap
				enum roce3_qp_type qp_type
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
static int roce3_set_kernel_sq_size(struct roce3_device *rdev,
	struct ib_qp_cap *cap, enum ib_qp_type qp_type, struct roce3_qp *rqp)

{
	u32 sq_buf_sz = 0;
	int sq_max_wqe_size = 0;
	int ret = 0;

	ret = roce3_set_kernel_sq_size_check(rdev, cap, &sq_max_wqe_size, qp_type);
	if (ret != 0)
		return ret;

	if (rqp->qp_type != IB_QPT_XRC_TGT) {
		rqp->sq.wqe_shift = (u32)ROCE_ILOG2(rdev->rdma_cap.wqebb_size);
		rqp->sq_max_wqes_per_wr =
			(u32)ROCE_DIV_ROUND_UP((unsigned int)sq_max_wqe_size,
			(u32)(1UL << (unsigned int)rqp->sq.wqe_shift));

/*
 * As one wqebb ought to be reserved for invalidate wqebb, 1 is added to sq.wqebb_cnt here
 * to satisfy the actual IB_MAD_QP_SEND_SIZE set by applications
 */
		rqp->sq.wqebb_cnt = (u32)((int)cap->max_send_wr * rqp->sq_max_wqes_per_wr + 1);
		/*lint -e587*/
		rqp->sq.wqebb_cnt = (u32)(ROCE_ROUNDUP_POW_OF_TWO(rqp->sq.wqebb_cnt) & 0xffffffff);
		/*lint +e587*/

		if ((u32)((u64)rqp->sq.wqebb_cnt << (u32)rqp->sq.wqe_shift) < PAGE_SIZE)
			rqp->sq.wqebb_cnt = (PAGE_SIZE >> ((u32)rqp->sq.wqe_shift));

		rqp->sq.max_sge = (u32)(((u64)rqp->sq_max_wqes_per_wr <<
			(unsigned int)rqp->sq.wqe_shift) -
			(unsigned int)roce3_send_wqe_overhead(qp_type));
		rqp->sq.max_sge =
			(u32)ROCE_MIN(rdev->rdma_cap.max_sq_desc_sz, rqp->sq.max_sge) /
			(int)sizeof(struct roce3_wqe_data_seg);

		sq_buf_sz = (u32)ALIGN((u64)rqp->sq.wqebb_cnt <<
			(unsigned int)rqp->sq.wqe_shift, PAGE_SIZE);
		rqp->buf_size = (int)ALIGN(((unsigned int)sq_buf_sz +
			((unsigned int)rqp->rq.wqebb_cnt << (unsigned int)rqp->rq.wqe_shift)),
			PAGE_SIZE);

		rqp->sq.offset = 0u;
		rqp->rq.offset = sq_buf_sz;

		if (((rqp->sq.wqebb_cnt - 1) / rqp->sq_max_wqes_per_wr) == 1) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE] %s:Only one WR,please check,func_id(%d)\n",
				__func__, rdev->glb_func_id);
			rqp->sq.max_post = ROCE_WR_MIN_NUM;
			cap->max_send_wr = rqp->sq.max_post;
		} else {
			rqp->sq.max_post = (rqp->sq.wqebb_cnt - 1) / rqp->sq_max_wqes_per_wr;
			cap->max_send_wr = (u32)rqp->sq.max_post;
		}

		cap->max_send_sge = (u32)ROCE_MIN(rdev->rdma_cap.max_sq_sg,
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_rq_sg);
		cap->max_send_sge = (u32)ROCE_MIN(rqp->sq.max_sge, cap->max_send_sge);
		rqp->max_inline_data = cap->max_inline_data;
	} else {
		rqp->sq.wqebb_cnt = 0;
		rqp->sq.wqe_shift = ROCE_QP_DEFAULT_WQE_SHIFT;
		rqp->buf_size = 0;
		rqp->sq.offset = 0;
		rqp->rq.offset = 0;
		rqp->max_inline_data = 0;
		cap->max_inline_data = 0;
	}

	rqp->sq.head = 0;
	rqp->sq.tail = 0;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_qp_async_event
 Description  : roce3_qp_async_event
 Input		: struct roce3_device *rdev
				struct roce3_qp *qp
				int type
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
void roce3_qp_async_event(struct roce3_device *rdev, struct roce3_qp *qp, int type)
{
	struct ib_event event;
	struct ib_qp *ibqp = &qp->ibqp;

	memset(&event, 0, sizeof(event));

	if (ibqp->event_handler) {
		event.device = ibqp->device;
		event.element.qp = ibqp;

		switch (type) {
		case ROCE_EVENT_TYPE_COMM_EST:
			event.event = IB_EVENT_COMM_EST;
			break;

		case ROCE_EVENT_TYPE_SQ_DRAINED:
			event.event = IB_EVENT_SQ_DRAINED;
			break;

		case ROCE_EVENT_TYPE_SRQ_QP_LAST_WQE:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;

		case ROCE_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;

		case ROCE_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;

		case ROCE_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;

		default:
			return;
		}

		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static void *roce3_buf_offset(struct roce3_buf *buf, u32 offset)
{
	return (void *)((char *)buf->direct.buf + offset);
}

void *roce3_get_wqe(struct roce3_qp *rqp, u32 offset)
{
	return roce3_buf_offset(&rqp->buf, offset);
}

static void *roce3_get_send_wqe_head(struct roce3_qp *rqp)
{
	return roce3_get_wqe(rqp, rqp->sq.offset);
}

/*
 ****************************************************************************
 Prototype	: roce3_get_send_wqe_tail
 Description  : roce3_get_send_wqe_tail
 Input		: struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2015/8/8
	Modification : Created function

****************************************************************************
*/
static void *roce3_get_send_wqe_tail(struct roce3_qp *rqp)
{
	return roce3_get_wqe(rqp, rqp->sq.offset + (rqp->sq.wqebb_cnt << (u32)rqp->sq.wqe_shift));
}

/*
 ****************************************************************************
 Prototype	: roce3_sq_buf_init
 Description  : roce3_sq_buf_init
 Input		: struct roce3_qp *qp
 Output	   : None

  1.Date		 : 2015/11/9
	Modification : Created function

****************************************************************************
*/
static void roce3_sq_buf_init(struct roce3_qp *qp)
{
	u32 entries = qp->rq.offset / (1U << qp->sq.wqe_shift);
	u8 *wqe = NULL;
	struct roce3_wqe_ctrl_seg *wqe_ctrl = NULL;
	u32 i;

	for (i = 0; i < entries; i++) {
		wqe = (u8 *)qp->buf.direct.buf + (int)(i * (int)(1U << ((u32)qp->sq.wqe_shift)));
		wqe_ctrl = (struct roce3_wqe_ctrl_seg *)((void *)wqe);
		wqe_ctrl->dw0.value = be32_to_cpu(wqe_ctrl->dw0.value);
		wqe_ctrl->dw0.bs.owner = 1;
		wqe_ctrl->dw0.value = cpu_to_be32(wqe_ctrl->dw0.value);
	}
}

static int roce3_check_and_get_umem(struct roce3_device *rdev,
	struct ib_pd *ibpd, struct ib_qp_init_attr *init_attr,
	struct ib_udata *udata, struct roce3_qp *rqp, struct create_qp_cmd *ucmd)
{
	int ret = 0;

	if ((udata == NULL) || (ib_copy_from_udata(ucmd, udata, sizeof(*ucmd)) != 0)) {
		ret = -EFAULT;
		return ret;
	}

	ret = roce3_set_user_sq_size(rdev, &init_attr->cap, rqp, ucmd);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to set user sq_size, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}
	rqp->umem = ib_umem_get(&rdev->ib_dev, ucmd->buf_addr, (size_t)rqp->buf_size, 0);
	if (IS_ERR(rqp->umem)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get ib_umem, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = (int)PTR_ERR(rqp->umem);
		return ret;
	}

	return ret;
}

static int roce3_alloc_qpc(struct roce3_qp *rqp, struct roce3_device *rdev,
	u32 qpn, struct ib_qp_init_attr *init_attr)
{
	struct tag_cqm_qpc_mpt *qpc_info = NULL;
	int ret;
	struct roce3_srq *rsrq;
	u32 qpn_tmp = qpn;
	bool low2bit_align_en = false;

	if (roce3_need_qpn_lb1_consistent_srqn(rqp, rdev, init_attr)) {
		rsrq = to_roce3_srq(init_attr->srq);
		qpn_tmp = ((rsrq->srqn & ROCE3_LB1_MASK) << ROCE3_QPN_BIT_INDEX) |
			qpn_tmp >> ROCE3_QPN_CTRL_BIT_NUM;
		low2bit_align_en = true;
	}

	qpc_info = cqm_object_qpc_mpt_create(rdev->hwdev, SERVICE_T_ROCE, CQM_OBJECT_SERVICE_CTX,
		rdev->rdma_cap.dev_rdma_cap.roce_own_cap.qpc_entry_sz, rqp, qpn_tmp,
		low2bit_align_en);
	if (qpc_info == NULL) {
		ret = -ENOMEM;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create qpc mpt, func_id(%d), qpn(%u)\n",
			__func__, rdev->glb_func_id, qpn_tmp);
		return ret;
	}

	rqp->qpc_info = qpc_info;
	rqp->qpn = rqp->qpc_info->xid;
	if (roce3_need_qpn_lb1_consistent_srqn(rqp, rdev, init_attr)) {
		rsrq = to_roce3_srq(init_attr->srq);
		if ((rsrq->srqn & ROCE3_LB1_MASK) != (rqp->qpn & ROCE3_LB1_MASK)) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Wrong srqn, func_id(%d), qpn(%u) srqn(%u)\n",
				__func__, rdev->glb_func_id, rqp->qpn, rsrq->srqn);
		}
	}
	return 0;
}

static int roce3_create_qp_user_mtt(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	u32 npages;
	int ret;

	npages = (u32)ib_umem_num_pages(rqp->umem);
	rqp->buf.page_shift = PAGE_SHIFT;

	rqp->mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, npages, (u32)rqp->buf.page_shift,
		&rqp->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc rdma_mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	ret = roce3_umem_write_mtt(rdev, &rqp->mtt, rqp->umem);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to write mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_write_mtt;
	}

	return 0;

err_write_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);
	return ret;
}

static void roce3_destroy_qp_user_mtt(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);
}

/*
 ****************************************************************************
 Prototype	: roce3_create_qp_user
 Description  : create qp resource for user space qp
 Input		: struct roce3_device *rdev
				struct ib_pd *ibpd
				struct ib_qp_init_attr *init_attr
				struct ib_udata *udata
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
static int roce3_create_qp_user(struct roce3_device *rdev, struct ib_pd *ibpd,
	struct ib_qp_init_attr *init_attr, struct ib_udata *udata, struct roce3_qp *rqp)
{
	int ret = 0;
	struct roce3_ucontext *roce3_uctx = NULL;
	struct create_qp_cmd ucmd = { 0 };
	u32 qpn = 0;

	ret = roce3_create_qp_user_pre_ext(init_attr, rqp, &qpn);
	if (ret != 0)
		return ret;

	roce3_uctx = to_roce3_ucontext(ibpd->uobject->context);

	ret = roce3_check_and_get_umem(rdev, ibpd, init_attr, udata, rqp, &ucmd);
	if (ret != 0)
		return ret;

	ret = roce3_create_qp_user_mtt(rdev, rqp);
	if (ret != 0)
		goto err_create_mtt;

	if (init_attr->qp_type != IB_QPT_XRC_TGT) {
		ret = roce3_db_map_user(roce3_uctx, ucmd.db_addr, &rqp->db);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to map db page to user, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			goto err_map_db;
		}
	}

	ret = roce3_alloc_qpc(rqp, rdev, qpn, init_attr);
	if (ret != 0)
		goto err_alloc_qpc;

	ret = roce3_create_qp_user_post_ext(ibpd, rdev, rqp, init_attr);
	if (ret != 0)
		goto err_extend_post;

	return 0;

err_extend_post:
	hiudk_cqm_object_delete(rdev->hwdev, &(rqp->qpc_info->object));

err_alloc_qpc:
	if (init_attr->qp_type != IB_QPT_XRC_TGT)
		roce3_db_unmap_user(roce3_uctx, &rqp->db);

err_map_db:
	roce3_destroy_qp_user_mtt(rdev, rqp);

err_create_mtt:
	ib_umem_release(rqp->umem);

	return ret;
}

static void roce3_free_wrid(struct roce3_qp *rqp)
{
	if (rqp->rq.wrid)
		kvfree(rqp->rq.wrid);

	if (rqp->sq.wrid)
		kvfree(rqp->sq.wrid);
}

static int roce3_get_wrid(struct roce3_qp *rqp, struct roce3_device *rdev)
{
	int ret = 0;

	rqp->sq.wrid = kcalloc((unsigned int)rqp->sq.wqebb_cnt, sizeof(u64), GFP_KERNEL);
	if (rqp->sq.wrid == NULL)
		rqp->sq.wrid = vzalloc((size_t)(rqp->sq.wqebb_cnt * sizeof(u64)));

	rqp->rq.wrid = kcalloc((unsigned int)rqp->rq.wqebb_cnt, sizeof(u64), GFP_KERNEL);
	if (rqp->rq.wrid == NULL)
		rqp->rq.wrid = vzalloc((size_t)(rqp->rq.wqebb_cnt * sizeof(u64)));

	if ((rqp->sq.wrid == NULL) || (rqp->rq.wrid == NULL)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc wrid of sq or rq, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		ret = -ENOMEM;
	}

	return ret;
}

static void roce3_create_qp_kernel_set_attr(struct roce3_qp *rqp,
					    struct tag_cqm_queue *qp_buf_info)
{
	memset(qp_buf_info->q_room_buf_1.direct.va, 0,
		(size_t)((unsigned int)rqp->buf_size));
	rqp->buf.direct.buf = qp_buf_info->q_room_buf_1.direct.va;
	rqp->buf.direct.map = qp_buf_info->q_room_buf_1.direct.pa;
	rqp->buf.page_shift = ROCE_ILOG2(qp_buf_info->q_room_buf_1.buf_size);

	roce3_sq_buf_init(rqp);

	rqp->db.db_record = (__be32 *)(void *)(&qp_buf_info->q_header_vaddr->doorbell_record);
	rqp->db.dma = qp_buf_info->q_header_paddr;

	qp_buf_info->q_header_vaddr->doorbell_record = 0;

	rqp->qp_buf_info = qp_buf_info;

	rqp->sq_head_addr = (u8 *)roce3_get_send_wqe_head(rqp);
	rqp->sq_tail_addr = (u8 *)roce3_get_send_wqe_tail(rqp);
	rqp->max_dwqe_size = 0;

	if (rqp->max_inline_data != 0)
		rqp->max_dwqe_size = ROCE_QP_MAX_DWQE_SIZE;
}

static int roce3_create_qp_kernel_normal(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	int ret;
	struct tag_cqm_queue *qp_buf_info = NULL;

	qp_buf_info = cqm_object_rdma_queue_create(rdev->hwdev, SERVICE_T_ROCE,
		CQM_OBJECT_RDMA_QP, (u32)rqp->buf_size, rqp, true, ROCE_QP_INVLID_QP_NUM);
	if (qp_buf_info == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create rdma queue by cqm object, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -1;
	}

	roce3_create_qp_kernel_set_attr(rqp, qp_buf_info);

	rqp->mtt.mtt_type = MTT_CMTT_TYPE;
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, qp_buf_info->q_room_buf_1.buf_number,
		(u32)rqp->buf.page_shift, &rqp->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_mtt;
	}
	ret = roce3_buf_write_mtt(rdev, &rqp->mtt, &rqp->qp_buf_info->q_room_buf_1);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to write rdma mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_write_mtt;
	}

	ret = roce3_get_wrid(rqp, rdev);
	if (ret != 0)
		goto err_alloc_wrid;

	return 0;

err_alloc_wrid:
	roce3_free_wrid(rqp);

err_write_mtt:
	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);

err_alloc_mtt:
	hiudk_cqm_object_delete(rdev->hwdev, &rqp->qp_buf_info->object);

	return ret;
}

static void roce3_destroy_qp_kernel_normal(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	roce3_free_wrid(rqp);
	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);
	hiudk_cqm_object_delete(rdev->hwdev, &rqp->qp_buf_info->object);
}

/*
 ****************************************************************************
 Prototype	: roce3_create_qp_kernel
 Description  : create qp resource for kernel space qp
 Input		: struct roce3_device *rdev
				struct ib_qp_init_attr *init_attr
				struct roce3_qp *rqp
				u32 qpn
 Output	   : None

  1.Date		 : 2016/01/30
	Modification : Created function

****************************************************************************
*/
static int roce3_create_qp_kernel(struct roce3_device *rdev,
	struct ib_qp_init_attr *init_attr, struct roce3_qp *rqp, u32 qpn)
{
	int ret = 0;

	ret = roce3_set_kernel_sq_size(rdev, &init_attr->cap, (enum ib_qp_type)rqp->qp_type, rqp);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to set sq buffer size in kernel, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	if (rqp->qp_type != IB_QPT_XRC_TGT) {
		ret = roce3_create_qp_kernel_normal(rdev, rqp);
		if (ret != 0)
			return ret;
	}

	ret = roce3_alloc_qpc(rqp, rdev, qpn, init_attr);
	if (ret != 0)
		goto err_alloc_qpc;

	return 0;

err_alloc_qpc:
	if (rqp->qp_type != IB_QPT_XRC_TGT)
		roce3_destroy_qp_kernel_normal(rdev, rqp);

	return ret;
}

static void roce3_qp_add_cq_list(struct ib_qp_init_attr *init_attr,
	struct roce3_qp *rqp, struct roce3_device *rdev)
{
	struct roce3_cq *send_rcq = to_roce3_cq(init_attr->send_cq);
	struct roce3_cq *recv_rcq = to_roce3_cq(init_attr->recv_cq);
	unsigned long flags;

	spin_lock_irqsave(&rdev->reset_flow_resource_lock, flags);
	roce3_lock_cqs(send_rcq, recv_rcq);
	list_add_tail(&rqp->qps_list, &rdev->qp_list);
	list_add_tail(&rqp->cq_send_list, &send_rcq->send_qp_list);
	list_add_tail(&rqp->cq_recv_list, &recv_rcq->recv_qp_list);
	roce3_unlock_cqs(send_rcq, recv_rcq);
	spin_unlock_irqrestore(&rdev->reset_flow_resource_lock, flags);
}

static void roce3_init_qp_state(struct roce3_qp *rqp, struct roce3_device *rdev)
{
	struct roce_qp_context *qpc = (struct roce_qp_context *)((void *)rqp->qpc_info->vaddr);

	if (!cqm_need_secure_mem(rdev->hwdev)) {
		qpc->sw_seg.drv_seg.dw0.bs.state = ROCE_QP_STATE_MEM_INIT;
		qpc->sw_seg.drv_seg.dw0.value = cpu_to_be32(qpc->sw_seg.drv_seg.dw0.value);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_create_qp_common
 Description  : roce3_create_qp_common
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
				struct ib_pd *ibpd
				struct ib_qp_init_attr *init_attr
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/4/29
	Modification : Created function

****************************************************************************
*/
static int roce3_do_create_qp(struct roce3_device *rdev, struct roce3_qp *rqp, struct ib_pd *ibpd,
	struct ib_qp_init_attr *init_attr, struct ib_udata *udata)
{
	int ret = 0;

	mutex_init(&rqp->mutex);
	/*lint -e708 -e413 */
	spin_lock_init(&rqp->sq.lock);
	spin_lock_init(&rqp->rq.lock);
	/*lint +e708 +e413 */

	rqp->qp_state = IB_QPS_RESET;
	rqp->qp_type = init_attr->qp_type;
	rqp->sq_signal_bits = (u32)(init_attr->sq_sig_type == IB_SIGNAL_ALL_WR);

	if (ibpd->uobject) {
		ret = roce3_set_rq_size(rdev, rqp, init_attr, true, rqp->has_rq);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to set rq size, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		ret = roce3_create_qp_pre_ext(rdev, rqp, init_attr);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] : Failed to handle qp create pre extension, func_id(%d)\n",
				rdev->glb_func_id);
			return ret;
		}

		ret = roce3_create_qp_user(rdev, ibpd, init_attr, udata, rqp);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] : Failed to create qp user, func_id(%d)\n",
				rdev->glb_func_id);
			return ret;
		}
	} else {
		ret = roce3_set_rq_size(rdev, rqp, init_attr, false, rqp->has_rq);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to set rq size, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		ret = roce3_create_qp_kernel(rdev, init_attr, rqp, ROCE_QP_INVLID_QP_NUM);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to create qp kernel, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		roce3_qp_add_cq_list(init_attr, rqp, rdev);
	}

	if (roce3_is_qp_normal(rqp, init_attr) != 0)
		roce3_init_qp_state(rqp, rdev);

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_create_qp_gsi
 Description  : roce3_create_qp_gsi
 Input		: struct roce3_device *rdev
				struct ib_pd *ibpd
				struct ib_qp_init_attr *init_attr
 Output	   : None

  1.Date		 : 2017/04/27
	Modification : Created function

****************************************************************************
*/
static struct roce3_qp *roce3_create_qp_gsi(struct roce3_device *rdev, struct ib_pd *ibpd,
	struct ib_qp_init_attr *init_attr)
{
	int ret;
	struct roce3_qp *rqp = NULL;
	struct roce3_sqp *sqp = NULL;

	sqp = kzalloc(sizeof(struct roce3_sqp), GFP_KERNEL);
	if (sqp == NULL)
		return (struct roce3_qp *)ERR_PTR((long)-ENOMEM);

	rqp = &sqp->qp;

	mutex_init(&rqp->mutex);
	/*lint -e708*/
	spin_lock_init(&rqp->sq.lock);
	spin_lock_init(&rqp->rq.lock);
	/*lint +e708*/
	rqp->qp_state = (u8)IB_QPS_RESET;
	rqp->qp_type = init_attr->qp_type;
	rqp->sq_signal_bits = (u32)(init_attr->sq_sig_type == IB_SIGNAL_ALL_WR);
	rqp->has_rq = !init_attr->srq;

	ret = roce3_set_rq_size(rdev, rqp, init_attr, false, rqp->has_rq);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to set rq size, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_out;
	}

	ret = roce3_create_qp_kernel(rdev, init_attr, rqp, ROCE_QP_GSI_QP_NUM);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create qp kernel, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_out;
	}

	rqp->qpn = ROCE_QP_GSI_QP_NUM;

	roce3_init_qp_state(rqp, rdev);
	roce3_qp_add_cq_list(init_attr, rqp, rdev);

	return rqp;

err_out:
	kfree(sqp);

	return (struct roce3_qp *)ERR_PTR((long)ret);
}

static int roce3_create_check_init_attr(const struct ib_pd *ibpd,
	const struct ib_qp_init_attr *init_attr, const struct ib_udata *udata)
{
	if (init_attr == NULL) {
		pr_err("[ROCE, ERR] %s: init_attr is null\n", __func__);
		return (-EINVAL);
	}

	if ((ibpd == NULL) && (init_attr->qp_type != IB_QPT_XRC_TGT)) {
		pr_err("[ROCE, ERR] %s: Ibpd is null and qp_type is not IB_QPT_XRC_TGT\n",
			__func__);
		return (-EINVAL);
	}

	if ((udata) && (init_attr->qp_type == IB_QPT_GSI)) {
		pr_err("[ROCE, ERR] %s: Udata is not null and qp_type is IB_QPT_GSI\n", __func__);
		return (-EINVAL);
	}

	return 0;
}

static int roce3_set_qp_attr(struct ib_qp_init_attr *init_attr, struct roce3_qp *rqp,
	struct roce3_device *rdev, struct ib_pd **ibpd, int qp_ext)
{
	u16 xrcdn = 0;

	rqp->qp_ext = (u8)qp_ext;
	if (init_attr->qp_type == IB_QPT_XRC_TGT) {
		*ibpd = to_roce3_xrcd(init_attr->xrcd)->pd;
		xrcdn = (u16)to_roce3_xrcd(init_attr->xrcd)->xrcdn;
		init_attr->send_cq = to_roce3_xrcd(init_attr->xrcd)->cq;
		init_attr->recv_cq = init_attr->send_cq;

		rqp->has_rq = false;
		rqp->xrcdn = xrcdn;
	} else if ((init_attr->qp_type == IB_QPT_XRC_INI) &&
		roce3_is_roceaa(rdev->cfg_info.scence_id)) {
		init_attr->recv_cq = init_attr->send_cq;
		rqp->has_rq = false;
	} else if (init_attr->qp_type == IB_QPT_XRC_INI) {
		init_attr->recv_cq = init_attr->send_cq;
		rqp->has_rq = false;
		if (rdev->is_vroce)
			rqp->sl = rdev->group_xrc_cos;
	} else if ((init_attr->qp_type == IB_QPT_RC) || (init_attr->qp_type == IB_QPT_UC) ||
		(init_attr->qp_type == IB_QPT_UD)) {
		rqp->has_rq = !init_attr->srq;
		if (init_attr->qp_type == IB_QPT_RC && rdev->is_vroce)
			rqp->sl = rdev->group_rc_cos;
		else if (rdev->is_vroce)
			rqp->sl = rdev->group_ud_cos;
	} else {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Unknown QP Type(%u), func_id(%d)\n",
			__func__, init_attr->qp_type, rdev->glb_func_id);
		return (-EINVAL);
	}
	return 0;
}

static struct ib_qp *roce3_create_gsi_qp_result(struct ib_pd *ibpd,
	struct ib_qp_init_attr *init_attr, struct roce3_device *rdev)
{
	int ret;
	struct roce3_qp *rqp = NULL;

	rqp = roce3_create_qp_gsi(rdev, ibpd, init_attr);
	if (IS_ERR(rqp)) {
		ret = (int)PTR_ERR(rqp);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create qp gsi, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return (struct ib_qp *)ERR_PTR((long)ret);
	}

	rqp->ibqp.qp_num = rqp->qpn;
	return &rqp->ibqp;
}

struct ib_qp *roce3_create_qp_common(struct ib_pd *ibpd, struct ib_qp_init_attr *init_attr,
	struct ib_udata *udata, int qp_ext)
{
	int ret = 0;
	struct roce3_qp *rqp = NULL;
	struct ib_device *ibdev = NULL;
	struct roce3_device *rdev = NULL;

	ret = roce3_create_check_init_attr(ibpd, init_attr, udata);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to check init attr\n", __func__);
		return (struct ib_qp *)ERR_PTR((long)ret);
	}

	ibdev = ibpd ? ibpd->device : init_attr->xrcd->device;
	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return (struct ib_qp *)ERR_PTR((long)-EPERM);
	}

	if (init_attr->qp_type == IB_QPT_GSI)
		return roce3_create_gsi_qp_result(ibpd, init_attr, rdev);

	rqp = kzalloc(sizeof(*rqp), GFP_KERNEL);
	if (rqp == NULL)
		return (struct ib_qp *)ERR_PTR((long)-ENOMEM);

	ret = roce3_set_qp_attr(init_attr, rqp, rdev, &ibpd, qp_ext);
	if (ret != 0)
		goto err_create_qp;

	ret = roce3_do_create_qp(rdev, rqp, ibpd, init_attr, udata);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to create qp in common process, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_create_qp;
	}

	roce3_set_qp_dif_attr(rqp, init_attr, rdev);
	rqp->ibqp.qp_num = rqp->qpn;
	rqp->rsp_depth = 0;

	mutex_lock(&rdev->qp_cnt.cur_qps_mutex);
	rdev->qp_cnt.alloc_qp_cnt++;
	mutex_unlock(&rdev->qp_cnt.cur_qps_mutex);

	return &rqp->ibqp;

err_create_qp:
	kfree(rqp);

	return (struct ib_qp *)ERR_PTR((long)ret);
}

struct ib_qp *roce3_create_qp(struct ib_pd *ibpd, struct ib_qp_init_attr *init_attr,
	struct ib_udata *udata)
{
	return roce3_create_qp_common(ibpd, init_attr, udata, ROCE_QP);
}
