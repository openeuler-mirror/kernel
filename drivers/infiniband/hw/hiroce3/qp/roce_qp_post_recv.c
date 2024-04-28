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
#include "roce_xrc.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#include "roce_main_extension.h"
#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif

/*
 ****************************************************************************
 Prototype	: roce3_get_recv_wqe
 Description  : roce3_get_recv_wqe
 Input		: struct roce3_qp *rqp
				int n
 Output	   : None

  1.Date		 : 2015/5/26
	Modification : Created function

****************************************************************************
*/
static void *roce3_get_recv_wqe(struct roce3_qp *rqp, u32 n)
{
	return roce3_get_wqe(rqp, rqp->rq.offset + (n << (unsigned int)rqp->rq.wqe_shift));
}

static int roce3_post_recv_check_qp(const struct roce3_qp *qp, const struct roce3_device *rdev,
	const struct ib_recv_wr **bad_wr, const struct ib_recv_wr *wr)
{
	if (ROCE_UNLIKELY((qp->qp_type == IB_QPT_XRC_INI) || (qp->qp_type == IB_QPT_XRC_TGT))) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Can't post WQE when TGT XRC QP, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		*bad_wr = wr;
		return -EINVAL;
	}

	if (ROCE_UNLIKELY(qp->qp_state == IB_QPS_RESET)) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Can't post WQE when QP is RST state, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		*bad_wr = wr;
		return -EINVAL;
	}

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	return 0;
}

static int roce3_post_recv_check_wr(struct roce3_qp *qp, const struct ib_recv_wr **bad_wr,
	const struct ib_recv_wr *wr, u32 wr_num)
{
	if (roce3_wq_overflow(&qp->rq, wr_num, qp->ibqp.recv_cq) != 0) {
		/*lint -e160 -e522*/
		pr_err_once("[ROCE, ERR] %s: SQ is full head:%x, tali:%x, wr_num:%d\n",
			__func__, (&qp->rq)->head, (&qp->rq)->tail, wr_num);
		/*lint +e160 +e522*/
		*bad_wr = wr;
		return -ENOMEM;
	}

	if (ROCE_UNLIKELY(((u32)wr->num_sge) > qp->rq.max_sge)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	return 0;
}

static int roce3_post_recv_check_length(struct roce3_device *rdev, const struct ib_recv_wr **bad_wr,
	const struct ib_recv_wr *wr, int i)
{
	u32 data_len = 0;

	/* single SGEָ signs data len should less than (2G-1)B */
	if (ROCE_UNLIKELY(wr->sg_list[i].length >
		rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz - 1)) {
		*bad_wr = wr;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Sge data len is over range, sg_list(%d), length(0x%x), max_msg_sz(0x%x), func_id(%d)\n",
			__func__, i, wr->sg_list[i].length,
			rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz, rdev->glb_func_id);
		return -EINVAL;
	}

	data_len += wr->sg_list[i].length;
	/* all SGEָ signs data len should less than 2GB */
	if (ROCE_UNLIKELY(data_len > rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz)) {
		*bad_wr = wr;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Data_len is over range, data_len(%d), max_msg_sz(%d), func_id(%d)\n",
			__func__, data_len, rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz,
			rdev->glb_func_id);
		return -EINVAL;
	}

	return 0;
}

static int roce3_post_recv_set_data_seg(const struct ib_recv_wr *wr, struct roce3_device *rdev,
	const struct ib_recv_wr **bad_wr, struct roce3_qp *qp, u32 index)
{
	int i = 0;
	int ret = 0;
	struct roce3_wqe_data_seg *dseg = NULL;

	dseg = (struct roce3_wqe_data_seg *)roce3_get_recv_wqe(qp, index);
	for (i = 0; i < wr->num_sge; ++i) {
		ret = roce3_post_recv_check_length(rdev, bad_wr, wr, i);
		if (ret != 0)
			return ret;

		roce3_set_data_seg(dseg, wr->sg_list + i);
		dseg++;
	}

	if (wr->num_sge != 0) {
		dseg--;
		dseg->key = cpu_to_be32((u32)(wr->sg_list[wr->num_sge - 1].lkey |
			ROCE_WQE_NEXT_SGE_INVALID));
	} else {
		dseg->key = ROCE_WQE_NEXT_SGE_INVALID;
		dseg->key = cpu_to_be32(dseg->key);
		dseg->dw2.bs.len = 0;
	}

	return 0;
}
/*
 ****************************************************************************
 Prototype	: roce3_post_recv
 Description  : roce3_post_recv
 Input		: struct ib_qp *ibqp
				struct ib_recv_wr *wr
				struct ib_recv_wr **bad_wr
 Output	   : None
 Return Value :
 Calls		:
 Called By	:

  History		:
  1.Date		 : 2015/4/29
	Author	   :
	Modification : Created function

****************************************************************************
*/
int roce3_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
	const struct ib_recv_wr **bad_wr)
{
	struct roce3_qp *qp = to_roce3_qp(ibqp);

	struct roce3_device *rdev = to_roce3_dev(ibqp->device);
	unsigned long flags = 0;
	int ret = 0;
	u32 wr_num = 0;
	u32 index = 0;
	const struct ib_recv_wr *wr_tmp = wr;

	ret = roce3_post_recv_check_qp(qp, rdev, bad_wr, wr_tmp);
	if (ret != 0)
		return ret;

	spin_lock_irqsave(&qp->rq.lock, flags);

	index = (unsigned int)qp->rq.head & ((unsigned int)qp->rq.wqebb_cnt - 1);

	for (wr_num = 0; wr_tmp != NULL; ++wr_num, wr_tmp = wr_tmp->next) {
		ret = roce3_post_recv_check_wr(qp, bad_wr, wr_tmp, wr_num);
		if (ret != 0)
			goto out;

		ret = roce3_post_recv_set_data_seg(wr_tmp, rdev, bad_wr, qp, index);
		if (ret != 0)
			goto out;

		qp->rq.wrid[index] = wr_tmp->wr_id;

		index = (index + 1) & (qp->rq.wqebb_cnt - 1);
	}

out:
	if (ROCE_LIKELY(wr_num != 0)) {
		qp->rq.head += (u32)wr_num;

		wmb();	/* Memory barrier before write db */

		/* SQ need head 4B,RQ need tail 4B */
		*(qp->db.db_record + 1) = cpu_to_be32(qp->rq.head & 0xffff);
	}

	spin_unlock_irqrestore(&qp->rq.lock, flags);

	return ret;
}

void roce3_drain_rq(struct ib_qp *ibqp)
{

}
