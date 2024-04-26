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
#include "roce_pd.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#ifdef __ROCE_DFX__
#include "roce_dfx.h"
#endif
#include "hinic3_hmm.h"

#ifdef ROCE_VBS_EN
#include "roce_vbs_qp.h"
#endif

static void roce3_clean_qp_user(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct roce3_ucontext *ucontext)
{
	roce3_free_opt_rdmarc(rqp);

	hiudk_cqm_object_delete(rdev->hwdev, &(rqp->qpc_info->object));

#ifdef ROCE_VBS_EN
	if (rqp->vbs_qp_ptr)
		roce3_vbs_destroy_sqpc(rdev->hwdev, rqp);
#endif

	if (rqp->qp_type != IB_QPT_XRC_TGT)
		roce3_db_unmap_user(ucontext, &rqp->db);

	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);

	ib_umem_release(rqp->umem);
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_clean_process
 Description  : roce3_cq_clean_process
 Input		: struct roce3_cq *cq
				u32 qpn
				struct roce3_srq *srq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
void roce3_cq_clean_process(struct roce3_cq *cq, u32 qpn, struct roce3_srq *srq)
{
	u32 prod_index = 0;
	int nfreed = 0;
	struct roce_cqe *cqe = NULL;
	struct roce_cqe *dest = NULL;
	u8 owner_bit = 0;

	/*
	 * First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->cons_index; roce3_get_sw_cqe(cq, prod_index); ++prod_index) {
		if (prod_index == (u32)((int)cq->cons_index + cq->ibcq.cqe))
			break;
	}

	/*
	 * Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	/*
	 * xcqe:qpn's cqe.
	 *					CI
	 *		     +--------+------+------+------+----------+
	 * b4_clean: |		| cqe1 | xcqe2| cqe3 |		      |
	 *		     +--------+------+------+------+----------+
	 *						  \
	 *							\
	 *		     +---------------+------+------+----------+
	 * af_clean: |			   | cqe1 | cqe3 |		      |
	 *		     +---------------+------+------+----------+
	 */
	while ((int) --prod_index - (int)cq->cons_index >= 0) {
		cqe = (struct roce_cqe *)roce3_get_cqe(cq, prod_index & (u32)cq->ibcq.cqe);

		cqe->dw0.value = roce3_convert_cpu32(cqe->dw0.value);
		cqe->dw1.value = roce3_convert_cpu32(cqe->dw1.value);
		cqe->dw7.value = roce3_convert_cpu32(cqe->dw7.value);

		if (cqe->dw0.bs.qpn == qpn) {
			if (srq && (cqe->dw1.bs.s_r == ROCE_CQE_RECV_COMP))
				roce3_free_srq_wqe(srq, cqe->dw7.bs.wqe_cnt);

			++nfreed;
		} else if (nfreed != 0) {
			dest = (struct roce_cqe *)roce3_get_cqe(cq,
				(unsigned int)((int)prod_index + nfreed) &
				(unsigned int)cq->ibcq.cqe);
			dest->dw0.value = roce3_convert_cpu32(dest->dw0.value);
			owner_bit = dest->dw0.bs.owner;
			memcpy((void *)dest, (void *)cqe, sizeof(struct roce_cqe));
			dest->dw0.bs.owner = owner_bit;
			dest->dw0.value = roce3_convert_be32(dest->dw0.value);
			dest->dw1.value = roce3_convert_be32(dest->dw1.value);
			dest->dw7.value = roce3_convert_be32(dest->dw7.value);
		} else {
			pr_info("[ROCE] %s: Nothing need to do\n", __func__);
		}

		cqe->dw0.value = roce3_convert_be32(cqe->dw0.value);
		cqe->dw1.value = roce3_convert_be32(cqe->dw1.value);
		cqe->dw7.value = roce3_convert_be32(cqe->dw7.value);
	}

	if (nfreed != 0) {
		cq->cons_index += (u32)nfreed;
		/*
		 * Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		wmb();

		roce3_cq_set_ci(cq);
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_clean_qp_kernel
 Description  : roce3_clean_qp_kernel
 Input		: struct roce3_device *rdev
				struct roce3_qp *rqp
 Output	   : None

  1.Date		 : 2017/04/26
	Modification : Created function

****************************************************************************
*/
static void roce3_clean_qp_kernel(struct roce3_device *rdev, struct roce3_qp *rqp)
{
	struct roce3_cq *send_cq = NULL;
	struct roce3_cq *recv_cq = NULL;
	unsigned long flags;

	roce3_free_opt_rdmarc(rqp);

	roce3_get_cqs(rqp, &send_cq, &recv_cq);

	spin_lock_irqsave(&rdev->reset_flow_resource_lock, flags);
	roce3_lock_cqs(send_cq, recv_cq);
	/* del from lists under both locks above to protect reset flow paths */
	list_del(&rqp->qps_list);
	list_del(&rqp->cq_send_list);
	list_del(&rqp->cq_recv_list);

	roce3_cq_clean_process(recv_cq, rqp->qpn, rqp->ibqp.srq ?
		to_roce3_srq(rqp->ibqp.srq) : NULL);

	if (send_cq != recv_cq)
		roce3_cq_clean_process(send_cq, rqp->qpn, NULL);

	roce3_unlock_cqs(send_cq, recv_cq);
	spin_unlock_irqrestore(&rdev->reset_flow_resource_lock, flags);

	hiudk_cqm_object_delete(rdev->hwdev, &(rqp->qpc_info->object));

	if (rqp->sq.wrid) {
		kvfree(rqp->sq.wrid);
		rqp->sq.wrid = NULL;
	}

	if (rqp->rq.wrid) {
		kvfree(rqp->rq.wrid);
		rqp->rq.wrid = NULL;
	}

	if (rqp->qp_type != IB_QPT_XRC_TGT)
		hiudk_cqm_object_delete(rdev->hwdev, &(rqp->qp_buf_info->object));

	hmm_rdma_mtt_free(rdev->hwdev, &rqp->mtt, SERVICE_T_ROCE);
}

static int roce3_qp_destroy(struct roce3_qp *rqp, struct roce3_device *rdev)
{
	int ret = 0;

	ret = roce3_qp_modify_2rst_cmd(rdev, rqp->qpn);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to modify QP(0x%06x) to RESET, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return ret;
	}

	ret = roce3_qp_cache_out_cmd(rdev, rqp);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: QP(0x%06x) cache invalid, func_id(%d)\n",
			__func__, rqp->qpn, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

int roce3_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_qp *rqp = NULL;
	struct roce3_device *rdev = NULL;
	struct roce3_ucontext *ucontext = NULL;

	if (ibqp == NULL) {
		pr_err("[ROCE, ERR] %s: Ibqp is null\n", __func__);
		return -EINVAL;
	}

	rqp = to_roce3_qp(ibqp);
	rdev = to_roce3_dev(ibqp->device);

	if (rqp->qp_state != IB_QPS_RESET) {
		ret = roce3_qp_destroy(rqp, rdev);
		if (ret != 0)
			return ret;

		rqp->qp_state = IB_QPS_RESET;
	}

	if (ibqp->uobject) {
		ucontext = rdma_udata_to_drv_context(udata, struct roce3_ucontext, ibucontext);
		roce3_clean_qp_user(rdev, rqp, ucontext);
		goto out;
	}

	roce3_clean_qp_kernel(rdev, rqp);
out:
	mutex_lock(&rdev->qp_cnt.cur_qps_mutex);
	rdev->qp_cnt.del_qp_cnt++;
	mutex_unlock(&rdev->qp_cnt.cur_qps_mutex);
	return 0;
}
