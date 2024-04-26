// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#include <linux/slab.h>

#include "hinic3_hw.h"

#include "roce.h"
#include "roce_srq.h"
#include "roce_qp.h"
#include "roce_mix.h"
#include "roce_xrc.h"
#include "roce_cq.h"

#include "roce_main_extension.h"

/*
 ****************************************************************************
 Prototype	: roce3_next_cqe_sw
 Description  : roce3_next_cqe_sw
 Input		: struct roce3_cq *cq
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static struct roce_cqe *roce3_next_cqe_sw(struct roce3_cq *cq)
{
	return (struct roce_cqe *)roce3_get_sw_cqe(cq, cq->cons_index);
}

/*lint -e26*/
static int g_error_cqe_to_wc[ROCE_CQE_SYNDROME_MAX] = {
	[ROCE_CQE_SYNDROME_LOCAL_LENGTH_ERR] = IB_WC_LOC_LEN_ERR,
	[ROCE_CQE_SYNDROME_LOCAL_QP_OP_ERR] = IB_WC_LOC_QP_OP_ERR,
	[ROCE_CQE_SYNDROME_LOCAL_PROT_ERR] = IB_WC_LOC_PROT_ERR,
	[ROCE_CQE_SYNDROME_WR_FLUSH_ERR] = IB_WC_WR_FLUSH_ERR,

	[ROCE_CQE_SYNDROME_MW_BIND_ERR] = IB_WC_MW_BIND_ERR,
	[ROCE_CQE_SYNDROME_BAD_RESP_ERR] = IB_WC_BAD_RESP_ERR,

	[ROCE_CQE_SYNDROME_LOCAL_ACCESS_ERR] = IB_WC_LOC_ACCESS_ERR,
	[ROCE_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR] = IB_WC_REM_INV_REQ_ERR,
	[ROCE_CQE_SYNDROME_REMOTE_ACCESS_ERR] = IB_WC_REM_ACCESS_ERR,
	[ROCE_CQE_SYNDROME_REMOTE_OP_ERR] = IB_WC_REM_OP_ERR,
	[ROCE_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR] = IB_WC_RETRY_EXC_ERR,

	[ROCE_CQE_SYNDROME_RNR_RETRY_EXC_ERR] = IB_WC_RNR_RETRY_EXC_ERR,

	[ROCE_CQE_SYNDROME_REMOTE_ABORTED_ERR] = IB_WC_REM_ABORT_ERR,
};
/*lint +e26*/

/*
 ****************************************************************************
 Prototype	: roce3_handle_error_cqe
 Description  : roce3_handle_error_cqe
 Input		: struct roce_err_cqe *cqe
				struct ib_wc *wc
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_handle_error_cqe(struct roce_err_cqe *cqe, struct ib_wc *wc)
{
	if (cqe->dw7.bs.syndrome >= ROCE_CQE_SYNDROME_MAX) {
		wc->status = IB_WC_GENERAL_ERR;
	} else if (cqe->dw7.bs.syndrome > 0) {
		wc->status = g_error_cqe_to_wc[cqe->dw7.bs.syndrome];
		if (wc->status == 0)
			wc->status = IB_WC_GENERAL_ERR;
	}

	wc->vendor_err = cqe->dw7.bs.vendor_err;
}

static void roce3_get_local_opcode_from_cqe(const struct roce_cqe *cqe, struct ib_wc *wc)
{
	switch (cqe->dw1.bs.op_type) {
	case ROCE_OPCODE_LOCAL_INV:
		wc->opcode = IB_WC_LOCAL_INV;
		break;
	case ROCE_OPCODE_REG_SIG_MR:
		wc->opcode = IB_WC_REG_MR;
		break;

	default:
		pr_warn("[ROCE] %s: Unknown cqe optype\n", __func__);
		break;
	}
}

static void roce3_get_opcode_type_part_1(struct roce_cqe *cqe, struct ib_wc *wc)
{
	switch (cqe->dw1.bs.op_type) {
	case ROCE_OPCODE_RDMA_WRITE_WITH_IMM:
		wc->opcode = IB_WC_RDMA_WRITE;
		wc->wc_flags = (int)((u32)wc->wc_flags | IB_WC_WITH_IMM);
		break;

	case ROCE_OPCODE_RDMA_WRITE:
		wc->opcode = IB_WC_RDMA_WRITE;
		break;

	case ROCE_OPCODE_SEND_WITH_IMM:
		wc->opcode = IB_WC_SEND;
		wc->wc_flags = (int)((u32)wc->wc_flags | IB_WC_WITH_IMM);
		break;

	case ROCE_OPCODE_SEND:
		wc->opcode = IB_WC_SEND;
		break;

	case ROCE_OPCODE_SEND_WITH_INV:
		wc->opcode = IB_WC_SEND;
		break;
	default:
		roce3_get_local_opcode_from_cqe(cqe, wc);
		break;
	}
}

static void roce3_get_opcode_type_part_2(struct roce_cqe *cqe, struct ib_wc *wc)
{
	switch (cqe->dw1.bs.op_type) {
	case ROCE_OPCODE_RDMA_READ:
		wc->opcode = IB_WC_RDMA_READ;
		wc->byte_len = cqe->byte_cnt;
		break;

	case ROCE_OPCODE_ATOMIC_COMP_AND_SWP:
		wc->opcode = IB_WC_COMP_SWAP;
		wc->byte_len = ATOMIC_DATA_LEN;
		break;

	case ROCE_OPCODE_ATOMIC_FETCH_AND_ADD:
		wc->opcode = IB_WC_FETCH_ADD;
		wc->byte_len = ATOMIC_DATA_LEN;
		break;

	case ROCE_OPCODE_ATOMIC_MASKED_COMP_AND_SWP:
		wc->opcode = IB_WC_MASKED_COMP_SWAP;
		wc->byte_len = ATOMIC_DATA_LEN;
		break;

	case ROCE_OPCODE_ATOMIC_MASKED_FETCH_AND_ADD:
		wc->opcode = IB_WC_MASKED_FETCH_ADD;
		wc->byte_len = ATOMIC_DATA_LEN;
		break;
	case ROCE_OPCODE_FAST_REG_PMR:
		wc->opcode = IB_WC_REG_MR;
		break;

	default:
		roce3_get_local_opcode_from_cqe(cqe, wc);
		break;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_get_opcode_from_scqe
 Description  : Set the opcode/flag/byte_len of wc according to the opcode of send_cqe
 Input		: struct roce_cqe *cqe
				struct ib_wc *wc
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_get_opcode_from_scqe(struct roce_cqe *cqe, struct ib_wc *wc)
{
	wc->wc_flags = 0;

	if (cqe->dw1.bs.op_type < ROCE_OPCODE_RDMA_READ)
		roce3_get_opcode_type_part_1(cqe, wc);
	else
		roce3_get_opcode_type_part_2(cqe, wc);
}

/*
 ****************************************************************************
 Prototype	: roce3_get_opcode_from_rcqe
 Description  : Set the opcode/flag/byte_len of wc according to the opcode of send_cqe
 Input		: struct roce_cqe *cqe
				struct ib_wc *wc
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_get_opcode_from_rcqe(struct roce_cqe *cqe, struct ib_wc *wc)
{
	wc->byte_len = cqe->byte_cnt;

	switch (cqe->dw1.bs.op_type) {
	case ROCE_RECV_OPCODE_RDMA_WRITE_WITH_IMM:
		wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags = IB_WC_WITH_IMM;
		/* The driver does not perform big or small endian
		 * conversion for immediate data, but the incoming CQE
		 * has been converted to the CPU endian, so it needs to be converted back
		 */
		wc->ex.imm_data = roce3_convert_be32(cqe->imm_invalid_rkey);
		break;

	case ROCE_RECV_OPCODE_SEND_WITH_INV:
		wc->opcode = IB_WC_RECV;
		wc->wc_flags = IB_WC_WITH_INVALIDATE;
		wc->ex.invalidate_rkey = cqe->imm_invalid_rkey;
		break;

	case ROCE_RECV_OPCODE_SEND:
		wc->opcode = IB_WC_RECV;
		wc->wc_flags = 0;
		break;

	case ROCE_RECV_OPCODE_SEND_WITH_IMM:
		wc->opcode = IB_WC_RECV;
		wc->wc_flags = IB_WC_WITH_IMM;
		/*
		 * The driver does not perform big or small endian conversion
		 * for immediate data, but the incoming CQE
		 * has been converted to the CPU endian, so it needs to be converted back
		 */
		wc->ex.imm_data = roce3_convert_be32(cqe->imm_invalid_rkey);
		break;

	default:
		pr_warn("[ROCE] %s: Not supported\n", __func__);
		break;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_poll_and_resize
 Description  : roce3_cq_poll_and_resize
 Input		: struct roce3_cq *cq
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static void roce3_cq_poll_and_resize(struct roce3_device *rdev, struct roce3_cq *cq)
{
	if (ROCE_LIKELY(cq->resize_buf != NULL)) {
		/* Release the original Buffer of CQ */
		hiudk_cqm_object_resize_free_old(rdev->hwdev, &cq->cqm_cq->object);
		cq->buf = cq->resize_buf->buf;
		cq->ibcq.cqe = cq->resize_buf->cqe;

		kfree(cq->resize_buf);
		cq->resize_buf = NULL;
	}

	--cq->cons_index;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_get_cur_qp
 Description  : roce3_cq_get_cur_qp
 Input		: struct roce3_cq *cq
				struct roce3_qp **cur_qp
				struct roce_cqe *cqe
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_get_cur_qp(struct roce3_cq *cq, struct roce3_qp **cur_qp, struct roce_cqe *cqe)
{
	struct roce3_device *rdev = NULL;
	struct tag_cqm_object *cqm_obj_qp = NULL;

	if ((!*cur_qp) || (cqe->dw0.bs.qpn != (u32)(*cur_qp)->qpn)) {
		/*
		 * We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		rdev = to_roce3_dev(cq->ibcq.device);
		cqm_obj_qp = cqm_object_get(rdev->hwdev, CQM_OBJECT_SERVICE_CTX,
			cqe->dw0.bs.qpn, false);
		if (cqm_obj_qp == NULL) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: CQ(%06x) with entry for unknown QPN(%06x), func_id(%d)\n",
				__func__, cq->cqn, cqe->dw0.bs.qpn, rdev->glb_func_id);
			return -EINVAL;
		}

		*cur_qp = cqmobj_to_roce_qp(cqm_obj_qp);
		hiudk_cqm_object_put(rdev->hwdev, cqm_obj_qp);
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_cq_get_xrc_srq
 Description  : roce3_cq_get_xrc_srq
 Input		: struct roce3_cq *cq
				struct roce3_srq **srq
				struct roce_cqe *cqe
				u32 qp_type
 Output	   : None

  1.Date		 : 2017/5/4
	Modification : Created function

****************************************************************************
*/
static int roce3_cq_get_xrc_srq(struct roce3_cq *cq, struct roce3_srq **srq,
	struct roce_cqe *cqe, u32 qp_type)
{
	u32 srq_num = 0;
	struct roce3_device *rdev = NULL;
	struct tag_cqm_object *cqm_obj_srq = NULL;

	if (qp_type == IB_QPT_XRC_TGT) {
		srq_num = cqe->dw6.bs.srqn_rqpn;

		/* SRQ is also in the radix tree */
		rdev = to_roce3_dev(cq->ibcq.device);
		cqm_obj_srq = cqm_object_get(rdev->hwdev, CQM_OBJECT_RDMA_SRQ, srq_num, false);
		if (cqm_obj_srq == NULL) {
			dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: CQ(%06x) with entry for unknown SRQN(%06x), func_id(%d)\n",
				__func__, cq->cqn, srq_num, rdev->glb_func_id);
			return -EINVAL;
		}

		/* Get roce3__srq structure through cqm object */
		*srq = cqmobj_to_roce3_srq(cqm_obj_srq);
		hiudk_cqm_object_put(rdev->hwdev, cqm_obj_srq);
	}

	return 0;
}

static int roce3_poll_recv_cqe(struct roce3_qp *cur_qp, struct roce3_srq *srq,
	struct roce_cqe trans_cqe, struct ib_wc *wc)
{
	u16 wqe_ctr = 0;
	unsigned int tail = 0;
	struct roce3_srq *srq_tmp;

	if (cur_qp->ibqp.srq) {
		srq_tmp = to_roce3_srq(cur_qp->ibqp.srq);

		wqe_ctr = (u16)trans_cqe.dw1.bs.wqebb_cnt;
		/* Determine whether to overflow */
		if (wqe_ctr > srq_tmp->max_depth) {
			pr_err("[ROCE, ERR] %s: Get wqe index(0x%x) from cqe\n", __func__, wqe_ctr);
			return -EINVAL;
		}

		wc->wr_id = srq_tmp->wrid[wqe_ctr];
		roce3_free_srq_wqe(srq_tmp, wqe_ctr);
	} else if (srq) {
		wqe_ctr = (u16)trans_cqe.dw1.bs.wqebb_cnt;
		/* Determine whether to overflow */
		if (wqe_ctr > srq->max_depth) {
			pr_err("[ROCE, ERR] %s: Get wqe index(0x%x) from cqe\n", __func__, wqe_ctr);
			return -EINVAL;
		}

		wc->wr_id = srq->wrid[wqe_ctr];
		roce3_free_srq_wqe(srq, wqe_ctr);
	} else {
		struct roce3_wq *wq = &(cur_qp->rq);

		tail = (u32)(wq->tail & ((unsigned int)wq->wqebb_cnt - 1));
		wc->wr_id = wq->wrid[tail];
		++wq->tail;
	}

	return 0;
}

static void roce3_poll_move_tail(const struct roce3_qp *cur_qp, struct roce3_wq *wq,
	struct roce_cqe *trans_cqe)
{
	u16 wqe_ctr = 0;

	if (cur_qp->sq_signal_bits == 0) {
		wqe_ctr = trans_cqe->dw7.bs.wqe_cnt;
		wq->tail += (u16)(wqe_ctr - (u16)wq->tail);
	}
}

static void roce3_poll_one_get_av_info(const struct roce3_qp *cur_qp, struct ib_wc *wc,
	struct roce_cqe trans_cqe, struct roce_cqe *cqe)
{
	if ((cur_qp->qp_type == IB_QPT_UD) || (cur_qp->qp_type == IB_QPT_GSI)) {
		wc->sl = trans_cqe.dw4.bs.vlan_pri;
		wc->src_qp = trans_cqe.dw6.bs.srqn_rqpn;
		wc->network_hdr_type = trans_cqe.dw6.bs.stp;
		/* Take the first Byte data, shift 8bit */
		wc->smac[0] = (u8)(trans_cqe.dw4.bs.smac_h >> 8);
		wc->smac[1] = (u8)(trans_cqe.dw4.bs.smac_h & 0xff);
		memcpy(&wc->smac[2], &cqe->smac_l, sizeof(cqe->smac_l)); // 2 : smac array idx
		wc->wc_flags = (int)((u32)wc->wc_flags | IB_WC_WITH_SMAC);
		if (trans_cqe.dw6.bs.vlan_pre != 0) {
			wc->vlan_id = trans_cqe.dw4.bs.vlan_id;
			wc->wc_flags = (int)((u32)wc->wc_flags | IB_WC_WITH_VLAN);
		}
	}
}

static int roce3_poll_one_get_qp_and_srq(struct roce3_cq *cq, struct roce3_qp **cur_qp,
	struct ib_wc *wc, struct roce_cqe *trans_cqe, struct roce3_srq **srq)
{
	int ret = 0;

	ret = roce3_cq_get_cur_qp(cq, cur_qp, trans_cqe);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get current qp\n", __func__);
		return ret;
	}

	wc->qp = &((*cur_qp)->ibqp);

	ret = roce3_cq_get_xrc_srq(cq, srq, trans_cqe, wc->qp->qp_type);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get xrc srq\n", __func__);
		return ret;
	}

	return ret;
}

static void roce3_bytes_trans(u32 *addr, int dw_num)
{
	u32 *dw = addr;
	int i = 0;

	for (i = 0; i < dw_num; i++) {
		*dw = roce3_convert_cpu32(*dw);
		dw++;
	}
}

static int roce3_get_and_trans_cqe(struct roce3_device *rdev, struct roce3_cq *cq,
	struct roce_cqe *trans_cqe, int *is_send, struct roce_cqe **cqe)
{
	do {
		*cqe = roce3_next_cqe_sw(cq);
		if (*cqe == NULL)
			return -EAGAIN;

		/* Later, it is necessary to perform big and small end conversion on CQE.
		 * In order to avoid turning back after processing, copy a copy
		 */
		memcpy((void *)trans_cqe, (void *)*cqe, sizeof(struct roce_cqe));
		++cq->cons_index;

		/*
		 * Make sure we read CQ entry contents after we've checked the
		 * ownership bit.
		 */
		rmb();

		/* Convert the CQE into the CPU endian corresponding to the running environment */
		roce3_bytes_trans((u32 *)(void *)trans_cqe,
			(int)(sizeof(struct roce_cqe) / CQ_DW_TO_BYTE));

		*is_send = trans_cqe->dw1.bs.s_r;
		/* Resize CQ operation in progress */
		if (ROCE_UNLIKELY(trans_cqe->dw1.bs.op_type == ROCE_OPCODE_RESIZE_CQE))
			roce3_cq_poll_and_resize(rdev, cq);
	} while (ROCE_UNLIKELY(trans_cqe->dw1.bs.op_type == ROCE_OPCODE_RESIZE_CQE));

	return 0;
}

static void roce3_poll_send_cqe(struct roce3_qp *cur_qp, struct roce_cqe *trans_cqe,
	struct ib_wc *wc)
{
	struct roce3_wq *wq = &(cur_qp->sq);
	/* QP of type IB_SIGNAL_REQ_WR, tail needs to skip several WRs that do not generate CQE */
	roce3_poll_move_tail(cur_qp, wq, trans_cqe);

	wc->wr_id = wq->wrid[wq->tail & ((unsigned int)wq->wqebb_cnt - 1)];
	++wq->tail;

	if (trans_cqe->dw1.bs.op_type == ROCE_OPCODE_ERR) {
		roce3_handle_error_cqe((struct roce_err_cqe *)(void *)trans_cqe, wc);
		return;
	}

	roce3_get_opcode_from_scqe(trans_cqe, wc);
}

/*
 ****************************************************************************
 Prototype	: roce3_poll_one
 Description  : roce3_poll_one
 Input		: struct roce3_cq *cq
				struct roce3_qp **cur_qp
				struct ib_wc *wc
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static int roce3_poll_one(struct roce3_device *rdev, struct roce3_cq *cq,
	struct roce3_qp **cur_qp, struct ib_wc *wc)
{
	int ret = 0;
	struct roce_cqe *cqe = NULL;
	struct roce_cqe trans_cqe;
	struct roce3_srq *srq = NULL;
	int is_send = 0;
	bool need_poll = true;

	while (need_poll) {
		ret = roce3_get_and_trans_cqe(rdev, cq, &trans_cqe, &is_send, &cqe);
		if (ret != 0)
			return -EAGAIN;

		ret = roce3_poll_one_get_qp_and_srq(cq, cur_qp, wc, &trans_cqe, &srq);
		if (ret != 0)
			return ret;

		/*
		 * Poll cq exception handling, generally cq judges
		 * user state information, xrc judges wrid
		 */
		if ((*cur_qp)->umem || ((*cur_qp)->ibqp.xrcd && !(srq->wrid))) {
			pr_err("[ROCE, ERR] %s: qp(%u) create in user space , but poll cq in kernel. NOT PERMIT!\n",
				__func__, (*cur_qp)->qpn);
			return -EACCES;
		}

		if (trans_cqe.dw1.bs.fake != 0) {
			pr_info("[ROCE] %s: Fake cqe go repoll.\n", __func__);
			continue;
		}

		wc->status = IB_WC_SUCCESS;
		if (is_send != 0) {
			roce3_poll_send_cqe(*cur_qp, &trans_cqe, wc);
			return 0;
		}
		ret = roce3_poll_recv_cqe(*cur_qp, srq, trans_cqe, wc);
		if (ret != 0)
			return ret;

		if (trans_cqe.dw1.bs.op_type == ROCE_OPCODE_ERR) {
			roce3_handle_error_cqe((struct roce_err_cqe *)(void *)&trans_cqe, wc);
			return 0;
		}

		roce3_get_opcode_from_rcqe(&trans_cqe, wc);
		wc->wc_flags = (int)((unsigned int)wc->wc_flags | IB_WC_GRH);
		wc->pkey_index = 0;
		wc->vlan_id = 0xffff;
		wc->sl = 0;

		/* avoid cm_req_handler()->ib_lid_be16() trigger call trace */
		wc->slid = 0;

		roce3_poll_one_get_av_info((*cur_qp), wc, trans_cqe, cqe);

		/* Kernel mode does not support receiving inline */
		if (trans_cqe.dw1.bs.inline_r == ROCE_CQE_RQ_INLINE) {
			pr_err("[ROCE, ERR] %s: Receive inline not supported in kernel space\n",
				__func__);
			return -EINVAL;
		}
		need_poll = false;
	}

	return 0;
}

static int sw_send_comp(struct roce3_qp *rqp, int num_entries, int *npolled, struct ib_wc *wc)
{
	struct roce3_wq *wq = &rqp->sq;
	unsigned int cur = wq->head - wq->tail;
	unsigned int i;

	if (cur == 0)
		goto out;

	for (i = 0; (i < cur) && (*npolled < num_entries); i++) {
		wc[*npolled].wr_id = wq->wrid[wq->tail & (wq->wqebb_cnt - 1)];
		wc[*npolled].status = IB_WC_WR_FLUSH_ERR;
		wc[*npolled].vendor_err = ROCE_CQE_SYNDROME_WR_FLUSH_ERR;
		wc[*npolled].qp = &rqp->ibqp;
		wq->tail++;
		(*npolled)++;
	}

out:
	return (*npolled >= num_entries);
}

static int sw_recv_comp(struct roce3_qp *rqp, int num_entries, int *npolled, struct ib_wc *wc)
{
	struct roce3_wq *wq = &rqp->rq;
	unsigned int cur = wq->head - wq->tail;
	unsigned int i;

	if (cur == 0)
		goto out;

	for (i = 0; (i < cur) && (*npolled < num_entries); i++) {
		wc[*npolled].wr_id = wq->wrid[wq->tail & (wq->wqebb_cnt - 1)];
		wc[*npolled].status = IB_WC_WR_FLUSH_ERR;
		wc[*npolled].vendor_err = ROCE_CQE_SYNDROME_WR_FLUSH_ERR;
		wc[*npolled].qp = &rqp->ibqp;
		wq->tail++;
		(*npolled)++;
	}

out:
	return (*npolled >= num_entries);
}

static int roce_poll_sw_comp(const struct roce3_cq *rcq, int num_entries, struct ib_wc *wc)
{
	struct roce3_qp *rqp = NULL;
	int npolled = 0;

	list_for_each_entry(rqp, &rcq->send_qp_list, cq_send_list) {
		if (sw_send_comp(rqp, num_entries, &npolled, wc) != 0)
			return npolled;
	}

	list_for_each_entry(rqp, &rcq->recv_qp_list, cq_recv_list) {
		if (sw_recv_comp(rqp, num_entries, &npolled, wc) != 0)
			return npolled;
	}

	return npolled;
}

/* the format of cq_ci DB:the bits of ci less than 24bit */
void roce3_cq_set_ci(struct roce3_cq *cq)
{
	*cq->set_ci_db = cpu_to_be32(cq->cons_index & 0xffffff);
}

int roce3_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct roce3_device *rdev = NULL;
	struct roce3_cq *rcq = to_roce3_cq(ibcq);
	struct roce3_qp *cur_qp = NULL;
	unsigned long flags = 0;
	int npolled = 0;
	int ret = 0;

	spin_lock_irqsave(&rcq->lock, flags);

	rdev = to_roce3_dev(ibcq->device);
	if (roce3_hca_is_present(rdev) == 0) {
		npolled = roce_poll_sw_comp(rcq, num_entries, wc);
		goto poll_out;
	}

	for (npolled = 0; npolled < num_entries; ++npolled) {
		ret = roce3_poll_one(rdev, rcq, &cur_qp, wc + npolled);
		if (ret != 0)
			break;
	}

	roce3_cq_set_ci(rcq);

poll_out:
	spin_unlock_irqrestore(&rcq->lock, flags);

	if ((ret == 0) || (ret == -EAGAIN))
		return npolled;

	return ret;
}

static void roce3_cq_arm(struct roce3_cq *cq, u32 cmd, void __iomem *uar_page)
{
	struct roce_db_cq_arm db_value;

	memset(&db_value, 0, sizeof(db_value));

	db_value.dw0.bs.type = 3;
	db_value.dw0.bs.cos = 0; /* arm_cq don't need cos */
	db_value.dw0.bs.cp = 1;  /* 1 for cp */
	db_value.dw0.bs.non_filter = 1;
	db_value.dw0.bs.cqc_type = 0;
	db_value.dw0.bs.cqn = cq->cqn;
	db_value.dw0.value = roce3_convert_be32(db_value.dw0.value);

	db_value.dw1.bs.cmd_sn = cq->arm_sn;
	db_value.dw1.bs.cmd = cmd;
	db_value.dw1.bs.ci = cq->cons_index;
	db_value.dw1.value = roce3_convert_be32(db_value.dw1.value);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();

	roce3_write64((u32 *)(void *)&db_value, uar_page);
}

int roce3_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	unsigned long lock_flags = 0;
	struct roce3_cq *cq = to_roce3_cq(ibcq);

	spin_lock_irqsave(&cq->lock, lock_flags);
	if (cq->arm_flag != 0) {
		spin_unlock_irqrestore(&cq->lock, lock_flags);
		return 0;
	}

	cq->arm_flag = 1;
	spin_unlock_irqrestore(&cq->lock, lock_flags);

	/* Only 64-bit is supported, 64-bit writes are atomic, no need to lock */
	roce3_cq_arm(to_roce3_cq(ibcq),
		(((unsigned int)flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED) ?
			ROCE_CQ_DB_REQ_NOT_SOL : ROCE_CQ_DB_REQ_NOT,
		to_roce3_dev(ibcq->device)->kernel_db_map);

	return 0;
}
