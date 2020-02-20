// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "roce_k_compat.h"
#include "rdfx_common.h"
#include "rdfx_intf.h"

#ifdef CONFIG_KERNEL_419
void rdfx_cp_rq_wqe_buf(struct hns_roce_dev *hr_dev,
			struct hns_roce_qp *hr_qp, int ind, void *wqe,
			const struct ib_recv_wr *wr)

#else
void rdfx_cp_rq_wqe_buf(struct hns_roce_dev *hr_dev,
			struct hns_roce_qp *hr_qp, int ind, void *wqe,
			struct ib_recv_wr *wr)
#endif
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp = NULL;
	struct rdfx_rq_info *rq = NULL;
	void *dfx_qp_buf = NULL;

	spin_lock(&(rdfx->qp.qp_lock));

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, hr_qp->qpn);
	if (ZERO_OR_NULL_PTR(rdfx_qp)) {
		dev_err(hr_dev->dev, "find qp 0x%lx failed while cp sq wqe buf\n",
			hr_qp->qpn);
		spin_unlock(&(rdfx->qp.qp_lock));
		return;
	}

	spin_unlock(&(rdfx->qp.qp_lock));

	rq = &rdfx_qp->rq;
	atomic_inc(&rq->rq_wqe_cnt);

	/*copy wqe buf*/
	dfx_qp_buf = hns_roce_buf_offset(rdfx_qp->buf,
	    hr_qp->rq.offset + (ind << hr_qp->rq.wqe_shift));
	memcpy(dfx_qp_buf, (void *)wqe,
	    (wr->num_sge) * sizeof(struct hns_roce_v2_wqe_data_seg));

	atomic_set(&rq->head, (int)hr_qp->rq.head);
	rq->head_addr =
	  (u64)get_recv_wqe(hr_qp, hr_qp->rq.head & (hr_qp->rq.wqe_cnt - 1));
	atomic_set(&rq->tail, (int)hr_qp->rq.tail);
	rq->tail_addr =
	  (u64)get_recv_wqe(hr_qp, hr_qp->rq.tail & (hr_qp->rq.wqe_cnt - 1));
}
EXPORT_SYMBOL_GPL(rdfx_cp_rq_wqe_buf);


#ifdef CONFIG_KERNEL_419
static void rdfx_change_sq_buf(const struct ib_send_wr *wr, int atomic_en,
			       void *dfx_qp_buf, const void *dfx_hns_wqe_sge,
			       struct rdfx_sq_info *sq,
			       struct hns_roce_dev *hr_dev,
			       struct hns_roce_qp *qp)

#else

static void rdfx_change_sq_buf(struct ib_send_wr *wr, int atomic_en,
			       void *dfx_qp_buf, void *dfx_hns_wqe_sge,
			       struct rdfx_sq_info *sq,
			       struct hns_roce_dev *hr_dev,
			       struct hns_roce_qp *qp)
#endif
{
	if (atomic_en && wr->num_sge >= 2)
		memcpy(dfx_qp_buf, dfx_hns_wqe_sge, wr->num_sge *
		    sizeof(struct hns_roce_v2_wqe_data_seg));
	else if (wr->num_sge > 2)
		memcpy(dfx_qp_buf, dfx_hns_wqe_sge, (wr->num_sge - 2) *
		    sizeof(struct hns_roce_v2_wqe_data_seg));

	if (wr->opcode <= IB_WR_REG_SIG_MR)
		atomic_inc(&(sq->sq_wqe_cnt[wr->opcode]));
	else
		dev_err(hr_dev->dev, "Error opcode - %d while post send.\n",
			wr->opcode);

	if (wr->send_flags & IB_SEND_SIGNALED)
		atomic_inc(&sq->sig_wqe_cnt);
	if (wr->send_flags & IB_SEND_INLINE)
		atomic_inc(&sq->inline_cnt);

	atomic_set(&sq->head, (int)qp->sq.head);
	sq->head_addr =
		(u64)get_send_wqe(qp, qp->sq.head &
		    (unsigned int)(qp->sq.wqe_cnt - 1));
	atomic_set(&sq->tail, (int)qp->sq.tail);
	sq->tail_addr =
		(u64)get_send_wqe(qp, qp->sq.tail &
		    (unsigned int)(qp->sq.wqe_cnt - 1));
}

#ifdef CONFIG_KERNEL_419
void rdfx_cp_sq_wqe_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *qp,
			unsigned int ind, void *wqe,
			struct hns_roce_v2_rc_send_wqe *rc_sq_wqe,
			const struct ib_send_wr *wr)

#else

void rdfx_cp_sq_wqe_buf(struct hns_roce_dev *hr_dev, struct hns_roce_qp *qp,
			unsigned int ind, void *wqe,
			struct hns_roce_v2_rc_send_wqe *rc_sq_wqe,
			struct ib_send_wr *wr)
#endif
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_qp_info *rdfx_qp = NULL;
	struct rdfx_sq_info *sq = NULL;
	void *dfx_hns_wqe_sge = NULL;
	void *dfx_qp_buf = NULL;
	int atomic_en = 0;

	spin_lock(&(rdfx->qp.qp_lock));

	rdfx_qp = rdfx_find_rdfx_qp(rdfx, qp->qpn);
	if (ZERO_OR_NULL_PTR(rdfx_qp)) {
		dev_err(hr_dev->dev, "find qp 0x%lx failed while cp sq wqe buf\n",
			qp->qpn);
		spin_unlock(&(rdfx->qp.qp_lock));
		return;
	}

	spin_unlock(&(rdfx->qp.qp_lock));

	sq = &rdfx_qp->sq;

	if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP ||
	    wr->opcode == IB_WR_ATOMIC_FETCH_AND_ADD)
		atomic_en = 1;
	//copy wqe buf
	dfx_qp_buf = hns_roce_buf_offset(rdfx_qp->buf, qp->sq.offset +
			((ind & (qp->sq.wqe_cnt - 1)) << qp->sq.wqe_shift));
	memcpy(dfx_qp_buf, (void *)rc_sq_wqe,
		sizeof(struct hns_roce_v2_rc_send_wqe));

	dfx_qp_buf += sizeof(struct hns_roce_v2_rc_send_wqe);
	dfx_hns_wqe_sge = wqe;
	memcpy(dfx_qp_buf, dfx_hns_wqe_sge,
		2 * sizeof(struct hns_roce_v2_wqe_data_seg));
	dfx_qp_buf = hns_roce_buf_offset(rdfx_qp->buf, qp->sge.offset);
	dfx_hns_wqe_sge = hns_roce_buf_offset(&qp->hr_buf, qp->sge.offset);
	rdfx_change_sq_buf(wr, atomic_en, dfx_qp_buf,
			   dfx_hns_wqe_sge, sq, hr_dev, qp);
}
EXPORT_SYMBOL_GPL(rdfx_cp_sq_wqe_buf);

void rdfx_cp_cqe_buf(struct hns_roce_dev *hr_dev, struct hns_roce_cq *hr_cq,
		     void *cqe)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq = NULL;
	void *dfx_cq_buf = NULL;
	u32 ci;

	spin_lock(&rdfx->cq.cq_lock);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, hr_cq->cqn);
	if (ZERO_OR_NULL_PTR(rdfx_cq)) {
		dev_err(hr_dev->dev, "find cq 0x%lx failed while cp cqe buf\n",
			hr_cq->cqn);
		spin_unlock(&rdfx->cq.cq_lock);
		return;
	}

	spin_unlock(&rdfx->cq.cq_lock);

	ci = hr_cq->cons_index & (hr_cq->ib_cq.cqe);
	dfx_cq_buf = hns_roce_buf_offset(rdfx_cq->buf,
		ci * HNS_ROCE_V2_CQE_ENTRY_SIZE);
	if (cqe)
		memcpy(dfx_cq_buf, cqe, sizeof(struct hns_roce_v2_cqe));
}
EXPORT_SYMBOL_GPL(rdfx_cp_cqe_buf);

void rdfx_set_err_cqe_info(u32 status, struct rdfx_cq_info *rdfx_cq)
{
	switch (status & HNS_ROCE_V2_CQE_STATUS_MASK) {
	case HNS_ROCE_CQE_V2_LOCAL_LENGTH_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_LOC_LEN_ERR]));
		break;
	case HNS_ROCE_CQE_V2_LOCAL_QP_OP_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_LOC_QP_OP_ERR]));
		break;
	case HNS_ROCE_CQE_V2_LOCAL_PROT_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_LOC_PROT_ERR]));
		break;
	case HNS_ROCE_CQE_V2_WR_FLUSH_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_WR_FLUSH_ERR]));
		break;
	case HNS_ROCE_CQE_V2_MW_BIND_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_MW_BIND_ERR]));
		break;
	case HNS_ROCE_CQE_V2_BAD_RESP_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_BAD_RESP_ERR]));
		break;
	case HNS_ROCE_CQE_V2_LOCAL_ACCESS_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_LOC_ACCESS_ERR]));
		break;
	case HNS_ROCE_CQE_V2_REMOTE_INVAL_REQ_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_REM_INV_REQ_ERR]));
		break;
	case HNS_ROCE_CQE_V2_REMOTE_ACCESS_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_REM_ACCESS_ERR]));
		break;
	case HNS_ROCE_CQE_V2_REMOTE_OP_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_REM_OP_ERR]));
		break;
	case HNS_ROCE_CQE_V2_TRANSPORT_RETRY_EXC_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_RETRY_EXC_ERR]));
		break;
	case HNS_ROCE_CQE_V2_RNR_RETRY_EXC_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_RNR_RETRY_EXC_ERR]));
		break;
	case HNS_ROCE_CQE_V2_REMOTE_ABORT_ERR:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_REM_ABORT_ERR]));
		break;
	default:
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_GENERAL_ERR]));
		break;
	}
}

void rdfx_set_send_cqe_info(u32 opcode, struct rdfx_cq_info *rdfx_cq)
{
	switch (opcode) {
	case HNS_ROCE_SQ_OPCODE_SEND:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_SEND]));
		break;
	case HNS_ROCE_SQ_OPCODE_SEND_WITH_INV:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_SEND_WITH_INV]));
		break;
	case HNS_ROCE_SQ_OPCODE_SEND_WITH_IMM:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_SEND_WITH_IMM]));
		break;
	case HNS_ROCE_SQ_OPCODE_RDMA_READ:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_RDMA_READ]));
		break;
	case HNS_ROCE_SQ_OPCODE_RDMA_WRITE:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_RDMA_WRITE]));
		break;
	case HNS_ROCE_SQ_OPCODE_RDMA_WRITE_WITH_IMM:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_RDMA_WRITE_WITH_IMM]));
		break;
	case HNS_ROCE_SQ_OPCODE_LOCAL_INV:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_LOCAL_INV]));
		break;
	case HNS_ROCE_SQ_OPCODE_ATOMIC_COMP_AND_SWAP:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_ATOMIC_CMP_AND_SWP]));
		break;
	case HNS_ROCE_SQ_OPCODE_ATOMIC_FETCH_AND_ADD:
		atomic_inc(&(rdfx_cq->scqe_cnt[IB_WR_ATOMIC_FETCH_AND_ADD]));
		break;
	case HNS_ROCE_SQ_OPCODE_ATOMIC_MASK_COMP_AND_SWAP:
		atomic_inc(
		&(rdfx_cq->scqe_cnt[IB_WR_MASKED_ATOMIC_CMP_AND_SWP]));
		break;
	case HNS_ROCE_SQ_OPCODE_ATOMIC_MASK_FETCH_AND_ADD:
		atomic_inc(
		&(rdfx_cq->scqe_cnt[IB_WR_MASKED_ATOMIC_FETCH_AND_ADD]));
		break;
	default:
		break;
	}
}

void rdfx_set_other_cqe_info(u32 opcode, struct rdfx_cq_info *rdfx_cq)
{
	switch (opcode) {
	case HNS_ROCE_V2_OPCODE_RDMA_WRITE_IMM:
		atomic_inc(&(rdfx_cq->rcqe_cnt[RECV_RDMA_WITH_IMM]));
		break;
	case HNS_ROCE_V2_OPCODE_SEND:
		atomic_inc(&(rdfx_cq->rcqe_cnt[RECV_SEND]));
		break;
	case HNS_ROCE_V2_OPCODE_SEND_WITH_IMM:
		atomic_inc(&(rdfx_cq->rcqe_cnt[RECV_SEND_WITH_IMM]));
		break;
	case HNS_ROCE_V2_OPCODE_SEND_WITH_INV:
		atomic_inc(&(rdfx_cq->rcqe_cnt[RECV_SEND_WITH_INV]));
		break;
	default:
		break;
	}
}

void rdfx_set_cqe_info(struct hns_roce_dev *hr_dev, struct hns_roce_cq *hr_cq,
		       struct hns_roce_v2_cqe *cqe)
{
	struct rdfx_info *rdfx = (struct rdfx_info *)hr_dev->dfx_priv;
	struct rdfx_cq_info *rdfx_cq;
	u32 status;
	u32 opcode;
	int is_send;

	spin_lock(&rdfx->cq.cq_lock);

	rdfx_cq = rdfx_find_rdfx_cq(rdfx, hr_cq->cqn);
	if (!rdfx_cq) {
		dev_err(hr_dev->dev, "find cq 0x%lx failed while set cqe info\n",
			hr_cq->cqn);
		spin_unlock(&rdfx->cq.cq_lock);
		return;
	}

	spin_unlock(&rdfx->cq.cq_lock);

	status = roce_get_field(cqe->byte_4, V2_CQE_BYTE_4_STATUS_M,
				V2_CQE_BYTE_4_STATUS_S);
	if (status)
		rdfx_set_err_cqe_info(status, rdfx_cq);
	else {
		atomic_inc(&(rdfx_cq->st_cnt[IB_WC_SUCCESS]));

		opcode = roce_get_field(cqe->byte_4, V2_CQE_BYTE_4_OPCODE_M,
			V2_CQE_BYTE_4_OPCODE_S) & 0x1f;
		is_send = !roce_get_bit(cqe->byte_4, V2_CQE_BYTE_4_S_R_S);
		if (is_send)
			rdfx_set_send_cqe_info(opcode, rdfx_cq);
		else
			rdfx_set_other_cqe_info(opcode, rdfx_cq);
	}
}
EXPORT_SYMBOL_GPL(rdfx_set_cqe_info);
