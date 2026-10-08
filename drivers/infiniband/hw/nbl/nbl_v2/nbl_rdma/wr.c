// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/bitfield.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_cm.h>
#include <rdma/ibta_vol1_c12.h>
#include "wr.h"
#include "umr.h"
#include "qp.h"
#include "debug.h"

static int nbl_qp_generate_rq_soft_wc(const struct ib_recv_wr *wr, struct nbl_qp *nbl_qp)
{
	int i;
	struct nbl_ib_wc *soft_wc;
	struct nbl_cq *nblcq = nbl_qp->rcq;

	while (wr) {
		soft_wc = kzalloc(sizeof(struct nbl_ib_wc), GFP_ATOMIC);
		if (!soft_wc)
			return -ENOMEM;

		for (i = 0; i < wr->num_sge; i++)
			soft_wc->info.bytes_xfered += wr->sg_list[i].length;
		soft_wc->info.qpn = nbl_qp->sc_qp.uk_qp.qpn;
		soft_wc->info.wr_id = wr->wr_id;
		soft_wc->info.op_type = NBL_OPCODE_RECV;
		soft_wc->ukqp = &nbl_qp->sc_qp.uk_qp;
		soft_wc->is_sq = false;
		soft_wc->info.qp_handle = (nbl_qp_handle)(unsigned long)&nbl_qp->sc_qp.uk_qp;
		soft_wc->info.comp_status = NBL_COMPL_STATUS_FLUSHED;
		soft_wc->info.major_err = NBL_ERR_RQ_FLUSH_COMPLETE;
		soft_wc->info.error = 1;
		nbl_generate_wc(nblcq, soft_wc);
		wr = wr->next;
	}
	return 0;
}


static int nbl_qp_generate_sq_soft_wc(const struct ib_send_wr *wr, struct nbl_qp *nbl_qp)
{
	int i;
	struct nbl_ib_wc *soft_wc;
	struct nbl_cq *nblcq = nbl_qp->scq;

	while (wr) {
		soft_wc = kzalloc(sizeof(struct nbl_ib_wc), GFP_ATOMIC);
		if (!soft_wc)
			return -ENOMEM;

		for (i = 0; i < wr->num_sge; i++)
			soft_wc->info.bytes_xfered += wr->sg_list[i].length;
		soft_wc->info.qpn = nbl_qp->sc_qp.uk_qp.qpn;
		soft_wc->info.wr_id = wr->wr_id;
		soft_wc->info.op_type = nbl_opcode[wr->opcode];
		soft_wc->ukqp = &nbl_qp->sc_qp.uk_qp;
		soft_wc->info.qp_handle = (nbl_qp_handle)(unsigned long)&nbl_qp->sc_qp.uk_qp;
		soft_wc->is_sq = true;
		soft_wc->info.comp_status = NBL_COMPL_STATUS_FLUSHED;
		soft_wc->info.major_err = NBL_ERR_SQ_FLUSH_COMPLETE;
		soft_wc->info.error = 1;
		nbl_generate_wc(nblcq, soft_wc);
		wr = wr->next;
	}
	return 0;
}

static void nbl_post_sq_db(struct nbl_uk_qp *uk_qp)
{
	u64 temp;

	temp = (__u64)(FIELD_PREP(NBL_SQ_DB_TC, uk_qp->db_tc) |
		       FIELD_PREP(NBL_SQ_DB_QPN, uk_qp->qpn));
	write64_reg(temp, uk_qp->sq_db);
}

static void nbl_fill_raddr_seg_info_v2(struct nbl_wqe_raddr_seg_v2 *rseg,
				       const struct ib_send_wr *wr,
				       u32 payload_len)
{
	rseg->raddr = cpu_to_be64(rdma_wr(wr)->remote_addr);
	rseg->rkey = cpu_to_be32(rdma_wr(wr)->rkey);
	rseg->len = cpu_to_be32(payload_len);
}

static __be64 *nbl_get_next_recv_wqe(struct nbl_qp *qp,
			      const struct ib_recv_wr *wr,
			      unsigned int *wqe_idx)
{
	unsigned int size_quanta;
	__be64 *wqe;
	int ret_code;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	size_quanta = uk_qp->rqe_mult;
	if (size_quanta > NBL_SQ_RING_FREE_QUANTA(uk_qp->rq_ring)) {
		nbl_pr_err("the rq ring is full.\n");
		return NULL;
	}
	NBL_ATOMIC_RING_MOVE_HEAD_BY_COUNT(uk_qp->rq_ring, *wqe_idx, size_quanta,
					   ret_code);
	if (ret_code) {
		nbl_pr_err("move rq ring head by count failed.\n");
		return NULL;
	}
	if (!*wqe_idx)
		uk_qp->rwqe_polarity = !uk_qp->rwqe_polarity;
	wqe = nbl_get_wqe(uk_qp->rq_base, &(qp->sc_qp.rqbuf.frag_buf),
			sizeof(struct nbl_qp_block), *wqe_idx, !qp->sc_qp.rq_pm);
	uk_qp->rq_wrid_array[*wqe_idx] = wr->wr_id;
	return wqe;
}

static void nbl_post_rq_db_v2(struct nbl_uk_qp *uk_qp, bool sw_pi_phase)
{
	__u64 temp;

	dma_wmb();
	temp = (__u64)(FIELD_PREP(NBL_RQ_DB_PI, uk_qp->rq_ring.head) |
		       FIELD_PREP(NBL_RQ_DB_PI_PHASE, sw_pi_phase) |
		       FIELD_PREP(NBL_RQ_DB_QPN, uk_qp->qpn) |
		       FIELD_PREP(NBL_RQ_DB_SEQ_NUM, uk_qp->seq_num));
	write64_reg(temp, uk_qp->rq_db);
}

static int check_srq_full(struct nbl_srq *srq)
{
	struct nbl_srq_subq *cur_subq = srq->cur_subq;
	struct nbl_srq_subq *prevq = srq->cur_subq->prevq;
	u32 buf_quanta = cur_subq->buf_quanta;
	u16 pi = srq->cur_subq->pi;
	u32 wqe_quanta = srq->wqe_quanta;

	/* ci on prevq */
	if (prevq && prevq->has_ci) {
		/* consider ring buffer, pi should not reach ci */
		if (prevq->ci > pi && (prevq->ci - pi <= wqe_quanta))
			return -ENOMEM;
	} else {
		/* pi reach the end of queue,
		 * no next queue OR ci on the start of queue
		 */
		if (pi + wqe_quanta > buf_quanta - 1) {
			if (!cur_subq->nextq ||
			    (cur_subq->has_ci && cur_subq->ci == 0)) {
				return -ENOMEM;
			}
		}
	}
	return 0;
}

static int get_wqe_index(struct nbl_srq *srq)
{
	struct nbl_srq_subq *cur_subq = srq->cur_subq;
	int index = cur_subq->pi / srq->wqe_quanta;

	return cur_subq->subq_id << srq->max_wr_shift | index;
}

static int fill_data_seg(const struct ib_recv_wr *wr, u8 *data_seg_buf_base,
			 struct nbl_rq_ctrl_param *param)
{
	u8 *dseg = data_seg_buf_base;
	void *wqe = dseg;
	struct nbl_rq_wqe_data_seg_v2 data = {};
	int i;
	int rsv_sge_num = 0;

	/* data seg */
	for (i = 0; i < wr->num_sge; i++) {
		if (unlikely(!wr->sg_list[i].length))
			continue;
		else if (wr->sg_list[i].length > RQ_DMA_MAX_LEN)
			return -EINVAL;

		(param->payload_len) += wr->sg_list[i].length;
		(param->valid_sge_num)++;

		data.wqe_valid_dma_len = cpu_to_be32(
			(u32)!param->wqe_vld << RQ_WQE_DATA_VALID_SHIFT |
			wr->sg_list[i].length);
		data.local_addr = cpu_to_be64(wr->sg_list[i].addr);
		data.lkey = cpu_to_be32(wr->sg_list[i].lkey);
		/* Compiler adds padding to struct fields for alignment,
		 * so set data into memory directly
		 */
		*(__be32 *)dseg = data.wqe_valid_dma_len;
		dseg += RQ_DATA_SEG_WQE_VLD_DMA_LEN_SIZE;

		*(__be64 *)dseg = data.local_addr;
		dseg += RQ_DATA_SEG_LOCAL_ADDR_SIZE;

		*(__be32 *)dseg = data.lkey;
		dseg += RQ_DATA_SEG_LKEY_SIZE;
	}

	rsv_sge_num = ((param->wqe_quanta * NBL_MIN_WQE_SIZE) /
		       sizeof(struct nbl_rq_wqe_data_seg_v2)) -
		      NBL_WQE_FIRST_QUANTA_SGE_NUM;
	nbl_set_sge_vld(wqe, rsv_sge_num, param->wqe_vld);

	return 0;
}

static int fill_ctrl_seg(u8 *wqe_ctrl_buf_base, struct nbl_rq_ctrl_param *param)
{
	__be32 *ctrl_head = (__be32 *)wqe_ctrl_buf_base;

	nbl_32bit_write(ctrl_head, RQ_WQE_IDX_PHASE, !param->wqe_vld);
	nbl_32bit_write(ctrl_head, RQ_WQE_IDX, param->wqe_idx);
	nbl_32bit_write(ctrl_head, RQ_WQE_DS_H,
			(param->valid_sge_num & RQ_CTRL_SEG_DS_5_4_MASK) >>
				RQ_CTRL_SEG_DS_5_4_SHIFT);
	nbl_32bit_write(ctrl_head, RQ_WQE_OPCODE, NBL_OPCODE_RQ_WQE);
	nbl_32bit_write(ctrl_head, RQ_WQE_QPN, param->qpn_srqn);
	nbl_32bit_write(ctrl_head, RQ_WQE_DS_L,
			param->valid_sge_num & RQ_CTRL_SEG_DS_3_0_MASK);
	nbl_32bit_write(ctrl_head, RQ_WQE_TS, param->wqe_quanta);
	nbl_32bit_write(ctrl_head, RQ_WQE_PAYLOAD_LEN, param->payload_len);

	dma_wmb();

	nbl_32bit_write_bool(ctrl_head, RQ_WQE_VLD, param->wqe_vld);

	return 0;
}

static int fill_wqe(struct nbl_srq *srq, u8 *wqe_buf_base, const struct ib_recv_wr *wr)
{
	int err = 0;
	struct nbl_rq_ctrl_param param = {};

	param.wqe_vld = srq->cur_subq->nxt_wqe_phase;
	param.wqe_idx = srq->cur_subq->pi;
	param.qpn_srqn = srq->srqn;
	param.wqe_quanta = srq->wqe_quanta;

	err = fill_data_seg(wr,
			    wqe_buf_base + NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE,
			    &param);
	if (err)
		goto out;

	err = fill_ctrl_seg(wqe_buf_base, &param);
out:
	return err;
}

static void move_pi_to_next_wqe(struct nbl_srq *srq)
{
	struct nbl_srq_subq *cur_subq = srq->cur_subq;
	u32 buf_quanta = cur_subq->buf_quanta;
	int wqe_quanta = srq->wqe_quanta;

	/* whether pi reach the end of subq */
	if (cur_subq->pi + wqe_quanta < buf_quanta) {
		cur_subq->pi += wqe_quanta;
	} else {
		cur_subq->has_pi = 0;
		cur_subq->pi = 0;
		srq->cur_subq = cur_subq->nextq;
		cur_subq = srq->cur_subq;
		/* revert phase */
		cur_subq->nxt_wqe_phase = !cur_subq->prevq->nxt_wqe_phase;
		cur_subq->has_pi = 1;
		cur_subq->pi = 0;
		/* db0 count set to 0 */
		srq->db0_count = 0;
		/* nxt_queue_num ++ */
		srq->nxt_queue_num =
			(srq->nxt_queue_num + 1) & SRQ_NXT_QUEUE_NUM_MASK;
	}
}

static void srq_ring_db(struct nbl_srq *srq)
{
	u64 db0, db1;
	/* nxt refers to the pi queue, which means cur_subq */
	u64 srq_nxt_ba = srq->cur_subq->mem.pa >> NBL_SRQ_SHDW_SRQ_NXT_BA_SHIFT;
	u32 srq_nxt_ba_51_24;
	u32 srq_nxt_ba_23_8;
	u8 srq_nxt_ba_7_0;

	srq_nxt_ba_51_24 = srq_nxt_ba >> NBL_SRQ_DB0_SRQ_NXT_BA_51_24_SHIFT;
	srq_nxt_ba_23_8 = (srq_nxt_ba >> NBL_SRQ_DB1_SRQ_NXT_BA_23_8_SHIFT) &
			  NBL_SRQ_DB1_SRQ_NXT_BA_23_8_MASK;
	srq_nxt_ba_7_0 = srq_nxt_ba & NBL_SRQ_DB1_SRQ_NXT_BA_7_0_MASK;

	/* valid bit is written before read shadow and ring db */
	mb();

	/* ring db0 */
	if (srq->db0_count < NBL_SRQ_DB0_TH) {
		db0 = (u64)(
			FIELD_PREP(NBL_SRQ_DB0_NXT_ID, srq->cur_subq->subq_id) |
			FIELD_PREP(NBL_SRQ_DB0_SEQ_NUM, srq->seq_num) |
			FIELD_PREP(NBL_SRQ_DB0_QUEUE_NUM, srq->nxt_queue_num) |
			FIELD_PREP(NBL_SRQ_DB0_SRQN_V2, srq->srqn) |
			FIELD_PREP(NBL_SRQ_DB0_SW_SRQ_PI_PAHSE_COPY,
				   (u8)srq->cur_subq->sw_srq_pi_phase) |
			FIELD_PREP(NBL_SRQ_DB0_NXT_SRQE_VLD,
				   (u8)srq->cur_subq->nxt_wqe_phase) |
			FIELD_PREP(NBL_SRQ_DB0_SRQ_NXT_PM,
				   (u8)srq->cur_subq->page_mode) |
			FIELD_PREP(NBL_SRQ_DB0_SRQ_NXT_BA_51_24,
				   srq_nxt_ba_51_24));
		write64_reg(db0, srq->srq_db0);
		/* make sure db0 before db1 */
		mb();
		srq->db0_count++;
	}

	db1 = (u64)(FIELD_PREP(NBL_SRQ_DB1_SRQ_NXT_BA_7_0, srq_nxt_ba_7_0) |
		      FIELD_PREP(NBL_SRQ_DB1_SEQ_NUM, srq->seq_num) |
		      FIELD_PREP(NBL_SRQ_DB1_QUEUE_NUM, srq->nxt_queue_num) |
		      FIELD_PREP(NBL_SRQ_DB1_SRQN_V2, srq->srqn) |
		      FIELD_PREP(NBL_SRQ_DB1_SW_SRQ_PI_PHASE,
				 (u8)srq->cur_subq->sw_srq_pi_phase) |
		      FIELD_PREP(NBL_SRQ_DB1_SW_SRQ_PI, srq->cur_subq->pi) |
		      FIELD_PREP(NBL_SRQ_DB1_SRQ_NXT_BA_23_8, srq_nxt_ba_23_8));
	write64_reg(db1, srq->srq_db1);
}

static void nbl_srq_shdw_update(struct nbl_srq *srq)
{
	/* nxt refers to the pi queue, which means cur_subq */
	u8 srq_nxt_pm = (u8)srq->cur_subq->page_mode;
	u8 srq_nxt_id = srq->cur_subq->subq_id;
	u8 nxt_srqe_vld = (u8)srq->cur_subq->nxt_wqe_phase;
	u64 srq_nxt_ba = srq->cur_subq->mem.pa >> NBL_SRQ_SHDW_SRQ_NXT_BA_SHIFT;
	u8 srq_nxt_ba_51_48;
	u64 srq_nxt_ba_47_0;
	u8 sw_srq_pi_phase = (u8)srq->cur_subq->sw_srq_pi_phase;
	u16 sw_srq_pi = srq->cur_subq->pi;
	u64 temp = 0;
	u8 seq_num = srq->seq_num;
	u8 nxt_queue_num = srq->nxt_queue_num;

	srq_nxt_ba_51_48 =
		(srq_nxt_ba >> SRQ_NXT_BA_51_48_SHIFT) & SRQ_NXT_BA_51_48_MASK;
	srq_nxt_ba_47_0 = srq_nxt_ba & SRQ_NXT_BA_47_0_MASK;

	get_64bit_val(srq->shdw.va, 0, &temp);

	temp = temp & FIELD_PREP(NBL_SRQ_SHDW_NXT_QUEUE_NUM, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SEQ_NUM, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_ID, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SRQ_PI_PHASE_COPY, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_NXT_SRQE_VLD, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_PM, 0) &
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_BA_51_48, 0);

	temp = temp |
	       FIELD_PREP(NBL_SRQ_SHDW_NXT_QUEUE_NUM, nxt_queue_num) |
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SEQ_NUM, seq_num) |
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_ID, srq_nxt_id) |
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SRQ_PI_PHASE_COPY, sw_srq_pi_phase) |
	       FIELD_PREP(NBL_SRQ_SHDW_NXT_SRQE_VLD, nxt_srqe_vld) |
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_PM, srq_nxt_pm) |
	       FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_BA_51_48, srq_nxt_ba_51_48);
	set_64bit_val((__be64 *)srq->shdw.va, 0, temp);

	dma_wmb();

	temp = 0;
	temp = FIELD_PREP(NBL_SRQ_SHDW_SRQ_NXT_BA_47_0, srq_nxt_ba_47_0) |
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SRQ_PI_PHASE, sw_srq_pi_phase) |
	       FIELD_PREP(NBL_SRQ_SHDW_SW_SRQ_PI, sw_srq_pi);
	set_64bit_val((__be64 *)srq->shdw.va, 8, temp);
}

int nbl_ib_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
				const struct ib_recv_wr **bad_wr)
{
	struct nbl_srq *srq = to_nbl_srq(ibsrq);
	struct ib_pd *ibpd = ibsrq->pd;
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	unsigned long flags;
	unsigned int nreq;
	int err = 0;
	void *wqe_buf_base;

	spin_lock_irqsave(&srq->lock, flags);

	if (unlikely(srq->user_mode)) {
		err = -EINVAL;
		*bad_wr = wr;
		goto out;
	}

	for (nreq = 0; wr; nreq++, wr = wr->next) {
		/* check full */
		err = check_srq_full(srq);
		if (err) {
			*bad_wr = wr;
			break;
		}

		if (unlikely(wr->num_sge > srq->max_sge)) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		srq->wrid[get_wqe_index(srq)] = wr->wr_id;

		wqe_buf_base = nbl_get_wqe(srq->cur_subq->mem.va,
					&(srq->cur_subq->subq_buf.frag_buf), NBL_WQE_QUANTA_SIZE,
					srq->cur_subq->pi, !srq->cur_subq->page_mode);
		if (!wqe_buf_base) {
			nbl_ib_err(&rf->sc_dev, "get srq next recv wqe failed.\n");
			*bad_wr = wr;
			err = -EINVAL;
			goto out;
		}

		err = fill_wqe(srq, wqe_buf_base, wr);
		if (err) {
			*bad_wr = wr;
			break;
		}

		move_pi_to_next_wqe(srq);
	}

	if (nreq) {
		dma_wmb();
		/* fill srqc */
		nbl_srq_shdw_update(srq);
		/* srq ring db */
		srq_ring_db(srq);
	}

out:
	spin_unlock_irqrestore(&srq->lock, flags);

	return err;
}

static void nbl_fill_wqe_ctrl(struct nbl_wqe_ctrl_seg *ctrl,
			      struct nbl_wqe_info *info)
{
	__u8 temp;
	__u8 opcode;
	__be32 *wqe;

	opcode = nbl_opcode[info->ib_opcode];

	if (opcode != NBL_OPCODE_FAST_MR) {
		ctrl->payload_len = cpu_to_be32(info->payload_len);
		if (info->is_inv)
			ctrl->imm_inv_rkey = cpu_to_be32(info->inv_rkey);
		else if (info->is_imm)
			ctrl->imm_inv_rkey = info->imm_data;
	}

	wqe = (__be32 *)ctrl;
	nbl_32bit_write(wqe, NBL_WQE_TS, info->wqe_size);
	nbl_32bit_write(wqe, NBL_WQE_QPN, info->qpn);

	nbl_32bit_write(wqe, NBL_WQE_DS_L, info->num_sge);

	nbl_32bit_write(wqe, NBL_WQE_OPCODE, opcode);

	temp = (info->num_sge & WQE_CTRL_DS_H_MASK) >> WQE_CTRL_DS_H_SHIFT;
	nbl_32bit_write(wqe, NBL_WQE_DS_H, temp);

	nbl_32bit_write(wqe, NBL_WQE_IDX, info->wqe_idx);
	nbl_32bit_write(wqe, NBL_WQE_IDX_PHASE, !info->wqe_vld);
	nbl_32bit_write(wqe, NBL_WQE_IDX, info->wqe_idx);
	if (unlikely(info->is_umr)) {
		/*
		 * for umr qp:
		 * inline is reused as revoke figure
		 * imm    is reused as kick pble figure
		 */
		if (info->umr_opcode == NBL_UMR_OP_REVOKE) {
			nbl_32bit_write(wqe, NBL_WQE_INLINE, 1);
			nbl_32bit_write(wqe, NBL_WQE_IMM, 0);
		} else if (info->umr_opcode == NBL_UMR_OP_FLDPBL) {
			nbl_32bit_write(wqe, NBL_WQE_INLINE, 0);
			nbl_32bit_write(wqe, NBL_WQE_IMM, 1);
		} else {
			nbl_32bit_write(wqe, NBL_WQE_INLINE, 0);
			nbl_32bit_write(wqe, NBL_WQE_IMM, 0);
		}
	} else {
		/*
		 * for normal qp:
		 * imm is reused as local read
		 */
		if (unlikely(info->dst_is_local &&
					info->local_rd_no_pkt &&
					opcode == NBL_OPCODE_READ))
			nbl_32bit_write(wqe, NBL_WQE_IMM, 1);
		else
			nbl_32bit_write(wqe, NBL_WQE_IMM, info->is_imm);
		nbl_32bit_write(wqe, NBL_WQE_INLINE, info->is_inline);
	}
	nbl_32bit_write(wqe, NBL_WQE_SE, info->se);
	nbl_32bit_write(wqe, NBL_WQE_CE, info->ce);
	nbl_32bit_write(wqe, NBL_WQE_FENCE, info->fence);

	dma_wmb();
	nbl_32bit_write_bool(wqe, NBL_WQE_VLD, info->wqe_vld);
}

void nbl_fill_32Byte_rsv_vld(__u32 sge_num, __u8 *wqe, bool wqe_vld,
			     __u8 cur_size)
{
	struct nbl_rq_wqe_data_seg_v2 data = {};
	int block_seg_size = NBL_WQE_QUANTA_SIZE / NBL_WQE_DATA_SIZE;
	int nmlz_num_sge;
	int quanta_position;
	int j, extra;
	__u8 *dseg = wqe;

	/* if a 64B block just has 2 sges, the remaining 32B still need fill wqe_vld */
	/* 1st, we got normalized sge number */

	nmlz_num_sge = sge_num + block_seg_size - cur_size;
	/* 2nd, we % 4 got the position in 64B */
	quanta_position = (nmlz_num_sge % block_seg_size);
	/* 3rd, if position in 64B is not zero, do the next work */
	if (quanta_position != 0) {
		/* 4th, calc the num we need to fill valid */
		extra = block_seg_size - quanta_position;
		for (j = 0; j < extra; j++) {
			data.wqe_valid_dma_len = cpu_to_be32(
				(__u32)wqe_vld << RQ_WQE_DATA_VALID_SHIFT);

			*(__be32 *)dseg = data.wqe_valid_dma_len;
			dseg += NBL_WQE_DATA_SIZE;
		}
	}
}

void nbl_set_sge_vld(void *wqe, int num_sge, bool vld)
{
	int i;
	__u8 *sge_addr = wqe;

	for (i = 0; i < num_sge; i += 2) {
		if (vld)
			*sge_addr |= NBL_WQE_VLD_TRUE_MASK;
		else
			*sge_addr &= NBL_WQE_VLD_FALSE_MASK;
		sge_addr += NBL_WQE_SGE_VLD_SHIFT;
	}
}

static void nbl_copy_sge_to_wqe(struct nbl_wqe_data_seg_v2 *dseg,
				struct ib_sge *wr_sge, bool vld)
{
	__u32 temp;

	dseg->local_addr = cpu_to_be64(wr_sge->addr);
	dseg->lkey = cpu_to_be32(wr_sge->lkey);
	temp = FIELD_PREP(NBL_WQE_SGE_VLD, vld) |
	       FIELD_PREP(NBL_WQE_SGE_LEN, wr_sge->length);
	set_32bit_val((__be32 *)dseg, 0, temp);
}

static void nbl_process_rev_wqe(struct nbl_sc_qp *sc_qp,
				const struct ib_send_wr *wr,
				struct nbl_wqe_info *info,
				struct nbl_wqe_data_seg_v2 *dseg)
{
	int i = 0;
	int j;
	int num_sge = 0;
	int count, extra;
	int block_seg_count = NBL_WQE_QUANTA_SIZE / NBL_WQE_DATA_SIZE;
	void *wqe = dseg;

	while (info->cur_size < info->avl_size) {
		if (unlikely(!wr->sg_list[i].length)) {
			++i;
			continue;
		}
		nbl_copy_sge_to_wqe(dseg, &wr->sg_list[i], !info->wqe_vld);
		info->cur_size += sizeof(struct nbl_wqe_data_seg);
		++dseg;
		++i;
	}
	num_sge = i;
	nbl_set_sge_vld(wqe, num_sge, info->wqe_vld);

	dseg = (struct nbl_wqe_data_seg_v2 *)nbl_get_wqe(
		sc_qp->uk_qp.sq_base, &(sc_qp->sqbuf.frag_buf),
		sizeof(struct nbl_qp_block), info->next_wqe_idx, !sc_qp->sq_pm);
	wqe = dseg;
	num_sge = 0;
	if (!info->next_wqe_idx)
		sc_qp->uk_qp.swqe_polarity = !sc_qp->uk_qp.swqe_polarity;

	for (j = i; j < wr->num_sge; j++) {
		if (unlikely(!wr->sg_list[j].length))
			continue;
		nbl_copy_sge_to_wqe(dseg, &wr->sg_list[j],
				    !sc_qp->uk_qp.swqe_polarity);
		info->cur_size += sizeof(struct nbl_wqe_data_seg);
		++dseg;
		++num_sge;
	}
	nbl_set_sge_vld(wqe, num_sge, sc_qp->uk_qp.swqe_polarity);
	count = ((j - i) % block_seg_count);

	if (count != 0) {
		/* 4th, calc the num we need to fill valid */
		extra = block_seg_count - count;
		for (j = 0; j < extra; j++) {
			set_32bit_val((__be32 *)dseg, 0,
				      FIELD_PREP(NBL_WQE_SGE_VLD,
						 sc_qp->uk_qp.swqe_polarity));
			++dseg;
		}
	}
}

static void nbl_set_wqe_sge_fragment(struct nbl_sc_qp *sc_qp,
				     const struct ib_send_wr *wr,
				     struct nbl_wqe_info *info, void *wqe)
{
	int i;
	struct nbl_wqe_data_seg_v2 *dseg = wqe;

	if (info->rev_page) {
		nbl_process_rev_wqe(sc_qp, wr, info, dseg);
	} else {
		for (i = 0; i < wr->num_sge; i++) {
			if (unlikely(!wr->sg_list[i].length))
				continue;
			nbl_copy_sge_to_wqe(dseg, &wr->sg_list[i],
					    !info->wqe_vld);
			++dseg;
			info->cur_size += sizeof(struct nbl_wqe_data_seg_v2);
		}
		nbl_set_sge_vld(wqe, info->num_sge, info->wqe_vld);
		nbl_fill_32Byte_rsv_vld(wr->num_sge, (__u8 *)dseg,
					info->wqe_vld, info->cur_sge_num);
	}
}
static void nbl_set_wqe_inline_fragment(struct nbl_sc_qp *sc_qp,
					const struct ib_send_wr *wr,
					struct nbl_wqe_info *info,
					void *inline_data)
{
}

static inline __u8 nbl_get_sq_avl_size(struct nbl_uk_qp *uk_qp)
{
	__u8 avl_qunata =
		MAX_HW_SQ_MSGE_QUANTA -
		(NBL_RING_CURRENT_HEAD(uk_qp->sq_ring) % MAX_HW_SQ_MSGE_QUANTA);
	return avl_qunata;
}

static void nbl_check_wqe_rev_page(struct nbl_sc_qp *sc_qp,
				   struct nbl_wqe_info *info)
{
	__u32 avl_quanta;

	if (!sc_qp->sq_pm) {
		if (info->wqe_idx >
		    sc_qp->uk_qp.sq_ring.size - MAX_HW_SQ_MSGE_QUANTA) {
			avl_quanta = nbl_get_sq_avl_size(&sc_qp->uk_qp);
			if (info->wqe_size > avl_quanta) {
				info->rev_page = true;
				info->avl_size = avl_quanta * NBL_MIN_WQE_SIZE;
				info->next_wqe_idx = 0;
			}
		}
	} else {
		if (info->wqe_idx % NBL_MAX_WQE_PER_PAGE > NBL_REV_PAGE_TH) {
			avl_quanta = nbl_get_sq_avl_size(&sc_qp->uk_qp);
			if (info->wqe_size > avl_quanta) {
				info->rev_page = true;
				info->avl_size = avl_quanta * NBL_MIN_WQE_SIZE;
				info->next_wqe_idx =
					(info->wqe_idx + avl_quanta) %
					sc_qp->uk_qp.sq_ring.size;
			}
		}
	}
}

static int nbl_calc_wqe_size_v2(const struct ib_send_wr *wr,
				struct nbl_wqe_info *info)
{
	int i;
	__u32 data_size = 0;
	__u32 pld_len = 0;

	for (i = 0; i < wr->num_sge; i++) {
		if (wr->sg_list[i].length) {
			if (wr->sg_list[i].length >= SZ_2G)
				return -EINVAL;
			++info->num_sge;
			pld_len += wr->sg_list[i].length;
		}
	}

	if (info->is_inline) {
		data_size = pld_len + NBL_GET_INLINE_WQE_SPLIT_NUM(pld_len);
		info->num_sge = 0;

	} else {
		data_size = NBL_WQE_DATA_SIZE * info->num_sge;
	}

	info->payload_len = pld_len;
	info->real_wqe_size = data_size + info->cur_size;

	info->wqe_size =
		ALIGN(info->real_wqe_size, NBL_MIN_WQE_SIZE) / NBL_MIN_WQE_SIZE;
	return 0;
}

static __be64 *nbl_check_wqe_size_and_get_wqe(struct nbl_sc_qp *sc_qp,
					      const struct ib_send_wr *wr,
					      struct nbl_wqe_info *info)
{
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	__be64 *wqe;

	if (nbl_calc_wqe_size_v2(wr, info))
		return NULL;

	if ((info->wqe_size + sc_qp->uk_qp.sq_safe_rsv) >
	    NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring))
		return NULL;
	info->wqe_idx = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);

	if (!info->wqe_idx)
		uk_qp->swqe_polarity = !uk_qp->swqe_polarity;
	info->wqe_vld = uk_qp->swqe_polarity;
	nbl_check_wqe_rev_page(sc_qp, info);

	uk_qp->sq_wrtrk_array[info->wqe_idx].wrid = wr->wr_id;
	uk_qp->sq_wrtrk_array[info->wqe_idx].wr_len = info->payload_len;
	uk_qp->sq_wrtrk_array[info->wqe_idx].quanta = info->wqe_size;
	uk_qp->sq_wrtrk_array[info->wqe_idx].driver_ce = 0;
	uk_qp->sq_wrtrk_array[info->wqe_idx].ib_op = wr->opcode;

	wqe = nbl_get_wqe(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf),
			  sizeof(struct nbl_qp_block), info->wqe_idx,
			  !sc_qp->sq_pm);
	return wqe;
}

static void nbl_uk_process_muti_sge(struct nbl_sc_qp *sc_qp, void *wqe,
				    const struct ib_send_wr *wr,
				    struct nbl_wqe_info *info)
{
	if (info->is_inline)
		nbl_set_wqe_inline_fragment(sc_qp, wr, info, wqe);
	else
		nbl_set_wqe_sge_fragment(sc_qp, wr, info, wqe);

	NBL_SQ_RING_MOVE_HEAD_BY_COUNT(sc_qp->uk_qp.sq_ring, info->wqe_size);
}

static void nbl_fill_ud_datagram(struct nbl_qp *qp, const struct ib_send_wr *wr,
				 void *wqe, struct nbl_wqe_info *info)
{
	struct nbl_ah *ah;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	ah = to_nbl_ah(ud_wr(wr)->ah);

	nbl_32bit_write(wqe, NBL_WQE_UD_IPV4_VLD,
			ah->av.vlan_tag_ipv4_valid & 0x1);
	nbl_32bit_write(wqe, NBL_WQE_UD_VLAN_EN,
			(ah->av.vlan_tag_ipv4_valid >> NBL_AH_VLAN_EN_SHIFT) &
				0x1);
	nbl_32bit_write(wqe, NBL_WQE_UD_SRC_ADDR_IDX, ah->av.src_addr_index);
	nbl_32bit_write(wqe, NBL_WQE_UD_FLOW_LABLE, ah->av.flow_label);

	if (ud_wr(wr)->remote_qkey == IB_QP_SET_QKEY)
		nbl_32bit_write(wqe, NBL_WQE_UD_QKEY, IB_QP1_QKEY);
	else
		nbl_32bit_write(wqe, NBL_WQE_UD_QKEY, ud_wr(wr)->remote_qkey);
	nbl_32bit_write(wqe, NBL_WQE_UD_DEST_QPN, ud_wr(wr)->remote_qpn);
	nbl_32bit_write(wqe, NBL_WQE_UD_UDP_SPORT, ah->av.udp_sport);
	nbl_32bit_write(wqe, NBL_WQE_UD_VLAN_TAG, ah->av.vlan_id);
	nbl_32bit_write(wqe, NBL_WQE_UD_RSS_LAG_EN, rf->sc_dev.rss_lag_en);
	nbl_32bit_write(wqe, NBL_WQE_UD_TUNNEL_EN, rf->sc_dev.tunnel_en);
	nbl_32bit_write(wqe, NBL_WQE_UD_FWD, rf->sc_dev.fwd);
	if (ah->av.is_local && rf->sc_dev.fwd == NBL_CPU_FWD) {
		nbl_32bit_write(wqe, NBL_WQE_UD_DPORT, NBL_DEFAULT_DPORT_HOST);
		nbl_32bit_write(wqe, NBL_WQE_UD_DPORT_ID, rf->vsi_id);
	} else {
		nbl_32bit_write(wqe, NBL_WQE_UD_DPORT, rf->sc_dev.dport);
		nbl_32bit_write(wqe, NBL_WQE_UD_DPORT_ID, rf->sc_dev.dport_id);
	}
	memcpy(wqe + NBL_WQE_UD_V2_DMAC_OFFSET, ah->av.dest_mac,
	       sizeof(ah->av.dest_mac));
	nbl_32bit_write(wqe, NBL_WQE_UD_TCLASS, ah->av.tclass);
	nbl_32bit_write(wqe, NBL_WQE_UD_HOPE_LIMIT, ah->av.hop_limit);
	nbl_32bit_write(wqe, NBL_WQE_UD_PD_IDX, ah->av.pd_idx);
	memcpy(wqe + NBL_WQE_UD_V2_DIP_OFFSET, ah->av.dest_ip,
	       sizeof(ah->av.dest_ip));
	nbl_32bit_write_bool(wqe, NBL_WQE_UD_WQE_VLD, info->wqe_vld);
}

static int nbl_process_uk_ud_send(struct nbl_qp *qp,
				  const struct ib_send_wr *wr,
				  struct nbl_wqe_info *info)
{
	void *wqe;
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	info->cur_size = NBL_WQE_CTRL_SIZE + NBL_WQE_DATAGRAM_SIZE;
	info->cur_sge_num = 0;

	ctrl = wqe = nbl_check_wqe_size_and_get_wqe(sc_qp, wr, info);
	if (!wqe)
		return -EINVAL;
	wqe += sizeof(struct nbl_wqe_ctrl_seg);

	nbl_fill_ud_datagram(qp, wr, wqe, info);

	wqe += NBL_WQE_DATAGRAM_SIZE;
	nbl_uk_process_muti_sge(sc_qp, wqe, wr, info);

	info->ib_opcode = wr->opcode;
	info->qpn = sc_qp->uk_qp.qpn;
	nbl_fill_wqe_ctrl(ctrl, info);
	return 0;
}

static int nbl_set_ud_wqe(struct nbl_qp *qp, const struct ib_send_wr *wr,
			  struct nbl_wqe_info *info)
{
	int err = 0;

	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
		info->is_imm = true;
		info->imm_data = wr->ex.imm_data;
		fallthrough;
	case IB_WR_SEND:
		info->is_ud = true;
		err = nbl_process_uk_ud_send(qp, wr, info);
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

static void nbl_set_strong_fence(struct nbl_uk_qp *uk_qp,
				 struct nbl_wqe_info *info)
{
	uk_qp->next_fence = true;
	info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
	/* set ce for hw  */
	if (!info->ce) {
		uk_qp->sq_wrtrk_array[info->wqe_idx].driver_ce = true;
		info->ce = true;
	}
}

static void nbl_check_local_nofnce(struct nbl_uk_qp *uk_qp,
				   struct nbl_wqe_info *info)
{
	__u8 pre_fence = uk_qp->next_fence;

	if (uk_qp->nvme_fmr_en) {
		/* local opcode and need ce or fence, must set strong fence
		 * if not ce flag for user, driver need to set the ce
		 */
		if (info->is_local && (info->ce || info->fence)) {
			nbl_set_strong_fence(uk_qp, info);
		} else {
			uk_qp->next_fence = false;
			if (info->is_local &&
			    uk_qp->local_cnt == NBL_LOCAL_CNT_TH) {
				nbl_set_strong_fence(uk_qp, info);
				uk_qp->local_cnt = 0;
			}
			if (pre_fence && !(info->is_local))
				info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		}
	} else {
		if (info->is_local) {
			uk_qp->next_fence = true;
			info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		} else {
			uk_qp->next_fence = false;
			if (pre_fence)
				info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		}
	}
}

static int nbl_process_uk_local(struct nbl_sc_qp *sc_qp,
				const struct ib_send_wr *wr,
				struct nbl_wqe_info *info)
{
	void *wqe;
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;

	info->wqe_size = NBL_WQE_MIN_QUANTA;

	if ((info->wqe_size + sc_qp->uk_qp.sq_safe_rsv) >
	    NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring))
		return -EINVAL;
	info->wqe_idx = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);

	if (!info->wqe_idx)
		uk_qp->swqe_polarity = !uk_qp->swqe_polarity;
	info->wqe_vld = uk_qp->swqe_polarity;

	/* attention, wr only use for opcode and wr id */
	info->ib_opcode = wr->opcode;
	uk_qp->sq_wrtrk_array[info->wqe_idx].wrid = wr->wr_id;
	uk_qp->sq_wrtrk_array[info->wqe_idx].wr_len = info->payload_len;
	uk_qp->sq_wrtrk_array[info->wqe_idx].quanta = info->wqe_size;
	uk_qp->sq_wrtrk_array[info->wqe_idx].driver_ce = 0;
	uk_qp->sq_wrtrk_array[info->wqe_idx].ib_op = info->ib_opcode;

	wqe = nbl_get_wqe(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf),
			  sizeof(struct nbl_qp_block), info->wqe_idx,
			  !sc_qp->sq_pm);
	if (!wqe)
		return -EINVAL;
	ctrl = wqe;

	info->qpn = sc_qp->uk_qp.qpn;
	nbl_32bit_write_bool(wqe, NBL_WQE_LOCAL_INV_VLD, info->wqe_vld);
	nbl_check_local_nofnce(uk_qp, info);
	nbl_fill_wqe_ctrl(ctrl, info);

	NBL_SQ_RING_MOVE_HEAD_BY_COUNT(sc_qp->uk_qp.sq_ring,
				       NBL_WQE_MIN_QUANTA);
	return 0;
}

static void nbl_set_fast_mr_wqe(struct nbl_device *nbldev,
				const struct ib_send_wr *wr, void *wqe,
				struct nbl_wqe_info *info)
{
	enum nbl_page_size pg_sz = NBL_PAGE_SIZE_4K;
	u64 hw_pa;
	struct nbl_mr *mr = to_nbl_mr(reg_wr(wr)->mr);
	struct nbl_pble_alloc *palloc = &mr->pbl.pble_alloc;
	u32 leaf_sz;
	u32 mr_rights = nbl_get_mr_access(nbldev, (reg_wr(wr)->access));

	if (mr->page_sz == SZ_4K)
		pg_sz = NBL_PAGE_SIZE_4K;
	else if (mr->page_sz == SZ_2M)
		pg_sz = NBL_PAGE_SIZE_2M;
	else if (mr->page_sz == SZ_1G)
		pg_sz = NBL_PAGE_SIZE_1G;
	else if (mr->page_sz == SZ_64K)
		pg_sz = NBL_PAGE_SIZE_64K;

	leaf_sz = mr->pbl.pbl_allocated ? 1 : 0;

	nbl_32bit_write(wqe, NBL_WQE_FMR_ACCESS_RIGHT, mr_rights);
	nbl_32bit_write(wqe, NBL_WQE_FMR_LEAF_SIZE, leaf_sz);
	nbl_32bit_write(wqe, NBL_WQE_FMR_PG_SZ, pg_sz);
	nbl_32bit_write(wqe, NBL_WQE_FMR_ADDR_TYPE, NBL_ADDR_TYPE_ZERO_BASED);

	nbl_32bit_write(wqe, NBL_WQE_FMR_LEN, mr->ibmr.length);
	nbl_32bit_write(wqe, NBL_WQE_FMR_VA_L, mr->ibmr.iova);
	nbl_32bit_write(wqe, NBL_WQE_FMR_VA_H, mr->ibmr.iova >> 32);
	nbl_32bit_write(wqe, NBL_WQE_FMR_STAG, reg_wr(wr)->key);

	if (!mr->pbl.pbl_allocated) {
		nbl_pr_err("fmr_error, pbl allocated val is wrong\n");
		hw_pa = mr->pa & ~(mr->page_sz - 1);
		nbl_32bit_write(wqe, NBL_WQE_FMR_PBL_ADDR_L, hw_pa);
		nbl_32bit_write(wqe, NBL_WQE_FMR_PBL_ADDR_H, hw_pa >> 32);
	} else {
		nbl_32bit_write(wqe, NBL_WQE_FMR_PBL_IDX,
				palloc->pble_info.idx);
		/* fill nbl_wqe_fast_mr_pa_seg for DF200 and ASIC V2R1 */
		nbl_64bit_write(wqe, NBL_WQE_FMR_PA0,
			(palloc->pble_info.pa0 >> NBL_PBLE_ADDR_SHIFT));
		nbl_64bit_write(wqe, NBL_WQE_FMR_PA1,
			(palloc->pble_info.pa1 >> NBL_PBLE_ADDR_SHIFT));
	}
	nbl_32bit_write(wqe, NBL_WQE_FMR_PBL_KEY, mr->pbl_key);
	nbl_32bit_write_bool(wqe, NBL_WQE_FMR_PBL_SEG_VLD, info->wqe_vld);
}

static int nbl_process_fast_mr(struct nbl_device *nbldev,
			       struct nbl_sc_qp *sc_qp,
			       const struct ib_send_wr *wr,
			       struct nbl_wqe_info *info)
{
	void *wqe;
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;

	info->wqe_size = NBL_WQE_MIN_QUANTA;

	if ((info->wqe_size + uk_qp->sq_safe_rsv) >
	    NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring))
		return -EINVAL;

	info->wqe_idx = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);

	if (!info->wqe_idx)
		uk_qp->swqe_polarity = !uk_qp->swqe_polarity;
	info->wqe_vld = uk_qp->swqe_polarity;

	uk_qp->sq_wrtrk_array[info->wqe_idx].wrid = wr->wr_id;
	uk_qp->sq_wrtrk_array[info->wqe_idx].wr_len = info->payload_len;
	uk_qp->sq_wrtrk_array[info->wqe_idx].quanta = info->wqe_size;
	uk_qp->sq_wrtrk_array[info->wqe_idx].driver_ce = 0;
	uk_qp->sq_wrtrk_array[info->wqe_idx].ib_op = wr->opcode;

	wqe = nbl_get_wqe(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf),
			  sizeof(struct nbl_qp_block), info->wqe_idx,
			  !sc_qp->sq_pm);
	if (!wqe)
		return -EINVAL;
	ctrl = wqe;
	info->ib_opcode = wr->opcode;
	info->qpn = sc_qp->uk_qp.qpn;
	nbl_set_fast_mr_wqe(nbldev, wr, wqe, info);
	nbl_check_local_nofnce(uk_qp, info);
	nbl_fill_wqe_ctrl(ctrl, info);

	NBL_SQ_RING_MOVE_HEAD_BY_COUNT(sc_qp->uk_qp.sq_ring,
				       NBL_WQE_MIN_QUANTA);
	return 0;
}

static int nbl_process_uk_rw(struct nbl_sc_qp *sc_qp,
			     const struct ib_send_wr *wr,
			     struct nbl_wqe_info *info)
{
	void *wqe;
	struct nbl_wqe_ctrl_seg *ctrl;

	info->cur_size = NBL_WQE_CTRL_SIZE + NBL_WQE_RADDR_SIZE;
	info->cur_sge_num = NBL_WQE_FIRST_QUANTA_SGE_NUM;

	ctrl = wqe = nbl_check_wqe_size_and_get_wqe(sc_qp, wr, info);
	if (!wqe)
		return -EINVAL;
	wqe += sizeof(struct nbl_wqe_ctrl_seg);
	nbl_fill_raddr_seg_info_v2((struct nbl_wqe_raddr_seg_v2 *)wqe, wr,
				   info->payload_len);

	wqe += sizeof(struct nbl_wqe_raddr_seg_v2);
	nbl_uk_process_muti_sge(sc_qp, wqe, wr, info);

	info->ib_opcode = wr->opcode;
	info->qpn = sc_qp->uk_qp.qpn;

	nbl_check_local_nofnce(&sc_qp->uk_qp, info);
	nbl_fill_wqe_ctrl(ctrl, info);
	return 0;
}

static int nbl_process_uk_rc_send(struct nbl_sc_qp *sc_qp,
				  const struct ib_send_wr *wr,
				  struct nbl_wqe_info *info)
{
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	void *wqe;
	struct nbl_wqe_ctrl_seg *ctrl;

	info->cur_size = NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE;
	info->cur_sge_num = NBL_WQE_FIRST_QUANTA_SGE_NUM;

	ctrl = wqe = nbl_check_wqe_size_and_get_wqe(sc_qp, wr, info);
	if (!wqe)
		return -EINVAL;

	wqe += sizeof(struct nbl_wqe_ctrl_seg) + NBL_WQE_RSV_SIZE;
	nbl_uk_process_muti_sge(sc_qp, wqe, wr, info);

	info->ib_opcode = wr->opcode;
	info->qpn = uk_qp->qpn;
	nbl_check_local_nofnce(uk_qp, info);
	nbl_fill_wqe_ctrl(ctrl, info);
	return 0;
}

static int nbl_set_rc_wqe(struct nbl_device *nbldev, struct nbl_sc_qp *sc_qp,
			  const struct ib_send_wr *wr,
			  struct nbl_wqe_info *info)
{
	int ret = 0;

	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
		info->is_imm = true;
		info->imm_data = wr->ex.imm_data;
		fallthrough;
	case IB_WR_SEND_WITH_INV:
		info->is_inv = true;
		info->inv_rkey = wr->ex.invalidate_rkey;
		fallthrough;
	case IB_WR_SEND:
		ret = nbl_process_uk_rc_send(sc_qp, wr, info);
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		info->is_imm = true;
		info->imm_data = wr->ex.imm_data;
		fallthrough;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_WRITE:
		ret = nbl_process_uk_rw(sc_qp, wr, info);
		break;
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		/*TODO*/
		break;
	case IB_WR_REG_MR:
		info->is_local = true;
		sc_qp->uk_qp.local_cnt++;
		ret = nbl_process_fast_mr(nbldev, sc_qp, wr, info);
		break;
	case IB_WR_LOCAL_INV:
		info->is_local = true;
		sc_qp->uk_qp.local_cnt++;
		info->is_inv = true;
		info->inv_rkey = wr->ex.invalidate_rkey;
		ret = nbl_process_uk_local(sc_qp, wr, info);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static inline void nbl_fill_local_pkt(struct nbl_sc_dev *sc_dev,
	struct nbl_qp *qp, struct nbl_wqe_info *info)
{
	info->dst_is_local = qp->dst_is_local;
	info->local_rd_no_pkt = sc_dev->local_rd_no_pkt;
}

int _nbl_ib_post_send_v2(struct ib_qp *ib_qp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	struct nbl_wqe_info info;
	struct nbl_qp *qp;
	struct nbl_sc_qp *sc_qp;
	struct nbl_uk_qp *uk_qp;
	bool need_delay_work = false;
	struct nbl_hw_attrs *attrs;
	struct nbl_sc_dev *sc_dev;
	int err = 0;
	int nreq = 0;
	unsigned long flags;

	qp = container_of(ib_qp, struct nbl_qp, ibqp);
	sc_qp = &qp->sc_qp;
	uk_qp = &qp->sc_qp.uk_qp;
	attrs = &(qp->nbldev->rf->sc_dev.hw_attrs);
	sc_dev = &(qp->nbldev->rf->sc_dev);

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->qp_state == NBL_QP_STATE_ERR) {
		if (qp->scq) {
			err = nbl_qp_generate_sq_soft_wc(wr, qp);
			if (err) {
				*bad_wr = wr;
				err = -EINVAL;
			} else {
				need_delay_work = true;
			}
		} else {
			*bad_wr = wr;
			err = -EINVAL;
		}
		goto out;
	}

	while (wr) {
		memset(&info, 0, sizeof(info));
		if (wr->num_sge > attrs->uk_attrs.max_hw_wq_sges) {
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}

		if (wr->send_flags & IB_SEND_FENCE)
			info.fence = NBL_WQE_CTRL_FENCE;
		if (wr->send_flags & IB_SEND_SIGNALED)
			info.ce = true;
		if (wr->send_flags & IB_SEND_SOLICITED)
			info.se = true;
		if (wr->send_flags & IB_SEND_INLINE)
			info.is_inline = true;

		switch (ib_qp->qp_type) {
		case IB_QPT_RC:
		case NBL_IB_QPT_SRP:
			nbl_fill_local_pkt(sc_dev, qp, &info);
			err = nbl_set_rc_wqe(qp->nbldev, sc_qp, wr, &info);
			break;
		case IB_QPT_UD:
		case IB_QPT_GSI:
			err = nbl_set_ud_wqe(qp, wr, &info);
			break;
		default:
			err = -EINVAL;
			break;
		}
		if (err) {
			*bad_wr = wr;
			goto out;
		}
		nreq++;
		wr = wr->next;
	}

out:
	if (nreq) {
		dma_wmb();
		nbl_post_sq_db(uk_qp);
	}

	spin_unlock_irqrestore(&qp->lock, flags);
	if (unlikely(need_delay_work))
		nbl_sched_qp_flush_work(qp);

	return err;
}

int _nbl_ib_post_recv_v2(struct ib_qp *ib_qp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	struct nbl_qp *qp;
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;
	bool need_delay_work = false;
	void *wqe;
	__u8 *ctrl;
	unsigned long flags;
	int err = 0;
	unsigned int wqe_idx;
	__u16 write_word = 0;
	bool sw_pi_phase;
	struct nbl_rq_ctrl_param param = {};

	qp = container_of(ib_qp, struct nbl_qp, ibqp);
	uk_qp = &qp->sc_qp.uk_qp;
	sc_qp = &qp->sc_qp;

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->qp_state == NBL_QP_STATE_ERR) {
		if (qp->rcq) {
			err = nbl_qp_generate_rq_soft_wc(wr, qp);
			if (err) {
				err = -EINVAL;
				*bad_wr = wr;
			} else {
				need_delay_work = true;
			}
		} else {
			err = -EINVAL;
			*bad_wr = wr;
		}
		goto out;
	}

	while (wr) {
		if (wr->num_sge > uk_qp->max_recv_sge) {
			*bad_wr = wr;
			err = -EINVAL;
			goto out;
		}

		ctrl = wqe = nbl_get_next_recv_wqe(qp, wr, &wqe_idx);
		if (!wqe) {
			*bad_wr = wr;
			err = -EINVAL;
			goto out;
		}
		memset(&param, 0, sizeof(param));
		/* offset of ctrl seg size */
		wqe += sizeof(struct nbl_rq_wqe_ctrl_seg);
		/* offset of rsv seg size */
		wqe += NBL_WQE_RSV_SIZE;

		param.wqe_vld = uk_qp->rwqe_polarity;
		param.wqe_idx = wqe_idx;
		param.qpn_srqn = uk_qp->qpn;
		param.wqe_quanta = uk_qp->rqe_mult;

		err = fill_data_seg(wr, (__u8 *)wqe, &param);
		if (err) {
			*bad_wr = wr;
			goto out;
		}

		err = fill_ctrl_seg(ctrl, &param);
		if (err) {
			*bad_wr = wr;
			goto out;
		}

		print_hex_dump_debug("RQ WQE ", DUMP_PREFIX_OFFSET, 16, 1, (u64 *)ctrl,
				     uk_qp->rqe_mult * 64, false);
		wr = wr->next;
	}

	dma_wmb();
	sw_pi_phase = uk_qp->rwqe_polarity;
	if (uk_qp->rq_ring.head != 0)
		sw_pi_phase = (sw_pi_phase ? false : true);

	write_word = (__u16)(FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_RQ_PI,
					uk_qp->rq_ring.head) |
			     FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_RQ_PI_PHASE,
					sw_pi_phase));
	set_16bit_val((__be16 *)sc_qp->qp_shadow.va, 28, write_word);

	nbl_post_rq_db_v2(uk_qp, sw_pi_phase);
out:
	spin_unlock_irqrestore(&qp->lock, flags);
	if (unlikely(need_delay_work))
		nbl_sched_qp_flush_work(qp);

	return err;
}

int nbl_umr_post_send(struct ib_qp *ib_qp, struct ib_cqe *cqe,
	struct umr_wr *umrwr)
{
	struct ib_send_wr ibwr;
	struct nbl_wqe_info info;
	struct nbl_qp *qp;
	struct nbl_sc_qp *sc_qp;
	struct nbl_uk_qp *uk_qp;
	struct nbl_hw_attrs *attrs;
	struct nbl_sc_dev *sc_dev;
	int err = 0;
	union {
		struct ib_cqe *ib_cqe;
		u64 wr_id;
	} id;
	unsigned long flags;

	qp = container_of(ib_qp, struct nbl_qp, ibqp);
	sc_qp = &qp->sc_qp;
	uk_qp = &qp->sc_qp.uk_qp;
	attrs = &(qp->nbldev->rf->sc_dev.hw_attrs);
	sc_dev = &(qp->nbldev->rf->sc_dev);

	spin_lock_irqsave(&qp->lock, flags);

	sc_qp->uk_qp.local_cnt++;
	id.ib_cqe = cqe;

	memset(&ibwr, 0, sizeof(ibwr));
	memset(&info, 0, sizeof(info));
	info.fence = NBL_WQE_CTRL_FENCE;
	info.ce = true;
	info.is_local = true;
	info.is_inv = true;
	info.inv_rkey = umrwr->mkey;
	info.is_umr = true;
	info.umr_opcode = umrwr->opcode;
	info.umr_wr_id = id.wr_id;
	ibwr.wr_id = info.umr_wr_id;
	ibwr.opcode = IB_WR_LOCAL_INV;
	err = nbl_process_uk_local(sc_qp, &ibwr, &info);
	if (!err) {
		dma_wmb();
		nbl_post_sq_db(uk_qp);
	}

	spin_unlock_irqrestore(&qp->lock, flags);

	return err;
}
