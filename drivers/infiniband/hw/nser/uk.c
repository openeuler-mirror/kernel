// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2022 WangXun Corporation */
#include "osdep.h"
#include "defs.h"
#include "user.h"
#include "nser.h"

/**
 * nser_set_fragment - set fragment in wqe
 * @wqe: wqe for setting fragment
 * @offset: offset value
 * @sge: sge length and stag
 * @valid: The wqe valid
 */
static void nser_set_fragment(__le64 *wqe, u32 offset, struct nser_sge *sge,
			       u8 valid)
{
	if (sge) {
		set_64bit_val(wqe, offset,
			      FIELD_PREP(NSERQPSQ_FRAG_TO, sge->tag_off));
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(NSERQPSQ_VALID, valid) |
			      FIELD_PREP(NSERQPSQ_FRAG_LEN, sge->len) |
			      FIELD_PREP(NSERQPSQ_FRAG_STAG, sge->stag));
	} else {
		set_64bit_val(wqe, offset, 0);
		set_64bit_val(wqe, offset + 8,
			      FIELD_PREP(NSERQPSQ_VALID, valid));
	}
}

/**
 * nser_nop_1 - insert a NOP wqe
 * @qp: hw qp ptr
 */
static int nser_nop_1(struct nser_qp_uk *qp)
{
	u64 hdr;
	__le64 *wqe;
	u32 wqe_idx;

	if (!qp->sq_ring.head)
		return -EINVAL;

	wqe_idx = NSER_RING_CURRENT_HEAD(qp->sq_ring);
	wqe = qp->sq_base[wqe_idx].elem;

	qp->sq_wrtrk_array[wqe_idx].quanta = NSER_QP_WQE_MIN_QUANTA;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 8, 0);
	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(NSERQPSQ_OPCODE, NSERQP_OP_NOP) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, false) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	/* make sure WQE is written before valid bit is set */
	dma_wmb();

	set_64bit_val(wqe, 24, hdr);

	return 0;
}

/**
 * nser_clr_wqes - clear next 128 sq entries
 * @qp: hw qp ptr
 * @qp_wqe_idx: wqe_idx
 */
void nser_clr_wqes(struct nser_qp_uk *qp, u32 qp_wqe_idx)
{
	__le64 *wqe;
	u32 wqe_idx;

	if (!(qp_wqe_idx & 0x7F)) {
		wqe_idx = (qp_wqe_idx + 128) % qp->sq_ring.size;
		wqe = qp->sq_base[wqe_idx].elem;
		if (wqe_idx)
			memset(wqe, qp->swqe_polarity ? 0 : 0xFF, 0x1000);
		else
			memset(wqe, qp->swqe_polarity ? 0xFF : 0, 0x1000);
	}
}

static void nser_uk_qp_fill_rqe_idx_in_shdw(struct nser_qp_uk *qp)
{
	u32 sw_rq_head;
	u64 temp;

	wmb(); /* make sure RQ WQE is written before fill shadow area */

	sw_rq_head = NSER_RING_CURRENT_HEAD(qp->rq_ring);
	temp = FIELD_PREP(NSER_QP_DBSA_SW_RQ_HEAD, sw_rq_head * qp->rqe_stride);
	set_64bit_val(qp->shadow_area, 64, temp);
}

static void nser_uk_qp_fill_sqe_idx_in_shdw(struct nser_qp_uk *qp)
{
	u32 sw_sq_head;
	u64 temp;

	sw_sq_head = NSER_RING_CURRENT_HEAD(qp->sq_ring);
	temp = FIELD_PREP(NSER_QP_DBSA_SW_RQ_HEAD, sw_sq_head);
	temp |= FIELD_PREP(NSER_QP_DBSA_POLARITY_BIT, qp->swqe_polarity);
	set_64bit_val(qp->shadow_area, 56, temp);
	wmb(); /* make sure hadow area is written before fill SQ WQE */
}

/**
 * nser_uk_qp_post_wr - ring doorbell
 * @qp: hw qp ptr
 */
void nser_uk_qp_post_wr(struct nser_qp_uk *qp)
{
	/* valid bit is written and loads completed before reading shadow */
	mb();
	//ring doorbell per post wr direct.
	writel(FIELD_PREP(NSER_WQE_ALLOCE_DB_QP_ID, qp->qp_id) |
		   FIELD_PREP(NSER_WQE_ALLOCE_DB_QSET, qp->qs_handle),
		   qp->wqe_alloc_db);
}

/**
 * nser_qp_get_next_send_wqe - pad with NOP if needed, return where next WR should go
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 * @quanta: (in/out) ptr to size of WR in quanta. Modified in case pad is needed
 * @total_size: size of WR in bytes
 * @info: info on WR
 */
__le64 *nser_qp_get_next_send_wqe(struct nser_qp_uk *qp, u32 *wqe_idx,
				   u16 *quanta, u32 total_size,
				   struct nser_post_sq_info *info)
{
	__le64 *wqe;
	u16 wqe_quanta = *quanta;
	u16 avail_quanta;
	u16 i;

	avail_quanta = qp->uk_attrs->max_hw_sq_chunk -
		       (NSER_RING_CURRENT_HEAD(qp->sq_ring) %
		       qp->uk_attrs->max_hw_sq_chunk);

	if (*quanta <= avail_quanta) {
		/* WR fits in current chunk */
		if (*quanta > NSER_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;
	} else {
		/* Need to pad with NOP */
		if (*quanta + avail_quanta >
			NSER_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;

		for (i = 0; i < avail_quanta; i++) {
			nser_nop_1(qp);
			NSER_RING_MOVE_HEAD_NOCHECK(qp->sq_ring);
		}
	}

	*wqe_idx = NSER_RING_CURRENT_HEAD(qp->sq_ring);
	if (!*wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;

	NSER_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, *quanta);

	nser_clr_wqes(qp, *wqe_idx);

	wqe = qp->sq_base[*wqe_idx].elem;
	qp->sq_wrtrk_array[*wqe_idx].wrid = info->wr_id;
	qp->sq_wrtrk_array[*wqe_idx].wr_len = total_size;
	qp->sq_wrtrk_array[*wqe_idx].quanta = wqe_quanta;

	return wqe;
}

/**
 * nser_qp_get_next_recv_wqe - get next qp's rcv wqe
 * @qp: hw qp ptr
 * @wqe_idx: return wqe index
 */
__le64 *nser_qp_get_next_recv_wqe(struct nser_qp_uk *qp, u32 *wqe_idx)
{
	__le64 *wqe;
	int ret_code;

	if (NSER_RING_FULL_ERR(qp->rq_ring))
		return NULL;

	NSER_ATOMIC_RING_MOVE_HEAD(qp->rq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		qp->rwqe_polarity = !qp->rwqe_polarity;
	/* rq_wqe_size_multiplier is no of 32 byte quanta in one rq wqe */
	wqe = qp->rq_base[*wqe_idx * qp->rq_wqe_size_multiplier].elem;

	return wqe;
}

/**
 * nser_uk_rdma_write - rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_rdma_write(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
			bool post_sq)
{
	u64 hdr;
	__le64 *wqe;
	struct nser_rdma_write *op_info;
	u32 i, wqe_idx;
	u32 total_size = 0, byte_off;
	int ret_code;
	u32 frag_cnt, addl_frag_cnt;
	bool read_fence = false;
	u16 quanta;

	op_info = &info->op.rdma_write;
	if (op_info->num_lo_sges > qp->max_sq_frag_cnt)
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].len;

	read_fence |= info->read_fence;

	if (info->imm_data_valid)
		frag_cnt = op_info->num_lo_sges + 1;
	else
		frag_cnt = op_info->num_lo_sges;
	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;
	ret_code = nser_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSERQPSQ_FRAG_TO, op_info->rem_addr.tag_off));

	if (info->imm_data_valid) {
		set_64bit_val(wqe, 0,
			      FIELD_PREP(NSERQPSQ_IMMDATA, info->imm_data));
		i = 0;
	} else {
		qp->wqe_ops.iw_set_fragment(wqe, 0,
					    op_info->lo_sg_list,
					    qp->swqe_polarity);
		i = 1;
	}

	for (byte_off = 32; i < op_info->num_lo_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(frag_cnt & 0x01) &&
	    frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		++addl_frag_cnt;
	}

	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, op_info->rem_addr.stag) |
	      FIELD_PREP(NSERQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(NSERQPSQ_IMMDATAFLAG, info->imm_data_valid) |
	      FIELD_PREP(NSERQPSQ_REPORTRTT, info->report_rtt) |
	      FIELD_PREP(NSERQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(NSERQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

int nser_uk_atomic_write(struct nser_qp_uk *qp,
			  struct nser_post_sq_info *info, bool post_sq)
{
	struct nser_atomic_write *op_info;
	u32 total_size = 0;
	u32 wqe_idx;
	u16 quanta = NSER_QP_WQE_MIN_QUANTA;
	__le64 *wqe;
	u64 hdr;

	op_info = &info->op.atomic_write;
	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	if (op_info->is_inline_data)
		set_64bit_val(wqe, 8, op_info->inline_data);
	else {
		set_64bit_val(wqe, 8,
		      FIELD_PREP(NSERQPSQ_LOCSTAG, op_info->stag) |
		      FIELD_PREP(NSERQPSQ_FRAG_LEN, NSERQP_ATOMIC_WRITE_FRAG_LEN) |
		      FIELD_PREP(NSERQPSQ_FRAG_VALID, qp->swqe_polarity));
	}
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(NSERQPSQ_INLINEDATAFLAG, op_info->is_inline_data) |
	      FIELD_PREP(NSERQPSQ_OPCODE, NSERQP_OP_ATOMIC_WRITE) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_atomic_fetch_add - atomic fetch and add operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_atomic_fetch_add(struct nser_qp_uk *qp,
			      struct nser_post_sq_info *info, bool post_sq)
{
	struct nser_atomic_fetch_add *op_info;
	u32 total_size = 0;
	u16 quanta = 2;
	u32 wqe_idx;
	__le64 *wqe;
	u64 hdr;

	op_info = &info->op.atomic_fetch_add;
	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(NSERQPSQ_LOCSTAG, op_info->stag));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(NSERQPSQ_ADDFRAGCNT, 1) |
	      FIELD_PREP(NSERQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(NSERQPSQ_OPCODE, NSERQP_OP_ATOMIC_FETCH_ADD) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	set_64bit_val(wqe, 32, op_info->fetch_add_data_bytes);
	set_64bit_val(wqe, 40, 0);
	set_64bit_val(wqe, 48, 0);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity));

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_atomic_compare_swap - atomic compare and swap operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_atomic_compare_swap(struct nser_qp_uk *qp,
				 struct nser_post_sq_info *info, bool post_sq)
{
	struct nser_atomic_compare_swap *op_info;
	u32 total_size = 0;
	u16 quanta = 2;
	u32 wqe_idx;
	__le64 *wqe;
	u64 hdr;

	op_info = &info->op.atomic_compare_swap;
	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	set_64bit_val(wqe, 0, op_info->tagged_offset);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(NSERQPSQ_LOCSTAG, op_info->stag));
	set_64bit_val(wqe, 16, op_info->remote_tagged_offset);

	hdr = FIELD_PREP(NSERQPSQ_ADDFRAGCNT, 1) |
	      FIELD_PREP(NSERQPSQ_REMSTAG, op_info->remote_stag) |
	      FIELD_PREP(NSERQPSQ_OPCODE, NSERQP_OP_ATOMIC_COMPARE_SWAP_ADD) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	set_64bit_val(wqe, 32, op_info->swap_data_bytes);
	set_64bit_val(wqe, 40, op_info->compare_data_bytes);
	set_64bit_val(wqe, 48, 0);
	set_64bit_val(wqe, 56,
		      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity));

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_rdma_read - rdma read command
 * @qp: hw qp ptr
 * @info: post sq information
 * @inv_stag: flag for inv_stag
 * @post_sq: flag to post sq
 */
int nser_uk_rdma_read(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		       bool inv_stag, bool post_sq)
{
	struct nser_rdma_read *op_info;
	int ret_code;
	u32 i, byte_off, total_size = 0;
	bool local_fence = false;
	bool ord_fence = false;
	u32 addl_frag_cnt;
	__le64 *wqe;
	u32 wqe_idx;
	u16 quanta;
	u64 hdr;

	op_info = &info->op.rdma_read;
	if (qp->max_sq_frag_cnt < op_info->num_lo_sges)
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].len;

	ret_code = nser_fragcnt_to_quanta_sq(op_info->num_lo_sges, &quanta);
	if (ret_code)
		return ret_code;

	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					 info);
	if (!wqe)
		return -ENOMEM;

	if (qp->rd_fence_rate && (qp->ord_cnt++ == qp->rd_fence_rate)) {
		ord_fence = true;
		qp->ord_cnt = 0;
	}

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	addl_frag_cnt = op_info->num_lo_sges > 1 ?
			(op_info->num_lo_sges - 1) : 0;
	local_fence |= info->local_fence;

	qp->wqe_ops.iw_set_fragment(wqe, 0, op_info->lo_sg_list,
				    qp->swqe_polarity);
	for (i = 1, byte_off = 32; i < op_info->num_lo_sges; ++i) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off,
					    &op_info->lo_sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(op_info->num_lo_sges & 0x01) && op_info->num_lo_sges) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		++addl_frag_cnt;
	}
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSERQPSQ_FRAG_TO, op_info->rem_addr.tag_off));
	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, op_info->rem_addr.stag) |
	      FIELD_PREP(NSERQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(NSERQPSQ_OPCODE,
			 (inv_stag ? NSERQP_OP_RDMA_READ_LOC_INV : NSERQP_OP_RDMA_READ)) |
	      FIELD_PREP(NSERQPSQ_READFENCE,
			 info->read_fence || ord_fence ? 1 : 0) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_send - rdma send command
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_send(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		  bool post_sq)
{
	__le64 *wqe;
	struct nser_post_send *op_info;
	u64 hdr;
	u32 i, wqe_idx, total_size = 0, byte_off;
	int ret_code;
	u32 frag_cnt, addl_frag_cnt;
	bool read_fence = false;
	u16 quanta;

	op_info = &info->op.send;
	if (qp->max_sq_frag_cnt < op_info->num_sges)
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].len;

	if (info->imm_data_valid)
		frag_cnt = op_info->num_sges + 1;
	else
		frag_cnt = op_info->num_sges;
	ret_code = nser_fragcnt_to_quanta_sq(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					 info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	read_fence |= info->read_fence;
	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;
	if (info->imm_data_valid) {
		set_64bit_val(wqe, 0,
			      FIELD_PREP(NSERQPSQ_IMMDATA, info->imm_data));
		i = 0;
	} else {
		qp->wqe_ops.iw_set_fragment(wqe, 0,
					    frag_cnt ? op_info->sg_list : NULL,
					    qp->swqe_polarity);
		i = 1;
	}

	for (byte_off = 32; i < op_info->num_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, &op_info->sg_list[i],
					    qp->swqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(frag_cnt & 0x01) &&
	    frag_cnt) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->swqe_polarity);
		++addl_frag_cnt;
	}

	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSERQPSQ_DESTQKEY, op_info->qkey) |
		      FIELD_PREP(NSERQPSQ_DESTQPN, op_info->dest_qp));
	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, info->stag_to_inv) |
	      FIELD_PREP(NSERQPSQ_AHID, op_info->ah_id) |
	      FIELD_PREP(NSERQPSQ_IMMDATAFLAG,
			 (info->imm_data_valid ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(NSERQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(NSERQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_UDPHEADER, info->udp_hdr) |
	      FIELD_PREP(NSERQPSQ_L4LEN, info->l4len) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_set_mw_bind_wqe - set mw bind in wqe
 * @wqe: wqe for setting mw bind
 * @op_info: info for setting wqe values
 */
static void nser_set_mw_bind_wqe(__le64 *wqe,
				  struct nser_bind_window *op_info)
{
	set_64bit_val(wqe, 0, (uintptr_t)op_info->va);
	set_64bit_val(wqe, 8,
		      FIELD_PREP(NSERQPSQ_PARENTMRSTAG, op_info->mr_stag) |
		      FIELD_PREP(NSERQPSQ_MWSTAG, op_info->mw_stag));
	set_64bit_val(wqe, 16, op_info->bind_len);
}

/**
 * nser_copy_inline_data - Copy inline data to wqe
 * @wqe: pointer to wqe
 * @sge_list: table of pointers to inline data
 * @num_sges: number of SGE's
 * @polarity: polarity of wqe valid bit
 */
static void nser_copy_inline_data(u8 *wqe, struct nser_sge *sge_list, u32 num_sges,
				   u8 polarity)
{
	u8 inline_valid = polarity << NSER_INLINE_VALID_S;
	u32 quanta_bytes_remaining = 8;
	u32 i;
	bool first_quanta = true;

	wqe += 8;

	for (i = 0; i < num_sges; i++) {
		u8 *cur_sge = (u8 *)(uintptr_t)sge_list[i].tag_off;
		u32 sge_len = sge_list[i].len;

		while (sge_len) {
			u32 bytes_copied;

			bytes_copied = min(sge_len, quanta_bytes_remaining);
			memcpy(wqe, cur_sge, bytes_copied);
			wqe += bytes_copied;
			cur_sge += bytes_copied;
			quanta_bytes_remaining -= bytes_copied;
			sge_len -= bytes_copied;

			if (!quanta_bytes_remaining) {
				quanta_bytes_remaining = 31;

				/* Remaining inline bytes reside after the hdr */
				if (first_quanta) {
					first_quanta = false;
					wqe += 16;
				} else {
					*wqe = inline_valid;
					wqe++;
				}
			}
		}
	}
	if (!first_quanta && quanta_bytes_remaining < 31)
		*(wqe + quanta_bytes_remaining) = inline_valid;
}

/**
 * nser_inline_data_size_to_quanta - based on inline data, quanta
 * @data_size: data size for inline
 *
 * Gets the quanta based on inline and immediate data.
 */
static u16 nser_inline_data_size_to_quanta(u32 data_size)
{
	if (data_size <= 8)
		return NSER_QP_WQE_MIN_QUANTA;
	else if (data_size <= 39)
		return 2;
	else if (data_size <= 70)
		return 3;
	else if (data_size <= 101)
		return 4;
	else if (data_size <= 132)
		return 5;
	else if (data_size <= 163)
		return 6;
	else if (data_size <= 194)
		return 7;
	else
		return 8;
}

/**
 * nser_uk_inline_rdma_write - inline rdma write operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_inline_rdma_write(struct nser_qp_uk *qp,
			       struct nser_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct nser_rdma_write *op_info;
	u64 hdr = 0;
	u32 wqe_idx;
	bool read_fence = false;
	u16 quanta;
	u32 i, total_size = 0;

	op_info = &info->op.rdma_write;

	if (unlikely(qp->max_sq_frag_cnt < op_info->num_lo_sges))
		return -EINVAL;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].len;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(total_size);
	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					 info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	read_fence |= info->read_fence;
	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSERQPSQ_FRAG_TO, op_info->rem_addr.tag_off));

	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, op_info->rem_addr.stag) |
	      FIELD_PREP(NSERQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(NSERQPSQ_INLINEDATALEN, total_size) |
	      FIELD_PREP(NSERQPSQ_REPORTRTT, info->report_rtt ? 1 : 0) |
	      FIELD_PREP(NSERQPSQ_INLINEDATAFLAG, 1) |
	      FIELD_PREP(NSERQPSQ_IMMDATAFLAG, info->imm_data_valid ? 1 : 0) |
	      FIELD_PREP(NSERQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	if (info->imm_data_valid)
		set_64bit_val(wqe, 0,
			      FIELD_PREP(NSERQPSQ_IMMDATA, info->imm_data));

	qp->wqe_ops.iw_copy_inline_data((u8 *)wqe, op_info->lo_sg_list,
					op_info->num_lo_sges, qp->swqe_polarity);
	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_inline_send - inline send operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_inline_send(struct nser_qp_uk *qp,
			 struct nser_post_sq_info *info, bool post_sq)
{
	__le64 *wqe;
	struct nser_post_send *op_info;
	u64 hdr;
	u32 wqe_idx;
	bool read_fence = false;
	u16 quanta;
	u32 i, total_size = 0;

	op_info = &info->op.send;

	if (unlikely(qp->max_sq_frag_cnt < op_info->num_sges))
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].len;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = qp->wqe_ops.iw_inline_data_size_to_quanta(total_size);
	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					 info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	set_64bit_val(wqe, 16,
		      FIELD_PREP(NSERQPSQ_DESTQKEY, op_info->qkey) |
		      FIELD_PREP(NSERQPSQ_DESTQPN, op_info->dest_qp));

	read_fence |= info->read_fence;
	hdr = FIELD_PREP(NSERQPSQ_REMSTAG, info->stag_to_inv) |
	      FIELD_PREP(NSERQPSQ_AHID, op_info->ah_id) |
	      FIELD_PREP(NSERQPSQ_OPCODE, info->op_type) |
	      FIELD_PREP(NSERQPSQ_INLINEDATALEN, total_size) |
	      FIELD_PREP(NSERQPSQ_IMMDATAFLAG,
			 (info->imm_data_valid ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_REPORTRTT, (info->report_rtt ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_INLINEDATAFLAG, 1) |
	      FIELD_PREP(NSERQPSQ_READFENCE, read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, info->local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_UDPHEADER, info->udp_hdr) |
	      FIELD_PREP(NSERQPSQ_L4LEN, info->l4len) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	if (info->imm_data_valid)
		set_64bit_val(wqe, 0,
			      FIELD_PREP(NSERQPSQ_IMMDATA, info->imm_data));
	qp->wqe_ops.iw_copy_inline_data((u8 *)wqe, op_info->sg_list,
					op_info->num_sges, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_stag_local_invalidate - stag invalidate operation
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_stag_local_invalidate(struct nser_qp_uk *qp,
				   struct nser_post_sq_info *info,
				   bool post_sq)
{
	__le64 *wqe;
	struct nser_inv_local_stag *op_info;
	u64 hdr;
	u32 wqe_idx;
	bool local_fence = false;
	struct nser_sge sge = {};
	u16 quanta = NSER_QP_WQE_MIN_QUANTA;

	op_info = &info->op.inv_local_stag;
	local_fence = info->local_fence;

	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta,
					 0, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	sge.stag = op_info->target_stag;
	qp->wqe_ops.iw_set_fragment(wqe, 0, &sge, 0);

	set_64bit_val(wqe, 16, 0);

	hdr = FIELD_PREP(NSERQPSQ_OPCODE, NSER_OP_TYPE_INV_STAG) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);
	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_mw_bind - bind Memory Window
 * @qp: hw qp ptr
 * @info: post sq information
 * @post_sq: flag to post sq
 */
int nser_uk_mw_bind(struct nser_qp_uk *qp, struct nser_post_sq_info *info,
		     bool post_sq)
{
	__le64 *wqe;
	struct nser_bind_window *op_info;
	u64 hdr;
	u32 wqe_idx;
	bool local_fence;
	u16 quanta = NSER_QP_WQE_MIN_QUANTA;

	op_info = &info->op.bind_window;
	local_fence = info->local_fence;

	wqe = nser_qp_get_next_send_wqe(qp, &wqe_idx, &quanta,
					 0, info);
	if (!wqe)
		return -ENOMEM;

	nser_uk_qp_fill_sqe_idx_in_shdw(qp);

	qp->wqe_ops.iw_set_mw_bind_wqe(wqe, op_info);

	hdr = FIELD_PREP(NSERQPSQ_OPCODE, NSER_OP_TYPE_BIND_MW) |
	      FIELD_PREP(NSERQPSQ_STAGRIGHTS,
			 ((op_info->ena_reads << 2) | (op_info->ena_writes << 3))) |
	      FIELD_PREP(NSERQPSQ_VABASEDTO,
			 (op_info->addressing_type == NSER_ADDR_TYPE_VA_BASED ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_MEMWINDOWTYPE,
			 (op_info->mem_window_type_1 ? 1 : 0)) |
	      FIELD_PREP(NSERQPSQ_READFENCE, info->read_fence) |
	      FIELD_PREP(NSERQPSQ_LOCALFENCE, local_fence) |
	      FIELD_PREP(NSERQPSQ_SIGCOMPL, info->signaled) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->swqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	if (post_sq)
		nser_uk_qp_post_wr(qp);

	return 0;
}

/**
 * nser_uk_post_receive - post receive wqe
 * @qp: hw qp ptr
 * @info: post rq information
 */
int nser_uk_post_receive(struct nser_qp_uk *qp,
			  struct nser_post_rq_info *info)
{
	u32 wqe_idx, i, byte_off;
	u32 addl_frag_cnt;
	__le64 *wqe;
	u64 hdr;

	if (qp->max_rq_frag_cnt < info->num_sges)
		return -EINVAL;

	wqe = nser_qp_get_next_recv_wqe(qp, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	qp->rq_wrid_array[wqe_idx] = info->wr_id;
	addl_frag_cnt = info->num_sges > 1 ? (info->num_sges - 1) : 0;
	qp->wqe_ops.iw_set_fragment(wqe, 0, info->sg_list,
				    qp->rwqe_polarity);

	for (i = 1, byte_off = 32; i < info->num_sges; i++) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, &info->sg_list[i],
					    qp->rwqe_polarity);
		byte_off += 16;
	}

	/* if not an odd number set valid bit in next fragment */
	if (!(info->num_sges & 0x01) &&
	    info->num_sges) {
		qp->wqe_ops.iw_set_fragment(wqe, byte_off, NULL,
					    qp->rwqe_polarity);
		++addl_frag_cnt;
	}

	set_64bit_val(wqe, 16, 0);
	hdr = FIELD_PREP(NSERQPSQ_ADDFRAGCNT, addl_frag_cnt) |
	      FIELD_PREP(NSERQPSQ_VALID, qp->rwqe_polarity);

	dma_wmb(); /* make sure WQE is populated before valid bit is set */

	set_64bit_val(wqe, 24, hdr);

	nser_uk_qp_fill_rqe_idx_in_shdw(qp);

	return 0;
}

/**
 * nser_uk_cq_resize - reset the cq buffer info
 * @cq: cq to resize
 * @cq_base: new cq buffer addr
 * @cq_size: number of cqes
 */
void nser_uk_cq_resize(struct nser_cq_uk *cq, void *cq_base, int cq_size)
{
	cq->cq_base = cq_base;
	cq->cq_size = cq_size;
	NSER_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;
}

/**
 * nser_uk_cq_set_resized_cnt - record the count of the resized buffers
 * @cq: cq to resize
 * @cq_cnt: the count of the resized cq buffers
 */
void nser_uk_cq_set_resized_cnt(struct nser_cq_uk *cq, u16 cq_cnt)
{
	u64 temp_val;
	u16 sw_cq_sel;
	u32 sw_cq_rptr;

	get_64bit_val(cq->shadow_area, 0, &temp_val);
	sw_cq_sel = (u16)FIELD_GET(NSER_CQ_DBSA_SW_CQ_SELECT, temp_val);
	sw_cq_rptr = (u32)FIELD_GET(NSER_CQ_DBSA_CQEIDX, temp_val);
	sw_cq_sel += cq_cnt;
	temp_val = FIELD_PREP(NSER_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
			   FIELD_PREP(NSER_CQ_DBSA_CQEIDX, sw_cq_rptr);

	set_64bit_val(cq->shadow_area, 0, temp_val);
}

/**
 * nser_uk_cq_request_notification - cq notification request (door bell)
 * @cq: hw cq
 * @cq_notify: notification type
 */
void nser_uk_cq_request_notification(struct nser_cq_uk *cq,
				      enum nser_cmpl_notify cq_notify)
{
	u8 arm_next = 0;

	cq->armed = true;

	if (cq_notify == NSER_CQ_COMPL_EVENT)
		arm_next = 1;

	dma_wmb(); /* make sure WQE is populated before valid bit is set */
	if (arm_next)
		writel(cq->cq_id, cq->cqe_alloc_db);
	else
		writel(FIELD_PREP(NSER_CQ_DB_CQN, cq->cq_id) |
			   FIELD_PREP(NSER_CQ_DB_ARMNEXTSE, true),
			   cq->cqe_alloc_db);
}

/**
 * nser_uk_cq_poll_cmpl - get cq completion info
 * @cq: hw cq
 * @info: cq poll information returned
 */
int nser_uk_cq_poll_cmpl(struct nser_cq_uk *cq,
			  struct nser_cq_poll_info *info)
{
	u64 comp_ctx, qword0, qword2, qword3;
	__le64 *cqe;
	struct nser_qp_uk *qp;
	struct nser_ring *pring = NULL;
	u32 wqe_idx;
	int ret_code;
	bool move_cq_head = true;
	u8 polarity;
	bool ext_valid;
	__le64 *ext_cqe;

	if (cq->avoid_mem_cflct)
		cqe = NSER_GET_CURRENT_EXTENDED_CQ_ELEM(cq);
	else
		cqe = NSER_GET_CURRENT_CQ_ELEM(cq);

	get_64bit_val(cqe, 24, &qword3);
	polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword3);
	if (polarity != cq->polarity)
		return -ENOENT;

	/* Ensure CQE contents are read after valid bit is checked */
	dma_rmb();

	ext_valid = (bool)FIELD_GET(NSER_CQ_EXTCQE, qword3);
	if (ext_valid) {
		u64 qword6, qword7;
		u32 peek_head;

		if (cq->avoid_mem_cflct) {
			ext_cqe = (__le64 *)((u8 *)cqe + 32);
			get_64bit_val(ext_cqe, 24, &qword7);
			polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword7);
		} else {
			peek_head = (cq->cq_ring.head + 1) % cq->cq_ring.size;
			ext_cqe = cq->cq_base[peek_head].buf;
			get_64bit_val(ext_cqe, 24, &qword7);
			polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword7);
			if (!peek_head)
				polarity ^= 1;
		}
		if (polarity != cq->polarity)
			return -ENOENT;

		/* Ensure ext CQE contents are read after ext valid bit is checked */
		dma_rmb();

		info->imm_valid = (bool)FIELD_GET(NSER_CQ_IMMVALID, qword7);
		if (info->imm_valid) {
			u64 qword4;

			get_64bit_val(ext_cqe, 0, &qword4);
			info->imm_data = (u32)FIELD_GET(NSER_CQ_IMMDATALOW32, qword4);
		}
		info->ud_smac_valid = (bool)FIELD_GET(NSER_CQ_UDSMACVALID, qword7);
		info->ud_vlan_valid = (bool)FIELD_GET(NSER_CQ_UDVLANVALID, qword7);
		if (info->ud_smac_valid || info->ud_vlan_valid) {
			get_64bit_val(ext_cqe, 16, &qword6);
			if (info->ud_vlan_valid)
				info->ud_vlan = (u16)FIELD_GET(NSER_CQ_UDVLAN, qword6);
			if (info->ud_smac_valid) {
				info->ud_smac[5] = qword6 & 0xFF;
				info->ud_smac[4] = (qword6 >> 8) & 0xFF;
				info->ud_smac[3] = (qword6 >> 16) & 0xFF;
				info->ud_smac[2] = (qword6 >> 24) & 0xFF;
				info->ud_smac[1] = (qword6 >> 32) & 0xFF;
				info->ud_smac[0] = (qword6 >> 40) & 0xFF;
			}
		}
	} else {
		info->imm_valid = false;
		info->ud_smac_valid = false;
		info->ud_vlan_valid = false;
	}

	info->q_type = (u8)FIELD_GET(NSER_CQ_SQ, qword3);
	info->error = (bool)FIELD_GET(NSER_CQ_ERROR, qword3);
	info->ipv4 = (bool)FIELD_GET(NSERCQ_IPV4, qword3);
	if (info->error) {
		info->major_err = FIELD_GET(NSER_CQ_MAJERR, qword3);
		info->minor_err = FIELD_GET(NSER_CQ_MINERR, qword3);
		if (info->major_err == NSER_FLUSH_MAJOR_ERR) {
			info->comp_status = NSER_COMPL_STATUS_FLUSHED;
			/* Set the min error to standard flush error code for remaining cqes */
			if (info->minor_err != FLUSH_GENERAL_ERR) {
				qword3 &= ~NSER_CQ_MINERR;
				qword3 |= FIELD_PREP(NSER_CQ_MINERR, FLUSH_GENERAL_ERR);
				set_64bit_val(cqe, 24, qword3);
			}
		} else {
			info->comp_status = NSER_COMPL_STATUS_UNKNOWN;
		}
	} else {
		info->comp_status = NSER_COMPL_STATUS_SUCCESS;
	}

	get_64bit_val(cqe, 0, &qword0);
	get_64bit_val(cqe, 16, &qword2);

	info->stat.raw = (u32)FIELD_GET(NSERCQ_ROCEPSN_RTT_TS, qword0);
	info->qp_id = (u32)FIELD_GET(NSERCQ_QPID, qword2);
	info->ud_src_qpn = (u32)FIELD_GET(NSERCQ_UDSRCQPN, qword2);

	get_64bit_val(cqe, 8, &comp_ctx);

	info->solicited_event = (bool)FIELD_GET(NSERCQ_SOEVENT, qword3);
	qp = (struct nser_qp_uk *)(unsigned long)comp_ctx;
	if (!qp || qp->destroy_pending) {
		ret_code = -EFAULT;
		goto exit;
	}
	wqe_idx = (u32)FIELD_GET(NSER_CQ_WQEIDX, qword3);
	info->qp_handle = (nser_qp_handle)(unsigned long)qp;
	info->op_type = (u8)FIELD_GET(NSERCQ_OP, qword3);

	if (info->q_type == NSER_CQE_QTYPE_RQ) {
		u32 array_idx;

		array_idx = wqe_idx / qp->rq_wqe_size_multiplier;

		if (info->comp_status == NSER_COMPL_STATUS_FLUSHED ||
		    info->comp_status == NSER_COMPL_STATUS_UNKNOWN) {
			if (!NSER_RING_MORE_WORK(qp->rq_ring)) {
				ret_code = -ENOENT;
				goto exit;
			}

			info->wr_id = qp->rq_wrid_array[qp->rq_ring.tail];
			array_idx = qp->rq_ring.tail;
		} else {
			info->wr_id = qp->rq_wrid_array[array_idx];
		}

		info->bytes_xfered = (u32)FIELD_GET(NSERCQ_PAYLDLEN, qword0);

		if (qword3 & NSERCQ_STAG) {
			info->stag_invalid_set = true;
			info->inv_stag = (u32)FIELD_GET(NSERCQ_INVSTAG, qword2);
		} else {
			info->stag_invalid_set = false;
		}
		NSER_RING_SET_TAIL(qp->rq_ring, array_idx + 1);

		pring = &qp->rq_ring;
	} else { /* q_type is NSER_CQE_QTYPE_SQ */
		if (qp->first_sq_wq) {
			if (wqe_idx + 1 >= qp->conn_wqes)
				qp->first_sq_wq = false;

			if (wqe_idx < qp->conn_wqes && qp->sq_ring.head == qp->sq_ring.tail) {
				u64 temp_val;
				u16 sw_cq_sel;
				u32 sw_cq_rptr;

				NSER_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
				NSER_RING_MOVE_TAIL(cq->cq_ring);

				get_64bit_val(cq->shadow_area, 0, &temp_val);
				sw_cq_sel = (u16)FIELD_GET(NSER_CQ_DBSA_SW_CQ_SELECT, temp_val);
				sw_cq_rptr = NSER_RING_CURRENT_HEAD(cq->cq_ring);
				temp_val = FIELD_PREP(NSER_CQ_DBSA_SW_CQ_SELECT, sw_cq_sel) |
						   FIELD_PREP(NSER_CQ_DBSA_CQEIDX, sw_cq_rptr);
				set_64bit_val(cq->shadow_area, 0, temp_val);

				memset(info, 0,
				       sizeof(struct nser_cq_poll_info));
				return nser_uk_cq_poll_cmpl(cq, info);
			}
		}
		if (info->comp_status != NSER_COMPL_STATUS_FLUSHED) {
			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			if (!info->comp_status)
				info->bytes_xfered = qp->sq_wrtrk_array[wqe_idx].wr_len;
			info->op_type = (u8)FIELD_GET(NSERCQ_OP, qword3);
			NSER_RING_SET_TAIL(qp->sq_ring,
					    wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
		} else {
			unsigned long flags;

			spin_lock_irqsave(qp->lock, flags);
			if (!NSER_RING_MORE_WORK(qp->sq_ring)) {
				spin_unlock_irqrestore(qp->lock, flags);
				ret_code = -ENOENT;
				goto exit;
			}

			do {
				__le64 *sw_wqe;
				u64 wqe_qword;
				u32 tail;

				tail = qp->sq_ring.tail;
				sw_wqe = qp->sq_base[tail].elem;
				get_64bit_val(sw_wqe, 24,
					      &wqe_qword);
				info->op_type = (u8)FIELD_GET(NSERQPSQ_OPCODE, wqe_qword);
				NSER_RING_SET_TAIL(qp->sq_ring,
						    tail + qp->sq_wrtrk_array[tail].quanta);
				if (info->op_type != NSERQP_OP_NOP) {
					info->wr_id = qp->sq_wrtrk_array[tail].wrid;
					info->bytes_xfered = qp->sq_wrtrk_array[tail].wr_len;
					break;
				}
			} while (1);

			if (info->op_type == NSER_OP_TYPE_BIND_MW &&
				info->minor_err == FLUSH_PROT_ERR)
				info->minor_err = FLUSH_MW_BIND_ERR;
			qp->sq_flush_seen = true;
			if (!NSER_RING_MORE_WORK(qp->sq_ring))
				qp->sq_flush_complete = true;
			spin_unlock_irqrestore(qp->lock, flags);
		}
		pring = &qp->sq_ring;
	}

	ret_code = 0;

exit:
	if (move_cq_head) {
		NSER_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!NSER_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		if (ext_valid && !cq->avoid_mem_cflct) {
			NSER_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
			if (!NSER_RING_CURRENT_HEAD(cq->cq_ring))
				cq->polarity ^= 1;
		}

		NSER_RING_MOVE_TAIL(cq->cq_ring);
		if (!cq->avoid_mem_cflct && ext_valid)
			NSER_RING_MOVE_TAIL(cq->cq_ring);
		set_64bit_val(cq->shadow_area, 0,
			      NSER_RING_CURRENT_HEAD(cq->cq_ring));
	} else {
		qword3 &= ~NSER_CQ_WQEIDX;
		qword3 |= FIELD_PREP(NSER_CQ_WQEIDX, pring->tail);
		set_64bit_val(cqe, 24, qword3);
	}

	return ret_code;
}

/**
 * nser_print_cqes - print cq completion info
 * @cq: hw cq
 */
void nser_print_cqes(struct nser_cq_uk *cq)
{
	__u8 cq_polarity = cq->polarity;
	int i = 0;

	pr_info("%s[%d]: CQ (cq_id=%u, polarity=%d, head=%u, size=%u)\n",
		__func__, __LINE__, cq->cq_id, cq_polarity, cq->cq_ring.head,
		cq->cq_ring.size);

	while (true) {
		__u64 comp_ctx, qword0, qword2, qword3;
		struct nser_cq_poll_info cqe_info;
		struct nser_cq_poll_info *info = &cqe_info;
		struct nser_qp_uk *qp;
		__le64 *ext_cqe = NULL;
		bool ext_valid;
		__u8 polarity;
		__u32 wqe_idx;
		__le64 *cqe;

		NSER_GET_CQ_ELEM_AT_OFFSET(cq, i, cqe);
		get_64bit_val(cqe, 24, &qword3);
		polarity = (__u8)FIELD_GET(NSER_CQ_VALID, qword3);

		if (polarity != cq_polarity) {
			pr_info("%s[%d]: CQ (cq_id=%u) is empty\n", __func__,
				__LINE__, cq->cq_id);
			return;
		}

		/* Ensure CQE contents are read after valid bit is checked */
		dma_rmb();

		ext_valid = (bool)FIELD_GET(NSER_CQ_EXTCQE, qword3);
		if (ext_valid) {
			__u64 qword7;
			__u32 peek_head;

			if (cq->avoid_mem_cflct) {
				ext_cqe = (__le64 *)((__u8 *)cqe + 32);
				get_64bit_val(ext_cqe, 24, &qword7);
				polarity = (__u8)FIELD_GET(NSER_CQ_VALID, qword7);
			} else {
				peek_head = NSER_GET_RING_OFFSET(cq->cq_ring, i + 1);
				ext_cqe = cq->cq_base[peek_head].buf;
				get_64bit_val(ext_cqe, 24, &qword7);
				polarity = (__u8)FIELD_GET(NSER_CQ_VALID, qword7);
				if (!peek_head)
					polarity ^= 1;
			}
			if (polarity != cq_polarity) {
				pr_info("%s[%d]: Extended CQ (cq_id=%u) is empty\n",
					__func__, __LINE__, cq->cq_id);
				return;
			}

			/* Ensure ext CQE contents are read after ext valid bit is checked */
			dma_rmb();

			memset(info, 0, sizeof(struct nser_cq_poll_info));
			info->imm_valid = (bool)FIELD_GET(NSER_CQ_IMMVALID, qword7);
			if (info->imm_valid) {
				__u64 qword4;

				get_64bit_val(ext_cqe, 0, &qword4);
				info->imm_data = (__u32)FIELD_GET(NSER_CQ_IMMDATALOW32, qword4);
			}
		} else {
			info->imm_valid = false;
		}

		info->q_type = (__u8)FIELD_GET(NSER_CQ_SQ, qword3);
		info->error = (bool)FIELD_GET(NSER_CQ_ERROR, qword3);
		info->ipv4 = (bool)FIELD_GET(NSERCQ_IPV4, qword3);
		if (info->error) {
			info->major_err = FIELD_GET(NSER_CQ_MAJERR, qword3);
			info->minor_err = FIELD_GET(NSER_CQ_MINERR, qword3);
			if (info->major_err == NSER_FLUSH_MAJOR_ERR)
				info->comp_status = NSER_COMPL_STATUS_FLUSHED;
			else
				info->comp_status = NSER_COMPL_STATUS_UNKNOWN;
		} else {
			info->comp_status = NSER_COMPL_STATUS_SUCCESS;
		}

		get_64bit_val(cqe, 0, &qword0);
		get_64bit_val(cqe, 16, &qword2);

		info->qp_id = (__u32)FIELD_GET(NSERCQ_QPID, qword2);
		get_64bit_val(cqe, 8, &comp_ctx);
		info->solicited_event = (bool)FIELD_GET(NSERCQ_SOEVENT, qword3);

		pr_info("%s[%d]: Found CQE (cq_id=%u major_err=%u minor_err=%u q_type=%u ipv4=%s solicited_event=%s imm_data=%u qp_id=%u)\n",
			__func__, __LINE__, cq->cq_id, info->major_err,
			info->minor_err, info->q_type,
			info->ipv4 ? "true" : "false",
			info->solicited_event ? "true" : "false",
			info->imm_valid ? info->imm_data : 0, info->qp_id);

		qp = (struct nser_qp_uk *)(uintptr_t)comp_ctx;
		if (!qp || qp->destroy_pending) {
			pr_info("%s[%d]: Found CQE for (cq_id=%u qp_id=%u): QP destroyed\n",
				__func__, __LINE__, cq->cq_id, info->qp_id);
			goto loop_end;
		}
		wqe_idx = (__u32)FIELD_GET(NSER_CQ_WQEIDX, qword3);
		info->qp_handle = (nser_qp_handle)(uintptr_t)qp;
		info->op_type = (__u8)FIELD_GET(NSERCQ_OP, qword3);

		if (info->q_type == NSER_CQE_QTYPE_RQ) {
			__u32 array_idx;

			array_idx = wqe_idx / qp->rq_wqe_size_multiplier;
			info->wr_id = qp->rq_wrid_array[array_idx];

			if (qword3 & NSERCQ_STAG) {
				info->stag_invalid_set = true;
				info->inv_stag = (__u32)FIELD_GET(NSERCQ_INVSTAG, qword2);
			} else {
				info->stag_invalid_set = false;
			}

			pr_info("%s[%d]: Found CQE for RQ qp_id=%u rq_ring (head=%u tail=%u size=%u) wr_id=%llu wqe_idx=%u, stag_invalid_set=%s op_type=%u\n",
				__func__, __LINE__, info->qp_id,
				qp->rq_ring.head, qp->rq_ring.tail,
				qp->rq_ring.size, info->wr_id, wqe_idx,
				info->stag_invalid_set ? "true" : "false",
				info->op_type);

		} else { /* q_type is NSER_CQE_QTYPE_SQ */

			if (qp->first_sq_wq) {
				pr_info("%s[%d]: Found CQE for SQ first_sq_wq (qp_id=%u, wqe_idx=%u, conn_wqes=%d)\n",
					__func__, __LINE__, info->qp_id,
					wqe_idx, qp->conn_wqes);

				if (wqe_idx < qp->conn_wqes && qp->sq_ring.head == qp->sq_ring.tail)
					goto loop_end;
			}

			info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
			info->op_type = (__u8)FIELD_GET(NSERCQ_OP, qword3);

			pr_info("%s[%d]: Found CQE for SQ qp_id=%u, rq_ring (head=%u tail=%u size=%u) wr_id=%llu wqe_idx=%u op_type=%u\n",
				__func__, __LINE__, info->qp_id,
				qp->sq_ring.head, qp->sq_ring.tail,
				qp->sq_ring.size, info->wr_id, wqe_idx,
				info->op_type);
		}
loop_end:
			i++;
			if (!NSER_GET_RING_OFFSET(cq->cq_ring, i))
				cq_polarity ^= 1;

			if (ext_valid && !cq->avoid_mem_cflct) {
				i++;
				if (!NSER_GET_RING_OFFSET(cq->cq_ring, i))
					cq_polarity ^= 1;
			}
	}
}

/**
 * nser_print_sq_wqes - print sqp wqes
 * @qp: hw qp
 */
void nser_print_sq_wqes(struct nser_qp_uk *qp)
{
	__u32 wqe_idx = NSER_RING_CURRENT_TAIL(qp->sq_ring);
	__u8 sq_polarity = qp->swqe_polarity;

	pr_info("%s[%d]: SQ (qp_id=%u sq_polarity=%d head=%u tail=%u size=%u)\n",
		__func__, __LINE__, qp->qp_id, sq_polarity, qp->sq_ring.head,
		qp->sq_ring.tail, qp->sq_ring.size);

	if (!NSER_RING_MORE_WORK(qp->sq_ring)) {
		pr_info("%s[%d]: SQ is empty (qp_id=%u)\n", __func__,
			__LINE__, qp->qp_id);
		return;
	}

	while (true) {
		__u8 wqe_polarity;
		__le64 *wqe;
		__u64 val;
		int i;

		wqe = qp->sq_base[wqe_idx].elem;
		get_64bit_val(wqe, 24, &val);
		wqe_polarity = FIELD_GET(NSERQPSQ_VALID, val);

		if (wqe_polarity != sq_polarity)
			break;

		pr_info("%s[%d]: Found WQE in SQ qp_id=%u wr_id=%llu wqe_idx=%u wr_len=%u quanta=%u hdr=0x%0llX\n",
			__func__, __LINE__, qp->qp_id, qp->sq_wrtrk_array[wqe_idx].wrid,
			wqe_idx, qp->sq_wrtrk_array[wqe_idx].wr_len,
			qp->sq_wrtrk_array[wqe_idx].quanta, val);

		for (i = 0; i < (qp->sq_wrtrk_array[wqe_idx].quanta *
						NSER_QP_WQE_MIN_SIZE / 8); i++)
			pr_debug("index %03d val: %016llx\n", i, *(wqe + i));
		wqe_idx += qp->sq_wrtrk_array[wqe_idx].quanta;

		if (!wqe_idx)
			sq_polarity = !qp->swqe_polarity;
	}
}

/**
 * nser_round_up_wq - return round up qp wq depth
 * @wqdepth: wq depth in quanta to round up
 */
static int nser_round_up_wq(u32 wqdepth)
{
	int scount = 1;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

/**
 * nser_get_wqe_shift - get shift count for maximum wqe size
 * @uk_attrs: qp HW attributes
 * @sge: Maximum Scatter Gather Elements wqe
 * @inline_data: Maximum inline data size
 * @shift: Returns the shift needed based on sge
 *
 * Shift can be used to left shift the wqe size based on number of SGEs and inlind data size.
 * For 1 SGE or inline data <= 8, shift = 0 (wqe size of 32
 * bytes). For 2 or 3 SGEs or inline data <= 39, shift = 1 (wqe
 * size of 64 bytes).
 * For 4-7 SGE's and inline <= 101 Shift of 2 otherwise (wqe
 * size of 256 bytes).
 */
void nser_get_wqe_shift(struct nser_uk_attrs *uk_attrs, u32 sge,
			 u32 inline_data, u8 *shift)
{
	*shift = 0;
	if (sge > 1 || inline_data > 8) {
		if (sge < 4 && inline_data <= 39)
			*shift = 1;
		else if (sge < 8 && inline_data <= 101)
			*shift = 2;
		else
			*shift = 3;
	}
}

/*
 * nser_get_sqdepth - get SQ depth (quanta)
 * @uk_attrs: qp HW attributes
 * @sq_size: SQ size
 * @shift: shift which determines size of WQE
 * @sqdepth: depth of SQ
 */
int nser_get_sqdepth(struct nser_uk_attrs *uk_attrs, u32 sq_size, u8 shift, u32 *sqdepth)
{
	*sqdepth = nser_round_up_wq((sq_size << shift) + NSER_SQ_RSVD);

	if (*sqdepth < (uk_attrs->min_hw_wq_size << shift))
		*sqdepth = uk_attrs->min_hw_wq_size << shift;
	else if (*sqdepth > uk_attrs->max_hw_wq_quanta)
		return -EINVAL;

	return 0;
}

/*
 * nser_get_rqdepth - get RQ depth (quanta)
 * @uk_attrs: qp HW attributes
 * @rq_size: SRQ size
 * @shift: shift which determines size of WQE
 * @rqdepth: depth of RQ/SRQ
 */
int nser_get_rqdepth(struct nser_uk_attrs *uk_attrs, u32 rq_size, u8 shift, u32 *rqdepth)
{
	*rqdepth = nser_round_up_wq((rq_size << shift) + NSER_RQ_RSVD);

	if (*rqdepth < (uk_attrs->min_hw_wq_size << shift))
		*rqdepth = uk_attrs->min_hw_wq_size << shift;
	else if (*rqdepth > uk_attrs->max_hw_rq_quanta)
		return -EINVAL;

	return 0;
}

static const struct nser_wqe_uk_ops iw_wqe_uk_ops = {
	.iw_copy_inline_data = nser_copy_inline_data,
	.iw_inline_data_size_to_quanta = nser_inline_data_size_to_quanta,
	.iw_set_fragment = nser_set_fragment,
	.iw_set_mw_bind_wqe = nser_set_mw_bind_wqe,
};

/**
 * nser_setup_connection_wqes - setup WQEs necessary to complete
 * connection.
 * @qp: hw qp (user and kernel)
 * @info: qp initialization info
 */
static void nser_setup_connection_wqes(struct nser_qp_uk *qp,
					struct nser_qp_uk_init_info *info)
{
	u16 move_cnt = 1;

	if ((qp->uk_attrs->feature_flags & NSER_FEATURE_RTS_AE))
		move_cnt = 3;

	qp->conn_wqes = move_cnt;
	NSER_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, move_cnt);
	NSER_RING_MOVE_TAIL_BY_COUNT(qp->sq_ring, move_cnt);
	NSER_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->initial_ring, move_cnt);
}

/**
 * nser_uk_qp_init - initialize shared qp
 * @qp: hw qp (user and kernel)
 * @info: qp initialization info
 *
 * initializes the vars used in both user and kernel mode.
 * size of the wqe depends on numbers of max. fragements
 * allowed. Then size of wqe * the number of wqes should be the
 * amount of memory allocated for sq and rq.
 */
int nser_uk_qp_init(struct nser_qp_uk *qp, struct nser_qp_uk_init_info *info)
{
	int ret_code = 0;
	u32 sq_ring_size;
	u8 sqshift, rqshift;
	u16 wqe_size = 0;

	qp->uk_attrs = info->uk_attrs;
	if (info->max_sq_frag_cnt > qp->uk_attrs->max_hw_wq_frags ||
	    info->max_rq_frag_cnt > qp->uk_attrs->max_hw_wq_frags)
		return -EINVAL;

	nser_get_wqe_shift(qp->uk_attrs, info->max_rq_frag_cnt, 0, &rqshift);

	nser_get_wqe_shift(qp->uk_attrs, info->max_sq_frag_cnt + 1,
				    info->max_inline_data, &sqshift);
	qp->qp_caps = info->qp_caps;
	qp->sq_base = info->sq;
	qp->rq_base = info->rq;
	qp->qp_type = info->type ? info->type : NSER_QP_TYPE_ROCE_RC;
	qp->shadow_area = info->shadow_area;
	qp->sq_wrtrk_array = info->sq_wrtrk_array;

	qp->rq_wrid_array = info->rq_wrid_array;
	qp->wqe_alloc_db = info->wqe_alloc_db;
	qp->rd_fence_rate = info->rd_fence_rate;
	qp->qp_id = info->qp_id;
	qp->sq_size = info->sq_size;
	qp->max_sq_frag_cnt = info->max_sq_frag_cnt;
	sq_ring_size = qp->sq_size << sqshift;
	NSER_RING_INIT(qp->sq_ring, sq_ring_size);
	NSER_RING_INIT(qp->initial_ring, sq_ring_size);
	if (info->first_sq_wq) {
		nser_setup_connection_wqes(qp, info);
		qp->swqe_polarity = 1;
		qp->first_sq_wq = true;
	} else {
		qp->swqe_polarity = 0;
	}
	qp->swqe_polarity_deferred = 1;
	qp->rwqe_polarity = 0;
	qp->rq_size = info->rq_size;
	qp->max_rq_frag_cnt = info->max_rq_frag_cnt;
	qp->max_inline_data = info->max_inline_data;
	qp->rq_wqe_size = rqshift;
	NSER_RING_INIT(qp->rq_ring, qp->rq_size);
	qp->rq_wqe_size_multiplier = 1 << rqshift;
	nser_fragcnt_to_wqesize_rq(qp->max_rq_frag_cnt, &wqe_size);
	qp->rqe_stride = wqe_size/NSER_QP_WQE_MIN_SIZE;
	qp->wqe_ops = iw_wqe_uk_ops;
	return ret_code;
}

/**
 * nser_uk_cq_init - initialize shared cq (user and kernel)
 * @cq: hw cq
 * @info: hw cq initialization info
 */
int nser_uk_cq_init(struct nser_cq_uk *cq, struct nser_cq_uk_init_info *info)
{
	cq->cq_base = info->cq_base;
	cq->cq_id = info->cq_id;
	cq->cq_size = info->cq_size;
	cq->cqe_alloc_db = info->cqe_alloc_db;
	cq->cq_ack_db = info->cq_ack_db;
	cq->shadow_area = info->shadow_area;
	cq->avoid_mem_cflct = info->avoid_mem_cflct;
	NSER_RING_INIT(cq->cq_ring, cq->cq_size);
	cq->polarity = 1;

	return 0;
}

/**
 * nser_uk_clean_cq - clean cq entries
 * @q: completion context
 * @cq: cq to clean
 */
void nser_uk_clean_cq(void *q, struct nser_cq_uk *cq)
{
	__le64 *cqe;
	u64 qword3, comp_ctx;
	u32 cq_head;
	u8 polarity, temp;

	cq_head = cq->cq_ring.head;
	temp = cq->polarity;
	do {
		if (cq->avoid_mem_cflct)
			cqe = ((struct nser_extended_cqe *)(cq->cq_base))[cq_head].buf;
		else
			cqe = cq->cq_base[cq_head].buf;
		get_64bit_val(cqe, 24, &qword3);
		polarity = (u8)FIELD_GET(NSER_CQ_VALID, qword3);

		if (polarity != temp)
			break;

		get_64bit_val(cqe, 8, &comp_ctx);
		if ((void *)(unsigned long)comp_ctx == q)
			set_64bit_val(cqe, 8, 0);

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			temp ^= 1;
	} while (true);
}


/**
 * nser_fragcnt_to_quanta_sq - calculate quanta based on fragment count for SQ
 * @frag_cnt: number of fragments
 * @quanta: quanta for frag_cnt
 */
int nser_fragcnt_to_quanta_sq(u32 frag_cnt, u16 *quanta)
{
	switch (frag_cnt) {
	case 0:
	case 1:
		*quanta = NSER_QP_WQE_MIN_QUANTA;
		break;
	case 2:
	case 3:
		*quanta = 2;
		break;
	case 4:
	case 5:
		*quanta = 3;
		break;
	case 6:
	case 7:
		*quanta = 4;
		break;
	case 8:
	case 9:
		*quanta = 5;
		break;
	case 10:
	case 11:
		*quanta = 6;
		break;
	case 12:
	case 13:
		*quanta = 7;
		break;
	case 14:
	case 15: /* when immediate data is present */
		*quanta = 8;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * nser_fragcnt_to_wqesize_rq - calculate wqe size based on fragment count for RQ
 * @frag_cnt: number of fragments
 * @wqe_size: size in bytes given frag_cnt
 */
int nser_fragcnt_to_wqesize_rq(u32 frag_cnt, u16 *wqe_size)
{
	switch (frag_cnt) {
	case 0:
	case 1:
		*wqe_size = 32;
		break;
	case 2:
	case 3:
		*wqe_size = 64;
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		*wqe_size = 128;
		break;
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
		*wqe_size = 256;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

