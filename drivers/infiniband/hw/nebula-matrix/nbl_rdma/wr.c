// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/bitfield.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_cm.h>
#include <rdma/ibta_vol1_c12.h>
#include "wr.h"
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

#if NBL_IO_POST_DB_MODE
static bool nbl_recheck_seq_num(struct nbl_uk_qp *uk_qp)
{
	bool ret;

	if (!(uk_qp->seq_first_err) && !(uk_qp->err_db_done)) {
		nbl_pr_err("qpn :%d fst seq_num err !\n", uk_qp->qpn);
		uk_qp->seq_first_err = true;
		uk_qp->err_db_done = true;
		ret = true;
	} else {
		if (!(uk_qp->seq_first_err)) {
			uk_qp->seq_err = true;
			nbl_pr_err("qpn :%d sec seq_num err !\n", uk_qp->qpn);
			ret = true;
		} else
			ret = false;
	}
	return ret;
}
static int nbl_check_db_fill_shadow(struct nbl_sc_qp *sc_qp)
{
	struct nbl_uk_qp *uk_qp;
	u16 hw_drop_db_ci;
	u16 sw_sq_pi;
	u64 temp;
	u16 write_word = 0;
	bool ring_db = false;
	bool sw_pi_phase;
	u16 sw_ring_db_pi;
	int hw_seq_num;

	uk_qp = &sc_qp->uk_qp;
	sw_ring_db_pi = uk_qp->sw_ring_db_pi;
	get_64bit_val(sc_qp->qp_shadow.va, 8, &temp);

	hw_seq_num = (__u16)FIELD_GET(NBL_QPC_SHADOW_AREA_HW_SEQ_NUM, temp);
	hw_drop_db_ci =
		(__u16)FIELD_GET(NBL_QPC_SHADOW_AREA_HW_DROP_DB_CI, temp);
	sw_sq_pi = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);
	if (hw_drop_db_ci == uk_qp->hw_drop_db_ci) {
		ring_db = true;
		uk_qp->sw_ring_db_pi = sw_sq_pi;
		goto set_pi;
	}
	if (hw_seq_num != uk_qp->seq_num) {
		ring_db = nbl_recheck_seq_num(uk_qp);
		if (ring_db)
			uk_qp->sw_ring_db_pi = sw_sq_pi;
	} else {
		uk_qp->seq_first_err = false;
		if (sw_sq_pi > sw_ring_db_pi) {
			if (hw_drop_db_ci >= sw_ring_db_pi &&
			    hw_drop_db_ci <= sw_sq_pi) {
				ring_db = true;
				uk_qp->sw_ring_db_pi = sw_sq_pi;
			}
		} else {
			if (hw_drop_db_ci >= sw_ring_db_pi ||
			    hw_drop_db_ci <= sw_sq_pi) {
				ring_db = true;
				uk_qp->sw_ring_db_pi = sw_sq_pi;
			}
		}
	}
set_pi:
	uk_qp->hw_drop_db_ci = hw_drop_db_ci;
	sw_pi_phase = uk_qp->swqe_polarity;
	if (uk_qp->sq_ring.head != 0)
		sw_pi_phase = (sw_pi_phase ? false : true);
	write_word = (__u16)(
		FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_SQ_PI, sw_sq_pi) |
		FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_SQ_PI_PHASE, sw_pi_phase));
	set_16bit_val((__be16 *)sc_qp->qp_shadow.va, 30, write_word);
	return ring_db;
}
#endif

static void nbl_post_sq_db(struct nbl_uk_qp *uk_qp)
{
	u64 temp;

	temp = (__u64)(FIELD_PREP(NBL_SQ_DB_TC, uk_qp->tc) |
		       FIELD_PREP(NBL_SQ_DB_QPN, uk_qp->qpn));
	write64_reg(temp, uk_qp->sq_db);
}

static int nbl_fill_ctrl_info(struct nbl_wqe_ctrl_seg *ctrl,
			      struct nbl_wqe_info *info)
{
	u64 temp;
	u8 opcode;

	opcode = nbl_opcode[info->ib_opcode];

	temp = (info->qpn) << NBL_WQE_CTRL_QPN_SHIFT |
	       ((info->num_sge) << NBL_WQE_CTRL_DATA_SIZE_SHIFT) |
	       info->wqe_size / NBL_MIN_WQE_SIZE;

	ctrl->qpn_ds_ts = cpu_to_be32(temp);

	if (opcode != NBL_OPCODE_FAST_MR) {
		ctrl->payload_len = cpu_to_be32(info->payload_len);
		if (info->is_inv)
			ctrl->imm_inv_rkey = cpu_to_be32(info->inv_rkey);
		else if (info->is_imm)
			ctrl->imm_inv_rkey = info->imm_data;
	}

	if ((!info->is_inline) && (info->wqe_size == NBL_MAX_WQE_SIZE)) {
		temp = FIELD_PREP(NBL_WQE_DMA_ADDR, info->addr) |
		       FIELD_PREP(NBL_WQE_DMA_ADDR_WQE_VLD, info->wqe_vld);
		dma_wmb();
		set_64bit_val((__be64 *)ctrl, 64, temp);
	}
	temp = (FIELD_PREP(NBL_SQ_WQE_OPCODE, opcode) |
		FIELD_PREP(NBL_SQ_WQE_IDX_PHASE, !info->wqe_vld) |
		FIELD_PREP(NBL_SQ_WQE_IDX, info->wqe_idx) |
		FIELD_PREP(NBL_SQ_WQE_IMM, info->is_imm) |
		FIELD_PREP(NBL_SQ_WQE_INLINE, info->is_inline) |
		FIELD_PREP(NBL_SQ_WQE_SE, info->se) |
		FIELD_PREP(NBL_SQ_WQE_CE, info->ce) |
		FIELD_PREP(NBL_SQ_WQE_FENCE, info->fence) |
		FIELD_PREP(NBL_SQ_WQE_VLD, info->wqe_vld));

	dma_wmb();
	set_32bit_val((__be32 *)ctrl, 0, temp);

	return 0;
}
static void nbl_copy_data_from_sge(const struct ib_send_wr *wr, void *wqe,
			bool rc_send, int cur_size, struct nbl_wqe_info *info)
{
	int i;
	bool vld;
	__be64 temp;
	bool addr_bit;

	if (wr->send_flags & IB_SEND_INLINE) {
		void *addr;
		unsigned int len;
		u8 *inline_seg;

		inline_seg = wqe;
		for (i = 0; i < wr->num_sge; i++) {
			addr = (void *)(unsigned long)(wr->sg_list[i].addr);
			len = wr->sg_list[i].length;
			memcpy(inline_seg, addr, len);
			inline_seg += len;
		}

	} else {
		struct nbl_wqe_data_seg *dseg;

		/* send, send with imm and send with inv need to shift rsv on wqe address */
		/*ud send not rsv*/
		if (rc_send) {
			wqe += NBL_WQE_RSV_SIZE;
			cur_size += NBL_WQE_RSV_SIZE;
		}
		dseg = wqe;
		for (i = 0; i < wr->num_sge; i++) {
			if (cur_size == NBL_MIN_WQE_SIZE) {
				vld = !info->wqe_vld;
				info->addr = wr->sg_list[i].addr;
			} else
				vld = false;

			addr_bit = wr->sg_list[i].addr >> NBL_WQE_ADDR_BIT_OFFSET;

			temp = FIELD_PREP(NBL_WQE_DMA_LEN, wr->sg_list[i].length) |
				FIELD_PREP(NBL_WQE_DMA_ADDR_BIT, addr_bit);
			set_32bit_val((__be32 *)dseg, 12, temp);

			dseg->lkey = cpu_to_be32(wr->sg_list[i].lkey);
			temp = FIELD_PREP(NBL_WQE_DMA_ADDR,
						  wr->sg_list[i].addr) |
				FIELD_PREP(NBL_WQE_DMA_ADDR_WQE_VLD,
						  vld);
			set_64bit_val((__be64 *)dseg, 0, temp);
			cur_size += sizeof(struct nbl_wqe_data_seg);
			++dseg;
		}
	}
}

static void
nbl_fill_fast_mr_seg_info(struct nbl_device *nbldev,
			  struct nbl_wqe_fast_mr_ctrl_seg *fast_ctrl,
			  const struct ib_send_wr *wr)
{
	struct nbl_wqe_fast_mr_addr_seg *fast_addr;
	struct nbl_wqe_fast_mr_pbl_seg *fast_pbl;
	enum nbl_page_size pg_sz = NBL_PAGE_SIZE_4K;
	void *wqe = fast_ctrl;

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

	leaf_sz = mr->pbl.pbl_allocated ? 1 : 0;

	fast_ctrl->access_rights = mr_rights;
	fast_ctrl->leaf_size = leaf_sz;
	fast_ctrl->pg_sz = pg_sz;
	fast_ctrl->addr_type = NBL_ADDR_TYPE_ZERO_BASED;

	wqe += sizeof(struct nbl_wqe_fast_mr_ctrl_seg);
	fast_addr = wqe;

	fast_addr->va = cpu_to_be64(mr->ibmr.iova);
	fast_addr->stag = cpu_to_be32(reg_wr(wr)->key);
	fast_addr->len = cpu_to_be32(mr->ibmr.length);

	wqe += sizeof(struct nbl_wqe_fast_mr_addr_seg);
	fast_pbl = wqe;

	fast_pbl->first_pbl_idx = cpu_to_be32(palloc->pble_info.idx);
}

/* MAD_BUF_WR_OFFSET is the relative address offset of members 'struct ib_mad_send_buf send_buf'
 * and 'struct ib_ud_wr send_wr' in 'struct ib_mad_send_wr_private'.
 * I have checked to the latest kernel version(6.7.6),and this value is the same.
 * If compiling a newer kernel version,this value needs to be checked.
 * struct ib_mad_send_wr_private is located in linux-/drivers/infiniband/core/mad_priv.h
 */
#define MAD_BUF_WR_OFFSET (sizeof(struct ib_mad_send_buf) + sizeof(u64) + sizeof(u64))
#define IB_CM_CLASS_VERSION	2

static inline bool is_cm_mad_hdr_req(struct ib_mad_hdr *mad_hdr)
{
	if (mad_hdr->base_version == IB_MGMT_BASE_VERSION &&
		mad_hdr->mgmt_class	== IB_MGMT_CLASS_CM &&
		mad_hdr->class_version == IB_CM_CLASS_VERSION &&
		mad_hdr->method	== IB_MGMT_METHOD_SEND &&
		mad_hdr->attr_id == CM_REQ_ATTR_ID)
		return true;

	return false;
}

static inline bool is_cm_mad_hdr_rep(struct ib_mad_hdr *mad_hdr)
{
	if (mad_hdr->base_version == IB_MGMT_BASE_VERSION &&
		mad_hdr->mgmt_class	== IB_MGMT_CLASS_CM &&
		mad_hdr->class_version == IB_CM_CLASS_VERSION &&
		mad_hdr->method	== IB_MGMT_METHOD_SEND &&
		mad_hdr->attr_id == CM_REP_ATTR_ID)
		return true;

	return false;
}

static void nbl_fill_datagram_seg_info(struct nbl_pci_f *rf, struct nbl_wqe_datagram_seg *ud_seg,
				const struct ib_send_wr *wr, enum ib_qp_type qp_type)
{
	struct nbl_ah *ah;
	struct ib_mad_send_buf *send_buf;
	struct ib_mad_hdr *mad_hdr;
	u8 rnr_retry_count;

	ah = to_nbl_ah(ud_wr(wr)->ah);
	ud_seg->ipv4_vlan_src_flow = cpu_to_be32(
		((ah->av.vlan_tag_ipv4_valid & 0x1) << NBL_QP_WQE_UD_IPV4) |
		(((ah->av.vlan_tag_ipv4_valid >> NBL_AH_VLAN_EN_SHIFT) & 0x1)
		 << NBL_QP_WQE_UD_VLAN) |
		((ah->av.src_addr_index & 0x7F) << NBL_QP_WQE_UD_SRC_ADDR_IDX) |
		(ah->av.flow_label & 0xFFFF));
	ud_seg->udp_sport = cpu_to_be16(ah->av.udp_sport);
	ud_seg->vlan_id = cpu_to_be16(ah->av.vlan_id);
	memcpy(ud_seg->dest_mac, ah->av.dest_mac, sizeof(ah->av.dest_mac));
	memcpy(ud_seg->dest_ip, ah->av.dest_ip, sizeof(ah->av.dest_ip));
	ud_seg->hop_limit = ah->av.hop_limit;
	ud_seg->tclass = ah->av.tclass;
	ud_seg->pd_idx = cpu_to_be32(ah->av.pd_idx << 8);
	ud_seg->dest_qp = cpu_to_be32(ud_wr(wr)->remote_qpn & 0xFFFFFF);
	ud_seg->q_key = cpu_to_be32(ud_wr(wr)->remote_qkey);
	if (ud_wr(wr)->remote_qkey == IB_QP_SET_QKEY) {
		ud_seg->q_key = cpu_to_be32(IB_QP1_QKEY);
		nbl_pr_dbg("qp_type:%d, num_sge:%d\r\n", qp_type, wr->num_sge);
		if (qp_type == IB_QPT_GSI && wr->num_sge > 1) {
			send_buf = (struct ib_mad_send_buf *)((char *)wr - MAD_BUF_WR_OFFSET);
			mad_hdr = (struct ib_mad_hdr *)send_buf->mad;
			print_hex_dump_debug("sg_list ", 0, 16, 1, (u64 *)send_buf->mad,
				wr->sg_list[0].length + wr->sg_list[1].length, false);
			nbl_pr_dbg("attr_id:%x\r\n", mad_hdr->attr_id);
			if (is_cm_mad_hdr_req(mad_hdr)) {
				rnr_retry_count = IBA_GET(CM_REQ_RNR_RETRY_COUNT, send_buf->mad);
				nbl_pr_dbg("req rnr_retry_count before:%d\r\n", rnr_retry_count);
				IBA_SET(CM_REQ_RNR_RETRY_COUNT, send_buf->mad,
					max_t(u8, NBL_DEFAULT_RNR_RETRY_TH, rnr_retry_count));
			} else if (is_cm_mad_hdr_rep(mad_hdr)) {
				rnr_retry_count = IBA_GET(CM_REP_RNR_RETRY_COUNT, send_buf->mad);
				nbl_pr_dbg("reply rnr_retry_count before:%d\r\n", rnr_retry_count);
				IBA_SET(CM_REP_RNR_RETRY_COUNT, send_buf->mad,
					max_t(u8, NBL_DEFAULT_RNR_RETRY_TH, rnr_retry_count));
			}
		}
	}
	ud_seg->rss_tunnel_fwd_dport = cpu_to_be32(
		(rf->sc_dev.rss_lag_en << NBL_QP_WQE_UD_RSS_LAG_EN) |
		(rf->sc_dev.tunnel_en << NBL_QP_WQE_UD_TUNNEL_EN) |
		(rf->sc_dev.fwd << NBL_QP_WQE_UD_FWD) |
		(rf->sc_dev.dport << NBL_QP_WQE_UD_DPORT) |
		(rf->sc_dev.dport_id & 0x3FF));
}

static void nbl_fill_atomic_seg_info(struct nbl_wqe_atomic_seg *atomic_seg,
				     const struct ib_send_wr *wr)
{
	/* fill atomic seg */
	if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
		atomic_seg->swap_add = cpu_to_be64(atomic_wr(wr)->swap);
		atomic_seg->compare = cpu_to_be64(atomic_wr(wr)->compare_add);
	} else {
		atomic_seg->swap_add = cpu_to_be64(atomic_wr(wr)->compare_add);
	}
}

static void nbl_fill_raddr_seg_info(struct nbl_wqe_raddr_seg *rseg,
			     const struct ib_send_wr *wr, u32 payload_len)
{
	rseg->raddr = cpu_to_be64(rdma_wr(wr)->remote_addr);
	rseg->rkey = cpu_to_be32(rdma_wr(wr)->rkey);
	rseg->len = cpu_to_be32(payload_len);
}

static int nbl_fill_atomic_raddr_seg_info(struct nbl_wqe_raddr_seg *rseg,
					  const struct ib_send_wr *wr,
					  __u32 payload_len)
{
	/* for atomic addr, need to align at 16B */
	if (atomic_wr(wr)->remote_addr & NBL_ATOMIC_ADDR_MASK ||
	    payload_len != NBL_ATOMIC_LEN)
		return -EINVAL;
	/* fill raddr seg */
	rseg->raddr = cpu_to_be64(atomic_wr(wr)->remote_addr);
	rseg->rkey = cpu_to_be32(atomic_wr(wr)->rkey);
	rseg->len = cpu_to_be32(payload_len);

	return 0;
}

static void nbl_construct_ctrl_info(const struct ib_send_wr *wr, struct nbl_uk_qp *uk_qp,
				    struct nbl_wqe_info *info)
{
	bool pre_fence = 0;

	pre_fence = uk_qp->next_fence;

	info->ib_opcode = wr->opcode;
	info->qpn = uk_qp->qpn;
	info->num_sge = wr->num_sge;

	if ((wr->send_flags & IB_SEND_FENCE) ||
		(wr->opcode == IB_WR_SEND_WITH_INV))
		info->fence = NBL_WQE_CTRL_FENCE;
	if (wr->send_flags & IB_SEND_SIGNALED)
		info->ce = true;
	if (wr->send_flags & IB_SEND_SOLICITED)
		info->se = true;
	if (wr->send_flags & IB_SEND_INLINE)
		info->is_inline = true;

	if (wr->opcode == IB_WR_SEND_WITH_IMM ||
	    wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM) {
		info->is_imm = true;
		info->imm_data = wr->ex.imm_data;
	}

	if (wr->opcode == IB_WR_SEND_WITH_INV ||
	    wr->opcode == IB_WR_LOCAL_INV) {
		info->is_inv = true;
		info->inv_rkey = wr->ex.invalidate_rkey;
	}

	if (uk_qp->fmr_nofence) {
		/* local opcode and need ce or fence, must set strong fence
		 * if not ce flag for user, driver need to set the ce
		 */
		if ((wr->opcode == IB_WR_LOCAL_INV || wr->opcode == IB_WR_REG_MR) &&
					(info->ce || (wr->send_flags & IB_SEND_FENCE))) {

			nbl_pr_dbg("fmr_en opcode:%d pre_fence:%d ce:%d fence:%d\n",
				wr->opcode, pre_fence, info->ce, wr->send_flags & IB_SEND_FENCE);

			uk_qp->next_fence = true;
			info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
			/* set ce for hw  */
			if (!info->ce) {
				uk_qp->sq_wrtrk_array
					[info->wqe_idx].driver_ce = 1;
				info->ce = true;
			}
		} else {
			uk_qp->next_fence = false;
			if (pre_fence && wr->opcode != IB_WR_LOCAL_INV &&
					wr->opcode != IB_WR_REG_MR)
				info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		}
	} else {
		if (wr->opcode == IB_WR_LOCAL_INV || wr->opcode == IB_WR_REG_MR) {
			uk_qp->next_fence = true;
			info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		} else {
			uk_qp->next_fence = false;
			if (pre_fence)
				info->fence = NBL_WQE_CTRL_STRONG_ORD_FENCE;
		}
	}
}

static void nbl_fill_nop_wqe(struct nbl_qp *qp)
{
	u32 wqe_idx = 0;
	struct nbl_nop_wqe *nop;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	u32 temp;

	wqe_idx = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);
	nop = nbl_get_wqe(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf), sizeof(struct nbl_qp_block),
		wqe_idx, !sc_qp->sq_pm);
	uk_qp->sq_wrtrk_array[wqe_idx].quanta = NBL_WQE_MIN_QUANTA;
	nop->opcode = NBL_OPCODE_NOP;
	temp = (uk_qp->qpn) << NBL_WQE_CTRL_QPN_SHIFT | NBL_WQE_MIN_QUANTA;
	nop->qpn_ds_ts = cpu_to_be32(temp);
	dma_wmb();
	if (uk_qp->swqe_polarity)
		nop->wqe_valid |= NBL_WQE_CTRL_VALID;
	else
		nop->wqe_valid &= ~NBL_WQE_CTRL_VALID;
}


static __be64 *
nbl_qp_get_next_send_wqe(const struct ib_send_wr *wr,
			 struct nbl_qp *qp,
			 struct nbl_hw_attrs *attrs, unsigned int size,
			 unsigned int payload_len, u32 *wqe_idx)
{
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;

	unsigned int size_quanta, avail_quanta;
	__be64 *wqe;
	int i;

	uk_qp = &qp->sc_qp.uk_qp;
	sc_qp = &qp->sc_qp;

	size_quanta = ALIGN(size, NBL_MIN_WQE_SIZE) / NBL_MIN_WQE_SIZE;
	avail_quanta = MAX_HW_SQ_CHUNK -
		       (NBL_RING_CURRENT_HEAD(uk_qp->sq_ring) % MAX_HW_SQ_CHUNK);

	if (size_quanta <= avail_quanta) {
		/*no need to pad with NOP*/
		if ((size_quanta + uk_qp->safe_rsv) >
		    NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring)) {
			nbl_pr_err("the sq ring is full.\n");
			return NULL;
		}

		/* make sure there has enough quanta space to clear wqe polarity */
		if (NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring) <
			(SAFE_CLEAN_WQE_LENGTH / NBL_MIN_WQE_SIZE)) {
			nbl_pr_err(
				"lack of enough space to clear wqe polarity.\n");
			return NULL;
		}
	} else {
		if ((size_quanta + avail_quanta + uk_qp->safe_rsv) >
		    NBL_SQ_RING_FREE_QUANTA(uk_qp->sq_ring)) {
			nbl_pr_err("the sq ring is full.\n");
			return NULL;
		}

		for (i = 0; i < avail_quanta; i++) {
			/*fill nop wqe*/
			nbl_fill_nop_wqe(qp);
			NBL_SQ_RING_MOVE_HEAD_BY_COUNT(uk_qp->sq_ring,
						       NOP_WQE_QUANTA);
		}
	}

	if (NBL_RING_FULL_ERR(uk_qp->sq_ring, size_quanta)) {
		nbl_pr_err("the sq ring is full.\n");
		return NULL;
	}


	*wqe_idx = NBL_RING_CURRENT_HEAD(uk_qp->sq_ring);
	NBL_SQ_RING_MOVE_HEAD_BY_COUNT(uk_qp->sq_ring, size_quanta);
	if (!*wqe_idx)
		uk_qp->swqe_polarity = !uk_qp->swqe_polarity;

	wqe = nbl_get_wqe(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf), sizeof(struct nbl_qp_block),
		*wqe_idx, !sc_qp->sq_pm);
	uk_qp->sq_wrtrk_array[*wqe_idx].wrid = wr->wr_id;
	uk_qp->sq_wrtrk_array[*wqe_idx].wr_len = payload_len;
	uk_qp->sq_wrtrk_array[*wqe_idx].quanta = size_quanta;

	return wqe;
}

static int nbl_calc_sq_wqe_size(const struct ib_send_wr *wr, unsigned int *payload_len,
		      bool is_rc)
{
	unsigned int size = NBL_WQE_CTRL_SIZE;
	unsigned int length = 0;
	int i;

	for (i = 0; i < wr->num_sge; i++)
		length += wr->sg_list[i].length;

	if (wr->send_flags & IB_SEND_INLINE)
		size += length;
	else
		size += NBL_WQE_DATA_SIZE * (wr->num_sge);

	*payload_len = length;

	switch (wr->opcode) {
	case IB_WR_SEND_WITH_INV:
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
		if (is_rc) {
			if (!(wr->send_flags & IB_SEND_INLINE))
				size += NBL_WQE_RSV_SIZE;
		} else {
			/* inlude UD and GSI*/
			size = NBL_MAX_WQE_SIZE;
		}
		break;
	case IB_WR_RDMA_READ:
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		size += NBL_WQE_RADDR_SIZE;
		break;
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		size += NBL_WQE_RADDR_SIZE + NBL_WQE_ATOMIC_SIZE;
		break;
	case IB_WR_LOCAL_INV:
		size = NBL_WQE_LOCAL_OPERATE_SIZE;
		break;
	case IB_WR_REG_MR:
		size = NBL_WQE_FAST_MR_SIZE;
		break;
	default:
		break;
	}

	return size;
}

int _nbl_ib_post_send(struct ib_qp *ib_qp, const struct ib_send_wr *wr,
		      const struct ib_send_wr **bad_wr)
{
	struct nbl_wqe_ctrl_seg *ctrl;
	struct nbl_wqe_raddr_seg *rseg;
	struct nbl_wqe_atomic_seg *atomic_seg;
	struct nbl_wqe_datagram_seg *ud_seg;
	struct nbl_wqe_fast_mr_ctrl_seg *fast_ctrl;
	struct nbl_wqe_info info;
	struct nbl_hw_attrs *attrs;
	struct nbl_sc_dev *sc_dev;
	struct nbl_qp *qp;
	struct nbl_uk_qp *uk_qp;
	void *wqe;
	bool rc_send;
	int wqe_size = 0;
	int cur_size;
	int err = 0;
	unsigned int payload_len = 0;
	unsigned int wqe_idx = 0;
	unsigned long flags;
	bool need_delay_work = false;

	qp = container_of(ib_qp, struct nbl_qp, ibqp);
	uk_qp = &qp->sc_qp.uk_qp;
	attrs = &(qp->nbldev->rf->sc_dev.hw_attrs);
	sc_dev = &(qp->nbldev->rf->sc_dev);

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->qp_state == NBL_QP_STATE_ERR) {
		err = nbl_qp_generate_sq_soft_wc(wr, qp);
		if (err) {
			*bad_wr = wr;
			err = -EINVAL;
		} else {
			need_delay_work = true;
		}
		goto out;
	}

	if (qp->nbldev->rf->sc_dev.has_high_temp_alarm) {
		qp->qp_state = NBL_QP_STATE_ERR;
		err = -EBUSY;
		goto out;
	}

	while (wr) {
		rc_send = false;
		cur_size = 0;
		memset(&info, 0, sizeof(info));
		if (attrs->uk_attrs.max_hw_wq_sges < wr->num_sge) {
			nbl_ib_err(sc_dev,
				"invalid wr num_sge, the value of num_sge is %d.\n",
				wr->num_sge);
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}
		wqe_size = nbl_calc_sq_wqe_size(wr, &payload_len, (ib_qp->qp_type == IB_QPT_RC));
		/* max wqe size is 128 bytes */
		if (wqe_size > NBL_MAX_WQE_SIZE) {
			nbl_ib_err(sc_dev,
				"invalid size, the size is %d.\n", wqe_size);
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}

		/* get wqe index to and next wqe */
		wqe = nbl_qp_get_next_send_wqe(wr, qp, attrs, wqe_size,
						      payload_len, &wqe_idx);
		if (!wqe) {
			nbl_ib_err(sc_dev,
				"get qp next send wqe failed.\n");
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}
		/*wqe size align to 64 or 128*/
		wqe_size = ALIGN(wqe_size, NBL_MIN_WQE_SIZE);
		info.wqe_idx = wqe_idx;
		info.wqe_size = wqe_size;
		info.payload_len = payload_len;
		info.wqe_vld = uk_qp->swqe_polarity;
		nbl_construct_ctrl_info(wr, uk_qp, &info);

		ctrl = wqe;

		switch (ib_qp->qp_type) {
		case IB_QPT_RC:
			switch (wr->opcode) {
			case IB_WR_SEND_WITH_IMM:
				if (!(uk_qp->qp_caps & NBL_SEND_WITH_IMM)) {
					err = EOPNOTSUPP;
					*bad_wr = wr;
					goto out;
				}
				fallthrough;
			case IB_WR_SEND_WITH_INV:
			case IB_WR_SEND:
				rc_send = true;
				wqe += sizeof(struct nbl_wqe_ctrl_seg);
				cur_size += sizeof(struct nbl_wqe_ctrl_seg);
				break;
			case IB_WR_RDMA_WRITE_WITH_IMM:
				if (!(uk_qp->qp_caps & NBL_WRITE_WITH_IMM)) {
					err = EOPNOTSUPP;
					*bad_wr = wr;
					goto out;
				}
				fallthrough;
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
				wqe += sizeof(struct nbl_wqe_ctrl_seg);
				cur_size += sizeof(struct nbl_wqe_ctrl_seg);
				rseg = wqe;
				nbl_fill_raddr_seg_info(rseg, wr, payload_len);
				wqe += sizeof(struct nbl_wqe_raddr_seg);
				cur_size += sizeof(struct nbl_wqe_raddr_seg);
				break;
			case IB_WR_ATOMIC_CMP_AND_SWP:
			case IB_WR_ATOMIC_FETCH_AND_ADD:
				if (!(uk_qp->qp_caps & NBL_ATOMIC)) {
					err = EINVAL;
					*bad_wr = wr;
					goto out;
				}
				wqe += sizeof(struct nbl_wqe_ctrl_seg);
				cur_size += sizeof(struct nbl_wqe_ctrl_seg);
				rseg = wqe;
				/*fill raddr seg*/
				err = nbl_fill_atomic_raddr_seg_info(
					rseg, wr, payload_len);
				if (err) {
					*bad_wr = wr;
					goto out;
				}
				wqe += sizeof(struct nbl_wqe_raddr_seg);
				cur_size += sizeof(struct nbl_wqe_raddr_seg);
				atomic_seg = wqe;
				/*fill atomic_seg*/
				nbl_fill_atomic_seg_info(atomic_seg, wr);
				wqe += sizeof(struct nbl_wqe_atomic_seg);
				cur_size += sizeof(struct nbl_wqe_atomic_seg);
				break;
			case IB_WR_LOCAL_INV:
				break;
			case IB_WR_REG_MR:
				fast_ctrl = wqe;
				nbl_fill_fast_mr_seg_info(qp->nbldev, fast_ctrl,
							  wr);
				break;
			default:
				break;
			}
			break;
		case IB_QPT_UD:
		case IB_QPT_GSI:
			switch (wr->opcode) {
			case IB_WR_SEND_WITH_IMM:
				if (!(uk_qp->qp_caps & NBL_SEND_WITH_IMM)) {
					err = EOPNOTSUPP;
					*bad_wr = wr;
					goto out;
				}
				fallthrough;
			case IB_WR_SEND:
				wqe += sizeof(struct nbl_wqe_ctrl_seg);
				cur_size += sizeof(struct nbl_wqe_ctrl_seg);
				ud_seg = wqe;
				nbl_fill_datagram_seg_info(qp->nbldev->rf, ud_seg, wr,
					ib_qp->qp_type);
				wqe += sizeof(struct nbl_wqe_datagram_seg);
				cur_size += sizeof(struct nbl_wqe_datagram_seg);
				break;
			default:
				break;
			}
		default:
			break;
		}

		/*fill data_seg or inline_seg*/
		if (wr->num_sge != 0)
			nbl_copy_data_from_sge(wr, wqe, rc_send, cur_size, &info);

		/*fill ctrl wqe_valid*/
		nbl_fill_ctrl_info(ctrl, &info);
		print_hex_dump_debug("SQ WQE  ", 0, 16, 1,
			(u64 *)ctrl, wqe_size, false);
		pr_debug("\n\n");
		wr = wr->next;

	}

	dma_wmb();

#if NBL_IO_POST_DB_MODE
	if (nbl_check_db_fill_shadow(&qp->sc_qp))
#endif
		nbl_post_sq_db(uk_qp);
out:
	spin_unlock_irqrestore(&qp->lock, flags);
	if (unlikely(need_delay_work))
		nbl_sched_qp_flush_work(qp);

	return err;
}

static __be64 *nbl_get_next_recv_wqe(struct nbl_qp *qp,
			      const struct ib_recv_wr *wr,
			      unsigned int *wqe_idx)
{
	unsigned int size_quanta;
	__be64 *wqe;
	int ret_code;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	size_quanta = uk_qp->rq_wqe_size_multiplier;
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
	wqe = nbl_get_wqe(uk_qp->rq_base, &(sc_qp->rqbuf.frag_buf), sizeof(struct nbl_qp_block),
		*wqe_idx, !sc_qp->rq_pm);
	uk_qp->rq_wrid_array[*wqe_idx] = wr->wr_id;
	return wqe;
}

static void nbl_post_rq_db(struct nbl_uk_qp *uk_qp, bool sw_pi_phase)
{
	__u64 temp;
	struct nbl_qp *qp = container_of(uk_qp, struct nbl_qp, sc_qp.uk_qp);
	struct nbl_pci_f *rf = qp->nbldev->rf;

	if (rf->sc_dev.has_high_temp_alarm)
		return;

	dma_wmb();
	temp = (__u64)(FIELD_PREP(NBL_RQ_DB_PI, uk_qp->rq_ring.head) |
		       FIELD_PREP(NBL_RQ_DB_PI_PHASE, sw_pi_phase) |
		       FIELD_PREP(NBL_RQ_DB_QPN, uk_qp->qpn));
	write64_reg(temp, uk_qp->rq_db);
	uk_qp->rq_db_flag = true;
}

static int nbl_copy_rc_rq_sge(const struct ib_recv_wr *wr,
			      struct nbl_wqe_data_seg *dseg,
			      unsigned int *payload_len, int max_rqe_size)
{
	int i;
	int wqe_size = NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE;

	for (i = 0; i < wr->num_sge; i++) {
		if (unlikely(!wr->sg_list[i].length))
			continue;
		wqe_size += sizeof(struct nbl_wqe_data_seg);
		if (wqe_size > max_rqe_size)
			return -ENOMEM;
		dseg->byte_count = cpu_to_be32(wr->sg_list[i].length);
		*payload_len += wr->sg_list[i].length;
		dseg->lkey = cpu_to_be32(wr->sg_list[i].lkey);
		dseg->local_addr = cpu_to_be64(wr->sg_list[i].addr);
		dseg++;
	}
	return 0;
}

static int nbl_copy_ud_rq_sge(const struct ib_recv_wr *wr,
			      struct nbl_wqe_data_seg *dseg,
			      unsigned int *payload_len, int max_rqe_size)
{
	int i;
	int wqe_size = NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE;
	__be32 len = 0;
	__be64 addr = 0;
	/*check 1st sge > 4096*/

	for (i = 0; i < wr->num_sge; i++) {
		if (unlikely(!wr->sg_list[i].length))
			continue;

		len  = wr->sg_list[i].length;
		*payload_len += len;
		addr = wr->sg_list[i].addr;

		while (len > NBL_ADAPTER_PAGE_SIZE) {
			wqe_size += sizeof(struct nbl_wqe_data_seg);
			if (wqe_size > max_rqe_size)
				return -ENOMEM;

			dseg->byte_count = cpu_to_be32(NBL_ADAPTER_PAGE_SIZE);
			dseg->lkey = cpu_to_be32(wr->sg_list[i].lkey);
			dseg->local_addr = cpu_to_be64(addr);

			len -= NBL_ADAPTER_PAGE_SIZE;
			addr += NBL_ADAPTER_PAGE_SIZE;
			dseg++;
		}
		wqe_size += sizeof(struct nbl_wqe_data_seg);
		if (wqe_size > max_rqe_size)
			return -ENOMEM;
		dseg->byte_count = cpu_to_be32(len);
		dseg->lkey = cpu_to_be32(wr->sg_list[i].lkey);
		dseg->local_addr = cpu_to_be64(addr);
		dseg++;
	}
	return 0;
}

int _nbl_ib_post_recv(struct ib_qp *ib_qp, const struct ib_recv_wr *wr,
		      const struct ib_recv_wr **bad_wr)
{
	struct nbl_qp *qp;
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;
	struct nbl_rq_wqe_ctrl_seg *ctrl;
	struct nbl_wqe_data_seg *dseg;
	struct nbl_sc_dev *sc_dev;
	void *wqe;
	unsigned long flags;
	int err = 0;
	unsigned int wqe_idx;
	unsigned int payload_len = 0;
	__u32 qpn_ds_ts;
	__u16 write_word = 0;
	bool sw_pi_phase;
	bool need_delay_work = false;

	qp = container_of(ib_qp, struct nbl_qp, ibqp);
	uk_qp = &qp->sc_qp.uk_qp;
	sc_qp = &qp->sc_qp;
	sc_dev = &qp->nbldev->rf->sc_dev;

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->qp_state == NBL_QP_STATE_ERR) {
		err = nbl_qp_generate_rq_soft_wc(wr, qp);
		if (err) {
			err = -EINVAL;
			*bad_wr = wr;
		} else {
			need_delay_work = true;
		}
		goto out;
	}


	while (wr) {
		if (uk_qp->max_recv_sge < wr->num_sge) {
			nbl_ib_err(sc_dev, "invalid max_rq_frag_cnt.\n");
			*bad_wr = wr;
			err = -EINVAL;
			goto out;
		}

		ctrl = wqe = nbl_get_next_recv_wqe(qp, wr, &wqe_idx);
		if (!wqe) {
			nbl_ib_err(sc_dev, "get next recv wqe failed.\n");
			*bad_wr = wr;
			err = -EINVAL;
			goto out;
		}

		/* offset of ctrl seg size */
		wqe += sizeof(struct nbl_rq_wqe_ctrl_seg);
		/* offset of rsv seg size */
		wqe += NBL_WQE_RSV_SIZE;
		dseg = wqe;
		payload_len = 0;

		if (ib_qp->qp_type == IB_QPT_UD ||
			ib_qp->qp_type == IB_QPT_GSI)
			err = nbl_copy_ud_rq_sge(wr, dseg, &payload_len,
						 uk_qp->rq_wqe_size);
		else
			err = nbl_copy_rc_rq_sge(wr, dseg, &payload_len,
						 uk_qp->rq_wqe_size);
		if (err) {
			nbl_ib_err(sc_dev, "copy sge fail.qpn :%#x, qp_type:%d\n",
				  uk_qp->qpn, ib_qp->qp_type);
			*bad_wr = wr;
			goto out;
		}

		ctrl->wqe_idx = cpu_to_be16(wqe_idx);
		ctrl->payload_len = cpu_to_be32(payload_len);
		ctrl->opcode = NBL_OPCODE_RQ_WQE;
		qpn_ds_ts = (uk_qp->qpn) << NBL_WQE_CTRL_QPN_SHIFT |
			    ((wr->num_sge) << NBL_WQE_CTRL_DATA_SIZE_SHIFT) |
			    uk_qp->rq_wqe_size_multiplier;
		ctrl->qpn_ds_ts = cpu_to_be32(qpn_ds_ts);

		if (uk_qp->rwqe_polarity)
			ctrl->wqe_valid |= NBL_RQ_WQE_CTRL_VALID;
		else
			ctrl->wqe_valid &= ~NBL_RQ_WQE_CTRL_VALID;
		print_hex_dump_debug("RQ WQE  ", 0, 16, 1,
			(u64 *)ctrl, uk_qp->rq_wqe_size, false);
		pr_debug("\n\n");
		wr = wr->next;
	}

	dma_wmb();
	sw_pi_phase = uk_qp->rwqe_polarity;
	if (uk_qp->rq_ring.head != 0)
		sw_pi_phase = (sw_pi_phase ? false : true);

	write_word = (__u16)(
		FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_RQ_PI_LOAD_FLAG, true));
	set_16bit_val((__be16 *)sc_qp->qp_shadow.va, 26, write_word);

	write_word = (__u16)(
		FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_RQ_PI, uk_qp->rq_ring.head) |
		FIELD_PREP(NBL_QPC_SHADOW_AREA_SW_RQ_PI_PHASE, sw_pi_phase));
	set_16bit_val((__be16 *)sc_qp->qp_shadow.va, 28, write_word);

	if ((!uk_qp->rq_db_flag) ||
		(ib_qp->qp_type == IB_QPT_UD || ib_qp->qp_type == IB_QPT_GSI))
		nbl_post_rq_db(uk_qp, sw_pi_phase);
out:
	spin_unlock_irqrestore(&qp->lock, flags);
	if (unlikely(need_delay_work))
		nbl_sched_qp_flush_work(qp);
	return err;
}
