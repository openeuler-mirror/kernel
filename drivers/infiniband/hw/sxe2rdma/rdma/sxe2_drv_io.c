// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_io.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/bitfield.h>
#include <linux/if_vlan.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_mad.h>

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_io.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_rdma_log.h"

static const rdma_disp_func g_rdma_op[SXE2_RDMA_MAX_ID] = {
	sxe2_hw_send,
	sxe2_hw_inline_send,
	sxe2_hw_rdma_write,
	sxe2_hw_inline_rdma_write,
	sxe2_hw_rdma_read,
	sxe2_hw_local_invalidate,
	sxe2_hw_mr_fast_register,
};

static const int g_frag2quanta[SXE2_MAX_FRAGCNT] = { 1, 1, 2, 2, 3, 3, 4, 4,
						     5, 5, 6, 6, 7, 7, 8, 8 };

static void sxe2_dump_wqe(struct sxe2_qp_common *qp, __le64 *wqe, __u16 quanta,
			  __u32 wqe_idx, const char *desc)
{
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;
	__le32 *p = (__le32 *)wqe;
	int i, offset = 0;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	if (desc) {
		DRV_RDMA_LOG_DEV_DEBUG("SQWQE DUMP TYPE=[%s], qpn [0x%x]\n"
				       "wqe_idx [0x%x] quanta [%u]:\n",
				       desc, qp->qpn, wqe_idx, quanta);
	} else
		DRV_RDMA_LOG_DEV_DEBUG(
			"RQWQE DUMP, qpn [0x%x], wqe_idx [0x%x]:\n", qp->qpn,
			wqe_idx);

	for (i = 0; i < quanta * SXE2_QP_WQE_MIN_SIZE; i += 32) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"[qpn 0x%x][offset %u] %08X %08X %08X %08X\n"
			"%08X %08X %08X %08X\n",
			qp->qpn, offset, le32_to_cpu(p[0]), le32_to_cpu(p[1]),
			le32_to_cpu(p[2]), le32_to_cpu(p[3]), le32_to_cpu(p[4]),
			le32_to_cpu(p[5]), le32_to_cpu(p[6]),
			le32_to_cpu(p[7]));
		p += 8;
		offset += 32;
	}
}

static inline int sxe2_fragcnt_to_quanta_cnt(__u32 frag_cnt, __u16 *quanta)
{
	if (frag_cnt >= SXE2_MAX_FRAGCNT)
		return -EINVAL;

	*quanta = (__u16)g_frag2quanta[frag_cnt];
	return 0;
}

static inline __u16 sxe2_inline_to_quanta_cnt(__u32 data_size)
{
	if (data_size <= 8)
		return SXE2_QP_WQE_MIN_QUANTA;
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

static void sxe2_qp_ring_normal_db(struct sxe2_qp_common *qp)
{
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;
	/* Serialize access to the foo structure */
	mb();
	writel(qp->qpn, qp->qp_db_no_llwqe);

	qp->initial_ring.head = qp->sq_ring.head;
	DRV_RDMA_LOG_DEV_DEBUG("DB NOTIFY: QPN (%u -> %p) PI %u\n", qp->qpn,
			       qp->qp_db_no_llwqe, qp->sq_ring.head);
}

static void sxe2_qp_push_wqe(struct sxe2_qp_common *qp, __le64 *wqe,
			     __u16 quanta, __u32 wqe_idx)
{
	__le64 *push;
	struct sxe2_llwqe *llwqe;
	unsigned long flags = 0;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;
	llwqe	 = qp->llwqe;

	if (!qp->llwqe_mode) {
		sxe2_qp_ring_normal_db(qp);
	} else {
		spin_lock_irqsave(&llwqe->lock, flags);

		push = (__le64 *)((uintptr_t)qp->push_wqe +
				  (wqe_idx & 0x7) * 0x20);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		INJECT_START(rdma_dev->rdma_func, "llwqe_flag", rdma_dev, push, wqe);
#else
		sxe2_memcpy_x64(push, wqe, quanta * SXE2_QP_WQE_MIN_SIZE);
#endif
		/* Ensure DMA buffer writes are ordered before kicking the device */
		wmb();

		set_32bit_val(qp->push_db, 0,
			      FIELD_PREP(SXE2_WQEALLOC_WQE_DESC_INDEX,
					 wqe_idx >> 3) |
				      qp->qpn);
		qp->initial_ring.head = qp->sq_ring.head;
		qp->llwqe_mode	      = true;
		qp->push_dropped      = false;
		spin_unlock_irqrestore(&llwqe->lock, flags);
		DRV_RDMA_LOG_DEV_DEBUG(
			"DB NOTIFY(LLWQE): QPN (%#x -> %#lx llwqe %#lx) idx %#x\n",
			qp->qpn, (uintptr_t)qp->push_db,
			(uintptr_t)qp->push_wqe, wqe_idx >> 3);
	}
}

static inline void sxe2_set_qkeyqpn(__le64 *wqe, __u32 offset, __u32 qkey,
				    __u32 qpn)
{
	union sxe2_dqpn_data msg;

	msg.val		    = 0;
	msg.field.dest_qkey = qkey;
	msg.field.dest_qpn  = qpn;

	wqe[offset >> 3] = cpu_to_le64(msg.val);
}

static inline void sxe2_set_remote_offset(__le64 *wqe, __u32 offset,
					  __u64 remote_offset)
{
	wqe[offset >> 3] = cpu_to_le64(remote_offset);
}

static void sxe2_set_send_hdr(__le64 *wqe, __u32 value,
			      struct sxe2_wr_info *wr_info,
			      struct sxe2_qp_common *qp)
{
	union sxe2_send_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val = 0;
	hdr.field.remote_inv_rkey =
		wr_info->rkey_to_inv | wr_info->op_info.send.ah_id;
	hdr.field.op		      = wr_info->op_type;
	hdr.field.addfragcnt	      = value;
	hdr.field.report_rtt	      = wr_info->report_rtt;
	hdr.field.imme_data_flag      = wr_info->imm_data_valid;
	hdr.field.push_wqe	      = wr_info->push_wqe;
	hdr.field.read_fence	      = wr_info->read_fence;
	hdr.field.local_fence	      = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("SND_WQE_HDR: (%#llx)\n"
			       "remote_inv_key: %#x\n"
			       "op            : %#x\n"
			       "addfragcnt    : %d\n"
			       "report_rtt    : %d\n"
			       "imme_data_flag: %d\n"
			       "push_wqe      : %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.remote_inv_rkey,
			       hdr.field.op, hdr.field.addfragcnt,
			       hdr.field.report_rtt, hdr.field.imme_data_flag,
			       hdr.field.push_wqe, hdr.field.read_fence,
			       hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_inlinesnd_hdr(__le64 *wqe, __u32 value,
				   struct sxe2_wr_info *wr_info,
				   struct sxe2_qp_common *qp)
{
	union sxe2_send_inline_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val = 0;
	hdr.field.remote_inv_rkey =
		wr_info->rkey_to_inv | wr_info->op_info.send.ah_id;
	hdr.field.op		      = wr_info->op_type;
	hdr.field.report_rtt	      = wr_info->report_rtt;
	hdr.field.imme_data_flag      = wr_info->imm_data_valid;
	hdr.field.inline_data_len     = value;
	hdr.field.push_wqe	      = wr_info->push_wqe;
	hdr.field.inline_data_flag    = 1;
	hdr.field.read_fence	      = wr_info->read_fence;
	hdr.field.local_fence	      = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("INSND_WQE_HDR: (%#llx)\n"
			       "remote_inv_key: %#x\n"
			       "op            : %#x\n"
			       "report_rtt    : %d\n"
			       "imme_data_flag: %d\n"
			       "inline_datalen: %d\n"
			       "push_wqe      : %d\n"
			       "inline_dataflg: %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.remote_inv_rkey,
			       hdr.field.op, hdr.field.report_rtt,
			       hdr.field.imme_data_flag,
			       hdr.field.inline_data_len, hdr.field.push_wqe,
			       hdr.field.inline_data_flag, hdr.field.read_fence,
			       hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_write_hdr(__le64 *wqe, __u32 value,
			       struct sxe2_wr_info *wr_info,
			       struct sxe2_qp_common *qp)
{
	union sxe2_write_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val			 = 0;
	hdr.field.remote_key	 = wr_info->op_info.rdma_write.rem_addr.lkey;
	hdr.field.op		 = wr_info->op_type;
	hdr.field.addfragcnt	 = value;
	hdr.field.report_rtt	 = wr_info->report_rtt;
	hdr.field.imme_data_flag = wr_info->imm_data_valid;
	hdr.field.push_wqe	 = wr_info->push_wqe;
	hdr.field.read_fence	 = wr_info->read_fence;
	hdr.field.local_fence	 = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("WRITE_WQE_HDR: (%#llx)\n"
			       "remote_key    : %#x\n"
			       "op            : %#x\n"
			       "addfragcnt    : %d\n"
			       "report_rtt    : %d\n"
			       "imme_data_flag: %d\n"
			       "push_wqe      : %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.remote_key,
			       hdr.field.op, hdr.field.addfragcnt,
			       hdr.field.report_rtt, hdr.field.imme_data_flag,
			       hdr.field.push_wqe, hdr.field.read_fence,
			       hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_inlinewrite_hdr(__le64 *wqe, __u32 value,
				     struct sxe2_wr_info *wr_info,
				     struct sxe2_qp_common *qp)
{
	union sxe2_write_inline_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val			   = 0;
	hdr.field.remote_key	   = wr_info->op_info.rdma_write.rem_addr.lkey;
	hdr.field.op		   = wr_info->op_type;
	hdr.field.report_rtt	   = wr_info->report_rtt;
	hdr.field.imme_data_flag   = wr_info->imm_data_valid;
	hdr.field.inline_data_len  = value;
	hdr.field.push_wqe	   = wr_info->push_wqe;
	hdr.field.inline_data_flag = 1;
	hdr.field.read_fence	   = wr_info->read_fence;
	hdr.field.local_fence	   = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("INWRITE_WQE_HDR: (%#llx)\n"
			       "remote_key    : %#x\n"
			       "op            : %#x\n"
			       "report_rtt    : %d\n"
			       "imme_data_flag: %d\n"
			       "inline_datalen: %d\n"
			       "push_wqe      : %d\n"
			       "inline_dataflg: %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.remote_key,
			       hdr.field.op, hdr.field.report_rtt,
			       hdr.field.imme_data_flag,
			       hdr.field.inline_data_len, hdr.field.push_wqe,
			       hdr.field.inline_data_flag, hdr.field.read_fence,
			       hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_read_hdr(__le64 *wqe, __u32 addfragcnt,
			      struct sxe2_wr_info *wr_info,
			      struct sxe2_qp_common *qp, bool ord_fence)
{
	union sxe2_read_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val		      = 0;
	hdr.field.remote_key  = wr_info->op_info.rdma_read.rem_addr.lkey;
	hdr.field.op	      = wr_info->op_type;
	hdr.field.addfragcnt  = addfragcnt;
	hdr.field.report_rtt  = wr_info->report_rtt;
	hdr.field.push_wqe    = wr_info->push_wqe;
	hdr.field.read_fence  = wr_info->read_fence || ord_fence ? 1 : 0;
	hdr.field.local_fence = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("READ_WQE_HDR: (%#llx)\n"
			       "remote_key    : %#x\n"
			       "op            : %#x\n"
			       "addfragcnt    : %d\n"
			       "report_rtt    : %d\n"
			       "push_wqe      : %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.remote_key,
			       hdr.field.op, hdr.field.addfragcnt,
			       hdr.field.report_rtt, hdr.field.push_wqe,
			       hdr.field.read_fence, hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_invalidate_hdr(__le64 *wqe, struct sxe2_wr_info *wr_info,
				    struct sxe2_qp_common *qp)
{
	union sxe2_inval_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val			      = 0;
	hdr.field.op		      = wr_info->op_type;
	hdr.field.push_wqe	      = wr_info->push_wqe;
	hdr.field.read_fence	      = wr_info->read_fence;
	hdr.field.local_fence	      = wr_info->local_fence;
	hdr.field.signaled_completion = wr_info->signaled;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("LOCALINVKEY_WQE_HDR: (%#llx)\n"
			       "op            : %#x\n"
			       "push_wqe      : %d\n"
			       "read_fence    : %d\n"
			       "local_fence   : %d\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.op,
			       hdr.field.push_wqe, hdr.field.read_fence,
			       hdr.field.local_fence,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static void sxe2_set_nop_hdr(__le64 *wqe, __u32 offset,
			     struct sxe2_qp_common *qp)
{
	union sxe2_nop_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val			      = 0;
	hdr.field.op		      = SXE2_OP_TYPE_NOP;
	hdr.field.signaled_completion = false;
	hdr.field.wqe_valid	      = qp->swqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, offset, hdr.val);

	DRV_RDMA_LOG_DEV_DEBUG("NOP_WQE_HDR: (%#llx)\n"
			       "op            : %#x\n"
			       "signaled      : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.op,
			       hdr.field.signaled_completion,
			       hdr.field.wqe_valid);
}

static int sxe2_hw_nop(struct sxe2_qp_common *qp)
{
	__le64 *wqe;
	__u32 wqe_idx;

	if (!qp->sq_ring.head)
		return -EINVAL;

	wqe_idx = SXE2_RING_CURRENT_HEAD(qp->sq_ring);
	wqe	= qp->sq_base[wqe_idx].elem;

	qp->sq_wrtrk_array[wqe_idx].quanta = SXE2_QP_WQE_MIN_QUANTA;

	set_64bit_val(wqe, 0, 0);
	set_64bit_val(wqe, 8, 0);
	set_64bit_val(wqe, 16, 0);

	sxe2_set_nop_hdr(wqe, 24, qp);

	return 0;
}

static void sxe2_set_rcvq_hdr(__le64 *wqe, __u32 addl_frag_cnt,
			      struct sxe2_qp_common *qp)
{
	union sxe2_rq_hdr hdr;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	hdr.val		     = 0;
	hdr.field.addfragcnt = addl_frag_cnt;
	hdr.field.wqe_valid  = qp->rwqe_polarity;

	dma_wmb();

	set_64bit_val(wqe, 24, hdr.val);
	DRV_RDMA_LOG_DEV_DEBUG("RCV_WQE_HDR: (%#llx)\n"
			       "addfragcnt    : %d\n"
			       "wqe_valid     : %d\n",
			       cpu_to_le64(hdr.val), hdr.field.addfragcnt,
			       hdr.field.wqe_valid);
}

static inline void sxe2_set_immedata(__le64 *wqe, __u32 offset, __u64 imm_data)
{
	wqe[offset >> 3] = cpu_to_le64(imm_data);
}

static inline void sxe2_set_sgelist_data(void *wqe, __u32 offset,
					 struct ib_sge *sge, __u8 valid)
{
	struct sxe2_frag_data *pmsg = (struct sxe2_frag_data *)wqe;
	uint32_t len;

	pmsg = pmsg + offset / sizeof(*pmsg);
	if (sge) {
		len		 = (sge->length & (1U << 31)) ? 0 : sge->length;
		pmsg->tag_offset = cpu_to_le64(sge->addr);
		pmsg->offset8.field.frag_valid = valid;
		pmsg->offset8.field.frag_len   = len;
		pmsg->offset8.field.stag       = sge->lkey;
		pmsg->offset8.val	       = cpu_to_le64(pmsg->offset8.val);
	} else {
		pmsg->tag_offset	       = 0;
		pmsg->offset8.field.frag_valid = valid;
		pmsg->offset8.val	       = cpu_to_le64(pmsg->offset8.val);
	}
}

static void sxe2_set_inline_data_seg_list(__u8 *wqe, struct ib_sge *sge_list,
					  __u32 num_sges, __u8 polarity)
{
	__u8 inline_valid	     = (__u8)(polarity << SXE2_INLINE_VALID_S);
	__u32 quanta_bytes_remaining = 8;
	__u32 i;
	bool first_quanta  = true;
	__u32 bytes_copied = 0;

	wqe += 8;

	for (i = 0; i < num_sges; i++) {
		__u8 *cur_sge = (__u8 *)(uintptr_t)sge_list[i].addr;
		__u32 sge_len = sge_list[i].length;

		while (sge_len) {
			bytes_copied = min(sge_len, quanta_bytes_remaining);
			memcpy(wqe, cur_sge, bytes_copied);
			wqe += bytes_copied;
			cur_sge += bytes_copied;
			quanta_bytes_remaining -= bytes_copied;
			sge_len -= bytes_copied;

			if (!quanta_bytes_remaining) {
				quanta_bytes_remaining = 31;

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

static __le64 *sxe2_qp_get_next_send_wqe(struct sxe2_qp_common *qp,
					 __u32 *wqe_idx, __u16 *quanta,
					 __u32 total_size, u64 wr_id,
					 bool push_wqe)
{
	__le64 *wqe;
	__u32 nop_wqe_idx;
	__u16 org_wqe_quanta = *quanta;
	__u16 wqe_quanta     = *quanta;
	bool push_wqe_pad    = false;
	__u16 avail_quanta;
	__u16 i;
	__le64 *nop_wqe;

	if (push_wqe && (wqe_quanta & SXE2_WQE_QUANTA_ODD_NUMBER)) {
		wqe_quanta   = wqe_quanta + 1;
		push_wqe_pad = true;
	}

	avail_quanta = qp->common_attrs->max_hw_sq_chunk -
		       (SXE2_RING_CURRENT_HEAD(qp->sq_ring) %
			qp->common_attrs->max_hw_sq_chunk);
	if (wqe_quanta <= avail_quanta) {
		if (wqe_quanta > SXE2_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;
	} else {
		if (wqe_quanta + avail_quanta >
		    SXE2_SQ_RING_FREE_QUANTA(qp->sq_ring))
			return NULL;

		nop_wqe_idx = SXE2_RING_CURRENT_HEAD(qp->sq_ring);
		for (i = 0; i < avail_quanta; i++) {
			(void)sxe2_hw_nop(qp);
			SXE2_RING_MOVE_HEAD_NOCHECK(qp->sq_ring);
		}
		if (qp->push_db && push_wqe)
			sxe2_qp_push_wqe(qp, qp->sq_base[nop_wqe_idx].elem,
					 avail_quanta, nop_wqe_idx);
	}

	*wqe_idx = SXE2_RING_CURRENT_HEAD(qp->sq_ring);
	if (!*wqe_idx)
		qp->swqe_polarity = !qp->swqe_polarity;
	SXE2_RING_MOVE_HEAD_BY_COUNT_NOCHECK(qp->sq_ring, wqe_quanta);

	wqe = qp->sq_base[*wqe_idx].elem;

	qp->sq_wrtrk_array[*wqe_idx].wrid   = wr_id;
	qp->sq_wrtrk_array[*wqe_idx].wr_len = total_size;
	qp->sq_wrtrk_array[*wqe_idx].quanta = org_wqe_quanta;

	if (push_wqe_pad) {
		nop_wqe_idx = *wqe_idx + org_wqe_quanta;
		nop_wqe	    = qp->sq_base[nop_wqe_idx].elem;
		qp->sq_wrtrk_array[nop_wqe_idx].quanta = SXE2_QP_WQE_MIN_QUANTA;

		set_64bit_val(nop_wqe, 0, 0);
		set_64bit_val(nop_wqe, 8, 0);
		set_64bit_val(nop_wqe, 16, 0);
		sxe2_set_nop_hdr(nop_wqe, 24, qp);
	}
	*quanta = wqe_quanta;

	return wqe;
}

static __le64 *sxe2_qp_get_next_recv_wqe(struct sxe2_qp_common *qp,
					 __u32 *wqe_idx)
{
	__le64 *wqe;
	int ret_code;

	if (SXE2_RING_FULL_ERR(qp->rq_ring))
		return NULL;

	SXE2_ATOMIC_RING_MOVE_HEAD(qp->rq_ring, *wqe_idx, ret_code);
	if (ret_code)
		return NULL;

	if (!*wqe_idx)
		qp->rwqe_polarity = !qp->rwqe_polarity;

	wqe = qp->rq_base[*wqe_idx * qp->rq_wqe_size_multiplier].elem;

	return wqe;
}

int sxe2_hw_send(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		 bool post_sq)
{
	__le64 *wqe;
	struct sxe2_post_send *op_info;
	__u32 i, wqe_idx, total_size = 0, byte_off;
	int ret_code;
	__u32 frag_cnt, addl_frag_cnt;
	__u16 quanta;
	u64 frag_info = 0;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	op_info = &wr_info->op_info.send;
	if (qp->max_sq_sge_cnt < op_info->num_sges)
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].length;

	if (wr_info->imm_data_valid)
		frag_cnt = op_info->num_sges + 1;
	else
		frag_cnt = op_info->num_sges;

	ret_code = sxe2_fragcnt_to_quanta_cnt(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;

	if (wr_info->imm_data_valid) {
		sxe2_set_immedata(wqe, 0, wr_info->imm_data);
		i = 0;
	} else {
		sxe2_set_sgelist_data(wqe, 0,
				      frag_cnt ? op_info->sg_list : NULL,
				      qp->swqe_polarity);
		i = 1;
	}

	if (total_size == 0) {
		get_64bit_val(wqe, 8, &frag_info);
		frag_info = frag_info & (~SXE2_WQE_FRAG_VALID);
		SXE2_SET_FIELD(frag_info, SXE2_WQE_FRAG_VALID,
			       !qp->swqe_polarity);
		set_64bit_val(wqe, 8, frag_info);
		DRV_RDMA_LOG_DEV_DEBUG("wr set frag_info [%#llx] field [%d]\n",
				       frag_info, !qp->swqe_polarity);
	}

	sxe2_set_qkeyqpn(wqe, 16, op_info->qkey, op_info->dest_qp);

	for (byte_off = 32; i < op_info->num_sges;) {
		sxe2_set_sgelist_data(wqe, byte_off, &op_info->sg_list[i],
				      qp->swqe_polarity);
		byte_off += 16;
		i++;
	}

	if (!(frag_cnt & 0x01) && frag_cnt)
		sxe2_set_sgelist_data(wqe, byte_off, NULL, qp->swqe_polarity);

	sxe2_set_send_hdr(wqe, addl_frag_cnt, wr_info, qp);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "send");

	return 0;
}

int sxe2_hw_inline_send(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
			bool post_sq)
{
	__le64 *wqe;
	struct sxe2_post_send *op_info;
	__u32 wqe_idx;
	__u32 i, total_size = 0;
	__u16 quanta;

	op_info = &wr_info->op_info.send;

	if (unlikely(qp->max_sq_sge_cnt < op_info->num_sges))
		return -EINVAL;

	for (i = 0; i < op_info->num_sges; i++)
		total_size += op_info->sg_list[i].length;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = sxe2_inline_to_quanta_cnt(total_size);
	wqe    = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					   wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	if (wr_info->imm_data_valid)
		sxe2_set_immedata(wqe, 0, wr_info->imm_data);

	sxe2_set_qkeyqpn(wqe, 16, op_info->qkey, op_info->dest_qp);

	sxe2_set_inline_data_seg_list((__u8 *)wqe, op_info->sg_list,
				      op_info->num_sges, qp->swqe_polarity);

	sxe2_set_inlinesnd_hdr(wqe, total_size, wr_info, qp);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);
	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "inline_send");

	return 0;
}

int sxe2_hw_rdma_write(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		       bool post_sq)
{
	__le64 *wqe;
	struct sxe2_rdma_write *op_info;
	__u32 i, wqe_idx;
	__u32 total_size = 0, byte_off;
	int ret_code;
	__u32 frag_cnt, addl_frag_cnt;
	__u16 quanta;
	u64 frag_info = 0;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	op_info = &wr_info->op_info.rdma_write;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	if (wr_info->imm_data_valid)
		frag_cnt = op_info->num_lo_sges + 1;
	else
		frag_cnt = op_info->num_lo_sges;

	addl_frag_cnt = frag_cnt > 1 ? (frag_cnt - 1) : 0;
	ret_code      = sxe2_fragcnt_to_quanta_cnt(frag_cnt, &quanta);
	if (ret_code)
		return ret_code;

	wqe = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	if (wr_info->imm_data_valid) {
		sxe2_set_immedata(wqe, 0, wr_info->imm_data);
		i = 0;
	} else {
		sxe2_set_sgelist_data(wqe, 0, op_info->lo_sg_list,
				      qp->swqe_polarity);
		i = 1;
	}

	if (total_size == 0) {
		get_64bit_val(wqe, 8, &frag_info);
		frag_info = frag_info & (~SXE2_WQE_FRAG_VALID);
		SXE2_SET_FIELD(frag_info, SXE2_WQE_FRAG_VALID,
			       !qp->swqe_polarity);
		set_64bit_val(wqe, 8, frag_info);
		DRV_RDMA_LOG_DEV_DEBUG("wr set frag_info [%#llx] field [%d]\n",
				       frag_info, !qp->swqe_polarity);
	}

	sxe2_set_remote_offset(wqe, 16, op_info->rem_addr.addr);

	for (byte_off = 32; i < op_info->num_lo_sges;) {
		sxe2_set_sgelist_data(wqe, byte_off, &op_info->lo_sg_list[i],
				      qp->swqe_polarity);
		byte_off += 16;
		i++;
	}

	if (!(frag_cnt & 0x01) && frag_cnt)
		sxe2_set_sgelist_data(wqe, byte_off, NULL, qp->swqe_polarity);

	sxe2_set_write_hdr(wqe, addl_frag_cnt, wr_info, qp);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "write");

	return 0;
}

int sxe2_hw_inline_rdma_write(struct sxe2_qp_common *qp,
			      struct sxe2_wr_info *wr_info, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_rdma_write *op_info;
	__u32 wqe_idx;
	__u32 i, total_size = 0;
	__u16 quanta;

	op_info = &wr_info->op_info.rdma_write;

	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	if (unlikely(total_size > qp->max_inline_data))
		return -EINVAL;

	quanta = sxe2_inline_to_quanta_cnt(total_size);
	wqe    = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					   wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	if (wr_info->imm_data_valid)
		sxe2_set_immedata(wqe, 0, wr_info->imm_data);

	sxe2_set_remote_offset(wqe, 16, op_info->rem_addr.addr);

	sxe2_set_inline_data_seg_list((__u8 *)wqe, op_info->lo_sg_list,
				      op_info->num_lo_sges, qp->swqe_polarity);

	sxe2_set_inlinewrite_hdr(wqe, total_size, wr_info, qp);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "inline_write");

	return 0;
}

int sxe2_hw_rdma_read(struct sxe2_qp_common *qp, struct sxe2_wr_info *wr_info,
		      bool post_sq)
{
	struct sxe2_rdma_read *op_info;
	int ret_code;
	__u32 i, byte_off, total_size = 0;
	__u32 addl_frag_cnt;
	__le64 *wqe;
	__u32 wqe_idx;
	__u16 quanta;
	u64 frag_info = 0;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;
	bool ord_fence = false;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;

	op_info = &wr_info->op_info.rdma_read;
	for (i = 0; i < op_info->num_lo_sges; i++)
		total_size += op_info->lo_sg_list[i].length;

	ret_code = sxe2_fragcnt_to_quanta_cnt(op_info->num_lo_sges, &quanta);
	if (ret_code)
		return ret_code;

	if (qp->rd_fence_rate && (qp->ord_cnt++ == qp->rd_fence_rate)) {
		ord_fence   = true;
		qp->ord_cnt = 0;
	}

	wqe = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, total_size,
					wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	addl_frag_cnt =
		op_info->num_lo_sges > 1 ? (op_info->num_lo_sges - 1) : 0;

	sxe2_set_sgelist_data(wqe, 0, op_info->lo_sg_list, qp->swqe_polarity);

	if (total_size == 0) {
		get_64bit_val(wqe, 8, &frag_info);
		frag_info = frag_info & (~SXE2_WQE_FRAG_VALID);
		SXE2_SET_FIELD(frag_info, SXE2_WQE_FRAG_VALID,
			       !qp->swqe_polarity);
		set_64bit_val(wqe, 8, frag_info);
		DRV_RDMA_LOG_DEV_DEBUG("wr set frag_info [%#llx] field [%d]\n",
				       frag_info, !qp->swqe_polarity);
	}

	sxe2_set_remote_offset(wqe, 16, op_info->rem_addr.addr);

	for (i = 1, byte_off = 32; i < op_info->num_lo_sges; ++i) {
		sxe2_set_sgelist_data(wqe, byte_off, &op_info->lo_sg_list[i],
				      qp->swqe_polarity);
		byte_off += 16;
	}

	if (!(op_info->num_lo_sges & 0x01) && op_info->num_lo_sges)
		sxe2_set_sgelist_data(wqe, byte_off, NULL, qp->swqe_polarity);

	sxe2_set_read_hdr(wqe, addl_frag_cnt, wr_info, qp, ord_fence);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "rdma_read");

	return 0;
}

int sxe2_hw_local_invalidate(struct sxe2_qp_common *qp,
			     struct sxe2_wr_info *wr_info, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_local_invalidate *op_info;
	__u32 wqe_idx;
	__u16 quanta	  = SXE2_QP_WQE_MIN_QUANTA;
	struct ib_sge sge = {};

	op_info = &wr_info->op_info.local_inval;

	wqe = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, 0,
					wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	sge.lkey = op_info->target_stag;
	sxe2_set_sgelist_data(wqe, 0, &sge, 0);

	set_64bit_val(wqe, 16, 0);

	sxe2_set_invalidate_hdr(wqe, wr_info, qp);

	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);
	else if (post_sq)
		sxe2_qp_ring_normal_db(qp);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "local_invalidate");

	return 0;
}

int sxe2_hw_mr_fast_register(struct sxe2_qp_common *qp,
			     struct sxe2_wr_info *wr_info, bool post_sq)
{
	__le64 *wqe;
	u32 wqe_idx;
	__u16 quanta = SXE2_QP_WQE_MIN_QUANTA;
	struct sxe2_quanta *buf;

	wqe = sxe2_qp_get_next_send_wqe(qp, &wqe_idx, &quanta, 0,
					wr_info->wr_id, wr_info->push_wqe);
	if (!wqe)
		return -ENOMEM;

	wr_info->op_info.fastreg_mr.wqe_valid = qp->swqe_polarity;

	buf = (struct sxe2_quanta *)&wr_info->op_info.fastreg_mr;

	set_64bit_val(wqe, 0, buf->buffer[0]);
	set_64bit_val(wqe, 8, buf->buffer[1]);
	set_64bit_val(wqe, 16, buf->buffer[2]);

	dma_wmb();

	set_64bit_val(wqe, 24, buf->buffer[3]);
	if (wr_info->push_wqe)
		sxe2_qp_push_wqe(qp, wqe, quanta, wqe_idx);

	sxe2_dump_wqe(qp, wqe, quanta, wqe_idx, "fast_regmr");

	return 0;
}

static int sxe2_hw_post_receive(struct sxe2_qp_common *qp,
				struct sxe2_rq_info *wr_info)
{
	__u32 wqe_idx, i, byte_off;
	__u32 addl_frag_cnt;
	__le64 *wqe;
	struct sxe2_rdma_qp *rdma_qp;
	struct sxe2_rdma_device *rdma_dev;

	rdma_qp	 = container_of(qp, struct sxe2_rdma_qp, qp_ctx.qp_common);
	rdma_dev = rdma_qp->dev;
	if (!qp->rq_size)
		return -EINVAL;

	wqe = sxe2_qp_get_next_recv_wqe(qp, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	qp->rq_wrid_array[wqe_idx] = wr_info->wr_id;
	addl_frag_cnt = wr_info->num_sges > 1 ? (wr_info->num_sges - 1) : 0;
	sxe2_set_sgelist_data(wqe, 0, wr_info->sg_list, qp->rwqe_polarity);

	for (i = 1, byte_off = 32; i < wr_info->num_sges; i++) {
		sxe2_set_sgelist_data(wqe, byte_off, &wr_info->sg_list[i],
				      qp->rwqe_polarity);
		byte_off += 16;
	}

	if (!(wr_info->num_sges & 0x01) && wr_info->num_sges)
		sxe2_set_sgelist_data(wqe, byte_off, NULL, qp->rwqe_polarity);

	set_64bit_val(wqe, 16, 0);

	sxe2_set_rcvq_hdr(wqe, addl_frag_cnt, qp);

	dma_wmb();

	qp->doorbell_note[SXE2_QP_RQ_PI] =
		cpu_to_le32(SXE2_RING_CURRENT_HEAD(qp->rq_ring));

	DRV_RDMA_LOG_DEV_DEBUG("POST RCV(qpn = %u): wqe_idx %u wr_id %llu\n"
			       " rq_pi %u ring_size %u\n",
			       qp->qpn, wqe_idx, qp->rq_wrid_array[wqe_idx],
			       SXE2_RING_CURRENT_HEAD(qp->rq_ring),
			       SXE2_RING_SIZE(qp->rq_ring));
	for (i = 0; i < wr_info->num_sges; i++) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"sgelist[%d] addr 0x%llx len [%u] lkey [%u]\n", i,
			wr_info->sg_list[i].addr, wr_info->sg_list[i].length,
			wr_info->sg_list[i].lkey);
	}
	return 0;
}
static void sxe2_wrinfo_init_inv(struct ib_qp *ibqp,
				 const struct ib_send_wr *ib_wr,
				 struct sxe2_wr_info *wr_info)
{
	if (ib_wr->opcode == IB_WR_SEND ||
	    ib_wr->opcode == IB_WR_SEND_WITH_IMM) {
		wr_info->op_type = SXE2_OP_TYPE_SEND;
		if (ib_wr->send_flags & IB_SEND_SOLICITED)
			wr_info->op_type = SXE2_OP_TYPE_SEND_SOL;
	} else {
		wr_info->op_type = SXE2_OP_TYPE_SEND_INV;
		if (ib_wr->send_flags & IB_SEND_SOLICITED)
			wr_info->op_type = SXE2_OP_TYPE_SEND_SOL_INV;
		wr_info->rkey_to_inv = ib_wr->ex.invalidate_rkey;
	}
	wr_info->op_info.send.num_sges = (u32)ib_wr->num_sge;
	wr_info->op_info.send.sg_list  = (struct ib_sge *)ib_wr->sg_list;
	if ((ibqp->qp_type == IB_QPT_UD) || (ibqp->qp_type == IB_QPT_GSI)) {
		struct sxe2_ah *ah =
			container_of(ud_wr(ib_wr)->ah, struct sxe2_ah, ibah);

		wr_info->op_info.send.ah_id = ah->ctx_ah.ah_info.field.ah_idx;
		if (ibqp->qp_type == IB_QPT_GSI)
			wr_info->op_info.send.qkey = IB_QP1_QKEY;
		else
			wr_info->op_info.send.qkey = ud_wr(ib_wr)->remote_qkey;
		wr_info->op_info.send.dest_qp = ud_wr(ib_wr)->remote_qpn;
	}
	wr_info->funid = SXE2_RDMA_SEND;
	if (ib_wr->send_flags & IB_SEND_INLINE)
		wr_info->funid = SXE2_RDMA_SEND_INLINE;
}
static void sxe2_wrinfo_init_reg_mr(struct ib_qp *ibqp,
				    const struct ib_send_wr *ib_wr,
				    struct sxe2_wr_info *wr_info)
{
	struct sxe2_mr *vendor_mr;
	struct sxe2_pbl_pble_alloc_info *palloc;
	struct sxe2_rdma_qp *kqp;

	kqp	  = to_qp(ibqp);
	vendor_mr = ibmr_to_vendor_mr(reg_wr(ib_wr)->mr);
	palloc	  = &vendor_mr->pble_alloc;
	wr_info->op_info.fastreg_mr.signaled_completion = wr_info->signaled;
	wr_info->op_info.fastreg_mr.read_fence		= wr_info->read_fence;
	wr_info->op_info.fastreg_mr.access_right =
		sxe2_get_mr_access(reg_wr(ib_wr)->access);
	wr_info->op_info.fastreg_mr.mr_key = reg_wr(ib_wr)->key & 0xff;
	wr_info->op_info.fastreg_mr.mr_idx = reg_wr(ib_wr)->key >> 8;
	wr_info->op_info.fastreg_mr.log_entity_size =
		ilog2(reg_wr(ib_wr)->mr->page_size);
	if (reg_wr(ib_wr)->access & IB_ZERO_BASED) {
		wr_info->op_info.fastreg_mr.va_based_flag =
			SXE2_ADDR_TYPE_ZERO_BASED;
		wr_info->op_info.fastreg_mr.va_or_offset =
			vendor_mr->ibmr.iova & (vendor_mr->page_size - 1);
	} else {
		wr_info->op_info.fastreg_mr.va_based_flag =
			SXE2_ADDR_TYPE_VA_BASED;
		wr_info->op_info.fastreg_mr.va_or_offset = vendor_mr->ibmr.iova;
	}
	wr_info->op_info.fastreg_mr.len	      = vendor_mr->ibmr.length;
	wr_info->op_info.fastreg_mr.op	      = SXE2_OP_TYPE_FAST_REG_MR;
	wr_info->op_info.fastreg_mr.pbl_mode  = palloc->pbl_mode.mode;
	wr_info->op_info.fastreg_mr.pbl_index = palloc->pbl_index;
	wr_info->op_info.fastreg_mr.push_wqe =
		kqp->qp_ctx.qp_common.push_db ? true : false;
	wr_info->op_info.fastreg_mr.local_fence = wr_info->read_fence;
	wr_info->funid				= SXE2_RDMA_FAST_REG_MR;
}
static int sxe2_wrinfo_init(struct ib_qp *ibqp, const struct ib_send_wr *ib_wr,
			    struct sxe2_wr_info *wr_info)
{
	struct sxe2_common_attrs *uk_attrs;
	struct sxe2_rdma_qp *kqp;
	struct sxe2_rdma_ctx_dev *ctx_dev;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_qp_common *cqp;
	int err = 0;

	kqp	 = to_qp(ibqp);
	ctx_dev	 = &kqp->dev->rdma_func->ctx_dev;
	uk_attrs = &ctx_dev->hw_attrs.uk_attrs;
	rdma_dev = kqp->dev;
	cqp	 = &kqp->qp_ctx.qp_common;

	memset(wr_info, 0, sizeof(*wr_info));

	wr_info->wr_id	  = (__u64)(ib_wr->wr_id);
	wr_info->push_wqe = kqp->qp_ctx.qp_common.push_db ? true : false;

	if ((ib_wr->send_flags & IB_SEND_SIGNALED) || kqp->sig_all)
		wr_info->signaled = true;

	if (ib_wr->send_flags & IB_SEND_FENCE)
		wr_info->read_fence = true;

	switch (ib_wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
		if (!(kqp->qp_ctx.qp_common.qp_caps & SXE2_SEND_WITH_IMM))
			return -EINVAL;
		wr_info->imm_data_valid = true;
		wr_info->imm_data	= ntohl(ib_wr->ex.imm_data);
		fallthrough;
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_INV:
		sxe2_wrinfo_init_inv(ibqp, ib_wr, wr_info);
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (!(kqp->qp_ctx.qp_common.qp_caps & SXE2_WRITE_WITH_IMM))
			return -EINVAL;

		wr_info->imm_data_valid = true;
		wr_info->imm_data	= ntohl(ib_wr->ex.imm_data);
		fallthrough;
	case IB_WR_RDMA_WRITE:
		if (ib_wr->num_sge > (int)cqp->max_sq_sge_cnt)
			return -EINVAL;
		wr_info->op_type = SXE2_OP_TYPE_RDMA_WRITE;
		if (ib_wr->send_flags & IB_SEND_SOLICITED)
			wr_info->op_type = SXE2_OP_TYPE_RDMA_WRITE_SOL;

		wr_info->op_info.rdma_write.num_lo_sges = (u32)ib_wr->num_sge;
		wr_info->op_info.rdma_write.lo_sg_list	= ib_wr->sg_list;
		wr_info->op_info.rdma_write.rem_addr.addr =
			rdma_wr(ib_wr)->remote_addr;
		wr_info->op_info.rdma_write.rem_addr.lkey =
			rdma_wr(ib_wr)->rkey;
		wr_info->funid = SXE2_RDMA_WRITE;
		if (ib_wr->send_flags & IB_SEND_INLINE)
			wr_info->funid = SXE2_RDMA_WRITE_INLINE;
		break;
	case IB_WR_RDMA_READ:
		if (ib_wr->num_sge > (int)uk_attrs->max_hw_read_sges)
			return -EINVAL;
		wr_info->op_type = SXE2_OP_TYPE_RDMA_READ;
		wr_info->op_info.rdma_read.rem_addr.addr =
			rdma_wr(ib_wr)->remote_addr;
		wr_info->op_info.rdma_read.rem_addr.lkey = rdma_wr(ib_wr)->rkey;

		wr_info->op_info.rdma_read.lo_sg_list  = ib_wr->sg_list;
		wr_info->op_info.rdma_read.num_lo_sges = (u32)ib_wr->num_sge;
		wr_info->funid			       = SXE2_RDMA_READ;
		break;
	case IB_WR_LOCAL_INV:
		wr_info->op_type     = SXE2_OP_TYPE_LOCAL_INV;
		wr_info->local_fence = wr_info->read_fence;
		wr_info->op_info.local_inval.target_stag =
			ib_wr->ex.invalidate_rkey;
		wr_info->funid	  = SXE2_RDMA_LOCAL_INV;
		wr_info->post_wqe = true;
		break;
	case IB_WR_REG_MR:
		sxe2_wrinfo_init_reg_mr(ibqp, ib_wr, wr_info);
		break;

	default:
		err = -EINVAL;
		break;
	}

	DRV_RDMA_LOG_DEV_DEBUG(
		"wr_info qpn [0x%x] opcode [%d]\n"
		"wr_id %llu push_mode %d post_wqe %d signald %d\n",
		ibqp->qp_num, ib_wr->opcode, wr_info->wr_id, wr_info->push_wqe,
		wr_info->post_wqe, wr_info->signaled);

	return err;
}

int sxe2_kpost_send(struct ib_qp *ibqp, const struct ib_send_wr *ib_wr,
		    const struct ib_send_wr **bad_wr)
{
	struct sxe2_rdma_qp *qp;
	struct sxe2_qp_common *kqp;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_wr_info wr_info;
	int err		    = 0;
	unsigned long flags = 0;
	struct sxe2_rdma_device *rdma_dev;

	qp  = to_qp(ibqp);
	kqp = &qp->qp_ctx.qp_common;
	dev = &qp->dev->rdma_func->ctx_dev;

	rdma_dev = qp->dev;

	spin_lock_irqsave(&qp->lock, flags);
	while (ib_wr) {
		err = sxe2_wrinfo_init(ibqp, ib_wr, &wr_info);
		if (err) {
			*bad_wr = ib_wr;
			break;
		}

		err = g_rdma_op[wr_info.funid](kqp, &wr_info, wr_info.post_wqe);
		if (err) {
			*bad_wr = ib_wr;
			break;
		}

		ib_wr = ib_wr->next;
	}

	if (!qp->flush_issued) {
		if (qp->ibqp_state <= IB_QPS_RTS) {
			if (!kqp->push_db)
				sxe2_qp_ring_normal_db(kqp);
		}
		spin_unlock_irqrestore(&qp->lock, flags);
	} else {
		spin_unlock_irqrestore(&qp->lock, flags);
		DRV_RDMA_LOG_DEV_DEBUG("io send trigger qp [%u] flush work\n",
				       qp->ibqp.qp_num);
		sxe2_sched_qp_flush_work(qp);
	}

	return err;
}

int sxe2_kpost_recv(struct ib_qp *ibqp, const struct ib_recv_wr *ib_wr,
		    const struct ib_recv_wr **bad_wr)
{
	struct sxe2_rdma_qp *qp		  = to_qp(ibqp);
	struct sxe2_qp_common *kqp	  = &qp->qp_ctx.qp_common;
	struct sxe2_rq_info rq_info	  = {};
	struct sxe2_rdma_device *rdma_dev = qp->dev;
	unsigned long flags		  = 0;
	int err				  = 0;

	if (kqp->srq) {
		*bad_wr = ib_wr;
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->lock, flags);

	while (ib_wr) {
		if (ib_wr->num_sge > (int)kqp->max_rq_sge_cnt) {
			err = -EINVAL;
			goto out;
		}
		rq_info.num_sges = (u32)ib_wr->num_sge;
		rq_info.wr_id	 = ib_wr->wr_id;
		rq_info.sg_list	 = ib_wr->sg_list;
		err		 = sxe2_hw_post_receive(kqp, &rq_info);
		if (err) {
			*bad_wr = ib_wr;
			goto out;
		}

		ib_wr = ib_wr->next;
	}

out:
	spin_unlock_irqrestore(&qp->lock, flags);
	if (qp->flush_issued) {
		DRV_RDMA_LOG_DEV_DEBUG("io recv trigger qp [%u] flush work\n",
				       qp->ibqp.qp_num);
		sxe2_sched_qp_flush_work(qp);
	}

	return err;
}

static bool sxe2_cq_empty(struct sxe2_rdma_cq_uk *cq)
{
	__le64 *cqe;
	struct sxe2_cqe_info cqe_info;

	cqe = SXE2_GET_CURRENT_CQ_ELEM(cq);

	cqe_info.info.buf[SXE2_CQE_SIZE - 1] =
		le64_to_cpu(cqe[SXE2_CQE_SIZE - 1]);

	return cqe_info.info.field.cqe_valid != cq->polarity;
}

static int sxe2_get_next_cqe(struct sxe2_rdma_cq_uk *cq,
			     struct sxe2_cqe_info *cqe_info)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	__le64 *cqe;
	int i;

	cq_ctx	 = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);

	cqe = SXE2_GET_CURRENT_CQ_ELEM(cq);
	cqe_info->info.buf[SXE2_CQE_SIZE - 1] =
		le64_to_cpu(cqe[SXE2_CQE_SIZE - 1]);

	if (cqe_info->info.field.cqe_valid != cq->polarity)
		return -ENOENT;

	dma_rmb();

	for (i = 0; i < SXE2_CQE_SIZE - 1; i++)
		cqe_info->info.buf[i] = le64_to_cpu(cqe[i]);

	DRV_RDMA_LOG_DEV_DEBUG(
		"CQ1 (%d) CI(0x%x) cqeinfo:\n"
		"%#llx(%#llx) %#llx(%#llx) %#llx(%#llx) %#llx(%#llx)\n"
		"%#llx(%#llx) %#llx(%#llx) %#llx(%#llx) %#llx(%#llx)\n",
		cq->cq_id, cq->cq_ring.head, cqe[0], cqe_info->info.buf[0],
		cqe[1], cqe_info->info.buf[1], cqe[2], cqe_info->info.buf[2],
		cqe[3], cqe_info->info.buf[3], cqe[4], cqe_info->info.buf[4],
		cqe[5], cqe_info->info.buf[5], cqe[6], cqe_info->info.buf[6],
		cqe[7], cqe_info->info.buf[7]);

	return SXE2_CQ_OK;
}

static int sxe2_read_cqe(__le64 *cqe, u8 cq_polarity,
			 struct sxe2_cqe_info *cqe_info)
{
	int i;

	cqe_info->info.buf[SXE2_CQE_SIZE - 1] =
		le64_to_cpu(cqe[SXE2_CQE_SIZE - 1]);

	if (cqe_info->info.field.cqe_valid != cq_polarity)
		return -ENOENT;

	dma_rmb();

	for (i = 0; i < SXE2_CQE_SIZE - 1; i++)
		cqe_info->info.buf[i] = le64_to_cpu(cqe[i]);

	return SXE2_CQ_OK;
}

static int sxe2_hw_flush_one_sq_wqe(struct sxe2_rdma_cq_uk *cq,
				    struct sxe2_qp_common *qp,
				    struct sxe2_cqe_info *cqe_info)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	__le64 *sw_wqe;
	__u64 wqe_hdr;
	__u32 tail;

	cq_ctx	 = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);

	if (!SXE2_RING_MORE_WORK(qp->sq_ring) || !SXE2_RING_MORE_WORK_PAD(qp->sq_ring))
		return -ENOENT;

	do {
		tail   = qp->sq_ring.tail;
		sw_wqe = qp->sq_base[tail].elem;
		get_64bit_val(sw_wqe, 24, &wqe_hdr);
		cqe_info->info.field.op =
			(u8)FIELD_GET(SXE2_WQE_OPCODE, wqe_hdr);
		SXE2_RING_SET_TAIL(qp->sq_ring,
				   tail + qp->sq_wrtrk_array[tail].quanta);
		if (cqe_info->info.field.op != SXE2_OP_TYPE_NOP) {
			cqe_info->wr_id = qp->sq_wrtrk_array[tail].wrid;
			cqe_info->bytes = qp->sq_wrtrk_array[tail].wr_len;
			DRV_RDMA_LOG_DEV_DEBUG(
				"flush qp %u sq_pi %u sq_ci %u wqe_idx %u wr_id %llu.\n",
				qp->qpn, SXE2_RING_CURRENT_HEAD(qp->sq_ring),
				SXE2_RING_CURRENT_TAIL(qp->sq_ring), tail,
				cqe_info->wr_id);
#ifdef SXE2_CFG_DEBUG
			qp->statistics.flushed_sq_cnt++;
			qp->statistics.last_rcvd_sqwrid = cqe_info->wr_id;
#endif
			break;
		}
	} while (1);

	return SXE2_CQ_OK;
}

static void sxe2_move_srq_ring_tail(struct sxe2_srq_drv *srq)
{
	struct sxe2_rdma_srq_ctx *srq_ctx;
	__u32 tail;

	srq_ctx = container_of(srq, struct sxe2_rdma_srq_ctx, srq_drv);

	while (SXE2_RING_MORE_WORK(srq->srq_ring)) {
		tail = SXE2_RING_CURRENT_TAIL(srq->srq_ring);
		if (srq_ctx->ksrq_rsc.srqe_array[tail] == SXE2_SRQE_BUSY)
			break;
		SXE2_RING_MOVE_TAIL(srq->srq_ring);
	}
}
static void sxe2_hw_deal_srq_cqe(struct sxe2_rdma_cq_uk *cq,
				 struct sxe2_cqe_info *cqe_info,
				 struct sxe2_qp_common *qp, __u32 qpn)
{
	struct sxe2_srq_drv *srq;
	struct sxe2_rdma_srq_ctx *srq_ctx;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	__u32 array_idx;
	__u32 wqe_idx;

	cq_ctx	  = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev  = to_rdmadev(cq_ctx->dev);
	wqe_idx	  = (__u32)cqe_info->info.field.wq_desc_idx;
	srq	  = qp->srq;
	srq_ctx	  = container_of(srq, struct sxe2_rdma_srq_ctx, srq_drv);
	array_idx = wqe_idx / srq->wqe_size_multiplier;
	if (srq_ctx->ksrq_rsc.srqe_array[array_idx] == SXE2_SRQE_BUSY)
		srq_ctx->ksrq_rsc.srqe_array[array_idx] = SXE2_SRQE_FREE;
	else
		DRV_RDMA_LOG_ERROR_BDF(
			"cq %u received invalid cqe\n"
			"(qpn %u srqn %u wqe_idx %u mul_size %d flag %#x).\n",
			cq->cq_id, qpn, srq->srq_id, wqe_idx,
			srq->wqe_size_multiplier,
			srq_ctx->ksrq_rsc.srqe_array[array_idx]);

	cqe_info->wr_id = srq_ctx->ksrq_rsc.srq_wrid_array[array_idx];
	sxe2_move_srq_ring_tail(srq);
}
static int sxe2_hw_deal_rq_cqe(struct sxe2_rdma_cq_uk *cq,
			       struct sxe2_cqe_info *cqe_info,
			       struct sxe2_qp_common *qp, __u32 qpn)
{
	__u32 array_idx;
	__u32 wqe_idx;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;

	cq_ctx	  = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev  = to_rdmadev(cq_ctx->dev);
	wqe_idx	  = (__u32)cqe_info->info.field.wq_desc_idx;
	array_idx = wqe_idx / qp->rq_wqe_size_multiplier;
	if (cqe_info->info.field.major_err == SXE2_WR_FLUSH_ERR) {
		if (!SXE2_RING_MORE_WORK(qp->rq_ring))
			return -ENOENT;
		DRV_RDMA_LOG_DEV_DEBUG(
			"flush qp %u state rq_pi %u rq_ci %u .\n", qpn,
			SXE2_RING_CURRENT_HEAD(qp->rq_ring),
			SXE2_RING_CURRENT_TAIL(qp->rq_ring));
		array_idx = qp->rq_ring.tail;
	}
	cqe_info->wr_id = qp->rq_wrid_array[array_idx];
	SXE2_RING_SET_TAIL(qp->rq_ring, array_idx + 1);
	DRV_RDMA_LOG_DEV_DEBUG(
		"update qp %u rq_ci %u wqeidx %u arridx %u wrid %llu.\n", qpn,
		SXE2_RING_CURRENT_TAIL(qp->rq_ring), wqe_idx, array_idx,
		cqe_info->wr_id);
	return 0;
}
static int sxe2_hw_deal_sq_cqe(struct sxe2_rdma_cq_uk *cq,
			       struct sxe2_cqe_info *cqe_info,
			       struct sxe2_qp_common *qp, __u32 qpn)
{
	__u32 wqe_idx;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;

	cq_ctx	 = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);
	wqe_idx	 = (__u32)cqe_info->info.field.wq_desc_idx;
	if (cqe_info->info.field.push_dropped) {
		qp->llwqe_mode	 = false;
		qp->push_dropped = true;
	}
	if (cqe_info->info.field.major_err != SXE2_WR_FLUSH_ERR) {
		cqe_info->wr_id = qp->sq_wrtrk_array[wqe_idx].wrid;
		cqe_info->bytes = qp->sq_wrtrk_array[wqe_idx].wr_len;
		SXE2_RING_SET_TAIL(qp->sq_ring, wqe_idx + qp->sq_wrtrk_array[wqe_idx].quanta);
		DRV_RDMA_LOG_DEV_DEBUG(
			"update qp %u sq_ci %u wqe_idx %u wr_id %llu.\n", qpn,
			SXE2_RING_CURRENT_TAIL(qp->sq_ring), wqe_idx,
			cqe_info->wr_id);
	} else {
		return sxe2_hw_flush_one_sq_wqe(cq, qp, cqe_info);
	}
	return 0;
}
static int sxe2_hw_cq_poll(struct sxe2_rdma_cq_uk *cq,
			   struct sxe2_cqe_info *cqe_info)
{
	struct sxe2_qp_common *qp;
	__u32 wqe_idx;
	__u32 qpn	  = 0;
	int ret_code	  = SXE2_CQ_OK;
	bool move_cq_head = true;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	struct sxe2_ring *cur_ring = NULL;
	__le64 *cqe;
	__u64 qword = 0;

	cq_ctx	 = container_of(cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);

	ret_code = sxe2_get_next_cqe(cq, cqe_info);
	if (ret_code != SXE2_CQ_OK)
		return ret_code;

	qp = (struct sxe2_qp_common *)(unsigned long)cqe_info->info.field.qpc;
	if (qp == NULL || qp->destroy_pending) {
		ret_code = -EFAULT;
		goto exit;
	}

	qpn	= qp->qpn;
	wqe_idx = (__u32)cqe_info->info.field.wq_desc_idx;
	cqe_info->bytes = cqe_info->info.field.payload_len;

	DRV_RDMA_LOG_DEV_DEBUG(
		"cqe process cqn [%u] ci [%u] qp [%u] wqeidx %u.\n", cq->cq_id,
		SXE2_RING_CURRENT_HEAD(cq->cq_ring), qpn, wqe_idx);

	if (cqe_info->info.field.is_srq) {
		sxe2_hw_deal_srq_cqe(cq, cqe_info, qp, qpn);
	} else if (cqe_info->info.field.qp_type == SXE2_CQE_QTYPE_RQ) {
		cur_ring = &qp->rq_ring;
		ret_code = sxe2_hw_deal_rq_cqe(cq, cqe_info, qp, qpn);
		if (ret_code)
			goto exit;
	} else {
		cur_ring = &qp->sq_ring;
		ret_code = sxe2_hw_deal_sq_cqe(cq, cqe_info, qp, qpn);
		if (ret_code)
			goto exit;
	}

exit:
	if (!ret_code && cqe_info->info.field.major_err == SXE2_WR_FLUSH_ERR) {
		if (cur_ring && SXE2_RING_MORE_WORK(*cur_ring))
			move_cq_head = false;
	}

	if (move_cq_head) {
		SXE2_RING_MOVE_HEAD_NOCHECK(cq->cq_ring);
		if (!SXE2_RING_CURRENT_HEAD(cq->cq_ring))
			cq->polarity ^= 1;

		SXE2_RING_MOVE_TAIL(cq->cq_ring);
		cq->doorbell_note[SXE2_CQ_SET_CI] =
			cpu_to_le32(SXE2_RING_CURRENT_HEAD(cq->cq_ring));
		DRV_RDMA_LOG_DEV_DEBUG("update qp %u cq %d ci %u.\n", qpn,
				       cq->cq_id,
				       SXE2_RING_CURRENT_HEAD(cq->cq_ring));
	} else {
		cqe = SXE2_GET_CURRENT_CQ_ELEM(cq);
		get_64bit_val(cqe, 24, &qword);
		qword &= ~SXE2_CQE_WQEIDX;
		qword |= FIELD_PREP(SXE2_CQE_WQEIDX, cur_ring->tail);
		set_64bit_val(cqe, 24, qword);

		DRV_RDMA_LOG_DEV_DEBUG(
			"cqn [%u] idx [%u] flush wqeidx %d to %d qpn %u.\n",
			cq->cq_id, SXE2_RING_CURRENT_HEAD(cq->cq_ring), wqe_idx,
			cur_ring->tail, qpn);
	}

	return ret_code;
}

static enum ib_wc_status
sxe2_flush_err_to_ib_wc_status(enum sxe2_major_opcode opcode)
{
	switch (opcode) {
	case SXE2_LOCAL_PROTECTION_ERR:
		return IB_WC_LOC_PROT_ERR;
	case SXE2_BAD_RESPONSE_ERR:
		return IB_WC_BAD_RESP_ERR;
	case SXE2_REMOTE_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case SXE2_LOCAL_QP_OP_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case SXE2_REMOTE_OPERATION_ERR:
		return IB_WC_REM_OP_ERR;
	case SXE2_LOCAL_LEN_ERR:
		return IB_WC_LOC_LEN_ERR;
	case SXE2_LOCAL_ACCESS_ERR:
		return IB_WC_LOC_ACCESS_ERR;
	case SXE2_WR_FLUSH_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case SXE2_TRANS_RETRY_CNT_EXCEED_ERR:
		return IB_WC_RETRY_EXC_ERR;
	case SXE2_MW_BIND_ERR:
		return IB_WC_MW_BIND_ERR;
	case SXE2_REMOTE_INVALID_REQUEST_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case SXE2_RNR_RETRY_CNT_EXCEED_ERR:
		return IB_WC_RNR_RETRY_EXC_ERR;
	default:
		return IB_WC_GENERAL_ERR;
	}
}

static inline void sxe2_set_ib_wc_op_sq(struct sxe2_cqe_info *cur_cqe,
					struct ib_wc *entry)
{
	switch (cur_cqe->info.field.op) {
	case SXE2_OP_TYPE_RDMA_WRITE:
	case SXE2_OP_TYPE_RDMA_WRITE_SOL:
		entry->opcode = IB_WC_RDMA_WRITE;
		break;
	case SXE2_OP_TYPE_RDMA_READ:
		entry->opcode = IB_WC_RDMA_READ;
		break;
	case SXE2_OP_TYPE_SEND_SOL:
	case SXE2_OP_TYPE_SEND_SOL_INV:
	case SXE2_OP_TYPE_SEND_INV:
	case SXE2_OP_TYPE_SEND:
		entry->opcode = IB_WC_SEND;
		break;
	case SXE2_OP_TYPE_FAST_REG_MR:
		entry->opcode = IB_WC_REG_MR;
		break;
	case SXE2_OP_TYPE_LOCAL_INV:
		entry->opcode = IB_WC_LOCAL_INV;
		break;
	default:
		entry->status = IB_WC_GENERAL_ERR;
	}
}

static inline void sxe2_set_ib_wc_op_rq(struct sxe2_cqe_info *cur_cqe,
					struct ib_wc *entry,
					bool send_imm_support)
{
	if (!send_imm_support) {
		entry->opcode = cur_cqe->info.field.imm_data_flag ?
					IB_WC_RECV_RDMA_WITH_IMM :
					IB_WC_RECV;
		return;
	}
	switch (cur_cqe->info.field.op) {
	case IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		entry->opcode = IB_WC_RECV_RDMA_WITH_IMM;
		break;
	default:
		entry->opcode = IB_WC_RECV;
	}
}

static void sxe2_cq_pollinfo_to_wc(struct ib_wc *entry,
				   struct sxe2_cqe_info *cur_cqe)
{
	struct sxe2_rdma_ctx_qp *qp;

	entry->wc_flags	  = 0;
	entry->pkey_index = 0;
	entry->wr_id	  = cur_cqe->wr_id;

	qp = (struct sxe2_rdma_ctx_qp *)(unsigned long)cur_cqe->info.field.qpc;
	entry->qp = qp->qp_common.back_qp;

	if (cur_cqe->info.field.error) {
		entry->status = sxe2_flush_err_to_ib_wc_status(
			cur_cqe->info.field.major_err);
		entry->vendor_err = (u32)(cur_cqe->info.field.major_err << 16 |
					  cur_cqe->info.field.minor_err);
	} else {
		entry->status = IB_WC_SUCCESS;
		if (cur_cqe->info.field.imm_data_flag) {
			entry->ex.imm_data =
				htonl(cur_cqe->info.field.imme_data);
			entry->wc_flags |= IB_WC_WITH_IMM;
		}
		if (cur_cqe->info.field.ud_smac_valid) {
			u64 dmac = cur_cqe->info.field.ud_smac;

			ether_addr_copy(entry->smac, (u8 *)&dmac);
			entry->wc_flags |= IB_WC_WITH_SMAC;
		}
		if (cur_cqe->info.field.vlan_tag_flag &&
		    ctxdev_to_rf(qp->dev)->vlan_parse_en) {
			u16 vlan =
				cur_cqe->info.field.ud_vlan_tag & VLAN_VID_MASK;

			entry->sl = cur_cqe->info.field.ud_vlan_tag >>
				    VLAN_PRIO_SHIFT;
			if (vlan) {
				entry->vlan_id = vlan;
				entry->wc_flags |= IB_WC_WITH_VLAN;
			}
		} else {
			entry->sl = 0;
		}
	}

	if (cur_cqe->info.field.qp_type == SXE2_CQE_QTYPE_SQ) {
		sxe2_set_ib_wc_op_sq(cur_cqe, entry);
	} else {
		sxe2_set_ib_wc_op_rq(
			cur_cqe, entry,
			qp->qp_common.qp_caps & SXE2_SEND_WITH_IMM ? true :
								     false);
		if (qp->qp_common.qp_type != IB_QPT_UD &&
		    cur_cqe->info.field.stag_or_lrkey) {
			entry->ex.invalidate_rkey = cur_cqe->info.field.l_r_key;
			entry->wc_flags |= IB_WC_WITH_INVALIDATE;
		}
	}

	if (qp->qp_common.qp_type == IB_QPT_UD) {
		entry->src_qp = cur_cqe->info.field.ud_src_qpn;
		entry->slid   = 0;
		entry->wc_flags |= (IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE);
		entry->network_hdr_type = cur_cqe->info.field.ipv4 ?
						  RDMA_NETWORK_IPV4 :
						  RDMA_NETWORK_IPV6;
	} else {
		entry->src_qp = cur_cqe->info.field.qp_id;
	}
	entry->byte_len = cur_cqe->bytes;
}

static int sxe2_poll_one(struct sxe2_rdma_cq_uk *ukcq,
			 struct sxe2_cqe_info *cur_cqe, struct ib_wc *entry)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	int ret;

	cq_ctx	 = container_of(ukcq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);

	ret = sxe2_hw_cq_poll(ukcq, cur_cqe);
	if (ret) {
		if (ret == -EFAULT) {
			DRV_RDMA_LOG_DEV_WARN(
				"CQ(kernel) %d Read CI(0x%x) cqe failed.\n",
				ukcq->cq_id, ukcq->cq_ring.head);
		}
		return ret;
	}

	DRV_RDMA_LOG_DEV_DEBUG(
		"CQ(kernel) (%d) CI(0x%x) wrid(%llu) cqeinfo:\n"
		"payload_len      : %ul\n"
		"packet_seq       : %d\n"
		"qpc              : %#llx\n"
		"l_r_key          : %ul\n"
		"qp_id            : %d\n"
		"minor_err        : %d\n"
		"major_err        : %d\n"
		"wq_desc_idx      : %d\n"
		"extended_cqe     : %d\n"
		"push_dropped     : %d\n"
		"ipv4             : %d\n"
		"stag_or_lrkey    : %d\n"
		"solicited_evt    : %d\n"
		"error            : %d\n"
		"op               : %d\n"
		"qp_type          : %d\n"
		"imme_data        : %ul\n"
		"srqn             : %d\n"
		"is_srq           : %d\n"
		"cqe_timestamp    : %#llx\n"
		"ud_smac          : %#llx\n"
		"ud_vlan_tag      : %d\n"
		"ud_src_qpn       : %d\n"
		"vsi_index        : %d\n"
		"vlan_tag_flag    : %d\n"
		"ud_smac_valid    : %d\n"
		"imm_data_flag    : %d\n"
		"cqe_valid        : %d\n",
		ukcq->cq_id, ukcq->cq_ring.head, cur_cqe->wr_id,
		cur_cqe->info.field.payload_len, cur_cqe->info.field.packet_seq,
		cur_cqe->info.field.qpc, cur_cqe->info.field.l_r_key,
		cur_cqe->info.field.qp_id, cur_cqe->info.field.minor_err,
		cur_cqe->info.field.major_err, cur_cqe->info.field.wq_desc_idx,
		cur_cqe->info.field.extended_cqe,
		cur_cqe->info.field.push_dropped, cur_cqe->info.field.ipv4,
		cur_cqe->info.field.stag_or_lrkey,
		cur_cqe->info.field.solicited_evt, cur_cqe->info.field.error,
		cur_cqe->info.field.op, cur_cqe->info.field.qp_type,
		cur_cqe->info.field.imme_data, cur_cqe->info.field.srqn,
		cur_cqe->info.field.is_srq, cur_cqe->info.field.cqe_timestamp,
		(__u64)cur_cqe->info.field.ud_smac,
		cur_cqe->info.field.ud_vlan_tag, cur_cqe->info.field.ud_src_qpn,
		cur_cqe->info.field.vsi_index,
		cur_cqe->info.field.vlan_tag_flag,
		cur_cqe->info.field.ud_smac_valid,
		cur_cqe->info.field.imm_data_flag,
		cur_cqe->info.field.cqe_valid);

	sxe2_cq_pollinfo_to_wc(entry, cur_cqe);

	return 0;
}

int sxe2_generated_cmpls(struct sxe2_rdma_cq *rdma_cq,
			 struct sxe2_cqe_info *out_cqeinfo)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_flushed_cqe *flushed_cqe;
	struct sxe2_qp_common *qp;
	struct sxe2_rdma_pci_f *rdma_func;

	rdma_dev = to_dev(rdma_cq->ibcq.device);

	if (list_empty(&rdma_cq->cmpl_generated))
		return -ENOENT;

	rdma_func = rdma_dev->rdma_func;

	flushed_cqe = list_first_entry_or_null(&rdma_cq->cmpl_generated,
					       struct sxe2_flushed_cqe, list);
	qp = (struct sxe2_qp_common *)flushed_cqe->cqeinfo.info.field.qpc;
	list_del(&flushed_cqe->list);
	memcpy(out_cqeinfo, &flushed_cqe->cqeinfo, sizeof(*out_cqeinfo));
	kfree(flushed_cqe);
	DRV_RDMA_LOG_DEV_DEBUG(
		"polled one flushed cqe wr_id = 0x%llx qp_id=%u wqe_idx=%u\n",
		out_cqeinfo->wr_id, out_cqeinfo->info.field.qp_id,
		out_cqeinfo->info.field.wq_desc_idx);

	return SXE2_CQ_OK;
}

int sxe2_kpoll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *entry)
{
	struct sxe2_rdma_cq *rdma_cq;
	struct sxe2_cqe_info *cur_cqe;
	unsigned long flags = 0;
	int npolled	    = 0;
	int ret		    = -EINVAL;

	rdma_cq = ibcq_to_vendor_cq(ibcq);
	cur_cqe = &rdma_cq->cur_cqe;

	spin_lock_irqsave(&rdma_cq->lock, flags);

	while (npolled < num_entries) {
		ret = sxe2_poll_one(&rdma_cq->cq_ctx.cq_uk, cur_cqe,
				    entry + npolled);
		if (ret == -ENOENT) {
			ret = sxe2_generated_cmpls(rdma_cq, cur_cqe);
			if (!ret) {
				sxe2_cq_pollinfo_to_wc(entry + npolled,
						       cur_cqe);
			}
		}

		if (ret == SXE2_CQ_OK) {
			++npolled;
			continue;
		}

		if (ret == -ENOENT)
			break;
	}

	spin_unlock_irqrestore(&rdma_cq->lock, flags);

	return npolled;
}

static void sxe2_cq_arm_notify(struct sxe2_rdma_cq_uk *arm_cq,
			       enum sxe2_arm_type arm_type)
{
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_cq *cq_ctx;
	uint64_t doorbell;
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	cq_ctx	 = container_of(arm_cq, struct sxe2_rdma_ctx_cq, cq_uk);
	rdma_dev = to_rdmadev(cq_ctx->dev);

	arm_cq->arm_sn++;
	sn = arm_cq->arm_sn & 3;
	ci = SXE2_RING_CURRENT_HEAD(arm_cq->cq_ring);

	if (arm_type == SXE2_CQ_ARM_SOLICITED)
		cmd = (uint32_t)SXE2_CQ_DB_REQ_SOLICITED;
	else
		cmd = SXE2_CQ_DB_REQ_NOSOLICITED;

	doorbell = 0;
	doorbell = sn << 29 | cmd | ci;
	doorbell <<= 32;
	doorbell |= arm_cq->cq_id;

	arm_cq->doorbell_note[SXE2_CQ_ARM_DB] =
		cpu_to_le32(sn << 29 | cmd | ci);

	dma_wmb();

	set_64bit_val(arm_cq->cqe_alloc_db, 0, doorbell);
	DRV_RDMA_LOG_DEV_DEBUG("CQ(kernel) (%u -> %p) ARM NOTIFY DBNOTE(0x%x)\n"
			       " DB(0x%llx) CI(%u) SN(%u) CMD(%u)\n",
			       arm_cq->cq_id, arm_cq->cqe_alloc_db,
			       cpu_to_le32(sn << 29 | cmd | ci),
			       cpu_to_le64(doorbell), ci, sn, cmd);
}

int sxe2_kreq_notify_cq(struct ib_cq *ibcq,
			enum ib_cq_notify_flags notify_flags)
{
	struct sxe2_rdma_cq *rdma_cq;
	struct sxe2_rdma_cq_uk *arm_cq;
	unsigned long flags	    = 0;
	enum sxe2_arm_type arm_type = SXE2_CQ_ARM_NEXT;
	bool promo_event	    = false;
	int ret			    = 0;

	rdma_cq = ibcq_to_vendor_cq(ibcq);
	arm_cq	= &rdma_cq->cq_ctx.cq_uk;

	spin_lock_irqsave(&rdma_cq->lock, flags);
	if (notify_flags == IB_CQ_SOLICITED) {
		arm_type = SXE2_CQ_ARM_SOLICITED;
	} else {
		if (rdma_cq->arm_type == SXE2_CQ_ARM_SOLICITED)
			promo_event = true;
	}

	if (!atomic_cmpxchg(&rdma_cq->armed, 0, 1) || promo_event) {
		rdma_cq->arm_type = arm_type;
		sxe2_cq_arm_notify(arm_cq, arm_type);
	}

	if ((notify_flags & IB_CQ_REPORT_MISSED_EVENTS) &&
	    (!sxe2_cq_empty(arm_cq) || !list_empty(&rdma_cq->cmpl_generated))) {
		ret = 1;
	}

	spin_unlock_irqrestore(&rdma_cq->lock, flags);

	return ret;
}

static bool qp_has_unpolled_cqes(struct sxe2_rdma_qp *rdma_qp,
				 struct sxe2_rdma_cq *iwcq)
{
	struct sxe2_rdma_cq_uk *cq	  = &iwcq->cq_ctx.cq_uk;
	struct sxe2_qp_common *qp	  = &rdma_qp->qp_ctx.qp_common;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;
	u32 cq_head			  = SXE2_RING_CURRENT_HEAD(cq->cq_ring);
	struct sxe2_cqe_info cqe_info;
	__le64 *cqe;
	u8 cq_polarity;
	int ret;

	cq_polarity = cq->polarity;
	do {
		cqe = ((struct sxe2_cqe *)(cq->cq_base))[cq_head].buf;
		ret = sxe2_read_cqe(cqe, cq_polarity, &cqe_info);
		if (ret)
			break;

		if ((struct sxe2_qp_common *)(unsigned long)
			    cqe_info.info.field.qpc == qp) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"qp [%u] has unpolled cqe left, cq id = %u\n",
				qp->qpn, cq->cq_id);
			return true;
		}

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			cq_polarity ^= 1;
	} while (true);

	DRV_RDMA_LOG_DEV_DEBUG(
		"qp [%u] doesn't have unpolled cqe left, cq id = %u\n", qp->qpn,
		cq->cq_id);

	return false;
}

static void sxe2_set_cpi_common_values(struct sxe2_cqe_info *cqeinfo,
				       struct sxe2_qp_common *qp, u32 qp_num)
{
	cqeinfo->info.field.error     = 1;
	cqeinfo->info.field.major_err = SXE2_WR_FLUSH_ERR;
	cqeinfo->info.field.qpc	      = (uintptr_t)qp;
	cqeinfo->info.field.qp_id     = qp_num;
}

void sxe2_generate_flush_completions(struct sxe2_rdma_qp *rdma_qp)
{
	struct sxe2_qp_common *qp	  = &rdma_qp->qp_ctx.qp_common;
	struct sxe2_ring *sq_ring	  = &qp->sq_ring;
	struct sxe2_ring *rq_ring	  = &qp->rq_ring;
	struct sxe2_rdma_device *rdma_dev = rdma_qp->dev;
	struct sxe2_flushed_cqe *flushed_cqe;
	__le64 *sw_wqe;
	u64 wqe_hdr;
	u32 wqe_idx;
	bool compl_generated = false;
	unsigned long flags1 = 0;
	unsigned long flags2 = 0;

	spin_lock_irqsave(&rdma_qp->send_cq->lock, flags1);
	if (!qp_has_unpolled_cqes(rdma_qp, rdma_qp->send_cq)) {
		spin_lock_irqsave(&rdma_qp->lock, flags2);
		while (SXE2_RING_MORE_WORK(*sq_ring)) {
			flushed_cqe = kzalloc(sizeof(*flushed_cqe), GFP_ATOMIC);
			if (!flushed_cqe) {
				spin_unlock_irqrestore(&rdma_qp->lock, flags2);
				spin_unlock_irqrestore(&rdma_qp->send_cq->lock,
						       flags1);
				return;
			}

			wqe_idx = sq_ring->tail;
			sxe2_set_cpi_common_values(&flushed_cqe->cqeinfo, qp,
						   qp->qpn);

			flushed_cqe->cqeinfo.wr_id =
				qp->sq_wrtrk_array[wqe_idx].wrid;
			sw_wqe = qp->sq_base[wqe_idx].elem;
			get_64bit_val(sw_wqe, 24, &wqe_hdr);
			flushed_cqe->cqeinfo.info.field.op =
				(u8)FIELD_GET(SXE2_WQE_OPCODE, wqe_hdr);
			flushed_cqe->cqeinfo.info.field.qp_type =
				SXE2_CQE_QTYPE_SQ;
			flushed_cqe->cqeinfo.info.field.wq_desc_idx = wqe_idx;

			SXE2_RING_SET_TAIL(
				*sq_ring,
				sq_ring->tail +
					qp->sq_wrtrk_array[sq_ring->tail]
						.quanta);

			if (flushed_cqe->cqeinfo.info.field.op ==
			    SXE2_OP_TYPE_NOP) {
				kfree(flushed_cqe);
				continue;
			}
			list_add_tail(&flushed_cqe->list,
				      &rdma_qp->send_cq->cmpl_generated);
			DRV_RDMA_LOG_DEV_DEBUG(
				"adding wr_id = 0x%llx SQ Completion\n"
				"\tto list qp_id=%u, wqe_idx=%u\n",
				flushed_cqe->cqeinfo.wr_id, qp->qpn, wqe_idx);
			compl_generated = true;
		}
		spin_unlock_irqrestore(&rdma_qp->lock, flags2);
		spin_unlock_irqrestore(&rdma_qp->send_cq->lock, flags1);
		if (compl_generated) {
			sxe2_rdma_comp_handler(&rdma_qp->send_cq->cq_ctx);
			compl_generated = false;
		}
	} else {
		spin_unlock_irqrestore(&rdma_qp->send_cq->lock, flags1);
		sxe2_sched_qp_flush_work(rdma_qp);
	}

	spin_lock_irqsave(&rdma_qp->recv_cq->lock, flags1);
	if (rq_ring->size && !qp_has_unpolled_cqes(rdma_qp, rdma_qp->recv_cq)) {
		spin_lock_irqsave(&rdma_qp->lock, flags2);
		while (SXE2_RING_MORE_WORK(*rq_ring)) {
			flushed_cqe = kzalloc(sizeof(*flushed_cqe), GFP_ATOMIC);
			if (!flushed_cqe) {
				spin_unlock_irqrestore(&rdma_qp->lock, flags2);
				spin_unlock_irqrestore(&rdma_qp->recv_cq->lock,
						       flags1);
				return;
			}

			wqe_idx = rq_ring->tail;
			sxe2_set_cpi_common_values(&flushed_cqe->cqeinfo, qp,
						   qp->qpn);

			flushed_cqe->cqeinfo.wr_id = qp->rq_wrid_array[wqe_idx];
			flushed_cqe->cqeinfo.info.field.qp_type =
				SXE2_CQE_QTYPE_RQ;
			flushed_cqe->cqeinfo.info.field.wq_desc_idx = wqe_idx;
			SXE2_RING_SET_TAIL(*rq_ring, rq_ring->tail + 1);

			list_add_tail(&flushed_cqe->list,
				      &rdma_qp->recv_cq->cmpl_generated);
			DRV_RDMA_LOG_DEV_DEBUG(
				"adding wr_id = 0x%llx RQ Completion to\n"
				"\tlist qp_id=%u, wqe_idx=%u\n",
				flushed_cqe->cqeinfo.wr_id, qp->qpn, wqe_idx);

			compl_generated = true;
		}
		spin_unlock_irqrestore(&rdma_qp->lock, flags2);
		spin_unlock_irqrestore(&rdma_qp->recv_cq->lock, flags1);
		if (compl_generated)
			sxe2_rdma_comp_handler(&rdma_qp->recv_cq->cq_ctx);
	} else {
		spin_unlock_irqrestore(&rdma_qp->recv_cq->lock, flags1);
		sxe2_sched_qp_flush_work(rdma_qp);
	}
}

static void sxe2_clean_base_cqe(struct sxe2_qp_common *qp,
				struct sxe2_rdma_cq_uk *cq, int cq_type)
{
	__le64 *cqe;
	u64 cqe_hdr, qpc;
	u32 cq_head;
	u8 polarity, cq_polarity;

	cq_head	    = cq->cq_ring.head;
	cq_polarity = cq->polarity;
	do {
		cqe = ((struct sxe2_cqe *)(cq->cq_base))[cq_head].buf;
		get_64bit_val(cqe, 56, &cqe_hdr);
		polarity = (u8)FIELD_GET(SXE2_CQE_VALID, cqe_hdr);

		if (polarity != cq_polarity)
			break;

		dma_rmb();

		get_64bit_val(cqe, 8, &qpc);
		if ((void *)(unsigned long)qpc == qp)
			set_64bit_val(cqe, 8, 0);

		cq_head = (cq_head + 1) % cq->cq_ring.size;
		if (!cq_head)
			cq_polarity ^= 1;
	} while (true);
}

void sxe2_clean_cqes(struct sxe2_rdma_qp *rdma_qp, struct sxe2_rdma_cq *rdma_cq,
		     int cq_type)
{
	struct sxe2_rdma_cq_uk *ukcq = &rdma_cq->cq_ctx.cq_uk;
	unsigned long flags	     = 0;
	struct sxe2_flushed_cqe *flushed_cqe;
	struct list_head *tmp_node, *list_node;

	spin_lock_irqsave(&rdma_cq->lock, flags);
	sxe2_clean_base_cqe(&rdma_qp->qp_ctx.qp_common, ukcq, cq_type);

	list_for_each_safe(list_node, tmp_node, &rdma_cq->cmpl_generated) {
		flushed_cqe =
			list_entry(list_node, struct sxe2_flushed_cqe, list);
		if (flushed_cqe->cqeinfo.info.field.qp_id ==
		    rdma_qp->ibqp.qp_num) {
#ifdef SXE2_CFG_DEBUG
			if (flushed_cqe->cqeinfo.info.field.qp_type ==
			    SXE2_CQE_QTYPE_SQ) {
				rdma_qp->qp_ctx.qp_common.statistics
					.cleaned_flushsq_cnt++;
			} else {
				rdma_qp->qp_ctx.qp_common.statistics
					.cleaned_flushrq_cnt++;
			}
#endif
			list_del(&flushed_cqe->list);
			kfree(flushed_cqe);
		}
	}

	spin_unlock_irqrestore(&rdma_cq->lock, flags);
}

static __le64 *sxe2_srq_get_next_recv_wqe(struct sxe2_rdma_srq *ksrq,
					  __u32 *wqe_idx)
{
	struct sxe2_srq_drv *ksrq_drv;
	int ret_code;
	__le64 *wqe;

	ksrq_drv = &ksrq->srq_ctx.srq_drv;
	if (SXE2_RING_FULL_ERR(ksrq_drv->srq_ring))
		return NULL;

	*wqe_idx = SXE2_RING_CURRENT_HEAD(ksrq_drv->srq_ring);
	if (ksrq->srq_ctx.ksrq_rsc.srqe_array[*wqe_idx] == SXE2_SRQE_BUSY)
		return NULL;

	SXE2_RING_MOVE_HEAD(ksrq_drv->srq_ring, ret_code);
	if (ret_code)
		return NULL;

	ksrq->srq_ctx.ksrq_rsc.srqe_array[*wqe_idx] = SXE2_SRQE_BUSY;

	if (!*wqe_idx)
		ksrq_drv->srq_polarity = !ksrq_drv->srq_polarity;

	wqe = ksrq_drv->srq_base[*wqe_idx * ksrq_drv->wqe_size_multiplier].elem;

	return wqe;
}

static int sxe2_hw_srq_post_receive(struct sxe2_rdma_srq *ksrq,
				    struct sxe2_rq_info *info)
{
	struct sxe2_srq_drv *ksrq_drv;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_kmode_srq *ksrq_rsc;
	__u32 wqe_idx, i, byte_off;
	__u32 addl_sge_cnt;
	__le64 *wqe;
	__u64 hdr;

	rdma_dev = to_dev(ksrq->ibsrq.device);
	ksrq_rsc = &ksrq->srq_ctx.ksrq_rsc;
	ksrq_drv = &ksrq->srq_ctx.srq_drv;
	wqe	 = sxe2_srq_get_next_recv_wqe(ksrq, &wqe_idx);
	if (!wqe)
		return -ENOMEM;

	ksrq_rsc->srq_wrid_array[wqe_idx] = info->wr_id;

	addl_sge_cnt = info->num_sges > 1 ? info->num_sges - 1 : 0;
	sxe2_set_sgelist_data(wqe, 0, info->sg_list, ksrq_drv->srq_polarity);

	for (i = 1, byte_off = 32; i < info->num_sges; i++) {
		sxe2_set_sgelist_data(wqe, byte_off, &info->sg_list[i],
				      ksrq_drv->srq_polarity);
		byte_off += 16;
	}

	if (!(info->num_sges & 0x01) && info->num_sges) {
		sxe2_set_sgelist_data(wqe, byte_off, NULL,
				      ksrq_drv->srq_polarity);
	}

	hdr = FIELD_PREP(SXE2_WQE_ADDSGECNT, addl_sge_cnt) |
	      FIELD_PREP(SXE2_WQE_VALID, ksrq_drv->srq_polarity);

	dma_wmb();

	set_64bit_val(wqe, 24, hdr);

	set_64bit_val(ksrq_drv->db_note, 0,
		      (__u64)SXE2_RING_CURRENT_HEAD(ksrq_drv->srq_ring) *
			      ksrq_drv->wqe_size_multiplier);

	DRV_RDMA_LOG_DEV_DEBUG("POST SRQ RCV(srqn = %u): wqe_idx %u\n"
			       "wr_id %llu ring_size %u mul_size %d\n",
			       ksrq->srq_id, wqe_idx,
			       ksrq_rsc->srq_wrid_array[wqe_idx],
			       SXE2_RING_SIZE(ksrq_drv->srq_ring),
			       ksrq_drv->wqe_size_multiplier);
	for (i = 0; i < info->num_sges; i++) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"sgelist[%d] addr 0x%llx len [%u] lkey [%u]\n", i,
			info->sg_list[i].addr, info->sg_list[i].length,
			info->sg_list[i].lkey);
	}

	return 0;
}

int sxe2_kpost_srq_recv(struct ib_srq *ib_srq, const struct ib_recv_wr *ib_wr,
			const struct ib_recv_wr **bad_wr)
{
	struct sxe2_rdma_srq *ksrq    = to_srq(ib_srq);
	struct sxe2_srq_drv *ksrq_drv = &ksrq->srq_ctx.srq_drv;
	struct sxe2_rq_info rq_info   = {};
	unsigned long flags	      = 0;
	int err			      = 0;

	spin_lock_irqsave(&ksrq->lock, flags);
	while (ib_wr) {
		if (ib_wr->num_sge > (int)ksrq_drv->max_srq_frag_cnt) {
			err = -EINVAL;
			goto out;
		}

		rq_info.num_sges = (u32)ib_wr->num_sge;
		rq_info.wr_id	 = ib_wr->wr_id;
		rq_info.sg_list	 = ib_wr->sg_list;
		err		 = sxe2_hw_srq_post_receive(ksrq, &rq_info);
		if (err)
			goto out;

		ib_wr = ib_wr->next;
	}

out:
	spin_unlock_irqrestore(&ksrq->lock, flags);

	if (err)
		*bad_wr = ib_wr;

	return err;
}
