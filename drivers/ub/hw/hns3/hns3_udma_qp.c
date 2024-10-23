// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include "hns3_udma_dca.h"
#include "hns3_udma_jfs.h"
#include "hns3_udma_jfr.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_abi.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_jetty.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_db.h"
#include "hns3_udma_eid.h"

static bool um_spray_en;
static ushort um_data_udp_start;
static ushort um_udp_range;

static inline uint8_t get_qp_bankid(uint64_t qpn)
{
	/* The lower 3 bits of QPN are used to hash to different banks */
	return (uint8_t)(qpn & QP_BANKID_MASK);
}

bool is_rc_jetty(struct hns3_udma_qp_attr *qp_attr)
{
	return (qp_attr->is_jetty && qp_attr->jetty && qp_attr->tp_mode == UBCORE_TP_RC);
}

bool is_rq_jetty(struct hns3_udma_qp_attr *qp_attr)
{
	return (qp_attr->is_jetty && qp_attr->jetty);
}

static void set_qpc_wqe_cnt(struct hns3_udma_qp *qp,
			    struct hns3_udma_qp_context *context,
			    struct hns3_udma_qp_context *context_mask)
{
	hns3_udma_reg_write(context, QPC_SGE_SHIFT,
			    to_hns3_udma_hem_entries_shift(qp->sge.sge_cnt,
							   qp->sge.sge_shift));
	hns3_udma_reg_clear(context_mask, QPC_SGE_SHIFT);

	hns3_udma_reg_write(context, QPC_SQ_SHIFT, ilog2(qp->sq.wqe_cnt));
	hns3_udma_reg_clear(context_mask, QPC_SQ_SHIFT);

	if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		hns3_udma_reg_write(context, QPC_RQ_SHIFT, ilog2(qp->rq.wqe_cnt));
		hns3_udma_reg_clear(context_mask, QPC_RQ_SHIFT);
	}
}

static void config_qp_sq_buf_mask(struct hns3_udma_qp_context *context_mask)
{
	hns3_udma_reg_clear(context_mask, QPC_SQ_CUR_BLK_ADDR_L);
	hns3_udma_reg_clear(context_mask, QPC_SQ_CUR_BLK_ADDR_H);
	hns3_udma_reg_clear(context_mask, QPC_SQ_CUR_SGE_BLK_ADDR_L);
	hns3_udma_reg_clear(context_mask, QPC_SQ_CUR_SGE_BLK_ADDR_H);
	hns3_udma_reg_clear(context_mask, QPC_RX_SQ_CUR_BLK_ADDR_L);
	hns3_udma_reg_clear(context_mask, QPC_RX_SQ_CUR_BLK_ADDR_H);
	hns3_udma_reg_clear(context_mask, QPC_WQE_SGE_BA_L);
	hns3_udma_reg_clear(context_mask, QPC_WQE_SGE_BA_H);
	hns3_udma_reg_clear(context_mask, QPC_SQ_HOP_NUM);
	hns3_udma_reg_clear(context_mask, QPC_SGE_HOP_NUM);
	hns3_udma_reg_clear(context_mask, QPC_WQE_SGE_BA_PG_SZ);
	hns3_udma_reg_clear(context_mask, QPC_WQE_SGE_BUF_PG_SZ);
}

static int config_qp_rq_buf(struct hns3_udma_dev *udma_device,
			    struct hns3_udma_qp *qp,
			    struct hns3_udma_qp_context *context,
			    struct hns3_udma_qp_context *context_mask)
{
	uint64_t mtts_wqe[MTT_MIN_COUNT] = {};
	int count;

	/* search RQ buf's mtts */
	count = hns3_udma_mtr_find(udma_device, &qp->qp_attr.jfr->buf_mtr, qp->qp_attr.jfr->offset,
			      mtts_wqe, ARRAY_SIZE(mtts_wqe), NULL);
	if (count < 1) {
		dev_err(udma_device->dev, "failed to find QP(0x%llx) RQ buf.\n",
			qp->qpn);
		return -EINVAL;
	}

	hns3_udma_reg_write(context, QPC_RQ_HOP_NUM,
			    to_hns3_udma_hem_hopnum(udma_device->caps.wqe_rq_hop_num,
						    qp->rq.wqe_cnt));
	hns3_udma_reg_clear(context_mask, QPC_RQ_HOP_NUM);

	hns3_udma_reg_write(context, QPC_RQ_CUR_BLK_ADDR_L,
			    to_hns3_udma_hw_page_addr(mtts_wqe[0]));
	hns3_udma_reg_write(context, QPC_RQ_CUR_BLK_ADDR_H,
			    upper_32_bits(to_hns3_udma_hw_page_addr(mtts_wqe[0])));
	hns3_udma_reg_clear(context_mask, QPC_RQ_CUR_BLK_ADDR_L);
	hns3_udma_reg_clear(context_mask, QPC_RQ_CUR_BLK_ADDR_H);

	hns3_udma_reg_write(context, QPC_RQ_NXT_BLK_ADDR_L,
			    to_hns3_udma_hw_page_addr(mtts_wqe[1]));
	hns3_udma_reg_write(context, QPC_RQ_NXT_BLK_ADDR_H,
			    upper_32_bits(to_hns3_udma_hw_page_addr(mtts_wqe[1])));
	hns3_udma_reg_clear(context_mask, QPC_RQ_NXT_BLK_ADDR_L);
	hns3_udma_reg_clear(context_mask, QPC_RQ_NXT_BLK_ADDR_H);

	return 0;
}

static void hns3_udma_reg_write_qpc_sq(struct hns3_udma_qp_context *context, uint64_t sge_cur_blk,
				       uint64_t sq_cur_blk, uint64_t wqe_sge_ba)
{
	hns3_udma_reg_write(context, QPC_SQ_CUR_BLK_ADDR_L,
			    lower_32_bits(to_hns3_udma_hw_page_addr(sq_cur_blk)));
	hns3_udma_reg_write(context, QPC_SQ_CUR_BLK_ADDR_H,
			    upper_32_bits(to_hns3_udma_hw_page_addr(sq_cur_blk)));
	hns3_udma_reg_write(context, QPC_SQ_CUR_SGE_BLK_ADDR_L,
			    lower_32_bits(to_hns3_udma_hw_page_addr(sge_cur_blk)));
	hns3_udma_reg_write(context, QPC_SQ_CUR_SGE_BLK_ADDR_H,
			    upper_32_bits(to_hns3_udma_hw_page_addr(sge_cur_blk)));
	hns3_udma_reg_write(context, QPC_RX_SQ_CUR_BLK_ADDR_L,
			    lower_32_bits(to_hns3_udma_hw_page_addr(sq_cur_blk)));
	hns3_udma_reg_write(context, QPC_RX_SQ_CUR_BLK_ADDR_H,
			    upper_32_bits(to_hns3_udma_hw_page_addr(sq_cur_blk)));
	hns3_udma_reg_write(context, QPC_WQE_SGE_BA_H, wqe_sge_ba >>
			    (WQE_SGE_BA_OFFSET + H_ADDR_OFFSET));
}

static void hns3_udma_reg_write_hopnum(struct hns3_udma_dev *udma_device,
				       struct hns3_udma_qp_context *context,
				       struct hns3_udma_qp *qp)
{
	hns3_udma_reg_write(context, QPC_SQ_HOP_NUM,
			    to_hns3_udma_hem_hopnum(udma_device->caps.wqe_sq_hop_num,
						    qp->sq.wqe_cnt));
	hns3_udma_reg_write(context, QPC_SGE_HOP_NUM,
			    to_hns3_udma_hem_hopnum(udma_device->caps.wqe_sge_hop_num,
						    qp->sge.sge_cnt));
	hns3_udma_reg_write(context, QPC_WQE_SGE_BA_PG_SZ,
			    to_hns3_udma_hw_page_shift(qp->mtr.hem_cfg.ba_pg_shift));
	hns3_udma_reg_write(context, QPC_WQE_SGE_BUF_PG_SZ,
			    to_hns3_udma_hw_page_shift(qp->mtr.hem_cfg.buf_pg_shift));
}

static int config_qp_sq_buf(struct hns3_udma_dev *udma_device,
			    struct hns3_udma_qp *qp,
			    struct hns3_udma_qp_context *context,
			    struct hns3_udma_qp_context *context_mask)
{
	uint64_t sge_cur_blk = 0;
	uint64_t sq_cur_blk = 0;
	uint64_t wqe_sge_ba = 0;
	int count;

	/* search qp buf's mtts */
	count = hns3_udma_mtr_find(udma_device, &qp->mtr, qp->sq.wqe_offset,
				   &sq_cur_blk, 1, &wqe_sge_ba);
	if (count < 1) {
		dev_err(udma_device->dev, "failed to find QP(0x%llx) SQ buf.\n", qp->qpn);
		return -EINVAL;
	}

	context->wqe_sge_ba = cpu_to_le32(wqe_sge_ba >> WQE_SGE_BA_OFFSET);

	if (qp->sge.sge_cnt > 0) {
		count = hns3_udma_mtr_find(udma_device, &qp->mtr,
					   qp->sge.wqe_offset, &sge_cur_blk, 1, NULL);
		if (count < 1) {
			dev_err(udma_device->dev, "failed to find QP(0x%llx) SGE buf.\n", qp->qpn);
			return -EINVAL;
		}
	}

	if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		count = config_qp_rq_buf(udma_device, qp, context, context_mask);
		if (count)
			return -EINVAL;
	}

	/*
	 * In v2 engine, software pass context and context mask to hardware
	 * when modifying qp. If software need modify some fields in context,
	 * we should set all bits of the relevant fields in context mask to
	 * 0 at the same time, else set them to 0x1.
	 */
	hns3_udma_reg_write_qpc_sq(context, sge_cur_blk, sq_cur_blk, wqe_sge_ba);
	hns3_udma_reg_write_hopnum(udma_device, context, qp);

	config_qp_sq_buf_mask(context_mask);

	return 0;
}

static void hns3_udma_set_path(struct hns3_udma_modify_tp_attr *attr,
			       struct hns3_udma_qp_context *context,
			       struct hns3_udma_qp_context *context_mask)
{
	if (attr == NULL)
		return;

	hns3_udma_reg_write(context, QPC_GMV_IDX, attr->sgid_index);
	hns3_udma_reg_clear(context_mask, QPC_GMV_IDX);

	memcpy(context->dgid, attr->dgid, sizeof(attr->dgid));
	memset(context_mask->dgid, 0, sizeof(attr->dgid));

	hns3_udma_reg_write(&(context->ext), QPCEX_DEID_H,
		       *(uint32_t *)(&attr->dgid[SGID_H_SHIFT]));
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_DEID_H);

	hns3_udma_reg_write(context, QPC_SL, attr->priority);
	hns3_udma_reg_clear(context_mask, QPC_SL);
}

static int hns3_udma_pass_qpc_to_hw(struct hns3_udma_dev *udma_device,
				    struct hns3_udma_qp_context *context,
				    struct hns3_udma_qp_context *qpc_mask,
				    struct hns3_udma_qp *qp)
{
	struct hns3_udma_cmd_mailbox *mailbox;
	struct hns3_udma_cmq_desc desc;
	int qpc_size;
	int ret;

	struct hns3_udma_mbox *mb = (struct hns3_udma_mbox *)desc.data;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mailbox = hns3_udma_alloc_cmd_mailbox(udma_device);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	mbox_desc_init(mb, mailbox->dma, 0, qp->qpn, HNS3_UDMA_CMD_MODIFY_QPC);
	qpc_size = udma_device->caps.qpc_sz;
	memcpy(mailbox->buf, context, qpc_size);
	memcpy(mailbox->buf + qpc_size, qpc_mask, qpc_size);

	ret = hns3_udma_cmd_mbox(udma_device, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);

	hns3_udma_free_cmd_mailbox(udma_device, mailbox);

	return ret;
}

int hns3_udma_set_dca_buf(struct hns3_udma_dev *dev, struct hns3_udma_qp *qp)
{
	struct hns3_udma_qp_context ctx[2] = {};
	struct hns3_udma_qp_context *msk = ctx + 1;
	struct hns3_udma_qp_context *qpc = ctx;
	int ret;

	memset(msk, 0xff, dev->caps.qpc_sz);

	ret = config_qp_sq_buf(dev, qp, qpc, msk);
	if (ret) {
		dev_err(dev->dev, "failed to config sq qpc, ret = %d.\n", ret);
		return ret;
	}

	ret = hns3_udma_pass_qpc_to_hw(dev, qpc, msk, qp);
	if (ret) {
		dev_err(dev->dev, "failed to modify DCA buf, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static bool check_qp_timeout_cfg_range(struct hns3_udma_dev *udma_device,
				       uint8_t *timeout)
{
	if (*timeout > QP_TIMEOUT_MAX) {
		dev_warn(udma_device->dev,
			 "Local ACK timeout shall be 0 to 31.\n");
		return false;
	}

	return true;
}

static enum hns3_udma_mtu to_hns3_udma_mtu(enum ubcore_mtu core_mtu)
{
	switch (core_mtu) {
	case UBCORE_MTU_256:
		return HNS3_UDMA_MTU_256;
	case UBCORE_MTU_512:
		return HNS3_UDMA_MTU_512;
	case UBCORE_MTU_1024:
		return HNS3_UDMA_MTU_1024;
	case UBCORE_MTU_2048:
		return HNS3_UDMA_MTU_2048;
	default:
		return HNS3_UDMA_MTU_4096;
	}
}

static inline enum ubcore_mtu get_mtu(struct hns3_udma_qp *qp,
				      struct ubcore_tp_attr *attr)
{
	if (qp->qp_type == QPT_UD || attr == NULL)
		return UBCORE_MTU_4096;

	return attr->mtu;
}

static int hns3_udma_alloc_reorder_cq_buf(struct hns3_udma_dev *udma_dev,
					  struct hns3_udma_qp_attr *qp_attr)
{
	struct hns3_udma_caps *caps = &udma_dev->caps;
	int buff_sz;

	buff_sz = (1 << caps->reorder_cq_shift) * caps->cqe_sz;
	qp_attr->reorder_cq_size = buff_sz;
	qp_attr->reorder_cq_page = dma_alloc_coherent(udma_dev->dev, buff_sz,
						      &qp_attr->reorder_cq_addr,
						      GFP_KERNEL);
	if (!qp_attr->reorder_cq_page) {
		dev_err(udma_dev->dev, "Dma alloc coherent failed\n");
		return -ENOMEM;
	}

	return 0;
}

static void hns3_udma_free_reorder_cq_buf(struct hns3_udma_dev *udma_dev,
					  struct hns3_udma_qp_attr *qp_attr)
{
	if (qp_attr->reorder_cq_page)
		dma_free_coherent(udma_dev->dev, qp_attr->reorder_cq_size,
				  qp_attr->reorder_cq_page,
				  qp_attr->reorder_cq_addr);
}

static void edit_qpc_for_inline(struct hns3_udma_qp_context *context,
				struct hns3_udma_qp_context *context_mask,
				struct hns3_udma_qp *qp)
{
	struct hns3_udma_dev *udma_dev = qp->udma_device;

	if (qp->qp_type != QPT_UD) {
		hns3_udma_reg_write(context, QPC_CQEIE,
				    !!(udma_dev->caps.flags &
				    HNS3_UDMA_CAP_FLAG_CQE_INLINE));
		hns3_udma_reg_clear(context_mask, QPC_CQEIE);
	}
}

static void edit_qpc_for_db(struct hns3_udma_qp_context *context,
			    struct hns3_udma_qp_context *context_mask,
			    struct hns3_udma_qp *qp)
{
	if (qp->en_flags & HNS3_UDMA_QP_CAP_RQ_RECORD_DB) {
		hns3_udma_reg_enable(context, QPC_RQ_RECORD_EN);
		hns3_udma_reg_clear(context_mask, QPC_RQ_RECORD_EN);
		if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
		    !qp->qp_attr.jetty->dca_en) {
			hns3_udma_reg_write(context, QPC_RQ_DB_RECORD_ADDR_L,
				lower_32_bits(qp->qp_attr.jfr->db.dma) >>
						DMA_DB_RECORD_SHIFT);
			hns3_udma_reg_write(context, QPC_RQ_DB_RECORD_ADDR_H,
				upper_32_bits(qp->qp_attr.jfr->db.dma));

			hns3_udma_reg_clear(context_mask, QPC_RQ_DB_RECORD_ADDR_L);
			hns3_udma_reg_clear(context_mask, QPC_RQ_DB_RECORD_ADDR_H);
		}
	}

	if (qp->en_flags & HNS3_UDMA_QP_CAP_OWNER_DB) {
		hns3_udma_reg_enable(context, QPC_OWNER_MODE);
		hns3_udma_reg_clear(context_mask, QPC_OWNER_MODE);
	}
}

static void edit_qpc_for_srqn(struct hns3_udma_qp *qp,
			      struct hns3_udma_qp_context *context,
			      struct hns3_udma_qp_context *context_mask)
{
	hns3_udma_reg_clear(context_mask, QPC_SRQ_EN);
	hns3_udma_reg_clear(context_mask, QPC_INV_CREDIT);
	if (qp->qp_attr.jfr) {
		if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
		    !qp->qp_attr.jetty->dca_en)
			return;
		hns3_udma_reg_enable(context, QPC_SRQ_EN);
		hns3_udma_reg_enable(context, QPC_INV_CREDIT);

		hns3_udma_reg_write(context, QPC_SRQN, qp->qp_attr.jfr->srqn);
		hns3_udma_reg_clear(context_mask, QPC_SRQN);
	}
}

static void edit_qpc_for_rxcqn(struct hns3_udma_qp *qp,
			       struct hns3_udma_qp_context *context,
			       struct hns3_udma_qp_context *context_mask)
{
	if (qp->recv_jfc) {
		hns3_udma_reg_write(context, QPC_RX_CQN, qp->recv_jfc->cqn);
		hns3_udma_reg_clear(context_mask, QPC_RX_CQN);
	}
}

static void edit_qpc_for_retransmission_parm(struct hns3_udma_dev *udma_device,
					     struct hns3_udma_qp *qp,
					     struct hns3_udma_modify_tp_attr *attr,
					     struct hns3_udma_qp_context *context,
					     struct hns3_udma_qp_context *context_mask)
{
	if (qp->qp_type != QPT_UD) {
		hns3_udma_reg_write(context, QPC_MIN_RNR_TIME,
				    attr->min_rnr_timer);
		hns3_udma_reg_clear(context_mask, QPC_MIN_RNR_TIME);

		hns3_udma_reg_write(context, QPC_RETRY_CNT,
				    attr->retry_cnt);
		hns3_udma_reg_clear(context_mask, QPC_RETRY_CNT);

		hns3_udma_reg_write(context, QPC_RETRY_NUM_INIT,
				    attr->retry_cnt);
		hns3_udma_reg_clear(context_mask, QPC_RETRY_NUM_INIT);

		hns3_udma_reg_write(context, QPC_RNR_CNT,
				    attr->rnr_retry);
		hns3_udma_reg_clear(context_mask, QPC_RNR_CNT);

		hns3_udma_reg_write(context, QPC_RNR_NUM_INIT,
				    attr->rnr_retry);
		hns3_udma_reg_clear(context_mask, QPC_RNR_NUM_INIT);

		if (check_qp_timeout_cfg_range(udma_device, &attr->ack_timeout)) {
			hns3_udma_reg_write(context, QPC_AT, attr->ack_timeout);
			hns3_udma_reg_clear(context_mask, QPC_AT);
		}
	}
}

static void edit_qpc_for_write(struct hns3_udma_qp *qp,
			       struct hns3_udma_qp_context *context,
			       struct hns3_udma_qp_context *context_mask)
{
	hns3_udma_reg_enable(context, QPC_FLUSH_EN);
	hns3_udma_reg_clear(context_mask, QPC_FLUSH_EN);

	hns3_udma_reg_enable(context, QPC_AW_EN);
	hns3_udma_reg_clear(context_mask, QPC_AW_EN);

	hns3_udma_reg_enable(context, QPC_WN_EN);
	hns3_udma_reg_clear(context_mask, QPC_WN_EN);

	hns3_udma_reg_enable(context, QPC_RMT_E2E);
	hns3_udma_reg_clear(context_mask, QPC_RMT_E2E);

	hns3_udma_reg_write(context, QPC_SIG_TYPE, SIGNAL_REQ_WR);
	hns3_udma_reg_clear(context_mask, QPC_SIG_TYPE);
}

static void edit_qpc_for_receive(struct hns3_udma_qp *qp,
				 struct hns3_udma_modify_tp_attr *attr,
				 struct hns3_udma_qp_context *context,
				 struct hns3_udma_qp_context *context_mask)
{
	uint8_t *dmac;

	dmac = (uint8_t *)attr->dmac;
	memcpy(&context->dmac, dmac, sizeof(uint32_t));
	hns3_udma_reg_write(context, QPC_DMAC_L, *((uint32_t *)(&dmac[0])));
	hns3_udma_reg_clear(context_mask, QPC_DMAC_L);

	hns3_udma_reg_write(context, QPC_DMAC_H,
			    *((uint16_t *)(&dmac[QPC_DMAC_H_IDX])));
	hns3_udma_reg_clear(context_mask, QPC_DMAC_H);

	context->rq_rnr_timer = 0;
	context_mask->rq_rnr_timer = 0;

	/* rocee send 2^lp_sgen_ini segs every time */
	hns3_udma_reg_write(context, QPC_LP_SGEN_INI, SGEN_INI_VALUE);
	hns3_udma_reg_clear(context_mask, QPC_LP_SGEN_INI);
}

static int modify_qp_reset_to_rtr(struct hns3_udma_qp *qp,
				  struct hns3_udma_modify_tp_attr *attr,
				  struct hns3_udma_qp_context *context,
				  struct hns3_udma_qp_context *context_mask)
{
	struct hns3_udma_dev *udma_device = qp->udma_device;

	hns3_udma_reg_write(context, QPC_RRE, 1);
	hns3_udma_reg_clear(context_mask, QPC_RRE);

	hns3_udma_reg_write(context, QPC_RWE, 1);
	hns3_udma_reg_clear(context_mask, QPC_RWE);

	hns3_udma_reg_write(context, QPC_TST, qp->qp_type);
	hns3_udma_reg_clear(context_mask, QPC_TST);

	hns3_udma_reg_write(context, QPC_RQWS, ilog2(qp->rq.max_gs));
	hns3_udma_reg_clear(context_mask, QPC_RQWS);

	/* No VLAN need to set 0xFFF */
	hns3_udma_reg_write(context, QPC_VLAN_ID, 0xfff);
	hns3_udma_reg_clear(context_mask, QPC_VLAN_ID);

	edit_qpc_for_db(context, context_mask, qp);

	edit_qpc_for_inline(context, context_mask, qp);

	hns3_udma_reg_write(&context->ext, QPCEX_P_TYPE, QPCEX_P_TYPE_HNS3_UDMA);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_P_TYPE);

	edit_qpc_for_srqn(qp, context, context_mask);

	edit_qpc_for_retransmission_parm(udma_device, qp, attr, context, context_mask);

	edit_qpc_for_rxcqn(qp, context, context_mask);

	/*
	 * Enable atomic WRITE and persistence WRITE and Write With Notify
	 * operations in QPC when modify_qp_init_to_rtr.
	 */
	edit_qpc_for_write(qp, context, context_mask);

	edit_qpc_for_receive(qp, attr, context, context_mask);

	return 0;
}

static int modify_qp_rtr_to_rts(struct hns3_udma_qp *qp,
				struct hns3_udma_qp_context *context,
				struct hns3_udma_qp_context *context_mask)
{
	struct hns3_udma_dev *udma_device = qp->udma_device;
	int ret;

	qp->sq.wqe_offset = qp->sq.offset;
	qp->sge.wqe_offset = qp->sge.offset;
	qp->rq.wqe_offset = qp->rq.offset;

	ret = config_qp_sq_buf(udma_device, qp, context, context_mask);
	if (ret) {
		dev_err(udma_device->dev, "failed to config sq buf, ret = %d.\n",
			ret);
		return ret;
	}
	if (qp->send_jfc) {
		hns3_udma_reg_write(context, QPC_TX_CQN, qp->send_jfc->cqn);
		hns3_udma_reg_clear(context_mask, QPC_TX_CQN);
	}

	if (qp->en_flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH) {
		hns3_udma_reg_enable(context, QPC_DCA_MODE);
		hns3_udma_reg_clear(context_mask, QPC_DCA_MODE);
	}

	set_qpc_wqe_cnt(qp, context, context_mask);

	return 0;
}

static enum hns3_udma_cong_type to_hns3_udma_cong_type(uint32_t cc_alg)
{
	switch ((enum ubcore_tp_cc_alg)cc_alg) {
	case UBCORE_TP_CC_DCQCN:
		return HNS3_UDMA_CONG_TYPE_DCQCN;
	case UBCORE_TP_CC_LDCP:
		return HNS3_UDMA_CONG_TYPE_LDCP;
	case UBCORE_TP_CC_HC3:
		return HNS3_UDMA_CONG_TYPE_HC3;
	case UBCORE_TP_CC_DIP:
		return HNS3_UDMA_CONG_TYPE_DIP;
	default:
		return HNS3_UDMA_CONG_TYPE_DCQCN;
	}
}

static void fill_congest_type(struct hns3_udma_congestion_algorithm *congest_alg,
			      enum hns3_udma_cong_type qp_cong_alg)
{
	switch (qp_cong_alg) {
	case HNS3_UDMA_CONG_TYPE_DCQCN:
		congest_alg->congest_type = CONGEST_DCQCN;
		congest_alg->alg_sel = DCQCN_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	case HNS3_UDMA_CONG_TYPE_LDCP:
		congest_alg->congest_type = CONGEST_LDCP;
		congest_alg->alg_sel = WINDOW_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_UNLIMIT;
		break;
	case HNS3_UDMA_CONG_TYPE_HC3:
		congest_alg->congest_type = CONGEST_HC3;
		congest_alg->alg_sel = WINDOW_ALG;
		congest_alg->alg_sub_sel = SUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	case HNS3_UDMA_CONG_TYPE_DIP:
		congest_alg->congest_type = CONGEST_DIP;
		congest_alg->alg_sel = DCQCN_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_VALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	default:
		congest_alg->congest_type = CONGEST_DCQCN;
		congest_alg->alg_sel = DCQCN_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	}
}

static int get_dip_ctx_idx(struct hns3_udma_qp *qp,
			   uint32_t *dip_idx)
{
	struct hns3_udma_dev *udma_dev = qp->udma_device;
	unsigned long *qpn_bitmap = udma_dev->qp_table.idx_table.qpn_bitmap;
	unsigned long *dip_idx_bitmap =
			udma_dev->qp_table.idx_table.dip_idx_bitmap;
	struct hns3_udma_modify_tp_attr *attr;
	struct hns3_udma_dip *udma_dip;
	unsigned long flags;
	uint32_t idx;
	int ret = 0;

	attr = &qp->m_attr;
	spin_lock_irqsave(&udma_dev->dip_list_lock, flags);
	if (!test_bit(qp->qpn, dip_idx_bitmap))
		set_bit(qp->qpn, qpn_bitmap);

	list_for_each_entry(udma_dip, &udma_dev->dip_list, node) {
		if (!memcmp(attr->dgid, udma_dip->dgid, HNS3_UDMA_GID_SIZE)) {
			*dip_idx = udma_dip->dip_idx;
			udma_dip->qp_cnt++;
			qp->dip = udma_dip;
			goto out;
		}
	}

	udma_dip = kzalloc(sizeof(*udma_dip), GFP_ATOMIC);
	if (!udma_dip) {
		ret = -ENOMEM;
		goto out;
	}

	idx = find_first_bit(qpn_bitmap, udma_dev->caps.num_qps);
	if (idx < udma_dev->caps.num_qps) {
		*dip_idx = idx;
		clear_bit(idx, qpn_bitmap);
		set_bit(idx, dip_idx_bitmap);
	} else {
		ret = -ENOENT;
		kfree(udma_dip);
		goto out;
	}

	(void)memcpy(udma_dip->dgid, attr->dgid, sizeof(attr->dgid));
	udma_dip->dip_idx = *dip_idx;
	udma_dip->qp_cnt++;
	qp->dip = udma_dip;
	list_add_tail(&udma_dip->node, &udma_dev->dip_list);

out:
	spin_unlock_irqrestore(&udma_dev->dip_list_lock, flags);
	return ret;
}

static int hns3_udma_set_cong_fields(struct hns3_udma_qp_context *context,
				     struct hns3_udma_qp_context *context_mask,
				     struct hns3_udma_qp *qp,
				     struct ubcore_tp_attr *attr)
{
	struct hns3_udma_congestion_algorithm congest_filed;
	uint32_t dip_idx = 0;
	int ret = 0;

	qp->congest_type = to_hns3_udma_cong_type(attr->flag.bs.cc_alg);
	fill_congest_type(&congest_filed, qp->congest_type);

	if (qp->qp_type == QPT_UD) {
		congest_filed.congest_type = CONGEST_DCQCN;
		congest_filed.alg_sel = DCQCN_ALG;
		congest_filed.alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_filed.dip_vld = DIP_INVALID;
		congest_filed.wnd_mode_sel = WND_LIMIT;
	}

	hns3_udma_reg_write(context, QPC_CONGEST_ALGO_TMPL_ID,
			    qp->udma_device->cong_algo_tmpl_id +
			    congest_filed.congest_type * HNS3_UDMA_CONGEST_SIZE);
	hns3_udma_reg_clear(context_mask, QPC_CONGEST_ALGO_TMPL_ID);

	hns3_udma_reg_write(&context->ext, QPCEX_CONGEST_ALG_SEL, congest_filed.alg_sel);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_CONGEST_ALG_SEL);

	hns3_udma_reg_write(&context->ext, QPCEX_CONGEST_ALG_SUB_SEL, congest_filed.alg_sub_sel);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_CONGEST_ALG_SUB_SEL);

	hns3_udma_reg_write(&context->ext, QPCEX_DIP_CTX_IDX_VLD, congest_filed.dip_vld);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_DIP_CTX_IDX_VLD);

	hns3_udma_reg_write(&context->ext, QPCEX_SQ_RQ_NOT_FORBID_EN, congest_filed.wnd_mode_sel);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_SQ_RQ_NOT_FORBID_EN);

	if (congest_filed.dip_vld == 0)
		goto out;

	ret = get_dip_ctx_idx(qp, &dip_idx);
	if (ret) {
		dev_err(qp->udma_device->dev,
			"failed to fill congest, ret = %d.\n", ret);
		goto out;
	}
	qp->dip_idx = (int64_t)dip_idx;
	if (dip_idx != qp->qpn) {
		ret = hns3_udma_table_get(qp->udma_device,
				     &qp->udma_device->qp_table.sccc_table,
				     dip_idx);
		if (ret) {
			dev_err(qp->udma_device->dev,
				"Failed to get SCC CTX table\n");
			goto out;
		}
	}

	hns3_udma_reg_write(&context->ext, QPCEX_DIP_CTX_IDX, dip_idx);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_DIP_CTX_IDX);

out:
	return ret;
}

static void hns3_udma_set_spray_field(struct hns3_udma_qp *qp,
				      struct ubcore_tp_attr *attr,
				      union ubcore_tp_attr_mask ubcore_mask,
				      struct hns3_udma_qp_context *context,
				      struct hns3_udma_qp_context *context_mask)
{
	uint16_t dus_regval;
	uint16_t aus_regval;
	uint16_t real_range;

	real_range = (attr->udp_range + UDP_SRCPORT_RANGE_BASE) &
		      UDP_SRCPORT_RANGE_SIZE_MASK;
	dus_regval = attr->data_udp_start & GENMASK(real_range, 0);
	aus_regval = attr->ack_udp_start & GENMASK(real_range, 0);

	hns3_udma_reg_enable(&context->ext, QPCEX_AR_EN);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_AR_EN);

	if (ubcore_mask.bs.ack_udp_start) {
		hns3_udma_reg_write(&context->ext, QPCEX_ACK_UDP_SRCPORT,
				    aus_regval);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_ACK_UDP_SRCPORT);
	}

	if (ubcore_mask.bs.data_udp_start) {
		hns3_udma_reg_write(&context->ext, QPCEX_DATA_UDP_SRCPORT_L,
				    dus_regval);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_DATA_UDP_SRCPORT_L);
		hns3_udma_reg_write(&context->ext, QPCEX_DATA_UDP_SRCPORT_H,
				    dus_regval >> QPCEX_DATA_UDP_SRCPORT_H_SHIFT);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_DATA_UDP_SRCPORT_H);
	}

	if (ubcore_mask.bs.udp_range) {
		hns3_udma_reg_write(&context->ext, QPCEX_UDP_SRCPORT_RANGE,
				    attr->udp_range);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_UDP_SRCPORT_RANGE);
	}
}

static void hns3_udma_set_oor_field(struct hns3_udma_qp *qp,
				    struct ubcore_tp_attr *attr,
				    union ubcore_tp_attr_mask ubcore_mask,
				    struct hns3_udma_qp_context *context,
				    struct hns3_udma_qp_context *context_mask)
{
	struct hns3_udma_dev *udma_dev = qp->udma_device;

	hns3_udma_reg_enable(&context->ext, QPCEX_OOR_EN);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_OOR_EN);

	hns3_udma_reg_write(&context->ext, QPCEX_REORDER_CAP,
			    udma_dev->caps.reorder_cap);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CAP);

	hns3_udma_reg_write(&context->ext, QPCEX_ON_FLIGHT_SIZE_L,
			    udma_dev->caps.onflight_size);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_ON_FLIGHT_SIZE_L);

	hns3_udma_reg_write(&context->ext, QPCEX_ON_FLIGHT_SIZE_H,
			    udma_dev->caps.onflight_size >>
			QPCEX_ON_FLIGHT_SIZE_H_SHIFT);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_ON_FLIGHT_SIZE_H);

	hns3_udma_reg_write(&context->ext, QPCEX_DYN_AT,
			    udma_dev->caps.dynamic_ack_timeout);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_DYN_AT);

	if (udma_dev->caps.reorder_cq_buffer_en &&
	    qp->qp_attr.reorder_cq_addr) {
		hns3_udma_reg_enable(&context->ext, QPCEX_REORDER_CQ_EN);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_EN);

		hns3_udma_reg_write(&context->ext, QPCEX_REORDER_CQ_ADDR_L,
				    lower_32_bits(qp->qp_attr.reorder_cq_addr) >>
				    QPCEX_REORDER_CQ_ADDR_SHIFT);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_ADDR_L);

		hns3_udma_reg_write(&context->ext, QPCEX_REORDER_CQ_ADDR_H,
				    upper_32_bits(qp->qp_attr.reorder_cq_addr));
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_ADDR_H);

		hns3_udma_reg_write(&context->ext, QPCEX_REORDER_CQ_SHIFT,
				    udma_dev->caps.reorder_cq_shift);
		hns3_udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_SHIFT);
	}
}

static void hns3_udma_set_mtu_field(struct hns3_udma_qp *qp,
				    struct ubcore_tp_attr *attr,
				    struct hns3_udma_qp_context *context,
				    struct hns3_udma_qp_context *context_mask)
{
	qp->ubcore_path_mtu = get_mtu(qp, attr);
	qp->path_mtu = to_hns3_udma_mtu(qp->ubcore_path_mtu);
	hns3_udma_reg_write(context, QPC_MTU, qp->path_mtu);
	hns3_udma_reg_clear(context_mask, QPC_MTU);

	hns3_udma_reg_write(context, QPC_LP_PKTN_INI, 0);
	hns3_udma_reg_clear(context_mask, QPC_LP_PKTN_INI);

	/* ACK_REQ_FREQ should be larger than or equal to LP_PKTN_INI */
	hns3_udma_reg_write(context, QPC_ACK_REQ_FREQ, 0);
	hns3_udma_reg_clear(context_mask, QPC_ACK_REQ_FREQ);
}

static void hns3_udma_set_opt_fields(struct hns3_udma_qp *qp,
				     struct ubcore_tp_attr *attr,
				     union ubcore_tp_attr_mask ubcore_mask,
				     struct hns3_udma_qp_context *context,
				     struct hns3_udma_qp_context *context_mask)
{
	struct hns3_udma_dev *udma_dev = qp->udma_device;

	if (attr == NULL)
		return;

	if (ubcore_mask.bs.flag && attr->flag.bs.oor_en && udma_dev->caps.oor_en)
		hns3_udma_set_oor_field(qp, attr, ubcore_mask, context, context_mask);

	if (ubcore_mask.bs.flag && attr->flag.bs.cc_en)
		hns3_udma_set_cong_fields(context, context_mask, qp, attr);

	if (ubcore_mask.bs.flag && attr->flag.bs.spray_en &&
		(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_AR)) {
		hns3_udma_set_spray_field(qp, attr, ubcore_mask, context, context_mask);
	} else {
		hns3_udma_reg_write(context, QPC_UDPSPN, attr->data_udp_start);
		hns3_udma_reg_clear(context_mask, QPC_UDPSPN);
	}

	if (ubcore_mask.bs.peer_tpn) {
		hns3_udma_reg_write(context, QPC_DQPN, attr->peer_tpn);
		hns3_udma_reg_clear(context_mask, QPC_DQPN);
	}

	if (ubcore_mask.bs.tx_psn) {
		hns3_udma_reg_write(context, QPC_RX_ACK_EPSN, attr->tx_psn);
		hns3_udma_reg_write(context, QPC_RETRY_MSG_PSN_L, attr->tx_psn);
		hns3_udma_reg_write(context, QPC_RETRY_MSG_PSN_H,
				    attr->tx_psn >> RETRY_MSG_PSN_H_OFFSET);
		hns3_udma_reg_write(context, QPC_RETRY_MSG_FPKT_PSN, attr->tx_psn);
		hns3_udma_reg_write(context, QPC_SQ_CUR_PSN, attr->tx_psn);
		hns3_udma_reg_write(context, QPC_SQ_MAX_PSN, attr->tx_psn);

		hns3_udma_reg_clear(context_mask, QPC_RX_ACK_EPSN);
		hns3_udma_reg_clear(context_mask, QPC_RETRY_MSG_PSN_L);
		hns3_udma_reg_clear(context_mask, QPC_RETRY_MSG_PSN_H);
		hns3_udma_reg_clear(context_mask, QPC_RETRY_MSG_FPKT_PSN);
		hns3_udma_reg_clear(context_mask, QPC_SQ_CUR_PSN);
		hns3_udma_reg_clear(context_mask, QPC_SQ_MAX_PSN);
	}

	if (ubcore_mask.bs.rx_psn) {
		hns3_udma_reg_write(context, QPC_RX_REQ_EPSN, attr->rx_psn);
		hns3_udma_reg_write(context, QPC_RAQ_PSN, attr->rx_psn - 1);

		hns3_udma_reg_clear(context_mask, QPC_RX_REQ_EPSN);
		hns3_udma_reg_clear(context_mask, QPC_RAQ_PSN);
	}

	if (ubcore_mask.bs.mtu)
		hns3_udma_set_mtu_field(qp, attr, context, context_mask);

	if (ubcore_mask.bs.hop_limit) {
		hns3_udma_reg_write(context, QPC_HOPLIMIT, attr->hop_limit);
		hns3_udma_reg_clear(context_mask, QPC_HOPLIMIT);
	}
}

static int hns3_udma_set_abs_fields(struct hns3_udma_qp *qp,
				    struct hns3_udma_modify_tp_attr *attr,
				    enum hns3_udma_qp_state curr_state,
				    enum hns3_udma_qp_state new_state,
				    struct hns3_udma_qp_context *context,
				    struct hns3_udma_qp_context *context_mask)
{
	struct hns3_udma_dev *udma_device = qp->udma_device;
	int ret = 0;

	if (curr_state == QPS_RESET && new_state == QPS_RTR) {
		ret = modify_qp_reset_to_rtr(qp, attr, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"something went wrong during reset to rtr, new_state = %d.\n",
				new_state);
			goto out;
		}
	} else if (curr_state == QPS_RESET && new_state == QPS_RTS) {
		ret = modify_qp_reset_to_rtr(qp, attr, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"something went wrong during reset to rtr, new_state = %d.\n",
				new_state);
			goto out;
		}
		ret = modify_qp_rtr_to_rts(qp, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"something went wrong during rtr to rts, new_state = %d.\n",
				new_state);
			goto out;
		}
	} else if (curr_state == QPS_RTR && new_state == QPS_RTS) {
		ret = modify_qp_rtr_to_rts(qp, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"something went wrong during rtr to rts, curr_state = %d.\n",
				curr_state);
			goto out;
		}
	}

out:
	return ret;
}

static void hns3_udma_set_um_attr(struct hns3_udma_qp *qp,
				  struct hns3_udma_qp_context *context,
				  struct hns3_udma_qp_context *context_mask)
{
	qp->ubcore_path_mtu = get_mtu(qp, NULL);
	qp->path_mtu = to_hns3_udma_mtu(qp->ubcore_path_mtu);
	hns3_udma_reg_write(context, QPC_MTU, qp->path_mtu);
	hns3_udma_reg_clear(context_mask, QPC_MTU);

	hns3_udma_reg_write(context, QPC_LP_PKTN_INI, 0);
	hns3_udma_reg_clear(context_mask, QPC_LP_PKTN_INI);

	/* ACK_REQ_FREQ should be larger than or equal to LP_PKTN_INI */
	hns3_udma_reg_write(context, QPC_ACK_REQ_FREQ, 0);
	hns3_udma_reg_clear(context_mask, QPC_ACK_REQ_FREQ);
}

int hns3_udma_modify_qp_common(struct hns3_udma_qp *qp,
			       struct ubcore_tp_attr *attr,
			       union ubcore_tp_attr_mask ubcore_mask,
			       enum hns3_udma_qp_state curr_state,
			       enum hns3_udma_qp_state new_state)
{
	struct hns3_udma_dev *udma_device = qp->udma_device;
	struct hns3_udma_qp_context ctx[2] = {};
	struct hns3_udma_qp_context *context = ctx;
	struct hns3_udma_qp_context *context_mask = ctx + 1;
	int ret = 0;

	memset(context, 0, udma_device->caps.qpc_sz);
	memset(context_mask, 0xff, udma_device->caps.qpc_sz);
	if (new_state != QPS_RESET) {
		ret = hns3_udma_set_abs_fields(qp, &qp->m_attr, curr_state, new_state,
					       context, context_mask);
		if (ret)
			goto out;
	}

	if (qp->qp_type == QPT_UD)
		hns3_udma_set_um_attr(qp, context, context_mask);

	hns3_udma_set_opt_fields(qp, attr, ubcore_mask, context, context_mask);

	/* Every status migrate must change state */
	hns3_udma_reg_write(context, QPC_QP_ST, new_state);
	hns3_udma_reg_clear(context_mask, QPC_QP_ST);

	hns3_udma_set_path(&qp->m_attr, context, context_mask);

	hns3_udma_reg_write(&context->ext, QPCEX_P_TYPE, QPCEX_P_TYPE_HNS3_UDMA);
	hns3_udma_reg_clear(&context_mask->ext, QPCEX_P_TYPE);
	/* SW pass context to HW */
	ret = hns3_udma_pass_qpc_to_hw(udma_device, context, context_mask, qp);
	if (ret) {
		dev_err(udma_device->dev, "failed to pass QPC to HW, ret = %d.\n",
			ret);
		goto out;
	}

	qp->state = new_state;

	if (qp->qp_type == QPT_RC &&
	    qp->en_flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_modify_dca(udma_device, qp);

out:
	return ret;
}

int fill_jfs_qp_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp_attr *qp_attr,
		     struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_jfs *hns3_udma_jfs;
	struct ubcore_jfs *jfs;
	struct ubcore_jfc *jfc;

	hns3_udma_jfs = (struct hns3_udma_jfs *)xa_load(&udma_dev->jfs_table.xa,
							ucmd->ini_id.jfs_id);
	if (IS_ERR_OR_NULL(hns3_udma_jfs)) {
		dev_err(udma_dev->dev, "failed to find jfs\n");
		return -EINVAL;
	}
	jfs = &hns3_udma_jfs->ubcore_jfs;
	jfc = jfs->jfs_cfg.jfc;
	qp_attr->send_jfc = to_hns3_udma_jfc(jfc);
	qp_attr->recv_jfc = NULL;
	qp_attr->jfs = hns3_udma_jfs;
	qp_attr->qpn_map = &qp_attr->jfs->qpn_map;
	qp_attr->uctx = qp_attr->jfs->ubcore_jfs.uctx;
	qp_attr->cap.max_send_wr = jfs->jfs_cfg.depth;
	qp_attr->cap.max_send_sge = jfs->jfs_cfg.max_sge;
	qp_attr->cap.max_inline_data = jfs->jfs_cfg.max_inline_data;
	qp_attr->cap.rnr_retry = jfs->jfs_cfg.rnr_retry;
	qp_attr->cap.ack_timeout = jfs->jfs_cfg.err_timeout;
	qp_attr->qp_type = QPT_RC;
	qp_attr->tgt_id = ucmd->tgt_id.jfr_id;
	qp_attr->tp_mode = hns3_udma_jfs->tp_mode;
	if (jfs->jfs_cfg.priority >= udma_dev->caps.sl_num) {
		qp_attr->priority = udma_dev->caps.sl_num > 0 ?
				    udma_dev->caps.sl_num - 1 : 0;
		dev_err(udma_dev->dev,
			"Incorrect priority(%u) configuration, maximum priority(%u).\n",
			jfs->jfs_cfg.priority, udma_dev->caps.sl_num);
	} else {
		qp_attr->priority = jfs->jfs_cfg.priority;
	}

	return 0;
}

int fill_jfr_qp_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp_attr *qp_attr,
		     struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_jfr *udma_jfr;
	struct ubcore_jfr *jfr;

	udma_jfr = (struct hns3_udma_jfr *)xa_load(&udma_dev->jfr_table.xa,
							ucmd->tgt_id.jfr_id);
	if (IS_ERR_OR_NULL(udma_jfr)) {
		dev_err(udma_dev->dev, "failed to find jfr\n");
		return -EINVAL;
	}
	jfr = &udma_jfr->ubcore_jfr;
	qp_attr->jfr = udma_jfr;
	qp_attr->recv_jfc = to_hns3_udma_jfc(jfr->jfr_cfg.jfc);
	qp_attr->uctx = qp_attr->jfr->ubcore_jfr.uctx;
	qp_attr->qpn_map = &qp_attr->jfr->qpn_map;
	qp_attr->tp_mode = udma_jfr->tp_mode;

	if (jfr->jfr_cfg.trans_mode == UBCORE_TP_UM) {
		dev_err(udma_dev->dev, "jfr tp mode error\n");
		return -EINVAL;
	} else {
		qp_attr->qp_type = QPT_RC;
	}
	qp_attr->cap.min_rnr_timer = jfr->jfr_cfg.min_rnr_timer;

	if (is_rq_jetty(qp_attr) && !qp_attr->jetty->shared_jfr &&
	    !qp_attr->jetty->dca_en) {
		qp_attr->cap.max_recv_wr = jfr->jfr_cfg.depth;
		qp_attr->cap.max_recv_sge = udma_jfr->max_sge;
	}

	return 0;
}

int fill_jetty_qp_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp_attr *qp_attr,
		       struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_jetty *udma_jetty;
	struct ubcore_jetty *jetty;
	uint32_t jetty_id;

	jetty_id = qp_attr->is_tgt ? ucmd->tgt_id.jetty_id : ucmd->ini_id.jetty_id;
	qp_attr->tgt_id = qp_attr->is_tgt ? ucmd->ini_id.jetty_id : ucmd->tgt_id.jetty_id;

	udma_jetty = (struct hns3_udma_jetty *)xa_load(&udma_dev->jetty_table.xa, jetty_id);
	if (IS_ERR_OR_NULL(udma_jetty)) {
		dev_err(udma_dev->dev, "failed to find jetty, id = %u.\n", jetty_id);
		return -EINVAL;
	}

	jetty = &udma_jetty->ubcore_jetty;
	if (udma_jetty->tp_mode == UBCORE_TP_UM) {
		dev_err(udma_dev->dev, "jetty tp mode error\n");
		return -EINVAL;
	}

	qp_attr->jetty = udma_jetty;
	qp_attr->tp_mode = udma_jetty->tp_mode;
	if (!qp_attr->is_tgt || udma_jetty->tp_mode == UBCORE_TP_RC) {
		qp_attr->uctx = jetty->uctx;
		qp_attr->qpn_map = &udma_jetty->qpn_map;
		qp_attr->send_jfc = to_hns3_udma_jfc(jetty->jetty_cfg.send_jfc);
		qp_attr->cap.max_send_wr = jetty->jetty_cfg.jfs_depth;
		qp_attr->cap.max_send_sge = jetty->jetty_cfg.max_send_sge;
		qp_attr->cap.max_inline_data = jetty->jetty_cfg.max_inline_data;
		if (jetty->jetty_cfg.priority >= udma_dev->caps.sl_num) {
			qp_attr->priority = udma_dev->caps.sl_num > 0 ?
					    udma_dev->caps.sl_num - 1 : 0;
			dev_err(udma_dev->dev,
				"Incorrect priority(%u) configuration, maximum priority(%u).\n",
				jetty->jetty_cfg.priority, udma_dev->caps.sl_num);
		} else {
			qp_attr->priority = jetty->jetty_cfg.priority;
		}
	}

	qp_attr->jfr = udma_jetty->hns3_udma_jfr;
	qp_attr->uctx = udma_jetty->hns3_udma_jfr->ubcore_jfr.uctx;
	qp_attr->qpn_map = &udma_jetty->qpn_map;
	qp_attr->recv_jfc = to_hns3_udma_jfc(udma_jetty->hns3_udma_jfr->ubcore_jfr.jfr_cfg.jfc);

	qp_attr->qp_type = QPT_RC;
	qp_attr->cap.min_rnr_timer = udma_jetty->hns3_udma_jfr->ubcore_jfr.jfr_cfg.min_rnr_timer;

	qp_attr->cap.ack_timeout = jetty->jetty_cfg.err_timeout;
	qp_attr->cap.rnr_retry = jetty->jetty_cfg.rnr_retry;

	if (is_rq_jetty(qp_attr) && !qp_attr->jetty->shared_jfr &&
	    !qp_attr->jetty->dca_en) {
		qp_attr->cap.max_recv_wr = udma_jetty->hns3_udma_jfr->ubcore_jfr.jfr_cfg.depth;
		qp_attr->cap.max_recv_sge = udma_jetty->hns3_udma_jfr->max_sge;
	}

	return 0;
}

int hns3_udma_fill_qp_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp_attr *qp_attr,
			   struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata)
{
	bool is_target = cfg->flag.bs.target;
	struct hns3_udma_create_tp_ucmd ucmd;
	struct hns3_udma_ucontext *udma_ctx;
	unsigned long byte;
	int eid_index;

	if (!udata->udrv_data->in_addr || udata->udrv_data->in_len < sizeof(ucmd)) {
		dev_err(udma_dev->dev, "Invalid tp in_len %u or null addr.\n",
			udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
			      sizeof(ucmd));
	if (byte) {
		dev_err(udma_dev->dev,
			"failed to copy create tp ucmd, byte = %lu.\n", byte);
		return -EFAULT;
	}

	qp_attr->is_tgt = is_target;
	qp_attr->is_jetty = ucmd.is_jetty;
	qp_attr->remote_eid = cfg->peer_eid;
	qp_attr->local_eid = cfg->local_eid;

	if (!is_target) {
		udma_ctx = to_hns3_udma_ucontext(udata->uctx);
		qp_attr->pdn = udma_ctx->pdn;
		qp_attr->eid_index = udma_ctx->eid_index;
		if (!ucmd.is_jetty)
			return fill_jfs_qp_attr(udma_dev, qp_attr, &ucmd);
		else
			return fill_jetty_qp_attr(udma_dev, qp_attr, &ucmd);
	} else {
		eid_index = hns3_udma_find_eid_idx(udma_dev, cfg->local_eid);
		if (eid_index < 0) {
			dev_err(udma_dev->dev,
				"Failed to find eid index, eid = "EID_FMT".\n",
				EID_ARGS(cfg->local_eid));
			return -EINVAL;
		}
		qp_attr->eid_index = eid_index;
		if (!ucmd.is_jetty)
			return fill_jfr_qp_attr(udma_dev, qp_attr, &ucmd);
		else
			return fill_jetty_qp_attr(udma_dev, qp_attr, &ucmd);
	}

	return 0;
}

static uint32_t get_wqe_ext_sge_cnt(struct hns3_udma_qp *qp)
{
	/* UD QP only has extended sge */
	if (qp->qp_type == QPT_UD)
		return qp->sq.max_gs;

	if (qp->sq.max_gs > HNS3_UDMA_SGE_IN_WQE)
		return qp->sq.max_gs - HNS3_UDMA_SGE_IN_WQE;

	return 0;
}

static void set_ext_sge_param(struct hns3_udma_dev *udma_dev, uint32_t sq_wqe_cnt,
			      struct hns3_udma_qp *qp, struct hns3_udma_qp_cap *cap)
{
	uint32_t max_inline_data;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t wqe_sge_cnt;

	qp->sge.sge_shift = HNS3_UDMA_SGE_SHIFT;

	max_inline_data = roundup_pow_of_two(cap->max_inline_data);
	ext_sge_cnt = max_inline_data / HNS3_UDMA_SGE_SIZE;

	/* Select the max data set by the user */
	qp->sq.max_gs = max_t(uint32_t, ext_sge_cnt, cap->max_send_sge);

	if (is_rc_jetty(&qp->qp_attr))
		qp->sge.offset = qp->qp_attr.jetty->rc_node.sge_offset;

	wqe_sge_cnt = get_wqe_ext_sge_cnt(qp);
	/* If the number of extended sge is not zero, they MUST use the
	 * space of HNS3_UDMA_EP_PAGE_SIZE at least.
	 */
	if (wqe_sge_cnt) {
		total_sge_cnt = roundup_pow_of_two(sq_wqe_cnt * wqe_sge_cnt);
		qp->sge.sge_cnt = max_t(uint32_t, total_sge_cnt,
					(uint32_t)(HNS3_UDMA_PAGE_SIZE / HNS3_UDMA_SGE_SIZE));
	}

	/* Ensure that the max_gs size does not exceed */
	qp->sq.max_gs = min_t(uint32_t, qp->sq.max_gs, udma_dev->caps.max_sq_sg);
}

static void set_rq_size(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			struct hns3_udma_qp_cap *cap)
{
	if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		qp->rq.wqe_cnt = roundup_pow_of_two(cap->max_recv_wr);
		qp->rq.max_gs = roundup_pow_of_two(cap->max_recv_sge);
		qp->rq.wqe_shift =
			ilog2(roundup_pow_of_two(HNS3_UDMA_SGE_SIZE * cap->max_recv_sge));
		qp->rq.offset = qp->qp_attr.jfr->offset;
		return;
	}
	/* set rq param to 0 */
	qp->rq.wqe_cnt = 0;
	qp->rq.max_gs = 1;
	cap->max_recv_wr = 0;
	cap->max_recv_sge = 0;
}

static int set_user_sq_size(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			    struct hns3_udma_qp_cap *cap)
{
	uint32_t cfg_depth;

	if (cap->max_send_wr > udma_dev->caps.max_wqes ||
	    cap->max_send_sge > udma_dev->caps.max_sq_sg)
		return -EINVAL;

	qp->sq.wqe_shift = HNS3_UDMA_SQ_WQE_SHIFT;
	cfg_depth = roundup_pow_of_two(cap->max_send_wr);
	qp->sq.wqe_cnt = cfg_depth < HNS3_UDMA_MIN_JFS_DEPTH ?
			 HNS3_UDMA_MIN_JFS_DEPTH : cfg_depth;

	set_ext_sge_param(udma_dev, qp->sq.wqe_cnt, qp, cap);

	return 0;
}

static int set_qp_param(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			struct ubcore_udata *udata,
			struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;
	unsigned long byte;
	int ret = 0;

	qp->qp_type = qp_attr->qp_type;

	if (!qp_attr->is_tgt) {
		qp->ack_timeout = qp_attr->cap.ack_timeout;
		qp->rnr_retry = qp_attr->cap.rnr_retry;
		if (qp_attr->is_jetty)
			qp->min_rnr_timer = qp_attr->cap.min_rnr_timer;
		qp->priority = qp_attr->priority;
	} else {
		qp->min_rnr_timer = qp_attr->cap.min_rnr_timer;
		if (qp_attr->is_jetty) {
			qp->ack_timeout = qp_attr->cap.ack_timeout;
			qp->rnr_retry = qp_attr->cap.rnr_retry;
			qp->priority = qp_attr->priority;
		}
	}

	if (qp_attr->cap.max_inline_data > udma_dev->caps.max_sq_inline)
		qp_attr->cap.max_inline_data = udma_dev->caps.max_sq_inline;

	qp->max_inline_data = qp_attr->cap.max_inline_data;

	set_rq_size(udma_dev, qp, &qp_attr->cap);

	if (!qp_attr->is_tgt) {
		if (!udata->udrv_data->in_addr ||
		    udata->udrv_data->in_len < sizeof(struct hns3_udma_create_tp_ucmd)) {
			dev_err(udma_dev->dev, "Invalid qp in_len %u or null addr.\n",
				udata->udrv_data->in_len);
			return -EINVAL;
		}

		byte = copy_from_user(ucmd, (void *)udata->udrv_data->in_addr,
				      sizeof(struct hns3_udma_create_tp_ucmd));
		if (byte) {
			dev_err(udma_dev->dev,
				"failed to copy create tp ucmd, byte:%lu\n", byte);
			return -EFAULT;
		}

		ret = set_user_sq_size(udma_dev, qp, &qp_attr->cap);
		if (ret)
			dev_err(udma_dev->dev,
				"failed to set user SQ size, ret = %d.\n", ret);
	} else {
		if (is_rc_jetty(qp_attr)) {
			ret = set_user_sq_size(udma_dev, qp, &qp_attr->cap);
			if (ret)
				dev_err(udma_dev->dev,
					"failed to set user SQ size for RC Jetty, ret = %d.\n",
					ret);
		}
	}

	return ret;
}

static uint8_t get_least_load_bankid_for_qp(struct hns3_udma_bank *bank,
					    struct hns3_udma_jfc *jfc)
{
	uint32_t least_load = HNS3_UDMA_INVALID_LOAD_QPNUM;
	uint8_t bankid = 0;
	uint32_t bankcnt;
	uint8_t i;

	for (i = 0; i < HNS3_UDMA_QP_BANK_NUM; ++i) {
		if (jfc && (get_affinity_cq_bank(i) != (jfc->cqn & CQ_BANKID_MASK)))
			continue;

		bankcnt = bank[i].inuse;
		if (bankcnt < least_load) {
			least_load = bankcnt;
			bankid = i;
		}
	}

	return bankid;
}

static int alloc_qpn_with_bankid(struct hns3_udma_bank *bank, uint8_t bankid,
				 uint32_t *qpn)
{
	uint32_t direct_wqe_max;
	uint32_t max;
	int idx;

	direct_wqe_max = HNS3_UDMA_DIRECT_WQE_MAX / HNS3_UDMA_QP_BANK_NUM - 1;
	max = (bank->max < direct_wqe_max) ? bank->max : direct_wqe_max;
	idx = ida_alloc_range(&bank->ida, bank->next, max, GFP_KERNEL);
	if (idx >= 0)
		goto alloc_qpn_succ;

	idx = ida_alloc_range(&bank->ida, bank->min, bank->next, GFP_KERNEL);
	if (idx >= 0)
		goto alloc_qpn_succ;

	if (bank->max < direct_wqe_max)
		goto alloc_qpn_fail;

	idx = ida_alloc_range(&bank->ida, direct_wqe_max, bank->max, GFP_KERNEL);
	if (idx < 0)
		goto alloc_qpn_fail;

alloc_qpn_succ:
	/* the lower 3 bits is bankid */
	*qpn = (idx << 3) | bankid;
	bank->next = (idx < max) ? (idx + 1) : bank->min;

	return 0;

alloc_qpn_fail:
	bank->next = bank->min;

	return idx;
}

int alloc_common_qpn(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *jfc,
		     uint32_t *qpn)
{
	struct hns3_udma_qp_table *qp_table = &udma_dev->qp_table;
	uint8_t bankid;
	int ret;

	mutex_lock(&qp_table->bank_mutex);
	bankid = get_least_load_bankid_for_qp(qp_table->bank, jfc);
	ret = alloc_qpn_with_bankid(&qp_table->bank[bankid], bankid, qpn);
	if (ret) {
		dev_err(udma_dev->dev, "failed to alloc qpn, ret = %d\n",
			ret);
		mutex_unlock(&qp_table->bank_mutex);
		return ret;
	}
	qp_table->bank[bankid].inuse++;
	mutex_unlock(&qp_table->bank_mutex);

	return ret;
}

void free_common_qpn(struct hns3_udma_dev *udma_dev, uint32_t qpn)
{
	struct hns3_udma_qp_table *qp_table = &udma_dev->qp_table;
	uint8_t bankid;

	bankid = get_qp_bankid(qpn);
	ida_free(&qp_table->bank[bankid].ida, qpn / HNS3_UDMA_QP_BANK_NUM);
	mutex_lock(&qp_table->bank_mutex);
	qp_table->bank[bankid].inuse--;
	mutex_unlock(&qp_table->bank_mutex);
}

static void alloc_qpn(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	struct hns3_udma_qp_attr *attr = &qp->qp_attr;

	if (attr->is_jetty)
		qp->qpn = attr->jetty->jetty_id;
	else if (attr->jfs)
		qp->qpn = attr->jfs->jfs_id;
	else
		qp->qpn = attr->jfr->jfrn;
}

static int set_wqe_buf_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			    struct hns3_udma_buf_attr *buf_attr, bool dca_en)
{
	uint32_t idx = 0;
	uint32_t buf_size;

	qp->buff_size = 0;

	/* SQ WQE */
	qp->sq.offset = 0;

	buf_size = to_hem_entries_size_by_page(qp->sq.wqe_cnt,
					    qp->sq.wqe_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sq_hop_num;
		idx++;
		qp->buff_size += buf_size;
	}
	/* extend SGE WQE in SQ */
	qp->sge.offset = qp->buff_size;

	buf_size = to_hem_entries_size_by_page(qp->sge.sge_cnt,
					    qp->sge.sge_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sge_hop_num;
		idx++;
		qp->buff_size += buf_size;
	}

	if (is_rq_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		/* RQ WQE */
		qp->rq.offset = qp->buff_size;

		buf_size = to_hem_entries_size_by_page(qp->rq.wqe_cnt,
						qp->rq.wqe_shift);
		if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
			buf_attr->region[idx].size = buf_size;
			buf_attr->region[idx].hopnum = udma_dev->caps.wqe_rq_hop_num;
			idx++;
			qp->buff_size += buf_size;
		}
	}
	if (qp->buff_size < 1)
		return -EINVAL;

	buf_attr->region_count = idx;
	buf_attr->page_shift = dca_en ? HNS3_UDMA_HW_PAGE_SHIFT : PAGE_SHIFT;
	buf_attr->mtt_only = dca_en;

	return 0;
}

static inline int hns3_udma_qp_has_direct_wqe(struct hns3_udma_dev *dev, struct hns3_udma_qp *qp)
{
	bool has_dwqe = dev->caps.num_qp_en ? (qp->qpn < HNS3_UDMA_DIRECT_WQE_MAX) : true;

	return ((PAGE_SIZE <= HNS3_UDMA_DWQE_SIZE) &&
		(dev->caps.flags & HNS3_UDMA_CAP_FLAG_DIRECT_WQE) &&
		has_dwqe);
}

static int alloc_wqe_buf(struct hns3_udma_dev *dev, struct hns3_udma_qp *qp,
			 struct hns3_udma_buf_attr *buf_attr, uint64_t addr,
			 bool dca_en)
{
	int ret;

	if (dca_en) {
		/* DCA must be enabled after the buffer attr is configured. */
		hns3_udma_enable_dca(dev, qp);
		qp->en_flags |= HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH;
	} else if (hns3_udma_qp_has_direct_wqe(dev, qp)) {
		qp->en_flags |= HNS3_UDMA_QP_CAP_DIRECT_WQE;
	}

	ret = hns3_udma_mtr_create(dev, &qp->mtr, buf_attr,
			      PAGE_SHIFT + dev->caps.mtt_ba_pg_sz, addr, true);
	if (ret) {
		dev_err(dev->dev, "failed to create WQE mtr, ret = %d.\n", ret);
		if (dca_en)
			hns3_udma_disable_dca(dev, qp);
	} else if (dca_en) {
		ret = hns3_udma_map_dca_safe_page(dev, qp);
	}

	return ret;
}

static bool check_dca_is_enable(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				uint64_t buf_addr)
{
	if (qp->qp_type != QPT_RC ||
	    !(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_DCA_MODE))
		return false;

	/* If the user QP's buffer addr is 0, the DCA mode should be enabled */
	return !buf_addr;
}

static int alloc_qp_wqe(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			uint64_t buf_addr)
{
	struct hns3_udma_buf_attr buf_attr = {};
	struct device *dev = udma_dev->dev;
	bool dca_en;
	int ret;

	dca_en = check_dca_is_enable(udma_dev, qp, buf_addr);
	if (dca_en && !udma_dev->dca_safe_buf) {
		ret = hns3_udma_alloc_dca_safe_page(udma_dev);
		if (ret)
			return ret;
	}

	ret = set_wqe_buf_attr(udma_dev, qp, &buf_attr, dca_en);
	if (ret) {
		dev_err(dev, "failed to set WQE attr, ret = %d.\n", ret);
		return ret;
	}

	ret = alloc_wqe_buf(udma_dev, qp, &buf_attr, buf_addr, dca_en);
	if (ret) {
		dev_err(dev, "failed to alloc WQE buf, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static int alloc_user_qp_db(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			    struct hns3_udma_create_tp_ucmd *ucmd)
{
	int ret;

	if (!ucmd->sdb_addr)
		return 0;

	ret = hns3_udma_db_map_user(qp->hns3_udma_uctx, ucmd->sdb_addr, &qp->sdb);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to map user sdb_addr, ret = %d.\n", ret);
		return ret;
	}

	qp->en_flags |= HNS3_UDMA_QP_CAP_SQ_RECORD_DB;

	return 0;
}

static int alloc_qp_db(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
		       struct ubcore_udata *udata,
		       struct hns3_udma_create_tp_ucmd *ucmd)
{
	int ret = 0;

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_SDI_MODE)
		qp->en_flags |= HNS3_UDMA_QP_CAP_OWNER_DB;

	if (udata) {
		qp->hns3_udma_uctx = to_hns3_udma_ucontext(udata->uctx);
		ret = alloc_user_qp_db(udma_dev, qp, ucmd);
	} else {
		qp->hns3_udma_uctx = NULL;
	}

	return ret;
}

static int alloc_qpc(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	struct hns3_udma_qp_table *qp_table = &udma_dev->qp_table;
	struct device *dev = udma_dev->dev;
	int ret;

	/* Alloc memory for QPC */
	ret = hns3_udma_table_get(udma_dev, &qp_table->qp_table, qp->qpn);
	if (ret) {
		dev_err(dev, "Failed to get QPC table\n");
		goto err_out;
	}

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		/* Alloc memory for SCC CTX */
		ret = hns3_udma_table_get(udma_dev, &qp_table->sccc_table,
				     qp->qpn);
		if (ret) {
			dev_err(dev, "Failed to get SCC CTX table\n");
			goto err_put_qp;
		}
	}

	if (udma_dev->caps.reorder_cq_buffer_en) {
		ret = hns3_udma_alloc_reorder_cq_buf(udma_dev, &qp->qp_attr);
		if (ret)
			dev_warn(udma_dev->dev,
				 "failed to alloc reorder cq buffer.\n");
	}

	return 0;

err_put_qp:
	hns3_udma_table_put(udma_dev, &qp_table->qp_table, qp->qpn);
err_out:
	return ret;
}

static int hns3_udma_qp_store(struct hns3_udma_dev *udma_dev,
			      struct hns3_udma_qp *qp)
{
	struct xarray *xa = &udma_dev->qp_table.xa;
	struct hns3_udma_qp *temp_qp;
	unsigned long flags;
	int ret = 0;

	xa_lock_irqsave(xa, flags);
	temp_qp = (struct hns3_udma_qp *)xa_load(xa, qp->qpn);
	if (!temp_qp)
		ret = xa_err(__xa_store(xa, qp->qpn, qp, GFP_KERNEL));
	xa_unlock_irqrestore(xa, flags);
	if (ret)
		dev_err(udma_dev->dev, "Failed to xa store for QPC\n");

	return ret;
}

static void hns3_udma_qp_remove(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				struct ubcore_tp *fail_ret_tp)
{
	struct xarray *xa = &udma_dev->qp_table.xa;
	unsigned long flags;

	xa_lock_irqsave(xa, flags);
	if (!fail_ret_tp)
		__xa_erase(xa, qp->qpn);
	xa_unlock_irqrestore(xa, flags);
}

static void free_qpc(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	if (udma_dev->caps.reorder_cq_buffer_en)
		hns3_udma_free_reorder_cq_buf(udma_dev, &qp->qp_attr);
}

static void free_qp_db(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	if (qp->no_free_wqe_buf)
		return;

	if (qp->en_flags & HNS3_UDMA_QP_CAP_SQ_RECORD_DB)
		if (qp->hns3_udma_uctx)
			hns3_udma_db_unmap_user(qp->hns3_udma_uctx, &qp->sdb);
}

static void free_wqe_buf(struct hns3_udma_dev *dev, struct hns3_udma_qp *qp)
{
	if (qp->no_free_wqe_buf)
		return;

	hns3_udma_mtr_destroy(dev, &qp->mtr);
	if (qp->en_flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_disable_dca(dev, qp);
}

static void free_qp_wqe(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	free_wqe_buf(udma_dev, qp);
}

bool hns3_udma_qp_need_alloc_sq(struct hns3_udma_qp_attr *qp_attr)
{
	if (qp_attr->is_jetty) {
		/* create qp for UM jetty */
		if (qp_attr->jetty->tp_mode == UBCORE_TP_UM)
			return true;

		if (qp_attr->jetty->tp_mode == UBCORE_TP_RC)
			return true;

		return !qp_attr->is_tgt;
	}

	/* create qp for jfs for send */
	if (qp_attr->jfs)
		return true;

	/* create qp for jfr for recv */
	return false;
}

static uint32_t hns3_udma_get_jetty_qpn(struct hns3_udma_qp *qp)
{
	struct hns3_udma_jetty *jetty = qp->qp_attr.jetty;
	uint32_t qpn = qp->qpn;

	if (jetty->tp_mode == UBCORE_TP_RC && jetty->rc_node.tp != NULL)
		qpn = jetty->rc_node.tpn;

	return qpn;
}

static int hns3_udma_alloc_qp_sq(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				 struct ubcore_udata *udata,
				 struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;
	int ret = 0;

	if (qp_attr->is_jetty && !qp_attr->jetty->shared_jfr && !qp_attr->jetty->dca_en)
		qp->en_flags |= HNS3_UDMA_QP_CAP_RQ_RECORD_DB;
	if (is_rc_jetty(qp_attr)) {
		qp->sdb = qp_attr->jetty->rc_node.sdb;
		qp->en_flags |= HNS3_UDMA_QP_CAP_SQ_RECORD_DB;
		qp->dca_ctx = &qp_attr->jetty->rc_node.context->dca_ctx;
		if (qp_attr->jetty->rc_node.buf_addr) {
			qp->mtr = qp_attr->jetty->rc_node.mtr;
			if (hns3_udma_qp_has_direct_wqe(udma_dev, qp))
				qp->en_flags |= HNS3_UDMA_QP_CAP_DIRECT_WQE;
		} else {
			ret = alloc_qp_wqe(udma_dev, qp, qp_attr->jetty->rc_node.buf_addr);
			if (ret)
				dev_err(udma_dev->dev,
					"failed to alloc QP buffer, ret = %d.\n",
					ret);
		}
	} else {
		ret = alloc_qp_wqe(udma_dev, qp, ucmd->buf_addr);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to alloc QP buffer, ret = %d.\n",
				ret);
			goto out;
		}
		ret = alloc_qp_db(udma_dev, qp, udata, ucmd);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to alloc QP doorbell, ret = %d.\n",
				ret);
			free_qp_wqe(udma_dev, qp);
		}
	}

out:
	return ret;
}

static void hns3_udma_free_qp_sq(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;

	if (is_rc_jetty(qp_attr)) {
		if (!qp_attr->jetty->rc_node.buf_addr)
			free_qp_wqe(udma_dev, qp);
	} else {
		free_qp_wqe(udma_dev, qp);
		free_qp_db(udma_dev, qp);
	}
}

int hns3_udma_init_qpc(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	struct hns3_udma_qp_context ctx[2] = {};
	int ret;

	ret = hns3_udma_pass_qpc_to_hw(udma_dev, ctx, ctx + 1, qp);
	if (ret)
		dev_err(udma_dev->dev, "failed to init QPC to HW, ret = %d.\n", ret);

	return ret;
}

static int hns3_udma_check_qp_need_sq(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				      struct ubcore_udata *udata,
				      struct hns3_udma_create_tp_ucmd *ucmd)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;
	int ret = 0;

	if (hns3_udma_qp_need_alloc_sq(qp_attr)) {
		ret = hns3_udma_alloc_qp_sq(udma_dev, qp, udata, ucmd);
		if (ret)
			dev_err(udma_dev->dev, "failed to alloc QP sq, ret = %d.\n", ret);
	}

	return ret;
}

static int create_qp_resp_to_user(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				  struct ubcore_udata *udata)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;
	struct hns3_udma_create_tp_resp resp = {};
	unsigned long byte = 0;

	if (!qp_attr->is_tgt) {
		if (!udata->udrv_data->out_addr ||
		    udata->udrv_data->out_len < sizeof(resp)) {
			dev_err(udma_dev->dev, "Invalid qp out_len %u or null addr.\n",
				udata->udrv_data->out_len);
			return -EINVAL;
		}

		resp.cap_flags = qp->en_flags;
		resp.qpn = qp->qpn;
		resp.priority = qp->priority;
		if (qp_attr->is_jetty && qp_attr->jetty)
			resp.qpn = hns3_udma_get_jetty_qpn(qp);

		resp.path_mtu = udma_dev->caps.max_mtu;
		resp.um_srcport.um_spray_en = um_spray_en;
		resp.um_srcport.um_data_udp_start = (uint16_t)um_data_udp_start;
		resp.um_srcport.um_udp_range = (uint8_t)um_udp_range + UDP_RANGE_BASE;
		byte = copy_to_user((void *)udata->udrv_data->out_addr, &resp,
				    sizeof(resp));
		if (byte) {
			dev_err(udma_dev->dev,
				"copy qp resp failed! byte = %lu.\n", byte);
			return -EFAULT;
		}
	}

	return 0;
}

int hns3_udma_create_qp_common(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			       struct ubcore_udata *udata)
{
	struct hns3_udma_qp_attr *qp_attr = &qp->qp_attr;
	struct hns3_udma_create_tp_ucmd ucmd;
	struct device *dev = udma_dev->dev;
	int ret;

	qp->state = QPS_RESET;
	qp->dip_idx = HNS3_UDMA_SCC_DIP_INVALID_IDX;
	if (!qp_attr->is_tgt)
		qp->dca_ctx = &(to_hns3_udma_ucontext(udata->uctx)->dca_ctx);

	ret = set_qp_param(udma_dev, qp, udata, &ucmd);
	if (ret) {
		dev_err(dev, "failed to set QP param, ret = %d.\n", ret);
		return ret;
	}

	alloc_qpn(udma_dev, qp);
	if (!qp->qpn) {
		dev_err(dev, "failed to alloc QPN.\n");
		return -EINVAL;
	}

	ret = hns3_udma_check_qp_need_sq(udma_dev, qp, udata, &ucmd);
	if (ret)
		return ret;

	ret = alloc_qpc(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to alloc QP context, ret = %d.\n", ret);
		goto err_qpc;
	}

	ret = hns3_udma_qp_store(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to store QP, ret = %d.\n", ret);
		goto err_store;
	}

	ret = create_qp_resp_to_user(udma_dev, qp, udata);
	if (ret)
		goto err_copy;

	refcount_set(&qp->refcount, 1);
	init_completion(&qp->free);

	return 0;

err_copy:
	hns3_udma_qp_remove(udma_dev, qp, NULL);
err_store:
	free_qpc(udma_dev, qp);
err_qpc:
	if (hns3_udma_qp_need_alloc_sq(qp_attr))
		hns3_udma_free_qp_sq(udma_dev, qp);

	return ret;
}

static void put_dip_ctx_idx(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp)
{
	unsigned long *dip_idx_bitmap =
				udma_dev->qp_table.idx_table.dip_idx_bitmap;
	unsigned long *qpn_bitmap = udma_dev->qp_table.idx_table.qpn_bitmap;
	struct hns3_udma_dip *udma_dip = qp->dip;
	unsigned long flags;

	spin_lock_irqsave(&udma_dev->dip_list_lock, flags);

	if (udma_dip) {
		udma_dip->qp_cnt--;
		if (!udma_dip->qp_cnt) {
			clear_bit(udma_dip->dip_idx, dip_idx_bitmap);
			set_bit(udma_dip->dip_idx, qpn_bitmap);
			list_del(&udma_dip->node);
			kfree(udma_dip);
		}
	}

	spin_unlock_irqrestore(&udma_dev->dip_list_lock, flags);
}

void hns3_udma_destroy_qp_common(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				 struct ubcore_tp *fail_ret_tp)
{
	if (qp->congest_type == HNS3_UDMA_CONG_TYPE_DIP)
		put_dip_ctx_idx(udma_dev, qp);

	hns3_udma_qp_remove(udma_dev, qp, fail_ret_tp);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);

	free_qpc(udma_dev, qp);
	if (hns3_udma_qp_need_alloc_sq(&qp->qp_attr) || qp->force_free_wqe_buf)
		hns3_udma_free_qp_sq(udma_dev, qp);
}

int hns3_udma_init_qp_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_qp_table *qp_table = &dev->qp_table;
	uint32_t reserved_from_bot;
	uint32_t i;

	qp_table->idx_table.qpn_bitmap = bitmap_zalloc(dev->caps.num_qps,
						       GFP_KERNEL);
	if (!qp_table->idx_table.qpn_bitmap)
		return -ENOMEM;

	qp_table->idx_table.dip_idx_bitmap = bitmap_zalloc(dev->caps.num_qps,
							   GFP_KERNEL);
	if (!qp_table->idx_table.dip_idx_bitmap) {
		bitmap_free(qp_table->idx_table.qpn_bitmap);
		return -ENOMEM;
	}

	mutex_init(&qp_table->bank_mutex);
	xa_init(&qp_table->xa);

	reserved_from_bot = dev->caps.reserved_qps;

	for (i = 0; i < reserved_from_bot; i++) {
		dev->qp_table.bank[get_qp_bankid(i)].inuse++;
		dev->qp_table.bank[get_qp_bankid(i)].min++;
	}

	for (i = 0; i < HNS3_UDMA_QP_BANK_NUM; i++) {
		ida_init(&dev->qp_table.bank[i].ida);
		dev->qp_table.bank[i].max = dev->caps.num_qps /
						HNS3_UDMA_QP_BANK_NUM - 1;
		dev->qp_table.bank[i].next = dev->qp_table.bank[i].min;
	}

	return 0;
}

void hns3_udma_cleanup_qp_table(struct hns3_udma_dev *dev)
{
	int i;

	for (i = 0; i < HNS3_UDMA_QP_BANK_NUM; i++)
		ida_destroy(&dev->qp_table.bank[i].ida);
	bitmap_free(dev->qp_table.idx_table.qpn_bitmap);
	bitmap_free(dev->qp_table.idx_table.dip_idx_bitmap);
}

int hns3_udma_flush_cqe(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *hns3_udma_qp,
			uint32_t sq_pi)
{
	struct hns3_udma_qp_context *qp_context;
	struct hns3_udma_cmd_mailbox *mailbox;
	struct hns3_udma_qp_context *qpc_mask;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	int ret;

	hns3_udma_qp->state = QPS_ERR;

	mailbox = hns3_udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	qp_context = (struct hns3_udma_qp_context *)mailbox->buf;
	qpc_mask = (struct hns3_udma_qp_context *)mailbox->buf + 1;
	memset(qpc_mask, 0xff, sizeof(struct hns3_udma_qp_context));

	hns3_udma_reg_write(qp_context, QPC_QP_ST, hns3_udma_qp->state);
	hns3_udma_reg_clear(qpc_mask, QPC_QP_ST);

	hns3_udma_reg_write(qp_context, QPC_SQ_PRODUCER_IDX, sq_pi);
	hns3_udma_reg_clear(qpc_mask, QPC_SQ_PRODUCER_IDX);

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, hns3_udma_qp->qpn, HNS3_UDMA_CMD_MODIFY_QPC);

	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(udma_dev->dev, "flush cqe qp(0x%llx) cmd error(%d).\n",
			hns3_udma_qp->qpn, ret);

	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

void hns3_udma_qp_event(struct hns3_udma_dev *udma_dev, uint32_t qpn, int event_type)
{
	struct device *dev = udma_dev->dev;
	struct hns3_udma_qp *qp;

	xa_lock(&udma_dev->qp_table.xa);
	qp = (struct hns3_udma_qp *)xa_load(&udma_dev->qp_table.xa, qpn);
	if (qp)
		refcount_inc(&qp->refcount);
	xa_unlock(&udma_dev->qp_table.xa);

	if (!qp) {
		dev_warn(dev, "Async event for bogus QP 0x%08x\n", qpn);
		return;
	}

	if (event_type == HNS3_UDMA_EVENT_TYPE_JFR_LAST_WQE_REACH ||
	    event_type == HNS3_UDMA_EVENT_TYPE_WQ_CATAS_ERROR ||
	    event_type == HNS3_UDMA_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR ||
	    event_type == HNS3_UDMA_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR) {
		qp->state = QPS_ERR;

		if (qp->sdb.virt_addr)
			qp->sq.head = *(int *)(qp->sdb.virt_addr);

		hns3_udma_flush_cqe(udma_dev, qp, qp->sq.head);
	}

	if (qp->event)
		qp->event(qp, (enum hns3_udma_event)event_type);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
}

module_param(um_spray_en, bool, 0644);
MODULE_PARM_DESC(um_spray_en,
		 "Set whether to enable the multipath function for UM Jetty/Jfs, default: 0(0:off, 1:on)");

module_param(um_data_udp_start, ushort, 0644);
MODULE_PARM_DESC(um_data_udp_start,
		 "Set the Initial source port number for UM Jetty/Jfs, valid when um_spray_en is set 1");

module_param(um_udp_range, ushort, 0644);
MODULE_PARM_DESC(um_udp_range,
		 "Set the variable bits of source port number for UM Jetty/Jfs, valid when um_spray_en is set 1, range:0-8, default: 0. 0 ~ (7 + um_udp_range) bits of source port are variable");
