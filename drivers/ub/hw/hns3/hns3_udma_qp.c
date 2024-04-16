// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
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

static bool is_rc_jetty(struct udma_qp_attr *qp_attr)
{
	if (qp_attr->is_jetty && qp_attr->jetty &&
	    qp_attr->tp_mode == UBCORE_TP_RC)
		return true;

	return false;
}

static void set_qpc_wqe_cnt(struct udma_qp *qp,
			    struct udma_qp_context *context,
			    struct udma_qp_context *context_mask)
{
	udma_reg_write(context, QPC_SGE_SHIFT,
		       to_udma_hem_entries_shift(qp->sge.sge_cnt,
						 qp->sge.sge_shift));
	udma_reg_clear(context_mask, QPC_SGE_SHIFT);

	udma_reg_write(context, QPC_SQ_SHIFT, ilog2(qp->sq.wqe_cnt));
	udma_reg_clear(context_mask, QPC_SQ_SHIFT);

	if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		udma_reg_write(context, QPC_RQ_SHIFT, ilog2(qp->rq.wqe_cnt));
		udma_reg_clear(context_mask, QPC_RQ_SHIFT);
	}
}

static void config_qp_sq_buf_mask(struct udma_qp_context *context_mask)
{
	udma_reg_clear(context_mask, QPC_SQ_CUR_BLK_ADDR_L);
	udma_reg_clear(context_mask, QPC_SQ_CUR_BLK_ADDR_H);
	udma_reg_clear(context_mask, QPC_SQ_CUR_SGE_BLK_ADDR_L);
	udma_reg_clear(context_mask, QPC_SQ_CUR_SGE_BLK_ADDR_H);
	udma_reg_clear(context_mask, QPC_RX_SQ_CUR_BLK_ADDR_L);
	udma_reg_clear(context_mask, QPC_RX_SQ_CUR_BLK_ADDR_H);
	udma_reg_clear(context_mask, QPC_WQE_SGE_BA_L);
	udma_reg_clear(context_mask, QPC_WQE_SGE_BA_H);
	udma_reg_clear(context_mask, QPC_SQ_HOP_NUM);
	udma_reg_clear(context_mask, QPC_SGE_HOP_NUM);
	udma_reg_clear(context_mask, QPC_WQE_SGE_BA_PG_SZ);
	udma_reg_clear(context_mask, QPC_WQE_SGE_BUF_PG_SZ);
}

static int config_qp_rq_buf(struct udma_dev *udma_device,
			    struct udma_qp *qp,
			    struct udma_qp_context *context,
			    struct udma_qp_context *context_mask)
{
	uint64_t mtts_wqe[MTT_MIN_COUNT] = {};
	int count;

	/* search RQ buf's mtts */
	count = udma_mtr_find(udma_device, &qp->qp_attr.jfr->buf_mtr, qp->qp_attr.jfr->offset,
			    mtts_wqe, ARRAY_SIZE(mtts_wqe), NULL);
	if (count < 1) {
		dev_err(udma_device->dev, "failed to find QP(0x%llx) RQ buf.\n",
			qp->qpn);
		return -EINVAL;
	}

	udma_reg_write(context, QPC_RQ_HOP_NUM,
			to_udma_hem_hopnum(udma_device->caps.wqe_rq_hop_num,
					qp->rq.wqe_cnt));
	udma_reg_clear(context_mask, QPC_RQ_HOP_NUM);

	udma_reg_write(context, QPC_RQ_CUR_BLK_ADDR_L,
		to_udma_hw_page_addr(mtts_wqe[0]));
	udma_reg_write(context, QPC_RQ_CUR_BLK_ADDR_H,
		upper_32_bits(to_udma_hw_page_addr(mtts_wqe[0])));
	udma_reg_clear(context_mask, QPC_RQ_CUR_BLK_ADDR_L);
	udma_reg_clear(context_mask, QPC_RQ_CUR_BLK_ADDR_H);

	udma_reg_write(context, QPC_RQ_NXT_BLK_ADDR_L,
		to_udma_hw_page_addr(mtts_wqe[1]));
	udma_reg_write(context, QPC_RQ_NXT_BLK_ADDR_H,
		upper_32_bits(to_udma_hw_page_addr(mtts_wqe[1])));
	udma_reg_clear(context_mask, QPC_RQ_NXT_BLK_ADDR_L);
	udma_reg_clear(context_mask, QPC_RQ_NXT_BLK_ADDR_H);

	return 0;
}

static int config_qp_sq_buf(struct udma_dev *udma_device,
			    struct udma_qp *qp,
			    struct udma_qp_context *context,
			    struct udma_qp_context *context_mask)
{
	uint64_t sge_cur_blk = 0;
	uint64_t sq_cur_blk = 0;
	uint64_t wqe_sge_ba = 0;
	int count;

	/* search qp buf's mtts */
	count = udma_mtr_find(udma_device, &qp->mtr, qp->sq.wqe_offset,
			      &sq_cur_blk, 1, &wqe_sge_ba);
	if (count < 1) {
		dev_err(udma_device->dev, "failed to find QP(0x%llx) SQ buf.\n", qp->qpn);
		return -EINVAL;
	}

	context->wqe_sge_ba = cpu_to_le32(wqe_sge_ba >> WQE_SGE_BA_OFFSET);

	if (qp->sge.sge_cnt > 0) {
		count = udma_mtr_find(udma_device, &qp->mtr,
				      qp->sge.wqe_offset, &sge_cur_blk, 1, NULL);
		if (count < 1) {
			dev_err(udma_device->dev, "failed to find QP(0x%llx) SGE buf.\n", qp->qpn);
			return -EINVAL;
		}
	}

	if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
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
	udma_reg_write(context, QPC_SQ_CUR_BLK_ADDR_L,
		       lower_32_bits(to_udma_hw_page_addr(sq_cur_blk)));
	udma_reg_write(context, QPC_SQ_CUR_BLK_ADDR_H,
		       upper_32_bits(to_udma_hw_page_addr(sq_cur_blk)));
	udma_reg_write(context, QPC_SQ_CUR_SGE_BLK_ADDR_L,
		       lower_32_bits(to_udma_hw_page_addr(sge_cur_blk)));
	udma_reg_write(context, QPC_SQ_CUR_SGE_BLK_ADDR_H,
		       upper_32_bits(to_udma_hw_page_addr(sge_cur_blk)));
	udma_reg_write(context, QPC_RX_SQ_CUR_BLK_ADDR_L,
		       lower_32_bits(to_udma_hw_page_addr(sq_cur_blk)));
	udma_reg_write(context, QPC_RX_SQ_CUR_BLK_ADDR_H,
		       upper_32_bits(to_udma_hw_page_addr(sq_cur_blk)));
	udma_reg_write(context, QPC_WQE_SGE_BA_H, wqe_sge_ba >>
		       (WQE_SGE_BA_OFFSET + H_ADDR_OFFSET));
	udma_reg_write(context, QPC_SQ_HOP_NUM,
		       to_udma_hem_hopnum(udma_device->caps.wqe_sq_hop_num,
					  qp->sq.wqe_cnt));
	udma_reg_write(context, QPC_SGE_HOP_NUM,
		       to_udma_hem_hopnum(udma_device->caps.wqe_sge_hop_num,
					  qp->sge.sge_cnt));
	udma_reg_write(context, QPC_WQE_SGE_BA_PG_SZ,
		       to_udma_hw_page_shift(qp->mtr.hem_cfg.ba_pg_shift));
	udma_reg_write(context, QPC_WQE_SGE_BUF_PG_SZ,
		       to_udma_hw_page_shift(qp->mtr.hem_cfg.buf_pg_shift));

	config_qp_sq_buf_mask(context_mask);

	return 0;
}

static void udma_set_path(struct udma_modify_tp_attr *attr,
			  struct udma_qp_context *context,
			  struct udma_qp_context *context_mask)
{
	if (attr == NULL)
		return;

	udma_reg_write(context, QPC_GMV_IDX, attr->sgid_index);
	udma_reg_clear(context_mask, QPC_GMV_IDX);

	memcpy(context->dgid, attr->dgid, sizeof(attr->dgid));
	memset(context_mask->dgid, 0, sizeof(attr->dgid));

	udma_reg_write(&(context->ext), QPCEX_DEID_H,
		       *(uint32_t *)(&attr->dgid[SGID_H_SHIFT]));
	udma_reg_clear(&context_mask->ext, QPCEX_DEID_H);

	udma_reg_write(context, QPC_SL, attr->priority);
	udma_reg_clear(context_mask, QPC_SL);
}

static int udma_pass_qpc_to_hw(struct udma_dev *udma_device,
			       struct udma_qp_context *context,
			       struct udma_qp_context *qpc_mask,
			       struct udma_qp *qp)
{
	struct udma_cmd_mailbox *mailbox;
	struct udma_cmq_desc desc;
	int qpc_size;
	int ret;

	struct udma_mbox *mb = (struct udma_mbox *)desc.data;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mailbox = udma_alloc_cmd_mailbox(udma_device);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	mbox_desc_init(mb, mailbox->dma, 0, qp->qpn, UDMA_CMD_MODIFY_QPC);
	qpc_size = udma_device->caps.qpc_sz;
	memcpy(mailbox->buf, context, qpc_size);
	memcpy(mailbox->buf + qpc_size, qpc_mask, qpc_size);

	ret = udma_cmd_mbox(udma_device, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);

	udma_free_cmd_mailbox(udma_device, mailbox);

	return ret;
}

int udma_set_dca_buf(struct udma_dev *dev, struct udma_qp *qp)
{
	struct udma_qp_context ctx[2] = {};
	struct udma_qp_context *msk = ctx + 1;
	struct udma_qp_context *qpc = ctx;
	int ret;

	memset(msk, 0xff, dev->caps.qpc_sz);

	ret = config_qp_sq_buf(dev, qp, qpc, msk);
	if (ret) {
		dev_err(dev->dev, "failed to config sq qpc, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_pass_qpc_to_hw(dev, qpc, msk, qp);
	if (ret) {
		dev_err(dev->dev, "failed to modify DCA buf, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static bool check_qp_timeout_cfg_range(struct udma_dev *udma_device,
				       uint8_t *timeout)
{
	if (*timeout > QP_TIMEOUT_MAX) {
		dev_warn(udma_device->dev,
			 "Local ACK timeout shall be 0 to 31.\n");
		return false;
	}

	return true;
}

static enum udma_mtu to_udma_mtu(enum ubcore_mtu core_mtu)
{
	switch (core_mtu) {
	case UBCORE_MTU_256:
		return UDMA_MTU_256;
	case UBCORE_MTU_512:
		return UDMA_MTU_512;
	case UBCORE_MTU_1024:
		return UDMA_MTU_1024;
	case UBCORE_MTU_2048:
		return UDMA_MTU_2048;
	default:
		return UDMA_MTU_4096;
	}
}

static inline enum ubcore_mtu get_mtu(struct udma_qp *qp,
				      struct ubcore_tp_attr *attr)
{
	if (qp->qp_type == QPT_UD || attr == NULL)
		return UBCORE_MTU_4096;

	return attr->mtu;
}

static int udma_alloc_reorder_cq_buf(struct udma_dev *udma_dev,
				     struct udma_qp_attr *qp_attr)
{
	struct udma_caps *caps = &udma_dev->caps;
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

static void udma_free_reorder_cq_buf(struct udma_dev *udma_dev,
				     struct udma_qp_attr *qp_attr)
{
	if (qp_attr->reorder_cq_page)
		dma_free_coherent(udma_dev->dev, qp_attr->reorder_cq_size,
				  qp_attr->reorder_cq_page,
				  qp_attr->reorder_cq_addr);
}

static void edit_qpc_for_inline(struct udma_qp_context *context,
				struct udma_qp_context *context_mask,
				struct udma_qp *qp)
{
	struct udma_dev *udma_dev = qp->udma_device;

	if (qp->qp_type != QPT_UD) {
		udma_reg_write(context, QPC_CQEIE,
			       !!(udma_dev->caps.flags &
				UDMA_CAP_FLAG_CQE_INLINE));
		udma_reg_clear(context_mask, QPC_CQEIE);
	}
}

static void edit_qpc_for_db(struct udma_qp_context *context, struct udma_qp_context *context_mask,
			    struct udma_qp *qp)
{
	if (qp->en_flags & UDMA_QP_CAP_RQ_RECORD_DB) {
		udma_reg_enable(context, QPC_RQ_RECORD_EN);
		udma_reg_clear(context_mask, QPC_RQ_RECORD_EN);
		if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
		    !qp->qp_attr.jetty->dca_en) {
			udma_reg_write(context, QPC_RQ_DB_RECORD_ADDR_L,
				lower_32_bits(qp->qp_attr.jfr->db.dma) >>
						DMA_DB_RECORD_SHIFT);
			udma_reg_write(context, QPC_RQ_DB_RECORD_ADDR_H,
				upper_32_bits(qp->qp_attr.jfr->db.dma));

			udma_reg_clear(context_mask, QPC_RQ_DB_RECORD_ADDR_L);
			udma_reg_clear(context_mask, QPC_RQ_DB_RECORD_ADDR_H);
		}
	}

	if (qp->en_flags & UDMA_QP_CAP_OWNER_DB) {
		udma_reg_enable(context, QPC_OWNER_MODE);
		udma_reg_clear(context_mask, QPC_OWNER_MODE);
	}
}

static void edit_qpc_for_srqn(struct udma_qp *qp,
			      struct udma_qp_context *context,
			      struct udma_qp_context *context_mask)
{
	if (qp->qp_attr.jfr) {
		if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
		    !qp->qp_attr.jetty->dca_en)
			return;
		udma_reg_enable(context, QPC_SRQ_EN);
		udma_reg_clear(context_mask, QPC_SRQ_EN);

		udma_reg_write(context, QPC_SRQN, qp->qp_attr.jfr->srqn);
		udma_reg_clear(context_mask, QPC_SRQN);
	}
}

static void edit_qpc_for_rxcqn(struct udma_qp *qp,
			       struct udma_qp_context *context,
			       struct udma_qp_context *context_mask)
{
	if (qp->recv_jfc) {
		udma_reg_write(context, QPC_RX_CQN, qp->recv_jfc->cqn);
		udma_reg_clear(context_mask, QPC_RX_CQN);
	}
}

static void edit_qpc_for_retransmission_parm(struct udma_dev *udma_device,
					     struct udma_qp *qp,
					     struct udma_modify_tp_attr *attr,
					     struct udma_qp_context *context,
					     struct udma_qp_context *context_mask)
{
	if (qp->qp_type != QPT_UD) {
		udma_reg_write(context, QPC_MIN_RNR_TIME,
			       attr->min_rnr_timer);
		udma_reg_clear(context_mask, QPC_MIN_RNR_TIME);

		udma_reg_write(context, QPC_RETRY_CNT,
			       attr->retry_cnt);
		udma_reg_clear(context_mask, QPC_RETRY_CNT);

		udma_reg_write(context, QPC_RETRY_NUM_INIT,
			       attr->retry_cnt);
		udma_reg_clear(context_mask, QPC_RETRY_NUM_INIT);

		udma_reg_write(context, QPC_RNR_CNT,
			       attr->rnr_retry);
		udma_reg_clear(context_mask, QPC_RNR_CNT);

		udma_reg_write(context, QPC_RNR_NUM_INIT,
			       attr->rnr_retry);
		udma_reg_clear(context_mask, QPC_RNR_NUM_INIT);

		if (check_qp_timeout_cfg_range(udma_device, &attr->ack_timeout)) {
			udma_reg_write(context, QPC_AT, attr->ack_timeout);
			udma_reg_clear(context_mask, QPC_AT);
		}
	}
}

static void edit_qpc_for_write(struct udma_qp *qp,
			       struct udma_qp_context *context,
			       struct udma_qp_context *context_mask)
{
	udma_reg_enable(context, QPC_FLUSH_EN);
	udma_reg_clear(context_mask, QPC_FLUSH_EN);

	udma_reg_enable(context, QPC_AW_EN);
	udma_reg_clear(context_mask, QPC_AW_EN);

	udma_reg_enable(context, QPC_WN_EN);
	udma_reg_clear(context_mask, QPC_WN_EN);

	udma_reg_enable(context, QPC_RMT_E2E);
	udma_reg_clear(context_mask, QPC_RMT_E2E);

	udma_reg_write(context, QPC_SIG_TYPE, SIGNAL_REQ_WR);
	udma_reg_clear(context_mask, QPC_SIG_TYPE);
}

static void edit_qpc_for_receive(struct udma_qp *qp,
				 struct udma_modify_tp_attr *attr,
				 struct udma_qp_context *context,
				 struct udma_qp_context *context_mask)
{
	uint8_t *dmac;

	dmac = (uint8_t *)attr->dmac;
	memcpy(&context->dmac, dmac, sizeof(uint32_t));
	udma_reg_write(context, QPC_DMAC_L, *((uint32_t *)(&dmac[0])));
	udma_reg_clear(context_mask, QPC_DMAC_L);

	udma_reg_write(context, QPC_DMAC_H,
			*((uint16_t *)(&dmac[QPC_DMAC_H_IDX])));
	udma_reg_clear(context_mask, QPC_DMAC_H);

	context->rq_rnr_timer = 0;
	context_mask->rq_rnr_timer = 0;

	/* rocee send 2^lp_sgen_ini segs every time */
	udma_reg_write(context, QPC_LP_SGEN_INI, SGEN_INI_VALUE);
	udma_reg_clear(context_mask, QPC_LP_SGEN_INI);
}

static int modify_qp_reset_to_rtr(struct udma_qp *qp,
				  struct udma_modify_tp_attr *attr,
				  struct udma_qp_context *context,
				  struct udma_qp_context *context_mask)
{
	struct udma_dev *udma_device = qp->udma_device;

	udma_reg_write(context, QPC_RRE, 1);
	udma_reg_clear(context_mask, QPC_RRE);

	udma_reg_write(context, QPC_RWE, 1);
	udma_reg_clear(context_mask, QPC_RWE);

	udma_reg_write(context, QPC_TST, qp->qp_type);
	udma_reg_clear(context_mask, QPC_TST);

	udma_reg_write(context, QPC_RQWS, ilog2(qp->rq.max_gs));
	udma_reg_clear(context_mask, QPC_RQWS);

	/* No VLAN need to set 0xFFF */
	udma_reg_write(context, QPC_VLAN_ID, 0xfff);
	udma_reg_clear(context_mask, QPC_VLAN_ID);

	edit_qpc_for_db(context, context_mask, qp);

	edit_qpc_for_inline(context, context_mask, qp);

	udma_reg_write(&context->ext, QPCEX_P_TYPE, QPCEX_P_TYPE_UDMA);
	udma_reg_clear(&context_mask->ext, QPCEX_P_TYPE);

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

static int modify_qp_rtr_to_rts(struct udma_qp *qp,
				struct udma_qp_context *context,
				struct udma_qp_context *context_mask)
{
	struct udma_dev *udma_device = qp->udma_device;
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
		udma_reg_write(context, QPC_TX_CQN, qp->send_jfc->cqn);
		udma_reg_clear(context_mask, QPC_TX_CQN);
	}

	if (qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH) {
		udma_reg_enable(context, QPC_DCA_MODE);
		udma_reg_clear(context_mask, QPC_DCA_MODE);
	}

	set_qpc_wqe_cnt(qp, context, context_mask);

	return 0;
}

static enum udma_cong_type to_udma_cong_type(uint32_t cc_alg)
{
	switch ((enum ubcore_tp_cc_alg)cc_alg) {
	case UBCORE_TP_CC_DCQCN:
		return UDMA_CONG_TYPE_DCQCN;
	case UBCORE_TP_CC_LDCP:
		return UDMA_CONG_TYPE_LDCP;
	case UBCORE_TP_CC_HC3:
		return UDMA_CONG_TYPE_HC3;
	case UBCORE_TP_CC_DIP:
		return UDMA_CONG_TYPE_DIP;
	default:
		return UDMA_CONG_TYPE_DCQCN;
	}
}

static void fill_congest_type(struct udma_congestion_algorithm *congest_alg,
			      enum udma_cong_type qp_cong_alg)
{
	switch (qp_cong_alg) {
	case UDMA_CONG_TYPE_DCQCN:
		congest_alg->congest_type = CONGEST_DCQCN;
		congest_alg->alg_sel = DCQCN_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	case UDMA_CONG_TYPE_LDCP:
		congest_alg->congest_type = CONGEST_LDCP;
		congest_alg->alg_sel = WINDOW_ALG;
		congest_alg->alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_UNLIMIT;
		break;
	case UDMA_CONG_TYPE_HC3:
		congest_alg->congest_type = CONGEST_HC3;
		congest_alg->alg_sel = WINDOW_ALG;
		congest_alg->alg_sub_sel = SUPPORT_CONGEST_DEGREE;
		congest_alg->dip_vld = DIP_INVALID;
		congest_alg->wnd_mode_sel = WND_LIMIT;
		break;
	case UDMA_CONG_TYPE_DIP:
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

static int get_dip_ctx_idx(struct udma_qp *qp,
			   uint32_t *dip_idx)
{
	struct udma_dev *udma_dev = qp->udma_device;
	uint32_t *spare_idx = udma_dev->qp_table.idx_table.spare_idx;
	uint32_t *head = &udma_dev->qp_table.idx_table.head;
	uint32_t *tail = &udma_dev->qp_table.idx_table.tail;
	struct udma_modify_tp_attr *attr;
	struct udma_dip *udma_dip;
	unsigned long flags;
	int ret = 0;

	attr = qp->m_attr;
	spin_lock_irqsave(&udma_dev->dip_list_lock, flags);

	spare_idx[*tail] = qp->qpn;
	*tail = (*tail == udma_dev->caps.num_qps - 1) ? 0 : (*tail + 1);

	list_for_each_entry(udma_dip, &udma_dev->dip_list, node) {
		if (!memcmp(attr->dgid, udma_dip->dgid, UDMA_GID_SIZE)) {
			*dip_idx = udma_dip->dip_idx;
			goto out;
		}
	}

	udma_dip = kzalloc(sizeof(*udma_dip), GFP_ATOMIC);
	if (!udma_dip) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(udma_dip->dgid, attr->dgid, sizeof(attr->dgid));
	udma_dip->dip_idx = *dip_idx = spare_idx[*head];
	*head = (*head == udma_dev->caps.num_qps - 1) ? 0 : (*head + 1);
	list_add_tail(&udma_dip->node, &udma_dev->dip_list);

out:
	spin_unlock_irqrestore(&udma_dev->dip_list_lock, flags);
	return ret;
}

static int udma_set_cong_fields(struct udma_qp_context *context,
				struct udma_qp_context *context_mask,
				struct udma_qp *qp,
				struct ubcore_tp_attr *attr)
{
	struct udma_congestion_algorithm congest_filed;
	enum udma_cong_type qp_cong_alg;
	uint32_t dip_idx = 0;
	int ret = 0;

	qp_cong_alg = to_udma_cong_type(attr->flag.bs.cc_alg);
	fill_congest_type(&congest_filed, qp_cong_alg);

	if (qp->qp_type == QPT_UD) {
		congest_filed.congest_type = CONGEST_DCQCN;
		congest_filed.alg_sel = DCQCN_ALG;
		congest_filed.alg_sub_sel = UNSUPPORT_CONGEST_DEGREE;
		congest_filed.dip_vld = DIP_INVALID;
		congest_filed.wnd_mode_sel = WND_LIMIT;
	}

	udma_reg_write(context, QPC_CONGEST_ALGO_TMPL_ID,
				   qp->udma_device->cong_algo_tmpl_id +
				   congest_filed.congest_type * UDMA_CONGEST_SIZE);
	udma_reg_clear(context_mask, QPC_CONGEST_ALGO_TMPL_ID);

	udma_reg_write(&context->ext, QPCEX_CONGEST_ALG_SEL, congest_filed.alg_sel);
	udma_reg_clear(&context_mask->ext, QPCEX_CONGEST_ALG_SEL);

	udma_reg_write(&context->ext, QPCEX_CONGEST_ALG_SUB_SEL, congest_filed.alg_sub_sel);
	udma_reg_clear(&context_mask->ext, QPCEX_CONGEST_ALG_SUB_SEL);

	udma_reg_write(&context->ext, QPCEX_DIP_CTX_IDX_VLD, congest_filed.dip_vld);
	udma_reg_clear(&context_mask->ext, QPCEX_DIP_CTX_IDX_VLD);

	udma_reg_write(&context->ext, QPCEX_SQ_RQ_NOT_FORBID_EN, congest_filed.wnd_mode_sel);
	udma_reg_clear(&context_mask->ext, QPCEX_SQ_RQ_NOT_FORBID_EN);

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
		ret = udma_table_get(qp->udma_device,
				     &qp->udma_device->qp_table.sccc_table,
				     dip_idx);
		if (ret) {
			dev_err(qp->udma_device->dev,
				"Failed to get SCC CTX table\n");
			goto out;
		}
	}

	udma_reg_write(&context->ext, QPCEX_DIP_CTX_IDX, dip_idx);
	udma_reg_clear(&context_mask->ext, QPCEX_DIP_CTX_IDX);

out:
	return ret;
}

static void udma_set_spray_field(struct udma_qp *qp,
				 struct ubcore_tp_attr *attr,
				 union ubcore_tp_attr_mask ubcore_mask,
				 struct udma_qp_context *context,
				 struct udma_qp_context *context_mask)
{
	uint16_t dus_regval;
	uint16_t aus_regval;
	uint16_t real_range;

	real_range = (attr->udp_range + UDP_SRCPORT_RANGE_BASE) &
		     UDP_SRCPORT_RANGE_SIZE_MASK;
	dus_regval = attr->data_udp_start & GENMASK(real_range, 0);
	aus_regval = attr->ack_udp_start & GENMASK(real_range, 0);

	udma_reg_enable(&context->ext, QPCEX_AR_EN);
	udma_reg_clear(&context_mask->ext, QPCEX_AR_EN);

	if (ubcore_mask.bs.ack_udp_start) {
		udma_reg_write(&context->ext, QPCEX_ACK_UDP_SRCPORT,
			       aus_regval);
		udma_reg_clear(&context_mask->ext, QPCEX_ACK_UDP_SRCPORT);
	}

	if (ubcore_mask.bs.data_udp_start) {
		udma_reg_write(&context->ext, QPCEX_DATA_UDP_SRCPORT_L,
			       dus_regval);
		udma_reg_clear(&context_mask->ext, QPCEX_DATA_UDP_SRCPORT_L);
		udma_reg_write(&context->ext, QPCEX_DATA_UDP_SRCPORT_H,
			       dus_regval >> QPCEX_DATA_UDP_SRCPORT_H_SHIFT);
		udma_reg_clear(&context_mask->ext, QPCEX_DATA_UDP_SRCPORT_H);
	}

	if (ubcore_mask.bs.udp_range) {
		udma_reg_write(&context->ext, QPCEX_UDP_SRCPORT_RANGE,
			       attr->udp_range);
		udma_reg_clear(&context_mask->ext, QPCEX_UDP_SRCPORT_RANGE);
	}
}

static void udma_set_oor_field(struct udma_qp *qp,
			       struct ubcore_tp_attr *attr,
			       union ubcore_tp_attr_mask ubcore_mask,
			       struct udma_qp_context *context,
			       struct udma_qp_context *context_mask)
{
	struct udma_dev *udma_dev = qp->udma_device;

	udma_reg_enable(&context->ext, QPCEX_OOR_EN);
	udma_reg_clear(&context_mask->ext, QPCEX_OOR_EN);

	udma_reg_write(&context->ext, QPCEX_REORDER_CAP,
			udma_dev->caps.reorder_cap);
	udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CAP);

	udma_reg_write(&context->ext, QPCEX_ON_FLIGHT_SIZE_L,
			udma_dev->caps.onflight_size);
	udma_reg_clear(&context_mask->ext, QPCEX_ON_FLIGHT_SIZE_L);

	udma_reg_write(&context->ext, QPCEX_ON_FLIGHT_SIZE_H,
			udma_dev->caps.onflight_size >>
			QPCEX_ON_FLIGHT_SIZE_H_SHIFT);
	udma_reg_clear(&context_mask->ext, QPCEX_ON_FLIGHT_SIZE_H);

	udma_reg_write(&context->ext, QPCEX_DYN_AT,
			udma_dev->caps.dynamic_ack_timeout);
	udma_reg_clear(&context_mask->ext, QPCEX_DYN_AT);

	if (udma_dev->caps.reorder_cq_buffer_en &&
	    qp->qp_attr.reorder_cq_addr) {
		udma_reg_enable(&context->ext, QPCEX_REORDER_CQ_EN);
		udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_EN);

		udma_reg_write(&context->ext, QPCEX_REORDER_CQ_ADDR_L,
			       lower_32_bits(qp->qp_attr.reorder_cq_addr) >>
			       QPCEX_REORDER_CQ_ADDR_SHIFT);
		udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_ADDR_L);

		udma_reg_write(&context->ext, QPCEX_REORDER_CQ_ADDR_H,
			       upper_32_bits(qp->qp_attr.reorder_cq_addr));
		udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_ADDR_H);

		udma_reg_write(&context->ext, QPCEX_REORDER_CQ_SHIFT,
			       udma_dev->caps.reorder_cq_shift);
		udma_reg_clear(&context_mask->ext, QPCEX_REORDER_CQ_SHIFT);
	}
}

static void udma_set_mtu_field(struct udma_qp *qp,
			       struct ubcore_tp_attr *attr,
			       struct udma_qp_context *context,
			       struct udma_qp_context *context_mask)
{
	qp->ubcore_path_mtu = get_mtu(qp, attr);
	qp->path_mtu = to_udma_mtu(qp->ubcore_path_mtu);
	udma_reg_write(context, QPC_MTU, qp->path_mtu);
	udma_reg_clear(context_mask, QPC_MTU);

	udma_reg_write(context, QPC_LP_PKTN_INI, 0);
	udma_reg_clear(context_mask, QPC_LP_PKTN_INI);

	/* ACK_REQ_FREQ should be larger than or equal to LP_PKTN_INI */
	udma_reg_write(context, QPC_ACK_REQ_FREQ, 0);
	udma_reg_clear(context_mask, QPC_ACK_REQ_FREQ);
}

static void udma_set_opt_fields(struct udma_qp *qp,
				struct ubcore_tp_attr *attr,
				union ubcore_tp_attr_mask ubcore_mask,
				struct udma_qp_context *context,
				struct udma_qp_context *context_mask)
{
	struct udma_dev *udma_dev = qp->udma_device;

	if (attr == NULL)
		return;

	if (ubcore_mask.bs.flag && attr->flag.bs.oor_en && udma_dev->caps.oor_en)
		udma_set_oor_field(qp, attr, ubcore_mask, context, context_mask);

	if (ubcore_mask.bs.flag && attr->flag.bs.cc_en)
		udma_set_cong_fields(context, context_mask, qp, attr);

	if (ubcore_mask.bs.flag && attr->flag.bs.spray_en &&
		(udma_dev->caps.flags & UDMA_CAP_FLAG_AR)) {
		udma_set_spray_field(qp, attr, ubcore_mask, context, context_mask);
	} else {
		udma_reg_write(context, QPC_UDPSPN, attr->data_udp_start);
		udma_reg_clear(context_mask, QPC_UDPSPN);
	}

	if (ubcore_mask.bs.peer_tpn) {
		udma_reg_write(context, QPC_DQPN, attr->peer_tpn);
		udma_reg_clear(context_mask, QPC_DQPN);
	}

	if (ubcore_mask.bs.tx_psn) {
		udma_reg_write(context, QPC_RX_ACK_EPSN, attr->tx_psn);
		udma_reg_write(context, QPC_RETRY_MSG_PSN_L, attr->tx_psn);
		udma_reg_write(context, QPC_RETRY_MSG_PSN_H,
				attr->tx_psn >> RETRY_MSG_PSN_H_OFFSET);
		udma_reg_write(context, QPC_RETRY_MSG_FPKT_PSN, attr->tx_psn);
		udma_reg_write(context, QPC_SQ_CUR_PSN, attr->tx_psn);
		udma_reg_write(context, QPC_SQ_MAX_PSN, attr->tx_psn);

		udma_reg_clear(context_mask, QPC_RX_ACK_EPSN);
		udma_reg_clear(context_mask, QPC_RETRY_MSG_PSN_L);
		udma_reg_clear(context_mask, QPC_RETRY_MSG_PSN_H);
		udma_reg_clear(context_mask, QPC_RETRY_MSG_FPKT_PSN);
		udma_reg_clear(context_mask, QPC_SQ_CUR_PSN);
		udma_reg_clear(context_mask, QPC_SQ_MAX_PSN);
	}

	if (ubcore_mask.bs.rx_psn) {
		udma_reg_write(context, QPC_RX_REQ_EPSN, attr->rx_psn);
		udma_reg_write(context, QPC_RAQ_PSN, attr->rx_psn - 1);

		udma_reg_clear(context_mask, QPC_RX_REQ_EPSN);
		udma_reg_clear(context_mask, QPC_RAQ_PSN);
	}

	if (ubcore_mask.bs.mtu)
		udma_set_mtu_field(qp, attr, context, context_mask);

	if (ubcore_mask.bs.hop_limit) {
		udma_reg_write(context, QPC_HOPLIMIT, attr->hop_limit);
		udma_reg_clear(context_mask, QPC_HOPLIMIT);
	}
}

static int udma_set_abs_fields(struct udma_qp *qp,
			       struct udma_modify_tp_attr *attr,
			       enum udma_qp_state curr_state,
			       enum udma_qp_state new_state,
			       struct udma_qp_context *context,
			       struct udma_qp_context *context_mask)
{
	struct udma_dev *udma_device = qp->udma_device;
	int ret = 0;

	if (curr_state == QPS_RESET && new_state == QPS_RTR) {
		ret = modify_qp_reset_to_rtr(qp, attr, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"Something went wrong during reset to rtr, new_state = %d.\n",
				new_state);
			goto out;
		}
	} else if (curr_state == QPS_RESET && new_state == QPS_RTS) {
		ret = modify_qp_reset_to_rtr(qp, attr, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"Something went wrong during reset to rtr, new_state = %d.\n",
				new_state);
			goto out;
		}
		ret = modify_qp_rtr_to_rts(qp, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"Something went wrong during rtr to rts, new_state = %d.\n",
				new_state);
			goto out;
		}
	} else if (curr_state == QPS_RTR && new_state == QPS_RTS) {
		ret = modify_qp_rtr_to_rts(qp, context, context_mask);
		if (ret) {
			dev_err(udma_device->dev,
				"Something went wrong during rtr to rts, curr_state = %d.\n",
				curr_state);
			goto out;
		}
	}

out:
	return ret;
}

static void udma_set_um_attr(struct udma_qp *qp,
			     struct udma_qp_context *context,
			     struct udma_qp_context *context_mask)
{
	qp->ubcore_path_mtu = get_mtu(qp, NULL);
	qp->path_mtu = to_udma_mtu(qp->ubcore_path_mtu);
	udma_reg_write(context, QPC_MTU, qp->path_mtu);
	udma_reg_clear(context_mask, QPC_MTU);

	udma_reg_write(context, QPC_LP_PKTN_INI, 0);
	udma_reg_clear(context_mask, QPC_LP_PKTN_INI);

	/* ACK_REQ_FREQ should be larger than or equal to LP_PKTN_INI */
	udma_reg_write(context, QPC_ACK_REQ_FREQ, 0);
	udma_reg_clear(context_mask, QPC_ACK_REQ_FREQ);
}

int udma_modify_qp_common(struct udma_qp *qp,
			  struct ubcore_tp_attr *attr,
			  union ubcore_tp_attr_mask ubcore_mask,
			  enum udma_qp_state curr_state,
			  enum udma_qp_state new_state)
{
	struct udma_dev *udma_device = qp->udma_device;
	struct udma_qp_context ctx[2] = {};
	struct udma_qp_context *context = ctx;
	struct udma_qp_context *context_mask = ctx + 1;
	int ret = 0;

	memset(context, 0, udma_device->caps.qpc_sz);
	memset(context_mask, 0xff, udma_device->caps.qpc_sz);
	if (new_state != QPS_RESET) {
		ret = udma_set_abs_fields(qp, qp->m_attr, curr_state, new_state,
					  context, context_mask);
		if (ret)
			goto out;
	}

	if (qp->qp_type == QPT_UD)
		udma_set_um_attr(qp, context, context_mask);

	udma_set_opt_fields(qp, attr, ubcore_mask, context, context_mask);

	udma_reg_write(context, QPC_INV_CREDIT, (!!qp->qp_attr.jfr) ? 1 : 0);
	udma_reg_clear(context_mask, QPC_INV_CREDIT);
	/* Every status migrate must change state */
	udma_reg_write(context, QPC_QP_ST, new_state);
	udma_reg_clear(context_mask, QPC_QP_ST);

	udma_set_path(qp->m_attr, context, context_mask);

	udma_reg_write(&context->ext, QPCEX_P_TYPE, QPCEX_P_TYPE_UDMA);
	udma_reg_clear(&context_mask->ext, QPCEX_P_TYPE);
	/* SW pass context to HW */
	ret = udma_pass_qpc_to_hw(udma_device, context, context_mask, qp);
	if (ret) {
		dev_err(udma_device->dev, "failed to pass QPC to HW, ret = %d.\n",
			ret);
		goto out;
	}

	qp->state = new_state;

	if (qp->qp_type == QPT_RC &&
	    qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_modify_dca(udma_device, qp);

out:
	return ret;
}

int fill_jfs_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		     struct udma_create_tp_ucmd *ucmd)
{
	struct udma_jfs *udma_jfs;
	struct ubcore_jfs *jfs;
	struct ubcore_jfc *jfc;

	udma_jfs = (struct udma_jfs *)xa_load(&udma_dev->jfs_table.xa,
					      ucmd->ini_id.jfs_id);
	if (IS_ERR_OR_NULL(udma_jfs)) {
		dev_err(udma_dev->dev, "failed to find jfs\n");
		return -EINVAL;
	}
	jfs = &udma_jfs->ubcore_jfs;
	jfc = jfs->jfs_cfg.jfc;
	qp_attr->send_jfc = to_udma_jfc(jfc);
	qp_attr->recv_jfc = NULL;
	qp_attr->jfs = udma_jfs;
	qp_attr->qpn_map = &qp_attr->jfs->qpn_map;
	qp_attr->uctx = qp_attr->jfs->ubcore_jfs.uctx;
	qp_attr->cap.max_send_wr = jfs->jfs_cfg.depth;
	qp_attr->cap.max_send_sge = jfs->jfs_cfg.max_sge;
	qp_attr->cap.max_inline_data = jfs->jfs_cfg.max_inline_data;
	qp_attr->cap.rnr_retry = jfs->jfs_cfg.rnr_retry;
	qp_attr->cap.ack_timeout = jfs->jfs_cfg.err_timeout;
	qp_attr->qp_type = QPT_RC;
	qp_attr->tgt_id = ucmd->tgt_id.jfr_id;
	qp_attr->tp_mode = udma_jfs->tp_mode;
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

int fill_jfr_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		     struct udma_create_tp_ucmd *ucmd)
{
	struct udma_jfr *udma_jfr;
	struct ubcore_jfr *jfr;

	udma_jfr = (struct udma_jfr *)xa_load(&udma_dev->jfr_table.xa,
					      ucmd->tgt_id.jfr_id);
	if (IS_ERR_OR_NULL(udma_jfr)) {
		dev_err(udma_dev->dev, "failed to find jfr\n");
		return -EINVAL;
	}
	jfr = &udma_jfr->ubcore_jfr;
	qp_attr->jfr = udma_jfr;
	qp_attr->recv_jfc = to_udma_jfc(jfr->jfr_cfg.jfc);
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

	if (is_rc_jetty(qp_attr) && !qp_attr->jetty->shared_jfr &&
	    !qp_attr->jetty->dca_en) {
		qp_attr->cap.max_recv_wr = jfr->jfr_cfg.depth;
		qp_attr->cap.max_recv_sge = jfr->jfr_cfg.max_sge;
	}

	return 0;
}

int fill_jetty_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		       struct udma_create_tp_ucmd *ucmd)
{
	struct udma_jetty *udma_jetty;
	struct ubcore_jetty *jetty;
	uint32_t jetty_id;

	jetty_id = qp_attr->is_tgt ? ucmd->tgt_id.jetty_id :
		   ucmd->ini_id.jetty_id;
	qp_attr->tgt_id = qp_attr->is_tgt ? ucmd->ini_id.jetty_id :
			  ucmd->tgt_id.jetty_id;

	udma_jetty = (struct udma_jetty *)xa_load(&udma_dev->jetty_table.xa,
						  jetty_id);
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
		qp_attr->send_jfc = to_udma_jfc(jetty->jetty_cfg.send_jfc);
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

	qp_attr->jfr = udma_jetty->udma_jfr;
	qp_attr->uctx = udma_jetty->udma_jfr->ubcore_jfr.uctx;
	qp_attr->qpn_map = &udma_jetty->qpn_map;
	qp_attr->recv_jfc = to_udma_jfc(udma_jetty->udma_jfr->ubcore_jfr.jfr_cfg.jfc);

	qp_attr->qp_type = QPT_RC;
	qp_attr->cap.min_rnr_timer = udma_jetty->udma_jfr->ubcore_jfr.jfr_cfg.min_rnr_timer;

	qp_attr->cap.ack_timeout = jetty->jetty_cfg.err_timeout;
	qp_attr->cap.rnr_retry = jetty->jetty_cfg.rnr_retry;

	if (is_rc_jetty(qp_attr) && !qp_attr->jetty->shared_jfr &&
	    !qp_attr->jetty->dca_en) {
		qp_attr->cap.max_recv_wr = udma_jetty->udma_jfr->ubcore_jfr.jfr_cfg.depth;
		qp_attr->cap.max_recv_sge = udma_jetty->udma_jfr->ubcore_jfr.jfr_cfg.max_sge;
	}

	return 0;
}

int udma_fill_qp_attr(struct udma_dev *udma_dev, struct udma_qp_attr *qp_attr,
		      struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata)
{
	bool is_target = cfg->flag.bs.target;
	struct udma_create_tp_ucmd ucmd;
	struct udma_ucontext *udma_ctx;
	int status, eid_index;

	if (!udata)
		return 0;

	status = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
				min(udata->udrv_data->in_len,
				    (uint32_t)sizeof(ucmd)));
	if (status) {
		dev_err(udma_dev->dev,
			"failed to copy create tp ucmd, status = %d.\n", status);
		return status;
	}

	qp_attr->is_tgt = is_target;
	qp_attr->is_jetty = ucmd.is_jetty;
	qp_attr->remote_eid = cfg->peer_eid;
	qp_attr->local_eid = cfg->local_eid;

	if (!is_target) {
		udma_ctx = to_udma_ucontext(udata->uctx);
		qp_attr->pdn = udma_ctx->pdn;
		qp_attr->eid_index = udma_ctx->eid_index;
		if (!ucmd.is_jetty)
			return fill_jfs_qp_attr(udma_dev, qp_attr, &ucmd);
		else
			return fill_jetty_qp_attr(udma_dev, qp_attr, &ucmd);
	} else {
		eid_index = udma_find_eid_idx(udma_dev, cfg->local_eid);
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

	return status;
}

static uint32_t get_wqe_ext_sge_cnt(struct udma_qp *qp)
{
	/* UD QP only has extended sge */
	if (qp->qp_type == QPT_UD)
		return qp->sq.max_gs;

	if (qp->sq.max_gs > UDMA_SGE_IN_WQE)
		return qp->sq.max_gs - UDMA_SGE_IN_WQE;

	return 0;
}

static void set_ext_sge_param(struct udma_dev *udma_dev, uint32_t sq_wqe_cnt,
			      struct udma_qp *qp, struct udma_qp_cap *cap)
{
	uint32_t max_inline_data;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t wqe_sge_cnt;

	qp->sge.sge_shift = UDMA_SGE_SHIFT;

	max_inline_data = roundup_pow_of_two(cap->max_inline_data);
	ext_sge_cnt = max_inline_data / UDMA_SGE_SIZE;

	/* Select the max data set by the user */
	qp->sq.max_gs = max(ext_sge_cnt, cap->max_send_sge);

	if (is_rc_jetty(&qp->qp_attr))
		qp->sge.offset = qp->qp_attr.jetty->rc_node.sge_offset;

	wqe_sge_cnt = get_wqe_ext_sge_cnt(qp);
	/* If the number of extended sge is not zero, they MUST use the
	 * space of UDMA_EP_PAGE_SIZE at least.
	 */
	if (wqe_sge_cnt) {
		total_sge_cnt = roundup_pow_of_two(sq_wqe_cnt * wqe_sge_cnt);
		qp->sge.sge_cnt = max(total_sge_cnt,
				      (uint32_t)UDMA_PAGE_SIZE / UDMA_SGE_SIZE);
	}

	/* Ensure that the max_gs size does not exceed */
	qp->sq.max_gs = min(qp->sq.max_gs, udma_dev->caps.max_sq_sg);
}

static void set_rq_size(struct udma_dev *udma_dev, struct udma_qp *qp, struct udma_qp_cap *cap)
{
	if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		qp->rq.wqe_cnt = roundup_pow_of_two(cap->max_recv_wr);
		qp->rq.max_gs = roundup_pow_of_two(cap->max_recv_sge);
		qp->rq.wqe_shift = ilog2(roundup_pow_of_two(UDMA_SGE_SIZE * cap->max_recv_sge));
		qp->rq.offset = qp->qp_attr.jfr->offset;
		return;
	}
	/* set rq param to 0 */
	qp->rq.wqe_cnt = 0;
	qp->rq.max_gs = 1;
	cap->max_recv_wr = 0;
	cap->max_recv_sge = 0;
}

static int set_user_sq_size(struct udma_dev *udma_dev, struct udma_qp *qp,
			    struct udma_qp_cap *cap)
{
	uint32_t cfg_depth;

	if (cap->max_send_wr > udma_dev->caps.max_wqes ||
	    cap->max_send_sge > udma_dev->caps.max_sq_sg)
		return -EINVAL;

	qp->sq.wqe_shift = UDMA_SQ_WQE_SHIFT;
	cfg_depth = roundup_pow_of_two(cap->max_send_wr);
	qp->sq.wqe_cnt = cfg_depth < UDMA_MIN_JFS_DEPTH ?
			 UDMA_MIN_JFS_DEPTH : cfg_depth;

	set_ext_sge_param(udma_dev, qp->sq.wqe_cnt, qp, cap);

	return 0;
}

static int set_qp_param(struct udma_dev *udma_dev, struct udma_qp *qp,
			struct ubcore_udata *udata,
			struct udma_create_tp_ucmd *ucmd)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct device *dev = udma_dev->dev;
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
		ret = copy_from_user(ucmd, (void *)udata->udrv_data->in_addr,
				     min(udata->udrv_data->in_len,
					 (uint32_t)sizeof(struct udma_create_tp_ucmd)));
		if (ret) {
			dev_err(dev, "failed to copy create tp ucmd\n");
			return ret;
		}

		ret = set_user_sq_size(udma_dev, qp, &qp_attr->cap);
		if (ret)
			dev_err(dev,
				"failed to set user SQ size, ret = %d.\n", ret);
	} else {
		if (is_rc_jetty(qp_attr)) {
			ret = set_user_sq_size(udma_dev, qp, &qp_attr->cap);
			if (ret)
				dev_err(dev,
					"failed to set user SQ size for RC Jetty, ret = %d.\n",
					ret);
		}
	}

	return ret;
}

static uint8_t get_least_load_bankid_for_qp(struct udma_bank *bank,
					    struct udma_jfc *jfc)
{
	uint32_t least_load = UDMA_INVALID_LOAD_QPNUM;
	uint8_t bankid = 0;
	uint32_t bankcnt;
	uint8_t i;

	for (i = 0; i < UDMA_QP_BANK_NUM; ++i) {
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

static int alloc_qpn_with_bankid(struct udma_bank *bank, uint8_t bankid,
				 uint32_t *qpn)
{
	int idx;

	idx = ida_alloc_range(&bank->ida, bank->next, bank->max, GFP_KERNEL);
	if (idx < 0) {
		idx = ida_alloc_range(&bank->ida, bank->min, bank->max,
				     GFP_KERNEL);
		if (idx < 0)
			return idx;
	}

	bank->next =
		((uint32_t)idx + 1) > bank->max ? bank->min : (uint32_t)idx + 1;

	/* the lower 3 bits is bankid */
	*qpn = (idx << 3) | bankid;

	return 0;
}

int alloc_common_qpn(struct udma_dev *udma_dev, struct udma_jfc *jfc,
		     uint32_t *qpn)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;
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

void free_common_qpn(struct udma_dev *udma_dev, uint32_t qpn)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;
	uint8_t bankid;

	bankid = get_qp_bankid(qpn);
	ida_free(&qp_table->bank[bankid].ida, qpn / UDMA_QP_BANK_NUM);
	mutex_lock(&qp_table->bank_mutex);
	qp_table->bank[bankid].inuse--;
	mutex_unlock(&qp_table->bank_mutex);
}

static int alloc_qpn(struct udma_dev *udma_dev, struct udma_qp *qp, bool is_target)
{
	struct udma_qp_attr *attr = &qp->qp_attr;

	if (attr->is_jetty)
		qp->qpn = attr->jetty->jetty_id;
	else if (attr->jfs)
		qp->qpn = attr->jfs->jfs_id;
	else
		qp->qpn = attr->jfr->jfrn;

	return 0;
}

static void init_qpn_bitmap(struct udma_qpn_bitmap *qpn_map, uint32_t qpn_shift)
{
	int i;

	qpn_map->qpn_shift = qpn_shift;
	mutex_init(&qpn_map->bank_mutex);
	/* reserved 0 for UD */
	qpn_map->bank[0].min = 1;
	qpn_map->bank[0].inuse = 1;
	qpn_map->bank[0].next = qpn_map->bank[0].min;
	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&qpn_map->bank[i].ida);
		qpn_map->bank[i].max = (1 << qpn_shift) / UDMA_QP_BANK_NUM - 1;
	}
}

void init_jetty_x_qpn_bitmap(struct udma_dev *dev,
			     struct udma_qpn_bitmap *qpn_map,
			     uint32_t jetty_x_shift,
			     uint32_t prefix, uint32_t jid)
{
#define QPN_SHIFT_MIN 3
	int qpn_shift;

	qpn_shift = dev->caps.num_qps_shift - jetty_x_shift -
		    UDMA_JETTY_X_PREFIX_BIT_NUM;
	if (qpn_shift <= QPN_SHIFT_MIN) {
		qpn_map->qpn_shift = 0;
		return;
	}

	qpn_map->qpn_prefix = prefix <<
			      (dev->caps.num_qps_shift -
			      UDMA_JETTY_X_PREFIX_BIT_NUM);
	qpn_map->jid = jid;
	init_qpn_bitmap(qpn_map, qpn_shift);
}

void clean_jetty_x_qpn_bitmap(struct udma_qpn_bitmap *qpn_map)
{
	int i;

	if (!qpn_map->qpn_shift)
		return;
	mutex_lock(&qpn_map->bank_mutex);
	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&qpn_map->bank[i].ida);
	mutex_unlock(&qpn_map->bank_mutex);
}

static int set_wqe_buf_attr(struct udma_dev *udma_dev, struct udma_qp *qp,
			    struct udma_buf_attr *buf_attr, bool dca_en)
{
	uint32_t idx = 0;
	int buf_size;

	qp->buff_size = 0;

	/* SQ WQE */
	qp->sq.offset = 0;

	buf_size = to_udma_hem_entries_size(qp->sq.wqe_cnt,
					    qp->sq.wqe_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sq_hop_num;
		idx++;
		qp->buff_size += buf_size;
	}
	/* extend SGE WQE in SQ */
	qp->sge.offset = qp->buff_size;

	buf_size = to_udma_hem_entries_size(qp->sge.sge_cnt,
					    qp->sge.sge_shift);
	if (buf_size > 0 && idx < ARRAY_SIZE(buf_attr->region)) {
		buf_attr->region[idx].size = buf_size;
		buf_attr->region[idx].hopnum = udma_dev->caps.wqe_sge_hop_num;
		idx++;
		qp->buff_size += buf_size;
	}

	if (is_rc_jetty(&qp->qp_attr) && !qp->qp_attr.jetty->shared_jfr &&
	    !qp->qp_attr.jetty->dca_en) {
		/* RQ WQE */
		qp->rq.offset = qp->buff_size;

		buf_size = to_udma_hem_entries_size(qp->rq.wqe_cnt,
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
	buf_attr->page_shift = UDMA_HW_PAGE_SHIFT;
	buf_attr->mtt_only = dca_en;

	return 0;
}

static int alloc_wqe_buf(struct udma_dev *dev, struct udma_qp *qp,
			 struct udma_buf_attr *buf_attr, uint64_t addr,
			 bool dca_en)
{
	int ret;

	if (dca_en) {
		/* DCA must be enabled after the buffer attr is configured. */
		udma_enable_dca(dev, qp);
		qp->en_flags |= UDMA_QP_CAP_DYNAMIC_CTX_ATTACH;
	} else if ((PAGE_SIZE <= UDMA_DWQE_SIZE) &&
		   (dev->caps.flags & UDMA_CAP_FLAG_DIRECT_WQE)) {
		qp->en_flags |= UDMA_QP_CAP_DIRECT_WQE;
	}

	ret = udma_mtr_create(dev, &qp->mtr, buf_attr,
			      PAGE_SHIFT + dev->caps.mtt_ba_pg_sz, addr, true);
	if (ret) {
		dev_err(dev->dev, "failed to create WQE mtr, ret = %d.\n", ret);
		if (dca_en)
			udma_disable_dca(dev, qp);
	}

	return ret;
}

static bool check_dca_is_enable(struct udma_dev *udma_dev, struct udma_qp *qp,
				uint64_t buf_addr)
{
	if (qp->qp_type != QPT_RC ||
	    !(udma_dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE))
		return false;

	/* If the user QP's buffer addr is 0, the DCA mode should be enabled */
	return !buf_addr;
}

static int alloc_qp_wqe(struct udma_dev *udma_dev, struct udma_qp *qp,
			uint64_t buf_addr)
{
	struct device *dev = udma_dev->dev;
	struct udma_buf_attr buf_attr = {};
	bool dca_en;
	int ret;

	dca_en = check_dca_is_enable(udma_dev, qp, buf_addr);
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

static int alloc_user_qp_db(struct udma_dev *udma_dev, struct udma_qp *qp,
			    struct udma_create_tp_ucmd *ucmd)
{
	int ret;

	if (!ucmd->sdb_addr)
		return 0;

	ret = udma_db_map_user(udma_dev, ucmd->sdb_addr, &qp->sdb);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to map user sdb_addr, ret = %d.\n", ret);
		return ret;
	}

	qp->en_flags |= UDMA_QP_CAP_SQ_RECORD_DB;

	return 0;
}

static int alloc_qp_db(struct udma_dev *udma_dev, struct udma_qp *qp,
		       struct ubcore_udata *udata,
		       struct udma_create_tp_ucmd *ucmd)
{
	int ret = 0;

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SDI_MODE)
		qp->en_flags |= UDMA_QP_CAP_OWNER_DB;

	if (udata)
		ret = alloc_user_qp_db(udma_dev, qp, ucmd);

	return ret;
}

static int alloc_qpc(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;
	struct device *dev = udma_dev->dev;
	int ret;

	/* Alloc memory for QPC */
	ret = udma_table_get(udma_dev, &qp_table->qp_table, qp->qpn);
	if (ret) {
		dev_err(dev, "Failed to get QPC table\n");
		goto err_out;
	}

	/* Alloc memory for IRRL */
	ret = udma_table_get(udma_dev, &qp_table->irrl_table, qp->qpn);
	if (ret) {
		dev_err(dev, "Failed to get IRRL table\n");
		goto err_put_qp;
	}

	if (udma_dev->caps.trrl_entry_sz) {
		/* Alloc memory for TRRL */
		ret = udma_table_get(udma_dev, &qp_table->trrl_table,
				     qp->qpn);
		if (ret) {
			dev_err(dev, "Failed to get TRRL table\n");
			goto err_put_irrl;
		}
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		/* Alloc memory for SCC CTX */
		ret = udma_table_get(udma_dev, &qp_table->sccc_table,
				     qp->qpn);
		if (ret) {
			dev_err(dev, "Failed to get SCC CTX table\n");
			goto err_put_trrl;
		}
	}

	if (udma_dev->caps.reorder_cq_buffer_en) {
		ret = udma_alloc_reorder_cq_buf(udma_dev, &qp->qp_attr);
		if (ret)
			dev_warn(udma_dev->dev,
				 "failed to alloc reorder cq buffer.\n");
	}

	return 0;

err_put_trrl:
	if (udma_dev->caps.trrl_entry_sz)
		udma_table_put(udma_dev, &qp_table->trrl_table, qp->qpn);
err_put_irrl:
	udma_table_put(udma_dev, &qp_table->irrl_table, qp->qpn);
err_put_qp:
	udma_table_put(udma_dev, &qp_table->qp_table, qp->qpn);
err_out:
	return ret;
}

static void udma_lock_cqs(struct udma_jfc *send_jfc, struct udma_jfc *recv_jfc)
			  __acquires(&send_jfc->lock)
			  __acquires(&recv_jfc->lock)
{
	if (unlikely(send_jfc == NULL && recv_jfc == NULL)) {
		__acquire(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (unlikely(send_jfc != NULL && recv_jfc == NULL)) {
		spin_lock_irq(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (unlikely(send_jfc == NULL && recv_jfc != NULL)) {
		spin_lock_irq(&recv_jfc->lock);
		__acquire(&send_jfc->lock);
	} else if (send_jfc == recv_jfc) {
		spin_lock_irq(&send_jfc->lock);
		__acquire(&recv_jfc->lock);
	} else if (send_jfc->cqn < recv_jfc->cqn) {
		spin_lock_irq(&send_jfc->lock);
		spin_lock_nested(&recv_jfc->lock, SINGLE_DEPTH_NESTING);
	} else {
		spin_lock_irq(&recv_jfc->lock);
		spin_lock_nested(&send_jfc->lock, SINGLE_DEPTH_NESTING);
	}
}

static void udma_unlock_cqs(struct udma_jfc *send_jfc,
			    struct udma_jfc *recv_jfc)
			__releases(&send_jfc->lock)
			__releases(&recv_jfc->lock)
{
	if (unlikely(send_jfc == NULL && recv_jfc == NULL)) {
		__release(&recv_jfc->lock);
		__release(&send_jfc->lock);
	} else if (unlikely(send_jfc != NULL && recv_jfc == NULL)) {
		__release(&recv_jfc->lock);
		spin_unlock(&send_jfc->lock);
	} else if (unlikely(send_jfc == NULL && recv_jfc != NULL)) {
		__release(&send_jfc->lock);
		spin_unlock(&recv_jfc->lock);
	} else if (send_jfc == recv_jfc) {
		__release(&recv_jfc->lock);
		spin_unlock_irq(&send_jfc->lock);
	} else if (send_jfc->cqn < recv_jfc->cqn) {
		spin_unlock(&recv_jfc->lock);
		spin_unlock_irq(&send_jfc->lock);
	} else {
		spin_unlock(&send_jfc->lock);
		spin_unlock_irq(&recv_jfc->lock);
	}
}

void copy_send_jfc(struct udma_qp *from_qp, struct udma_qp *to_qp)
{
	to_qp->qp_attr.send_jfc = from_qp->qp_attr.send_jfc;
	udma_lock_cqs(to_qp->qp_attr.send_jfc, NULL);
	list_add_tail(&to_qp->sq_node, &to_qp->qp_attr.send_jfc->sq_list);
	udma_unlock_cqs(to_qp->qp_attr.send_jfc, NULL);
}

static void add_qp_to_list(struct udma_dev *udma_dev, struct udma_qp *qp,
			   struct udma_jfc *send_jfc, struct udma_jfc *recv_jfc)
{
	unsigned long flags;

	spin_lock_irqsave(&udma_dev->qp_list_lock, flags);
	udma_lock_cqs(send_jfc, recv_jfc);

	list_add_tail(&qp->node, &udma_dev->qp_list);

	if (send_jfc)
		list_add_tail(&qp->sq_node, &send_jfc->sq_list);
	if (recv_jfc)
		list_add_tail(&qp->rq_node, &recv_jfc->rq_list);

	udma_unlock_cqs(send_jfc, recv_jfc);
	spin_unlock_irqrestore(&udma_dev->qp_list_lock, flags);
}

static int udma_qp_store(struct udma_dev *udma_dev,
			 struct udma_qp *qp)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct xarray *xa = &udma_dev->qp_table.xa;
	struct udma_qp *temp_qp;
	unsigned long flags;
	int ret = 0;

	xa_lock_irqsave(xa, flags);
	temp_qp = (struct udma_qp *)xa_load(xa, qp->qpn);
	if (!temp_qp)
		ret = xa_err(__xa_store(xa, qp->qpn, qp, GFP_KERNEL));
	xa_unlock_irqrestore(xa, flags);
	if (ret)
		dev_err(udma_dev->dev, "Failed to xa store for QPC\n");
	else
		/* add QP to device's QP list for softwc */
		add_qp_to_list(udma_dev, qp, qp_attr->send_jfc,
			       qp_attr->recv_jfc);

	return ret;
}

static void udma_qp_remove(struct udma_dev *udma_dev, struct udma_qp *qp,
			   struct ubcore_tp *fail_ret_tp)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct xarray *xa = &udma_dev->qp_table.xa;
	struct udma_jfc *send_jfc;
	struct udma_jfc *recv_jfc;
	unsigned long flags;

	send_jfc = qp_attr->send_jfc;
	recv_jfc = qp_attr->recv_jfc;

	xa_lock_irqsave(xa, flags);
	if (!fail_ret_tp)
		__xa_erase(xa, qp->qpn);
	xa_unlock_irqrestore(xa, flags);

	spin_lock_irqsave(&udma_dev->qp_list_lock, flags);
	udma_lock_cqs(send_jfc, recv_jfc);

	list_del(&qp->node);

	if (send_jfc)
		list_del(&qp->sq_node);
	if (recv_jfc)
		list_del(&qp->rq_node);

	udma_unlock_cqs(send_jfc, recv_jfc);
	spin_unlock_irqrestore(&udma_dev->qp_list_lock, flags);
}

static void free_qpc(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_table *qp_table = &udma_dev->qp_table;

	if (udma_dev->caps.reorder_cq_buffer_en)
		udma_free_reorder_cq_buf(udma_dev, &qp->qp_attr);

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		udma_table_put(udma_dev, &qp_table->sccc_table, qp->qpn);
		if (qp->dip_idx != qp->qpn && qp->dip_idx >= 0)
			udma_table_put(udma_dev, &qp_table->sccc_table,
				       qp->dip_idx);
	}

	if (udma_dev->caps.trrl_entry_sz)
		udma_table_put(udma_dev, &qp_table->trrl_table, qp->qpn);

	udma_table_put(udma_dev, &qp_table->irrl_table, qp->qpn);
}

static void free_qp_db(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	if ((is_rc_jetty(&qp->qp_attr) &&
	    !(qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)) ||
	    qp->no_free_wqe_buf)
		return;

	if (qp->en_flags & UDMA_QP_CAP_SQ_RECORD_DB)
		udma_db_unmap_user(udma_dev, &qp->sdb);
}

static void free_wqe_buf(struct udma_dev *dev, struct udma_qp *qp)
{
	if ((is_rc_jetty(&qp->qp_attr) &&
	    !(qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)) ||
	    qp->no_free_wqe_buf)
		return;

	udma_mtr_destroy(dev, &qp->mtr);
	if (qp->en_flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_disable_dca(dev, qp);
}

static void free_qp_wqe(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	free_wqe_buf(udma_dev, qp);
}

bool udma_qp_need_alloc_sq(struct udma_qp_attr *qp_attr)
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

static uint32_t udma_get_jetty_qpn(struct udma_qp *qp)
{
	struct udma_jetty *jetty = qp->qp_attr.jetty;
	uint32_t qpn = qp->qpn;

	if (jetty->tp_mode == UBCORE_TP_RC && jetty->rc_node.tp != NULL)
		qpn = jetty->rc_node.tpn;

	return qpn;
}

static int udma_alloc_qp_sq(struct udma_dev *udma_dev, struct udma_qp *qp,
			    struct ubcore_udata *udata,
			    struct udma_create_tp_ucmd *ucmd)
{
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	int ret = 0;

	if (is_rc_jetty(qp_attr)) {
		qp->sdb = qp_attr->jetty->rc_node.sdb;
		qp->en_flags |= UDMA_QP_CAP_SQ_RECORD_DB;
		if (!qp_attr->jetty->shared_jfr && !qp_attr->jetty->dca_en)
			qp->en_flags |= UDMA_QP_CAP_RQ_RECORD_DB;
		qp->dca_ctx = &qp_attr->jetty->rc_node.context->dca_ctx;
		if (qp_attr->jetty->rc_node.buf_addr) {
			qp->mtr = qp_attr->jetty->rc_node.mtr;
			if ((PAGE_SIZE <= UDMA_DWQE_SIZE) &&
			    (udma_dev->caps.flags & UDMA_CAP_FLAG_DIRECT_WQE))
				qp->en_flags |= UDMA_QP_CAP_DIRECT_WQE;
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

int udma_init_qpc(struct udma_dev *udma_dev, struct udma_qp *qp)
{
	struct udma_qp_context ctx[2] = {};
	int ret;

	ret = udma_pass_qpc_to_hw(udma_dev, ctx, ctx + 1, qp);
	if (ret)
		dev_err(udma_dev->dev, "failed to init QPC to HW, ret = %d.\n", ret);

	return ret;
}

int udma_create_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp,
			  struct ubcore_udata *udata)
{
	struct udma_ucontext *uctx = to_udma_ucontext(udata->uctx);
	struct udma_qp_attr *qp_attr = &qp->qp_attr;
	struct udma_create_tp_resp resp = {};
	struct device *dev = udma_dev->dev;
	struct udma_create_tp_ucmd ucmd;
	int ret;

	qp->state = QPS_RESET;
	qp->dip_idx = UDMA_SCC_DIP_INVALID_IDX;
	if (!qp_attr->is_tgt)
		qp->dca_ctx = &uctx->dca_ctx;

	ret = set_qp_param(udma_dev, qp, udata, &ucmd);
	if (ret) {
		dev_err(dev, "failed to set QP param, ret = %d.\n", ret);
		return ret;
	}

	ret = alloc_qpn(udma_dev, qp, !udata->uctx);
	if (ret) {
		dev_err(dev, "failed to alloc QPN, ret = %d.\n", ret);
		goto err_qpn;
	}

	if (!qp->qpn) {
		ret = -EINVAL;
		goto err_qpn;
	}

	if (udma_qp_need_alloc_sq(qp_attr)) {
		ret = udma_alloc_qp_sq(udma_dev, qp, udata, &ucmd);
		if (ret) {
			dev_err(dev, "failed to alloc QP sq, ret = %d.\n", ret);
			goto err_sq;
		}
	}

	ret = alloc_qpc(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to alloc QP context, ret = %d.\n",
			ret);
		goto err_qpc;
	}

	ret = udma_qp_store(udma_dev, qp);
	if (ret) {
		dev_err(dev, "failed to store QP, ret = %d.\n", ret);
		goto err_store;
	}

	if (!qp_attr->is_tgt) {
		resp.cap_flags = qp->en_flags;
		resp.qpn = qp->qpn;
		resp.priority = qp->priority;
		if (qp_attr->is_jetty && qp_attr->jetty)
			resp.qpn = udma_get_jetty_qpn(qp);

		resp.path_mtu = udma_dev->caps.max_mtu;
		resp.um_srcport.um_spray_en = um_spray_en;
		resp.um_srcport.um_data_udp_start = (uint16_t)um_data_udp_start;
		resp.um_srcport.um_udp_range = (uint8_t)um_udp_range +
					       UDP_RANGE_BASE;
		ret = copy_to_user((void *)udata->udrv_data->out_addr, &resp,
				   min(udata->udrv_data->out_len,
				       (uint32_t)sizeof(resp)));
		if (ret) {
			dev_err(dev, "copy qp resp failed!\n");
			goto err_copy;
		}
	}

	refcount_set(&qp->refcount, 1);
	init_completion(&qp->free);

	return 0;

err_copy:
	udma_qp_remove(udma_dev, qp, NULL);
err_store:
	free_qpc(udma_dev, qp);
err_qpc:
	if (udma_qp_need_alloc_sq(&qp->qp_attr) && !is_rc_jetty(qp_attr)) {
		free_qp_db(udma_dev, qp);
		free_qp_wqe(udma_dev, qp);
	}
err_sq:
err_qpn:
	return ret;
}

void udma_destroy_qp_common(struct udma_dev *udma_dev, struct udma_qp *qp,
			    struct ubcore_tp *fail_ret_tp)
{
	udma_qp_remove(udma_dev, qp, fail_ret_tp);

	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);

	free_qpc(udma_dev, qp);
	if (udma_qp_need_alloc_sq(&qp->qp_attr) || qp->force_free_wqe_buf) {
		free_qp_db(udma_dev, qp);
		free_qp_wqe(udma_dev, qp);
	}
}

int udma_init_qp_table(struct udma_dev *dev)
{
	struct udma_qp_table *qp_table = &dev->qp_table;
	uint32_t reserved_from_bot;
	uint32_t i;

	qp_table->idx_table.spare_idx = kcalloc(dev->caps.num_qps,
					sizeof(uint32_t), GFP_KERNEL);
	if (!qp_table->idx_table.spare_idx)
		return -ENOMEM;

	mutex_init(&qp_table->bank_mutex);
	xa_init(&qp_table->xa);

	reserved_from_bot = dev->caps.reserved_qps;

	for (i = 0; i < reserved_from_bot; i++) {
		dev->qp_table.bank[get_qp_bankid(i)].inuse++;
		dev->qp_table.bank[get_qp_bankid(i)].min++;
	}

	for (i = 0; i < UDMA_QP_BANK_NUM; i++) {
		ida_init(&dev->qp_table.bank[i].ida);
		dev->qp_table.bank[i].max = dev->caps.num_qps /
						UDMA_QP_BANK_NUM - 1;
		dev->qp_table.bank[i].next = dev->qp_table.bank[i].min;
	}

	return 0;
}

void udma_cleanup_qp_table(struct udma_dev *dev)
{
	int i;

	for (i = 0; i < UDMA_QP_BANK_NUM; i++)
		ida_destroy(&dev->qp_table.bank[i].ida);
	kfree(dev->qp_table.idx_table.spare_idx);
}

int udma_flush_cqe(struct udma_dev *udma_dev, struct udma_qp *udma_qp,
		   uint32_t sq_pi)
{
	struct udma_qp_context *qp_context;
	struct udma_cmd_mailbox *mailbox;
	struct udma_qp_context *qpc_mask;
	struct udma_cmq_desc desc;
	struct udma_mbox *mb;
	int ret;

	udma_qp->state = QPS_ERR;

	mailbox = udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);
	qp_context = (struct udma_qp_context *)mailbox->buf;
	qpc_mask = (struct udma_qp_context *)mailbox->buf + 1;
	memset(qpc_mask, 0xff, sizeof(struct udma_qp_context));

	udma_reg_write(qp_context, QPC_QP_ST, udma_qp->state);
	udma_reg_clear(qpc_mask, QPC_QP_ST);

	udma_reg_write(qp_context, QPC_SQ_PRODUCER_IDX, sq_pi);
	udma_reg_clear(qpc_mask, QPC_SQ_PRODUCER_IDX);

	mb = (struct udma_mbox *)desc.data;
	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, udma_qp->qpn, UDMA_CMD_MODIFY_QPC);

	ret = udma_cmd_mbox(udma_dev, &desc, UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(udma_dev->dev, "flush cqe qp(0x%llx) cmd error(%d).\n",
			udma_qp->qpn, ret);

	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

void udma_qp_event(struct udma_dev *udma_dev, uint32_t qpn, int event_type)
{
	struct device *dev = udma_dev->dev;
	struct udma_qp *qp;

	xa_lock(&udma_dev->qp_table.xa);
	qp = (struct udma_qp *)xa_load(&udma_dev->qp_table.xa, qpn);
	if (qp)
		refcount_inc(&qp->refcount);
	xa_unlock(&udma_dev->qp_table.xa);

	if (!qp) {
		dev_warn(dev, "Async event for bogus QP 0x%08x\n", qpn);
		return;
	}

	if (event_type == UDMA_EVENT_TYPE_JFR_LAST_WQE_REACH ||
	    event_type == UDMA_EVENT_TYPE_WQ_CATAS_ERROR ||
	    event_type == UDMA_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR ||
	    event_type == UDMA_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR) {
		qp->state = QPS_ERR;

		if (qp->sdb.virt_addr)
			qp->sq.head = *(int *)(qp->sdb.virt_addr);

		udma_flush_cqe(udma_dev, qp, qp->sq.head);
	}

	if (qp->event)
		qp->event(qp, (enum udma_event)event_type);

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
