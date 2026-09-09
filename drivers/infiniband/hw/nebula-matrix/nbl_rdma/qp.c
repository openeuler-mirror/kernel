// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/crc32.h>
#include <rdma/nbl-abi.h>
#include <rdma/ib_addr.h>
#include "qp.h"
#include "main.h"
#include "defs.h"
#include "pd.h"
#include "mem.h"
#include "cqp.h"
#include "ah.h"
#include "alloc.h"
#include "debug.h"
#include "grc.h"
#include "dbgfs.h"
#include "counters.h"
#include "dump_fields.h"
#include "gid.h"

/* cc rate:Mbps rtt:us */
/* TODO: The configuration method needs to be considered */
#define RNIC_RTT  20
#define BITS_PER_BLOCK  512
#define QCN_RP_LIMIT_RATE_PERIOD 128
#define QCN_RP_LIMIT_RATE_PERIOD_FACTOR 100

/* increase rto to avoid retry timeout when bond slave failover */
static int rto_arry[NBL_RTO_ARRY_MAX_SIZE] = {
	4,  4,	4,  4,	4,  4,	4,  4,	4,  4,	4,  6,	8,  9,	12, 12,
	13, 13, 14, 15, 16, 17, 18, 19, 20, 25, 25, 25, 25, 25, 25, 25,
};

static void nbl_flush_wqe_worker(struct work_struct *work)
{
	struct flush_work *fwork = container_of(work, struct flush_work, work);
	struct nbl_qp *qp = fwork->qp;
	struct ib_event ib_event;
	unsigned long flags;

	kfree(fwork);

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->flush_issued || qp->sc_qp.uk_qp.destroy_pending) {
		nbl_qp_rem_ref(&qp->ibqp);
		spin_unlock_irqrestore(&qp->lock, flags);
		return;
	}

	spin_unlock_irqrestore(&qp->lock, flags);

	nbl_modify_qp_to_err(qp);

	if (qp->ibqp.event_handler) {
		ib_event.event = IB_EVENT_QP_FATAL;
		ib_event.device = qp->ibqp.device;
		ib_event.element.qp = &qp->ibqp;
		qp->ibqp.event_handler(&ib_event, qp->ibqp.qp_context);
	}
	nbl_qp_rem_ref(&qp->ibqp);
}

void nbl_flush_work(struct nbl_qp *qp)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct flush_work *fwork;
	unsigned long flags;

	spin_lock_irqsave(&nbldev->rf->qptable_lock, flags);
	if (!nbldev->rf->qp_table[qp->ibqp.qp_num]) {
		spin_unlock_irqrestore(&nbldev->rf->qptable_lock, flags);
		nbl_ib_err(&nbldev->rf->sc_dev, "qp_num %d is already freed\n",
			   qp->ibqp.qp_num);
		return;
	}

	fwork = kzalloc(sizeof(*fwork), GFP_ATOMIC);
	if (!fwork) {
		spin_unlock_irqrestore(&nbldev->rf->qptable_lock, flags);
		return;
	}

	nbl_qp_add_ref(qp);
	spin_unlock_irqrestore(&nbldev->rf->qptable_lock, flags);
	fwork->qp = qp;
	INIT_WORK(&fwork->work, nbl_flush_wqe_worker);
	queue_work(nbldev->rf->flush_wq, &fwork->work);
}


static inline enum ib_mtu nbl_mtu_to_ib(enum nbl_mtu mtu)
{
	if (mtu < NBL_MTU_256 || mtu > NBL_MTU_4096) {
		nbl_pr_err("invalid nbl mtu\n");
		return IB_MTU_INVALID_NBL;
	}
	return mtu + 1;
}

static inline enum nbl_mtu ib_mtu_to_nbl(enum ib_mtu mtu)
{
	if (mtu < IB_MTU_256 || mtu > IB_MTU_4096) {
		nbl_pr_err("invalid ib mtu\n");
		return NBL_MTU_INVALID;
	}
	return mtu - 1;
}

static int nbl_cqp_flush_wqe_cmd(struct nbl_qp *qp)
{
	int ret = 0;
	__be64 *in;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0,
				FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_QP_FLUSH_WQE) |
				FIELD_PREP(NBL_CQP_QP_SQEN, true) |
				FIELD_PREP(NBL_CQP_QP_RQEN, true));
	set_64bit_val(in, 8,
				FIELD_PREP(NBL_CQP_OP_HOST_ID, host_id) |
				FIELD_PREP(NBL_CQP_OP_VF_ID, rf->sc_dev.function_id) |
				FIELD_PREP(NBL_CQP_OP_FLUSH_QPN, qp->sc_qp.uk_qp.qpn));

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	kfree(in);
	return ret;
}

/** nbl_flush_operation - flush operation will continux even meet error.
 * @qp: qp struct
 * @nbldev: nbl device struct
 */
static void nbl_flush_operation(struct nbl_qp *qp, struct nbl_device *nbldev)
{
	struct nbl_pci_f *rf = nbldev->rf;
	unsigned long qp_leave_time;
	unsigned long timeout = msecs_to_jiffies(FLUSH_TIME_OUT);
	int ret;

	ret = nbl_cqp_flush_wqe_cmd(qp);
	if (ret)
		nbl_pr_err("flush wqe cqp err, QPN %u, cmd return:%d\n",
			qp->sc_qp.uk_qp.qpn, ret);
	else if (!rf->sc_dev.has_high_temp_alarm) {
		qp_leave_time =
			wait_for_completion_timeout(&qp->flush_qp, timeout);
		if (unlikely(!qp_leave_time))
			nbl_pr_err("wait for flush_qp timeout(vfid 0x%x, QPN %u)\n",
				rf->sc_dev.function_id, qp->sc_qp.uk_qp.qpn);
	}

	/* flush cache */
	ret = nbl_cqp_flush_s1_cache_cmd(qp);
	if (ret)
		nbl_pr_err("flush s1 cache cqp err, QPN %u, cmd return:%d\n",
			qp->sc_qp.uk_qp.qpn, ret);

#if NBL_DIRECT_WQE_EN
	ret = nbl_cqp_flush_sqrq_cache_cmd(qp);
	if (ret)
		nbl_pr_err("flush sqrq cache cqp failed, QPN %u, cmd return:%d\n",
			qp->sc_qp.uk_qp.qpn, ret);
#endif

	/* Rechk BD not flush, TQP may visit SQ wqe, can lead access violation.
	 * If need, sleep here.
	 */
}

static int nbl_get_qpc_base_addr(u32 qp_num,
				 struct nbl_ctx_hmc_base_info *hmc_info,
				 struct nbl_hmc_obj_sd_info *qp_sd_info)
{
	u32 num_one_page; /* how many qpc in one page */
	u32 page_index; /* page index that qpc located */
	struct nbl_hmc_obj_sd_addr *sd;

	/* for 4K, here we got 8 */
	num_one_page = qp_sd_info->page_sz / NBL_QP_CTX_SIZE;

	/* get page index, for qpn=17 we got 2 */
	page_index = qp_num / num_one_page;
	if (page_index >= qp_sd_info->cnt) {
		nbl_pr_err("invalid page_index, the page_index is %u.\n",
			   page_index);
		return -EFAULT;
	}

	sd = &qp_sd_info->sd_addr[page_index];

	hmc_info->va = sd->va;
	hmc_info->pa = sd->dma_addr;
	hmc_info->ctx_size = NBL_QP_CTX_SIZE;
	hmc_info->shadow_offset = NBL_QP_SHADOW_OFFST;
	hmc_info->shadow_size = NBL_QP_SHADOW_SIZE;
	hmc_info->page_size = qp_sd_info->page_sz;

	return 0;
}

static int nbl_user_qp_shadow(struct nbl_qp *qp,
			      struct nbl_ib_create_qp_resp *uresp,
			      struct nbl_hmc_obj_sd_info *qp_sd_info)
{
	struct nbl_ctx_hmc_base_info hmc_info;
	struct nbl_pd *nblpd = qp->nblpd;
	int ret;
	int num_one_page;
	int qpc_idx;
	struct shadow_node *qpc_shadow = NULL;
	u32 map_size;

	num_one_page = qp_sd_info->page_sz / NBL_QP_CTX_SIZE;
	qpc_idx = qp->ibqp.qp_num % num_one_page;

	ret = nbl_get_qpc_base_addr(qp->ibqp.qp_num, &hmc_info, qp_sd_info);
	if (ret) {
		nbl_pr_err("get nbl qpc base addr failed.\n");
		return ret;
	}

	uresp->shadow_base_addr = hmc_info.pa & PAGE_MASK;
	uresp->sys_page_offset = hmc_info.pa & (PAGE_SIZE - 1);
	uresp->qpc_size = hmc_info.ctx_size;
	uresp->shadow_offset = hmc_info.shadow_offset;
	uresp->shadow_size = hmc_info.shadow_size;
	uresp->page_size = hmc_info.page_size;

	qp->sc_qp.qp_shadow.va =
		hmc_info.va + (qpc_idx * NBL_QP_CTX_SIZE) + NBL_QP_SHADOW_OFFST;
	qp->sc_qp.qp_shadow.pa =
		hmc_info.pa + (qpc_idx * NBL_QP_CTX_SIZE) + NBL_QP_SHADOW_OFFST;
	qp->sc_qp.qp_shadow.size = NBL_QP_SHADOW_SIZE;

	map_size = uresp->page_size <= PAGE_SIZE ? PAGE_SIZE : uresp->page_size;
	nbl_pr_dbg("qp hmc_info.pa=0x%llx,shadow_base_addr=0x%llx,sys_page_offset=0x%llx\n",
		   hmc_info.pa, uresp->shadow_base_addr, uresp->sys_page_offset);
	qpc_shadow = nbl_find_shadow_mmap(nblpd->uctx, uresp->shadow_base_addr, map_size);
	if (!qpc_shadow) {
		nbl_pr_dbg(
			"not find valid shadow node, and start to add new shadow node.\n");
		return nbl_add_shadow_mmap(nblpd->uctx, hmc_info.va, uresp->shadow_base_addr,
					   map_size);
	}

	return 0;
}

static int nbl_kernel_qp_shadow(struct nbl_qp *qp,
				struct nbl_hmc_obj_sd_info *qp_sd_info)
{
	struct nbl_ctx_hmc_base_info hmc_info;
	u32 num_one_page; /* how many qpc in one page */
	u32 qpc_index; /* qpc index in a page */
	int ret;

	num_one_page = qp_sd_info->page_sz / NBL_QP_CTX_SIZE;
	qpc_index = qp->ibqp.qp_num % num_one_page;

	ret = nbl_get_qpc_base_addr(qp->ibqp.qp_num, &hmc_info, qp_sd_info);
	if (ret) {
		nbl_pr_err("get nbl qpc base addr failed.\n");
		return ret;
	}
	qp->sc_qp.qp_shadow.va =
		hmc_info.va + (qpc_index * NBL_QP_CTX_SIZE) + NBL_QP_SHADOW_OFFST;
	qp->sc_qp.qp_shadow.pa = hmc_info.pa + (qpc_index * NBL_QP_CTX_SIZE) +
				 NBL_QP_SHADOW_OFFST;
	qp->sc_qp.qp_shadow.size = NBL_QP_SHADOW_SIZE;

	return 0;
}

void nbl_set_qp_ctx(struct nbl_qp *qp, __be64 *qp_ctx)
{
	struct nbl_qp_ctx *ctx_info;
	u64 temp = 0;
	u8 *ptr = (u8 *)qp_ctx;

	ctx_info = &qp->ctx_info;
	temp = FIELD_PREP(NBL_QPC_P_KEY, ctx_info->p_key) |
	       FIELD_PREP(NBL_QPC_QPN, ctx_info->qpn) |
	       FIELD_PREP(NBL_QPC_VFID, ctx_info->vfid) |
	       FIELD_PREP(NBL_QPC_HOST_ID, ctx_info->host_id) |
	       FIELD_PREP(NBL_QPC_STAT_ID, ctx_info->stat_id) |
	       FIELD_PREP(NBL_QPC_TVER, ctx_info->tver) |
	       FIELD_PREP(NBL_QPC_MIG, ctx_info->mig);
	set_64bit_val(qp_ctx, 0, temp);

	temp = FIELD_PREP(NBL_QPC_IRQ_BA, ctx_info->irq_ba) |
	       FIELD_PREP(NBL_QPC_QP_STATE, ctx_info->qp_st) |
	       FIELD_PREP(NBL_QPC_PMTU, ctx_info->pmtu) |
	       FIELD_PREP(NBL_QPC_SERVICE_TYPE, ctx_info->service_type);
	set_64bit_val(qp_ctx, 8, temp);

	temp = FIELD_PREP(NBL_QPC_LOCAL_RNR_TIMER_VALUE,
			  ctx_info->local_rnr_timer_value) |
	       FIELD_PREP(NBL_QPC_RQ_PM, ctx_info->rq_pm) |
	       FIELD_PREP(NBL_QPC_SQ_PM, ctx_info->sq_pm) |
	       FIELD_PREP(NBL_QPC_DMA_LEN_MAX, ctx_info->dma_len_max) |
	       FIELD_PREP(NBL_QPC_RQ_WQE_SIZE, ctx_info->rq_wqe_size) |
	       FIELD_PREP(NBL_QPC_RQ_SIZE, ctx_info->rq_size) |
	       FIELD_PREP(NBL_QPC_PD_IDX, ctx_info->pd_idx) |
	       FIELD_PREP(NBL_QPC_SCH_NET_TC, ctx_info->sch_net_tc) |
	       FIELD_PREP(NBL_QPC_SPORT_ID, ctx_info->sport_id) |
	       FIELD_PREP(NBL_QPC_CREDIT_EN, true) |
	       FIELD_PREP(NBL_QPC_CC_PKT_NUM_EN, ctx_info->cc_pkt_num_en) |
	       FIELD_PREP(NBL_QPC_QP1_MODE, ctx_info->qp1_mode) |
	       FIELD_PREP(NBL_QPC_ATOMIC_EN, qp->sc_qp.uk_qp.qp_caps & NBL_ATOMIC);
	set_64bit_val(qp_ctx, 16, temp);

	temp = FIELD_PREP(NBL_QPC_SWRQPI_TH, ctx_info->swrqpi_th) |
		FIELD_PREP(NBL_QPC_CC_MODE, ctx_info->cc_mode) |
		FIELD_PREP(NBL_QPC_ATOMIC_NO_FENCE, false) |
		FIELD_PREP(NBL_QPC_WQE_PREFETCH_EN, ctx_info->wqe_prefetch_en) |
		FIELD_PREP(NBL_QPC_WQE_CAP, ctx_info->default_wqe_cap) |
		FIELD_PREP(NBL_QPC_ORQ_BA, ctx_info->orq_ba);
	set_64bit_val(qp_ctx, 24, temp);

	temp = FIELD_PREP(NBL_QPC_RQ_PD_BA_H, (ctx_info->rq_pd_ba >> NBL_ADAPTER_PAGE_SHIFT)) |
		FIELD_PREP(NBL_QPC_VLAN_TAG, ctx_info->vlan_tag) |
		FIELD_PREP(NBL_QPC_DFT_RAQE_CAP, NBL_DEFAULT_RAQ_WQE_CAP);
	set_64bit_val(qp_ctx, 32, temp);

	temp = FIELD_PREP(NBL_QPC_RQ_PD_BA_L, (ctx_info->rq_pd_ba & 0xFFF)) |
			FIELD_PREP(NBL_QPC_CC_TARGETWIN_MIN, ctx_info->cc_targetwin_min) |
			FIELD_PREP(NBL_QPC_UD_QKEY, ctx_info->ud_qkey);

	set_64bit_val(qp_ctx, 40, temp);

	temp = FIELD_PREP(NBL_QPC_CC_OAM_ACK_NET_TC, ctx_info->cc_oamack_net_tc) |
			FIELD_PREP(NBL_QPC_CC_OAM_ACK_TC_EN, ctx_info->cc_oamack_tc_en) |
			FIELD_PREP(NBL_QPC_CC_SENDACK_BLK_CNT_TH, ctx_info->cc_oamack_blk_th) |
			FIELD_PREP(NBL_QPC_CC_RTTMINTH_ADD_MULT, ctx_info->cc_rtt_qp_mult) |
			FIELD_PREP(NBL_QPC_RTO_TIMER_VALUE, ctx_info->rto_timer_value) |
			FIELD_PREP(NBL_QPC_FRMR_EN, ctx_info->txmr_frmr_en) |
			FIELD_PREP(NBL_QPC_DEST_QPN, ctx_info->dest_qpn) |
			FIELD_PREP(NBL_QPC_TX_RETRY_TH, ctx_info->tx_retry_th) |
			FIELD_PREP(NBL_QPC_IRQ_SIZE, ctx_info->irq_size) |
		FIELD_PREP(NBL_QPC_SQ_SIZE, ctx_info->sq_size);
	set_64bit_val(qp_ctx, 48, temp);

	temp = FIELD_PREP(NBL_QPC_SQ_PD_BA, ctx_info->sq_pd_ba) |
	       FIELD_PREP(NBL_QPC_ACKREQ_TH, ctx_info->ackreq_th) |
	       FIELD_PREP(NBL_QPC_OAM_REQ_NET_TC, ctx_info->cc_oamreq_net_tc) |
	       FIELD_PREP(NBL_QPC_OAM_REQ_TC_EN, ctx_info->cc_oamreq_tc_en);
	set_64bit_val(qp_ctx, 56, temp);

	temp = FIELD_PREP(NBL_QPC_UDP_SPORT, ctx_info->udp_sport) |
	       FIELD_PREP(NBL_QPC_FLOW_LABLE, ctx_info->flow_label) |
	       FIELD_PREP(NBL_QPC_SRC_ADDR_IDX, ctx_info->src_addr_idx) |
	       FIELD_PREP(NBL_QPC_VLAN, ctx_info->vlan_en) |
	       FIELD_PREP(NBL_QPC_IPV4, ctx_info->ipv4) |
	       FIELD_PREP(NBL_QPC_DPORT_ID, ctx_info->dport_id) |
	       FIELD_PREP(NBL_QPC_DPORT, ctx_info->dport) |
	       FIELD_PREP(NBL_QPC_FWD, ctx_info->fwd) |
	       FIELD_PREP(NBL_QPC_RSS_LAG_EN, ctx_info->rss_lag_en);
	set_64bit_val(qp_ctx, 64, temp);

	temp = FIELD_PREP(NBL_QPC_HOP_LIMIT, ctx_info->hop_limit) |
	       FIELD_PREP(NBL_QPC_TCLASS, ctx_info->tclass) |
	       FIELD_PREP(NBL_QPC_DMAC, ether_addr_to_u64(ctx_info->dest_mac));
	set_64bit_val(qp_ctx, 72, temp);

	/* RAM0 80-95 DST IP */
	memcpy(&ptr[80], ctx_info->dest_ip, NBL_QPC_DSIP_TOTAL_LEN);

	temp = FIELD_PREP(NBL_QPC_UNAQ_BA, ctx_info->unaq_ba);
	set_64bit_val(qp_ctx, 96, temp);

	temp = FIELD_PREP(NBL_QPC_SHADOW_AREA_BA, ctx_info->shadow_area_ba) |
	       FIELD_PREP(NBL_QPC_SQ_CE_EN, ctx_info->sq_ce_en);
	set_64bit_val(qp_ctx, 104, temp);

	temp = FIELD_PREP(NBL_QPC_SQ_CQN, ctx_info->sq_cqn) |
	       FIELD_PREP(NBL_QPC_RQ_CQN, ctx_info->rq_cqn) |
	       FIELD_PREP(NBL_QPC_CEAQ_RQ_TH, ctx_info->ceaq_rq_th) |
	       FIELD_PREP(NBL_QPC_CEAQ_SQ_TH, ctx_info->ceaq_sq_th);
	set_64bit_val(qp_ctx, 112, temp);

	temp = FIELD_PREP(NBL_QPC_QP_COMP_CTX, ctx_info->qp_completion_ctx);
	set_64bit_val(qp_ctx, 120, temp);

	temp = FIELD_PREP(NBL_QPC_QCN_REMAIN_TRANS_BITS,
		ctx_info->qcn_remain_trans_bits);
	set_64bit_val(qp_ctx, 128, temp);

	temp = FIELD_PREP(NBL_QPC_QCN_SENDPKT_TARGETWIN,
		ctx_info->qcn_sendpkt_tarwin);
	set_64bit_val(qp_ctx, 136, temp);

	temp = FIELD_PREP(NBL_QPC_QCN_FIRST_RECDB_FLAG,
		ctx_info->qcn_first_recdb_flag);
	set_64bit_val(qp_ctx, 144, temp);

	temp = FIELD_PREP(NBL_QPC_QCN_LIMIT_RP, ctx_info->qcn_limit_rp) |
		FIELD_PREP(NBL_QPC_QCN_TARGET_RP, ctx_info->qcn_target_rp) |
		FIELD_PREP(NBL_QPC_QCN_MAIN_STATUS, ctx_info->qcn_main_status);
	set_64bit_val(qp_ctx, 152, temp);

	temp = FIELD_PREP(NBL_QPC_SQ_NEXT_WQE_CAP, NBL_DEFAULT_WQE_CAP);
	set_64bit_val(qp_ctx, 160, temp);
	temp = FIELD_PREP(NBL_QPC_RAQ_NEXT_WQE_CAP, NBL_DEFAULT_RAQ_WQE_CAP);
	set_64bit_val(qp_ctx, 168, temp);
	temp = FIELD_PREP(NBL_QPC_RETRY_CNT, ctx_info->tx_retry_th);
	set_64bit_val(qp_ctx, 192, temp);

	temp = FIELD_PREP(NBL_QPC_RAQ_BA, ctx_info->raq_ba);
	set_64bit_val(qp_ctx, 248, temp);

	temp = FIELD_PREP(NBL_QPC_RXP_REQ_PRE_OPCODE,
			  NBL_DEFAULT_RXP_REQ_PRE_OPCODE) |
	       FIELD_PREP(NBL_QPC_RXP_EPSN, ctx_info->rq_psn);
	set_64bit_val(qp_ctx, 256, temp);

	temp = FIELD_PREP(NBL_QPC_RX_RESP_PRE_OPCODE,
			  NBL_DEFAULT_RX_RESP_PRE_OPCODE);
	set_64bit_val(qp_ctx, 320, temp);

	temp = FIELD_PREP(NBL_QPC_IRQ_BA_CLONE, ctx_info->irq_ba);
	set_64bit_val(qp_ctx, 336, temp);

	temp = FIELD_PREP(NBL_QPC_RNR_RETRY_NUM, ctx_info->rnr_retry) |
	       FIELD_PREP(NBL_QPC_RNR_RETRY_TH, ctx_info->rnr_retry);
	set_64bit_val(qp_ctx, 392, temp);

	temp = FIELD_PREP(NBL_QPC_CC_TARGETWIN, ctx_info->targetwin);
	set_64bit_val(qp_ctx, 408, temp);

	temp = FIELD_PREP(NBL_QPC_SEQ_NUM, ctx_info->seq_num);
	set_64bit_val(qp_ctx, 456, temp);

	temp = FIELD_PREP(NBL_QPC_RXP_RQ_NXT_PD_PA_H,
			  ctx_info->rxp_rq_nxt_pd_pa_h) |
	       FIELD_PREP(NBL_QPC_RXP_RQ_NXT_PD_PA_VLD, true) |
	       FIELD_PREP(NBL_QPC_PSN_MAX, ctx_info->psn_max);
	set_64bit_val(qp_ctx, 416, temp);

	temp = FIELD_PREP(NBL_QPC_RXP_RQ_NXT_PD_PA_L,
			  ctx_info->rxp_rq_nxt_pd_pa_l) |
	       FIELD_PREP(NBL_QPC_RXP_RQ_CUR_PD_PA_VLD, true) |
	       FIELD_PREP(NBL_QPC_RXP_RQ_CUR_PD_PA_H,
			  ctx_info->rxp_rq_cur_pd_pa_h);
	set_64bit_val(qp_ctx, 424, temp);

	temp = FIELD_PREP(NBL_QPC_RXP_RQ_CUR_PD_PA_L,
			  ctx_info->rxp_rq_cur_pd_pa_l) |
	       FIELD_PREP(NBL_QPC_TXP_SQ_NXT_PD_PA,
			  ctx_info->txp_sq_nxt_pd_pa) |
	       FIELD_PREP(NBL_QPC_TXP_SQ_NXT_PD_PA_VLD, true);
	set_64bit_val(qp_ctx, 432, temp);

	temp = FIELD_PREP(NBL_QPC_TXP_SQ_CUR_PD_PA,
			  ctx_info->txp_sq_cur_pd_pa) |
	       FIELD_PREP(NBL_QPC_TXP_SQ_CUR_PD_PA_VLD, true);
	set_64bit_val(qp_ctx, 440, temp);

	temp = FIELD_PREP(NBL_FMR_NOFENCE_EN, ctx_info->fmr_nofence);
	set_64bit_val(qp_ctx, 472, temp);
}

static int nbl_copy_data_to_user(struct nbl_pci_f *rf, struct nbl_uk_qp *uk_qp,
					struct nbl_ib_create_qp_resp *resp, struct ib_udata *udata)
{
	int state;
	struct nbl_ucontext *uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext,
					 ibucontext);

	resp->sq_size = uk_qp->sq_size;
	resp->rq_size = uk_qp->rq_size;
	resp->qp_id = uk_qp->qpn;
	resp->qp_caps = uk_qp->qp_caps;
	resp->seq_num = uk_qp->seq_num;
	resp->fwd = rf->sc_dev.fwd;
	resp->dport = rf->sc_dev.dport;
	resp->dport_id = rf->sc_dev.dport_id;
	resp->rss_lag_en = rf->sc_dev.rss_lag_en;
	resp->tunnel_en = rf->sc_dev.tunnel_en;
	if (rf->sc_dev.dwqe_en && uctx->is_lat_process)
		resp->dwqe_en = true;
	else
		resp->dwqe_en = false;
	resp->batch_wqe_th = rf->sc_dev.batch_wqe_th;
	resp->tc2pri = rf->sc_dev.tc2pri;
	resp->qp_dump_flag = rf->sc_dev.dev_dump_flag;
	state = ib_copy_to_udata(udata, resp,
				min(sizeof(*resp), udata->outlen));
	return state;
}

static int nbl_init_qp_ref(struct nbl_qp *qp)
{
	int state = 0;

	state = nbl_add_cqc_ref(qp->scq);
	if (state)
		return -EINVAL;

	state = nbl_add_cqc_ref(qp->rcq);
	if (state)
		goto dec_scq_cqc_num;

	state = nbl_cqp_create_qp_cmd(qp);
	if (state)
		goto dec_rcq_cqc_num;

	qp->nbldev->rf->qp_table[qp->sc_qp.uk_qp.qpn] = qp;
	refcount_set(&qp->refcnt, 1);
	refcount_set(&qp->flush_cnt, NBL_QP_FLUSH_AE_EXP_NUM);

	init_completion(&qp->free_qp);
	init_completion(&qp->flush_qp);
	mutex_init(&qp->qp_err_mutex);
	spin_lock_init(&qp->lock);
	return 0;

dec_rcq_cqc_num:
	nbl_dec_cqc_ref(qp->rcq);
dec_scq_cqc_num:
	nbl_dec_cqc_ref(qp->scq);
	return state;
}

static int nbl_process_qp_2m_buffer(struct nbl_device *nbldev, struct nbl_qp *qp,
			__u32 sq_size, __u32 rq_size, struct nbl_create_qp_req *req,
			struct ib_udata *udata)
{
	bool sq_continue = 0;
	bool rq_continue = 0;
	int state = 0;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	/* alloc sq continue */
	state = nbl_umem_get(qp, &sc_qp->sqbuf, nbldev,
			     req->sq_bufer, sq_size, udata);
	if (state)
		return state;
	nbl_get_umem_info(sc_qp->sqbuf.umem, &sc_qp->sq_pagen, &sq_continue);

	/* alloc rq continue */
	state = nbl_umem_get(qp, &sc_qp->rqbuf, nbldev,
			     req->rq_bufer, rq_size, udata);

	if (state) {
		ib_umem_release(sc_qp->sqbuf.umem);
		return state;
	}

	nbl_get_umem_info(sc_qp->rqbuf.umem, &sc_qp->rq_pagen, &rq_continue);

	if (sq_continue && rq_continue) {
		sc_qp->sq_pm = NBL_LEVEL0_PAGE_MODE;
		sc_qp->rq_pm = NBL_LEVEL0_PAGE_MODE;
		nbl_process_level0_buffer(&sc_qp->sqmem, &sc_qp->sqbuf, req->sq_bufer);
		nbl_process_level0_buffer(&sc_qp->rqmem, &sc_qp->rqbuf, req->rq_bufer);
	} else if (!sq_continue && !rq_continue) {
		sc_qp->sq_pm = NBL_LEVEL1_PAGE_MODE;
		sc_qp->rq_pm = NBL_LEVEL1_PAGE_MODE;
		state = nbl_sqrq_use_one_12k_pd(nbldev, sc_qp);
	} else if (!sq_continue && rq_continue) {
		sc_qp->sq_pm = NBL_LEVEL1_PAGE_MODE;
		state = nbl_qp_use_8k_pd(nbldev, &sc_qp->sqbuf, &sc_qp->sqmem,
						sc_qp->sq_pagen, &sc_qp->sq_pdsize);

		sc_qp->rq_pm = NBL_LEVEL0_PAGE_MODE;
		nbl_process_level0_buffer(&sc_qp->rqmem, &sc_qp->rqbuf, req->rq_bufer);
	}  else if (sq_continue && !rq_continue) {
		sc_qp->sq_pm = NBL_LEVEL0_PAGE_MODE;
		nbl_process_level0_buffer(&sc_qp->sqmem, &sc_qp->sqbuf, req->sq_bufer);

		sc_qp->rq_pm = NBL_LEVEL1_PAGE_MODE;
		state = nbl_qp_use_8k_pd(nbldev, &sc_qp->rqbuf, &sc_qp->rqmem,
			sc_qp->rq_pagen, &sc_qp->rq_pdsize);
	}
	return state;

}

static int nbl_create_user_qp(struct nbl_qp *qp, struct ib_udata *udata,
			      struct ib_qp_init_attr *init_attr)
{
	struct nbl_create_qp_req req;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	int state = 0;
	__u32 sq_size;
	__u32 rq_size;

	state = ib_copy_from_udata(&req, udata,
					   min(sizeof(req), udata->inlen));
	if (state)
		return -EINVAL;

	qp->ctx_info.qp_completion_ctx = req.qp;
	qp->user_mode = true;

	if (req.sq_bufer && req.rq_bufer) {
		sq_size = req.sq_size;
		rq_size = req.rq_size;
		uk_qp->sq_base =
			(struct nbl_qp_block *)req.sq_bufer;
		uk_qp->rq_base = (struct nbl_qp_block *)req.rq_bufer;
		if (sq_size == SZ_2M || rq_size == SZ_2M) {
			state = nbl_process_qp_2m_buffer(qp->nbldev, qp, sq_size,
						rq_size, &req, udata);
			if (state)
				return state;
		} else {
			/* alloc sq buffer */
			state = nbl_alloc_qp_buffer(qp, qp->nbldev, &sc_qp->sqbuf,
						req.sq_bufer, sq_size, 1, udata);
			if (state) {
				nbl_free_user_qp_buffer(qp->nbldev->rf, sc_qp);
				return state;
			}
			/* alloc rq buffer */
			state = nbl_alloc_qp_buffer(qp, qp->nbldev, &sc_qp->rqbuf,
						 req.rq_bufer, rq_size, 0, udata);
			if (state) {
				nbl_free_user_qp_buffer(qp->nbldev->rf, sc_qp);
				return state;
			}
		}
		uk_qp->sq_size = ilog2(sq_size >> 6);
		uk_qp->rq_size = ilog2(rq_size >> 6);
	}
	return 0;
}

/**
 * nbl_check_qp_init_attr - check the attr is valid
 * @init_attr: init info from user
 * @uk_attr: uk_attr from device
 */
int nbl_check_qp_init_attr(struct ib_qp_init_attr *init_attr,
			   struct nbl_uk_attrs *uk_attrs)
{
	if (init_attr->create_flags) {
		nbl_pr_err("create_flags is true, not support\n");
		return -EOPNOTSUPP;
	}

	if (init_attr->cap.max_inline_data > uk_attrs->max_hw_inline) {
		nbl_pr_err(
			"invalid parameter, the max_inline_data of init_attr is %u.\n",
			init_attr->cap.max_inline_data);
		return -EOPNOTSUPP;
	}

	if (init_attr->cap.max_send_sge > uk_attrs->max_hw_wq_sges) {
		nbl_pr_err(
			"invalid parameter, the max_send_sge of init_attr is %u.\n",
			init_attr->cap.max_send_sge);
		return -EOPNOTSUPP;
	}

	if (init_attr->cap.max_recv_sge > uk_attrs->max_hw_wq_sges) {
		nbl_pr_err(
			"invalid parameter, the max_recv_sge of init_attr is %u.\n",
			init_attr->cap.max_recv_sge);
		return -EOPNOTSUPP;
	}

	if (init_attr->qp_type != IB_QPT_RC &&
	    init_attr->qp_type != IB_QPT_UD &&
		init_attr->qp_type != IB_QPT_GSI) {
		nbl_pr_err("invalid qp_type, the qp_type of init_attr is %u.\n",
			   init_attr->qp_type);
		return -EOPNOTSUPP;
	}

	return 0;
}


static void nbl_init_qpc_seq_num(struct nbl_pci_f *rf, struct nbl_sc_qp *sc_qp)
{
	int qpn = sc_qp->uk_qp.qpn;

	if (rf->qp_seq_table[qpn] != NBL_MAX_SEQ_NUM)
		rf->qp_seq_table[qpn] += 1;
	else
		rf->qp_seq_table[qpn] = 1;

	sc_qp->uk_qp.seq_num = rf->qp_seq_table[qpn];
	set_64bit_val(sc_qp->qp_shadow.va, 8,
			FIELD_PREP(NBL_QPC_SHADOW_AREA_HW_SEQ_NUM, sc_qp->uk_qp.seq_num));
}
static void nbl_init_qp(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr)
{
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	sc_qp->sc_pd = &qp->nblpd->sc_pd;
	sc_qp->dev = sc_qp->sc_pd->dev;
	sc_qp->uk_qp.rq_db = sc_qp->dev->hw_regs[NBL_RQ_DB];
	sc_qp->uk_qp.sq_db = sc_qp->dev->hw_regs[NBL_SQ_DB];
	sc_qp->sqrq_one_pd = false;
	qp->scq = to_nblcq(init_attr->send_cq);
	qp->rcq = to_nblcq(init_attr->recv_cq);
	qp->ibqp.send_cq = init_attr->send_cq;
	qp->ibqp.recv_cq = init_attr->recv_cq;
	qp->qp_state = NBL_QP_STATE_RST;
}

static void nbl_uk_qp_init(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	if (init_attr->qp_type == IB_QPT_RC) {
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_RC;
		uk_qp->qp_caps = NBL_WRITE_WITH_IMM | NBL_SEND_WITH_IMM;
		if (qp->nbldev->atomic_cap)
			uk_qp->qp_caps |= NBL_ATOMIC;
	} else {
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_UD;
		uk_qp->qp_caps = NBL_SEND_WITH_IMM;
	}
	uk_qp->qp_type = init_attr->qp_type;

	uk_qp->max_inline_data = init_attr->cap.max_inline_data;
	uk_qp->max_send_sge = init_attr->cap.max_send_sge;
	uk_qp->max_recv_sge = init_attr->cap.max_recv_sge;
	uk_qp->max_outstanding_read = qp->nbldev->rf->nbl_actual_rd_atom;
	if (init_attr->cap.max_recv_sge <= NBL_MIN_RQWQE_SGE) {
		uk_qp->rq_wqe_size = NBL_MIN_RQ_WQE_SIZE;
		uk_qp->rq_wqe_size_multiplier = 1;
	} else {
		uk_qp->rq_wqe_size = NBL_MAX_RQ_WQE_SIZE;
		uk_qp->rq_wqe_size_multiplier = 2;
	}
	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		uk_qp->sig_all = true;
	uk_qp->destroy_pending = false;
	uk_qp->sw_ring_db_pi = 0;
	uk_qp->rq_db_flag = 0;
	uk_qp->seq_first_err = false;
	uk_qp->err_db_done = false;
	uk_qp->seq_err = false;
	uk_qp->tc = 0;
	uk_qp->next_fence = 0;
	uk_qp->back_qp = qp;

}

static int nbl_get_qp_num(struct ib_qp_init_attr *init_attr,
				struct nbl_qp *qp, struct nbl_pci_f *rf)
{
	__u32 qp_num;

	if (init_attr->qp_type == IB_QPT_GSI) {
		qp_num = NBL_QP_NUM_FOR_CM;
	} else {
		if (nbl_alloc_qpn_rsrc(rf, &qp_num, &rf->next_qp)) {
			nbl_pr_err("get qpn err, used qp %u,max qp %u\n",
				   rf->used_qps, rf->max_qp);
			return -EINVAL;
		}
	}
	qp->ibqp.qp_num = qp_num;
	qp->sc_qp.uk_qp.qpn = qp_num;
	return 0;
}

static int nbl_alloc_qp_rsc(struct nbl_pci_f *rf, struct nbl_sc_qp *sc_qp)
{

	/* alloc qp ctx mem */
	sc_qp->qp_ctx_mem.va =
		nbl_dma_alloc_coherent(rf->sc_dev.hw->device, NBL_QP_CTX_SIZE,
				       &sc_qp->qp_ctx_mem.pa, GFP_KERNEL);
	if (!sc_qp->qp_ctx_mem.va)
		return -ENOMEM;

	sc_qp->qp_ctx_mem.size = NBL_QP_CTX_SIZE;
	/* alloc unaq mem */
	sc_qp->unaq_mem.va =
		nbl_dma_alloc_coherent(rf->sc_dev.hw->device, NBL_UNAQ_SIZE,
				       &sc_qp->unaq_mem.pa, GFP_KERNEL);
	if (!sc_qp->unaq_mem.va)
		return -ENOMEM;

	/* alloc irq mem */
	sc_qp->irq_mem.va =
		nbl_dma_alloc_coherent(rf->sc_dev.hw->device, NBL_IRQ_SIZE,
				       &sc_qp->irq_mem.pa, GFP_KERNEL);
	if (!sc_qp->irq_mem.va)
		return -ENOMEM;

	/* alloc orq mem */
	sc_qp->orq_mem.va =
		nbl_dma_alloc_coherent(rf->sc_dev.hw->device, NBL_ORQ_SIZE,
				       &sc_qp->orq_mem.pa, GFP_KERNEL);
	if (!sc_qp->orq_mem.va)
		return -ENOMEM;

	sc_qp->raq_mem.va =
		nbl_dma_alloc_coherent(rf->sc_dev.hw->device, NBL_RAQ_SIZE,
				       &sc_qp->raq_mem.pa, GFP_KERNEL);
	if (!sc_qp->raq_mem.va)
		return -ENOMEM;

	return 0;
}

/**
 * nbl_ib_create_qp - create qp in kernel
 * @ibpd: pd
 * @init_attr: attr info
 * @udata: udata form user
 */
int nbl_ib_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr,
		     struct ib_udata *udata)
{
	struct ib_pd *ibpd = ibqp->pd;
	struct nbl_ib_create_qp_resp resp = {};
	struct nbl_device *nbldev = to_nbl_dev(ibpd->device);
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_qp *sc_qp;
	struct nbl_qp *qp;
	struct nbl_uk_attrs *uk_attrs = &rf->sc_dev.hw_attrs.uk_attrs;
	int state = 0;

	state = nbl_check_qp_init_attr(init_attr, uk_attrs);
	if (state)
		return state;

	qp = container_of(ibqp, struct nbl_qp, ibqp);
	sc_qp = &qp->sc_qp;

	state = nbl_get_qp_num(init_attr, qp, rf);
	if (state)
		goto free_qp;
	state = nbl_alloc_qp_rsc(rf, sc_qp);
	if (state)
		goto free_qpn;

	qp->nbldev = nbldev;
	qp->nblpd = to_nbl_pd(ibpd);
	sc_qp->uk_qp.uk_attrs = uk_attrs;
	nbl_init_qp(qp, init_attr);

	if (udata) {
		state = nbl_create_user_qp(qp, udata, init_attr);
		if (state)
			goto free_rsrc;
		state = nbl_user_qp_shadow(qp, &resp, rf->qp_sd_info);
		if (state)
			goto free_rsrc;
	} else {
		state = nbl_create_kmode_qp(nbldev, qp, init_attr);
		if (state)
			goto free_rsrc;
		nbl_kernel_qp_shadow(qp, rf->qp_sd_info);
	}

	nbl_uk_qp_init(qp, init_attr);
	nbl_init_qpc_seq_num(rf, sc_qp);
	nbl_fill_qpc_info(qp, &qp->ctx_info);
	nbl_set_qp_ctx(qp, sc_qp->qp_ctx_mem.va);
	state = nbl_init_qp_ref(qp);
	if (state)
		goto free_rsrc;

	if (udata) {
		state = nbl_copy_data_to_user(rf, &sc_qp->uk_qp, &resp, udata);
		if (state)
			goto free_rsrc;
	}

	return 0;

free_rsrc:
	nbl_free_qp_rsrc(qp);
free_qpn:
	nbl_free_qp_num(rf, qp->sc_qp.uk_qp.qpn);
free_qp:
	return state;
}
static int nbl_modify_hw_qp_state(struct nbl_qp *qp, struct ib_qp_attr *attr,
		struct nbl_qp_ctx *ctx_info)
{
	u8 issue_flush = 0;
	unsigned long flags;

	if (nbl_cqp_modify_qp_cmd(qp->nbldev, qp, ctx_info->qp_st)) {
		nbl_pr_err("nbl modify qp cmd failed. qpn:%#x qp_type :%d, cur_state:%d next state:%d\n",
				qp->ibqp.qp_num, qp->ibqp.qp_type, qp->qp_state, ctx_info->qp_st);
		return -EINVAL;
	}

	spin_lock_irqsave(&qp->lock, flags);
	qp->qp_state = ctx_info->qp_st;
	qp->ibqp_state = attr->qp_state;
	if ((ctx_info->qp_st == NBL_QP_STATE_ERR) && !qp->flush_issued) {
		qp->flush_issued = 1;
		issue_flush = 1;
	}
	spin_unlock_irqrestore(&qp->lock, flags);

	if (issue_flush) {
		down(&qp->nbldev->rf->qp_flush_sem);
		/* flush oper is just do our best,
		 * even meet err, we must continue,
		 * so cancel return check here.
		 */
		nbl_flush_operation(qp, qp->nbldev);
		up(&qp->nbldev->rf->qp_flush_sem);
	}

	return 0;
}

static int nbl_check_qp_state(struct nbl_qp *qp, struct ib_qp_attr *attr,
				struct nbl_qp_ctx *ctx_info)
{
	u8 next_qp_state = 0;

	switch (attr->qp_state) {
	case IB_QPS_INIT:
		if (qp->qp_state == NBL_QP_STATE_RST ||
			qp->qp_state == NBL_QP_STATE_INIT) {
			next_qp_state = NBL_QP_STATE_INIT;
		} else if (qp->qp_state > NBL_QP_STATE_INIT) {
			nbl_pr_err("modify qp to INIT failed! curr_state:%u, qpn:%#x, qp_type :%d\n",
				qp->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		break;
	case IB_QPS_RTR:
		if (qp->qp_state != NBL_QP_STATE_INIT) {
			nbl_pr_err("modify qp to RTR failed! curr_state:%u, qpn:%#x, qp_type :%d\n",
					qp->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		next_qp_state = NBL_QP_STATE_RTR;
		break;
	case IB_QPS_RTS:
		if (qp->qp_state < NBL_QP_STATE_RTR ||
			qp->qp_state > NBL_QP_STATE_SQD) {
			nbl_pr_err("modify qp to RTS failed! curr_state:%u, qpn:%#x, qp_type :%d\n",
				qp->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		next_qp_state = NBL_QP_STATE_RTS;
		break;
	case IB_QPS_SQD:
		if (qp->qp_state == NBL_QP_STATE_SQD ||
			qp->qp_state == NBL_QP_STATE_RTS) {
			next_qp_state = NBL_QP_STATE_SQD;
		} else {
			nbl_pr_err("modify qp to SQD failed! curr_state:%u, qpn:%#x, qp_type :%d\n",
				qp->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		break;
	case IB_QPS_SQE:
	case IB_QPS_RESET:
	case IB_QPS_ERR:
		nbl_pr_dbg("modify qp to ERR! curr_qp_state:%u, qpn:%#x, qp_type :%d\n",
				qp->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
		next_qp_state = NBL_QP_STATE_ERR;
		break;
	default:
		return -EINVAL;
	}
	qp->ibqp_state = attr->qp_state;
	ctx_info->qp_st = next_qp_state;

	return 0;
}

static int nbl_modify_sw_qp_state(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
				  struct ib_qp_attr *attr, int attr_mask)
{
	unsigned long flags;

	spin_lock_irqsave(&qp->lock, flags);

	if (attr_mask & IB_QP_STATE) {
		if (!ib_modify_qp_is_ok(qp->ibqp_state, attr->qp_state,
					qp->ibqp.qp_type, attr_mask)) {
			nbl_pr_err("attr_mask err: cur state:%u, attr state: %u, qpn :%#x, qp_type :%u\n",
				qp->qp_state, attr->qp_state, qp->ibqp.qp_num, qp->ibqp.qp_type);
			spin_unlock_irqrestore(&qp->lock, flags);
			return -EINVAL;
		}
		if (nbl_check_qp_state(qp, attr, ctx_info)) {
			spin_unlock_irqrestore(&qp->lock, flags);
			return -EINVAL;
		}
	}
	nbl_set_qp_ctx(qp, qp->sc_qp.qp_ctx_mem.va);

	spin_unlock_irqrestore(&qp->lock, flags);

	return 0;
}

static u32 nbl_hash_by_l3l4(bool is_ipv4, u8 *dip, u8 *sip,
	__be16 dport, __be16 sport)
{
	u8 hash_buf[NBL_QP_SPORT_L3L4_HASH_MAX];
	u8 proto = IPPROTO_UDP;
	size_t buf_len = 0;
	u32 crc = 0;

	if (is_ipv4) {
		memcpy(hash_buf + buf_len, &sip[NBL_QP_GID_V4_BEGIN], 4);
		buf_len += 4;
		memcpy(hash_buf + buf_len, &dip[NBL_QP_GID_V4_BEGIN], 4);
		buf_len += 4;
	} else {
		memcpy(hash_buf + buf_len, sip, 16);
		buf_len += 16;
		memcpy(hash_buf + buf_len, dip, 16);
		buf_len += 16;
	}
	memcpy(hash_buf + buf_len, &sport, 2);
	buf_len += 2;
	memcpy(hash_buf + buf_len, &dport, 2);
	buf_len += 2;
	memcpy(hash_buf + buf_len, &proto, 1);
	buf_len += 1;

	crc = crc32(0, hash_buf, buf_len);

	return crc;
}

static u16 nbl_uport_by_l3l4(bool is_ipv4, u8 *dip, u8 *sip, u16 bsport, u32 qpn)
{
	u16 sport = bsport;
	u16 dport = 0x12b7;
	u32 hash;

	hash = nbl_hash_by_l3l4(is_ipv4, dip, sip, htons(dport), htons(sport));
	while ((hash & 0x1) != (qpn & 0x1)) {
		if (sport == IB_ROCE_UDP_ENCAP_VALID_PORT_MAX)
			sport = IB_ROCE_UDP_ENCAP_VALID_PORT_MIN;
		else
			sport++;
		hash = nbl_hash_by_l3l4(is_ipv4, dip, sip, htons(dport), htons(sport));
	}

	return sport;
}

static int nbl_get_ah_info(struct nbl_qp *qp, struct ib_qp_attr *attr,
				struct nbl_qp_ctx *ctx_info)
{
	int ret = 0;
	u16 src_addr_idx;
	u8 src_ip[NBL_SRC_IP_SIZE];
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	const struct ib_global_route *grh =
		rdma_ah_read_grh(&attr->ah_attr);
	const struct ib_gid_attr *sgid_attr = grh->sgid_attr;

	if (attr->ah_attr.ah_flags & IB_AH_GRH) {
		ctx_info->hop_limit = attr->ah_attr.grh.hop_limit;
		ctx_info->flow_label = attr->ah_attr.grh.flow_label;
		ctx_info->tclass = attr->ah_attr.grh.traffic_class;
		if (nbldev->tcd[0].val >= 0)
			ctx_info->tclass = nbldev->tcd[0].val;
		if (ctx_info->cc_mode == NBL_QCN && (ctx_info->tclass & ECN_CE) != ECN_ECT_1)
			ctx_info->tclass |= ECN_ECT_0;
		ctx_info->sch_net_tc = NBL_GET_PRI_FROM_T2P(
			qp->nbldev->rf->sc_dev.tc2pri, NBL_GET_PRI_FROM_TOS(ctx_info->tclass));
		uk_qp->tc = ctx_info->tclass;
	}

	memcpy(ctx_info->dest_ip, &grh->dgid, NBL_GRH_DGID_RAW_SIZE);
	memcpy(ctx_info->dest_mac, attr->ah_attr.roce.dmac,
		sizeof(attr->ah_attr.roce.dmac));

	if (ipv6_addr_v4mapped((struct in6_addr *)&sgid_attr->gid))
		ctx_info->ipv4 = true;

	if (sgid_attr->ndev && is_vlan_dev(sgid_attr->ndev)) {
		ctx_info->vlan_en = true;
		ctx_info->vlan_tag = vlan_dev_vlan_id(sgid_attr->ndev);
	}

	ret = nbl_get_src_addr_info(nbldev, grh->sgid_index,
					    &src_addr_idx, src_ip);
	if (ret) {
		nbl_pr_err("get src addr index failed, function_id: %u, sgid_index: %u.\n",
			nbldev->rf->sc_dev.function_id,
			grh->sgid_index);
		ret = -ENODATA;
		return ret;
	}
	ctx_info->src_addr_idx = src_addr_idx;

	if (cdev_info->is_lag)
		ctx_info->udp_sport = nbl_uport_by_l3l4(ctx_info->ipv4,
			ctx_info->dest_ip, src_ip, rf->lag_bsport, uk_qp->qpn);
	else
		ctx_info->udp_sport = nbl_ah_get_udp_sport(nbldev, &attr->ah_attr);

	qp->sgid_index = grh->sgid_index;
	return 0;
}

static int nbl_get_ctx_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
				struct ib_qp_attr *attr, int attr_mask)
{
	int ret = 0;
	enum ib_mtu active_mtu;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	if (attr_mask & IB_QP_DEST_QPN)
		ctx_info->dest_qpn = attr->dest_qp_num;

	if (attr_mask & IB_QP_SQ_PSN) {
		ctx_info->sq_psn = attr->sq_psn;
		ctx_info->psn_max = (attr->sq_psn) - 1;
	}

	if (attr_mask & IB_QP_RQ_PSN)
		ctx_info->rq_psn = attr->rq_psn;

	if (attr_mask & IB_QP_QKEY)
		ctx_info->ud_qkey = attr->qkey;

	if (attr_mask & IB_QP_PATH_MTU) {
		ctx_info->pmtu = ib_mtu_to_nbl(attr->path_mtu);
		if (ctx_info->pmtu == NBL_MTU_INVALID)
			return -EINVAL;
	}

	if (attr_mask & IB_QP_MIN_RNR_TIMER) {
		if (attr->min_rnr_timer == 0 ||
			attr->min_rnr_timer > NBL_DEFAULT_RNR_TIMER)
			ctx_info->local_rnr_timer_value = NBL_DEFAULT_RNR_TIMER;
		else
			ctx_info->local_rnr_timer_value = attr->min_rnr_timer;
	}

	if (attr_mask & IB_QP_TIMEOUT) {
		if (attr->timeout > NBL_RTO_MAX_VALUE)
			return -EINVAL;
		ctx_info->rto_timer_value = rto_arry[attr->timeout];
	}

	if (attr_mask & IB_QP_RETRY_CNT)
		ctx_info->tx_retry_th = attr->retry_cnt;

	if (attr_mask & IB_QP_RNR_RETRY)
		ctx_info->rnr_retry = attr->rnr_retry;

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > uk_qp->max_outstanding_read)
			return -ENODATA;
		else if (attr->max_rd_atomic == 0)
			ctx_info->irq_size = ilog2(uk_qp->max_outstanding_read);
		else
			ctx_info->irq_size = ilog2(attr->max_rd_atomic);
	}

	if (uk_qp->qp_type == IB_QPT_UD || uk_qp->qp_type == IB_QPT_GSI) {
		active_mtu = iboe_get_mtu(qp->nbldev->netdev->mtu);
		ctx_info->pmtu = ib_mtu_to_nbl(active_mtu);
	}

	if (attr_mask & IB_QP_AV)
		ret = nbl_get_ah_info(qp, attr, ctx_info);

	return ret;
}

/**
 * nbl_ib_modify_qp - modify qp in kernal
 * @ibqp: ibqp
 * @attr: modify attr
 * @attr_mask: whitch attr will be modified
 */
int __nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask)
{
	struct nbl_qp *qp = container_of(ibqp, struct nbl_qp, ibqp);
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_qp_ctx *ctx_info;
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	int ret = 0;

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS ||
	((attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) || (attr_mask & IB_QP_PATH_MIG_STATE))) {
		nbl_ib_err(sc_dev, "qpn :%#x, err attr_mask:%d.\n",
			    qp->ibqp.qp_num, attr_mask);
		return -EOPNOTSUPP;
	}

	ctx_info = &qp->ctx_info;
	ret = nbl_get_ctx_info(qp, ctx_info, attr, attr_mask);
	if (ret)
		return ret;

	ret = nbl_modify_sw_qp_state(qp, ctx_info, attr, attr_mask);
	if (ret)
		return ret;

	if (attr_mask & IB_QP_STATE) {
		ret = nbl_modify_hw_qp_state(qp, attr, ctx_info);
		if (ret)
			return ret;
	}
	return 0;
}

int nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		     struct ib_udata *udata)
{
	struct nbl_qp *nblqp = container_of(ibqp, struct nbl_qp, ibqp);
	int ret;

	if (attr->qp_state == IB_QPS_ERR ||
		attr->qp_state == IB_QPS_SQE)
		ret = nbl_modify_qp_to_err(nblqp);
	else
		ret = __nbl_ib_modify_qp(ibqp, attr, attr_mask);
	return ret;
}

/**
 * nbl_ib_destroy_qp - destroy qp in kernal
 * @ibqp: ibqp
 * @udata: udata form user
 */
int nbl_ib_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	int ret;
	struct nbl_qp *nblqp = container_of(ibqp, struct nbl_qp, ibqp);
	struct nbl_sc_dev *sc_dev = &nblqp->nbldev->rf->sc_dev;
	struct nbl_cq *send_cq;
	struct nbl_cq *recv_cq;

	nblqp->sc_qp.uk_qp.destroy_pending = true;
	nbl_modify_qp_to_err(nblqp);

	if (!nblqp->user_mode) {
		send_cq = ibqp->send_cq ? to_nblcq(ibqp->send_cq) : NULL;
		recv_cq = ibqp->recv_cq ? to_nblcq(ibqp->recv_cq) : NULL;
		if (send_cq)
			nbl_clean_cqes(send_cq, ibqp->qp_num);
		if (recv_cq && recv_cq != send_cq)
			nbl_clean_cqes(recv_cq, ibqp->qp_num);
	}

	nbl_qp_rem_ref(ibqp);
	wait_for_completion(&nblqp->free_qp);

	/* issud cqp to hardware */
	ret = nbl_cqp_destroy_qp_cmd(nblqp);
	if (ret)
		nbl_ib_err(sc_dev, "destroy qp cqp ret:%d, qpn :%d\n",
			ret, nblqp->sc_qp.uk_qp.qpn);
	memset(nblqp->sc_qp.qp_shadow.va, 0, nblqp->sc_qp.qp_shadow.size);
	nbl_dec_cqc_ref(nblqp->scq);
	nbl_dec_cqc_ref(nblqp->rcq);
	nbl_free_qp_rsrc(nblqp);
	nbl_free_qp_num(nblqp->nbldev->rf, nblqp->sc_qp.uk_qp.qpn);

	return 0;
}

static int nbl_query_qp_psn(struct nbl_qp *qp, struct ib_qp_attr *attr)
{
	int err_code;
	struct nbl_dma_mem qpc_mem;
	__u64 temp;
	__be64 *in;
	struct nbl_device *nbldev = qp->nbldev;

	qpc_mem.size = NBL_QP_CTX_SIZE;
	qpc_mem.va =
		nbl_dma_alloc_coherent(nbldev->rf->sc_dev.hw->device,
				       qpc_mem.size, &qpc_mem.pa, GFP_KERNEL);
	if (!qpc_mem.va)
		return -ENOMEM;
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(nbldev->rf->sc_dev.hw->device, qpc_mem.size,
				  qpc_mem.va, qpc_mem.pa);
		return -ENOMEM;
	}
	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_QUERY_QP) |
			      FIELD_PREP(NBL_CQP_QP_NUM, qp->sc_qp.uk_qp.qpn));
	set_64bit_val(in, 8, FIELD_PREP(NBL_CQP_QP_CTX_ADDR, qpc_mem.pa));
	err_code = nbl_cmd_exec(nbldev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		goto out;

	get_64bit_val(qpc_mem.va, 416, &temp);
	attr->sq_psn = (__u32)FIELD_GET(NBL_QPC_PSN_MAX, temp);
	get_64bit_val(qpc_mem.va, 256, &temp);
	attr->rq_psn = (__u32)FIELD_GET(NBL_QPC_RXP_EPSN, temp);


out:
	kfree(in);
	dma_free_coherent(nbldev->rf->sc_dev.hw->device, qpc_mem.size,
			  qpc_mem.va, qpc_mem.pa);
	return err_code;
}
/**
 * nbl_ib_query_qp - query qp in kernal
 * @ibqp: ibqp
 * @attr: attr
 * @attr_mask: whitch attr will be queried
 * @udata: udata form user
 */
int nbl_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int attr_mask,
		    struct ib_qp_init_attr *qp_init_attr)
{
	struct nbl_qp *qp = container_of(ibqp, struct nbl_qp, ibqp);
	struct nbl_sc_qp *scqp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	struct nbl_qp_ctx *ctx_info = &qp->ctx_info;
	struct rdma_ah_attr *ah_attr;
	int ret = 0;

	memset(qp_attr, 0, sizeof(*qp_attr));
	memset(qp_init_attr, 0, sizeof(*qp_init_attr));

	qp_attr->qp_state = qp->ibqp_state;
	qp_attr->cur_qp_state = qp->ibqp_state;
	qp_attr->sq_draining = (qp->ibqp_state == IB_QPS_SQD) ? true : false;
	qp_attr->cap.max_send_wr = uk_qp->max_send_wr;
	qp_attr->cap.max_recv_wr = uk_qp->max_recv_wr;
	qp_attr->cap.max_send_sge = uk_qp->max_send_sge;
	qp_attr->cap.max_recv_sge = uk_qp->max_recv_sge;
	qp_attr->cap.max_inline_data = scqp->uk_qp.max_inline_data;

	qp_init_attr->qp_type = ibqp->qp_type;
	qp_init_attr->send_cq = qp->ibqp.send_cq;
	qp_init_attr->recv_cq = qp->ibqp.recv_cq;
	qp_init_attr->event_handler = qp->ibqp.event_handler;
	qp_init_attr->qp_context = qp->ibqp.qp_context;

	qp_attr->path_mtu = nbl_mtu_to_ib(ctx_info->pmtu);
	if (qp_attr->path_mtu == IB_MTU_INVALID_NBL)
		return -EINVAL;

	qp_attr->dest_qp_num = ctx_info->dest_qpn;
	qp_attr->timeout = ctx_info->rto_timer_value;
	qp_attr->min_rnr_timer = ctx_info->local_rnr_timer_value;
	qp_attr->retry_cnt = ctx_info->tx_retry_th;
	qp_attr->rnr_retry = ctx_info->rnr_retry;
	qp_attr->max_dest_rd_atomic = NBL_MAX_ORD_SIZE;
	qp_attr->max_rd_atomic = ctx_info->irq_size;
	qp_attr->port_num = 1;

	qp_attr->qkey = ctx_info->ud_qkey;
	qp_init_attr->cap = qp_attr->cap;
	qp_init_attr->sq_sig_type = (ctx_info->sq_ce_en == true) ?
					IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;

	ah_attr = &qp_attr->ah_attr;
	ah_attr->type = RDMA_AH_ATTR_TYPE_ROCE;
	rdma_ah_set_grh(ah_attr, NULL, ctx_info->flow_label, qp->sgid_index,
			 ctx_info->hop_limit, ctx_info->tclass);
	rdma_ah_set_dgid_raw(ah_attr, ctx_info->dest_ip);
	memcpy(ah_attr->roce.dmac, ctx_info->dest_mac,
		       sizeof(ah_attr->roce.dmac));

	ret = nbl_query_qp_psn(qp, qp_attr);
	if (ret)
		nbl_pr_err("get qpc psn fail\n");
	return ret;
}

void nbl_qp_add_ref(struct nbl_qp *qp)
{
	refcount_inc(&qp->refcnt);
}

void nbl_free_qp_num(struct nbl_pci_f *rf, u32 qp_num)
{
	if (qp_num != NBL_QP_NUM_FOR_RSV && qp_num != NBL_QP_NUM_FOR_CM &&
	    qp_num < rf->max_qp)
		nbl_free_qpn_rsrc(rf, qp_num);
}

void nbl_free_qp_rsrc(struct nbl_qp *qp)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	/* TODO vsi qos*/
	if (sc_qp->qp_ctx_mem.va) {
		dma_free_coherent(rf->sc_dev.hw->device, NBL_QP_CTX_SIZE,
				  sc_qp->qp_ctx_mem.va, sc_qp->qp_ctx_mem.pa);
		sc_qp->qp_ctx_mem.va = NULL;
	}

	if (sc_qp->unaq_mem.va) {
		dma_free_coherent(rf->sc_dev.hw->device, NBL_UNAQ_SIZE,
				  sc_qp->unaq_mem.va, sc_qp->unaq_mem.pa);
		sc_qp->unaq_mem.va = NULL;
	}

	if (sc_qp->orq_mem.va) {
		dma_free_coherent(rf->sc_dev.hw->device, NBL_ORQ_SIZE,
				  sc_qp->orq_mem.va, sc_qp->orq_mem.pa);
		sc_qp->orq_mem.va = NULL;
	}

	if (sc_qp->irq_mem.va) {
		dma_free_coherent(rf->sc_dev.hw->device, NBL_IRQ_SIZE,
				  sc_qp->irq_mem.va, sc_qp->irq_mem.pa);
		sc_qp->irq_mem.va = NULL;
	}

	if (sc_qp->raq_mem.va) {
		dma_free_coherent(rf->sc_dev.hw->device, NBL_RAQ_SIZE,
				  sc_qp->raq_mem.va, sc_qp->raq_mem.pa);
		sc_qp->raq_mem.va = NULL;
	}

	if (qp->user_mode) {
		nbl_free_user_qp_buffer(rf, sc_qp);
	} else {
		if (sc_qp->sqmem.va)
			nbl_free_kmode_qp_buffer(qp, nbldev, &sc_qp->sqbuf, true);

		if (sc_qp->rqmem.va)
			nbl_free_kmode_qp_buffer(qp, nbldev, &sc_qp->rqbuf, false);
		kfree(qp->kqp.sq_wrid_mem);
		kfree(qp->kqp.rq_wrid_mem);
		qp->kqp.sq_wrid_mem = NULL;
		qp->kqp.rq_wrid_mem = NULL;
		sc_qp->uk_qp.sq_wrtrk_array = NULL;
		sc_qp->uk_qp.rq_wrid_array = NULL;
	}
}

int nbl_modify_qp_to_err(struct nbl_qp *nblqp)
{
	struct ib_qp_attr attr;
	int ret = 0;

	mutex_lock(&nblqp->qp_err_mutex);
	if (nblqp->qp_state != NBL_QP_STATE_ERR &&
	    nblqp->qp_state != NBL_QP_STATE_RST) {
		attr.qp_state = IB_QPS_ERR;
		ret = __nbl_ib_modify_qp(&nblqp->ibqp, &attr, IB_QP_STATE);
	}
	mutex_unlock(&nblqp->qp_err_mutex);
	return ret;
}

void nbl_qp_rem_ref(struct ib_qp *ibqp)
{
	struct nbl_qp *qp = container_of(ibqp, struct nbl_qp, ibqp);
	struct nbl_device *nbldev = qp->nbldev;
	u32 qp_num;
	unsigned long flags;

	spin_lock_irqsave(&nbldev->rf->qptable_lock, flags);
	if (!refcount_dec_and_test(&qp->refcnt)) {
		nbl_ib_dbg(&qp->nbldev->rf->sc_dev,
			   "qp refcnt:%d is not zero.\n",
			   refcount_read(&qp->refcnt));
		spin_unlock_irqrestore(&nbldev->rf->qptable_lock, flags);
		return;
	}

	qp_num = qp->ibqp.qp_num;
	nbldev->rf->qp_table[qp_num] = NULL;
	spin_unlock_irqrestore(&nbldev->rf->qptable_lock, flags);
	complete(&qp->free_qp);
}

int nbl_cqp_modify_qp_cmd(struct nbl_device *nbldev, struct nbl_qp *qp,
			  u8 next_qp_state)
{
	struct nbl_qp_ctx *ctx_info;
	bool epsn_valid = false;
	bool psnmax_valid = false;
	int ret = 0;
	__be64 *in;

	ctx_info = &qp->ctx_info;
	if (qp->qp_state != next_qp_state) {
		if (next_qp_state == NBL_QP_STATE_RTR)
			epsn_valid = true;
		if (next_qp_state == NBL_QP_STATE_RTS)
			psnmax_valid = true;
	}

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQP_QP_TYPE, qp->sc_qp.uk_qp.nbl_qp_service_type) |
			      FIELD_PREP(NBL_CQP_QP_NEXT_STATE, next_qp_state) |
			      FIELD_PREP(NBL_CQP_QP_MODIFY_EPSN,
					 (epsn_valid ? 1 : 0)) |
			      FIELD_PREP(NBL_CQP_QP_MODIFY_PSNMAX,
					 (psnmax_valid ? 1 : 0)) |
			      FIELD_PREP(NBL_CQPSQ_OPCODE,
					 NBL_MODIFY_QP_CMD_CODE) |
			      FIELD_PREP(NBL_CQP_QP_NUM, qp->sc_qp.uk_qp.qpn));
	set_64bit_val(in, 8,
		      FIELD_PREP(NBL_CQP_QP_CTX_ADDR, qp->sc_qp.qp_ctx_mem.pa));
	set_64bit_val(in, 16,
		      FIELD_PREP(NBL_CQP_QP_EPSN, ctx_info->rq_psn) |
			      FIELD_PREP(NBL_CQP_QP_PSNMAX, ctx_info->psn_max));

	ret = nbl_cmd_exec(nbldev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);
	return ret;
}

int nbl_umem_get(struct nbl_qp *qp, struct nbl_ib_qp_buf *q_buf, struct nbl_device *dev,
						unsigned long addr, int q_size,
						struct ib_udata *udata)
{
	int status;

	q_buf->umem =
		ib_umem_get(&dev->ibdev, addr, q_size, IB_ACCESS_LOCAL_WRITE);

	if (IS_ERR(q_buf->umem)) {
		nbl_ib_err(&dev->rf->sc_dev, "pin and dma map addr failed.\n");
		status = PTR_ERR(q_buf->umem);
		return status;
	}
	return 0;
}

int nbl_qp_use_8k_pd(struct nbl_device *dev, struct nbl_ib_qp_buf *q_buf,
			struct nbl_dma_mem *mem, __u32 page_num, __u32 *pd_size)
{
	u32 pas_size;
	u32 copy_num;
	int status;

	/*alloc 8K PD buffer*/
	pas_size =  NBL_QP_USE_8K_PD_SIZE;
	mem->va = nbl_dma_alloc_coherent(dev->rf->sc_dev.hw->device, pas_size,
					 &mem->pa, GFP_KERNEL);

	if (!mem->va)
		goto exit;

	status = nbl_copy_user_pgaddrs(q_buf->umem, mem->va, NBL_ADAPTER_PAGE_SIZE,
					page_num, &copy_num);
	if (status)
		goto exit;
	*pd_size = pas_size;
	return 0;
exit:
	ib_umem_release(q_buf->umem);
	dma_free_coherent(dev->rf->sc_dev.hw->device, pas_size, mem->va,
			  mem->pa);
	return NBL_ERR_ALLOCMEM_FAILED;
}

int nbl_sqrq_use_one_12k_pd(struct nbl_device *dev, struct nbl_sc_qp *sc_qp)
{
	struct nbl_dma_mem *mem;
	u32 pas_size;
	u32 copy_num;
	int status;

	/*first try alloc 12K PD buffer*/
	pas_size = NBL_QP_USE_12K_PD_SIZE;
	mem = &sc_qp->sqmem;
	mem->va = nbl_dma_alloc_coherent(dev->rf->sc_dev.hw->device, pas_size,
					 &mem->pa, GFP_KERNEL);

	/*TODO sec try 8K SQ PD and 8k RQ PD*/
	if (!mem->va)
		goto exit;

	status = nbl_copy_user_pgaddrs(sc_qp->sqbuf.umem, mem->va, NBL_ADAPTER_PAGE_SIZE,
					       sc_qp->sq_pagen, &copy_num);
	if (status)
		goto exit;

	status = nbl_copy_user_pgaddrs(sc_qp->rqbuf.umem,
				       (mem->va) + NBL_ADAPTER_PAGE_SIZE,
				       NBL_ADAPTER_PAGE_SIZE, sc_qp->rq_pagen,
				       &copy_num);
	if (status)
		goto exit;

	sc_qp->rqmem.va = mem->va + NBL_ADAPTER_PAGE_SIZE;
	sc_qp->rqmem.pa = mem->pa + NBL_ADAPTER_PAGE_SIZE;
	sc_qp->sqrq_one_pd = true;
	sc_qp->sqrq_pdsize = pas_size;
	return 0;
exit:
	ib_umem_release(sc_qp->rqbuf.umem);
	ib_umem_release(sc_qp->sqbuf.umem);
	dma_free_coherent(dev->rf->sc_dev.hw->device, pas_size, mem->va,
			  mem->pa);
	return NBL_ERR_ALLOCMEM_FAILED;
}


void nbl_process_level0_buffer(struct nbl_dma_mem *mem,
				struct nbl_ib_qp_buf *q_buf, __u64 addr)
{
	mem->va = (void *)addr;
	mem->pa = nbl_get_first_sg_dma_addr(q_buf->umem);
}

int nbl_alloc_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			struct nbl_ib_qp_buf *q_buf, unsigned long addr,
			int q_size, bool is_sq, struct ib_udata *udata)
{
	struct nbl_dma_mem *mem;
	u32 pas_size;
	int status = 0;
	u32 copy_num;
	u32 pg_num;
	bool is_contiguous;

	status = nbl_umem_get(qp, q_buf, dev, addr, q_size, udata);
	if (status)
		return status;
	nbl_get_umem_info(q_buf->umem, &pg_num, &is_contiguous);

	if (is_sq)
		mem = &qp->sc_qp.sqmem;
	else
		mem = &qp->sc_qp.rqmem;

	if (is_contiguous) {
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL0_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL0_PAGE_MODE;

		mem->va = (void *)addr;
		mem->pa = nbl_get_first_sg_dma_addr(q_buf->umem);
	} else {
		if (is_sq) {
			qp->sc_qp.sq_pm = NBL_LEVEL1_PAGE_MODE;
			qp->sc_qp.sq_pdsize = NBL_ADAPTER_PAGE_SIZE;
		} else {
			qp->sc_qp.rq_pm = NBL_LEVEL1_PAGE_MODE;
			qp->sc_qp.rq_pdsize = NBL_ADAPTER_PAGE_SIZE;
		}
		/* just support one page by now*/
		pas_size = NBL_ADAPTER_PAGE_SIZE;
		mem->va = nbl_dma_alloc_coherent(dev->rf->sc_dev.hw->device,
						 NBL_ADAPTER_PAGE_SIZE,
						 &mem->pa, GFP_KERNEL);
		if (!mem->va) {
			nbl_ib_err(&dev->rf->sc_dev, "dma alloc coherent failed.\n");
			ib_umem_release(q_buf->umem);
			return NBL_ERR_ALLOCMEM_FAILED;
		}

		status = nbl_copy_user_pgaddrs(q_buf->umem, mem->va, pas_size,
					       pg_num, &copy_num);
		if (status) {
			nbl_ib_err(&dev->rf->sc_dev, "copy nbl user pgaddrs failed.\n");
			dma_free_coherent(dev->rf->sc_dev.hw->device,
					  NBL_ADAPTER_PAGE_SIZE, mem->va, mem->pa);
			ib_umem_release(q_buf->umem);
			return status;
		}
	}
	return status;
}

static int nbl_calc_send_wqe(struct ib_qp_init_attr *init_attr)
{
	int size = 0; /*wqe size*/
	int inline_size = 0; /*inline wqe size*/
	int tot_size = 0;

	if (init_attr->cap.max_inline_data) {
		inline_size = init_attr->cap.max_inline_data +
			      NBL_WQE_CTRL_SIZE + NBL_WQE_RADDR_SIZE;
		inline_size = ALIGN(inline_size, NBL_MIN_WQE_SIZE);
	}

	if (init_attr->qp_type == IB_QPT_RC)
		init_attr->cap.max_inline_data = NBL_MAX_WRITE_INLINE;
	else if (init_attr->qp_type == IB_QPT_UD)
		init_attr->cap.max_inline_data = 0;

	size += NBL_WQE_CTRL_SIZE + NBL_WQE_RADDR_SIZE;
	size += init_attr->cap.max_send_sge * sizeof(struct nbl_wqe_data_seg);
	size = ALIGN(size, NBL_MIN_WQE_SIZE);

	tot_size = max(size, inline_size);
	if (tot_size > NBL_MAX_WQE_SIZE) {
		pr_err("tot_size :%d, cap inlie:%d, cap max_send_sge :%d\n",
		       tot_size, init_attr->cap.max_inline_data,
		       init_attr->cap.max_send_sge);
		return -EINVAL;
	}
	return tot_size;
}

static void nbl_calc_rqwqe_size(struct nbl_uk_qp *uk_qp, __u32 max_sge)
{
	__u32 size;

	size = NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE +
	       max_t(uint32_t, max_sge, MIN_WR_SGE) * NBL_WQE_DATA_SIZE;
	size = roundup_pow_of_two(size);
	uk_qp->rq_wqe_size_multiplier = size / NBL_MIN_WQE_SIZE;
	uk_qp->rq_wqe_size = size;
}
/**
 * nbl_create_kmode_qp - create kernal mode qp
 * @nbldev: nbl_device
 * @qp: nbl_qp
 * @sq_wr_size: the wr size of sq
 * @rq_wr_size: the wr size of rq
 * return 0 if success, otherwise return error
 */
int nbl_create_kmode_qp(struct nbl_device *nbldev, struct nbl_qp *qp,
			struct ib_qp_init_attr *init_attr)
{
	enum nbl_status_code status;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	int ret = 0;
	int wqe_size;
	int sqdepth, rqdepth;

	wqe_size = nbl_calc_send_wqe(init_attr);
	if (wqe_size < 0)
		return -EINVAL;

	sqdepth = (init_attr->cap.max_send_wr + NBL_SQ_RSVD) * wqe_size;
	sqdepth = roundup_pow_of_two(sqdepth);
	uk_qp->safe_rsv = (NBL_SQ_RSVD * wqe_size) / NBL_MIN_WQE_SIZE;

	if (sqdepth < NBL_MIN_QP_DEPTH)
		sqdepth = NBL_MIN_QP_DEPTH;
	uk_qp->max_send_wr = sqdepth / NBL_MIN_WQE_SIZE;

	if (uk_qp->max_send_wr > NBL_MAX_QP_WR) {
		pr_err("inv sq_wqe_cnt:%d, wqe_size: %d, max_send_wr :%d\n",
		       uk_qp->max_send_wr, wqe_size,
		       init_attr->cap.max_send_wr);
		return -EINVAL;
	}
	nbl_calc_rqwqe_size(uk_qp, init_attr->cap.max_recv_sge);
	if (uk_qp->rq_wqe_size > NBL_MAX_WQE_SIZE) {
		pr_err("rq_wqe_size: %d, max_recv_sge :%d\n",
		       uk_qp->rq_wqe_size, init_attr->cap.max_recv_sge);
		return -EINVAL;
	}
	rqdepth =
		(init_attr->cap.max_recv_wr + NBL_RQ_RSVD) * uk_qp->rq_wqe_size;
	rqdepth = roundup_pow_of_two(rqdepth);
	if (rqdepth < NBL_MIN_QP_DEPTH)
		rqdepth = NBL_MIN_QP_DEPTH;
	uk_qp->max_recv_wr = rqdepth / NBL_MIN_WQE_SIZE;
	if (uk_qp->max_recv_wr > NBL_MAX_QP_WR) {
		pr_err("inv rq_wqe_cnt:%d, rq wqe_size: %d, max_recv_wr :%d\n",
		       uk_qp->max_recv_wr, uk_qp->rq_wqe_size,
		       init_attr->cap.max_recv_wr);
		return -EINVAL;
	}

	qp->kqp.sq_wrid_mem = kcalloc(uk_qp->max_send_wr,
				      sizeof(*qp->kqp.sq_wrid_mem), GFP_KERNEL);
	qp->kqp.rq_wrid_mem = kcalloc(uk_qp->max_recv_wr,
				      sizeof(*qp->kqp.rq_wrid_mem), GFP_KERNEL);

	status = nbl_alloc_kmode_qp_buffer(qp, nbldev, &sc_qp->sqbuf, sqdepth,
					   true);
	if (status) {
		nbl_ib_err(&nbldev->rf->sc_dev,
			   "alloc nbl kmode sqbuf failed, status is %d.\n", status);
		ret = status;
		goto free_rq_wrid_mem;
	}

	status = nbl_alloc_kmode_qp_buffer(qp, nbldev, &sc_qp->rqbuf, rqdepth,
					   false);
	if (status) {
		nbl_ib_err(&nbldev->rf->sc_dev,
			   "alloc nbl kmode rqbuf failed, status is %d.\n", status);
		ret = status;
		goto free_sq_buf;
	}

	/* express size as a power of 2, the unit of sq_size and rq_size is a block (64Byte) */
	uk_qp->sq_size = ilog2(sqdepth >> 6);
	uk_qp->rq_size = ilog2(rqdepth >> 6);

	uk_qp->sq_wrtrk_array = qp->kqp.sq_wrid_mem;
	uk_qp->rq_wrid_array = qp->kqp.rq_wrid_mem;

	uk_qp->sq_base = sc_qp->sqmem.va;
	uk_qp->rq_base = sc_qp->rqmem.va;
	qp->user_mode = 0;
	qp->ctx_info.qp_completion_ctx = uk_qp->qpn;

	NBL_RING_INIT(uk_qp->sq_ring, uk_qp->max_send_wr);
	NBL_RING_INIT(uk_qp->rq_ring, uk_qp->max_recv_wr);

	INIT_DELAYED_WORK(&qp->dwork_flush, nbl_flush_dworker);
	qp->first_4a = false;
	qp->first_4b = false;

	return ret;

free_sq_buf:
	nbl_free_kmode_qp_buffer(qp, nbldev, &sc_qp->sqbuf, true);
free_rq_wrid_mem:
	kfree(qp->kqp.rq_wrid_mem);
	qp->kqp.rq_wrid_mem = NULL;
	kfree(qp->kqp.sq_wrid_mem);
	qp->kqp.sq_wrid_mem = NULL;
	return ret;
}

int nbl_alloc_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			      struct nbl_ib_qp_buf *q_buf, int q_size,
			      bool is_sq)
{
	struct nbl_dma_mem *mem;
	int status = 0;

	mem = is_sq ? &qp->sc_qp.sqmem : &qp->sc_qp.rqmem;
	mem->size = ALIGN(round_up(q_size, NBL_QP_QUEUE_ALIGN_SIZE),
			  NBL_QP_QUEUE_ALIGN_SIZE);
	mem->va = nbl_dma_alloc_coherent(dev->rf->sc_dev.hw->device, mem->size,
					 &mem->pa, GFP_KERNEL);
	q_buf->frag_buf.size = mem->size;
	if (mem->va) {
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL0_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL0_PAGE_MODE;
		/*if alloc sq buff is connitue, we use 0/2m mode, sq max size < 2m*/
		q_buf->frag_buf.npages = NBL_SQRQ_2M_PAGE_NUM;
	} else {
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL1_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL1_PAGE_MODE;

		q_buf->frag_buf.npages = DIV_ROUND_UP(mem->size, NBL_ADAPTER_PAGE_SIZE);
		status =
			nbl_frag_buf_alloc(dev->rf->sc_dev.hw->device, &mem->va,
					   &mem->pa, &q_buf->frag_buf);
	}

	return status;
}

void nbl_free_user_qp_buffer(struct nbl_pci_f *rf,
				struct nbl_sc_qp *sc_qp)
{
	if (sc_qp->sqrq_one_pd) {
		dma_free_coherent(rf->sc_dev.hw->device, sc_qp->sqrq_pdsize,
					sc_qp->sqmem.va, sc_qp->sqmem.pa);
		ib_umem_release(sc_qp->sqbuf.umem);
		ib_umem_release(sc_qp->rqbuf.umem);
	} else {
		if (sc_qp->sqmem.va) {
			if (sc_qp->sq_pm == NBL_LEVEL1_PAGE_MODE)
				dma_free_coherent(rf->sc_dev.hw->device, sc_qp->sq_pdsize,
							sc_qp->sqmem.va, sc_qp->sqmem.pa);
			ib_umem_release(sc_qp->sqbuf.umem);
		}

		if (sc_qp->rqmem.va) {
			if (sc_qp->rq_pm == NBL_LEVEL1_PAGE_MODE)
				dma_free_coherent(rf->sc_dev.hw->device, sc_qp->rq_pdsize,
							sc_qp->rqmem.va, sc_qp->rqmem.pa);
			ib_umem_release(sc_qp->rqbuf.umem);
		}
	}
}

void nbl_free_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			     struct nbl_ib_qp_buf *q_buf, bool is_sq)
{
	struct nbl_dma_mem *mem;
	bool page_mode;

	mem = is_sq ? &qp->sc_qp.sqmem : &qp->sc_qp.rqmem;
	page_mode = is_sq ? qp->sc_qp.sq_pm : qp->sc_qp.rq_pm;

	if (!page_mode)
		dma_free_coherent(dev->rf->sc_dev.hw->device, mem->size,
				  mem->va, mem->pa);
	else
		nbl_frag_buf_free(dev->rf->sc_dev.hw->device, mem->va, mem->pa,
				  &q_buf->frag_buf);
}

void nbl_fill_qpc_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	__u64 *temp_addr;
	__u64 pd_entry;

	/* used by CC RAM0 */
	ctx_info->cc_oamreq_tc_en =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMREQ_TC_EN];
	ctx_info->cc_oamreq_net_tc =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMREQ_NET_TC];
	ctx_info->cc_oamack_tc_en =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMACK_TC_EN];
	ctx_info->cc_oamack_net_tc =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMACK_NET_TC];
	ctx_info->cc_oamack_blk_th =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMACK_BLK_TH];
	ctx_info->cc_targetwin_min =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_TARGETWIN_MIN];
	ctx_info->cc_mode = rf->sc_dev.cc_mode;
	ctx_info->cc_pkt_num_en =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_PKT_NUM_EN];
	ctx_info->cc_rtt_qp_mult =
		rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_CMP_RTT_QP_MULT];

	/* used by CC RAM1~3 */
	ctx_info->qcn_limit_rp = rf->sc_dev.cc_dbgfs_params[NBL_CFG_QCN_START_RATE] *
		QCN_RP_LIMIT_RATE_PERIOD / QCN_RP_LIMIT_RATE_PERIOD_FACTOR;
	ctx_info->qcn_target_rp = ctx_info->qcn_limit_rp;
	ctx_info->qcn_remain_trans_bits = 0;
	ctx_info->qcn_first_recdb_flag = true;
	if (ctx_info->cc_mode == NBL_CC)
		ctx_info->targetwin =
			rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_TARGETWIN];
	ctx_info->qcn_sendpkt_tarwin = 0;
	ctx_info->qcn_main_status = 1;

	ctx_info->vfid = qp->nbldev->rf->sc_dev.function_id;
	ctx_info->host_id = host_id;
	ctx_info->qp_st = qp->qp_state;
	ctx_info->service_type = uk_qp->nbl_qp_service_type;

	ctx_info->dma_len_max = NBL_DMA_LEN_MAX;
	ctx_info->sq_size = uk_qp->sq_size;
	ctx_info->rq_size = uk_qp->rq_size;
	ctx_info->ackreq_th = rf->sc_dev.ackreq_th;
	ctx_info->seq_num = uk_qp->seq_num;

	ctx_info->p_key = NBL_DEFAULT_PKEY;

	ctx_info->qpn = uk_qp->qpn;
	if (ctx_info->qpn == 1)
		ctx_info->qp1_mode = true;
	ctx_info->irq_ba = (sc_qp->irq_mem.pa >> NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->pd_idx = qp->nblpd->sc_pd.pd_id;
	ctx_info->swrqpi_th = NBL_DEFAULT_SWRQPI_TH;
	ctx_info->orq_ba = (sc_qp->orq_mem.pa >> NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->raq_ba = (sc_qp->raq_mem.pa >> NBL_ADAPTER_PAGE_SHIFT);

	ctx_info->unaq_ba = (sc_qp->unaq_mem.pa >> NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->sq_cqn = qp->scq->cq_num;
	ctx_info->rq_cqn = qp->rcq->cq_num;
	ctx_info->shadow_area_ba = ((sc_qp->qp_shadow.pa) >> 9);
	ctx_info->sq_pd_ba = (sc_qp->sqmem.pa >> NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->rq_pd_ba = (sc_qp->rqmem.pa >> NBL_ADAPTER_PAGE_SHIFT);
	if (sc_qp->sq_pm) {
		temp_addr = sc_qp->sqmem.va;
		pd_entry = temp_addr[0];
		pd_entry = be64_to_cpu(pd_entry);
		ctx_info->txp_sq_cur_pd_pa =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT);

		pd_entry = temp_addr[1];
		pd_entry = be64_to_cpu(pd_entry);
		ctx_info->txp_sq_nxt_pd_pa =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT);
	} else {
		ctx_info->txp_sq_cur_pd_pa = ctx_info->sq_pd_ba;
	}

	if (sc_qp->rq_pm) {
		temp_addr = sc_qp->rqmem.va;
		pd_entry = temp_addr[1];
		pd_entry = be64_to_cpu(pd_entry);
		ctx_info->rxp_rq_nxt_pd_pa_l =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT) & 0xFFFF;
		ctx_info->rxp_rq_nxt_pd_pa_h =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT) >> 16;

		pd_entry = temp_addr[0];
		pd_entry = be64_to_cpu(pd_entry);

		ctx_info->rxp_rq_cur_pd_pa_l =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT) & 0xFF;
		ctx_info->rxp_rq_cur_pd_pa_h =
			(pd_entry >> NBL_ADAPTER_PAGE_SHIFT) >> 8;
	} else {
		ctx_info->rxp_rq_cur_pd_pa_l =
			(qp->sc_qp.rqmem.pa >> NBL_ADAPTER_PAGE_SHIFT) & 0xFF;
		ctx_info->rxp_rq_cur_pd_pa_h =
			(qp->sc_qp.rqmem.pa >> NBL_ADAPTER_PAGE_SHIFT) >> 8;
	}

	ctx_info->ceaq_sq_th = NBL_DEFAULT_CEAQ_SQ_TH;
	ctx_info->ceaq_rq_th = NBL_DEFAULT_CEAQ_RQ_TH;
	if ((uk_qp->qp_type == IB_QPT_GSI) && rf->sc_dev.stat_id)
		ctx_info->stat_id = rf->sc_dev.stat_id + NBL_DEFAULT_CM_STAT_ID_OFFSET;
	else
		ctx_info->stat_id = rf->sc_dev.stat_id;
	ctx_info->dport = rf->sc_dev.dport;
	ctx_info->dport_id = rf->sc_dev.dport_id;
	ctx_info->fwd = rf->sc_dev.fwd;
	ctx_info->rss_lag_en = rf->sc_dev.rss_lag_en;
	ctx_info->tunnel_en =  rf->sc_dev.tunnel_en;
	ctx_info->tver = NBL_DEFAULT_TVER;
	ctx_info->mig = NBL_DEFAULT_MIG;
	if (!qp->user_mode) {
		ctx_info->txmr_frmr_en = true;
		/* only kernel QP enable FMR */
		ctx_info->fmr_nofence = rf->sc_dev.fmr_nofence;
		qp->sc_qp.uk_qp.fmr_nofence = ctx_info->fmr_nofence;
	}
	ctx_info->sq_pm = sc_qp->sq_pm;
	ctx_info->rq_pm = sc_qp->rq_pm;
	if (qp->sc_qp.uk_qp.rq_wqe_size == NBL_MIN_RQ_WQE_SIZE)
		ctx_info->rq_wqe_size = NBL_QPC_MIN_RQ_WQE_SIZE;
	else
		ctx_info->rq_wqe_size = NBL_QPC_MAX_RQ_WQE_SIZE;
	ctx_info->sq_ce_en = uk_qp->sig_all;
	ctx_info->wqe_prefetch_en = NBL_DEFAULT_WQE_PREFETCH;
	ctx_info->default_wqe_cap = NBL_DEFAULT_WQE_CAP;
	ctx_info->sport_id = rf->vsi_id;
	ctx_info->vlan_tag = NBL_DEFAULT_VLAN_TAG;
	ctx_info->irq_size = ilog2(rf->nbl_actual_rd_atom);
	ctx_info->local_rnr_timer_value = NBL_DEFAULT_RNR_TIMER;
	ctx_info->rto_timer_value = NBL_DEFAULT_RTO_TIMER;
	ctx_info->rnr_retry = NBL_DEFAULT_RNR_RETRY_TH;
}

int nbl_cqp_create_qp_cmd(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	int ret = 0;
	u64 temp;
	__be64 *in;

	u32 in_size = NBL_CMD_INPUT_SIZE;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;
	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CREATE_QP_CMD_CODE) |
	       FIELD_PREP(NBL_CQP_NEXT_QP_STATE, NBL_QP_STATE_RST) |
	       FIELD_PREP(NBL_CQP_QP_TYPE, qp->sc_qp.uk_qp.nbl_qp_service_type) |
	       FIELD_PREP(NBL_CQP_QP_ID, qp->sc_qp.uk_qp.qpn);

	set_64bit_val(in, 0, temp);

	temp = FIELD_PREP(NBL_CQP_QP_CONTEXT_ADDRESS, qp->sc_qp.qp_ctx_mem.pa);
	set_64bit_val(in, 8, temp);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);
	return ret;
}

int nbl_cqp_destroy_qp_cmd(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	u64 temp;
	int ret = 0;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_DESTROY_QP_CMD_CODE) |
	       FIELD_PREP(NBL_CQP_QP_ID, qp->sc_qp.uk_qp.qpn);

	set_64bit_val(in, 0, temp);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);

	kfree(in);

	return ret;
}

/**
 * nbl_modify_hw_qpc - modify qpc and send cqp to hw
 * Only for qpc info that can`t modify by ib_modify_qp
 * @qp: nbl_qp
 * @ctx_info: ctx_info with data you want to change
 * @qpc_mask: nbl additional qpc mask
 */
int nbl_modify_hw_qpc(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
		      int qpc_mask)
{
	u8 next_qp_state;
	unsigned long flags;

	next_qp_state = qp->qp_state;
	spin_lock_irqsave(&qp->lock, flags);

	switch (qpc_mask) {
	case NBL_QPC_STAT_ID_MASK:
		qp->ctx_info.stat_id = ctx_info->stat_id;
		break;
	case NBL_QPC_OAMREQ_TC_EN_MASK:
		qp->ctx_info.cc_oamreq_tc_en = ctx_info->cc_oamreq_tc_en;
		break;
	case NBL_QPC_OAMREQ_NET_TC_MASK:
		qp->ctx_info.cc_oamreq_net_tc = ctx_info->cc_oamreq_net_tc;
		break;
	case NBL_QPC_OAMACK_TC_EN_MASK:
		qp->ctx_info.cc_oamack_tc_en = ctx_info->cc_oamack_tc_en;
		break;
	case NBL_QPC_OAMACK_NET_TC_MASK:
		qp->ctx_info.cc_oamack_net_tc = ctx_info->cc_oamack_net_tc;
		break;
	case NBL_QPC_OAMACK_BLK_TH_MASK:
		qp->ctx_info.cc_oamack_blk_th = ctx_info->cc_oamack_blk_th;
		break;
	case NBL_QPC_TARGETWIN_MIN_MASK:
		qp->ctx_info.cc_targetwin_min = ctx_info->cc_targetwin_min;
		break;
	case NBL_QPC_CC_MODE_MASK:
		qp->ctx_info.cc_mode = ctx_info->cc_mode;
		break;
	case NBL_QPC_CC_PKT_NUM_EN_MASK:
		qp->ctx_info.cc_pkt_num_en = ctx_info->cc_pkt_num_en;
		break;
	case NBL_QPC_CC_CMP_RTT_QP_MULT_MASK:
		qp->ctx_info.cc_rtt_qp_mult = ctx_info->cc_rtt_qp_mult;
		break;
	default:
		spin_unlock_irqrestore(&qp->lock, flags);
		nbl_pr_err("unsupport qpc_mask:%d\n", qpc_mask);
		return -EINVAL;
	}

	/* add additional mask here */

	nbl_set_qp_ctx(qp, qp->sc_qp.qp_ctx_mem.va);
	spin_unlock_irqrestore(&qp->lock, flags);

	return nbl_cqp_modify_qp_cmd(qp->nbldev, qp, next_qp_state);
}

int nbl_cqp_flush_s1_cache_cmd(struct nbl_qp *qp)
{
	int ret = 0;
	__be64 *in;
	u64 temp;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_FLUSH_CACHE) |
	       FIELD_PREP(NBL_CQP_FLUASH_CACHE_TYPE, FLUSH_CACHE_S1) |
	       FIELD_PREP(NBL_CQP_FLUASH_CACHE_QPN, qp->sc_qp.uk_qp.qpn);

	set_64bit_val(in, 0, temp);
	set_64bit_val(in, 8, FIELD_PREP(NBL_CQP_FLUASH_CACHE_VFID, rf->sc_dev.function_id));

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	kfree(in);
	return ret;
}

int nbl_cqp_flush_sqrq_cache_cmd(struct nbl_qp *qp)
{
	int ret = 0;
	__be64 *in;
	u64 temp;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_FLUSH_CACHE) |
	       FIELD_PREP(NBL_CQP_FLUASH_CACHE_TYPE, FLUSH_CACHE_SQRQC) |
	       FIELD_PREP(NBL_CQP_FLUASH_CACHE_QPN, qp->sc_qp.uk_qp.qpn);

	set_64bit_val(in, 0, temp);
	set_64bit_val(in, 8, FIELD_PREP(NBL_CQP_FLUASH_CACHE_VFID, rf->sc_dev.function_id));

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	kfree(in);
	return ret;
}

int nbl_dump_hmc_qpc(struct nbl_device *nbl_dev, u32 dump_mask)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_ctx_hmc_base_info hmc_info;
	struct nbl_func_file *func_file = &nbl_dev->func_dump_info->dump_func_file;
	u32 num_one_page; /* how many qpc in one page */
	u32 offset;
	u32 qpn;
	int ret;

	qpn = dump_mask & NBL_QPN_MASK;
	if (qpn >= rf->max_qp) {
		nbl_ib_err(sc_dev, "[qpc] dump qpc with wrong qpn(%u)\n", qpn);
		return -EFAULT;
	}

	ret = nbl_get_qpc_base_addr(qpn, &hmc_info, rf->qp_sd_info);
	if (ret) {
		nbl_ib_err(sc_dev, "[qpc] get nbl qpc base addr failed.\n");
		return -EFAULT;
	}

	num_one_page = (hmc_info.page_size / hmc_info.ctx_size);
	offset = ((qpn % num_one_page) * hmc_info.ctx_size);

	nbl_ib_err(sc_dev,
		   "[qpc] dump qpn(%u) qpc(sd va %p, 0x%llx, offset 0x%x)", qpn,
		   hmc_info.va, (u64)((uintptr_t)hmc_info.va), offset);
	nbl_dump_hex(rf, (hmc_info.va + offset), hmc_info.ctx_size);
	nbl_dump_fields(func_file, (hmc_info.va + offset), NBL_DBG_DUMP_QPC);
	return 0;
}

int nbl_dbg_create_qp(struct nbl_pci_f *rf, u32 qpn_input)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_dma_mem data_buf;
	u8 *ptr;
	u32 qpn;
	int ret;
	u64 temp;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;

	qpn = qpn_input & NBL_QPN_MASK;
	if (qpn >= rf->max_qp) {
		nbl_ib_err(
			sc_dev,
			"[dbg qp] create with wrong qpn(%u), max qpn is(%u)\n",
			qpn, rf->max_qp);
		return -EFAULT;
	}

	data_buf.size = SZ_4K;
	data_buf.va =
		nbl_dma_alloc_coherent(sc_dev->hw->device, data_buf.size,
				       &data_buf.pa, GFP_KERNEL | __GFP_ZERO);
	if (!data_buf.va)
		return -ENOMEM;

	memset(data_buf.va, 0xff, data_buf.size);
	ptr = (u8 *)data_buf.va;
	ptr[0] = 0x80;
	ptr[1] = 0x00;
	ptr[2] = 0x00;
	ptr[3] = ((qpn >> 16) & 0xff);
	ptr[4] = ((qpn >> 8) & 0xff);
	ptr[5] = (qpn & 0xff);

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(sc_dev->hw->device, data_buf.size,
				  data_buf.va, data_buf.pa);
		return -ENOMEM;
	}
	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CREATE_QP_CMD_CODE) |
	       FIELD_PREP(NBL_CQP_NEXT_QP_STATE, 0) |
	       FIELD_PREP(NBL_CQP_QP_TYPE, 0) | FIELD_PREP(NBL_CQP_QP_ID, qpn);
	set_64bit_val(in, 0, temp);

	temp = FIELD_PREP(NBL_CQP_QP_CONTEXT_ADDRESS, data_buf.pa);
	set_64bit_val(in, 8, temp);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);
	if (ret)
		nbl_ib_err(sc_dev, "[dbg qp] create qp(%u) cmd err\n", qpn);

	kfree(in);
	dma_free_coherent(sc_dev->hw->device, data_buf.size, data_buf.va,
			  data_buf.pa);

	return ret;
}

int nbl_dbg_destroy_qp(struct nbl_pci_f *rf, u32 qpn_input)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	u64 temp;
	int ret = 0;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;
	u32 qpn;

	qpn = qpn_input & NBL_QPN_MASK;
	if (qpn >= rf->max_qp) {
		nbl_ib_err(
			sc_dev,
			"[dbg qp] destroy with wrong qpn(%u), max qpn is(%u)\n",
			qpn, rf->max_qp);
		return -EFAULT;
	}

	in = kzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	temp = FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_DESTROY_QP_CMD_CODE) |
	       FIELD_PREP(NBL_CQP_QP_ID, qpn);

	set_64bit_val(in, 0, temp);
	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);
	if (ret)
		nbl_ib_err(sc_dev, "[dbg qp] destroy qp(%u) cmd err\n", qpn);

	kfree(in);

	return ret;
}

void nbl_modify_qp_fwd(struct nbl_pci_f *rf)
{
	int ret;
	int i;
	int attr_mask = IB_QP_STATE;
	struct nbl_qp *qp;
	struct nbl_qp_ctx *ctx_info;
	struct ib_qp_attr attr = {0};
	u8 rdma_dump_flag;

	attr.qp_state = IB_QPS_RTS;

	for (i = 1; i < rf->max_qp; i++) {
		qp = rf->qp_table[i];
		rdma_dump_flag = rf->sc_dev.fwd == NBL_NORMAL_FWD ? 1 : 0;
		if (qp) {
			ctx_info = &qp->ctx_info;
			ctx_info->fwd = rf->sc_dev.fwd;
			set_64bit_val(qp->sc_qp.qp_shadow.va, 0,
				FIELD_PREP(NBL_QPC_SHADOW_ENABLE_RDMA_DUMP_FLAG, rdma_dump_flag));
			ret = nbl_ib_modify_qp(&qp->ibqp, &attr, attr_mask, NULL);
			if (ret)
				nbl_ib_err(&rf->sc_dev, "modify qp[%u] fwd ret=%d",
					   qp->sc_qp.uk_qp.qpn, ret);
		}
	}
}
