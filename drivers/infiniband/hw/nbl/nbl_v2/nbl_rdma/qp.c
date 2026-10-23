// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/crc32.h>
#include <rdma/nbl-v2-abi.h>
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
#include "rdma_dump_hw.h"
#include "device.h"
#include "srq.h"

/* cc rate:Mbps rtt:us */
#define QCN_RP_LIMIT_RATE_PERIOD 128
#define QCN_RP_LIMIT_RATE_PERIOD_FACTOR 100

/* TQP time maybe 4 times of stand val, so here
 * we need to decrese rto value to balanse this
 * here rto 16,17,18,19,20,21,22,23,24,25,26 has
 * decrease to half or a quarter of its std value
 */
int rto_arry[NBL_RTO_ARRY_MAX_SIZE] = {
	4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 6, 8, 9, 10, 11,
	11, 11, 12, 13, 14, 15, 16, 17,
	18, 23, 24, 25, 25, 25, 25, 25,
};

static void nbl_dump_qpc_hex(struct nbl_pci_f *rf, u32 qpn, u8 *buf, int len)
{
	int ix = 0;

	while (ix < len) {
		dev_err(rf->sc_dev.hw->device,
			"qp[%d][%d-%d]%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
			qpn, ix, ix + 15, buf[ix], buf[ix + 1], buf[ix + 2],
			buf[ix + 3], buf[ix + 4], buf[ix + 5], buf[ix + 6],
			buf[ix + 7], buf[ix + 8], buf[ix + 9], buf[ix + 10],
			buf[ix + 11], buf[ix + 12], buf[ix + 13], buf[ix + 14],
			buf[ix + 15]);
		ix += 16;
	}
}

static void nbl_debug_query_cache_qpc(struct nbl_qp *qp)
{
	int err_code;
	struct nbl_dma_mem qpc_mem;
	__be64 *in;
	u32 qpn = qp->sc_qp.uk_qp.qpn;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	qpc_mem.size = NBL_QP_CTX_SIZE;
	qpc_mem.va = nbl_dma_alloc_coherent(rf->sc_dev.hw, qpc_mem.size,
					    &qpc_mem.pa, GFP_KERNEL);
	if (!qpc_mem.va)
		return;
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(rf->sc_dev.hw->device, qpc_mem.size,
				  qpc_mem.va, qpc_mem.pa);
		return;
	}

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_QP);
	nbl_64bit_write(in, NBL_CQP_QPN, qpn);
	nbl_64bit_write(in, NBL_CQP_QP_CTX_ADDR, qpc_mem.pa);

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		goto out;
	nbl_dump_qpc_hex(rf, qpn, qpc_mem.va, NBL_QP_CTX_SIZE);
out:
	kfree(in);
	dma_free_coherent(rf->sc_dev.hw->device, qpc_mem.size, qpc_mem.va,
			  qpc_mem.pa);
}

static void nbl_flush_wqe_worker(struct work_struct *work)
{
	struct flush_work *fwork = container_of(work, struct flush_work, work);
	struct nbl_qp *qp = fwork->qp;
	struct ib_event ib_event;
	unsigned long flags;
	u32 ae_id = fwork->ae_id;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	kfree(fwork);

	spin_lock_irqsave(&qp->lock, flags);

	if (qp->flush_issued) {
		nbl_qp_rem_ref(&qp->ibqp);
		spin_unlock_irqrestore(&qp->lock, flags);
		return;
	}

	spin_unlock_irqrestore(&qp->lock, flags);

	if (ae_id == rf->sc_dev.debug_errcdoe) {
		nbl_debug_query_cache_qpc(qp);
		if (qp->sc_qp.uk_qp.use_srq)
			nbl_debug_query_cache_srqc(rf, qp->sc_qp.uk_qp.srqn);
	}
	nbl_modify_qp_to_err(qp, NULL);

	if (qp->ibqp.event_handler) {
		ib_event.event = IB_EVENT_QP_FATAL;
		ib_event.device = qp->ibqp.device;
		ib_event.element.qp = &qp->ibqp;
		qp->ibqp.event_handler(&ib_event, qp->ibqp.qp_context);
	}
	nbl_qp_rem_ref(&qp->ibqp);
}

void nbl_flush_work(struct nbl_qp *qp, u32 ae_id)
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
	fwork->ae_id = ae_id;
	INIT_WORK(&fwork->work, nbl_flush_wqe_worker);
	queue_work(nbldev->rf->flush_wq, &fwork->work);
}

static u8 ib_qp_type_to_nbl(u8 ib_qp_type)
{
	u8 nbl_type;

	switch (ib_qp_type) {
	case IB_QPT_XRC_INI:
		nbl_type = NBL_QPT_INI;
		break;
	case IB_QPT_XRC_TGT:
		nbl_type = NBL_QPT_TGT;
		break;
	default:
		nbl_type = NBL_QPT_OTHER;
		break;
	}

	return nbl_type;
}

static inline enum ib_mtu nbl_mtu_to_ib(enum nbl_mtu mtu)
{
	if (mtu < NBL_MTU_256 || mtu > NBL_MTU_8192) {
		nbl_pr_err("invalid nbl mtu\n");
		return IB_MTU_INVALID_NBL;
	}
	return mtu + 1;
}

static inline int nbl_mtu_emu_to_init(enum nbl_mtu mtu)
{
	switch (mtu) {
	case NBL_MTU_256:
		return 256;
	case NBL_MTU_512:
		return 512;
	case NBL_MTU_1024:
		return 1024;
	case NBL_MTU_2048:
		return 2048;
	case NBL_MTU_4096:
		return 4096;
	case NBL_MTU_8192:
		return 8192;
	default:
		return IB_MTU_INVALID_NBL;
	}
}

int nbl_get_mtu(struct nbl_qp_ctx *ctx_info,
			      struct nbl_device *nbldev, enum ib_mtu user_mtu)
{
	int active_mtu = 0;
	int rdma_mtu;
	int eth_mtu;

	rdma_mtu = nbl_mtu_emu_to_init(IB_MTU_TO_NBL(user_mtu));
	eth_mtu = nbldev->netdev->mtu -
		  (IB_GRH_BYTES + IB_UDP_BYTES + IB_BTH_BYTES +
		   IB_EXT_XRC_BYTES + IB_EXT_ATOMICETH_BYTES + IB_ICRC_BYTES);

	if (rdma_mtu > eth_mtu) {
		/* adjust rdma mtu  according to the eth atcive_mtu*/
		active_mtu = iboe_get_mtu(nbldev->netdev->mtu);
		if (!active_mtu) {
			pr_err("inv netdev->mtu:%d\n", nbldev->netdev->mtu);
			return -EINVAL;
		}
		ctx_info->pmtu = IB_MTU_TO_NBL(active_mtu);
	} else {
		ctx_info->pmtu = IB_MTU_TO_NBL(user_mtu);
	}
	return 0;
}

static int nbl_cqp_flush_wqe_cmd(struct nbl_qp *qp)
{
	int ret = 0;
	__be64 *in;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_QP_FLUSH_WQE);
	nbl_64bit_write(in, NBL_CQP_QP_SQEN, true);
	nbl_64bit_write(in, NBL_CQP_QP_RQEN, true);

	nbl_64bit_write(in, NBL_CQP_OP_HOST_ID, rf->product->host_id);
	nbl_64bit_write(in, NBL_CQP_OP_VF_ID, rf->sc_dev.function_id);
	nbl_64bit_write(in, NBL_CQP_OP_FLUSH_QPN, qp->sc_qp.uk_qp.qpn);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&qp->nbldev->rf->sc_dev,
			   "CQP QP FLUSH WQE failed(%d)\n", ret);

	kfree(in);
	return ret;
}

/** nbl_flush_operation - flush operation will continux even meet error.
 * @qp: qp struct
 * @nbldev: nbl device struct
 */
void nbl_flush_operation(struct nbl_qp *qp, struct nbl_device *nbldev)
{
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_uk_qp *ukqp = &qp->sc_qp.uk_qp;
	unsigned long qp_leave_time;
	unsigned long timeout = msecs_to_jiffies(FLUSH_TIME_OUT);
	int ret;

	if (rf->rdma_reset)
		return;

	ret = nbl_cqp_flush_wqe_cmd(qp);
	if (ret)
		nbl_pr_err("flush wqe cqp err, QPN %u, cmd return:%d\n",
			ukqp->qpn, ret);
	else {
		qp_leave_time =
			wait_for_completion_timeout(&qp->flush_qp, timeout);
		if (unlikely(!qp_leave_time))
			nbl_pr_err("wait for flush_qp timeout(vfid 0x%x, QPN %u)\n",
				rf->sc_dev.function_id, ukqp->qpn);
	}

	/* flush cache */
	ret = nbl_cqp_v2_flush_s1_cache_cmd(ukqp->qpn, rf->sc_dev.function_id, rf, false);
	if (ret)
		nbl_pr_err("flush s1 cache cqp err, QPN %u, cmd return:%d\n",
			ukqp->qpn, ret);

	if ((NBL_RF_TO_HW_VER(rf) == NBL_VER_4) &&
		(ukqp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_SRP))
		nbl_flush_pdc_cache(rf, rf->sc_dev.function_id);

#if NBL_DIRECT_WQE_EN
	ret = nbl_cqp_flush_sqrq_cache_cmd(qp);
	if (ret)
		nbl_pr_err("flush sqrq cache cqp failed, QPN %u, cmd return:%d\n",
			ukqp->qpn, ret);
#endif
}

static int nbl_get_ddr_qpc_shdw_addr(u32 qp_num,
				struct nbl_ctx_hmc_base_info *hmc_info,
				struct nbl_hmc_obj_sd_info *qp_sd_info)
{
	u32 num_one_page; /* how many qpc in one page */
	u32 page_index; /* page index that qpc located */
	u32 qpc_index;
	struct nbl_hmc_obj_sd_addr *sd;

	/* 4K/32 = 128 */
	num_one_page = qp_sd_info->page_sz / NBL_QP_SHADOW_SIZE;

	/* get page index, for qpn=17 we got 2 */
	page_index = qp_num / num_one_page;
	if (page_index >= qp_sd_info->cnt) {
		nbl_pr_err("invalid page_index, the page_index is %u.\n",
			   page_index);
		return -EFAULT;
	}
	qpc_index = qp_num % num_one_page;

	sd = &qp_sd_info->sd_addr[page_index];

	hmc_info->va = sd->va;
	hmc_info->pa = sd->dma_addr;
	hmc_info->ctx_size = NBL_QP_CTX_SIZE;
	hmc_info->shadow_offset = (qpc_index * NBL_QP_SHADOW_SIZE);
	hmc_info->shadow_size = NBL_QP_SHADOW_SIZE;
	hmc_info->page_size = qp_sd_info->page_sz;

	return 0;
}

int nbl_get_qpc_base_addr(struct nbl_pci_f *rf, u32 qp_num,
				 struct nbl_ctx_hmc_base_info *hmc_info,
				 struct nbl_hmc_obj_sd_info *qp_sd_info)
{
	u32 num_one_page; /* how many qpc in one page */
	u32 page_index; /* page index that qpc located */
	u32 qpc_index;
	struct nbl_hmc_obj_sd_addr *sd;

	if (rf->sc_dev.ddr_mode_en)
		return nbl_get_ddr_qpc_shdw_addr(qp_num, hmc_info, qp_sd_info);

	/* for 4K, here we got 8 */
	num_one_page = qp_sd_info->page_sz / NBL_QP_CTX_SIZE;

	/* get page index, for qpn=17 we got 2 */
	page_index = qp_num / num_one_page;
	if (page_index >= qp_sd_info->cnt) {
		nbl_pr_err("invalid page_index, the page_index is %u.\n",
			   page_index);
		return -EFAULT;
	}
	qpc_index = qp_num % num_one_page;

	sd = &qp_sd_info->sd_addr[page_index];

	hmc_info->va = sd->va;
	hmc_info->pa = sd->dma_addr;
	hmc_info->ctx_size = NBL_QP_CTX_SIZE;
	hmc_info->shadow_offset = (qpc_index * NBL_QP_CTX_SIZE) + NBL_QP_SHADOW_OFFST;
	hmc_info->shadow_size = NBL_QP_SHADOW_SIZE;
	hmc_info->page_size = qp_sd_info->page_sz;

	return 0;
}

static int nbl_user_qp_shadow(struct nbl_pci_f *rf, struct nbl_qp *qp,
			struct ib_udata *udata, struct nbl_ib_create_qp_resp *uresp)
{
	struct nbl_hmc_obj_sd_info *qp_sd_info = rf->qp_sd_info;
	struct nbl_ctx_hmc_base_info hmc_info;
	struct nbl_ucontext *uctx;
	bool found;
	int ret;
	u32 map_size;

	uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext,
					 ibucontext);

	ret = nbl_get_qpc_base_addr(rf, qp->ibqp.qp_num, &hmc_info, qp_sd_info);
	if (ret) {
		nbl_pr_err("get nbl qpc base addr failed.\n");
		return ret;
	}

	uresp->shadow_base_addr = hmc_info.pa;
	uresp->qpc_size = hmc_info.ctx_size;
	uresp->shadow_offset = hmc_info.shadow_offset;
	uresp->shadow_size = hmc_info.shadow_size;
	uresp->page_size = hmc_info.page_size;

	qp->sc_qp.qp_shadow.va = hmc_info.va + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.pa = hmc_info.pa + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.size = hmc_info.shadow_size;

	map_size = uresp->page_size <= PAGE_SIZE ? PAGE_SIZE : uresp->page_size;
	found = nbl_find_shadow_mmap(uctx, uresp->shadow_base_addr, map_size);
	if (!found) {
		nbl_pr_dbg(
			"not find valid shadow node, and start to add new shadow node.\n");
		return nbl_add_shadow_mmap(uctx, hmc_info.va, uresp->shadow_base_addr,
					   map_size);
	}

	return 0;
}

static int nbl_kernel_qp_shadow(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	struct nbl_hmc_obj_sd_info *qp_sd_info = rf->qp_sd_info;
	struct nbl_ctx_hmc_base_info hmc_info;
	int ret;

	ret = nbl_get_qpc_base_addr(rf, qp->ibqp.qp_num, &hmc_info, qp_sd_info);
	if (ret) {
		nbl_pr_err("get nbl qpc base addr failed.\n");
		return ret;
	}
	qp->sc_qp.qp_shadow.va = hmc_info.va + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.pa = hmc_info.pa + hmc_info.shadow_offset;
	qp->sc_qp.qp_shadow.size = hmc_info.shadow_size;

	return 0;
}

void nbl_fill_qp_ctx(struct nbl_qp *qp, __be64 *qp_ctx)
{
	nbl_set_qp_ctx_v2(qp, qp_ctx);
}

void nbl_copy_qp_ctx(struct nbl_qp *qp)
{
	memcpy(&qp->ctx_info_copy, &qp->ctx_info, sizeof(struct nbl_qp_ctx));
}

static void nbl_reset_qp_ctx(struct nbl_qp *qp)
{
	memcpy(&qp->ctx_info, &qp->ctx_info_copy, sizeof(struct nbl_qp_ctx));
	qp->ctx_info.seq_num = qp->sc_qp.uk_qp.seq_num;
}

static void nbl_set_rxp_req_pre_hwqpc_v2(__be64 *qp_ctx, u32 opcode)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RXP_REQ_PRE_OPCODE, opcode);
}

static void nbl_set_rxp_req_pre_hwqpc_rnic(__be64 *qp_ctx, u32 opcode)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RXP_REQ_PRE_OPCODE_V4, opcode);
}

static void nbl_encode_qcn_v2(__be64 *qp_ctx,
			      const struct nbl_qp_ctx *ctx_info)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_REMAIN_TRANS_BITS,
			ctx_info->qcn_remain_trans_bits);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_SENDPKT_TARGETWIN,
			ctx_info->qcn_sendpkt_tarwin);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_FIRST_RECDB_FLAG,
			ctx_info->qcn_first_recdb_flag);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_LIMIT_RP,
			ctx_info->qcn_limit_rp);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_TARGET_RP,
			ctx_info->qcn_target_rp);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QCN_MAIN_STATUS,
			ctx_info->qcn_main_status);
}

static void nbl_encode_qcn_rnic400(__be64 *qp_ctx,
				   const struct nbl_qp_ctx *ctx_info)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_REMAIN_TRANS_BITS,
			ctx_info->qcn_remain_trans_bits);
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_SENDPKT_TARGETWIN,
			ctx_info->qcn_sendpkt_tarwin);
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_FIRST_RECDB_FLAG,
			ctx_info->qcn_first_recdb_flag);
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_LIMIT_RP,
			ctx_info->qcn_limit_rp);
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_TARGET_RP,
			ctx_info->qcn_target_rp);
	nbl_64bit_write(qp_ctx, NBL_QPC_V4_QCN_MAIN_STATUS,
			ctx_info->qcn_main_status);
}

const struct nbl_qpc_ops nbl_df200_qpc_ops = {
	.set_rxp_req_pre_hwqpc = nbl_set_rxp_req_pre_hwqpc_v2,
	.set_qcn_hwqpc = nbl_encode_qcn_v2,
	.iorqe_size = NBL_ADAPTER_PAGE_SIZE,
	.default_raq_wqe_cap = NBL_DEFAULT_RAQ_WQE_CAP_V2,
	.rnr_timer_when_set_zero = 0,
};

const struct nbl_qpc_ops nbl_draco_qpc_ops = {
	.set_rxp_req_pre_hwqpc = nbl_set_rxp_req_pre_hwqpc_v2,
	.set_qcn_hwqpc = nbl_encode_qcn_v2,
	.iorqe_size = NBL_ADAPTER_PAGE_SIZE,
	.default_raq_wqe_cap = NBL_DEFAULT_RAQ_WQE_CAP_V2,
	.rnr_timer_when_set_zero = NBL_MAX_RNR_TIMER,
};

const struct nbl_qpc_ops nbl_rnic400_qpc_ops = {
	.set_rxp_req_pre_hwqpc = nbl_set_rxp_req_pre_hwqpc_rnic,
	.set_qcn_hwqpc = nbl_encode_qcn_rnic400,
	.iorqe_size = NBL_ADAPTER_PAGE_SIZE << 1,
	.default_raq_wqe_cap = NBL_DEFAULT_RAQ_WQE_CAP_V4,
	.rnr_timer_when_set_zero = 0,
};

static void nbl_set_hwqpc(struct nbl_qp *qp, __be64 *qp_ctx, struct nbl_qp_ctx *ctx_info)
{
	const struct nbl_qpc_ops *ops = qp->nbldev->rf->product->qpc_ops;

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TXP_SQ_NEXT_WQE_CAP, ctx_info->default_wqe_cap);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TXP_RAQ_NEXT_WQE_CAP,
			ctx_info->default_raq_wqe_cap);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RETRY_CNT, ctx_info->tx_retry_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TXP_SQ_RETRY_CNT_PSN, ctx_info->txp_sq_retry_cnt_psn);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RAQ_BA, ctx_info->raq_ba);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_EPSN, ctx_info->rq_psn);
	if (ctx_info->srp_en)
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RXP_HPSN, ctx_info->rxp_hpsn);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RNR_RETRY_NUM, ctx_info->rnr_retry);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RXP_RESP_PRE_OPCODE,
			NBL_DEFAULT_RX_RESP_PRE_OPCODE);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_PSN_MAX, ctx_info->psn_max);

	if (!ctx_info->srp_en) {
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_NXT_PD_PA_VLD,
				ctx_info->rq_pd.nxt_pa_vld);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_NXT_PD_PA,
				ctx_info->rq_pd.nxt_pd_pa);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_CUR_PD_PA_VLD,
				ctx_info->rq_pd.cur_pa_vld);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_CUR_PD_PA,
				ctx_info->rq_pd.cur_pd_pa);
		ops->set_rxp_req_pre_hwqpc(qp_ctx,
					       NBL_DEFAULT_RXP_REQ_PRE_OPCODE);
	}
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_NXT_PD_PA_VLD,
			ctx_info->sq_pd.nxt_pa_vld);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_NXT_PD_PA,
			ctx_info->sq_pd.nxt_pd_pa);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_CUR_PD_PA_VLD,
			ctx_info->sq_pd.cur_pa_vld);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_CUR_PD_PA,
			ctx_info->sq_pd.cur_pd_pa);

	/* V1 V2 is same field */
	nbl_64bit_write(qp_ctx, NBL_QPC_V1_CC_TARGETWIN, ctx_info->targetwin);

	if (qp->sc_qp.uk_qp.qp_type == IB_QPT_RC || ctx_info->srp_en)
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_E2E_FC_EN, true);
	else
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_E2E_FC_EN, false);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SHADOW_QPC_BA,
			ctx_info->qpc_ba_low9bit_mask);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SHADOW_SEQ_NUM, ctx_info->seq_num);
	if (ctx_info->cc_mode == NBL_QCN)
		ops->set_qcn_hwqpc(qp_ctx, ctx_info);

	if (ctx_info->srp_en) {
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_TLP_TIMER,
				ctx_info->tlp_timer);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_TLP_RETRY_TH,
				ctx_info->tlp_retry_th);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_TLP_RETRY_CNT,
				ctx_info->tlp_retry_th);
	}
}

static void nbl_set_swqpc_ram0_4th_32Byte(__be64 *qp_ctx,
					  struct nbl_qp_ctx *ctx_info)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_UNAQ_BA, ctx_info->unaq_ba);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TC_CLASS_HIGH, ctx_info->tc_class_high);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_VLAN_PRI_HIGH, ctx_info->vlan_pri_high);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TXP_NOFENCE, ctx_info->nvme_fmr_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_CE_EN, ctx_info->sq_ce_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_ACKREQ_TH, ctx_info->ackreq_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_PD_BA, ctx_info->sq_pd.pd_ba);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CEAQ_SQ_TH, ctx_info->ceaq_sq_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CEAQ_RQ_TH, ctx_info->ceaq_rq_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_CQN, ctx_info->sq_cqn);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_CQN, ctx_info->rq_cqn);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QP_SEQ_NUM, ctx_info->seq_num);
}

static void nbl_set_swqpc_ram0_3th_32Byte(__be64 *qp_ctx,
					  struct nbl_qp_ctx *ctx_info)
{
	u8 *ptr = (u8 *)qp_ctx;

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RSS_LAG_EN, ctx_info->rss_lag_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_FWD, ctx_info->fwd);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_DPORT, ctx_info->dport);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_DPORT_ID, ctx_info->dport_id);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_VLAN, ctx_info->vlan_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRC_ADDR_IDX,
			ctx_info->src_addr_idx);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_FLOW_LABLE, ctx_info->flow_label);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_UDP_SPORT, ctx_info->udp_sport);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_DMAC,
			ether_addr_to_u64(ctx_info->dest_mac));
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TCLASS, ctx_info->tclass);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_HOP_LIMIT, ctx_info->hop_limit);
	/* RAM0 80-95 DST IP  Litte Endian*/
	memcpy(&ptr[80], ctx_info->dest_ip, NBL_QPC_DSIP_TOTAL_LEN);
}

static void nbl_set_swqpc_ram0_2nd_32Byte(__be64 *qp_ctx,
					  struct nbl_qp_ctx *ctx_info)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_VLAN_TAG, ctx_info->vlan_tag);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_IPV4, ctx_info->ipv4);

	if (ctx_info->srq_en) {
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQPD_BA_H_OR_SRQN_H,
			(ctx_info->srqn >> NBL_ADAPTER_PAGE_SHIFT));
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQPD_BA_L_OR_SRQN_L,
			(ctx_info->srqn & 0xFFF));
	} else {
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQPD_BA_H_OR_SRQN_H,
				(ctx_info->rq_pd.pd_ba >>
				 NBL_ADAPTER_PAGE_SHIFT));
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQPD_BA_L_OR_SRQN_L,
				(ctx_info->rq_pd.pd_ba & 0xFFF));
	}

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_TARGETWIN_MIN, ctx_info->cc_targetwin_min);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_UD_QKEY, ctx_info->ud_qkey);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_SIZE, ctx_info->sq_size);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_DEST_QPN, ctx_info->dest_qpn);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TX_RETRY_TH, ctx_info->tx_retry_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRP_EN, ctx_info->srp_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRQ_EN, ctx_info->srq_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_IRQ_SIZE, ctx_info->irq_size);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RTO_TIMER_VALUE, ctx_info->rto_timer_value);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_FRMR_EN, ctx_info->txmr_frmr_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_RTTMINTH_ADD_MULT, ctx_info->cc_rtt_qp_mult);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_READ_EN, ctx_info->read_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_WRITE_EN, ctx_info->write_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRC_ADDR_SEQ_NUM, ctx_info->src_addr_idx_seq_num);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_OAM_ACK_TC_EN, ctx_info->cc_oamack_tc_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_OAM_ACK_NET_TC, ctx_info->cc_oamack_net_tc);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_OAM_REQ_TC_EN, ctx_info->cc_oamreq_tc_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_OAM_REQ_NET_TC, ctx_info->cc_oamreq_net_tc);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RNR_RETRY_TH, ctx_info->rnr_retry);
	if (ctx_info->srp_en) {
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRQWC_BA,
				ctx_info->srqew_ba);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRP_RQ_FPDPA,
				ctx_info->rq_pd.cur_pd_pa);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRP_SPRAY,
				ctx_info->srp_spray_en);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRP_SRACK_TIMER_VALUE,
				ctx_info->srp_srack_timer);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_SRP_EXT_BMP_EN,
				ctx_info->sr_ext_bmp_en);
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_QP_SPRAY_EN,
				ctx_info->mp_port_spray_en);
	} else
		nbl_64bit_write(qp_ctx, NBL_QPC_V2_DOMAIN, ctx_info->xrcdn);
}

static void nbl_set_swqpc_ram0_1st_32Byte(__be64 *qp_ctx,
					  struct nbl_qp_ctx *ctx_info)
{
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_MIG, ctx_info->mig);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TVER, ctx_info->tver);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_STAT_ID, ctx_info->stat_id);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_HOST_ID, ctx_info->host_id);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_VF_ID, ctx_info->vfid);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QPN, ctx_info->qpn);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_PKEY, ctx_info->p_key);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SERVICE_TYPE,
			ctx_info->service_type);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QP_STATE, ctx_info->qp_st);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_PMTU, ctx_info->pmtu);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_IORQ_BA, ctx_info->iorq_ba);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QP1_MODE, ctx_info->qp1_mode);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SCH_NET_TC, ctx_info->sch_net_tc);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_PD_IDX, ctx_info->pd_idx);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SPORT_ID, ctx_info->sport_id);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_READ_OPTIMIZE_EN,
			ctx_info->read_optimize_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CREDIT_EN, true);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_PKT_NUM_EN,
			ctx_info->cc_pkt_num_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_WQE_PREFETCH_EN,
			ctx_info->wqe_prefetch_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_TUNNEL_EN, ctx_info->tunnel_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_SIZE, ctx_info->rq_size);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQWQE_TS, ctx_info->rq_wqe_size);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_QP_TYPE, ctx_info->q_type);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SQ_PM, ctx_info->sq_pm);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RQ_PM, ctx_info->rq_pm);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_ATOMIC_EN, ctx_info->atomic_en);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_RNR_TIMER_VAL,
			ctx_info->local_rnr_timer_value);

	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SWRQPI_TH, ctx_info->swrqpi_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_CC_MODE, ctx_info->cc_mode);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_ATOMIC_NO_FENCE, false);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_HW_RQCI_TH, ctx_info->rqci_th);
	nbl_64bit_write(qp_ctx, NBL_QPC_V2_SHADOW_BA,
			ctx_info->qpc_ba_low9bit_mask);
}

void nbl_set_qp_ctx_v2(struct nbl_qp *qp, __be64 *qp_ctx)
{
	struct nbl_qp_ctx *ctx_info;

	ctx_info = &qp->ctx_info;
	nbl_set_swqpc_ram0_1st_32Byte(qp_ctx, ctx_info);
	nbl_set_swqpc_ram0_2nd_32Byte(qp_ctx, ctx_info);
	nbl_set_swqpc_ram0_3th_32Byte(qp_ctx, ctx_info);
	nbl_set_swqpc_ram0_4th_32Byte(qp_ctx, ctx_info);
	nbl_set_hwqpc(qp, qp_ctx, ctx_info);
}

static void nbl_dealloc_dwqe_page(struct nbl_pci_f *rf, struct nbl_uk_qp *uk_qp)
{
	int ret;

	if (uk_qp->dpage_idx == NBL_INVALID_DPAGE_IDX)
		return;

	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_dpage, uk_qp->dpage_idx);

	ret = nbl_cqp_process_dpage_idx_cmd(rf, uk_qp->dpage_idx,
				NBL_CQP_OP_DEALLOC_DWQE);
	if (ret)
		nbl_pr_err("dealloc dwqe page cmd fail\n");
	uk_qp->dpage_idx = NBL_INVALID_DPAGE_IDX;
}

static int nbl_alloc_dwqe_page(struct nbl_pci_f *rf, struct nbl_uk_qp *uk_qp)
{
	int ret;
	int dpage_idx;

	ret = nbl_alloc_dpage_rsrc(&rf->rsrc_lock, rf->allocated_dpage,
				   rf->max_dpage, &dpage_idx, &rf->next_dpage, rf->start_dpage);
	if (ret)
		goto invld_idx;

	nbl_pr_dbg("is_ctrl_dev=%u,dpage_idx=%u\n",
		   nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV), dpage_idx);
	ret = nbl_cqp_process_dpage_idx_cmd(rf, dpage_idx,
					NBL_CQP_OP_ALLOC_DWQE);
	if (ret) {
		nbl_pr_err("nbl get page idx err:%u\n", ret);
		goto free_rsrc;
	}
	uk_qp->dpage_idx = dpage_idx;
	return 0;

free_rsrc:
	nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_dpage, uk_qp->dpage_idx);
invld_idx:
	uk_qp->dpage_idx = NBL_INVALID_DPAGE_IDX;
	return -EINVAL;
}

static void nbl_remove_dpage(struct nbl_pci_f *rf, struct nbl_qp *qp)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	nbl_dealloc_dwqe_page(rf, uk_qp);

	if (qp->user_mode && uk_qp->dpage_mmap_entry) {
		rdma_user_mmap_entry_remove(uk_qp->dpage_mmap_entry);
		uk_qp->dpage_mmap_entry = NULL;
	}

}

static int nbl_setup_dpage(struct nbl_ucontext *uctx, struct nbl_pci_f *rf,
			struct nbl_uk_qp *uk_qp, struct nbl_ib_create_qp_resp *resp)
{
	__u64 bar_off;
	int ret;

	ret = nbl_alloc_dwqe_page(rf, uk_qp);
	if (ret) {
		nbl_pr_dbg("nbl alloc dwqe page idx fail\n");
		return ret;
	}

	bar_off = (uintptr_t)rf->sc_dev.hw_regs[NBL_DWQE_OFFSET];

	if (PAGE_SIZE == SZ_64K) {
		uk_qp->dpage_offset = (uk_qp->dpage_idx - rf->start_dpage) * NBL_DPAGE_SIZE;
		bar_off += uk_qp->dpage_offset;
		bar_off = ALIGN_DOWN(bar_off, PAGE_SIZE);
		uk_qp->dpage_offset = uk_qp->dpage_offset % PAGE_SIZE;
	} else {
		bar_off += uk_qp->dpage_idx * NBL_DPAGE_SIZE;
		uk_qp->dpage_offset = 0;
	}

	uk_qp->dpage_mmap_entry = nbl_user_mmap_entry_insert(
		uctx, bar_off, NBL_MMAP_IO_WC, &uk_qp->dpage_mmap_key);

	if (!uk_qp->dpage_mmap_entry)
		goto free_dpage_idx;

	uk_qp->dwqe_en = true;
	return 0;

free_dpage_idx:
	nbl_dealloc_dwqe_page(rf, uk_qp);
	uk_qp->dwqe_en = false;
	return -EINVAL;
}

static void nbl_free_user_qp_buffer(struct device *device, struct nbl_dma_mem *mem,
				struct nbl_ib_qp_buf *q_buf, bool page_mode)
{
	if (mem->va) {
		if (page_mode == NBL_LEVEL1_PAGE_MODE)
			dma_free_coherent(device, NBL_ADAPTER_PAGE_SIZE,
					  mem->va, mem->pa);
		nbl_ib_umem_release(q_buf->umem, q_buf->nbl_peer);
	}
}

static void nbl_free_qp_buffer(struct nbl_qp *qp)
{
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	struct nbl_device *nbldev = qp->nbldev;
	struct device  *device = qp->device;

	if (uk_qp->has_sq) {
		if (qp->user_mode)
			nbl_free_user_qp_buffer(device, &sc_qp->sqmem, &sc_qp->sqbuf, sc_qp->sq_pm);
		else
			nbl_free_kmode_qp_buffer(qp, nbldev, &sc_qp->sqbuf, true);
	}

	if (uk_qp->has_rq) {
		if (qp->user_mode)
			nbl_free_user_qp_buffer(device, &sc_qp->rqmem, &sc_qp->rqbuf, sc_qp->rq_pm);
		else
			nbl_free_kmode_qp_buffer(qp, nbldev, &sc_qp->rqbuf, false);
	}
}

static void nbl_dbg_qp_chk_add(struct nbl_qp *qp)
{
	if (NBL_QP_NEED_DBG_QP(qp->sc_qp.uk_qp.qpn))
		nbl_debug_qp_add(qp->nbldev, qp);
}

static void nbl_dbg_qp_chk_remove(struct nbl_qp *qp)
{
	if (NBL_QP_NEED_DBG_QP(qp->sc_qp.uk_qp.qpn))
		nbl_debug_qp_remove(qp->nbldev, qp);
}

static int nbl_qp_ref_init(struct nbl_pci_f *rf, struct nbl_qp *qp)
{
	int state;

	if (qp->scq) {
		state = nbl_add_cqc_ref(qp->scq);
		if (state)
			return state;
	}

	if (qp->rcq) {
		state = nbl_add_cqc_ref(qp->rcq);
		if (state)
			goto dec_scq_ref;
	}

	state = nbl_cqp_create_qp_cmd(qp);
	if (state)
		goto dec_rcq_ref;

	rf->qp_table[qp->sc_qp.uk_qp.qpn] = qp;
	refcount_set(&qp->refcnt, 1);
	/* flush cnt init to 2 for sq/rq ae come when flush */
	refcount_set(&qp->flush_cnt, NBL_QP_FLUSH_AE_EXP_NUM);

	init_completion(&qp->free_qp);
	init_completion(&qp->flush_qp);
	init_completion(&qp->qp_err);
	mutex_init(&qp->modify_mutex);
	spin_lock_init(&qp->lock);

	nbl_dbg_qp_chk_add(qp);

	return 0;

dec_rcq_ref:
	if (qp->rcq)
		nbl_dec_cqc_ref(qp->rcq);
dec_scq_ref:
	if (qp->scq)
		nbl_dec_cqc_ref(qp->scq);
	return state;

}

/**
 * nbl_fill_qpc_seq_num - update seq num and fill qpc shadow fields
 * @rf: nbl rf struct
 * @sc_qp: sc qp
 *
 * Attention: qp seq num can only update by this api, and ukqp is only
 * source of qp seq num.
 */
void nbl_fill_qpc_seq_num(struct nbl_pci_f *rf, struct nbl_sc_qp *sc_qp)
{
	int qpn = sc_qp->uk_qp.qpn;
	int seq_max = NBL_MAX_SEQ_NUM_V2;

	if (rf->qp_seq_table[qpn] != seq_max)
		rf->qp_seq_table[qpn] += 1;
	else
		rf->qp_seq_table[qpn] = 1;

	sc_qp->uk_qp.seq_num = rf->qp_seq_table[qpn];
	nbl_64bit_write(sc_qp->qp_shadow.va, NBL_HMC_QPC_SHADOW_SEQ_NUM,
			sc_qp->uk_qp.seq_num);

	nbl_64bit_write(sc_qp->qp_shadow.va, NBL_HMC_QPC_SHADOW_QPC_BA,
			(sc_qp->qp_shadow.pa) >> NBL_QPC_BA_SHIFT);
	nbl_64bit_write(sc_qp->qp_shadow.va,
			NBL_HMC_QPC_SHADOW_SW_SEQ_NUM,
			sc_qp->uk_qp.seq_num);
}

static void nbl_uk_qp_init_base(struct nbl_uk_qp *uk_qp)
{
	uk_qp->destroy_pending = false;
	uk_qp->sw_ring_db_pi = 0;
	uk_qp->rq_db_flag = 0;
	uk_qp->seq_first_err = false;
	uk_qp->err_db_done = false;
	uk_qp->seq_err = false;
	uk_qp->db_tc = 0;
	uk_qp->next_fence = 0;
	uk_qp->local_cnt = 0;
	uk_qp->first_sq_cqe_come = false;
	uk_qp->first_rq_cqe_come = false;
	uk_qp->sq_cqe_err_occur = false;
	uk_qp->rq_cqe_err_occur = false;
	uk_qp->sq_flush_complete = false;
	uk_qp->rq_flush_complete = false;
}

static void nbl_uk_qp_init(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	uk_qp->max_inline_data = init_attr->cap.max_inline_data;
	uk_qp->max_send_sge = init_attr->cap.max_send_sge;
	uk_qp->max_recv_sge = init_attr->cap.max_recv_sge;
	uk_qp->qp_max_rd_atom = 0;
	uk_qp->qp_max_dest_rd_atom = 0;

	uk_qp->back_qp = qp;
	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		uk_qp->sig_all = true;
	nbl_uk_qp_init_base(uk_qp);
}

static int nbl_copy_data_to_user(struct nbl_pci_f *rf, struct nbl_uk_qp *uk_qp,
					struct nbl_ib_create_qp_resp *resp, struct ib_udata *udata)
{
	int state;

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
	resp->tc2pri = rf->sc_dev.tc2pri;
	resp->vsi_id = rf->vsi_id;

	if (rf->sc_dev.dwqe_en && uk_qp->dwqe_en) {
		resp->dwqe_en = uk_qp->dwqe_en;
		resp->dpage_mmap_key = uk_qp->dpage_mmap_key;
		resp->dpage_offset = uk_qp->dpage_offset;
	}
	state = ib_copy_to_udata(udata, resp,
				min(sizeof(*resp), udata->outlen));
	return state;
}

void nbl_free_qp_hw_queue_mem(struct nbl_pci_f *rf,
				     struct nbl_sc_qp *sc_qp)
{
	int idx = NBL_QP_HW_QUEUE_MAX;
	struct device *device = rf->sc_dev.hw->device;

	while (idx--) {
		struct nbl_dma_mem *mem = &sc_qp->mem_list[idx];

		dma_free_coherent(device, mem->size, mem->va, mem->pa);
	}
	kfree(sc_qp->mem_list);

	dma_free_coherent(device, sc_qp->qp_ctx_mem.size, sc_qp->qp_ctx_mem.va,
			  sc_qp->qp_ctx_mem.pa);
}

void nbl_free_qp_num(struct nbl_pci_f *rf, u32 qp_num)
{
	if (qp_num != NBL_QP_NUM_FOR_RSV &&
		qp_num != NBL_QP_NUM_FOR_CM && qp_num != NBL_QP_NUM_FOR_DUMP)
		nbl_free_qpn_rsrc(rf, qp_num);
}

static int nbl_create_user_qp(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr,
				struct nbl_ib_create_qp_resp *resp, struct ib_udata *udata)
{
	int state;
	int sq_size, rq_size;
	int sq_wr_size, rq_wr_size;
	struct nbl_create_qp_req req;
	struct nbl_pci_f *rf = qp->nbldev->rf;
	struct device *device = qp->device;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;

	state = ib_copy_from_udata(&req, udata,
					min(sizeof(req), udata->inlen));
	if (state)
		return state;

	qp->ctx_info.qp_completion_ctx = req.qp;
	qp->user_mode = 1;

	sq_wr_size = NBL_GET_WR_SIZE(init_attr->cap.max_send_wr);
	rq_wr_size = NBL_GET_RQ_WR_SIZE(init_attr->cap.max_recv_wr);

	/*alloc sq buffer*/
	if (req.sq_bufer) {
		sq_size = req.sq_size;
		uk_qp->sq_base = (struct nbl_qp_block *)(uintptr_t)req.sq_bufer;
		uk_qp->max_send_wr = sq_wr_size;
		state = nbl_alloc_user_qp_buffer(qp, qp->nbldev, &sc_qp->sqbuf,
					req.sq_bufer, sq_size, true, udata);
		if (state)
			return state;
		uk_qp->sq_size = ilog2(sq_size >> 6);
	}

	/*alloc rq buffer*/
	if (req.rq_bufer && uk_qp->has_rq) {
		nbl_calc_rqwqe_size(uk_qp, init_attr->cap.max_recv_sge);
		rq_size = req.rq_size;
		uk_qp->rq_base = (struct nbl_qp_block *)(uintptr_t)req.rq_bufer;
		uk_qp->max_recv_wr = rq_wr_size;

		state = nbl_alloc_user_qp_buffer(qp, qp->nbldev, &sc_qp->rqbuf,
							req.rq_bufer, rq_size, 0, udata);
		if (state)
			goto free_sq_buffer;
		uk_qp->rq_size = ilog2(rq_size >> 6);
	} else {
		uk_qp->rq_base = NULL;
		uk_qp->max_recv_wr = 0;
		uk_qp->rq_size = 0;
	}

	/* setup user mode qp shadow area */
	state = nbl_user_qp_shadow(rf, qp, udata, resp);
	if (state)
		goto free_rq_buffer;

	return 0;

free_rq_buffer:
	if (uk_qp->has_rq)
		nbl_free_user_qp_buffer(device, &sc_qp->rqmem, &sc_qp->rqbuf, sc_qp->rq_pm);
free_sq_buffer:
	nbl_free_user_qp_buffer(device, &sc_qp->sqmem, &sc_qp->sqbuf, sc_qp->sq_pm);
	return state;
}

int nbl_alloc_hw_queue_mem(struct nbl_pci_f *rf, struct nbl_qp *qp)
{
	int ret;
	int idx;
	struct nbl_hw *hw = rf->sc_dev.hw;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	/* alloc qp ctx mem */
	sc_qp->qp_ctx_mem.size = NBL_QP_CTX_SIZE;
	sc_qp->qp_ctx_mem.va =
		nbl_dma_alloc_coherent(hw, sc_qp->qp_ctx_mem.size,
				   &sc_qp->qp_ctx_mem.pa, GFP_KERNEL);
	if (!sc_qp->qp_ctx_mem.va)
		return -ENOMEM;

	sc_qp->mem_list = kcalloc(NBL_QP_HW_QUEUE_MAX,
				  sizeof(struct nbl_dma_mem), GFP_KERNEL);
	if (!sc_qp->mem_list) {
		ret = -ENOMEM;
		goto free_qpc;
	}

	for (idx = 0; idx < NBL_QP_HW_QUEUE_MAX; idx++) {
		if (idx == NBL_QP_HW_V2_IORQE)
			sc_qp->mem_list[idx].size = rf->product->qpc_ops->iorqe_size;
		else
			sc_qp->mem_list[idx].size = NBL_ADAPTER_PAGE_SIZE;
		sc_qp->mem_list[idx].va =
			nbl_dma_alloc_coherent(hw, sc_qp->mem_list[idx].size,
					   &sc_qp->mem_list[idx].pa,
					   GFP_KERNEL);
		if (!sc_qp->mem_list[idx].va) {
			ret = -ENOMEM;
			goto free_mem_list;
		}
	}

	return 0;
free_mem_list:
	while (idx--) {
		struct nbl_dma_mem *mem = &sc_qp->mem_list[idx];

		dma_free_coherent(hw->device, mem->size, mem->va, mem->pa);
	}
	kfree(sc_qp->mem_list);
free_qpc:
	dma_free_coherent(hw->device, sc_qp->qp_ctx_mem.size, sc_qp->qp_ctx_mem.va,
			  sc_qp->qp_ctx_mem.pa);
	return ret;
}

int nbl_get_qp_num(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	u32 qp_num;
	u32 next_qpn = 0;
	int ret = 0;

	if (uk_qp->qp_type == IB_QPT_GSI) {
		qp_num = NBL_QP_NUM_FOR_CM;
	} else if (uk_qp->qp_type == IB_QPT_RAW_PACKET) {
		qp_num = NBL_QP_NUM_FOR_DUMP;
	} else {
		/* srp search from 0 */
		if (rf->sc_dev.srp_en)
			ret = nbl_alloc_qpn_rsrc(rf, &qp_num, &next_qpn);
		else
			ret = nbl_alloc_qpn_rsrc(rf, &qp_num, &rf->next_qp);
		if (ret) {
			nbl_pr_err("get qpn err, used qp %u,max qp %u\n",
				   rf->used_qps, rf->max_qp);
			return -EINVAL;
		}
	}
	qp->ibqp.qp_num = qp_num;
	qp->sc_qp.uk_qp.qpn = qp_num;

	return 0;
}

static int nbl_process_qp_type(struct nbl_qp *qp,
				struct ib_qp_init_attr *init_attr)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	if (init_attr->srq) {
		/* QP use srq */
		uk_qp->use_srq = true;
		uk_qp->has_rq = false;
		uk_qp->srqn = to_nbl_srq(init_attr->srq)->srqn;
	} else {
		uk_qp->use_srq = false;
		uk_qp->has_rq = true;
	}

	uk_qp->has_sq = true;
	switch (init_attr->qp_type) {
	case IB_QPT_RC:
		if (qp->nbldev->rf->sc_dev.srp_en) {
			uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_SRP;
			uk_qp->qp_caps = NBL_WRITE_WITH_IMM |
					 NBL_SEND_WITH_IMM | NBL_SRP_EN;
		} else {
			uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_RC;
			uk_qp->qp_caps = NBL_WRITE_WITH_IMM | NBL_SEND_WITH_IMM;
		}
		if (nbl_product_cap_enabled(qp->nbldev->rf,
					    NBL_PRODUCT_CAP_ATOMIC))
			uk_qp->qp_caps |= NBL_ATOMIC;
		break;
	case IB_QPT_XRC_INI:
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_XRC;
		uk_qp->qp_caps =
			NBL_WRITE_WITH_IMM | NBL_SEND_WITH_IMM;
		if (nbl_product_cap_enabled(qp->nbldev->rf,
					    NBL_PRODUCT_CAP_ATOMIC))
			uk_qp->qp_caps |= NBL_ATOMIC;
		break;
	case IB_QPT_XRC_TGT:
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_XRC;
		uk_qp->qp_caps = 0;
		uk_qp->has_sq = false;
		/* only TGT QP use xrcdn */
		uk_qp->xrcdn =
			to_nbl_xrcd(init_attr->xrcd)->xrcdn;
		if (nbl_product_cap_enabled(qp->nbldev->rf,
					    NBL_PRODUCT_CAP_ATOMIC))
			uk_qp->qp_caps |= NBL_ATOMIC;
		break;
	case IB_QPT_UD:
	case IB_QPT_GSI:
		/* UD and GSI */
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_UD;
		uk_qp->qp_caps = NBL_SEND_WITH_IMM;
		break;
	case NBL_IB_QPT_REG_UMR:
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_UMR;
		uk_qp->qp_caps = 0;
		break;
	case NBL_IB_QPT_SRP:
		uk_qp->nbl_qp_service_type = NBL_QP_SERVICE_TYPE_SRP;
		uk_qp->qp_caps =
			NBL_WRITE_WITH_IMM | NBL_SEND_WITH_IMM | NBL_SRP_EN;
		break;
	case IB_QPT_RAW_PACKET:
		uk_qp->has_sq = false;
		break;
	default:
		nbl_pr_err("inv QP type %d\n", init_attr->qp_type);
		return -EINVAL;
	}
	uk_qp->qp_type = init_attr->qp_type;

	return 0;
}

static int nbl_check_qp_init_attr(struct ib_pd *ibpd,
			struct ib_qp_init_attr *init_attr,
			struct nbl_uk_attrs *uk_attrs)
{
	if (!ibpd && init_attr->qp_type != IB_QPT_XRC_TGT) {
		nbl_pr_err("pd pointer missing error\n");
		return -EINVAL;
	}

	if (init_attr->create_flags) {
		nbl_pr_err("create_flags not support\n");
		return -EINVAL;
	}

	if (init_attr->cap.max_inline_data > uk_attrs->max_hw_inline) {
		nbl_pr_err("inv para, init_attr max_inline_data: %u\n",
			init_attr->cap.max_inline_data);
		return -EINVAL;
	}

	if (init_attr->cap.max_send_sge > uk_attrs->max_hw_wq_sges) {
		nbl_pr_err("inv para, init_attr max_send_sge: %u\n",
			init_attr->cap.max_send_sge);
		return -EINVAL;
	}

	if (init_attr->cap.max_recv_sge > uk_attrs->max_hw_wq_sges) {
		nbl_pr_err("inv para, init_attr max_recv_sge: %u\n",
			init_attr->cap.max_recv_sge);
		return -EINVAL;
	}

	return 0;
}

static void nbl_qp_init(struct ib_pd *ibpd, struct nbl_qp *qp,
			struct ib_qp_init_attr *init_attr)
{
	struct ib_device *ibdev = ibpd ? ibpd->device : init_attr->xrcd->device;
	struct nbl_device *nbldev = to_nbl_dev(ibdev);
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	struct nbl_uk_attrs *uk_attrs = &sc_dev->hw_attrs.uk_attrs;

	qp->nbldev = nbldev;
	qp->device = sc_dev->hw->device;
	qp->sc_qp.sc_dev = sc_dev;
	qp->sc_qp.uk_qp.uk_attrs = uk_attrs;
	qp->sc_qp.uk_qp.dwqe_en = false;

	if (ibpd) {
		qp->nblpd = to_nbl_pd(ibpd);
		qp->sc_qp.sc_pd = &qp->nblpd->sc_pd;
	} else {
		qp->nblpd = NULL;
		qp->sc_qp.sc_pd = NULL;
	}

	/* ibqp.send_cq and ibqp.recv_cq is filled by OFED, del its init */
	qp->scq = init_attr->send_cq ? to_nbl_cq(init_attr->send_cq) : NULL;
	qp->rcq = init_attr->recv_cq ? to_nbl_cq(init_attr->recv_cq) : NULL;

	qp->sc_qp.uk_qp.rq_db = sc_dev->hw_regs[NBL_RQ_DB];
	qp->sc_qp.uk_qp.sq_db = sc_dev->hw_regs[NBL_SQ_DB];
	qp->qp_state = NBL_QP_STATE_RST;

	qp->srq = init_attr->srq ? to_nbl_srq(init_attr->srq) : NULL;
}

static void get_cqs(struct nbl_qp *nblqp, struct ib_qp *ibqp,
			struct nbl_cq **send_cq, struct nbl_cq **recv_cq)
{
	struct nbl_uk_qp *ukqp = &nblqp->sc_qp.uk_qp;

	switch (ukqp->qp_type) {
	case IB_QPT_XRC_TGT:
		*send_cq = NULL;
		*recv_cq = NULL;
		break;
	case NBL_IB_QPT_REG_UMR:
	case IB_QPT_XRC_INI:
		*send_cq = ibqp->send_cq ? to_nbl_cq(ibqp->send_cq) : NULL;
		*recv_cq = NULL;
		break;
	default:
		*send_cq = ibqp->send_cq ? to_nbl_cq(ibqp->send_cq) : NULL;
		*recv_cq = ibqp->recv_cq ? to_nbl_cq(ibqp->recv_cq) : NULL;
		break;
	}
}

static struct nbl_ucontext *nbl_get_uctx(struct ib_pd *ibpd, struct ib_udata *udata)
{
	return udata ? rdma_udata_to_drv_context(udata, struct nbl_ucontext, ibucontext) : NULL;
}

/**
 * nbl_ib_create_qp - create qp in kernal
 * @ibpd: pd
 * @init_attr: attr info
 * @udata: udata form user
 */
int nbl_ib_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr, struct ib_udata *udata)
{
	int state = 0;
	struct nbl_qp *qp;
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;
	struct nbl_ib_create_qp_resp resp = {};
	struct nbl_pci_f *rf;
	struct nbl_ucontext *uctx = NULL;

	struct ib_pd *ibpd = ibqp->pd;

	qp = container_of(ibqp, struct nbl_qp, ibqp);
	sc_qp = &qp->sc_qp;
	uk_qp = &sc_qp->uk_qp;

	nbl_qp_init(ibpd, qp, init_attr);
	rf = qp->nbldev->rf;

	state = nbl_check_qp_init_attr(ibpd, init_attr, uk_qp->uk_attrs);
	if (state)
		goto free_qp;

	state = nbl_process_qp_type(qp, init_attr);
	if (state)
		goto free_qp;

	state = nbl_get_qp_num(qp);
	if (state)
		goto free_qp;
	nbl_ib_dbg(&rf->sc_dev, "create qp[%d]\n", qp->ibqp.qp_num);

	state = nbl_alloc_hw_queue_mem(rf, qp);
	if (state)
		goto free_qpn;

	if (uk_qp->qp_type == IB_QPT_XRC_TGT) {
		/* only need shadow area for qp seq num */
		state = nbl_kernel_qp_shadow(qp);
		if (state)
			goto free_hw_queue_mem;

		qp->ctx_info.qp_completion_ctx = uk_qp->qpn;
	} else {
		if (udata) {
			state = nbl_create_user_qp(qp, init_attr, &resp, udata);
			if (state)
				goto free_hw_queue_mem;
		} else {
			state = nbl_create_kernel_qp(qp, init_attr);
			if (state)
				goto free_hw_queue_mem;
		}
	}

	nbl_uk_qp_init(qp, init_attr);
	nbl_fill_qpc_seq_num(rf, sc_qp);
	nbl_fill_qpc_info(qp, &qp->ctx_info);
	nbl_fill_qp_ctx(qp, sc_qp->qp_ctx_mem.va);
	nbl_copy_qp_ctx(qp);
	state = nbl_qp_ref_init(rf, qp);
	if (state)
		goto free_qp_buffer;

	if (udata &&
		uk_qp->qp_type != IB_QPT_XRC_TGT &&
		uk_qp->qp_type != IB_QPT_XRC_INI &&
		rf->sc_dev.dwqe_en &&
		nbl_product_flag_enabled(rf, NBL_PRODUCT_F_CTRL_DEV)) {
		/*get uctx to process direct wqe*/
		/*init/tgt qp no post wqe*/
		uctx = nbl_get_uctx(ibpd, udata);
		if (uctx && uctx->is_lat_process) {
			state = nbl_setup_dpage(uctx, rf, uk_qp, &resp);
			/*if alloc direct wqe page fail, continue*/
			if (!state)
				uk_qp->dwqe_en = true;
		}
	}

	if (udata) {
		state = nbl_copy_data_to_user(rf, uk_qp, &resp, udata);
		if (state)
			goto free_qp_page;
	}

	return 0;
free_qp_page:
	if (uk_qp->dwqe_en)
		nbl_remove_dpage(rf, qp);
free_qp_buffer:
	nbl_free_qp_buffer(qp);
free_hw_queue_mem:
	nbl_free_qp_hw_queue_mem(rf, sc_qp);
free_qpn:
	nbl_free_qp_num(rf, uk_qp->qpn);
free_qp:
	return state;
}

static int nbl_modify_hw_qp_state(struct nbl_qp *qp, struct ib_qp_attr *attr,
				  int attr_mask, struct nbl_qp_ctx *ctx_info)
{
	bool issue_flush = false;
	unsigned long flags;

	if (nbl_cqp_modify_qp_cmd(qp->nbldev, qp, ctx_info->qp_st)) {
		nbl_pr_err("nbl modify qp cmd failed. qpn:%#x qp_type :%d, cur_state:%s next state:%s\n",
				qp->ibqp.qp_num, qp->ibqp.qp_type,
				nbl_qp_stat_to_str(qp->qp_state),
				nbl_qp_stat_to_str(ctx_info->qp_st));
		return -EINVAL;
	}

	if (attr_mask & IB_QP_STATE) {
		spin_lock_irqsave(&qp->lock, flags);
		/* qp_state ibqp_state flush_issued used not here, so add spin lock */
		qp->qp_state = ctx_info->qp_st;
		qp->ibqp_state = attr->qp_state;
		if ((ctx_info->qp_st == NBL_QP_STATE_ERR) &&
		    !qp->flush_issued) {
			qp->flush_issued = true;
			issue_flush = true;
		}
		spin_unlock_irqrestore(&qp->lock, flags);
	}

	if (issue_flush) {
		down(&qp->nbldev->rf->qp_flush_sem);
		/* flush oper is just do our best,
		 * even meet err, we must continue,
		 * so cancel return check here.
		 */
		nbl_flush_operation(qp, qp->nbldev);
		up(&qp->nbldev->rf->qp_flush_sem);
		complete(&qp->qp_err);
	}

	return 0;
}

int nbl_check_qp_state(struct nbl_qp *qp, enum ib_qp_state ibst,
				struct nbl_qp_ctx *ctx_info)
{
	u8 next_qp_state = 0;

	switch (ibst) {
	case IB_QPS_INIT:
		if (qp->qp_state == NBL_QP_STATE_RST ||
			qp->qp_state == NBL_QP_STATE_INIT) {
			next_qp_state = NBL_QP_STATE_INIT;
		} else if (qp->qp_state > NBL_QP_STATE_INIT) {
			nbl_pr_err("modify qp to INIT failed! curr_state:%s, qpn:%#x, qp_type :%d\n",
				nbl_qp_stat_to_str(qp->qp_state),
				qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		break;
	case IB_QPS_RTR:
		if (qp->qp_state != NBL_QP_STATE_INIT) {
			nbl_pr_err("modify qp to RTR failed! curr_state:%s, qpn:%#x, qp_type :%d\n",
					nbl_qp_stat_to_str(qp->qp_state),
					qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		next_qp_state = NBL_QP_STATE_RTR;
		break;
	case IB_QPS_RTS:
		if (qp->qp_state < NBL_QP_STATE_RTR ||
			qp->qp_state > NBL_QP_STATE_SQD) {
			nbl_pr_err("modify qp to RTS failed! curr_state:%s, qpn:%#x, qp_type :%d\n",
				nbl_qp_stat_to_str(qp->qp_state),
				qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		next_qp_state = NBL_QP_STATE_RTS;
		break;
	case IB_QPS_SQD:
		if (qp->qp_state == NBL_QP_STATE_SQD ||
			qp->qp_state == NBL_QP_STATE_RTS) {
			next_qp_state = NBL_QP_STATE_SQD;
		} else {
			nbl_pr_err("modify qp to SQD failed! curr_state:%s, qpn:%#x, qp_type :%d\n",
				nbl_qp_stat_to_str(qp->qp_state),
				qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		break;
	case IB_QPS_RESET:
		if (qp->qp_state != NBL_QP_STATE_ERR) {
			nbl_pr_err("modify qp to RST failed! curr_state:%s, qpn:%#x, qp_type :%d\n",
					nbl_qp_stat_to_str(qp->qp_state),
					qp->ibqp.qp_num, qp->ibqp.qp_type);
			return -EINVAL;
		}
		next_qp_state = NBL_QP_STATE_RST;
		break;
	case IB_QPS_SQE:
	case IB_QPS_ERR:
		nbl_pr_dbg("modify qp to ERR! curr_qp_state:%s, qpn:%#x, qp_type :%d\n",
				nbl_qp_stat_to_str(qp->qp_state),
				qp->ibqp.qp_num, qp->ibqp.qp_type);
		next_qp_state = NBL_QP_STATE_ERR;
		break;
	default:
		return -EINVAL;
	}
	ctx_info->qp_st = next_qp_state;

	return 0;
}

static bool ignored_ts_check(enum ib_qp_type qp_type)
{
	if (qp_type == NBL_IB_QPT_REG_UMR || qp_type == NBL_IB_QPT_SRP)
		return true;

	return false;
}

static void nbl_qp_clean_cqes(struct nbl_qp *nblqp)
{
	struct ib_qp *ibqp = &nblqp->ibqp;
	struct nbl_pci_f *rf = nblqp->nbldev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_cq *send_cq;
	struct nbl_cq *recv_cq;

	get_cqs(nblqp, ibqp, &send_cq, &recv_cq);
	if (send_cq)
		nbl_clean_cqes(sc_dev, send_cq, ibqp->qp_num);
	if (recv_cq && recv_cq != send_cq)
		nbl_clean_cqes(sc_dev, recv_cq, ibqp->qp_num);
}

static void nbl_clear_ring_buf(void *base, struct nbl_frag_buf *buf,
	bool pa_continue, u64 buf_size)
{
	struct nbl_buf_list *frag;
	int i;

	if (pa_continue) {
		if (!base)
			return;
		memset(base, 0, buf_size);
	} else if (buf) {
		for (i = 0; i < buf->npages; i++) {
			frag = &buf->frags[i];
			memset(frag->buf, 0, NBL_ADAPTER_PAGE_SIZE);
		}
	}
}

static void nbl_reset_qp(struct nbl_qp *nblqp)
{
	struct nbl_pci_f *rf = nblqp->nbldev->rf;
	struct nbl_uk_qp *uk_qp;
	struct nbl_sc_qp *sc_qp;

	uk_qp = &nblqp->sc_qp.uk_qp;
	sc_qp = &nblqp->sc_qp;

	nbl_fill_qpc_seq_num(rf, sc_qp); /* update seq when reset */

	nbl_uk_qp_init_base(uk_qp);
	/* reset flush */
	nblqp->flush_issued = false;
	refcount_set(&nblqp->flush_cnt, NBL_QP_FLUSH_AE_EXP_NUM);
	reinit_completion(&nblqp->qp_err);
	/* clean cq, sq, rq */
	if (!nblqp->user_mode) {
		nbl_qp_clean_cqes(nblqp);
		if (uk_qp->has_sq) {
			NBL_RING_INIT(uk_qp->sq_ring, uk_qp->max_send_wr);
			nbl_clear_ring_buf(uk_qp->sq_base, &(sc_qp->sqbuf.frag_buf),
				!sc_qp->sq_pm, (1 << uk_qp->sq_size) << NBL_SQWQE_BLOCK_SHIFT);
		}
		if (uk_qp->has_rq) {
			NBL_RING_INIT(uk_qp->rq_ring, uk_qp->max_recv_wr);
			nbl_clear_ring_buf(uk_qp->rq_base, &(sc_qp->rqbuf.frag_buf),
				!sc_qp->rq_pm, (1 << uk_qp->rq_size) << NBL_RQWQE_BLOCK_SHIFT);
		}
	}
}

static int nbl_modify_sw_qp_state(struct nbl_qp *qp,
				  struct nbl_qp_ctx *ctx_info,
				  struct ib_qp_attr *attr, int attr_mask)
{
	if (attr_mask & IB_QP_STATE) {
		if (!ignored_ts_check(qp->ibqp.qp_type)) {
			if (!ib_modify_qp_is_ok(qp->ibqp_state, attr->qp_state,
						qp->ibqp.qp_type, attr_mask)) {
				nbl_pr_err(
					"attr_mask:%#x err: cur state: %s | %s attr state:%s, qpn :%#x, qp_type :%u\n",
					attr_mask,
					nbl_qp_stat_to_str(qp->qp_state),
					ib_qp_stat_to_str(qp->ibqp_state),
					ib_qp_stat_to_str(attr->qp_state),
					qp->ibqp.qp_num, qp->ibqp.qp_type);
				return -EINVAL;
			}
		}
		if (nbl_check_qp_state(qp, attr->qp_state, ctx_info))
			return -EINVAL;

		/* reset qp , qpc and seq num update */
		if (attr->qp_state == IB_QPS_RESET) {
			nbl_reset_qp(qp);
			nbl_reset_qp_ctx(qp);
		}
	}
	nbl_fill_qp_ctx(qp, qp->sc_qp.qp_ctx_mem.va);

	return 0;
}

static int nbl_get_ah_info(struct nbl_qp *qp, struct ib_qp_attr *attr,
				struct nbl_qp_ctx *ctx_info)
{
	int ret = 0;
	u16 src_addr_idx;
	u8 seq_num;
	u8 src_ip[NBL_SRC_IP_SIZE];
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	bool pt_en = rf->sc_dev.pt_params.en.pt_en;
	u8 pt_trimmable_val = rf->sc_dev.pt_params.code.pt_code_trimmable;
	u8 pt_control_val = rf->sc_dev.pt_params.code.pt_code_control;

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
		if (pt_en) {
			/* tc_class DSCP = pt_trimmable_val, preserve ECN */
			NBL_SET_TC_DSCP(ctx_info->tclass, pt_trimmable_val);
			/* tc_class_high DSCP = pt_control_val, preserve ECN */
			NBL_SET_TC_DSCP(ctx_info->tc_class_high, pt_control_val);
			ctx_info->tc_class_high |= (ctx_info->tclass & ECN_CE);
		}
		ctx_info->sch_net_tc = NBL_GET_PRI_FROM_T2P(
			rf->sc_dev.tc2pri, NBL_GET_PRI_FROM_TOS(ctx_info->tclass));
		uk_qp->db_tc = ctx_info->sch_net_tc;
	}

	memcpy(ctx_info->dest_ip, &grh->dgid, NBL_GRH_DGID_RAW_SIZE);
	memcpy(ctx_info->dest_mac, attr->ah_attr.roce.dmac,
		sizeof(attr->ah_attr.roce.dmac));

	if (nbl_gid_in_src_addr_table(nbldev, &grh->dgid)) {
		qp->dst_is_local = true;
		/* set look back to local */
		if (rf->product->host_id == HOST_ID_TYPE_ECPU)
			ctx_info->dport = NBL_DEFAULT_DPORT_ECPU;
		else
			ctx_info->dport = NBL_DEFAULT_DPORT_HOST;
		ctx_info->dport_id = rf->vsi_id;
	} else
		qp->dst_is_local = false;

	if (ipv6_addr_v4mapped((struct in6_addr *)&sgid_attr->gid))
		ctx_info->ipv4 = true;

	if (sgid_attr->ndev && is_vlan_dev(sgid_attr->ndev)) {
		ctx_info->vlan_en = true;
		ctx_info->vlan_tag = vlan_dev_vlan_id(sgid_attr->ndev);
		if (pt_en) {
			NBL_SET_VLAN_TAG_PRI(ctx_info->vlan_tag, NBL_DSCP_TO_PRI(pt_trimmable_val));
			/* vlan_pri_high = high 3 bits of pt_control_val */
			ctx_info->vlan_pri_high = NBL_DSCP_TO_PRI(pt_control_val);
		}
	}

	ret = nbl_get_src_addr_info(nbldev, grh->sgid_index,
					    &src_addr_idx, src_ip, &seq_num);
	if (ret) {
		nbl_pr_err("get src addr index failed, function_id: %u, sgid_index: %u.\n",
			nbldev->rf->sc_dev.function_id,
			grh->sgid_index);
		ret = -ENODATA;
		return ret;
	}
	ctx_info->src_addr_idx = src_addr_idx;
	ctx_info->src_addr_idx_seq_num = seq_num;

	ctx_info->udp_sport = nbl_ah_get_udp_sport(nbldev, &attr->ah_attr);

	memcpy(qp->src_ip, src_ip, NBL_SRC_IP_SIZE);
	qp->sgid_index = grh->sgid_index;
	return 0;
}

static void nbl_set_access_flags(struct nbl_uk_qp *uk_qp,
		struct nbl_qp_ctx *ctx_info, struct ib_qp_attr *attr, int attr_mask)
{
	u8 dest_rd_atomic;
	u32 access_flags;

	dest_rd_atomic = (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) ?
			attr->max_dest_rd_atomic : uk_qp->resp_depth;
	access_flags = (attr_mask & IB_QP_ACCESS_FLAGS) ?
			attr->qp_access_flags : uk_qp->atomic_rd_en;
	if (!dest_rd_atomic)
		access_flags &= IB_ACCESS_REMOTE_WRITE;

	ctx_info->read_en = !!(access_flags & IB_ACCESS_REMOTE_READ);
	ctx_info->write_en = !!(access_flags & IB_ACCESS_REMOTE_WRITE);
	if (uk_qp->qp_caps & NBL_ATOMIC)
		ctx_info->atomic_en = !!(access_flags & IB_ACCESS_REMOTE_ATOMIC);

	/* record attr for future use */
	if (attr_mask & IB_QP_ACCESS_FLAGS)
		uk_qp->atomic_rd_en = attr->qp_access_flags;
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		uk_qp->resp_depth = attr->max_dest_rd_atomic;
}

void nbl_check_srp_ext_bmp_en(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	u32 ext_qpn_max;

	ext_qpn_max = rf->sc_dev.srp_ext_bmp_qpn_max;
	if (ctx_info->srp_en &&
		ctx_info->qpn <= ext_qpn_max &&
		ctx_info->dest_qpn <= ext_qpn_max)
		ctx_info->sr_ext_bmp_en = true;
	else
		ctx_info->sr_ext_bmp_en = false;
}

int nbl_rts_set_irq_size(u32 qp_max_rd_atom, u32 qp_max_dest_rd_atom, struct nbl_qp_ctx *ctx_info)
{
	/*if rts set 0, not need to replace */
	if (!qp_max_rd_atom)
		return 0;

	/*if rts ost == 64, rtr ost must be 64 or 0*/
	if (qp_max_rd_atom == NBL_MAX_OST_RD_ATOMIC_V2) {
		if ((qp_max_dest_rd_atom != NBL_MAX_OST_RD_ATOMIC_V2) &&
			(qp_max_dest_rd_atom != 0))
			return -EINVAL;
		ctx_info->read_optimize_en = true;
	/*if rts ost == 8/16/32, rtr ost must not be 64*/
	} else {
		if (qp_max_dest_rd_atom == NBL_MAX_OST_RD_ATOMIC_V2)
			return -EINVAL;
		ctx_info->read_optimize_en = false;
	}
	ctx_info->irq_size = ilog2(qp_max_rd_atom);
	return 0;
}

void nbl_rtr_set_irq_size(u32 qp_max_dest_rd_atom, struct nbl_qp_ctx *ctx_info)
{
	/*rtr is the first time change irq_size and read_optimize_en */
	if (!qp_max_dest_rd_atom) {
		ctx_info->irq_size = 0;
		ctx_info->read_optimize_en = false;
		return;
	}

	ctx_info->irq_size = ilog2(qp_max_dest_rd_atom);
	if (qp_max_dest_rd_atom == NBL_MAX_OST_RD_ATOMIC_V2)
		ctx_info->read_optimize_en = true;
	else
		ctx_info->read_optimize_en = false;
}

static int nbl_get_ctx_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info,
				struct ib_qp_attr *attr, int attr_mask)
{
	int ret = 0;
	enum ib_mtu active_mtu;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	struct nbl_hw_attrs *hw_attr = &qp->nbldev->rf->sc_dev.hw_attrs;

	if (attr_mask & IB_QP_DEST_QPN) {
		ctx_info->dest_qpn = attr->dest_qp_num;
		nbl_check_srp_ext_bmp_en(qp, ctx_info);
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		ctx_info->sq_psn = attr->sq_psn;
		ctx_info->psn_max = (attr->sq_psn) - 1;
	}

	if (attr_mask & IB_QP_RQ_PSN) {
		ctx_info->rq_psn = attr->rq_psn;
		ctx_info->rxp_hpsn = (ctx_info->rq_psn - 1) & NBL_QPC_HPSN_MASK;
	}

	if (attr_mask & IB_QP_QKEY)
		ctx_info->ud_qkey = attr->qkey;

	if (attr_mask & IB_QP_PATH_MTU) {
		if (nbl_get_mtu(ctx_info, qp->nbldev, attr->path_mtu))
			return -EINVAL;
	}

	if (attr_mask & IB_QP_MIN_RNR_TIMER) {
		if (attr->min_rnr_timer > NBL_MAX_RNR_TIMER)
			ctx_info->local_rnr_timer_value = NBL_DEFAULT_RNR_TIMER;
		else if (attr->min_rnr_timer == 0)
			ctx_info->local_rnr_timer_value =
				qp->nbldev->rf->product->qpc_ops->rnr_timer_when_set_zero;
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

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (attr->max_dest_rd_atomic > hw_attr->max_qp_dest_rd_atom)
			return -EINVAL;
		uk_qp->qp_max_dest_rd_atom = attr->max_dest_rd_atomic;
		nbl_rtr_set_irq_size(uk_qp->qp_max_dest_rd_atom, ctx_info);
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic > hw_attr->max_qp_rd_atom)
			return -EINVAL;
		uk_qp->qp_max_rd_atom = attr->max_rd_atomic;
		if (nbl_rts_set_irq_size(uk_qp->qp_max_rd_atom,
				uk_qp->qp_max_dest_rd_atom, ctx_info))
			return -EINVAL;
	}

	if (attr_mask & (IB_QP_ACCESS_FLAGS | IB_QP_MAX_DEST_RD_ATOMIC))
		nbl_set_access_flags(uk_qp, ctx_info, attr, attr_mask);

	/*UD don't set IB_QP_PATH_MTU mask, we must use netdev mtu*/
	if (uk_qp->qp_type == IB_QPT_UD || uk_qp->qp_type == IB_QPT_GSI) {
		active_mtu = iboe_get_mtu(qp->nbldev->netdev->mtu);
		if (!active_mtu) {
			pr_err("inv netdev->mtu:%d\n", qp->nbldev->netdev->mtu);
			return -EINVAL;
		}
		ctx_info->pmtu = IB_MTU_TO_NBL(active_mtu);
	}

	/* modify udp sport */
	if (attr_mask == (IB_QP_AV | IB_QP_PORT)) {
		ctx_info->udp_sport = attr->ah_attr.grh.flow_label;
		nbl_ib_dbg(qp->sc_qp.sc_dev, "modify qpn :%#x udp sport:%#x\n",
			   qp->ibqp.qp_num, ctx_info->udp_sport);
	} else if (attr_mask & IB_QP_AV)
		ret = nbl_get_ah_info(qp, attr, ctx_info);

	return ret;
}

static int nbl_copy_udata_to_user(struct nbl_qp *qp, struct ib_qp_attr *attr,
				  int attr_mask, struct ib_udata *udata)
{
	struct nbl_ib_modify_qp_resp uresp = {};

	if (udata && udata->outlen) {
		/* this info get from nbl_get_ah_info
		 * set by mask IB_QP_AV
		 */
		if (attr_mask & IB_QP_STATE && attr->qp_state == IB_QPS_RTR) {
			uresp.dst_is_local = qp->dst_is_local;
			uresp.local_rd_no_pkt =
				qp->nbldev->rf->sc_dev.local_rd_no_pkt;
			uresp.real_tclass = qp->ctx_info.tclass;
			uresp.pmtu = nbl_mtu_emu_to_init(qp->ctx_info.pmtu);
			/*only create qp and reset can get seq num*/
		} else if (attr_mask & IB_QP_STATE &&
			   attr->qp_state == IB_QPS_RESET) {
			uresp.seq_num = qp->sc_qp.uk_qp.seq_num;
		}

		return ib_copy_to_udata(udata, &uresp,
					min(sizeof(uresp), udata->outlen));
	}
	return 0;
}

/**
 * __nbl_ib_modify_qp - modify qp in kernal(protect by mutex lock)
 * @ibqp: ibqp
 * @attr: modify attr
 * @attr_mask: whitch attr will be modified
 */
static int __nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			      int attr_mask)
{
	struct nbl_qp *qp = container_of(ibqp, struct nbl_qp, ibqp);
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_qp_ctx *ctx_info;
	struct nbl_sc_dev *sc_dev = &nbldev->rf->sc_dev;
	int ret = 0;

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS ||
	((attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) || (attr_mask & IB_QP_PATH_MIG_STATE))) {
		nbl_ib_err(sc_dev, "qpn :%#x, err attr_mask:%#x.\n",
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

	return nbl_modify_hw_qp_state(qp, attr, attr_mask, ctx_info);
}

int nbl_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		     struct ib_udata *udata)
{
	struct nbl_qp *nblqp = container_of(ibqp, struct nbl_qp, ibqp);
	int ret;

	/* without qp state change */
	if (!(attr_mask & IB_QP_STATE))
		return nbl_modify_qp(ibqp, attr, attr_mask, udata);

	/* modify qp state */
	switch (attr->qp_state) {
	case IB_QPS_ERR:
	case IB_QPS_SQE:
		/* modify to err stat, ib spec any to err require no attr */
		ret = nbl_modify_qp_to_err(nblqp, udata);
		break;
	case IB_QPS_RESET:
		ret = nbl_modify_qp_to_reset(ibqp, attr, attr_mask, udata);
		break;
	default:
		ret = nbl_modify_qp(ibqp, attr, attr_mask, udata);
		break;
	}

	return ret;
}

static void nbl_free_qp_rsrc(struct nbl_qp *qp)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_pci_f *rf = nbldev->rf;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;

	nbl_free_qp_buffer(qp);
	nbl_free_qp_hw_queue_mem(rf, sc_qp);
	nbl_free_qp_num(rf, sc_qp->uk_qp.qpn);
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
	struct nbl_uk_qp *uk_qp = &nblqp->sc_qp.uk_qp;
	struct nbl_pci_f *rf = nblqp->nbldev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;

	/*free direct wqe page idx*/
	if (uk_qp->dwqe_en)
		nbl_remove_dpage(rf, nblqp);

	nblqp->sc_qp.uk_qp.destroy_pending = true;
	nbl_modify_qp_to_err(nblqp, NULL);

	/* clean work */
	if (uk_qp->qp_type != IB_QPT_XRC_TGT && !nblqp->user_mode)
		nbl_qp_clean_cqes(nblqp);

	nbl_qp_rem_ref(ibqp);
	wait_for_completion(&nblqp->free_qp);

	nbl_dbg_qp_chk_remove(nblqp);

	/* issud cqp to hardware */
	ret = nbl_cqp_destroy_qp_cmd(nblqp);
	if (ret)
		nbl_ib_err(sc_dev, "destroy qp cqp ret:%d, qpn :%d\n", ret,
			   nblqp->sc_qp.uk_qp.qpn);
	memset(nblqp->sc_qp.qp_shadow.va, 0, nblqp->sc_qp.qp_shadow.size);
	if (nblqp->scq)
		nbl_dec_cqc_ref(nblqp->scq);
	if (nblqp->rcq)
		nbl_dec_cqc_ref(nblqp->rcq);

	nbl_free_qp_rsrc(nblqp);

	return 0;
}

static int nbl_query_qp_psn(struct nbl_qp *qp, struct ib_qp_attr *attr)
{
	int err_code;
	struct nbl_dma_mem qpc_mem;
	__be64 *in;
	struct nbl_device *nbldev = qp->nbldev;

	qpc_mem.size = NBL_QP_CTX_SIZE;
	qpc_mem.va = nbl_dma_alloc_coherent(nbldev->rf->sc_dev.hw,
					qpc_mem.size, &qpc_mem.pa, GFP_KERNEL);
	if (!qpc_mem.va)
		return -ENOMEM;
	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		dma_free_coherent(nbldev->rf->sc_dev.hw->device, qpc_mem.size,
				  qpc_mem.va, qpc_mem.pa);
		return -ENOMEM;
	}

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_QUERY_QP);
	nbl_64bit_write(in, NBL_CQP_QPN, qp->sc_qp.uk_qp.qpn);
	nbl_64bit_write(in, NBL_CQP_QP_CTX_ADDR, qpc_mem.pa);

	err_code = nbl_cmd_exec(nbldev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code) {
		nbl_ib_err(&nbldev->rf->sc_dev, "CQP query qp failed: %u\n",
			   err_code);
		goto out;
	}

	attr->sq_psn = (__u32)nbl_64bit_read(qpc_mem.va, NBL_QPC_V2_PSN_MAX);
	attr->rq_psn = (__u32)nbl_64bit_read(qpc_mem.va, NBL_QPC_V2_EPSN);
	qp->ae_flag = nbl_64bit_read(qpc_mem.va, NBL_QPC_V2_AE_FLAG);

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
	struct nbl_qp_ctx *ctx_info = &qp->ctx_info;
	struct rdma_ah_attr *ah_attr;
	int ret = 0;

	memset(qp_attr, 0, sizeof(*qp_attr));
	memset(qp_init_attr, 0, sizeof(*qp_init_attr));

	qp_attr->qp_state = qp->ibqp_state;
	qp_attr->cur_qp_state = qp->ibqp_state;
	qp_attr->sq_draining = (qp->ibqp_state == IB_QPS_SQD) ? true : false;
	qp_attr->cap.max_send_wr = scqp->uk_qp.max_send_wr;
	qp_attr->cap.max_recv_wr = scqp->uk_qp.max_recv_wr;
	qp_attr->cap.max_send_sge = scqp->uk_qp.max_send_sge;
	qp_attr->cap.max_recv_sge = scqp->uk_qp.max_recv_sge;
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
	qp_attr->max_dest_rd_atomic = scqp->uk_qp.qp_max_dest_rd_atom;
	qp_attr->max_rd_atomic = scqp->uk_qp.qp_max_rd_atom;
	qp_attr->port_num = 1;

	qp_attr->qkey = ctx_info->ud_qkey;
	qp_init_attr->cap = qp_attr->cap;
	qp_init_attr->sq_sig_type = (ctx_info->sq_ce_en == true) ?
					IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;

	ah_attr = &qp_attr->ah_attr;
	ah_attr->type = RDMA_AH_ATTR_TYPE_ROCE;
	ah_attr->port_num = 1;
	rdma_ah_set_grh(ah_attr, NULL, ctx_info->flow_label, qp->sgid_index,
			ctx_info->hop_limit, ctx_info->tclass);
	rdma_ah_set_dgid_raw(ah_attr, ctx_info->dest_ip);
	memcpy(ah_attr->roce.dmac, ctx_info->dest_mac,
		       sizeof(ah_attr->roce.dmac));

	ret = nbl_query_qp_psn(qp, qp_attr);
	if (ret)
		nbl_pr_err("get qpc psn fail\n");
	if (qp->ae_flag && qp->ibqp_state != IB_QPS_ERR) {
		if (wait_for_completion_timeout(
			    &qp->qp_err,
			    msecs_to_jiffies(MODIFY_QP_ERR_TIME_OUT)))
			qp->ibqp_state = IB_QPS_ERR;
	}
	qp_attr->qp_state = qp->ibqp_state;
	qp_attr->cur_qp_state = qp->ibqp_state;
	return ret;
}

void nbl_qp_add_ref(struct nbl_qp *qp)
{
	refcount_inc(&qp->refcnt);
}

/* modify qp case 1, modify qp except to err stat */
int nbl_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata)
{
	struct nbl_qp *nblqp = container_of(ibqp, struct nbl_qp, ibqp);
	int ret = 0;

	mutex_lock(&nblqp->modify_mutex);
	ret = __nbl_ib_modify_qp(ibqp, attr, attr_mask);
	if (!ret && udata)
		ret = nbl_copy_udata_to_user(nblqp, attr, attr_mask, udata);
	mutex_unlock(&nblqp->modify_mutex);
	return ret;
}

/* modify qp case 2, modify qp to err only */
int nbl_modify_qp_to_err(struct nbl_qp *nblqp, struct ib_udata *udata)
{
	struct ib_qp_attr attr;
	int ret = 0;

	mutex_lock(&nblqp->modify_mutex);
	if (nblqp->qp_state != NBL_QP_STATE_ERR &&
	    nblqp->qp_state != NBL_QP_STATE_RST) {
		attr.qp_state = IB_QPS_ERR;
		if (!nblqp->is_dev_obj) {
			ret = __nbl_ib_modify_qp(&nblqp->ibqp, &attr, IB_QP_STATE);
			if (!ret && udata)
				ret = nbl_copy_udata_to_user(nblqp, &attr, IB_QP_STATE, udata);
		} else
			ret = nbl_dv_modify_qp_to_err(nblqp);
	}
	mutex_unlock(&nblqp->modify_mutex);
	return ret;
}

/* modify qp case 3, modify qp to reset only */
int nbl_modify_qp_to_reset(struct ib_qp *ibqp, struct ib_qp_attr *attr, int attr_mask,
		    struct ib_udata *udata)
{
	struct nbl_qp *nblqp = container_of(ibqp, struct nbl_qp, ibqp);
	struct ib_qp_attr err_attr = {0};
	int ret = 0;

	mutex_lock(&nblqp->modify_mutex);

	if (nblqp->qp_state == NBL_QP_STATE_RST)
		goto modify_finish;

	if (nblqp->qp_state != NBL_QP_STATE_ERR) {
		/* make sure state change to ERR */
		err_attr.qp_state = IB_QPS_ERR;
		ret = __nbl_ib_modify_qp(&nblqp->ibqp, &err_attr, IB_QP_STATE);
		if (ret)
			goto modify_finish;
	}

	/* change state to RESET */
	ret = __nbl_ib_modify_qp(ibqp, attr, attr_mask);

modify_finish:
	if (!ret && udata)
		ret = nbl_copy_udata_to_user(nblqp, attr, attr_mask, udata);
	mutex_unlock(&nblqp->modify_mutex);

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

/**
 * nbl_cqp_modify_qp_cmd - modify qp cqp cmd handle
 * @nbldev: nbl device
 * @qp: nbl qp pointer
 * @next_qp_state: nbl qp state
 */
int nbl_cqp_modify_qp_cmd(struct nbl_device *nbldev, struct nbl_qp *qp,
			  u8 next_qp_state)
{
	struct nbl_qp_ctx *ctx_info;
	struct nbl_uk_qp *uk_qp;
	bool epsn_valid = false;
	bool psnmax_valid = false;
	bool total_qpc_flag = false;
	int ret = 0;
	__be64 *in;

	nbl_ib_dbg(&nbldev->rf->sc_dev,
		"[Modify QP] curr nbl qp state: %s, next nbl qp state: %s",
		nbl_qp_stat_to_str(qp->qp_state),
		nbl_qp_stat_to_str(next_qp_state));

	ctx_info = &qp->ctx_info;
	uk_qp = &qp->sc_qp.uk_qp;

	if (qp->qp_state != next_qp_state) {
		if (next_qp_state == NBL_QP_STATE_RTR)
			epsn_valid = true;
		if (next_qp_state == NBL_QP_STATE_RTS)
			psnmax_valid = true;
		if (next_qp_state == NBL_QP_STATE_RST) {
			epsn_valid = false;
			psnmax_valid = false;
			total_qpc_flag = true;
		}
	}

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_MODIFY_QP);
	nbl_64bit_write(in, NBL_CQP_QP_TYPE, uk_qp->nbl_qp_service_type);
	nbl_64bit_write(in, NBL_CQP_QP_NEXT_STATE, next_qp_state);
	nbl_64bit_write(in, NBL_CQP_QP_MODIFY_EPSN, (epsn_valid ? 1 : 0));
	nbl_64bit_write(in, NBL_CQP_QP_MODIFY_PSNMAX, (psnmax_valid ? 1 : 0));
	nbl_64bit_write(in, NBL_CQP_QP_MODIFY_TOTAL_QPC, (total_qpc_flag ? 1 : 0));
	nbl_64bit_write(in, NBL_CQP_QPN, uk_qp->qpn);

	nbl_64bit_write(in, NBL_CQP_QP_CTX_ADDR, qp->sc_qp.qp_ctx_mem.pa);

	nbl_64bit_write(in, NBL_CQP_QP_EPSN, ctx_info->rq_psn);
	nbl_64bit_write(in, NBL_CQP_QP_PSNMAX, ctx_info->psn_max);

	ret = nbl_cmd_exec(nbldev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&qp->nbldev->rf->sc_dev,
			   "CQP modify qp failed(%u)\n", ret);
	kfree(in);
	return ret;
}

int nbl_alloc_user_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			struct nbl_ib_qp_buf *q_buf, unsigned long addr,
			int q_size, bool is_sq, struct ib_udata *udata)
{
	struct nbl_hw *hw = dev->rf->sc_dev.hw;
	struct nbl_dma_mem *mem;
	u32 pas_size;
	int status = 0;
	u32 copy_num;
	u32 pg_num;
	bool is_contiguous;

	q_buf->nbl_peer = false;
	/* maybe gpu mem */
#ifdef CONFIG_INFINIBAND_PEER_MEMORY
	q_buf->umem =
		ib_umem_get_peer(&dev->ibdev, addr, q_size,
			IB_ACCESS_LOCAL_WRITE, 0);
#else
	q_buf->umem = ib_umem_get(&dev->ibdev, addr, q_size,
				   IB_ACCESS_LOCAL_WRITE);
#endif
	if (IS_ERR(q_buf->umem)) {
		nbl_ib_err(&dev->rf->sc_dev, "pin and dma map addr failed.\n");
		return PTR_ERR(q_buf->umem);
	}

	nbl_get_umem_info(q_buf->umem, &pg_num, &is_contiguous, false);

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
		if (is_sq)
			qp->sc_qp.sq_pm = NBL_LEVEL1_PAGE_MODE;
		else
			qp->sc_qp.rq_pm = NBL_LEVEL1_PAGE_MODE;

		/* just support one page by now*/
		pas_size = NBL_ADAPTER_PAGE_SIZE;
		mem->va = nbl_dma_alloc_coherent(hw,
					     NBL_ADAPTER_PAGE_SIZE, &mem->pa,
					     GFP_KERNEL);
		if (!mem->va) {
			nbl_ib_err(&dev->rf->sc_dev,
				   "dma alloc coherent failed.\n");
			nbl_ib_umem_release(q_buf->umem, q_buf->nbl_peer);
			return NBL_ERR_ALLOCMEM_FAILED;
		}

		status = nbl_copy_user_pgaddrs(q_buf->umem, mem->va, pas_size,
					       pg_num, &copy_num);
		if (status) {
			nbl_ib_err(&dev->rf->sc_dev,
				   "copy nbl user pgaddrs failed.\n");
			dma_free_coherent(hw->device,
					  NBL_ADAPTER_PAGE_SIZE, mem->va,
					  mem->pa);
			nbl_ib_umem_release(q_buf->umem, q_buf->nbl_peer);
			return status;
		}
	}
	return status;
}

int nbl_create_kernel_rq(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr)
{
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	enum nbl_status_code status;
	int rqdepth;

	if (init_attr->cap.max_recv_wr > NBL_MAX_QP_WR) {
		pr_err("inv max_recv_wr:%d\n", init_attr->cap.max_recv_wr);
		return -EINVAL;
	}

	nbl_calc_rqwqe_size(uk_qp, init_attr->cap.max_recv_sge);
	uk_qp->max_recv_wr = NBL_MAX_QP_WR;
	rqdepth = uk_qp->max_recv_wr * NBL_MIN_WQE_SIZE;
	qp->kqp.rq_wrid_mem = kcalloc(uk_qp->max_recv_wr,
				      sizeof(*qp->kqp.rq_wrid_mem), GFP_KERNEL);
	if (!qp->kqp.rq_wrid_mem)
		return -ENOMEM;

	status = nbl_alloc_kmode_qp_buffer(qp, qp->nbldev, &sc_qp->rqbuf,
						   rqdepth, false);
	if (status)
		goto free_rq_wrid_mem;

	uk_qp->rq_size = ilog2(rqdepth >> 6);
	uk_qp->rq_wrid_array = qp->kqp.rq_wrid_mem;
	uk_qp->rq_base = qp->sc_qp.rqmem.va;
	NBL_RING_INIT(uk_qp->rq_ring, uk_qp->max_recv_wr);
	return 0;

free_rq_wrid_mem:
	kfree(qp->kqp.rq_wrid_mem);
	qp->kqp.rq_wrid_mem = NULL;
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

	size += NBL_WQE_CTRL_SIZE;
	if (init_attr->qp_type == IB_QPT_RC) {
		init_attr->cap.max_inline_data = NBL_MAX_RC_INLINE_V2;
		size += NBL_WQE_RADDR_SIZE;
	} else if (init_attr->qp_type == IB_QPT_UD) {
		init_attr->cap.max_inline_data = NBL_MAX_UD_INLINE_V2;
		size += NBL_WQE_DATAGRAM_SIZE;
	}
	size += init_attr->cap.max_send_sge *
		sizeof(struct nbl_wqe_data_seg_v2);
	size = ALIGN(size, NBL_MIN_WQE_SIZE);

	tot_size = max(size, inline_size);
	if (tot_size > NBL_V2_MAX_WQE_SIZE) {
		pr_err("tot_size :%d, cap inlie:%d, cap max_send_sge :%d\n",
		       tot_size, init_attr->cap.max_inline_data,
		       init_attr->cap.max_send_sge);
		return -EINVAL;
	}
	return tot_size;
}

int nbl_get_sq_safe_rsv(u16 sq_ost_count, int wqe_size)
{
	return NBL_CALC_SFAE_RSV_CNT(wqe_size, sq_ost_count);
}

int nbl_create_kernel_sq(struct nbl_qp *qp, struct ib_qp_init_attr *init_attr)
{
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	enum nbl_status_code status;
	int sqdepth;
	int wqe_size;

	wqe_size = nbl_calc_send_wqe(init_attr);
	if (wqe_size < 0)
		return -EINVAL;

	uk_qp->sq_safe_rsv =
		nbl_get_sq_safe_rsv(qp->nbldev->rf->product->limits->sq_ost_count,
				    wqe_size);

	sqdepth = (init_attr->cap.max_send_wr * wqe_size) +
		  (uk_qp->sq_safe_rsv * NBL_MIN_WQE_SIZE);
	sqdepth = roundup_pow_of_two(sqdepth);

	if (sqdepth < NBL_MIN_QP_DEPTH)
		sqdepth = NBL_MIN_QP_DEPTH;
	uk_qp->max_send_wr = sqdepth / NBL_MIN_WQE_SIZE;

	if (uk_qp->max_send_wr > NBL_MAX_QP_WR) {
		pr_err("inv sq_wqe_cnt:%d, wqe_size: %d, max_send_wr :%d\n",
		       uk_qp->max_send_wr, wqe_size,
		       init_attr->cap.max_send_wr);
		return -EINVAL;
	}

	qp->kqp.sq_wrid_mem = kcalloc(uk_qp->max_send_wr,
				      sizeof(*qp->kqp.sq_wrid_mem), GFP_KERNEL);
	if (!qp->kqp.sq_wrid_mem)
		return -ENOMEM;

	status = nbl_alloc_kmode_qp_buffer(qp, qp->nbldev, &sc_qp->sqbuf, sqdepth,
					   true);
	if (status)
		goto free_sq_wrid_mem;

	uk_qp->sq_size = ilog2(sqdepth >> 6);
	uk_qp->sq_wrtrk_array = qp->kqp.sq_wrid_mem;
	uk_qp->sq_base = sc_qp->sqmem.va;
	NBL_RING_INIT(uk_qp->sq_ring, uk_qp->max_send_wr);
	return 0;

free_sq_wrid_mem:
	kfree(qp->kqp.sq_wrid_mem);
	qp->kqp.sq_wrid_mem = NULL;
	return status;
}


int nbl_create_kernel_qp(struct nbl_qp *qp,
			struct ib_qp_init_attr *init_attr)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	enum nbl_status_code status;

	status = nbl_create_kernel_sq(qp, init_attr);
	if (status)
		return status;
	if (uk_qp->has_rq) {
		status = nbl_create_kernel_rq(qp, init_attr);
		if (status)
			goto free_sq_buf;
	} else {
		uk_qp->rq_size = 0;
		qp->kqp.rq_wrid_mem = NULL;
		uk_qp->rq_wrid_array = NULL;
		uk_qp->rq_base = NULL;
		uk_qp->max_recv_wr = 0;
	}
	status = nbl_kernel_qp_shadow(qp);
	if (status)
		goto free_rq_buf;
	qp->ctx_info.qp_completion_ctx = qp->sc_qp.uk_qp.qpn;
	qp->user_mode = 0;
	INIT_DELAYED_WORK(&qp->dwork_flush, nbl_flush_dworker);
	qp->first_4a = false;
	qp->first_4b = false;

	return 0;

free_rq_buf:
	if (uk_qp->has_rq)
		nbl_free_kmode_qp_buffer(qp, qp->nbldev, &qp->sc_qp.rqbuf, false);
free_sq_buf:
	nbl_free_kmode_qp_buffer(qp, qp->nbldev, &qp->sc_qp.sqbuf, true);
	return status;
}

void nbl_calc_rqwqe_size(struct nbl_uk_qp *uk_qp, __u32 max_sge)
{
	__u32 size;

	size = NBL_WQE_CTRL_SIZE + NBL_WQE_RSV_SIZE +
	       max_t(uint32_t, max_sge, MIN_WR_SGE) * NBL_WQE_DATA_SIZE;
	size = roundup_pow_of_two(size);
	uk_qp->rqe_mult = size / NBL_WQE_QUANTA_SIZE;
	uk_qp->rq_wqe_size = size;
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
	mem->va = nbl_dma_alloc_coherent(dev->rf->sc_dev.hw, mem->size,
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
			nbl_frag_buf_alloc(dev->rf->sc_dev.hw, &mem->va,
					   &mem->pa, &q_buf->frag_buf);
	}

	return status;
}

void nbl_free_kmode_qp_buffer(struct nbl_qp *qp, struct nbl_device *dev,
			     struct nbl_ib_qp_buf *q_buf, bool is_sq)
{
	struct nbl_hw *hw = dev->rf->sc_dev.hw;
	struct nbl_dma_mem *mem;
	bool page_mode;

	mem = is_sq ? &qp->sc_qp.sqmem : &qp->sc_qp.rqmem;
	page_mode = is_sq ? qp->sc_qp.sq_pm : qp->sc_qp.rq_pm;

	if (!page_mode)
		dma_free_coherent(qp->device, mem->size,
				  mem->va, mem->pa);
	else
		nbl_frag_buf_free(hw, mem->va, mem->pa,
				  &q_buf->frag_buf);
	if (is_sq) {
		kfree(qp->kqp.sq_wrid_mem);
		qp->kqp.sq_wrid_mem = NULL;
		qp->sc_qp.uk_qp.sq_wrtrk_array = NULL;
	} else {
		kfree(qp->kqp.rq_wrid_mem);
		qp->kqp.rq_wrid_mem = NULL;
		qp->sc_qp.uk_qp.rq_wrid_array = NULL;
	}
}

static void nbl_get_and_fill_queue_pa(struct nbl_pci_f *rf,
				      struct nbl_sc_qp *sc_qp,
				      struct nbl_qp_ctx *ctx_info)
{
	ctx_info->raq_ba = (sc_qp->mem_list[NBL_QP_HW_V2_RAQE].pa >>
					NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->iorq_ba = (sc_qp->mem_list[NBL_QP_HW_V2_IORQE].pa >>
					NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->srqew_ba = (sc_qp->mem_list[NBL_QP_HW_V2_SRQEW].pa >>
					NBL_ADAPTER_PAGE_SHIFT);
	ctx_info->unaq_ba = (sc_qp->mem_list[NBL_QP_HW_V2_UNAQE].pa >>
					NBL_ADAPTER_PAGE_SHIFT);
}

static void nbl_get_pd_pa(struct nbl_dma_mem *mem, struct nbl_pd_info *pd_info)
{
	__u64 *temp_addr;
	__u64 pd_entry;

	pd_info->pd_ba = (mem->pa >> NBL_ADAPTER_PAGE_SHIFT);
	temp_addr = (__u64 *)mem->va;
	pd_entry = temp_addr[0];
	pd_entry = be64_to_cpu(pd_entry);
	pd_info->cur_pd_pa = (pd_entry >> NBL_ADAPTER_PAGE_SHIFT);

	pd_entry = temp_addr[1];
	pd_entry = be64_to_cpu(pd_entry);
	pd_info->nxt_pd_pa = (pd_entry >> NBL_ADAPTER_PAGE_SHIFT);
}

static void nbl_fill_level0_pd_info(struct nbl_dma_mem *mem,
				    struct nbl_pd_info *pd_info)
{
	pd_info->pd_ba = (mem->pa >> NBL_ADAPTER_PAGE_SHIFT);
	pd_info->cur_pd_pa = pd_info->pd_ba;
	pd_info->cur_pa_vld = true;
	pd_info->nxt_pa_vld = false;
}

static void nbl_fill_level1_pd_info(struct nbl_dma_mem *mem,
				    struct nbl_pd_info *pd_info)
{
	nbl_get_pd_pa(mem, pd_info);
	pd_info->cur_pa_vld = true;
	pd_info->nxt_pa_vld = true;
}

static void nbl_get_and_fill_sqrq_pd_pa(struct nbl_sc_qp *sc_qp,
					struct nbl_qp_ctx *ctx_info)
{
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;

	if (uk_qp->has_sq) {
		if (sc_qp->sq_pm)
			nbl_fill_level1_pd_info(&sc_qp->sqmem,
						&ctx_info->sq_pd);
		else
			nbl_fill_level0_pd_info(&sc_qp->sqmem,
						&ctx_info->sq_pd);
	} else {
		memset(&ctx_info->sq_pd, 0, sizeof(struct nbl_pd_info));
	}

	if (uk_qp->has_rq) {
		if (sc_qp->rq_pm) {
			nbl_fill_level1_pd_info(&sc_qp->rqmem,
						&ctx_info->rq_pd);

			ctx_info->rxp_rq_cur_pd_pa_l =
				(ctx_info->rq_pd.cur_pd_pa &
				 NBL_RQ_CUR_PD_PA_MASK);
			ctx_info->rxp_rq_cur_pd_pa_h =
				(ctx_info->rq_pd.cur_pd_pa) >>
				NBL_RQ_CUR_PD_PA_SHIFT;
			ctx_info->rxp_rq_nxt_pd_pa_l =
				(ctx_info->rq_pd.nxt_pd_pa &
				 NBL_RQ_NXT_PD_PA_MASK);
			ctx_info->rxp_rq_nxt_pd_pa_h =
				(ctx_info->rq_pd.nxt_pd_pa) >>
				NBL_RQ_NXT_PD_PA_SHIFT;
		} else {
			nbl_fill_level0_pd_info(&sc_qp->rqmem,
						&ctx_info->rq_pd);
			ctx_info->rxp_rq_cur_pd_pa_l =
				(ctx_info->rq_pd.cur_pd_pa) &
				NBL_RQ_CUR_PD_PA_MASK;
			ctx_info->rxp_rq_cur_pd_pa_h =
				(ctx_info->rq_pd.cur_pd_pa) >>
				NBL_RQ_CUR_PD_PA_SHIFT;
		}
	} else {
		memset(&ctx_info->rq_pd, 0, sizeof(struct nbl_pd_info));
		ctx_info->rxp_rq_cur_pd_pa_h = 0;
		ctx_info->rxp_rq_cur_pd_pa_l = 0;
		ctx_info->rxp_rq_nxt_pd_pa_h = 0;
		ctx_info->rxp_rq_nxt_pd_pa_l = 0;
	}
}

static inline u32 nbl_get_cqn(struct nbl_qp *qp, bool is_sq)
{
	if (qp->is_dev_obj)
		return (is_sq ? qp->dev_obj->cqn_snd : qp->dev_obj->cqn_rcv);
	if (is_sq)
		return (qp->scq ? qp->scq->cq_num : NBL_INVALID_CQ_IDX);
	else
		return (qp->rcq ? qp->rcq->cq_num : NBL_INVALID_CQ_IDX);
}

static inline u32 nbl_get_pdn(struct nbl_qp *qp)
{
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;

	if (qp->is_dev_obj)
		return qp->dev_obj->pdn;

	if (uk_qp->qp_type != IB_QPT_XRC_TGT)
		return qp->nblpd->sc_pd.pd_id;

	return 0;
}

void nbl_fill_qpc_info(struct nbl_qp *qp, struct nbl_qp_ctx *ctx_info)
{
	struct nbl_device *nbldev = qp->nbldev;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &qp->sc_qp.uk_qp;
	struct nbl_pci_f *rf = nbldev->rf;

	/* CC is only supported while the service type of qp is RC/SRP/XRC */
	if (uk_qp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_RC ||
		uk_qp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_SRP ||
		uk_qp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_XRC) {
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
		if (ctx_info->cc_mode == NBL_CC || ctx_info->cc_mode == NBL_PCC)
			ctx_info->targetwin =
				rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_TARGETWIN];

		ctx_info->qcn_main_status = 1;
		ctx_info->qcn_limit_rp =
			rf->sc_dev.cc_dbgfs_params[NBL_CFG_QCN_START_RATE] *
			QCN_RP_LIMIT_RATE_PERIOD / QCN_RP_LIMIT_RATE_PERIOD_FACTOR;
		ctx_info->qcn_target_rp = ctx_info->qcn_limit_rp;
		ctx_info->qcn_first_recdb_flag = true;
		ctx_info->qcn_sendpkt_tarwin = 0;
		ctx_info->qcn_remain_trans_bits = 0;
		ctx_info->qcn_alpha = 1023;
	}

	ctx_info->vfid = qp->nbldev->rf->sc_dev.function_id;
	ctx_info->host_id = rf->product->host_id;
	ctx_info->qp_st = qp->qp_state;
	ctx_info->service_type = uk_qp->nbl_qp_service_type;

	ctx_info->dma_len_max = NBL_DMA_LEN_MAX;
	ctx_info->sq_size = uk_qp->sq_size;
	if (qp->srq) /* TODO, ibgda srq check */
		ctx_info->rq_size = ilog2(qp->srq->subq_buf_quanta);
	else
		ctx_info->rq_size = uk_qp->rq_size;
	ctx_info->ackreq_th = rf->sc_dev.ackreq_th;
	ctx_info->seq_num = uk_qp->seq_num;
	ctx_info->p_key = NBL_DEFAULT_PKEY;

	nbl_get_and_fill_queue_pa(rf, sc_qp, ctx_info);
	nbl_get_and_fill_sqrq_pd_pa(sc_qp, ctx_info);
	ctx_info->qpn = uk_qp->qpn;
	if (ctx_info->qpn == NBL_QP_NUM_FOR_CM)
		ctx_info->qp1_mode = true;
	ctx_info->pd_idx = nbl_get_pdn(qp);
	ctx_info->swrqpi_th = NBL_DEFAULT_SWRQPI_TH;

	ctx_info->sq_cqn = nbl_get_cqn(qp, true);
	ctx_info->rq_cqn = nbl_get_cqn(qp, false);
	ctx_info->qpc_ba_low9bit_mask =
		((sc_qp->qp_shadow.pa) >> NBL_QPC_BA_SHIFT);

	ctx_info->ceaq_sq_th = NBL_DEFAULT_CEAQ_SQ_TH;
	ctx_info->ceaq_rq_th = NBL_DEFAULT_CEAQ_RQ_TH;
	if ((uk_qp->qp_type == IB_QPT_GSI) && rf->sc_dev.stat_id)
		ctx_info->stat_id = rf->sc_dev.stat_id +
			NBL_DEFAULT_CM_STAT_ID_OFFSET;
	else if ((uk_qp->qp_type == IB_QPT_RAW_PACKET) &&
				rf->sc_dev.stat_id)
		ctx_info->stat_id =
			rf->sc_dev.stat_id + NBL_DEFAULT_DUMP_STAT_ID_OFFSET;
	else
		ctx_info->stat_id = rf->sc_dev.stat_id;
	ctx_info->dport = rf->sc_dev.dport;
	ctx_info->dport_id = rf->sc_dev.dport_id;
	ctx_info->fwd = rf->sc_dev.fwd;
	ctx_info->rss_lag_en = rf->sc_dev.rss_lag_en;
	ctx_info->tunnel_en =  rf->sc_dev.tunnel_en;
	ctx_info->tver = NBL_DEFAULT_TVER;
	ctx_info->mig = NBL_DEFAULT_MIG;
	if (!qp->user_mode
		&& (uk_qp->qp_type != IB_QPT_XRC_TGT)
		&& (uk_qp->qp_type != NBL_IB_QPT_REG_UMR)) {
		ctx_info->txmr_frmr_en = true;
		/* only kernel QP enable FMR */
		ctx_info->nvme_fmr_en = rf->sc_dev.nvme_fmr_en;
		qp->sc_qp.uk_qp.nvme_fmr_en = ctx_info->nvme_fmr_en;
	}
	ctx_info->sq_pm = sc_qp->sq_pm;
	ctx_info->rq_pm = sc_qp->rq_pm;

	ctx_info->txp_sq_retry_cnt_psn = NBL_DEFAULT_TXP_SQ_RETRY_CNT_PSN;
	if (qp->srq) /* TODO, ibgda srq check */
		ctx_info->rq_wqe_size = qp->srq->wqe_ts;
	else
		ctx_info->rq_wqe_size = uk_qp->rqe_mult;

	ctx_info->wqe_prefetch_en = NBL_DEFAULT_WQE_PREFETCH;

	ctx_info->default_raq_wqe_cap =
		rf->product->qpc_ops->default_raq_wqe_cap;
	/*set txp sq wqe cap 0x10*/
	ctx_info->default_wqe_cap = NBL_DEFAULT_WQE_CAP_V2;
	ctx_info->sport_id = rf->vsi_id;
	ctx_info->vlan_tag = NBL_DEFAULT_VLAN_TAG;
	ctx_info->read_optimize_en = false;
	ctx_info->irq_size = 0;
	/*
	 * local_rnr_timer_value is reused by UD and RC
	 * RC: rnr timer, UD: load pi interval
	 */
	ctx_info->local_rnr_timer_value =
		((uk_qp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_UD) ?
		NBL_DEFAULT_LOAD_PI_INTERVAL : NBL_DEFAULT_RNR_TIMER);
	ctx_info->rto_timer_value = NBL_DEFAULT_RTO_TIMER;
	ctx_info->tx_retry_th = NBL_DEFAULT_RETRY_TH;
	ctx_info->rnr_retry = NBL_DEFAULT_RNR_RETRY_TH;

	ctx_info->q_type = ib_qp_type_to_nbl(uk_qp->qp_type);
	ctx_info->xrcdn = uk_qp->xrcdn;
	ctx_info->srq_en = uk_qp->use_srq;
	if (ctx_info->q_type == NBL_QPT_TGT)
		ctx_info->srq_en = true;
	if (uk_qp->nbl_qp_service_type == NBL_QP_SERVICE_TYPE_SRP)
		ctx_info->srp_en = true;
	if (ctx_info->srp_en)
		ctx_info->srp_spray_en = rf->sc_dev.srp_spray_en;
	/* multi plane spray only for srp qp when 4pf bond mp_en */
	ctx_info->mp_port_spray_en = ctx_info->srp_en && rf->sc_dev.mp_en;
	ctx_info->srp_srack_timer = rf->sc_dev.srp_srack_timer;
	ctx_info->srqn = uk_qp->srqn;
	ctx_info->sq_ce_en = uk_qp->sig_all;
	/* atomic read write enable set as max capability for access ctl */
	ctx_info->atomic_en = qp->sc_qp.uk_qp.qp_caps & NBL_ATOMIC;
	ctx_info->read_en = true;
	ctx_info->write_en = true;
	ctx_info->raqe_cap = NBL_DEFAULT_RAQ_WQE_CAP;
	ctx_info->rqci_th = NBL_DEFAULT_RQCI_TH;
	ctx_info->tlp_timer = rf->sc_dev.tlp_timer;
	ctx_info->tlp_retry_th = rf->sc_dev.tlp_retry_th;
}


int nbl_cqp_process_dpage_idx_cmd(struct nbl_pci_f *rf, int dpage_idx,
				__u32 cmd_code)
{
	int ret = 0;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;
	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, cmd_code);
	nbl_64bit_write(in, NBL_CQP_V2_QP_DWQE_VFID, rf->sc_dev.function_id);
	nbl_64bit_write(in, NBL_CQP_V2_QP_DWQE_PAGE_IDX, dpage_idx);
	nbl_64bit_write(in, NBL_CQP_V2_QP_DWQE_ECPU_FLAG,
			rf->product->host_id == HOST_ID_TYPE_ECPU);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);

	return ret;
}

int nbl_cqp_create_qp_cmd(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	struct nbl_sc_qp *sc_qp = &qp->sc_qp;
	struct nbl_uk_qp *uk_qp = &sc_qp->uk_qp;
	int ret = 0;
	__be64 *in;

	u32 in_size = NBL_CMD_INPUT_SIZE;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_CREATE_QP);
	nbl_64bit_write(in, NBL_CQP_QP_TYPE, uk_qp->nbl_qp_service_type);
	nbl_64bit_write(in, NBL_CQP_QP_NEXT_STATE, NBL_QP_STATE_RST);
	nbl_64bit_write(in, NBL_CQP_QPN, uk_qp->qpn);

	nbl_64bit_write(in, NBL_CQP_QP_CTX_ADDR, sc_qp->qp_ctx_mem.pa);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);
	if (ret)
		nbl_ib_err(&qp->nbldev->rf->sc_dev,
			   "CQP QP create failed(%u)\n", ret);
	kfree(in);
	return ret;
}

int nbl_cqp_destroy_qp_cmd(struct nbl_qp *qp)
{
	struct nbl_pci_f *rf = qp->nbldev->rf;
	int ret = 0;
	__be64 *in;
	u32 in_size = NBL_CMD_INPUT_SIZE;

	in = kzalloc(in_size, GFP_ATOMIC);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_DESTROY_QP);
	nbl_64bit_write(in, NBL_CQP_QPN, qp->sc_qp.uk_qp.qpn);

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
	int ret = 0;

	mutex_lock(&qp->modify_mutex);
	next_qp_state = qp->qp_state;

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
		nbl_pr_err("unsupport qpc_mask:%d\n", qpc_mask);
		ret = -EINVAL;
		goto exit;
	}

	nbl_fill_qp_ctx(qp, qp->sc_qp.qp_ctx_mem.va);
	ret = nbl_cqp_modify_qp_cmd(qp->nbldev, qp, next_qp_state);

exit:
	mutex_unlock(&qp->modify_mutex);
	return ret;
}

int nbl_cqp_v2_flush_s1_cache_cmd(u32 qpn, u16 flush_vfid,
				  struct nbl_pci_f *rf, bool vf_flush_flag)
{
	int ret = 0;
	__be64 *in;
	u16 function_id = flush_vfid;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_S1);
	nbl_64bit_write(in, NBL_CQP_V2_FLUSH_FLAG, vf_flush_flag);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_QPN, qpn);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, function_id);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&rf->sc_dev, "FLUSH s1 CACHE failed(%d),vf_flush_flag=%u,vfid=%u\n",
			   ret, vf_flush_flag, function_id);
	kfree(in);
	return ret;
}

int nbl_cqp_flush_sqrq_cache_cmd(struct nbl_qp *qp)
{
	int ret = 0;
	__be64 *in;
	struct nbl_pci_f *rf = qp->nbldev->rf;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return NBL_ERR_ALLOCMEM_FAILED;

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_FLUSH_CACHE);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_TYPE, FLUSH_CACHE_SQRQC);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_QPN, qp->sc_qp.uk_qp.qpn);
	nbl_64bit_write(in, NBL_CQP_V2_FLUASH_CACHE_VFID, rf->sc_dev.function_id);

	ret = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (ret)
		nbl_ib_err(&qp->nbldev->rf->sc_dev, "CQP QP FLUSH CACHE failed(%u)\n", ret);
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

	ret = nbl_get_qpc_base_addr(rf, qpn, &hmc_info, rf->qp_sd_info);
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
	nbl_dump_fields(rf, func_file, (hmc_info.va + offset), NBL_DBG_DUMP_QPC);
	return 0;
}

int nbl_dbg_create_qp(struct nbl_pci_f *rf, u32 qpn_input)
{
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_dma_mem data_buf;
	u8 *ptr;
	u32 qpn;
	int ret;
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
	data_buf.va = nbl_dma_alloc_coherent(sc_dev->hw, data_buf.size,
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

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_CREATE_QP);
	nbl_64bit_write(in, NBL_CQP_QP_TYPE, 0);
	nbl_64bit_write(in, NBL_CQP_QP_NEXT_STATE, 0);
	nbl_64bit_write(in, NBL_CQP_QPN, qpn);

	nbl_64bit_write(in, NBL_CQP_QP_CTX_ADDR, data_buf.pa);

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

	nbl_64bit_write(in, NBL_CQPSQ_OPCODE_T, NBL_CQP_OP_DESTROY_QP);
	nbl_64bit_write(in, NBL_CQP_QPN, qpn);

	ret = nbl_cmd_exec(rf, in, in_size, NULL, 0);
	if (ret)
		nbl_ib_err(sc_dev, "[dbg qp] destroy qp(%u) cmd err\n", qpn);

	kfree(in);

	return ret;
}

void nbl_qp_ae_handle(struct nbl_qp *nblqp, u16 ae_id)
{
	struct ib_event ib_event;

	if (nblqp->ibqp.event_handler) {
		ib_event.device = nblqp->ibqp.device;
		ib_event.element.qp = &nblqp->ibqp;
		switch (ae_id) {
		case NBL_ERR_V2_SRQ_INV_ERR:
		case NBL_ERR_V2_INV_XRCETH:
		case NBL_ERR_V2_XRC_DOMAIN_ERR:
			ib_event.event = IB_EVENT_QP_ACCESS_ERR;
			break;
		case NBL_ERR_SOFT_AEQ_LAST_WQE:
			ib_event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;
		default:
			return;
		}
		nblqp->ibqp.event_handler(&ib_event,
						nblqp->ibqp.qp_context);
	}
}

static int nbl_set_vf_dump_cfg(struct nbl_pci_f *rf, bool enable_flag)
{
	int ret = 0;
	u8 in[NBL_CMD_INPUT_SIZE] = {0};
	u8 out[NBL_CMD_OUTPUT_SIZE] = {0};
	u8 data_len = 0;
	struct set_vf_dump_req req;
	struct grc_cache_msg_header *head;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SET_VF_DUMP_CFG;
	head->payload_len = sizeof(struct set_vf_dump_req);
	data_len += sizeof(struct grc_cache_msg_header);

	req.vsi_id = rf->vsi_id;
	memcpy(req.rx_vlan_vsi_id, rf->rx_vlan_vsi_id, sizeof(req.rx_vlan_vsi_id));
	req.function_id = rf->sc_dev.function_id;
	req.enable_flag = enable_flag;
	req.is_lag = core_info->is_lag;

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret)
		nbl_dev_err(&rf->pcidev->dev, "set vf=%u dump cfg enable_flag=%u cmd err=%d",
			    rf->sc_dev.function_id, enable_flag, ret);
	return ret;
}

static int nbl_df200_set_dump_cfg(struct nbl_pci_f *rf, bool enable)
{
	nbl_set_dump_rdma_cfg_v3(&rf->hw, rf->vsi_id, enable);
	return 0;
}

static int nbl_rnic400_set_dump_cfg(struct nbl_pci_f *rf, bool enable)
{
	nbl_set_dump_rdma_cfg_v4(&rf->hw, rf->vsi_id,
				 rf->sc_dev.function_id, rf->product->host_id,
				 enable);
	return 0;
}

const struct nbl_dump_ops nbl_df200_dump_ops = {
	.set_cfg = nbl_df200_set_dump_cfg,
};

const struct nbl_dump_ops nbl_draco_dump_ops = {
	.set_cfg = nbl_set_vf_dump_cfg,
};

const struct nbl_dump_ops nbl_rnic400_dump_ops = {
	.set_cfg = nbl_rnic400_set_dump_cfg,
};

struct ib_flow *nbl_ib_create_flow(struct ib_qp *qp, struct ib_flow_attr *flow_attr,
				   struct ib_udata *udata)
{
	int ret;
	struct nbl_qp *nbl_qp = container_of(qp, struct nbl_qp, ibqp);
	struct nbl_pci_f *rf = nbl_qp->nbldev->rf;

	if (flow_attr->type != IB_FLOW_ATTR_SNIFFER) {
		nbl_pr_err("invalid flow type=%d,qpn=%u\n", flow_attr->type, qp->qp_num);
		ret = -EINVAL;
		goto exit;
	}

	nbl_qp->nbl_flow = kcalloc(1, sizeof(struct nbl_ib_flow), GFP_KERNEL);
	if (!nbl_qp->nbl_flow) {
		ret = -ENOMEM;
		goto exit;
	}

	nbl_qp->nbl_flow->flow.qp = &nbl_qp->ibqp;

	ret = rf->product->dump_ops->set_cfg(rf, true);
	if (ret) {
		kfree(nbl_qp->nbl_flow);
		goto exit;
	}

	return &nbl_qp->nbl_flow->flow;
exit:
	return ERR_PTR(ret);
}

int nbl_ib_destroy_flow(struct ib_flow *dump_flow)
{
	struct nbl_qp *qp = container_of(dump_flow->qp, struct nbl_qp, ibqp);
	struct nbl_pci_f *rf = qp->nbldev->rf;

	rf->product->dump_ops->set_cfg(rf, false);
	kfree(qp->nbl_flow);
	return 0;
}
