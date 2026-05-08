// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject_reg.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)

#include <linux/delay.h>
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_mq_debugfs.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_rdma_inject_reg.h"
#define INJECT_AEQ_ADD_CQ_RET	      (-1)
#define INJECT_CQ_ICM_CTX_DESTROY_RET (-1)
#define INJECT_COMMON_RET	      (-EFAULT)
#define INJECT_COMMON_ERR_PTR	      ERR_PTR(INJECT_COMMON_RET)

static void sxe2_drv_inject_ah_err_idx(char *user_data,
				       union sxe2_ah_info *ah_info)
{
	int count = 0;
	long data = 0;

	count = kstrtol(user_data, 0, &data);
	ah_info->field.ah_idx = data;
}

static void sxe2_drv_inject_mq_creat(char *user_data,
				     struct sxe2_mq_err_dbg_val *err_val)
{
	int count = 0;

	count = kstrtol(user_data, 0, (long *)&err_val->mqc_ignore_vld);

}

static void sxe2_drv_inject_mq_dma_err(char *user_data,
				       struct sxe2_mq_err_dbg_val *err_val,
				       u32 *p1, u32 *p2, struct sxe2_mq_ctx *mq)
{
	int count = 0;

	err_val->mqc_addr_vld = true;
	count = kstrtol(user_data, 16, (long *)&err_val->mqc_addr);

	if (err_val->mqc_addr_vld) {
		*p1 = (u32)(err_val->mqc_addr >> MQ_BITS_PER_INT);
		*p2 = (u32)(err_val->mqc_addr);
		DRV_RDMA_LOG_DEBUG(
			"MQ DEBUGFS:ori addr:%#llx, modify addr:%#llx\n",
			mq->mq_ctx_pa, err_val->mqc_addr);
	}

}

static void sxe2_drv_inject_cq_swstatus_err(char *user_data, struct sxe2_rdma_device *rdma_dev,
			struct sxe2_rdma_ctx_cq *cq_ctx)
{
	if (rdma_dev->rdma_func->inject_aeq.cq_sw_status_err) {
		cq_ctx->cqc.sw_status = 0;
		DRV_RDMA_LOG_DEBUG_BDF("inject cq sw_status 0 err.\n");
	}
}

static void sxe2_drv_inject_ceq_sw_status_err(char *user_data,
			struct sxe2_rdma_device *rdma_dev, struct sxe2_rdma_ctx_ceq *ceq_ctx)
{
	if (rdma_dev->rdma_func->inject_aeq.ceq_sw_status_err) {
		ceq_ctx->eqc.sw_status = 0;
		DRV_RDMA_LOG_DEBUG_BDF("inject ceq sw_status 0 err.\n");
	}
}

static void sxe2_drv_inject_db_ceqn_err(char *user_data,
			struct sxe2_rdma_device *rdma_dev, u32 *ci_eqn)
{
	if (rdma_dev->rdma_func->inject_aeq.db_ceqn_err) {
		*ci_eqn = 0xffff;
		DRV_RDMA_LOG_DEBUG_BDF("inject db ceqn 0xffff err.\n");
	}
}

static void sxe2_drv_inject_srq_limit_flag(char *user_data,
			struct sxe2_rdma_device *rdma_dev, struct mq_wqe_of_srq *wqe)
{
	if (rdma_dev->rdma_func->inject_aeq.srq_limit_flag) {
		wqe->lwm = 4;
		DRV_RDMA_LOG_DEV_DEBUG("inject srq limit err. lwm(%d)\n", wqe->lwm);
	}
}

static void sxe2_drv_inject_ceq_ci_noupdate(char *user_data,
			struct sxe2_rdma_device *rdma_dev, u32 *ceq_size, u32 ceq_id)
{
	if (rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate == SXE2_INJECT_EQ_CEQ0_VALUE &&
				 ceq_id == 0) {
		DRV_RDMA_LOG_DEBUG_BDF("inject ceq0 ci no update err ceq min size16.\n");
		*ceq_size = SXE2_MIN_EQ_SIZE * 4;
	} else if (rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate == SXE2_INJECT_EQ_CEQS_VALUE &&
				 ceq_id != 0) {
		DRV_RDMA_LOG_DEBUG_BDF("inject ceq%u ci no update err ceq min size8.\n", ceq_id);
		*ceq_size = SXE2_MIN_EQ_SIZE * 2;
	}
}

static void sxe2_drv_inject_mq_duplicate_creat(char *user_data, u32 *p1,
					       u32 *p2, struct sxe2_mq_ctx *mq)
{
	SXE2_BAR_WRITE_32(*p1, mq->dev->hw_regs[MQC_ADDR_HIGH]);
	SXE2_BAR_WRITE_32(*p2, mq->dev->hw_regs[MQC_ADDR_LOW]);
	SXE2_BAR_WRITE_32(SXE2_MQC_ADDR_VLD_SET,
			  mq->dev->hw_regs[MQC_ADDR_VLD]);
	udelay(mq->dev->hw_attrs.max_done_count *
	       mq->dev->hw_attrs.max_sleep_count);
	DRV_RDMA_LOG_DEBUG("MQ DEBUGFS:duplicate create\n");

}

static void sxe2_drv_inject_mq_size(char *user_data,
				    struct sxe2_mq_err_dbg_val *err_val,
				    struct sxe2_mqc *mqc,
				    struct sxe2_mq_ctx *mq)
{
	int count = 0;

	err_val->mqc_size_vld = true;
	count = kstrtol(user_data, 16, (long *)&err_val->mqc_size);

	if (err_val->mqc_size_vld) {
		mqc->SQ_size = err_val->mqc_size & 0xF;
		DRV_RDMA_LOG_DEBUG(
			"MQ DEBUGFS:ori mq_size:%#llx, modify mq_size:%#llx\n",
			mq->hw_mq_size, mqc->SQ_size);
	}

}

static void sxe2_drv_inject_mq_base(char *user_data,
				    struct sxe2_mq_err_dbg_val *err_val,
				    struct sxe2_mqc *mqc,
				    struct sxe2_mq_ctx *mq)
{
	int count = 0;

	err_val->mqc_base_vld = true;
	count = kstrtol(user_data, 16, (long *)&err_val->mqc_base);

	if (err_val->mqc_base_vld) {
		mqc->SQ_base = err_val->mqc_base;
		DRV_RDMA_LOG_DEBUG(
			"MQ DEBUGFS:ori mq_base:%#llx, modify mq_base:%#llx\n",
			(mq->mq_buf_pa >> SXE2_MQC_SQ_BASE_OFFSET),
			mqc->SQ_base);
	}

}

static void
sxe2_drv_inject_rcms_ctx_err_qp(char *user_data,
				struct sxe2_rcms_create_obj_info *info,
				struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val)
{
	int count = 0;

	err_cqe_val->fpte_rsc_type = SXE2_RCMS_OBJ_QP;
	count = kstrtol(user_data, 10, (long *)&err_cqe_val->fpte_err_type);

	g_inject_fpte_err = 0;
	if ((info->rsrc_type == err_cqe_val->fpte_rsc_type) &&
	    (err_cqe_val->fpte_err_type != 0)) {
		g_inject_fpte_err = err_cqe_val->fpte_err_type;
		DRV_RDMA_LOG_DEBUG(
			"MQ DEBUGFS:fpte_rsc_type:%#x, fpte_err_type %#x,\n"
			"fptes_index[0]:%#x, add_fpt_cnt:%#x\n",
			err_cqe_val->fpte_rsc_type, err_cqe_val->fpte_err_type,
			info->rcms_info->fpte_indexes[0], info->add_fpte_cnt);
	}

}

static void
sxe2_drv_inject_rcms_ctx_err_ssnt(char *user_data,
				  struct sxe2_rcms_create_obj_info *info,
				  struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val)
{
	int count = 0;

	err_cqe_val->fpte_rsc_type = SXE2_RCMS_OBJ_SSNT;
	count = kstrtol(user_data, 10, (long *)&err_cqe_val->fpte_err_type);

	g_inject_fpte_err = 0;
	if ((info->rsrc_type == err_cqe_val->fpte_rsc_type) &&
	    (err_cqe_val->fpte_err_type != 0)) {
		g_inject_fpte_err = err_cqe_val->fpte_err_type;
		DRV_RDMA_LOG_DEBUG(
			"MQ DEBUGFS:fpte_rsc_type:%#x, fpte_err_type %#x,\n"
			"fptes_index[0]:%#x, add_fpt_cnt:%#x\n",
			err_cqe_val->fpte_rsc_type, err_cqe_val->fpte_err_type,
			info->rcms_info->fpte_indexes[0], info->add_fpte_cnt);
	}

}

static void sxe2_drv_inject_mq_rsc_wqe_qpn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	void *qp_wqe, struct sxe2_rdma_ctx_qp *qp, u8 opcode)
{
	int count = 0;
	struct qp_mq_wqe *normal_qp = NULL;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe = NULL;

	err_cqe_val->rsc_wqe_err_type = QPN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	if (!rdma_qp->sw_cc_enable || opcode != SXE2_MQ_OP_CREATE_QP) {
		normal_qp      = (struct qp_mq_wqe *)qp_wqe;
		normal_qp->qpn = (u64)err_cqe_val->rsc_wqe_err_val;
	} else {
		create_cc_qp_wqe = (struct qp_mq_create_cc_qp_wqe *)qp_wqe;
		create_cc_qp_wqe->qp_id = (u64)err_cqe_val->rsc_wqe_err_val;
	}
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#x,\n"
		"ori_qpn %#x\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		qp->qp_common.qpn);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpctx(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	void *qp_wqe, struct sxe2_rdma_ctx_qp *qp, u8 opcode)
{
	int count = 0;
	struct qp_mq_wqe *normal_qp = NULL;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe = NULL;

	err_cqe_val->rsc_wqe_err_type = QP_CTX_PA_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	if (!rdma_qp->sw_cc_enable || opcode != SXE2_MQ_OP_CREATE_QP) {
		normal_qp = (struct qp_mq_wqe *)qp_wqe;
		normal_qp->qp_context_address =
			(u64)err_cqe_val->rsc_wqe_err_val;
	} else {
		create_cc_qp_wqe = (struct qp_mq_create_cc_qp_wqe *)qp_wqe;
		create_cc_qp_wqe->qp_context_address =
			(u64)err_cqe_val->rsc_wqe_err_val;
	}

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#x,\n"
		"ori_qp_ctx_pa %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		qp->hw_host_ctx_pa);

}

static void sxe2_drv_inject_mq_rsc_wqe_createOp(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	void *qp_wqe, struct sxe2_rdma_ctx_qp *qp)
{
	int count = 0;
	struct qp_mq_wqe *normal_qp = NULL;
	struct sxe2_rdma_qp *rdma_qp =
		(struct sxe2_rdma_qp *)qp->qp_common.back_qp;
	struct qp_mq_create_cc_qp_wqe *create_cc_qp_wqe = NULL;

	err_cqe_val->rsc_wqe_err_type = QP_CREATE_OP_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	if (!rdma_qp->sw_cc_enable) {
		normal_qp     = (struct qp_mq_wqe *)qp_wqe;
		normal_qp->op = (u64)err_cqe_val->rsc_wqe_err_val;
	} else {
		create_cc_qp_wqe     = (struct qp_mq_create_cc_qp_wqe *)qp_wqe;
		create_cc_qp_wqe->op = (u64)err_cqe_val->rsc_wqe_err_val;
	}

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#x,\n"
		"err_qp_create_op %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)SXE2_MQ_OP_CREATE_QP);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_swState(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SW_STATE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->qp_state = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori qpc_state 0x0, err qpc_state %#x\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_srqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SRQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->srqn = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_srqn %#x, err qpc_srqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->ctx_info.srqn, (u64)qpc->srqn);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_scqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SEND_CQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->cqn_snd = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_send_cqn %#x, err qpc_send_cqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->ctx_info.send_cq_num, (u64)qpc->cqn_snd);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_rcqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_RECV_CQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->cqn_rcv = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_recv_cqn %#x, err qpc_recv_cqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->ctx_info.rcv_cq_num, (u64)qpc->cqn_rcv);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_type(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_TYPE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_type %#x\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)qpc->qp_type);
	qpc->qp_type = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG("MQ DEBUGFS:err qpc_type %#llx\n",
			   (u64)qpc->qp_type);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_pmtu(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_PMTU_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->pmtu = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_pmtu %#x, err qpc_pmtu %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->ctx_info.udp_info->pmtu, (u64)qpc->pmtu);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_sqSize(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SQ_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->log_sq_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_sq_size %#x, err qpc_sq_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->qp_ctx.hw_sq_size, (u64)qpc->log_sq_size);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_rqSize(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SQ_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->log_rq_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_sq_size %#x, err qpc_sq_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->qp_ctx.hw_rq_size, (u64)qpc->log_rq_size);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_rqType(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_RQ_TYPE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->rq_type = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_rq_type %#x, err qpc_rq_type %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u32)(rdma_qp->qp_ctx.qp_common.srq ? SXE2_SRQ :
						      SXE2_REGULAR_RQ),
		(u64)qpc->rq_type);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_pageSize(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_qpc *qpc, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_PAGE_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	qpc->log_page_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori qpc_page_size %#x, err qpc_page_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		rdma_qp->log_page_size, (u64)qpc->log_page_size);

}

static void sxe2_drv_inject_mq_rsc_wqe_qpc_swState_jump(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct ib_qp_attr *attr, struct sxe2_rdma_qp *rdma_qp)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = QPC_SW_STATE_JUMP_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	rdma_qp->qp_ctx.qp_state = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori qpc_state %#x, err qpc_state %#x\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u32)attr->qp_state, rdma_qp->qp_ctx.qp_state);

}

static void sxe2_drv_inject_mq_rsc_wqe_cqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_cq_wqe *cq_wqe, struct sxe2_rdma_ctx_cq *cq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	cq_wqe->cqn = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori cqc_eqn %#llx, err cqc_eqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		cq->cqc.eqn, cq_wqe->eqn);

}

static void sxe2_drv_inject_mq_rsc_wqe_cqcn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_cq_wqe *cq_wqe, struct sxe2_rdma_ctx_cq *cq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CQC_CEQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	cq_wqe->eqn = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori cqc_eqn %#llx, err cqc_eqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		cq->cqc.eqn, cq_wqe->eqn);

}

static void sxe2_drv_inject_mq_rsc_wqe_cq_swState(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_cq_wqe *cq_wqe, struct sxe2_rdma_ctx_cq *cq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CQC_SW_STATE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	cq_wqe->sw_status = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori cqc_state %#llx, err cqc_state %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		cq->cqc.sw_status, cq_wqe->sw_status);

}

static void sxe2_drv_inject_mq_rsc_wqe_cq_size(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_cq_wqe *cq_wqe, struct sxe2_rdma_ctx_cq *cq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CQC_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	cq_wqe->log_cq_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori cqc_size %#llx, err cqc_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		cq->cqc.log_cq_size, cq_wqe->log_cq_size);

}

static void sxe2_drv_inject_mq_rsc_wqe_srqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct mq_wqe_of_srq *srq_wqe, struct sxe2_rdma_srq_ctx *srq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = SRQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	srq_wqe->srqn = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori srqn %#x, err srqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		srq->srq_drv.srq_id, srq_wqe->srqn);

}

static void sxe2_drv_inject_mq_rsc_wqe_srq_swState(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct mq_wqe_of_srq *srq_wqe, struct sxe2_rdma_srq_ctx *srq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = SRQC_SW_STATE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	srq_wqe->state = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori srqc_state 0, err srqc_state %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		srq_wqe->state);

}

static void sxe2_drv_inject_mq_rsc_wqe_srq_size(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct mq_wqe_of_srq *srq_wqe, struct sxe2_rdma_srq_ctx *srq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = SRQC_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	srq_wqe->log_srq_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x,\n"
		"\trsc_err_val %#llx ori srq_size %#lx, err srq_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		srq->hw_srq_size, srq_wqe->log_srq_size);

}

static void sxe2_drv_inject_mq_rsc_wqe_ceqn(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_eq_wqe *eq_wqe, struct sxe2_rdma_ctx_ceq *ceq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CEQN_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	eq_wqe->eqn = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori ceqn %#x, err ceqn %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		ceq->ceq_id, eq_wqe->eqn);

}

static void sxe2_drv_inject_mq_rsc_wqe_ceq_swState(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_eq_wqe *eq_wqe, struct sxe2_rdma_ctx_ceq *ceq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CEQC_SW_STATE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	eq_wqe->sw_status = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori ceqc_state %#llx, err ceqc_state %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		ceq->eqc.sw_status, eq_wqe->sw_status);

}

static void sxe2_drv_inject_mq_rsc_wqe_ceq_size(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_eq_wqe *eq_wqe, struct sxe2_rdma_ctx_ceq *ceq)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = CEQC_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	eq_wqe->log_eq_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori ceqc_size %#llx, err ceqc_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		ceq->eqc.log_eq_size, eq_wqe->log_eq_size);

}

static void
sxe2_drv_inject_mq_rsc_wqe_ah(char *user_data,
			      struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
			      struct sxe2_ctx_ah *ctx_ah)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = AH_ID_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	ctx_ah->ah_info.field.ah_idx = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori ah_id %#llx, err ah_id %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)ctx_ah->ah_info.field.ah_idx);

}

static void sxe2_drv_inject_mq_rsc_wqe_ah_query(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_hw_ahc *ah_ctx)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = AH_ID_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	ah_ctx->field.ah_idx = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori ah_id %#llx, err ah_id %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)ah_ctx->field.ah_idx);

}

static void sxe2_drv_inject_mq_rsc_wqe_fpte(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_rcms_update_fpte_wqe *update_fpte_wqe)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = FPTE_CNT_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	update_fpte_wqe->fpt_entry_cnt = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
		"ori fpte_cnt %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)update_fpte_wqe->fpt_entry_cnt);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_id_reg(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_reg_mr_info *mr_info)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_ID_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	mr_info->field.mr_idx = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"err mr_id %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		mr_info->field.mr_idx);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_id_dereg(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_dereg_mr_info *mr_info)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_ID_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	mr_info->field.mr_idx = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"err mr_id %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		mr_info->field.mr_idx);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_id_query(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	u32 *mr_index)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_ID_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	*mr_index = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"err mr_id %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		*mr_index);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_accessRight(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_reg_mr_info *mr_info)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_ACCESS_RIGHT_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	mr_info->field.access_right = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"err mr_access_right %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		mr_info->field.access_right);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_type(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_reg_mr_info *mr_info, struct sxe2_mr *vendor_mr)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_TYPE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	mr_info->field.mr_type = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori mr_type %#llx, err mr_type %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)vendor_mr->is_mw, mr_info->field.mr_type);

}

static void sxe2_drv_inject_mq_rsc_wqe_mr_pageSize(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	union sxe2_reg_mr_info *mr_info, struct sxe2_mr *vendor_mr)
{
	int count = 0;

	err_cqe_val->rsc_wqe_err_type = MR_PAGE_SIZE_DEBUGFS;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->rsc_wqe_err_val);

	mr_info->field.log_entity_size = err_cqe_val->rsc_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx,\n"
		"ori mr_page_size %#llx, err mr_page_size %#llx\n",
		err_cqe_val->rsc_wqe_err_type, err_cqe_val->rsc_wqe_err_val,
		(u64)ilog2(vendor_mr->page_size),
		mr_info->field.log_entity_size);

}

static void sxe2_drv_inject_mq_pbl_err(
	char *user_data, struct sxe2_rcms_manage_vf_pble_cp_wqe *manage_cp_wqe,
	struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val)
{
	int count = 0;

	err_cqe_val->manage_pbl_wqe_err_type = MQ_MNG_PBL_OPCODE;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->manage_pbl_wqe_err_val);

	manage_cp_wqe->op = err_cqe_val->manage_pbl_wqe_err_val;
	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx ori op %#x, err op %#llx\n",
		err_cqe_val->manage_pbl_wqe_err_type,
		err_cqe_val->manage_pbl_wqe_err_val,
		(u32)SXE2_MQ_OP_MANAGE_PBLE_BP, manage_cp_wqe->op);

}

static void
sxe2_drv_inject_rcms_commit_err_qp(char *user_data,
				   struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
				   struct sxe2_rcms_info *rcms_info)
{
	int count = 0;

	err_cqe_val->commit_wqe_err_type = SXE2_RCMS_OBJ_QP;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->commit_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject commit_wqe_err_type:%#x, commit_wqe_err_val\n"
		"%#x, ori qp_cnt %#llx, err qp_cnt %#llx\n",
		err_cqe_val->commit_wqe_err_type,
		err_cqe_val->commit_wqe_err_val,
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].cnt,
		err_cqe_val->commit_wqe_err_val);
	rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].cnt =
		err_cqe_val->commit_wqe_err_val;

}

static void
sxe2_drv_inject_rcms_commit_err_cq(char *user_data,
				   struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
				   struct sxe2_rcms_info *rcms_info)
{
	int count = 0;

	err_cqe_val->commit_wqe_err_type = SXE2_RCMS_OBJ_CQ;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->commit_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject commit_wqe_err_type:%#x, commit_wqe_err_val %#x,\n"
		"ori cq_cnt %#llx, err cq_cnt %#llx\n",
		err_cqe_val->commit_wqe_err_type,
		err_cqe_val->commit_wqe_err_val,
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].cnt,
		err_cqe_val->commit_wqe_err_val);
	rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].cnt =
		err_cqe_val->commit_wqe_err_val;

}

static void sxe2_drv_inject_rcms_commit_err_srq(
	char *user_data, struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
	struct sxe2_rcms_info *rcms_info)
{
	int count = 0;

	err_cqe_val->commit_wqe_err_type = SXE2_RCMS_OBJ_SRQ;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->commit_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject commit_wqe_err_type:%#x, commit_wqe_err_val %#x,\n"
		"ori srq_cnt %#llx, err srq_cnt %#llx\n",
		err_cqe_val->commit_wqe_err_type,
		err_cqe_val->commit_wqe_err_val,
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt,
		err_cqe_val->commit_wqe_err_val);
	rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt =
		err_cqe_val->commit_wqe_err_val;

}

static void
sxe2_drv_inject_rcms_commit_err_mr(char *user_data,
				   struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
				   struct sxe2_rcms_info *rcms_info)
{
	int count = 0;

	err_cqe_val->commit_wqe_err_type = SXE2_RCMS_OBJ_MR;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->commit_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject commit_wqe_err_type:%#x, commit_wqe_err_val %#x,\n"
		"ori mr_cnt %#llx, err mr_cnt %#llx\n",
		err_cqe_val->commit_wqe_err_type,
		err_cqe_val->commit_wqe_err_val,
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_MR].cnt,
		err_cqe_val->commit_wqe_err_val);
	rcms_info->rcms_obj[SXE2_RCMS_OBJ_MR].cnt =
		err_cqe_val->commit_wqe_err_val;

}

static void
sxe2_drv_inject_rcms_commit_err_ah(char *user_data,
				   struct sxe2_mq_err_mcqe_dbg_val *err_cqe_val,
				   struct sxe2_rcms_info *rcms_info)
{
	int count = 0;

	err_cqe_val->commit_wqe_err_type = SXE2_RCMS_OBJ_AH;
	count = kstrtol(user_data, 16, (long *)&err_cqe_val->commit_wqe_err_val);

	DRV_RDMA_LOG_DEBUG(
		"MQ DEBUGFS:inject commit_wqe_err_type:%#x, commit_wqe_err_val %#x,\n"
		"ori ah_cnt %#llx, err ah_cnt %#llx\n",
		err_cqe_val->commit_wqe_err_type,
		err_cqe_val->commit_wqe_err_val,
		rcms_info->rcms_obj[SXE2_RCMS_OBJ_AH].cnt,
		err_cqe_val->commit_wqe_err_val);
	rcms_info->rcms_obj[SXE2_RCMS_OBJ_AH].cnt =
		err_cqe_val->commit_wqe_err_val;

}

static void
sxe2_drv_inject_llwqe_flag(char *user_data, struct sxe2_rdma_device *rdma_dev,
								__le64 *push, __le64 *wqe)
{
	if (rdma_dev->rdma_func->inject_aeq.llwqe_flag)
		memcpy(push, wqe, 4);
}

static void sxe2_drv_inject_aeq_ci_noupdate(char *user_data,
			struct sxe2_rdma_device *rdma_dev, u32 *aeq_size)
{
	if (rdma_dev->rdma_func->inject_aeq.aeq_ci_noupdate) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"inject aeq ci no update err ceq min size8.\n");
		*aeq_size = SXE2_MIN_EQ_SIZE * 2;
	}
}

s32 sxe2_drv_inject_reg(struct sxe2_rdma_pci_f *dev)
{
	s32 ret;

	ret = INJECT_REG(dev, "ah_err_idx", sxe2_drv_inject_ah_err_idx,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("ah_err_idx inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "mq_creat", sxe2_drv_inject_mq_creat,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_creat inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "mq_dma_err", sxe2_drv_inject_mq_dma_err,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_dma_err inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "mq_duplicate_creat",
			 sxe2_drv_inject_mq_duplicate_creat,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_duplicate_creat inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_size", sxe2_drv_inject_mq_size,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_size inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "mq_base", sxe2_drv_inject_mq_base,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_base inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "rcms_ctx_err_qp",
			 sxe2_drv_inject_rcms_ctx_err_qp, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("rcms_ctx_err_qp inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "rcms_ctx_err_ssnt",
			 sxe2_drv_inject_rcms_ctx_err_ssnt, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_ctx_err_ssnt inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpn", sxe2_drv_inject_mq_rsc_wqe_qpn,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_qpn inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpctx",
			 sxe2_drv_inject_mq_rsc_wqe_qpctx, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_qpctx inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_createOp",
			 sxe2_drv_inject_mq_rsc_wqe_createOp,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_createOp inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_swState",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_swState,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_swState inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_srqn",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_srqn,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_srqn inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_scqn",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_scqn,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_scqn inject reg fail, ret %d\n", ret);
	}
	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_rcqn",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_rcqn,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rcqn inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_type",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_type,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_type inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_pmtu",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_pmtu,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_pmtu inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_sqSize",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_sqSize,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_sqSize inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_rqSize",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_rqSize,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rqSize inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_rqType",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_rqType,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rqType inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_pageSize",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_pageSize,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_pageSize inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_qpc_swState_jump",
			 sxe2_drv_inject_mq_rsc_wqe_qpc_swState_jump,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_swState_jump inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_cqn", sxe2_drv_inject_mq_rsc_wqe_cqn,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_cqn inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_cqcn",
			 sxe2_drv_inject_mq_rsc_wqe_cqcn, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_cqn inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_cq_swState",
			 sxe2_drv_inject_mq_rsc_wqe_cq_swState,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_cq_swState inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_cq_size",
			 sxe2_drv_inject_mq_rsc_wqe_cq_size,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_cq_size inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_srqn",
			 sxe2_drv_inject_mq_rsc_wqe_srqn, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_srqn inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_srq_swState",
			 sxe2_drv_inject_mq_rsc_wqe_srq_swState,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_srq_swState inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_srq_size",
			 sxe2_drv_inject_mq_rsc_wqe_srq_size,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_srq_size inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_ceqn",
			 sxe2_drv_inject_mq_rsc_wqe_ceqn, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_ceqn inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_ceq_swState",
			 sxe2_drv_inject_mq_rsc_wqe_ceq_swState,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ceq_swState inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_ceq_size",
			 sxe2_drv_inject_mq_rsc_wqe_ceq_size,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ceq_size inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_ah", sxe2_drv_inject_mq_rsc_wqe_ah,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_ah inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_ah_query",
			 sxe2_drv_inject_mq_rsc_wqe_ah_query,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ah_query inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_fpte",
			 sxe2_drv_inject_mq_rsc_wqe_fpte, SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_fpte inject reg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_id_reg",
			 sxe2_drv_inject_mq_rsc_wqe_mr_id_reg,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_reg inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_id_dereg",
			 sxe2_drv_inject_mq_rsc_wqe_mr_id_dereg,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_dereg inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_id_query",
			 sxe2_drv_inject_mq_rsc_wqe_mr_id_query,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_query inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_accessRight",
			 sxe2_drv_inject_mq_rsc_wqe_mr_accessRight,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_accessRight inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_type",
			 sxe2_drv_inject_mq_rsc_wqe_mr_type,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_type inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "mq_rcs_wqe_mr_pageSize",
			 sxe2_drv_inject_mq_rsc_wqe_mr_pageSize,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_pageSize inject reg fail, ret %d\n",
			ret);
	}

	ret = INJECT_REG(dev, "mq_pbl_err", sxe2_drv_inject_mq_pbl_err,
			 SXE2_INJECT_MID_MQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_pbl_err inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "rcms_commit_err_qp",
			 sxe2_drv_inject_rcms_commit_err_qp,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_qp inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "rcms_commit_err_cq",
			 sxe2_drv_inject_rcms_commit_err_cq,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_cq inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "rcms_commit_err_srq",
			 sxe2_drv_inject_rcms_commit_err_srq,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_srq inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "rcms_commit_err_mr",
			 sxe2_drv_inject_rcms_commit_err_mr,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_mr inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "rcms_commit_err_ah",
			 sxe2_drv_inject_rcms_commit_err_ah,
			 SXE2_INJECT_MID_MQ);
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_ah inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_REG(dev, "cq_sw_status_err", sxe2_drv_inject_cq_swstatus_err,
					 SXE2_INJECT_MID_CQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("cq_swstatus_err inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "ceq_sw_status_err", sxe2_drv_inject_ceq_sw_status_err,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("ceq_sw_status_err inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "db_ceqn_err", sxe2_drv_inject_db_ceqn_err,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("db_ceqn_err inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "srq_limit_flag", sxe2_drv_inject_srq_limit_flag,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("srq_limit_flag inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "ceq_ci_noupdate", sxe2_drv_inject_ceq_ci_noupdate,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("ceq_ci_noupdate inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "llwqe_flag", sxe2_drv_inject_llwqe_flag,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("llwqe_flag inject reg fail, ret %d\n", ret);

	ret = INJECT_REG(dev, "aeq_ci_noupdate", sxe2_drv_inject_aeq_ci_noupdate,
					 SXE2_INJECT_MID_CEQ);
	if (ret)
		DRV_RDMA_LOG_ERROR("aeq_ci_noupdate inject reg fail, ret %d\n", ret);

	return ret;
}

void sxe2_drv_inject_unreg(struct sxe2_rdma_pci_f *dev)
{
	s32 ret;

	ret = INJECT_UNREG(dev, "ah_err_idx");
	if (ret) {
		DRV_RDMA_LOG_ERROR("ah_err_idx inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_creat");
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_creat inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "mq_dma_err");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_dma_err inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_duplicate_creat");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_duplicate_creat inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_size");
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_size inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "mq_base");
	if (ret)
		DRV_RDMA_LOG_ERROR("mq_base inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "rcms_ctx_err_qp");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_ctx_err_qp inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "rcms_ctx_err_ssnt");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_ctx_err_ssnt inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpn");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_qpn inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpctx");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpctx inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_createOp");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_createOp inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_swState");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_swState inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_srqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_srqn inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_scqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_scqn inject unreg fail, ret %d\n", ret);
	}
	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_rcqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rcqn inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_type");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_type inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_pmtu");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_pmtu inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_sqSize");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_sqSize inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_rqSize");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rqSize inject reg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_rqType");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_rqType inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_pageSize");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_pageSize inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_qpc_swState_jump");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_qpc_swState_jump inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_cqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_cqn inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_cqcn");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_cqn inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_cq_swState");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_cq_swState inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_cq_size");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_cq_size inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_srqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_srqn inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_srq_swState");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_srq_swState inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_srq_size");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_srq_size inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_ceqn");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ceqn inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_ceq_swState");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ceq_swState inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_ceq_size");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ceq_size inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_ah");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_rcs_wqe_ah inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_ah_query");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_ah_query inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_fpte");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_fpte inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_id_reg");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_reg inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_id_dereg");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_dereg inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_id_query");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_id_query inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_accessRight");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_accessRight inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_type");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_type inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "mq_rcs_wqe_mr_pageSize");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"mq_rcs_wqe_mr_pageSize inject unreg fail, ret %d\n",
			ret);
	}

	ret = INJECT_UNREG(dev, "mq_pbl_err");
	if (ret) {
		DRV_RDMA_LOG_ERROR("mq_pbl_err inject unreg fail, ret %d\n",
				   ret);
	}

	ret = INJECT_UNREG(dev, "rcms_commit_err_qp");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_qp inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "rcms_commit_err_cq");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_cq inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "rcms_commit_err_srq");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_srq inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "rcms_commit_err_mr");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_mr inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "rcms_commit_err_ah");
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"rcms_commit_err_ah inject unreg fail, ret %d\n", ret);
	}

	ret = INJECT_UNREG(dev, "cq_sw_status_err");
	if (ret)
		DRV_RDMA_LOG_ERROR("cq_swstatus_err inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "ceq_sw_status_err");
	if (ret)
		DRV_RDMA_LOG_ERROR("ceq_sw_status_err inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "db_ceqn_err");
	if (ret)
		DRV_RDMA_LOG_ERROR("db_ceqn_err inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "srq_limit_flag");
	if (ret)
		DRV_RDMA_LOG_ERROR("srq_limit_flag inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "ceq_ci_noupdate");
	if (ret)
		DRV_RDMA_LOG_ERROR("ceq_ci_noupdate inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "llwqe_flag");
	if (ret)
		DRV_RDMA_LOG_ERROR("llwqe_flag inject unreg fail, ret %d\n", ret);

	ret = INJECT_UNREG(dev, "aeq_ci_noupdate");
	if (ret)
		DRV_RDMA_LOG_ERROR("aeq_ci_noupdate inject unreg fail, ret %d\n", ret);
}

#endif
