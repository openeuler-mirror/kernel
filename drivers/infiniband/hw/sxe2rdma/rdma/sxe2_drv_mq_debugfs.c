// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mq_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_mq_debugfs.h"
#include "sxe2_drv_rdma_inject.h"

#define MQ_DEBUGFS_WRITE_BUF_MAX_LEN (64)
#define INJECT_CMD_LEN		     32

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
enum {
	MQ_SIZE_DEBUGFS,
	MQ_BASE_DEBUGFS,
};

static char *mq_fields[] = {
	[MQ_SIZE_DEBUGFS] = "mq_size",
	[MQ_BASE_DEBUGFS] = "mq_base",
};

char *rcms_type_fields[] = {
	[SXE2_RCMS_OBJ_QP] = "qp",     [SXE2_RCMS_OBJ_CQ] = "cq",
	[SXE2_RCMS_OBJ_SRQ] = "srq",   [SXE2_RCMS_OBJ_MR] = "mr",
	[SXE2_RCMS_OBJ_RESP] = "resp", [SXE2_RCMS_OBJ_IRRL] = "irrl",
	[SXE2_RCMS_OBJ_SSNT] = "ssnt", [SXE2_RCMS_OBJ_AH] = "ah",
};

int size_rcms_type = ARRAY_SIZE(rcms_type_fields);

char *mq_rsc_wqe_err_fields[] = {
	[MQ_WQE_ERR_DEBUGFS_CLR]    = "no",
	[QPN_DEBUGFS]		    = "qpn",
	[CQN_DEBUGFS]		    = "cqn",
	[SRQN_DEBUGFS]		    = "srqn",
	[CEQN_DEBUGFS]		    = "ceqn",
	[AEQN_DEBUGFS]		    = "aeqn",
	[QPC_SRQN_DEBUGFS]	    = "qpc_srqn",
	[QPC_SEND_CQN_DEBUGFS]	    = "qpc_send_cqn",
	[QPC_RECV_CQN_DEBUGFS]	    = "qpc_recv_cqn",
	[CQC_CEQN_DEBUGFS]	    = "cqc_ceqn",
	[QPC_SW_STATE_DEBUGFS]	    = "qpc_state",
	[CQC_SW_STATE_DEBUGFS]	    = "cqc_state",
	[SRQC_SW_STATE_DEBUGFS]	    = "srqc_state",
	[CEQC_SW_STATE_DEBUGFS]	    = "ceqc_state",
	[AEQC_SW_STATE_DEBUGFS]	    = "aeqc_state",
	[QPC_TYPE_DEBUGFS]	    = "qpc_type",
	[QPC_PMTU_DEBUGFS]	    = "qpc_pmtu",
	[QPC_SQ_SIZE_DEBUGFS]	    = "qpc_sq_size",
	[QPC_RQ_SIZE_DEBUGFS]	    = "qpc_rq_size",
	[CQC_SIZE_DEBUGFS]	    = "cqc_size",
	[SRQC_SIZE_DEBUGFS]	    = "srqc_size",
	[CEQC_SIZE_DEBUGFS]	    = "ceqc_size",
	[AEQC_SIZE_DEBUGFS]	    = "aeqc_size",
	[QPC_RQ_TYPE_DEBUGFS]	    = "qpc_rq_type",
	[QPC_PAGE_SIZE_DEBUGFS]	    = "qpc_page_size",
	[QPC_SW_STATE_JUMP_DEBUGFS] = "qpc_jump_state",
	[FPTE_CNT_DEBUGFS]	    = "fpte_cnt",
	[AH_ID_DEBUGFS]		    = "ah_id",
	[MR_ID_DEBUGFS]		    = "mr_id",
	[MR_ACCESS_RIGHT_DEBUGFS]   = "mr_access_right",
	[MR_TYPE_DEBUGFS]	    = "mr_type",
	[MR_PAGE_SIZE_DEBUGFS]	    = "mr_page_size",
	[QP_CTX_PA_DEBUGFS]	    = "qp_ctx_pa",
	[QP_CREATE_OP_DEBUGFS]	    = "qp_create_op",
};

int mq_rsc_wqe_size = ARRAY_SIZE(mq_rsc_wqe_err_fields);

char *mq_mng_pbl_wqe_err_fields = "opcode";

#endif

static void mq_cmd_print(char *rsp_end, u32 *len_total,
			 struct sxe2_rdma_device *rdma_dev)
{
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total,
		"0x00.SXE2_MQ_OP_CREATE_QP    %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_CREATE_QP],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_CREATE_QP]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x01.SXE2_MQ_OP_MODIFY_QP %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_MODIFY_QP],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_MODIFY_QP]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x02.SXE2_MQ_OP_DESTROY_QP %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DESTROY_QP],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DESTROY_QP]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x03.SXE2_MQ_OP_CREATE_CQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_CREATE_CQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_CREATE_CQ]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x04.SXE2_MQ_OP_MODIFY_CQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_MODIFY_CQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_MODIFY_CQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x05.SXE2_MQ_OP_DESTROY_CQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DESTROY_CQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DESTROY_CQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x09.SXE2_MQ_OP_ALLOC_MR_key %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_ALLOC_MR_key],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_ALLOC_MR_key]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x0a.SXE2_MQ_OP_REG_MR %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_REG_MR],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_REG_MR]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x0b.SXE2_MQ_OP_QUERY_MR_key %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_QUERY_MR_key],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_QUERY_MR_key]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x0d.SXE2_MQ_OP_DEALLOC_MR_key %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DEALLOC_MR_key],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DEALLOC_MR_key]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x10.SXE2_MQ_OP_MANAGE_PBLE_BP %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_MANAGE_PBLE_BP],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_MANAGE_PBLE_BP]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x13.SXE2_MQ_OP_QUERY_QP %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_QP],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_QP]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total,
		"0x15.SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev
			.mq_post_stats[SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE],
		rdma_dev->rdma_func->ctx_dev
			.mq_cmd_stats[SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x16.SXE2_MQ_OP_CREATE_CEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_CREATE_CEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_CREATE_CEQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x18.SXE2_MQ_OP_DESTROY_CEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DESTROY_CEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DESTROY_CEQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x19.SXE2_MQ_OP_CREATE_AEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_CREATE_AEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_CREATE_AEQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x1b.SXE2_MQ_OP_DESTROY_AEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DESTROY_AEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DESTROY_AEQ]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total,
		"0x1c.SXE2_MQ_OP_CREATE_ADDR_HANDLE %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev
			.mq_post_stats[SXE2_MQ_OP_CREATE_ADDR_HANDLE],
		rdma_dev->rdma_func->ctx_dev
			.mq_cmd_stats[SXE2_MQ_OP_CREATE_ADDR_HANDLE]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total,
		"0x1d.SXE2_MQ_OP_MODIFY_ADDR_HANDLE %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev
			.mq_post_stats[SXE2_MQ_OP_MODIFY_ADDR_HANDLE],
		rdma_dev->rdma_func->ctx_dev
			.mq_cmd_stats[SXE2_MQ_OP_MODIFY_ADDR_HANDLE]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total,
		"0x1e.SXE2_MQ_OP_DESTROY_ADDR_HANDLE %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev
			.mq_post_stats[SXE2_MQ_OP_DESTROY_ADDR_HANDLE],
		rdma_dev->rdma_func->ctx_dev
			.mq_cmd_stats[SXE2_MQ_OP_DESTROY_ADDR_HANDLE]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x1f.SXE2_MQ_OP_UPDATE_FPT %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_UPDATE_FPT],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_UPDATE_FPT]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x20.SXE2_MQ_OP_QUERY_FPM_VAL %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_QUERY_FPM_VAL],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_QUERY_FPM_VAL]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x21.SXE2_MQ_OP_COMMIT_FPM_VAL %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_COMMIT_FPM_VAL],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_COMMIT_FPM_VAL]);
	*len_total += dbg_vsnprintf(
		rsp_end, *len_total, "0x24.SXE2_MQ_OP_NOP %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_NOP],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_NOP]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x2e.SXE2_MQ_OP_GATHER_STATS %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_GATHER_STATS],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_GATHER_STATS]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x30.SXE2_MQ_OP_CREATE_SRQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_CREATE_SRQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_CREATE_SRQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x31.SXE2_MQ_OP_MODIFY_SRQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_MODIFY_SRQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_MODIFY_SRQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x32.SXE2_MQ_OP_DESTROY_SRQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DESTROY_SRQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DESTROY_SRQ]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x33.SXE2_MQ_OP_DEREGISTER_MR %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_DEREGISTER_MR],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_DEREGISTER_MR]);
	*len_total +=
		dbg_vsnprintf(rsp_end, *len_total,
			      "0x34.SXE2_MQ_OP_MODIFY_CEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_MODIFY_CEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_MODIFY_CEQ]);
}

static ssize_t mq_kget_status_dbg_read_op(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_mq *mq;
	struct sxe2_rdma_mcq *mcq;
	struct mq_wqe_nop *wqe = NULL;
	u32 pending_index      = 0;
	u32 pending_count      = 0;
	u32 pending_i	       = 0;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	mq  = &rdma_dev->rdma_func->mq;
	mcq = &rdma_dev->rdma_func->mcq;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "mq:status:\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "MQ head %#x, tail %#x, size %#x\n",
				   mq->mq.mq_ring.head, mq->mq.mq_ring.tail,
				   mq->mq.mq_ring.size);

	pending_count = (u32)SXE2_RING_USED_QUANTA(mq->mq.mq_ring);
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "MQ pending WQE count %#x\n", pending_count);
	for (pending_i = 0; pending_i < pending_count; pending_i++) {
		pending_index = mq->mq.mq_ring.tail;
		wqe = (struct mq_wqe_nop *)(mq->mq.mq_buf_va[pending_index]
						    .elem);
		if (wqe)
			len_total +=
				dbg_vsnprintf(rsp_end, len_total,
					      "MQ pending WQE %#x:opcode %#x\n",
					      pending_index, wqe->op);
		else
			len_total +=
				dbg_vsnprintf(rsp_end, len_total,
					      "MQ pending WQE %#x:not found\n",
					      pending_index);
		pending_index = (pending_index + 1) % mq->mq.mq_ring.size;
	}

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "MCQ head %#x, tail %#x, size %#x\n",
				   mcq->ctx_cq.cq_uk.cq_ring.head,
				   mcq->ctx_cq.cq_uk.cq_ring.tail,
				   mcq->ctx_cq.cq_uk.cq_ring.size);

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "---Opcode---postcount---handlecount---\n");
	mq_cmd_print(rsp_end, (u32 *)&len_total, rdma_dev);
	len_total += dbg_vsnprintf(
		rsp_end, len_total, "0x35.SXE2_MQ_OP_QUERY_CEQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_CEQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_CEQ]);
	len_total +=
		dbg_vsnprintf(rsp_end, len_total,
			      "0x36.SXE2_MQ_OP_MODIFY_AEQ %#llx %#llx\n",
			      rdma_dev->rdma_func->ctx_dev
				      .mq_post_stats[SXE2_MQ_OP_MODIFY_AEQ],
			      rdma_dev->rdma_func->ctx_dev
				      .mq_cmd_stats[SXE2_MQ_OP_MODIFY_AEQ]);
	len_total += dbg_vsnprintf(
		rsp_end, len_total, "0x37.SXE2_MQ_OP_QUERY_AEQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_AEQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_AEQ]);
	len_total += dbg_vsnprintf(
		rsp_end, len_total, "0x38.SXE2_MQ_OP_QUERY_CQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_CQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_CQ]);
	len_total += dbg_vsnprintf(
		rsp_end, len_total, "0x39.SXE2_MQ_OP_QUERY_SRQ %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_SRQ],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_SRQ]);
	len_total += dbg_vsnprintf(
		rsp_end, len_total, "0x3b.SXE2_MQ_OP_QUERY_MR %#llx %#llx\n",
		rdma_dev->rdma_func->ctx_dev.mq_post_stats[SXE2_MQ_OP_QUERY_MR],
		rdma_dev->rdma_func->ctx_dev.mq_cmd_stats[SXE2_MQ_OP_QUERY_MR]);

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_mq_status_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kget_status_dbg_read_op,
};

static ssize_t mq_khandle_nop_cmd_dbg_read_op(struct file *filp,
					      char __user *buf, size_t count,
					      loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'post' 'wait' 'count' > mq_gen_nop\n"
		"post:0-1,0 won't post cmd, 1 post cmd right now\n"
		"wait:1-4,1 pollreg,2 pollcqe,3 waitevent,4 waitcqe\n"
		"count:mq nop cmd counts, decimal data\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo 1 10 > mq_gen_nop\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_khandle_nop_cmd_dbg_write_op(struct file *filp,
					       const char __user *buf,
					       size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u32 op_wait	   = 0;
	u32 op_count	   = 0;
	u32 op_post	   = 0;
	bool op_post_param = false;
	u32 i;

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %zd\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %zd\n",
				   ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %zd\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	cmd[count - 1] = '\0';
	ret	       = sscanf(cmd, "%u %u %u", &op_post, &op_wait, &op_count);
	if (ret != DEBUG_PARA_CONT3) {
		ret = -ENODATA;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Please input 'post wait count', three params, ret %zd\n",
			ret);
		goto end;
	}
	if (op_post > 1) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:post_type err,please input 0/1\n");
		goto end;
	}
	if ((op_wait == 0) || (op_wait > SXE2_MQ_WAIT_CQE)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:wait_type err,please input 1-4\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:input post %u, wait %u, count %u\n",
			       op_post, op_wait, op_count);

	if (op_post == 0)
		op_post_param = false;
	else if (op_post == 1)
		op_post_param = true;

	if ((op_wait == SXE2_MQ_WAIT_EVENT) || (op_wait == SXE2_MQ_WAIT_CQE)) {
		for (i = 0; i < op_count; i++) {
			ret = sxe2_mq_kexec_nop_op(rdma_dev, op_post_param,
						   op_wait);
			if (ret == 0) {
				DRV_RDMA_LOG_DEV_DEBUG(
					"MQ DEBUGFS:NOP cmd post %u,\n"
					"\twait_type %u, now_count %u, ret %zd\n",
					op_post_param, op_wait, i, ret);
			} else {
				DRV_RDMA_LOG_DEV_ERR(
					"MQ DEBUGFS:NOP cmd post %u,\n"
					"\twait_type %u, now_count %u, ret %zd\n",
					op_post_param, op_wait, i, ret);
				goto end;
			}
		}
	} else if ((op_wait == SXE2_MQ_WAIT_POLL_REGS) ||
		   (op_wait == SXE2_MQ_WAIT_POLL_CQ)) {
		for (i = 0; i < op_count; i++) {
			ret = sxe2_knop(&rdma_dev->rdma_func->mq.mq, 0,
					op_post_param, (u8)op_wait);
			if (ret == 0) {
				DRV_RDMA_LOG_DEV_DEBUG(
					"MQ DEBUGFS:NOP cmd post %u,\n"
					"\twait_type %u, now_count %u, ret %zd\n",
					op_post_param, op_wait, i, ret);
			} else {
				DRV_RDMA_LOG_DEV_ERR(
					"MQ DEBUGFS:NOP cmd post %u,\n"
					"\twait_type %u, now_count %u, ret %zd\n",
					op_post_param, op_wait, i, ret);
				goto end;
			}
		}
	} else {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:op_wait err,please input 1-4, ret %zd\n",
			ret);
	}

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_nop_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_khandle_nop_cmd_dbg_read_op,
	.write = mq_khandle_nop_cmd_dbg_write_op,
};

static ssize_t mq_kignore_mcqe_dbg_read_op(struct file *filp, char __user *buf,
					   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	if (rdma_dev->rdma_func->mq.mcqe_ignore)
		len_total +=
			dbg_vsnprintf(rsp_end, len_total, "Now ignore MCQE\n");
	else
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "Now not ignore MCQE\n");

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo '0/1' > mcqe_ignore\n"
		"1:all mcqe will be ignored, 0:all mcqe will be handled\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kignore_mcqe_dbg_write_op(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %zd\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %zd\n",
				   ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %zd\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_INFO("MQ DEBUGFS:Request command :%s\n", cmd);

	cmd[count - 1] = '\0';
	if (strcmp(cmd, "1") == 0) {
		rdma_dev->rdma_func->mq.mcqe_ignore = true;
		DRV_RDMA_LOG_DEV_INFO(
			"MQ DEBUGFS:from now,all mcqe will be ignored\n");
	} else if (strcmp(cmd, "0") == 0) {
		rdma_dev->rdma_func->mq.mcqe_ignore = false;
		DRV_RDMA_LOG_DEV_INFO(
			"MQ DEBUGFS:from now,all mcqe will be processed\n");
	} else {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd is not 1, please retry, ret %zd\n",
			ret);
	}

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_ignore_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kignore_mcqe_dbg_read_op,
	.write = mq_kignore_mcqe_dbg_write_op,
};

static u64 mq_kread_debugfs_field(struct sxe2_rdma_device *rdma_dev, void *data,
				  enum drv_rdma_dbg_rsc_type type, char *buf)
{
	int ret;
	struct sxe2_mqc mqc;
	struct sxe2_mq *mq;
	size_t len = 0;

	memset(&mqc, 0, sizeof(mqc));

	if (!rdma_dev || !data) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:RDMA Dev/Data is NULL, ret %d\n",
				   ret);
		goto end;
	}

	if (type == SXE2_DBG_RSC_MQ) {
		mq = (struct sxe2_mq *)data;
		memcpy(&mqc, mq->mq.mq_ctx_va, sizeof(mqc));
	}

	len += dbg_vsnprintf(buf, len, "mq:context:\n");
	len += dbg_vsnprintf(buf, len, "enable_fine_grained_timers:%#x\n",
			     (u32)mqc.enable_fine_grained_timers);
	len += dbg_vsnprintf(buf, len, "disable_FPDU_packing:%#x\n",
			     (u32)mqc.disable_FPDU_packing);
	len += dbg_vsnprintf(buf, len, "RoCEv2_RTO_policy:%#x\n",
			     (u32)mqc.RoCEv2_RTO_policy);
	len += dbg_vsnprintf(buf, len, "protocol_used:%#x\n",
			     (u32)mqc.protocol_used);
	len += dbg_vsnprintf(buf, len, "struct_version:%#x\n",
			     (u32)mqc.struct_version);
	len += dbg_vsnprintf(buf, len, "num_CEQs_per_VF:%#x\n",
			     (u32)mqc.num_CEQs_per_VF);
	len += dbg_vsnprintf(buf, len, "SQ_base:%#llx\n", (u64)mqc.SQ_base);
	len += dbg_vsnprintf(buf, len, "rcms_profile_type:%#x\n",
			     (u32)mqc.rcms_profile_type);
	len += dbg_vsnprintf(buf, len, "remote_endpoint_trk_en:%#x\n",
			     (u32)mqc.remote_endpoint_trk_en);
	len += dbg_vsnprintf(buf, len, "rdpa_assist:%#x\n",
			     (u32)mqc.rdpa_assist);
	len += dbg_vsnprintf(buf, len, "cache_line_64byte_en:%#x\n",
			     (u32)mqc.cache_line_64byte_en);
	len += dbg_vsnprintf(buf, len, "PE_enabled_vf_count:%#x\n",
			     (u32)mqc.PE_enabled_vf_count);
	len += dbg_vsnprintf(buf, len, "QP_completion_context:%#llx\n",
			     (u64)mqc.QP_completion_context);
	len += dbg_vsnprintf(buf, len, "hw_minor_version:%#x\n",
			     (u32)mqc.hw_minor_version);
	len += dbg_vsnprintf(buf, len, "hw_major_version:%#x\n",
			     (u32)mqc.hw_major_version);
	len += dbg_vsnprintf(buf, len, "dcqcn_min_rate:%#x\n",
			     (u32)mqc.dcqcn_min_rate);
	len += dbg_vsnprintf(buf, len, "dcqcn_min_dec_factor:%#x\n",
			     (u32)mqc.dcqcn_min_dec_factor);
	len += dbg_vsnprintf(buf, len, "dcqcn_T:%#x\n", (u32)mqc.dcqcn_T);
	len += dbg_vsnprintf(buf, len, "cc_hai_factor:%#x\n",
			     (u32)mqc.cc_hai_factor);
	len += dbg_vsnprintf(buf, len, "cc_rai_factor:%#x\n",
			     (u32)mqc.cc_rai_factor);
	len += dbg_vsnprintf(buf, len, "dcqcn_B:%#x\n", (u32)mqc.dcqcn_B);
	len += dbg_vsnprintf(buf, len, "dcqcn_F:%#x\n", (u32)mqc.dcqcn_F);
	len += dbg_vsnprintf(buf, len, "cc_cfg_valid:%#x\n",
			     (u32)mqc.cc_cfg_valid);
	len += dbg_vsnprintf(buf, len, "dcqcn_rreduce_mperiod:%#x\n",
			     (u32)mqc.dcqcn_rreduce_mperiod);

end:
	return len;
}

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
void sxe2_kadd_mq_nop_debugfs_files(struct sxe2_rdma_device *rdma_dev)
{
	debugfs_create_file("mq_gen_nop", SXE2_DEBUG_FILE_ONLY_WRITE,
			    rdma_dev->hdl->mq_debugfs, rdma_dev,
			    &sxe2_rdma_mq_nop_fops);
	debugfs_create_file("mcqe_ignore", SXE2_DEBUG_FILE_ONLY_WRITE,
			    rdma_dev->hdl->mq_debugfs, rdma_dev,
			    &sxe2_rdma_mq_ignore_fops);
}

static ssize_t mq_kcreate_dup_dbg_read_op(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'count' 'first_ignore_hw' > dup_create\n"
		"count:creation counts, decimal data\n"
		"first_ignore_hw:0/1, if ignore hw in first creation\n");
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "ex:echo 2 0 > dup_create\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kcreate_dup_dbg_write_op(struct file *filp,
					   const char __user *buf, size_t count,
					   loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u64 op_count  = 1;
	u64 if_ignore = 0;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	char cmd_buf[INJECT_CMD_LEN]	 = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %ld\n",
				   ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Please input 'count' 'first_ignore_hw'\n");
		goto end;
	}

	ret = kstrtoull(argv[0], 10, &op_count);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get op_count param value failed, ret (%ld)\n",
			ret);
		goto end;
	}

	ret = kstrtoull(argv[1], 10, &if_ignore);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get if_ignore param value failed, ret (%ld)\n",
			ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:count %llu, if_notify %llu\n",
			       op_count, if_ignore);
	snprintf(cmd_buf, sizeof(cmd_buf), "-u %llu", if_ignore);
	if (op_count == 1 && if_ignore == 1) {
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_creat", cmd_buf);
		ret = sxe2_kcreate_mq(rdma_dev);
		if (ret == 0) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"MQ DEBUGFS:create mq, ret %ld\n", ret);
		}
	}

	if (op_count == 2 && if_ignore == 0) {
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_duplicate_creat",
			      cmd_buf);
	}

	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_creat");

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_dup_create_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kcreate_dup_dbg_read_op,
	.write = mq_kcreate_dup_dbg_write_op,
};

static ssize_t mq_kcreate_ctx_addr_dbg_read_op(struct file *filp,
					       char __user *buf, size_t count,
					       loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:mqc_addr vld %d, mqc_addr %#llx\n\n",
		rdma_dev->rdma_func->mq.err_val.mqc_addr_vld,
		rdma_dev->rdma_func->mq.err_val.mqc_addr);

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "CMD HELP:\n"
				   "Please echo 'addr' > 0x2_mqc_addr\n"
				   "addr:Hex data\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo 0xFFFFFFFF > 0x2_mqc_addr\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kcreate_ctx_addr_dbg_write_op(struct file *filp,
						const char __user *buf,
						size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u64 mqc_addr = 0;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	char cmd_buf[INJECT_CMD_LEN]	 = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT1) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	ret = kstrtoull(argv[0], 16, &mqc_addr);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "-u %llx", mqc_addr);
	INJECT_ACTIVE(rdma_dev->rdma_func, "mq_dma_err", cmd_buf);
	DRV_RDMA_LOG_DEBUG_BDF("MQ DEBUGFS:addr %#llx\n", mqc_addr);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_ctx_addr_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kcreate_ctx_addr_dbg_read_op,
	.write = mq_kcreate_ctx_addr_dbg_write_op,
};

static ssize_t mq_kcreate_ctx_dbg_read_op(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:mq_size vld:%d,\n"
		"\tmq_size:%#llx, mq_base vld:%d, mq_base:%#llx\n\n",
		rdma_dev->rdma_func->mq.err_val.mqc_size_vld,
		rdma_dev->rdma_func->mq.err_val.mqc_size,
		rdma_dev->rdma_func->mq.err_val.mqc_base_vld,
		rdma_dev->rdma_func->mq.err_val.mqc_base);

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "CMD HELP:\n"
				   "Please echo 'field' 'val' > mqc_err\n"
				   "field:mq_size/mq_base, val:Hex data\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex1:echo mq_size 0xFFFFFFFF > mqc_err\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex2:echo mq_base 0x58FFFFBA > mqc_err\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kcreate_ctx_dbg_write_op(struct file *filp,
					   const char __user *buf, size_t count,
					   loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	u64 temp_value;
	size_t i;
	char cmd_buf[INJECT_CMD_LEN] = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(mq_fields); i++) {
		if (!strncmp(argv[0], mq_fields[i], strlen(mq_fields[i])))
			break;
	}

	ret = kstrtoull(argv[1], 16, &temp_value);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "-u %llx", temp_value);

	switch (i) {
	case MQ_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_size", cmd_buf);
		break;
	case MQ_BASE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_base", cmd_buf);
		break;
	default:
		DRV_RDMA_LOG_DEV_WARN("MQ DEBUGFS:invalid index %zu\n", i);
		goto end;
	}
	DRV_RDMA_LOG_DEV_INFO(
		"MQ DEBUGFS:modify mq i:%zu, type:%s, temp_value:%#llx\n", i,
		mq_fields[i], temp_value);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_ctx_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kcreate_ctx_dbg_read_op,
	.write = mq_kcreate_ctx_dbg_write_op,
};

static void sxe2_kadd_mq_err_debugfs_files(struct sxe2_rdma_device *rdma_dev)
{
	debugfs_create_file("dup_create", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_debugfs, rdma_dev,
			    &sxe2_rdma_mq_dup_create_fops);
	debugfs_create_file("0x2_mqc_addr", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_debugfs, rdma_dev,
			    &sxe2_rdma_mq_ctx_addr_fops);
	debugfs_create_file("mqc_err", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_debugfs, rdma_dev,
			    &sxe2_rdma_mq_ctx_err_fops);
}

static ssize_t mq_kupdate_fpte_dbg_read_op(struct file *filp, char __user *buf,
					   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:update fptes:rsc_type:%u, temp_value:%u\n\n",
		rdma_dev->rdma_func->mq.err_cqe_val.fpte_rsc_type,
		rdma_dev->rdma_func->mq.err_cqe_val.fpte_err_type);

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'rsc_type' 'err_type' > rcms_ctx_err\n"
		"rsc_type:qp/cq/srq/mr/resp/irrl/ssnt/ah\n"
		"err_type:decimal data,1:fpte invalid,2:addr\n"
		"all 0 in fpte,3:addr all F in fpte\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo qp 2 > rcms_ctx_err\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kupdate_fpte_dbg_write_op(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	u64 temp_value;
	size_t i;
	char cmd_buf[INJECT_CMD_LEN] = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(rcms_type_fields); i++) {
		if (!strncmp(argv[0], rcms_type_fields[i],
			     strlen(rcms_type_fields[i]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "-u %u", (u32)temp_value);

	switch (i) {
	case SXE2_RCMS_OBJ_QP:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_ctx_err_qp", cmd_buf);
		break;

	case SXE2_RCMS_OBJ_SSNT:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_ctx_err_ssnt",
			      cmd_buf);
		break;

	default:
		DRV_RDMA_LOG_DEV_WARN("MQ DEBUGFS:invalid index %zu\n", i);
		break;
	}

	DRV_RDMA_LOG_DEV_INFO(
		"MQ DEBUGFS:update fptes:rsc_type:%u, temp_value:%u\n",
		rdma_dev->rdma_func->mq.err_cqe_val.fpte_rsc_type,
		rdma_dev->rdma_func->mq.err_cqe_val.fpte_err_type);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_fpte_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kupdate_fpte_dbg_read_op,
	.write = mq_kupdate_fpte_dbg_write_op,
};

static ssize_t mq_kinject_wqe_dbg_read_op(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	size_t i;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:rsrc wqe inject:err_type:%u, temp_value:%u\n\n",
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val);

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'err_type' 'val' > rsc_wqe_err' > mqc_err\n"
		"err_type:");
	for (i = 0; i < ARRAY_SIZE(mq_rsc_wqe_err_fields); i++) {
		if (i == ARRAY_SIZE(mq_rsc_wqe_err_fields) - 1) {
			len_total += dbg_vsnprintf(rsp_end, len_total, "%s\n",
						   mq_rsc_wqe_err_fields[i]);
		} else {
			len_total += dbg_vsnprintf(rsp_end, len_total, "%s/",
						   mq_rsc_wqe_err_fields[i]);
		}
	}
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "val:hex data,inject value\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo qpn 0xFFFF > rsc_wqe_err\n");
	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"if clr injection,please echo 0 0 > rsc_wqe_err\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kinject_wqe_dbg_write_op(struct file *filp,
					   const char __user *buf, size_t count,
					   loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	u64 temp_value;
	size_t i;
	char cmd_buf[INJECT_CMD_LEN] = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(mq_rsc_wqe_err_fields); i++) {
		if (!strncmp(argv[0], mq_rsc_wqe_err_fields[i],
			     strlen(mq_rsc_wqe_err_fields[i]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 16, &temp_value);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "-u %x", (u32)temp_value);
	switch (i) {
	case 0:
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type = (u32)i;
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val =
			temp_value;
		break;
	case QPN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpn", cmd_buf);
		break;
	case CQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqn", cmd_buf);
		break;
	case SRQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srqn", cmd_buf);
		break;
	case CEQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn", cmd_buf);
		break;
	case QPC_SRQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_srqn",
			      cmd_buf);
		break;
	case QPC_SEND_CQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_scqn",
			      cmd_buf);
		break;
	case QPC_RECV_CQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rcqn",
			      cmd_buf);
		break;
	case CQC_CEQN_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqcn", cmd_buf);
		break;
	case QPC_SW_STATE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_swState",
			      cmd_buf);
		break;
	case CQC_SW_STATE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_swState",
			      cmd_buf);
		break;
	case SRQC_SW_STATE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_swState",
			      cmd_buf);
		break;
	case CEQC_SW_STATE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_swState",
			      cmd_buf);
		break;
	case QPC_TYPE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_type",
			      cmd_buf);
		break;
	case QPC_PMTU_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pmtu",
			      cmd_buf);
		break;
	case QPC_SQ_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_sqSize",
			      cmd_buf);
		break;
	case QPC_RQ_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqSize",
			      cmd_buf);
		break;
	case CQC_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cq_size",
			      cmd_buf);
		break;
	case SRQC_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_srq_size",
			      cmd_buf);
		break;
	case CEQC_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_size",
			      cmd_buf);
		break;
	case AEQC_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_cqn", cmd_buf);
		break;
	case QPC_RQ_TYPE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_rqType",
			      cmd_buf);
		break;
	case QPC_PAGE_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpc_pageSize",
			      cmd_buf);
		break;
	case QPC_SW_STATE_JUMP_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func,
			      "mq_rcs_wqe_qpc_swState_jump", cmd_buf);
		break;
	case FPTE_CNT_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_fpte", cmd_buf);
		break;
	case AH_ID_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ah", cmd_buf);
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ah_query",
			      cmd_buf);
		break;
	case MR_ID_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_reg",
			      cmd_buf);
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_dereg",
			      cmd_buf);
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_query",
			      cmd_buf);
		break;
	case MR_ACCESS_RIGHT_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_accessRight",
			      cmd_buf);
		break;
	case MR_TYPE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_type",
			      cmd_buf);
		break;
	case MR_PAGE_SIZE_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_pageSize",
			      cmd_buf);
		break;
	case QP_CTX_PA_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_qpctx", cmd_buf);
		break;
	case QP_CREATE_OP_DEBUGFS:
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_createOp",
			      cmd_buf);
		break;
	default:
		DRV_RDMA_LOG_DEV_WARN("MQ DEBUGFS:invalid index %zu\n", i);
		break;
	}

	DRV_RDMA_LOG_DEV_INFO(
		"MQ DEBUGFS:rsrc wqe inject:err_type:%u, temp_value:%llu\n",
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_rsc_wqe_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kinject_wqe_dbg_read_op,
	.write = mq_kinject_wqe_dbg_write_op,
};

static ssize_t mq_kcommit_rcms_dbg_read_op(struct file *filp, char __user *buf,
					   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:commit rcms:err_vld %d, rsc_type:%u, temp_value:%u\n\n",
		rdma_dev->rdma_func->mq.err_cqe_val.commit_wqe_err_vld,
		rdma_dev->rdma_func->mq.err_cqe_val.commit_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.commit_wqe_err_val);

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'rsc_type' 'err_val' > rcms_commit_err\n"
		"rsc_type:qp/cq/srq/ah/mr\n"
		"err_val:hex data\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo qp 0x300 > rcms_commit_err\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kcommit_rcms_dbg_write_op(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	u64 temp_value;
	size_t i;
	char cmd_buf[INJECT_CMD_LEN] = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(rcms_type_fields); i++) {
		if (!strncmp(argv[0], rcms_type_fields[i],
			     strlen(rcms_type_fields[i]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 16, &temp_value);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "-u %x", (u32)temp_value);
	switch (i) {
	case SXE2_RCMS_OBJ_QP:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_commit_err_qp",
			      cmd_buf);
		break;
	case SXE2_RCMS_OBJ_CQ:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_commit_err_cq",
			      cmd_buf);
		break;
	case SXE2_RCMS_OBJ_SRQ:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_commit_err_srq",
			      cmd_buf);
		break;
	case SXE2_RCMS_OBJ_MR:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_commit_err_mr",
			      cmd_buf);
		break;
	case SXE2_RCMS_OBJ_AH:
		INJECT_ACTIVE(rdma_dev->rdma_func, "rcms_commit_err_ah",
			      cmd_buf);
		break;

	default:
		DRV_RDMA_LOG_DEV_WARN("MQ DEBUGFS:invalid index %zu\n", i);
		break;
	}

	DRV_RDMA_LOG_DEV_INFO(
		"MQ DEBUGFS:commit rcms:rsc_type:%u, temp_value:%u\n",
		rdma_dev->rdma_func->mq.err_cqe_val.commit_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.commit_wqe_err_val);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_commit_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kcommit_rcms_dbg_read_op,
	.write = mq_kcommit_rcms_dbg_write_op,
};

static ssize_t mq_kmanage_pbl_dbg_read_op(struct file *filp, char __user *buf,
					  size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"NOW STATE---MQ DEBUGFS:manage pbl:err_vld:%d, err_type:%#x, err_value:%#llx\n\n",
		rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_vld,
		rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_val);

	len_total += dbg_vsnprintf(
		rsp_end, len_total,
		"CMD HELP:\n"
		"Please echo 'err_type' 'err_val' > vf_manage_pbl_err\n"
		"err_type:no|spte_cnt|first_spte_index|fpte_index|opcode\n"
		"err_val:hex data\n");
	len_total +=
		dbg_vsnprintf(rsp_end, len_total,
			      "ex:echo spte_cnt 0xFF > vf_manage_pbl_err\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kmanage_pbl_dbg_write_op(struct file *filp,
					   const char __user *buf, size_t count,
					   loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	u64 temp_value;
	bool flag		     = false;
	char cmd_buf[INJECT_CMD_LEN] = { 0 };

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Invalid param nums\n");
		goto end;
	}

	if (!strncmp(argv[0], mq_mng_pbl_wqe_err_fields,
		     strlen(mq_mng_pbl_wqe_err_fields))) {
		flag = true;
	}

	ret = kstrtoull(argv[1], 16, &temp_value);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get param value failed, ret (%ld)\n", ret);
		goto end;
	}

	rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_vld = flag;

	if (flag) {
		snprintf(cmd_buf, sizeof(cmd_buf), "-u %llx", (u64)temp_value);
		INJECT_ACTIVE(rdma_dev->rdma_func, "mq_pbl_err", cmd_buf);
	} else {
		DRV_RDMA_LOG_DEV_WARN("MQ DEBUGFS:invalid\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_INFO(
		"MQ DEBUGFS:manage pbl:err_type:%#x, err_value:%#llx\n",
		rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_type,
		rdma_dev->rdma_func->mq.err_cqe_val.manage_pbl_wqe_err_val);

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_manage_pbl_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kmanage_pbl_dbg_read_op,
	.write = mq_kmanage_pbl_dbg_write_op,
};

static ssize_t mq_kmanage_func_tbl_dbg_read_op(struct file *filp,
					       char __user *buf, size_t count,
					       loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "CMD HELP:\n"
				   "Please echo 'vf_id' > manage_func_tbl\n"
				   "vf_id:hex data\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "ex:echo 0xA > manage_func_tbl\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_kmanage_func_tbl_dbg_write_op(struct file *filp,
						const char __user *buf,
						size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	u64 vf_id = 0;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX]	= { 0 };
	struct sxe2_rcms_fcn_info rcms_fcn_info = {};

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT1) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:Please input 'vf_id'\n");
		goto end;
	}

	ret = kstrtoull(argv[0], 16, &vf_id);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get vf_id param value failed, ret (%ld)\n",
			ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:vf_id %#llx\n", vf_id);

	rcms_fcn_info.protocol_used = (u8)SXE2_ROCE_PROTOCOL_ONLY;
	rcms_fcn_info.vf_id	    = (u32)vf_id;
	ret = sxe2_vchnl_manage_rcms_pm_func_table(&rdma_dev->rdma_func->mq.mq,
						   &rcms_fcn_info, 0, 1);
	if (ret == 0) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"MQ DEBUGFS:manage func table, cmd post, ret %ld\n",
			ret);
	} else {
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:manage func table, cmd post err, ret %ld\n",
			ret);
	}

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_mq_manage_fun_tbl_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_kmanage_func_tbl_dbg_read_op,
	.write = mq_kmanage_func_tbl_dbg_write_op,
};

static ssize_t mq_handle_op_failed_read_op(struct file *filp, char __user *buf,
					   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	int i;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;
	len_total +=
		dbg_vsnprintf(rsp_end, len_total, "Inject op failed opcode:\n");
	for (i = 0; i < MQ_MAX_OPS; i++) {
		if (rdma_dev->rdma_func->mq.ops_failed[i]) {
			len_total +=
				dbg_vsnprintf(rsp_end, len_total, "%u ", i);
		}
	}
	len_total += dbg_vsnprintf(rsp_end, len_total, "\n");

	ret = simple_read_from_buffer(buf, count, off, rsp, len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static ssize_t mq_handle_op_failed_write_op(struct file *filp,
					    const char __user *buf,
					    size_t count, loff_t *off)
{
	ssize_t ret			       = 0;
	char cmd[MQ_DEBUGFS_WRITE_BUF_MAX_LEN] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	bool en;
	u64 opcode;
	int i;
	u64 temp_value;

	if (*off != 0)
		goto end;

	if (count >= MQ_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:Cmd exceeded length limit, ret %d\n", ret);
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("MQ DEBUGFS:dev find failed, ret %d\n", ret);
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Cmd copy from user failed, ret %ld\n", ret);
		goto end;
	}
	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:Request command :%s\n", cmd);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(cmd, &argc, argv);
	if (ret)
		goto end;
	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:Please input 'en opcode' or 'en'\n");
		goto end;
	}

	ret = kstrtoull(argv[0], MQ_STR_TO_LL_AUTO_BASE, &temp_value);
	if (ret) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:get en param value failed\n");
		goto end;
	}
	en = (temp_value != 0) ? true : false;
	ret = kstrtoull(argv[1], MQ_STR_TO_LL_AUTO_BASE, &opcode);
	if (ret) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:get opcode param value failed\n");
		goto end;
	}

	if (opcode != MQ_INJECT_ALL_OPCODE_CTRL_VAL && opcode >= MQ_MAX_OPS) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:input opcode param %llu err please input 0xFF or 0-36\n",
			opcode);
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG("MQ DEBUGFS:en %u opcode %llu\n", en, opcode);
	if (opcode == MQ_INJECT_ALL_OPCODE_CTRL_VAL) {
		for (i = 0; i < MQ_MAX_OPS; i++)
			rdma_dev->rdma_func->mq.ops_failed[i] = en;
	} else {
		rdma_dev->rdma_func->mq.ops_failed[opcode] = en;
	}

end:
	ret = ret ? ret : (ssize_t)count;
	return ret;
}

static const struct file_operations sxe2_rdma_op_failed_err_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = mq_handle_op_failed_read_op,
	.write = mq_handle_op_failed_write_op,
};

static void
sxe2_kadd_mq_err_cqe_debugfs_files(struct sxe2_rdma_device *rdma_dev)
{
	debugfs_create_file("rcms_ctx_err", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_cqe_debugfs, rdma_dev,
			    &sxe2_rdma_mq_fpte_err_fops);
	debugfs_create_file("rsc_wqe_err", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_cqe_debugfs, rdma_dev,
			    &sxe2_rdma_mq_rsc_wqe_err_fops);
	debugfs_create_file("rcms_commit_err", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_cqe_debugfs, rdma_dev,
			    &sxe2_rdma_mq_commit_err_fops);
	debugfs_create_file("vf_manage_pbl_err", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_cqe_debugfs, rdma_dev,
			    &sxe2_rdma_mq_manage_pbl_err_fops);
	debugfs_create_file("manage_func_tbl", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_err_cqe_debugfs, rdma_dev,
			    &sxe2_rdma_mq_manage_fun_tbl_fops);
}

static void
sxe2_kadd_mq_op_failed_debugfs_files(struct sxe2_rdma_device *rdma_dev)
{
	debugfs_create_file("op_failed", SXE2_DEBUG_FILE_READ_WRITE,
			    rdma_dev->hdl->mq_op_failed_debugfs, rdma_dev,
			    &sxe2_rdma_op_failed_err_fops);
}

int sxe2_kadd_mq_err_debugfs(struct sxe2_rdma_device *rdma_dev)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:debugfs root dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->mq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq debugfs dir not exist, ret (%d)\n", ret);
		goto end;
	}

	rdma_dev->hdl->mq_err_debugfs =
		debugfs_create_dir("MQ_ERR", rdma_dev->hdl->mq_debugfs);
	if (!rdma_dev->hdl->mq_err_debugfs) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:create mq err dir failed, ret %d\n", ret);
		goto end;
	}
	sxe2_kadd_mq_err_debugfs_files(rdma_dev);

	rdma_dev->hdl->mq_err_cqe_debugfs =
		debugfs_create_dir("MQ_ERR_CQE", rdma_dev->hdl->mq_debugfs);
	if (!rdma_dev->hdl->mq_err_cqe_debugfs) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:create mq err cqe dir failed, ret %d\n",
			ret);
		goto remove_mq_err_debug;
	}
	sxe2_kadd_mq_err_cqe_debugfs_files(rdma_dev);

	rdma_dev->hdl->mq_op_failed_debugfs =
		debugfs_create_dir("MQ_OP_FAILED", rdma_dev->hdl->mq_debugfs);
	if (!rdma_dev->hdl->mq_op_failed_debugfs) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:create mq op failed dir failed, ret %d\n",
			ret);
		goto remove_mq_err_cqe_debug;
	}
	sxe2_kadd_mq_op_failed_debugfs_files(rdma_dev);
	goto end;

remove_mq_err_cqe_debug:
	debugfs_remove_recursive(rdma_dev->hdl->mq_err_cqe_debugfs);
	rdma_dev->hdl->mq_err_debugfs = NULL;

remove_mq_err_debug:
	debugfs_remove_recursive(rdma_dev->hdl->mq_err_debugfs);
	rdma_dev->hdl->mq_err_debugfs = NULL;
end:
	return ret;
}

void sxe2_kremove_mq_err_debugfs(struct sxe2_rdma_device *rdma_dev)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("debugfs root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->mq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("mq debugfs dir not exist\n");
		goto end;
	}

	debugfs_remove_recursive(rdma_dev->hdl->mq_err_cqe_debugfs);
	rdma_dev->hdl->mq_err_cqe_debugfs = NULL;

	debugfs_remove_recursive(rdma_dev->hdl->mq_err_debugfs);
	rdma_dev->hdl->mq_err_debugfs = NULL;

	debugfs_remove_recursive(rdma_dev->hdl->mq_op_failed_debugfs);
	rdma_dev->hdl->mq_op_failed_debugfs = NULL;

end:
	return;
}
#endif

int sxe2_kadd_mq_rsc_debugfs(struct sxe2_rdma_device *rdma_dev,
			     struct sxe2_mq *mq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:debugfs root dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->mq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq debugfs dir not exist, ret (%d)\n", ret);
		goto end;
	}

	mq->dbg_node =
		drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_MQ,
				      rdma_dev->hdl->mq_debugfs,
				      mq_kread_debugfs_field, NULL, 0, mq);
	if (!mq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq debug res tree add failed, ret %d\n",
			ret);
		goto end;
	}

	debugfs_create_file("mq_status", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->mq_debugfs, rdma_dev,
			    &sxe2_rdma_mq_status_fops);

end:
	return ret;
}

void sxe2_kremove_mq_rsc_debugfs(struct sxe2_rdma_device *rdma_dev,
				 struct sxe2_mq *mq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("debugfs root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->mq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("mq debugfs dir not exist\n");
		goto end;
	}

	if (mq->dbg_node) {
		drv_rdma_rm_res_tree(mq->dbg_node);
		mq->dbg_node = NULL;
	}

end:
	return;
}
