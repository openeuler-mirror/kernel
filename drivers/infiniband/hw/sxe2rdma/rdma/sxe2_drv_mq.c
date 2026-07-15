// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mq.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/printk.h>
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_stats.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_srq.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_mq_debugfs.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_main.h"

#define SXE2_MQ_WQE_OPCODE_OFFSET (24)
#define SXE2_MQ_DB_VLD_VALUE	  (1)
#define SXE2_MQ_DB_VLD_SHIFT	  (11)
#define SXE2_MQ_WQE_OPCODE_BITS GENMASK_ULL(37, 32)
#define SXE2_MQ_WQE_VALID_BITS	 BIT_ULL_MASK(63)
#define MQ_WQE_MEMSET_NUM_0	 (0)
#define MQ_WQE_MEMSET_NUM_3	 (3)
#define MQ_WQE_MEMSET_NUM_4	 (4)
#define MQ_WQE_MEMSET_BYTES_24	 (24)
#define MQ_WQE_MEMSET_BYTES_32	 (32)
#define MQ_TIMEOUT_THRESHOLD	 (500)
#define MCQ_DB_NOTE_OFFSET_0	 (0)
#define MCQ_DB_NOTE_OFFSET_4	 (4)
#define MCQ_DB_NOTE_CMDSN_MASK	 (4)
#define MCQ_DB_NOTE_CMD_VALUE	 (0)
#define MQC_64B_CACHE_LINE_EN	 (1)
#define MQC_64B_CACHE_LINE_NO_EN (0)

static const char *const sxe2_mq_cmd_names[SXE2_MQ_OP_MAX] = {
	[SXE2_MQ_OP_CREATE_QP]	    = "Create QP Cmd",
	[SXE2_MQ_OP_MODIFY_QP]	    = "Modify QP Cmd",
	[SXE2_MQ_OP_DESTROY_QP]	    = "Destroy QP Cmd",
	[SXE2_MQ_OP_CREATE_CQ]	    = "Create CQ Cmd",
	[SXE2_MQ_OP_MODIFY_CQ]	    = "Modify CQ Cmd",
	[SXE2_MQ_OP_DESTROY_CQ]	    = "Destroy CQ Cmd",
	[SXE2_MQ_OP_ALLOC_MR_key]   = "Allocate MR key Cmd",
	[SXE2_MQ_OP_REG_MR]	    = "Register MR Cmd",
	[SXE2_MQ_OP_QUERY_MR_key]   = "Query MR key Cmd",
	[SXE2_MQ_OP_DEALLOC_MR_key] = "Deallocate MR key Cmd",
	[SXE2_MQ_OP_MANAGE_PBLE_BP] = "Manage Function PBLE Backing Pages Cmd",
	[SXE2_MQ_OP_QUERY_QP]	    = "Query QP Cmd",
	[SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE] =
		"Manage RCMS PM Function Table Cmd",
	[SXE2_MQ_OP_CREATE_CEQ]		 = "Create CEQ Cmd",
	[SXE2_MQ_OP_DESTROY_CEQ]	 = "Destroy CEQ Cmd",
	[SXE2_MQ_OP_CREATE_AEQ]		 = "Create AEQ Cmd",
	[SXE2_MQ_OP_DESTROY_AEQ]	 = "Destroy AEQ Cmd",
	[SXE2_MQ_OP_CREATE_ADDR_HANDLE]	 = "Create Address Handle Cmd",
	[SXE2_MQ_OP_MODIFY_ADDR_HANDLE]	 = "Modify Address Handle Cmd",
	[SXE2_MQ_OP_DESTROY_ADDR_HANDLE] = "Destroy Address Handle Cmd",
	[SXE2_MQ_OP_UPDATE_FPT]		 = "Update FPTs Cmd",
	[SXE2_MQ_OP_QUERY_FPM_VAL]	 = "Query FPM Values Cmd",
	[SXE2_MQ_OP_COMMIT_FPM_VAL]	 = "Commit FPM Values Cmd",
	[SXE2_MQ_OP_NOP]		 = "NOP Cmd",
	[SXE2_MQ_OP_GATHER_STATS]	 = "Gather Statistics Cmd",
	[SXE2_MQ_OP_CREATE_SRQ]		 = "Create SRQ Cmd",
	[SXE2_MQ_OP_MODIFY_SRQ]		 = "Modify SRQ Cmd",
	[SXE2_MQ_OP_DESTROY_SRQ]	 = "Destroy SRQ Cmd",
	[SXE2_MQ_OP_DEREGISTER_MR]	 = "Deregister MR Cmd",
	[SXE2_MQ_OP_MODIFY_CEQ]		 = "Modify CEQ Cmd",
	[SXE2_MQ_OP_QUERY_CEQ]		 = "Query CEQ Cmd",
	[SXE2_MQ_OP_MODIFY_AEQ]		 = "Modify AEQ Cmd",
	[SXE2_MQ_OP_QUERY_AEQ]		 = "Query AEQ Cmd",
	[SXE2_MQ_OP_QUERY_CQ]		 = "Query CQ Cmd",
	[SXE2_MQ_OP_QUERY_SRQ]		 = "Query SRQ Cmd",
	[SXE2_MQ_OP_QUERY_MR]		 = "Query MR Cmd",
};

static const struct sxe2_mq_ctx_err_code sxe2_mq_ctx_err_list[] = {
	{ 0x1, "Duplicate Create" },
	{ 0x2, "DMA" },
	{ 0x3, "Func Not Allocated" },
	{ 0x4, "SQ Size Illegal" },
};

static const struct sxe2_mq_err_info sxe2_mq_cqe_err_list[] = {
	{ 0xF000, 0x0000, "Cache Address Translation Error" },
	{ 0xF000, 0x0001, "Cache Read RCMS space, but PCIe return Error" },
	{ 0xF001, 0x0004, "Context SRAM multi-bit Error" },
	{ 0xF002, 0x0001, "WQE QPN/CQN/SRQN/EQN Out of Range" },
	{ 0xF002, 0x0002, "QPC:SRQN Out of Range" },
	{ 0xF002, 0x0004, "QPC.Send_CQN Out of Range" },
	{ 0xF002, 0x0008, "QPC.Receive_CQN Out of Range" },
	{ 0xF002, 0x0010, "CQC.CEQN Out of Range" },
	{ 0xF003, 0x0001, "QPC/CQC/SRQC/EQC.SW State used rsv value" },
	{ 0xF003, 0x0002, "QP Type used rsv value" },
	{ 0xF003, 0x0004, "QPC.pmtu used rsv value" },
	{ 0xF003, 0x0008, "QPC/CQC/SRQC/EQC.log_size used rsv value" },
	{ 0xF003, 0x0010, "QPC.rq_type used rsv value" },
	{ 0xF003, 0x0020, "QPC.log_page_size used rsv value" },
	{ 0xFFFF, 0x8003, "Invalid Next QP State" },
	{ 0xFFFF, 0x800C, "FPT Index Out of Range" },
	{ 0xFFFF, 0x800D, "SPT Index Out of Range" },
	{ 0xFFFF, 0x800E, "SPT Page Boundary Exceeded" },
	{ 0xFFFF, 0x800F, "FPT Boundary Exceeded" },
	{ 0xFFFF, 0x8010, "Invalid Function Type" },
	{ 0xFFFF, 0x8013, "AH ID Out of Range" },
	{ 0xFFFF, 0x8014, "Invalid MRTE Index" },
	{ 0xFFFF, 0x8019, "Invalid Access Rights" },
	{ 0xFFFF, 0x8020, "Invalid Flag on Reg MR" },
	{ 0xFFFF, 0x8021, "Invalid PBL/Host Page" },
	{ 0xFFFF, 0x8023, "Invalid RoCE QPID" },
	{ 0xFFFF, 0x8025, "Commit RCMS Value Check Error" },
	{ 0xFFFF, 0x8026, "VF Num Overflow" },
	{ 0xFFFF, 0x8027, "Illegal RCMS Profile Type" },
	{ 0xFFFF, 0x8028, "PCIe Unsupported Request" },
	{ 0xFFFF, 0x8029, "Update FPT WQE Check Error" },
	{ 0xFFFF, 0x802A, "VF Bind Conflict" },
	{ 0xFFFF, 0x8030, "MQC Not Created" },
	{ 0xFFFF, 0x8031, "SQ Base Access Error" },
	{ 0xFFFF, 0x8032, "MQ Context Buf multi-bit ECC error" },
	{ 0xFFFF, 0x8033, "MQ WQE Buf multi-bit ECC error" },
	{ 0xFFFF, 0x8034, "QP Destroy Abort error" },
	{ 0xFFFF, 0x80EE, "Unsupported Opcode" },
};

static const struct sxe2_mq_err_info sxe2_mq_cqe_not_err_list[] = {
	{ 0x0000, 0x0001, "STag Invalid" },
};

__le64 *sxe2_kget_next_mq_wqe_idx(struct sxe2_mq_ctx *mq, u64 scratch,
				  u32 *wqe_idx)
{
	__le64 *wqe = NULL;
	int ret_code;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);

	if (SXE2_RING_FULL_ERR(mq->mq_ring)) {
		DRV_RDMA_LOG_DEV_ERR(
			"WQE: MQ is full, head 0x%x tail 0x%x size 0x%x\n",
			mq->mq_ring.head, mq->mq_ring.tail, mq->mq_ring.size);
		goto end;
	}

	SXE2_ATOMIC_RING_MOVE_HEAD(mq->mq_ring, *wqe_idx, ret_code);
	if (ret_code)
		goto end;

	mq->requested_ops++;
	if (!*wqe_idx)
		mq->polarity = !mq->polarity;

	wqe			    = mq->mq_buf_va[*wqe_idx].elem;
	mq->scratch_array[*wqe_idx] = scratch;

	memset(&wqe[MQ_WQE_MEMSET_NUM_0], 0, MQ_WQE_MEMSET_BYTES_24);
	memset(&wqe[MQ_WQE_MEMSET_NUM_4], 0, MQ_WQE_MEMSET_BYTES_32);
	wqe[MQ_WQE_MEMSET_NUM_3] &= SXE2_MQ_WQE_VALID_BITS;

end:
	return wqe;
}

void sxe2_kpost_mq(struct sxe2_mq_ctx *mq)
{
	struct mq_wqe_nop *wqe		  = NULL;
	u32 head			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);

	SXE2_BAR_WRITE_32(((u32)(SXE2_MQ_DB_VLD_VALUE << SXE2_MQ_DB_VLD_SHIFT) |
			   SXE2_RING_CURRENT_HEAD(mq->mq_ring)),
			  mq->dev->hw_regs[MQ_DB]);

	if (mq->mq_ring.head > 0)
		head = mq->mq_ring.head - 1;
	else
		head = mq->mq_ring.size - 1;
	wqe = (struct mq_wqe_nop *)(mq->mq_buf_va[head].elem);
	mq->dev->mq_post_stats[wqe->op]++;

	DRV_RDMA_LOG_DEV_DEBUG(
		"WQE: MQ head %#x, tail %#x, opcode %#x, MQ size %#x\n",
		mq->mq_ring.head, mq->mq_ring.tail, wqe->op, mq->mq_ring.size);
}

struct sxe2_mq_request *sxe2_kalloc_and_get_mq_request(struct sxe2_mq *mq,
						       bool wait)
{
	struct sxe2_mq_request *mq_request = NULL;
	unsigned long flags		   = 0;
	struct sxe2_rdma_device *rdma_dev  = to_rdmadev(mq->mq.dev);

	spin_lock_irqsave(&mq->req_lock, flags);
	if (!list_empty(&mq->mq_avail_reqs)) {
		mq_request = list_entry(mq->mq_avail_reqs.next,
					struct sxe2_mq_request, list);
		list_del_init(&mq_request->list);
	}
	spin_unlock_irqrestore(&mq->req_lock, flags);

	if (!mq_request) {
		mq_request = kzalloc(sizeof(*mq_request), GFP_ATOMIC);
		if (mq_request) {
			mq_request->dynamic = true;
			if (wait)
				init_waitqueue_head(&mq_request->waitq);
		}
	}
	if (!mq_request) {
		DRV_RDMA_LOG_DEV_ERR("ERR: MQ Request Fail: No Memory");
		goto end;
	}

	mq_request->waiting = wait;
	refcount_set(&mq_request->refcnt, 1);
	memset(&mq_request->cmpl_info, 0, sizeof(mq_request->cmpl_info));

end:
	return mq_request;
}

static bool mq_kquery_ring_full(struct sxe2_mq_ctx *mq)
{
	return SXE2_RING_FULL_ERR(mq->mq_ring);
}

int sxe2_knop(struct sxe2_mq_ctx *mq, u64 scratch, bool post_mq, u8 wait_type)
{
	__le64 *wqe		   = NULL;
	struct mq_wqe_nop *nop_wqe = NULL;
	u32 tail, val, error = 0;
	struct sxe2_rdma_device *rdma_dev;
	int ret_code = 0;

	rdma_dev = to_rdmadev(mq->dev);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n",
				     ret_code);
		goto end;
	}

	nop_wqe		   = (struct mq_wqe_nop *)wqe;
	nop_wqe->op	   = SXE2_MQ_OP_NOP;
	nop_wqe->wqe_valid = mq->polarity;

	sxe2_kget_mq_reg_info(mq, &val, &tail, &error);

	if (post_mq) {
		sxe2_kpost_mq(mq);
		if (wait_type == SXE2_MQ_WAIT_POLL_REGS) {
			ret_code = sxe2_kpoll_mq_registers(
				mq, tail, mq->dev->hw_attrs.max_done_count);
		} else if (wait_type == SXE2_MQ_WAIT_POLL_CQ) {
			ret_code = sxe2_kpoll_mcq(mq, SXE2_MQ_OP_NOP, NULL);
		}
	}

end:
	return ret_code;
}

int mq_kexec_cmd(struct sxe2_rdma_ctx_dev *dev, struct mq_cmds_info *pcmdinfo)
{
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_dma_mem val_mem;

	switch (pcmdinfo->mq_cmd) {
	case MQ_OP_CREATE_QP:
		ret_code = sxe2_ctx_qp_create(pcmdinfo->in.u.qp_create.qp,
					      &pcmdinfo->in.u.qp_create.info,
					      pcmdinfo->in.u.qp_create.scratch,
					      pcmdinfo->post_mq);
		break;
	case MQ_OP_MODIFY_QP:
		ret_code = sxe2_ctx_qp_modify(pcmdinfo->in.u.qp_modify.qp,
					      &pcmdinfo->in.u.qp_modify.info,
					      pcmdinfo->in.u.qp_modify.scratch,
					      pcmdinfo->post_mq);
		break;
	case MQ_OP_DESTROY_QP:
		ret_code =
			sxe2_ctx_qp_destroy(pcmdinfo->in.u.qp_destroy.qp,
					    &pcmdinfo->in.u.qp_destroy.info,
					    pcmdinfo->in.u.qp_destroy.scratch,
					    pcmdinfo->post_mq);
		break;
	case MQ_OP_CREATE_CQ:
		ret_code = sxe2_drv_cq_create(
			pcmdinfo->in.u.cq_create.cq,
			pcmdinfo->in.u.cq_create.scratch,
			pcmdinfo->in.u.cq_create.check_overflow,
			pcmdinfo->post_mq);
		break;
	case MQ_OP_MODIFY_CQ:
		ret_code = sxe2_drv_cq_modify(pcmdinfo->in.u.cq_modify.cq,
					      pcmdinfo->in.u.cq_modify.cqc,
					      pcmdinfo->in.u.cq_modify.scratch,
					      pcmdinfo->post_mq);
		break;
	case MQ_OP_DESTROY_CQ:
		ret_code =
			sxe2_drv_cq_destroy(pcmdinfo->in.u.cq_destroy.cq,
					    pcmdinfo->in.u.cq_destroy.scratch,
					    pcmdinfo->post_mq);
		break;
	case MQ_OP_ALLOC_MR_KEY:
	case MQ_OP_REG_MR:
	case MQ_OP_QUERY_MR:
	case MQ_OP_DEALLOC_MR_KEY:
	case MQ_OP_DEREGISTER_MR:
		ret_code = sxe2_hw_set_mq_wqe(dev, pcmdinfo);
		break;
	case MQ_OP_CREATE_ADDR_HANDLE:
	case MQ_OP_MODIFY_ADDR_HANDLE:
	case MQ_OP_DESTROY_ADDR_HANDLE:
		ret_code = sxe2_ah_set_mq_wqe(dev, pcmdinfo);
		break;
	case MQ_OP_QUERY_MR_KEY:
		break;
	case MQ_OP_MANAGE_PBLE_BP:
		ret_code = sxe2_pbl_manage_pble_cp_cmd(
			pcmdinfo->in.u.manage_pble_bp.mq,
			&pcmdinfo->in.u.manage_pble_bp.info,
			pcmdinfo->in.u.manage_pble_bp.scratch, true);

		break;
	case MQ_OP_QUERY_QP:
		ret_code = sxe2_ctx_qp_query(pcmdinfo->in.u.qp_query.qp,
					     &pcmdinfo->in.u.qp_query.info,
					     pcmdinfo->in.u.qp_query.scratch,
					     pcmdinfo->post_mq);
		break;
	case MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE:
		ret_code = sxe2_vchnl_manage_rcms_pm_func_table(
			pcmdinfo->in.u.manage_rcms_pm.dev->mq,
			&pcmdinfo->in.u.manage_rcms_pm.info,
			pcmdinfo->in.u.manage_rcms_pm.scratch, true);
		break;
	case MQ_OP_CREATE_CEQ:
		ret_code = sxe2_drv_ceq_create(pcmdinfo->in.u.ceq_ops.ceq,
					       pcmdinfo->in.u.ceq_ops.scratch,
					       pcmdinfo->post_mq);
		break;
	case MQ_OP_DESTROY_CEQ:
		ret_code = sxe2_drv_ceq_destroy(pcmdinfo->in.u.ceq_ops.ceq,
						pcmdinfo->in.u.ceq_ops.scratch,
						pcmdinfo->post_mq);
		break;
	case MQ_OP_CREATE_AEQ:
		ret_code = sxe2_drv_aeq_create(pcmdinfo->in.u.aeq_ops.aeq,
					       pcmdinfo->in.u.aeq_ops.scratch,
					       pcmdinfo->post_mq);
		break;
	case MQ_OP_DESTROY_AEQ:
		ret_code = sxe2_drv_aeq_destroy(pcmdinfo->in.u.aeq_ops.aeq,
						pcmdinfo->in.u.aeq_ops.scratch,
						pcmdinfo->post_mq);
		break;
	case MQ_OP_UPDATE_FPT:
		ret_code = sxe2_rcms_update_pe_fptes(
			pcmdinfo->in.u.update_pe_fptes.dev,
			&pcmdinfo->in.u.update_pe_fptes.info,
			pcmdinfo->in.u.update_pe_fptes.scratch);
		break;
	case MQ_OP_QUERY_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.query_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.query_fpm_val.fpm_val_va;
		ret_code   = sxe2_rcms_query_fpm_val_cmd(
			  pcmdinfo->in.u.query_fpm_val.mq,
			  pcmdinfo->in.u.query_fpm_val.scratch,
			  pcmdinfo->in.u.query_fpm_val.rcms_fn_id, &val_mem, true,
			  SXE2_MQ_WAIT_EVENT);

		break;
	case MQ_OP_COMMIT_FPM_VAL:
		val_mem.pa = pcmdinfo->in.u.commit_fpm_val.fpm_val_pa;
		val_mem.va = pcmdinfo->in.u.commit_fpm_val.fpm_val_va;
		ret_code   = sxe2_rcms_commit_fpm_val_cmd(
			  pcmdinfo->in.u.commit_fpm_val.mq,
			  pcmdinfo->in.u.commit_fpm_val.scratch,
			  pcmdinfo->in.u.commit_fpm_val.rcms_fn_id, &val_mem,
			  true, SXE2_MQ_WAIT_EVENT);
		break;
	case MQ_OP_NOP:
		ret_code =
			sxe2_knop(pcmdinfo->in.u.nop.mq,
				  pcmdinfo->in.u.nop.scratch, pcmdinfo->post_mq,
				  (u8)pcmdinfo->in.u.nop.wait_type);
		break;
	case MQ_OP_GATHER_STATS:
		ret_code =
			sxe2_kgather_stats(pcmdinfo->in.u.stats_gather.mq,
					   &pcmdinfo->in.u.stats_gather.info,
					   pcmdinfo->in.u.stats_gather.scratch);
		break;
	case MQ_OP_CREATE_SRQ:
		ret_code =
			sxe2_kcreate_srq_ctx(pcmdinfo->in.u.srq_create.srq,
					     pcmdinfo->in.u.srq_create.scratch,
					     pcmdinfo->post_mq);
		break;
	case MQ_OP_MODIFY_SRQ:
		ret_code =
			sxe2_kmodify_srq_ctx(pcmdinfo->in.u.srq_modify.srq,
					     pcmdinfo->in.u.srq_modify.srqc,
					     pcmdinfo->in.u.srq_modify.scratch,
					     pcmdinfo->post_mq);
		break;
	case MQ_OP_DESTROY_SRQ:
		ret_code = sxe2_kdestroy_srq_ctx(
			pcmdinfo->in.u.srq_destroy.srq,
			pcmdinfo->in.u.srq_destroy.scratch, pcmdinfo->post_mq);
		break;
	case MQ_OP_MODIFY_CEQ:
		ret_code =
			sxe2_drv_ceq_modify(pcmdinfo->in.u.ceq_modify.ceq,
					    pcmdinfo->in.u.ceq_modify.ceqc,
					    pcmdinfo->in.u.ceq_modify.scratch,
					    pcmdinfo->post_mq);
		break;
	case MQ_OP_QUERY_CEQ:
		ret_code = sxe2_drv_ceq_query(pcmdinfo->in.u.ceq_query.ceq,
					      pcmdinfo->in.u.ceq_query.query_pa,
					      pcmdinfo->in.u.ceq_query.scratch,
					      pcmdinfo->post_mq);
		break;
	case MQ_OP_MODIFY_AEQ:
		ret_code =
			sxe2_drv_aeq_modify(pcmdinfo->in.u.aeq_modify.aeq,
					    pcmdinfo->in.u.aeq_modify.aeqc,
					    pcmdinfo->in.u.aeq_modify.scratch,
					    pcmdinfo->post_mq);
		break;
	case MQ_OP_QUERY_AEQ:
		ret_code = sxe2_drv_aeq_query(pcmdinfo->in.u.aeq_query.aeq,
					      pcmdinfo->in.u.aeq_query.query_pa,
					      pcmdinfo->in.u.aeq_query.scratch,
					      pcmdinfo->post_mq);
		break;
	case MQ_OP_QUERY_CQ:
		ret_code = sxe2_drv_cq_query(pcmdinfo->in.u.cq_query.cq,
					     pcmdinfo->in.u.cq_query.query_pa,
					     pcmdinfo->in.u.cq_query.scratch,
					     pcmdinfo->post_mq);
		break;
	case MQ_OP_QUERY_SRQ:
		ret_code =
			sxe2_kquery_srq_ctx(pcmdinfo->in.u.srq_query.srq,
					    pcmdinfo->in.u.srq_query.query_pa,
					    pcmdinfo->in.u.srq_query.scratch,
					    pcmdinfo->post_mq);
		break;
	default:
		ret_code = -EOPNOTSUPP;
		break;
	}

	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR(
			"%s process cmd [opcode : %d] [ret : %d]\n", __func__,
			pcmdinfo->mq_cmd, ret_code);
	}

	return ret_code;
}

bool mq_kcheck_cqe_err(struct sxe2_rdma_ctx_dev *dev, u8 mq_cmd, bool error,
		       u16 maj_err_code, u16 min_err_code)
{
	size_t i = 0;
	u8 min_err_l, min_err_h;
	bool ret_code			  = true;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	for (i = 0; i < ARRAY_SIZE(sxe2_mq_cqe_err_list); ++i) {
		if (maj_err_code == sxe2_mq_cqe_err_list[i].maj &&
		    min_err_code == sxe2_mq_cqe_err_list[i].min &&
		    error == true) {
			if (sxe2_mq_cmd_names[mq_cmd]) {
				DRV_RDMA_LOG_DEV_ERR(
					"MQ: [%s Error][%s] maj=%#04X min=%#04X\n",
					sxe2_mq_cqe_err_list[i].desc,
					sxe2_mq_cmd_names[mq_cmd], maj_err_code,
					min_err_code);
			} else {
				DRV_RDMA_LOG_DEV_ERR(
					"MQ: [%s Error][Opcode Err] maj=%#04X min=%#04X\n",
					sxe2_mq_cqe_err_list[i].desc,
					maj_err_code, min_err_code);
			}
			ret_code = false;
			goto end;
		}
	}

	for (i = 0; i < ARRAY_SIZE(sxe2_mq_cqe_not_err_list); ++i) {
		if (maj_err_code == sxe2_mq_cqe_not_err_list[i].maj &&
		    min_err_code == sxe2_mq_cqe_not_err_list[i].min &&
		    error == false) {
			if (sxe2_mq_cmd_names[mq_cmd]) {
				DRV_RDMA_LOG_DEV_INFO(
					"MQ: [%s NotError][%s] maj=%#04X min=%#04X\n",
					sxe2_mq_cqe_not_err_list[i].desc,
					sxe2_mq_cmd_names[mq_cmd], maj_err_code,
					min_err_code);
			} else {
				DRV_RDMA_LOG_DEV_INFO(
					"MQ: [%s NotError][Opcode Err] maj=%#04X min=%#04X\n",
					sxe2_mq_cqe_not_err_list[i].desc,
					maj_err_code, min_err_code);
			}
			ret_code = false;
			goto end;
		}
	}

	if (maj_err_code == 0x0000) {
		min_err_l = (u8)(min_err_code & 0xFF);
		min_err_h = (u8)((min_err_code >> 8) & 0xFF);
		if ((min_err_l == 0x00) && (min_err_h != 0x00) &&
		    (error == false)) {
			if (sxe2_mq_cmd_names[mq_cmd]) {
				DRV_RDMA_LOG_DEV_INFO("MQ: [STag Valid][%s] maj=%#04X\n"
					"\tmin=%#04X, STag key is %#02X\n",
					sxe2_mq_cmd_names[mq_cmd], maj_err_code,
					min_err_code, min_err_h);
			} else {
				DRV_RDMA_LOG_DEV_INFO("MQ: [STag Valid][Opcode Err]\n"
					"\tmaj=%#04X min=%#04X, STag key is %#02X\n",
					maj_err_code, min_err_code, min_err_h);
			}
			ret_code = false;
		}
	}

end:
	return ret_code;
}

int mq_kget_mcqe_info(struct sxe2_rdma_ctx_cq *mcq,
		      struct sxe2_mcq_cqe_info *info)
{
	u64 temp;
	struct mcq_cqe *cqe = NULL;
	struct sxe2_mq_ctx *mq;
	u32 wqe_idx;
	u8 polarity			  = 0;
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mcq->dev);

	cqe = (struct mcq_cqe *)SXE2_GET_CURRENT_CQ_ELEM(&mcq->cq_uk);

	polarity = (u8)(cqe->CQE_valid);
	if (polarity != mcq->cq_uk.polarity) {
		ret_code = -ENOENT;
		goto end;
	}

	dma_rmb();

	mq = (struct sxe2_mq_ctx *)(unsigned long)(cqe->MQ_completion_context);

	info->error	   = (bool)cqe->error;
	info->maj_err_code = (u16)cqe->major_error_code;
	info->min_err_code = (u16)cqe->minor_error_code;

	wqe_idx	      = (u32)cqe->MQ_desc_index;
	info->scratch = mq->scratch_array[wqe_idx];

	info->op_ret_val = (u32)cqe->operation_return_value;

	get_64bit_val(mq->mq_buf_va[wqe_idx].elem, SXE2_MQ_WQE_OPCODE_OFFSET,
		      &temp);
	info->op_code = (u8)FIELD_GET(SXE2_MQ_WQE_OPCODE_BITS, temp);
	info->mq      = mq;
	mq->dev->mq_cmd_stats[info->op_code]++;

	SXE2_RING_MOVE_HEAD(mcq->cq_uk.cq_ring, ret_code);
	if (!SXE2_RING_CURRENT_HEAD(mcq->cq_uk.cq_ring))
		mcq->cq_uk.polarity ^= 1;

	SXE2_RING_MOVE_TAIL(mcq->cq_uk.cq_ring);
	set_32bit_val(mcq->cq_uk.doorbell_note, MCQ_DB_NOTE_OFFSET_0,
		      SXE2_RING_CURRENT_HEAD(mcq->cq_uk.cq_ring));

	dma_wmb();

	SXE2_RING_MOVE_TAIL(mq->mq_ring);
	atomic64_inc(&mq->completed_ops);

	if (mq_kcheck_cqe_err(mcq->dev, info->op_code, info->error,
			      info->maj_err_code, info->min_err_code) &&
	    (info->error == true)) {
		DRV_RDMA_LOG_DEV_ERR(
			"Not Match Standard errcode:mq opcode = %#x, error = %d,\n"
			"\tmaj_err_code = %#04X, min_err_code = %#04X\n",
			info->op_code, info->error, info->maj_err_code,
			info->min_err_code);
	}

end:
	return ret_code;
}

static void mq_kcomplete_mq_request(struct sxe2_mq *mq,
				    struct sxe2_mq_request *mq_request)
{
	WRITE_ONCE(mq_request->request_done, true);

	if (mq_request->waiting)
		wake_up(&mq_request->waitq);
	else if (mq_request->callback_fcn)
		mq_request->callback_fcn(mq_request);

	sxe2_kput_mq_request(mq, mq_request);
}

static void *mq_kremove_cmd_head(struct sxe2_rdma_ctx_dev *dev)
{
	struct list_head *entry = NULL;
	struct list_head *list	= &dev->mq_cmd_head;

	if (list_empty(list))
		goto end;

	entry = list->next;
	list_del(entry);

end:
	return entry;
}

int mq_kprocess_remaining_cmd(struct sxe2_rdma_ctx_dev *dev)
{
	int ret_code = 0;
	struct mq_cmds_info *pcmdinfo;
	unsigned long flags = 0;

	spin_lock_irqsave(&dev->mq_lock, flags);
	while (!list_empty(&dev->mq_cmd_head) &&
	       !mq_kquery_ring_full(dev->mq)) {
		pcmdinfo = (struct mq_cmds_info *)mq_kremove_cmd_head(dev);
		ret_code = mq_kexec_cmd(dev, pcmdinfo);
		if (ret_code)
			break;
	}
	spin_unlock_irqrestore(&dev->mq_lock, flags);
	return ret_code;
}

void mq_karm_mcq(struct sxe2_rdma_ctx_cq *mcq)
{
	u32 temp_val  = 0;
	u32 arm_ci    = 0;
	u8 ori_cmd_sn = 0;
	u8 cmd_sn     = 0;
	u64 doorbell  = 0;

	get_32bit_val(mcq->cq_uk.doorbell_note, MCQ_DB_NOTE_OFFSET_4,
		      &temp_val);
	arm_ci =
		(u32)(SXE2_RING_CURRENT_HEAD(mcq->cq_uk.cq_ring) & INVALID_U32);
	ori_cmd_sn = (u8)FIELD_GET(SXE2_CQ_DBNOTE_CMDSN, temp_val);
	cmd_sn	   = (++ori_cmd_sn) % MCQ_DB_NOTE_CMDSN_MASK;
	temp_val   = FIELD_PREP(SXE2_CQ_DBNOTE_ARMCI, arm_ci) |
		   FIELD_PREP(SXE2_CQ_DBNOTE_CMDSN, cmd_sn) |
		   FIELD_PREP(SXE2_CQ_DBNOTE_CMD, MCQ_DB_NOTE_CMD_VALUE);
	set_32bit_val(mcq->cq_uk.doorbell_note, MCQ_DB_NOTE_OFFSET_4, temp_val);

	dma_wmb();

	doorbell =
		(((u64)temp_val) << MQ_BITS_PER_INT) | ((u64)mcq->cq_uk.cq_id);
	set_64bit_val(mcq->cq_uk.cqe_alloc_db, 0, doorbell);
}

void sxe2_khandler_mcqe(struct sxe2_rdma_pci_f *rdma_func,
			struct sxe2_rdma_ctx_cq *mcq, bool flag)
{
	struct sxe2_mq_request *mq_request;
	struct sxe2_rdma_ctx_dev *dev = &rdma_func->ctx_dev;
	u32 cqe_count		      = 0;
	struct sxe2_mcq_cqe_info info;
	unsigned long flags = 0;
	int ret_code;
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;

#ifdef SXE2_CFG_DEBUG
	if (rdma_dev->rdma_func->mq.mcqe_ignore)
		return;
#endif

	do {
		memset(&info, 0, sizeof(info));
		spin_lock_irqsave(&rdma_func->mq.cmpl_lock, flags);
		ret_code = mq_kget_mcqe_info(mcq, &info);
		spin_unlock_irqrestore(&rdma_func->mq.cmpl_lock, flags);
		if (ret_code)
			break;
		mq_request = (struct sxe2_mq_request *)(uintptr_t)info.scratch;
		if (mq_request) {
			mq_request->cmpl_info.maj_err_code = info.maj_err_code;
			mq_request->cmpl_info.min_err_code = info.min_err_code;
			mq_request->cmpl_info.op_ret_val   = info.op_ret_val;
			mq_request->cmpl_info.error	   = info.error;
			mq_kcomplete_mq_request(&rdma_func->mq, mq_request);
		}
		if (mq_request && mq_request->waiting == false && info.error &&
		    (!rdma_func->reset)) {
			if ((info.maj_err_code == MQ_CRIERR_MAJ_ERRCODE) &&
			    ((info.min_err_code == MQ_CRIERR_MQC_NOT_CREATED) ||
			     (info.min_err_code == MQ_CRIERR_MQ_BASE_ERR) ||
			     (info.min_err_code == MQ_CRIERR_MQC_ECC_ERR) ||
			     ((info.min_err_code ==
			       MQ_CRIERR_QP_DESTROY_ABORT)))) {
				DRV_RDMA_LOG_DEV_ERR(
					"Critical Err:Request Reset,\n"
					"\tmaj_err %#04X, min_err %#04X, async mode\n",
					info.maj_err_code, info.min_err_code);
				rdma_func->reset = true;
				rdma_func->gen_ops.request_reset(rdma_func);
			}
		}
		cqe_count++;
	} while (1);

	if (cqe_count)
		mq_kprocess_remaining_cmd(dev);

	if (flag)
		mq_karm_mcq(dev->mcq);
}

void mq_kcheck_progress(struct sxe2_mq_timeout *timeout,
			struct sxe2_rdma_ctx_dev *dev)
{
	u64 completed_ops = atomic64_read(&dev->mq->completed_ops);

	if (timeout->cmpl_mq_cmds != completed_ops) {
		timeout->cmpl_mq_cmds = completed_ops;
		timeout->count	      = 0;
	} else if (timeout->cmpl_mq_cmds != dev->mq->requested_ops) {
		timeout->count++;
	}
}

int sxe2_kwait_event(struct sxe2_rdma_pci_f *rdma_func,
		     struct sxe2_mq_request *mq_request)
{
	struct sxe2_mq_timeout mq_timeout = {};
	bool mq_error			  = false;
	u16 maj_err			  = 0;
	u16 min_err			  = 0;
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	int wait_time_ms = (int)rdma_func->ctx_dev.hw_attrs
					   .max_mq_compl_wait_time_ms;
	struct mq_cmds_info *info	  = &mq_request->info;
	bool hw_rsrc_clean		  = false;

	mq_timeout.cmpl_mq_cmds =
		(u64)atomic64_read(&rdma_func->ctx_dev.mq->completed_ops);
	do {
		hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(&rdma_func->ctx_dev);
		if (rdma_func->reset && hw_rsrc_clean) {
			ret_code = (info->destroy ? 0 : -EBUSY);
			goto end;
		}
		if (rdma_func->reset && !hw_rsrc_clean && !info->destroy) {
			ret_code = -EBUSY;
			goto end;
		}

		sxe2_khandler_mcqe(rdma_func, &rdma_func->mcq.ctx_cq, false);
		if (wait_event_timeout(mq_request->waitq,
				       READ_ONCE(mq_request->request_done),
				       msecs_to_jiffies(wait_time_ms))) {
			break;
		}

		mq_kcheck_progress(&mq_timeout, &rdma_func->ctx_dev);

		if (mq_timeout.count < MQ_TIMEOUT_THRESHOLD)
			continue;
		if (!rdma_func->reset) {
			DRV_RDMA_LOG_DEV_ERR("Timeout Handle:Request Reset\n");
			rdma_func->reset = true;
			rdma_func->gen_ops.request_reset(rdma_func);
		}
		ret_code = -ETIMEDOUT;
		goto end;
	} while (1);

	if (mq_request->cmpl_info.error)
		mq_error = mq_request->cmpl_info.error;
	if (mq_error) {
		maj_err	 = mq_request->cmpl_info.maj_err_code;
		min_err	 = mq_request->cmpl_info.min_err_code;
		ret_code = -EIO;
		if ((maj_err == MQ_CRIERR_MAJ_ERRCODE) &&
		    ((min_err == MQ_CRIERR_MQC_NOT_CREATED) ||
		     (min_err == MQ_CRIERR_MQ_BASE_ERR) ||
		     (min_err == MQ_CRIERR_MQC_ECC_ERR) ||
		     ((min_err == MQ_CRIERR_QP_DESTROY_ABORT)))) {
			if (!rdma_func->reset) {
				DRV_RDMA_LOG_DEV_ERR(
					"Critical Err:Request Reset\n"
					"\t, maj_err %#04X, min_err %#04X\n",
					maj_err, min_err);
				rdma_func->reset = true;
				rdma_func->gen_ops.request_reset(rdma_func);
			}
		}
	}

end:
	return ret_code;
}

void mq_kfree_mq_request(struct sxe2_mq *mq, struct sxe2_mq_request *mq_request)
{
	unsigned long flags = 0;

	if (mq_request->dynamic) {
		kfree(mq_request);
	} else {
		WRITE_ONCE(mq_request->request_done, false);
		mq_request->callback_fcn = NULL;
		mq_request->waiting	 = false;

		spin_lock_irqsave(&mq->req_lock, flags);
		list_add_tail(&mq_request->list, &mq->mq_avail_reqs);
		spin_unlock_irqrestore(&mq->req_lock, flags);
	}
	wake_up(&mq->remove_wq);
}

void sxe2_kput_mq_request(struct sxe2_mq *mq,
			  struct sxe2_mq_request *mq_request)
{
	if (refcount_dec_and_test(&mq_request->refcnt))
		mq_kfree_mq_request(mq, mq_request);
}

int sxe2_khandle_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			struct sxe2_mq_request *mq_request)
{
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;
	struct mq_cmds_info *info	  = &mq_request->info;
	int ret_code			  = 0;
	bool put_mq_request		  = true;
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	bool hw_rsrc_clean		  = false;
	unsigned long flags		  = 0;

	hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(dev);
	if (rdma_func->reset && hw_rsrc_clean) {
		ret_code = (info->destroy ? 0 : -EBUSY);
		goto end;
	}
	if (rdma_func->reset && !hw_rsrc_clean && !info->destroy) {
		ret_code = -EBUSY;
		goto end;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[info->mq_cmd] &&
	    !info->destroy) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       info->mq_cmd);
		ret_code = -EBUSY;
		goto end;
	}
#endif

	sxe2_kget_mq_request(mq_request);

	spin_lock_irqsave(&dev->mq_lock, flags);
	if (list_empty(&dev->mq_cmd_head) && !mq_kquery_ring_full(dev->mq))
		ret_code = mq_kexec_cmd(dev, info);
	else {
		DRV_RDMA_LOG_DEV_INFO(
			"MQ list is full or cmd_list empty:buf %d, list %d\n",
			mq_kquery_ring_full(dev->mq),
			list_empty(&dev->mq_cmd_head));
		list_add_tail(&info->mq_cmd_entry, &dev->mq_cmd_head);
	}
	spin_unlock_irqrestore(&dev->mq_lock, flags);
	if (ret_code)
		goto err;

	if (mq_request->waiting) {
		put_mq_request = false;
		ret_code       = sxe2_kwait_event(rdma_func, mq_request);
		if (ret_code)
			goto err;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[info->mq_cmd] && info->destroy &&
	    !ret_code) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       info->mq_cmd);
		ret_code = -EBUSY;
		goto end;
	}
#endif

	goto end;

err:
	if (put_mq_request)
		sxe2_kput_mq_request(&rdma_func->mq, mq_request);
end:
	return ret_code;
}

int sxe2_kpoll_mq_registers(struct sxe2_mq_ctx *mq, u32 tail, u32 count)
{
	u32 i = 0;
	u32 newtail, error, val;
	u32 err_code;
	u16 maj_err_code, min_err_code;
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	struct mq_wqe_nop *wqe		  = NULL;
	u32 cmd_tail			  = 0;

	while (i++ < count) {
		sxe2_kget_mq_reg_info(mq, &val, &newtail, &error);

		if (newtail != tail) {
			SXE2_RING_MOVE_TAIL(mq->mq_ring);
			atomic64_inc(&mq->completed_ops);
			if (mq->mq_ring.tail > 0)
				cmd_tail = mq->mq_ring.tail - 1;
			else
				cmd_tail = mq->mq_ring.size - 1;

			wqe	 = (struct mq_wqe_nop *)(mq->mq_buf_va[cmd_tail]
								 .elem);
			mq->dev->mq_cmd_stats[wqe->op]++;

			err_code =
				SXE2_BAR_READ_32(mq->dev->hw_regs[MQ_ERRCODES]);
			min_err_code = (u16)(err_code & 0xFFFF);
			maj_err_code = (u16)((err_code >> 16) & 0xFFFF);
			if (mq_kcheck_cqe_err(mq->dev, (u8)wqe->op, (bool)error,
					      maj_err_code, min_err_code) &&
			    (error == true)) {
				DRV_RDMA_LOG_DEV_ERR(
					"Not Match Standard errcode:mq opcode = %#x, error = %d,\n"
					"\tmaj_err_code = %#04X, min_err_code = %#04X\n",
					(u8)wqe->op, error, maj_err_code,
					min_err_code);
			}
			if (error)
				ret_code = -EIO;
			goto end;
		}
		udelay(mq->dev->hw_attrs.max_sleep_count);
	}

	ret_code = -ETIMEDOUT;
	DRV_RDMA_LOG_DEV_ERR("MQ: MQ Poll Reg timeout, ret_code %d\n",
			     ret_code);

end:
	return ret_code;
}

int sxe2_kpoll_mcq(struct sxe2_mq_ctx *mq, u8 op_code,
		   struct sxe2_mcq_cqe_info *cmpl_info)
{
	struct sxe2_mcq_cqe_info info = {};
	struct sxe2_rdma_ctx_cq *mcq;
	int ret_code			  = 0;
	u32 cnt				  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	unsigned long flags = 0;

	mcq = mq->dev->mcq;
	while (1) {
		if (cnt++ > mq->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			goto end;
		}

		spin_lock_irqsave(&rdma_dev->rdma_func->mq.cmpl_lock, flags);
		ret_code = mq_kget_mcqe_info(mcq, &info);
		spin_unlock_irqrestore(&rdma_dev->rdma_func->mq.cmpl_lock, flags);
		if (ret_code) {
			udelay(mq->dev->hw_attrs.max_sleep_count);
			continue;
		}

		if (info.error)
			ret_code = -EIO;

		if (op_code == info.op_code)
			goto cmpl_end;

		ret_code = -EFAULT;
		DRV_RDMA_LOG_DEV_ERR(
			"WQE: opcode mismatch for my op code %#x, returned opcode %#x\n",
			op_code, info.op_code);
	}

cmpl_end:
	if (cmpl_info)
		memcpy(cmpl_info, &info, sizeof(*cmpl_info));
end:
	return ret_code;
}

void sxe2_kwork_mq_cmpl(struct work_struct *work)
{
	struct sxe2_rdma_pci_f *rdma_func =
		container_of(work, struct sxe2_rdma_pci_f, mq_cmpl_work);
	struct sxe2_rdma_ctx_cq *cq = &rdma_func->mcq.ctx_cq;

	sxe2_khandler_mcqe(rdma_func, cq, true);
}

int sxe2_mq_kexec_nop_op(struct sxe2_rdma_device *rdma_dev, bool post, u32 wait)
{
	int ret_code;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	bool wait_type;

	if (wait == (u32)SXE2_MQ_WAIT_CQE) {
		wait_type = true;
	} else if (wait == (u32)SXE2_MQ_WAIT_EVENT) {
		wait_type = false;
	} else {
		ret_code = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("inv wait_type param %d, ret %d\n", wait,
				     ret_code);
		goto end;
	}

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, wait_type);
	if (!mq_request) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("Get mq_request failed, ret %d\n",
				     ret_code);
		goto end;
	}
	mq_info		= &mq_request->info;
	mq_info->mq_cmd = MQ_OP_NOP;

	if (post)
		mq_info->post_mq = 1;
	else
		mq_info->post_mq = 0;

	mq_info->in.u.nop.wait_type = wait;
	mq_info->in.u.nop.mq	    = &rdma_func->mq.mq;
	mq_info->in.u.nop.scratch   = (uintptr_t)mq_request;
	ret_code = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret_code)
		DRV_RDMA_LOG_DEV_ERR("MQ NOP cmd failed, ret %d\n", ret_code);

end:
	return ret_code;
}

static int mq_kinit_context(struct sxe2_mq_ctx *mq,
			    struct sxe2_mq_init_info *info)
{
	u8 hw_mq_size;
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);

	if (info->mqe_count > SXE2_MQE_COUNT_2048 ||
	    info->mqe_count < SXE2_MQE_COUNT_4 ||
	    ((info->mqe_count & (info->mqe_count - 1)))) {
		ret_code = -EINVAL;
		goto end;
	}

	hw_mq_size =
		sxe2_kget_encoded_wqe_size(info->mqe_count, SXE2_QUEUE_TYPE_MQ);

	mq->size	  = sizeof(*mq);
	mq->mqe_count	  = info->mqe_count;
	mq->hw_mq_size	  = hw_mq_size;
	mq->mq_buf_va	  = info->mq_buf_va;
	mq->mq_ctx_va	  = info->mq_ctx_va;
	mq->mq_buf_pa	  = info->mq_buf_pa;
	mq->mq_ctx_pa	  = info->mq_ctx_pa;
	mq->dev		  = info->dev;
	mq->protocol_used = info->protocol_used;
	mq->struct_ver = info->struct_ver;
	mq->hw_maj_ver	  = info->hw_maj_ver;
	mq->hw_min_ver	  = info->hw_min_ver;
	mq->scratch_array = info->scratch_array;
	mq->polarity = 0;
	mq->ceqs_per_vf	      = info->ceqs_per_vf;
	mq->rocev2_rto_policy = info->rocev2_rto_policy;
	mq->ena_vf_count	= info->ena_vf_count;
	mq->rcms_profile	= info->rcms_profile;
	mq->en_rem_endpoint_trk = info->en_rem_endpoint_trk;

	info->dev->mq = mq;

	SXE2_RING_INIT(mq->mq_ring, mq->mqe_count);
	mq->requested_ops = 0;
	atomic64_set(&mq->completed_ops, 0);
	INIT_LIST_HEAD(&mq->dev->mq_cmd_head);

	DRV_RDMA_LOG_DEV_INFO(
		"WQE: mq_size[%04d] hw_mq_size[%04d] mq_base[%p]\n"
		"\tmq_pa[%pK] mq[%p] polarity[x%04x]\n",
		mq->mqe_count, mq->hw_mq_size, mq->mq_buf_va,
		(u64 *)(uintptr_t)mq->mq_buf_pa, mq, mq->polarity);

end:
	return ret_code;
}

static void mq_mqc_init(struct sxe2_mq_ctx *mq, struct sxe2_mqc *mqc,
			struct sxe2_rdma_device *rdma_dev)
{
	memset(mqc, 0, sizeof(*mqc));
	mqc->RoCEv2_RTO_policy = mq->rocev2_rto_policy;
	mqc->protocol_used     = mq->protocol_used;
	mqc->SQ_size	       = mq->hw_mq_size;
	mqc->struct_version    = mq->struct_ver;
	mqc->num_CEQs_per_VF   = mq->ceqs_per_vf;

	mqc->SQ_base = (mq->mq_buf_pa >> SXE2_MQC_SQ_BASE_OFFSET);

	DRV_RDMA_LOG_DEBUG_BDF("Create MQ:mq_buf_pa %#llx, mqc.SQ_base %#llx\n",
			       mq->mq_buf_pa, mqc->SQ_base);

	mqc->rcms_profile_type	    = mq->rcms_profile;
	mqc->PE_enabled_vf_count    = mq->ena_vf_count;
	mqc->remote_endpoint_trk_en = mq->en_rem_endpoint_trk;

#ifndef SXE2_NATIVE_CPUID_NOT_SUPPORT
	if (rdma_dev->rdma_func->hygon_cpu_en == (u8)SXE2_RDMA_HYGON_DEFAULT) {
		if (true == sxe2_rdma_get_cpu_vendor(rdma_dev)) {
			mqc->cache_line_64byte_en  = MQC_64B_CACHE_LINE_EN;
			rdma_dev->cache_line_64_en = true;
		} else {
			mqc->cache_line_64byte_en  = MQC_64B_CACHE_LINE_NO_EN;
			rdma_dev->cache_line_64_en = false;
		}
	} else if (rdma_dev->rdma_func->hygon_cpu_en ==
		   (u8)SXE2_RDMA_HYGON_FORCE_ENABLE) {
		mqc->cache_line_64byte_en  = MQC_64B_CACHE_LINE_EN;
		rdma_dev->cache_line_64_en = true;
	} else if (rdma_dev->rdma_func->hygon_cpu_en ==
		   (u8)SXE2_RDMA_HYGON_FORCE_DISABLE) {
		mqc->cache_line_64byte_en  = MQC_64B_CACHE_LINE_NO_EN;
		rdma_dev->cache_line_64_en = false;
	}
#else
	mqc->cache_line_64byte_en  = MQC_64B_CACHE_LINE_NO_EN;
	rdma_dev->cache_line_64_en = false;
#endif
	DRV_RDMA_LOG_DEBUG_BDF(
		"MQC HYGON CPU:cfg_param:%#x, mqc.cache_line_64byte_en:%#llx,\n"
		"\trdma_dev->cache_line_64_en %d\n",
		rdma_dev->rdma_func->hygon_cpu_en, mqc->cache_line_64byte_en,
		rdma_dev->cache_line_64_en);

	mqc->QP_completion_context = (uintptr_t)mq;
	mqc->hw_minor_version	   = mq->hw_min_ver;
	mqc->hw_major_version	   = mq->hw_maj_ver;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_size",
		     &rdma_dev->rdma_func->mq.err_val, mqc, mq);

	INJECT_START(rdma_dev->rdma_func, "mq_base",
		     &rdma_dev->rdma_func->mq.err_val, mqc, mq);

	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_size");
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_base");
#endif

	memcpy(mq->mq_ctx_va, mqc, sizeof(*mqc));
	DRV_RDMA_LOG_INFO_BDF(
		"mqc : ena_fine_grained_timers %#x, RoCEv2_RTO_policy %#x\n"
		"mqc : protocol_used %#x, SQ_size %#x, struct_version %#x\n"
		"mqc : num_CEQs_per_VF %#x, SQ_base %#llx, rcms_profile_type %#x\n"
		"mqc : remote_endpoint_trk_en %#x, rdpa_assist %#x,\n"
		"cache_line_64byte_en %#x, PE_enabled_vf_count %#x\n"
		"mqc : QP_completion_context %#llx, hw_minor_ver %#x, hw_major_ver\n"
		"%#x\n"
		"mqc : dcqcn_min_rate %#x, dcqcn_min_dec_factor %#x, dcqcn_T %#x\n"
		"mqc : cc_hai_factor %#x, cc_rai_factor %#x, dcqcn_B %#x, dcqcn_F %#x\n"
		"mqc : cc_cfg_valid %#x, dcqcn_rreduce_mperiod %#x\n",
		mqc->enable_fine_grained_timers, mqc->RoCEv2_RTO_policy,
		mqc->protocol_used, mqc->SQ_size, mqc->struct_version,
		mqc->num_CEQs_per_VF, mqc->SQ_base, mqc->rcms_profile_type,
		mqc->remote_endpoint_trk_en, mqc->rdpa_assist,
		mqc->cache_line_64byte_en, mqc->PE_enabled_vf_count,
		mqc->QP_completion_context, mqc->hw_minor_version,
		mqc->hw_major_version, mqc->dcqcn_min_rate,
		mqc->dcqcn_min_dec_factor, mqc->dcqcn_T, mqc->cc_hai_factor,
		mqc->cc_rai_factor, mqc->dcqcn_B, mqc->dcqcn_F,
		mqc->cc_cfg_valid, mqc->dcqcn_rreduce_mperiod);
}

int mq_kcreate_context(struct sxe2_mq_ctx *mq)
{
	u32 cnt = 0, p1, p2, val = 0;
	u32 err_bit, err_code = 0;
	u32 mqc_vld = SXE2_MQC_ADDR_VLD_SET;
	size_t i    = 0;
	struct sxe2_mqc mqc;
	int ret_code			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	u32 mqc_cnt			  = 0;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_creat",
		     &rdma_dev->rdma_func->mq.err_val);

	if (rdma_dev->rdma_func->mq.err_val.mqc_ignore_vld) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"MQ DEBUGFS:dbg_mqc_ignore_vld:%#x\n",
			rdma_dev->rdma_func->mq.err_val.mqc_ignore_vld);
		return 0;
	}
#endif

	mq->fptebuf.size = ALIGN(SXE2_UPDATE_FPT_BUFF_SIZE * mq->mqe_count,
				 SXE2_FPT_BUF_ALIGNMENT);
	mq->fptebuf.va =
		dma_alloc_coherent(mq->dev->hw->device, mq->fptebuf.size,
				   &mq->fptebuf.pa, GFP_KERNEL);
	if (!mq->fptebuf.va) {
		ret_code = -ENOMEM;
		goto end;
	}
	memset(mq->fptebuf.va, 0, mq->fptebuf.size);
	spin_lock_init(&mq->dev->mq_lock);
	mq_mqc_init(mq, &mqc, rdma_dev);
	print_hex_dump_debug("WQE: MQ_HOST_CTX WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, mq->mq_ctx_va,
			     SXE2_MQ_CTX_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);
#ifdef SXE2_CFG_DEBUG
	DATA_DUMP(mq->mq_ctx_va, sizeof(mqc), "create mqc");
#endif
	p1 = (u32)(mq->mq_ctx_pa >> MQ_BITS_PER_INT);
	p2 = (u32)(mq->mq_ctx_pa);

	for (mqc_cnt = 0; mqc_cnt < SXE2_MQ_CTX_SIZE; mqc_cnt++) {
		DRV_RDMA_LOG_DEV_DEBUG("Create MQ:mq->mq_ctx_va[%#x]:%#llx\n",
				       mqc_cnt, mq->mq_ctx_va[mqc_cnt]);
	}
	DRV_RDMA_LOG_DEV_DEBUG("Create MQ:va %p, pa %#llx, p1 %#x, p2 %#x\n",
			       mq->mq_ctx_va, mq->mq_ctx_pa, p1, p2);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_dma_err",
		     &rdma_dev->rdma_func->mq.err_val, &p1, &p2, mq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_dma_err");

	INJECT_START(rdma_dev->rdma_func, "mq_duplicate_creat", &p1, &p2, mq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_duplicate_creat");
#endif

	SXE2_BAR_WRITE_32(p1, mq->dev->hw_regs[MQC_ADDR_HIGH]);
	SXE2_BAR_WRITE_32(p2, mq->dev->hw_regs[MQC_ADDR_LOW]);
	SXE2_BAR_WRITE_32(mqc_vld, mq->dev->hw_regs[MQC_ADDR_VLD]);

	do {
		if (cnt++ > mq->dev->hw_attrs.max_done_count) {
			ret_code = -ETIMEDOUT;
			DRV_RDMA_LOG_DEV_ERR(
				"Create MQ:wait reg timeout, ret %d\n",
				ret_code);
			goto err;
		}
		udelay(mq->dev->hw_attrs.max_sleep_count);
		val = SXE2_BAR_READ_32(mq->dev->hw_regs[MQ_STATUS]);
	} while (!val);

	err_bit = FIELD_GET(SXE2_RDMA_MQ_STATUS_ERR, val);
	if (err_bit) {
		err_code = FIELD_GET(SXE2_RDMA_MQ_STATUS_ERRCODE, val);
		for (i = 0; i < ARRAY_SIZE(sxe2_mq_ctx_err_list); ++i) {
			if (err_code == sxe2_mq_ctx_err_list[i].err) {
				DRV_RDMA_LOG_DEV_ERR(
					"Create MQ: [%s Error] err=%#x\n",
					sxe2_mq_ctx_err_list[i].desc, err_code);
				ret_code = -EOPNOTSUPP;
				goto err;
			}
		}
	}
	mq->process_mq_fpt = sxe2_rcms_update_fptes_cmd;

	goto end;

err:
	dma_free_coherent(mq->dev->hw->device, mq->fptebuf.size, mq->fptebuf.va,
			  mq->fptebuf.pa);
	mq->fptebuf.va = NULL;
end:
	return ret_code;
}

static int mq_kdestroy_context(struct sxe2_mq_ctx *mq, bool free_hwmq)
{
	u32 cnt = 0, val = 0;
	u32 mqc_vld  = SXE2_MQC_ADDR_VLD_SET;
	int ret_code = 0;

	if (free_hwmq) {
		SXE2_BAR_WRITE_32(0, mq->dev->hw_regs[MQC_ADDR_HIGH]);
		SXE2_BAR_WRITE_32(0, mq->dev->hw_regs[MQC_ADDR_LOW]);
		SXE2_BAR_WRITE_32(mqc_vld, mq->dev->hw_regs[MQC_ADDR_VLD]);
		do {
			if (cnt++ > mq->dev->hw_attrs.max_done_count) {
				ret_code = -ETIMEDOUT;
				break;
			}
			udelay(mq->dev->hw_attrs.max_sleep_count);
			val = SXE2_BAR_READ_32(mq->dev->hw_regs[MQ_STATUS]);
		} while (!(FIELD_GET(SXE2_RDMA_MQ_STATUS_DONE, val)));
	}

	dma_free_coherent(mq->dev->hw->device, mq->fptebuf.size, mq->fptebuf.va,
			  mq->fptebuf.pa);
	mq->fptebuf.va = NULL;
	return ret_code;
}

static int mq_info_init(struct sxe2_mq_init_info *mq_init_info,
			struct sxe2_rdma_ctx_dev *dev,
			struct sxe2_rdma_pci_f *rdma_func, u32 mqe_count,
			struct sxe2_rdma_dma_mem mem)
{
	int ret_code	   = 0;
	struct sxe2_mq *mq = &rdma_func->mq;

	mq_init_info->dev	= dev;
	mq_init_info->mqe_count = mqe_count;
	mq_init_info->mq_buf_va = mq->mq_buf.va;
	mq_init_info->mq_buf_pa = mq->mq_buf.pa;
	mq_init_info->mq_ctx_pa = mem.pa;
	mq_init_info->mq_ctx_va = mem.va;

	mq_init_info->rcms_profile	  = rdma_func->rsrc_profile;
	mq_init_info->ena_vf_count	  = rdma_func->max_rdma_vfs;
	mq_init_info->scratch_array	  = mq->scratch_array;
	mq_init_info->protocol_used	  = rdma_func->protocol_used;
	mq_init_info->en_rem_endpoint_trk = rdma_func->en_rem_endpoint_trk;
	mq_init_info->hw_maj_ver = SXE2_HW_MAJVER_GEN_1;

	ret_code = mq_kinit_context(dev->mq, mq_init_info);
	if (ret_code)
		DRV_RDMA_LOG_ERROR("ERR: mq init status %d\n", ret_code);

	return ret_code;
}

int sxe2_kcreate_mq(struct sxe2_rdma_device *rdma_dev)
{
	u32 mqe_count = SXE2_MQE_COUNT_2048;
	struct sxe2_rdma_dma_mem mem;
	struct sxe2_rdma_pci_f *rdma_func     = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	      = &rdma_func->ctx_dev;
	struct sxe2_mq_init_info mq_init_info = {};
	struct sxe2_mq *mq		      = &rdma_func->mq;
	u32 i				      = 0;
	int ret_code			      = 0;
	bool free_hwmq	   = true;
	bool hw_rsrc_clean = false;
	int err_ret_code   = 0;

	mq->mq_requests =
		kcalloc(mqe_count, sizeof(*mq->mq_requests), GFP_KERNEL);
	if (!mq->mq_requests) {
		ret_code = -ENOMEM;
		goto end;
	}

	mq->scratch_array =
		kcalloc(mqe_count, sizeof(*mq->scratch_array), GFP_KERNEL);
	if (!mq->scratch_array) {
		ret_code = -ENOMEM;
		goto err_scratch;
	}

	dev->mq	     = &mq->mq;
	dev->mq->dev = dev;

	mq->mq_buf.size = ALIGN(sizeof(struct sxe2_mq_wqe) * mqe_count,
				SXE2_MQ_ALIGNMENT);
	mq->mq_buf.va	= dma_alloc_coherent(dev->hw->device, mq->mq_buf.size,
					     &mq->mq_buf.pa, GFP_KERNEL);
	if (!mq->mq_buf.va) {
		ret_code = -ENOMEM;
		goto err_mq;
	}
	memset(mq->mq_buf.va, 0, mq->mq_buf.size);

	ret_code = sxe2_kget_aligned_mem(rdma_func, &mem,
					 sizeof(struct sxe2_mq_context),
					 SXE2_HOST_CTX_ALIGNMENT_M);
	if (ret_code)
		goto err_ctx;

	dev->mq->mq_ctx_pa = mem.pa;
	dev->mq->mq_ctx_va = mem.va;
	DRV_RDMA_LOG_DEBUG_BDF(
		"CREATE MQ:mq_buf.va %p, mq_buf.pa %#llx mq_ctx.va %p, mq_ctx.pa %#llx\n",
		(u64 *)mq->mq_buf.va, (u64)mq->mq_buf.pa, (u64 *)mem.va,
		(u64)mem.pa);

	ret_code = mq_info_init(&mq_init_info, dev, rdma_func, mqe_count, mem);
	if (ret_code)
		goto err_ctx;

	spin_lock_init(&mq->req_lock);
	spin_lock_init(&mq->cmpl_lock);

	ret_code = mq_kcreate_context(dev->mq);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("ERR: mq create failed - ret_code %d\n",
				     ret_code);
		goto err_ctx;
	}

	INIT_LIST_HEAD(&mq->mq_avail_reqs);

	for (i = 0; i < mqe_count; i++) {
		init_waitqueue_head(&mq->mq_requests[i].waitq);
		list_add_tail(&mq->mq_requests[i].list, &mq->mq_avail_reqs);
	}
	init_waitqueue_head(&mq->remove_wq);

	ret_code = sxe2_kadd_mq_rsc_debugfs(rdma_dev, mq);
	if (unlikely(ret_code)) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding MQ to debug file system, ret %d\n",
			ret_code);
		hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(dev);
		if (rdma_func->reset && hw_rsrc_clean)
			free_hwmq = false;

		err_ret_code = mq_kdestroy_context(dev->mq, free_hwmq);
		if (unlikely(err_ret_code))
			DRV_RDMA_LOG_DEV_ERR(
				"ERR: debugfs err, and destroy MQ failed %d\n",
				err_ret_code);
		goto err_ctx;
	}

	goto end;

err_ctx:
	dma_free_coherent(dev->hw->device, mq->mq_buf.size, mq->mq_buf.va,
			  mq->mq_buf.pa);
	mq->mq_buf.va = NULL;
err_mq:
	kfree(mq->scratch_array);
	mq->scratch_array = NULL;
err_scratch:
	kfree(mq->mq_requests);
	mq->mq_requests = NULL;
end:
	return ret_code;
}

static void mq_kfree_pending_mq_request(struct sxe2_mq *mq,
					struct sxe2_mq_request *mq_request)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->mq.dev);

	mq_request->cmpl_info.error = true;
	WRITE_ONCE(mq_request->request_done, true);

	if (mq_request->waiting)
		wake_up(&mq_request->waitq);

	wait_event_timeout(mq->remove_wq,
			   refcount_read(&mq_request->refcnt) == 1, 1000);
	sxe2_kput_mq_request(mq, mq_request);

	DRV_RDMA_LOG_DEV_DEBUG("DESTROY MQ:free mq_request opcode %#x\n",
			       mq_request->info.mq_cmd);
}

static void mq_kcleanup_pending_op(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_rdma_ctx_dev *dev	   = &rdma_func->ctx_dev;
	struct sxe2_mq *mq		   = &rdma_func->mq;
	struct sxe2_mq_request *mq_request = NULL;
	struct mq_cmds_info *pcmdinfo	   = NULL;
	u32 i, pending_work, wqe_idx;

	pending_work = SXE2_RING_USED_QUANTA(mq->mq.mq_ring);
	wqe_idx	     = SXE2_RING_CURRENT_TAIL(mq->mq.mq_ring);

	for (i = 0; i < pending_work; i++) {
		mq_request = (struct sxe2_mq_request *)(uintptr_t)
				     mq->scratch_array[wqe_idx];
		if (mq_request)
			mq_kfree_pending_mq_request(mq, mq_request);
		wqe_idx = (wqe_idx + 1) % SXE2_RING_SIZE(mq->mq.mq_ring);
	}

	while (!list_empty(&dev->mq_cmd_head)) {
		pcmdinfo = (struct mq_cmds_info *)mq_kremove_cmd_head(dev);
		mq_request =
			container_of(pcmdinfo, struct sxe2_mq_request, info);
		if (mq_request)
			mq_kfree_pending_mq_request(mq, mq_request);
	}
}

void sxe2_kdestroy_mq(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;
	struct sxe2_mq *mq		  = &rdma_func->mq;
	bool free_hwmq			  = true;
	int ret_code			  = 0;
	bool hw_rsrc_clean		  = false;

	hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(dev);
	if (rdma_func->reset && hw_rsrc_clean)
		free_hwmq = false;

	sxe2_kremove_mq_rsc_debugfs(rdma_dev, mq);

	ret_code = mq_kdestroy_context(dev->mq, free_hwmq);
	if (ret_code)
		DRV_RDMA_LOG_DEV_ERR("ERR: Destroy MQ failed %d\n", ret_code);
	mq_kcleanup_pending_op(rdma_func);

	dma_free_coherent(dev->hw->device, mq->mq_buf.size, mq->mq_buf.va,
			  mq->mq_buf.pa);
	mq->mq_buf.va = NULL;

	kfree(mq->scratch_array);
	mq->scratch_array = NULL;
	kfree(mq->mq_requests);
	mq->mq_requests = NULL;

	DRV_RDMA_LOG_DEV_INFO("Destroy MQ over\n");
}

void sxe2_kuninit_mq_handler(struct sxe2_rdma_device *rdma_dev)
{
	if (rdma_dev->rdma_func->mq_cmpl_wq) {
		destroy_workqueue(rdma_dev->rdma_func->mq_cmpl_wq);
		rdma_dev->rdma_func->mq_cmpl_wq = NULL;
	}
}

int sxe2_kinit_mq_handler(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	int ret_code			  = 0;

	rdma_func->mq_cmpl_wq =
		alloc_ordered_workqueue("mq_cmpl_wq", WQ_HIGHPRI | WQ_UNBOUND);
	if (!rdma_func->mq_cmpl_wq) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("Alloc MQ Cmpl Wq fail, ret_code %d\n",
				     ret_code);
		goto end;
	}

	INIT_WORK(&rdma_func->mq_cmpl_work, sxe2_kwork_mq_cmpl);

	mq_karm_mcq(rdma_func->ctx_dev.mcq);

end:
	return ret_code;
}
