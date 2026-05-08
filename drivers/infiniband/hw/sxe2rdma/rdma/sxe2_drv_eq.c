// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_eq.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/interrupt.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/radix-tree.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/atomic.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "sxe2_compat.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_eq_debugfs.h"
#include "sxe2_drv_aux.h"
#include "sxe2_drv_srq.h"

#define SXE2_EQC_PHY_ADDR_OFFSET (8)

static void sxe2_rdma_ena_intr(struct sxe2_rdma_ctx_dev *dev, u32 msix_id)
{
	dev->irq_ops->sxe2_rdma_en_irq(dev, msix_id);
}

static void sxe2_eq_update_ci(u32 __iomem *addr, u32 cons_index, u32 eqn)
{
	u32 val = (eqn & SXE2_DB_EQN_MASK) | (cons_index << SXE2_DB_CI_OFFSET);

	DRV_RDMA_LOG_DEBUG("db eqn:%d addr:%p cons_index:%d\n", eqn, addr,
			   cons_index);
	set_32bit_val(addr, 0, val);
	/* Ensure all prior memory operations are completed */
	mb();
}

static void *sxe2_ctx_process_ceq(struct sxe2_rdma_pci_f *rf,
				  struct sxe2_rdma_ctx_ceq *ceq)
{
	u64 temp;
	__le64 *ceqe;
	struct sxe2_rdma_ctx_cq *cq = NULL;
	struct sxe2_rdma_cq *temp_cq;
	struct sxe2_rdma_mcq *temp_mcq;
	u8 polarity;
	u32 cq_idx;
	struct sxe2_rdma_device *rdma_dev = rf->rdma_dev;

	do {
		if (rdma_dev->cache_line_64_en == false)
			ceqe = SXE2_GET_CURRENT_CEQ_ELEM(ceq);
		else
			ceqe = SXE2_GET_CURRENT_CEQ_ELEM_HYGON(ceq);

		get_64bit_val(ceqe, 0, &temp);
		DRV_RDMA_LOG_DEV_DEBUG("ceq:tail %#x, ceqe %#llx\n",
				       SXE2_RING_CURRENT_TAIL((ceq)->ceq_ring),
				       temp);
		polarity = (u8)FIELD_GET(SXE2_CEQE_VALID, temp);
		cq_idx	 = FIELD_GET(SXE2_CEQE_CQID, temp);
		DRV_RDMA_LOG_DEV_DEBUG(
			"ceq valid:%d ceq->polarity:%d. cq_idx:%d\n", polarity,
			ceq->polarity, cq_idx);
		if (polarity != ceq->polarity)
			return NULL;

		if (cq_idx > rf->max_cq) {
			cq_idx = SXE2_INVALID_CQ_IDX;
			SXE2_RING_MOVE_TAIL(ceq->ceq_ring);

			if (!SXE2_RING_CURRENT_TAIL(ceq->ceq_ring))
				ceq->polarity ^= 1;
			continue;
		}

		if (cq_idx == 0) {
			temp_mcq = &rf->mcq;
			cq	 = &temp_mcq->ctx_cq;
		} else {
			temp_cq = rf->cq_table[cq_idx];
			if (!temp_cq) {
				cq_idx = SXE2_INVALID_CQ_IDX;
				SXE2_RING_MOVE_TAIL(ceq->ceq_ring);

				if (!SXE2_RING_CURRENT_TAIL(ceq->ceq_ring))
					ceq->polarity ^= 1;
				continue;
			}

			cq = &temp_cq->cq_ctx;
		}

		SXE2_RING_MOVE_TAIL(ceq->ceq_ring);
		ceq->cons_index = SXE2_RING_CURRENT_TAIL(ceq->ceq_ring);
		if (!SXE2_RING_CURRENT_TAIL(ceq->ceq_ring))
			ceq->polarity ^= 1;
	} while (cq_idx == SXE2_INVALID_CQ_IDX);

	return cq;
}

void sxe2_rdma_comp_handler(struct sxe2_rdma_ctx_cq *cq_ctx)
{
	struct sxe2_rdma_cq *cq = cq_ctx->back_cq;

	if (!cq->user_mode)
		atomic_set(&cq->armed, 0);

	if (cq->ibcq.comp_handler)
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
static void sxe2_rdma_err_inject_ci_no_update(struct sxe2_rdma_device *rdma_dev,
		struct sxe2_rdma_ctx_ceq *ctx_ceq, u32 update_ci_eqn)
{
	if ((rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate ==
			 SXE2_INJECT_EQ_CEQ0_VALUE &&
		 ctx_ceq->ceq_id == 0) ||
		(rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate ==
			 SXE2_INJECT_EQ_CEQS_VALUE &&
		 ctx_ceq->ceq_id != 0)) {
		DRV_RDMA_LOG_DEBUG_BDF("inject ceq%u ci no update err.\n", ctx_ceq->ceq_id);
	} else {
		sxe2_eq_update_ci(ctx_ceq->doorbell, ctx_ceq->cons_index,
						   update_ci_eqn);
		DRV_RDMA_LOG_DEBUG_BDF("ceq:%d process update ci:%d.\n",
							   ctx_ceq->ceq_id, update_ci_eqn);
	}
}
#endif
static void sxe2_process_ceq(struct sxe2_rdma_pci_f *rf,
			     struct sxe2_rdma_ceq *ceq)
{
	struct sxe2_rdma_ctx_ceq *ctx_ceq;
	struct sxe2_rdma_ctx_cq *cq;
	unsigned long flags = 0;
	u32 num_eqes	    = 0;
	u32 update_ci_eqn;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_device *rdma_dev;

	ctx_ceq	 = &ceq->ctx_ceq;
	dev	 = ctx_ceq->dev;
	rdma_dev = to_rdmadev(dev);
	DRV_RDMA_LOG_DEV_DEBUG("ceq:%d process start.\n", ctx_ceq->ceq_id);

	update_ci_eqn = ctx_ceq->ceq_id + 1;

	do {
		DRV_RDMA_LOG_DEV_DEBUG("ceqe:%d process.\n", num_eqes);
		spin_lock_irqsave(&ceq->ce_lock, flags);
		cq = sxe2_ctx_process_ceq(rf, ctx_ceq);
		if (!cq) {
			DRV_RDMA_LOG_DEV_DEBUG("ceq process end.\n");
			spin_unlock_irqrestore(&ceq->ce_lock, flags);
			break;
		}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->inject_aeq.db_ceqn_err) {
		update_ci_eqn = 0xffff;
		DRV_RDMA_LOG_DEV_DEBUG("inject db ceqn 0xffff err.\n");
	}
#endif

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	sxe2_rdma_err_inject_ci_no_update(rdma_dev, ctx_ceq, update_ci_eqn);
#else
		sxe2_eq_update_ci(ctx_ceq->doorbell, ctx_ceq->cons_index,
				  update_ci_eqn);
		DRV_RDMA_LOG_DEV_DEBUG("ceq:%d process update ci:%d.\n",
				       ctx_ceq->ceq_id, update_ci_eqn);
#endif

		++num_eqes;

		if (cq->cq_type == SXE2_RDMA_CQ_TYPE_IO)
			sxe2_rdma_comp_handler(cq);
		spin_unlock_irqrestore(&ceq->ce_lock, flags);

		if (cq->cq_type == SXE2_RDMA_CQ_TYPE_MQ && rf->mq_cmpl_wq != NULL)
			queue_work(rf->mq_cmpl_wq, &rf->mq_cmpl_work);
	} while (num_eqes < SXE2_EQ_POLLING_BUDGET);
}

struct sxe2_ae_desc ae_desc_list[] = {
	{ SXE2_AE_AMP_UNALLOCATED_STAG, "SXE2_AE_AMP_UNALLOCATED_STAG", 0,
	  "Unallocated memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_INVALID_STAG, "SXE2_AE_AMP_INVALID_STAG", 0,
	  "Invalid memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_BAD_QP, "SXE2_AE_AMP_BAD_QP", 0,
	  "Memory protection error: Accessing Memory Window (MW) which belongs to a different QP" },
	{ SXE2_AE_AMP_BAD_PD, "SXE2_AE_AMP_BAD_PD", 0,
	  "Memory protection error: Accessing Memory Window\n"
	  "\t(MW)/Memory Region (MR) which belongs to a different PD" },
	{ SXE2_AE_AMP_BAD_STAG_KEY, "SXE2_AE_AMP_BAD_STAG_KEY", 0,
	  "Bad memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_BAD_STAG_INDEX, "SXE2_AE_AMP_BAD_STAG_INDEX", 0,
	  "Bad memory key (L-Key/R-Key): Too large memory key index" },
	{ SXE2_AE_AMP_BOUNDS_VIOLATION, "SXE2_AE_AMP_BOUNDS_VIOLATION", 0,
	  "Memory Window (MW)/Memory Region (MR) bounds violation" },
	{ SXE2_AE_AMP_RIGHTS_VIOLATION, "SXE2_AE_AMP_RIGHTS_VIOLATION", 0,
	  "Memory Window (MW)/Memory Region (MR) rights violation" },
	{ SXE2_AE_AMP_FASTREG_VALID_STAG, "SXE2_AE_AMP_FASTREG_VALID_STAG", 0,
	  "Fastreg error: Registration to a valid MR" },
	{ SXE2_AE_AMP_FASTREG_MW_STAG, "SXE2_AE_AMP_FASTREG_MW_STAG", 0,
	  "Fastreg error: Registration to a valid Memory Window (MW)" },
	{ SXE2_AE_AMP_FASTREG_INVALID_RIGHTS,
	  "SXE2_AE_AMP_FASTREG_INVALID_RIGHTS", 0,
	  "Fastreg error: Invalid rights" },
	{ SXE2_AE_AMP_FASTREG_INVALID_LENGTH,
	  "SXE2_AE_AMP_FASTREG_INVALID_LENGTH", 0,
	  "Fastreg error: Invalid length" },
	{ SXE2_AE_AMP_REMOTE_INVALIDATE_MR_RD_ERR,
	  "SXE2_AE_AMP_REMOTE_INVALIDATE_MR_RD_ERR", 0,
	  "Remote invalidate key error: mr dma error" },
	{ SXE2_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS,
	  "SXE2_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS", 0,
	  "Attempt to remotely invalidate Memory Window (MW)/Memory Region (MR) without rights" },
	{ SXE2_AE_AMP_INVALIDATE_MR_WITH_BOUND_WINDOWS,
	  "SXE2_AE_AMP_INVALIDATE_MR_WITH_BOUND_WINDOWS", 0,
	  "Attempt to invalidate MR with a bound Memory Window (MW)" },
	{ SXE2_AE_AMP_MWBIND_VALID_STAG, "SXE2_AE_AMP_MWBIND_VALID_STAG", 0,
	  "Attempt to bind an Memory Window (MW) with a valid MW memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_MWBIND_OF_MR_STAG, "SXE2_AE_AMP_MWBIND_OF_MR_STAG", 0,
	  "Attempt to bind an Memory Window (MW) with an MR memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_MWBIND_TO_ZERO_BASED_STAG,
	  "SXE2_AE_AMP_MWBIND_TO_ZERO_BASED_STAG", 0,
	  "Attempt to bind an Memory Window (MW) to a zero based MR" },
	{ SXE2_AE_AMP_MWBIND_TO_MW_STAG, "SXE2_AE_AMP_MWBIND_TO_MW_STAG", 0,
	  "Attempt to bind an Memory Window (MW) using MW memory key\n"
	  "\t(L-Key/R-Key) instead of MR memory key (L-Key/R-Key)" },
	{ SXE2_AE_AMP_MWBIND_INVALID_RIGHTS,
	  "SXE2_AE_AMP_MWBIND_INVALID_RIGHTS", 0,
	  "Memory Window (MW) bind error: Invalid rights" },
	{ SXE2_AE_AMP_MWBIND_INVALID_BOUNDS,
	  "SXE2_AE_AMP_MWBIND_INVALID_BOUNDS", 0,
	  "Memory Window (MW) bind error: Invalid bounds" },
	{ SXE2_AE_AMP_MWBIND_TO_INVALID_PARENT,
	  "SXE2_AE_AMP_MWBIND_TO_INVALID_PARENT", 0,
	  "Memory Window (MW) bind error: Invalid parent MR" },
	{ SXE2_AE_AMP_MWBIND_BIND_DISABLED, "SXE2_AE_AMP_MWBIND_BIND_DISABLED",
	  0, "Memory Window (MW) bind error: Disabled bind support" },
	{ SXE2_AE_AMP_INVALIDATE_TYPE1_MW, "SXE2_AE_AMP_INVALIDATE_TYPE1_MW", 0,
	  "Memory Window (MW) error: Invalidate type 1 MW" },
	{ SXE2_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW,
	  "SXE2_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW", 0,
	  "Memory Window (MW) bind error: Zero-based addressing for type 1 MW" },
	{ SXE2_AE_AMP_MWBIND_WRONG_TYPE, "SXE2_AE_AMP_MWBIND_WRONG_TYPE", 0,
	  "MB bind error: Wrong Memory Window (MW) type" },
	{ SXE2_AE_AMP_FASTREG_PBLE_MISMATCH,
	  "SXE2_AE_AMP_FASTREG_PBLE_MISMATCH", 0,
	  "Fastreg error: Invalid request to change physical MR to virtual or vice versa" },
	{ SXE2_AE_CQ_OPERATION_ERROR, "SXE2_AE_CQ_OPERATION_ERROR", 0,
	  "CQ overflow" },
	{ SXE2_AE_LLP_TOO_MANY_RETRIES, "SXE2_AE_LLP_TOO_MANY_RETRIES", 0,
	  "Connection error: The max number of retries has been reached" },
	{ SXE2_AE_QP_SUSPEND_COMPLETE, "SXE2_AE_QP_SUSPEND_COMPLETE", 0,
	  "QP event: Suspend complete" },
	{ SXE2_AE_LLWQE_ERR, "SXE2_AE_LLWQE_ERR", 0,
	  "DB_PROC error: The LLWQE received data less than 8B." },
	{ SXE2_AE_DOORBELL_ERR, "SXE2_AE_DOORBELL_ERR", 0,
	  "DB_PROC error: The DB received data less than 4B." },
	{ SXE2_AE_LLWQE_8B_INVALID, "SXE2_AE_LLWQE_8B_INVALID", 0,
	  "DB_PROC error: The LLWQE received data invalid, not aligned with 8B." },
	{ SXE2_AE_DOORBELL_QSET_ERR, "SXE2_AE_DOORBELL_QSET_ERR", 0,
	  "DB_PROC error: The FID was not assigned Qset." },
	{ SXE2_AE_DOORBELL_QPN_ERR, "SXE2_AE_DOORBELL_QPN_ERR", 0,
	  "DB_PROC error: QPN is not in FID." },
	{ SXE2_AE_DOORBELL_EQN_ERR, "SXE2_AE_DOORBELL_EQN_ERR", 0,
	  "DB_PROC error: EQN is not in FID." },
	{ SXE2_AE_DOORBELL_CQN_ERR, "SXE2_AE_DOORBELL_CQN_ERR", 0,
	  "DB_PROC error: CQN is not in FID." },
	{ SXE2_AE_DOORBELL_QPN_NUM_ERR, "SXE2_AE_DOORBELL_QPN_NUM_ERR", 0,
	  "DB_PROC error: QPN conversion successful, but absolute QPN=0." },
	{ SXE2_AE_WQE_LOAD_QPC_PBL_ERR, "SXE2_AE_WQE_LOAD_QPC_PBL_ERR", 0,
	  "Load qpc PBL err." },
	{ SXE2_AE_WQE_LOAD_QPC_DMA_ERR, "SXE2_AE_WQE_LOAD_QPC_DMA_ERR", 0,
	  "Load qpc DMA err." },
	{ SXE2_AE_WQE_QPC_CFG_ERR, "SXE2_AE_WQE_QPC_CFG_ERR", 0,
	  "QP error: QPC cfg err." },
	{ SXE2_AE_WQE_RD_DMA_ERR, "SXE2_AE_WQE_RD_DMA_ERR", 0,
	  "QP error: DMA arb err." },
	{ SXE2_AE_WQE_CFG_ERR, "SXE2_AE_WQE_CFG_ERR", 0,
	  "QP error: WQE info check err." },
	{ SXE2_AE_WQE_OPCODE_ERR, "SXE2_AE_WQE_OPCODE_ERR", 0,
	  "QP error: WQE opcode verification failed." },
	{ SXE2_AE_WQE_LENGTH_ERR, "SXE2_AE_WQE_LENGTH_ERR", 0,
	  "QP error: WQE length err." },
	{ SXE2_AE_WQE_LLWQE_ERR, "SXE2_AE_WQE_LLWQE_ERR", 0,
	  "QP error: WQE read err." },
	{ SXE2_AE_WQE_RD_RESP_DMA_ERR, "SXE2_AE_WQE_RD_RESP_DMA_ERR", 0,
	  "Read response err." },
	{ SXE2_AE_WQE_RD_AH_ERR, "SXE2_AE_WQE_RD_AH_ERR", 0,
	  "QP error: Read AH DMA err." },
	{ SXE2_AE_WQE_AH_CFG_ERR, "SXE2_AE_WQE_AH_CFG_ERR", 0,
	  "QP error: Read AH info err." },
	{ SXE2_AE_WQE_PBL_DMA_ERR, "SXE2_AE_WQE_PBL_DMA_ERR", 0,
	  "pbl dma err." },
	{ SXE2_AE_RXENG_RXT_OPCODE_ERR, "SXE2_AE_RXENG_RXT_OPCODE_ERR", 0,
	  "QP error: RXT opcode err." },
	{ SXE2_AE_RXENG_RXT_LENGTH_ERR, "SXE2_AE_RXENG_RXT_LENGTH_ERR", 0,
	  "QP error: RXT pkg length err." },
	{ SXE2_AE_RXENG_RXT_RDMA_READ_OUTSTANDING_ERR,
	  "SXE2_AE_RXENG_RXT_RDMA_READ_OUTSTANDING_ERR", 0,
	  "QP error: RXT outstanding err." },
	{ SXE2_AE_RXENG_RXI_BAD_RESPONSE, "SXE2_AE_RXENG_RXI_BAD_RESPONSE", 0,
	  "QP error: RXI bad response." },
	{ SXE2_AE_RXENG_RXI_LENGTH_ERR, "SXE2_AE_RXENG_RXI_LENGTH_ERR", 0,
	  "QP error: RXI length err." },
	{ SXE2_AE_RXENG_RXI_IRRL_DMA_ERR, "SXE2_AE_RXENG_RXI_IRRL_DMA_ERR", 0,
	  "QP error: RXI irrl dma err." },
	{ SXE2_AE_RXENG_RXT_RESP_WR_PADDR_ERR,
	  "SXE2_AE_RXENG_RXT_RESP_WR_PADDR_ERR", 0,
	  "QP error: RXT resp wr paddr err." },
	{ SXE2_AE_RXENG_RXT_RESP_RD_DMA_ERR,
	  "SXE2_AE_RXENG_RXT_RESP_RD_DMA_ERR", 0,
	  "QP error: RXT resp rd dma err." },
	{ SXE2_AE_RXENG_RXI_SSNT_OVERSIZE_ERR,
	  "SXE2_AE_RXENG_RXI_SSNT_OVERSIZE_ERR", 0,
	  "QP error: RXI ssnt oversize err." },
	{ SXE2_AE_RXENG_RXI_SSNT_DMA_ERR, "SXE2_AE_RXENG_RXI_SSNT_DMA_ERR", 0,
	  "QP error: RXI ssnt dma err." },
	{ SXE2_AE_RXENG_RXT_RQE_LIMIT, "SXE2_AE_RXENG_RXT_RQE_LIMIT", 0,
	  "RQE num reaches watermark." },
	{ SXE2_AE_RXENG_RX_LOAD_QPC_DMA_ERR,
	  "SXE2_AE_RXENG_RX_LOAD_QPC_DMA_ERR", 0, "QPC load DMA err." },
	{ SXE2_AE_RXENG_RX_LOAD_QPC_PA_ERR, "SXE2_AE_RXENG_RX_LOAD_QPC_PA_ERR",
	  0, "QPC load PA err." },
	{ SXE2_AE_RXENG_RX_LOAD_SRQC_DMA_ERR,
	  "SXE2_AE_RXENG_RX_LOAD_SRQC_DMA_ERR", 0, "SRQC load DMA err." },
	{ SXE2_AE_RXENG_RX_LOAD_SRQC_PA_ERR,
	  "SXE2_AE_RXENG_RX_LOAD_SRQC_PA_ERR", 0, "SRQC load PA err." },
	{ SXE2_AE_RXENG_RQ_PI_DMA_ERR, "SXE2_AE_RXENG_RQ_PI_DMA_ERR", 0,
	  "QP error: DMA timeout to get srq/rp PI pointer." },
	{ SXE2_AE_RXENG_RQ_ADDR_ERR, "SXE2_AE_RXENG_RQ_ADDR_ERR", 0,
	  "QP error: FPT, get srq/rq page table addr err." },
	{ SXE2_AE_RXENG_RQ_DMA_ERR, "SXE2_AE_RXENG_RQ_DMA_ERR", 0,
	  "QP error: DMA timeout or ECC err to get srqe/rqe." },
	{ SXE2_AE_RXENG_RQ_WQE_VLD_ERR, "SXE2_AE_RXENG_RQ_WQE_VLD_ERR", 0,
	  "QP error: Get srqe/rqe err, wqe_valid != qpc valid." },
	{ SXE2_AE_RXENG_SRQC_STS_ERR, "SXE2_AE_RXENG_SRQC_STS_ERR", 0,
	  "QP error: Get srqc err : return reserved." },
	{ SXE2_AE_RXENG_SRQC_STS_RSV, "SXE2_AE_RXENG_SRQC_STS_RSV", 0,
	  "QP error: Get srqc state err." },
	{ SXE2_AE_RXENG_SRQ_LAST_WQE, "SXE2_AE_RXENG_SRQ_LAST_WQE", 0,
	  "SRQ: srq qp modify error complete." },
	{ SXE2_AE_RXENG_DBR_VALUE_ERR, "SXE2_AE_RXENG_DBR_VALUE_ERR", 0,
	  "QP error: |PI - CI| more than SIZE ." },
	{ SXE2_AE_RXENG_RTR_FIRST_PKT, "SXE2_AE_RXENG_RTR_FIRST_PKT", 0,
	  "QP: Get the first valid data at RTR state." },
	{ SXE2_AE_SRQC_LOAD_SRQC_DMA_ERR, "SXE2_AE_SRQC_LOAD_SRQC_DMA_ERR", 0,
	  "SRQ: Load srq DMA read err." },
	{ SXE2_AE_SRQC_LOAD_SRQC_PA_ERR, "SXE2_AE_SRQC_LOAD_SRQC_PA_ERR", 0,
	  "SRQ：Load srq PA err." },
	{ SXE2_AE_SRQC_STS_ERR, "SXE2_AE_SRQC_STS_ERR", 0,
	  "SRQ: srq state err." },
	{ SXE2_AE_RXENG_REMOTE_INVALID_ERROR,
	  "SXE2_AE_RXENG_REMOTE_INVALID_ERROR", 0,
	  "QP: Remote invalid request err." },
	{ SXE2_AE_RXENG_REMOTE_ACCESS_ERROR,
	  "SXE2_AE_RXENG_REMOTE_ACCESS_ERROR", 0, "QP: Remote access err." },
	{ SXE2_AE_RXENG_REMOTE_QP_ERROR, "SXE2_AE_RXENG_REMOTE_QP_ERROR", 0,
	  "QP: Remote operation err." },
	{ SXE2_AE_RXENG_RXI_WQE_MISMATCH, "SXE2_AE_RXENG_RXI_WQE_MISMATCH", 0,
	  "QP: psn not match msn." },
	{ SXE2_AE_TXENG_PAYLOAD_RD_DMA_ERR, "SXE2_AE_TXENG_PAYLOAD_RD_DMA_ERR",
	  0, "QP error: The sq request pcie data err: dma err." },
	{ SXE2_AE_TXENG_RD_PKEY_ERR, "SXE2_AE_TXENG_RD_PKEY_ERR", 0,
	  "QP error: PHG get pkey err." },
	{ SXE2_AE_TXENG_RD_SSNT_PBL_ERR, "SXE2_AE_TXENG_RD_SSNT_PBL_ERR", 0,
	  "QP error: Get SSNT PA err." },
	{ SXE2_AE_TXENG_RD_IRRL_PBL_ERR, "SXE2_AE_TXENG_RD_IRRL_PBL_ERR", 0,
	  "QP error: Get IRRL PA err." },
	{ SXE2_AE_TXENG_RESP_PAYLOAD_RD_DMA_ERR,
	  "SXE2_AE_TXENG_RESP_PAYLOAD_RD_DMA_ERR", 0,
	  "QP error: RDMA read resp request pcie data err: dma err." },
	{ SXE2_AE_TMO_WR_PA_ERR, "SXE2_AE_TMO_WR_PA_ERR", 0,
	  "TimeOut queue's write PA err: DMA FPT ERR." },
	{ SXE2_AE_TMO_RD_PA_ERR, "SXE2_AE_TMO_RD_PA_ERR", 0,
	  "TimeOut queue's read PA err: DMA FPT ERR." },
	{ SXE2_AE_TMO_RD_DMA_ERR, "SXE2_AE_TMO_RD_DMA_ERR", 0,
	  "Read host memory err: DMA err." },
	{ SXE2_AE_TMO_RD_QPC_ERR, "SXE2_AE_TMO_RD_QPC_ERR", 0,
	  "TimeOut queue read QPC err." },
	{ SXE2_AE_CC_QP_RATE, "SXE2_AE_CC_QP_RATE", 0,
	  "The flow of QP is reduced to the minimum rate through congestion control." },
	{ SXE2_AE_CEQ_OVERFLOW, "SXE2_AE_CEQ_OVERFLOW", 0, "CEQ overflow." },
	{ SXE2_AE_EQ_STATUS_ERR, "SXE2_AE_EQ_STATUS_ERR", 0,
	  "CEQ access err." },
	{ SXE2_AE_CQ_STATUS_ERR, "SXE2_AE_CQ_STATUS_ERR", 0, "CQ access err." },
	{ SXE2_AE_QP_CQ_OVERFLOW, "SXE2_AE_QP_CQ_OVERFLOW", 0,
	  "The QP's CQE causes CQ overflows." },
};

const char *sxe2_get_ae_desc(u16 ae_code)
{
	const char *desc = "";
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ae_desc_list); i++) {
		if (ae_desc_list[i].id == ae_code) {
			desc = ae_desc_list[i].desc;
			break;
		}
	}
	return desc;
}

void sxe2_set_ae_count(u16 ae_code)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ae_desc_list); i++) {
		if (ae_desc_list[i].id == ae_code) {
			ae_desc_list[i].count++;
			break;
		}
	}
}

struct sxe2_ae_desc *sxe2_get_ae_desc_list(void)
{
	return ae_desc_list;
}

int sxe2_get_ae_desc_list_size(void)
{
	return ARRAY_SIZE(ae_desc_list);
}

static void sxe2_set_flush_fields(struct sxe2_rdma_ctx_qp *qp_ctx,
				  struct sxe2_aeqe_info *info)
{
	enum sxe2_qp_event_type qp_event;

	switch (info->ae_code) {
	case SXE2_AE_AMP_UNALLOCATED_STAG:
	case SXE2_AE_AMP_INVALID_STAG:
	case SXE2_AE_AMP_BAD_QP:
	case SXE2_AE_AMP_BAD_PD:
	case SXE2_AE_AMP_BAD_STAG_KEY:
	case SXE2_AE_AMP_BAD_STAG_INDEX:
	case SXE2_AE_AMP_BOUNDS_VIOLATION:
	case SXE2_AE_AMP_RIGHTS_VIOLATION:
	case SXE2_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS:
	case SXE2_AE_AMP_MWBIND_INVALID_RIGHTS:
	case SXE2_AE_AMP_MWBIND_BIND_DISABLED:
	case SXE2_AE_AMP_MWBIND_INVALID_BOUNDS:
	case SXE2_AE_AMP_MWBIND_VALID_STAG:
	case SXE2_AE_RXENG_RXT_RESP_WR_PADDR_ERR:
	case SXE2_AE_RXENG_RXT_RESP_RD_DMA_ERR:
		qp_event = SXE2_QP_EVENT_ACCESS_ERR;
		break;
	case SXE2_AE_RXENG_RXT_OPCODE_ERR:
	case SXE2_AE_RXENG_RXT_LENGTH_ERR:
	case SXE2_AE_RXENG_RXT_RDMA_READ_OUTSTANDING_ERR:
		qp_event = SXE2_QP_EVENT_REQ_ERR;
		break;
	case SXE2_AE_RXENG_RTR_FIRST_PKT:
		qp_event = SXE2_QP_EVENT_COMM_EST;
		break;
	case SXE2_AE_RXENG_SRQ_LAST_WQE:
		qp_event = SXE2_QP_EVENT_QP_LASTWQE_REACHED;
		break;
	default:
		qp_event = SXE2_QP_EVENT_CATASTROPHIC;
		break;
	}

	qp_ctx->event_type = qp_event;
}

static int sxe2_get_next_aeqe(struct sxe2_rdma_ctx_aeq *aeq,
			      struct sxe2_aeqe_info *info)
{
	u64 temp, compl_ctx;
	__le64 *aeqe;
	u8 ae_src;
	u8 polarity;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(aeq->dev);

	if (rdma_dev->cache_line_64_en == false)
		aeqe = SXE2_GET_CURRENT_AEQ_ELEM(aeq);
	else
		aeqe = SXE2_GET_CURRENT_AEQ_ELEM_HYGON(aeq);

	get_64bit_val(aeqe, 8, &temp);
	DRV_RDMA_LOG_DEV_DEBUG("aeq:tail %#x, aeqe_8 %#llx\n",
			       SXE2_RING_CURRENT_TAIL((aeq)->aeq_ring), temp);
	polarity = (u8)FIELD_GET(SXE2_AEQE_VALID, temp);
	DRV_RDMA_LOG_DEV_DEBUG("aeq valid:%d aeq->polarity:%d.\n", polarity,
			       aeq->polarity);

	if (aeq->polarity != polarity)
		return -ENOENT;

	dma_rmb();

	get_64bit_val(aeqe, 0, &compl_ctx);

	ae_src		    = (u8)FIELD_GET(SXE2_AEQE_AESRC, temp);
	info->wqe_idx	    = (u16)FIELD_GET(SXE2_AEQE_WQDESCIDX, temp);
	info->qp_cq_id	    = (u32)FIELD_GET(SXE2_AEQE_QPCQID_L, temp);
	info->ae_code	    = (u16)FIELD_GET(SXE2_AEQE_AECODE, temp);
	info->rdma_state    = (u8)FIELD_GET(SXE2_AEQE_RDMA_STATE, temp);
	info->aeqe_overflow = (bool)FIELD_GET(SXE2_AEQE_OVERFLOW, temp);
	info->ae_source	    = ae_src;

	switch (ae_src) {
	case SXE2_AE_SOURCE_RQ:
		info->qp	       = true;
		info->rq	       = true;
		info->err_rq_idx_valid = true;
		info->compl_ctx	       = compl_ctx;
		break;
	case SXE2_AE_SOURCE_CQ:
		info->cq	= true;
		info->compl_ctx = LS_64_1(compl_ctx, 1);
		break;
	case SXE2_AE_SOURCE_SQ:
		info->qp	= true;
		info->sq	= true;
		info->compl_ctx = compl_ctx;
		break;
	case SXE2_AE_SOURCE_SRQ:
		info->srq	= true;
		info->compl_ctx = compl_ctx;
		break;
	case SXE2_AE_SOURCE_TMO:
		info->tmo = true;
		if ((info->ae_code == SXE2_AE_TMO_RD_DMA_ERR) ||
		    (info->ae_code == SXE2_AE_TMO_RD_QPC_ERR))
			info->qp = true;
		break;
	case SXE2_AE_SOURCE_CC:
		info->cc = true;
		break;
	case SXE2_AE_SOURCE_DB_PROC:
		info->db = true;
		break;
	case SXE2_AE_SOURCE_RSVD:
	default:
		break;
	}

	SXE2_RING_MOVE_TAIL(aeq->aeq_ring);
	aeq->cons_index = SXE2_RING_CURRENT_TAIL(aeq->aeq_ring);
	if (!SXE2_RING_CURRENT_TAIL(aeq->aeq_ring))
		aeq->polarity ^= 1;

	return 0;
}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
static void sxe2_process_aeq_err_inject_noupdate_ci(
			struct sxe2_rdma_device *rdma_dev,
			struct sxe2_rdma_ctx_aeq *ctx_aeq)
{
	if (rdma_dev->rdma_func->inject_aeq.aeq_ci_noupdate ==
			 SXE2_INJECT_EQ_AEQ_VALUE) {
		DRV_RDMA_LOG_DEBUG_BDF("inject aeq ci no update err.\n");
	} else {
		sxe2_eq_update_ci(ctx_aeq->doorbell, ctx_aeq->cons_index, 0);
		DRV_RDMA_LOG_DEBUG_BDF("aeq process update ci:%u.\n", ctx_aeq->cons_index);
	}
}
#endif
static void sxe2_process_aeq(struct sxe2_rdma_pci_f *rf)
{
	struct sxe2_rdma_aeq *aeq	  = &rf->aeq;
	struct sxe2_rdma_ctx_aeq *ctx_aeq = &aeq->ctx_aeq;
	struct sxe2_aeqe_info aeinfo;
	struct sxe2_aeqe_info *info	  = &aeinfo;
	struct sxe2_rdma_cq *cq		  = NULL;
	struct sxe2_rdma_qp *qp		  = NULL;
	struct sxe2_rdma_srq *srq	  = NULL;
	struct sxe2_rdma_device *rdma_dev = rf->rdma_dev;
	unsigned long flags		  = 0;
	int ret;
	u32 aeqcnt		    = 0;
	struct ib_event srq_ibevent = {};

	if (!ctx_aeq->size)
		return;
	DRV_RDMA_LOG_DEV_DEBUG("aeq process start.\n");

	do {
		memset(info, 0, sizeof(*info));
		ret = sxe2_get_next_aeqe(ctx_aeq, info);
		if (ret) {
			DRV_RDMA_LOG_DEV_DEBUG("aeq process end.\n");
			break;
		}

		if (info->aeqe_overflow) {
			DRV_RDMA_LOG_DEV_DEBUG("AEQ has overflowed\n");
			if (!rf->reset) {
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
			return;
		}

		++aeqcnt;
		DRV_RDMA_LOG_DEV_DEBUG(
			"AEQ: ae_id = 0x%x (%s), is_qp = %d,\n"
			"\tcq_qp_id = %u, rdma_state = %d, ae_src = %d\n",
			info->ae_code, sxe2_get_ae_desc(info->ae_code),
			info->qp, info->qp_cq_id, info->rdma_state,
			info->ae_source);

#ifdef SXE2_CFG_DEBUG
		sxe2_set_ae_count(info->ae_code);
#endif

		switch (info->ae_code) {
		case SXE2_AE_CQ_OPERATION_ERROR:
		case SXE2_AE_CQ_STATUS_ERR:
			DRV_RDMA_LOG_DEV_DEBUG(
				"Processing CQ[0x%x] op error, AE 0x%04X\n",
				info->qp_cq_id, info->ae_code);

			if (info->qp_cq_id > rf->max_cq) {
				DRV_RDMA_LOG_DEV_ERR(
					"AEQ: cq_id %u invalid, max_cq:%u\n",
					info->qp_cq_id, rf->max_cq);
				break;
			}

			if (info->qp_cq_id != 0) {
				spin_lock_irqsave(&rf->cqtable_lock, flags);
				cq = rf->cq_table[info->qp_cq_id];
				if (!cq) {
					spin_unlock_irqrestore(
						&rf->cqtable_lock, flags);
					DRV_RDMA_LOG_DEV_DEBUG(
						"AEQ: cq_id %u is already freed\n",
						info->qp_cq_id);
					continue;
				}
				sxe2_drv_cq_add_ref(cq);
				spin_unlock_irqrestore(&rf->cqtable_lock,
						       flags);

				if (cq->ibcq.event_handler) {
					struct ib_event ibevent;

					ibevent.device	   = cq->ibcq.device;
					ibevent.event	   = IB_EVENT_CQ_ERR;
					ibevent.element.cq = &cq->ibcq;
					cq->ibcq.event_handler(
						&ibevent, cq->ibcq.cq_context);
				}
				sxe2_drv_cq_rem_ref(cq);
			}

			if ((info->qp_cq_id == 0) ||
			    (info->ae_code == SXE2_AE_CQ_STATUS_ERR)) {
				if (!rf->reset) {
					DRV_RDMA_LOG_DEV_ERR(
						"Request Reset, cq err\n");
					rf->reset = true;
					rf->gen_ops.request_reset(rf);
				}
			}
			break;
		case SXE2_AE_LLWQE_ERR:
		case SXE2_AE_DOORBELL_ERR:
		case SXE2_AE_LLWQE_8B_INVALID:
		case SXE2_AE_DOORBELL_QSET_ERR:
		case SXE2_AE_DOORBELL_QPN_ERR:
		case SXE2_AE_DOORBELL_EQN_ERR:
		case SXE2_AE_DOORBELL_CQN_ERR:
		case SXE2_AE_DOORBELL_QPN_NUM_ERR:
			DRV_RDMA_LOG_DEV_WARN("AEQ: DB PROC ae_id:0x%x (%s)\n",
					      info->ae_code,
					      sxe2_get_ae_desc(info->ae_code));
			break;
		case SXE2_AE_CC_QP_RATE:
			DRV_RDMA_LOG_DEV_WARN("AEQ: CC ae_id:0x%x (%s)\n",
					      info->ae_code,
					      sxe2_get_ae_desc(info->ae_code));
			break;
		case SXE2_AE_RXENG_RXT_RQE_LIMIT:
			if ((info->qp_cq_id <
			     rf->ctx_dev.hw_attrs.min_hw_srq_id) ||
			    (info->qp_cq_id >
			     (rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ]
				      .cnt -
			      1))) {
				DRV_RDMA_LOG_DEV_ERR(
					"srqn err, SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
				continue;
			}
			spin_lock_irqsave(&rf->srqtable_lock, flags);
			srq = rf->srq_table[info->qp_cq_id];
			if (!srq) {
				spin_unlock_irqrestore(&rf->srqtable_lock,
						       flags);
				DRV_RDMA_LOG_DEV_ERR(
					"AEQ: srq_id %d is already freed\n",
					info->qp_cq_id);
				continue;
			}
			sxe2_kadd_srq_ref(&srq->ibsrq);
			spin_unlock_irqrestore(&rf->srqtable_lock, flags);
			srq->srq_ctx.srq_limit = 0;
			if (srq->ibsrq.event_handler) {
				DRV_RDMA_LOG_DEV_DEBUG(
					"Processing SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
				srq_ibevent.device = srq->ibsrq.device;
				srq_ibevent.element.port_num = 1;
				srq_ibevent.element.srq	     = &srq->ibsrq;
				srq_ibevent.event = IB_EVENT_SRQ_LIMIT_REACHED;
				srq->ibsrq.event_handler(
					&srq_ibevent, srq->ibsrq.srq_context);
			} else {
				DRV_RDMA_LOG_DEV_ERR(
					"handle err, Processing SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
			}
			sxe2_krem_srq_ref(&srq->ibsrq);
			break;
		case SXE2_AE_SRQC_LOAD_SRQC_DMA_ERR:
		case SXE2_AE_SRQC_LOAD_SRQC_PA_ERR:
		case SXE2_AE_SRQC_STS_ERR:
			if ((info->qp_cq_id <
			     rf->ctx_dev.hw_attrs.min_hw_srq_id) ||
			    (info->qp_cq_id >
			     (rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ]
				      .cnt -
			      1))) {
				DRV_RDMA_LOG_DEV_ERR(
					"srqn err, SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
				continue;
			}
			spin_lock_irqsave(&rf->srqtable_lock, flags);
			srq = rf->srq_table[info->qp_cq_id];
			if (!srq) {
				spin_unlock_irqrestore(&rf->srqtable_lock,
						       flags);
				DRV_RDMA_LOG_DEV_ERR(
					"AEQ: srq_id %d is already freed\n",
					info->qp_cq_id);
				continue;
			}
			sxe2_kadd_srq_ref(&srq->ibsrq);
			spin_unlock_irqrestore(&rf->srqtable_lock, flags);
			if (srq->ibsrq.event_handler) {
				DRV_RDMA_LOG_DEV_DEBUG(
					"Processing SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
				srq_ibevent.device	= srq->ibsrq.device;
				srq_ibevent.element.srq = &srq->ibsrq;
				srq_ibevent.event	= IB_EVENT_SRQ_ERR;
				srq->ibsrq.event_handler(
					&srq_ibevent, srq->ibsrq.srq_context);
			} else {
				DRV_RDMA_LOG_DEV_ERR(
					"handle err, Processing SRQ[0x%x] op error, AE 0x%04X\n",
					info->qp_cq_id, info->ae_code);
			}
			sxe2_krem_srq_ref(&srq->ibsrq);
			if (!rf->reset) {
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
			break;
		case SXE2_AE_RXENG_SRQ_LAST_WQE:
			DRV_RDMA_LOG_DEV_WARN(
				"qp modify to err state finish\n");
			if ((info->qp) && (info->qp_cq_id > 0) &&
			    (info->qp_cq_id < rf->max_qp)) {
				spin_lock_irqsave(&rf->qptable_lock, flags);
				qp = rf->qp_table[info->qp_cq_id];
				if (!qp) {
					spin_unlock_irqrestore(
						&rf->qptable_lock, flags);
					DRV_RDMA_LOG_DEV_DEBUG(
						"AEQ: qp_id %u is already freed\n",
						info->qp_cq_id);
					continue;
				}

				sxe2_qp_add_ref(&qp->ibqp);
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);

				sxe2_set_flush_fields(&qp->qp_ctx, info);
				sxe2_ib_qp_event(qp, qp->qp_ctx.event_type);
				sxe2_qp_rem_ref(&qp->ibqp);
			}
			break;
		case SXE2_AE_WQE_LOAD_QPC_PBL_ERR:
		case SXE2_AE_WQE_LOAD_QPC_DMA_ERR:
		case SXE2_AE_RXENG_RX_LOAD_QPC_DMA_ERR:
		case SXE2_AE_RXENG_RX_LOAD_QPC_PA_ERR:
		case SXE2_AE_RXENG_SRQC_STS_ERR:
		case SXE2_AE_RXENG_SRQC_STS_RSV:
		case SXE2_AE_TMO_WR_PA_ERR:
		case SXE2_AE_TMO_RD_PA_ERR:
		case SXE2_AE_TMO_RD_DMA_ERR:
		case SXE2_AE_CEQ_OVERFLOW:
		case SXE2_AE_EQ_STATUS_ERR:
			if (!rf->reset) {
				DRV_RDMA_LOG_DEV_WARN("aeq request reset.\n");
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
			break;
		case SXE2_AE_RXENG_RQ_PI_DMA_ERR:
		case SXE2_AE_RXENG_RQ_ADDR_ERR:
		case SXE2_AE_RXENG_RQ_DMA_ERR:
		case SXE2_AE_RXENG_RX_LOAD_SRQC_DMA_ERR:
		case SXE2_AE_RXENG_RX_LOAD_SRQC_PA_ERR:
			if ((info->qp) && (info->qp_cq_id > 0) &&
			    (info->qp_cq_id < rf->max_qp)) {
				spin_lock_irqsave(&rf->qptable_lock, flags);
				qp = rf->qp_table[info->qp_cq_id];
				if (!qp) {
					spin_unlock_irqrestore(
						&rf->qptable_lock, flags);
					DRV_RDMA_LOG_DEV_DEBUG(
						"AEQ: qp_id %u is already freed\n",
						info->qp_cq_id);
					continue;
				}

				sxe2_qp_add_ref(&qp->ibqp);
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);

				sxe2_set_flush_fields(&qp->qp_ctx, info);
				sxe2_ib_qp_event(qp, qp->qp_ctx.event_type);
				sxe2_qp_rem_ref(&qp->ibqp);
			}

			if (!rf->reset) {
				DRV_RDMA_LOG_DEV_WARN("aeq request reset.\n");
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
			break;
		case SXE2_AE_QP_SUSPEND_COMPLETE:
			DRV_RDMA_LOG_WARN_BDF("qp:%u modify to SQD finish.\n",
					      info->qp_cq_id);

			if (info->qp_cq_id > rf->max_qp) {
				DRV_RDMA_LOG_DEV_ERR(
					"AEQ: qp_id %u invalid, max_qp:%u\n",
					info->qp_cq_id, rf->max_qp);
				break;
			}

			spin_lock_irqsave(&rf->qptable_lock, flags);
			qp = rf->qp_table[info->qp_cq_id];
			if (!qp) {
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);

				if (!rdma_dev->vsi.tc_change_pending)
					continue;

				atomic_dec(&rdma_dev->vsi.qp_suspend_reqs);
				wake_up(&rdma_dev->suspend_wq);

				DRV_RDMA_LOG_DEV_DEBUG(
					"AEQ: qp_id %u is already freed\n",
					info->qp_cq_id);
				break;
			}

			sxe2_qp_add_ref(&qp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);

			if (rdma_dev->vsi.tc_change_pending) {
				if (!atomic_dec_return(
					    &rdma_dev->vsi.qp_suspend_reqs))
					wake_up(&rdma_dev->suspend_wq);
			}

			if (qp->suspend_pending) {
				qp->suspend_pending = false;
				wake_up(&qp->dev->suspend_wq);
			}

			sxe2_qp_rem_ref(&qp->ibqp);
			break;
		case SXE2_AE_AMP_UNALLOCATED_STAG:
		case SXE2_AE_AMP_INVALID_STAG:
		case SXE2_AE_AMP_BAD_QP:
		case SXE2_AE_AMP_BAD_PD:
		case SXE2_AE_AMP_BAD_STAG_KEY:
		case SXE2_AE_AMP_BAD_STAG_INDEX:
		case SXE2_AE_AMP_BOUNDS_VIOLATION:
		case SXE2_AE_AMP_RIGHTS_VIOLATION:
		case SXE2_AE_AMP_FASTREG_VALID_STAG:
		case SXE2_AE_AMP_FASTREG_MW_STAG:
		case SXE2_AE_AMP_FASTREG_INVALID_RIGHTS:
		case SXE2_AE_AMP_FASTREG_INVALID_LENGTH:
		case SXE2_AE_AMP_REMOTE_INVALIDATE_MR_RD_ERR:
		case SXE2_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS:
		case SXE2_AE_AMP_INVALIDATE_MR_WITH_BOUND_WINDOWS:
		case SXE2_AE_AMP_MWBIND_VALID_STAG:
		case SXE2_AE_AMP_MWBIND_OF_MR_STAG:
		case SXE2_AE_AMP_MWBIND_TO_ZERO_BASED_STAG:
		case SXE2_AE_AMP_MWBIND_TO_MW_STAG:
		case SXE2_AE_AMP_MWBIND_INVALID_RIGHTS:
		case SXE2_AE_AMP_MWBIND_INVALID_BOUNDS:
		case SXE2_AE_AMP_MWBIND_TO_INVALID_PARENT:
		case SXE2_AE_AMP_MWBIND_BIND_DISABLED:
		case SXE2_AE_AMP_INVALIDATE_TYPE1_MW:
		case SXE2_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW:
		case SXE2_AE_AMP_MWBIND_WRONG_TYPE:
		case SXE2_AE_AMP_FASTREG_PBLE_MISMATCH:
		case SXE2_AE_LLP_TOO_MANY_RETRIES:
		case SXE2_AE_RXENG_RXT_RESP_WR_PADDR_ERR:
		case SXE2_AE_RXENG_RXT_RESP_RD_DMA_ERR:
		case SXE2_AE_WQE_RD_RESP_DMA_ERR:
		case SXE2_AE_TXENG_RESP_PAYLOAD_RD_DMA_ERR:
		case SXE2_AE_TMO_RD_QPC_ERR:
		case SXE2_AE_QP_CQ_OVERFLOW:
		case SXE2_AE_WQE_QPC_CFG_ERR:
		case SXE2_AE_WQE_RD_DMA_ERR:
		case SXE2_AE_WQE_CFG_ERR:
		case SXE2_AE_WQE_OPCODE_ERR:
		case SXE2_AE_WQE_LENGTH_ERR:
		case SXE2_AE_WQE_LLWQE_ERR:
		case SXE2_AE_WQE_RD_AH_ERR:
		case SXE2_AE_WQE_AH_CFG_ERR:
		case SXE2_AE_WQE_PBL_DMA_ERR:
		case SXE2_AE_RXENG_RXT_OPCODE_ERR:
		case SXE2_AE_RXENG_RXT_LENGTH_ERR:
		case SXE2_AE_RXENG_RXT_RDMA_READ_OUTSTANDING_ERR:
		case SXE2_AE_RXENG_RXI_BAD_RESPONSE:
		case SXE2_AE_RXENG_RXI_LENGTH_ERR:
		case SXE2_AE_RXENG_RXI_IRRL_DMA_ERR:
		case SXE2_AE_RXENG_RXI_SSNT_OVERSIZE_ERR:
		case SXE2_AE_RXENG_RXI_SSNT_DMA_ERR:
		case SXE2_AE_RXENG_RQ_WQE_VLD_ERR:
		case SXE2_AE_TXENG_PAYLOAD_RD_DMA_ERR:
		case SXE2_AE_TXENG_RD_PKEY_ERR:
		case SXE2_AE_TXENG_RD_SSNT_PBL_ERR:
		case SXE2_AE_TXENG_RD_IRRL_PBL_ERR:
		case SXE2_AE_RXENG_DBR_VALUE_ERR:
		case SXE2_AE_RXENG_RTR_FIRST_PKT:
		case SXE2_AE_RXENG_REMOTE_INVALID_ERROR:
		case SXE2_AE_RXENG_REMOTE_ACCESS_ERROR:
		case SXE2_AE_RXENG_REMOTE_QP_ERROR:
		case SXE2_AE_RXENG_RXI_WQE_MISMATCH:
			DRV_RDMA_LOG_DEV_WARN(
				"AEQ: abnormal ae_id = 0x%x  , is_qp = %d, qp_id = %u\n",
				info->ae_code, info->qp, info->qp_cq_id);

			if (info->qp_cq_id > rf->max_qp) {
				DRV_RDMA_LOG_DEV_ERR(
					"AEQ: qp_id %u invalid, max_qp:%u\n",
					info->qp_cq_id, rf->max_qp);
				break;
			}

			spin_lock_irqsave(&rf->qptable_lock, flags);
			qp = rf->qp_table[info->qp_cq_id];
			if (!qp) {
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);
				DRV_RDMA_LOG_DEV_DEBUG(
					"AEQ: qp_id %u is already freed\n",
					info->qp_cq_id);
				break;
			}

			sxe2_qp_add_ref(&qp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);

			if ((info->ae_code == SXE2_AE_RXENG_RXT_OPCODE_ERR) ||
			    (info->ae_code == SXE2_AE_RXENG_RXT_LENGTH_ERR)) {
				if (qp->qp_ctx.qp_common.qp_type != IB_QPT_RC) {
					DRV_RDMA_LOG_DEV_INFO(
						"UD type ae_id = 0x%x ignore\n",
						info->ae_code);
					sxe2_qp_rem_ref(&qp->ibqp);
					break;
				}
			}

			sxe2_set_flush_fields(&qp->qp_ctx, info);
			if (info->ae_code == SXE2_AE_RXENG_RTR_FIRST_PKT)
				sxe2_ib_qp_event(qp, qp->qp_ctx.event_type);
			else
				sxe2_cm_disconn(qp);

			sxe2_qp_rem_ref(&qp->ibqp);
			break;
		default:
			break;
		}
	} while (aeqcnt < SXE2_EQ_POLLING_BUDGET);

	if (aeqcnt) {
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
		sxe2_process_aeq_err_inject_noupdate_ci(rdma_dev, ctx_aeq);
#else
		sxe2_eq_update_ci(ctx_aeq->doorbell, ctx_aeq->cons_index, 0);
		DRV_RDMA_LOG_DEV_DEBUG("aeq process update ci:%u.\n",
				       ctx_aeq->cons_index);
#endif
	}
}

#ifndef NO_HAVE_TASKLET_SETUP
static void sxe2_eq_cb(struct tasklet_struct *t)
{
	struct sxe2_rdma_pci_f *rf = from_tasklet(rf, t, dpc_tasklet);

	if (rf->msix_shared)
		sxe2_process_ceq(rf, rf->ceqlist);

	if (!atomic_read(&rf->aeq_created))
		goto end;

	sxe2_process_aeq(rf);

end:
	sxe2_rdma_ena_intr(&rf->ctx_dev, rf->sxe2_msixtbl[0].idx);
}

irqreturn_t sxe2_eq_handler(int irq, void *data)
{
	struct sxe2_rdma_pci_f *rf = data;

	tasklet_schedule(&rf->dpc_tasklet);

	return IRQ_HANDLED;
}

irqreturn_t sxe2_ceq_handler(int irq, void *data)
{
	struct sxe2_rdma_ceq *ceq	  = data;
	struct sxe2_rdma_device *rdma_dev = ceq->rf->rdma_dev;

	if (ceq->irq != irq) {
		DRV_RDMA_LOG_DEV_ERR("expected irq = %d received irq = %d\n",
				     ceq->irq, irq);
	}
	tasklet_schedule(&ceq->dpc_tasklet);

	return IRQ_HANDLED;
}

void sxe2_ceq_cb(struct tasklet_struct *t)
{
	struct sxe2_rdma_ceq *ceq  = from_tasklet(ceq, t, dpc_tasklet);
	struct sxe2_rdma_pci_f *rf = ceq->rf;

	sxe2_process_ceq(rf, ceq);
	sxe2_rdma_ena_intr(&rf->ctx_dev, ceq->msix_idx);
}
#else
static irqreturn_t sxe2_ceq_cb(int irq, void *private)
{
	struct sxe2_rdma_ceq *ceq = private;
	struct sxe2_rdma_pci_f *rf = ceq->rf;

	sxe2_process_ceq(rf, ceq);
	sxe2_rdma_ena_intr(&rf->ctx_dev, ceq->msix_idx);

	return IRQ_HANDLED;
}

static irqreturn_t sxe2_aeq_ceq0_cb(int irq, void *private)
{
	struct sxe2_rdma_pci_f *rf = private;

	if (rf->msix_shared)
		sxe2_process_ceq(rf, rf->ceqlist);

	if (!atomic_read(&rf->aeq_created))
		goto end;

	sxe2_process_aeq(rf);

end:
	sxe2_rdma_ena_intr(&rf->ctx_dev, rf->sxe2_msixtbl[0].idx);

	return IRQ_HANDLED;
}

#endif

static u32 sxe2_get_ceq_abs_id(struct sxe2_rdma_pci_f *rdma_func,
			       u32 ceq_rel_id)
{
	struct sxe2_rdma_ctx_dev *dev	  = NULL;
	struct sxe2_rdma_device *rdma_dev = NULL;
	int fid				  = 0;
	u32 offset			  = 0;
	u32 ceq_abs_id			  = 0;

	rdma_dev = rdma_func->rdma_dev;
	dev	 = &rdma_func->ctx_dev;
	if (dev->privileged) {
		fid = rdma_func->pf_id;
	} else {
		fid	    = dev->rcms_info->pmf_index - SXE2_FIRST_VF_FPM_ID;
		dev->pf_cnt = rdma_func->pf_cnt;
		offset	    = dev->pf_cnt * dev->rcms_info->pf_max_ceqs;
	}
	ceq_abs_id = offset + dev->rcms_info->max_ceqs * fid + ceq_rel_id;
	DRV_RDMA_LOG_DEV_DEBUG(
		"CEQ:ceq_abs_id=%#x, pf_cnt=%#x, pf_max_ceqs=%#x,\n"
		"offset=%#x, max_ceqs=%#x, pf_id=%#x, pmf_index=%#x, fid=%#x, ceq_rel_id=%#x\n",
		ceq_abs_id, dev->pf_cnt, dev->rcms_info->pf_max_ceqs, offset,
		dev->rcms_info->max_ceqs, rdma_func->pf_id,
		dev->rcms_info->pmf_index, fid, ceq_rel_id);

	return ceq_abs_id;
}

static int sxe2_vchnl_cfg_ceq(struct sxe2_rdma_ctx_dev *dev, u32 ceq_id,
			      u32 idx, bool map)
{
	int ret;
	struct sxe2_rdma_pci_f *rdma_func   = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev   = rdma_func->rdma_dev;
	struct aux_core_dev_info *cdev_info = rdma_func->cdev;
	struct aux_qvlist_info *qvl_info;
	struct aux_qv_info *qvinfo;
	u32    qvl_size = 0;

	qvl_size = sizeof(struct aux_qvlist_info) + sizeof(struct aux_qv_info);

	qvl_info = kzalloc(qvl_size, GFP_KERNEL);
	if (!qvl_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"eq: qvl info alloc failed\n");
		ret = -ENOMEM;
		goto end;
	}

	qvinfo = &qvl_info->qv_info[0];

	qvl_info->num_vectors = 1;
	qvinfo->aeq_idx	     = SXE2_Q_INVALID_IDX;
	qvinfo->ceq_idx	     = (u16)ceq_id;
	qvinfo->v_idx	     = idx;
	qvinfo->itr_idx	     = 0;

	DRV_RDMA_LOG_DEV_DEBUG("ceq_id:%#x, v_idx=%#x, map %d\n",
			       qvinfo->ceq_idx, qvinfo->v_idx, map);

	if (!rdma_func->reset) {
		ret = cdev_info->ops->vc_queue_vec_map_unmap(cdev_info,
							     qvl_info, map);
	} else {
		ret = 0;
		DRV_RDMA_LOG_WARN_BDF(
			"ceq map/unmap not processed, need reset\n");
	}

	kfree(qvl_info);
	qvl_info = NULL;

end:
	return ret;
}

static int sxe2_vchnl_cfg_aeq(struct sxe2_rdma_ctx_dev *dev, u32 idx, bool map)
{
	int ret;
	struct sxe2_rdma_pci_f *rdma_func   = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev   = rdma_func->rdma_dev;
	struct aux_core_dev_info *cdev_info = rdma_func->cdev;
	struct aux_qvlist_info *qvl_info;
	struct aux_qv_info *qvinfo;
	u32    qvl_size = 0;

	qvl_size = sizeof(struct aux_qvlist_info) + sizeof(struct aux_qv_info);

	qvl_info = kzalloc(qvl_size, GFP_KERNEL);
	if (!qvl_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"eq: qvl info alloc failed\n");
		ret = -ENOMEM;
		goto end;
	}

	qvinfo = &qvl_info->qv_info[0];

	qvl_info->num_vectors = 1;
	qvinfo->aeq_idx	     = 0;
	qvinfo->ceq_idx	     = SXE2_Q_INVALID_IDX;
	qvinfo->v_idx	     = idx;
	qvinfo->itr_idx	     = 0;

	DRV_RDMA_LOG_DEV_DEBUG("aeq_id:%#x, v_idx=%#x, map %d\n",
			       qvinfo->aeq_idx, qvinfo->v_idx, map);

	if (!rdma_func->reset) {
		ret = cdev_info->ops->vc_queue_vec_map_unmap(cdev_info,
							     qvl_info, map);
		if (ret)
			DRV_RDMA_LOG_WARN_BDF("aeq map/unmap fail, ret %d\n",
					     ret);
	} else {
		ret = 0;
		DRV_RDMA_LOG_WARN_BDF(
			"aeq map/unmap not processed, need reset\n");
	}

	kfree(qvl_info);
	qvl_info = NULL;

end:
	return ret;
}

static void sxe2_destroy_irq(struct sxe2_rdma_pci_f *rf,
			     struct sxe2_rdma_msix_vector *msix_vec,
			     void *dev_id)
{
	struct sxe2_rdma_ctx_dev *dev = &rf->ctx_dev;

	dev->irq_ops->sxe2_rdma_dis_irq(dev, msix_vec->idx);
	irq_update_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
	if (rf == dev_id) {
		tasklet_kill(&rf->dpc_tasklet);
	} else {
		struct sxe2_rdma_ceq *iwceq = (struct sxe2_rdma_ceq *)dev_id;

		tasklet_kill(&iwceq->dpc_tasklet);
	}
}

#ifndef NO_HAVE_TASKLET_SETUP
static int sxe2_cfg_ceq_vector(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_ceq *ceq, u32 ceq_id,
			       struct sxe2_rdma_msix_vector *msix_vec)
{
	int ret;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	u32 ceq_abs_id		   = 0;

	if (rf->msix_shared && !ceq_id) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2rdma-%s-AEQMCEQ", dev_name(&rf->pcidev->dev));

		tasklet_setup(&rf->dpc_tasklet, sxe2_eq_cb);
		ret = request_irq(msix_vec->irq, sxe2_eq_handler, 0,
				  msix_vec->name, rf);
		DRV_RDMA_LOG_DEV_DEBUG(
			"EQ:msix shared request irq ret=%d irq=%u name=%s\n",
			ret, msix_vec->irq, msix_vec->name);
	} else {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2rdma-%s-CEQ-%d", dev_name(&rf->pcidev->dev),
			 ceq_id);

		tasklet_setup(&ceq->dpc_tasklet, sxe2_ceq_cb);
		ret = request_irq(msix_vec->irq, sxe2_ceq_handler, 0,
				  msix_vec->name, ceq);
		DRV_RDMA_LOG_DEV_DEBUG(
			"EQ:msix no shared request irq ret=%d irq=%u name=%s\n",
			ret, msix_vec->irq, msix_vec->name);
	}

	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_update_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: ceq irq config fail\n");
		goto end;
	}

	msix_vec->ceq_id = ceq_id;

	ceq_abs_id	     = sxe2_get_ceq_abs_id(rf, ceq_id);
	msix_vec->ceq_abs_id = ceq_abs_id;

	if (rf->ctx_dev.privileged) {
		rf->ctx_dev.irq_ops->sxe2_rdma_cfg_ceq(&rf->ctx_dev, ceq_abs_id,
						       msix_vec->idx, true);
	} else {
		ret = sxe2_vchnl_cfg_ceq(&rf->ctx_dev, ceq_abs_id,
					 msix_vec->idx, true);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"ERR: ceq vchnl config fail, ret %d\n", ret);
			goto free_irq;
		}
	}

	goto end;
free_irq:
	if (rf->msix_shared && !ceq_id)
		sxe2_destroy_irq(rf, msix_vec, rf);
	else
		sxe2_destroy_irq(rf, msix_vec, ceq);
end:
	return ret;
}
#else
static int sxe2_cfg_ceq_vector(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_ceq *ceq, u32 ceq_id,
			       struct sxe2_rdma_msix_vector *msix_vec)
{
	int ret;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	u32 ceq_abs_id = 0;

	if (rf->msix_shared && !ceq_id) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2rdma-%s-AEQMCEQ", dev_name(&rf->pcidev->dev));

		ret = request_threaded_irq(msix_vec->irq, NULL,
					   sxe2_aeq_ceq0_cb, IRQF_ONESHOT,
					   msix_vec->name, rf);
		DRV_RDMA_LOG_DEBUG_BDF(
			"EQ:msix shared request irq ret=%d irq=%u name=%u\n",
			ret, msix_vec->irq, msix_vec->name);
	} else {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2rdma-%s-CEQ-%d", dev_name(&rf->pcidev->dev),
			 ceq_id);
		ret = request_threaded_irq(msix_vec->irq, NULL, sxe2_ceq_cb,
					   IRQF_ONESHOT, msix_vec->name, ceq);
		DRV_RDMA_LOG_DEBUG_BDF(
			"EQ:msix no shared request irq ret=%d irq=%u name=%u\n",
			ret, msix_vec->irq, msix_vec->name);
	}

	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_update_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF("ERR: ceq irq config fail\n");
		goto end;
	}

	msix_vec->ceq_id = ceq_id;

	ceq_abs_id = sxe2_get_ceq_abs_id(rf, ceq_id);
	msix_vec->ceq_abs_id = ceq_abs_id;

	if (rf->ctx_dev.privileged) {
		rf->ctx_dev.irq_ops->sxe2_rdma_cfg_ceq(&rf->ctx_dev, ceq_abs_id,
						       msix_vec->idx, true);
	} else {
		ret = sxe2_vchnl_cfg_ceq(&rf->ctx_dev, ceq_abs_id,
					 msix_vec->idx, true);
		if (ret) {
			DRV_RDMA_LOG_ERROR_BDF(
				"ERR: ceq vchnl config fail, ret %d\n", ret);
			goto free_irq;
		}
	}

	goto end;
free_irq:
	if (rf->msix_shared && !ceq_id)
		sxe2_destroy_irq(rf, msix_vec, rf);
	else
		sxe2_destroy_irq(rf, msix_vec, ceq);
end:
	return ret;
}
#endif

#ifndef NO_HAVE_TASKLET_SETUP
static int sxe2_cfg_aeq_vector(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf	       = rdma_dev->rdma_func;
	struct sxe2_rdma_msix_vector *msix_vec = rf->sxe2_msixtbl;
	int ret				       = 0;

	if (!rf->msix_shared) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2rdma-%s-AEQ", dev_name(&rf->pcidev->dev));
		tasklet_setup(&rf->dpc_tasklet, sxe2_eq_cb);
		ret = request_irq(msix_vec->irq, sxe2_eq_handler, 0,
				  msix_vec->name, rf);
	}

	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: aeq irq config fail\n");
		return ret;
	}

	if (rf->ctx_dev.privileged) {
		rf->ctx_dev.irq_ops->sxe2_rdma_cfg_aeq(&rf->ctx_dev,
						       msix_vec->idx, true);
	} else {
		ret = sxe2_vchnl_cfg_aeq(&rf->ctx_dev, msix_vec->idx, true);
		if (ret)
			DRV_RDMA_LOG_DEV_ERR(
				"ERR: aeq vchnl config fail, ret %d\n", ret);
	}

	return ret;
}
#else
static int sxe2_cfg_aeq_vector(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	struct sxe2_rdma_msix_vector *msix_vec = rf->sxe2_msixtbl;
	int ret = 0;

	if (!rf->msix_shared) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "sxe2_rdma-%s-AEQ", dev_name(&rf->pcidev->dev));
		ret = request_threaded_irq(msix_vec->irq, NULL,
					   sxe2_aeq_ceq0_cb, IRQF_ONESHOT,
					   msix_vec->name, rf);
	}

	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF("ERR: aeq irq config fail\n");
		return ret;
	}

	if (rf->ctx_dev.privileged) {
		rf->ctx_dev.irq_ops->sxe2_rdma_cfg_aeq(&rf->ctx_dev,
						       msix_vec->idx, true);
	} else {
		ret = sxe2_vchnl_cfg_aeq(&rf->ctx_dev, msix_vec->idx, true);
		if (ret)
			DRV_RDMA_LOG_ERROR_BDF(
				"ERR: aeq vchnl config fail, ret %d\n", ret);
	}

	return ret;
}

#endif
int sxe2_drv_ceq_create(struct sxe2_rdma_ctx_ceq *ceq, u64 scratch,
			bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = ceq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_CREATE_CEQ]) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_CREATE_CEQ);
		ret = -EBUSY;
		goto end;
	}
#endif

	if (rdma_dev->rdma_func->reset)
		return -EBUSY;

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = ceq->eqc.oi;
	eq_wqe->vsi_index     = ceq->eqc.vsi_index;
	eq_wqe->sw_owner_bit  = ceq->eqc.sw_owner_bit;
	eq_wqe->sw_status     = ceq->eqc.sw_status;
	eq_wqe->uar_page      = ceq->eqc.uar_page;
	eq_wqe->log_eq_size   = ceq->eqc.log_eq_size;
	eq_wqe->pbl_mode      = ceq->eqc.pbl_mode;
	eq_wqe->TPH_value     = ceq->eqc.TPH_value;
	eq_wqe->TPH_en	      = ceq->eqc.TPH_en;
	eq_wqe->page_offset   = ceq->eqc.page_offset;
	eq_wqe->log_page_size = ceq->eqc.log_page_size;
	eq_wqe->pbl_index     = ceq->eqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_CREATE_CEQ;
	eq_wqe->eqn			= ceq->ceq_id;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_size");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);
	ret = 0;

end:
	return ret;
}

static int sxe2_ctx_mceq_create_done(struct sxe2_rdma_ctx_ceq *ceq)
{
	struct sxe2_mq_ctx *mq;

	mq = ceq->dev->mq;
	return sxe2_kpoll_mcq(mq, SXE2_MQ_OP_CREATE_CEQ, NULL);
}

static int sxe2_ctx_mceq_create(struct sxe2_rdma_ctx_ceq *ceq, u64 scratch)
{
	int ret;
	struct sxe2_rdma_ctx_dev *dev = ceq->dev;

	dev->mcq->vsi = ceq->vsi;
	ret	      = sxe2_drv_ceq_create(ceq, scratch, true);
	if (!ret)
		ret = sxe2_ctx_mceq_create_done(ceq);

	return ret;
}

static int sxe2_mq_ceq_cmd(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_ceq *ctx_ceq, u8 op)
{
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	int ret;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info			      = &mq_request->info;
	mq_info->post_mq	      = 1;
	mq_info->mq_cmd		      = op;
	mq_info->in.u.ceq_ops.ceq     = ctx_ceq;
	mq_info->in.u.ceq_ops.scratch = (uintptr_t)mq_request;
	if (op == MQ_OP_DESTROY_CEQ)
		mq_info->destroy = true;

	ret = sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle ceq failed, ret (%d)\n", ret);

end:
	return ret;
}

static int sxe2_drv_ceq_ctx_init(struct sxe2_rdma_device *rdma_dev,
				 struct sxe2_rdma_ctx_ceq *ceq_ctx,
				 struct sxe2_ceq_init_info *info)
{
	u32 st_mode = 0;
	s32 cpu_id  = 0;

	if (info->ceq_id > (info->dev->rcms_info->max_ceqs - 1)) {
		DRV_RDMA_LOG_DEV_ERR("ceq id:%d more than max_ceqs:%d.",
				     info->ceq_id,
				     info->dev->rcms_info->max_ceqs);
		return -EINVAL;
	}

	ceq_ctx->size = info->ceq_size;
	if (rdma_dev->cache_line_64_en == false)
		ceq_ctx->ceqe_base = info->ceqe_base;
	else
		ceq_ctx->ceqe_hygon_base = info->ceqe_hygon_base;

	ceq_ctx->dev	    = &(rdma_dev->rdma_func->ctx_dev);
	ceq_ctx->vsi	    = &rdma_dev->vsi;
	ceq_ctx->polarity   = 1;
	ceq_ctx->ceq_id	    = info->ceq_id;
	ceq_ctx->cons_index = 0;
	ceq_ctx->doorbell   = info->doorbell;
	SXE2_RING_INIT(ceq_ctx->ceq_ring, ceq_ctx->size);
	ceq_ctx->dev->ceq[info->ceq_id] = ceq_ctx;
	ceq_ctx->eqc.oi			= rdma_dev->rdma_func->oi;
	ceq_ctx->eqc.vsi_index		= info->eqc.vsi_index;
	ceq_ctx->eqc.sw_owner_bit	= 0;
	ceq_ctx->eqc.sw_status		= 0xA;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "ceq_sw_status_err", rdma_dev, ceq_ctx);
#endif
	ceq_ctx->eqc.uar_page	 = info->eqc.uar_page;
	ceq_ctx->eqc.log_eq_size = info->eqc.log_eq_size;
	ceq_ctx->eqc.pbl_mode	 = info->eqc.pbl_mode;
	ceq_ctx->eqc.TPH_en = sxe2_drv_core_is_tph_enable(
		rdma_dev, SXE2_KERNEL_TPH_EN_DEFAULT, &st_mode);
	if (ceq_ctx->eqc.TPH_en) {
		if (st_mode != MODE_NO_ST)
			cpu_id = TPH_GET_CPU();
		ceq_ctx->eqc.TPH_value =
			(cpu_id & TPH_CPUID_MASK) | (PH_DWHR << 8);
	}
	ceq_ctx->eqc.page_offset   = info->eqc.page_offset;
	ceq_ctx->eqc.log_page_size = info->eqc.log_page_size;
	ceq_ctx->eqc.pbl_index	   = info->eqc.pbl_index;

	DRV_RDMA_LOG_DEV_INFO("ceq_ctx db map :%p\n", ceq_ctx->doorbell);

	DRV_RDMA_LOG_DEV_DEBUG(
		"ceq:%d ceqc : ceqsz %#x, pbl %#llx\n"
		"pgsz %#x, pg_offset %#x, pblm %#x, vsi_id %#x, oi %#x, sw_owner_bit %#x\n"
		"sw_status %#x, uar_page %#x, TPH_value %#x, TPH_en %#x\n",
		ceq_ctx->ceq_id, ceq_ctx->eqc.log_eq_size,
		ceq_ctx->eqc.pbl_index, ceq_ctx->eqc.log_page_size,
		ceq_ctx->eqc.page_offset, ceq_ctx->eqc.pbl_mode,
		ceq_ctx->eqc.vsi_index, ceq_ctx->eqc.oi,
		ceq_ctx->eqc.sw_owner_bit, ceq_ctx->eqc.sw_status,
		ceq_ctx->eqc.uar_page, ceq_ctx->eqc.TPH_value,
		ceq_ctx->eqc.TPH_en);
	return 0;
}

static int sxe2_create_ceq_pble(struct sxe2_rdma_pci_f *rf, struct sxe2_rdma_ceq *ceq)
{
	u32 pg_cnt;
	int ret;
	u32 i;
	u64 temp_liner_addr;
	u8 *addr;
	struct page *vm_page;
	struct sxe2_ceq_pble_buf *mem;
	struct sxe2_rdma_device *rdma_dev = rf->rdma_dev;

	pg_cnt = DIV_ROUND_UP(ceq->mem.size, PAGE_SIZE);
	ceq->mem.va = vzalloc(ceq->mem.size);
	if (ceq->mem.va == NULL) {
		ret = -ENOMEM;
		goto end;
	}

	ceq->pble_buf =
		kcalloc(pg_cnt, sizeof(struct sxe2_rdma_dma_mem), GFP_KERNEL);
	if (unlikely(!ceq->pble_buf)) {
		DRV_RDMA_LOG_DEV_ERR("buf alloc err npages %d, sz %lu\n",
				     pg_cnt, sizeof(struct sxe2_rdma_dma_mem));
		ret = -ENOMEM;
		goto free_va;
	}

	ret = sxe2_pbl_get_pble(rf->pble_rsrc, &ceq->palloc, pg_cnt,
				PBL_OBJ_EQ);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq get pble failed. ret:%d\n", ret);
		goto free_mem;
	}

	temp_liner_addr = ceq->palloc.pble_info.liner_addr;

	addr = (u8 *)(uintptr_t)ceq->mem.va;
	for (i = 0; i < pg_cnt; i++) {
		vm_page = vmalloc_to_page(addr);
		if (vm_page == NULL) {
			ret = -ENOMEM;
			goto free_dma;
		}

		mem	 = &ceq->pble_buf[i];
		mem->map = dma_map_page(rf->hw.device, vm_page, 0, PAGE_SIZE,
					DMA_BIDIRECTIONAL);
		if (dma_mapping_error(rf->hw.device, mem->map)) {
			ret = -ENOMEM;
			goto free_dma;
		}

		ret = sxe2_pbl_set_pble(rf->pble_rsrc, temp_liner_addr,
					mem->map, false);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("set pble failed %d\n", ret);
			goto free_dma;
		}

		temp_liner_addr += sizeof(u64);
		addr += PAGE_SIZE;
	}

	goto end;

free_dma:
	while (i--) {
		mem = &ceq->pble_buf[i];
		dma_unmap_page(rf->hw.device, mem->map, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);
	}

free_mem:
	kfree(ceq->pble_buf);
	ceq->pble_buf = NULL;
free_va:
	vfree(ceq->mem.va);
	ceq->mem.va = NULL;
end:
	return ret;
}

static void sxe2_destroy_ceq_pble(struct sxe2_rdma_pci_f *rf, struct sxe2_rdma_ceq *ceq)
{
	u32 i;
	struct sxe2_ceq_pble_buf *mem;

	sxe2_pbl_free_pble(rf->pble_rsrc, ceq->palloc.pble_info.liner_addr,
			   ceq->palloc.needed_pble_cnt, false);

	for (i = 0; i < ceq->palloc.needed_pble_cnt; i++) {
		mem = &ceq->pble_buf[i];
		dma_unmap_page(rf->hw.device, mem->map, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);
	}

	kfree(ceq->pble_buf);
	ceq->pble_buf = NULL;
	vfree(ceq->mem.va);
	ceq->mem.va = NULL;
}

static int sxe2_rdma_create_ceq(struct sxe2_rdma_device *rdma_dev,
				struct sxe2_rdma_ceq *ceq, u32 ceq_id,
				struct sxe2_rdma_ctx_vsi *vsi)
{
	int ret;
	struct sxe2_ceq_init_info info = {};
	struct sxe2_rdma_pci_f *rf     = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev  = &rf->ctx_dev;
	u64 scratch;
	u32 ceq_size = 0;

	info.ceq_id = ceq_id;
	ceq->rf	    = rf;
	ceq_size    = min(rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].cnt,
			  dev->hw_attrs.max_hw_ceq_size);
	ceq_size = (unsigned long)roundup_pow_of_two((unsigned long)ceq_size);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "ceq_ci_noupdate", rdma_dev, &ceq_size, ceq_id);
#endif
	if ((ceq_size < SXE2_MIN_EQ_SIZE) || (ceq_size > SXE2_MAX_EQ_SIZE)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("ceq size(%d) invalid.ret:%d", ceq_size,
				     ret);
		goto end;
	}

	if (rdma_dev->cache_line_64_en == false) {
		ceq->mem.size = (u32)ALIGN(sizeof(struct sxe2_eqe) * ceq_size,
					   SXE2_CEQ_ALIGNMENT);
		DRV_RDMA_LOG_DEV_DEBUG(
			"ceq:no_hygon,EQE=32B, ceq->mem.size %#x\n",
			ceq->mem.size);
	} else {
		ceq->mem.size =
			(u32)ALIGN(sizeof(struct sxe2_eqe_hygon) * ceq_size,
				   SXE2_CEQ_ALIGNMENT);
		DRV_RDMA_LOG_DEV_DEBUG("ceq:hygon,EQE=64B, ceq->mem.size %#x\n",
				       ceq->mem.size);
	}

	ceq->mem.va = dma_alloc_coherent(dev->hw->device, ceq->mem.size,
					 &ceq->mem.pa, GFP_KERNEL);
	if (ceq->mem.va) {
		memset(ceq->mem.va, 0, ceq->mem.size);
		info.ceqe_pa = ceq->mem.pa;
		info.eqc.pbl_mode      = CQ_EQ_PA_FIRST_MODE;
		info.eqc.pbl_index     = info.ceqe_pa;
		goto skip_ceq_pble;
	}

	ret = sxe2_create_ceq_pble(rf, ceq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq mem create use pble failed. ret:%d\n",
				     ret);
		goto end;
	}

	info.eqc.pbl_index = ceq->palloc.pbl_index;
	info.eqc.pbl_mode  = ceq->palloc.pbl_mode.cq_eq_mode;
	info.pble_map	   = true;
	ceq->pble_map	   = info.pble_map;

skip_ceq_pble:

	info.ceq_id   = ceq_id;
	info.ceq_size = ceq_size;
	if (rdma_dev->cache_line_64_en == false)
		info.ceqe_base = ceq->mem.va;
	else
		info.ceqe_hygon_base = ceq->mem.va;

	info.dev     = dev;
	info.vsi     = vsi;
	DRV_RDMA_LOG_DEV_INFO("ceq db map:%p\n", rf->db->map);
	info.doorbell = rf->db->map + SXE2_RDMA_DB_EQ_INFO_OFFSET;
	DRV_RDMA_LOG_DEV_INFO("ceq db map offset 4 :%p\n", info.doorbell);

	info.eqc.vsi_index     = vsi->vsi_idx;
	info.eqc.log_eq_size   = order_base_2(ceq_size);
	info.eqc.log_page_size = order_base_2(PAGE_SIZE);
	info.eqc.page_offset   = offset_in_page(ceq->mem.pa);

	ret = sxe2_drv_ceq_ctx_init(rdma_dev, &ceq->ctx_ceq, &info);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("ceq ctx init failed.ret:%d pble_map %d\n",
							ret,  ceq->pble_map);
		goto free_dma;
	}

	if (dev->ceq_valid) {
		ret = sxe2_mq_ceq_cmd(rdma_dev, &ceq->ctx_ceq,
				      MQ_OP_CREATE_CEQ);
	} else {
		scratch = (uintptr_t)&rf->mq.mq;
		ret	= sxe2_ctx_mceq_create(&ceq->ctx_ceq, scratch);
	}

	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ceq create failed.ret:%d pble_map %d\n",
							ret,  ceq->pble_map);
		goto free_dma;
	}

	DRV_RDMA_LOG_DEV_INFO("ceq:%d create success.ret:%d pble_map:%d\n",
						ceq_id, ret, ceq->pble_map);
	goto end;

free_dma:
	if (ceq->pble_map) {
		sxe2_destroy_ceq_pble(rf, ceq);
	} else {
		dma_free_coherent(dev->hw->device, ceq->mem.size, ceq->mem.va,
				  ceq->mem.pa);
		ceq->mem.va = NULL;
	}

end:
	return ret;
}

int sxe2_drv_ceq_destroy(struct sxe2_rdma_ctx_ceq *ceq, u64 scratch,
			 bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = ceq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = ceq->eqc.oi;
	eq_wqe->vsi_index     = ceq->eqc.vsi_index;
	eq_wqe->sw_owner_bit  = ceq->eqc.sw_owner_bit;
	eq_wqe->sw_status     = ceq->eqc.sw_status;
	eq_wqe->uar_page      = ceq->eqc.uar_page;
	eq_wqe->log_eq_size   = ceq->eqc.log_eq_size;
	eq_wqe->pbl_mode      = ceq->eqc.pbl_mode;
	eq_wqe->TPH_value     = ceq->eqc.TPH_value;
	eq_wqe->TPH_en	      = ceq->eqc.TPH_en;
	eq_wqe->page_offset   = ceq->eqc.page_offset;
	eq_wqe->log_page_size = ceq->eqc.log_page_size;
	eq_wqe->pbl_index     = ceq->eqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_DESTROY_CEQ;
	eq_wqe->eqn			= ceq->ceq_id;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

static int sxe2_ctx_mceq_destroy_done(struct sxe2_rdma_ctx_ceq *ceq)
{
	struct sxe2_mq_ctx *mq;

	mq		   = ceq->dev->mq;
	mq->process_mq_fpt = sxe2_rcms_update_fptes_cmd;

	return sxe2_kpoll_mcq(mq, SXE2_MQ_OP_DESTROY_CEQ, NULL);
}

static void sxe2_rdma_destroy_ceq(struct sxe2_rdma_device *rdma_dev,
				  struct sxe2_rdma_ceq *ceq)
{
	struct sxe2_rdma_pci_f *rf    = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev = &rf->ctx_dev;
	int ret;
	bool hw_rsrc_clean = false;
	unsigned long flags = 0;

	hw_rsrc_clean = sxe2_get_hw_rsrc_clean_flag(&rf->ctx_dev);
	if (rf->reset && hw_rsrc_clean) {
		DRV_RDMA_LOG_DEV_DEBUG("already reset\n");
		goto exit;
	}

	spin_lock_irqsave(&rf->ctx_dev.mq_lock, flags);
	ret = sxe2_drv_ceq_destroy(&ceq->ctx_ceq, 0, 1);
	spin_unlock_irqrestore(&rf->ctx_dev.mq_lock, flags);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: CEQ destroy command failed %d\n",
				     ret);
		goto exit;
	}

	ret = sxe2_ctx_mceq_destroy_done(&ceq->ctx_ceq);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_DESTROY_CEQ] && !ret) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_DESTROY_CEQ);
		ret = -EBUSY;
	}
#endif
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: CEQ destroy completion failed %d\n",
				     ret);
	}
exit:
	if (ceq->pble_map) {
		sxe2_destroy_ceq_pble(rf, ceq);
	} else {
		dma_free_coherent(dev->hw->device, ceq->mem.size, ceq->mem.va,
				  ceq->mem.pa);
		ceq->mem.va = NULL;
	}
}

void sxe2_del_mceq(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	struct sxe2_rdma_ceq *ceq  = rf->ceqlist;
	struct sxe2_rdma_msix_vector *msix_vec;
	int ret = 0;

	if (rf->msix_shared) {
		msix_vec = &rf->sxe2_msixtbl[0];
		DRV_RDMA_LOG_DEV_DEBUG(
			"ceq unmap in, ceq_rel_id=%#x, ceq_abs_id=%#x, idx=%#x\n",
			msix_vec->ceq_id, msix_vec->ceq_abs_id, msix_vec->idx);
		if (rf->ctx_dev.privileged) {
			rf->ctx_dev.irq_ops->sxe2_rdma_cfg_ceq(
				&rf->ctx_dev, msix_vec->ceq_abs_id,
				msix_vec->idx, false);
		} else {
			ret = sxe2_vchnl_cfg_ceq(&rf->ctx_dev,
						 msix_vec->ceq_abs_id,
						 msix_vec->idx, false);
			if (ret) {
				DRV_RDMA_LOG_ERROR_BDF(
					"ceq %#x unmap fail, ceq_abs_id=%#x, ret %d\n",
					msix_vec->ceq_id, msix_vec->ceq_abs_id,
					ret);
			}
		}
		sxe2_destroy_irq(rf, msix_vec, rf);
	} else {
		msix_vec = &rf->sxe2_msixtbl[1];
		DRV_RDMA_LOG_DEV_DEBUG(
			"ceq unmap in, ceq_rel_id=%#x, ceq_abs_id=%#x, idx=%#x\n",
			msix_vec->ceq_id, msix_vec->ceq_abs_id, msix_vec->idx);
		if (rf->ctx_dev.privileged) {
			rf->ctx_dev.irq_ops->sxe2_rdma_cfg_ceq(
				&rf->ctx_dev, msix_vec->ceq_abs_id,
				msix_vec->idx, false);
		} else {
			ret = sxe2_vchnl_cfg_ceq(&rf->ctx_dev,
						 msix_vec->ceq_abs_id,
						 msix_vec->idx, false);
			if (ret) {
				DRV_RDMA_LOG_ERROR_BDF(
					"ceq %#x unmap fail, ceq_abs_id=%#x, ret %d\n",
					msix_vec->ceq_id, msix_vec->ceq_abs_id,
					ret);
			}
		}
		sxe2_destroy_irq(rf, msix_vec, ceq);
	}

	sxe2_kuninit_mq_handler(rdma_dev);

	drv_rdma_debug_ceq_remove(rdma_dev, ceq);
	sxe2_rdma_destroy_ceq(rdma_dev, ceq);
	rf->ctx_dev.ceq_valid = false;
	rf->ceqs_count	      = 0;
}

void sxe2_del_ceqs(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	struct sxe2_rdma_ceq *ceq  = &rf->ceqlist[1];
	struct sxe2_rdma_msix_vector *msix_vec;
	u32 i = 0;
	int ret;

	if (rf->msix_shared)
		msix_vec = &rf->sxe2_msixtbl[1];
	else
		msix_vec = &rf->sxe2_msixtbl[2];

	for (i = 1; i < rf->ceqs_count; i++, msix_vec++, ceq++) {
		if (rf->ctx_dev.privileged) {
			rf->ctx_dev.irq_ops->sxe2_rdma_cfg_ceq(
				&rf->ctx_dev, msix_vec->ceq_abs_id,
				msix_vec->idx, false);
		} else {
			ret = sxe2_vchnl_cfg_ceq(&rf->ctx_dev,
						 msix_vec->ceq_abs_id,
						 msix_vec->idx, false);
			if (ret)
				DRV_RDMA_LOG_ERROR_BDF(
					"ceq %#x unmap fail, ceq_abs_id=%#x, ret %d\n",
					msix_vec->ceq_id, msix_vec->ceq_abs_id,
					ret);
		}

		sxe2_destroy_irq(rf, msix_vec, ceq);

		drv_rdma_debug_ceq_remove(rdma_dev, ceq);

		ret = sxe2_mq_ceq_cmd(rdma_dev, &ceq->ctx_ceq,
				      MQ_OP_DESTROY_CEQ);
		if (ret)
			DRV_RDMA_LOG_DEV_ERR(
				"ERR: CEQ:%d destroy command failed %d\n",
				ceq->ctx_ceq.ceq_id, ret);
		if (ceq->pble_map) {
			sxe2_destroy_ceq_pble(rf, ceq);
		} else {
			dma_free_coherent(rf->ctx_dev.hw->device, ceq->mem.size,
					  ceq->mem.va, ceq->mem.pa);
			ceq->mem.va = NULL;
		}
	}
	rf->ceqs_count = 1;
}

int sxe2_setup_mceq(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_ceq *ceq;
	struct sxe2_rdma_msix_vector *msix_vec;
	u32 i;
	int ret			   = 0;
	u32 num_ceqs		   = 0;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;

	num_ceqs    = min(rf->msix_count, rf->ctx_dev.rcms_info->max_ceqs);
	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("ERR: ceq buf alloc failed. ret = %d\n",
				     ret);
		goto exit;
	}

	ceq = &rf->ceqlist[0];
	ret = sxe2_rdma_create_ceq(rdma_dev, ceq, 0, &rf->default_vsi);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: create ceq ret = %d\n", ret);
		goto exit;
	}

	ret = drv_rdma_debug_ceq_add(rdma_dev, ceq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"failed adding ceq:%d to debug file system, ret (%d)\n",
			0, ret);
		sxe2_rdma_destroy_ceq(rdma_dev, ceq);
		goto exit;
	}

	spin_lock_init(&ceq->ce_lock);
	i	      = rf->msix_shared ? 0 : 1;
	msix_vec      = &rf->sxe2_msixtbl[i];
	ceq->irq      = msix_vec->irq;
	ceq->msix_idx = msix_vec->idx;
	ret	      = sxe2_cfg_ceq_vector(rdma_dev, ceq, 0, msix_vec);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: cfg ceq:%d vector failed. ret = %d\n", 0, ret);

		drv_rdma_debug_ceq_remove(rdma_dev, ceq);
		sxe2_rdma_destroy_ceq(rdma_dev, ceq);
		goto exit;
	}

	sxe2_rdma_ena_intr(&rf->ctx_dev, msix_vec->idx);
	rf->ceqs_count++;
	rf->ctx_dev.ceq_valid = true;

exit:
	if (ret && !rf->ceqs_count) {
		kfree(rf->ceqlist);
		rf->ceqlist = NULL;
	}

	return ret;
}

int sxe2_setup_ceqs(struct sxe2_rdma_device *rdma_dev)
{
	u32 msix_cnt;
	u32 ceq_id;
	struct sxe2_rdma_ceq *ceq;
	struct sxe2_rdma_msix_vector *msix_vec;
	int ret;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;

	msix_cnt	 = (rf->msix_shared) ? 1 : 2;
	for (ceq_id = 1; ceq_id < rf->ctx_dev.rcms_info->max_ceqs
			&& msix_cnt < rf->msix_count; msix_cnt++, ceq_id++) {
		ceq = &rf->ceqlist[ceq_id];
		ret = sxe2_rdma_create_ceq(rdma_dev, ceq, ceq_id,
					   &rdma_dev->vsi);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("ERR: create ceq ret = %d\n", ret);
			goto del_ceqs;
		}
		spin_lock_init(&ceq->ce_lock);

		ret = drv_rdma_debug_ceq_add(rdma_dev, ceq);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"failed adding ceq:%d to debug file system, ret (%d)\n",
				ceq_id, ret);
			sxe2_rdma_destroy_ceq(rdma_dev, ceq);
			goto del_ceqs;
		}

		msix_vec      = &rf->sxe2_msixtbl[msix_cnt];
		ceq->irq      = msix_vec->irq;
		ceq->msix_idx = msix_vec->idx;
		ret = sxe2_cfg_ceq_vector(rdma_dev, ceq, ceq_id, msix_vec);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"ERR: cfg ceq:%d vector failed. ret = %d\n",
				ceq_id, ret);
			drv_rdma_debug_ceq_remove(rdma_dev, ceq);
			sxe2_rdma_destroy_ceq(rdma_dev, ceq);
			goto del_ceqs;
		}
		sxe2_rdma_ena_intr(&rf->ctx_dev, msix_vec->idx);
		rf->ceqs_count++;
	}

	return 0;

del_ceqs:
	sxe2_del_ceqs(rdma_dev);
	return ret;
}

int sxe2_drv_aeq_create(struct sxe2_rdma_ctx_aeq *aeq, u64 scratch,
			bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = aeq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = aeq->eqc.oi;
	eq_wqe->vsi_index     = aeq->eqc.vsi_index;
	eq_wqe->sw_owner_bit  = aeq->eqc.sw_owner_bit;
	eq_wqe->sw_status     = aeq->eqc.sw_status;
	eq_wqe->uar_page      = aeq->eqc.uar_page;
	eq_wqe->log_eq_size   = aeq->eqc.log_eq_size;
	eq_wqe->pbl_mode      = aeq->eqc.pbl_mode;
	eq_wqe->TPH_value     = aeq->eqc.TPH_value;
	eq_wqe->TPH_en	      = aeq->eqc.TPH_en;
	eq_wqe->page_offset   = aeq->eqc.page_offset;
	eq_wqe->log_page_size = aeq->eqc.log_page_size;
	eq_wqe->pbl_index     = aeq->eqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_CREATE_AEQ;
	eq_wqe->eqn			= 0;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	switch (rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type) {
	case AEQN_DEBUGFS:
		eq_wqe->eqn =
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val;
		DRV_RDMA_LOG_DEV_DEBUG(
			"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
			"ori ceqn 0, err ceqn %#llx\n",
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val,
			(u64)eq_wqe->eqn);
		break;
	case AEQC_SW_STATE_DEBUGFS:
		eq_wqe->sw_status =
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val;
		DRV_RDMA_LOG_DEV_DEBUG(
			"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
			"ori ceqc_state %#llx, err ceqc_state %#llx\n",
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val,
			(u64)aeq->eqc.sw_status, (u64)eq_wqe->sw_status);
		break;
	case AEQC_SIZE_DEBUGFS:
		eq_wqe->log_eq_size =
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val;
		DRV_RDMA_LOG_DEV_DEBUG(
			"MQ DEBUGFS:inject rsc_err_type:%#x, rsc_err_val %#llx\n"
			"ori ceqc_size %#llx, err ceqc_size %#llx\n",
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val,
			(u64)aeq->eqc.log_eq_size, (u64)eq_wqe->log_eq_size);
		break;
	default:
		break;
	}
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_aeq_destroy(struct sxe2_rdma_ctx_aeq *aeq, u64 scratch,
			 bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_ctx_dev *dev;
	int ret;

	mq	 = aeq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);

	dev = aeq->dev;
	if (dev->privileged)
		writel(0, dev->hw_regs[PF_INT_AEQCTL]);

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = aeq->eqc.oi;
	eq_wqe->vsi_index     = aeq->eqc.vsi_index;
	eq_wqe->sw_owner_bit  = aeq->eqc.sw_owner_bit;
	eq_wqe->sw_status     = aeq->eqc.sw_status;
	eq_wqe->uar_page      = aeq->eqc.uar_page;
	eq_wqe->log_eq_size   = aeq->eqc.log_eq_size;
	eq_wqe->pbl_mode      = aeq->eqc.pbl_mode;
	eq_wqe->TPH_value     = aeq->eqc.TPH_value;
	eq_wqe->TPH_en	      = aeq->eqc.TPH_en;
	eq_wqe->page_offset   = aeq->eqc.page_offset;
	eq_wqe->log_page_size = aeq->eqc.log_page_size;
	eq_wqe->pbl_index     = aeq->eqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_DESTROY_AEQ;
	eq_wqe->eqn			= 0;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

static int sxe2_mq_aeq_cmd(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_aeq *aeq_ctx, u8 op)
{
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *cqp_info;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	int ret;

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	cqp_info		       = &mq_request->info;
	cqp_info->post_mq	       = 1;
	cqp_info->mq_cmd	       = op;
	cqp_info->in.u.aeq_ops.aeq     = aeq_ctx;
	cqp_info->in.u.aeq_ops.scratch = (uintptr_t)mq_request;
	if (op == MQ_OP_DESTROY_AEQ)
		cqp_info->destroy = true;

	ret = sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle aeq failed, ret (%d)\n", ret);

end:
	return ret;
}

static int sxe2_drv_aeq_ctx_init(struct sxe2_rdma_ctx_aeq *aeq_ctx,
				 struct sxe2_aeq_init_info *info)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(info->dev);
	u32 st_mode			  = 0;
	s32 cpu_id			  = 0;

	aeq_ctx->size = info->aeq_size;
	if (rdma_dev->cache_line_64_en == false)
		aeq_ctx->aeqe_base = info->aeqe_base;
	else
		aeq_ctx->aeqe_hygon_base = info->aeqe_hygon_base;

	aeq_ctx->dev	    = info->dev;
	aeq_ctx->vsi	    = info->vsi;
	aeq_ctx->polarity   = 1;
	aeq_ctx->cons_index = 0;
	aeq_ctx->doorbell   = info->doorbell;
	aeq_ctx->msix_idx   = info->msix_idx;
	aeq_ctx->irq	    = info->irq;
	SXE2_RING_INIT(aeq_ctx->aeq_ring, aeq_ctx->size);
	aeq_ctx->dev->aeq = aeq_ctx;

	if (info->dev->privileged)
		aeq_ctx->eqc.oi = rdma_dev->rdma_func->oi;
	else
		aeq_ctx->eqc.oi = 1;

	aeq_ctx->eqc.vsi_index	  = info->eqc.vsi_index;
	aeq_ctx->eqc.sw_owner_bit = 0;
	aeq_ctx->eqc.sw_status	  = 0xA;
	aeq_ctx->eqc.uar_page	  = info->eqc.uar_page;
	aeq_ctx->eqc.log_eq_size  = info->eqc.log_eq_size;
	aeq_ctx->eqc.pbl_mode	  = info->eqc.pbl_mode;
	aeq_ctx->eqc.TPH_en = sxe2_drv_core_is_tph_enable(
		rdma_dev, SXE2_KERNEL_TPH_EN_DEFAULT, &st_mode);
	if (aeq_ctx->eqc.TPH_en) {
		if (st_mode != MODE_NO_ST)
			cpu_id = TPH_GET_CPU();
		aeq_ctx->eqc.TPH_value =
			(cpu_id & TPH_CPUID_MASK) | (PH_DWHR << 8);
	}
	aeq_ctx->eqc.page_offset   = info->eqc.page_offset;
	aeq_ctx->eqc.log_page_size = info->eqc.log_page_size;
	aeq_ctx->eqc.pbl_index	   = info->eqc.pbl_index;

	DRV_RDMA_LOG_DEV_DEBUG(
		"aeqc : aeqsz %#x, pbl_l %#llx,\n"
		"pgsz %#x, pg_offset %#x, pblm %#x, vsi_id %#x, oi %#x, sw_owner_bit %#x\n"
		"sw_status %#x, uar_page %#x, TPH_value %#x, TPH_en %#x\n",
		aeq_ctx->eqc.log_eq_size, aeq_ctx->eqc.pbl_index,
		aeq_ctx->eqc.log_page_size, aeq_ctx->eqc.page_offset,
		aeq_ctx->eqc.pbl_mode, aeq_ctx->eqc.vsi_index, aeq_ctx->eqc.oi,
		aeq_ctx->eqc.sw_owner_bit, aeq_ctx->eqc.sw_status,
		aeq_ctx->eqc.uar_page, aeq_ctx->eqc.TPH_value,
		aeq_ctx->eqc.TPH_en);

	return 0;
}

static int sxe2_create_aeq_pble(struct sxe2_rdma_pci_f *rf, u32 size)
{
	u32 pg_cnt;
	int ret;
	u32 i;
	u64 temp_liner_addr;
	u8 *addr;
	struct page *vm_page;
	struct sxe2_aeq_pble_buf *mem;
	struct sxe2_rdma_device *rdma_dev = rf->rdma_dev;
	struct sxe2_rdma_aeq *aeq	  = &rf->aeq;

	if (rdma_dev->cache_line_64_en == false)
		aeq->mem.size = (u32)sizeof(struct sxe2_eqe) * size;
	else
		aeq->mem.size = (u32)sizeof(struct sxe2_eqe_hygon) * size;

	pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);

	aeq->mem.va = vzalloc(aeq->mem.size);
	if (aeq->mem.va == NULL) {
		ret = -ENOMEM;
		goto end;
	}

	aeq->pble_buf =
		kcalloc(pg_cnt, sizeof(struct sxe2_rdma_dma_mem), GFP_KERNEL);
	if (unlikely(!aeq->pble_buf)) {
		DRV_RDMA_LOG_DEV_ERR("buf alloc err npages %d, sz %lu\n",
				     pg_cnt, sizeof(struct sxe2_rdma_dma_mem));
		ret = -ENOMEM;
		goto free_va;
	}

	ret = sxe2_pbl_get_pble(rf->pble_rsrc, &aeq->palloc, pg_cnt,
				PBL_OBJ_EQ);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq get pble failed. ret:%d\n", ret);
		goto free_mem;
	}

	temp_liner_addr = aeq->palloc.pble_info.liner_addr;

	addr = (u8 *)(uintptr_t)aeq->mem.va;
	for (i = 0; i < pg_cnt; i++) {
		vm_page = vmalloc_to_page(addr);
		if (vm_page == NULL) {
			ret = -ENOMEM;
			goto free_dma;
		}

		mem	 = &aeq->pble_buf[i];
		mem->map = dma_map_page(rf->hw.device, vm_page, 0, PAGE_SIZE,
					DMA_BIDIRECTIONAL);
		if (dma_mapping_error(rf->hw.device, mem->map)) {
			ret = -ENOMEM;
			goto free_dma;
		}

		ret = sxe2_pbl_set_pble(rf->pble_rsrc, temp_liner_addr,
					mem->map, false);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("set pble failed %d\n", ret);
			goto free_dma;
		}

		temp_liner_addr += sizeof(u64);
		addr += PAGE_SIZE;
	}

	goto end;

free_dma:
	while (i--) {
		mem = &aeq->pble_buf[i];
		dma_unmap_page(rf->hw.device, mem->map, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);
	}

free_mem:
	kfree(aeq->pble_buf);
	aeq->pble_buf = NULL;
free_va:
	vfree(aeq->mem.va);
	aeq->mem.va = NULL;
end:
	return ret;
}

static void sxe2_destroy_aeq_pble(struct sxe2_rdma_pci_f *rf)
{
	u32 i;
	struct sxe2_aeq_pble_buf *mem;
	struct sxe2_rdma_aeq *aeq = &rf->aeq;

	sxe2_pbl_free_pble(rf->pble_rsrc, aeq->palloc.pble_info.liner_addr,
			   aeq->palloc.needed_pble_cnt, false);

	for (i = 0; i < aeq->palloc.needed_pble_cnt; i++) {
		mem = &aeq->pble_buf[i];
		dma_unmap_page(rf->hw.device, mem->map, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);
	}

	kfree(aeq->pble_buf);
	aeq->pble_buf = NULL;
	vfree(aeq->mem.va);
	aeq->mem.va = NULL;
}

static int sxe2_rdma_aeq_alloc_coherent_mem(struct sxe2_rdma_device *rdma_dev,
					    struct sxe2_aeq_init_info *info)
{
	struct sxe2_rdma_pci_f *rf    = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev = &rf->ctx_dev;
	struct sxe2_rdma_aeq *aeq     = &rf->aeq;
	int ret			      = 0;

#ifndef SXE2_CFG_DEBUG
	aeq->mem.va =
		dma_alloc_coherent(dev->hw->device, aeq->mem.size, &aeq->mem.pa,
				   GFP_KERNEL | __GFP_NOWARN);
	if (aeq->mem.va) {
		memset(aeq->mem.va, 0, aeq->mem.size);
		info->aeq_elem_pa   = aeq->mem.pa;
		info->eqc.pbl_index = info->aeq_elem_pa;
		info->eqc.pbl_mode  = CQ_EQ_PA_FIRST_MODE;
	} else {
		ret = -ENOMEM;
		DRV_RDMA_LOG_WARN_BDF("aeq dma alloc failed.\n");
	}
#else
	if (rf->aeq_pble_en) {
		DRV_RDMA_LOG_INFO_BDF("aeq alloc use pble.\n");
	} else {
		aeq->mem.va = dma_alloc_coherent(dev->hw->device, aeq->mem.size,
						 &aeq->mem.pa,
						 GFP_KERNEL | __GFP_NOWARN);
		if (aeq->mem.va) {
			memset(aeq->mem.va, 0, aeq->mem.size);
			info->aeq_elem_pa = aeq->mem.pa;
			info->eqc.pbl_index = info->aeq_elem_pa;
			info->eqc.pbl_mode = CQ_EQ_PA_FIRST_MODE;
		} else {
			ret = -ENOMEM;
			DRV_RDMA_LOG_WARN_BDF("aeq dma alloc failed.\n");
		}
	}
#endif

	return ret;
}

static int sxe2_rdma_create_aeq(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf     = rdma_dev->rdma_func;
	struct sxe2_aeq_init_info info = {};
	struct sxe2_rdma_ctx_dev *dev  = &rf->ctx_dev;
	struct sxe2_rdma_aeq *aeq      = &rf->aeq;
	u32 aeq_size;
	int ret;

	aeq_size = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].cnt +
		   rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].cnt;
	aeq_size = min(aeq_size, dev->hw_attrs.max_hw_aeq_size);
	aeq_size = (u32)roundup_pow_of_two(aeq_size);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "aeq_ci_noupdate",
				rdma_dev, &aeq_size);
#endif

	if ((aeq_size < SXE2_MIN_EQ_SIZE) || (aeq_size > SXE2_MAX_EQ_SIZE)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("aeq size(%d) invalid.ret:%d", aeq_size,
				     ret);
		goto end;
	}

	if (rdma_dev->cache_line_64_en == false) {
		aeq->mem.size = (u32)ALIGN(sizeof(struct sxe2_eqe) * aeq_size,
					   SXE2_AEQ_ALIGNMENT);
		DRV_RDMA_LOG_DEV_DEBUG(
			"aeq:no_hygon,EQE=32B, aeq->mem.size %#x",
			aeq->mem.size);
	} else {
		aeq->mem.size =
			(u32)ALIGN(sizeof(struct sxe2_eqe_hygon) * aeq_size,
				   SXE2_AEQ_ALIGNMENT);
		DRV_RDMA_LOG_DEV_DEBUG("aeq:hygon,EQE=64B, aeq->mem.size %#x",
				       aeq->mem.size);
	}

	if (!sxe2_rdma_aeq_alloc_coherent_mem(rdma_dev, &info))
		goto skip_aeq_pble;

	ret = sxe2_create_aeq_pble(rf, aeq_size);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq mem create use pble failed. ret:%d\n",
				     ret);
		goto end;
	}

	info.eqc.pbl_index = aeq->palloc.pbl_index;
	info.eqc.pbl_mode  = aeq->palloc.pbl_mode.cq_eq_mode;
	info.pble_map	   = true;
	aeq->pble_map	   = info.pble_map;

skip_aeq_pble:
	if (rdma_dev->cache_line_64_en == false)
		info.aeqe_base = aeq->mem.va;
	else
		info.aeqe_hygon_base = aeq->mem.va;

	info.aeq_size = aeq_size;
	info.dev      = dev;
	info.irq      = rf->sxe2_msixtbl->irq;
	info.msix_idx = rf->sxe2_msixtbl->idx;
	info.vsi      = &rf->default_vsi;
	DRV_RDMA_LOG_DEV_INFO("aeq db map:%p\n", rf->db->map);
	info.doorbell = rf->db->map + SXE2_RDMA_DB_EQ_INFO_OFFSET;
	DRV_RDMA_LOG_DEV_INFO("aeq db map offset 4 :%p\n", info.doorbell);

	info.eqc.vsi_index     = rf->default_vsi.vsi_idx;
	info.eqc.log_eq_size   = order_base_2(aeq_size);
	info.eqc.log_page_size = order_base_2(PAGE_SIZE);
	info.eqc.page_offset   = offset_in_page(aeq->mem.pa);

	sxe2_drv_aeq_ctx_init(&aeq->ctx_aeq, &info);

	ret = sxe2_mq_aeq_cmd(rdma_dev, &aeq->ctx_aeq, MQ_OP_CREATE_AEQ);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("aeq create ops failed. ret:%d\n", ret);
		if (aeq->pble_map) {
			sxe2_destroy_aeq_pble(rf);
		} else {
			dma_free_coherent(dev->hw->device, aeq->mem.size,
					  aeq->mem.va, aeq->mem.pa);
			aeq->mem.va = NULL;
		}
	}

end:
	return ret;
}

void sxe2_del_aeq(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rf    = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev = &rf->ctx_dev;
	struct sxe2_rdma_aeq *aeq     = &rf->aeq;
	int ret;

	atomic_set(&rf->aeq_created, 0);

	if (rf->ctx_dev.privileged)
		rf->ctx_dev.irq_ops->sxe2_rdma_cfg_aeq(
			&rf->ctx_dev, rf->sxe2_msixtbl->idx, false);
	else
		ret = sxe2_vchnl_cfg_aeq(&rf->ctx_dev, rf->sxe2_msixtbl->idx,
					 false);

	if (!rf->msix_shared)
		sxe2_destroy_irq(rf, rf->sxe2_msixtbl, rf);

	drv_rdma_debug_aeq_remove(rdma_dev, aeq);

	aeq->ctx_aeq.size = 0;
	ret = sxe2_mq_aeq_cmd(rdma_dev, &aeq->ctx_aeq, MQ_OP_DESTROY_AEQ);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("del AEQ failed %d\n", ret);

	if (aeq->pble_map) {
		sxe2_destroy_aeq_pble(rf);
	} else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va,
				  aeq->mem.pa);
		aeq->mem.va = NULL;
	}
}

int sxe2_setup_aeq(struct sxe2_rdma_device *rdma_dev)
{
	int ret;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;

	ret = sxe2_rdma_create_aeq(rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: create aeq ret = %d\n", ret);
		goto end;
	}

	ret = drv_rdma_debug_aeq_add(rdma_dev, &rdma_dev->rdma_func->aeq);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"failed adding AEQ to debug file system, ret (%d)\n",
			ret);
		sxe2_del_aeq(rdma_dev);
		goto end;
	}

	ret = sxe2_cfg_aeq_vector(rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("ERR: cfg aeq vector failed. ret = %d\n",
				     ret);
		drv_rdma_debug_aeq_remove(rdma_dev, &rdma_dev->rdma_func->aeq);
		sxe2_del_aeq(rdma_dev);
		goto end;
	}

	if (!rf->msix_shared)
		sxe2_rdma_ena_intr(&rf->ctx_dev, rf->sxe2_msixtbl[0].idx);

	atomic_set(&rf->aeq_created, 1);
end:
	return ret;
}

int sxe2_drv_ceq_query(struct sxe2_rdma_ctx_ceq *ceq, u64 query_pa, u64 scratch,
		       bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = ceq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe				= (struct sxe2_eq_wqe *)wqe;
	eq_wqe->op			= SXE2_MQ_OP_QUERY_CEQ;
	eq_wqe->eqn			= ceq->ceq_id;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = query_pa >> SXE2_EQC_PHY_ADDR_OFFSET;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_ceq_query_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_ceq *ceq, u64 query_pa)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_QUERY_CEQ;
	mq_info->post_mq		 = 1;
	mq_info->in.u.ceq_query.ceq	 = ceq;
	mq_info->in.u.ceq_query.scratch	 = (uintptr_t)mq_request;
	mq_info->in.u.ceq_query.query_pa = query_pa;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle query ceq failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

int sxe2_drv_ceq_modify(struct sxe2_rdma_ctx_ceq *ceq,
			struct sxe2_rdma_eqc *ceqc, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = ceq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = ceqc->seqc.oi;
	eq_wqe->vsi_index     = ceqc->seqc.vsi_index;
	eq_wqe->sw_owner_bit  = ceqc->seqc.sw_owner_bit;
	eq_wqe->sw_status     = ceqc->seqc.sw_status;
	eq_wqe->uar_page      = ceqc->seqc.uar_page;
	eq_wqe->log_eq_size   = ceqc->seqc.log_eq_size;
	eq_wqe->pbl_mode      = ceqc->seqc.pbl_mode;
	eq_wqe->TPH_value     = ceqc->seqc.TPH_value;
	eq_wqe->TPH_en	      = ceqc->seqc.TPH_en;
	eq_wqe->page_offset   = ceqc->seqc.page_offset;
	eq_wqe->log_page_size = ceqc->seqc.log_page_size;
	eq_wqe->pbl_index     = ceqc->seqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_MODIFY_CEQ;
	eq_wqe->eqn			= ceq->ceq_id;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceqn");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_swState",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_swState");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_size",
		     &rdma_dev->rdma_func->mq.err_cqe_val, eq_wqe, ceq);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ceq_size");
#endif

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_ceq_modify_op(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_ceq *ceq,
			   struct sxe2_rdma_eqc *ceqc)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_MODIFY_CEQ;
	mq_info->post_mq		 = 1;
	mq_info->in.u.ceq_modify.ceq	 = ceq;
	mq_info->in.u.ceq_modify.scratch = (uintptr_t)mq_request;
	mq_info->in.u.ceq_modify.ceqc	 = ceqc;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle modify ceq failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

int sxe2_drv_aeq_query(struct sxe2_rdma_ctx_aeq *aeq, u64 query_pa, u64 scratch,
		       bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = aeq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe				= (struct sxe2_eq_wqe *)wqe;
	eq_wqe->op			= SXE2_MQ_OP_QUERY_AEQ;
	eq_wqe->eqn			= 0;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = query_pa >> SXE2_EQC_PHY_ADDR_OFFSET;

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_aeq_query_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_aeq *aeq, u64 query_pa)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_QUERY_AEQ;
	mq_info->post_mq		 = 1;
	mq_info->in.u.aeq_query.aeq	 = aeq;
	mq_info->in.u.aeq_query.scratch	 = (uintptr_t)mq_request;
	mq_info->in.u.aeq_query.query_pa = query_pa;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle query aeq failed, ret (%d)\n",
				     ret);

end:
	return ret;
}

int sxe2_drv_aeq_modify(struct sxe2_rdma_ctx_aeq *aeq,
			struct sxe2_rdma_eqc *aeqc, u64 scratch, bool post_sq)
{
	__le64 *wqe;
	struct sxe2_eq_wqe *eq_wqe;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;
	int ret;

	mq	 = aeq->dev->mq;
	rdma_dev = to_rdmadev(mq->dev);
	wqe	 = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get next wqe failed, ret (%d)\n", ret);
		goto end;
	}

	eq_wqe		      = (struct sxe2_eq_wqe *)wqe;
	eq_wqe->oi	      = aeqc->seqc.oi;
	eq_wqe->vsi_index     = aeqc->seqc.vsi_index;
	eq_wqe->sw_owner_bit  = aeqc->seqc.sw_owner_bit;
	eq_wqe->sw_status     = aeqc->seqc.sw_status;
	eq_wqe->uar_page      = aeqc->seqc.uar_page;
	eq_wqe->log_eq_size   = aeqc->seqc.log_eq_size;
	eq_wqe->pbl_mode      = aeqc->seqc.pbl_mode;
	eq_wqe->TPH_value     = aeqc->seqc.TPH_value;
	eq_wqe->TPH_en	      = aeqc->seqc.TPH_en;
	eq_wqe->page_offset   = aeqc->seqc.page_offset;
	eq_wqe->log_page_size = aeqc->seqc.log_page_size;
	eq_wqe->pbl_index     = aeqc->seqc.pbl_index;

	eq_wqe->op			= SXE2_MQ_OP_MODIFY_AEQ;
	eq_wqe->eqn			= 0;
	eq_wqe->WQE_Valid		= mq->polarity;
	eq_wqe->physical_buffer_address = 0;

	if (post_sq)
		sxe2_kpost_mq(mq);

	ret = 0;

end:
	return ret;
}

int sxe2_drv_aeq_modify_op(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_aeq *aeq,
			   struct sxe2_rdma_eqc *aeqc)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

	mq_info				 = &mq_request->info;
	mq_info->mq_cmd			 = MQ_OP_MODIFY_AEQ;
	mq_info->post_mq		 = 1;
	mq_info->in.u.aeq_modify.aeq	 = aeq;
	mq_info->in.u.aeq_modify.scratch = (uintptr_t)mq_request;
	mq_info->in.u.aeq_modify.aeqc	 = aeqc;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle modify aeq failed, ret (%d)\n", ret);

end:
	return ret;
}
