// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */
#include "main.h"
#include "user.h"
#include "icrdma_hw.h"
#include "hmc.h"
#include "smmu/kernel/adk_mmu600.h"

/* types of hmc objects */
enum zxdh_hmc_rsrc_type iw_hmc_obj_types[ZXDH_HMC_IW_TXWINDOW + 1] = {
	ZXDH_HMC_IW_QP, ZXDH_HMC_IW_CQ,	 ZXDH_HMC_IW_SRQ,      ZXDH_HMC_IW_AH,
	ZXDH_HMC_IW_MR, ZXDH_HMC_IW_IRD, ZXDH_HMC_IW_TXWINDOW,
};

/**
 * zxdh_iwarp_ce_handler - handle iwarp completions
 * @iwcq: iwarp cq receiving event
 */
static void zxdh_iwarp_ce_handler(struct zxdh_sc_cq *iwcq)
{
	struct zxdh_cq *cq = iwcq->back_cq;

	if (cq != NULL) {
		if (!cq->user_mode)
			cq->armed = false;
		if (cq->ibcq.comp_handler && (iwcq->cq_uk.valid_cq == true))
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
	}
}

static void zxdh_ceq_ena_intr(struct zxdh_sc_dev *dev, u32 ceq_id);

/**
 * zxdh_process_ceq - handle ceq for completions
 * @rf: RDMA PCI function
 * @ceq: ceq having cq for completion
 */
static void zxdh_process_ceq(struct zxdh_pci_f *rf, struct zxdh_ceq *ceq)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_sc_ceq *sc_ceq;
	struct zxdh_sc_cq *cq;
	unsigned long flags;

	sc_ceq = &ceq->sc_ceq;
	do {
		spin_lock_irqsave(&ceq->ce_lock, flags);
		cq = zxdh_sc_process_ceq(dev, sc_ceq);
		if (!cq) {
			spin_unlock_irqrestore(&ceq->ce_lock, flags);
			break;
		}
		if (cq->cq_type == ZXDH_CQ_TYPE_IO)
			zxdh_iwarp_ce_handler(cq);
		spin_unlock_irqrestore(&ceq->ce_lock, flags);

		if (cq->cq_type == ZXDH_CQ_TYPE_CQP) {
			rf->sc_dev.ceq_interrupt = true;
			queue_work(rf->cqp_cmpl_wq, &rf->cqp_cmpl_work);
		}
	} while (1);
}

static void zxdh_set_flush_fields_requester(struct zxdh_sc_qp *qp, struct zxdh_aeqe_info *info)
{
	switch (info->ae_id) {
	case ZXDH_AE_REQ_NVME_IDX_ERR:
	case ZXDH_AE_REQ_NVME_PD_IDX_ERR:
	case ZXDH_AE_REQ_NVME_KEY_ERR:
	case ZXDH_AE_REQ_NVME_ACC_ERR:
	case ZXDH_AE_REQ_NVME_TX_ROUTE_IDX_ERR:
	case ZXDH_AE_REQ_NVME_TX_ROUTE_PD_IDX_ERR:
	case ZXDH_AE_REQ_NVME_TX_ROUTE_KEY_ERR:
	case ZXDH_AE_REQ_NVME_TX_ROUTE_ACC_ERR:
	case ZXDH_AE_REQ_MW_INV_LKEY_ERR:
	case ZXDH_AE_REQ_MW_INV_TYPE_ERR:
	case ZXDH_AE_REQ_MW_INV_STATE_INV:
	case ZXDH_AE_REQ_MW_INV_PD_IDX_ERR:
	case ZXDH_AE_REQ_MW_INV_SHARE_MEM_ERR:
	case ZXDH_AE_REQ_MW_INV_PARENT_STATE_INV:
	case ZXDH_AE_REQ_MW_INV_MW_NUM_ZERO:
	case ZXDH_AE_REQ_MW_INV_MW_STAG_31_8_ZERO:
	case ZXDH_AE_REQ_MW_INV_QP_NUM_ERR:
	case ZXDH_AE_REQ_MR_INV_INV_LKEY_ERR:
	case ZXDH_AE_REQ_MR_INV_MW_NUM_ZERO:
	case ZXDH_AE_REQ_MR_INV_STATE_ERR:
	case ZXDH_AE_REQ_MR_INV_EN_ERR:
	case ZXDH_AE_REQ_MR_INV_SHARE_MEM_ERR:
	case ZXDH_AE_REQ_MR_INV_PD_IDX_ERR:
	case ZXDH_AE_REQ_MR_INV_MW_STAG_31_8_ZERO:
	case ZXDH_AE_REQ_MWBIND_WRITE_ACC_ERR:
	case ZXDH_AE_REQ_MWBIND_VA_BIND_ERR:
	case ZXDH_AE_REQ_MWBIND_PD_IDX_ERR:
	case ZXDH_AE_REQ_MWBIND_MRTE_STATE_TYPE_ERR:
	case ZXDH_AE_REQ_MWBIND_VA_LEN_ERR:
	case ZXDH_AE_REQ_MWBIND_TYPE_VA_ERR:
	case ZXDH_AE_REQ_MWBIND_TYPE_IDX_ERR:
	case ZXDH_AE_REQ_MWBIND_MRTE_MR_ERR:
	case ZXDH_AE_REQ_MWBIND_TYPE2_LEN_ERR:
	case ZXDH_AE_REQ_MWBIND_MRTE_STATE_ERR:
	case ZXDH_AE_REQ_MWBIND_QPC_EN_ERR:
	case ZXDH_AE_REQ_MWBIND_PARENT_MR_ERR:
	case ZXDH_AE_REQ_MWBIND_ACC_BIT4_ERR:
	case ZXDH_AE_REQ_MWBIND_MW_STAG_ERR:
	case ZXDH_AE_REQ_MWBIND_IDX_OUT_RANGE:
	case ZXDH_AE_REQ_MR_FASTREG_ACC_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_PD_IDX_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_MRTE_STATE_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_MR_IS_NOT_1:
	case ZXDH_AE_REQ_MR_FASTREG_QPC_EN_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_STAG_LEN_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_SHARE_MR_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_MW_STAG_ERR:
	case ZXDH_AE_REQ_MR_FASTREG_IDX_OUT_RANGE:
	case ZXDH_AE_REQ_MR_FASTREG_MR_EN_ERR:
	case ZXDH_AE_REQ_MW_BIND_PD_IDX_ERR:
	case ZXDH_AE_REQ_MRTE_STATE_FREE:
	case ZXDH_AE_REQ_MRTE_STATE_INVALID:
	case ZXDH_AE_REQ_MRTE_MW_QP_ID_ERR:
	case ZXDH_AE_REQ_MRTE_PD_IDX_ERR:
	case ZXDH_AE_REQ_MRTE_KEY_ERR:
	case ZXDH_AE_REQ_MRTE_STAG_IDX_RANGE_ERR:
	case ZXDH_AE_REQ_MRTE_VIRT_ADDR_AND_LEN_ERR:
	case ZXDH_AE_REQ_MRTE_ACC_ERR:
	case ZXDH_AE_REQ_MRTE_STAG_IDX_RANGE_RSV_ERR:
	case ZXDH_AE_REQ_REM_INV_RKEY:
	case ZXDH_AE_REQ_WQE_MRTE_STATE_FREE:
	case ZXDH_AE_REQ_WQE_MRTE_STATE_INV:
	case ZXDH_AE_REQ_WQE_MRTE_MW_QP_ID_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_PD_IDX_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_KEY_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_STAG_IDX_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_VIRT_ADDR_AND_LEN_CHK_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_ACC_ERR:
	case ZXDH_AE_REQ_WQE_MRTE_RSV_LKEY_EN_ERR:
		qp->event_type = ZXDH_QP_EVENT_ACCESS_ERR;
		break;
	case ZXDH_AE_REQ_REM_INV_OPCODE:
	case ZXDH_AE_REQ_OFED_INVALID_SQ_OPCODE:
	case ZXDH_AE_REQ_NVME_INVALID_SQ_OPCODE:
		qp->event_type = ZXDH_QP_EVENT_REQ_ERR;
		break;
	default:
		qp->event_type = ZXDH_QP_EVENT_CATASTROPHIC;
		break;
	}
}

static void zxdh_set_flush_fields_responder(struct zxdh_sc_qp *qp, struct zxdh_aeqe_info *info)
{
	switch (info->ae_id) {
	case ZXDH_AE_RSP_PRIFIELD_CHK_INV_OPCODE:
		qp->event_type = ZXDH_QP_EVENT_REQ_ERR;
		break;
	case ZXDH_AE_RSP_PKT_TYPE_NOF_PD_IDX_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_NOF_RKEY_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_NOF_ACC_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_DISTRIBUTE_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_INV_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_QP_CHK_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_PD_CHK_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_KEY_CHK_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_STAG_IDX_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_BOUNDARY_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_ACC_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MR_STAG0_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_STATE_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_PD_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_KEY_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_TYPE2B_QPN_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_KEY_IDX_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_SHARE_MR:
	case ZXDH_AE_RSP_PKT_TYPE_MW_TYPE_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_REM_INV_PD_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_REM_INV_KEY_ERR:
	case ZXDH_AE_RSP_PKT_TYPE_REM_INV_ACC_ERR:
	case ZXDH_AE_RSP_CHK_ERR_SHARE_MR:
	case ZXDH_AE_RSP_MW_NUM_ERR:
	case ZXDH_AE_RSP_INV_EN_ERR:
		qp->event_type = ZXDH_QP_EVENT_ACCESS_ERR;
		break;
	default:
		qp->event_type = ZXDH_QP_EVENT_CATASTROPHIC;
		break;
	}
}

int zxdh_set_smmu_invalid(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 cnt = 0, val = 0, status = 0;

	writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

	zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_OP_SET_SMMU_INVALID, 0x12, 0x13, 0x15, dev->vf_id);

	do {
		val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
		if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
			status = -ETIMEDOUT;
			pr_info("vhca_id:%d waiting completed SET_SMMU_INVALID mailbox too long time,timeout!\n",
				dev->vhca_id);
			break;
		}
		if (dev->hw_attrs.self_health == true) {
			status = -ETIMEDOUT;
			break;
		}
		udelay(ZXDH_MAILBOX_SLEEP_TIME);
	} while (!val);

	return status;
}

int zxdh_vf_init_hmc(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 cnt = 0, val = 0, status = 0;

	writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

	zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_VCHNL_OP_GET_HMC_FCN, 0x12, 0x13, 0x15, dev->vf_id);

	do {
		val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
		if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
			status = -ETIMEDOUT;
			pr_info("vhca_id:%d waiting completed GET_HMC mailbox too long time,timeout!\n",
				dev->vhca_id);
			break;
		}
		if (dev->hw_attrs.self_health == true) {
			status = -ETIMEDOUT;
			break;
		}
		udelay(ZXDH_MAILBOX_SLEEP_TIME);
	} while (!val);

	return status;
}

int zxdh_vf_init_np_tbl(struct zxdh_pci_f *rf)
{
	struct iidc_core_dev_info *cdev_info = rf->cdev;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 cnt = 0, val = 0, status = 0;

	if (!rf->sc_dev.np_mode_low_lat) {
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

		zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_OP_REQ_NP_CONFIG, cdev_info->vport_id, 0, 0,
					 dev->vf_id);
		do {
			val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
			if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
				pr_info("vhca_id:%d waiting completed NP_CONFIG mailbox too long time,timeout!\n",
					dev->vhca_id);
				status = -ETIMEDOUT;
				break;
			}
			if (dev->hw_attrs.self_health == true) {
				status = -ETIMEDOUT;
				break;
			}
			udelay(ZXDH_MAILBOX_SLEEP_TIME);
		} while (!val);

	} else {
		if (!rf->iwdev->netdev->dev_addr) {
			pr_err("[%s] dev_addr is null!\n", __func__);
			status = -EINVAL;
			return status;
		}

		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE));

		zxdh_sc_send_mailbox_cmd(dev, ZTE_ZXDH_OP_REQ_NP_MAC_ADD, cdev_info->vport_id,
					 (u64)rf->iwdev->netdev->dev_addr, 0, dev->vf_id);

		do {
			val = readl(dev->hw->hw_addr + C_RDMA_CQP_CQ_DISTRIBUTE_DONE);
			if (cnt++ > ZXDH_MAILBOX_CYC_NUM * dev->hw_attrs.max_done_count) {
				pr_info("vhca_id:%d waiting completed NP_MAC_ADD mailbox too long time,timeout!\n",
					dev->vhca_id);
				status = -ETIMEDOUT;
				break;
			}
			if (dev->hw_attrs.self_health == true) {
				status = -ETIMEDOUT;
				break;
			}
			udelay(ZXDH_MAILBOX_SLEEP_TIME);
		} while (!val);

		ether_addr_copy(rf->iwdev->mac_addr, rf->iwdev->netdev->dev_addr);
	}

	return status;
}

void zxdh_stop_cap_worker(struct work_struct *work)
{
	u32 reg_val = 0;
	struct aeq_stop_cap_work *aeq_stop_cap_work =
		container_of(work, struct aeq_stop_cap_work, work);
	struct zxdh_pci_f *rf = aeq_stop_cap_work->rf;

	kfree(aeq_stop_cap_work);
	if (rf->sc_dev.tx_stop_on_aeq == 1) {
		if (zxdh_rdma_reg_read(rf, RDMATX_DATA_START_CAP, &reg_val))
			pr_err("zxdh_rdma_reg_read RDMATX_DATA_START_CAP failed\n");
		if (reg_val != 0 && zxdh_rdma_reg_write(rf, RDMATX_DATA_START_CAP, 0))
			pr_err("zxdh_rdma_reg_write RDMATX_DATA_START_CAP failed\n");
		rf->sc_dev.tx_stop_on_aeq = 0;
	}

	if (rf->sc_dev.rx_stop_on_aeq == 1) {
		if (zxdh_rdma_reg_read(rf, RDMARX_DATA_START_CAP, &reg_val))
			pr_err("zxdh_rdma_reg_read RDMARX_DATA_START_CAP failed\n");
		if (reg_val != 0 && zxdh_rdma_reg_write(rf, RDMARX_DATA_START_CAP, 0))
			pr_err("zxdh_rdma_reg_write RDMARX_DATA_START_CAP failed\n");
		rf->sc_dev.rx_stop_on_aeq = 0;
	}
}

void zxdh_aeq_process_stop_cap(struct zxdh_pci_f *rf)
{
	struct aeq_stop_cap_work *stop_cap_work;

	stop_cap_work = kzalloc(sizeof(*stop_cap_work), GFP_ATOMIC);
	if (!stop_cap_work)
		return;

	stop_cap_work->rf = rf;
	INIT_WORK(&stop_cap_work->work, zxdh_stop_cap_worker);
	queue_work(rf->iwdev->cleanup_wq, &stop_cap_work->work);
}

void zrdma_cleanup_rdma_tools_cfg(struct zxdh_pci_f *rf)
{
	struct zxdh_cap_addr_info *cap_addr_info = NULL;
	int i;
	struct zxdh_device *iwdev = rf->iwdev;

	if (rf->sc_dev.tx_stop_on_aeq != 0)
		rf->sc_dev.tx_stop_on_aeq = 0;
	if (rf->sc_dev.rx_stop_on_aeq != 0)
		rf->sc_dev.rx_stop_on_aeq = 0;
	if (rf->sc_dev.hw_attrs.self_health == false) {
		if (zxdh_rdma_reg_write(rf, RDMATX_DATA_START_CAP, 0))
			pr_err("%s write RDMATX_DATA_START_CAP failed\n", __func__);
		if (zxdh_rdma_reg_write(rf, RDMARX_DATA_START_CAP, 0))
			pr_err("%s write RDMARX_DATA_START_CAP failed\n", __func__);
	}
	for (i = 0; i < CAP_NODE_NUM; i++) {
		free_cap_addr(iwdev, &iwdev->hw_data_cap.cap_tx_use_direct_dma[i]);
		free_cap_addr(iwdev, &iwdev->hw_data_cap.cap_rx_use_direct_dma[i]);
		cap_addr_info = &iwdev->hw_data_cap.cap_txrx_use_iova[i];
		if (cap_addr_info->entry_info.cap_mmap_entry != NULL) {
			rdma_user_mmap_entry_remove(cap_addr_info->entry_info.cap_mmap_entry);
			cap_addr_info->entry_info.cap_mmap_entry = NULL;
		}
		if (iwdev->hw_data_cap.cap_txrx_use_iova[i].addr_info.cap_iova_addr != 0)
			iwdev->hw_data_cap.cap_txrx_use_iova[i].addr_info.cap_iova_addr = 0;
	}
}

/**
 * zxdh_process_aeq - handle aeq events
 * @rf: RDMA PCI function
 */
static void zxdh_process_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_aeq *aeq = &rf->aeq;
	struct zxdh_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct zxdh_aeqe_info aeinfo;
	struct zxdh_aeqe_info *info = &aeinfo;
	int ret;
	struct zxdh_qp *iwqp = NULL;
	struct zxdh_cq *iwcq = NULL;
	struct zxdh_srq *iwsrq = NULL;
	struct zxdh_sc_qp *qp = NULL;
	unsigned long flags;
	struct ib_event ibevent;

	u32 aeqcnt = 0;

	if (!sc_aeq->size)
		return;

	do {
		memset(info, 0, sizeof(*info));
		ret = zxdh_sc_get_next_aeqe(sc_aeq, info);
		if (ret)
			break;

		aeqcnt++;
		zxdh_dbg(
			dev,
			"AEQ: ae_id = 0x%x bool qp=%d qp_id = %d tcp_state=%d iwarp_state=%d ae_src=%d\n",
			info->ae_id, info->qp, info->qp_cq_id, info->tcp_state, info->iwarp_state,
			info->ae_src);

		if (info->qp) {
			spin_lock_irqsave(&rf->qptable_lock, flags);
			if (info->qp_cq_id < dev->base_qpn) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				pr_err("qp information is valid,qpn < base_qpn, qpn:%d\n",
				       info->qp_cq_id);
				continue;
			} else if (info->qp_cq_id >= (dev->base_qpn + dev->max_qp)) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				pr_err("qp information is valid,qpn >= (base_qpn + max_qp), qpn:%d\n",
				       info->qp_cq_id);
				continue;
			}
			iwqp = rf->qp_table[info->qp_cq_id - dev->base_qpn];
			if (!iwqp) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				zxdh_dbg(dev, "AEQ: qp_id %d is already freed\n", info->qp_cq_id);
				continue;
			}
			zxdh_qp_add_ref(&iwqp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);
			qp = &iwqp->sc_qp;
			spin_lock_irqsave(&iwqp->lock, flags);
			iwqp->hw_iwarp_state = info->iwarp_state;
			iwqp->last_aeq = info->ae_id;
			spin_unlock_irqrestore(&iwqp->lock, flags);
		} else {
			if (info->ae_id == ZXDH_AE_REQ_WQE_FLUSH)
				continue;
			else if (info->ae_id == ZXDH_AE_RSP_WQE_FLUSH)
				continue;
			else if (info->ae_id == ZXDH_AE_REQ_WR_CQP_QP_STATE) {
				pr_info("[%s] cqp qp state err!\n", __func__);
				continue;
			}
		}

		if ((rf->sc_dev.tx_stop_on_aeq != 0 || rf->sc_dev.rx_stop_on_aeq != 0) &&
		    info->ae_id != ZXDH_AE_RSP_SRQ_WATER_SIG) {
			zxdh_aeq_process_stop_cap(rf);
		}

		switch (info->ae_id) {
		case ZXDH_AE_RSP_SRQ_WATER_SIG:
			spin_lock_irqsave(&rf->srqtable_lock, flags);
			if (info->qp_cq_id < dev->base_srqn) {
				spin_unlock_irqrestore(&rf->srqtable_lock, flags);
				pr_err("aeq srq water limit event,srqn < base_srqn, srqn:%d\n",
				       info->qp_cq_id);
				continue;
			} else if (info->qp_cq_id >= (dev->base_srqn + dev->max_srq)) {
				spin_unlock_irqrestore(&rf->srqtable_lock, flags);
				pr_err("aeq srq water limit event,srqn >= (base_srqn + max_srq), srqn:%d\n",
				       info->qp_cq_id);
				continue;
			}
			iwsrq = rf->srq_table[info->qp_cq_id - dev->base_srqn];
			if (!iwsrq) {
				spin_unlock_irqrestore(&rf->srqtable_lock, flags);
				zxdh_dbg(dev, "AEQ: srq_id %d is already freed\n", info->qp_cq_id);
				continue;
			}
			zxdh_srq_add_ref(&iwsrq->ibsrq);
			spin_unlock_irqrestore(&rf->srqtable_lock, flags);
			if (iwsrq->ibsrq.event_handler) {
				ibevent.device = iwsrq->ibsrq.device;
				ibevent.event = IB_EVENT_SRQ_LIMIT_REACHED;
				ibevent.element.srq = &iwsrq->ibsrq;
				iwsrq->ibsrq.event_handler(&ibevent, iwsrq->ibsrq.srq_context);
			}
			zxdh_srq_rem_ref(&iwsrq->ibsrq);
			break;
		case ZXDH_AE_RSP_PKT_TYPE_CQ_OVERFLOW:
		case ZXDH_AE_RSP_PKT_TYPE_CQ_TWO_PBLE_RSP:
			dev_err(idev_to_dev(dev), "Processing CQ[0x%x] op error, AE 0x%04X\n",
				info->qp_cq_id, info->ae_id);
			spin_lock_irqsave(&rf->cqtable_lock, flags);
			if (info->qp_cq_id < dev->base_cqn) {
				spin_unlock_irqrestore(&rf->cqtable_lock, flags);
				pr_err("aeq cq err, cqn < base_cqn cqn:%d\n", info->qp_cq_id);
				continue;
			} else if (info->qp_cq_id >= (dev->base_cqn + dev->max_cq)) {
				spin_unlock_irqrestore(&rf->cqtable_lock, flags);
				pr_err("aeq cq err, cqn >= (base_cqn + max_cq) cqn:%d\n",
				       info->qp_cq_id);
				continue;
			}
			iwcq = rf->cq_table[info->qp_cq_id - dev->base_cqn];
			if (!iwcq) {
				spin_unlock_irqrestore(&rf->cqtable_lock, flags);
				zxdh_dbg(dev, "AEQ: cq_id %d is already freed\n", info->qp_cq_id);
				continue;
			}
			zxdh_cq_add_ref(&iwcq->ibcq);
			spin_unlock_irqrestore(&rf->cqtable_lock, flags);
			if (iwcq->ibcq.event_handler) {
				ibevent.device = iwcq->ibcq.device;
				ibevent.event = IB_EVENT_CQ_ERR;
				ibevent.element.cq = &iwcq->ibcq;
				iwcq->ibcq.event_handler(&ibevent, iwcq->ibcq.cq_context);
			}
			zxdh_cq_rem_ref(&iwcq->ibcq);
			break;
		case ZXDH_AE_RSP_SRQ_AXI_RSP_SIG:

			spin_lock_irqsave(&rf->qptable_lock, flags);
			if (info->qp_cq_id < dev->base_qpn) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				pr_err("aeq srq axi err, qpn < base_qpn qpn:%d\n", info->qp_cq_id);
				continue;
			} else if (info->qp_cq_id >= (dev->base_qpn + dev->max_qp)) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				pr_err("aeq srq axi err, qpn >= (base_qpn + max_qp) qpn:%d\n",
				       info->qp_cq_id);
				continue;
			}
			iwqp = rf->qp_table[info->qp_cq_id - dev->base_qpn];
			if (!iwqp) {
				spin_unlock_irqrestore(&rf->qptable_lock, flags);
				zxdh_dbg(dev, "AEQ: qp_id %d is already freed\n", info->qp_cq_id);
				continue;
			}
			spin_unlock_irqrestore(&rf->qptable_lock, flags);

			if (iwqp->is_srq == false) {
				pr_err("aeq srq axi err, qp is not bound to srq\n");
				continue;
			}
			iwsrq = iwqp->iwsrq;

			spin_lock_irqsave(&rf->srqtable_lock, flags);
			if (!iwsrq) {
				spin_unlock_irqrestore(&rf->srqtable_lock, flags);
				zxdh_dbg(dev, "AEQ: srq_id %d is already freed\n", info->qp_cq_id);
				continue;
			}
			zxdh_srq_add_ref(&iwsrq->ibsrq);
			spin_unlock_irqrestore(&rf->srqtable_lock, flags);
			if (iwsrq->ibsrq.event_handler) {
				ibevent.device = iwsrq->ibsrq.device;
				ibevent.event = IB_EVENT_SRQ_ERR;
				ibevent.element.srq = &iwsrq->ibsrq;
				iwsrq->ibsrq.event_handler(&ibevent, iwsrq->ibsrq.srq_context);
			}
			zxdh_srq_rem_ref(&iwsrq->ibsrq);
			break;
		case ZXDH_AE_RSP_WQE_FLUSH:
			if (iwqp && iwqp->is_srq == true) {
				if (iwqp->ibqp.event_handler) {
					ibevent.device = iwqp->ibqp.device;
					ibevent.event = IB_EVENT_QP_LAST_WQE_REACHED;
					ibevent.element.qp = &iwqp->ibqp;
					iwqp->ibqp.event_handler(&ibevent, iwqp->ibqp.qp_context);
				}
			}
			break;
		case ZXDH_AE_REQ_RETRY_EXC_LOC_ACK_OUT_RANGE:
			// 0x8f3��������
			if (iwqp)
				zxdh_aeq_process_retry_err(iwqp);

			break;
		case ZXDH_AE_REQ_RETRY_EXC_TX_WINDOW_GET_ENTRY_ERR:
			// 0x8f5��������
			if (iwqp)
				zxdh_aeq_process_entry_err(iwqp);

			break;
		default:
			if (!qp)
				break;

			if (info->ae_src == ZXDH_AE_REQUESTER) { //requestor
				zxdh_set_flush_fields_requester(qp, info);
			} else if (info->ae_src == ZXDH_AE_RESPONDER) { //responder
				zxdh_set_flush_fields_responder(qp, info);
			} else {
				pr_err("bad ae_src, ae_src:%d\n", info->ae_src);
				break;
			}
			if (iwqp)
				zxdh_aeq_qp_disconn(iwqp);

			break;
		}

		if (info->qp)
			zxdh_qp_rem_ref(&iwqp->ibqp);
	} while (1);

	if (aeqcnt)
		zxdh_sc_repost_aeq_tail(dev, sc_aeq->aeq_ring.tail);
}

/**
 * zxdh_ceq_ena_intr - set up device interrupts
 * @dev: hardware control device structure
 * @ceq_id: ceq of the interrupt to be enabled
 */
static void zxdh_ceq_ena_intr(struct zxdh_sc_dev *dev, u32 ceq_id)
{
	dev->irq_ops->zxdh_ceq_en_irq(dev, ceq_id);
}

/**
 * zxdh_aeq_ena_intr - set up device interrupts
 * @dev: hardware control device structure
 * @enable: aeq of the interrupt to be enabled
 */
static void zxdh_aeq_ena_intr(struct zxdh_sc_dev *dev, bool enable)
{
	dev->irq_ops->zxdh_aeq_en_irq(dev, enable);
}

/**
 * zxdh_dpc - tasklet for aeq and ceq 0
 * @t: tasklet_struct ptr
 */
static void zxdh_dpc(struct tasklet_struct *t)
{
	struct zxdh_pci_f *rf = from_tasklet(rf, t, dpc_tasklet);

	zxdh_process_aeq(rf);
	zxdh_aeq_ena_intr(&rf->sc_dev, true);
}

/**
 * zxdh_ceq_dpc - dpc handler for CEQ
 * @t: tasklet_struct ptr
 */
static void zxdh_ceq_dpc(struct tasklet_struct *t)
{
	struct zxdh_ceq *iwceq = from_tasklet(iwceq, t, dpc_tasklet);
	struct zxdh_pci_f *rf = iwceq->rf;

	zxdh_process_ceq(rf, iwceq);
	zxdh_ceq_ena_intr(&rf->sc_dev, iwceq->sc_ceq.ceq_id);
}

/**
 * zxdh_save_msix_info - copy msix vector information to iwarp device
 * @rf: RDMA PCI function
 *
 * Allocate iwdev msix table and copy the msix info to the table
 * Return 0 if successful, otherwise return error
 */
static int zxdh_save_msix_info(struct zxdh_pci_f *rf)
{
	struct zxdh_qvlist_info *iw_qvlist;
	struct zxdh_qv_info *iw_qvinfo;
#ifdef MSIX_DEBUG
	struct msix_entry *pmsix;
#else
	u32 vector;
	u16 entry;
#endif
	u32 ceq_idx;
	u32 i;
	u32 size;
	u32 online_cpus_num;

	if (!rf->msix_count)
		return -EINVAL;

	size = sizeof(struct zxdh_msix_vector) * rf->msix_count;
	size += sizeof(struct zxdh_qvlist_info);
	size += sizeof(struct zxdh_qv_info) * rf->msix_count - 1;
	rf->iw_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->iw_msixtbl)
		return -ENOMEM;

	rf->iw_qvlist = (struct zxdh_qvlist_info *)(&rf->iw_msixtbl[rf->msix_count]);
	iw_qvlist = rf->iw_qvlist;
	iw_qvinfo = iw_qvlist->qv_info;
	iw_qvlist->num_vectors = rf->msix_count;
	online_cpus_num = num_online_cpus();
#ifdef MSIX_DEBUG
	pmsix = rf->msix_entries;
#else
	entry = rf->msix_entries->entry;
#endif

#ifdef MSIX_SUPPORT
	for (i = 0, ceq_idx = 0; i < rf->msix_count; i++, iw_qvinfo++) {
#ifdef MSIX_DEBUG
		rf->iw_msixtbl[i].idx = pmsix->entry;
		rf->iw_msixtbl[i].irq = pmsix->vector;
#else
		rf->iw_msixtbl[i].idx = entry + i;
		vector = pci_irq_vector(rf->pcidev, (entry + i));
		rf->iw_msixtbl[i].irq = vector;
#endif
		if (rf->msix_count <= (online_cpus_num + 1))
			rf->iw_msixtbl[i].cpu_affinity = ceq_idx;
		else
			rf->iw_msixtbl[i].cpu_affinity = (ceq_idx % online_cpus_num);
		if (!i) {
			iw_qvinfo->aeq_idx = 0;
			iw_qvinfo->ceq_idx = ZXDH_Q_INVALID_IDX;
		} else {
			iw_qvinfo->aeq_idx = ZXDH_Q_INVALID_IDX;
			iw_qvinfo->ceq_idx = ceq_idx++;
		}
		iw_qvinfo->itr_idx = ZXDH_IDX_NOITR;
		iw_qvinfo->v_idx = rf->iw_msixtbl[i].idx;
#ifdef MSIX_DEBUG
		pmsix++;
#endif
	}
#endif
	return 0;
}

/**
 * zxdh_aeq_handler - interrupt handler for aeq
 * @irq: Interrupt request number
 * @data: RDMA PCI function
 */
static irqreturn_t zxdh_aeq_handler(int irq, void *data)
{
	struct zxdh_pci_f *rf = data;

	tasklet_schedule(&rf->dpc_tasklet);

	return IRQ_HANDLED;
}

/**
 * zxdh_ceq_handler - interrupt handler for ceq
 * @irq: interrupt request number
 * @data: ceq pointer
 */
static irqreturn_t zxdh_ceq_handler(int irq, void *data)
{
	struct zxdh_ceq *iwceq = data;

	if (iwceq->irq != irq)
		dev_err(idev_to_dev(&iwceq->rf->sc_dev), "expected irq = %d received irq = %d\n",
			iwceq->irq, irq);
	tasklet_schedule(&iwceq->dpc_tasklet);

	return IRQ_HANDLED;
}

/**
 * zxdh_destroy_irq - destroy device interrupts
 * @msix_vec: msix vector to disable irq
 * @dev_id: parameter to pass to free_irq (used during irq setup)
 *
 * The function is called when destroying aeq/ceq
 */
static void zxdh_destroy_irq(struct zxdh_msix_vector *msix_vec, void *dev_id)
{
	irq_set_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
}

/**
 * zxdh_destroy_cqp  - destroy control qp
 * @rf: RDMA PCI function
 * @free_hwcqp: 1 if hw cqp should be freed
 *
 * Issue destroy cqp request and
 * free the resources associated with the cqp
 */
static void zxdh_destroy_cqp(struct zxdh_pci_f *rf, bool free_hwcqp)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_cqp *cqp = &rf->cqp;
	int status = 0;

	if (rf->cqp_cmpl_wq)
		destroy_workqueue(rf->cqp_cmpl_wq);
	status = zxdh_sc_cqp_destroy(dev->cqp, free_hwcqp);
	if (status)
		zxdh_dbg(dev, "ERR: Destroy CQP failed %d\n", status);

	zxdh_cleanup_pending_cqp_op(rf);
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va, cqp->sq.pa);
	cqp->sq.va = NULL;
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;
}

static void zxdh_destroy_virt_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_aeq *aeq = &rf->aeq;
	u32 pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);
	dma_addr_t *pg_arr = (dma_addr_t *)aeq->palloc.level1.addr;

	zxdh_unmap_vm_page_list(&rf->hw, pg_arr, pg_cnt);
	zxdh_free_pble(rf->pble_rsrc, &aeq->palloc);
	vfree(aeq->mem.va);
}

static int zxdh_destroy_aeq_reg_cmd(struct zxdh_sc_dev *dev, struct zxdh_sc_aeq *aeq)
{
	struct zxdh_sc_cqp *cqp;
	__le64 *wqe;
	u64 hdr;
	u32 tail = 0, val = 0;
	int ret_code = 0;
	u64 scratch = 0;

	cqp = dev->cqp;
	wqe = zxdh_sc_cqp_get_next_send_wqe(cqp, scratch);
	if (!wqe)
		return -ENOSPC;

	hdr = FIELD_PREP(ZXDH_AEQC_INTR_IDX, aeq->msix_idx) | FIELD_PREP(ZXDH_AEQC_AEQ_HEAD, 0) |
	      FIELD_PREP(ZXDH_AEQC_LEAF_PBL_SIZE, aeq->pbl_chunk_size) |
	      FIELD_PREP(ZXDH_AEQC_VIRTUALLY_MAPPED, aeq->virtual_map) |
	      FIELD_PREP(ZXDH_AEQC_AEQ_SIZE, aeq->elem_cnt) | FIELD_PREP(ZXDH_AEQC_AEQ_STATE, 1);
	dma_wmb();
	set_64bit_val(wqe, 8, hdr);

	set_64bit_val(wqe, 16, aeq->virtual_map ? aeq->first_pm_pbl_idx : aeq->aeq_elem_pa);

	hdr = FIELD_PREP(ZXDH_CQPSQ_OPCODE, ZXDH_CQP_OP_DESTROY_AEQ) |
	      FIELD_PREP(ZXDH_CQPSQ_WQEVALID, cqp->polarity);
	dma_wmb(); /* make sure WQE is written before valid bit is set */

	set_64bit_val(wqe, 0, hdr);

	print_hex_dump_debug("WQE: AEQ_DESTROY WQE", DUMP_PREFIX_OFFSET, 16, 8, wqe,
			     ZXDH_CQP_WQE_SIZE * 8, false);

	val = readl(dev->hw->hw_addr + C_RDMA_CQP_TAIL);
	tail = (u32)FIELD_GET(ZXDH_CQPTAIL_WQTAIL, val);

	zxdh_sc_cqp_post_sq(cqp);

	ret_code = zxdh_cqp_poll_registers(cqp, tail, dev->hw_attrs.max_done_count);

	if (ret_code)
		return ret_code;

	return 0;
}

/**
 * zxdh_destroy_aeq_reg - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
static void zxdh_destroy_aeq_reg(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_aeq *aeq = &rf->aeq;
	int status = -EBUSY;
#ifdef MSIX_SUPPORT
	zxdh_destroy_irq(rf->iw_msixtbl, rf);
#endif
	aeq->sc_aeq.size = 0;
	status = zxdh_destroy_aeq_reg_cmd(dev, &aeq->sc_aeq);
	if (status)
		zxdh_dbg(dev, "ERR: Destroy AEQ failed %d\n", status);

	if (aeq->virtual_map)
		zxdh_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va, aeq->mem.pa);
		aeq->mem.va = NULL;
	}
}

/**
 * zxdh_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
static void zxdh_destroy_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_aeq *aeq = &rf->aeq;
	int status = -EBUSY;
#ifdef MSIX_SUPPORT
	if (aeq->irq_sta == true) {
		aeq->irq_sta = false;
		zxdh_destroy_irq(rf->iw_msixtbl, rf);
	}
#endif
	aeq->sc_aeq.size = 0;
	status = zxdh_cqp_aeq_cmd(dev, &aeq->sc_aeq, ZXDH_OP_AEQ_DESTROY);
	if (status)
		zxdh_dbg(dev, "ERR: Destroy AEQ failed %d\n", status);

	if (aeq->virtual_map)
		zxdh_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va, aeq->mem.pa);
		aeq->mem.va = NULL;
	}
}

/**
 * zxdh_destroy_ceq - destroy ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq to be destroyed
 *
 * Issue a destroy ceq request and
 * free the resources associated with the ceq
 */
static void zxdh_destroy_ceq(struct zxdh_pci_f *rf, struct zxdh_ceq *iwceq)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	int status;
	unsigned long flags;

	if (rf->reset)
		goto exit;

	status = zxdh_sc_ceq_destroy(&iwceq->sc_ceq, 0, 1);
	if (status) {
		zxdh_dbg(dev, "ERR: CEQ destroy command failed %d\n", status);
		goto exit;
	}

	status = zxdh_sc_cceq_destroy_done(&iwceq->sc_ceq);
	if (status)
		zxdh_dbg(dev, "ERR: CEQ destroy completion failed %d\n", status);
exit:
	spin_lock_irqsave(&iwceq->ce_lock, flags);
	iwceq->sc_ceq.valid_ceq = false;
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);
	dma_free_coherent(dev->hw->device, iwceq->mem.size, iwceq->mem.va, iwceq->mem.pa);
	iwceq->mem.va = NULL;
}

/**
 * zxdh_del_ceq_0 - destroy ceq 0
 * @rf: RDMA PCI function
 *
 * Disable the ceq 0 interrupt and destroy the ceq 0
 */
static void zxdh_del_ceq_0(struct zxdh_pci_f *rf)
{
	struct zxdh_ceq *iwceq = rf->ceqlist;
	struct zxdh_msix_vector *msix_vec;

	msix_vec = &rf->iw_msixtbl[1];

#ifdef MSIX_SUPPORT
	if (iwceq->irq_sta == true) {
		iwceq->irq_sta = false;
		zxdh_destroy_irq(msix_vec, iwceq);
	}
#endif
	zxdh_destroy_ceq(rf, iwceq);
	rf->sc_dev.ceq_valid = false;
	rf->ceqs_count = 0;
}

/**
 * zxdh_del_ceqs - destroy all ceq's except CEQ 0
 * @rf: RDMA PCI function
 *
 * Go through all of the device ceq's, except 0, and for each
 * ceq disable the ceq interrupt and destroy the ceq
 */
static void zxdh_del_ceqs(struct zxdh_pci_f *rf)
{
	struct zxdh_ceq *iwceq = &rf->ceqlist[1];

	struct zxdh_msix_vector *msix_vec;
	u32 i = 0;
	unsigned long flags;

	msix_vec = &rf->iw_msixtbl[2];
	for (i = 1; i < rf->ceqs_count; i++, msix_vec++, iwceq++) {
#ifdef MSIX_SUPPORT
		if (iwceq->irq_sta == true) {
			iwceq->irq_sta = false;
			zxdh_destroy_irq(msix_vec, iwceq);
		}
#endif
		zxdh_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq, ZXDH_OP_CEQ_DESTROY);
		spin_lock_irqsave(&iwceq->ce_lock, flags);
		iwceq->sc_ceq.valid_ceq = false;
		spin_unlock_irqrestore(&iwceq->ce_lock, flags);
		dma_free_coherent(rf->sc_dev.hw->device, iwceq->mem.size, iwceq->mem.va,
				  iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}

	rf->ceqs_count = 1;
}

/**
 * zxdh_destroy_ccq - destroy control cq
 * @rf: RDMA PCI function
 *
 * Issue destroy ccq request and
 * free the resources associated with the ccq
 */
static void zxdh_destroy_ccq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_ccq *ccq = &rf->ccq;
	int status = 0;

	if (!rf->reset)
		status = zxdh_sc_ccq_destroy(dev->ccq, 0, true);
	if (status)
		zxdh_dbg(dev, "ERR: CCQ destroy failed %d\n", status);
	dma_free_coherent(dev->hw->device, ccq->mem_cq.size, ccq->mem_cq.va, ccq->mem_cq.pa);
	ccq->mem_cq.va = NULL;
	dma_free_coherent(dev->hw->device, ccq->shadow_area.size, ccq->shadow_area.va,
			  ccq->shadow_area.pa);
	ccq->shadow_area.va = NULL;
	zxdh_free_rsrc(rf, rf->allocated_cqs, ccq->sc_cq.cq_uk.cq_id - dev->base_cqn);
}

void zxdh_del_data_cap_objects(struct zxdh_sc_dev *dev)
{
	unsigned int i;
	struct zxdh_hmc_sd_entry *sd_entry;
	struct zxdh_dma_mem *mem = NULL;

	for (i = 0; i < dev->data_cap_sd.sd_cnt; i++) {
		if (!dev->data_cap_sd.entry[i].valid)
			continue;

		sd_entry = &dev->data_cap_sd.entry[i];
		mem = &sd_entry->u.bp.addr;
		if (!mem || !mem->va)
			pr_err("HMC: error cqp sd mem\n");
		else {
			dma_free_coherent(dev->hw->device, mem->size, mem->va, mem->pa);
			mem->va = NULL;
		}
	}
}

void zxdh_del_hmc_objects(struct zxdh_sc_dev *dev, struct zxdh_hmc_info *hmc_info)
{
	unsigned int i, sd_idx;
	u32 del_sd_cnt = 0;
	struct zxdh_hmc_sd_entry *sd_entry;
	struct zxdh_dma_mem *mem = NULL;
	struct zxdh_dma_mem *mem_harware = NULL;

	for (i = 0; i < hmc_info->hmc_entry_total; i++) {
		if (!hmc_info->sd_table.sd_entry[i].valid)
			continue;
		zxdh_prep_remove_sd_bp(hmc_info, i);
		hmc_info->sd_indexes[del_sd_cnt] = (u16)i;
		del_sd_cnt++;
	}

	for (i = 0; i < del_sd_cnt; i++) {
		sd_idx = hmc_info->sd_indexes[i];
		sd_entry = &hmc_info->sd_table.sd_entry[sd_idx];
		mem = &sd_entry->u.bp.addr;
		if (!mem || !mem->va)
			pr_err("HMC: error cqp sd mem\n");
		else {
			dma_free_coherent(dev->hw->device, mem->size, mem->va, mem->pa);
			mem->va = NULL;
		}

		mem_harware = &sd_entry->u.bp.addr_hardware;
		if (mem_harware && mem_harware->va) {
			dma_free_coherent(dev->hw->device, mem_harware->size, mem_harware->va,
					  mem_harware->pa);
			mem_harware->va = NULL;
		}
	}
}

/**
 * zxdh_create_hmc_objs - create all hmc objects for the device
 * @rf: RDMA PCI function
 * @privileged: permission to create HMC objects
 *
 * Create the device hmc objects and allocate hmc pages
 * Return 0 if successful, otherwise clean up and return error
 */
static int zxdh_create_hmc_objs(struct zxdh_pci_f *rf, bool privileged)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_hmc_create_obj_info info = {};
	int i, status = 0;

	info.hmc_info = dev->hmc_info;
	info.privileged = privileged;
	info.add_sd_cnt = 0;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt) {
			info.rsrc_type = iw_hmc_obj_types[i];
			info.count = dev->hmc_info->hmc_obj[info.rsrc_type].cnt;
			status = zxdh_sc_create_hmc_obj(dev, &info);
			if (status) {
				zxdh_del_hmc_objects(&rf->sc_dev, rf->sc_dev.hmc_info);
				zxdh_dbg(dev, "ERR: create obj type %d status = %d\n",
					 iw_hmc_obj_types[i], status);
				break;
			}
		}
	}

	return status;
}

static int zxdh_create_hmcobjs_dpuddr(struct zxdh_pci_f *rf)
{
	u32 sd_lmt, hmc_entry_total = 0, j = 0, k = 0, mem_size = 0, cnt = 0;
	u64 fpm_limit = 0;
	struct zxdh_hmc_info *hmc_info;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_virt_mem virt_mem = {};
	struct zxdh_hmc_obj_info *obj_info;

	hmc_info = dev->hmc_info;

	zxdh_hmc_dpu_capability(dev);
	for (k = 0; k < ZXDH_HMC_IW_MAX; k++)
		zxdh_sc_write_hmc_register(dev, hmc_info->hmc_obj, k, dev->vhca_id);

	obj_info = hmc_info->hmc_obj;
	for (k = ZXDH_HMC_IW_PBLE; k < ZXDH_HMC_IW_MAX; k++) {
		cnt = obj_info[k].cnt;

		fpm_limit = obj_info[k].size * cnt;

		if (fpm_limit == 0)
			continue;

		if (k == ZXDH_HMC_IW_PBLE)
			hmc_info->hmc_first_entry_pble = hmc_entry_total;

		if (k == ZXDH_HMC_IW_PBLE_MR)
			hmc_info->hmc_first_entry_pble_mr = hmc_entry_total;

		sd_lmt = (u32)((fpm_limit - 1) / ZXDH_HMC_DIRECT_BP_SIZE);
		sd_lmt += 1;

		if (sd_lmt == 1) {
			hmc_entry_total++;
		} else {
			for (j = 0; j < sd_lmt - 1; j++)
				hmc_entry_total++;

			if (fpm_limit % ZXDH_HMC_DIRECT_BP_SIZE)
				hmc_entry_total++;
		}
	}

	mem_size = sizeof(struct zxdh_hmc_sd_entry) * hmc_entry_total;
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va) {
		zxdh_dbg(dev, "HMC: failed to allocate memory for sd_entry buffer\n");
		return -ENOMEM;
	}
	hmc_info->sd_table.sd_entry = virt_mem.va;
	hmc_info->hmc_entry_total = hmc_entry_total;

	return 0;
}

/**
 * zxdh_create_cqp - create control qp
 * @rf: RDMA PCI function
 *
 * Return 0, if the cqp and all the resources associated with it
 * are successfully created, otherwise return error
 */
static int zxdh_create_cqp(struct zxdh_pci_f *rf)
{
	u32 sqsize = ZXDH_CQP_SW_SQSIZE_2048;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_cqp_init_info cqp_init_info = {};
	struct zxdh_cqp *cqp = &rf->cqp; // this struct will be transferred to CQE.
	u16 maj_err, min_err;
	int i, status;

	cqp->cqp_requests = kcalloc(sqsize, sizeof(*cqp->cqp_requests), GFP_KERNEL);
	if (!cqp->cqp_requests)
		return -ENOMEM;

	cqp->scratch_array = kcalloc(sqsize, sizeof(*cqp->scratch_array), GFP_KERNEL);
	if (!cqp->scratch_array) {
		status = -ENOMEM;
		goto err_scratch;
	}

	dev->cqp = &cqp->sc_cqp;
	dev->cqp->dev = dev;
	cqp->sq.size = ALIGN(sizeof(struct zxdh_cqp_sq_wqe) * sqsize, ZXDH_CQP_ALIGNMENT);
	cqp->sq.va = dma_alloc_coherent(dev->hw->device, cqp->sq.size, &cqp->sq.pa, GFP_KERNEL);
	if (!cqp->sq.va) {
		status = -ENOMEM;
		goto err_sq;
	}

	// populate the cqp init info
	cqp_init_info.dev = dev;
	cqp_init_info.sq_size = sqsize;
	cqp_init_info.sq = cqp->sq.va;
	cqp_init_info.sq_pa = cqp->sq.pa;
	if (dev->privileged) {
		cqp_init_info.hmc_profile = rf->rsrc_profile;
		cqp_init_info.ena_vf_count = rf->max_rdma_vfs;
	}
	cqp_init_info.scratch_array = cqp->scratch_array;
	cqp_init_info.protocol_used = rf->protocol_used;
	memcpy(&cqp_init_info.dcqcn_params, &rf->dcqcn_params, sizeof(cqp_init_info.dcqcn_params));

	cqp_init_info.hw_maj_ver = ZXDH_CQPHC_HW_MAJVER_GEN_2;
	status = zxdh_sc_cqp_init(dev->cqp, &cqp_init_info);
	if (status) {
		pr_err("ERR: cqp init status %d\n", status);
		goto err_ctx;
	}

	spin_lock_init(&cqp->req_lock);
	spin_lock_init(&cqp->compl_lock);

	status = zxdh_sc_cqp_create(dev->cqp, &maj_err, &min_err);
	if (status) {
		zxdh_dbg(dev, "ERR: cqp create failed - status %d maj_err %d min_err %d\n", status,
			 maj_err, min_err);
		goto err_create;
	}

	INIT_LIST_HEAD(&cqp->cqp_avail_reqs);
	INIT_LIST_HEAD(&cqp->cqp_pending_reqs);

	/* init the waitqueue of the cqp_requests and add them to the list */
	for (i = 0; i < sqsize; i++) {
		init_waitqueue_head(&cqp->cqp_requests[i].waitq);
		list_add_tail(&cqp->cqp_requests[i].list, &cqp->cqp_avail_reqs);
	}
	init_waitqueue_head(&cqp->remove_wq);
	return 0;

err_create:
err_ctx:
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va, cqp->sq.pa);
	cqp->sq.va = NULL;
err_sq:
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
err_scratch:
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;

	return status;
}

/**
 * zxdh_create_ccq - create control cq
 * @rf: RDMA PCI function
 *
 * Return 0, if the ccq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int zxdh_create_ccq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_ccq_init_info info = {};
	struct zxdh_ccq *ccq = &rf->ccq;
	u32 cq_num = 0;
	int status;

	status = zxdh_alloc_rsrc(rf, rf->allocated_cqs, rf->max_cq, &cq_num,
				 &rf->next_cq); /* cq_num is the allocated cq_id. */
	if (status)
		return status;
	cq_num += dev->base_cqn;
	info.cq_num = cq_num;
	dev->ccq = &ccq->sc_cq;
	dev->ccq->dev = dev;
	info.dev = dev;
	ccq->shadow_area.size = sizeof(struct zxdh_cq_shadow_area);
	ccq->mem_cq.size = ALIGN(sizeof(struct zxdh_cqe) * IW_CCQ_SIZE, ZXDH_CQ0_ALIGNMENT);
	ccq->mem_cq.va =
		dma_alloc_coherent(dev->hw->device, ccq->mem_cq.size, &ccq->mem_cq.pa, GFP_KERNEL);
	if (!ccq->mem_cq.va)
		return -ENOMEM;

	ccq->shadow_area.va = dma_alloc_coherent(dev->hw->device, ccq->shadow_area.size,
						 &ccq->shadow_area.pa, GFP_KERNEL);
	if (!ccq->shadow_area.va) {
		dma_free_coherent(dev->hw->device, ccq->mem_cq.size, ccq->mem_cq.va,
				  ccq->mem_cq.pa);
		ccq->mem_cq.va = NULL;
		zxdh_free_rsrc(rf, rf->allocated_cqs, cq_num - dev->base_cqn);
		return -ENOMEM;
	}

	ccq->sc_cq.back_cq = ccq;
	/* populate the ccq init info */
	info.cq_base = ccq->mem_cq.va;
	info.cq_pa = ccq->mem_cq.pa;
	info.num_elem = IW_CCQ_SIZE;
	info.shadow_area = ccq->shadow_area.va;
	info.shadow_area_pa = ccq->shadow_area.pa;
	info.ceqe_mask = false;
	info.ceq_id_valid = true;
	info.ceq_id = dev->base_ceqn;
	info.ceq_index = 0;
	info.shadow_read_threshold = 16;
	info.cqe_size = ZXDH_CQE_SIZE_64;
	info.cq_max = 0;
	info.cq_period = 0;
	info.scqe_break_moderation_en = false;
	info.cq_st = 0;
	info.is_in_list_cnt = 0;

	status = zxdh_sc_ccq_init(dev->ccq, &info);
	if (status)
		goto exit;

	status = zxdh_sc_ccq_create(dev->ccq, 0, true);
exit:
	if (status) {
		dma_free_coherent(dev->hw->device, ccq->mem_cq.size, ccq->mem_cq.va,
				  ccq->mem_cq.pa);
		ccq->mem_cq.va = NULL;
		dma_free_coherent(dev->hw->device, ccq->shadow_area.size, ccq->shadow_area.va,
				  ccq->shadow_area.pa);
		ccq->shadow_area.va = NULL;
		zxdh_free_rsrc(rf, rf->allocated_cqs, cq_num - dev->base_cqn);
	}

	return status;
}

/**
 * zxdh_cfg_ceq_vector - set up the msix interrupt vector for
 * ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq associated with the vector
 * @ceq_id: the id number of the iwceq
 * @msix_vec: interrupt vector information
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int zxdh_cfg_ceq_vector(struct zxdh_pci_f *rf, struct zxdh_ceq *iwceq, u32 ceq_id,
			       struct zxdh_msix_vector *msix_vec)
{
#ifndef MSIX_SUPPORT
	return 0;
#endif
	int status;

	tasklet_setup(&iwceq->dpc_tasklet, zxdh_ceq_dpc);
	status = request_irq(msix_vec->irq, zxdh_ceq_handler, 0, "CEQ", iwceq);
	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_set_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (status) {
		pr_err("ERR: ceq irq config fail\n");
		return status;
	}
	iwceq->irq = msix_vec->irq;
	iwceq->msix_idx = msix_vec->idx;
	iwceq->irq_sta = true;
	msix_vec->ceq_id = ceq_id;
	return 0;
}

/**
 * zxdh_cfg_aeq_vector - set up the msix vector for aeq
 * @rf: RDMA PCI function
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int zxdh_cfg_aeq_vector(struct zxdh_pci_f *rf)
{
#ifndef MSIX_SUPPORT
	return 0;
#endif
	struct zxdh_msix_vector *msix_vec = rf->iw_msixtbl;
	u32 ret = 0;

	tasklet_setup(&rf->dpc_tasklet, zxdh_dpc);
	ret = request_irq(msix_vec->irq, zxdh_aeq_handler, 0, "AEQ", rf);
	if (ret) {
		pr_err("ERR: aeq irq config fail\n");
		return -EINVAL;
	}
	rf->sc_dev.irq_ops->zxdh_cfg_aeq(&rf->sc_dev, msix_vec->idx);
	rf->aeq.irq = msix_vec->irq;
	rf->aeq.msix_idx = msix_vec->idx;
	rf->aeq.irq_sta = true;
	return 0;
}

/**
 * zxdh_create_ceq - create completion event queue
 * @rf: RDMA PCI function
 * @iwceq: pointer to the ceq resources to be created
 * @ceq_id: the id number of the iwceq
 *
 * Return 0, if the ceq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int zxdh_create_ceq(struct zxdh_pci_f *rf, struct zxdh_ceq *iwceq, u32 ceq_id)
{
	int status;
	struct zxdh_ceq_init_info info = {};
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u64 scratch;
	u32 ceq_size;
	u32 log2_ceq_size;

	info.ceq_id = ceq_id;
	info.ceq_index = ceq_id - dev->base_ceqn;
	iwceq->rf = rf;
	ceq_size = min(rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].cnt,
		       dev->hw_attrs.max_hw_ceq_size);
	ceq_size = roundup_pow_of_two(ceq_size);
	log2_ceq_size = order_base_2(ceq_size);

	iwceq->mem.size = ALIGN(sizeof(struct zxdh_ceqe) * ceq_size, ZXDH_CEQ_ALIGNMENT);
	iwceq->mem.va =
		dma_alloc_coherent(dev->hw->device, iwceq->mem.size, &iwceq->mem.pa, GFP_KERNEL);
	if (!iwceq->mem.va)
		return -ENOMEM;

	info.ceqe_base = iwceq->mem.va;
	info.ceqe_pa = iwceq->mem.pa;
	info.elem_cnt = ceq_size;
	info.log2_elem_size = log2_ceq_size;
	info.msix_idx = iwceq->msix_idx;
	iwceq->sc_ceq.ceq_id = ceq_id;
	iwceq->sc_ceq.valid_ceq = true;
	info.dev = dev;
	scratch = (uintptr_t)&rf->cqp.sc_cqp;
	status = zxdh_sc_ceq_init(&iwceq->sc_ceq, &info);

	if (!status) {
		if (dev->ceq_valid)
			status = zxdh_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq, ZXDH_OP_CEQ_CREATE);
		else
			status = zxdh_sc_cceq_create(&iwceq->sc_ceq, scratch);
	}

	if (status) {
		dma_free_coherent(dev->hw->device, iwceq->mem.size, iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
	}

	return status;
}

/**
 * zxdh_setup_ceq_0 - create CEQ 0 and it's interrupt resource
 * @rf: RDMA PCI function
 *
 * Allocate a list for all device completion event queues
 * Create the ceq 0 and configure it's msix interrupt vector
 * Return 0, if successfully set up, otherwise return error
 */
static int zxdh_setup_ceq_0(struct zxdh_pci_f *rf)
{
	struct zxdh_ceq *iwceq;
	struct zxdh_msix_vector *msix_vec;
	int status = 0;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.max_ceqs);
	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist) {
		status = -ENOMEM;
		goto exit;
	}

	iwceq = &rf->ceqlist[0];
	//0 is aeq, 1~xx is ceq
	msix_vec = &rf->iw_msixtbl[1];
	iwceq->irq = msix_vec->irq;
	iwceq->msix_idx = msix_vec->idx;
	status = zxdh_create_ceq(rf, iwceq, rf->sc_dev.base_ceqn);
	if (status) {
		pr_err("ERR: create ceq status = %d\n", status);
		goto exit;
	}

	spin_lock_init(&iwceq->ce_lock);
	status = zxdh_cfg_ceq_vector(rf, iwceq, rf->sc_dev.base_ceqn, msix_vec);
	if (status) {
		zxdh_destroy_ceq(rf, iwceq);
		goto exit;
	}

	zxdh_ceq_ena_intr(&rf->sc_dev, iwceq->sc_ceq.ceq_id);
	rf->ceqs_count++;

exit:
	if (status && !rf->ceqs_count) {
		kfree(rf->ceqlist);
		rf->ceqlist = NULL;
		return status;
	}
	rf->sc_dev.ceq_valid = true;

	return 0;
}

/**
 * zxdh_setup_ceqs - manage the device ceq's and their interrupt resources
 * @rf: RDMA PCI function
 *
 * Allocate a list for all device completion event queues
 * Create the ceq's and configure their msix interrupt vectors
 * Return 0, if ceqs are successfully set up, otherwise return error
 */
static int zxdh_setup_ceqs(struct zxdh_pci_f *rf)
{
	u32 i;
	u32 ceq_id;
	u32 ceq_id_offset;
	struct zxdh_ceq *iwceq;
	struct zxdh_msix_vector *msix_vec;
	int status;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.max_ceqs);
	i = 2;
	for (ceq_id_offset = 1; ceq_id_offset < num_ceqs; i++, ceq_id_offset++) {
		iwceq = &rf->ceqlist[ceq_id_offset];
		ceq_id = rf->sc_dev.base_ceqn + ceq_id_offset;
		msix_vec = &rf->iw_msixtbl[i];
		iwceq->irq = msix_vec->irq;
		iwceq->msix_idx = msix_vec->idx;
		status = zxdh_create_ceq(rf, iwceq, ceq_id);
		if (status) {
			pr_err("ERR: create ceq status = %d\n", status);
			goto del_ceqs;
		}
		spin_lock_init(&iwceq->ce_lock);
		status = zxdh_cfg_ceq_vector(rf, iwceq, ceq_id, msix_vec);
		if (status) {
			zxdh_destroy_ceq(rf, iwceq);
			goto del_ceqs;
		}

		zxdh_ceq_ena_intr(&rf->sc_dev, iwceq->sc_ceq.ceq_id);
		rf->ceqs_count++;
	}

	return 0;

del_ceqs:
	zxdh_del_ceqs(rf);

	return status;
}

/**
 * zxdh_create_aeq - create async event queue
 * @rf: RDMA PCI function
 *
 * Return 0, if the aeq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int zxdh_create_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_aeq_init_info info = {};
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_aeq *aeq = &rf->aeq;
	struct zxdh_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	u32 aeq_size;
	u8 multiplier = (rf->protocol_used == ZXDH_IWARP_PROTOCOL_ONLY) ? 2 : 1;
	int status;

	aeq_size = multiplier * hmc_info->hmc_obj[ZXDH_HMC_IW_QP].cnt +
		   hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].cnt + hmc_info->hmc_obj[ZXDH_HMC_IW_SRQ].cnt;
	aeq_size = min(aeq_size, dev->hw_attrs.max_hw_aeq_size);

	aeq->mem.size = ALIGN(sizeof(struct zxdh_sc_aeqe) * aeq_size, ZXDH_AEQ_ALIGNMENT);
	aeq->mem.va = dma_alloc_coherent(dev->hw->device, aeq->mem.size, &aeq->mem.pa,
					 GFP_KERNEL | __GFP_NOWARN);

	if (aeq->mem.va)
		goto skip_virt_aeq;

	pr_err("aeq_size out of range, failed to apply for physical memory!\n");
	return -ENOMEM;

skip_virt_aeq:
	info.aeqe_base = aeq->mem.va;
	info.aeq_elem_pa = aeq->mem.pa;
	info.elem_cnt = aeq_size;
	info.dev = dev;
	info.msix_idx = rf->iw_msixtbl->idx;
	status = zxdh_sc_aeq_init(&aeq->sc_aeq, &info);
	if (status)
		goto err;

	status = zxdh_cqp_aeq_create(&aeq->sc_aeq);
	if (status)
		goto err;

	return 0;

err:
	if (aeq->virtual_map)
		zxdh_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va, aeq->mem.pa);
		aeq->mem.va = NULL;
	}
	return status;
}

/**
 * zxdh_setup_aeq - set up the device aeq
 * @rf: RDMA PCI function
 *
 * Create the aeq and configure its msix interrupt vector
 * Return 0 if successful, otherwise return error
 */
static int zxdh_setup_aeq(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	int status;

	status = zxdh_create_aeq(rf);
	if (status)
		return status;
	status = zxdh_cfg_aeq_vector(rf);
	if (status) {
		zxdh_init_destroy_aeq(rf);
		return status;
	}
	zxdh_aeq_ena_intr(dev, true);
	return 0;
}

/**
 * zxdh_hmc_setup - create hmc objects for the device
 * @rf: RDMA PCI function
 *
 * Set up the device private memory space for the number and size of
 * the hmc objects and create the objects
 * Return 0 if successful, otherwise return error
 */
static int zxdh_hmc_setup(struct zxdh_pci_f *rf)
{
	int status;
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	status = zxdh_cfg_fpm_val(dev);
	if (status)
		return status;

	status = zxdh_create_hmc_objs(rf, true);

	return status;
}

static int zxdh_data_cap_setup(struct zxdh_pci_f *rf)
{
	int status;
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	status = zxdh_sc_create_date_cap_obj(dev);
	if (status) {
		zxdh_del_data_cap_objects(&rf->sc_dev);
		zxdh_dbg(dev, "ERR: create data cap status = %d\n", status);
	}
	return status;
}

/**
 * zxdh_del_init_mem - deallocate memory resources
 * @rf: RDMA PCI function
 */
static void zxdh_del_init_mem(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;

	kfree(dev->hmc_info->sd_table.sd_entry);
	dev->hmc_info->sd_table.sd_entry = NULL;
	vfree(rf->mem_rsrc);
	rf->mem_rsrc = NULL;

	kfree(rf->ceqlist);
	rf->ceqlist = NULL;
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;
}

/**
 * zxdh_initialize_dev - initialize device
 * @rf: RDMA PCI function
 *
 * Allocate memory for the hmc objects and initialize iwdev
 * Return 0 if successful, otherwise clean up the resources
 * and return error
 */
static int zxdh_initialize_dev(struct zxdh_pci_f *rf)
{
	struct zxdh_device_init_info info = {};
	int ret = 0;

	info.bar0 = rf->hw.hw_addr;
	info.privileged = !rf->ftype;
	info.max_vfs = rf->max_rdma_vfs;
	info.hw = &rf->hw;
	rf->vlan_parse_en = 1;
	ret = zxdh_sc_dev_init(rf->rdma_ver, &rf->sc_dev, &info);

	return ret;
}

/**
 * zxdh_rt_deinit_hw - clean up the zrdma device resources
 * @iwdev: zrdma device
 *
 * remove the mac ip entry and ipv4/ipv6 addresses, destroy the
 * device queues and free the pble and the hmc objects
 */
void zxdh_rt_deinit_hw(struct zxdh_device *iwdev)
{
	switch (iwdev->init_state) {
	case AEQ_CREATED:
	case PBLE_CHUNK_MEM:
	case CEQS_CREATED:
	default:
		dev_warn(idev_to_dev(&iwdev->rf->sc_dev), "rt bad init_state = %d\n",
			 iwdev->init_state);
		break;
	}

	if (iwdev->cleanup_wq)
		destroy_workqueue(iwdev->cleanup_wq);
}

static int zxdh_setup_init_state(struct zxdh_pci_f *rf)
{
	int status;

	status = zxdh_save_msix_info(rf);
	if (status)
		return status;
	rf->hw.device = &rf->pcidev->dev;

	mutex_init(&rf->sc_dev.vchnl_mutex);
	status = zxdh_initialize_dev(rf);
	if (status)
		goto clean_msixtbl;

	return 0;

clean_msixtbl:
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	return status;
}

/**
 * zxdh_get_used_rsrc - determine resources used internally
 * @iwdev: zrdma device
 *
 * Called at the end of open to get all internal allocations
 */
static void zxdh_get_used_rsrc(struct zxdh_device *iwdev)
{
	iwdev->rf->used_pds = find_next_zero_bit(iwdev->rf->allocated_pds, iwdev->rf->max_pd, 0);
	iwdev->rf->used_qps = find_next_zero_bit(iwdev->rf->allocated_qps, iwdev->rf->max_qp, 0);
	iwdev->rf->used_cqs = find_next_zero_bit(iwdev->rf->allocated_cqs, iwdev->rf->max_cq, 0);
	iwdev->rf->used_mrs = find_next_zero_bit(iwdev->rf->allocated_mrs, iwdev->rf->max_mr, 0);
	iwdev->rf->used_srqs = find_next_zero_bit(iwdev->rf->allocated_srqs, iwdev->rf->max_srq, 0);
}

static void zxdh_shutdown_vhca(struct zxdh_pci_f *rf)
{
	u32 invalid_sid = 63;
	u32 qpc_axi_info;

	writel(invalid_sid, (u32 __iomem *)(rf->sc_dev.hw->hw_addr + C_RDMAIO_TABLE2));
	qpc_axi_info = readl((u32 __iomem *)(rf->sc_dev.hw->hw_addr + C_HMC_QPC_RX));
	qpc_axi_info |= (3 << 2);
	writel(qpc_axi_info, (u32 __iomem *)(rf->sc_dev.hw->hw_addr + C_HMC_QPC_RX));
}

void zxdh_ctrl_deinit_hw(struct zxdh_pci_f *rf)
{
	u16 vf_id;
	struct zxdh_vfdev *vf_dev = NULL;
	enum init_completion_state state = rf->init_state;

	rf->init_state = INVALID_STATE;
	if (state > AEQ_CREATED)
		zxdh_destroy_aeq(rf);
	else if (state == AEQ_CREATED)
		zxdh_destroy_aeq_reg(rf);
	if (rf->rsrc_created) {
		zxdh_destroy_pble_prm(rf->pble_rsrc);
		zxdh_destroy_pble_prm(rf->pble_mr_rsrc);
		zxdh_del_ceqs(rf);
		rf->rsrc_created = false;
	}

	switch (state) {
	case CEQ0_CREATED:
		zxdh_del_ceq_0(rf);
		fallthrough;
	case CCQ_CREATED:
		zxdh_destroy_ccq(rf);
		fallthrough;
	case HW_RSRC_INITIALIZED:
	case HMC_OBJS_CREATED:
		zxdh_del_hmc_objects(&rf->sc_dev, rf->sc_dev.hmc_info);
		fallthrough;
	case DATA_CAP_CREATED:
		zxdh_del_data_cap_objects(&rf->sc_dev);
		fallthrough;
	case CQP_QP_CREATED:
		zxdh_destroy_cqp_qp(rf);
		fallthrough;
	case SMMU_PAGETABLE_INITIALIZED:
		if (!rf->ftype)
			zxdh_smmu_pagetable_exit(&rf->sc_dev);
		fallthrough;
	case CQP_CREATED:
		zxdh_destroy_cqp(rf, !rf->reset);
		fallthrough;
	case INITIAL_STATE:
		zxdh_del_init_mem(rf);
		break;
	case INVALID_STATE:
	default:
		pr_warn("ctrl bad init_state = %d\n", rf->init_state);
		break;
	}

	if (rf->ftype == 0) {
		for (vf_id = 0; vf_id < rf->max_rdma_vfs; vf_id++) {
			vf_dev = zxdh_find_vf_dev(&rf->sc_dev, vf_id);
			if (vf_dev) {
				zxdh_del_hmc_objects(&rf->sc_dev,
						     &rf->sc_dev.vf_dev[vf_id]->hmc_info);
				zxdh_put_vfdev(&rf->sc_dev, rf->sc_dev.vf_dev[vf_id]);
				zxdh_remove_vf_dev(&rf->sc_dev, rf->sc_dev.vf_dev[vf_id]);
			}
		}
	}
	zxdh_shutdown_vhca(rf);
}

/**
 * zxdh_rt_init_hw - Initializes runtime portion of HW
 * @iwdev: zrdma device
 *
 * Create device queues ILQ, IEQ, CEQs and PBLEs. Setup zrdma
 * device resource objects.
 */
int zxdh_rt_init_hw(struct zxdh_device *iwdev)
{
	struct zxdh_pci_f *rf = iwdev->rf;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	int status;

	zxdh_sc_dev_qplist_init(dev);
	do {
		if (!rf->rsrc_created) {
			status = zxdh_setup_ceqs(rf);
			if (status)
				break;

			iwdev->init_state = CEQS_CREATED;

			rf->pble_rsrc->fpm_base_addr =
				rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE].base;
			rf->sc_dev.hmc_info->pble_hmc_index =
				rf->sc_dev.hmc_info->hmc_first_entry_pble;
			status = zxdh_hmc_init_pble(&rf->sc_dev, rf->pble_rsrc, PBLE_QUEUE);
			if (status) {
				zxdh_del_ceqs(rf);
				break;
			}
			rf->pble_mr_rsrc->fpm_base_addr =
				rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_PBLE_MR].base;
			rf->sc_dev.hmc_info->pble_mr_hmc_index =
				rf->sc_dev.hmc_info->hmc_first_entry_pble_mr;
			status = zxdh_hmc_init_pble(&rf->sc_dev, rf->pble_mr_rsrc, PBLE_MR);
			if (status) {
				zxdh_destroy_pble_prm(rf->pble_rsrc);
				zxdh_del_ceqs(rf);
				break;
			}

			iwdev->init_state = PBLE_CHUNK_MEM;
			rf->rsrc_created = true;
		}

		iwdev->device_cap_flags = IB_DEVICE_MEM_WINDOW | IB_DEVICE_MEM_MGT_EXTENSIONS |
					  IB_DEVICE_BAD_QKEY_CNTR | IB_DEVICE_SYS_IMAGE_GUID |
					  IB_DEVICE_RC_RNR_NAK_GEN | IB_DEVICE_N_NOTIFY_CQ;

		iwdev->cleanup_wq =
			alloc_workqueue("zrdma-cleanup-wq", WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
		if (!iwdev->cleanup_wq)
			return -ENOMEM;

		zxdh_get_used_rsrc(iwdev);
		init_waitqueue_head(&iwdev->suspend_wq);

		return 0;
	} while (0);

	dev_err(idev_to_dev(dev), "HW runtime init FAIL status = %d last cmpl = %d\n", status,
		iwdev->init_state);
	zxdh_rt_deinit_hw(iwdev);

	return status;
}

static void zxdh_config_tx_regs(struct zxdh_sc_dev *dev)
{
	u32 temp;

	temp = FIELD_PREP(ZXDH_TX_CACHE_ID, 0) |
	       FIELD_PREP(ZXDH_TX_INDICATE_ID, ZXDH_INDICATE_HOST_NOSMMU) |
	       FIELD_PREP(ZXDH_TX_AXI_ID, (ZXDH_AXID_HOST_EP0 + dev->ep_id)) |
	       FIELD_PREP(ZXDH_TX_WAY_PARTITION, 0);

	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_ACK_SQWQE_PARA_CFG));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_ACK_DDR_PARA_CFG));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_DB_SQWQE_ID_CFG));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_SQWQE_PARA_CFG));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_PAYLOAD_PARA_CFG));

	if (dev->hmc_use_dpu_ddr) {
		temp = FIELD_PREP(ZXDH_TX_CACHE_ID, dev->cache_id) |
		       FIELD_PREP(ZXDH_TX_INDICATE_ID, ZXDH_INDICATE_DPU_DDR) |
		       FIELD_PREP(ZXDH_TX_AXI_ID, (ZXDH_AXID_HOST_EP0 + dev->ep_id)) |
		       FIELD_PREP(ZXDH_TX_WAY_PARTITION, 0);
	} else {
		temp = FIELD_PREP(ZXDH_TX_CACHE_ID, dev->cache_id) |
		       FIELD_PREP(ZXDH_TX_INDICATE_ID, ZXDH_INDICATE_HOST_SMMU) |
		       FIELD_PREP(ZXDH_TX_AXI_ID, (ZXDH_AXID_HOST_EP0 + dev->ep_id)) |
		       FIELD_PREP(ZXDH_TX_WAY_PARTITION, 0);
	}
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + C_HMC_MRTE_TX2));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + C_HMC_PBLEMR_TX2));

	writel((ZXDH_AXID_HOST_EP0 + dev->ep_id),
	       (u32 __iomem *)(dev->hw->hw_addr + RDMATX_HOSTID_CFG));

	/*adding token config to 200Gbps, equal to time(us)*size(Byte)*/
	writel(0x1, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_ADD_TOKEN_CHANGE_EN));
	writel(0x1900, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_TIME_ADD_TOKEN_CFG));
	writel(0x132d7, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_SIZE_ADD_TOKEN_CFG));
	writel(0x3FFFFFF, (u32 __iomem *)(dev->hw->hw_addr + RDMATX_TOKEN_MAX_CFG));
}

static void zxdh_config_rx_regs(struct zxdh_sc_dev *dev)
{
	u32 temp;

	temp = FIELD_PREP(ZXDH_RX_CACHE_ID, 0) |
	       FIELD_PREP(ZXDH_RX_INDICATE_ID, ZXDH_INDICATE_HOST_NOSMMU) |
	       FIELD_PREP(ZXDH_RX_AXI_ID, (ZXDH_AXID_HOST_EP0 + dev->ep_id)) |
	       FIELD_PREP(ZXDH_RX_WAY_PARTITION, 0);

	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_PLD_WR_AXIID_RAM));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_RQ_AXI_RAM));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_SRQ_AXI_RAM));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_ACK_RQDB_AXI_RAM));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_CQ_CQE_AXI_INFO_RAM));
	writel(temp, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_CQ_DBSA_AXI_INFO_RAM));
	writel(dev->hmc_fn_id, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_MUL_CACHE_CFG_SIDN_RAM));
	writel((ZXDH_AXID_HOST_EP0 + dev->ep_id),
	       (u32 __iomem *)(dev->hw->hw_addr + RDMARX_MUL_COPY_QPN_INDICATE));
	writel(RDMARX_MAX_MSG_SIZE, (u32 __iomem *)(dev->hw->hw_addr + RDMARX_VHCA_MAX_SIZE_RAM));
}

static void zxdh_config_io_regs(struct zxdh_sc_dev *dev)
{
	u32 temp0, temp1, temp2;
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);

	temp0 = FIELD_PREP(ZXDH_IOTABLE2_SID, dev->hmc_fn_id);
	writel(temp0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE2));

	temp1 = FIELD_PREP(ZXDH_IOTABLE4_EPID, (ZXDH_HOST_EP0_ID + dev->ep_id)) |
		FIELD_PREP(ZXDH_IOTABLE4_VFID, dev->vf_id) |
		FIELD_PREP(ZXDH_IOTABLE4_PFID, rf->pf_id);
	writel(temp1, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE4));

	temp0 = 0x10000;
	writel(temp0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE3));
	for (temp0 = 0; temp0 < 32; temp0++) {
		if (temp0 < ZXDH_RW_PAYLOAD || temp0 == ZXDH_QPC_OBJ_ID) {
			writel(0,
			       (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_0 + (temp0 * 4)));
		} else {
			writel((rf->ftype),
			       (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_0 + (temp0 * 4)));
		}
	}

	if (rf->ftype == 0) {
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_0));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_1));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_2));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_3));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_4));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_5));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_6));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_7));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_8));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_9));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_10));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_11));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_12));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_13));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_14));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE6_15));

		temp2 = FIELD_PREP(ZXDH_IOTABLE7_PFID, rf->pf_id) |
			FIELD_PREP(ZXDH_IOTABLE7_EPID, (ZXDH_HOST_EP0_ID + rf->ep_id));
		writel(temp2, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE7));
	} else {
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_0));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_1));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_2));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_3));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_4));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_5));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_6));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_7));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_8));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_9));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_10));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_11));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_12));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_13));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_14));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_15));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_16));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_17));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_18));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_19));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_20));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_21));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_22));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_23));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_24));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_25));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_26));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_27));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_28));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_29));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_30));
		writel(0, (u32 __iomem *)(dev->hw->hw_addr + C_RDMAIO_TABLE5_31));
	}
}

static void zxdh_config_hw_regs(struct zxdh_sc_dev *dev)
{
	zxdh_config_tx_regs(dev);
	zxdh_config_rx_regs(dev);
	zxdh_config_io_regs(dev);
}
/**
 * zxdh_ctrl_init_hw - Initializes control portion of HW
 * @rf: RDMA PCI function
 *
 * Create admin queues, HMC obejcts and RF resource objects
 */
int zxdh_ctrl_init_hw(struct zxdh_pci_f *rf)
{
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 k = 0;
	int status = 0;

	do {
		status = zxdh_setup_init_state(rf);
		if (status)
			break;
		rf->init_state = INITIAL_STATE;

		zxdh_config_hw_regs(dev);

		status = zxdh_create_cqp(rf);
		if (status)
			break;
		rf->init_state = CQP_CREATED;
		zxdh_init_destroy_aeq(rf);
		if (!rf->ftype) {
			status = zxdh_smmu_pagetable_init(dev);
			if (status)
				break;
			rf->init_state = SMMU_PAGETABLE_INITIALIZED;
			if (rf->sc_dev.ep_id != ZXDH_ZF_EPID || dev->hmc_use_dpu_ddr) {
				status = zxdh_data_cap_setup(rf);
				if (status)
					break;
				rf->init_state = DATA_CAP_CREATED;
			}
			if (dev->hmc_use_dpu_ddr) {
				status = zxdh_clear_dpuddr(dev, true); //TODO:VF clear dpu ddr
				if (status) {
					if (dev->clear_dpu_mem.va) {
						dma_free_coherent(dev->hw->device,
								  dev->clear_dpu_mem.size,
								  dev->clear_dpu_mem.va,
								  dev->clear_dpu_mem.pa);
						dev->clear_dpu_mem.va = NULL;
					}
					break;
				}
				status = zxdh_create_hmcobjs_dpuddr(rf);
			} else
				status = zxdh_hmc_setup(rf);

			if (dev->clear_dpu_mem.va) {
				dma_free_coherent(dev->hw->device, dev->clear_dpu_mem.size,
						  dev->clear_dpu_mem.va, dev->clear_dpu_mem.pa);
				dev->clear_dpu_mem.va = NULL;
			}

			for (k = 0; k < rf->max_rdma_vfs; k++)
				zxdh_pf_get_vf_hmc_res(dev, k);

		} else if (rf->ftype == 1) {
			zxdh_hmc_dpu_capability(dev);
			for (k = 0; k < ZXDH_HMC_IW_MAX; k++) {
				zxdh_sc_write_hmc_register(dev, dev->hmc_info->hmc_obj, k,
							   dev->vhca_id);
			}
			zxdh_create_vf_pblehmc_entry(dev);
		} else {
			pr_info("ftype is error!!\n");
			status = EINVAL;
		}

		if (status)
			break;
		rf->init_state = HMC_OBJS_CREATED;

		status = zxdh_initialize_hw_rsrc(rf);
		if (status)
			break;
		rf->init_state = HW_RSRC_INITIALIZED;
		status = zxdh_create_cqp_qp(rf);
		if (status)
			break;
		rf->init_state = CQP_QP_CREATED;

		status = zxdh_setup_aeq(rf);
		if (status)
			break;
		rf->init_state = AEQ_CREATED;

		status = zxdh_create_ccq(rf);
		if (status)
			break;
		rf->init_state = CCQ_CREATED;

		status = zxdh_setup_ceq_0(rf);
		if (status)
			break;

		rf->sc_dev.ceq_0_ok = true;
		rf->sc_dev.ceq_interrupt = false;
		rf->init_state = CEQ0_CREATED;
		/* Handles processing of CQP completions */
		rf->cqp_cmpl_wq = alloc_ordered_workqueue("cqp_cmpl_wq", WQ_HIGHPRI | WQ_UNBOUND);
		if (!rf->cqp_cmpl_wq) {
			status = -ENOMEM;
			break;
		}
		INIT_WORK(&rf->cqp_cmpl_work, cqp_compl_worker);
#ifdef MSIX_SUPPORT
		zxdh_sc_ccq_arm(dev->ccq);
#endif

		if (rf->ftype == 1 && !dev->hmc_use_dpu_ddr) {
			zxdh_set_smmu_invalid(rf);
			status = zxdh_vf_init_hmc(rf);
			if (status)
				break;
		}

		if (rf->ftype) {
			status = zxdh_vf_init_np_tbl(rf);
			if (status)
				break;
		}

		return 0;
	} while (0);

	pr_err("ZRDMA hardware initialization FAILED init_state=%d status=%d\n", rf->init_state,
	       status);
	zxdh_ctrl_deinit_hw(rf);
	return status;
}

/**
 * zxdh_set_hw_rsrc - set hw memory resources.
 * @rf: RDMA PCI function
 */
static void zxdh_set_hw_rsrc(struct zxdh_pci_f *rf)
{
#ifdef Z_CONFIG_RDMA_ARP
	rf->allocated_srqs =
		(void *)(rf->mem_rsrc + (sizeof(struct zxdh_arp_entry) * rf->arp_table_size));
#else
	rf->allocated_srqs = (void *)(rf->mem_rsrc);
#endif
	rf->allocated_qps = &rf->allocated_srqs[BITS_TO_LONGS(rf->max_srq)];
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_mrs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->allocated_mcgs = &rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)];
#ifdef Z_CONFIG_RDMA_ARP
	rf->allocated_arps = &rf->allocated_mcgs[BITS_TO_LONGS(rf->max_mcg)];
	rf->qp_table = (struct zxdh_qp **)(&rf->allocated_arps[BITS_TO_LONGS(rf->arp_table_size)]);

#else
	rf->qp_table = (struct zxdh_qp **)(&rf->allocated_mcgs[BITS_TO_LONGS(rf->max_mcg)]);
#endif
	rf->cq_table = (struct zxdh_cq **)(&rf->qp_table[rf->max_qp]);
	rf->srq_table = (struct zxdh_srq **)(&rf->cq_table[rf->max_cq]);

	spin_lock_init(&rf->rsrc_lock);
#ifdef Z_CONFIG_RDMA_ARP
	spin_lock_init(&rf->arp_lock);
#endif
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->cqtable_lock);
	spin_lock_init(&rf->srqtable_lock);
}

/**
 * zxdh_calc_mem_rsrc_size - calculate memory resources size.
 * @rf: RDMA PCI function
 */
static u32 zxdh_calc_mem_rsrc_size(struct zxdh_pci_f *rf)
{
	u32 rsrc_size;

#ifdef Z_CONFIG_RDMA_ARP
	rsrc_size = sizeof(struct zxdh_arp_entry) * rf->arp_table_size;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_srq);
#else
	rsrc_size = sizeof(unsigned long) * BITS_TO_LONGS(rf->max_srq);
#endif
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
#ifdef Z_CONFIG_RDMA_ARP
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->arp_table_size);
#endif
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mcg);
	rsrc_size += sizeof(struct zxdh_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct zxdh_cq **) * rf->max_cq;
	rsrc_size += sizeof(struct zxdh_srq **) * rf->max_srq;

	return rsrc_size;
}

/**
 * zxdh_initialize_hw_rsrc - initialize hw resource tracking array
 * @rf: RDMA PCI function
 */
u32 zxdh_initialize_hw_rsrc(struct zxdh_pci_f *rf)
{
	u32 rsrc_size;
	u32 mrdrvbits;
	u32 ret;

	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp = rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_QP].cnt;
	rf->max_mr = rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_MR].cnt;
	rf->max_cq = rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_CQ].cnt;
	rf->max_srq = rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_SRQ].cnt;
	rf->max_pd = rf->sc_dev.hw_attrs.max_hw_pds;
	rf->max_ah = rf->sc_dev.hmc_info->hmc_obj[ZXDH_HMC_IW_AH].cnt;
	rf->max_mcg = rf->max_qp;

	rsrc_size = zxdh_calc_mem_rsrc_size(rf);
	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		ret = -ENOMEM;
		goto mem_rsrc_vmalloc_fail;
	}
#ifdef Z_CONFIG_RDMA_ARP
	rf->arp_table = (struct zxdh_arp_entry *)rf->mem_rsrc;
#endif

	zxdh_set_hw_rsrc(rf);

	set_bit(0, rf->allocated_mrs);
	set_bit(1, rf->allocated_mrs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_qps);
#ifdef Z_CONFIG_RDMA_ARP
	set_bit(0, rf->allocated_arps);
#endif
	set_bit(0, rf->allocated_ahs);
	set_bit(0, rf->allocated_mcgs);
	set_bit(0, rf->allocated_srqs);

	/* stag index mask has a minimum of 14 bits */
	mrdrvbits = 24 - max(get_count_order(rf->max_mr), 14);
	rf->mr_stagmask = ~(((1 << mrdrvbits) - 1) << (32 - mrdrvbits));

	return 0;

mem_rsrc_vmalloc_fail:
	return ret;
}

/**
 * zxdh_cqp_ce_handler - handle cqp completions
 * @rf: RDMA PCI function
 * @cq: cq for cqp completions
 */
void zxdh_cqp_ce_handler(struct zxdh_pci_f *rf, struct zxdh_sc_cq *cq)
{
	struct zxdh_cqp_request *cqp_request;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	u32 cqe_count = 0;
	struct zxdh_ccq_cqe_info info;
	unsigned long flags;
	int ret = 0;

	do {
		memset(&info, 0, sizeof(info));
		spin_lock_irqsave(&rf->cqp.compl_lock, flags);
		ret = zxdh_sc_ccq_get_cqe_info(cq, &info);
		spin_unlock_irqrestore(&rf->cqp.compl_lock, flags);
		if (ret) {
			if (dev->hw_attrs.self_health == true)
				return;
			break;
		}

		cqp_request = (struct zxdh_cqp_request *)(unsigned long)info.scratch;
		if (info.error && zxdh_cqp_crit_err(dev, cqp_request->info.cqp_cmd,
						    info.maj_err_code, info.min_err_code))
			pr_err("cqp opcode = 0x%x maj_err_code = 0x%x min_err_code = 0x%x\n",
			       info.op_code, info.maj_err_code, info.min_err_code);
		if (cqp_request && (info.mailbox_cqe != 1)) {
			cqp_request->compl_info.maj_err_code = info.maj_err_code;
			cqp_request->compl_info.min_err_code = info.min_err_code;
			cqp_request->compl_info.op_ret_val = info.op_ret_val;
			cqp_request->compl_info.error = info.error;

			if (info.op_code == ZXDH_CQP_OP_WQE_DMA_READ_USECQE) {
				cqp_request->compl_info.addrbuf[0] = info.addrbuf[0];
				cqp_request->compl_info.addrbuf[1] = info.addrbuf[1];
				cqp_request->compl_info.addrbuf[2] = info.addrbuf[2];
				cqp_request->compl_info.addrbuf[3] = info.addrbuf[3];
				cqp_request->compl_info.addrbuf[4] = info.addrbuf[4];
			}

			if (cqp_request->waiting) {
				cqp_request->request_done = true;
				wake_up(&cqp_request->waitq);
				zxdh_put_cqp_request(&rf->cqp, cqp_request);
			} else {
				if (cqp_request->callback_fcn)
					cqp_request->callback_fcn(cqp_request);
				zxdh_put_cqp_request(&rf->cqp, cqp_request);
			}
		} else if (info.mailbox_cqe == 1) {
			if (rf->ftype == 0) {
				ret = zxdh_recv_mb(dev, &info);
				if (ret != 0)
					pr_info("pf recv mb failed\n");
			}
		}

		cqe_count++;
	} while (1);

	if (cqe_count) {
		zxdh_sc_ccq_arm(dev->ccq);
		dev->ceq_interrupt = false;
		zxdh_process_bh(dev);
	}
	if (dev->ceq_interrupt == true) {
		zxdh_sc_ccq_arm(dev->ccq);
		dev->ceq_interrupt = false;
	}
}

/**
 * cqp_compl_worker - Handle cqp completions
 * @work: Pointer to work structure
 */
void cqp_compl_worker(struct work_struct *work)
{
	struct zxdh_pci_f *rf = container_of(work, struct zxdh_pci_f, cqp_cmpl_work);
	struct zxdh_sc_cq *cq = &rf->ccq.sc_cq;

	zxdh_cqp_ce_handler(rf, cq);
}

/**
 * zxdh_hw_flush_wqes - flush qp's wqe
 * @rf: RDMA PCI function
 * @qp: hardware control qp
 * @info: info for flush
 * @wait: flag wait for completion
 */
int zxdh_hw_flush_wqes(struct zxdh_pci_f *rf, struct zxdh_sc_qp *qp,
		       struct zxdh_qp_flush_info *info, bool wait)
{
	int status;
	struct zxdh_qp_flush_info *hw_info;
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.qp_flush_wqes.info;
	memcpy(hw_info, info, sizeof(*hw_info));
	cqp_info->cqp_cmd = ZXDH_OP_QP_FLUSH_WQES;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_flush_wqes.qp = qp;
	cqp_info->in.u.qp_flush_wqes.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	if (status) {
		qp->qp_uk.sq_flush_complete = true;
		qp->qp_uk.rq_flush_complete = true;
		zxdh_put_cqp_request(&rf->cqp, cqp_request);
		return status;
	}

	if (!wait || cqp_request->compl_info.maj_err_code)
		goto put_cqp;

	if (info->rq) {
		if (cqp_request->compl_info.min_err_code == ZXDH_CQP_COMPL_SQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* RQ WQE flush was requested but did not happen */
			qp->qp_uk.rq_flush_complete = true;
		}
	}
	if (info->sq) {
		if (cqp_request->compl_info.min_err_code == ZXDH_CQP_COMPL_RQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* SQ WQE flush was requested but did not happen */
			qp->qp_uk.sq_flush_complete = true;
		}
	}

put_cqp:
	zxdh_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void zxdh_flush_wqes(struct zxdh_qp *iwqp, u32 flush_mask)
{
	struct zxdh_qp_flush_info info = {};
	struct zxdh_pci_f *rf = iwqp->iwdev->rf;
	u8 flush_code = iwqp->sc_qp.flush_code;

	if (!(flush_mask & ZXDH_FLUSH_SQ) && !(flush_mask & ZXDH_FLUSH_RQ))
		return;

	if (iwqp->sc_qp.is_nvmeof_ioq)
		return;

	if (iwqp->ibqp.qp_num == 1)
		return;

	/* Set flush info fields*/
	info.sq = flush_mask & ZXDH_FLUSH_SQ;
	info.rq = flush_mask & ZXDH_FLUSH_RQ;

	/* Generate userflush errors in CQE */
	info.sq_major_code = ZXDH_FLUSH_MAJOR_ERR;
	info.sq_minor_code = FLUSH_GENERAL_ERR;
	info.rq_major_code = ZXDH_FLUSH_MAJOR_ERR;
	info.rq_minor_code = FLUSH_GENERAL_ERR;
	info.userflushcode = true;

	if (flush_mask & ZXDH_REFLUSH) {
		if (info.sq)
			iwqp->sc_qp.flush_sq = false;
		if (info.rq)
			iwqp->sc_qp.flush_rq = false;
	} else {
		if (flush_code) {
			if (info.sq && iwqp->sc_qp.sq_flush_code)
				info.sq_minor_code = flush_code;
			if (info.rq && iwqp->sc_qp.rq_flush_code)
				info.rq_minor_code = flush_code;
		}
	}

	/* Issue flush */
	(void)zxdh_hw_flush_wqes(rf, &iwqp->sc_qp, &info, flush_mask & ZXDH_FLUSH_WAIT);
	iwqp->flush_issued = true;
}
