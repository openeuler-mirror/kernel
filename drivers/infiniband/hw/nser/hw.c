// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "main.h"

/* types of hmc objects */
static enum nser_hmc_rsrc_type iw_hmc_obj_types[] = {
	NSER_HMC_IW_IRRQ_LITE,
	NSER_HMC_IW_IRRQ,
	NSER_HMC_IW_ORRQ,
	NSER_HMC_IW_XF,
	NSER_HMC_IW_SQCQE,
	NSER_HMC_IW_RQCQE,
	NSER_HMC_IW_CQP,
	NSER_HMC_IW_AEQ,
	NSER_HMC_IW_QP,
	NSER_HMC_IW_CQ,
	NSER_HMC_IW_CEQ,
	NSER_HMC_IW_MR,
	NSER_HMC_IW_MG,
	NSER_HMC_IW_MG_ID,
	NSER_HMC_IW_AH,
	NSER_HMC_IW_ARP,
	NSER_HMC_IW_DUP_IRRQ,
	NSER_HMC_IW_PBLE,
	NSER_HMC_IW_FW,
	NSER_HMC_IW_SQCQEFL,
	NSER_HMC_IW_RQCQEFL,
	NSER_HMC_IW_XFFL,
	NSER_HMC_IW_IRRQ_LITE_FL,
	NSER_HMC_IW_ORRQFL,
};

/**
 * nser_rdma_ce_handler - handle rdma completions
 * @iwcq: rdma cq receiving event
 */
static void nser_rdma_ce_handler(struct nser_sc_cq *iwcq)
{
	struct nser_cq *cq = iwcq->back_cq;

	if (!cq->user_mode)
		atomic_set(&cq->armed, 0);
	if (cq->ibcq.comp_handler)
		cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
}

/**
 * nser_process_ceq - handle ceq for completions
 * @rf: RDMA PCI function
 * @ceq: ceq having cq for completion
 */
static void nser_process_ceq(struct nser_pci_f *rf, struct nser_ceq *ceq)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_sc_ceq *sc_ceq;
	struct nser_sc_cq *cq;
	unsigned long flags;

	sc_ceq = &ceq->sc_ceq;
	do {
		spin_lock_irqsave(&ceq->ce_lock, flags);
		cq = nser_sc_process_ceq(dev, sc_ceq);
		if (!cq) {
			spin_unlock_irqrestore(&ceq->ce_lock, flags);
			break;
		}

		if (cq->cq_type == NSER_CQ_TYPE_RDMA)
			nser_rdma_ce_handler(cq);

		spin_unlock_irqrestore(&ceq->ce_lock, flags);

		if (cq->cq_type == NSER_CQ_TYPE_CQP)
			queue_work(rf->cqp_cmpl_wq, &rf->cqp_cmpl_work);
	} while (1);
}

static void nser_set_flush_fields(struct nser_sc_qp *qp,
				   struct nser_aeqe_info *info)
{
	qp->sq_flush_code = info->sq;
	qp->rq_flush_code = info->rq;

	switch (info->ae_id) {
	case NSER_AE_AMP_BOUNDS_VIOLATION:
	case NSER_AE_AMP_INVALID_STAG:
	case NSER_AE_AMP_RIGHTS_VIOLATION:
	case NSER_AE_AMP_UNALLOCATED_STAG:
	case NSER_AE_AMP_BAD_PD:
	case NSER_AE_AMP_BAD_QP:
	case NSER_AE_AMP_BAD_STAG_KEY:
	case NSER_AE_AMP_BAD_STAG_INDEX:
	case NSER_AE_AMP_TO_WRAP:
	case NSER_AE_PRIV_OPERATION_DENIED:
		qp->flush_code = FLUSH_PROT_ERR;
		qp->event_type = NSER_QP_EVENT_ACCESS_ERR;
		break;
	case NSER_AE_UDA_XMIT_BAD_PD:
	case NSER_AE_WQE_UNEXPECTED_OPCODE:
		qp->flush_code = FLUSH_LOC_QP_OP_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	case NSER_AE_UDA_XMIT_DGRAM_TOO_SHORT:
	case NSER_AE_UDA_XMIT_DGRAM_TOO_LONG:
	case NSER_AE_UDA_L4LEN_INVALID:
	case NSER_AE_DDP_UBE_DDP_MESSAGE_TOO_LONG_FOR_AVAILABLE_BUFFER:
		qp->flush_code = FLUSH_LOC_LEN_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	case NSER_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS:
	case NSER_AE_IB_REMOTE_ACCESS_ERROR:
		qp->flush_code = FLUSH_REM_ACCESS_ERR;
		qp->event_type = NSER_QP_EVENT_ACCESS_ERR;
		break;
	case NSER_AE_AMP_MWBIND_INVALID_RIGHTS:
	case NSER_AE_AMP_MWBIND_BIND_DISABLED:
	case NSER_AE_AMP_MWBIND_INVALID_BOUNDS:
		qp->flush_code = FLUSH_MW_BIND_ERR;
		qp->event_type = NSER_QP_EVENT_ACCESS_ERR;
		break;
	case NSER_AE_LLP_TOO_MANY_RETRIES:
		qp->flush_code = FLUSH_RETRY_EXC_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	case NSER_AE_IB_INVALID_REQUEST:
		qp->flush_code = FLUSH_REM_INV_REQ_ERR;
		qp->event_type = NSER_QP_EVENT_REQ_ERR;
		break;
	case NSER_AE_LLP_RECEIVED_MPA_CRC_ERROR:
	case NSER_AE_ROCE_RSP_LENGTH_ERROR:
	case NSER_AE_IB_REMOTE_OP_ERROR:
		qp->flush_code = FLUSH_REM_OP_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	case NSER_AE_LCE_QP_CATASTROPHIC:
		qp->flush_code = FLUSH_FATAL_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	default:
		qp->flush_code = FLUSH_GENERAL_ERR;
		qp->event_type = NSER_QP_EVENT_CATASTROPHIC;
		break;
	}
}

/**
 * nser_complete_cqp_request - perform post-completion cleanup
 * @cqp: device CQP
 * @cqp_request: CQP request
 *
 * Mark CQP request as done, wake up waiting thread or invoke
 * callback function and release/free CQP request.
 */
static void nser_complete_cqp_request(struct nser_cqp *cqp,
				       struct nser_cqp_request *cqp_request)
{
	if (cqp_request->waiting) {
		cqp_request->request_done = true;
		wake_up(&cqp_request->waitq);
	} else if (cqp_request->callback_fcn) {
		cqp_request->callback_fcn(cqp_request);
	}
	nser_put_cqp_request(cqp, cqp_request);
}

static void nser_disconnect_worker(struct work_struct *work)
{
	struct disconn_work *dwork = container_of(work, struct disconn_work, work);
	struct nser_qp *iwqp = dwork->iwqp;
	struct nser_sc_qp *qp = NULL;
	struct ib_qp_attr attr;
	unsigned long flags;

	kfree(dwork);
	qp = &iwqp->sc_qp;
	spin_lock_irqsave(&iwqp->lock, flags);
	if (iwqp->flush_issued || iwqp->sc_qp.qp_uk.destroy_pending) {
		spin_unlock_irqrestore(&iwqp->lock, flags);
		nser_qp_rem_ref(&iwqp->ibqp);

		return;
	}

	spin_unlock_irqrestore(&iwqp->lock, flags);
	attr.qp_state = IB_QPS_ERR;
	nser_modify_qp_roce(&iwqp->ibqp, &attr, IB_QP_STATE, NULL);
	nser_ib_qp_event(iwqp, qp->event_type);
	nser_qp_rem_ref(&iwqp->ibqp);
}


void nser_disconn(struct nser_qp *iwqp)
{
	struct nser_device *iwdev = iwqp->iwdev;
	struct disconn_work *work;
	unsigned long flags;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;

	spin_lock_irqsave(&iwdev->rf->qptable_lock, flags);
	if (!iwdev->rf->qp_table[iwqp->ibqp.qp_num]) {
		spin_unlock_irqrestore(&iwdev->rf->qptable_lock, flags);
		nser_dbg(iwdev_to_idev(iwdev),
			  "qp_id %d is already freed\n",
			  iwqp->ibqp.qp_num);
		kfree(work);
		return;
	}
	nser_qp_add_ref(&iwqp->ibqp);
	spin_unlock_irqrestore(&iwdev->rf->qptable_lock, flags);

	work->iwqp = iwqp;
	INIT_WORK(&work->work, nser_disconnect_worker);
	queue_work(iwdev->cleanup_wq, &work->work);
}


/**
 * nser_process_aeq - handle aeq events
 * @rf: RDMA PCI function
 */
static void nser_process_aeq(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_aeq *aeq = &rf->aeq;
	struct nser_sc_aeq *sc_aeq = &aeq->sc_aeq;
	struct nser_aeqe_info aeinfo;
	struct nser_aeqe_info *info = &aeinfo;
	int ret;
	struct nser_qp *iwqp = NULL;
	struct nser_cq *iwcq = NULL;
	struct nser_sc_qp *qp = NULL;
	struct nser_qp_host_ctx_info *ctx_info = NULL;
	unsigned long flags;

	u32 aeqcnt = 0;

	if (!sc_aeq->size)
		return;

	do {
		memset(info, 0, sizeof(*info));
		ret = nser_sc_get_next_aeqe(sc_aeq, info);
		if (ret)
			break;

		aeqcnt++;
		nser_dbg(dev,
				"AEQ: ae_id = 0x%x bool qp=%d qp_id = %d rdma_state=%d ae_src=%d\n",
				info->ae_id, info->qp, info->qp_cq_id,
				info->rdma_state, info->ae_src);

		if (info->qp) {
			spin_lock_irqsave(&rf->qptable_lock, flags);
			iwqp = rf->qp_table[info->qp_cq_id];
			if (!iwqp) {
				spin_unlock_irqrestore(&rf->qptable_lock,
						       flags);
				if (info->ae_id == NSER_AE_QP_SUSPEND_COMPLETE) {
					struct nser_device *iwdev = rf->iwdev;

					atomic_dec(&iwdev->vsi.qp_suspend_reqs);
					wake_up(&iwdev->suspend_wq);
					continue;
				}
				nser_dbg(dev,
						"AEQ: qp_id %d is already freed\n",
						info->qp_cq_id);
				continue;
			}
			nser_qp_add_ref(&iwqp->ibqp);
			spin_unlock_irqrestore(&rf->qptable_lock, flags);
			qp = &iwqp->sc_qp;
			spin_lock_irqsave(&iwqp->lock, flags);
			iwqp->hw_rdma_state = info->rdma_state;
			if (info->ae_id != NSER_AE_QP_SUSPEND_COMPLETE)
				iwqp->last_aeq = info->ae_id;
			spin_unlock_irqrestore(&iwqp->lock, flags);
			ctx_info = &iwqp->ctx_info;
		} else {
			if (info->ae_id != NSER_AE_CQ_OPERATION_ERROR)
				continue;
		}

		switch (info->ae_id) {
		case NSER_AE_QP_SUSPEND_COMPLETE:
			if (iwqp->iwdev->vsi.tc_change_pending) {
				atomic_dec(&iwqp->sc_qp.vsi->qp_suspend_reqs);
				wake_up(&iwqp->iwdev->suspend_wq);
			}
			break;
		case NSER_AE_CQ_OPERATION_ERROR:
			dev_err(idev_to_dev(dev),
				"Processing CQ[0x%x] op error, AE 0x%04X\n",
				info->qp_cq_id, info->ae_id);
			spin_lock_irqsave(&rf->cqtable_lock, flags);
			iwcq = rf->cq_table[info->qp_cq_id];
			if (!iwcq) {
				spin_unlock_irqrestore(&rf->cqtable_lock,
						       flags);
				nser_dbg(dev,
						"AEQ: cq_id %d is already freed\n",
						info->qp_cq_id);
				continue;
			}
			nser_cq_add_ref(&iwcq->ibcq);
			spin_unlock_irqrestore(&rf->cqtable_lock, flags);
			if (iwcq->ibcq.event_handler) {
				struct ib_event ibevent;

				ibevent.device = iwcq->ibcq.device;
				ibevent.event = IB_EVENT_CQ_ERR;
				ibevent.element.cq = &iwcq->ibcq;
				iwcq->ibcq.event_handler(&ibevent,
							 iwcq->ibcq.cq_context);
			}
			nser_cq_rem_ref(&iwcq->ibcq);
			break;
		case NSER_AE_LLP_DOUBT_REACHABILITY:
		case NSER_AE_RESOURCE_EXHAUSTION:
			break;
		case NSER_AE_PRIV_OPERATION_DENIED:
		case NSER_AE_STAG_ZERO_INVALID:
		case NSER_AE_IB_RREQ_AND_Q1_FULL:
		case NSER_AE_RDMAP_ROE_UNEXPECTED_OPCODE:
		case NSER_AE_ROE_INVALID_RDMA_READ_REQUEST:
		case NSER_AE_ROE_INVALID_RDMA_WRITE_OR_READ_RESP:
		case NSER_AE_INVALID_ARP_ENTRY:
		case NSER_AE_STALE_ARP_ENTRY:
		case NSER_AE_LLP_RECEIVED_MPA_CRC_ERROR:
		case NSER_AE_LLP_TOO_MANY_RETRIES:
		case NSER_AE_LCE_QP_CATASTROPHIC:
		case NSER_AE_LCE_FUNCTION_CATASTROPHIC:
		case NSER_AE_LCE_CQ_CATASTROPHIC:
		case NSER_AE_UDA_XMIT_DGRAM_TOO_LONG:
		default:
			dev_err(idev_to_dev(dev),
				"abnormal ae_id = 0x%x bool qp=%d qp_id = %d, ae_source=%d\n",
				info->ae_id, info->qp, info->qp_cq_id,
				info->ae_src);
			ctx_info->roce_info->err_rq_idx_valid = info->rq;
			if (info->rq) {
				ctx_info->roce_info->err_rq_idx = info->wqe_idx;
				nser_sc_qp_setctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va,
							ctx_info);
			}
			nser_set_flush_fields(qp, info);
			nser_disconn(iwqp);

			break;
		}
		if (info->qp)
			nser_qp_rem_ref(&iwqp->ibqp);
	} while (1);

	if (aeqcnt)
		nser_sc_repost_aeq_entries(dev, aeqcnt);
}

/**
 * nser_ena_intr - set up device interrupts
 * @dev: hardware control device structure
 * @msix_id: id of the interrupt to be enabled
 */
static void nser_ena_intr(struct nser_sc_dev *dev, u32 msix_id)
{
	dev->irq_ops->nser_en_irq(dev, msix_id);
}

/**
 * nser_aeq_ceq0_irq_thread - irq thread handler for aeq and ceq 0
 * @irq: msix vector
 * @private: rf struct
 */
static irqreturn_t nser_aeq_ceq0_irq_thread(int irq, void *private)
{
	struct nser_pci_f *rf = private;

	if (rf->msix_shared)
		nser_process_ceq(rf, rf->ceqlist);
	nser_process_aeq(rf);

	nser_ena_intr(&rf->sc_dev, rf->iw_msixtbl[0].idx);

	return IRQ_HANDLED;
}

/**
 * nser_ceq_irq_thread - irq thread handler for CEQ
 * @irq: msix vector
 * @private: rf struct
 */
static irqreturn_t nser_ceq_irq_thread(int irq, void *private)
{
	struct nser_ceq *iwceq = private;
	struct nser_pci_f *rf = iwceq->rf;

	nser_process_ceq(rf, iwceq);
	nser_ena_intr(&rf->sc_dev, iwceq->msix_idx);

	return IRQ_HANDLED;
}

/**
 * nser_save_msix_info - copy msix vector information to rdma device
 * @rf: RDMA PCI function
 *
 * Allocate iwdev msix table and copy the msix info to the table
 * Return 0 if successful, otherwise return error
 */
static int nser_save_msix_info(struct nser_pci_f *rf)
{
	struct nser_qvlist_info *iw_qvlist;
	struct nser_qv_info *iw_qvinfo;
	struct msix_entry *pmsix;
	u32 ceq_idx;
	u32 i;
	u32 size;

	if (!rf->msix_count)
		return -EINVAL;

	size = sizeof(struct nser_msix_vector) * rf->msix_count;
	size += sizeof(struct nser_qvlist_info);
	size += sizeof(struct nser_qv_info) * rf->msix_count - 1;
	rf->iw_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rf->iw_msixtbl)
		return -ENOMEM;

	rf->iw_qvlist = (struct nser_qvlist_info *)
			(&rf->iw_msixtbl[rf->msix_count]);
	iw_qvlist = rf->iw_qvlist;
	iw_qvinfo = iw_qvlist->qv_info;
	iw_qvlist->num_vectors = rf->msix_count;
	if (rf->msix_count <= num_online_cpus())
		rf->msix_shared = true;
	else if (rf->msix_count > num_online_cpus() + 1)
		rf->msix_count = num_online_cpus() + 1;

	pmsix = rf->msix_entries;
	for (i = 0, ceq_idx = 0; i < rf->msix_count; i++, iw_qvinfo++) {
		rf->iw_msixtbl[i].idx = pmsix->entry;
		rf->iw_msixtbl[i].irq = pmsix->vector;
		rf->iw_msixtbl[i].cpu_affinity = ceq_idx;
		if (!i) {
			iw_qvinfo->aeq_idx = 0;
			if (rf->msix_shared)
				iw_qvinfo->ceq_idx = ceq_idx++;
			else
				iw_qvinfo->ceq_idx = NSER_Q_INVALID_IDX;
		} else {
			iw_qvinfo->aeq_idx = NSER_Q_INVALID_IDX;
			iw_qvinfo->ceq_idx = ceq_idx++;
		}
		iw_qvinfo->itr_idx = NSER_IDX_NOITR;
		iw_qvinfo->v_idx = rf->iw_msixtbl[i].idx;
		pmsix++;
	}

	return 0;
}

/**
 * nser_destroy_irq - destroy device interrupts
 * @rf: RDMA PCI function
 * @msix_vec: msix vector to disable irq
 * @dev_id: parameter to pass to free_irq (used during irq setup)
 *
 * The function is called when destroying aeq/ceq
 */
static void nser_destroy_irq(struct nser_pci_f *rf,
			      struct nser_msix_vector *msix_vec, void *dev_id)
{
	struct nser_sc_dev *dev = &rf->sc_dev;

	dev->irq_ops->nser_dis_irq(dev, msix_vec->idx);
	irq_update_affinity_hint(msix_vec->irq, NULL);
	free_irq(msix_vec->irq, dev_id);
}

/**
 * nser_destroy_cqp  - destroy control qp
 * @rf: RDMA PCI function
 * @free_hwcqp: 1 if hw cqp should be freed
 *
 * Issue destroy cqp request and
 * free the resources associated with the cqp
 */
static void nser_destroy_cqp(struct nser_pci_f *rf, bool free_hwcqp)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_cqp *cqp = &rf->cqp;
	int status = 0;

	if (rf->cqp_cmpl_wq)
		destroy_workqueue(rf->cqp_cmpl_wq);
	status = nser_sc_cqp_destroy(dev->cqp, free_hwcqp);
	if (status)
		nser_dbg(dev, "ERR: Destroy CQP failed %d\n", status);

	nser_cleanup_pending_cqp_op(rf);
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va,
			  cqp->sq.pa);
	cqp->sq.va = NULL;
	kfree(cqp->scratch_array);
	cqp->scratch_array = NULL;
	kfree(cqp->cqp_requests);
	cqp->cqp_requests = NULL;
}

static void nser_destroy_virt_aeq(struct nser_pci_f *rf)
{
	struct nser_aeq *aeq = &rf->aeq;
	u32 pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);
	dma_addr_t *pg_arr = (dma_addr_t *)aeq->palloc.level1.addr;

	nser_unmap_vm_page_list(&rf->hw, pg_arr, pg_cnt);
	nser_free_pble(rf->pble_rsrc, &aeq->palloc);
	vfree(aeq->mem.va);
}

/**
 * nser_destroy_aeq - destroy aeq
 * @rf: RDMA PCI function
 *
 * Issue a destroy aeq request and
 * free the resources associated with the aeq
 * The function is called during driver unload
 */
static void nser_destroy_aeq(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_aeq *aeq = &rf->aeq;
	int status = -EBUSY;

	if (!rf->msix_shared) {
		/* Non-privileged drivers call the IDC..*/
		nser_destroy_irq(rf, rf->iw_msixtbl, rf);
	}
	if (rf->reset)
		goto exit;

	aeq->sc_aeq.size = 0;
	status = nser_cqp_aeq_cmd(dev, &aeq->sc_aeq, NSER_OP_AEQ_DESTROY);
	if (status)
		nser_dbg(dev, "ERR: Destroy AEQ failed %d\n", status);

exit:
	if (aeq->virtual_map)
		nser_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va,
				  aeq->mem.pa);
		aeq->mem.va = NULL;
	}
}

/**
 * nser_destroy_ceq - destroy ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq to be destroyed
 *
 * Issue a destroy ceq request and
 * free the resources associated with the ceq
 */
static void nser_destroy_ceq(struct nser_pci_f *rf, struct nser_ceq *iwceq)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	int status;

	if (rf->reset)
		goto exit;

	status = nser_sc_ceq_destroy(&iwceq->sc_ceq, 0, 1);
	if (status) {
		nser_dbg(dev, "ERR: CEQ destroy command failed %d\n", status);
		goto exit;
	}

	status = nser_sc_cceq_destroy_done(&iwceq->sc_ceq);
	if (status)
		nser_dbg(dev, "ERR: CEQ destroy completion failed %d\n",
			  status);
exit:
	dma_free_coherent(dev->hw->device, iwceq->mem.size, iwceq->mem.va,
			  iwceq->mem.pa);
	iwceq->mem.va = NULL;

	kfree(iwceq->sc_ceq.reg_cq);
}

/**
 * nser_del_ceq_0 - destroy ceq 0
 * @rf: RDMA PCI function
 *
 * Disable the ceq 0 interrupt and destroy the ceq 0
 */
static void nser_del_ceq_0(struct nser_pci_f *rf)
{
	struct nser_ceq *iwceq = rf->ceqlist;
	struct nser_msix_vector *msix_vec;

	if (rf->msix_shared) {
		msix_vec = &rf->iw_msixtbl[0];
		nser_destroy_irq(rf, msix_vec, rf);
	} else {
		msix_vec = &rf->iw_msixtbl[1];
		nser_destroy_irq(rf, msix_vec, iwceq);
	}

	nser_destroy_ceq(rf, iwceq);
	rf->sc_dev.ceq_valid = false;
	rf->ceqs_count = 0;
}

/**
 * nser_del_ceqs - destroy all ceq's except CEQ 0
 * @rf: RDMA PCI function
 *
 * Go through all of the device ceq's, except 0, and for each
 * ceq disable the ceq interrupt and destroy the ceq
 */
static void nser_del_ceqs(struct nser_pci_f *rf)
{
	struct nser_ceq *iwceq = &rf->ceqlist[1];
	struct nser_msix_vector *msix_vec;
	u32 i = 0;

	if (rf->msix_shared)
		msix_vec = &rf->iw_msixtbl[1];
	else
		msix_vec = &rf->iw_msixtbl[2];

	for (i = 1; i < rf->ceqs_count; i++, msix_vec++, iwceq++) {
		nser_destroy_irq(rf, msix_vec, iwceq);
		nser_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
				  NSER_OP_CEQ_DESTROY);
		dma_free_coherent(rf->sc_dev.hw->device, iwceq->mem.size,
				  iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
		kfree(iwceq->sc_ceq.reg_cq);
	}
	rf->ceqs_count = 1;
}

/**
 * nser_destroy_ccq - destroy control cq
 * @rf: RDMA PCI function
 *
 * Issue destroy ccq request and
 * free the resources associated with the ccq
 */
static void nser_destroy_ccq(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_ccq *ccq = &rf->ccq;
	int status = 0;

	if (!rf->reset)
		status = nser_sc_ccq_destroy(dev->ccq, 0, true);
	if (status)
		nser_dbg(dev, "ERR: CCQ destroy failed %d\n", status);
	dma_free_coherent(dev->hw->device, ccq->mem_cq.size, ccq->mem_cq.va,
			  ccq->mem_cq.pa);
	ccq->mem_cq.va = NULL;
}

static void nser_vsi_reset(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	int status = 0;

	if (!rf->reset)
		status = nser_sc_vsi_reset(dev, 0, true);
	if (status)
		nser_dbg(dev, "ERR: VSI reset failed %d\n", status);
}


/**
 * nser_close_hmc_objects_type - delete hmc objects of a given type
 * @dev: rdma device
 * @obj_type: the hmc object type to be deleted
 * @hmc_info: host memory info struct
 * @privileged: permission to close HMC objects
 * @reset: true if called before reset
 */
static void nser_close_hmc_objects_type(struct nser_sc_dev *dev,
					 enum nser_hmc_rsrc_type obj_type,
					 struct nser_hmc_info *hmc_info,
					 bool privileged, bool reset)
{
	struct nser_hmc_del_obj_info info = {};

	info.hmc_info = hmc_info;
	info.rsrc_type = obj_type;
	info.count = hmc_info->hmc_obj[obj_type].cnt;
	info.privileged = privileged;
	if (nser_sc_del_hmc_obj(dev, &info, reset))
		nser_dbg(dev, "ERR: del HMC obj of type %d failed\n",
				obj_type);
}

/**
 * nser_del_hmc_objects - remove all device hmc objects
 * @dev: rdma device
 * @hmc_info: hmc_info to free
 * @privileged: permission to delete HMC objects
 * @reset: true if called before reset
 */
void nser_del_hmc_objects(struct nser_sc_dev *dev,
			   struct nser_hmc_info *hmc_info, bool privileged,
			   bool reset)
{
	unsigned int i;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt)
			nser_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
						     hmc_info, privileged, reset);
	}
}

/**
 * nser_create_hmc_obj_type - create hmc object of a given type
 * @dev: hardware control device structure
 * @info: information for the hmc object to create
 */
static int nser_create_hmc_obj_type(struct nser_sc_dev *dev,
				     struct nser_hmc_create_obj_info *info)
{
	return nser_sc_create_hmc_obj(dev, info);
}

/**
 * nser_create_hmc_objs - create all hmc objects for the device
 * @rf: RDMA PCI function
 * @privileged: permission to create HMC objects
 *
 * Create the device hmc objects and allocate hmc pages
 * Return 0 if successful, otherwise clean up and return error
 */
static int nser_create_hmc_objs(struct nser_pci_f *rf, bool privileged)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_hmc_create_obj_info info = {};
	int i, status = 0;

	info.hmc_info = dev->hmc_info;
	info.privileged = privileged;
	info.entry_type = rf->sd_type;

	for (i = 0; i < IW_HMC_OBJ_TYPE_NUM; i++) {
		if (iw_hmc_obj_types[i] == NSER_HMC_IW_PBLE)
			continue;
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt) {
			info.rsrc_type = iw_hmc_obj_types[i];
			info.count = dev->hmc_info->hmc_obj[info.rsrc_type].cnt;
			info.add_sd_cnt = 0;
			status = nser_create_hmc_obj_type(dev, &info);
			if (status) {
				nser_dbg(dev,
					  "ERR: create obj type %d status = %d\n",
					  iw_hmc_obj_types[i], status);
				break;
			}
		}
	}

	if (!status)
		return nser_sc_static_hmc_pages_allocated(dev->cqp, 0, dev->hmc_fn_id,
							   true, true);

	while (i) {
		i--;
		/* destroy the hmc objects of a given type */
		if (dev->hmc_info->hmc_obj[iw_hmc_obj_types[i]].cnt)
			nser_close_hmc_objects_type(dev, iw_hmc_obj_types[i],
						     dev->hmc_info, privileged,
						     false);
	}

	return status;
}

/**
 * nser_obj_aligned_mem - get aligned memory from device allocated memory
 * @rf: RDMA PCI function
 * @memptr: points to the memory addresses
 * @size: size of memory needed
 * @mask: mask for the aligned memory
 *
 * Get aligned memory of the requested size and
 * update the memptr to point to the new aligned memory
 * Return 0 if successful, otherwise return no memory error
 */
int nser_obj_aligned_mem(struct nser_pci_f *rf, struct nser_dma_mem *memptr,
			  u32 size, u32 mask)
{
	unsigned long va, newva;
	unsigned long extra;

	va = (unsigned long)rf->obj_next.va;
	newva = va;
	if (mask)
		newva = ALIGN(va, (unsigned long)mask + 1ULL);
	extra = newva - va;
	memptr->va = (u8 *)va + extra;
	memptr->pa = rf->obj_next.pa + extra;
	memptr->size = size;
	if (((u8 *)memptr->va + size) > ((u8 *)rf->obj_mem.va + rf->obj_mem.size))
		return -ENOMEM;

	rf->obj_next.va = (u8 *)memptr->va + size;
	rf->obj_next.pa = memptr->pa + size;

	return 0;
}

/**
 * nser_create_cqp - create control qp
 * @rf: RDMA PCI function
 *
 * Return 0, if the cqp and all the resources associated with it
 * are successfully created, otherwise return error
 */
static int nser_create_cqp(struct nser_pci_f *rf)
{
	u32 sqsize = NSER_CQP_SW_SQSIZE_2048;
	struct nser_dma_mem mem;
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_cqp_init_info cqp_init_info = {};
	struct nser_cqp *cqp = &rf->cqp;
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
	cqp->sq.size = ALIGN(sizeof(struct nser_cqp_sq_wqe) * sqsize,
			     NSER_CQP_ALIGNMENT);
	cqp->sq.va = dma_alloc_coherent(dev->hw->device, cqp->sq.size,
					&cqp->sq.pa, GFP_KERNEL);
	if (!cqp->sq.va) {
		status = -ENOMEM;
		goto err_sq;
	}

	status = nser_obj_aligned_mem(rf, &mem, sizeof(struct nser_cqp_ctx),
				       NSER_HOST_CTX_ALIGNMENT_M);
	if (status)
		goto err_ctx;

	dev->cqp->host_ctx_pa = mem.pa;
	dev->cqp->host_ctx = mem.va;
	/* populate the cqp init info */
	cqp_init_info.dev = dev;
	cqp_init_info.sq_size = sqsize;
	cqp_init_info.sq = cqp->sq.va;
	cqp_init_info.sq_pa = cqp->sq.pa;
	cqp_init_info.host_ctx_pa = mem.pa;
	cqp_init_info.host_ctx = mem.va;
	if (dev->privileged) {
		cqp_init_info.hmc_profile = rf->rsrc_profile;
		cqp_init_info.ena_vf_count = rf->max_rdma_vfs;
	}
	cqp_init_info.scratch_array = cqp->scratch_array;
	memcpy(&cqp_init_info.cc_params, &rf->cc_params,
	       sizeof(cqp_init_info.cc_params));

	cqp_init_info.timely_ena = rf->timely_ena;
	cqp_init_info.dcqcn_ena = rf->dcqcn_ena;

	if (rf->hmc_va && !rf->ftype && nser_hmc_on_chip &&
		rf->sc_dev.hw_attrs.uk_attrs.hw_rev == IIDC_RDMA_GEN_MOONSTONE)
		cqp_init_info.hmc_on_chip = true;
	else
		cqp_init_info.hmc_on_chip = false;

	cqp_init_info.mirror_ena = nser_mirror_ena;

	cqp_init_info.hw_maj_ver = NSER_CQPHC_HW_MAJVER_GEN_2;
	status = nser_sc_cqp_init(dev->cqp, &cqp_init_info);
	if (status) {
		nser_dbg(dev, "ERR: cqp init status %d\n", status);
		goto err_ctx;
	}

	spin_lock_init(&cqp->req_lock);
	spin_lock_init(&cqp->compl_lock);

	status = nser_sc_cqp_create(dev->cqp, &maj_err, &min_err);
	if (status) {
		nser_dbg(dev,
			  "ERR: cqp create failed - status %d maj_err %d min_err %d\n",
			  status, maj_err, min_err);
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
	dma_free_coherent(dev->hw->device, cqp->sq.size, cqp->sq.va,
			  cqp->sq.pa);
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
 * nser_create_ccq - create control cq
 * @rf: RDMA PCI function
 *
 * Return 0, if the ccq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int nser_create_ccq(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_ccq_init_info info = {};
	struct nser_ccq *ccq = &rf->ccq;
	int status;

	dev->ccq = &ccq->sc_cq;
	dev->ccq->dev = dev;
	info.dev = dev;
	ccq->shadow_area.size = sizeof(struct nser_cq_shadow_area);
	ccq->mem_cq.size = ALIGN(sizeof(struct nser_cqe) * IW_CCQ_SIZE,
				 NSER_CQ0_ALIGNMENT);
	ccq->mem_cq.va = dma_alloc_coherent(dev->hw->device, ccq->mem_cq.size,
					    &ccq->mem_cq.pa, GFP_KERNEL);
	if (!ccq->mem_cq.va)
		return -ENOMEM;

	status = nser_obj_aligned_mem(rf, &ccq->shadow_area,
				       ccq->shadow_area.size,
				       NSER_SHADOWAREA_M);
	if (status)
		goto exit;

	ccq->sc_cq.back_cq = ccq;
	/* populate the ccq init info */
	info.cq_base = ccq->mem_cq.va;
	info.cq_pa = ccq->mem_cq.pa;
	info.num_elem = IW_CCQ_SIZE;
	info.shadow_area = ccq->shadow_area.va;
	info.shadow_area_pa = ccq->shadow_area.pa;
	info.ceqe_mask = false;
	info.ceq_id_valid = true;
	info.shadow_read_threshold = 16;
	info.vsi = &rf->default_vsi;
	status = nser_sc_ccq_init(dev->ccq, &info);
	if (!status)
		status = nser_sc_ccq_create(dev->ccq, 0, false, true);
exit:
	if (status) {
		dma_free_coherent(dev->hw->device, ccq->mem_cq.size,
				  ccq->mem_cq.va, ccq->mem_cq.pa);
		ccq->mem_cq.va = NULL;
	}

	return status;
}

/**
 * nser_cfg_ceq_vector - set up the msix interrupt vector for
 * ceq
 * @rf: RDMA PCI function
 * @iwceq: ceq associated with the vector
 * @ceq_id: the id number of the iwceq
 * @msix_vec: interrupt vector information
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int nser_cfg_ceq_vector(struct nser_pci_f *rf, struct nser_ceq *iwceq,
				u32 ceq_id, struct nser_msix_vector *msix_vec)
{
	int status;

	if (rf->msix_shared && !ceq_id) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "nser-%s-AEQCEQ-0", dev_name(&rf->pcidev->dev));
		status = request_threaded_irq(msix_vec->irq, NULL,
				nser_aeq_ceq0_irq_thread, IRQF_ONESHOT,
				msix_vec->name, rf);
	} else {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "nser-%s-CEQ-%d",
			 dev_name(&rf->pcidev->dev), ceq_id);
		status = request_threaded_irq(msix_vec->irq, NULL,
				nser_ceq_irq_thread, IRQF_ONESHOT,
				msix_vec->name, iwceq);
	}
	cpumask_clear(&msix_vec->mask);
	cpumask_set_cpu(msix_vec->cpu_affinity, &msix_vec->mask);
	irq_update_affinity_hint(msix_vec->irq, &msix_vec->mask);
	if (status) {
		nser_dbg(&rf->sc_dev, "ERR: ceq irq config fail\n");
		return status;
	}

	msix_vec->ceq_id = ceq_id;
	return 0;
}

/**
 * nser_cfg_aeq_vector - set up the msix vector for aeq
 * @rf: RDMA PCI function
 *
 * Allocate interrupt resources and enable irq handling
 * Return 0 if successful, otherwise return error
 */
static int nser_cfg_aeq_vector(struct nser_pci_f *rf)
{
	struct nser_msix_vector *msix_vec = rf->iw_msixtbl;
	int status = 0;

	if (!rf->msix_shared) {
		snprintf(msix_vec->name, sizeof(msix_vec->name) - 1,
			 "nser-%s-AEQ", dev_name(&rf->pcidev->dev));
		status = request_threaded_irq(msix_vec->irq, NULL,
				nser_aeq_ceq0_irq_thread, IRQF_ONESHOT,
				msix_vec->name, rf);
	}
	if (status)
		nser_dbg(&rf->sc_dev, "ERR: aeq irq config fail\n");
	return status;
}

/**
 * nser_create_ceq - create completion event queue
 * @rf: RDMA PCI function
 * @iwceq: pointer to the ceq resources to be created
 * @ceq_id: the id number of the iwceq
 * @vsi: SC vsi struct
 *
 * Return 0, if the ceq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int nser_create_ceq(struct nser_pci_f *rf, struct nser_ceq *iwceq,
			    u32 ceq_id, struct nser_sc_vsi *vsi)
{
	int status;
	struct nser_ceq_init_info info = {};
	struct nser_sc_dev *dev = &rf->sc_dev;
	u32 ceq_size;

	info.ceq_id = ceq_id;
	iwceq->rf = rf;
	ceq_size = min(rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt,
		       dev->hw_attrs.max_hw_ceq_size);
	iwceq->mem.size = ALIGN(sizeof(struct nser_ceqe) * ceq_size,
				NSER_CEQ_ALIGNMENT);
	iwceq->mem.va = dma_alloc_coherent(dev->hw->device, iwceq->mem.size,
					   &iwceq->mem.pa, GFP_KERNEL);
	if (!iwceq->mem.va)
		return -ENOMEM;

	info.reg_cq = kmalloc_array(rf->max_cq, sizeof(struct nser_sc_cq *), GFP_KERNEL);
	if (!info.reg_cq)
		return -ENOMEM;

	info.ceq_id = ceq_id;
	info.ceqe_base = iwceq->mem.va;
	info.ceqe_pa = iwceq->mem.pa;
	info.elem_cnt = ceq_size;
	info.int_en = 1;
	info.msix_idx = iwceq->msix_idx;

	iwceq->sc_ceq.ceq_id = ceq_id;
	info.dev = dev;
	info.vsi = vsi;
	status = nser_sc_ceq_init(&iwceq->sc_ceq, &info);
	if (!status) {
		if (dev->ceq_valid)
			status = nser_cqp_ceq_cmd(&rf->sc_dev, &iwceq->sc_ceq,
						   NSER_OP_CEQ_CREATE);
		else
			status = nser_sc_cceq_create(&iwceq->sc_ceq);
	}

	if (status) {
		dma_free_coherent(dev->hw->device, iwceq->mem.size,
				  iwceq->mem.va, iwceq->mem.pa);
		iwceq->mem.va = NULL;
		kfree(info.reg_cq);
	}

	return status;
}

/**
 * nser_setup_ceq_0 - create CEQ 0 and it's interrupt resource
 * @rf: RDMA PCI function
 *
 * Allocate a list for all device completion event queues
 * Create the ceq 0 and configure it's msix interrupt vector
 * Return 0, if successfully set up, otherwise return error
 */
static int nser_setup_ceq_0(struct nser_pci_f *rf)
{
	struct nser_ceq *iwceq;
	struct nser_msix_vector *msix_vec;
	u32 i;
	int status = 0;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	rf->ceqlist = kcalloc(num_ceqs, sizeof(*rf->ceqlist), GFP_KERNEL);
	if (!rf->ceqlist) {
		status = -ENOMEM;
		goto exit;
	}

	iwceq = &rf->ceqlist[0];
	i = rf->msix_shared ? 0 : 1;
	msix_vec = &rf->iw_msixtbl[i];
	iwceq->irq = msix_vec->irq;
	iwceq->msix_idx = msix_vec->idx;
	status = nser_create_ceq(rf, iwceq, 0, &rf->default_vsi);
	if (status) {
		nser_dbg(&rf->sc_dev, "ERR: create ceq status = %d\n",
			  status);
		goto exit;
	}

	spin_lock_init(&iwceq->ce_lock);
	status = nser_cfg_ceq_vector(rf, iwceq, 0, msix_vec);
	if (status) {
		nser_destroy_ceq(rf, iwceq);
		goto exit;
	}

	nser_ena_intr(&rf->sc_dev, msix_vec->idx);

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
 * nser_setup_ceqs - manage the device ceq's and their interrupt resources
 * @rf: RDMA PCI function
 * @vsi: VSI structure for this CEQ
 *
 * Allocate a list for all device completion event queues
 * Create the ceq's and configure their msix interrupt vectors
 * Return 0, if ceqs are successfully set up, otherwise return error
 */
static int nser_setup_ceqs(struct nser_pci_f *rf, struct nser_sc_vsi *vsi)
{
	u32 i;
	u32 ceq_id;
	struct nser_ceq *iwceq;
	struct nser_msix_vector *msix_vec;
	int status;
	u32 num_ceqs;

	num_ceqs = min(rf->msix_count, rf->sc_dev.hmc_fpm_misc.max_ceqs);
	i = (rf->msix_shared) ? 1 : 2;
	for (ceq_id = 1; i < num_ceqs; i++, ceq_id++) {
		iwceq = &rf->ceqlist[ceq_id];
		msix_vec = &rf->iw_msixtbl[i];
		iwceq->irq = msix_vec->irq;
		iwceq->msix_idx = msix_vec->idx;
		status = nser_create_ceq(rf, iwceq, ceq_id, vsi);
		if (status) {
			nser_dbg(&rf->sc_dev,
				  "ERR: create ceq status = %d\n", status);
			goto del_ceqs;
		}
		spin_lock_init(&iwceq->ce_lock);
		status = nser_cfg_ceq_vector(rf, iwceq, ceq_id, msix_vec);
		if (status) {
			nser_destroy_ceq(rf, iwceq);
			goto del_ceqs;
		}
		nser_ena_intr(&rf->sc_dev, msix_vec->idx);
		rf->ceqs_count++;
	}

	return 0;

del_ceqs:
	nser_del_ceqs(rf);

	return status;
}

static int nser_create_virt_aeq(struct nser_pci_f *rf, u32 size)
{
	struct nser_aeq *aeq = &rf->aeq;
	dma_addr_t *pg_arr;
	u32 pg_cnt;
	int status;

	aeq->mem.size = sizeof(struct nser_sc_aeqe) * size;
	aeq->mem.va = vzalloc(aeq->mem.size);

	if (!aeq->mem.va)
		return -ENOMEM;

	pg_cnt = DIV_ROUND_UP(aeq->mem.size, PAGE_SIZE);
	status = nser_get_pble(rf->pble_rsrc, &aeq->palloc, pg_cnt, true);
	if (status) {
		vfree(aeq->mem.va);
		return status;
	}

	pg_arr = (dma_addr_t *)aeq->palloc.level1.addr;
	status = nser_map_vm_page_list(&rf->hw, aeq->mem.va, pg_arr, pg_cnt);
	if (status) {
		nser_free_pble(rf->pble_rsrc, &aeq->palloc);
		vfree(aeq->mem.va);
		return status;
	}

	return 0;
}

/**
 * nser_create_aeq - create async event queue
 * @rf: RDMA PCI function
 *
 * Return 0, if the aeq and the resources associated with it
 * are successfully created, otherwise return error
 */
static int nser_create_aeq(struct nser_pci_f *rf)
{
	struct nser_aeq_init_info info = {};
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_aeq *aeq = &rf->aeq;
	struct nser_hmc_info *hmc_info = rf->sc_dev.hmc_info;
	u32 aeq_size;
	int status;

	aeq_size = hmc_info->hmc_obj[NSER_HMC_IW_QP].cnt +
		   hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt;
	aeq_size = min(aeq_size, dev->hw_attrs.max_hw_aeq_size);

	aeq->mem.size = ALIGN(sizeof(struct nser_sc_aeqe) * aeq_size,
			      NSER_AEQ_ALIGNMENT);
	aeq->mem.va = dma_alloc_coherent(dev->hw->device, aeq->mem.size,
					 &aeq->mem.pa,
					 GFP_KERNEL | __GFP_NOWARN);
	if (aeq->mem.va)
		goto skip_virt_aeq;

	/* physically mapped aeq failed. setup virtual aeq */
	status = nser_create_virt_aeq(rf, aeq_size);
	if (status)
		return status;

	info.virtual_map = true;
	aeq->virtual_map = info.virtual_map;
	info.pbl_chunk_size = 1;
	info.first_pm_pbl_idx = aeq->palloc.level1.idx;

skip_virt_aeq:
	info.aeqe_base = aeq->mem.va;
	info.aeq_elem_pa = aeq->mem.pa;
	info.elem_cnt = aeq_size;
	info.dev = dev;
	info.msix_idx = rf->iw_msixtbl->idx;
	status = nser_sc_aeq_init(&aeq->sc_aeq, &info);
	if (status)
		goto err;

	status = nser_cqp_aeq_cmd(dev, &aeq->sc_aeq, NSER_OP_AEQ_CREATE);
	if (status)
		goto err;

	return 0;

err:
	if (aeq->virtual_map)
		nser_destroy_virt_aeq(rf);
	else {
		dma_free_coherent(dev->hw->device, aeq->mem.size, aeq->mem.va,
				  aeq->mem.pa);
		aeq->mem.va = NULL;
	}

	return status;
}

/**
 * nser_setup_aeq - set up the device aeq
 * @rf: RDMA PCI function
 *
 * Create the aeq and configure its msix interrupt vector
 * Return 0 if successful, otherwise return error
 */
static int nser_setup_aeq(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	int status;

	status = nser_create_aeq(rf);
	if (status)
		return status;

	status = nser_cfg_aeq_vector(rf);
	if (status) {
		nser_destroy_aeq(rf);
		return status;
	}

	if (!rf->msix_shared)
		nser_ena_intr(dev, rf->iw_msixtbl[0].idx);

	return 0;
}

/**
 * nser_hmc_setup - create hmc objects for the device
 * @rf: RDMA PCI function
 *
 * Set up the device private memory space for the number and size of
 * the hmc objects and create the objects
 * Return 0 if successful, otherwise return error
 */
static int nser_hmc_setup(struct nser_pci_f *rf)
{
	int status;
	struct nser_sc_dev *dev = &rf->sc_dev;

	rf->sd_type = NSER_SD_TYPE_DIRECT;
	status = nser_cfg_fpm_val(dev);
	if (status)
		return status;

	status = nser_create_hmc_objs(rf, true);

	return status;
}

/**
 * nser_del_init_mem - deallocate memory resources
 * @rf: RDMA PCI function
 */
static void nser_del_init_mem(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;

	kfree(dev->hmc_info->sd_table.sd_entry);
	dev->hmc_info->sd_table.sd_entry = NULL;
	vfree(rf->mem_rsrc);
	rf->mem_rsrc = NULL;
	dma_free_coherent(rf->hw.device, rf->obj_mem.size, rf->obj_mem.va, rf->obj_mem.pa);
	rf->obj_mem.va = NULL;

	kfree(rf->allocated_ws_nodes);
	rf->allocated_ws_nodes = NULL;

	kfree(rf->ceqlist);
	rf->ceqlist = NULL;
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;
	if (rf->vchnl_wq)
		destroy_workqueue(rf->vchnl_wq);
}

/**
 * nser_initialize_dev - initialize device
 * @rf: RDMA PCI function
 *
 * Allocate memory for the hmc objects and initialize iwdev
 * Return 0 if successful, otherwise clean up the resources
 * and return error
 */
static int nser_initialize_dev(struct nser_pci_f *rf)
{
	int status;
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_device_init_info info = {};
	struct nser_dma_mem mem;
	u32 size;

	size = sizeof(struct nser_hmc_pble_rsrc) +
	       sizeof(struct nser_hmc_info) +
	       (sizeof(struct nser_hmc_obj_info) * NSER_HMC_IW_MAX);

	rf->hmc_info_mem = kzalloc(size, GFP_KERNEL);
	if (!rf->hmc_info_mem)
		return -ENOMEM;

	rf->pble_rsrc = (struct nser_hmc_pble_rsrc *)rf->hmc_info_mem;
	dev->hmc_info = &rf->hw.hmc;
	dev->hmc_info->hmc_obj = (struct nser_hmc_obj_info *)
				 (rf->pble_rsrc + 1);

	status = nser_obj_aligned_mem(rf, &mem, NSER_QUERY_FPM_BUF_SIZE,
				       NSER_FPM_QUERY_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_query_buf_pa = mem.pa;
	info.fpm_query_buf = mem.va;

	status = nser_obj_aligned_mem(rf, &mem, NSER_COMMIT_FPM_BUF_SIZE,
				       NSER_FPM_COMMIT_BUF_ALIGNMENT_M);
	if (status)
		goto error;

	info.fpm_commit_buf_pa = mem.pa;
	info.fpm_commit_buf = mem.va;

	info.bar0 = rf->hw.hw_addr;
	/* Not used in SRIOV VF mode */
	info.hmc_fn_id = rf->pf_id;
	info.privileged = !rf->ftype;
	info.vchnl_wq = rf->vchnl_wq;
	info.max_vfs = rf->max_rdma_vfs;
	info.vsi_num = rf->default_vsi.vsi_idx;
	info.hw = &rf->hw;
	info.hmc_va = rf->hmc_va;

	status = nser_sc_dev_init(&rf->sc_dev, &info);
	if (status)
		goto error;

	if (!rf->sc_dev.privileged)
		status = nser_vchnl_vf_get_vlan_parsing_cfg(&rf->sc_dev,
							     &rf->vlan_parse_en);
	else
		rf->vlan_parse_en = 1;
	if (status)
		goto error;

	return status;
error:
	kfree(rf->hmc_info_mem);
	rf->hmc_info_mem = NULL;

	return status;
}

/**
 * nser_rt_deinit_hw - clean up the nser device resources
 * @iwdev: nser device
 *
 * remove the mac ip entry and ipv4/ipv6 addresses, destroy the
 * device queues and free the pble and the hmc objects
 */
void nser_rt_deinit_hw(struct nser_device *iwdev)
{
	nser_dbg(&iwdev->rf->sc_dev, "INIT: state = %d\n", iwdev->init_state);

	switch (iwdev->init_state) {
	case IP_ADDR_REGISTERED:
	case AEQ_CREATED:
	case PBLE_CHUNK_MEM:
	case CEQS_CREATED:
	case REM_ENDPOINT_TRK_CREATED:
		break;
	default:
		dev_warn(idev_to_dev(&iwdev->rf->sc_dev),
				"bad init_state = %d\n", iwdev->init_state);
		break;
	}

	if (iwdev->vsi.pestat) {
		nser_vsi_stats_free(&iwdev->vsi);
		kfree(iwdev->vsi.pestat);
	}
	if (iwdev->cleanup_wq)
		destroy_workqueue(iwdev->cleanup_wq);
}

static int nser_setup_init_state(struct nser_pci_f *rf)
{
	int status;

	status = nser_save_msix_info(rf);
	if (status)
		return status;

	rf->hw.device = &rf->pcidev->dev;
	rf->obj_mem.size = ALIGN(8192, NSER_HW_PAGE_SIZE);
	rf->obj_mem.va = dma_alloc_coherent(rf->hw.device, rf->obj_mem.size,
					    &rf->obj_mem.pa, GFP_KERNEL);
	if (!rf->obj_mem.va) {
		status = -ENOMEM;
		goto clean_msixtbl;
	}

	rf->obj_next = rf->obj_mem;
	rf->vchnl_wq = alloc_ordered_workqueue("nser-virtchnl-wq", 0);
	if (!rf->vchnl_wq) {
		status = -ENOMEM;
		goto clean_obj_mem;
	}

	mutex_init(&rf->sc_dev.vchnl_mutex);
	status = nser_initialize_dev(rf);
	if (status)
		goto clean_wq;

	return 0;

clean_wq:
	destroy_workqueue(rf->vchnl_wq);
clean_obj_mem:
	dma_free_coherent(rf->hw.device, rf->obj_mem.size, rf->obj_mem.va,
			  rf->obj_mem.pa);
	rf->obj_mem.va = NULL;
clean_msixtbl:
	kfree(rf->iw_msixtbl);
	rf->iw_msixtbl = NULL;
	return status;
}

/**
 * nser_get_used_rsrc - determine resources used internally
 * @iwdev: nser device
 *
 * Called at the end of open to get all internal allocations
 */
static void nser_get_used_rsrc(struct nser_device *iwdev)
{
	iwdev->rf->used_pds = find_next_zero_bit(iwdev->rf->allocated_pds,
						 iwdev->rf->max_pd, 0);
}

void nser_ctrl_deinit_hw(struct nser_pci_f *rf)
{
	enum init_completion_state state = rf->init_state;

	rf->init_state = INVALID_STATE;
	if (rf->rsrc_created) {
		nser_destroy_aeq(rf);
		nser_destroy_pble_prm(rf->pble_rsrc);
		nser_del_ceqs(rf);
		rf->rsrc_created = false;
	}

	switch (state) {
	case CEQ0_CREATED:
		nser_del_ceq_0(rf);
		fallthrough;
	case CCQ_CREATED:
		nser_destroy_ccq(rf);
		fallthrough;
	case HW_RSRC_INITIALIZED:
	case HMC_OBJS_CREATED:
		nser_vsi_reset(rf);
		nser_del_hmc_objects(&rf->sc_dev, rf->sc_dev.hmc_info, true,
				      rf->reset);
		fallthrough;
	case CQP_CREATED:
		nser_destroy_cqp(rf, !rf->reset);
		if (!rf->sc_dev.privileged)
			nser_vchnl_vf_put_hmc_fcn(&rf->sc_dev);
		fallthrough;
	case INITIAL_STATE:
		nser_del_init_mem(rf);
		break;
	case INVALID_STATE:
	default:
		pr_warn("bad init_state = %d\n", rf->init_state);
		break;
	}
}

/**
 * nser_rt_init_hw - Initializes runtime portion of HW
 * @iwdev: nser device
 * @l2params: qos, tc, mtu info from netdev driver
 *
 * Create device queues ILQ, IEQ, CEQs and PBLEs. Setup nser
 * device resource objects.
 */
int nser_rt_init_hw(struct nser_device *iwdev,
		     struct nser_l2params *l2params)
{
	struct nser_pci_f *rf = iwdev->rf;
	struct nser_sc_dev *dev = &rf->sc_dev;
	struct nser_vsi_init_info vsi_info = {};
	struct nser_vsi_stats_info stats_info = {};
	int status;

	vsi_info.vm_vf_type = rf->ftype ? NSER_VF_TYPE : NSER_PF_TYPE;
	vsi_info.dev = dev;
	vsi_info.back_vsi = iwdev;
	vsi_info.params = l2params;
	vsi_info.pf_data_vsi_num = iwdev->vsi_num;
	vsi_info.register_qset = rf->gen_ops.register_qset;
	vsi_info.unregister_qset = rf->gen_ops.unregister_qset;
	vsi_info.exception_lan_q = 2;
	nser_sc_vsi_init(&iwdev->vsi, &vsi_info);

	stats_info.pestat = kzalloc(sizeof(*stats_info.pestat), GFP_KERNEL);
	if (!stats_info.pestat)
		return -ENOMEM;
	stats_info.fcn_id = dev->hmc_fn_id;
	status = nser_vsi_stats_init(&iwdev->vsi, &stats_info);
	if (status) {
		kfree(stats_info.pestat);
		return status;
	}

	do {
		if (!rf->rsrc_created) {
			status = nser_setup_ceqs(rf, &iwdev->vsi);
			if (status)
				break;

			iwdev->init_state = CEQS_CREATED;

			status = nser_hmc_init_pble(&rf->sc_dev,
						     rf->pble_rsrc);
			if (status) {
				nser_del_ceqs(rf);
				break;
			}

			iwdev->init_state = PBLE_CHUNK_MEM;

			status = nser_setup_aeq(rf);
			if (status) {
				nser_destroy_pble_prm(rf->pble_rsrc);
				nser_del_ceqs(rf);
				break;
			}
			iwdev->init_state = AEQ_CREATED;
			rf->rsrc_created = true;
		}

		iwdev->device_cap_flags = IB_DEVICE_MEM_WINDOW |
					  IB_DEVICE_MEM_MGT_EXTENSIONS;

		iwdev->device_cap_flags |= IB_DEVICE_RC_RNR_NAK_GEN;

		iwdev->device_cap_flags |= IB_DEVICE_MEM_WINDOW_TYPE_2B;

		nser_add_ip(iwdev);
		iwdev->init_state = IP_ADDR_REGISTERED;

		/* handles asynch cleanup tasks - disconnect CM , free qp,
		 * free cq bufs
		 */
		iwdev->cleanup_wq = alloc_workqueue("nser-cleanup-wq",
					WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
		if (!iwdev->cleanup_wq)
			return -ENOMEM;
		nser_get_used_rsrc(iwdev);
		init_waitqueue_head(&iwdev->suspend_wq);

		return 0;
	} while (0);

	dev_err(idev_to_dev(dev), "HW runtime init FAIL status = %d last cmpl = %d\n",
		status, iwdev->init_state);
	nser_rt_deinit_hw(iwdev);

	return status;
}

/**
 * nser_ctrl_init_hw - Initializes control portion of HW
 * @rf: RDMA PCI function
 *
 * Create admin queues, HMC obejcts and RF resource objects
 */
int nser_ctrl_init_hw(struct nser_pci_f *rf)
{
	struct nser_sc_dev *dev = &rf->sc_dev;
	int status;

	do {
		status = nser_setup_init_state(rf);
		if (status)
			break;
		rf->init_state = INITIAL_STATE;

		status = nser_create_cqp(rf);
		if (status)
			break;
		rf->init_state = CQP_CREATED;

		dev->feature_info[NSER_FEATURE_FW_INFO] = NSER_FW_VER_DEFAULT;

		status = nser_get_rdma_features(dev);
		if (status)
			break;


		status = nser_hmc_setup(rf);
		if (status)
			break;
		rf->init_state = HMC_OBJS_CREATED;

		status = nser_initialize_hw_rsrc(rf);
		if (status)
			break;
		rf->init_state = HW_RSRC_INITIALIZED;

		status = nser_create_ccq(rf);
		if (status)
			break;
		rf->init_state = CCQ_CREATED;

		status = nser_setup_ceq_0(rf);
		if (status)
			break;
		rf->init_state = CEQ0_CREATED;
		/* Handles processing of CQP completions */
		rf->cqp_cmpl_wq = alloc_ordered_workqueue("cqp_cmpl_wq",
						WQ_HIGHPRI | WQ_UNBOUND);
		if (!rf->cqp_cmpl_wq) {
			status = -ENOMEM;
			break;
		}
		INIT_WORK(&rf->cqp_cmpl_work, cqp_compl_worker);
		nser_sc_ccq_arm(dev->ccq);
		return 0;
	} while (0);

	pr_err("nser hardware initialization FAILED init_state=%d status=%d\n",
	       rf->init_state, status);
	nser_ctrl_deinit_hw(rf);
	return status;
}

/**
 * nser_set_hw_rsrc - set hw memory resources.
 * @rf: RDMA PCI function
 */
static void nser_set_hw_rsrc(struct nser_pci_f *rf)
{
	rf->allocated_qps = (void *)(rf->mem_rsrc +
		   (sizeof(struct nser_arp_entry) * rf->arp_table_size));
	rf->allocated_cqs = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_mrs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_pds = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->allocated_mcgs = &rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)];
	rf->allocated_arps = &rf->allocated_mcgs[BITS_TO_LONGS(rf->max_mcg)];

	rf->qp_table = (struct nser_qp **)
		(&rf->allocated_arps[BITS_TO_LONGS(rf->arp_table_size)]);
	rf->cq_table = (struct nser_cq **)(&rf->qp_table[rf->max_qp]);
	rf->allocated_qps_ts = (u64 *)(&rf->cq_table[rf->max_cq]);
	rf->allocated_cqs_ts = &rf->allocated_qps_ts[rf->max_qp];
	rf->allocated_mrs_ts = &rf->allocated_cqs_ts[rf->max_cq];
	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->arp_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->cqtable_lock);
	spin_lock_init(&rf->qh_list_lock);
}

/**
 * nser_calc_mem_rsrc_size - calculate memory resources size.
 * @rf: RDMA PCI function
 */
static u32 nser_calc_mem_rsrc_size(struct nser_pci_f *rf)
{
	u32 rsrc_size;

	rsrc_size = sizeof(struct nser_arp_entry) * rf->arp_table_size;
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qp);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->arp_table_size);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mcg);
	rsrc_size += sizeof(struct nser_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct nser_cq **) * rf->max_cq;
	rsrc_size += sizeof(u64) * rf->max_qp;
	rsrc_size += sizeof(u64) * rf->max_cq;
	rsrc_size += sizeof(u64) * rf->max_mr;
	return rsrc_size;
}

/**
 * nser_initialize_hw_rsrc - initialize hw resource tracking array
 * @rf: RDMA PCI function
 */
u32 nser_initialize_hw_rsrc(struct nser_pci_f *rf)
{
	u32 rsrc_size;
	u32 mrdrvbits;
	u32 ret;

	rf->allocated_ws_nodes =
		kcalloc(BITS_TO_LONGS(NSER_MAX_WS_NODES),
			sizeof(unsigned long), GFP_KERNEL);
	if (!rf->allocated_ws_nodes)
		return -ENOMEM;

	set_bit(0, rf->allocated_ws_nodes);
	rf->max_ws_node_id = NSER_MAX_WS_NODES;

	rf->max_cqe = rf->sc_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_QP].cnt;
	rf->max_mr = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_MR].cnt;
	rf->max_cq = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_CQ].cnt;
	rf->max_pd = rf->sc_dev.hw_attrs.max_hw_pds;
	rf->arp_table_size = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_ARP].cnt;
	rf->max_ah = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_AH].cnt;
	rf->max_mcg = rf->sc_dev.hmc_info->hmc_obj[NSER_HMC_IW_MG_ID].cnt;

	rf->qp_id_group_num = (rf->max_qp % 512) ? (rf->max_qp / 512) + 1 : (rf->max_qp / 512);
	memset(rf->used_qp_id_num, 0, sizeof(rf->used_qp_id_num));

	rsrc_size = nser_calc_mem_rsrc_size(rf);
	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		ret = -ENOMEM;
		goto mem_rsrc_vmalloc_fail;
	}

	rf->arp_table = (struct nser_arp_entry *)rf->mem_rsrc;

	nser_set_hw_rsrc(rf);

	set_bit(0, rf->allocated_mrs);
	set_bit(0, rf->allocated_qps);
	set_bit(0, rf->allocated_cqs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_arps);
	set_bit(0, rf->allocated_ahs);
	set_bit(1, rf->allocated_qps);
	set_bit(1, rf->allocated_cqs);
	set_bit(1, rf->allocated_pds);
	set_bit(2, rf->allocated_cqs);
	set_bit(2, rf->allocated_pds);
	rf->used_qp_id_num[0] = 2;

	memset(rf->allocated_qps_ts, 0, sizeof(u64)*rf->max_qp);
	memset(rf->allocated_cqs_ts, 0, sizeof(u64)*rf->max_cq);
	memset(rf->allocated_mrs_ts, 0, sizeof(u64)*rf->max_mr);

	INIT_LIST_HEAD(&rf->mc_qht_list.list);
	/* stag index mask has a minimum of 14 bits */
	mrdrvbits = 24 - max(get_count_order(rf->max_mr), 14);
	rf->mr_stagmask = ~(((1 << mrdrvbits) - 1) << (32 - mrdrvbits));

	return 0;

mem_rsrc_vmalloc_fail:
	kfree(rf->allocated_ws_nodes);
	rf->allocated_ws_nodes = NULL;

	return ret;
}

/**
 * nser_cqp_ce_handler - handle cqp completions
 * @rf: RDMA PCI function
 * @cq: cq for cqp completions
 */
void nser_cqp_ce_handler(struct nser_pci_f *rf, struct nser_sc_cq *cq)
{
	struct nser_cqp_request *cqp_request;
	struct nser_sc_dev *dev = &rf->sc_dev;
	u32 cqe_count = 0;
	struct nser_ccq_cqe_info info;
	unsigned long flags;
	int ret;

	do {
		memset(&info, 0, sizeof(info));
		spin_lock_irqsave(&rf->cqp.compl_lock, flags);
		ret = nser_sc_ccq_get_cqe_info(cq, &info);
		spin_unlock_irqrestore(&rf->cqp.compl_lock, flags);
		if (ret)
			break;

		cqp_request = (struct nser_cqp_request *)
			      (uintptr_t)info.scratch;
		if (info.error && !IS_ERR(cqp_request) && cqp_request &&
			nser_cqp_crit_err(dev, cqp_request->info.cqp_cmd,
						     info.maj_err_code,
						     info.min_err_code))
			dev_err(idev_to_dev(dev),
				"cqp opcode = 0x%x maj_err_code = 0x%x min_err_code = 0x%x\n",
				info.op_code, info.maj_err_code,
				info.min_err_code);
		if (!IS_ERR(cqp_request) && cqp_request) {
			cqp_request->compl_info.maj_err_code = info.maj_err_code;
			cqp_request->compl_info.min_err_code = info.min_err_code;
			cqp_request->compl_info.op_ret_val = info.op_ret_val;
			cqp_request->compl_info.error = info.error;
			nser_complete_cqp_request(&rf->cqp, cqp_request);
		} else if (cqp_request) {
			pr_err("%s:%d cqp_request(0x%p) is Illegal Address!!!\n",
					__func__, __LINE__, cqp_request);
		}

		cqe_count++;
	} while (1);

	if (cqe_count) {
		nser_process_bh(dev);
		nser_sc_ccq_arm(dev->ccq);
	}
}

/**
 * cqp_compl_worker - Handle cqp completions
 * @work: Pointer to work structure
 */
void cqp_compl_worker(struct work_struct *work)
{
	struct nser_pci_f *rf = container_of(work, struct nser_pci_f,
					      cqp_cmpl_work);
	struct nser_sc_cq *cq = &rf->ccq.sc_cq;

	nser_cqp_ce_handler(rf, cq);
}

/**
 * nser_manage_arp_cache - manage hw arp cache
 * @rf: RDMA PCI function
 * @mac_addr: mac address ptr
 * @ip_addr: ip addr for arp cache
 * @action: add, delete or modify
 */
void nser_manage_arp_cache(struct nser_pci_f *rf, const unsigned char *mac_addr,
			    u32 *ip_addr, u32 action)
{
	struct nser_add_arp_cache_entry_info *info;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int arp_index;

	arp_index = nser_arp_table(rf, ip_addr, mac_addr, action);
	if (arp_index == -1)
		return;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, false);
	if (!cqp_request)
		return;

	cqp_info = &cqp_request->info;
	if (action == NSER_ARP_ADD) {
		cqp_info->cqp_cmd = NSER_OP_ADD_ARP_CACHE_ENTRY;
		info = &cqp_info->in.u.add_arp_cache_entry.info;
		memset(info, 0, sizeof(*info));
		info->arp_index = (u16)arp_index;
		info->permanent = true;
		ether_addr_copy(info->mac_addr, mac_addr);
		cqp_info->in.u.add_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.add_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
	} else {
		cqp_info->cqp_cmd = NSER_OP_DELETE_ARP_CACHE_ENTRY;
		cqp_info->in.u.del_arp_cache_entry.scratch =
			(uintptr_t)cqp_request;
		cqp_info->in.u.del_arp_cache_entry.cqp = &rf->cqp.sc_cqp;
		cqp_info->in.u.del_arp_cache_entry.arp_index = arp_index;
	}

	cqp_info->post_sq = 1;
	nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);
}

/**
 * nser_hw_flush_wqes - flush qp's wqe
 * @rf: RDMA PCI function
 * @qp: hardware control qp
 * @info: info for flush
 * @wait: flag wait for completion
 */
int nser_hw_flush_wqes(struct nser_pci_f *rf, struct nser_sc_qp *qp,
			struct nser_qp_flush_info *info, bool wait)
{
	int status;
	struct nser_qp_flush_info *hw_info;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct nser_qp *iwqp = qp->qp_uk.back_qp;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.qp_flush_wqes.info;
	memcpy(hw_info, info, sizeof(*hw_info));
	cqp_info->cqp_cmd = NSER_OP_QP_FLUSH_WQES;
	cqp_info->post_sq = 1;
	cqp_info->in.u.qp_flush_wqes.qp = qp;
	cqp_info->in.u.qp_flush_wqes.scratch = (uintptr_t)cqp_request;
	status = nser_handle_cqp_op(rf, cqp_request);
	if (status) {
		qp->qp_uk.sq_flush_complete = true;
		qp->qp_uk.rq_flush_complete = true;
		nser_put_cqp_request(&rf->cqp, cqp_request);
		return status;
	}

	if (!wait || cqp_request->compl_info.maj_err_code)
		goto put_cqp;

	if (info->rq) {
		if (cqp_request->compl_info.min_err_code == NSER_CQP_COMPL_SQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* RQ WQE flush was requested but did not happen */
			qp->qp_uk.rq_flush_complete = true;
		}
	}
	if (info->sq) {
		if (cqp_request->compl_info.min_err_code == NSER_CQP_COMPL_RQ_WQE_FLUSHED ||
		    cqp_request->compl_info.min_err_code == 0) {
			/* SQ WQE flush was requested but did not happen */
			qp->qp_uk.sq_flush_complete = true;
		}
	}
	nser_dbg(&rf->sc_dev,
		  "VERBS: qp_id=%d  qpstate=%d ibqpstate=%d last_aeq=%d hw_iw_state=%d maj_err_code=%d min_err_code=%d\n",
		  iwqp->ibqp.qp_num, iwqp->rdma_state,
		  iwqp->ibqp_state, iwqp->last_aeq, iwqp->hw_rdma_state,
		  cqp_request->compl_info.maj_err_code,
		  cqp_request->compl_info.min_err_code);
put_cqp:
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

/**
 * nser_hw_manage_vf_pble_bp - manage vf pbles
 * @dev: hardware control device structure
 * @info: info for managing pble
 */
int nser_hw_manage_vf_pble_bp(struct nser_sc_dev *dev,
			       struct nser_manage_vf_pble_info *info)
{
	struct nser_pci_f *rf = dev_to_rf(dev);
	struct nser_manage_vf_pble_info *hw_info;
	struct nser_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int status;
	bool wait = true;

	if (rf->init_state < CCQ_CREATED)
		wait = false;

	cqp_request = nser_alloc_and_get_cqp_request(&rf->cqp, wait);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	hw_info = &cqp_request->info.in.u.manage_vf_pble_bp.info;
	memcpy(hw_info, info, sizeof(*hw_info));

	cqp_info->cqp_cmd = NSER_OP_MANAGE_VF_PBLE_BP;
	cqp_info->post_sq = 1;
	cqp_info->in.u.manage_vf_pble_bp.cqp = &rf->cqp.sc_cqp;
	cqp_info->in.u.manage_vf_pble_bp.scratch = (uintptr_t)cqp_request;

	status = nser_handle_cqp_op(rf, cqp_request);
	nser_put_cqp_request(&rf->cqp, cqp_request);

	return status;
}

void nser_flush_wqes(struct nser_qp *iwqp, u32 flush_mask)
{
	if (!(flush_mask & NSER_FLUSH_SQ) && !(flush_mask & NSER_FLUSH_RQ))
		return;

	if (!iwqp->user_mode)
		nser_sched_qp_flush_work(iwqp);

	iwqp->flush_issued = true;
}

