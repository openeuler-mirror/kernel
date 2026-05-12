// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Interrupt Management
 */

#define pr_fmt(fmt) "UMMU: " fmt
#include <linux/interrupt.h>

#include "trace/trace.h"
#include "ummu.h"
#include "queue.h"
#include "regs.h"
#include "logic_ummu/logic_ummu.h"
#include "interrupt.h"

#define EVT_LOG_LIMIT_TIMEOUT 5000

enum ummu_evtq_evt_name {
	EVT_UNKNOWN = 0x0,
	/* unsupport translation type */
	EVT_UT,
	/* dstEid overflow */
	EVT_BAD_DSTEID,
	/* abort when visit tect, or addr overflow */
	EVT_TECT_FETCH,
	/* TECT not valid, (V=0) */
	EVT_BAD_TECT,
	/* tect ent lack tokenid */
	EVT_RESERVE_0 = 0x5,
	/* reserved, no content */
	EVT_BAD_TOKENID,
	/*
	 * 1. TECT.TCT_MAXNUM = 0, tokenid disable,
	 * 2. TECT.ST_MODE[0] = 0, stage 1 translation close.
	 * 3. tokenid > TECT.TCT_MAXNUM
	 * 4. lvl1 tct invalid in two-level tct
	 */
	EVT_TCT_FETCH,
	/* invalid tct */
	EVT_BAD_TCT,
	/* error when Address Table walk */
	EVT_A_PTW_EABT,
	/*
	 * translation input bigger than max valid value,
	 * or no valid translation table descriptor
	 */
	EVT_A_TRANSLATION = 0xa,
	/* address translation out put bigger than max valid value */
	EVT_A_ADDR_SIZE,
	/* Access flag fault because of AF=0 */
	EVT_ACCESS,
	/* address translation permission error */
	EVT_A_PERMISSION,
	/* TLB or PLB conflicted in translation */
	EVT_TBU_CONFLICT,
	/* config cache conflicted in translation */
	EVT_CFG_CONFLICT = 0xf,
	/* error occurred when getting VMS */
	EVT_VMS_FETCH,
	/* error when Permission Table walk */
	EVT_P_PTW_EABT,
	/* abnormal software configuration in PTW */
	EVT_P_CFG_ERROR,
	/* permission exception in PTW process */
	EVT_P_PERMISSION,
	/* E-Bit verification failed */
	EVT_RESERVE_1 = 0x14,
	/* reserved, no content */
	EVT_EBIT_DENY,
	/*
	 * the UMMU hardware reports the execution result
	 * of the CMD_CREAT_DSTEID_TECT_RELATION command
	 * to the software.
	 */
	EVT_CREATE_DSTEID_TECT_RELATION_RESULT = 0x60,
	/*
	 * the UMMU hardware reports the execution result
	 * of the CMD_DELETE_DSTEID_TECT_RELATION command
	 * to the software.
	 */
	EVT_DELETE_DSTEID_TECT_RELATION_RESULT,
};

static phys_addr_t ummu_msi_cfg[UMMU_MAX_MSIS][3] = {
	[EVTQ_MSI_INDEX] = {
		UMMU_EVENT_QUE_MSI_ADDR0,
		UMMU_EVENT_QUE_MSI_DATA,
		UMMU_EVENT_QUE_MSI_ATTR,
	},
	[GERROR_MSI_INDEX] = {
		UMMU_GLB_ERR_INT_MSI_ADDR0,
		UMMU_GLB_ERR_INT_MSI_DATA,
		UMMU_GLB_ERR_INT_MSI_ATTR,
	},
};

/* implementation is based on the ARM SMMU arm_smmu_cmdq_skip_err */
static void ummu_device_mcmdq_skip_err(struct ummu_device *ummu,
				  struct ummu_queue *q)
{
	static const char * const cerror_str[] = {
		[MCMDQ_CERROR_NONE_IDX] = "No error",
		[MCMDQ_CERROR_ILL_IDX] = "Illegal command",
		[MCMDQ_CERROR_ABT_IDX] = "Abort on command fetch",
	};

	u32 cons = readl_relaxed(q->cons_reg);
	u32 rsn_idx = FIELD_GET(MCMDQ_CONS_ERR_REASON, cons);
	struct ummu_mcmdq_ent cmd_sync = {
		.opcode = CMD_SYNC,
	};
	u64 cmd[MCMDQ_ENT_DWORDS];
	size_t i;

	dev_err_ratelimited(ummu->dev, "MCMDQ error (cons 0x%08x): %s\n", cons,
		rsn_idx < ARRAY_SIZE(cerror_str) ? cerror_str[rsn_idx] :
							 "Unknown");

	switch (rsn_idx) {
	case MCMDQ_CERROR_ABT_IDX:
		dev_err_ratelimited(ummu->dev, "retrying command fetch\n");
		return;
	case MCMDQ_CERROR_NONE_IDX:
		return;
	case MCMDQ_CERROR_ILL_IDX:
		break;
	default:
		break;
	}

	/*
	 * We may have concurrent producers, so we need to be careful
	 * not to touch any of the shadow cmdq state.
	 */
	ummu_queue_read(cmd, Q_ENT(q, cons), q->ent_dwords);
	dev_err_ratelimited(ummu->dev, "skipping command in error state:\n");
	for (i = 0; i < ARRAY_SIZE(cmd); ++i)
		dev_err_ratelimited(ummu->dev, "\t0x%016llx\n", (unsigned long long)cmd[i]);

	/* Convert the erroneous command into a CMD_SYNC */
	if (ummu_mcmdq_build_cmd(ummu, cmd, &cmd_sync)) {
		dev_err_ratelimited(ummu->dev, "failed to convert to CMD_SYNC\n");
		return;
	}

	ummu_queue_write(Q_ENT(q, cons), cmd, q->ent_dwords);
}

static void ummu_mcmdq_skip_err(struct ummu_device *ummu)
{
	struct ummu_mcmdq *mcmdq;
	unsigned long flags;
	u32 prod, cons;
	u32 i;

	for (i = 0; i < ummu->nr_mcmdq; i++) {
		mcmdq = *per_cpu_ptr(ummu->mcmdq, i);
		prod = readl_relaxed(mcmdq->q.prod_reg);
		cons = readl_relaxed(mcmdq->q.cons_reg);
		if (((prod ^ cons) & MCMDQ_CONS_ERR) == 0)
			continue;

		ummu_device_mcmdq_skip_err(ummu, &mcmdq->q);

		write_lock_irqsave(&mcmdq->mcmdq_lock, flags);
		mcmdq->mcmdq_prod &= ~MCMDQ_PROD_ERRACK;
		mcmdq->mcmdq_prod |= cons & MCMDQ_CONS_ERR;

		prod = readl_relaxed(mcmdq->q.prod_reg);
		prod &= ~MCMDQ_PROD_ERRACK;
		prod |= cons & MCMDQ_CONS_ERR;
		writel(prod, mcmdq->q.prod_reg);
		write_unlock_irqrestore(&mcmdq->mcmdq_lock, flags);
	}
}

static irqreturn_t ummu_gerror_handler(int irq, void *dev)
{
	struct ummu_device *ummu = (struct ummu_device *)dev;
	u32 gerror, gerrorn, active;

	gerror = readl_relaxed(ummu->base + UMMU_GERROR);
	gerrorn = readl_relaxed(ummu->base + UMMU_GERRORN);

	active = gerror ^ gerrorn;
	if (!(active & GERROR_ERR_MASK))
		return IRQ_NONE; /* No errors pending */

	dev_err_ratelimited(
		ummu->dev,
		"unexpected global error reported (0x%08x), this could be serious\n",
		active);

	if (active & GERROR_MSI_GERR_ABT_ERR)
		dev_err_ratelimited(ummu->dev, "GERROR MSI write aborted\n");

	if (active & GERROR_MSI_UIEQ_ABT_ERR)
		dev_err_ratelimited(ummu->dev, "UIEQ MSI sync cmdq write aborted\n");

	if (active & GERROR_MSI_EVTQ_ABT_ERR)
		dev_err_ratelimited(ummu->dev, "EVTQ MSI write aborted\n");

	if (active & GERROR_MSI_MCMDQ_ABT_ERR)
		dev_err_ratelimited(ummu->dev, "CMDQ MSI write aborted\n");

	if (active & GERROR_EVTQ_ABT_ERR)
		dev_err_ratelimited(ummu->dev,
			"EVTQ write aborted -- events may have been lost\n");

	if (active & GERROR_MCMDQ_ERR)
		ummu_mcmdq_skip_err(ummu);

	writel(gerror, ummu->base + UMMU_GERRORN);
	return IRQ_HANDLED;
}

static void ummu_make_iommu_fault(struct ummu_device *ummu,
				  struct ummu_device_event *evt,
				  struct iommu_fault *flt)
{
	flt->type = IOMMU_FAULT_PAGE_REQ;
	flt->prm.flags = IOMMU_FAULT_PAGE_REQUEST_LAST_PAGE |
			 IOMMU_FAULT_PAGE_REQUEST_PRIV_DATA |
			 IOMMU_FAULT_PAGE_REQUEST_PASID_VALID;
	flt->prm.grpid = evt->stag;
	flt->prm.perm = (evt->instruction ? IOMMU_FAULT_PERM_EXEC : 0) |
			(evt->privileged ? IOMMU_FAULT_PERM_PRIV : 0) |
			(evt->read ? IOMMU_FAULT_PERM_READ :
				     IOMMU_FAULT_PERM_WRITE);
	flt->prm.addr = evt->iova;
	flt->prm.private_data[0] = evt->tect_tag;
	flt->prm.private_data[1] = (u64)(uintptr_t)ummu;
	flt->prm.pasid = evt->tid;
}

void ummu_page_response(struct device *dev, struct iopf_fault *evt,
			struct iommu_page_response *resp)
{
	struct iommu_fault_page_request *prm = &evt->fault.prm;
	struct ummu_device *ummu = (struct ummu_device *)(uintptr_t)prm->private_data[1];
	struct ummu_mcmdq_ent cmd = { 0 };

	if (!(prm->flags & IOMMU_FAULT_PAGE_REQUEST_PRIV_DATA)) {
		dev_err(dev, "tect_tag and ummu instance not set.\n");
		return;
	}

	cmd.opcode = CMD_STALL_RESUME;
	cmd.stall_resume.tag = resp->grpid;
	cmd.stall_resume.tect_tag = prm->private_data[0];

	switch (resp->code) {
	case IOMMU_PAGE_RESP_INVALID:
	case IOMMU_PAGE_RESP_FAILURE:
		cmd.stall_resume.abort = true;
		dev_err_ratelimited(ummu->dev,
			"page fault failed. pasid=0x%x grpid=0x%x perm=0x%x tect_tag=0x%llx\n",
			prm->pasid, prm->grpid, prm->perm, prm->private_data[0]);
		break;
	case IOMMU_PAGE_RESP_SUCCESS:
		cmd.stall_resume.retry = true;
		break;
	default:
		return;
	}
	ummu_mcmdq_issue_cmd(ummu, &cmd);
}

static inline void ummu_abort_page_fault(struct ummu_device *ummu,
					 u32 gripid, u32 tect_tag)
{
	struct ummu_mcmdq_ent cmd = { 0 };

	cmd.opcode = CMD_STALL_RESUME;
	cmd.stall_resume.tag = gripid;
	cmd.stall_resume.tect_tag = tect_tag;
	cmd.stall_resume.abort = true;

	ummu_mcmdq_issue_cmd(ummu, &cmd);
}

static bool ummu_report_iommu_fault(struct device *evt_src, u32 tid)
{
	struct iommu_domain *domain = ummu_core_get_domain_by_tid(evt_src, tid);

	if (!domain) {
		pr_err("get domain failed.\n");
		return false;
	}

	domain = iommu_to_agent_domain(domain);
	if (!domain->mm || iommu_is_ksva_domain(domain)) {
		pr_err("An iopf event reported by ksva/dma device is not allowed.\n");
		return false;
	}
	return true;
}

/* IRQ and event handlers */
static int ummu_handle_iopf(struct ummu_device *ummu,
			    struct ummu_device_event *evt)
{
	struct iopf_fault pf_fault = { 0 };
	struct iommu_fault *iommu_flt = &pf_fault.fault;
	struct device *dev = evt->dev;
	int ret;

	ummu_make_iommu_fault(ummu, evt, iommu_flt);
	/* S2 never fault */
	if (evt->s2) {
		ret = -EFAULT;
		goto abort_req;
	}
	/* tid or tid related device has been released */
	if (!dev) {
		ret = -EINVAL;
		goto abort_req;
	}

	/* DMA Fault or KSVA Fault should be filtered */
	if (!ummu_report_iommu_fault(dev, iommu_flt->prm.pasid)) {
		ret = -EOPNOTSUPP;
		goto abort_req;
	}
	ret = iommu_report_device_fault(dev, &pf_fault);
	if (ret)
		goto abort_req;

	return 0;

abort_req:
	ummu_abort_page_fault(ummu, iommu_flt->prm.grpid,
			      iommu_flt->prm.private_data[0]);
	pr_err("handle iopf failed, ret = %d\n", ret);

	return ret;
}

static void ummu_device_decode_event(struct ummu_device *ummu, u64 *raw,
				     struct ummu_device_event *event)
{
	event->code = FIELD_GET(EVTQ_ENT0_CODE, raw[0]);
	event->read = FIELD_GET(EVTQ_ENT0_RNW, raw[0]);
	event->instruction = FIELD_GET(EVTQ_ENT0_IND, raw[0]);
	event->privileged = FIELD_GET(EVTQ_ENT0_PNU, raw[0]);
	event->cls = FIELD_GET(EVTQ_ENT0_CLS, raw[0]);
	event->ns_ipa = FIELD_GET(EVTQ_ENT0_NSIPA, raw[0]);
	event->s2 = FIELD_GET(EVTQ_ENT0_S2, raw[0]);
	event->stall = FIELD_GET(EVTQ_ENT0_STALL, raw[0]);
	event->tid = FIELD_GET(EVTQ_ENT0_TID, raw[0]);
	event->stag = FIELD_GET(EVTQ_ENT1_STAG, raw[1]);
	event->ipa = raw[2] & EVTQ_ENT2_IPA;
	event->iova = FIELD_GET(EVTQ_ENT3_IADDR, raw[3]);
	event->tect_tag = FIELD_GET(EVTQ_ENT4_TECTE_TAG, raw[4]);

	event->dev = ummu_core_get_device(&ummu->core_dev, event->tid);
}

static int ummu_device_handle_evt(struct ummu_device *ummu,
				  struct ummu_device_event *event)
{
	int ret;

	if (event->stall)
		ret = ummu_handle_iopf(ummu, event);
	else
		ret = -EOPNOTSUPP;

	return ret;
}

static void ummu_device_dump_event(struct ummu_device *ummu, u64 *raw,
				   struct ummu_device_event *evt)
{
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	static u8 last_evt_code;
	static u64 timeout;
	int i;

	if (!__ratelimit(&rs))
		return;

	if (last_evt_code == evt->code && time_is_after_jiffies64(timeout))
		return;

	last_evt_code = evt->code;
	timeout = get_jiffies_64() + msecs_to_jiffies(EVT_LOG_LIMIT_TIMEOUT);

	dev_info(ummu->dev, "event 0x%02x received:\n", evt->code);
	for (i = 0; i < EVTQ_ENT_DWORDS; ++i)
		dev_info(ummu->dev, "\t0x%016llx\n", raw[i]);
}

/* implementation is based on the ARM SMMU arm_smmu_evtq_thread */
static irqreturn_t ummu_evtq_thread(int irq, void *dev)
{
	struct ummu_device *ummu = (struct ummu_device *)dev;
	struct ummu_queue *q = &ummu->evtq.q;
	struct ummu_ll_queue *llq = &q->llq;
	struct ummu_device_event event = {0};
	u64 evt[EVTQ_ENT_DWORDS];

	do {
		while (!ummu_queue_remove_raw(q, evt)) {
			ummu_device_decode_event(ummu, evt, &event);
			trace_ummu_event(dev_name(ummu->dev), event.code, evt, EVTQ_ENT_DWORDS);
			if (ummu_device_handle_evt(ummu, &event))
				ummu_device_dump_event(ummu, evt, &event);
			ummu_core_put_device(event.dev);
			cond_resched();
		}

		if (ummu_queue_sync_prod_in(q) == -EOVERFLOW)
			dev_err(ummu->dev, "EVTQ overflow -- events lost\n");
	} while (!ummu_queue_empty(llq));

	/* Sync overflow flag */
	ummu_queue_sync_cons_ovf(q);
	return IRQ_HANDLED;
}

static void ummu_free_msis(void *data)
{
	struct device *dev = (struct device *)data;

	platform_msi_domain_free_irqs(dev);
}

static void ummu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct device *dev = msi_desc_to_dev(desc);
	struct ummu_device *ummu = dev_get_drvdata(dev);
	phys_addr_t msi_addr;
	phys_addr_t *cfg;

	if (desc->msi_index > GERROR_MSI_INDEX) {
		if (ummu->impl_ops && ummu->impl_ops->write_msi_msg)
			ummu->impl_ops->write_msi_msg(desc, msg);

		return;
	}
	cfg = ummu_msi_cfg[desc->msi_index];
	/* 32 bit addresses are converted to 64 bit addresses. */
	msi_addr = (((u64)msg->address_hi) << 32) | msg->address_lo;
	msi_addr &= UMMU_MSI_ADDR_MASK;

	writeq_relaxed(msi_addr, ummu->base + cfg[0]);
	writel_relaxed(msg->data, ummu->base + cfg[1]);
	writel_relaxed(UMMU_MEMATTR_DEVICE_nGnRE, ummu->base + cfg[2]);
}

static int ummu_device_setup_msis(struct ummu_device *ummu)
{
	struct device *dev = ummu->dev;
	int ret;

	if (!(ummu->cap.features & UMMU_FEAT_MSI))
		return -EOPNOTSUPP;

	if (!dev->msi.domain)
		return -ENODEV;

	/* Clear the MSI address regs */
	writeq_relaxed(0, ummu->base + UMMU_EVENT_QUE_MSI_ADDR0);
	writeq_relaxed(0, ummu->base + UMMU_GLB_ERR_INT_MSI_ADDR0);

	if (ummu->impl_ops && ummu->impl_ops->set_msis)
		ummu->impl_ops->set_msis(ummu);

	/* Allocate MSIs for evtq, gerror */
	ret = platform_msi_domain_alloc_irqs(dev, UMMU_MAX_MSIS, ummu_write_msi_msg);
	if (ret) {
		dev_err(dev, "failed to allocate MSIs. ret = %d\n", ret);
		return ret;
	}

	/* Add callback to free MSIs on teardown */
	ret = devm_add_action_or_reset(dev, ummu_free_msis, dev);
	if (ret)
		dev_err(dev, "failed to add free msis action ret = %d.\n", ret);

	return ret;
}

static inline void ummu_disable_irqs(struct ummu_device *ummu)
{
	writel_relaxed(0, ummu->base + UMMU_GLB_IRQ_EN);
}

static inline void ummu_enable_irqs(struct ummu_device *ummu)
{
	u32 irqen_flags = IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;

	writel_relaxed(irqen_flags, ummu->base + UMMU_GLB_IRQ_EN);
}

static inline void ummu_init_evtq_irq(struct ummu_device *ummu, int irq)
{
	int ret = devm_request_threaded_irq(ummu->dev, irq, NULL,
					    ummu_evtq_thread, IRQF_ONESHOT,
					    "ummu-evtq", ummu);
	if (ret < 0)
		dev_warn(ummu->dev, "failed to enable evtq irq\n");
}

static inline void ummu_init_gerr_irq(struct ummu_device *ummu, int irq)
{
	int ret = devm_request_irq(ummu->dev, irq, ummu_gerror_handler, 0,
				   "ummu-gerror", ummu);
	if (ret < 0)
		dev_warn(ummu->dev, "failed to enable gerror irq\n");
}

void ummu_setup_irqs(struct ummu_device *ummu)
{
	u32 evtq_irq, gerr_irq;
	int ret;

	ummu_disable_irqs(ummu);

	ret = ummu_device_setup_msis(ummu);
	if (ret) {
		dev_err(ummu->dev, "failed to setup msis. ret = %d\n", ret);
		return;
	}

	evtq_irq = msi_get_virq(ummu->dev, EVTQ_MSI_INDEX);
	if (evtq_irq)
		ummu_init_evtq_irq(ummu, evtq_irq);
	else
		dev_warn(ummu->dev,
			 "no evtq irq - events will not be reported!\n");

	gerr_irq = msi_get_virq(ummu->dev, GERROR_MSI_INDEX);
	if (gerr_irq)
		ummu_init_gerr_irq(ummu, gerr_irq);
	else
		dev_warn(ummu->dev,
			 "no gerr irq - errors will not be reported!\n");

	if (ummu->impl_ops && ummu->impl_ops->setup_irqs)
		ummu->impl_ops->setup_irqs(ummu);

	ummu_enable_irqs(ummu);
}
