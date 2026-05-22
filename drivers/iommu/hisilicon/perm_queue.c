// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU permission queue implement.
 */

#define pr_fmt(fmt) "UMMU: " fmt
#include <linux/iopoll.h>

#include "cfg_table.h"
#include "ummu.h"
#include "regs.h"
#include "perm_queue.h"

#define PERMQ_CTXTBL_BYTES 64U
#define PERMQ_CTXTBL_STATUS GENMASK(1, 0)
#define PERMQ_CTXTBL_RESET 0x0
#define PERMQ_CTXTBL_READY 0x1
#define PERMQ_CTXTBL_ERROR 0x2
#define PERMQ_CTXTBL_QSIZE GENMASK(5, 2)
#define PERMQ_CTXTBL_ENT_QBASE GENMASK_ULL(51, 12)
#define PERMQ_CTXTBL_ENT_MA GENMASK_ULL(61, 58)
#define PERMQ_CTXTBL_WBWA 1

#define PERMQ_CTXTBL_ENT_SH GENMASK_ULL(63, 62)

#define PERMQ_CTXTBL_ENT2_TECTE_TAG GENMASK(15, 0)

#define PERMQ_CTXTBL_ENT4_TID GENMASK(19, 0)
#define PERMQ_CTXTBL_ENT4_UIEQN GENMASK(28, 24)
#define PERMQ_CTXTBL_ENT4_INTEN (1UL << 29)
#define PERMQ_INT_ENABLE 0x1

#define PERMQ_CTXTBL_ENT5_PCMDQPI GENMASK(15, 0)
#define PERMQ_CTXTBL_ENT5_PCMDQCI GENMASK(31, 16)
#define PERMQ_CTXTBL_ENT5_PCPLQPI GENMASK_ULL(47, 32)
#define PERMQ_CTXTBL_ENT5_PCPLQCI GENMASK_ULL(63, 48)

#define PERMQ_CTXTBL_ENT6_NEXT_QID GENMASK_ULL(47, 0)
#define PERMQ_CTXTBL_ENT6_QM_FLAG (1ULL << 48)

void ummu_device_uninit_permqs(struct ummu_device *ummu)
{
	size_t ctxtbl_size;

	if (!(ummu->cap.features & UMMU_FEAT_MAPT))
		return;

	xa_destroy(&ummu->permq_ctx_cfg.permq_xa);
	mutex_destroy(&ummu->permq_ctx_cfg.permq_rel_mutex);
	if (!ummu->permq_ctx_cfg.tbl_va)
		return;

	ctxtbl_size = (u32)PERMQ_CTXTBL_BYTES * ummu->cap.permq_num;
	free_pages((unsigned long)ummu->permq_ctx_cfg.tbl_va, get_order(ctxtbl_size));
	ummu->permq_ctx_cfg.tbl_va = NULL;
}

int ummu_device_init_permqs(struct ummu_device *ummu)
{
	u32 qnum = ummu->cap.permq_num;
	struct page *pages;
	size_t ctxtbl_size;

	/* init qid container */
	xa_init_flags(&ummu->permq_ctx_cfg.permq_xa, XA_FLAGS_ALLOC);

	/* alloc permqs->ctxtbl, it should be physical coherent */
	ctxtbl_size = (u32)PERMQ_CTXTBL_BYTES * qnum;

	pages = alloc_pages_node(dev_to_node(ummu->dev),
				 UMMU_GFP(GFP_KERNEL) | __GFP_ZERO | __GFP_COMP,
				 get_order(ctxtbl_size));
	if (!pages) {
		xa_destroy(&ummu->permq_ctx_cfg.permq_xa);
		return -ENOMEM;
	}
	ummu->permq_ctx_cfg.tbl_va = page_address(pages);
	ummu->permq_ctx_cfg.tbl_pa = virt_to_phys(ummu->permq_ctx_cfg.tbl_va);

	ummu->permq_ctx_cfg.tbl_reg_addr = PERMQ_CTXT_ADDR_MASK &
					   ummu->permq_ctx_cfg.tbl_pa;

	mutex_init(&ummu->permq_ctx_cfg.permq_rel_mutex);
	return 0;
}

void ummu_device_init_permq_ctrl_page(struct ummu_device *ummu)
{
	u64 ctrl_base_pa;

	ctrl_base_pa = ((vmalloc_to_pfn(ummu->base) << PAGE_SHIFT) +
			UMMU_PERMQ_CTRL_PAGE_BASE);
	ummu->permq_ctrl_page = devm_ioremap(ummu->dev, ctrl_base_pa,
					     UMMU_CTRL_PAGE_SIZE * ummu->cap.permq_num);
	/*
	 * we don't return error code even if ioremap failed, since some times
	 * we not use permission table.
	 */
}

int ummu_get_permq_resource(struct ummu_device *ummu, u32 qid,
			    struct queue_args *queue)
{
	struct ummu_permq_desc *permq;
	u64 ctrl_page_pa;

	permq = (struct ummu_permq_desc *)xa_load(&ummu->permq_ctx_cfg.permq_xa,
						  qid);
	if (!permq) {
		dev_err(ummu->dev, "given qid %u don't have permq resource!",
			qid);
		return -EINVAL;
	}

	queue->pcmdq_base = permq->pcmdq.pa;
	queue->pcplq_base = permq->pcplq.pa;

	/* pcmdq_pi is head of the page specified by qid */
	ctrl_page_pa = vmalloc_to_pfn(ummu->permq_ctrl_page) << PAGE_SHIFT;
	queue->ctrl_page = ctrl_page_pa + PERMQ_PCMDQ_PI(qid);

	return 0;
}

int ummu_get_tid_res(struct tid_args *args)
{
	const struct ummu_capability *cap;

	cap = ummu_get_cap();
	if (!cap)
		return -EPERM;

	args->pcmdq_order =
		get_order(cap->permq_ent_num.cmdq_num * PCMDQ_ENT_BYTES);
	args->pcplq_order =
		get_order(cap->permq_ent_num.cplq_num * PCPLQ_ENT_BYTES);

	return 0;
}

static void ummu_device_release_ucmdq(struct ummu_device *ummu, u32 qid)
{
	u32 reg_rep;
	int ret;

	guard(mutex)(&ummu->permq_ctx_cfg.permq_rel_mutex);
	writel_relaxed((qid & PERMQ_RELEASE_ID),
		       ummu->base + UMMU_RELEASE_PERMQ_ID);
	writel_relaxed(PERMQ_RELEASE_CPL_BIT, ummu->base + UMMU_RELEASE_PERMQ);

	ret = readl_relaxed_poll_timeout(ummu->base + UMMU_RELEASE_PERMQ,
					  reg_rep,
					  !(reg_rep & PERMQ_RELEASE_CPL_BIT), 1,
					  PERMQ_RELEASE_TIMEOUT_US);
	if (ret)
		dev_err(ummu->dev, "ummu release ucmdq failed, qid = %u\n", qid);
}

void ummu_release_permq_resource(struct ummu_domain *domain)
{
	struct ummu_device *ummu = core_to_ummu_device(
					domain->base_domain.core_dev);
	u32 qid = domain->qid;
	struct ummu_permq_desc *permq;
	size_t pcmdq_size, pcplq_size;

	domain->qid = UMMU_INVALID_QID;

	ummu_device_release_ucmdq(ummu, qid);

	/*
	 * we not clear ctxtbl entry, because the qid is unused now, the
	 * entry will be overwrite when this qid come again.
	 */
	permq = (struct ummu_permq_desc *)xa_erase(
		&ummu->permq_ctx_cfg.permq_xa, qid);
	if (!permq) {
		pr_warn("The qid(%u) does not have the corresponding permission queue\n",
			qid);
		return;
	}

	/* free the entry */
	pcmdq_size = PCMDQ_ENT_BYTES * ummu->cap.permq_ent_num.cmdq_num;
	free_pages((unsigned long)permq->pcmdq.va, get_order(pcmdq_size));
	pcplq_size = PCPLQ_ENT_BYTES * ummu->cap.permq_ent_num.cplq_num;
	free_pages((unsigned long)permq->pcplq.va, get_order(pcplq_size));
	kfree(permq);
}

void ummu_device_set_permq_ctxtbl(struct ummu_device *ummu)
{
	u64 permq_ctxtbl_reg;
	void *mapt_base_va;
	u32 val;

	permq_ctxtbl_reg =
		ummu->permq_ctx_cfg.tbl_reg_addr |
		FIELD_PREP(MAPT_CMDQ_CTXT_SIZE, ilog2(ummu->cap.permq_num));

	mapt_base_va = ummu->base + UMMU_MAPT_CMDQ_CTXT_BADDR;
	if (!mapt_base_va) {
		dev_err(ummu->dev, "ummu remap mapt base failed.\n");
		return;
	}

	val = FIELD_PREP(MAPT_CTXT_MEM_ATTR_CFG, UMMU_MEMATTR_DEVICE_nGnRnE) |
	      FIELD_PREP(MAPT_CTXT_SH_CFG, UMMU_SH_NSH);
	writeq_relaxed(cpu_to_le64(permq_ctxtbl_reg), mapt_base_va);
	writel_relaxed(cpu_to_le32(val), ummu->base + UMMU_MAPT_CMDQ_CTXT_MATTR);
}

static void ummu_init_permq_ctxtbl_ent(struct ummu_domain *domain,
				       struct ummu_permq_desc *permq)
{
	struct ummu_device *ummu = core_to_ummu_device(
					domain->base_domain.core_dev);
	u8 ucmdq_ent, ucplq_ent, sh;
	__le64 *ctxtbl_ptr;
	u32 tid, qid;
	u64 val;

	qid = domain->qid;
	tid = domain->base_domain.tid;
	ctxtbl_ptr = (__le64 *)(ummu->permq_ctx_cfg.tbl_va +
		     qid * PERMQ_CTXTBL_BYTES);

	/* we don't implement user eventq now */
	val = FIELD_PREP(PERMQ_CTXTBL_ENT4_INTEN, 0) |
	      FIELD_PREP(PERMQ_CTXTBL_ENT4_TID, tid);
	ctxtbl_ptr[4] = cpu_to_le64(val);

	val = FIELD_PREP(PERMQ_CTXTBL_ENT2_TECTE_TAG, domain->cfgs.tecte_tag);
	ctxtbl_ptr[2] = cpu_to_le64(val);

	sh = FIELD_GET(TCT_ENT1_MSD, domain->cfgs.s1_cfg.tct.tcr1);
	ucplq_ent = ilog2(ummu->cap.permq_ent_num.cplq_num);
	val = cpu_to_le64(PERMQ_CTXTBL_ENT_QBASE & permq->pcplq.pa) |
	      FIELD_PREP(PERMQ_CTXTBL_ENT_MA, PERMQ_CTXTBL_WBWA) |
	      FIELD_PREP(PERMQ_CTXTBL_QSIZE, ucplq_ent) |
	      FIELD_PREP(PERMQ_CTXTBL_ENT_SH, sh);
	ctxtbl_ptr[1] = cpu_to_le64(val);

	ucmdq_ent = ilog2(ummu->cap.permq_ent_num.cmdq_num);
	val = cpu_to_le64(PERMQ_CTXTBL_ENT_QBASE & permq->pcmdq.pa) |
	      FIELD_PREP(PERMQ_CTXTBL_STATUS, PERMQ_CTXTBL_READY) |
	      FIELD_PREP(PERMQ_CTXTBL_ENT_MA, PERMQ_CTXTBL_WBWA) |
	      FIELD_PREP(PERMQ_CTXTBL_QSIZE, ucmdq_ent) |
	      FIELD_PREP(PERMQ_CTXTBL_ENT_SH, sh);
	WRITE_ONCE(ctxtbl_ptr[0], cpu_to_le64(val));
}

static void ummu_init_permq_ctrltbl_ent(void __iomem *ctrl_base, u32 qid)
{
	/*
	 * the ctrl table is registers of ummu, and the addr is specified by
	 * UMMU_PCMDQ_PI, UMMU_PCMDQ_CI, UMMU_PCPLQ_PI, UMMU_PCPLQ_CI. so
	 * the init operation is clear the specified register.
	 */

	writel_relaxed(0, ctrl_base + PERMQ_PCMDQ_CI(qid));
	writel_relaxed(0, ctrl_base + PERMQ_PCMDQ_PI(qid));

	writel_relaxed(0, ctrl_base + PERMQ_PCPLQ_PI(qid));
	writel_relaxed(0, ctrl_base + PERMQ_PCPLQ_CI(qid));
}

int ummu_domain_config_permq(struct ummu_domain *domain)
{
	struct ummu_device *ummu = core_to_ummu_device(
					domain->base_domain.core_dev);
	struct xa_limit limit = { .min = 0, .max = ummu->cap.permq_num - 1 };
	struct page *pcmdq_pages, *pcplq_pages;
	struct ummu_permq_desc *permq;
	size_t pcmdq_size, pcplq_size;
	u32 qid;
	int ret;

	if (!ummu->permq_ctx_cfg.tbl_va || !ummu->permq_ctrl_page) {
		dev_err(ummu->dev, "permqs resource is unavailable!\n");
		return -EINVAL;
	}

	permq = kzalloc(sizeof(*permq), GFP_KERNEL);
	if (!permq)
		return -ENOMEM;

	pcmdq_size = PCMDQ_ENT_BYTES * ummu->cap.permq_ent_num.cmdq_num;
	pcmdq_pages = alloc_pages_node(dev_to_node(ummu->dev),
				UMMU_GFP(GFP_KERNEL) | __GFP_ZERO | __GFP_COMP,
				get_order(pcmdq_size));
	if (!pcmdq_pages) {
		ret = -ENOMEM;
		goto e_free_permq;
	}
	permq->pcmdq.va = page_address(pcmdq_pages);
	permq->pcmdq.pa = virt_to_phys(permq->pcmdq.va);

	pcplq_size = PCPLQ_ENT_BYTES * ummu->cap.permq_ent_num.cplq_num;
	pcplq_pages = alloc_pages_node(dev_to_node(ummu->dev),
				UMMU_GFP(GFP_KERNEL) | __GFP_ZERO | __GFP_COMP,
				get_order(pcplq_size));
	if (!pcplq_pages) {
		ret = -ENOMEM;
		goto e_free_pcmdq;
	}
	permq->pcplq.va = page_address(pcplq_pages);
	permq->pcplq.pa = virt_to_phys(permq->pcplq.va);

	ret = xa_alloc(&ummu->permq_ctx_cfg.permq_xa, &qid, permq, limit,
		       GFP_KERNEL);
	if (ret) {
		dev_err(ummu->dev, "store permq resource to xarray failed!");
		goto e_free_pcplq;
	}

	domain->qid = qid;
	ummu_init_permq_ctxtbl_ent(domain, permq);
	dma_wmb();
	ummu_init_permq_ctrltbl_ent(ummu->permq_ctrl_page, qid);
	return 0;

e_free_pcplq:
	free_pages((unsigned long)permq->pcplq.va, get_order(pcplq_size));
e_free_pcmdq:
	free_pages((unsigned long)permq->pcmdq.va, get_order(pcmdq_size));
e_free_permq:
	kfree(permq);
	return ret;
}
