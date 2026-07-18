// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <uapi/linux/iommufd.h>
#include <linux/platform_device.h>
#include <linux/preempt.h>
#include <linux/bitops.h>
#include <linux/ummu_core.h>

#include "trace/trace.h"
#include "ummu.h"
#include "queue.h"
#include "flush.h"
#include "nested.h"

enum ummu_tlbi_scene {
	UMMU_TLBI_SCENE_DMA = 0,
	UMMU_TLBI_SCENE_SVA,
	UMMU_TLBI_SCENE_NUM,
};

enum ummu_tlbi_scope {
	UMMU_TLBI_SCOPE_CTX = 0,
	UMMU_TLBI_SCOPE_RNG,
	UMMU_TLBI_SCOPE_NUM,
};

enum ummu_tlbi_type {
	UMMU_TLBI_TYPE_S1E2H = 0,
	UMMU_TLBI_TYPE_S1NH,
	UMMU_TLBI_TYPE_S2,
	UMMU_TLBI_TYPE_NUM,
};

const static
u8 ummu_tlbi_code_table[UMMU_TLBI_SCENE_NUM][UMMU_TLBI_SCOPE_NUM][UMMU_TLBI_TYPE_NUM] = {
	[UMMU_TLBI_SCENE_DMA] = {
		[UMMU_TLBI_SCOPE_CTX] = {
			[UMMU_TLBI_TYPE_S1E2H]	= CMD_TLBI_HYP_TID,
			[UMMU_TLBI_TYPE_S1NH]	= CMD_TLBI_OS_TID,
			[UMMU_TLBI_TYPE_S2]	= CMD_TLBI_S1S2_VMALL,
		},
		[UMMU_TLBI_SCOPE_RNG] =  {
			[UMMU_TLBI_TYPE_S1E2H]	= CMD_TLBI_HYP_VA,
			[UMMU_TLBI_TYPE_S1NH]	= CMD_TLBI_OS_TID,
			[UMMU_TLBI_TYPE_S2]	= CMD_TLBI_OS_VA,
		},
	},
	[UMMU_TLBI_SCENE_SVA] = {
		[UMMU_TLBI_SCOPE_CTX] = {
			[UMMU_TLBI_TYPE_S1E2H]	= CMD_TLBI_HYP_ASID_U,
			[UMMU_TLBI_TYPE_S1NH]	= CMD_TLBI_OS_ASID_U,
			[UMMU_TLBI_TYPE_S2]	= CMD_TLBI_OS_ASID_U,
		},
		[UMMU_TLBI_SCOPE_RNG] =  {
			[UMMU_TLBI_TYPE_S1E2H]	= CMD_TLBI_HYP_VA_U,
			[UMMU_TLBI_TYPE_S1NH]	= CMD_TLBI_OS_ASID_U,
			[UMMU_TLBI_TYPE_S2]	= CMD_TLBI_OS_VA_U,
		},
	},
};

static int ummu_domain_tlbi_cmd(struct ummu_domain *domain,
				enum ummu_tlbi_scope scope,
				enum ummu_tlbi_scene scene,
				struct ummu_mcmdq_ent *cmd)
{
	struct ummu_s1_cfg *s1cfg = &domain->cfgs.s1_cfg;
	struct ummu_s2_cfg *s2cfg = &domain->cfgs.s2_cfg;
	struct ummu_device *ummu_dev;
	enum ummu_tlbi_type type;
	bool e2h;

	switch (domain->cfgs.stage) {
	case UMMU_DOMAIN_S1:
		if (scene == UMMU_TLBI_SCENE_DMA) {
			if (domain->base_domain.tid == UMMU_INVALID_TID)
				return -EINVAL;

			cmd->tlbi.tid = domain->base_domain.tid;
		} else {
			cmd->tlbi.asid = s1cfg->tct.asid;
		}

		ummu_dev = core_to_ummu_device(domain->base_domain.core_dev);
		e2h = !!(ummu_dev->cap.features & UMMU_FEAT_E2H);
		type = e2h ? UMMU_TLBI_TYPE_S1E2H : UMMU_TLBI_TYPE_S1NH;
		break;
	case UMMU_DOMAIN_S2:
		if (scene == UMMU_TLBI_SCENE_DMA)
			cmd->tlbi.tect_tag = domain->cfgs.tecte_tag;
		else
			cmd->tlbi.vmid = s2cfg->vmid;

		type = UMMU_TLBI_TYPE_S2;
		break;
	default:
		WARN(1, "get unexpected domain stage: %d",
			 (int)domain->cfgs.stage);
		return -EINVAL;
	}

	cmd->opcode = ummu_tlbi_code_table[scene][scope][type];
	return 0;
}

static void ummu_range_tlbi_nofeat(struct ummu_device *ummu,
				   struct ummu_mcmdq_ent *cmd,
				   struct ummu_tlb_range *range)
{
	unsigned long rg_start = range->iova, rg_end = range->iova + range->size;
	struct ummu_mcmdq_batch batch_cmds = {};

	while (rg_start < rg_end) {
		cmd->tlbi.addr = rg_start;
		ummu_mcmdq_batch_add(ummu, &batch_cmds, cmd);
		rg_start += range->granule;
	}
	ummu_mcmdq_batch_submit(ummu, &batch_cmds);
}

/* `granule` is inv granule and `translation_granule` is the granule of page table */
#define granule_to_lvl(granule, translation_granule) \
	(4 - (ilog2(granule) - 3) / ((translation_granule)-3))
/* this function highly rely on pagetable format, follow arm implementation now */
static void __ummu_tlbi_range(struct ummu_mcmdq_ent *cmd,
			      struct ummu_tlb_range *range,
			      struct ummu_domain *domain)
{
	struct ummu_device *ummu = core_to_ummu_device(domain->base_domain.core_dev);
	unsigned long num_pages, gs, rg_start, rg_end, scale, num, max_scale;
	struct ummu_mcmdq_batch batch_cmds = {};
	size_t ranged;

	if (range->iova == ULONG_MAX || range->size == 0)
		return;

	trace_ummu_iotlb_sync(domain->base_domain.tid, range->iova,
			      range->size, dev_name(ummu->dev));

	if (!(ummu->cap.features & UMMU_FEAT_RANGE_INV)) {
		ummu_range_tlbi_nofeat(ummu, cmd, range);
		return;
	}

	max_scale = CMD_TLBI_RANGE_SCALE_MAX;
	if (ummu->cap.options & UMMU_OPT_TLBI_LIMIT_SCALE)
		max_scale = CMD_TLBI_RANGE_SCALE_LIMIT;

	rg_start = range->iova;
	rg_end = rg_start + range->size;
	/* tg will be 12, 14, 16, indicating 4K, 16K, 64K pgtable */
	gs = __ffs(domain->base_domain.domain.pgsize_bitmap);
	num_pages = range->size >> gs;

	/* transfer 12,14,16 to 1,2,3, refer to the protocol */
	cmd->tlbi.gs = (gs - 10) >> 1;
	cmd->tlbi.tl = granule_to_lvl(range->granule, gs);

	while (rg_start < rg_end) {
		cmd->tlbi.addr = rg_start;

		scale = min(__ffs(num_pages), max_scale);
		cmd->tlbi.scale = scale;

		num = ((num_pages >> scale) & CMD_TLBI_RANGE_NUM_MAX) ?: CMD_TLBI_RANGE_NUM_MAX;
		cmd->tlbi.num = num - 1;

		ummu_mcmdq_batch_add(ummu, &batch_cmds, cmd);

		ranged = num << (scale + gs);
		num_pages -= num << scale;
		rg_start += ranged;
	}
	ummu_mcmdq_batch_submit(ummu, &batch_cmds);
}

static void ummu_tlbi_range(struct ummu_tlb_range *range, bool leaf,
			    struct ummu_domain *u_domain)
{
	struct ummu_mcmdq_ent cmd = {0};
	int err;

	if (u_domain->base_domain.domain.type == IOMMU_DOMAIN_SVA)
		err = ummu_domain_tlbi_cmd(u_domain, UMMU_TLBI_SCOPE_RNG,
					   UMMU_TLBI_SCENE_SVA, &cmd);
	else
		err = ummu_domain_tlbi_cmd(u_domain, UMMU_TLBI_SCOPE_RNG,
					   UMMU_TLBI_SCENE_DMA, &cmd);
	if (err)
		return;

	cmd.tlbi.leaf = leaf;
	__ummu_tlbi_range(&cmd, range, u_domain);
}

/* for io_pgtable */
void ummu_tlbi_context(void *cookie)
{
	struct ummu_domain *u_domain = (struct ummu_domain *)cookie;
	struct ummu_device *ummu = core_to_ummu_device(
					u_domain->base_domain.core_dev);
	struct ummu_mcmdq_ent cmd = {0};
	int err;

	if (u_domain->base_domain.domain.type == IOMMU_DOMAIN_SVA && u_domain->tlbi_asid)
		err = ummu_domain_tlbi_cmd(u_domain, UMMU_TLBI_SCOPE_CTX,
					   UMMU_TLBI_SCENE_SVA, &cmd);
	else
		err = ummu_domain_tlbi_cmd(u_domain, UMMU_TLBI_SCOPE_CTX,
					   UMMU_TLBI_SCENE_DMA, &cmd);
	if (err)
		return;
	trace_ummu_flush_iotlb_all(u_domain->base_domain.tid, dev_name(ummu->dev));
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
}

void ummu_tlbi_walk(unsigned long iova, size_t size, size_t granule,
		    void *cookie)
{
	struct ummu_domain *u_domain = (struct ummu_domain *)cookie;

	ummu_core_tlb_inv_walk(u_domain->domain, iova, size, granule);
}

void ummu_tlbi_page(struct iommu_iotlb_gather *gather, unsigned long iova,
		    size_t granule, void *cookie)
{
	struct ummu_domain *u_domain = (struct ummu_domain *)cookie;

	iommu_iotlb_gather_add_page(u_domain->domain, gather, iova, granule);
}

void ummu_iotlb_sync(struct iommu_domain *domain,
		     struct iommu_iotlb_gather *gather)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_tlb_range range = {
		.iova = gather->start,
		.size = gather->end - gather->start + 1,
		.granule = gather->pgsize,
	};

	ummu_tlbi_range(&range, true, u_domain);
}

void ummu_device_tlb_inv_walk(struct iommu_domain *domain,
			       struct iommu_iotlb_gather *gather)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_tlb_range range = {
		.iova = gather->start,
		.size = gather->end - gather->start + 1,
		.granule = gather->pgsize,
	};

	ummu_tlbi_range(&range, false, u_domain);
}

void ummu_flush_iotlb_all_asid(struct iommu_domain *domain)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);

	u_domain->tlbi_asid = true;
	ummu_tlbi_context(u_domain);
}

void ummu_flush_iotlb_all(struct iommu_domain *domain)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);

	ummu_tlbi_context(u_domain);
}

void ummu_sync_iommu_domain(struct ummu_base_domain *base_domain,
			    struct iommu_domain *domain)
{
	struct ummu_nested_domain *nested_domain;
	struct ummu_domain *u_domain;

	if (base_domain->domain.type == IOMMU_DOMAIN_NESTED) {
		nested_domain = to_nested_domain(&base_domain->domain);
		nested_domain->domain = domain;
	} else {
		u_domain = to_ummu_domain(&base_domain->domain);
		u_domain->domain = domain;
	}
}

void ummu_init_flush_iotlb(struct ummu_device *ummu)
{
	struct ummu_mcmdq_ent cmd;

	if (ummu->cap.features & UMMU_FEAT_HYP) {
		cmd.opcode = CMD_TLBI_HYP_ALL;
		ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
	}

	cmd.opcode = CMD_TLBI_NS_OS_ALL;
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
}

void ummu_device_prefetch_cfg(struct ummu_device *ummu, u32 tecte_tag,
			      u32 tid)
{
	struct ummu_mcmdq_ent cmd_prefet = {
		.opcode = CMD_PREFET_CFG,
		.prefet = {
			.tkv = (tid == UMMU_INVALID_TID) ? false : true,
			.tid = tid,
			.deid_0 = tecte_tag,
		},
	};

	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_prefet);
}

void ummu_sync_tect_range(struct ummu_device *ummu, u32 tecte_tag,
			  u8 range)
{
	struct ummu_mcmdq_ent cmd_cfgi_tect_range = {
		.opcode = CMD_CFGI_TECT_RANGE,
		.cfgi = {
			.range = range,
			.deid_0 = tecte_tag,
		},
	};

	trace_ummu_sync_tect_range(dev_name(ummu->dev), tecte_tag, range);
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_cfgi_tect_range);
}

void ummu_sync_tect_all(struct ummu_device *ummu)
{
	ummu_sync_tect_range(ummu, 0, CMD_TLBI_RANGE_NUM_MAX);
}

void ummu_device_sync_tect(struct ummu_device *ummu, u32 tecte_tag)
{
	struct ummu_mcmdq_ent cmd_cfgi_tect = {
		.opcode = CMD_CFGI_TECT,
		.cfgi = {
			.leaf = true,
			.deid_0 = tecte_tag,
		},
	};

	trace_ummu_sync_tect(dev_name(ummu->dev), tecte_tag);
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_cfgi_tect);
}

void ummu_sync_tct(struct ummu_device *ummu, u32 tecte_tag, u32 tid,
		   bool leaf)
{
	struct ummu_mcmdq_ent cmd_cfgi_tct = {
		.opcode = CMD_CFGI_TCT,
		.cfgi = {
			.leaf = leaf,
			.tid = tid,
			.deid_0 = tecte_tag,
		},
	};

	if (ummu->cap.options & UMMU_OPT_SYNC_WITH_PLBI) {
		struct ummu_mcmdq_ent cmd_plbi_all = {
			.opcode = CMD_PLBI_OS_EIDTID,
			.plbi = {
				.tid = tid,
				.tecte_tag = tecte_tag,
			},
		};
		ummu_mcmdq_issue_cmd(ummu, &cmd_plbi_all);
	}

	trace_ummu_sync_tct(dev_name(ummu->dev), tecte_tag, tid, leaf);
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_cfgi_tct);
}

void ummu_sync_tct_all(struct ummu_device *ummu, u32 tecte_tag)
{
	struct ummu_mcmdq_ent cmd_cfgi_tct_all = {
		.opcode = CMD_CFGI_TCT_ALL,
		.cfgi = {
			.deid_0 = tecte_tag,
		},
	};

	trace_ummu_sync_tct_all(dev_name(ummu->dev), tecte_tag);
	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_cfgi_tct_all);
}

static u8 get_minist_log2size_range(size_t size)
{
	u8 index = 0;

	if (size > 0)
		size -= 1;

	while (size > 0) {
		size >>= 1;
		index++;
	}

	return index;
}

int ummu_device_flush_plb(struct ummu_device *ummu, u32 tag, u32 tid,
			  u64 addr, size_t size)
{
	u32 plbi_num = (ummu->cap.options & UMMU_OPT_DOUBLE_PLBI) ? 2 : 1;
	struct ummu_mcmdq_ent cmd = {
		.opcode = CMD_PLBI_OS_VA,
		.plbi = {
			.tid = tid,
			.tecte_tag = (u16)tag,
			.range = get_minist_log2size_range(size),
			.addr = addr,
		},
	};
	u32 idx;
	int ret;

	for (idx = 0; idx < plbi_num; idx++) {
		ret = ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
		if (ret)
			dev_err(ummu->dev,
				"issue plbi va cmd failed, idx = %u, ret = %d\n", idx, ret);
	}

	return ret;
}

void ummu_device_flush_plb_all(struct iommu_domain *domain)
{
	struct ummu_base_domain *base_domain = to_ummu_base_domain(domain);
	struct ummu_device *ummu = core_to_ummu_device(base_domain->core_dev);
	u32 plbi_num = (ummu->cap.options & UMMU_OPT_DOUBLE_PLBI) ? 2 : 1;
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_mcmdq_ent cmd = {
		.opcode = CMD_PLBI_OS_EIDTID,
		.plbi = {
			.tid = base_domain->tid,
			.tecte_tag = u_domain->cfgs.tecte_tag,
		},
	};
	u32 idx;
	int ret;

	for (idx = 0; idx < plbi_num; idx++) {
		ret = ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
		if (ret)
			dev_err(ummu->dev,
				"issue plbi tid cmd failed, idx = %u, ret = %d\n", idx, ret);
	}
}

void ummu_device_flush_ioplb_all(struct ummu_device *ummu)
{
	struct ummu_mcmdq_ent cmd = {
		.opcode = CMD_PLBI_OS_EID,
		.plbi = {
			.tecte_tag = LOCAL_TECT_TAG,
		},
	};

	ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd);
}

int ummu_device_check_pa_continuity(struct ummu_device *ummu, u64 addr,
				    u32 size_order, u32 id)
{
	struct ummu_mcmdq_ent cmd_ent = {
		.opcode = CMD_NULL_OP,
		.null_op = {
			.sub_op = SUB_CMD_NULL_CHECK_PA_CONTINUITY,
			.check_pa_conti = {
				.result = 0,
				.flag = 0,
				.size_order = size_order,
				.id = id,
				.addr = addr,
			},
		},
	};

	return ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_ent);
}
