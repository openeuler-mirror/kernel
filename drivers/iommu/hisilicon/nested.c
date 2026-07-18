// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: enable nested mode
 */

#include <uapi/linux/iommufd.h>

#include "iommu.h"
#include "cfg_table.h"
#include "queue.h"
#include "nested.h"

static void ummu_build_nested_domain_tct(struct ummu_domain *u_domain,
					 struct ummu_tecte_data *target)
{
	struct ummu_device *ummu = core_to_ummu_device(
				u_domain->base_domain.core_dev);
	u64 tcr_sel;

	target->data[1] |= cpu_to_le64(
		FIELD_PREP(TECT_ENT1_TCT_MAX_NUM, ummu->local_tct_cfg->tcte_max_bits) |
		FIELD_PREP(TECT_ENT1_TCT_FMT, ummu->local_tct_cfg->tct_fmt) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MD0, TECT_ENT1_MD_CACHE_WBRA) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MD1, TECT_ENT1_MD_CACHE_WBRA) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MSD, TECT_ENT1_MD_CACHE_WB));

	if (!(ummu->cap.features & UMMU_FEAT_STALLS))
		target->data[1] |= cpu_to_le64(TECT_ENT1_TCT_STALL_DISABLE);

	tcr_sel = (ummu->cap.features & UMMU_FEAT_E2H) ? TECT_ENT0_TCR_EL2 :
						  TECT_ENT0_TCR_NSEL1;
	target->data[0] |= cpu_to_le64(
		FIELD_PREP(TECT_ENT0_TCRC_SEL, tcr_sel) |
		((ummu->cap.features & UMMU_FEAT_MAPT) ? TECT_ENT0_MAPT_EN : 0));
}

static void ummu_build_nested_domain_tecte(
				struct ummu_nested_domain *nested_domain,
				struct ummu_tecte_data *tecte)
{
	struct ummu_domain *s2_parent = nested_domain->s2_parent;

	ummu_build_s2_domain_tecte(s2_parent, tecte);
	tecte->data[0] |= cpu_to_le64(
		TECT_ENT0_V |
		FIELD_PREP(TECT_ENT0_ST_MODE, TECT_ENT0_ST_MODE_NESTED) |
		FIELD_PREP(TECT_ENT0_PRIV_SEL, TECT_ENT0_PRIV_SEL_PRIV));

	tecte->data[0] |= nested_domain->tecte[0] &
			  ~cpu_to_le64(TECT_ENT0_ST_MODE | TECT_ENT0_PRIV_SEL);
	tecte->data[1] |= nested_domain->tecte[1];

	ummu_build_nested_domain_tct(s2_parent, tecte);
}

static int ummu_attach_dev_nested(struct iommu_domain *domain,
				  struct device *dev)
{
	struct ummu_nested_domain *nested_domain = to_nested_domain(domain);
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);
	struct ummu_tecte_data target;

	guard(mutex)(&nested_domain->s2_parent->init_mutex);
	ummu_build_nested_domain_tecte(nested_domain, &target);
	ummu_device_write_tecte(master->ummu,
		nested_domain->s2_parent->cfgs.tecte_tag, &target);
	return 0;
}

static void ummu_domain_nested_free(struct iommu_domain *domain)
{
	kfree(to_nested_domain(domain));
}

static struct iommu_domain *
ummu_get_msi_mapping_domain(struct iommu_domain *domain)
{
	struct ummu_nested_domain *nested_domain = to_nested_domain(domain);

	return &nested_domain->s2_parent->base_domain.domain;
}

static const struct iommu_domain_ops ummu_nested_ops = {
	.attach_dev = ummu_attach_dev_nested,
	.free = ummu_domain_nested_free,
	.get_msi_mapping_domain = ummu_get_msi_mapping_domain,
};

static int ummu_validate_vtecte_data(struct iommu_hwpt_ummu *arg)
{
	unsigned int cfg;

	if (!(arg->tecte[0] & cpu_to_le64(TECT_ENT0_V))) {
		memset(arg->tecte, 0, sizeof(arg->tecte));
		return 0;
	}

	if ((arg->tecte[0] & ~TECTE_0_NESTED_CONFIG_MASK) ||
	    (arg->tecte[1] & ~TECTE_1_NESTED_CONFIG_MASK))
		return -EIO;

	cfg = FIELD_GET(TECT_ENT0_ST_MODE, le64_to_cpu(arg->tecte[0]));
	if (cfg != TECT_ENT0_ST_MODE_S1 && cfg != TECT_ENT0_ST_MODE_ABORT &&
	    cfg != TECT_ENT0_ST_MODE_BYPASS)
		return -EINVAL;

	return 0;
}

struct iommu_domain *
ummu_viommu_alloc_domain_nested(struct iommu_domain *parent, u32 flags,
				const struct iommu_user_data *user_data)
{
	struct ummu_nested_domain *nested_domain;
	struct ummu_domain *ummu_parent;
	struct iommu_hwpt_ummu arg;
	int ret;

	if (flags & ~IOMMU_HWPT_FAULT_ID_VALID)
		return ERR_PTR(-EOPNOTSUPP);

	ummu_parent = to_ummu_domain(parent);
	if (!(ummu_parent->base_domain.domain.type & __IOMMU_DOMAIN_PAGING) ||
	    ummu_parent->cfgs.stage != UMMU_DOMAIN_S2)
		return ERR_PTR(-EINVAL);

	ret = iommu_copy_struct_from_user(&arg, user_data,
					  IOMMU_HWPT_DATA_UMMU, tecte);
	if (ret)
		return ERR_PTR(ret);

	ret = ummu_validate_vtecte_data(&arg);
	if (ret)
		return ERR_PTR(ret);

	nested_domain = kzalloc(sizeof(*nested_domain), GFP_KERNEL_ACCOUNT);
	if (!nested_domain)
		return ERR_PTR(-ENOMEM);

	nested_domain->base_domain.domain.type = IOMMU_DOMAIN_NESTED;
	nested_domain->base_domain.domain.ops = &ummu_nested_ops;
	nested_domain->s2_parent = ummu_parent;
	nested_domain->tecte[0] = arg.tecte[0];
	nested_domain->tecte[1] = arg.tecte[1];

	return &nested_domain->base_domain.domain;
}

static int ummu_fix_user_cmd(struct ummu_device *ummu,
			    u64 *cmd, u32 tecte_tag, u16 vmid)
{
	u8 opcode;
	int i;

	for (i = 0; i < MCMDQ_ENT_DWORDS; i++)
		cmd[i] = le64_to_cpu(cmd[i]);

	opcode = cmd[0] & CMD_0_OP;
	switch (opcode) {
	case CMD_TLBI_HYP_ALL:
	case CMD_TLBI_HYP_VAA:
	case CMD_TLBI_NS_OS_ALL:
	case CMD_TLBI_HYP_TID:
	case CMD_TLBI_HYP_VA:
	case CMD_TLBI_HYP_ASID_U:
		break;
	case CMD_PLBI_OS_EID:
	case CMD_PLBI_OS_EIDTID:
	case CMD_PLBI_OS_VA:
		cmd[2] &= ~CMD_PLBI_2_TECTE_TAG;
		cmd[2] |= FIELD_PREP(CMD_PLBI_2_TECTE_TAG, tecte_tag);
		break;
	case CMD_TLBI_OS_ALL:
	case CMD_TLBI_OS_TID:
	case CMD_TLBI_OS_VA:
	case CMD_TLBI_OS_VAA:
	case CMD_TLBI_S1S2_VMALL:
	case CMD_TLBI_S2_IPA:
		cmd[2] &= ~CMD_TLBI_2_TECTE_TAG;
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, tecte_tag);
		break;
	case CMD_CFGI_TECT:
	case CMD_CFGI_TECT_RANGE:
	case CMD_CFGI_TCT:
	case CMD_CFGI_TCT_ALL:
		cmd[2] &= ~CMD_CFGI_2_TECTE_TAG;
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_TECTE_TAG, tecte_tag);
		break;
	case CMD_TLBI_OS_ASID_U:
		cmd[0] &= ~CMD_TLBI_0_VMID;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, vmid);
		break;
	default:
		return -EIO;
	}

	return 0;
}

int ummu_viommu_cache_invalidate_user(struct iommu_domain *domain,
				      struct iommu_user_data_array *array)
{
	struct ummu_nested_domain *nested_domain;
	struct iommufd_viommu_ummu_invalidate *cmds;
	struct iommufd_viommu_ummu_invalidate *last;
	struct iommufd_viommu_ummu_invalidate *cur;
	struct iommufd_viommu_ummu_invalidate *end;
	struct ummu_device *ummu;
	u64 tecte_tag;
	u16 vmid;
	int ret;

	nested_domain = to_nested_domain(domain);
	tecte_tag = nested_domain->s2_parent->cfgs.tecte_tag;
	vmid = nested_domain->s2_parent->vmid;

	ummu = core_to_ummu_device(nested_domain->base_domain.core_dev);

	cmds = kcalloc(array->entry_num, sizeof(*cmds), GFP_KERNEL);
	if (!cmds)
		return -ENOMEM;
	cur = cmds;
	end = cmds + array->entry_num;

	static_assert(sizeof(*cmds) == MCMDQ_ENT_DWORDS * sizeof(u64));
	ret = iommu_copy_struct_from_full_user_array(cmds, sizeof(*cmds), array,
					IOMMU_VIOMMU_INVALIDATE_DATA_UMMU);
	if (ret)
		goto out;

	last = cmds;
	while (cur != end) {
		ret = ummu_fix_user_cmd(ummu, cur->cmd, tecte_tag, vmid);
		if (ret)
			goto out;

		cur++;
		if (cur != end && (cur - last) != MCMDQ_BATCH_ENTRIES - 1)
			continue;

		ret = ummu_mcmdq_issue_cmdlist(ummu, last->cmd, cur - last, true);
		if (ret) {
			cur--;
			goto out;
		}
		last = cur;
	}
out:
	array->entry_num = cur - cmds;
	kfree(cmds);
	return ret;
}

struct iommufd_viommu *ummu_viommu_alloc(struct device *dev,
					 struct iommu_domain *parent,
					 struct iommufd_ctx *ictx,
					 unsigned int viommu_type)
{
	return NULL;
}

