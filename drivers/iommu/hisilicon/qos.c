// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ummu mpam internal interface.
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/iopoll.h>
#include <linux/errno.h>
#include <linux/bitfield.h>
#include <linux/kernel.h>

#include "regs.h"
#include "flush.h"
#include "cfg_table.h"
#include "logic_ummu/logic_ummu.h"
#include "qos.h"

#define UMMU_INVALID_PARTID 0xFFFF
#define UMMU_USER_MPAM_EN (1UL << 30)
#define UMMU_PARTID_MASK GENMASK_ULL(4, 0)
#define PAID_ARRAY_SIZE 32

static u16 *g_partids;

static int ummu_check_mpam_cap_info(struct ummu_device *ummu,
				    u32 partid, u32 pmg)
{
	if (!(ummu->cap.features & UMMU_FEAT_MTM)) {
		dev_warn(ummu->dev, "ummu mpam is not supported!\n");
		return -EINVAL;
	}

	if (partid > ummu->cap.mtm_id_max || pmg > ummu->cap.mtm_gp_max) {
		dev_err(ummu->dev,
			"ummu mpam rmid exceeds range: partid[0, %u] pmg[0, %u]\n",
			ummu->cap.mtm_id_max, ummu->cap.mtm_gp_max);
		return -ERANGE;
	}
	return 0;
}

static void ummu_set_tct_mtm(__le64 *tcte, u32 partid, u32 pmg)
{
	u64 val = le64_to_cpu(tcte[1]);

	val &= ~(TCT_ENT1_MTM_ID | TCT_ENT1_MTM_GP);
	val |= FIELD_PREP(TCT_ENT1_MTM_ID, partid);
	val |= FIELD_PREP(TCT_ENT1_MTM_GP, pmg);
	WRITE_ONCE(tcte[1], cpu_to_le64(val));
}

void ummu_release_partid_map(void)
{
	if (g_partids) {
		free_page((unsigned long)(void *)g_partids);
		g_partids = NULL;
	}
}

static int ummu_partid_map(int partid, __le64 *tecte)
{
	int index, i = 0;
	phys_addr_t phys;
	u64 val;
	u16 ran;

	if (!g_partids) {
		g_partids = (u16 *)(uintptr_t)__get_free_page(GFP_KERNEL);
		if (!g_partids) {
			pr_err("apply for partid array failed!\n");
			return -ENOMEM;
		}

		for (i = 0; i < PAID_ARRAY_SIZE; i++)
			g_partids[i] = UMMU_INVALID_PARTID;

		phys = virt_to_phys((void *)g_partids);
		val = le64_to_cpu(tecte[5]);
		val &= ~(TECT_ENT5_MTMC_PTR);
		val |= phys & TECT_ENT5_MTMC_PTR;
		WRITE_ONCE(tecte[5], cpu_to_le64(val));
	}

	index = (int)((unsigned int)partid & UMMU_PARTID_MASK);
	if (g_partids[index] == UMMU_INVALID_PARTID) {
		get_random_bytes(&ran, sizeof(u16));
		g_partids[index] = ran;
	}

	return 0;
}

static int check_domain_type(struct device *dev, struct ummu_mpam *mpam)
{
	struct iommu_domain *domain;
	u32 domain_type;

	if (mpam->tid != UMMU_INVALID_TID) {
		domain = ummu_core_get_domain_by_tid(dev, mpam->tid);
		if (!domain) {
			pr_err("the domain is NULL.\n");
			return -ENXIO;
		}
		domain_type = domain->type & IOMMU_DOMAIN_ALLOC_FLAGS;
		if (domain_type == IOMMU_DOMAIN_IDENTITY || domain_type == IOMMU_DOMAIN_BLOCKED) {
			pr_err("the domain_type is error.\n");
			return -EINVAL;
		}
	}
	return 0;
}

static int ummu_check_mpam_info(struct ummu_device *ummu,
				struct ummu_mpam *mpam)
{
	int ret;

	ret = ummu_check_mpam_cap_info(ummu, mpam->partid, mpam->pmg);
	if (ret)
		return ret;

	return 0;
}

static int ummu_get_tecte_and_tcte(struct ummu_device *ummu,
				   struct ummu_mpam *mpam, u32 tect_tag,
				   __le64 **tecte, __le64 **tcte)
{
	struct ummu_tct_desc_cfg *tct_cfg;

	*tecte = ummu_get_tecte_ptr(ummu, tect_tag);
	if (!(*tecte)) {
		pr_err("can not find tect entry to write.\n");
		return -EINVAL;
	}
	if (!(le64_to_cpu((*tecte)[0]) & TECT_ENT0_V)) {
		pr_err("tecte invalid\n");
		return -EINVAL;
	}

	if (mpam->tid != UMMU_INVALID_TID) {
		tct_cfg = ummu->local_tct_cfg;
		*tcte = ummu_get_tcte_ptr(tct_cfg, mpam->tid);
		if (!(*tcte)) {
			pr_err("can not find tct entry to write!\n");
			return -ENOMEM;
		}

		if (!(le64_to_cpu((*tcte)[0]) & TCT_ENT0_V)) {
			pr_err("invalid tid[%d]\n", mpam->tid);
			return -EINVAL;
		}
	}

	return 0;
}

static void ummu_set_tct_mtm_en(int tid, __le64 *tecte)
{
	u64 val = le64_to_cpu(tecte[1]);

	val &= ~TECT_ENT1_TCT_MTM_EN;
	if (tid != UMMU_INVALID_TID)
		val |= FIELD_PREP(TECT_ENT1_TCT_MTM_EN, 1);

	WRITE_ONCE(tecte[1], cpu_to_le64(val));
}

static void ummu_set_tect_mtm(struct ummu_mpam *mpam, __le64 *tecte)
{
	u64 val = le64_to_cpu(tecte[6]);

	val &= ~(TECT_ENT6_MTM_ID | TECT_ENT6_MTM_GP);
	val |= FIELD_PREP(TECT_ENT6_MTM_ID, mpam->partid);
	val |= FIELD_PREP(TECT_ENT6_MTM_GP, mpam->pmg);
	WRITE_ONCE(tecte[6], cpu_to_le64(val));
}

static int ummu_get_st_mode(__le64 *tecte, u32 tect_tag,
			    bool *is_nested, bool *s1_only)
{
	u64 val = le64_to_cpu(tecte[0]);

	switch (FIELD_GET(TECT_ENT0_ST_MODE, val)) {
	case TECT_ENT0_ST_MODE_S2:
	case TECT_ENT0_ST_MODE_BYPASS:
		break;
	case TECT_ENT0_ST_MODE_ABORT:
		pr_warn("currently in abort mode, eid[%u]\n", tect_tag);
		return -EINVAL;
	case TECT_ENT0_ST_MODE_S1:
		*s1_only = true;
		break;
	case TECT_ENT0_ST_MODE_NESTED:
		*is_nested = true;
		break;
	default:
		pr_err("unexpected TECT_ENT0_ST_MODE:%lu\n", FIELD_GET(TECT_ENT0_ST_MODE, val));
		return -EINVAL;
	}

	return 0;
}

static int ummu_set_master_mpam(struct ummu_device *ummu, struct ummu_mpam *mpam)
{
	bool is_nested = false;
	bool s1_only = false;
	u32 tect_tag = 0;
	__le64 *tecte;
	__le64 *tcte;
	int ret;

	ret = ummu_check_mpam_info(ummu, mpam);
	if (ret)
		return ret;

	ret = ummu_get_tecte_tag_by_eid(mpam->eid, &tect_tag);
	if (ret) {
		dev_err(ummu->dev, "invalid eid_high[0x%llx] eid_low[0x%llx]\n",
			(u64)(mpam->eid >> EID_HIGH_SZ_SHIFT),
			(u64)(mpam->eid));
		return -EINVAL;
	}

	ret = ummu_get_tecte_and_tcte(ummu, mpam, tect_tag, &tecte, &tcte);
	if (ret)
		return ret;

	ret = ummu_get_st_mode(tecte, tect_tag, &is_nested, &s1_only);
	if (ret)
		return ret;

	/* write mpam info to tecte */
	ummu_set_tct_mtm_en(mpam->tid, tecte);

	if (mpam->tid == UMMU_INVALID_TID) {
		ummu_set_tect_mtm(mpam, tecte);
		ummu_device_sync_tect(ummu, tect_tag);
		/* It's likely that we'll want to use the new tecte soon */
		ummu_device_prefetch_cfg(ummu, tect_tag, UMMU_INVALID_TID);
		goto out;
	}

	if (!s1_only && !is_nested) {
		pr_err("the current stage is wrong.\n");
		return -EINVAL;
	}

	/* write mpam info to tcte */
	ummu_set_tct_mtm(tcte, mpam->partid, mpam->pmg);

	if (is_nested) {
		ret = ummu_partid_map(mpam->partid, tecte);
		if (ret)
			return ret;
	}
	ummu_device_sync_tect(ummu, tect_tag);

	/* It's likely that we'll want to use the new tcte soon */
	ummu_device_prefetch_cfg(ummu, tect_tag, mpam->tid);
out:
	dev_info(ummu->dev, "partid %d, pmg %d already matched\n", mpam->partid,
		 mpam->pmg);
	return 0;
}

static int ummu_device_set_mpam(struct device *dev, struct ummu_mpam *mpam)
{
	struct ummu_master *master;

	if (!dev || !mpam) {
		pr_err("Invalid input parameter during set_mpam!\n");
		return -EINVAL;
	}

	master = (struct ummu_master *)dev_iommu_priv_get(dev);
	if (!master) {
		pr_err("get invalid dev!\n");
		return -EINVAL;
	}

	if (check_domain_type(dev, mpam))
		return -EINVAL;

	return ummu_set_master_mpam(master->ummu, mpam);
}

static int ummu_get_mpam_from_tcte(struct ummu_device *ummu,
				   struct ummu_mpam *mpam)
{
	__le64 *tcte;
	u64 val;

	tcte = ummu_get_tcte_ptr(ummu->local_tct_cfg, mpam->tid);
	if (!tcte)
		return -ENOMEM;

	if (!(le64_to_cpu(tcte[0]) & TCT_ENT0_V)) {
		pr_err("invalid tid[%d]\n", mpam->tid);
		return -EINVAL;
	}

	val = le64_to_cpu(tcte[1]);
	mpam->partid = (int)FIELD_GET(TCT_ENT1_MTM_ID, val);
	mpam->pmg = (int)FIELD_GET(TCT_ENT1_MTM_GP, val);

	return 0;
}

static int ummu_get_master_mpam(struct ummu_device *ummu, struct ummu_mpam *mpam)
{
	u32 tect_tag;
	__le64 *tecte;
	u64 val;
	int tid_valid;

	if (ummu_get_tecte_tag_by_eid(mpam->eid, &tect_tag)) {
		dev_err(ummu->dev, "invalid eid_high[0x%llx] eid_low[0x%llx]\n",
			(u64)(mpam->eid >> EID_HIGH_SZ_SHIFT),
			(u64)(mpam->eid));
		return -EINVAL;
	}

	tecte = ummu_get_tecte_ptr(ummu, tect_tag);
	if (!tecte)
		return -ENOMEM;

	val = le64_to_cpu(tecte[0]);
	if (!(val & TECT_ENT0_V)) {
		dev_err(ummu->dev, "invalid eid[%u]\n", tect_tag);
		return -EINVAL;
	}

	if (FIELD_GET(TECT_ENT0_ST_MODE, val) == TECT_ENT0_ST_MODE_ABORT) {
		pr_warn("currently in abort mode, eid[%u]\n", tect_tag);
		return -EINVAL;
	}

	tid_valid = (int)FIELD_GET(TECT_ENT1_TCT_MTM_EN, tecte[1]);
	if (tid_valid)
		return ummu_get_mpam_from_tcte(ummu, mpam);

	mpam->partid = (int)FIELD_GET(TECT_ENT6_MTM_ID, tecte[6]);
	mpam->pmg = (int)FIELD_GET(TECT_ENT6_MTM_GP, tecte[6]);

	return 0;
}

static int ummu_device_get_mpam(struct device *dev, struct ummu_mpam *mpam)
{
	struct ummu_master *master;

	if (!dev || !mpam) {
		pr_err("Invalid input parameter during get_mpam!\n");
		return -EINVAL;
	}

	master = (struct ummu_master *)dev_iommu_priv_get(dev);
	if (!master) {
		pr_err("get invalid dev!\n");
		return -EINVAL;
	}

	if (check_domain_type(dev, mpam))
		return -EINVAL;

	return ummu_get_master_mpam(master->ummu, mpam);
}

static int ummu_get_cfg_table_ptr(struct ummu_device *ummu,
				  u32 tid, __le64 **tcte)
{
	struct ummu_tct_desc_cfg *tct_cfg;

	tct_cfg = ummu->local_tct_cfg;
	*tcte = ummu_get_tcte_ptr(tct_cfg, tid);
	if (!(*tcte))
		return -ESPIPE;

	if (!(le64_to_cpu((*tcte)[0]) & TCT_ENT0_V))
		return -ENXIO;

	return 0;
}

int ummu_group_set_mpam(struct iommu_group *group, u16 partid, u8 pmg)
{
	struct iommu_domain *domain;
	struct ummu_domain *u_domain;
	struct ummu_device *ummu;
	u32 domain_type, tid;
	__le64 *tcte;
	int ret;

	domain = iommu_get_domain_for_group(group);
	domain_type = domain->type & IOMMU_DOMAIN_ALLOC_FLAGS;
	if (domain_type == IOMMU_DOMAIN_IDENTITY ||
		domain_type == IOMMU_DOMAIN_BLOCKED)
		return -EINVAL;

	u_domain = to_ummu_domain(iommu_to_agent_domain(domain));
	ummu = core_to_ummu_device(u_domain->base_domain.core_dev);

	ret = ummu_check_mpam_cap_info(ummu, partid, pmg);
	if (ret)
		return ret;

	tid = u_domain->base_domain.tid;
	ret = ummu_get_cfg_table_ptr(ummu, tid, &tcte);
	if (ret)
		return ret;

	/* write mpam info to tcte */
	ummu_set_tct_mtm(tcte, partid, pmg);
	ummu_sync_tct(ummu, 0, tid, true);

	/* It's likely that we'll want to use the new tcte soon */
	ummu_device_prefetch_cfg(ummu, 0, tid);
	pr_info("partid %u, pmg %u already matched\n", partid, pmg);
	return 0;
}

static int ummu_get_mpam_info(struct ummu_device *ummu,
			      u32 tid, u16 *partid, u8 *pmg)
{
	__le64 *tcte;
	u64 val;
	int ret;

	ret = ummu_get_cfg_table_ptr(ummu, tid, &tcte);
	if (ret)
		return ret;

	val = le64_to_cpu(tcte[1]);
	*partid = (int)FIELD_GET(TCT_ENT1_MTM_ID, val);
	*pmg = (int)FIELD_GET(TCT_ENT1_MTM_GP, val);

	return 0;
}

int ummu_group_get_mpam(struct iommu_group *group, u16 *partid, u8 *pmg)
{
	struct iommu_domain *domain;
	struct ummu_domain *u_domain;
	struct ummu_device *ummu;
	u32 domain_type;

	if (!partid || !pmg)
		return -ENXIO;

	domain = iommu_get_domain_for_group(group);
	domain_type = domain->type & IOMMU_DOMAIN_ALLOC_FLAGS;
	if (domain_type == IOMMU_DOMAIN_IDENTITY ||
	    domain_type == IOMMU_DOMAIN_BLOCKED)
		return -EINVAL;
	u_domain = to_ummu_domain(iommu_to_agent_domain(domain));
	ummu = core_to_ummu_device(u_domain->base_domain.core_dev);
	return ummu_get_mpam_info(ummu,
				  u_domain->base_domain.tid, partid, pmg);
}

int ummu_set_bypass_mpam(struct ummu_device *ummu, int partid, int pmg)
{
	void __iomem *bp_mtm_addr;
	u32 reg = 0;
	u32 val;
	int ret;

	ret = ummu_check_mpam_cap_info(ummu, partid, pmg);
	if (ret)
		return ret;

	bp_mtm_addr = ummu->base + UMMU_GBPA_MTM_CFG;
	reg |= FIELD_PREP(GBPA_TRANS_MTM_ID, partid);
	reg |= FIELD_PREP(GBPA_TRANS_MTM_GP, pmg);
	writel_relaxed(reg | GBPA_UPDATE_FLAG, bp_mtm_addr);
	ret = readl_relaxed_poll_timeout(bp_mtm_addr, val,
					 !(val & GBPA_UPDATE_FLAG), 1,
					 UMMU_REG_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(ummu->dev, "ummu write bypass_mpam data timeout\n");
		return ret;
	}
	return 0;
}

int ummu_get_bypass_mpam(struct ummu_device *ummu, int *partid, int *pmg)
{
	void __iomem *bp_mtm_addr;
	u32 reg;

	if (!ummu || !partid || !pmg)
		return -EINVAL;

	bp_mtm_addr = ummu->base + UMMU_GBPA_MTM_CFG;
	reg = readl_relaxed(bp_mtm_addr);
	*partid = FIELD_GET(GBPA_TRANS_MTM_ID, reg);
	*pmg = FIELD_GET(GBPA_TRANS_MTM_GP, reg);
	return 0;
}

int ummu_set_uotr_mpam(struct ummu_device *ummu, int partid, int pmg)
{
	void __iomem *cr3_addr;
	u32 reg = 0;
	u32 val;
	int ret;

	ret = ummu_check_mpam_cap_info(ummu, partid, pmg);
	if (ret)
		return ret;

	cr3_addr = ummu->base + UMMU_CR3;
	reg |= FIELD_PREP(CR3_TRANS_MTM_ID, partid);
	reg |= FIELD_PREP(CR3_TRANS_MTM_GP, pmg);

	writel_relaxed(reg | CR3_UPDATE_FLAG, cr3_addr);
	ret = readl_relaxed_poll_timeout(cr3_addr, val, !(val & CR3_UPDATE_FLAG), 1,
					 UMMU_REG_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(ummu->dev, "ummu write uotr_mpam data timeout\n");
		return ret;
	}
	return 0;
}

int ummu_get_uotr_mpam(struct ummu_device *ummu, int *partid, int *pmg)
{
	void __iomem *cr3_addr;
	u32 reg;

	if (!ummu || !partid || !pmg)
		return -EINVAL;

	cr3_addr = ummu->base + UMMU_CR3;
	reg = readl_relaxed(cr3_addr);
	*partid = FIELD_GET(CR3_TRANS_MTM_ID, reg);
	*pmg = FIELD_GET(CR3_TRANS_MTM_GP, reg);
	return 0;
}

int ummu_device_dev_config(struct device *dev, int type, int command, void *data)
{
	switch (type) {
	case UMMU_MPAM:
		switch (command) {
		case UMMU_COMMAND_SET:
			return ummu_device_set_mpam(dev, (struct ummu_mpam *)data);
		case UMMU_COMMAND_GET:
			return ummu_device_get_mpam(dev, (struct ummu_mpam *)data);
		default:
			pr_err("unexpected device config command %d\n", command);
			return -EINVAL;
		}
	default:
		pr_err("unexpected device config type %d\n", type);
		return -EINVAL;
	}
}
