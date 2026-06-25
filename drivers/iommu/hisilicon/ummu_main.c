// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Device's implementations
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/iopoll.h>
#include <ub/ubfi/ubfi.h>
#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/mmu_notifier.h>

#include "logic_ummu/logic_ummu.h"
#include "ummu_impl.h"
#include "interrupt.h"
#include "perm_queue.h"
#include "page_table.h"
#include "queue.h"
#include "regs.h"
#include "flush.h"
#include "ummu.h"
#include "attribute.h"
#include "cfg_table.h"
#include "iommu.h"
#include "sva.h"
#include "qos.h"

#define UMMU_DRV_NAME "ummu"
#define HISI_VENDOR_ID 0xCC08

static bool sva_separated_mode = true;
module_param(sva_separated_mode, bool, 0444);
MODULE_PARM_DESC(sva_separated_mode,
	"Enable user-mode SVA with an independent page table (no process page table sharing).");

static u16 ummu_chip_identifier;
bool hw_bypass;

bool ummu_sva_separated_enabled(void)
{
	return sva_separated_mode;
}

int ummu_write_reg_sync(struct ummu_device *ummu, u32 val,
			u32 reg_off, u32 ack_off)
{
	u32 reg;

	writel_relaxed(val, ummu->base + reg_off);
	return readl_relaxed_poll_timeout(ummu->base + ack_off, reg, reg == val,
					  1, UMMU_REG_POLL_TIMEOUT_US);
}

static int ummu_update_gbpa(struct ummu_device *ummu, u32 set,
			    u32 clr)
{
	void __iomem *gbpa = ummu->base + UMMU_GBPA;
	u32 reg;
	int ret;

	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE_BIT), 1,
					 UMMU_REG_POLL_TIMEOUT_US);
	if (ret)
		return ret;

	reg &= ~clr;
	reg |= set;
	writel_relaxed(reg | GBPA_UPDATE_BIT, gbpa);
	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE_BIT), 1,
					 UMMU_REG_POLL_TIMEOUT_US);
	if (ret)
		dev_err(ummu->dev, "GBPA not responding to update\n");
	return ret;
}

static int ummu_ioremap(struct ummu_device *ummu, resource_size_t start,
			resource_size_t size)
{
	struct resource res = DEFINE_RES_MEM(start, size);

	ummu->base = devm_ioremap_resource(ummu->dev, &res);
	if (IS_ERR(ummu->base))
		return PTR_ERR(ummu->base);

	return 0;
}

static int ummu_device_register(struct ummu_device *ummu)
{
	const struct attribute_group **groups;
	int ret;

	groups = get_attribute_group();
	ret = iommu_device_sysfs_add(&ummu->core_dev.iommu, ummu->dev, groups,
				     "%s", dev_name(ummu->dev));
	if (ret) {
		dev_err(ummu->dev, "add iommu sysfs failed, ret = %d.\n", ret);
		return ret;
	}

	ummu->helper_ops = &ummu_helper;
	ret = logic_add_ummu_device(ummu, &ummu_iommu_ops, &ummu_ops);
	if (ret) {
		iommu_device_sysfs_remove(&ummu->core_dev.iommu);
		return ret;
	}
	dev_info(ummu->dev, "ummu register to ummu core successful!\n");
	return 0;
}

static void ummu_device_unregister(struct ummu_device *ummu)
{
	logic_remove_ummu_device(ummu);
	iommu_device_sysfs_remove(&ummu->core_dev.iommu);
}

static int ummu_init_structures(struct ummu_device *ummu)
{
	int ret;

	ret = ummu_init_queues(ummu);
	if (ret) {
		dev_err(ummu->dev, "init queues failed\n");
		return ret;
	}

	ret = ummu_prepare_tect_tct(ummu);
	if (ret) {
		dev_err(ummu->dev, "prepare tect failed\n");
		goto resource_release;
	}

	ret = ummu_device_init_hash_table(ummu);
	if (ret)
		goto resource_release;

	if (ummu->cap.features & UMMU_FEAT_MAPT) {
		/* ctrl page is private for every ummu hardware */
		ummu_device_init_permq_ctrl_page(ummu);
		/* ctx table is common for every ummu hardware */
		ret = ummu_device_init_permqs(ummu);
		if (ret)
			goto resource_release;
	}

	return 0;

resource_release:
	ummu_iopf_queue_free(ummu);
	return ret;
}

static void ummu_device_hw_probe_iidr(struct ummu_device *ummu)
{
	u32 reg;

	/*
	 * In the 1st generation On the hisi chip, IIDR_PROD_ID is set to 0,
	 * ummu enables chip_identifier to perform some specialized operations.
	 */
	reg = readl_relaxed(ummu->base + UMMU_IIDR);
	if (ummu_chip_identifier == HISI_VENDOR_ID) {
		if (!FIELD_GET(IIDR_PROD_ID, reg)) {
			ummu->cap.options |= UMMU_OPT_DOUBLE_PLBI;
			ummu->cap.options |= UMMU_OPT_KCMD_PLBI;
			ummu->cap.options |= UMMU_OPT_CHK_MAPT_CONTINUITY;
			ummu->cap.options |= UMMU_OPT_SYNC_WITH_PLBI;
			ummu->cap.options |= UMMU_OPT_KV_CAM_CONTINUITY;
			ummu->cap.options |= UMMU_OPT_ONE_MCMDQ;
			ummu->cap.options |= UMMU_OPT_DOUBLE_TLBI;
			ummu->cap.options |= UMMU_OPT_TLBI_LIMIT_SCALE;
			ummu->cap.features &= ~UMMU_FEAT_BTM;
			ummu->cap.features &= ~UMMU_FEAT_STALLS;
		} else {
			ummu->cap.options |= UMMU_OPT_UMAU;
		}
	}
	dev_notice(ummu->dev, "features 0x%08x, options 0x%08x.\n",
		   ummu->cap.features, ummu->cap.options);
}

static void ummu_device_hw_probe_cap0(struct ummu_device *ummu)
{
	u32 reg, pasids, ubrt_pasids, cap_pasids;

	reg = readl_relaxed(ummu->base + UMMU_CAP0);
	/* 2-level tect structures */
	if (reg & CAP0_TECT_LVL_BIT)
		ummu->cap.features |= UMMU_FEAT_2_LVL_TECT;

	/* 2-level tct structures */
	if (reg & CAP0_TCT_LVL_BIT)
		ummu->cap.features |= UMMU_FEAT_2_LVL_TCT;

	/* TID size */
	ummu->cap.tid_bits = FIELD_GET(CAP0_TIDSIZE_MASK, reg);
	/* The tid cap should follow the UB protocol */
	ubrt_pasids = ummu->core_dev.iommu.max_pasids;
	cap_pasids = 1 << ummu->cap.tid_bits;
	if (ubrt_pasids > cap_pasids)
		dev_warn(ummu->dev, "ubrt max_pasids[%u] beyond capacity.\n",
			 ubrt_pasids);
	pasids = min(cap_pasids, (1UL << UB_MAX_TID_BITS));
	ummu->core_dev.iommu.max_pasids = min(ubrt_pasids, pasids);
	/* TECTE_TAG size */
	ummu->cap.deid_bits = FIELD_GET(CAP0_DEIDSIZE_MASK, reg);
	if (ummu->cap.deid_bits < TECT_SPLIT)
		ummu->cap.features &= ~UMMU_FEAT_2_LVL_TECT;
}

static void ummu_device_hw_probe_cap1(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CAP1);

	/* Maximum number of outstanding stalls */
	ummu->evtq.max_stalls = FIELD_GET(CAP1_STALL_MAX, reg);

	/* Support generation of WFE wake-up events to PE */
	if (reg & CAP1_EVENT_GEN)
		ummu->cap.features |= UMMU_FEAT_SEV;

	/* MCMDQ's support, numbers and depth */
	if (reg & CAP1_MCMDQ_SUPPORT) {
		ummu->cap.features |= UMMU_FEAT_MCMDQ;
		ummu->cap.mcmdq_log2num = FIELD_GET(CAP1_MCMDQ_LOG2NUM, reg);
		ummu->cap.mcmdq_log2size = min(FIELD_GET(CAP1_MCMDQ_LOG2SIZE, reg),
					       MCMDQ_MAX_LOG2SIZE);
	}

	/* EVENTQ's support, numbers and depth */
	if (reg & CAP1_EVENTQ_SUPPORT) {
		ummu->cap.features |= UMMU_FEAT_EVENTQ;
		ummu->cap.evtq_log2num = FIELD_GET(CAP1_EVENTQ_LOG2NUM, reg);
		ummu->cap.evtq_log2size = min(FIELD_GET(CAP1_EVENTQ_LOG2SIZE, reg),
					      EVTQ_MAX_LOG2SIZE);
	}
}

static int ummu_device_get_ttf(struct ummu_device *ummu, u32 reg)
{
	switch (FIELD_GET(CAP2_TTF_MASK, reg)) {
	case CAP2_TTF_AARCH32_64:
		ummu->cap.ias = CAP2_TTF_IAS_40;
		break;
	case CAP2_TTF_AARCH64:
		break;
	default:
		dev_err(ummu->dev, "page table format not supported!\n");
		return -ENXIO;
	}
	return 0;
}

static int ummu_device_get_trans_stage(struct ummu_device *ummu, u32 reg)
{
	if (!(reg & (CAP2_S1P_BIT | CAP2_S2P_BIT))) {
		dev_err(ummu->dev, "no translation stage support!\n");
		return -ENXIO;
	}

	if (reg & CAP2_S1P_BIT)
		ummu->cap.features |= UMMU_FEAT_TRANS_S1;

	if (reg & CAP2_S2P_BIT)
		ummu->cap.features |= UMMU_FEAT_TRANS_S2;

	if ((ummu->cap.features & UMMU_FEAT_TRANS_S1) &&
	    (ummu->cap.features & UMMU_FEAT_TRANS_S2))
		ummu->cap.features |= UMMU_FEAT_NESTING;

	return 0;
}

static void ummu_device_get_pgsize(struct ummu_device *ummu, u32 reg)
{
	/* page sizes */
	if (reg & CAP2_GRAN64K_BIT)
		ummu->cap.pgsize_bitmap |= SZ_64K | SZ_512M;
	if (reg & CAP2_GRAN16K_BIT)
		ummu->cap.pgsize_bitmap |= SZ_16K | SZ_32M;
	if (reg & CAP2_GRAN4K_BIT)
		ummu->cap.pgsize_bitmap |= SZ_4K | SZ_2M | SZ_1G;

	if (ummu_iommu_ops.pgsize_bitmap == -1UL)
		ummu_iommu_ops.pgsize_bitmap = ummu->cap.pgsize_bitmap;
	else
		ummu_iommu_ops.pgsize_bitmap |= ummu->cap.pgsize_bitmap;
}

static void ummu_device_get_oas(struct ummu_device *ummu, u32 reg)
{
	/* output address size */
	switch (FIELD_GET(CAP2_OAS_MASK, reg)) {
	case CAP2_OAS_32_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_32;
		break;
	case CAP2_OAS_36_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_36;
		break;
	case CAP2_OAS_40_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_40;
		break;
	case CAP2_OAS_42_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_42;
		break;
	case CAP2_OAS_44_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_44;
		break;
	default:
		dev_warn(ummu->dev,
			 "unknown output address size. truncating to 48-bit\n");
		fallthrough;
	case CAP2_OAS_48_BIT:
		ummu->cap.oas = CAP2_TTF_OAS_48;
		break;
	}
}

static int ummu_device_hw_probe_cap2(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CAP2);
	int ret;

	ret = ummu_device_get_ttf(ummu, reg);
	if (ret)
		return ret;

	ret = ummu_device_get_trans_stage(ummu, reg);
	if (ret)
		return ret;

	/* input address size */
	if (FIELD_GET(CAP2_VA_EXT_MASK, reg) == CAP2_VA_EXT_52)
		ummu->cap.features |= UMMU_FEAT_VAX;

	ummu_device_get_pgsize(ummu, reg);

	ummu_device_get_oas(ummu, reg);

	ummu->cap.ias = max(ummu->cap.ias, ummu->cap.oas);

	if (FIELD_GET(CAP2_RTLBI_BIT, reg))
		ummu->cap.features |= UMMU_FEAT_RANGE_INV;

	if (FIELD_GET(CAP2_BTLBI_BIT, reg))
		ummu->cap.features |= UMMU_FEAT_BTM;
	else
		dev_warn(ummu->dev, "don't support BTM!\n");

	if (FIELD_GET(CAP2_HW_BYPASS, reg))
		hw_bypass = true;

	return 0;
}

static void ummu_device_get_stall_model(struct ummu_device *ummu, u32 reg)
{
	switch (FIELD_GET(CAP3_STALL_MODEL_MASK, reg)) {
	case CAP3_STALL_MODE_FORCE:
		ummu->cap.features |= UMMU_FEAT_STALL_FORCE;
		fallthrough;
	case CAP3_STALL_MODE:
		ummu->cap.features |= UMMU_FEAT_STALLS;
	default:
		break;
	}
}

static void ummu_device_get_httu(struct ummu_device *ummu, u32 reg)
{
	switch (FIELD_GET(CAP3_HTTU_MASK, reg)) {
	case CAP3_HTTU_ACCESS_DIRTY:
		ummu->cap.features |= UMMU_FEAT_HD;
		fallthrough;
	case CAP3_HTTU_ACCESS:
		ummu->cap.features |= UMMU_FEAT_HA;
	default:
		break;
	}
}

static void ummu_device_get_bbm_level(struct ummu_device *ummu, u32 reg)
{
	switch (FIELD_GET(CAP3_BBML_MASK, reg)) {
	case CAP3_BBML0:
		break;
	case CAP3_BBML1:
		ummu->cap.features |= UMMU_FEAT_BBML1;
		break;
	case CAP3_BBML2:
		ummu->cap.features |= UMMU_FEAT_BBML2;
		break;
	default:
		dev_warn(ummu->dev, "unknown/unsupported BBM behavior level\n");
	}
}

static int ummu_device_hw_probe_cap3(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CAP3);

	ummu_device_get_stall_model(ummu, reg);

	if (reg & CAP3_MSI_SUPPORT_BIT)
		ummu->cap.features |= UMMU_FEAT_MSI;

	if (reg & CAP3_HYP_S1CTX_BIT) {
		ummu->cap.features |= UMMU_FEAT_HYP;
		if (cpus_have_cap(ARM64_HAS_VIRT_HOST_EXTN)) {
			ummu->cap.features |= UMMU_FEAT_E2H;
			pr_debug("support hypervisor and E2H\n");
		}
	}

	ummu_device_get_httu(ummu, reg);

	if (reg & CAP3_MTM_BIT)
		ummu->cap.features |= UMMU_FEAT_MTM;

	if (reg & CAP3_COHACC_BIT) {
		ummu->cap.features |= UMMU_FEAT_COHERENCY;
		if (ummu->cap.features & UMMU_FEAT_MSI)
			ummu->cap.options |= UMMU_OPT_MSIPOLL;
	}

	ummu_device_get_bbm_level(ummu, reg);

	return 0;
}

static int ummu_device_hw_probe_cap4(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CAP4);
	int hw_permq_ent;

	if (reg & CAP4_PPLB_SUPPORT)
		ummu->cap.features |= UMMU_FEAT_PPLBI;

	hw_permq_ent = 1 << FIELD_GET(CAP4_UCMDQ_LOG2SIZE, reg);
	ummu->cap.permq_ent_num.cmdq_num =
		min_t(int, round_up(PAGE_SIZE / PCMDQ_ENT_BYTES, PCMDQ_ENT_BYTES),
		hw_permq_ent);

	hw_permq_ent = 1 << FIELD_GET(CAP4_UCPLQ_LOG2SIZE, reg);
	ummu->cap.permq_ent_num.cplq_num =
		min_t(int, round_up(PAGE_SIZE / PCPLQ_ENT_BYTES, PCPLQ_ENT_BYTES),
		hw_permq_ent);

	if (ummu->impl_ops && ummu->impl_ops->hw_probe)
		return ummu->impl_ops->hw_probe(ummu);
	return 0;
}

static void ummu_device_hw_probe_cap5(struct ummu_device *ummu)
{
	u32 reg;

	reg = readl_relaxed(ummu->base + UMMU_CAP5);
	if (reg & CAP5_FREE_BIT_SUPPORT)
		ummu->cap.features |= UMMU_FEAT_FREE_BIT;

	if (reg & CAP5_RANGE_PLBI_BIT)
		ummu->cap.features |= UMMU_FEAT_RANGE_PLBI;

	if (reg & CAP5_MAPT_SUPPORT)
		ummu->cap.features |= UMMU_FEAT_MAPT;

	if (reg & CAP5_PT_GRAN4K_BIT)
		ummu->cap.ptsize_bitmap |= SZ_4K;

	if (reg & CAP5_PT_GRAN2M_BIT)
		ummu->cap.ptsize_bitmap |= SZ_2M;

	if (reg & CAP5_TKVALCHK_BIT)
		ummu->cap.features |= UMMU_FEAT_TOKEN_CHK;

	/*
	 * the ASID and VMID capabilities are determined based on
	 * the bit widths of the ASID and VMID in the configuration table.
	 */
	ummu->cap.asid_bits = ilog2(UMMU_MAX_ASIDS);
	ummu->cap.vmid_bits = ilog2(UMMU_MAX_VMIDS);
	if (ummu_sva_supported(ummu))
		ummu->cap.features |= UMMU_FEAT_SVA;

	dev_info(ummu->dev, "ias %u-bit, oas %u-bit.\n",
		 ummu->cap.ias, ummu->cap.oas);
}

static void ummu_device_hw_probe_cap6(struct ummu_device *ummu)
{
	u32 reg;

	if (ummu->cap.features & UMMU_FEAT_MTM) {
		reg = readl_relaxed(ummu->base + UMMU_CAP6);
		ummu->cap.mtm_id_max = FIELD_GET(CAP6_MTM_ID_MAX, reg);
		ummu->cap.mtm_gp_max = FIELD_GET(CAP6_MTM_GP_MAX, reg);
	}
	dev_dbg(ummu->dev, "partid_max %u, pmg_max %u.\n", ummu->cap.mtm_id_max,
		ummu->cap.mtm_gp_max);
}

static int ummu_device_hw_init(struct ummu_device *ummu)
{
	int ret;

	ummu_device_hw_probe_cap0(ummu);
	ummu_device_hw_probe_cap1(ummu);

	ret = ummu_device_hw_probe_cap2(ummu);
	if (ret)
		return ret;

	ret = ummu_device_hw_probe_cap3(ummu);
	if (ret)
		return ret;

	ret = ummu_device_hw_probe_cap4(ummu);
	if (ret)
		return ret;

	ummu_device_hw_probe_cap5(ummu);
	ummu_device_hw_probe_cap6(ummu);
	ummu_device_hw_probe_iidr(ummu);

	return 0;
}

static void ummu_device_sync(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CR0);
	if (reg & CR0_UMMU_EN) {
		dev_warn(ummu->dev, "ummu currently enabled! Resetting...\n");
		ummu_update_gbpa(ummu, GBPA_ABORT_BIT, 0);
	}
}

static int ummu_device_disable(struct ummu_device *ummu)
{
	int ret;

	ret = ummu_write_reg_sync(ummu, 0, UMMU_CR0, UMMU_CR0ACK);
	if (ret)
		dev_err(ummu->dev, "disable ummu interface failed, ret = %d.\n", ret);

	return ret;
}

static int ummu_device_enable(struct ummu_device *ummu)
{
	int ret;
	u32 cr0;

	cr0 = readl_relaxed(ummu->base + UMMU_CR0);
	cr0 |= CR0_UMMU_EN;
	ret = ummu_write_reg_sync(ummu, cr0, UMMU_CR0, UMMU_CR0ACK);
	if (ret)
		dev_err(ummu->dev, "enable ummu interface failed.\n");

	return ret;
}

static void ummu_device_set_mem_attr(struct ummu_device *ummu)
{
	u32 reg;

	reg = CR1_TECT_MODE_SEL | CR1_E2H |
	      FIELD_PREP(CR1_TABLE_SH, UMMU_SH_ISH) |
	      FIELD_PREP(CR1_TABLE_OC, UMMU_CACHE_WB) |
	      FIELD_PREP(CR1_TABLE_IC, UMMU_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_SH, UMMU_SH_ISH) |
	      FIELD_PREP(CR1_QUEUE_OC, UMMU_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_IC, UMMU_CACHE_WB);

	writel_relaxed(reg, ummu->base + UMMU_CR1);
}

static int ummu_device_mapt_enable(struct ummu_device *ummu)
{
	u32 reg = readl_relaxed(ummu->base + UMMU_CR0);
	int ret;

	reg |= CR0_MAPT_EN;

	ret = ummu_write_reg_sync(ummu, reg, UMMU_CR0, UMMU_CR0ACK);
	if (ret) {
		dev_err(ummu->dev, "enable ummu mapt func failed, ret = %d.\n", ret);
		return ret;
	}

	if (ummu->cap.features & UMMU_FEAT_PPLBI) {
		reg = readl_relaxed(ummu->base + UMMU_CR2);
		reg |= CR2_POSITIVE_PLB;
		writel_relaxed(reg, ummu->base + UMMU_CR2);
	}

	return 0;
}

static int ummu_device_reset(struct ummu_device *ummu)
{
	int ret;

	ummu_device_sync(ummu);

	ret = ummu_device_disable(ummu);
	if (ret)
		return ret;

	/* set configuration table and queue memory attributes */
	ummu_device_set_mem_attr(ummu);

	ummu_device_set_tect(ummu);

	ummu_device_config_hash_table(ummu);
	ret = ummu_device_mcmdq_init_cfg(ummu);
	if (ret)
		return ret;

	ret = ummu_write_evtq_regs(ummu);
	if (ret)
		return ret;

	if (ummu->cap.features & UMMU_FEAT_MAPT) {
		ummu_device_set_permq_ctxtbl(ummu);
		ret = ummu_device_mapt_enable(ummu);
		if (ret)
			return ret;
	}

	ummu_setup_irqs(ummu);
	ummu_sync_tect_all(ummu);
	ummu_init_flush_iotlb(ummu);
	ummu_device_flush_ioplb_all(ummu);

	return ummu_device_enable(ummu);
}

static void release_ummu_dev_res(void *data)
{
	struct ummu_device *ummu = (struct ummu_device *)data;
	ummu_device_free_mcmdq(ummu);
	ummu_device_free_evtq(ummu);
	ummu_iopf_queue_free(ummu);
	ummu_device_uninit_permqs(ummu);
}

static int ummu_device_ubrt_probe(struct ummu_device *ummu)
{
	struct fwnode_handle *fwnode = dev_fwnode(ummu->dev);
	struct ubrt_fwnode *fw;
	struct ummu_node *node;

	if (!fwnode)
		return -EINVAL;

	fw = ubrt_fwnode_get(fwnode);
	if (!fw) {
		dev_err(ummu->dev, "get ubrt fwnode failed!\n");
		return -ENXIO;
	}

	if (fw->type != UBRT_UMMU) {
		dev_err(ummu->dev, "get invalid ubct type!\n");
		return -ESPIPE;
	}

	node = (struct ummu_node *)fw->ubrt_node;
	ummu_chip_identifier = node->vendor_id;

	ummu->core_dev.iommu.min_pasids = node->min_tid;
	ummu->core_dev.iommu.max_pasids = node->max_tid;

	return 0;
}

static int ummu_device_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ummu_device *ummu;
	struct resource *res;
	int ret;

	ummu = devm_kzalloc(dev, sizeof(*ummu), GFP_KERNEL);
	if (!ummu)
		return -ENOMEM;

	ummu->dev = dev;

	ret = ummu_device_ubrt_probe(ummu);
	if (ret) {
		dev_err(dev, "failed to probe ummu_node: %d\n", ret);
		return ret;
	}

	/* Base address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "IO resource is null\n");
		return -EINVAL;
	}

	ummu = ummu_impl_init(ummu);
	if (IS_ERR(ummu))
		return PTR_ERR(ummu);

	/*
	 * Don't map the IMPLEMENTATION DEFINED regions, since they may contain
	 * the root registers which are reserved by the bios.
	 */
	ret = ummu_ioremap(ummu, res->start, UMMU_REG_SZ);
	if (ret)
		return ret;

	/* hardware init */
	ret = ummu_device_hw_init(ummu);
	if (ret)
		return ret;

	ret = ummu_check_cap(ummu);
	if (ret)
		return ret;

	/* Initialise in-memory data structures */
	ret = ummu_init_structures(ummu);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, release_ummu_dev_res, ummu);
	if (ret)
		return ret;

	/* record ummu device */
	platform_set_drvdata(pdev, ummu);

	ret = ummu_device_reset(ummu);
	if (ret)
		goto err_disable_ummu;

	ret = ummu_device_register(ummu);
	if (ret) {
		dev_err(dev, "register ummu device failed, ret = %d.\n", ret);
		goto err_disable_ummu;
	}

	if (ummu->impl_ops && ummu->impl_ops->dev_probe) {
		ret = ummu->impl_ops->dev_probe(ummu);
		if (ret) {
			dev_err(dev,
				"probe ummu impl device failed, ret = %d.\n",
				ret);
			goto probe_res_release;
		}
	}

	if (!hw_bypass)
		(void)ummu_global_identity_pgtbl_init(ummu);

	return 0;

probe_res_release:
	logic_remove_ummu_device(ummu);
	iommu_device_sysfs_remove(&ummu->core_dev.iommu);
err_disable_ummu:
	(void)ummu_device_disable(ummu);
	return ret;
}

static int ummu_device_remove(struct platform_device *pdev)
{
	struct ummu_device *ummu = platform_get_drvdata(pdev);

	if (ummu->impl_ops && ummu->impl_ops->dev_remove)
		ummu->impl_ops->dev_remove(ummu);

	ummu_device_disable(ummu);
	ummu_device_unregister(ummu);

	ummu_put_tct_table(ummu->local_tct_cfg);
	ummu_put_tect_table(ummu->tect_cfg);
	dev_dbg(&pdev->dev, "Remove ummu successful!\n");
	return 0;
}

static void ummu_device_shutdown(struct platform_device *pdev)
{
	struct ummu_device *ummu = platform_get_drvdata(pdev);

	ummu_device_disable(ummu);
}

#ifdef CONFIG_OF
static const struct of_device_id hisi_ummu_of_match[] = {
	{ .compatible = "ub,ummu", },
	{ }
};
MODULE_DEVICE_TABLE(of, hisi_ummu_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id hisi_ummu_acpi_match[] = {
	{ "HISI0551", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_ummu_acpi_match);
#endif

struct platform_driver ummu_driver = {
	.driver = {
		.name = UMMU_DRV_NAME,
		.suppress_bind_attrs = true,
		.of_match_table = of_match_ptr(hisi_ummu_of_match),
		.acpi_match_table = ACPI_PTR(hisi_ummu_acpi_match),
	},
	.probe = ummu_device_probe,
	.remove = ummu_device_remove,
	.shutdown = ummu_device_shutdown,
};

static int __init ummu_driver_register(struct platform_driver *drv)
{
	int ret = logic_ummu_device_init();

	if (ret) {
		pr_err("init logic ummu failed, ret = %d.\n", ret);
		return ret;
	}
	ret = ummu_init_global_meta();
	if (ret) {
		pr_err("global meta resource init failed, ret = %d\n", ret);
		ummu_free_global_meta();
		return ret;
	}
	return platform_driver_register(drv);
}

static void __exit ummu_driver_unregister(struct platform_driver *drv)
{
	mmu_notifier_synchronize();
	platform_driver_unregister(drv);
	ummu_release_partid_map();
	ummu_free_global_meta();
	if (!hw_bypass)
		ummu_global_identity_pgtbl_free();

	logic_ummu_device_exit();
}

module_driver(ummu_driver, ummu_driver_register, ummu_driver_unregister);

MODULE_IMPORT_NS(UMMU_CORE_DRIVER);
MODULE_IMPORT_NS(UMMU_INTERNAL);
MODULE_IMPORT_NS(IOMMUFD);
MODULE_DESCRIPTION("Hisilicon ummu driver");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" UMMU_DRV_NAME);
