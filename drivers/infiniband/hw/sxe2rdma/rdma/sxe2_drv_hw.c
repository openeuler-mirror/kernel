// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_hw.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/bitfield.h>

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_rdma_log.h"

static u32 sxe2_pf_bar_regs_offset[SXE2_PF_MAX_BAR_REGS] = {
	PF_QSET_APPLY_REQ_OFFSET,
	PF_QSET_APPLY_RESP_OFFSET,
	PF_QSET_QUERY_REQ_OFFSET,
	PF_QSET_QUERY_RESP_OFFSET,
	PF_QSET_RELEASE_REQ_OFFSET,
	PF_QSET_RELEASE_RESP_OFFSET,
	PF_QSET_QP_BIND_REQ_OFFSET,
	PF_QSET_QP_BIND_RESP_OFFSET,
	PF_GLINT_CTRL_DYN_CTL_OFFSET(0),
	PF_MQC_ADDR_HIGH_OFFEST,
	PF_MQC_ADDR_LOW_OFFEST,
	PF_MQC_ADDR_VLD_OFFEST,
	PF_MQ_STATUS_OFFEST,
	PF_MQ_DB_OFFEST,
	PF_MQ_WQE_DONE_OFFEST,
	PF_MQ_ERRCODES_OFFEST,
	PF_RCMS_SPT_CACHE_FAST_INVALID_MASK_OFFSET,
	PF_RCMS_SPT_CACHE_FAST_INVALID_IDX_OFFSET,
	PF_RDMA_FEATURE_HW_VERSION_LOW_OFFSET,
	PF_RDMA_FEATURE_HW_VERSION_HIGH_OFFSET,
	PF_RDMA_FEATURE_ENDPT_TRK_OFFSET,
	PF_RDMA_FEATURE_QSETS_MAX_OFFSET,
	PF_RDMA_FEATURE_FW_VERSION_OFFSET,
	PF_RDMA_CONFIG_PKEY_OFFSET,
	GLINT_CTRL_PF_INT_AEQCTL_OFFSET,
	GLINT_CTRL_PF_INT_CEQCTL_OFFSET(0),
	SXE2_PF_INT_RATE(0),
};

static u32 sxe2_vf_bar_regs_offset[SXE2_VF_MAX_BAR_REGS] = {
	VF_QSET_APPLY_REQ_OFFSET,
	VF_QSET_APPLY_RESP_OFFSET,
	VF_QSET_QUERY_REQ_OFFSET,
	VF_QSET_QUERY_RESP_OFFSET,
	VF_QSET_RELEASE_REQ_OFFSET,
	VF_QSET_RELEASE_RESP_OFFSET,
	VF_QSET_QP_BIND_REQ_OFFSET,
	VF_QSET_QP_BIND_RESP_OFFSET,
	VF_GLINT_CTRL_DYN_CTL_OFFSET(0),
	VF_MQC_ADDR_HIGH_OFFEST,
	VF_MQC_ADDR_LOW_OFFEST,
	VF_MQC_ADDR_VLD_OFFEST,
	VF_MQ_STATUS_OFFEST,
	VF_MQ_DB_OFFEST,
	VF_MQ_WQE_DONE_OFFEST,
	VF_MQ_ERRCODES_OFFEST,
	VF_RCMS_SPT_CACHE_FAST_INVALID_MASK_OFFSET,
	VF_RCMS_SPT_CACHE_FAST_INVALID_IDX_OFFSET,
	VF_RDMA_FEATURE_HW_VERSION_LOW_OFFSET,
	VF_RDMA_FEATURE_HW_VERSION_HIGH_OFFSET,
	VF_RDMA_FEATURE_ENDPT_TRK_OFFSET,
	VF_RDMA_FEATURE_QSETS_MAX_OFFSET,
	VF_RDMA_FEATURE_FW_VERSION_OFFSET,
	VF_RDMA_CONFIG_PKEY_OFFSET,
};

void sxe2_hw_ena_irq(struct sxe2_rdma_ctx_dev *dev, u32 idx)
{
	u32 val;
	u32 interval = 0;

	if (dev->ceq_itr && dev->aeq->msix_idx != idx)
		interval = dev->ceq_itr >> 1;

	val = (u32)(FIELD_PREP((s64)SXE2_GLINT_DYN_CTL_ITR_INDEX,
			       SXE2_RDMA_IDX_ITR0) |
		    FIELD_PREP((s64)SXE2_GLINT_DYN_CTL_INTERVAL, interval) |
		    FIELD_PREP((s64)SXE2_GLINT_DYN_CTL_INTENA, true) |
		    FIELD_PREP((s64)SXE2_GLINT_DYN_CTL_CLEARPBA, true));

	writel(val, dev->hw_regs[IRQ_DYN_CTL] + idx);
}

void sxe2_hw_disable_irq(struct sxe2_rdma_ctx_dev *dev, u32 idx)
{
	writel(0, dev->hw_regs[IRQ_DYN_CTL] + idx);
}

void sxe2_hw_cfg_aeq(struct sxe2_rdma_ctx_dev *dev, u32 idx, bool enable)
{
	u32 reg_val;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	reg_val = (u32)(FIELD_PREP((s64)SXE2_PFINT_AEQCTL_CAUSE_ENA, enable) |
			FIELD_PREP((s64)SXE2_PFINT_AEQCTL_MSIX_INDEX, idx) |
			FIELD_PREP((s64)SXE2_PFINT_AEQCTL_ITR_INDEX,
				   SXE2_RDMA_IDX_NOITR));

	DRV_RDMA_LOG_DEV_DEBUG("aeq idx: %#x, enable: %u\n", idx, enable);
	writel(reg_val, dev->hw_regs[PF_INT_AEQCTL]);
}

void sxe2_hw_cfg_ceq(struct sxe2_rdma_ctx_dev *dev, u32 ceq_id, u32 idx,
		     bool enable)
{
	u32 reg_val;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	reg_val = enable ? SXE2_GLINT_CEQCTL_CAUSE_ENA : 0;
	reg_val |= (idx << SXE2_GLINT_CEQCTL_MSIX_INDEX_S) |
		   (SXE2_RDMA_IDX_ITR0 << SXE2_GLINT_CEQCTL_ITR_INDEX_S);

	DRV_RDMA_LOG_DEV_DEBUG(
		"ceq_id: %#x, idx: %#x, enable: %u, ceq_itr: %u\n", ceq_id, idx,
		enable, dev->ceq_itr);

	writel(reg_val, dev->hw_regs[PF_INT_CEQCTL] + ceq_id);
}

static const struct sxe2_rdma_irq_ops sxe2_irq_ops = {
	.sxe2_rdma_cfg_aeq = sxe2_hw_cfg_aeq,
	.sxe2_rdma_cfg_ceq = sxe2_hw_cfg_ceq,
	.sxe2_rdma_dis_irq = sxe2_hw_disable_irq,
	.sxe2_rdma_en_irq  = sxe2_hw_ena_irq,
};

static const struct sxe2_rdma_hw_stat_map sxe2_rdma_hw_stats_map[] = {
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXOCTS] = { 0, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXPKTS] = { 8, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCOCTS] = { 16, 0,
						  SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCPKTS] = { 24, 0,
						  SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXOCTS] = { 32, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXPKTS] = { 40, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCOCTS] = { 48, 0,
						  SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCPKTS] = { 56, 0,
						  SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXWRS] = { 64, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXRDS] = { 72, 0, SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXSNDS] = { 80, 0,
						 SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXBND] = { 88, 0, SXE2_RDMA_MAX_STATS_32 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXINV] = { 88, 32,
						SXE2_RDMA_MAX_STATS_32 },
	[SXE2_RDMA_HW_STAT_INDEX_TXCNPSENT] = { 96, 0, SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS]	  = { 128, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXPKTS]	  = { 136, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXDISCARD]	  = { 144, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCOCTS]	  = { 152, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCPKTS]	  = { 160, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXOCTS]	  = { 168, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXPKTS]	  = { 176, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXDISCARD]	  = { 184, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCOCTS]	  = { 192, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCPKTS]	  = { 200, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXWRS]	  = { 208, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXRDS]	  = { 216, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXSNDS]	  = { 224, 0,
						      SXE2_RDMA_MAX_STATS_48 },
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXINV]	  = { 232, 0,
						      SXE2_RDMA_MAX_STATS_32 },
	[SXE2_RDMA_HW_STAT_INDEX_RXECNMARKEDPKTS] = { 232, 32,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPHANDLED]	  = { 240, 0,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPIGNORED]	  = { 240, 32,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXNAKPKTS]	  = { 248, 0,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXSEQERR]	  = { 248, 32,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXRNRNAKPKTS]	  = { 256, 0,
						      SXE2_RDMA_MAX_STATS_24 },
	[SXE2_RDMA_HW_STAT_INDEX_RXRETRANS]	  = { 256, 32,
						      SXE2_RDMA_MAX_STATS_24 },
};

void sxe2_rdma_init_hw(struct sxe2_rdma_ctx_dev *dev)
{
	int i;
	u8 __iomem *hw_addr;

	hw_addr = dev->hw->hw_addr;

	if (dev->privileged) {
		dev->hw_attrs.max_hw_vf_fpm_id	 = SXE2_MAX_VF_FPM_ID;
		dev->hw_attrs.first_hw_vf_fpm_id = SXE2_FIRST_VF_FPM_ID;
		for (i = 0; i < SXE2_PF_MAX_BAR_REGS; i++)
			dev->hw_regs[i] =
				(u32 __iomem *)(hw_addr +
						sxe2_pf_bar_regs_offset[i]);

	} else {
		for (i = 0; i < SXE2_VF_MAX_BAR_REGS; i++)
			dev->hw_regs[i] =
				(u32 __iomem *)(hw_addr +
						sxe2_vf_bar_regs_offset[i]);
	}

	dev->irq_ops = &sxe2_irq_ops;

	dev->hw_stats_map	   = sxe2_rdma_hw_stats_map;
	dev->hw_attrs.max_stat_idx = SXE2_RDMA_HW_STAT_INDEX_MAX;
	dev->hw_attrs.max_rra	   = SXE2_MAX_RRA_SIZE;
	dev->hw_attrs.max_sra	   = SXE2_MAX_SRA_SIZE;

	dev->hw_attrs.page_size_cap		= SZ_4K | SZ_2M | SZ_1G;
	dev->hw_attrs.max_hw_device_pages	= SXE2_MAX_PUSH_PAGE_COUNT;
	dev->hw_attrs.uk_attrs.max_hw_wq_frags	= SXE2_MAX_WQ_FRAGMENT_COUNT;
	dev->hw_attrs.uk_attrs.max_hw_read_sges = SXE2_MAX_SGE_RD;
	dev->hw_attrs.uk_attrs.min_hw_wq_size	= SXE2_MIN_WQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_sq_chunk	= SXE2_MAX_QUANTA_PER_WR;
}
