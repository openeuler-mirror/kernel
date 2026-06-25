// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_irq.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/numa.h>

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2_monitor.h"
#include "sxe2_rx.h"
#include "sxe2_tx.h"
#include "sxe2_xsk.h"
#include "sxe2_irq.h"

#define SXE2_MSIX_SCHEME_CNT 9
#define SXE2_DIM_DFLT_PROFILE_IDX 1

#define SXE2_MSIX_SCHEME_SAFE_MOD_INDEX 0
#define SXE2_MSIX_SCHEME_NORMAL_MOD_INDEX 1

#define SXE2_MSIX_CNT_WITH_2_PORT 1024
#define SXE2_ADQ_MAX_MSIXS 256

#define SXE2_DYNAMIC_STATE_ITR 4

static inline bool sxe2_judge_over_size(struct sxe2_adapter *adapter, u32 scheme_cnt)
{
	if (scheme_cnt >= SXE2_MSIX_SCHEME_CNT) {
		LOG_INFO_BDF("msix scheme count(%d) init over max size(%d)\n",
			     scheme_cnt, SXE2_MSIX_SCHEME_CNT);
		return true;
	}
	return false;
}

static const u16 tx_itr_profile[] = {
		2,
		8,
		40,
		128,
		256
};

static const u16 rx_itr_profile[] = {
		2,
		8,
		16,
		32,
		64
};

irqreturn_t sxe2_msix_ring_irq_handler(int __always_unused irq, void *data)
{
	struct sxe2_irq_data *irq_data = (struct sxe2_irq_data *)data;

	if (!SXE2_IRQ_HAS_TXQ(irq_data) && !SXE2_IRQ_HAS_RXQ(irq_data))
		goto l_end;

	irq_data->event_ctr++;

	napi_schedule(&irq_data->napi);
l_end:
	return IRQ_HANDLED;
}

irqreturn_t sxe2_msix_lb_rx_irq_handler(int __always_unused irq, void *data)
{
	return IRQ_HANDLED;
}

irqreturn_t sxe2_msix_ctrl_vsi_handler(int __always_unused irq, void *data)
{
	struct sxe2_irq_data *irq_data = (struct sxe2_irq_data *)data;

#define FNAV_RX_DESC_CLEAN_BUDGET 64
	if (SXE2_IRQ_HAS_RXQ(irq_data))
		(void)sxe2_rxq_irq_clean(irq_data->rx.list.next,
					 FNAV_RX_DESC_CLEAN_BUDGET);

	if (SXE2_IRQ_HAS_TXQ(irq_data))
		sxe2_ctrl_txq_irq_clean(irq_data->tx.list.next);

	return IRQ_HANDLED;
}

STATIC s32 sxe2_msix_entries_alloc(struct sxe2_adapter *adapter, u16 msix_cnt)
{
	s32 ret = 0;
	u16 i;

	adapter->irq_ctxt.msix_entries =
			devm_kcalloc(&adapter->pdev->dev, msix_cnt,
				     sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->irq_ctxt.msix_entries) {
		ret = -ENOMEM;
		LOG_DEV_ERR("msi-x irq entry num:%u per size:%lu kcalloc failed, ret=%d\n",
			    msix_cnt, sizeof(struct msix_entry), ret);
		goto l_end;
	}

	for (i = 0; i < msix_cnt; i++)
		adapter->irq_ctxt.msix_entries[i].entry = i;

l_end:
	return ret;
}

static void sxe2_msix_entries_free(struct sxe2_adapter *adapter)
{
	if (!adapter->irq_ctxt.msix_entries)
		return;
	devm_kfree(&adapter->pdev->dev, adapter->irq_ctxt.msix_entries);
	adapter->irq_ctxt.msix_entries = NULL;
}

STATIC s32 sxe2_msix_enable(struct sxe2_adapter *adapter, u16 min_msix, u16 msix_cnt)
{
	s32 ret;

	ret = sxe2_msix_entries_alloc(adapter, msix_cnt);
	if (ret)
		goto l_end;

	ret = pci_enable_msix_range(adapter->pdev, adapter->irq_ctxt.msix_entries,
				    min_msix, msix_cnt);
	if (ret < 0) {
		LOG_ERROR_BDF("enable msix range[%d-%d] failed, ret=%d\n", min_msix,
			      msix_cnt, ret);
		goto l_ena_failed;
	}
	return ret;

l_ena_failed:
	sxe2_msix_entries_free(adapter);
l_end:
	return ret;
}

STATIC void sxe2_msix_deinit(struct sxe2_adapter *adapter)
{
	pci_disable_msix(adapter->pdev);
	sxe2_msix_entries_free(adapter);
}

STATIC void sxe2_safe_mode_irq_num_init(struct sxe2_adapter *adapter)
{
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;

	irq_layout->event = SXE2_EVENT_MSIX_CNT;
	irq_layout->fnav = 0;
	irq_layout->eswitch = 0;
	irq_layout->dpdk_eswitch = 0;
	irq_layout->lan = SXE2_LAN_MSIX_MIN_CNT;
	irq_layout->dpdk = 0;
	irq_layout->rdma = 0;
	irq_layout->macvlan = 0;
	irq_layout->sriov = 0;
}

STATIC void sxe2_safe_mode_irq_layout_init(struct sxe2_adapter *adapter)
{
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u16 max_msix = adapter->irq_ctxt.max_cnt;

	irq_layout->event_offset = SXE2_EVENT_IRQ_IDX;
	irq_layout->fnav_offset = irq_layout->event_offset + irq_layout->event;
	irq_layout->eswitch_offset = irq_layout->fnav_offset + irq_layout->fnav;
	irq_layout->lan_offset = irq_layout->eswitch_offset + irq_layout->eswitch;
	irq_layout->rdma_offset = irq_layout->lan_offset + irq_layout->lan;
	irq_layout->macvlan_offset = irq_layout->rdma_offset + irq_layout->rdma;
	irq_layout->sriov_offset = max_msix;
}

STATIC void sxe2_irq_num_init(struct sxe2_adapter *adapter)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 local_cpu_cnt = sxe2_local_cpus_cnt_get(dev);
	u32 standard_cpu_cnt = sxe2_standardize_cpu_cnt(local_cpu_cnt);
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u32 mode = (u32)sxe2_com_mode_get(adapter);

	irq_layout->event = SXE2_EVENT_MSIX_CNT;
	irq_layout->lb = SXE2_LB_RXQ_MSIX_CNT;
	irq_layout->fnav = SXE2_FNAV_MSIX_CNT;
	irq_layout->eswitch = SXE2_ESWITCH_MSIX_CNT;

	if (mode == SXE2_COM_MODULE_KERNEL) {
		irq_layout->fnav = SXE2_FNAV_MSIX_CNT;
		irq_layout->lan = (u16)max_t(int, standard_cpu_cnt,
					     SXE2_LAN_MSIX_MIN_CNT);
		irq_layout->rdma = (u16)(standard_cpu_cnt > SXE2_RDMA_MSIX_MIN_CNT ?
					 standard_cpu_cnt + SXE2_RDMA_AEQ_MSIX_CNT :
					 SXE2_RDMA_MSIX_MIN_CNT);
	} else if (mode == SXE2_COM_MODULE_DPDK) {
		irq_layout->dpdk = SXE2_DPDK_MSIX_MAX_CNT;
		irq_layout->dpdk_eswitch = SXE2_DPDK_ESWITCH_MSIX_CNT;
	} else {
		irq_layout->fnav = SXE2_FNAV_MSIX_CNT;
		irq_layout->lan = (u16)max_t(int, standard_cpu_cnt,
					     SXE2_LAN_MSIX_MIN_CNT);
		irq_layout->rdma = (u16)(standard_cpu_cnt > SXE2_RDMA_MSIX_MIN_CNT ?
					 standard_cpu_cnt + SXE2_RDMA_AEQ_MSIX_CNT :
					 SXE2_RDMA_MSIX_MIN_CNT);
		irq_layout->dpdk = SXE2_DPDK_MSIX_DFLT_CNT;
		irq_layout->dpdk_eswitch = SXE2_DPDK_ESWITCH_MSIX_CNT;
	}

	irq_layout->macvlan = 0;
	irq_layout->sriov = 0;
}

STATIC void sxe2_irq_layout_init(struct sxe2_adapter *adapter)
{
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u16 max_msix = adapter->irq_ctxt.max_cnt;

	irq_layout->event_offset = SXE2_EVENT_IRQ_IDX;
	irq_layout->lb_offset = irq_layout->event_offset + irq_layout->event;
	irq_layout->fnav_offset = irq_layout->lb_offset + irq_layout->lb;
	irq_layout->eswitch_offset = irq_layout->fnav_offset + irq_layout->fnav;

	irq_layout->lan_offset = irq_layout->eswitch_offset + irq_layout->eswitch;
	irq_layout->rdma_offset = irq_layout->lan_offset + irq_layout->lan;
	irq_layout->dpdk_offset = irq_layout->rdma_offset + irq_layout->rdma;
	irq_layout->dpdk_eswitch_offset = irq_layout->dpdk_offset + irq_layout->dpdk;

	irq_layout->macvlan_offset =
			irq_layout->dpdk_eswitch_offset + irq_layout->dpdk_eswitch;
	irq_layout->sriov_offset = max_msix;
}

STATIC void sxe2_msix_irq_num_init(struct sxe2_adapter *adapter)
{
	if (sxe2_is_safe_mode(adapter))
		sxe2_safe_mode_irq_num_init(adapter);
	else
		sxe2_irq_num_init(adapter);
}

STATIC void sxe2_msix_irq_layout_init(struct sxe2_adapter *adapter)
{
	if (sxe2_is_safe_mode(adapter))
		sxe2_safe_mode_irq_layout_init(adapter);
	else
		sxe2_irq_layout_init(adapter);
}

STATIC u16 sxe2_msix_num_calc(struct sxe2_adapter *adapter)
{
	u16 irq_cnt = 0;
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;

	irq_cnt += irq_layout->lan + irq_layout->event + irq_layout->rdma +
		   irq_layout->eswitch + irq_layout->fnav + irq_layout->lb +
		   irq_layout->dpdk + irq_layout->dpdk_eswitch;

	return irq_cnt;
}

STATIC void sxe2_msix_adjust(struct sxe2_adapter *adapter, u16 max_msix)
{
	u16 left_cnt;
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u32 mode = (u32)sxe2_com_mode_get(adapter);

	s32 expected_cnt = sxe2_msix_num_calc(adapter);

	if (sxe2_is_safe_mode(adapter))
		goto l_end;

	left_cnt = (u16)(max_msix - SXE2_EVENT_MSIX_CNT);
	if (expected_cnt > max_msix) {
		if (mode == SXE2_COM_MODULE_KERNEL) {
			left_cnt = (u16)(left_cnt - SXE2_FNAV_MSIX_CNT -
					 SXE2_ESWITCH_MSIX_CNT);

			irq_layout->lan = left_cnt / 2;
			irq_layout->rdma = (u16)(left_cnt - irq_layout->lan);
		} else if (mode == SXE2_COM_MODULE_DPDK) {
			irq_layout->dpdk =
					(u16)(left_cnt - (u16)SXE2_ESWITCH_MSIX_CNT -
					      (u16)SXE2_DPDK_ESWITCH_MSIX_CNT);
		} else {
			left_cnt = (u16)(left_cnt - SXE2_FNAV_MSIX_CNT -
					 SXE2_DPDK_MSIX_MIN_CNT -
					 SXE2_DPDK_ESWITCH_MSIX_CNT -
					 SXE2_ESWITCH_MSIX_CNT);
			irq_layout->lan = left_cnt / 2;
			irq_layout->rdma = (u16)(left_cnt - irq_layout->lan);
			irq_layout->dpdk = SXE2_DPDK_MSIX_MIN_CNT;
		}
	}

l_end:
	return;
}

STATIC s32 sxe2_msix_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	s32 expected_cnt;
	s32 applied_cnt = 0;
	u16 min_msix;
	u16 max_msix = adapter->irq_ctxt.max_cnt;

	sxe2_msix_irq_num_init(adapter);

	min_msix = sxe2_min_msix_num_calc(adapter);

	expected_cnt = sxe2_msix_num_calc(adapter) + SXE2_MAX_NUM_VMDQ_VSI;

	applied_cnt = min_t(s32, expected_cnt, (s32)max_msix);

	applied_cnt = sxe2_msix_enable(adapter, min_msix, (u16)applied_cnt);
	if (applied_cnt < 0) {
		ret = applied_cnt;
		goto l_end;
	}

	if (applied_cnt < (expected_cnt - SXE2_MAX_NUM_VMDQ_VSI)) {
		clear_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags);
		adapter->irq_ctxt.fixed_cnt = (u16)applied_cnt;
		sxe2_msix_adjust(adapter, (u16)applied_cnt);
	} else {
		adapter->irq_ctxt.fixed_cnt = sxe2_msix_num_calc(adapter);
	}

	adapter->irq_ctxt.avail_cnt = (u16)expected_cnt;

	sxe2_msix_irq_layout_init(adapter);

l_end:
	return ret;
}

s32 sxe2_irq_init(struct sxe2_adapter *adapter)
{
	s32 ret;

	ret = sxe2_msix_init(adapter);
	if (ret)
		goto l_end;

	ret = sxe2_event_irq_request(adapter);
	if (ret)
		goto l_failed;

	return ret;

l_failed:
	sxe2_msix_deinit(adapter);
l_end:
	return ret;
}

STATIC s32 sxe2_msix_resume(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	s32 applied_cnt = 0;
	u16 min_msix;

	min_msix = sxe2_min_msix_num_calc(adapter);

	applied_cnt = sxe2_msix_enable(adapter, min_msix,
				       adapter->irq_ctxt.avail_cnt);
	if (applied_cnt <
	    adapter->irq_ctxt.avail_cnt) {
		ret = -ENOMEM;
		goto l_end;
	}

l_end:
	return ret;
}

s32 sxe2_irq_resume(struct sxe2_adapter *adapter)
{
	s32 ret;

	ret = sxe2_msix_resume(adapter);
	if (ret != 0)
		goto l_failed;

	ret = sxe2_event_irq_request(adapter);
	if (ret != 0)
		goto l_failed;

	return ret;

l_failed:
	sxe2_msix_deinit(adapter);
	return ret;
}

void sxe2_irq_deinit(struct sxe2_adapter *adapter)
{
	sxe2_event_irq_free(adapter);
	sxe2_msix_deinit(adapter);
}

#define EVENT_INDEX0 (0)
#define EVENT_INDEX1 (1)
#define EVENT_INDEX2 (2)
STATIC void sxe2_event_irq_common_handler(struct sxe2_adapter *adapter, u32 oicr)
{
	u32 fw_event;
	struct sxe2_hw *hw = &adapter->hw;
	s32 gltsyn_stat;

	if (oicr & SXE2_PF_INT_OICR_FW) {
		fw_event = sxe2_hw_fw_irq_cause_get(hw);
		if (fw_event & SXE2_PF_INT_RDMA_AEQ_OVERFLOW) {
			LOG_ERROR_BDF("recv fw rdma aeq overflow irq cause.\n");
			set_bit(SXE2_FLAG_RDMA_AEQ_OVERFLOW, adapter->flags);
			sxe2_monitor_work_schedule(adapter);
		}

		if (fw_event & SXE2_PF_INT_CGMAC_LINK_CHG) {
			LOG_INFO_BDF("lsc irq occur.\n");
			set_bit(SXE2_FLAG_LINK_CHECK, adapter->flags);
			sxe2_monitor_work_schedule(adapter);
		}

		if (fw_event & SXE2_PF_INT_VFLR_DONE) {
			LOG_INFO_BDF("vflr irq occur.\n");
			set_bit(SXE2_FLAG_VFLR_PENDING, adapter->flags);
			sxe2_dev_ctrl_work_schedule(adapter);
		}
	}

	if (oicr & SXE2_PF_INT_OICR_FWQ_INT || oicr & SXE2_PF_INT_OICR_MBXQ_INT)
		sxe2_rq_recv_work_schedule(adapter);

	if (oicr & SXE2_PF_INT_OICR_ECC_ERR)
		adapter->dev_ctrl_ctxt.print_flag |= SXE2_PRINT_ECC_ERROR;

	if ((oicr & SXE2_PF_INT_OICR_INT_CFG_ADDR_ERR) ||
	    (oicr & SXE2_PF_INT_OICR_INT_CFG_DATA_ERR) ||
	    (oicr & SXE2_PF_INT_OICR_INT_CFG_ADR_UNRANGE)) {
		adapter->dev_ctrl_ctxt.print_flag |= SXE2_PRINT_REG_CFG_ERR;
	}

	if (oicr & SXE2_PF_INT_OICR_INT_RAM_CONFLICT)
		adapter->dev_ctrl_ctxt.print_flag |= SXE2_PRINT_RAM_CONFLICT;

	if (oicr & SXE2_PF_INT_OICR_TSYN_TX)
		sxe2_ptp_txts_process(adapter);

	if (oicr & SXE2_PF_INT_OICR_TSYN_EVENT) {
		gltsyn_stat = sxe2_hw_ptp_stat_get(&adapter->hw);
		if (gltsyn_stat & GLTSYN_STAT_EVENT0_M)
			set_bit(EVENT_INDEX0, adapter->ptp_ctxt.extts.irq);

		if (gltsyn_stat & GLTSYN_STAT_EVENT1_M)
			set_bit(EVENT_INDEX1, adapter->ptp_ctxt.extts.irq);

		if (gltsyn_stat & GLTSYN_STAT_EVENT2_M)
			set_bit(EVENT_INDEX2, adapter->ptp_ctxt.extts.irq);

		sxe2_ptp_extts_intr(adapter);
	}

	if (oicr & SXE2_PF_INT_OICR_LAN_TX_ERR)
		set_bit(SXE2_FLAG_MDD_TX_PENDING, adapter->flags);

	if (oicr & SXE2_PF_INT_OICR_LAN_RX_ERR)
		set_bit(SXE2_FLAG_MDD_RX_PENDING, adapter->flags);

	if (oicr & SXE2_PF_INT_OICR_LAN_TX_ERR || oicr & SXE2_PF_INT_OICR_LAN_RX_ERR)
		sxe2_monitor_work_schedule(adapter);
}

STATIC irqreturn_t sxe2_msix_event_irq_handler(int irq, void *data)
{
	struct sxe2_adapter *adapter = data;
	struct sxe2_hw *hw = &adapter->hw;
	u32 oicr, ena_mask;
#ifndef SXE2_HARDWARE_SIM

	if (unlikely(sxe2_corer_check(adapter))) {
		sxe2_dev_ctrl_work_schedule(adapter);
		goto l_end;
	}
#endif
	oicr = sxe2_hw_evt_irq_cause_get(hw);
	ena_mask = sxe2_hw_evt_irq_mask_get(hw);

	ena_mask |= SXE2_PF_INT_OICR_FWQ_INT | SXE2_PF_INT_OICR_MBXQ_INT;

	ena_mask |= SXE2_PF_INT_OICR_INT_CFG_ADDR_ERR |
		    SXE2_PF_INT_OICR_INT_CFG_DATA_ERR |
		    SXE2_PF_INT_OICR_INT_CFG_ADR_UNRANGE | SXE2_PF_INT_OICR_ECC_ERR |
		    SXE2_PF_INT_OICR_INT_RAM_CONFLICT;

	LOG_DEBUG_BDF("event irq oicr:0x%x, ena_mask: 0x%x.\n", oicr, ena_mask);
	oicr &= ena_mask;
	adapter->irq_ctxt.event_irq_cnt++;

	sxe2_event_irq_common_handler(adapter, oicr);
#ifndef SXE2_HARDWARE_SIM
l_end:
#endif
	sxe2_hw_irq_enable(hw, SXE2_EVENT_IRQ_IDX);
	return IRQ_HANDLED;
}

void sxe2_event_irq_enable(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;
	u32 value = 0;
	u16 itr_idx = SXE2_ITR_IDX_0;

	value = SXE2_PF_INT_OICR_VFLR | SXE2_PF_INT_OICR_SWINT |
		SXE2_PF_INT_OICR_FW | SXE2_PF_INT_OICR_LAN_TX_ERR |
		SXE2_PF_INT_OICR_LAN_RX_ERR | SXE2_PF_INT_OICR_GRST;

	sxe2_hw_evt_irq_cfg(hw, value, itr_idx, SXE2_EVENT_IRQ_IDX);
	sxe2_hw_fwq_irq_cfg(hw, itr_idx, SXE2_EVENT_IRQ_IDX);
	sxe2_hw_mbxq_irq_cfg(hw, itr_idx, SXE2_EVENT_IRQ_IDX);
	(void)sxe2_flush(hw);

	sxe2_hw_irq_itr_set(hw, SXE2_EVENT_IRQ_IDX, itr_idx, SXE2_ITR_20K);
	(void)sxe2_flush(hw);

	sxe2_hw_irq_enable(hw, SXE2_EVENT_IRQ_IDX);

	adapter->cmd_channel_ctxt.mode = SXE2_CMD_NOTIFY;
}

void sxe2_event_irq_disable(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;
	struct msix_entry *msix_entries = NULL;

	adapter->cmd_channel_ctxt.mode = SXE2_CMD_POLLING;

	msix_entries = adapter->irq_ctxt.msix_entries;
	sxe2_hw_fwq_irq_clear(hw);
	sxe2_hw_mbxq_irq_clear(hw);

	sxe2_hw_evt_irq_clear(hw);

	if (msix_entries)
		synchronize_irq(msix_entries[SXE2_EVENT_IRQ_IDX].vector);

	sxe2_hw_irq_disable(hw, SXE2_EVENT_IRQ_IDX);
	sxe2_hw_irq_itr_set(hw, SXE2_EVENT_IRQ_IDX, SXE2_ITR_IDX_0, 0);

	(void)sxe2_flush(hw);
}

s32 sxe2_event_irq_request(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct msix_entry *msix_entries = adapter->irq_ctxt.msix_entries;

	(void)snprintf(adapter->irq_ctxt.event_int_name,
		       sizeof(adapter->irq_ctxt.event_int_name) - 1, "%s-%s:event",
		       dev_driver_string(dev), dev_name(dev));
	ret = devm_request_irq(dev, msix_entries[SXE2_EVENT_IRQ_IDX].vector,
			       sxe2_msix_event_irq_handler, 0,
			       adapter->irq_ctxt.event_int_name, adapter);
	if (ret) {
		LOG_DEV_ERR("devm_request_irq for %s failed, ret=%d\n",
			    adapter->irq_ctxt.event_int_name, ret);
		goto l_end;
	}

	sxe2_event_irq_enable(adapter);

l_end:
	return ret;
}

void sxe2_event_irq_free(struct sxe2_adapter *adapter)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	struct msix_entry *msix_entries = adapter->irq_ctxt.msix_entries;

	sxe2_event_irq_disable(adapter);

	if (msix_entries)
		devm_free_irq(dev, msix_entries[SXE2_EVENT_IRQ_IDX].vector, adapter);

	memset(adapter->irq_ctxt.event_int_name, 0,
	       sizeof(adapter->irq_ctxt.event_int_name));
}

s32 sxe2_irq_offset_get(struct sxe2_adapter *adapter, u16 cnt, u8 vsi_type)
{
	s32 ret = 0;
	s32 offset;
	unsigned long *map = adapter->irq_ctxt.map;
	u16 size = adapter->irq_ctxt.avail_cnt;
	struct sxe2_irq_layout *irq_layout = &adapter->irq_ctxt.irq_layout;
	u16 start_idx = irq_layout->macvlan_offset;

	if (cnt > size) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("get %d irq from %u failed, ret=%d\n", cnt, size, ret);
		goto l_end;
	}

	switch (vsi_type) {
	case SXE2_VSI_T_PF:
		offset = irq_layout->lan_offset;
		break;
	case SXE2_VSI_T_LB:
		offset = irq_layout->lb_offset;
		break;
	case SXE2_VSI_T_CTRL:
		offset = irq_layout->fnav_offset;
		break;
	case SXE2_VSI_T_RDMA:
		offset = irq_layout->rdma_offset;
		break;
	case SXE2_VSI_T_ESW:
		offset = irq_layout->eswitch_offset;
		break;
	case SXE2_VSI_T_DPDK_PF:
		offset = irq_layout->dpdk_offset;
		break;
	case SXE2_VSI_T_DPDK_ESW:
		offset = irq_layout->dpdk_eswitch_offset;
		break;
	case SXE2_VSI_T_MACVLAN:
		mutex_lock(&adapter->irq_ctxt.lock);
		offset = (s32)bitmap_find_next_zero_area(map,
				(s32)size, (s32)start_idx, (s32)cnt, 0);
		if (offset >= (s32)size) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("get %d irqs from map(size %u) failed, ret=%d\n",
				      cnt, size, ret);
			mutex_unlock(&adapter->irq_ctxt.lock);
			goto l_end;
		}
		bitmap_set(map, (unsigned int)offset, (unsigned int)cnt);
		irq_layout->macvlan++;
		mutex_unlock(&adapter->irq_ctxt.lock);
		break;
	default:
		offset = -1;
		break;
	}

	if (offset >= (s32)size) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("get %d irqs from map(size %u) failed, ret=%d\n", cnt,
			      size, ret);
		goto l_end;
	}
	ret = offset;

l_end:
	return ret;
}

void sxe2_irq_rate_limit_init(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;
	u16 rate_limit;

	if ((SXE2_IS_ITR_DYNAMIC(&irq_data->tx) ||
	     SXE2_IS_ITR_DYNAMIC(&irq_data->rx)) &&
	    irq_data->vsi != irq_data->vsi->adapter->eswitch_ctxt.esw_vsi) {
		rate_limit = SXE2_DYNAMIC_STATE_ITR;
	} else {
		rate_limit = irq_data->rate_limit;
	}

	sxe2_hw_irq_rate_limit_set(hw, irq_data->idx_in_pf, rate_limit);
}

static void sxe2_dim_work_tx(struct work_struct *work)
{
	struct sxe2_irq_data *irq_data;
	struct sxe2_q_container *qc;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	irq_data = (struct sxe2_irq_data *)dim->priv;
	qc = &irq_data->tx;

	WARN_ON(dim->profile_ix >= ARRAY_SIZE(tx_itr_profile));
	SXE2_BUG_ON(dim->profile_ix >= ARRAY_SIZE(tx_itr_profile));

	itr = tx_itr_profile[dim->profile_ix];

	sxe2_itr_set(irq_data, qc, itr);

	dim->state = DIM_START_MEASURE;
}

static void sxe2_dim_work_rx(struct work_struct *work)
{
	struct sxe2_irq_data *irq_data;
	struct sxe2_q_container *qc;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	irq_data = (struct sxe2_irq_data *)dim->priv;
	qc = &irq_data->rx;

	WARN_ON(dim->profile_ix >= ARRAY_SIZE(rx_itr_profile));
	SXE2_BUG_ON(dim->profile_ix >= ARRAY_SIZE(rx_itr_profile));

	itr = rx_itr_profile[dim->profile_ix];

	sxe2_itr_set(irq_data, qc, itr);

	dim->state = DIM_START_MEASURE;
}

void sxe2_dim_init(struct sxe2_irq_data *irq_data)
{
	struct sxe2_q_container *qc;
	u16 itr;

	qc = &irq_data->tx;
	INIT_WORK(&qc->dim.work, sxe2_dim_work_tx);
	qc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qc->dim.profile_ix = SXE2_DIM_DFLT_PROFILE_IDX;
	qc->dim.priv = irq_data;

	itr = (u16)(SXE2_IS_ITR_DYNAMIC(qc) ? tx_itr_profile[qc->dim.profile_ix]
					    : qc->itr_setting);

	sxe2_itr_set(irq_data, qc, itr);

	qc = &irq_data->rx;
	INIT_WORK(&qc->dim.work, sxe2_dim_work_rx);
	qc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	qc->dim.profile_ix = SXE2_DIM_DFLT_PROFILE_IDX;
	qc->dim.priv = irq_data;

	itr = (u16)(SXE2_IS_ITR_DYNAMIC(qc) ? rx_itr_profile[qc->dim.profile_ix]
					    : qc->itr_setting);
	sxe2_itr_set(irq_data, qc, itr);
}

static void sxe2_net_dim(u16 event_ctr, u64 packets, u64 bytes, struct dim *dim)
{
	struct dim_sample dim_sample = {};

	dim_update_sample(event_ctr, packets, bytes, &dim_sample);
	dim_sample.comp_ctr = 0;

	if (ktime_ms_delta(dim_sample.time, dim->start_sample.time) >= 1000)
		dim->state = DIM_START_MEASURE;

	net_dim(dim, dim_sample);
}

void sxe2_dynamic_itr(struct sxe2_irq_data *irq_data)
{
	struct sxe2_q_container *tqc = &irq_data->tx;
	struct sxe2_q_container *rqc = &irq_data->rx;
	struct sxe2_queue *queue;

	if (SXE2_IS_ITR_DYNAMIC(tqc)) {
		u64 packets = 0, bytes = 0;

		sxe2_for_each_queue(queue, irq_data->tx.list)
		{
			packets += queue->stats->packets;
			bytes += queue->stats->bytes;
		}
		sxe2_net_dim(irq_data->event_ctr, packets, bytes, &irq_data->tx.dim);
	}

	if (SXE2_IS_ITR_DYNAMIC(rqc)) {
		u64 packets = 0, bytes = 0;

		sxe2_for_each_queue(queue, irq_data->rx.list)
		{
			packets += queue->stats->packets;
			bytes += queue->stats->bytes;
		}
		sxe2_net_dim(irq_data->event_ctr, packets, bytes, &irq_data->rx.dim);
	}
}

void sxe2_irq_itr_init(struct sxe2_irq_data *irq_data)
{
	sxe2_dim_init(irq_data);
}

void sxe2_trigger_soft_intr(struct sxe2_hw *hw, struct sxe2_irq_data *irq_data)
{
	u32 value;

	irq_data->multiple_polling = false;
	value = SXE2_VF_DYN_CTL_INTENABLE |
		SXE2_VF_DYN_CTL_CLEARPBA |
		(SXE2_ITR_IDX_2 << SXE2_VF_DYN_CTL_ITR_IDX_S) |
		(SXE2_ITR_20K / hw->hw_cfg.itr_gran)
				<< SXE2_VF_DYN_CTL_INTERVAL_S |
		SXE2_VF_DYN_CTL_SWINT_TRIG |
		SXE2_ITR_IDX_2 << SXE2_VF_DYN_CTL_SW_ITR_IDX_S |
		SXE2_VF_DYN_CTL_SW_ITR_IDX_ENABLE;

	sxe2_hw_irq_dyn_ctl(hw, irq_data->idx_in_pf, value);
}

STATIC void sxe2_napi_irq_enable(struct sxe2_irq_data *irq_data)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;

	if (irq_data->multiple_polling)
		sxe2_trigger_soft_intr(hw, irq_data);
	else
		sxe2_hw_irq_enable(hw, irq_data->idx_in_pf);
}

int sxe2_napi_poll(struct napi_struct *napi, int weight)
{
	struct sxe2_irq_data *irq_data =
			container_of(napi, struct sxe2_irq_data, napi);
	struct sxe2_queue *txq;
	struct sxe2_queue *rxq;
	int total_cleaned = 0;
	int budget_per_ring;
	bool complete = true;
	s32 clean;

	sxe2_for_each_queue(txq, irq_data->tx.list)
	{
#ifdef HAVE_AF_XDP_ZC_SUPPORT
		bool wd = txq->xsk_pool ? sxe2_txq_irq_clean_zc(txq, weight)
					: sxe2_txq_irq_clean(txq, weight);
#else
		bool wd = sxe2_txq_irq_clean(txq, weight);
#endif
		if (!wd)
			complete = false;
	}

	if (unlikely(weight <= 0))
		return weight;

	if (unlikely(irq_data->rx.list.cnt > 1))
		budget_per_ring = max_t(int, ((u32)weight / irq_data->rx.list.cnt),
					1);
	else
		budget_per_ring = weight;

	sxe2_trace(irq_rxclean_begin, irq_data, total_cleaned);
	sxe2_for_each_queue(rxq, irq_data->rx.list)
	{
		sxe2_trace(rxq_clean_begin, rxq);
#ifdef HAVE_AF_XDP_ZC_SUPPORT
		clean = rxq->xsk_pool ? sxe2_rx_irq_clean_zc(rxq, budget_per_ring)
				      : sxe2_rxq_irq_clean(rxq, budget_per_ring);
#else
		clean = sxe2_rxq_irq_clean(rxq, budget_per_ring);
#endif
		sxe2_trace(rxq_clean_end, rxq, clean);
		total_cleaned += clean;
		if (clean >= budget_per_ring)
			complete = false;
	}
	sxe2_trace(irq_rxclean_end, irq_data, total_cleaned);

	if (!complete) {
		irq_data->multiple_polling = true;
		return weight;
	}

	if (napi_complete_done(napi, total_cleaned)) {
		sxe2_dynamic_itr(irq_data);
		sxe2_napi_irq_enable(irq_data);
	}

	return min_t(int, total_cleaned, (weight - 1));
}

int sxe2_esw_napi_poll(struct napi_struct *napi, int weight)
{
	struct sxe2_irq_data *irq_data =
			container_of(napi, struct sxe2_irq_data, napi);
	struct sxe2_queue *txq;
	struct sxe2_queue *rxq;
	int total_cleaned = 0;
	bool complete = true;

	sxe2_for_each_queue(txq, irq_data->tx.list)
	{
		bool wd = sxe2_txq_irq_clean(txq, weight);

		if (!wd)
			complete = false;
	}

	if (unlikely(weight <= 0))
		return weight;

	sxe2_for_each_queue(rxq, irq_data->rx.list)
	{
		s32 clean = sxe2_rxq_irq_clean(rxq, weight);

		total_cleaned += clean;
		if (clean >= weight)
			complete = false;
	}

	if (!complete) {
		irq_data->multiple_polling = true;
		return weight;
	}

	if (napi_complete_done(napi, total_cleaned))
		sxe2_napi_irq_enable(irq_data);

	return min_t(int, total_cleaned, (weight - 1));
}

s32 sxe2_dpdk_irq_cnt_get(void *adapter)
{
	struct sxe2_adapter *pf_adapter = adapter;

	return pf_adapter->irq_ctxt.irq_layout.dpdk;
}

s32 sxe2_dpdk_irq_vector_idx_get(void *adapter, u16 irq_idx)
{
	struct sxe2_adapter *pf_adapter = adapter;
	u16 offset = pf_adapter->irq_ctxt.irq_layout.dpdk_offset + irq_idx;

	if (!pf_adapter->irq_ctxt.msix_entries)
		return -EINVAL;

	return (s32)pf_adapter->irq_ctxt.msix_entries[offset].vector;
}
