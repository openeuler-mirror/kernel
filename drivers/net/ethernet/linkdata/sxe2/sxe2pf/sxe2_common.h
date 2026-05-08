/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_common.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_COMMON_H__
#define __SXE2_COMMON_H__

#include "sxe2.h"
#include "sxe2_spec.h"

#ifndef SXE2_VSI_DFLT_IRQS_MAX_CNT
#define SXE2_VSI_DFLT_IRQS_MAX_CNT 64
#endif
#define SXE2_VSI_DFLT_IRQS_MIN_CNT 8

#define SXE2_ADAPTER_TO_DEV(adapter)                                           \
	(&((adapter)->pdev->dev))

#define SXE2_SAFE_MODE_TXQ_CNT (1)
#define SXE2_SAFE_MODE_RXQ_CNT (1)
#define SXE2_SAFE_MODE_IRQ_CNT (2)
#define SXE2_SAFE_MODE_VSI_CNT (1)
#define SXE2_CTRLQ_CNT         (1)
#define SXE2_LBQ_CNT           (1)
#define SXE2_NON_SAFEMODE_MIN_TXQ_CNT                                          \
		(SXE2_SAFE_MODE_TXQ_CNT + SXE2_CTRLQ_CNT + SXE2_LBQ_CNT)

s32 sxe2_caps_get(struct sxe2_adapter *adapter);

u32 sxe2_local_cpus_cnt_get(struct device *device);

u32 sxe2_standardize_cpu_cnt(u32 cpu_cnt);

bool sxe2_is_safe_mode(struct sxe2_adapter *adapter);

void sxe2_safe_mode_caps_set(struct sxe2_adapter *adapter);

bool sxe2_is_vf_vlan_enabled(struct sxe2_vsi *vsi);

static inline void sxe2_itr_set(struct sxe2_irq_data *irq_data,
				struct sxe2_q_container *qc, u16 itr)
{
	struct sxe2_hw *hw = &irq_data->vsi->adapter->hw;

	sxe2_hw_irq_itr_set(hw, irq_data->idx_in_pf, qc->itr_idx, itr);
}

s32 sxe2_hw_mtu_init(struct sxe2_adapter *adapter, u32 init_mtu, u8 is_set_hw);

s32 sxe2_err_code_trans_hw(s32 err);

s32 sxe2_fwc_pxe_disable(struct sxe2_adapter *adapter);

s32 sxe2_fwc_func_caps_get(struct sxe2_adapter *adapter);

void sxe2_queue_work(struct sxe2_adapter *adapter, struct workqueue_struct *wq,
		     struct work_struct *dwork);

u16 sxe2_min_msix_num_calc(struct sxe2_adapter *adapter);

u16 sxe2_min_queue_num_calc(struct sxe2_adapter *adapter);

s32 sxe2_dpdk_pf_caps_get(struct sxe2_adapter *adapter, struct sxe2_fwc_func_caps *caps);

s32 sxe2_drv_mode_set(struct sxe2_adapter *adapter, enum sxe2_com_module type);

s32 __sxe2_drv_mode_get(struct sxe2_adapter *adapter,
			struct sxe2_fwc_drv_mode_resp *resp, u32 resp_len);

s32 sxe2_drv_mode_get(struct sxe2_adapter *adapter);

#endif
