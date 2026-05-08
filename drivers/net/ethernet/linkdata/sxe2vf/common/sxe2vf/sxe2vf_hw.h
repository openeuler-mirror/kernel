/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_hw.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
#include <rte_version.h>
#if (RTE_VERSION_NUM(22, 0, 0, 0) <= RTE_VERSION)
#include <bus_pci_driver.h>
#else
#include <rte_bus_pci.h>
#endif
#include "sxe2_osal.h"
#include "sxe2_type.h"
#include "sxe2_common.h"
#else
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/bitfield.h>
#include "sxe2_mbx_public.h"
#endif

#ifndef __SXE2VF_HW_H__
#define __SXE2VF_HW_H__

#define SXE2VF_REG_INVAL_VALUE 0xFFFFFFFF

enum sxe2vf_hw_err_code {
	SXE2VF_HW_ERR_SUCCESS = 0,
	SXE2VF_HW_ERR_FAULT,
	SXE2VF_HW_ERR_TIMEDOUT,
	SXE2VF_HW_ERR_IO,
};

#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
struct sxe2vf_hw;
typedef struct rte_pci_device *(*sxe2vf_get_pci_device)(struct sxe2vf_hw *hw);
#endif

struct sxe2vf_hw {
	u8 __iomem *reg_base_addr;

	u32 (*reg_read)(void __iomem *reg);
	void (*reg_write)(u32 value, void __iomem *reg);
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2_fw_ver_msg fw_ver;
	struct sxe2vf_adapter *adapter;
#endif
#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
	struct rte_pci_device *pci_device;
#endif
};

#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
#define __SXE2_INTERNAL __rte_internal
#else
#define __SXE2_INTERNAL
#endif

u32 sxe2vf_reg_read(struct sxe2vf_hw *hw, u32 reg);

void sxe2vf_reg_write(struct sxe2vf_hw *hw, u32 reg, u32 value);
__SXE2_INTERNAL s32 sxe2vf_hw_mbx_txq_enable(struct sxe2vf_hw *hw, u16 depth, dma_addr_t addr);

__SXE2_INTERNAL void sxe2vf_hw_mbx_txq_disable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL s32 sxe2vf_hw_mbx_rxq_enable(struct sxe2vf_hw *hw, u16 depth, dma_addr_t addr);

__SXE2_INTERNAL void sxe2vf_hw_mbx_rxq_disable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL u32 sxe2vf_hw_mbx_txq_h_read(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_mbx_txq_t_write(struct sxe2vf_hw *hw, u32 tail);

__SXE2_INTERNAL void sxe2vf_hw_mbx_txq_fault_clear(struct sxe2vf_hw *hw, u32 *err);

__SXE2_INTERNAL u32 sxe2vf_hw_mbx_rxq_h_read(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_mbx_rxq_t_write(struct sxe2vf_hw *hw, u32 tail);

__SXE2_INTERNAL void sxe2vf_hw_irq_enable(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL void sxe2vf_hw_irq_dyn_ctl(struct sxe2vf_hw *hw, u16 irq_idx, u32 value);

__SXE2_INTERNAL void sxe2vf_hw_event_irq_enable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_event_irq_disable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_irq_disable(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL bool sxe2vf_hw_mbx_txq_is_enable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL bool sxe2vf_hw_mbx_rxq_is_enable(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_int_itr_set(struct sxe2vf_hw *hw, u16 itr_idx, u16 irq_idx, u32 itr);

__SXE2_INTERNAL bool sxe2vf_hw_corer_check(struct sxe2vf_hw *hw);

__SXE2_INTERNAL bool sxe2vf_hw_corer_done(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_corer_stop_drop(struct sxe2vf_hw *hw);

__SXE2_INTERNAL s32 sxe2vf_hw_corer_stop_drop_done(struct sxe2vf_hw *hw);

__SXE2_INTERNAL bool sxe2vf_hw_vfr_is_checked(struct sxe2vf_hw *hw);

__SXE2_INTERNAL bool sxe2vf_hw_vfr_is_complete(struct sxe2vf_hw *hw);

__SXE2_INTERNAL bool sxe2vf_hw_vf_is_active(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_irq_trigger(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL void sxe2vf_hw_vfr_clear(struct sxe2vf_hw *hw);

__SXE2_INTERNAL void sxe2vf_hw_mbx_regs_dump(struct sxe2vf_hw *hw);

__SXE2_INTERNAL u32 sxe2vf_hw_rxq_tail_read(struct sxe2vf_hw *hw, u16 queue_id);

__SXE2_INTERNAL void sxe2vf_hw_rxq_tail_write(struct sxe2vf_hw *hw, u16 queue_id, u32 value);

__SXE2_INTERNAL u32 sxe2vf_hw_txq_tail_read(struct sxe2vf_hw *hw, u16 queue_id);

__SXE2_INTERNAL void sxe2vf_hw_txq_tail_write(struct sxe2vf_hw *hw, u16 queue_id, u32 value);

__SXE2_INTERNAL void __iomem *sxe2vf_reg_addr_get(struct sxe2vf_hw *hw, u64 reg);

__SXE2_INTERNAL void sxe2vf_hw_msix_disable(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL void sxe2vf_hw_msix_enable(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL void sxe2vf_hw_irq_clear_pba(struct sxe2vf_hw *hw, u16 irq_idx);

__SXE2_INTERNAL u32 sxe2vf_hw_irq_dyn_ctl_read(struct sxe2vf_hw *hw, u16 irq_idx);
#endif
