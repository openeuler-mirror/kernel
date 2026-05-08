// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_hw.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
#include "sxe2vf.h"
#else
#include <rte_io.h>
#endif

#include "sxe2vf_hw.h"
#include "sxe2vf_regs.h"
#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
#else
#include "sxe2_log.h"
#endif

#ifdef SXE2_CFG_DEBUG
extern int vf_reg_log;
#endif

u32 sxe2vf_reg_read(struct sxe2vf_hw *hw, u32 reg)
{
	u32 value;
	u8 __iomem *base_addr = hw->reg_base_addr;
#ifdef SXE2_CFG_DEBUG
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif

#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
	value = rte_read32(base_addr + reg);
#else
	value = hw->reg_read(base_addr + reg);
#endif

#ifdef SXE2_CFG_DEBUG
	if (vf_reg_log)
		LOG_DEBUG_BDF("reg: 0x%x, read value: 0x%x\n", reg, value);
#endif

	return value;
}

void sxe2vf_reg_write(struct sxe2vf_hw *hw, u32 reg, u32 value)
{
	u8 __iomem *base_addr = hw->reg_base_addr;
#ifdef SXE2_CFG_DEBUG
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif
#if defined(SXE2_DPDK_VF_DRIVER) || defined(SXE2_DPDK_DRIVER)
	rte_write32(value, base_addr + reg);
#else
	hw->reg_write(value, base_addr + reg);
#endif

#ifdef SXE2_CFG_DEBUG
	if (vf_reg_log)
		LOG_DEBUG_BDF("reg:0x%x write value:0x%x read value:0x%x.\n", reg,
			      value, hw->reg_read(base_addr + reg));
#endif
}

s32 sxe2vf_hw_mbx_txq_enable(struct sxe2vf_hw *hw, u16 depth, dma_addr_t addr)
{
	s32 ret = 0;
	u32 value;
	u32 old_tail;
	u32 old_head;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif

	old_tail = sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_TAIL);
	old_head = sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_HEAD);
	if (old_tail >= old_head) {
		sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_TAIL, 0);
	} else {
		sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_TAIL, 0);
		sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_TAIL, old_tail);
		sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_TAIL, 0);
	}
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	LOG_INFO_BDF("mbx txq old tail:0x%x old head:0x%x.\n", old_tail, old_head);
#endif
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_HEAD, 0);

	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_BAL, lower_32_bits(addr));
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_BAH, upper_32_bits(addr));

	value = (u32)(FIELD_PREP(SXE2VF_MBX_Q_LEN_M, depth) |
		      SXE2VF_MBX_Q_LEN_ENA_M);
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_LEN, value);

	if (sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_BAL) != lower_32_bits(addr))
		ret = -SXE2VF_HW_ERR_IO;
	return ret;
}

void sxe2vf_hw_mbx_txq_disable(struct sxe2vf_hw *hw)
{
	u32 value;

	value = sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_LEN);
	value &= ~(SXE2VF_MBX_Q_LEN_VFE_M | SXE2VF_MBX_Q_LEN_OVFL_M |
		   SXE2VF_MBX_Q_LEN_CRIT_M | SXE2VF_MBX_Q_LEN_ENA_M);
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_LEN, value);

	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_BAL, 0);
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_BAH, 0);
}

u32 sxe2vf_hw_mbx_txq_h_read(struct sxe2vf_hw *hw)
{
	return sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_HEAD);
}

bool sxe2vf_hw_mbx_txq_is_enable(struct sxe2vf_hw *hw)
{
	return !!(sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_LEN) & SXE2VF_MBX_Q_LEN_ENA_M);
}

bool sxe2vf_hw_mbx_rxq_is_enable(struct sxe2vf_hw *hw)
{
	return !!(sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN) & SXE2VF_MBX_Q_LEN_ENA_M);
}

void sxe2vf_hw_mbx_txq_fault_clear(struct sxe2vf_hw *hw, u32 *err)
{
	u32 value = sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_LEN);

	if (value & SXE2VF_MBX_Q_LEN_VFE_M)
		*err |= SXE2VF_MBX_Q_LEN_VFE_M;
	else if (value & SXE2VF_MBX_Q_LEN_OVFL_M)
		*err |= SXE2VF_MBX_Q_LEN_OVFL_M;
	else if (value & SXE2VF_MBX_Q_LEN_CRIT_M)
		*err |= SXE2VF_MBX_Q_LEN_CRIT_M;
	if (*err) {
		value &= ~(SXE2VF_MBX_Q_LEN_VFE_M | SXE2VF_MBX_Q_LEN_OVFL_M |
			   SXE2VF_MBX_Q_LEN_CRIT_M);
		sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_LEN, value);
	}
}

void sxe2vf_hw_mbx_txq_t_write(struct sxe2vf_hw *hw, u32 tail)
{
	sxe2vf_reg_write(hw, SXE2VF_MBX_TQ_TAIL, tail);
}

u32 sxe2vf_hw_mbx_rxq_h_read(struct sxe2vf_hw *hw)
{
	return sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_HEAD);
}

void sxe2vf_hw_mbx_rxq_t_write(struct sxe2vf_hw *hw, u32 tail)
{
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_TAIL, tail);
}

s32 sxe2vf_hw_mbx_rxq_enable(struct sxe2vf_hw *hw, u16 depth, dma_addr_t addr)
{
	s32 ret = 0;
	u32 value;

	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_HEAD, 0);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_TAIL, 0);

	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_BAL, lower_32_bits(addr));
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_BAH, upper_32_bits(addr));

	value = FIELD_PREP(SXE2VF_MBX_Q_LEN_M, depth) | SXE2VF_MBX_Q_LEN_ENA_M |
		(sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN) & SXE2VF_MBX_Q_LEN_VFE_M);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_LEN, value);

	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_TAIL, (u32)(depth - 1));

	if (sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_BAL) != lower_32_bits(addr))
		ret = -SXE2VF_HW_ERR_IO;

	return ret;
}

void sxe2vf_hw_mbx_rxq_disable(struct sxe2vf_hw *hw)
{
	u32 val;

	val = sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN);
	val &= ~(SXE2VF_MBX_Q_LEN_OVFL_M | SXE2VF_MBX_Q_LEN_CRIT_M |
		 SXE2VF_MBX_Q_LEN_ENA_M);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_LEN, val);

	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_HEAD, 0);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_TAIL, 0);

	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_BAL, 0);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_BAH, 0);
}

void sxe2vf_hw_irq_enable(struct sxe2vf_hw *hw, u16 irq_idx)
{
	u32 value = SXE2VF_DYN_CTL_INTENABLE |
		    (SXE2VF_ITR_IDX_NONE
		     << SXE2VF_DYN_CTL_ITR_IDX_SHIFT);

	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL(irq_idx), value);
}

u32 sxe2vf_hw_irq_dyn_ctl_read(struct sxe2vf_hw *hw, u16 irq_idx)
{
	return sxe2vf_reg_read(hw, SXE2VF_DYN_CTL(irq_idx));
}

void sxe2vf_hw_irq_dyn_ctl(struct sxe2vf_hw *hw, u16 irq_idx, u32 value)
{
	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL(irq_idx), value);
}

void sxe2vf_hw_msix_disable(struct sxe2vf_hw *hw, u16 irq_idx)
{
	sxe2vf_reg_write(hw, SXE2VF_BAR4_MSIX_CTL(irq_idx),
			 SXE2VF_BAR4_MSIX_DISABLE);
}

void sxe2vf_hw_msix_enable(struct sxe2vf_hw *hw, u16 irq_idx)
{
	sxe2vf_reg_write(hw, SXE2VF_BAR4_MSIX_CTL(irq_idx), SXE2VF_BAR4_MSIX_ENABLE);
}

void sxe2vf_hw_irq_clear_pba(struct sxe2vf_hw *hw, u16 irq_idx)
{
	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL(irq_idx),
			 (SXE2VF_ITR_IDX_NONE << SXE2VF_DYN_CTL_ITR_IDX_SHIFT) |
					 SXE2VF_DYN_CTL_CLEARPBA |
					 SXE2VF_DYN_CTL_INTENABLE_MSK);
}

void sxe2vf_hw_irq_trigger(struct sxe2vf_hw *hw, u16 irq_idx)
{
	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL(irq_idx),
			 (SXE2VF_ITR_IDX_NONE << SXE2VF_DYN_CTL_ITR_IDX_SHIFT) |
					 SXE2VF_DYN_CTL_SWINT_TRIG |
					 SXE2VF_DYN_CTL_INTENABLE_MSK);
}

void sxe2vf_hw_int_itr_set(struct sxe2vf_hw *hw, u16 itr_idx, u16 irq_idx, u32 itr)
{
	sxe2vf_reg_write(hw, SXE2VF_INT_ITR(itr_idx, irq_idx), itr);
}

void sxe2vf_hw_event_irq_enable(struct sxe2vf_hw *hw)
{
	u32 value = SXE2VF_DYN_CTL_INTENABLE |
		    (SXE2VF_ITR_IDX_NONE
		     << SXE2VF_DYN_CTL_ITR_IDX_SHIFT);

	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL0, value);
}

void sxe2vf_hw_event_irq_disable(struct sxe2vf_hw *hw)
{
	u32 value = (SXE2VF_ITR_IDX_NONE
		     << SXE2VF_DYN_CTL_ITR_IDX_SHIFT);

	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL0, value);
}

void sxe2vf_hw_irq_disable(struct sxe2vf_hw *hw, u16 irq_idx)
{
	u32 value = (SXE2VF_ITR_IDX_NONE << SXE2VF_DYN_CTL_ITR_IDX_SHIFT);

	sxe2vf_reg_write(hw, SXE2VF_DYN_CTL(irq_idx), value);
}

bool sxe2vf_hw_corer_check(struct sxe2vf_hw *hw)
{
	u32 val = 0;
	bool ret = 0;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)hw->adapter;
	(void)pci_read_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY, &val);
#else
	(void)rte_pci_read_config(hw->pci_device, &val, sizeof(val),
				  SXE2VF_PCIE_SYS_READY);
#endif
	if (val == SXE2VF_REG_INVAL_VALUE)
		return 0;
	ret = !(val & SXE2VF_PCIE_SYS_READY_STOP_DROP_DONE);
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	if (ret)
		LOG_INFO_BDF("core reset detected.\n");
#endif

	return ret;
}

bool sxe2vf_hw_corer_done(struct sxe2vf_hw *hw)
{
	u32 val;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)hw->adapter;

	(void)pci_read_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY, &val);
	if (val == SXE2VF_REG_INVAL_VALUE)
		return 0;

#else
	(void)rte_pci_read_config(hw->pci_device, &val, sizeof(val),
				  SXE2VF_PCIE_SYS_READY);
#endif

	return val & SXE2VF_PCIE_SYS_READY_R5;
}

void sxe2vf_hw_corer_stop_drop(struct sxe2vf_hw *hw)
{
	u32 val;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)hw->adapter;
	(void)pci_read_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY, &val);
	(void)pci_write_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY,
				     (val | SXE2VF_PCIE_SYS_READY_STOP_DROP));
#else
	(void)rte_pci_read_config(hw->pci_device, &val, sizeof(val),
				  SXE2VF_PCIE_SYS_READY);
	val = val | SXE2VF_PCIE_SYS_READY_STOP_DROP;
	(void)rte_pci_write_config(hw->pci_device, &val, sizeof(val),
				   SXE2VF_PCIE_SYS_READY);
#endif
}

s32 sxe2vf_hw_corer_stop_drop_done(struct sxe2vf_hw *hw)
{
	u32 val;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)hw->adapter;

	(void)pci_read_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY, &val);
	if (val == SXE2VF_REG_INVAL_VALUE)
		return 0;

#else
	(void)rte_pci_read_config(hw->pci_device, &val, sizeof(val),
				  SXE2VF_PCIE_SYS_READY);
#endif
	return val & SXE2VF_PCIE_SYS_READY_STOP_DROP_DONE;
}

bool sxe2vf_hw_vfr_is_checked(struct sxe2vf_hw *hw)
{
	u32 val;
	bool ret = false;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif

	val = sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN);
	if (val == SXE2VF_REG_INVAL_VALUE)
		return ret;

	ret = val & SXE2VF_MBX_Q_LEN_VFE_M;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	if (ret) {
		LOG_DEBUG_BDF("vf hw reset detected\n");
		sxe2vf_hw_vfr_clear(&adapter->hw);
	}
#endif

	return ret;
}

void sxe2vf_hw_vfr_clear(struct sxe2vf_hw *hw)
{
	u32 val;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif
	val = sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN) & (~SXE2VF_MBX_Q_LEN_VFE_M);
	sxe2vf_reg_write(hw, SXE2VF_MBX_RQ_LEN, val);
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	LOG_INFO_BDF("vfr status cleared.\n");
#endif
}

bool sxe2vf_hw_vfr_is_complete(struct sxe2vf_hw *hw)
{
	u32 val;
	bool done;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif
	val = sxe2vf_reg_read(hw, SXE2VF_VF_VRC_VFGEN_RSTAT);

	if (val != SXE2VF_REG_INVAL_VALUE)
		done = !!(val & SXE2VF_VF_VRC_VFGEN_VFRSTAT_COMPLETE);
	else
		done = false;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	if (done)
		LOG_INFO_BDF("vfr is complete.\n");
#endif
	return done;
}

bool sxe2vf_hw_vf_is_active(struct sxe2vf_hw *hw)
{
	u32 val;
	bool active;
#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;
#endif
	val = sxe2vf_reg_read(hw, SXE2VF_VF_VRC_VFGEN_RSTAT);

	if (val != SXE2VF_REG_INVAL_VALUE)
		active = !!(val & SXE2VF_VF_VRC_VFGEN_VFRSTAT_VF_ACTIVE);
	else
		active = false;

#if !defined(SXE2_DPDK_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	if (active)
		LOG_INFO_BDF("vf is active.\n");
#endif
	return active;
}

void sxe2vf_hw_mbx_regs_dump(struct sxe2vf_hw *hw)
{
#if !defined(SXE2_DPKD_VF_DRIVER) && !defined(SXE2_DPDK_DRIVER)
	struct sxe2vf_adapter *adapter = hw->adapter;

	LOG_DEBUG_BDF("RXQH:0x%x RXQT:0x%x RXQLEN:0x%x base addr high:0x%x\n"
		      "base addr low:0x%x TXQH:0x%x TXQT:0x%x\n"
		      "TXQLEN:0x%x base addr high:0x%x base addr low:0x%x.\n",
		      sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_HEAD),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_TAIL),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_LEN),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_BAH),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_RQ_BAL),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_HEAD),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_TAIL),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_LEN),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_BAH),
		      sxe2vf_reg_read(hw, SXE2VF_MBX_TQ_BAL));
#else
	(void)hw;
#endif
}

u32 sxe2vf_hw_rxq_tail_read(struct sxe2vf_hw *hw, u16 queue_id)
{
	return sxe2vf_reg_read(hw, SXE2VF_RXQ_TAIL(queue_id));
}

void sxe2vf_hw_rxq_tail_write(struct sxe2vf_hw *hw, u16 queue_id, u32 value)
{
	sxe2vf_reg_write(hw, SXE2VF_RXQ_TAIL(queue_id), value);
}

u32 sxe2vf_hw_txq_tail_read(struct sxe2vf_hw *hw, u16 queue_id)
{
	return sxe2vf_reg_read(hw, SXE2VF_TXQ_TAIL(queue_id));
}

void sxe2vf_hw_txq_tail_write(struct sxe2vf_hw *hw, u16 queue_id, u32 value)
{
	sxe2vf_reg_write(hw, SXE2VF_TXQ_TAIL(queue_id), value);
}

void __iomem *sxe2vf_reg_addr_get(struct sxe2vf_hw *hw, u64 reg)
{
	return (void __iomem *)(hw->reg_base_addr + reg);
}
