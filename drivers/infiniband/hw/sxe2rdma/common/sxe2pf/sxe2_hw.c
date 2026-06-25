// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_hw.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifdef SXE2_DPDK_DRIVER
#include "sxe2_ethdev.h"
#else
#include "sxe2.h"
#endif
#include "sxe2_hw.h"
#include "sxe2_log.h"
#include "sxe2_spec.h"

#ifdef SXE2_CFG_DEBUG
extern int reg_log;
#endif

#ifdef SXE2_DPDK_DRIVER
#define SXE2_HW_REG_WRITE(hw, reg, value)                                           \
	do {                                                                        \
		(void)hw;                                                           \
		rte_write32(value, reg);                                            \
	} while (0)

#define SXE2_HW_REG_READ(hw, reg) ((void)(hw), rte_read32(reg))

#define SXE2_HW_PCI_DEV(_ad)                                                        \
	(RTE_DEV_TO_PCI(rte_eth_devices[(_ad)->dev_info.dev_data->port_id].device))
#else
#define SXE2_HW_REG_WRITE(hw, reg, value) ((hw)->reg_write(value, reg))
#define SXE2_HW_REG_READ(hw, reg) ((hw)->reg_read(reg))
#endif

#define SXE2_SET_USED(x) ((void)(x))

void __iomem *sxe2_reg_addr_get(struct sxe2_hw *hw, resource_size_t reg)
{
#ifdef SXE2_DPDK_DRIVER
	return (u8 __iomem *)hw->hw_map + reg;
#else
	u32 i;
	struct sxe2_map_info *map;
	struct sxe2_hw_map *hw_addr = (struct sxe2_hw_map *)hw->hw_map;

	if (WARN_ON(!hw_addr))
		return (void __iomem *)ERR_PTR(-SXE2_HW_ERR_FAULT);

	for (i = 0, map = hw_addr->maps; i < hw_addr->map_cnt; i++, map++)
		if (reg >= map->start && reg < map->end)
			return (u8 __iomem *)map->addr + (reg - map->start);

	LOG_WARN("Unable to map register address 0x%llx to kernel address", reg);

	return (void __iomem *)ERR_PTR(-SXE2_HW_ERR_FAULT);
#endif
}

bool sxe2_hw_is_fault(struct sxe2_hw *hw)
{
	u32 val;

	val = sxe2_hw_read_pcie_sys_ready(hw);
	if (val == SXE2_REG_INVALID_VALUE)
		return true;
	else
		return false;
}

u32 sxe2_read_reg(struct sxe2_hw *hw, u32 reg)
{
	u32 value;
	struct sxe2_adapter *adapter = hw->adapter;
	u8 __iomem *reg_addr = sxe2_reg_addr_get(hw, reg);

	SXE2_SET_USED(adapter);

	if (IS_ERR(reg_addr)) {
		LOG_DEBUG_BDF("reg addr:0x%x is error.\n", reg);
		value = SXE2_REG_INVALID_VALUE;
		goto l_ret;
	}

	value = SXE2_HW_REG_READ(hw, reg_addr);

#ifdef SXE2_CFG_DEBUG
	if (reg_log)
		LOG_DEBUG_BDF("reg: 0x%x, value: 0x%x\n", reg, value);
#endif

l_ret:
	return value;
}

STATIC u32 sxe2_read_reg_valid(struct sxe2_hw *hw, u32 reg, u32 dflt_val)
{
	u32 val = sxe2_read_reg(hw, reg);

	return val == SXE2_REG_INVALID_VALUE ? dflt_val : val;
}

u64 sxe2_read_reg64(struct sxe2_hw *hw, u32 reg)
{
	u32 low, high;

	low = sxe2_read_reg(hw, reg);
	high = sxe2_read_reg(hw, reg + 4);
	return low + ((u64)high << 32);
}

void sxe2_write_reg(struct sxe2_hw *hw, u32 reg, u32 value)
{
	u8 __iomem *reg_addr = sxe2_reg_addr_get(hw, reg);
	struct sxe2_adapter *adapter = hw->adapter;

	SXE2_SET_USED(adapter);

	if (unlikely(sxe2_hw_is_fault(hw)) || IS_ERR(reg_addr))
		goto l_ret;

	SXE2_HW_REG_WRITE(hw, reg_addr, value);

#ifdef SXE2_CFG_DEBUG
	if (reg_log)
		LOG_DEBUG_BDF("reg:0x%x write value:0x%x read value:0x%x.\n", reg,
			      value, SXE2_HW_REG_READ(hw, reg_addr));
#endif

l_ret:
	return;
}

static void sxe2_hw_evt_irq_cause_cfg(struct sxe2_hw *hw, u32 cause)
{
	sxe2_write_reg(hw, SXE2_PF_INT_OICR_ENABLE, 0);
	(void)sxe2_read_reg(hw, SXE2_PF_INT_OICR);
	(void)sxe2_hw_fw_irq_cause_get(hw);

	sxe2_write_reg(hw, SXE2_PF_INT_OICR_ENABLE, cause);
}

static void sxe2_hw_evt_irq_cause_enable(struct sxe2_hw *hw, u16 itr_idx,
					 u16 irq_idx)
{
	u32 value;

	value = (irq_idx & SXE2_PF_INT_OICR_CTL_MSIX_IDX) |
		(itr_idx << SXE2_PF_INT_OICR_CTL_ITR_IDX_S &
		 SXE2_PF_INT_OICR_CTL_ITR_IDX) |
		SXE2_PF_INT_OICR_CTL_CAUSE_ENABLE;

	sxe2_write_reg(hw, SXE2_PF_INT_OICR_CTL, value);
}

void sxe2_hw_evt_irq_clear(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, SXE2_PF_INT_OICR_CTL, 0);
	sxe2_write_reg(hw, SXE2_PF_INT_OICR_ENABLE, 0);
	(void)sxe2_read_reg(hw, SXE2_PF_INT_OICR);
}

u32 sxe2_hw_evt_irq_mask_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_PF_INT_OICR_ENABLE);
}

u32 sxe2_hw_evt_irq_cause_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg_valid(hw, SXE2_PF_INT_OICR, 0);
}

void sxe2_hw_evt_irq_cfg(struct sxe2_hw *hw, u32 value, u16 itr_idx, u16 irq_idx)
{
	sxe2_hw_evt_irq_cause_cfg(hw, value);

	sxe2_hw_evt_irq_cause_enable(hw, itr_idx, irq_idx);
}

void sxe2_hw_fwq_irq_cfg(struct sxe2_hw *hw, u16 itr_idx, u16 irq_idx)
{
	u32 value;
	(void)itr_idx;
	value = (irq_idx & SXE2_PF_INT_FWQ_CTL_MSIX_IDX) |
		SXE2_PF_INT_FWQ_CTL_CAUSE_ENABLE;
	sxe2_write_reg(hw, SXE2_PF_INT_FWQ_CTL, value);
}

void sxe2_hw_mbxq_irq_cfg(struct sxe2_hw *hw, u16 itr_idx, u16 irq_idx)
{
	u32 value;
	(void)itr_idx;
	value = (irq_idx & SXE2_PF_INT_MBX_CTL_MSIX_IDX) |
		SXE2_PF_INT_MBX_CTL_CAUSE_ENABLE;
	sxe2_write_reg(hw, SXE2_PF_INT_MBX_CTL, value);
}

void sxe2_hw_fwq_irq_clear(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, SXE2_PF_INT_FWQ_CTL, 0);
}

void sxe2_hw_mbxq_irq_clear(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, SXE2_PF_INT_MBX_CTL, 0);
}

void sxe2_hw_irq_enable(struct sxe2_hw *hw, u16 irq_idx)
{
	u32 value = SXE2_VF_DYN_CTL_INTENABLE |
		    SXE2_VF_DYN_CTL_CLEARPBA |
		    (SXE2_ITR_IDX_NONE
		     << SXE2_VF_DYN_CTL_ITR_IDX_S);

	sxe2_write_reg(hw, SXE2_VF_DYN_CTL(irq_idx), value);
}

void sxe2_hw_irq_disable(struct sxe2_hw *hw, u16 irq_idx)
{
	u32 value = (SXE2_ITR_IDX_NONE << SXE2_VF_DYN_CTL_ITR_IDX_S);

	sxe2_write_reg(hw, SXE2_VF_DYN_CTL(irq_idx), value);
}

void sxe2_hw_irq_trigger(struct sxe2_hw *hw, u16 irq_idx)
{
	sxe2_write_reg(hw, SXE2_VF_DYN_CTL(irq_idx),
		       (SXE2_ITR_IDX_NONE << SXE2_VF_DYN_CTL_ITR_IDX_S) |
				       SXE2_VF_DYN_CTL_SWINT_TRIG |
				       SXE2_VF_DYN_CTL_INTENABLE_MSK);
}

void sxe2_hw_irq_dyn_ctl(struct sxe2_hw *hw, u16 irq_idx, u32 value)
{
	sxe2_write_reg(hw, SXE2_VF_DYN_CTL(irq_idx), value);
}

void sxe2_hw_irq_itr_set(struct sxe2_hw *hw, u16 irq_idx, u16 itr_idx, u16 interval)
{
	u32 value = (interval / hw->hw_cfg.itr_gran) & SXE2_VF_INT_ITR_INTERVAL;

	sxe2_write_reg(hw, SXE2_VF_INT_ITR(itr_idx, irq_idx), value);
}

void sxe2_hw_irq_rate_limit_set(struct sxe2_hw *hw, u16 irq_idx, u16 rate_limit)
{
	u32 value, rate_limit_reg, credit_max_value_reg;

	if (rate_limit == 0) {
		value = 0;
	} else {
		rate_limit_reg = (u32)FIELD_PREP(SXE2_PF_INT_RATE_CREDIT_INTERVAL,
						 (rate_limit /
						  hw->hw_cfg.credit_interval_gran));
		credit_max_value_reg =
				SXE2_PF_INT_RATE_CREDIT_MAX_VALUE;

		value = rate_limit_reg | credit_max_value_reg |
			SXE2_PF_INT_RATE_INTRL_ENABLE;
	}

	sxe2_write_reg(hw, SXE2_PF_INT_RATE(irq_idx), value);
}

u32 sxe2_hw_irq_gran_info_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_PFG_INT_CTL);
}

void sxe2_hw_txq_irq_cause_setup(struct sxe2_hw *hw, u16 txq_idx, u16 itr_idx,
				 u16 irq_idx)
{
	u32 value;

	value = FIELD_PREP(SXE2_PF_INT_TQCTL_MSIX_IDX,
			   irq_idx) |
		FIELD_PREP(SXE2_PF_INT_TQCTL_ITR_IDX,
			   itr_idx) |
		SXE2_PF_INT_TQCTL_CAUSE_ENABLE;

	sxe2_write_reg(hw, SXE2_PF_INT_TQCTL(txq_idx), value);
}

void sxe2_hw_txq_irq_cause_clear(struct sxe2_hw *hw, u16 txq_idx)
{
	u32 old_value = sxe2_read_reg(hw, SXE2_PF_INT_TQCTL(txq_idx));
	u32 value;

	value = old_value & ~SXE2_PF_INT_TQCTL_CAUSE_ENABLE;
	if (old_value != value)
		sxe2_write_reg(hw, SXE2_PF_INT_TQCTL(txq_idx), value);
}

void sxe2_hw_txq_irq_cause_switch(struct sxe2_hw *hw, u16 txq_idx, bool enable)
{
	u32 old_value = sxe2_read_reg(hw, SXE2_PF_INT_TQCTL(txq_idx));
	u32 value;

	if (enable)
		value = old_value | SXE2_PF_INT_TQCTL_CAUSE_ENABLE;
	else
		value = old_value & ~SXE2_PF_INT_TQCTL_CAUSE_ENABLE;

	if (old_value != value)
		sxe2_write_reg(hw, SXE2_PF_INT_TQCTL(txq_idx), value);
}

void sxe2_hw_rxq_irq_cause_setup(struct sxe2_hw *hw, u16 rxq_idx, u16 itr_idx,
				 u16 irq_idx)
{
	u32 value;

	value = FIELD_PREP(SXE2_PF_INT_RQCTL_MSIX_IDX,
			   irq_idx) |
		FIELD_PREP(SXE2_PF_INT_RQCTL_ITR_IDX,
			   itr_idx) |
		SXE2_PF_INT_RQCTL_CAUSE_ENABLE;

	sxe2_write_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx), value);
}

void sxe2_hw_rxq_irq_cause_clear(struct sxe2_hw *hw, u16 rxq_idx)
{
	u32 old_value = sxe2_read_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx));
	u32 value;

	value = old_value & ~SXE2_PF_INT_RQCTL_CAUSE_ENABLE;
	sxe2_write_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx), value);
}

void sxe2_hw_rxq_irq_idx_change(struct sxe2_hw *hw, u16 rxq_idx, u16 irq_idx)
{
	u32 old_value = sxe2_read_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx));
	u32 value;

	value = old_value & ~SXE2_PF_INT_RQCTL_MSIX_IDX;
	value |= irq_idx;

	if (old_value != value)
		sxe2_write_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx), value);
}

void sxe2_hw_rxq_irq_cause_switch(struct sxe2_hw *hw, u16 rxq_idx, bool enable)
{
	u32 old_value = sxe2_read_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx));
	u32 value;

	if (enable)
		value = old_value | SXE2_PF_INT_RQCTL_CAUSE_ENABLE;
	else
		value = old_value & ~SXE2_PF_INT_RQCTL_CAUSE_ENABLE;

	if (old_value != value)
		sxe2_write_reg(hw, SXE2_PF_INT_RQCTL(rxq_idx), value);
}

#define SXE2_HW_CMD_QUEUE_ENABLE(type)                                              \
	do {                                                                        \
		s32 ret = 0;                                                        \
		u32 value;                                                          \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##H, 0);                     \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, 0);                     \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##BAL, lower_32_bits(addr)); \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##BAH, upper_32_bits(addr)); \
		value = FIELD_PREP(SXE2_CMD_REG_LEN_M, depth) |                     \
			SXE2_CMD_REG_LEN_ENABLE_M;                                  \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##LEN, value);               \
		if (sxe2_read_reg(hw, SXE2_PF_CTRLQ_##type##BAL) !=                 \
		    lower_32_bits(addr)) {                                          \
			ret = -SXE2_HW_ERR_IO;                                      \
		}                                                                   \
		return ret;                                                         \
	} while (0)

#define SXE2_HW_CMD_QUEUE_DISABLE(type)                                             \
	do {                                                                        \
		bool is_admin = false;                                              \
		bool old_tail = false;                                              \
		bool old_head = false;                                              \
		u32 value = sxe2_read_reg(hw, SXE2_PF_CTRLQ_##type##LEN);           \
		value &= ~(SXE2_CMD_REG_LEN_VFE_M | SXE2_CMD_REG_LEN_OVFL_M |       \
			   SXE2_CMD_REG_LEN_CRIT_M | SXE2_CMD_REG_LEN_ENABLE_M);    \
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##LEN, value);               \
		is_admin = ((SXE2_PF_CTRLQ_##type##LEN ==                           \
			     SXE2_PF_CTRLQ_FW_ARQLEN) ||                            \
			    (SXE2_PF_CTRLQ_##type##LEN == SXE2_PF_CTRLQ_FW_ATQLEN)) \
					   ? true                                   \
					   : false;                                 \
		if (!is_admin) {                                                    \
			if (SXE2_PF_CTRLQ_##type##LEN ==                            \
			    SXE2_PF_CTRLQ_MBX_ATQLEN) {                             \
				old_tail = sxe2_read_reg(hw,                        \
							 SXE2_PF_CTRLQ_##type##T);  \
				old_head = sxe2_read_reg(hw,                        \
							 SXE2_PF_CTRLQ_##type##H);  \
				if (old_tail >= old_head) {                         \
					sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, \
						       0);                          \
				} else {                                            \
					sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, \
						       0);                          \
					sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, \
						       old_tail);                   \
					sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, \
						       0);                          \
				}                                                   \
				sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##H, 0);     \
			} else {                                                    \
				sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, 0);     \
				sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##H, 0);     \
			}                                                           \
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##BAL, 0);           \
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##BAH, 0);           \
		}                                                                   \
	} while (0)

#define SXE2_HW_CMD_QUEUE_WRITE_TAIL(type)                                          \
	sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##T, value & SXE2_CMD_REG_HEAD_M)
#define SXE2_HW_CMD_QUEUE_READ_HEAD(type)                                           \
	({ (sxe2_read_reg(hw, SXE2_PF_CTRLQ_##type##H) & SXE2_CMD_REG_HEAD_M); })

#define SXE2_HW_CMD_QUEUE_GET_ERR(type)                                             \
	do {                                                                        \
		u32 err = 0;                                                        \
		u32 value = sxe2_read_reg(hw, SXE2_PF_CTRLQ_##type##LEN);           \
		if (value == SXE2_REG_INVALID_VALUE)                                \
			return 0;                                                   \
		if (value & SXE2_CMD_REG_LEN_VFE_M) {                               \
			err |= SXE2_CMD_REG_LEN_VFE_M;                              \
		} else if (value & SXE2_CMD_REG_LEN_CRIT_M) {                       \
			err |= SXE2_CMD_REG_LEN_CRIT_M;                             \
		}                                                                   \
		if (err) {                                                          \
			value &= ~(SXE2_CMD_REG_LEN_VFE_M |                         \
				   SXE2_CMD_REG_LEN_CRIT_M);                        \
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_##type##LEN, value);       \
		}                                                                   \
		return err;                                                         \
	} while (0)

s32 sxe2_hw_fw_tq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(depth);
	SXE2_SET_USED(addr);

	SXE2_HW_CMD_QUEUE_ENABLE(FW_ATQ);
}

void sxe2_hw_fw_tq_disable(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_DISABLE(FW_ATQ);
}

s32 sxe2_hw_fw_tq_is_idle(struct sxe2_hw *hw)
{
	u32 val;
	s32 ret;
	u32 old_tail;
	u32 old_head;

	val = sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_HW_STS);
	if (val == SXE2_REG_INVALID_VALUE) {
		ret = true;
		goto l_out;
	}
	ret = val & SXE2_PF_CTRLQ_FW_ATQ_IDLE_MASK;

l_out:
	if (ret) {
		old_tail = sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ATQT);
		old_head = sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_ATQH);
		if (old_tail >= old_head) {
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQT, 0);
		} else {
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQT, 0);
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQT, old_tail);
			sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQT, 0);
		}
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQH, 0);

		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQBAL, 0);
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ATQBAH, 0);
	}

	return ret;
}

void sxe2_hw_fw_tq_write_tail(struct sxe2_hw *hw, u32 value)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(value);

	SXE2_HW_CMD_QUEUE_WRITE_TAIL(FW_ATQ);
}

u32 sxe2_hw_fw_tq_read_head(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	return SXE2_HW_CMD_QUEUE_READ_HEAD(FW_ATQ);
}

u32 sxe2_hw_fw_tq_get_error(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_GET_ERR(FW_ATQ);
}

s32 sxe2_hw_fw_rq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(depth);
	SXE2_SET_USED(addr);

	SXE2_HW_CMD_QUEUE_ENABLE(FW_ARQ);
}

void sxe2_hw_fw_rq_disable(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_DISABLE(FW_ARQ);
}

s32 sxe2_hw_fw_rq_is_idle(struct sxe2_hw *hw)
{
	u32 val;
	s32 ret;

	SXE2_SET_USED(hw);
	val = sxe2_read_reg(hw, SXE2_PF_CTRLQ_FW_HW_STS);
	if (val == SXE2_REG_INVALID_VALUE) {
		ret = true;
		goto l_out;
	}
	ret = val & SXE2_PF_CTRLQ_FW_ARQ_IDLE_MASK;

l_out:
	if (ret) {
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ARQH, 0);
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ARQT, 0);
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ARQBAL, 0);
		sxe2_write_reg(hw, SXE2_PF_CTRLQ_FW_ARQBAH, 0);
	}

	return ret;
}

void sxe2_hw_fw_rq_write_tail(struct sxe2_hw *hw, u32 value)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(value);

	SXE2_HW_CMD_QUEUE_WRITE_TAIL(FW_ARQ);
}

u32 sxe2_hw_fw_rq_read_head(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	return SXE2_HW_CMD_QUEUE_READ_HEAD(FW_ARQ);
}

u32 sxe2_hw_fw_rq_get_error(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_GET_ERR(FW_ARQ);
}

s32 sxe2_hw_mbx_tq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(depth);
	SXE2_SET_USED(addr);

	SXE2_HW_CMD_QUEUE_ENABLE(MBX_ATQ);
}

void sxe2_hw_mbx_tq_disable(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_DISABLE(MBX_ATQ);
}

void sxe2_hw_mbx_tq_write_tail(struct sxe2_hw *hw, u32 value)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(value);

	SXE2_HW_CMD_QUEUE_WRITE_TAIL(MBX_ATQ);
}

u32 sxe2_hw_mbx_tq_read_head(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	return SXE2_HW_CMD_QUEUE_READ_HEAD(MBX_ATQ);
}

u32 sxe2_hw_mbx_tq_get_error(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_GET_ERR(MBX_ATQ);
}

s32 sxe2_hw_mbx_rq_enable(struct sxe2_hw *hw, u16 depth, dma_addr_t addr)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(depth);
	SXE2_SET_USED(addr);

	SXE2_HW_CMD_QUEUE_ENABLE(MBX_ARQ);
}

void sxe2_hw_mbx_rq_disable(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_DISABLE(MBX_ARQ);
}

void sxe2_hw_mbx_rq_write_tail(struct sxe2_hw *hw, u32 value)
{
	SXE2_SET_USED(hw);
	SXE2_SET_USED(value);

	SXE2_HW_CMD_QUEUE_WRITE_TAIL(MBX_ARQ);
}

u32 sxe2_hw_mbx_rq_read_head(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	return SXE2_HW_CMD_QUEUE_READ_HEAD(MBX_ARQ);
}

u32 sxe2_hw_mbx_rq_get_error(struct sxe2_hw *hw)
{
	SXE2_SET_USED(hw);

	SXE2_HW_CMD_QUEUE_GET_ERR(MBX_ARQ);
}

void sxe2_hw_rxq_ctxt_cfg(struct sxe2_hw *hw, struct sxe2_hw_rxq_ctxt *rxq_ctxt,
			  u16 rxq_idx)
{
	u8 i;
	struct sxe2_adapter *adapter = hw->adapter;
	u32 value[SXE2_RX_CTXT_CNT];
	u32 base_addr_h = rxq_ctxt->base_addr >> SXE2_RX_CTXT_BASE_L_W;
	u16 depth_h = rxq_ctxt->depth >> SXE2_RX_CTXT_DEPTH_L_W;

	SXE2_SET_USED(adapter);

	value[SXE2_RX_CTXT0] = SXE2_CTXT_REG_VALUE(rxq_ctxt->base_addr,
						   SXE2_RX_CTXT_BASE_L_S,
						   SXE2_RX_CTXT_BASE_L_W);

	value[SXE2_RX_CTXT1] = SXE2_CTXT_REG_VALUE(base_addr_h,
						   SXE2_RX_CTXT_BASE_H_S,
						   SXE2_RX_CTXT_BASE_H_W);
	value[SXE2_RX_CTXT1] |=
			SXE2_CTXT_REG_VALUE(rxq_ctxt->depth, SXE2_RX_CTXT_DEPTH_L_S,
					    SXE2_RX_CTXT_DEPTH_L_W);

	value[SXE2_RX_CTXT2] = SXE2_CTXT_REG_VALUE(depth_h, SXE2_RX_CTXT_DEPTH_H_S,
						   SXE2_RX_CTXT_DEPTH_H_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->dbuff_len,
						    SXE2_RX_CTXT_DBUFF_S,
						    SXE2_RX_CTXT_DBUFF_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->hbuff_len,
						    SXE2_RX_CTXT_HBUFF_S,
						    SXE2_RX_CTXT_HBUFF_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->hsplit_type,
						    SXE2_RX_CTXT_HSPLT_TYPE_S,
						    SXE2_RX_CTXT_HSPLT_TYPE_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->desc_type,
						    SXE2_RX_CTXT_DESC_TYPE_S,
						    SXE2_RX_CTXT_DESC_TYPE_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->crc_strip,
						    SXE2_RX_CTXT_CRC_S,
						    SXE2_RX_CTXT_CRC_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->l2tag1_show,
						    SXE2_RX_CTXT_L2TAG_FLAG_S,
						    SXE2_RX_CTXT_L2TAG_FLAG_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->hsplit_0,
						    SXE2_RX_CTXT_HSPLT_0_S,
						    SXE2_RX_CTXT_HSPLT_0_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->hsplit_1,
						    SXE2_RX_CTXT_HSPLT_1_S,
						    SXE2_RX_CTXT_HSPLT_1_W);
	value[SXE2_RX_CTXT2] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->inner_vlan_strip,
						    SXE2_RX_CTXT_INVALN_STP_S,
						    SXE2_RX_CTXT_INVALN_STP_W);

	value[SXE2_RX_CTXT3] = SXE2_CTXT_REG_VALUE(rxq_ctxt->lro_enable,
						   SXE2_RX_CTXT_LRO_ENABLE_S,
						   SXE2_RX_CTXT_LRO_ENABLE_W);
	value[SXE2_RX_CTXT3] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->cpuid,
						    SXE2_RX_CTXT_CPUID_S,
						    SXE2_RX_CTXT_CPUID_W);
	value[SXE2_RX_CTXT3] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->max_frame_size,
						    SXE2_RX_CTXT_MAX_FRAME_SIZE_S,
						    SXE2_RX_CTXT_MAX_FRAME_SIZE_W);
	value[SXE2_RX_CTXT3] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->lro_desc_max,
						    SXE2_RX_CTXT_LRO_DESC_MAX_S,
						    SXE2_RX_CTXT_LRO_DESC_MAX_W);

	value[SXE2_RX_CTXT4] = SXE2_CTXT_REG_VALUE(rxq_ctxt->tphrdesc_enable,
						   SXE2_RX_CTXT_THPRDESC_ENABLE_S,
						   SXE2_RX_CTXT_THPRDESC_ENABLE_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->tphwdesc_enable,
						    SXE2_RX_CTXT_THPWDESC_ENABLE_S,
						    SXE2_RX_CTXT_THPWDESC_ENABLE_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->tphdata_enable,
						    SXE2_RX_CTXT_THPRDATA_ENABLE_S,
						    SXE2_RX_CTXT_THPRDATA_ENABLE_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->tphhead_enable,
						    SXE2_RX_CTXT_THPHEAD_ENABLE_S,
						    SXE2_RX_CTXT_THPHEAD_ENABLE_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->low_desc_waterline,
						    SXE2_RX_CTXT_LOW_DESC_LINE_S,
						    SXE2_RX_CTXT_LOW_DESC_LINE_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->vfid,
						    SXE2_RX_CTXT_VF_ID_S,
						    SXE2_RX_CTXT_VF_ID_W);
	value[SXE2_RX_CTXT4] |= SXE2_CTXT_REG_VALUE(rxq_ctxt->pfid,
						    SXE2_RX_CTXT_PF_ID_S,
						    SXE2_RX_CTXT_PF_ID_W);
	value[SXE2_RX_CTXT4] |=
			SXE2_CTXT_REG_VALUE(rxq_ctxt->vfen, SXE2_RX_CTXT_VF_ENABLE_S,
					    SXE2_RX_CTXT_VF_ENABLE_W);
	value[SXE2_RX_CTXT4] |=
			SXE2_CTXT_REG_VALUE(rxq_ctxt->vsi_id, SXE2_RX_CTXT_VSI_ID_S,
					    SXE2_RX_CTXT_VSI_ID_W);

	for (i = 0; i < SXE2_RX_CTXT_CNT; i++) {
		SXE2_REG_WRITE(hw, SXE2_RXQ_CTXT(i, rxq_idx), value[i]);
		LOG_INFO_BDF("rxq:%u ctxt[%u]:0x%x.\n", rxq_idx, i, value[i]);
	}
}

void sxe2_hw_vf_irq_cfg(struct sxe2_hw *hw, struct sxe2_hw_vf_irq *vf_irq)
{
	u32 value;
	u16 idx;

	value = (((vf_irq->first_in_dev << SXE2_PFVP_INT_ALLOC_FIRST_S) &
		  SXE2_PFVP_INT_ALLOC_FIRST_M) |
		 ((vf_irq->last_in_dev << SXE2_PFVP_INT_ALLOC_LAST_S) &
		  SXE2_PFVP_INT_ALLOC_LAST_M) |
		 SXE2_PFVP_INT_ALLOC_VALID);
	SXE2_REG_WRITE(hw, SXE2_PFVP_INT_ALLOC(vf_irq->vfid_in_pf), value);

	value = (((vf_irq->first_in_dev << SXE2_PCI_PFVP_INT_ALLOC_FIRST_S) &
		  SXE2_PCI_PFVP_INT_ALLOC_FIRST_M) |
		 ((vf_irq->last_in_dev << SXE2_PCI_PFVP_INT_ALLOC_LAST_S) &
		  SXE2_PCI_PFVP_INT_ALLOC_LAST_M) |
		 SXE2_PCI_PFVP_INT_ALLOC_VALID);
	SXE2_REG_WRITE(hw, SXE2_PCI_PFVP_INT_ALLOC(vf_irq->vfid_in_pf), value);

	for (idx = vf_irq->first_in_pf; idx <= vf_irq->last_in_pf; idx++) {
		value = (((vf_irq->vfid_in_dev << SXE2_PCIEPROC_INT2FUNC_VF_NUM_S) &
			  SXE2_PCIEPROC_INT2FUNC_VF_NUM_M) |
			 ((vf_irq->pf_id << SXE2_PCIEPROC_INT2FUNC_PF_NUM_S) &
			  SXE2_PCIEPROC_INT2FUNC_PF_NUM_M));
		SXE2_REG_WRITE(hw, SXE2_PCIEPROC_INT2FUNC(idx), value);
	}

	SXE2_REG_WRITE(hw, SXE2_VSI_PF(vf_irq->vfid_in_dev),
		       SXE2_VSI_PF_EN_M | (vf_irq->pf_id & SXE2_VSI_PF_ID_M));

	SXE2_REG_WRITE(hw, SXE2_MBX_CTL(vf_irq->vfid_in_dev),
		       SXE2_MBX_CTL_CAUSE_ENA_M | (vf_irq->first_in_pf &
						   SXE2_MBX_CTL_MSIX_INDX_M));
}

void sxe2_hw_vf_queue_cfg(struct sxe2_hw *hw, struct sxe2_hw_vf_queue *vf_queue)
{
	u32 reg;

	SXE2_REG_WRITE(hw, SXE2_VF_TXQ_MAPENA(vf_queue->vfid_in_pf),
		       SXE2_VF_TXQ_MAPENA_M);
	reg = (((vf_queue->txq_first_in_pf << SXE2_VF_TXQ_BASE_FIRST_Q_S) &
		SXE2_VF_TXQ_BASE_FIRST_Q_M) |
	       (((vf_queue->txq_cnt - 1) << SXE2_VF_TXQ_BASE_Q_NUM_S) &
		SXE2_VF_TXQ_BASE_Q_NUM_M));
	SXE2_REG_WRITE(hw, SXE2_VF_TXQ_BASE(vf_queue->vfid_in_pf), reg);

	SXE2_REG_WRITE(hw, SXE2_VF_RXQ_MAPENA(vf_queue->vfid_in_pf),
		       SXE2_VF_RXQ_MAPENA_M);

	reg = (((vf_queue->rxq_first_in_pf << SXE2_VF_RXQ_BASE_FIRST_Q_S) &
		SXE2_VF_RXQ_BASE_FIRST_Q_M) |
	       (((vf_queue->rxq_cnt - 1) << SXE2_VF_RXQ_BASE_Q_NUM_S) &
		SXE2_VF_RXQ_BASE_Q_NUM_M));
	SXE2_REG_WRITE(hw, SXE2_VF_RXQ_BASE(vf_queue->vfid_in_pf), reg);
}

void sxe2_hw_vf_irq_decfg(struct sxe2_hw *hw, struct sxe2_hw_vf_irq *vf_irq)
{
	u16 idx;
	u32 value;

	SXE2_REG_WRITE(hw, SXE2_MBX_CTL(vf_irq->vfid_in_dev), 0);

	SXE2_REG_WRITE(hw, SXE2_VSI_PF(vf_irq->vfid_in_dev), 0);

	for (idx = vf_irq->first_in_pf; idx <= vf_irq->last_in_pf; idx++) {
		value = (((1 << SXE2_PCIEPROC_INT2FUNC_IS_PF_S) &
			  SXE2_PCIEPROC_INT2FUNC_IS_PF_M) |
			 ((vf_irq->pf_id << SXE2_PCIEPROC_INT2FUNC_PF_NUM_S) &
			  SXE2_PCIEPROC_INT2FUNC_PF_NUM_M));
		SXE2_REG_WRITE(hw, SXE2_PCIEPROC_INT2FUNC(idx), value);
	}

	SXE2_REG_WRITE(hw, SXE2_PCI_PFVP_INT_ALLOC(vf_irq->vfid_in_pf), 0);
	SXE2_REG_WRITE(hw, SXE2_PFVP_INT_ALLOC(vf_irq->vfid_in_pf), 0);
}

void sxe2_hw_vf_queue_decfg(struct sxe2_hw *hw, struct sxe2_hw_vf_queue *vf_queue)
{
	SXE2_REG_WRITE(hw, SXE2_VF_RXQ_BASE(vf_queue->vfid_in_pf), 0);
	SXE2_REG_WRITE(hw, SXE2_VF_RXQ_MAPENA(vf_queue->vfid_in_pf), 0);

	SXE2_REG_WRITE(hw, SXE2_VF_TXQ_BASE(vf_queue->vfid_in_pf), 0);
	SXE2_REG_WRITE(hw, SXE2_VF_TXQ_MAPENA(vf_queue->vfid_in_pf), 0);
}

s32 sxe2_hw_rxq_status_check(struct sxe2_hw *hw, u32 reg_idx, bool enable)
{
	struct sxe2_adapter *adapter = hw->adapter;
	s32 ret;
	u8 i;
	u32 value;

	(void)adapter;

	for (i = 0; i < SXE2_QUEUE_WAIT_RETRY_CNT; i++) {
		value = SXE2_REG_READ(hw, SXE2_RXQ_CTRL(reg_idx));
		if ((enable == !!(value & SXE2_RXQ_CTRL_STATUS_ACTIVE)) ||
		    value == SXE2_REG_INVALID_VALUE) {
			ret = 0;
			LOG_DEBUG_BDF("rxq[%u] %s done.\n", reg_idx,
				      enable ? "enable" : "disable");
			goto l_out;
		}

		usleep_range(20, 40);
	}

	ret = -SXE2_HW_ERR_TIMEDOUT;

l_out:
	return ret;
}

s32 sxe2_hw_rxq_ctrl(struct sxe2_hw *hw, u16 reg_idx, bool enable, bool wait,
		     bool cde)
{
	s32 ret = 0;
	u32 ctrl_reg = SXE2_REG_READ(hw, SXE2_RXQ_CTRL(reg_idx));
	u32 value;

	if (enable == !!(ctrl_reg & SXE2_RXQ_CTRL_STATUS_ACTIVE)) {
		LOG_WARN("rxq idx:%u status:%u already.\n", reg_idx, enable);
		return ret;
	}

	if (enable) {
		value = cde ? (SXE2_RXQ_CTRL_ENABLED | SXE2_RXQ_CTRL_CDE_ENABLE)
			    : SXE2_RXQ_CTRL_ENABLED;
		ctrl_reg |= value;
	} else {
		ctrl_reg &= ~(SXE2_RXQ_CTRL_ENABLED | SXE2_RXQ_CTRL_CDE_ENABLE);
	}

	SXE2_REG_WRITE(hw, SXE2_RXQ_CTRL(reg_idx), ctrl_reg);

	if (!wait)
		return ret;

	sxe2_flush(hw);
	ret = sxe2_hw_rxq_status_check(hw, reg_idx, enable);

	sxe2_flush(hw);

	return ret;
}

u32 sxe2_fw_state_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_STATE);
}

u32 sxe2_fw_ver_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_VER);
}

u32 sxe2_fw_comp_ver_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_COMP_VER_ADDR);
}

u32 sxe2_fw_mode_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_MISC) & SXE2_FW_MISC_MODE_M;
}

u32 sxe2_fw_pop_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_MISC) & SXE2_FW_MISC_POP_M;
}

void sxe2_hw_l2tag_accept(struct sxe2_hw *hw, u16 vsi_hw_id)
{
	u32 val;

	val = (SXE2_PFP_L2TAGSEN_ALL_TAG << SXE2_VSI_TAR_UNTAGGED_SHIFT) |
	      SXE2_PFP_L2TAGSEN_ALL_TAG;

	sxe2_write_reg(hw, SXE2_VSI_TAR(vsi_hw_id), val);
}

static s32 sxe2_tpid_to_bits(bool pvlan_exist, bool is_strip, u16 tpid, u32 *bits)
{
	if (!pvlan_exist) {
		switch (tpid) {
		case ETH_P_8021Q:
			*bits = is_strip ? SXE2_VSI_TSR_ID_OUT_VLAN1
					 : SXE2_VSI_L2TAGSTXVALID_ID_OUT_VLAN1;
			break;
		case ETH_P_8021AD:
			*bits = is_strip ? SXE2_VSI_TSR_ID_STAG
					 : SXE2_VSI_L2TAGSTXVALID_ID_STAG;
			break;
		case ETH_P_QINQ1:
			*bits = is_strip ? SXE2_VSI_TSR_ID_OUT_VLAN2
					 : SXE2_VSI_L2TAGSTXVALID_ID_OUT_VLAN2;
			break;
		default:
			return -SXE2_HW_ERR_INVAL;
		}
	} else {
		if (tpid != ETH_P_8021Q)
			return -SXE2_HW_ERR_INVAL;
		*bits = is_strip ? SXE2_VSI_TSR_ID_VLAN
				 : SXE2_VSI_L2TAGSTXVALID_ID_VLAN;
	}

	return 0;
}

s32 sxe2_hw_desc_vlan_param_check(bool pvlan_exist, bool is_strip, u16 tpid)
{
	u32 bits = 0;

	if (sxe2_tpid_to_bits(pvlan_exist, is_strip, tpid, &bits))
		return -SXE2_HW_ERR_INVAL;

	return 0;
}

s32 sxe2_hw_desc_vlan_strip_switch(struct sxe2_hw *hw, u16 vsi_hw_id, u16 tpid,
				   bool pvlan_exist, bool en)
{
	u32 val;
	u32 bits = 0;

	if (sxe2_tpid_to_bits(pvlan_exist, true, tpid, &bits))
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_TSR(vsi_hw_id));
	if (en)
		val |= (bits << SXE2_VSI_TSR_STRIP_TAG_S) |
		       (bits << SXE2_VSI_TSR_SHOW_TAG_S);
	else
		val &= ~((bits << SXE2_VSI_TSR_STRIP_TAG_S) |
			 (bits << SXE2_VSI_TSR_SHOW_TAG_S));
	sxe2_write_reg(hw, SXE2_VSI_TSR(vsi_hw_id), val);

	return 0;
}

s32 sxe2_hw_desc_vlan_insert_switch(struct sxe2_hw *hw, u16 vsi_hw_id, u16 tpid,
				    bool pvlan_exist, bool en)
{
	u32 val;
	u32 bits = 0;

	if (sxe2_tpid_to_bits(pvlan_exist, false, tpid, &bits))
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id));
	if (en)
		val |= (bits << SXE2_VSI_L2TAGSTXVALID_L2TAG1_ID_S) |
		       SXE2_VSI_L2TAGSTXVALID_L2TAG1_VALID;
	else
		val &= ~((SXE2_VSI_L2TAGSTXVALID_L2TAG1_ID_M
			  << SXE2_VSI_L2TAGSTXVALID_L2TAG1_ID_S) |
			 SXE2_VSI_L2TAGSTXVALID_L2TAG1_VALID);

	sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id), val);

	return 0;
}

s32 sxe2_hw_desc_outer_vlan_insert_switch(struct sxe2_hw *hw, u16 vsi_hw_id,
					  u16 tpid, bool pvlan_exist, bool en)
{
	u32 val;
	u32 bits = 0;

	if (sxe2_tpid_to_bits(pvlan_exist, false, tpid, &bits))
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id));
	if (en)
		val |= (bits << SXE2_VSI_L2TAGSTXVALID_L2TAG2_ID_S) |
		       SXE2_VSI_L2TAGSTXVALID_L2TAG2_VALID;
	else
		val &= ~((SXE2_VSI_L2TAGSTXVALID_L2TAG2_ID_M
			  << SXE2_VSI_L2TAGSTXVALID_L2TAG2_ID_S) |
			 SXE2_VSI_L2TAGSTXVALID_L2TAG2_VALID);

	sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id), val);

	return 0;
}

s32 sxe2_hw_port_vlan_setup(struct sxe2_hw *hw, u16 vsi_hw_id, u16 vlan_info,
			    u16 tpid)
{
	u32 val;
	u32 strip_bits = 0;
	u32 insert_bits = 0;

	if (vlan_info) {
		if (sxe2_tpid_to_bits(false, true, tpid, &strip_bits))
			return -SXE2_HW_ERR_INVAL;
		if (sxe2_tpid_to_bits(false, false, tpid, &insert_bits))
			return -SXE2_HW_ERR_INVAL;

		val = strip_bits << SXE2_VSI_TSR_STRIP_TAG_S;
		sxe2_write_reg(hw, SXE2_VSI_TSR(vsi_hw_id), val);

		val = (insert_bits << SXE2_VSI_L2TAGSTXVALID_TIR0_ID_S) |
		      SXE2_VSI_L2TAGSTXVALID_TIR0_VALID;
		sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id), val);
	} else {
		sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_hw_id), 0);
		sxe2_write_reg(hw, SXE2_VSI_TSR(vsi_hw_id), 0);
	}

	sxe2_write_reg(hw, SXE2_VSI_TIR0(vsi_hw_id), vlan_info);

	return 0;
}

s32 sxe2_hw_port_inner_vlan_acceptrule_setup(struct sxe2_hw *hw, u16 vsi_hw_id,
					     bool acceptedtagged,
					     bool accepteduntagged)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VSI_TAR(vsi_hw_id));
	if (acceptedtagged)
		val |= (BIT(SXE2_VSI_L2TAGSTXVALID_ID_VLAN)
			<< SXE2_ACCEPT_RULE_TAGGED_S);
	else
		val &= ~(BIT(SXE2_VSI_L2TAGSTXVALID_ID_VLAN)
			 << SXE2_ACCEPT_RULE_TAGGED_S);

	if (accepteduntagged)
		val |= (BIT(SXE2_VSI_L2TAGSTXVALID_ID_VLAN)
			<< SXE2_ACCEPT_RULE_UNTAGGED_S);
	else
		val &= ~(BIT(SXE2_VSI_L2TAGSTXVALID_ID_VLAN)
			 << SXE2_ACCEPT_RULE_UNTAGGED_S);

	sxe2_write_reg(hw, SXE2_VSI_TAR(vsi_hw_id), val);

	return 0;
}

void sxe2_hw_rx_vlan_filter_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VSI_RX_SWITCH_CTRL(vsi_hw_id));
	if (en)
		val |= SXE2_VSI_RX_SW_CTRL_VLAN_PRUNE;
	else
		val &= ~SXE2_VSI_RX_SW_CTRL_VLAN_PRUNE;
	sxe2_write_reg(hw, SXE2_VSI_RX_SWITCH_CTRL(vsi_hw_id), val);
}

void sxe2_hw_vsi_loopback_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id));
	if (en)
		val |= SXE2_VSI_TX_SW_CTRL_LOOPBACK_EN;
	else
		val &= ~SXE2_VSI_TX_SW_CTRL_LOOPBACK_EN;
	sxe2_write_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id), val);
}

void sxe2_hw_vsi_mac_spoofchk_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id));
	if (en)
		val |= SXE2_VSI_TX_SW_CTRL_MACAS_EN;
	else
		val &= ~SXE2_VSI_TX_SW_CTRL_MACAS_EN;
	sxe2_write_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id), val);
}

void sxe2_hw_vsi_vlan_spoofchk_switch(struct sxe2_hw *hw, u16 vsi_hw_id, bool en)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id));
	if (en)
		val |= SXE2_VSI_TX_SW_CTRL_VLAN_PRUNE;
	else
		val &= ~SXE2_VSI_TX_SW_CTRL_VLAN_PRUNE;
	sxe2_write_reg(hw, SXE2_VSI_TX_SWITCH_CTRL(vsi_hw_id), val);
}

u32 sxe2_hw_fw_irq_cause_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg_valid(hw, SXE2_PF_INT_FW_EVENT, 0);
}

s32 sxe2_hw_corer_irq_cause_get(struct sxe2_hw *hw)
{
	u32 val;
	struct sxe2_adapter *adapter = (struct sxe2_adapter *)hw->adapter;
#ifndef SXE2_DPDK_DRIVER
	pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);

	if (val == SXE2_REG_INVALID_VALUE)
		return 0;
	if (val & SXE2_PCIE_SYS_READY_CORER_ASSERT)
		pci_write_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY,
				       SXE2_PCIE_SYS_READY_CORER_ASSERT);
#else
	u32 val_wr;

	rte_pci_read_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
			    SXE2_PCIE_SYS_READY);
	if (val & SXE2_PCIE_SYS_READY_CORER_ASSERT) {
		val_wr = SXE2_PCIE_SYS_READY_CORER_ASSERT;
		(void)rte_pci_write_config(SXE2_HW_PCI_DEV(adapter), &val_wr,
					   sizeof(val_wr), SXE2_PCIE_SYS_READY);
	}
#endif

	return val & SXE2_PCIE_SYS_READY_CORER_ASSERT;
}

void sxe2_hw_trigger_pfr(struct sxe2_hw *hw)
{
	u32 reg;

	reg = sxe2_read_reg(hw, SXE2_PFGEN_CTRL);

	sxe2_write_reg(hw, SXE2_PFGEN_CTRL, (reg | SXE2_PFGEN_CTRL_PFSWR));
}

s32 sxe2_hw_pfr_done(struct sxe2_hw *hw)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_PFGEN_CTRL);
	if (val == SXE2_REG_INVALID_VALUE) {
		if (!sxe2_hw_stop_drop_done(hw))
			return -EBUSY;

		return 0;
	}

	return !(val & SXE2_PFGEN_CTRL_PFSWR);
}

void sxe2_hw_trigger_corer(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, SXE2_TOP_CFG_CORE, SXE2_TOP_CFG_CORE_RST_CODE);
}

s32 sxe2_hw_corer_done(struct sxe2_hw *hw)
{
	u32 val;
	struct sxe2_adapter *adapter = (struct sxe2_adapter *)hw->adapter;
#ifndef SXE2_DPDK_DRIVER
	pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);

	if (val == SXE2_REG_INVALID_VALUE)
		return 0;
#else
	rte_pci_read_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
			    SXE2_PCIE_SYS_READY);
#endif
	return val & SXE2_PCIE_SYS_READY_R5;
}

void sxe2_hw_stop_drop(struct sxe2_hw *hw)
{
	u32 val;
	struct sxe2_adapter *adapter = (struct sxe2_adapter *)hw->adapter;
#ifndef SXE2_DPDK_DRIVER
	pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);
	pci_write_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY,
			       (val | SXE2_PCIE_SYS_READY_STOP_DROP));
#else
	rte_pci_read_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
			    SXE2_PCIE_SYS_READY);
	val = val | SXE2_PCIE_SYS_READY_STOP_DROP;
	(void)rte_pci_write_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
				   SXE2_PCIE_SYS_READY);
#endif
}

s32 sxe2_hw_stop_drop_done(struct sxe2_hw *hw)
{
	u32 val;
	struct sxe2_adapter *adapter = (struct sxe2_adapter *)hw->adapter;

#ifndef SXE2_DPDK_DRIVER
	pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);
	if (val == SXE2_REG_INVALID_VALUE)
		return 0;
#else
	rte_pci_read_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
			    SXE2_PCIE_SYS_READY);
#endif
	return val & SXE2_PCIE_SYS_READY_STOP_DROP_DONE;
}

u32 sxe2_hw_read_pcie_sys_ready(struct sxe2_hw *hw)
{
	u32 val;
	struct sxe2_adapter *adapter = (struct sxe2_adapter *)hw->adapter;
#ifndef SXE2_DPDK_DRIVER
	pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);
#else
	rte_pci_read_config(SXE2_HW_PCI_DEV(adapter), &val, sizeof(val),
			    SXE2_PCIE_SYS_READY);
#endif
	return val;
}

u32 sxe2_hw_heartbeat_get(struct sxe2_hw *hw)
{
	return sxe2_read_reg(hw, SXE2_FW_HEARTBEAT);
}

void sxe2_hw_trigger_vfr(struct sxe2_hw *hw, u16 vf_id)
{
	u32 reg;

	reg = sxe2_read_reg(hw, SXE2_VFGEN_CTRL(vf_id));

	sxe2_write_reg(hw, SXE2_VFGEN_CTRL(vf_id), (reg | SXE2_VFGEN_CTRL_VFSWR));

	LOG_INFO("vf:%d vfr triggered.\n", vf_id);
}

u32 sxe2_hw_vfr_done(struct sxe2_hw *hw, u16 vf_id)
{
	u32 val;
	struct sxe2_adapter *adapter = hw->adapter;

#ifdef SXE2_DPDK_DRIVER
	UNUSED(adapter);
#endif

	val = sxe2_read_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id));
	if (val == SXE2_REG_INVALID_VALUE) {
		LOG_WARN_BDF("core reset or pfr detected.\n");
		return SXE2_REG_UNACCESS;
	}

	return (val & SXE2_VF_VRC_VFGEN_VFRSTAT_COMPLETE);
}

void sxe2_hw_vf_active(struct sxe2_hw *hw, u16 vf_id)
{
	u32 val;
	u32 reg_val;
	struct sxe2_adapter *adapter = hw->adapter;

#ifdef SXE2_DPDK_DRIVER
	UNUSED(adapter);
#endif

	reg_val = sxe2_read_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id));

	val = FIELD_PREP(SXE2_VF_VRC_VFGEN_VFRSTAT,
			 SXE2_VF_VRC_VFGEN_VFRSTAT_VF_ACTIVE) |
	      SXE2_VF_VRC_VFGEN_VFRSTAT_FORVF_MASK | reg_val;
	sxe2_write_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id), val);

	LOG_INFO_BDF("vf_id:%u activated 0x%x.\n", vf_id,
		     sxe2_read_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id)));
}

void sxe2_hw_vf_deactive(struct sxe2_hw *hw, u16 vf_id)
{
	u32 val;

	val = sxe2_read_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id));
	val &= ~(SXE2_VF_VRC_VFGEN_VFRSTAT_VF_ACTIVE);
	sxe2_write_reg(hw, SXE2_VF_VRC_VFGEN_RSTAT(vf_id), val);
}

bool sxe2_hw_vflr_cause_get(struct sxe2_hw *hw, u16 vf_id_in_dev)
{
	u32 val;
	u32 reg_idx, bit_idx;

	reg_idx = vf_id_in_dev / 32;
	bit_idx = vf_id_in_dev % 32;

	val = sxe2_read_reg(hw, SXE2_GLGEN_VFLRSTAT(reg_idx));
	return !!(val & BIT(bit_idx));
}

void sxe2_hw_vflr_cause_clear(struct sxe2_hw *hw, u16 vf_id_in_dev)
{
	u32 reg_idx, bit_idx;

	reg_idx = vf_id_in_dev / 32;
	bit_idx = vf_id_in_dev % 32;

	sxe2_write_reg(hw, (u32)SXE2_GLGEN_VFLRSTAT(reg_idx), (u32)BIT(bit_idx));
}

s32 sxe2_hw_port_outer_vlan_acceptrule_setup(struct sxe2_hw *hw, u16 vsi_hw_id,
					     u16 tpid, bool acceptedtagged,
					     bool accepteduntagged)
{
	u32 val;
	u32 tag_id = 0;

	if (sxe2_tpid_to_bits(false, false, tpid, &tag_id))
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_TAR(vsi_hw_id));
	if (acceptedtagged)
		val |= (u32)(BIT(tag_id) << SXE2_ACCEPT_RULE_TAGGED_S);
	else
		val &= (u32)(~(BIT(tag_id) << SXE2_ACCEPT_RULE_TAGGED_S));

	if (accepteduntagged)
		val |= (u32)(BIT(tag_id) << SXE2_ACCEPT_RULE_UNTAGGED_S);
	else
		val &= (u32)(~(BIT(tag_id) << SXE2_ACCEPT_RULE_UNTAGGED_S));

	sxe2_write_reg(hw, SXE2_VSI_TAR(vsi_hw_id), val);

	return 0;
}

void sxe2_hw_ptp_main_enable(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, GLTSYN, GLTSYN_ENA_M);
}

void sxe2_hw_ptp_main_disable(struct sxe2_hw *hw)
{
	u32 val = sxe2_read_reg(hw, GLTSYN);

	val &= ~GLTSYN_ENA_M;
	sxe2_write_reg(hw, GLTSYN, val);
}

bool sxe2_hw_ptp_main_is_enabled(struct sxe2_hw *hw)
{
	u32 val = sxe2_read_reg(hw, GLTSYN);

	if (val & GLTSYN_ENA_M)
		return true;

	return false;
}

void sxe2_hw_ptp_init_incval(struct sxe2_hw *hw, u64 incval)
{
	sxe2_write_reg(hw, GLTSYN_SHADJ_NS, upper_32_bits(incval));
	sxe2_write_reg(hw, GLTSYN_SHADJ_SUBNS, lower_32_bits(incval));

	sxe2_write_reg(hw, GLTSYN_CMD, GLTSYN_CMD_INIT_INCVAL);
	sxe2_write_reg(hw, GLTSYN_SYNC, GLTSYN_SYNC_EXEC | GLTSYN_SYNC_GEN_PULSE);
}

void sxe2_hw_ptp_tsyn_switch(struct sxe2_hw *hw, bool on)
{
	u32 reg;

	reg = sxe2_read_reg(hw, SXE2_PF_INT_OICR_ENABLE);
	if (on)
		reg |= SXE2_PF_INT_OICR_TSYN_TX;
	else
		reg &= ~SXE2_PF_INT_OICR_TSYN_TX;
	sxe2_write_reg(hw, SXE2_PF_INT_OICR_ENABLE, reg);
}

void sxe2_hw_ptp_tsyn_event_switch(struct sxe2_hw *hw, bool on)
{
	u32 oicr_value;

	oicr_value = sxe2_read_reg(hw, SXE2_PF_INT_OICR_ENABLE);
	if (on)
		oicr_value |= SXE2_PF_INT_OICR_TSYN_EVENT;
	else
		oicr_value &= ~SXE2_PF_INT_OICR_TSYN_EVENT;
	sxe2_write_reg(hw, SXE2_PF_INT_OICR_ENABLE, oicr_value);
}

void sxe2_hw_ptp_aux_in_set(struct sxe2_hw *hw, u32 index, u32 value)
{
	sxe2_write_reg(hw, (u32)GLTSYN_AUXIN(index), value);
}

u64 sxe2_hw_ptp_get_event_second(struct sxe2_hw *hw, u32 index)
{
	u32 lo;
	u32 hi;

	lo = sxe2_read_reg(hw, (u32)GLTSYN_EVENT_S_L(index));
	hi = sxe2_read_reg(hw, (u32)GLTSYN_EVENT_S_H(index));

	return (((u64)(hi & GLTSYN_EVENT_S_H_MASK)) << 32) | lo;
}

u64 sxe2_hw_ptp_get_event_nanosecond(struct sxe2_hw *hw, u32 index)
{
	return sxe2_read_reg(hw, (u32)GLTSYN_EVENT_NS(index));
}

static bool sxe2_hw_ptp_tx_tstamp_valid(struct sxe2_hw *hw, u8 port_id, u32 index)
{
	u32 val;

	val = sxe2_read_reg(hw, (u32)PFP_CGM_TX_TSMEM(port_id, index / 32));
	if (!(val & BIT(index % 32)))
		return false;

	return true;
}

static bool sxe2_hw_ptp_mac_tx_tstamp_valid(struct sxe2_hw *hw, u8 phy_id, u32 index)
{
	u32 val;

	val = sxe2_read_reg(hw, PFP_CGM_MAC_TX_TSMEM(phy_id, index / 32));
	if (!(val & BIT(index % 32)))
		return false;

	return true;
}

#define SXE2_TSTAMP_TX_HI_SHIFT (24)
#define SXE2_TSTAMP_TX_LO_SHIFT (8)
bool sxe2_hw_ptp_tx_tstamp_read(struct sxe2_hw *hw, u8 port_id, u32 index,
				u64 *timestamp)
{
	u32 lo;
	u32 hi;

	if (!sxe2_hw_ptp_tx_tstamp_valid(hw, port_id, index))
		return false;

	hi = sxe2_read_reg(hw, (u32)PFP_CGM_TX_TXHI(port_id, index));
	lo = sxe2_read_reg(hw, (u32)PFP_CGM_TX_TXLO(port_id, index));

	*timestamp = ((u64)hi << SXE2_TSTAMP_TX_HI_SHIFT |
		      (u64)lo >> SXE2_TSTAMP_TX_LO_SHIFT);
	return true;
}

bool sxe2_hw_ptp_mac_tx_tstamp_read(struct sxe2_hw *hw, u8 phy_id, u8 index,
				    u64 *timestamp)
{
	u32 lo;
	u32 hi;

	if (!sxe2_hw_ptp_mac_tx_tstamp_valid(hw, phy_id, index))
		return false;

	lo = sxe2_read_reg(hw, PFP_CGM_MAC_TX_TXLO(phy_id, index));
	hi = sxe2_read_reg(hw, PFP_CGM_MAC_TX_TXHI(phy_id, index)) & 0x7F;
	*timestamp = ((u64)hi << 24 | (u64)lo >> 8);
	return true;
}

void sxe2_hw_ptp_tx_tstamp_discard(struct sxe2_hw *hw, u8 port_id, u32 index)
{
	u32 value = sxe2_read_reg(hw, (u32)PFP_CGM_TX_TSMEM(port_id, index / 32));

	value &= (u32)~BIT(index % 32);
	sxe2_write_reg(hw, (u32)PFP_CGM_TX_TSMEM(port_id, index / 32), value);
}

void sxe2_hw_ptp_mac_tx_tstamp_discard(struct sxe2_hw *hw, u8 phy_id, u32 index)
{
	u32 value = sxe2_read_reg(hw, PFP_CGM_MAC_TX_TSMEM(phy_id, index / 32));

	value &= (u32)(~(1ULL << (index % 32)));
	sxe2_write_reg(hw, PFP_CGM_MAC_TX_TSMEM(phy_id, index / 32), value);
}

void sxe2_hw_ptp_mac_tx_tstamp_clear_all(struct sxe2_hw *hw, u8 phy_id, u32 reg_idx)
{
	sxe2_write_reg(hw, PFP_CGM_MAC_TX_TSMEM(phy_id, reg_idx), 0);
}

bool sxe2_hw_ptp_acquire_1588_lock(struct sxe2_hw *hw)
{
	u32 value;

	value = sxe2_read_reg(hw, GLTSYN_SEM);
	value = value & GLTSYN_SEM_BUSY_M;
	return !(!!value);
}

void sxe2_hw_ptp_release_1588_lock(struct sxe2_hw *hw)
{
	sxe2_write_reg(hw, GLTSYN_SEM, 0);
}

void sxe2_hw_ptp_1588_timestamp_read(struct sxe2_hw *hw, u64 *second,
				     u64 *nanosecond)
{
	u32 sh_hi;
	u32 sh_lo;
	u32 sh_ns;
	u32 sh_ns2;

	sxe2_write_reg(hw, GLTSYN_CMD, GLTSYN_CMD_LATCHING_SHTIME);
	sxe2_write_reg(hw, GLTSYN_SYNC, GLTSYN_SYNC_EXEC | GLTSYN_SYNC_GEN_PULSE);
	sh_ns = sxe2_read_reg(hw, GLTSYN_SHTIME_NS);
	sh_hi = sxe2_read_reg(hw, GLTSYN_SHTIME_S_H);
	sh_lo = sxe2_read_reg(hw, GLTSYN_SHTIME_S_L);
	sh_ns2 = sxe2_read_reg(hw, GLTSYN_SHTIME_NS);

	if (sh_ns != sh_ns2) {
		sh_hi = sxe2_read_reg(hw, GLTSYN_SHTIME_S_H);
		sh_lo = sxe2_read_reg(hw, GLTSYN_SHTIME_S_L);
		sh_ns = sxe2_read_reg(hw, GLTSYN_SHTIME_NS);
	}
	*nanosecond = sh_ns;

	*second = (((u64)(sh_hi & 0xFFFF)) << 32) | sh_lo;
}

void sxe2_hw_ptp_1588_timestamp_write(struct sxe2_hw *hw, u64 second, u32 nanosecond)
{
	sxe2_write_reg(hw, GLTSYN_SHTIME_S_H, upper_32_bits(second));
	sxe2_write_reg(hw, GLTSYN_SHTIME_S_L, lower_32_bits(second));
	sxe2_write_reg(hw, GLTSYN_SHTIME_NS, nanosecond);
	sxe2_write_reg(hw, GLTSYN_SHTIME_SUBNS, 0);

	sxe2_write_reg(hw, GLTSYN_CMD, GLTSYN_CMD_INIT_TIME);
	sxe2_write_reg(hw, GLTSYN_SYNC, GLTSYN_SYNC_EXEC | GLTSYN_SYNC_GEN_PULSE);
}

void sxe2_hw_ptp_1588_clockout_write(struct sxe2_hw *hw, u32 index, u64 period,
				     u64 second, u64 nanosecond)
{
	sxe2_write_reg(hw, GLTSYN_CLKO(index), (u32)period);
	sxe2_write_reg(hw, GLTSYN_TGT_NS(index), (u32)nanosecond);

	sxe2_write_reg(hw, GLTSYN_TGT_S_L(index), (u32)second);
	sxe2_write_reg(hw, GLTSYN_TGT_S_H(index), second >> 32);
}

u32 sxe2_hw_ptp_auxout_get(struct sxe2_hw *hw, u32 index)
{
	return sxe2_read_reg(hw, GLTSYN_AUXOUT(index));
}

void sxe2_hw_ptp_auxout_set(struct sxe2_hw *hw, u32 index, u32 value)
{
	sxe2_write_reg(hw, GLTSYN_AUXOUT(index), value);
}

#define PTP_GLTSYN_SHADJ_NS_POS (0x3fffffff)
#define PTP_GLTSYN_SHADJ_NS_NEG (0x80000000)
void sxe2_hw_ptp_1588_timestamp_adjust(struct sxe2_hw *hw, u32 nanosecond, bool neg)
{
	sxe2_write_reg(hw, GLTSYN_SHADJ_SUBNS, 0);
	if (!neg)
		sxe2_write_reg(hw, GLTSYN_SHADJ_NS,
			       nanosecond & PTP_GLTSYN_SHADJ_NS_POS);
	else
		sxe2_write_reg(hw, GLTSYN_SHADJ_NS,
			       nanosecond | PTP_GLTSYN_SHADJ_NS_NEG);

	sxe2_write_reg(hw, GLTSYN_CMD, GLTSYN_CMD_ADJ_TIME);
	sxe2_write_reg(hw, GLTSYN_SYNC, GLTSYN_SYNC_EXEC | GLTSYN_SYNC_GEN_PULSE);
}

void sxe2_hw_ptp_1588_timestamp_adjust_at_time(struct sxe2_hw *hw, u32 nanosecond)
{
	sxe2_write_reg(hw, GLTSYN_SHADJ_SUBNS, 0);
	sxe2_write_reg(hw, GLTSYN_SHADJ_NS, nanosecond);
	sxe2_write_reg(hw, GLTSYN_CMD, GLTSYN_CMD_ADJ_TIME_AT_TIME);
	sxe2_write_reg(hw, GLTSYN_SYNC, GLTSYN_SYNC_EXEC | GLTSYN_SYNC_GEN_PULSE);
}

s32 sxe2_hw_ptp_stat_get(struct sxe2_hw *hw)
{
	return (s32)sxe2_read_reg(hw, GLTSYN_STAT);
}

#define SXE2_IPSEC_RX_SPI_TBL (0x1)
#define SXE2_IPSEC_RX_KEY_TBL (0x2)

void sxe2_hw_ipsec_tcam_clear(struct sxe2_hw *hw, u32 sa_index)
{
	u32 val = 0;

	sxe2_write_reg(hw, SXE2_IPSEC_RX_IPSIPID_ADDR, 0);

	sxe2_write_reg(hw, SXE2_IPSEC_RX_IPSSPI0_ADDR, 0);
	sxe2_write_reg(hw, SXE2_IPSEC_RX_IPSSPI0_ADDR,
		       0 ^ SXE2_IPSEC_RX_IPSSPI1_SPI_Y_MASK);

	val = (SXE2_IPSEC_RX_SPI_TBL << SXE2_IPSEC_RX_IPSIDX_TABLE_SHIFT) &
	      SXE2_IPSEC_RX_IPSIDX_TABLE_MASK;
	val &= ~(BIT(SXE2_IPSEC_RX_IPSIDX_VBI_SHIFT));
	val |= (sa_index << SXE2_IPSEC_RX_IPSIDX_SA_IDX_SHIFT) &
	       SXE2_IPSEC_RX_IPSIDX_SA_IDX_MASK;
	val |= SXE2_IPSEC_RX_IPSIDX_SWRITE_SHIFT;
	sxe2_write_reg(hw, SXE2_IPSEC_RX_IPSIDX_ADDR, val);
}

STATIC void sxe2_stat_update32(struct sxe2_hw *hw, u32 reg, u64 *prev_stat,
			       u64 *cur_stat, bool prev_stat_loaded)
{
	u32 new_data;

	new_data = sxe2_read_reg(hw, reg);

	if (new_data == BIT_ULL(32) - 1)
		goto l_end;

	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	*prev_stat = new_data;

l_end:
	return;
}

void sxe2_hw_pause_stats_update(struct sxe2_hw *hw, u8 port_idx, bool prev_loaded,
				struct sxe2_pause_stats *cur,
				struct sxe2_pause_stats *prev)
{
	u32 i;

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		sxe2_stat_update32(hw, SXE2_TXPFCXONFRAMES_LO(port_idx, i),
				   &prev->prio_xon_tx[i], &cur->prio_xon_tx[i],
				   prev_loaded);

		sxe2_stat_update32(hw, SXE2_TXPFCXOFFFRAMES_LO(port_idx, i),
				   &prev->prio_xoff_tx[i], &cur->prio_xoff_tx[i],
				   prev_loaded);

		sxe2_stat_update32(hw, SXE2_TXPFCXONTOXOFFFRAMES_LO(port_idx, i),
				   &prev->prio_xon_2_xoff[i],
				   &cur->prio_xon_2_xoff[i], prev_loaded);

		sxe2_stat_update32(hw, SXE2_RXPFCXONFRAMES_LO(port_idx, i),
				   &prev->prio_xon_rx[i], &cur->prio_xon_rx[i],
				   prev_loaded);

		sxe2_stat_update32(hw, SXE2_RXPFCXOFFFRAMES_LO(port_idx, i),
				   &prev->prio_xoff_rx[i], &cur->prio_xoff_rx[i],
				   prev_loaded);
	}

	sxe2_stat_update32(hw, SXE2_TXPAUSEXOFFFRAMES_LO(port_idx), &prev->tx_pause,
			   &cur->tx_pause, prev_loaded);

	sxe2_stat_update32(hw, SXE2_RXPAUSEXOFFFRAMES_LO(port_idx), &prev->rx_pause,
			   &cur->rx_pause, prev_loaded);
}
