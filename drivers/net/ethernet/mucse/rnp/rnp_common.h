/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2025 Mucse Corporation. */

#ifndef _RNP_COMMON_H_
#define _RNP_COMMON_H_

#include <linux/skbuff.h>
#include <linux/highmem.h>
#include "rnp_type.h"
#include "rnp.h"
#include "rnp_regs.h"

struct rnp_adapter;
#define ADAPTER_TO_DEV(adapter) (&(adapter)->pdev->dev)
#define HW_TO_DEV(hw) (&(hw)->pdev->dev)

#define TRACE() pr_debug("==[ %s %d ] ==\n", __func__, __LINE__)

#define rnp_skb_dump(skb, full_pkt)

int rnp_acquire_msix_vectors(struct rnp_adapter *adapter, int vectors);

//================= registers  read/write helper =====
#define p_rnp_wr_reg(reg, val)                                           \
	do {                                                             \
		pr_debug(" wr-reg: %p <== 0x%08x \t#%-4d %s\n", \
		       (reg), (val), __LINE__, __FILE__);                \
		iowrite32((val), (void *)(reg));                         \
	} while (0)

static inline unsigned int prnp_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	pr_debug("  %p => 0x%08x\n", reg, v);
	return v;
}

#define rnp_rd_reg(reg) readl(reg)
#define rnp_wr_reg(reg, val) writel(val, reg)

#define rd32(hw, off) rnp_rd_reg((hw)->hw_addr + (off))
#define wr32(hw, off, val) rnp_wr_reg((hw)->hw_addr + (off), (val))

#define nic_rd32(nic, off) rnp_rd_reg((nic)->nic_base_addr + (off))
#define nic_wr32(nic, off, val) rnp_wr_reg((nic)->nic_base_addr + (off), (val))

#define dma_rd32(dma, off) rnp_rd_reg((dma)->dma_base_addr + (off))
#define dma_wr32(dma, off, val) rnp_wr_reg((dma)->dma_base_addr + (off), (val))

#define dma_ring_rd32(dma, off) rnp_rd_reg((dma)->dma_ring_addr + (off))
#define dma_ring_wr32(dma, off, val) \
	rnp_wr_reg((dma)->dma_ring_addr + (off), (val))

#define eth_rd32(eth, off) rnp_rd_reg((eth)->eth_base_addr + (off))
#define eth_wr32(eth, off, val) rnp_wr_reg((eth)->eth_base_addr + (off), (val))

#define mac_rd32(mac, off) rnp_rd_reg((mac)->mac_addr + (off))
#define mac_wr32(mac, off, val) rnp_wr_reg((mac)->mac_addr + (off), (val))
#ifdef debug_ring
static inline unsigned int rnp_rd_reg_1(int ring, u32 off, void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	pr_debug("%d rd-reg: %x <== 0x%08x\n", ring, off, v);
	return v;
}

#define ring_rd32(ring, off) \
	rnp_rd_reg_1(ring->rnp_queue_idx, off, (ring)->ring_addr + (off))
#define ring_wr32(ring, off, val) rnp_wr_reg((ring)->ring_addr + (off), (val))
#else
#define ring_rd32(ring, off) rnp_rd_reg((ring)->ring_addr + (off))
#define ring_wr32(ring, off, val) rnp_wr_reg((ring)->ring_addr + (off), (val))
#endif

#define pwr32(hw, off, val) p_rnp_wr_reg((hw)->hw_addr + (off), (val))

#define rnp_mbx_rd(hw, off) rnp_rd_reg((hw)->ring_msix_base + (off))
#define rnp_mbx_wr(hw, off, val) rnp_wr_reg((hw)->ring_msix_base + (off), val)

static inline void hw_queue_strip_rx_vlan(struct rnp_hw *hw, u8 ring_num,
					  bool enable)
{
	u32 reg = RNP_ETH_VLAN_VME_REG(ring_num / 32);
	u32 offset = ring_num % 32;
	u32 data = rd32(hw, reg);

	if (enable == true)
		data |= (1 << offset);
	else
		data &= ~(1 << offset);
	wr32(hw, reg, data);
}

#define rnp_set_reg_bit(hw, reg_def, bit)               \
	do {                                            \
		u32 reg = reg_def;                      \
		u32 value = rd32(hw, reg);              \
		pr_debug("before set  %x %x\n", reg, value); \
		value |= (0x01 << bit);                 \
		pr_debug("after set %x %x\n", reg, value);   \
		wr32(hw, reg, value);                   \
	} while (0)

#define rnp_clr_reg_bit(hw, reg_def, bit)              \
	do {                                           \
		u32 reg = reg_def;                     \
		u32 value = rd32(hw, reg);             \
		pr_debug("before clr %x %x\n", reg, value); \
		value &= (~(0x01 << bit));             \
		pr_debug("after clr %x %x\n", reg, value);  \
		wr32(hw, reg, value);                  \
	} while (0)

#define rnp_vlan_filter_on(hw) \
	rnp_set_reg_bit(hw, RNP_ETH_VLAN_FILTER_ENABLE, 30)
#define rnp_vlan_filter_off(hw) \
	rnp_clr_reg_bit(hw, RNP_ETH_VLAN_FILTER_ENABLE, 30)

static inline __le64 build_ctob(u32 vlan_cmd, u32 mac_ip_len, u32 size)
{
	return cpu_to_le64(((u64)vlan_cmd << 32) | ((u64)mac_ip_len << 16) |
			   ((u64)size));
}

#define MII_BUSY 0x00000001
#define MII_WRITE 0x00000002
#define MII_DATA_MASK GENMASK(15, 0)

extern unsigned int cpu_offset;

int pci_device_check_offline(struct pci_dev *pdev);
#endif /* RNP_COMMON */
