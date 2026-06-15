/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#ifndef _RNPM_COMMON_H_
#define _RNPM_COMMON_H_
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/highmem.h>
#include "rnpm_type.h"
#include "rnpm.h"
#include "rnpm_regs.h"

struct rnpm_adapter;
#define ADAPTER_TO_DEV(adapter) (&(adapter)->pdev->dev)
#define HW_TO_DEV(hw) (&(hw)->pdev->dev)

void rnpm_free_msix_vectors(struct rnpm_adapter *adapter);
int rnpm_acquire_msix_vectors(struct rnpm_adapter *adapter, int vectors);
s32 rnpm_init_ops_generic(struct rnpm_hw *hw);
s32 rnpm_init_hw_generic(struct rnpm_hw *hw);
void rnpm_reset_msix_table_generic(struct rnpm_hw *hw);
s32 rnpm_start_hw_generic(struct rnpm_hw *hw);
s32 rnpm_clear_hw_cntrs_generic(struct rnpm_hw *hw);
s32 rnpm_get_mac_addr_generic(struct rnpm_hw *hw, u8 *mac_addr);
s32 rnpm_get_permtion_mac_addr(struct rnpm_hw *hw, u8 *mac_addr);
enum rnpm_bus_width rnpm_convert_bus_width(u16 link_status);
enum rnpm_bus_speed rnpm_convert_bus_speed(u16 link_status);
int rnpm_get_cpu_l3_cache_size(void);
s32 rnpm_set_rar_generic(struct rnpm_hw *hw, u32 index, u8 *addr, u32 vmdq,
			 u32 enable_addr);
s32 rnpm_set_rar_mac(struct rnpm_hw *hw, u32 index, u8 *addr, u32 vmdq,
		     u32 port);
s32 rnpm_clear_rar_generic(struct rnpm_hw *hw, u32 index);
s32 rnpm_clear_rar_mac(struct rnpm_hw *hw, u32 index, u32 port);
s32 rnpm_init_rx_addrs_generic(struct rnpm_hw *hw);
s32 rnpm_update_mc_addr_list_generic(struct rnpm_hw *hw,
				     struct net_device *netdev);
s32 rnpm_update_mutiport_mc_addr_list_generic(struct rnpm_hw *hw,
					      struct net_device *netdev);
s32 rnpm_enable_mc_generic(struct rnpm_hw *hw);
s32 rnpm_disable_mc_generic(struct rnpm_hw *hw);
s32 rnpm_fc_enable_generic(struct rnpm_hw *hw);
s32 rnpm_setup_fc(struct rnpm_hw *hw);
bool rnpm_device_supports_autoneg_fc(struct rnpm_hw *hw);
void rnpm_fc_autoneg(struct rnpm_hw *hw);
s32 rnpm_get_san_mac_addr_generic(struct rnpm_hw *hw, u8 *san_mac_addr);
s32 rnpm_set_vmdq_generic(struct rnpm_hw *hw, u32 rar, u32 vmdq);
s32 rnpm_set_vmdq_san_mac_generic(struct rnpm_hw *hw, u32 vmdq);
s32 rnpm_clear_vmdq_generic(struct rnpm_hw *hw, u32 rar, u32 vmdq);
s32 rnpm_init_uta_tables_generic(struct rnpm_hw *hw);
s32 rnpm_set_vfta_generic(struct rnpm_hw *hw, u32 vlan, u32 vind,
			  bool vlan_on);
s32 rnpm_set_vfta_mac_generic(struct rnpm_hw *hw, u32 vlan, u32 vind,
			      bool vlan_on);
void rnpm_ncsi_set_mc_mta_generic(struct rnpm_hw *hw);
void rnpm_ncsi_set_vfta_mac_generic(struct rnpm_hw *hw);
void rnpm_ncsi_set_uc_addr_generic(struct rnpm_hw *hw);

s32 rnpm_clear_vfta_generic(struct rnpm_hw *hw);
s32 rnpm_check_mac_link_generic(struct rnpm_hw *hw, rnpm_link_speed *speed,
				bool *link_up,
				bool link_up_wait_to_complete);
s32 rnpm_get_thermal_sensor_data_generic(struct rnpm_hw *hw);
s32 rnpm_init_thermal_sensor_thresh_generic(struct rnpm_hw *hw);
int rnpm_priv_err_mask_set(struct rnpm_adapter *adapter, bool on);

#ifdef IO_PRINT
static inline unsigned int rnpm_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	pr_debug("rd-reg: %p ==> 0x%08x\n", reg, v);
	return v;
}

#define rnpm_wr_reg(reg, val)                                         \
	do {                                                          \
		pr_debug("wr-reg: %p <== 0x%08x \t#%-4d %s\n", (reg), \
			 (val), __LINE__, __FILE__);                  \
		iowrite32((val), (void *)(reg));                      \
	} while (0)
#else
#define rnpm_rd_reg(reg) readl((void *)(reg))
#define rnpm_wr_reg(reg, val) writel((val), (void *)(reg))
#endif

#define rd32(hw, off) rnpm_rd_reg((hw)->hw_addr + (off))
#define wr32(hw, off, val) rnpm_wr_reg((hw)->hw_addr + (off), (val))

#define ring_rd32(ring, off) rnpm_rd_reg((ring)->dma_hw_addr + (off))
#define ring_wr32(ring, off, val) \
	rnpm_wr_reg((ring)->dma_hw_addr + (off), val)

#define rnpm_mbx_rd(hw, off) rnpm_rd_reg((hw)->ring_msix_base + (off))
#define rnpm_mbx_wr(hw, off, val) \
	rnpm_wr_reg((hw)->ring_msix_base + (off), val)

static inline void hw_queue_strip_rx_vlan(struct rnpm_hw *hw, u8 ring_num,
					  bool enable)
{
	u32 reg = RNPM_ETH_VLAN_VME_REG(ring_num / 32);
	u32 offset = ring_num % 32;
	u32 data = rd32(hw, reg);

	if (enable)
		data |= (1 << offset);
	else
		data &= ~(1 << offset);
	wr32(hw, reg, data);
}

#define rnpm_set_reg_bit(hw, reg_def, bit) \
	do {                               \
		u32 reg = reg_def;         \
		u32 value = rd32(hw, reg); \
		value |= (0x01 << (bit));    \
		wr32(hw, reg, value);      \
	} while (0)

#define rnpm_clr_reg_bit(hw, reg_def, bit) \
	do {                               \
		u32 reg = reg_def;         \
		u32 value = rd32(hw, reg); \
		value &= (~(0x01 << (bit))); \
		wr32(hw, reg, value);      \
	} while (0)

#define rnpm_vlan_filter_on(hw) \
	rnpm_set_reg_bit(hw, RNPM_ETH_VLAN_FILTER_ENABLE, 30)
#define rnpm_vlan_filter_off(hw) \
	rnpm_clr_reg_bit(hw, RNPM_ETH_VLAN_FILTER_ENABLE, 30)

#define TRACE()                                                      \
	dev_info(&hw->pdev->dev, "rnpm trace:[ %s %d ]\n", __func__, \
		 __LINE__)

#define rnpm_skb_dump(skb, full_pkt)

extern unsigned int cpu_offset;

static inline u64 rnpm_recalculate_err_pkts(u64 now, u64 *init,
					    bool is_u64)
{
	u64 data = 0;

	if (now >= *init)
		data = now - *init;
	else
		data = is_u64 ? (u64)-1 - *init + now :
				(u32)-1 - *init + now;
	*init = now;
	return data;
}

static inline u32 rnpm_vid_crc32_le(u16 vid_le)
{
	u8 *data = (unsigned char *)&vid_le;
	u8 data_byte = 0;
	u32 crc = ~0x0;
	u32 temp = 0;
	int i, bits;
#define RNPM_VLAN_VID_MASK (0x0fff)

	bits = get_bitmask_order(RNPM_VLAN_VID_MASK);
	for (i = 0; i < bits; i++) {
		if ((i % 8) == 0)
			data_byte = data[i / 8];

		temp = ((crc & 1) ^ data_byte) & 1;
		crc >>= 1;
		data_byte >>= 1;

		if (temp)
			crc ^= 0xedb88320;
	}

	return crc;
}

#endif /* RNPM_COMMON */
