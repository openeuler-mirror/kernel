/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPGBE_COMMON_H_
#define _RNPGBE_COMMON_H_

#include <linux/skbuff.h>
#include <linux/highmem.h>
#include "rnpgbe_type.h"
#include "rnpgbe.h"
#include "rnpgbe_regs.h"

struct rnpgbe_adapter;

#define TRACE() printk(KERN_DEBUG "==[ %s %d ] ==\n", __func__, __LINE__)

#ifdef CONFIG_RNP_RX_DEBUG
#define rx_debug_printk printk
#define rx_buf_dump buf_dump
#define rx_dbg(fmt, args...)                                                   \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define rx_debug_printk(fmt, args...)
#define rx_buf_dump(a, b, c)
#define rx_dbg(fmt, args...)
#endif /* CONFIG_RNP_RX_DEBUG */

#ifdef CONFIG_RNP_TX_DEBUG
#define desc_hex_dump(msg, buf, len)                                           \
	print_hex_dump(KERN_WARNING, msg, DUMP_PREFIX_OFFSET, 16, 1, (buf),    \
		       (len), false)

#define tx_dbg(fmt, args...)                                                   \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define desc_hex_dump(msg, buf, len)
#define tx_dbg(fmt, args...)
#endif /* CONFIG_RNP_TX_DEBUG */

#ifdef DEBUG
#define dbg(fmt, args...)                                                      \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define dbg(fmt, args...)
#endif

#ifdef CONFIG_RNP_VF_DEBUG
#define vf_dbg(fmt, args...)                                                   \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define vf_dbg(fmt, args...)
#endif

/* ================= registers  read/write helper ===== */
#define p_rnpgbe_wr_reg(reg, val)                                              \
	do {                                                                   \
		printk(KERN_DEBUG " wr-reg: %p <== 0x%08x \t#%-4d %s\n",       \
		       (reg), (val), __LINE__, __FILE__);                      \
		iowrite32((val), (void *)(reg));                               \
	} while (0)

static inline unsigned int prnpgbe_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	printk(KERN_DEBUG "  %p => 0x%08x\n", reg, v);
	return v;
}

#ifdef IO_PRINT
static inline unsigned int rnpgbe_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	dbg(" rd-reg: %p <== 0x%08x\n", reg, v);
	return v;
}

#define rnpgbe_wr_reg(reg, val)                                                \
	do {                                                                   \
		dbg(" wr-reg: %p <== 0x%08x \t#%-4d %s\n", (reg), (val),       \
		    __LINE__, __FILE__);                                       \
		iowrite32((val), (void *)(reg));                               \
	} while (0)
#else
#define rnpgbe_rd_reg(reg) readl((void *)(reg))
#define rnpgbe_wr_reg(reg, val) writel((val), (void *)(reg))
#endif

#define rd32(hw, off) rnpgbe_rd_reg((hw)->hw_addr + (off))
#define wr32(hw, off, val) rnpgbe_wr_reg((hw)->hw_addr + (off), (val))

#define nic_rd32(nic, off) rnpgbe_rd_reg((nic)->nic_base_addr + (off))
#define nic_wr32(nic, off, val)                                                \
	rnpgbe_wr_reg((nic)->nic_base_addr + (off), (val))

#define dma_rd32(dma, off) rnpgbe_rd_reg((dma)->dma_base_addr + (off))
#define dma_wr32(dma, off, val)                                                \
	rnpgbe_wr_reg((dma)->dma_base_addr + (off), (val))

#define dma_ring_rd32(dma, off) rnpgbe_rd_reg((dma)->dma_ring_addr + (off))
#define dma_ring_wr32(dma, off, val)                                           \
	rnpgbe_wr_reg((dma)->dma_ring_addr + (off), (val))

#define eth_rd32(eth, off) rnpgbe_rd_reg((eth)->eth_base_addr + (off))
#define eth_wr32(eth, off, val)                                                \
	rnpgbe_wr_reg((eth)->eth_base_addr + (off), (val))

#define mac_rd32(mac, off) rnpgbe_rd_reg((mac)->mac_addr + (off))
#define mac_wr32(mac, off, val) rnpgbe_wr_reg((mac)->mac_addr + (off), (val))
#ifdef debug_ring
static inline unsigned int rnpgbe_rd_reg_1(int ring, u32 off, void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	printk(KERN_DEBUG "%d rd-reg: %x <== 0x%08x\n", ring, off, v);
	return v;
}

#define ring_rd32(ring, off)                                                   \
	rnpgbe_rd_reg_1(ring->rnpgbe_queue_idx, off, ring->ring_addr + (off))
#define ring_wr32(ring, off, val)                                              \
	rnpgbe_wr_reg(ring->ring_addr + (off), (val))
#else
#define ring_rd32(ring, off) rnpgbe_rd_reg(ring->ring_addr + (off))
#define ring_wr32(ring, off, val)                                              \
	rnpgbe_wr_reg(ring->ring_addr + (off), (val))
#endif

#define pwr32(hw, off, val) p_rnpgbe_wr_reg((hw)->hw_addr + (off), (val))

#define rnpgbe_mbx_rd(hw, off) rnpgbe_rd_reg((hw)->ring_msix_base + (off))
#define rnpgbe_mbx_wr(hw, off, val)                                            \
	rnpgbe_wr_reg((hw)->ring_msix_base + (off), val)

#define rnpgbe_set_reg_bit(hw, reg_def, bit)                                   \
	do {                                                                   \
		u32 reg = reg_def;                                             \
		u32 value = rd32(hw, reg);                                     \
		dbg("before set  %x %x\n", reg, value);                        \
		value |= (0x01 << (bit));                                        \
		dbg("after set %x %x\n", reg, value);                          \
		wr32(hw, reg, value);                                          \
	} while (0)

#define rnpgbe_clr_reg_bit(hw, reg_def, bit)                                   \
	do {                                                                   \
		u32 reg = reg_def;                                             \
		u32 value = rd32(hw, reg);                                     \
		dbg("before clr %x %x\n", reg, value);                         \
		value &= (~(0x01 << (bit)));                                     \
		dbg("after clr %x %x\n", reg, value);                          \
		wr32(hw, reg, value);                                          \
	} while (0)

#define rnpgbe_vlan_filter_on(hw)                                              \
	rnpgbe_set_reg_bit(hw, RNP_ETH_VLAN_FILTER_ENABLE, 30)
#define rnpgbe_vlan_filter_off(hw)                                             \
	rnpgbe_clr_reg_bit(hw, RNP_ETH_VLAN_FILTER_ENABLE, 30)

#define DPRINTK(nlevel, klevel, fmt, args...)                                  \
	((NETIF_MSG_##nlevel & adapter->msg_enable) ?                          \
		 (void)(netdev_printk(KERN_##klevel, adapter->netdev, fmt,     \
				      ##args)) :                               \
		 NULL)

/* ==== log helper === */
#ifdef HW_DEBUG
#define hw_dbg(hw, fmt, args...) printk(KERN_DEBUG "hw-dbg : " fmt, ##args)
#define eth_dbg(eth, fmt, args...) printk(KERN_DEBUG "hw-dbg : " fmt, ##args)
#else
#define hw_dbg(hw, fmt, args...)
#define eth_dbg(hw, fmt, args...)
#endif

#ifdef RNP_DEBUG_OPEN
#define rnpgbe_dbg(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#else
#define rnpgbe_dbg(fmt, args...)
#endif
#define rnpgbe_info(fmt, args...) printk(KERN_DEBUG "rnp-info: " fmt, ##args)
#define rnpgbe_warn(fmt, args...) printk(KERN_DEBUG "rnp-warn: " fmt, ##args)
#define rnpgbe_err(fmt, args...) printk(KERN_ERR "rnp-err : " fmt, ##args)

#define e_info(msglvl, format, arg...)                                         \
	netif_info(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_err(msglvl, format, arg...)                                          \
	netif_err(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_warn(msglvl, format, arg...)                                         \
	netif_warn(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_crit(msglvl, format, arg...)                                         \
	netif_crit(adapter, msglvl, adapter->netdev, format, ##arg)

#define e_dev_info(format, arg...) dev_info(&adapter->pdev->dev, format, ##arg)
#define e_dev_warn(format, arg...) dev_warn(&adapter->pdev->dev, format, ##arg)
#define e_dev_err(format, arg...) dev_err(&adapter->pdev->dev, format, ##arg)

#ifdef CONFIG_RNP_TX_DEBUG
static inline void buf_dump_line(const char *msg, int line, void *buf, int len)
{
	int i, offset = 0;
	int msg_len = 1024;
	u8 msg_buf[1024];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d line:%d buf:%p==\n000: ", msg, len, line,
			   buf);

	for (i = 0; i < len; ++i) {
		if (i != 0 && (i % 16) == 0 && (offset >= (1024 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
		offset += snprintf(msg_buf + offset, msg_len, "%02x ", ptr[i]);
	}

	offset += snprintf(msg_buf + offset, msg_len, "\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}
#else
#define buf_dump_line(msg, line, buf, len)
#endif

static inline __le64 build_ctob(u32 vlan_cmd, u32 mac_ip_len, u32 size)
{
	return cpu_to_le64(((u64)vlan_cmd << 32) | ((u64)mac_ip_len << 16) |
			   ((u64)size));
}

static inline void buf_dump(const char *msg, void *buf, int len)
{
	int i, offset = 0;
	int msg_len = 1024;
	char msg_buf[1024];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d ==\n000: ", msg, len);

	for (i = 0; i < len; ++i) {
		if (i != 0 && (i % 16) == 0 && (offset >= (1024 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
		offset += snprintf(msg_buf + offset, msg_len, "%02x ", ptr[i]);
	}

	offset += snprintf(msg_buf + offset, msg_len, "\n=== done ==\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}

enum RNP_LOG_EVT {
	LOG_MBX_IN,
	LOG_MBX_OUT,
	LOG_MBX_MSG_IN,
	LOG_MBX_MSG_OUT,
	LOG_LINK_EVENT,
	LOG_ADPT_STAT,
	LOG_MBX_ABLI,
	LOG_MBX_LINK_STAT,
	LOG_MBX_IFUP_DOWN,
	LOG_MBX_LOCK,
	LOG_ETHTOOL,
	LOG_PHY,

};

#define MII_BUSY 0x00000001
#define MII_WRITE 0x00000002
#define MII_DATA_MASK GENMASK(15, 0)

extern unsigned int rnpgbe_loglevel;

#define rnpgbe_logd(evt, fmt, args...)                                         \
	do {                                                                   \
		if (BIT(evt) & rnpgbe_loglevel) {                              \
			printk(KERN_DEBUG fmt, ##args);                        \
		}                                                              \
	} while (0)

#endif /* RNPGBE_COMMON */
