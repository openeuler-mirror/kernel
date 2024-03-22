/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPGBEVF_REGS_H_
#define _RNPGBEVF_REGS_H_

enum NIC_MODE {
	MODE_NIC_MODE_2PORT_40G = 0,
	MODE_NIC_MODE_2PORT_10G = 1,
	MODE_NIC_MODE_4PORT_10G = 2,
	MODE_NIC_MODE_8PORT_10G = 3,
};

#define RNPGBE_DMA_RING_BASE 0x8000
#define RNPGBE_DMA_RX_DESC_TIMEOUT_TH 0x8000
#define RNPGBE_DMA_TX_DESC_FETCH_CTL 0x8004
#define RNPGBE_DMA_TX_FLOW_CTRL_TM 0x8008
#define RNPGBE_RING_BASE_N10 (0x8000)
#define RNPGBE_RING_BASE_N500 (0x1000)

#define RNPGBE_RING_OFFSET(i) (0x100 * (i))

#define RNPGBE_DMA_RX_START (0x10)
#define RNPGBE_DMA_RX_READY (0x14)
#define RNPGBE_DMA_TX_START (0x18)
#define RNPGBE_DMA_TX_READY (0x1c)
#define RNPGBE_DMA_INT_STAT (0x20)
#define RNPGBE_DMA_INT_MASK (0x24)
#define TX_INT_MASK (0x1 << 1)
#define RX_INT_MASK (0x1 << 0)
#define RNPGBE_DMA_INT_CLR (0x28)
#define RNPGBE_DMA_INT_TRIG (0x2c)
#define RNPGBE_DMA_REG_RX_DESC_BUF_BASE_ADDR_HI (0x30)
#define RNPGBE_DMA_REG_RX_DESC_BUF_BASE_ADDR_LO (0x34)
#define RNPGBE_DMA_REG_RX_DESC_BUF_LEN (0x38)
#define RNPGBE_DMA_REG_RX_DESC_BUF_HEAD (0x3c)
#define RNPGBE_DMA_REG_RX_DESC_BUF_TAIL (0x40)
#define RNPGBE_DMA_REG_RX_DESC_FETCH_CTRL (0x44)
#define RNPGBE_DMA_REG_RX_INT_DELAY_TIMER (0x48)
#define RNPGBE_DMA_REG_RX_INT_DELAY_PKTCNT (0x4c)
#define RNPGBE_DMA_REG_RX_ARB_DEF_LVL (0x50)
#define PCI_DMA_REG_RX_DESC_TIMEOUT_TH (0x54)
#define PCI_DMA_REG_RX_SCATTER_LENGTH (0x58)
#define RNPGBE_DMA_REG_TX_DESC_BUF_BASE_ADDR_HI (0x60)
#define RNPGBE_DMA_REG_TX_DESC_BUF_BASE_ADDR_LO (0x64)
#define RNPGBE_DMA_REG_TX_DESC_BUF_LEN (0x68)
#define RNPGBE_DMA_REG_TX_DESC_BUF_HEAD (0x6c)
#define RNPGBE_DMA_REG_TX_DESC_BUF_TAIL (0x70)
#define RNPGBE_DMA_REG_TX_DESC_FETCH_CTRL (0x74)
#define RNPGBE_DMA_REG_TX_INT_DELAY_TIMER (0x78)
#define RNPGBE_DMA_REG_TX_INT_DELAY_PKTCNT (0x7c)
#define RNPGBE_DMA_REG_TX_ARB_DEF_LVL (0x80)
#define RNPGBE_DMA_REG_TX_FLOW_CTRL_TH (0x84)
#define RNPGBE_DMA_REG_TX_FLOW_CTRL_TM (0x88)

#define VEB_TBL_CNTS 64
#define RNPGBE_DMA_PORT_VBE_MAC_LO_TBL_N10(port, vf)                           \
	(0x80A0 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VBE_MAC_HI_TBL_N10(port, vf)                           \
	(0x80B0 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VEB_VID_TBL_N10(port, vf)                              \
	(0x80C0 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VEB_VF_RING_TBL_N10(port, vf)                          \
	(0x80D0 + 4 * (port) +                                                 \
	 0x100 * (vf))

#define RNPGBE_DMA_PORT_VBE_MAC_LO_TBL_N500 (0x10c0)
#define RNPGBE_DMA_PORT_VBE_MAC_HI_TBL_N500 (0x10c4)
#define RNPGBE_DMA_PORT_VEB_VID_TBL_N500 (0x10c8)
#define RNPGBE_DMA_PORT_VEB_VF_RING_TBL_N500 (0x10cc)

#define RNPGBE_DMA_STATS_DMA_TO_MAC (0x1a0)
#define RNPGBE_DMA_STATS_DMA_TO_SWITCH (0x1a4)
#define RNPGBE_DMA_STATS_MAC_TO_MAC (0x1b0)
#define RNPGBE_DMA_STATS_SWITCH_TO_SWITCH (0x1a4)
#define RNPGBE_DMA_STATS_MAC_TO_DMA (0x1a8)
#define RNPGBE_DMA_STATS_SWITCH_TO_DMA (0x1ac)

#define RNPVF500_VEB_VFMPRC(i) (0x4018 + 0x100 * (i))
#define VF_NUM_REG 0xa3000
#define VF_NUM_REG_N10 0x75f000
#define VF_NUM_REG_N500 (0xe000)
/* 8bit: 7:vf_actiove 6:fun0/fun1 [5:0]:vf_num */
#define VF_NUM(vfnum, fun) ((1 << 7) | (((fun) & 0x1) << 6) | ((vfnum) & 0x3f))
#define PF_NUM(fun) (((fun) & 0x1) << 6)

#define RING_VECTOR(n) (0x4000 + 0x04 * (n))

static inline unsigned int p_rnpgbevf_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	printk(KERN_DEBUG " rd-reg: %p ==> 0x%08x\n", reg, v);
	return v;
}

#define p_rnpgbevf_wr_reg(reg, val)                                            \
	do {                                                                   \
		printk(KERN_DEBUG " wr-reg: %p <== 0x%08x \t#%-4d %s\n", (reg), (val),    \
		       __LINE__, __FILE__);                                    \
		iowrite32((val), (void *)(reg));                               \
	} while (0)

#ifdef IO_PRINT
#define rnpgbevf_rd_reg(reg) p_rnpgbevf_rd_reg(reg)
#define rnpgbevf_wr_reg(reg, val) p_rnpgbevf_wr_reg(reg, val)
#else
#define rnpgbevf_rd_reg(reg) readl((void *)(reg))
#define rnpgbevf_wr_reg(reg, val) writel((val), (void *)(reg))
#endif

#ifdef CONFIG_RNPGBE_MBX_DEBUG
#define mbx_rd32(hw, reg) p_rnpgbevf_rd_reg((hw)->hw_addr + (reg))
#define mbx_wr32(hw, reg, val) p_rnpgbevf_wr_reg((hw)->hw_addr + (reg), (val))
#else
#define mbx_rd32(hw, reg) rnpgbevf_rd_reg((hw)->hw_addr + (reg))
#define mbx_wr32(hw, reg, val) rnpgbevf_wr_reg((hw)->hw_addr + (reg), (val))
#endif

#define rd32(hw, off) rnpgbevf_rd_reg((hw)->hw_addr + (off))
#define wr32(hw, off, val) rnpgbevf_wr_reg((hw)->hw_addr + (off), (val))

#define ring_rd32(ring, off) rnpgbevf_rd_reg((ring)->ring_addr + (off))
#define ring_wr32(ring, off, val)                                              \
	rnpgbevf_wr_reg((ring)->ring_addr + (off), (val))

#define pwr32(hw, reg, val)                                                    \
	do {                                                                   \
		printk(KERN_DEBUG " wr-reg: %p <== 0x%08x \t#%-4d %s\n",                  \
		       (hw)->hw_addr + (reg), (val), __LINE__, __FILE__);      \
		iowrite32((val), (hw)->hw_addr + (reg));                       \
	} while (0)

#ifdef DEBUG
#define hw_dbg(hw, fmt, args...) printk(KERN_DEBUG "hw-dbg : " fmt, ##args)
#else
#define hw_dbg(hw, fmt, args...)
#endif

#endif /* _RNPGBEVF_REGS_H_ */
