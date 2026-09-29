/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_HW_N20_H_
#define _MCE_HW_N20_H_

#define N20_VLAN_MAX_STRIP_CNT 2
#define N20_VLAN_DEFAULT_STRIP_CNT 1

/* ==============================N20 invariants start ====================*/
#define N20_MAX_Q_CNT 512

#define N20_VF_MAX_QUEUE_CNT 64
#define N20_VF_DEFAULT_QUEUE_CNT 4

/* TODO: in FPGA, soc must modify this */
#define N20_PF_CNT 1
#define N20_VF_CNT (hw->func_caps.common_cap.max_vfs)
#define N20_RSS_PF_TABLE_SIZE 512
#define N20_MAX_RING_CNT N20_RSS_PF_TABLE_SIZE
#define N20_RSS_VF_TABLE_SIZE (hw->vf_max_ring)
#define N20_RSS_HASH_KEY_SIZE (13 * 4)
#define N20_MAX_NTUPLE_CNT MCE_ACL_MAX_TUPLE5_CNT
#define N20_MAX_ETYPE_CNT MCE_MAX_ETYPE_CNT
#define N20_MAX_FDIR_CNT \
	(N20_MAX_NTUPLE_CNT + (N20_VF_CNT + N20_PF_CNT) * N20_MAX_ETYPE_CNT)
#define N20_LOC_FDIR_CNT \
	(N20_MAX_NTUPLE_CNT + (pf->num_vfs + N20_PF_CNT) * N20_MAX_ETYPE_CNT)
#define N20_MBOX_IRQ_BASE 0
#define N20_NUM_MBOX_IRQS 1
#define N20_RDMA_IRQ_BASE (N20_MAX_Q_CNT + N20_NUM_MBOX_IRQS)
#define N20_NUM_RDMA_IRQS 2
#define N20_QVEC_IRQ_BASE 1
#define N20_MAX_IRQS (N20_MAX_Q_CNT + N20_NUM_MBOX_IRQS + N20_NUM_RDMA_IRQS)
#define N20_VAL_RX_TIMEOUT 100000 /* 100ms */
#define N20_USECSTOCOUNT 500
#define N20_FIFO_PROG_CNT 8
#define N20_FIFO_TAL_DEEP 8192
#define N20_RESEVER 512
/* vf num start from 4 */
#define N20_VEB_MAX_VF_MACVLAN_NUMS MCE_VEB_MAX_VF_MACVLAN_NUMS

/* the vf max entries is 512, setup 32 for fpga debug */
#define N20_VEB_MAX_ENTRIES 512
/* VEB invariants*/
#define N20_VEB_BCMC_ADDR_ENTRY_OFF (N20_VEB_MAX_ENTRIES - 1)
#define N20_VEB_VF_ADDR_ENTRY_OFF (N20_VEB_BCMC_ADDR_ENTRY_OFF - N20_VF_CNT)
#define N20_VEB_PF_ADDR_ENTRY_OFF (N20_VEB_VF_ADDR_ENTRY_OFF - 1)
#define N20_VEB_PF_DEFAULT_ADDR_ENTRY N20_VEB_PF_ADDR_ENTRY_OFF
/* one vf support max macvlan nums */
#define N20_VEB_MACVLAN_ADDR_ENTRY_OFF   \
	(N20_VEB_PF_DEFAULT_ADDR_ENTRY - \
	 N20_VF_CNT * N20_VEB_MAX_VF_MACVLAN_NUMS)

#define MODIFY_BITFIELD(reg, val, width, offset)                  \
	(reg = (((reg) & (~((~((~(0x0)) << (width))) << (offset)))) | \
		(((val) & (~((~0x0) << (width)))) << (offset))))

/* MAC + PCS reg */
#define N20_CE_REG_BASE (0x60000)
/* SOC reg offset */
#define _SOC_F_(off) (N20_CE_REG_BASE + 0x6800 + (off))
#define N20_MAC_INT_STAT(i) _SOC_F_(0x0100 + (i) * 0x4)
#define N20_MAC_INT_MASK(i) _SOC_F_(0x0120 + (i) * 0x4)
#define N20_MAC_INT_CLR(i) _SOC_F_(0x0140 + (i) * 0x4)

/* MAC reg offset */
#define _MAC_F_(off) (N20_CE_REG_BASE + 0x4000 + (off))

#define N20_M_CFG _MAC_F_(0x00)
#define F_M_CFG_RCLRC BIT(24)
#define F_M_MAC_RATE_100G BIT(0)
#define F_M_LP_EN BIT(3)
#define F_M_TX_PARITY_EN BIT(4)
#define F_MTRUNCATE_EN BIT(5)
#define F_M_CFG_JUMBO_EN BIT(6)
#define F_M_QTAG_EN BIT(7)
#define F_M_DB_QTAG_EN BIT(8)
#define F_M_PAUSE_EN BIT(9)
#define F_M_PAUSE_STOP_EN BIT(10)
#define F_M_PFC_EN_TX BIT(11)
#define F_M_PFC_EN_RX BIT(12)
#define F_M_DIC_EN BIT(13)
#define F_M_STPAD_EN BIT(14)
#define F_M_STCRC_EN BIT(15)
#define F_M_IF_MODE_EN BIT(16)
#define F_M_IPI_MODE_EN BIT(17)
#define F_M_TX_FIFO_RST_EN BIT(18)
#define F_M_RX_FIFO_RST_EN BIT(19)
#define F_M_PAU_DISCARD BIT(20)
#define F_M_LPI_REQ_VALID BIT(21)
#define F_M_PAU_TIMER_PIN BIT(22)
#define F_M_RD_CLR_EN BIT(24)
#define F_M_UNI_DA_FILTER_EN BIT(25)
#define F_M_TX_EN BIT(26)
#define F_M_RX_EN BIT(27)
#define F_M_BYPASS_PTP_TIMER_EN BIT(28)

#define N20_MAC_SA_HI _MAC_F_(0x14)
#define N20_MAC_SA_LO _MAC_F_(0x10)
#define DEFAULT_THRES 0x1000
#define PAUSE_TIMER_ALDONE_THRES _MAC_F_(0x40)

#define N20_M_JUMBO_LENGTH _MAC_F_(0xc)
#define N20_M_PAUSE_TIMER _MAC_F_(0x1c)
#define N20_MAC_PFC_TIMER(a) _MAC_F_(0x20 + (a) * 0x4)

#define N20_PTP_OFF(off) _MAC_F_(off)

/*----- MAC manager counter------------------- */
/* Rx FCS Error Frames Num Base */
#define MCE_M_RX_FCS_ERR _MAC_F_(0x88)
/* Rx Good Frame Num Base */
#define MCE_M_RX_GFRAMSB _MAC_F_(0x84)
#define MCE_M_RX_GFRAMSB_HI _MAC_F_(0xac)
/* Rx Good Bytes Base */
#define MCE_M_RX_GOCTGB _MAC_F_(0x180)
#define MCE_M_RX_GOCTGB_HI _MAC_F_(0x1cc)
/* RX Bad Frame Num Base */
#define MCE_M_RX_BFRMB _MAC_F_(0x184)
#define MCE_M_RX_BFRMB_HI _MAC_F_(0x1d0)
/* Rx Good Pause Frame Num Base */
#define MCE_M_RX_PAUSE_FRAMS _MAC_F_(0x94)
/* Rx Good Vlan Frame Num Base */
#define MCE_M_RX_VLAN_FRAMB _MAC_F_(0xa4)
/* Rx Good PFC priority 0 Frame Num */
#define MCE_M_RX_PFC_PRI0_NUM _MAC_F_(0xe0)
/* Rx Good PFC priority 1 Frame Num */
#define MCE_M_RX_PFC_PRI1_NUM _MAC_F_(0xe4)
/* Rx Good PFC priority 2 Frame Num */
#define MCE_M_RX_PFC_PRI2_NUM _MAC_F_(0xe8)
/* Rx Good PFC priority 3 Frame Num */
#define MCE_M_RX_PFC_PRI3_NUM _MAC_F_(0xec)
/* Rx Good PFC priority 4 Frame Num */
#define MCE_M_RX_PFC_PRI4_NUM _MAC_F_(0xf0)
/* Rx Good PFC priority 5 Frame Num */
#define MCE_M_RX_PFC_PRI5_NUM _MAC_F_(0xf4)
/* Rx Good PFC priority 6 Frame Num */
#define MCE_M_RX_PFC_PRI6_NUM _MAC_F_(0xf8)
/* Rx Good PFC priority 7 Frame Num */
#define MCE_M_RX_PFC_PRI7_NUM _MAC_F_(0xfc)
/* Rx Good Unicast Frame Num Base */
#define MCE_M_RX_GUCASTB _MAC_F_(0x188)
#define MCE_M_RX_GUCASTB_HI _MAC_F_(0x1d4)
/* Rx Good Multicast Frame Num Base */
#define MCE_M_RX_GMCASTB _MAC_F_(0x18c)
#define MCE_M_RX_GMCASTB_HI _MAC_F_(0x1d8)
/* Rx Good Broadcast Frame Num Base */
#define MCE_M_RX_GBCASTB _MAC_F_(0x190)
#define MCE_M_RX_GBCASTB_HI _MAC_F_(0x1dc)
/* Rx Good And Bad Bytes Num Base */
#define MCE_M_RX_GBOCTGB _MAC_F_(0x198)
#define MCE_M_RX_GBOCTGB_HI _MAC_F_(0x1e0)
/* Rx Good And Bad Frame Num Base */
#define MCE_M_RX_GBFRMB _MAC_F_(0x19c)
#define MCE_M_RX_GBFRMB_HI _MAC_F_(0x1e4)
/* Rx undersize_pkts_counter */
#define MCE_M_RX_USIZECB _MAC_F_(0x1a0)
/* Rx Good And Bad 64Bytes Frame Num */
#define MCE_M_RX_64_BYTESB _MAC_F_(0x1a4)
#define MCE_M_RX_64_BYTESB_HI _MAC_F_(0x1e8)
/* Rx Good And Bad 65 to 127 Bytes Frame Num */
#define MCE_M_RX_65TO127_BYTESB _MAC_F_(0x1a8)
#define MCE_M_RX_65TO127_BYTESB_HI _MAC_F_(0x1ec)
/* Rx 128Bytes To 255Bytes Frame Num Base */
#define MCE_M_RX_128TO255_BYTESB _MAC_F_(0x1ac)
#define MCE_M_RX_128TO255_BYTESB_HI _MAC_F_(0x1f0)
/* Rx 256Bytes To 511Bytes Frame Num Base */
#define MCE_M_RX_256TO511_BYTESB _MAC_F_(0x1b0)
#define MCE_M_RX_256TO511_BYTESB_HI _MAC_F_(0x1f4)
/* Rx 512Bytes To 1023Bytes Frame Num Base */
#define MCE_M_RX_512TO1023_BYTESB _MAC_F_(0x1b4)
#define MCE_M_RX_512TO1023_BYTESB_HI _MAC_F_(0x1f8)
/* Rx 1024bytes To 1518Bytes Frame Num Base */
#define MCE_M_RX_1024TO1518_BYTESB _MAC_F_(0x1b8)
#define MCE_M_RX_1024TO1518_BYTESB_HI _MAC_F_(0x178)
/* Rx 1519toMax Bytes Frame Num Base */
#define MCE_M_RX_1519TOMAX_BYTESB _MAC_F_(0x1bc)
#define MCE_M_RX_1519TOMAX_BYTESB_HI _MAC_F_(0x17c)
/* Rx len Oversize Than Support with correct crc */
#define MCE_M_RX_OSIZE_FRMB _MAC_F_(0x1c0)
/* Rx len Oversize Than support with invalid crc */
#define MCE_M_RX_JABBER_FRMB _MAC_F_(0x1c4)
/* Rx Less Than 64Bytes with crc err Base*/
#define MCE_M_RX_RUNTERB _MAC_F_(0x1c8)
/* Rx discard num */
#define MCE_M_RX_DISCARD _MAC_F_(0x1fc)
/* Rx frame_too_long_errors_counter */
#define MCE_M_RX_TLE_FRMB _MAC_F_(0x98)
/* Rx alignment_errors_counter */
#define MCE_M_RX_ALIGNE_FRMB _MAC_F_(0x8c)
/* Rx in_range_length_errors_counter */
#define MCE_M_RX_ORSE_FRAM _MAC_F_(0x9c)

/* Tx Good Frame Num Base */
#define MCE_M_TX_GFRAMSB _MAC_F_(0x80)
#define MCE_M_TX_GFRAMSB_HI _MAC_F_(0xa8)
/* Tx Good Bytes Base */
#define MCE_M_TX_GOCTGB _MAC_F_(0x100)
#define MCE_M_TX_GOCTGB_HI _MAC_F_(0x140)
/* TX Bad Frame Num Base */
#define MCE_M_TX_BFRMB _MAC_F_(0x104)
#define MCE_M_TX_BFRMB_HI _MAC_F_(0x144)
/* Tx Good Pause Frame Num Base */
#define MCE_M_TX_PAUSE_FRAMS _MAC_F_(0x90)
/* Tx Good Vlan Frame Num Base */
#define MCE_M_TX_VLAN_FRAMB _MAC_F_(0xa0)
/* Tx Good PFC priority 0 Frame Num */
#define MCE_M_TX_PFC_PRI0_NUM _MAC_F_(0xc0)
/* Tx Good PFC priority 1 Frame Num */
#define MCE_M_TX_PFC_PRI1_NUM _MAC_F_(0xc4)
/* Tx Good PFC priority 2 Frame Num */
#define MCE_M_TX_PFC_PRI2_NUM _MAC_F_(0xc8)
/* Tx Good PFC priority 3 Frame Num */
#define MCE_M_TX_PFC_PRI3_NUM _MAC_F_(0xcc)
/* Tx Good PFC priority 4 Frame Num */
#define MCE_M_TX_PFC_PRI4_NUM _MAC_F_(0xd0)
/* Tx Good PFC priority 5 Frame Num */
#define MCE_M_TX_PFC_PRI5_NUM _MAC_F_(0xd4)
/* Tx Good PFC priority 6 Frame Num */
#define MCE_M_TX_PFC_PRI6_NUM _MAC_F_(0xd8)
/* Tx Good PFC priority 7 Frame Num */
#define MCE_M_TX_PFC_PRI7_NUM _MAC_F_(0xdc)
/* Tx Good Unicast Frame Num Base */
#define MCE_M_TX_GUCASTB _MAC_F_(0x108)
#define MCE_M_TX_GUCASTB_HI _MAC_F_(0x148)
/* Tx Good Multicast Frame Num Base */
#define MCE_M_TX_GMCASTB _MAC_F_(0x10c)
#define MCE_M_TX_GMCASTB_HI _MAC_F_(0x14c)
/* Tx Good Broadcast Frame Num Base */
#define MCE_M_TX_GBCASTB _MAC_F_(0x110)
#define MCE_M_TX_GBCASTB_HI _MAC_F_(0x150)
/* Tx Good And Bad Bytes Base */
#define MCE_M_TX_GBOCTGB _MAC_F_(0x114)
#define MCE_M_TX_GBOCTGB_HI _MAC_F_(0x154)
/* Tx Good And Bad Frame Num Base */
#define MCE_M_TX_GBFRMB _MAC_F_(0x118)
#define MCE_M_TX_GBFRMB_HI _MAC_F_(0x158)
/* Tx Good And Bad 64Bytes Frame Num */
#define MCE_M_TX_64_BYTESB _MAC_F_(0x11c)
#define MCE_M_TX_64_BYTESB_HI _MAC_F_(0x15c)
/* Tx Good And Bad 65 to 127 Bytes Frame Num */
#define MCE_M_TX_65TO127_BYTESB _MAC_F_(0x120)
#define MCE_M_TX_65TO127_BYTESB_HI _MAC_F_(0x160)
/* Tx 128Bytes To 255Bytes Frame Num Base */
#define MCE_M_TX_128TO255_BYTESB _MAC_F_(0x124)
#define MCE_M_TX_128TO255_BYTESB_HI _MAC_F_(0x164)
/* Tx 256Bytes To 511Bytes Frame Num Base */
#define MCE_M_TX_256TO511_BYTESB _MAC_F_(0x128)
#define MCE_M_TX_256TO511_BYTESB_HI _MAC_F_(0x168)
/* Tx 512Bytes To 1023Bytes Frame Num Base */
#define MCE_M_TX_512TO1023_BYTESB _MAC_F_(0x12c)
#define MCE_M_TX_512TO1023_BYTESB_HI _MAC_F_(0x16c)
/* Tx 1024bytes To 1518Bytes Frame Num Base */
#define MCE_M_TX_1024TO1518_BYTESB _MAC_F_(0x130)
#define MCE_M_TX_1024TO1518_BYTESB_HI _MAC_F_(0x170)
/* Tx 1519toMax Bytes Frame Num Base */
#define MCE_M_TX_1519TOMAX_BYTESB _MAC_F_(0x134)
#define MCE_M_TX_1519TOMAX_BYTESB_HI _MAC_F_(0x174)
/* Tx len Oversize Than Support with correct crc */
#define MCE_M_TX_OSIZE_FRMB _MAC_F_(0x138)
/* Tx len Oversize Than support with invalid crc */
#define MCE_M_TX_JABBER_FRMB _MAC_F_(0x13C)

/* PCS reg offset */
#define _PCS_F_(off) (N20_CE_REG_BASE + (off))

#define MCE_PCS_CESOC(off) (N20_CE_REG_BASE + 0x6800 + (off)) /* 0x6_6800 */
#define CESOC_LP_EN MCE_PCS_CESOC(0x30)
#define MII_RX2TX_EN BIT(9)
#define MII_TX2RX_EN BIT(8)
#define MII_LOOPBACK_RX_USE_TX_CLK (0b1111 << 4)
#define PMA_LOOPBACK_ENABLE (0b1111 << 0)
#define PMA_LOOPBACK_DISABLE (0b0000 << 0)

#define CESOC_LP_RESET MCE_PCS_CESOC(0x34)
#define PMA_LOOPBACK_RESET (0b1111 << 0)
#define PMA_LOOPBACK_RESET_RELEASE (0b0000 << 0)
#define MII_LP_RX_TO_TX_FIFO_RESET BIT(4)

/* PMA reg offset*/
#define PHY_PMA_BASE (0x50000)
#define pma_ioread16(hw, reg) \
	raw_rd32((hw)->eth_bar_base + PHY_PMA_BASE + (((reg) - 0x6000) << 2))
#define pma_iowrite16(hw, reg, v) \
	raw_wr32((v) & 0xffff,    \
		 (hw)->eth_bar_base + PHY_PMA_BASE + (((reg) - 0x6000) << 2))

#define SERDES_LOOPBACK_FIFO 0x9803

/* NIC reg*/
#define N20_NIC_REG_BASE (0x70000)
#define _NIC_F_(off) (N20_NIC_REG_BASE + (off))

#define N20_NIC_VERSION _NIC_F_(0x0000)
#define N20_NIC_CONFIG _NIC_F_(0x0004)
#define F_VIRTUAAL_SW_OFFSET (0)
#define N20_NIC_STATUS _NIC_F_(0x0008)
#define N20_NIC_DUMMY _NIC_F_(0x000c)
#define N20_NIC_RESET _NIC_F_(0x0010)
#define F_NIC_RESET_NIC BIT(0)
#define F_NIC_RESET_BMC BIT(1)
#define F_NIC_RESET_REG BIT(2)
#define F_NIC_RESET_EN (F_NIC_RESET_NIC | F_NIC_RESET_REG)
#define F_NIC_RESET_NIC_MASK BIT(16)
#define F_NIC_RESET_BMC_MASK BIT(17)
#define F_NIC_RESET_REG_MASK BIT(18)
#define F_NIC_RESET_MASK (F_NIC_RESET_NIC_MASK | F_NIC_RESET_REG_MASK)

#define N20_NIC_MSI_CONFIG _NIC_F_(0x0014)
#define F_NIC_MSI_CONFIG_LEGACY_EN BIT(31)
#define F_NIC_MSI_CONFIG_MSIX_TICK_TIMER(reg, val) \
	MODIFY_BITFIELD(reg, val, 31, 0)

#define N20_NIC_MSIX_CONFIG _NIC_F_(0x0018)
#define N20_NIC_INTR_EN_REG _NIC_F_(0x001C)

#define N20_NIC_MAC_OUI _NIC_F_(0x2000)
#define N20_NIC_MAC_SN _NIC_F_(0x2004)

/* DMA reg */
#define N20_DMA_REG_BASE (0x40000)
#define _DMA_F_(off) (N20_DMA_REG_BASE + (off))

#define N20_DMA_VERSION _DMA_F_(0x0)
#define N20_DMA_CONFIG _DMA_F_(0x4)
#define F_VF_ACTIVE_OFFSET (25) /* DMA 0x4 flags */
#define N20_DMA_STATUS _DMA_F_(0x8)
#define F_DMA_TSO_CNTS_EN BIT(30)
#define F_TX_WB_EN BIT(31)
#define F_RX_WB_EN BIT(30)
#define N20_DMA_DUMY _DMA_F_(0xc)
#define N20_DMA_AXI_EN _DMA_F_(0x10)
#define F_TX_AXI_RW_MS (0xc0000)
#define F_TX_AXI_RW_EN (0x0000c)
#define F_RX_AXI_RW_MS (0x30000)
#define F_RX_AXI_RW_EN (0x00003)
#define N20_DMA_AXI_STATUS _DMA_F_(0x14)
#define N20_IFIFO_DATA_PROG_FULL _DMA_F_(0x88)
#define N20_PFC_FIFO_DEPTH(i) _DMA_F_(0xd0 + (i) * 0x4)
#define N20_PFC_FIFO_SELECT _DMA_F_(0xe0)

#define N20_DEBUG_PROBE_10 _DMA_F_(0x150)
#define N20_NIC_DMA_FLR_STATUS(i) _DMA_F_(0x30 + (i) * 4)
#define N20_NIC_DMA_FLR_MASK(i) _DMA_F_(0x40 + (i) * 4)
#define N20_NIC_DMA_FLR_CLR(i) _DMA_F_(0x50 + (i) * 4)
/* tc */
#define N20_DMA_TC_BW(i) _DMA_F_(0x1000 + (0x4 * (i)))
#define N20_DMA_TC_CTRL _DMA_F_(0x1020)
#define F_TC_EN BIT(31)
#define F_TC_BP_MOD BIT(30)
#define F_TC_PP_MOD BIT(29)
#define F_TC_CRC BIT(28)
#define F_TC_INTERAL_EN BIT(27)
#define F_TC_INTERAL_OFFSET (16)
#define F_TC_VALID_OFFSET (8)
#define F_TC_TSA_OFFSET (0)
#define N20_DMA_TC_TAL_BW _DMA_F_(0x1024)
#define F_PF_BW_EN BIT(31)
#define ETS_TIMEOUT 0x0400
/* bit[31:16] sp timeout bit[15:0] ets timeout */
#define N20_DMA_TC_TIMEOUT _DMA_F_(0x1028)
#define F_TC_BW_EN BIT(31)
#define F_TC_BW_SHARE_EN BIT(30)
#define F_TC_BW_OFFSET (0)
#define N20_DMA_TC_QG_CTRL(i) _DMA_F_(0x1200 + (0x4 * (i)))
#define F_BURST_EN BIT(31)
#define F_RESTRIC_BYTE BIT(30)
#define F_WEIGHT_EN BIT(7)
#define N20_DMA_VF_QG_CTRL _DMA_F_(0x102c)
#define F_VF_LIMIT_EN BIT(31)
#define F_SET_VF_QG_NUM(reg, val) MODIFY_BITFIELD(reg, val, 3, 0)

#define N20_DMA_TC_QG_PPS_CIR(i) _DMA_F_(0x1400 + (0x4 * (i)))
#define N20_DMA_TC_QG_PPS_PIR(i) _DMA_F_(0x1600 + (0x4 * (i)))
#define N20_DMA_TC_QG_BPS_CIR(i) _DMA_F_(0x1800 + (0x4 * (i)))
#define N20_DMA_TC_QG_BPS_PIR(i) _DMA_F_(0x1a00 + (0x4 * (i)))
#define N20_DMA_TC_VF_QG_BYTE_LIMIT(i) _DMA_F_(0x1c00 + (0x4 * (i)))

/* DMA debug */
#define N20_DMA_D_TX_IRQ_CNT _DMA_F_(0x200)
#define N20_DMA_D_RX_IRQ_CNT _DMA_F_(0x204)
#define N20_DMA_D_CH0_TX_CTRL_DATA_FRAG_CNT _DMA_F_(0x208)
#define N20_DMA_D_CH1_TX_CTRL_DATA_FRAG_CNT _DMA_F_(0x20c)
#define N20_DMA_D_CH2_TX_CTRL_DATA_FRAG_CNT _DMA_F_(0x210)
#define N20_DMA_D_CH3_TX_CTRL_DATA_FRAG_CNT _DMA_F_(0x214)
#define N20_DMA_D_TX_CTRL_RD_DESC_CNT _DMA_F_(0x218)
#define N20_DMA_D_TX_CTRL_RD_PKGS_CNT _DMA_F_(0x21c)
#define N20_DMA_D_TX_CTRL_FIFO0_DESC_AVG _DMA_F_(0x220)
#define N20_DMA_D_TX_CTRL_FIFO1_DESC_AVG _DMA_F_(0x224)
#define N20_DMA_D_TX_CTRL_FIFO2_DESC_AVG _DMA_F_(0x228)
#define N20_DMA_D_TX_CTRL_FIFO3_DESC_AVG _DMA_F_(0x22c)
#define N20_DMA_D_RX_CTRL_PCIE_RD_REQ _DMA_F_(0x230)
#define N20_DMA_D_RX_CTRL_PCIE_WR_REQ _DMA_F_(0x234)
#define N20_DMA_D_RX_CTRL_WR_DESC_CNT _DMA_F_(0x238)
#define N20_DMA_D_RX_CTRL_RD_PKGS_CNT _DMA_F_(0x23c)
#define N20_DMA_D_RX_CTRL_FIFO0_DESC_AVG _DMA_F_(0x240)
#define N20_DMA_D_RX_CTRL_FIFO1_DESC_AVG _DMA_F_(0x244)
#define N20_DMA_D_RX_CTRL_FIFO2_DESC_AVG _DMA_F_(0x248)
#define N20_DMA_D_RX_CTRL_FIFO3_DESC_AVG _DMA_F_(0x24c)
#define N20_DMA_D_RX_CTRL_RING0_NO_DESC_AVG _DMA_F_(0x250)
#define N20_DMA_D_RX_CTRL_RING1_NO_DESC_AVG _DMA_F_(0x254)
#define N20_DMA_D_RX_CTRL_RING2_NO_DESC_AVG _DMA_F_(0x258)
#define N20_DMA_D_RX_CTRL_RING3_NO_DESC_AVG _DMA_F_(0x25c)
#define N20_DMA_D_TX_AXI_RD_CMD_CNT _DMA_F_(0x260)
#define N20_DMA_D_TX_AXI_WR_CMD_CNT _DMA_F_(0x264)
#define N20_DMA_D_TX_AXI_RD_PKGS_CNT _DMA_F_(0x268)
#define N20_DMA_D_TX_AXI_WR_PKGS_CNT _DMA_F_(0x26c)
#define N20_DMA_D_TX_AXI_RD_CMD_AVG _DMA_F_(0x270)
#define N20_DMA_D_TX_AXI_WR_CMD_AVG _DMA_F_(0x274)
#define N20_DMA_D_TX_AXI_RD_PKGS_AVG _DMA_F_(0x278)
#define N20_DMA_D_TX_AXI_WR_PKGS_AVG _DMA_F_(0x27c)
#define N20_DMA_D_RX_AXI_RD_CMD_CNT _DMA_F_(0x280)
#define N20_DMA_D_RX_AXI_WR_CMD_CNT _DMA_F_(0x284)
#define N20_DMA_D_RX_AXI_RD_PKGS_CNT _DMA_F_(0x288)
#define N20_DMA_D_RX_AXI_WR_PKGS_CNT _DMA_F_(0x28c)
#define N20_DMA_D_RX_AXI_RD_CMD_AVG _DMA_F_(0x290)
#define N20_DMA_D_RX_AXI_WR_CMD_AVG _DMA_F_(0x294)
#define N20_DMA_D_RX_AXI_RD_PKGS_AVG _DMA_F_(0x298)
#define N20_DMA_D_RX_AXI_WR_PKGS_AVG _DMA_F_(0x29c)
#define N20_DMA_D_RX_IFIFO_PKGS_IN_CNT _DMA_F_(0x2a0)
#define N20_DMA_D_RX_IFIFO_PKGS_OUT_CNT _DMA_F_(0x2a4)
#define N20_DMA_D_RX_OFIFO_PKGS_IN_CNT _DMA_F_(0x2a8)
#define N20_DMA_D_RX_OFIFO_PKGS_OUT_CNT _DMA_F_(0x2ac)
#define N20_DMA_D_TX_RING0_INT_STATUS _DMA_F_(0x2c8)
#define N20_DMA_D_TX_RING1_INT_STATUS _DMA_F_(0x2cc)
#define N20_DMA_D_TX_RING2_INT_STATUS _DMA_F_(0x2d0)
#define N20_DMA_D_TX_RING3_INT_STATUS _DMA_F_(0x2d4)
#define N20_DMA_D_RX_RING0_INT_STATUS _DMA_F_(0x2d8)
#define N20_DMA_D_RX_RING1_INT_STATUS _DMA_F_(0x2dc)
#define N20_DMA_D_RX_RING2_INT_STATUS _DMA_F_(0x2e0)
#define N20_DMA_D_RX_RING3_INT_STATUS _DMA_F_(0x2e4)

/* Ring common REG */
#define N20_RING_BASE (0x0000)
#define N20_RING_OFF(i) (N20_RING_BASE + (0x100 * (i)))

/* Ring Enable and interrupt status REG*/
#define N20_DMA_REG_RX_START (0x10)
#define F_RX_START_FLR_EN BIT(1)
#define F_RX_START_EN BIT(0)
#define N20_DMA_REG_RX_READY (0x14)
#define N20_DMA_REG_TX_START (0x18)
#define F_TX_START_FLR_EN BIT(1)
#define F_TX_START_EN BIT(0)
#define N20_DMA_REG_TX_READY (0x1c)
#define N20_DMA_REG_INT_STAT (0x20)
#define N20_DMA_REG_INT_MASK (0x24)
#define N20_DMA_REG_INT_CTRL (0x28)
#define N20_DMA_REG_INT_TRIG (0x2c)
#define _F_N20_DMA_INT_SET_TRIG_TX (BIT(19) | BIT(3))
#define _F_N20_DMA_INT_CLR_TRIG_TX BIT(19)

/* Dma ring stats */
#define N20_DMA_REG_READ_CLEAD (0x90)
#define N20_DMA_REG_RX_MISS_DROP (0x5c)
#define N20_DMA_REG_RX_BYTES_LO (0xc0)
#define N20_DMA_REG_RX_BYTES_HI (0xc4)
#define N20_DMA_REG_RX_UNICAST_LO (0xc8)
#define N20_DMA_REG_RX_UNICAST_HI (0xcc)
#define N20_DMA_REG_RX_MULTICAST_LO (0xd0)
#define N20_DMA_REG_RX_MULTICAST_HI (0xd4)
#define N20_DMA_REG_RX_BROADCAST_LO (0xd8)
#define N20_DMA_REG_RX_BROADCAST_HI (0xdc)

#define N20_DMA_REG_TX_BYTES_LO (0xe0)
#define N20_DMA_REG_TX_BYTES_HI (0xe4)
#define N20_DMA_REG_TX_UNICAST_LO (0xe8)
#define N20_DMA_REG_TX_UNICAST_HI (0xec)
#define N20_DMA_REG_TX_MULTICAST_LO (0xf0)
#define N20_DMA_REG_TX_MULTICAST_HI (0xf4)
#define N20_DMA_REG_TX_BROADCAST_LO (0xf8)
#define N20_DMA_REG_TX_BROADCAST_HI (0xfc)

/*HW RX DIM*/
/* 200,000 -- 1500,000 should use hw dim */
#define IRQ_MAX_200K (30 * 1024 * 1024) /* 30 / ms 30000 /s */
#define IRQ_MIN_200K 10 /* 5 / ms 5000 /s */

#define IRQ_MAX_200K_RX (30 * 1024 * 1024) /* 30 / ms 30000 /s */
#define IRQ_MIN_200K_RX 1000 /* 5 / ms 5000 /s */

#define IRQ_MAX_50K 50000
#define DMA_REG_RX_PKT_RATE_LOW 0xA0
#define DMA_REG_RX_PKT_RATE_HIGH 0xA4
#define DMA_REG_RX_INT_FRAMES 0xA8
#define DMA_REG_RX_INT_USECS 0xAC
/*HW TX DIM*/
#define DMA_REG_TX_PKT_RATE_LOW 0xB0
#define DMA_REG_TX_PKT_RATE_HIGH 0xB4
#define DMA_REG_TX_INT_FRAMES 0xB8
#define DMA_REG_TX_INT_USECS 0xBC
#define DMA_INT_INTERVAL_EN BIT(31)

#define F_TX_INT_MASK_MS_BIT 17
#define F_TX_INT_MASK_EN_BIT 1
#define F_RX_INT_MASK_MS_BIT 16
#define F_RX_INT_MASK_EN_BIT 0
#define F_TX_INT_TRIG_MS_BIT 17
#define F_TX_INT_TRIG_EN_BIT 1
#define F_RX_INT_TRIG_MS_BIT 16
#define F_RX_INT_TRIG_EN_BIT 0

/* TxRing REG */
#define N20_DMA_REG_TX_DESC_BASE_ADDR_HI 0x60
#define N20_DMA_REG_TX_DESC_BASE_ADDR_LO 0x64
#define N20_DMA_REG_TX_DESC_LEN 0x68
#define N20_DMA_REG_TX_DESC_HEAD 0x6c
#define N20_DMA_REG_TX_DESC_TAIL 0x70
#define N20_DMA_REG_TX_DESC_FETCH_CTRL 0x74
#define N20_DMA_REG_TX_INT_DELAY_TIMER 0x78
#define N20_DMA_REG_TX_INT_DELAY_PKTCNT 0x7c
#define N20_DMA_REG_TX_PRIO_LVL 0x80
#define F_RING_TC_EN BIT(31)
#define F_RING_PFC_EN BIT(30)
#define F_RING_TC_LOC 16 /* [23:16] is tc7-0 */
#define N20_DMA_REG_TX_FLOW_CTRL_TH 0x84
#define N20_DMA_REG_TX_FLOW_CTRL_TM 0x88

/* RxRing REG */
#define N20_DMA_REG_RX_DESC_BASE_ADDR_HI 0x30
#define N20_DMA_REG_RX_DESC_BASE_ADDR_LO 0x34
#define N20_DMA_REG_RX_DESC_LEN 0x38
#define N20_DMA_REG_RX_DESC_HEAD 0x3c
#define N20_DMA_REG_RX_DESC_TAIL 0x40
#define N20_DMA_REG_RX_DESC_FETCH_CTRL 0x44
#define N20_DMA_REG_RX_INT_DELAY_TIMER 0x48
#define N20_DMA_REG_RX_INT_DELAY_PKTCNT 0x4c
#define N20_DMA_REG_RX_ARB_DEF_LVL 0x50
#define N20_DMA_REG_RX_DESC_TIMEOUT_TH 0x54
#define N20_DMA_REG_RX_SCATTER_LENGTH 0x58
#define N20_DMA_REG_RX_TIMEOUT_DROP 0x5c
#define N20_DMA_REG_RX_MPKT_L 0xd0
#define N20_DMA_REG_RX_MPKT_H 0xd4
#define N20_DMA_REG_RX_BPKT_L 0xd8
#define N20_DMA_REG_RX_BPKT_H 0xdc
/* ETH reg */
#define N20_ETH_REG_BASE 0x80000
#define _ETH_F_(off) (N20_ETH_REG_BASE + (off))

#define N20_ETH_PROG_REG_LO(i, j) \
	(_ETH_F_(0x2000) + (i) * 0x200 + 0x8 * (j))
#define N20_ETH_PROG_REG_HI(i, j) \
	(_ETH_F_(0x2000) + (i) * 0x200 + 0x8 * (j) + 0x4)

#define N20_ETH_RX_DEBUG0 _ETH_F_(0x6400)
#define N20_ETH_RX_DEBUG4 _ETH_F_(0x6410)
#define N20_ETH_RX_DEBUG5 _ETH_F_(0x6414)
#define N20_ETH_PARSER_CTRL _ETH_F_(0x8000)
#define F_DDP_EXTRA_EN BIT(28)

#define N20_ETH_VXLAN_PORT _ETH_F_(0x1000)
#define N20_ETH_VXLAN_GPE_PORT _ETH_F_(0x1100)
#define N20_ETH_GENEVE_PORT _ETH_F_(0x1200)
#define N20_ETH_IPSEC_PORT _ETH_F_(0x1500)

#define N20_ETH_EXCEPT_RX_PROC _ETH_F_(0x0470)
#define F_DGB_RXTRANS_BUS_OFF 24
#define F_DEFAULT_ACTION_OFF 8
#define F_CRC_ERROR BIT(0)
#define F_NON_DATA_ERROR BIT(1)
#define F_UNDER_SIZE_ERROR BIT(2)
#define F_OVER_SIZE_ERROR BIT(3)
#define F_8023_LEN_ERROR BIT(4)
#define F_REMOTE_WAKE_UP BIT(5)
#define F_MAGIC BIT(6)
#define F_DMAC_MATCH_ERROR BIT(7)
#define F_OTHER_ERROR BIT(8)
#define N20_ETH_EXCEPT_TX_PROC _ETH_F_(0x0474)
#define N20_ETH_EMAC_POST_CTRL _ETH_F_(0x047c)
#define F_PORT_CTRL_MUL_ANTI_SPOOF_EN BIT(31)
#define F_EMAC_PFC_EN BIT(6)
#define F_VIRTUAL_INNER_EN BIT(7)
#define F_COPY_EN 0x3
#define N20_ETH_VLAN_TPID(i) _ETH_F_(0x0480 + (4 * (i)))
#define N20_ETH_CFG_ADAPTER_CTRL0 _ETH_F_(0x04c0)
#define F_RX_CTRL BIT(14)
#define F_TX_CDC (16)
#define F_RX_CDC (0)
#define N20_ETH_CFG_ADAPTER_CTRL1 _ETH_F_(0x04c4)
#define N20_ETH_CFG_ADAPTER_CTRL(i) _ETH_F_(0x04c8 + 0x4 * (i))
#define PFC_LOCK_EN BIT(31)

#define N20_ETH_O_VLAN_TYPE(i) _ETH_F_(0x1700 + (4 * (i)))
#define N20_ETH_I_VLAN_TYPE(i) _ETH_F_(0x1800 + (4 * (i)))

#define N20_ETH_PTP_TX_TSVALUE_STATUS _ETH_F_(0x6488)
#define N20_ETH_PTP_TX_LTIMES _ETH_F_(0x6480)
#define N20_ETH_PTP_TX_HTIMES _ETH_F_(0x6484)
#define N20_ETH_PTP_TX_CLEAR _ETH_F_(0x4c0)

#define N20_ETH_L2_CTRL0 _ETH_F_(0x8010)
#define F_L2_FILTER_EN BIT(31) /* ETH 0x8010 flags */
#define F_DMAC_FILTER_EN BIT(30) /* ETH 0x8010 flags */
#define F_ANTI_SPOOF_SMAC_FLR_EN BIT(29) /* ETH 0x8010 flags */
#define F_ANTI_SPOOF_VTAG_FLR_EN BIT(28) /* ETH 0x8010 flags */
#define F_VLAN_FILTER_EN BIT(26) /* ETH 0x8010 flags */
#define F_UC_HASH_EN BIT(24) /* ETH 0x8010 flags */
#define F_MC_HASH_EN BIT(23) /* ETH 0x8010 flags */
#define F_BC_BYPASS_EN BIT(20) /* ETH 0x8010 flags */
#define F_DN_ANTI_SPOOF_SMAC_FILTER_EN BIT(19) /* ETH 0x8010 flags */
#define F_DN_ANTI_SPOOF_VTAG_FILTER_EN BIT(18) /* ETH 0x8010 flags */
#define F_DN_ANTI_SPOOF_DMAC_FILTER_EN BIT(17) /* ETH 0x8010 flags */
#define F_VEPA_SW_EN BIT(7) /* ETH 0x8010 flags */
#define F_DN2UP_FLR_EN BIT(6) /* ETH 0x8010 flags */
#define F_UC_SEL BIT(2) /* ETH 0x8010 flags */
#define F_MC_SEL BIT(3) /* ETH 0x8010 flags */
#define N20_ETH_L2_CTRL0_DEFAULT_CFG                                       \
	(F_ANTI_SPOOF_VTAG_FLR_EN | F_ANTI_SPOOF_SMAC_FLR_EN |             \
	 F_DN_ANTI_SPOOF_SMAC_FILTER_EN | F_DN_ANTI_SPOOF_VTAG_FILTER_EN | \
	 F_DN_ANTI_SPOOF_DMAC_FILTER_EN | F_DN2UP_FLR_EN)

#define N20_ETH_L2_CTRL1 _ETH_F_(0x8014)
#define F_MC_CONVERT_TO_BC_EN BIT(31)
#define F_T10_MATCH_EN BIT(21)
#define F_T10_MASK_MATCH BIT(20)
#define F_T4_UP_MASK_MATCH BIT(19)
#define F_T4_DN_MASK_MATCH BIT(18)
#define F_T4_DN_TUNNEL_MASK_MATCH BIT(17)
#define F_T4_DN_VLAN_MATCH_MASK BIT(16)
#define F_T4_DN_IPORT_MATCH_MASK BIT(14)
#define F_T4_UP_TUNNEL_MASK_MATCH BIT(13)
#define F_T4_UP_VLAN_MATCH_MASK BIT(12)
#define F_T4_UP_IPORT_MATCH_MASK BIT(10)
#define F_T4_T10_CONFIG_MASK \
	(F_T10_MATCH_EN | F_T10_MASK_MATCH | F_T4_UP_MASK_MATCH | \
	 F_T4_DN_MASK_MATCH)

#define N20_ETH_FWD_CTRL _ETH_F_(0x801c)
#define F_DFT_PPORT_OFFSET 25
#define F_PROMISC_VPORT_UPLINK_EN BIT(11)
#define F_PROMISC_VPORT_VEB_EN BIT(10)
#define F_TRUST_VPORT_EN BIT(9)
#define F_RX_SELF_EN BIT(3)
#define F_CONGEST_DROP BIT(2)

#define N20_ETH_RQA_CTRL _ETH_F_(0x8020)
#define _ETH_F_(off) (N20_ETH_REG_BASE + (off))
#define F_REDIR_EN BIT(31)
#define F_FD_EN BIT(30)
#define F_ETYPE_EN BIT(29)
#define F_TCP_SYNC_EN BIT(28)
#define F_TUPLE5_EN BIT(27)
#define F_RSS_EN BIT(26)
#define F_VF_VLAN_FLR_EN BIT(23)
#define F_ARP_RSS_EN BIT(22)
#define F_MULTI_FILTER_TABLE_EN BIT(25)
#define F_IN_L4_CHK_ERR_MASK BIT(15)
#define F_IN_L3_CHK_ERR_MASK BIT(14)
#define F_EX_L4_CHK_ERR_MASK BIT(13)
#define F_EX_L3_CHK_ERR_MASK BIT(12)
#define F_EX_LEN_CHK_ERR_MASK BIT(11)
#define F_EX_MAC_CHK_ERR_MASK BIT(10)
#define F_RX_CHK_ERR_MASK                                                     \
	(F_EX_MAC_CHK_ERR_MASK | F_EX_LEN_CHK_ERR_MASK |                      \
	 F_EX_L3_CHK_ERR_MASK | F_EX_L4_CHK_ERR_MASK | F_IN_L3_CHK_ERR_MASK | \
	 F_IN_L4_CHK_ERR_MASK)
#define N20_ETH_EDTUP_CTRL _ETH_F_(0x8024)
#define F_SWC_DROP BIT(7)
#define F_UPS_DROP BIT(6)

#define N20_ETH_RX_PKTS_INGRESS _ETH_F_(0x6000)
#define N20_ETH_RX_PKTS_EGRESS _ETH_F_(0x6004)
#define N20_ETH_RX_EXCEPT_SHORT _ETH_F_(0x6008)
#define N20_ETH_RX_INNER_SCTP _ETH_F_(0x6084)
#define N20_ETH_RX_INNER_TCPSYN _ETH_F_(0x6088)
#define N20_ETH_RX_INNER_TCP _ETH_F_(0x608c)
#define N20_ETH_RX_INNER_UDP _ETH_F_(0x6090)

#define N20_ETH_RX_INGRESS_PKT_IN _ETH_F_(0x61a0)
#define N20_ETH_RX_INGRESS_PKT_DROP _ETH_F_(0x61a4)

#define N20_ETH_RX_EDTUP_PKT_IN _ETH_F_(0x61d0)
#define N20_ETH_RX_EDTUP_PKT_OUT _ETH_F_(0x61d4)

#define N20_ETH_PORT0_RX_PKTS _ETH_F_(0x6200)
#define N20_ETH_PORT1_RX_PKTS _ETH_F_(0x6204)

#define N20_ETH_RX_ATTR_INGRESS_PKT_IN _ETH_F_(0x6230)
#define N20_ETH_RX_ATTR_EGRESS_PKT_OUT _ETH_F_(0x6234)
#define N20_ETH_RX_ATTR_EGRESS_PKT_DROP _ETH_F_(0x6238)

#define N20_ETH_DFT_RXTRANS_MIN_LEN _ETH_F_(0x80f0)
#define N20_ETH_DFT_RXTRANS_MAX_LEN _ETH_F_(0x80f4)

#define N20_ETH_TSO_MAX_LEN _ETH_F_(0x80f8)
#define N20_ETH_TX_DBG_INPUT_PKTS _ETH_F_(0x6500)
#define N20_ETH_TX_DBG_OUTPUT_PKTS _ETH_F_(0x6504)
#define N20_ETH_TX_DBG_STATE_STATUS _ETH_F_(0x6508)

#define N20_RDMA_TX_VPORT_UNICAST_PKTS (0x20118)
#define N20_RDMA_TX_VPORT_UNICAST_BYTS (0x202e8)
#define N20_RDMA_RX_VPORT_UNICAST_PKTS (0x20210)
#define N20_RDMA_RX_VPORT_UNICAST_BYTS (0x202f0)
#define N20_RDMA_NP_CNP_SENT (0x2015c)
#define N20_RDMA_RP_CNP_HANDLED (0x3007c)
#define N20_RDMA_NP_ECN_MARKED_ROCE_PACKETS (0x202b0)
#define N20_RDMA_RP_CNP_IGNORED (0x30080)
#define N20_RDMA_OUT_OF_SEQUENCE (0x1f21c)
#define N20_RDMA_PACKET_SEQ_ERR (0x1f220)
#define N20_RDMA_ACK_TIMEOUT_ERR (0x1f26c)
#define N20_RDMA_TRIG (0x18004)

#define N20_RXTRANS_BUS_STATIC _ETH_F_(0x6300)

/* eth reg -- mac wap */
/* mac rx dscp to up, each up 4bit, effective value is 0~7 */
#define N20_ETH_RX_DSCP2UP_MAP(n) _ETH_F_(0xe300 + ((n) * 0x4))
/* mac tx dscp to up, each up 4bit, effective value is 0~7 */
#define N20_ETH_TX_DSCP2UP_MAP(n) _ETH_F_(0xe400 + ((n) * 0x4))
#define N20_HW_FIFO_CNT (8)
#define N20_ETH_RXADDR_N_RAM(n) \
	_ETH_F_(0xe500 + ((n) * 0x4)) /* [31:16]-head，[15:0]-tail */
#define N20_ETH_TXADDR_N_RAM(n) \
	_ETH_F_(0xe520 + ((n) * 0x4)) /* [31:16]-head，[15:0]-tail */
/* rx up to mac rx fifo, each up 4bit, effective value is 0~7(rx fifo[0:7]) */
#define N20_ETH_RX_UP2FIFO_MAP _ETH_F_(0xe540)
/* tx up to mac rx fifo, each up 4bit, effective value is 0~7(rx fifo[0:7]) */
#define N20_ETH_TX_UP2FIFO_MAP _ETH_F_(0xe544)
/* When pfc is enabled, the rx fifo of non-IP packets or non-VLAN packets,
 * which effective value is 0~7
 */
#define N20_ETH_RX_DEFAULT_FIFO _ETH_F_(0xe548)
#define N20_ETH_RXADDR_ENA _ETH_F_(0xe550)
#define N20_ETH_TXADDR_ENA _ETH_F_(0xe554)
/* rx FIFO_0-FIFO7 addr effective, high level */
#define F_RXTXADDR_EN BIT(1)
/* rx FIFO_0-FIFO7 addr effective, rising edge */
#define F_RXTXADDR_VALID BIT(0)
/* rx FIFO0-FIFO3 up, each FIFO 8bit */
#define N20_ETH_RXFIFO03_PRIO _ETH_F_(0xe558)
/* rx FIFO4-FIFO7 up, each FIFO 8bit */
#define N20_ETH_RXFIFO47_PRIO _ETH_F_(0xe55c)
/* tx FIFO0-FIFO3 up, each FIFO 8bit */
#define N20_ETH_TXFIFO03_PRIO _ETH_F_(0xe5d0)
/* tx FIFO4-FIFO7 up, each FIFO 8bit */
#define N20_ETH_TXFIFO47_PRIO _ETH_F_(0xe5d4)
/**
 * bit[15:00]：MAC receive FIFO0 low water level,bit[31:16]：MAC receive FIFO0 high water level
 */
#define N20_ETH_RXFIFO_N_LEAVEL(n) _ETH_F_(0xe560 + ((n) * 0x4))
#define N20_ETH_PAUSE_CTRL _ETH_F_(0xe580)
#define F_RX_PAUSE_EN BIT(0) /* ETH 0xe580 flags */
#define F_TX_PAUSE_EN BIT(1) /* ETH 0xe580 flags */
#define F_DSCP_MODE_EN BIT(2)
#define N20_ETH_RXMUX_CTRL _ETH_F_(0xe584)
#define N20_ETH_RXMUX_WRR(i) _ETH_F_(0xe590 + 0x4 * (i))
/* Traverse each FIFO in RR mode */
#define F_MAC_RR_MODE BIT(1)
/* Traverse each FIFO in WRR mode */
#define F_MAC_WRR_MODE BIT(0)
#define N20_ETH_TXMUX_CTRL _ETH_F_(0xe588)
#define N20_ETH_PORT_RX_PROGFULL_DFT 0x100
/* prot(0-7) rx fifo threshold */
#define N20_ETH_PORT_RX_PROGFULL(n) _ETH_F_(0x4000 + ((n) * 0x4))
/* prot(0-7) tx fifo threshold */
#define N20_ETH_PORT_TX_PROGFULL(n) _ETH_F_(0x4020 + ((n) * 0x4))
#define N20_ETH_TSO_IFIFO_THRESH _ETH_F_((0x40d0))
#define N20_ETH_TSO_DATA_THRESH _ETH_F_((0x40d4))
#define N20_ETH_TSO_OFIFO_THRESH _ETH_F_((0x40d8))

/* ETH FWD ATTR */
#define N20_ETH_TRUSTED_VPORT_ADDR(vfid) _ETH_F_(0xe000 + ((vfid) / 32) * 4)
#define F_SET_TRUSTED_VPORT_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))
#define F_CLR_TRUSTED_VPORT_CTRL(vfid, val) ((val) &= ~BIT((vfid) % 32))

#define N20_ETH_TRUE_PROMISC_VPORT_ADDR(vfid) \
	_ETH_F_(0xe010 + ((vfid) / 32) * 4)
#define F_SET_TRUE_PROMISC_VPORT_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))
#define F_CLR_TRUE_PROMISC_VPORT_CTRL(vfid, val) ((val) &= ~BIT((vfid) % 32))

#define N20_ETH_VTAG_VPORT_FILTER_ADDR(vfid) _ETH_F_(0xe210 + ((vfid) / 32) * 4)
#define F_SET_VTAG_VPORT_FILTER_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))
#define F_CLR_VTAG_VPORT_FILTER_CTRL(vfid, val) ((val) &= ~BIT((vfid) % 32))

#define N20_ETH_DEFAULT_VPORT_ADDR(vfid) _ETH_F_(0xe100 + ((vfid) / 32) * 4)
#define F_SET_DEFAULT_VPORT_CTRL(vfid, val) ((val) |= BIT((vfid) % 32))

/* ETH filter reg */
#define N20_ETH_FILTER_REG_BASE (0x90000)
#define _ETH_FLR_F_(off) (N20_ETH_FILTER_REG_BASE + (off))

#define N20_DMAC_FILTER_COUNT_H (N20_ETH_FILTER_REG_BASE + 0x4900)
#define N20_DMAC_FILTER_COUNT_L (N20_ETH_FILTER_REG_BASE + 0x4920)
#define N20_ETH_VEB_VLAN_PVF(i) _ETH_FLR_F_(0x1800 + 4 * (i))
#define N20_ETH_VEB_ACT_PVF(i) _ETH_FLR_F_(0x2800 + 4 * (i))
#define F_SET_VM_MATCH_INDEX(reg, val) MODIFY_BITFIELD(reg, val, 10, 8)
#define F_FORWARD_TO_SWITCH_EN BIT(5)

#define N20_ETH_FLTR_DMAC_RAL(i) _ETH_FLR_F_(0x5000 + (4 * (i)))
#define N20_ETH_FLTR_DMAC_RAH(i) _ETH_FLR_F_(0x5800 + (4 * (i)))
#define F_MAC_FLTR_EN BIT(31)

#define N20_ETH_VM_IPORT_PVF(i) _ETH_FLR_F_(0x0000 + (4 * (i)))
#define F_IPORT_FILTER_PVF_EN BIT(15)
#define F_MAC_FILTER_PVF_EN BIT(14)
#define F_VLAN_FILTER_PVF_EN BIT(13)
#define F_MATCH_TYPE_PVF_EN BIT(11)

#define N20_ETH_VM_DMAC_RAL(i) _ETH_FLR_F_(0x0800 + (4 * (i)))
#define N20_ETH_VM_DMAC_RAH(i) _ETH_FLR_F_(0x1000 + (4 * (i)))
#define N20_ETH_VM_T4_ACT_PVF(i) _ETH_FLR_F_(0x2800 + (4 * (i)))

#define N20_ETH_T10_VM_PORT(i) _ETH_FLR_F_(0x3400 + (4 * (i)))
#define N20_ETH_T10_VM_TYPE(i) _ETH_FLR_F_(0x3600 + (4 * (i)))

#define N20_ETH_UC_HASH_TABLE(i) _ETH_FLR_F_(0x4200 + (4 * (i)))
#define N20_ETH_MC_HASH_TABLE(i) _ETH_FLR_F_(0x4400 + (4 * (i)))
#define N20_ETH_VLAN_HASH_TABLE(i) _ETH_FLR_F_(0x4600 + (4 * (i)))

/* ETH filter anti-spoof reg */
#define N20_ETH_VM_ANTI_SMAC_RAL(i) _ETH_FLR_F_(0x4c00 + (4 * (i)))
#define N20_ETH_VM_ANTI_VTAG_SMAC_RAH(i) _ETH_FLR_F_(0x4e00 + (4 * (i)))
#define F_SET_ANTI_SPOOF_VLAN_ID(reg, val) MODIFY_BITFIELD(reg, val, 12, 16)
#define F_ANTI_SPOOF_VLAN_VALID BIT(31)
#define F_ANTI_SPOOF_SRC_MAC_VALID BIT(30)
#define F_ANTI_SPOOF_DST_MAC_VALID BIT(29)
#define F_ANTI_SPOOF_MAC_VALID \
	(F_ANTI_SPOOF_SRC_MAC_VALID | F_ANTI_SPOOF_DST_MAC_VALID)

/* ETH vport attr */
#define N20_ETH_VPORT_ATTR_BASE (0xa0000)
#define _ETH_VPORT_F_(off) (N20_ETH_VPORT_ATTR_BASE + (off))

#define N20_ETH_VPORT_ATTR_TABLE(i) _ETH_VPORT_F_(0x0000 + (4 * (i)))
#define F_VPORT_TRUE_PROMISC_EN BIT(31) /* ETH 0x0000 flags */
#define F_VPORT_LIMIT_LEN_EN BIT(30) /* ETH 0x0000 flags */
#define F_SET_VPORT_MAX_LEN(val, len) \
	MODIFY_BITFIELD(val, len, 14, 16) /* ETH 0xe100 flags */
#define F_SET_VPORT_DEFAULT_RING(val, len) \
	MODIFY_BITFIELD(val, len, 9, 7) /* ETH 0xe100 flags */
#define F_VPORT_TUN_SELECT_INNER BIT(6) /* ETH 0x0000 flags */
#define F_VPORT_TUN_SELECT_INNER_OUTER_EN BIT(5) /* ETH 0x0000 flags */
#define F_VPORT_MC_PROMISC_EN BIT(4) /* ETH 0x0000 flags */
#define F_VPORT_UC_PROMISC_EN BIT(3) /* ETH 0x0000 flags */
#define F_VPORT_VLAN_PROMISC_EN BIT(2) /* ETH 0x0000 flags */
#define F_VPORT_DROP BIT(0) /* ETH 0x0000 flags */
#define N20_ETH_VPORT_BITMAP_MEM0(i) _ETH_VPORT_F_(0x1000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM1(i) _ETH_VPORT_F_(0x2000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM2(i) _ETH_VPORT_F_(0x3000 + 4 * (i))
#define N20_ETH_VPORT_BITMAP_MEM3(i) _ETH_VPORT_F_(0x4000 + 4 * (i))

#define N20_PF_VF_NUM_ISOLATED_OFF 0x7f000
#define N20_PF_VF_NUM_NO_ISOLATED 0x30000

#define N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) (0x1000 * (((vfnum) / 32) + 1))
#define N20_ETH_VPORT_BITMAP_MEM_OFFSET(off) (4 * ((off) % 1024))
#define N20_ETH_VPORT_SET_BITMAP(vfnum, off)                  \
	_ETH_VPORT_F_(N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) + \
		      N20_ETH_VPORT_BITMAP_MEM_OFFSET(off))

/* ACL rule action */
#define F_ACL_ACTION_DROP BIT(31)
#define F_ACL_ACTION_RING_EN BIT(30)
#define F_ACL_ACTION_VLAN_EN BIT(29)
#define F_ACL_ACTION_MARK_EN BIT(28)
#define F_ACL_ACTION_PRIO_EN BIT(27)
#define F_ACL_ACTION_SET_RING_ID(val, id) MODIFY_BITFIELD(val, id, 9, 18)
#define F_ACL_ACTION_SET_MARK(val, mr) MODIFY_BITFIELD(val, mr, 16, 0)

#define N20_ETH_RQA_ETYPE_BASE (0xb0000)
/* every vf has it's own etype filter */
#define N20_ETH_RQA_ETQF_OFF(vfid, off) \
	(N20_ETH_RQA_ETYPE_BASE + (vfid) * 0x40 + (off) * 4)
#define N20_ETH_RQA_ETQS_OFF(vfid, off) \
	(N20_ETH_RQA_ETYPE_BASE + 0x2000 + (vfid) * 0x40 + (off) * 4)

/* VF MC white lists table */
#define N20_ETH_VF_MC_FILTER_MEM_BASE(bank) (0xb4000 + (bank) * 0x2000)
#define N20_ETH_VF_MC_OFF(bank, vfnum, idx) \
	(N20_ETH_VF_MC_FILTER_MEM_BASE((bank)) + (idx) * 4 + (vfnum) * 0x40)

/* VF VLAN white lists table */
#define N20_ETH_VF_VLAN_FILTER_MEM_BASE (0xb8000)
#define N20_ETH_VF_VLAN_OFF(vfnum, entry) \
	(N20_ETH_VF_VLAN_FILTER_MEM_BASE + ((entry) / 2) * 4 + (vfnum) * 0x20)

/* RQA tcpsync filter */
#define N20_RQA_TCP_SYNC_BASE (0xc0000)
#define N20_RQA_TCP_SYNC_OFF(off) (N20_RQA_TCP_SYNC_BASE + (off))
#define N20_RQA_TCP_SYNC_ACL(loc) (0x00 + 0x8 * (loc))
#define N20_RQA_TCP_SYNC_PRI(loc) (0x04 + 0x8 * (loc))

/* RQA tuple5 filter */
#define N20_NTUPLE_REG_BASE (0xd0000)
#define N20_NTUPLE_SIP(i) (0x00 + (0x20 * (i)))
#define N20_NTUPLE_DIP(i) (0x04 + (0x20 * (i)))
#define N20_NTUPLE_PORT(i) (0x08 + (0x20 * (i)))
#define N20_NTUPLE_FILTER(i) (0x0c + (0x20 * (i)))
#define N20_NTUPLE_POLICY(i) (0x10 + (0x20 * (i)))

#define N20_NTUPLE_OFF(off) (N20_NTUPLE_REG_BASE + (off))
#define F_T5_SET_DPORT(val, port) MODIFY_BITFIELD(val, port, 16, 16)
#define F_T5_SET_SPORT(val, port) MODIFY_BITFIELD(val, port, 16, 0)
#define F_T5_FILTER_EN BIT(31)
#define F_T5_VPORT_EN BIT(30)
#define F_T5_SET_VPORT_ID(val, id) MODIFY_BITFIELD(val, id, 7, 23)
#define F_T5_SET_PRIO_ID(val, id) MODIFY_BITFIELD(val, id, 3, 20)
#define F_T5_L4_TYPE_MASK BIT(19)
#define F_T5_DPORT_MASK BIT(18)
#define F_T5_SPORT_MASK BIT(17)
#define F_T5_DIP_MASK BIT(16)
#define F_T5_SIP_MASK BIT(15)
#define F_T5_SET_IP4_TYPE(val) MODIFY_BITFIELD(val, 0, 1, 8)
#define F_T5_SET_IP6_TYPE(val) MODIFY_BITFIELD(val, 1, 1, 8)
#define F_T5_SET_L4_TYPE(val, t) MODIFY_BITFIELD(val, t, 8, 0)

/* RQA RSS reg*/
#define N20_RSS_REG_BASE (0xe0000)
#define N20_RSS_OFF(off) (N20_RSS_REG_BASE + (off))

#define N20_RSS_VFT_CONFIG_MEM_BASE(i) (0x2000 + (4 * (i)))
#define N20_RSS_VFT_CONFIG_MEM(i) (0x2000 + (4 * (i)))
#define N20_RSS_PFT_CONFIG_MEM(i) (0x6000 + (4 * (i)))

#define N20_RSS_ACT_CONFIG_MEM(i) (0x4000 + (4 * (i)))
#define F_SET_VLAN_STRIP_EN(val, cmd) MODIFY_BITFIELD(val, cmd, 1, 29)
#define F_SET_VLAN_STRIP_CNT(val, cnt) MODIFY_BITFIELD(val, cnt, 2, 16)
#define F_SET_RETA_HASH_QUEUE_ID(val, id) MODIFY_BITFIELD(val, id, 9, 18)
#define F_RSS_RETA_QUEUE_EN BIT(30)
#define F_RSS_RETA_MASK_EN BIT(28)

#define N20_RSS_HASH_ENTRY(i, vfid) (0x0000 + ((i) << 2) + (vfid) * 0x40)
#define F_IPV6_HASH_SCTP_EN MCE_F_HASH_IPV6_SCTP
#define F_IPV4_HASH_SCTP_EN MCE_F_HASH_IPV4_SCTP
#define F_IPV6_HASH_UDP_EN MCE_F_HASH_IPV6_UDP
#define F_IPV4_HASH_UDP_EN MCE_F_HASH_IPV4_UDP
#define F_IPV6_HASH_TCP_EN MCE_F_HASH_IPV6_TCP
#define F_IPV4_HASH_TCP_EN MCE_F_HASH_IPV4_TCP
#define F_IPV6_HASH_EN MCE_F_HASH_IPV6
#define F_IPV4_HASH_EN MCE_F_HASH_IPV4
#define F_IPV6_HASH_TEID_EN MCE_F_HASH_IPV6_TEID
#define F_IPV4_HASH_TEID_EN MCE_F_HASH_IPV4_TEID
#define F_IPV6_HASH_SPI_EN MCE_F_HASH_IPV6_SPI
#define F_IPV4_HASH_SPI_EN MCE_F_HASH_IPV4_SPI
#define F_IPV6_HASH_FLEX_EN MCE_F_HASH_IPV6_FLEX
#define F_IPV4_HASH_FLEX_EN MCE_F_HASH_IPV4_FLEX
#define F_ONLY_HASH_FLEX_EN MCE_F_HASH_ONLY_FLEX
#define F_RSS_HASH_PTP_EN MCE_F_HASH_PTP
#define F_RSS_HASH_ORDER_EN MCE_F_HASH_ORDER
#define F_RSS_HASH_XOR_OR_TOP_EN MCE_F_HASH_XOR_OR_TOP
#define F_RSS_HASH_EN BIT(31)
#define N20_RSS_HASH_TYPE_CFG                                              \
	(F_IPV6_HASH_EN | F_IPV4_HASH_EN | F_IPV6_HASH_TCP_EN |            \
	 F_IPV4_HASH_TCP_EN | F_IPV6_HASH_UDP_EN | F_IPV4_HASH_UDP_EN |    \
	 F_IPV6_HASH_SCTP_EN | F_IPV4_HASH_SCTP_EN | F_ONLY_HASH_FLEX_EN | \
	 F_IPV6_HASH_FLEX_EN | F_IPV4_HASH_FLEX_EN)
/* PHY reg */
#define N20_PHY_BASE (0x30000)
#define N20_PHY_CTRL0 (0x0)
#define N20_PHY_RGMI_CTRL0 (0x200)

#define N20_PHY_OFF(off) (N20_PHY_BASE + (off))

/* MSIX reg */
#define N20_MSIX_BASE (0x30000)
#define N20_MSIX_RING_VEC(n) (0x7000 + (0x04 * (n)))
#define N20_IRQ_MB_ST_CLR (0xf108)
#define F_IRQ_AVOID_DROP_INTR_EN BIT(31)
#define N20_MSIX_OFF(off) (N20_MSIX_BASE + (off))
#define N20_MSIX_CFG_VF_NUM (0xb000)
#define N20_MSIX_MISC_IRQ_ST (0xb048)
#define N20_MSIX_MISC_IRQ_CLR (0xb044)
#define N20_MSIX_MISC_IRQ_VEC(i) (0xa000 + (i) * 4)

/* ============MBX ==== */
#define N20_MBX_BASE (0x20000 + 0x10000)
#define N20_MBX_OFF(off) (N20_MSIX_MBX_BASE + (off))

#define PF2FW_SHM_SZ 64
#define PF2FW_SHM 0x6000
#define PF2FW_MBX_CTRL (0x6100)

#define FW2PF_SHM_SZ 64
#define FW2PF_SHM (0x6040)
#define FW2PF_MBX_CTRL (0x6200)
#define FW2PF_MB_VEC 0x8600

#define PF2VF_SHM_SIZE 32
#define PF2VF_SHM(nr_vf) \
	(0x4000 + (nr_vf) * PF2VF_SHM_SIZE) /* CPU2VF_SHM,pf as CPU */
#define PF2VF_SHM_LOCK(nr_vf) \
	(0x5200 + (nr_vf) * 4) /* CPU2VF_MBX_CTRL, pf as cpu */
#define PF2VF_REQ_CTRL(nr_vf) (0x2200 + (nr_vf) * 4)

#define VF2PF_SHM_SIZE 64
#define VF2PF_SHM(nr_vf) (0x0000 + (nr_vf) * VF2PF_SHM_SIZE)
#define VF2PF_SHM_LOCK(nr_vf) (0x2200 + (nr_vf) * 4)
#define VF2PF_REQ_CTRL(nr_vf) (0x2000 + (nr_vf) * 4)
#define VF2PF_MB_VEC(nr_vf) (0x8200 + (nr_vf) * 4)

#define VF2PF_REQ_ST0 (0x2500)

/* ============ PTP ==== */

#define N20_MAC_PAUSE_TIMER 0x1c
#define BYPASS_PTP_TIMER_EN BIT(28)
#define N20_PTP_CFG_1 (0x283c)
#define N20_PTP_CFG (0x60)
#define N20_TS_CFG_S (0x300)
#define N20_TS_CFG_NS (0x304)
#define N20_TS_INCR_CNT (0x308) /* [15:0] 2  bit[31:16] 16 */
#define N20_INCR_CNT_NS_FINE (0x310)
#define N20_INCR_CNT_NS_FINE_2 (0x31c)
#define N20_INITIAL_UPDATE_CMD (0x30c)
#define N20_TS_GET_S (0x314)
#define N20_TS_GET_NS (0x318)
#define N20_TS_COMP (0x390)

#define N20_PTP_TCR_TSENA BIT(0) /*Timestamp Enable*/
#define N20_PTP_TX_EN BIT(1)
#define N20_PTP_RX_EN BIT(2)
/* Enable Timestamp for All Frames */
#define N20_PTP_TCR_TSENALL BIT(8)
/* Enable Processing of PTP over Ethernet Frames */
#define N20_PTP_TCR_TSIPENA BIT(9)
/* Enable Processing of PTP Frames Sent over IPv4-UDP */
#define N20_PTP_TCR_TSIPV4ENA BIT(10)
/* Enable Processing of PTP Frames Sent over IPv6-UDP */
#define N20_PTP_TCR_TSIPV6ENA BIT(11)
/* Enable Timestamp Snapshot for Event Messages */
#define N20_PTP_TCR_TSEVNTENA BIT(12)

/* pause fifo */
#define N20_FIFO0_DFT_DEEP (8192 - 112)
#define N20_UP_DEEP_FOR_FIFO (0x100)

#define N20_RDMA_REG_FUNC_SIZE (0x1C)
#define N20_RDMA_REG_PF_ID_ADDR (0x60)
#define N20_RDMA_HOL_BLOCKING_EN (0x200)
#define N20_RDMA_CFG_PRIO(i) (0x204 + (i) * 0x4)
#define N20_RDMA_FIFO_FULL_TH(i) (0x224 + (i) * 0x4)
#define N20_RDMA_US_VALUE (0x038)
#define N20_RDMA_DEADLOCK_VALUE (0x244)
#define N20_RDMA_DEADLOCK_EN (0x248)
#define N20_RDMA_DSCP_TABLE(i) (0x30 + (i) * 0x4)
#define N20_RDMA_CFG_PRIO_TC(i) (0x320 + (i) * 0x4)
#define N20_RDMA_BYTES_TC(i) (0x340 + (i) * 0x4)
#define N20_RDMA_TOTAL_BYTE (0x360)
#define N20_RDMA_TC_MODE (0x364)
#define N20_RDMA_TC_TIME (0x368)
#define RDMA_ETS_EN BIT(8)
#define N20_RDMA_TX_RX_ENABLE (0x24)
#define N20_RDMA_PRIO_TYPE (0x2c)
#define N20_RDMA_DCNQCN_OFF(i) (0x30000 + (i))
#define N20_RDMA_BTH(i) (0x20000 + (i))
void n20_enable_proc(struct mce_hw *hw);
void n20_disable_proc(struct mce_hw *hw);
#endif /*_MCE_HW_N20_H_*/
