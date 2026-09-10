/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#ifndef RNPGBE_REGS_H
#define RNPGBE_REGS_H

/*             BAR2 memory                   */
/* ------------------------------------------*/
/*	module  | size  |  start   |    end  */
/*	DMA	| 32KB	| 0_0000H  | 0_7FFFH */
/*	REG	| 32KB	| 0_8000H  | 0_FFFFH */
/*	ETH	| 64KB	| 1_0000H  | 1_FFFFH */
/*	GMAC	| 32KB	| 2_0000H  | 2_7FFFH */
/*	MSIX    | 32KB  | 2_8000H  | 2_FFFFH */
/* ------------------------------------------*/

/* ==================== DMA Global Registers ==================== */
#define RNPGBE_RING_BASE (0x1000)
#define RING_OFFSET(queue_idx) (0x100 * (queue_idx))
#define RNP_DMA_VERSION (0x0000)
#define RNP_DMA_CONFIG (0x0004)
#define DMA_MAC_LOOPBACK BIT(0)
#define DMA_SWITCH_LOOPBACK BIT(1)
#define DMA_VEB_BYPASS BIT(4)
#define DMA_AXI_ORDER BIT(5)
#define DMA_RX_PADDING BIT(8)
#define DMA_MAP_MODE(n) ((n) << 12)
#define DMA_RX_FRAGMENT_BYTES(n) (((n) / 16) << 16)
#define RNP_DMA_STATUS (0x0008)
#define RNP_DMA_RX_DATA_PROG_FULL_THRESH (0x00a0)
#define DMA_RING_NUM (0xff << 24)
#define RC_CONTROL_HW (0x01)
#define RC_CONTROL_PHY_DRIVER (0x02)
#define RC_JUMP_STATUS (0x04)
#define RC_PHY_LINK_DONE (0x08)
#define RC_LINK_CHANGE (0x10)
#define RNP_DMA_DUMY (0x000c)
#define RNP_DMA_RX_START (0x10)
#define RNP_DMA_RX_READY (0x14)
#define RNP_DMA_TX_START (0x18)
#define RNP_DMA_TX_READY (0x1c)
#define RNP_DMA_INT_STAT (0x20)
#define RNP_DMA_INT_MASK (0x24)
#define TX_INT_MASK (0x1 << 1)
#define RX_INT_MASK (0x1 << 0)
#define RNP_DMA_INT_CLR (0x28)
#define RNP_DMA_INT_TRIG (0x2c)
#define RNP_DMA_AXI_EN (0x0010)
#define RX_AXI_RW_EN (0x03 << 0)
#define TX_AXI_RW_EN (0x03 << 2)
#define RNP_DMA_AXI_STAT (0x0014)
#define RNPGBE_VEB_MAC_MASK_LO (0x0020)
#define RNPGBE_VEB_MAC_MASK_HI (0x0024)
#define RNP_VEB_VLAN_MASK (0x0028)
#define DEBUG_PROBE_NUM 16
#define RNP_DMA_DEBUG_PROBE_LO_REG(n) (0x0100 + 0x08 * (n))
#define RNP_DMA_DEBUG_PROBE_HI_REG(n) (0x0100 + 0x08 * (n))
#define DEBUG_CNT_NUM 76
/* RX-Queue Registers */
#define RNP_DMA_REG_RX_DESC_BUF_BASE_ADDR_HI (0x30)
#define RNP_DMA_REG_RX_DESC_BUF_BASE_ADDR_LO (0x34)
#define RNP_DMA_REG_RX_DESC_BUF_LEN (0x38)
#define RNP_DMA_REG_RX_DESC_BUF_HEAD (0x3c)
#define RNP_DMA_REG_RX_DESC_BUF_TAIL (0x40)
#define RNP_DMA_REG_RX_DESC_FETCH_CTRL (0x44)
#define RNP_DMA_REG_RX_INT_DELAY_TIMER (0x48)
#define RNP_DMA_REG_RX_INT_DELAY_PKTCNT (0x4c)
#define RNP_DMA_REG_RX_ARB_DEF_LVL (0x50)
#define PCI_DMA_REG_RX_DESC_TIMEOUT_TH (0x54)
#define PCI_DMA_REG_RX_SCATTER_LENGTH (0x58)
/* TX-Queue Registers */
#define RNP_DMA_REG_TX_DESC_BUF_BASE_ADDR_HI (0x60)
#define RNP_DMA_REG_TX_DESC_BUF_BASE_ADDR_LO (0x64)
#define RNP_DMA_REG_TX_DESC_BUF_LEN (0x68)
#define RNP_DMA_REG_TX_DESC_BUF_HEAD (0x6c)
#define RNP_DMA_REG_TX_DESC_BUF_TAIL (0x70)
#define RNP_DMA_REG_TX_DESC_FETCH_CTRL (0x74)
#define RNP_DMA_REG_TX_INT_DELAY_TIMER (0x78)
#define RNP_DMA_REG_TX_INT_DELAY_PKTCNT (0x7c)
#define RNP_DMA_REG_TX_ARB_DEF_LVL (0x80)
#define RNP_DMA_REG_TX_FLOW_CTRL_TH (0x84)
#define RNP_DMA_REG_TX_FLOW_CTRL_TM (0x88)
#define RNP_DMA_PKT_FIFO_DATA_PROG_FULL_THRESH (0x0098)
/* VEB Registers */
#define VEB_TBL_CNTS 64
#define RNP_DMA_PORT_VBE_MAC_LO_TBL(port, vf)                                  \
	(0x80A0 + 4 * (port) + 0x100 * (vf))
#define RNP_DMA_PORT_VBE_MAC_HI_TBL(port, vf)                                  \
	(0x80B0 + 4 * (port) + 0x100 * (vf))
#define RNP_DMA_PORT_VEB_VID_TBL(port, vf) (0x80C0 + 4 * (port) + 0x100 * (vf))
#define RNP_DMA_PORT_VEB_VF_RING_TBL(port, vf)                                 \
	(0x80D0 + 4 * (port) + 0x100 * (vf))
#define RNP_DMA_STATS_MAC_TO_MAC (0x1b0)
#define RNP_DMA_STATS_SWITCH_TO_SWITCH (0x1a4)

/* ================================================================== */
#define RNPGBE_NIC_BASE (0x8000)
#define RNPGBE_TOP_NIC_REST_N (0x8010 - RNPGBE_NIC_BASE)
#define RNPGBE_TOP_MAC_OUI (0xc004 - RNPGBE_NIC_BASE)
#define RNPGBE_TOP_MAC_SN (0xc008 - RNPGBE_NIC_BASE)
#define RNPGBE_TOP_NIC_CONFIG (0x0004)

/* ==================== RNP-ETH Global Registers ==================== */
/*
 * [3:0]:
 * 4'b0000：RSS disable
 * 4'b0001：RSS only
 * 4'b0100：DCB and RSS--8*16
 * 4'b1010：POOLS and RSS--32*4
 * [3] :virtual enable
 * [16]:ipv4_hash_tcp_enable
 * [17]:ipv4_hash_enable
 * [20]:ipv6_hash_enable
 * [21]:ipv6_hash_tcp_enable
 * [22]:ipv4_hash_udp_enable
 * [23]:ipv6_hash_udp_enable
 * [24]:ipv4_hash_sctp_enable
 * [25]:ipv6_hash_sctp_enable
 */

#define INNER_L4_BIT BIT(6)
#define PKT_LEN_ERR (2)
#define HDR_LEN_ERR (1)
#define DROP_ALL_THRESH (2046) /* drop all rx */
#define RECEIVE_ALL_THRESH (0x270) /* receive all rx */
#define RNPGBE_VEB_TBL_CNTS 8
#define RNPGBE_DMA_RBUF_FIFO (0x00b0)
#define RNPGBE_DMA_PORT_VBE_MAC_LO_TBL(port, vf)                               \
	(0x10c0 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VBE_MAC_HI_TBL(port, vf)                               \
	(0x10c4 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VEB_VID_TBL(port, vf)                                  \
	(0x10C8 + 4 * (port) + 0x100 * (vf))
#define RNPGBE_DMA_PORT_VEB_VF_RING_TBL(port, vf)                              \
	(0x10cc + 4 * (port) + 0x100 * (vf))
#define RNPGBE_ETH_BASE (0x10000)
#define RNPGBE_ETH_TUPLE5_SAQF(n) (0xc000 + 0x04 * (n))
#define RNPGBE_ETH_TUPLE5_DAQF(n) (0xc400 + 0x04 * (n))
#define RNPGBE_ETH_TUPLE5_SDPQF(n) (0xc800 + 0x04 * (n))
#define RNPGBE_ETH_TUPLE5_FTQF(n) (0xcc00 + 0x04 * (n))
#define RNPGBE_ETH_TUPLE5_POLICY(n) (0xce00 + 0x04 * (n))
#define RNPGBE_ETH_DEFAULT_RX_MIN_LEN (0x80f0)
#define RNPGBE_ETH_DEFAULT_RX_MAX_LEN (0x80f4)
#define RNPGBE_ETH_VLAN_VME_REG(n) (0x8040 + 0x04 * (n))
#define RNPGBE_ETH_RSS_MASK (0x3ff0001)
#define RNPGBE_ETH_ENABLE_RSS_ONLY (0x3f30001)
#define RNPGBE_ETH_RSS_CONTROL (0x92a0)
#define RNPGBE_MRQC_IOV_EN (0x92a0)
#define RNPGBE_IOV_ENABLED BIT(3)
#define RNPGBE_ETH_SYNQF (0x9290)
#define RNPGBE_ETH_SYNQF_PRIORITY (0x9294)
#define RNPGBE_ETH_FCS_EN (0x804c)
#define RNPGBE_ETH_HIGH_WATER(n) (0x80c0 + (n) * (0x08))
#define RNPGBE_ETH_LOW_WATER(n) (0x80c4 + (n) * (0x08))
#define RNPGBE_ETH_WRAP_FIELD_TYPE (0x805c)
#define RNPGBE_ETH_TX_VLAN_CONTROL_EANBLE (0x0070)
#define RNPGBE_ETH_TX_VLAN_TYPE (0x0074)
#define RNPGBE_ETH_WHOLE_PKT_LEN_ERR_DROP (0x807c)
#define RNPGBE_RAH_AV 0x80000000
#define RNPGBE_ETH_RAR_RL(n) (0xa000 + 0x04 * (n))
#define RNPGBE_ETH_RAR_RH(n) (0xa400 + 0x04 * (n))
#define RNPGBE_FCTRL_BPE BIT(10)
#define RNPGBE_FCTRL_UPE BIT(9)
#define RNPGBE_FCTRL_MPE BIT(8)
#define RNPGBE_ETH_DMAC_FCTRL (0x9110)
#define RNPGBE_ETH_DMAC_MCSTCTRL (0x9114)
#define RNPGBE_MCSTCTRL_MULTICASE_TBL_EN BIT(4)
#define RNPGBE_MCSTCTRL_UNICASE_TBL_EN BIT(3)
#define RNPGBE_VM_DMAC_MPSAR_RING(entry)                                       \
	(0xb400 + (4 * (entry)))
#define RNPGBE_ETH_MUTICAST_HASH_TABLE(n) (0xac00 + 0x04 * (n))
#define RNPGBE_ETH_RSS_KEY (0x92d0)
#define RNPGBE_ETH_TC_IPH_OFFSET_TABLE(n) (0xe800 + 0x04 * (n))
#define RNPGBE_ETH_RSS_INDIR_TBL(n) (0xe000 + 0x04 * (n))
#define RNPGBE_ETH_VLAN_FILTER_TABLE(n) (0xb000 + 0x04 * (n))
#define RNPGBE_VFTA RNPGBE_ETH_VLAN_FILTER_TABLE
#define RNPGBE_VLVF(idx) (0xb600 + 4 * (idx))
#define RNPGBE_VLVF_TABLE(idx) (0xb700 + 4 * (idx))
#define RNPGBE_ETH_VLAN_FILTER_ENABLE (0x9118)
#define RNPGBE_PRIORITY_1_MARK (0x8080)
#define RNPGBE_PRIORITY_1 (400)
#define RNPGBE_PRIORITY_0 (300)
#define RNPGBE_PRIORITY_0_MARK (0x8084)
#define RNPGBE_PRIORITY_EN (0x8088)
#define RNPGBE_PRIORITY_EN_8023 (0x808c)
#define RNPGBE_ETH_LAYER2_ETQF(n) (0x9200 + 0x04 * (n))
#define RNPGBE_ETH_LAYER2_ETQS(n) (0x9240 + 0x04 * (n))
#define RNPGBE_ETH_BYPASS (0x8000)
#define RNPGBE_ETH_ERR_MASK_VECTOR (0x8060)
#define RNPGBE_ETH_PRIV_DATA_CONTROL_REG (0x8068)
#define RNPGBE_ETH_DEFAULT_RX_RING (0x806c)
#define RNPGBE_ETH_DOUBLE_VLAN_DROP (0x8078)
#define RNPGBE_HOST_FILTER_EN (0x800c)
#define RNPGBE_BAD_PACKETS_RECEIVE_EN (0x8024)
#define RNPGBE_REDIR_EN (0x8030)
#define WATCHDOG_TIMER_ERROR BIT(0)
#define RUN_FRAME_ERROR BIT(1)
#define GAINT_FRAME_ERROR BIT(2)
#define LATE_COLLISION_ERROR BIT(3)
#define GMII_ERROR BIT(4)
#define DRIBBLING_BIT_ERROR BIT(5)
#define CRC_ERROR BIT(6)
#define LENGTH_ERROR BIT(8)
#define DA_FILTER_ERROR BIT(9)
#define SA_FILTER_ERROR BIT(10)
#define RNPGBE_MAC_ERR_MASK (0x8034)
#define RNPGBE_ETH_SCTP_CHECKSUM_EN (0x8038)
#define RNPGBE_ETH_VLAN_RM_TYPE (0x8054)
#define RNPGBE_ETH_EXCEPT_DROP_PROC (0x0470)
#define RNPGBE_ETH_EMAC_PARSE_PROGFULL_THRESH (0x8098)
#define RNPGBE_ETH_TX_MUX_DROP (0x98)
#define RNPGBE_VEB_VFMPRC(n) (0x4018 + 0x100 * (n))
#define RNPGBE_VEB_VFBPRC(n) (0x401c + 0x100 * (n))
#define RNPGBE_RX_TIMEOUT_DROP(n) (0x404c + 0x100 * (n))
#define RNPGBE_STATISTIC_CRL(n) (0x4048 + 0x100 * (n))
/* rnpgbe statistics REG */
#define RNPGBE_RX_MAC_LCS_ERR_NUM (0x8308)
#define RNPGBE_TX_MULTI_NUM (0x214)
#define RNPGBE_TX_BROADCAST_NUM (0x218)
#define RNPGBE_RX_DROP_PKT_NUM (0X8230)
#define RNPGBE_RXTRANS_DROP (0x8908)
#define RNPGBE_RXTRANS_LCS_ERR_NUM (0x8924)
#define RNPGBE_RXTRANS_LEN_ERR_NUM (0x8928)
#define RNPGBE_RXTRANS_SLEN_ERR_NUM (0x8934)
#define RNPGBE_RXTRANS_GLEN_ERR_NUM (0x8938)
#define RNPGBE_RXTRANS_CUT_ERR_PKTS (0x894c)
#define RNPGBE_RXTRANS_EXCEPT_NUM (0x8950)
#define RNPGBE_RXTRANS_FCS_ERR_NUM (0x8954)
#define RNPGBE_DECAP_PKT_DROP1_NUM (0X82ec)
#define RNPGBE_MAC_GLEN_ERR_NUM (0X01a8)
#define RNPGBE_RX_DEBUG(n) (0x8400 + 0x04 * (n))
#define RNPGBE_ETH_HOST_L2_DROP_PKTS RNPGBE_RX_DEBUG(4)
#define RNPGBE_ETH_REDIR_INPUT_MATCH_DROP_PKTS RNPGBE_RX_DEBUG(5)
#define RNPGBE_ETH_ETYPE_DROP_PKTS RNPGBE_RX_DEBUG(6)
#define RNPGBE_ETH_TCP_SYN_DROP_PKTS RNPGBE_RX_DEBUG(7)
#define RNPGBE_ETH_REDIR_TUPLE5_DROP_PKTS RNPGBE_RX_DEBUG(8)

// tx status in hw
#define RNPGBE_ETH_3TO1_HOST (0x200)
#define RNPGBE_ETH_3TO1_SW (0x204)
#define RNPGBE_ETH_3TO1_BMC (0x208)
#define RNPGBE_ETH_3TO1_OUT (0x210)
#define RNPGBE_ETH_OUT_MULTIPLE (0x214)
#define RNPGBE_ETH_OUT_BROADCAST (0x218)
#define RNPGBE_ETH_OUT_PTP (0x21c)
#define RNPGBE_ETH_OUT_DROP (0x220)
#define RNPGBE_ETH_TX_TRANS (0x250)
#define RNPGBE_ETH_TX_TRANS_STATUS_0 (0x120)
#define RNPGBE_ETH_TX_TRANS_STATUS_1 (0x124)
#define RNPGBE_ETH_TX_TRANS_SOP (0x300)
#define RNPGBE_ETH_TX_TRANS_EOP (0x304)

// rx status in hw
// rx trans
#define RNPGBE_ETH_PKTS_IN (0x8900)
#define RNPGBE_ETH_PKTS_OUT (0x8904)
#define RNPGBE_ETH_PKTS_DRIP (0x8908)
#define RNPGBE_ETH_PKTS_IN_ETH2 (0x890c)
#define RNPGBE_ETH_PKTS_IN_8023 (0x8910)
#define RNPGBE_ETH_PKTS_IN_CONTROL (0x8914)
#define RNPGBE_ETH_PKTS_IN_UDP (0x8918)
#define RNPGBE_ETH_PKTS_IN_TCP (0x891c)
#define RNPGBE_ETH_PKTS_IN_ICMP (0x8920)
#define RNPGBE_ETH_PKTS_IN_LCS_ERR (0x8924)
#define RNPGBE_ETH_PKTS_IN_LEN_ERR (0x8928)
#define RNPGBE_ETH_PKTS_IN_DMAC_F (0x892c)
#define RNPGBE_ETH_PKTS_IN_SMAC_F (0x8930)
#define RNPGBE_ETH_PKTS_IN_SLEN_ERR (0x8934)
#define RNPGBE_ETH_PKTS_IN_GLEN_ERR (0x8938)
#define RNPGBE_ETH_PKTS_IN_IPH_ERR (0x893c)
#define RNPGBE_ETH_PKTS_IN_PAYLOAD_ERR (0x8940)
#define RNPGBE_ETH_PKTS_IN_IPV4 (0x8944)
#define RNPGBE_ETH_PKTS_IN_IPV6 (0x8948)
#define RNPGBE_ETH_PKTS_IN_CUT_ERR (0x894c)
#define RNPGBE_ETH_PKTS_IN_EXCEPT_BYTES (0x8950)
#define RNPGBE_ETH_PKTS_IN_FCS_ERR (0x8954)
#define RNPGBE_ETH_PKTS_IN_MAC_LEN_ERR (0x8958)
// emac gater
#define RNPGBE_GATHER_PKTS_IN (0x8240)
#define RNPGBE_GATHER_PKTS_OUT (0x8220)
#define RNPGBE_GATHER_PKTS_OUT_MUL (0x8224)
#define RNPGBE_GATHER_PKTS_OUT_BRO (0x8228)
#define RNPGBE_GATHER_PKTS_IN_DROP (0x8230)
#define RNPGBE_GATHER_PKTS_IN_MAC_CUT (0x8304)
#define RNPGBE_GATHER_PKTS_IN_MAC_LCS_ERR (0x8308)
#define RNPGBE_GATHER_PKTS_IN_MAC_LEN_ERR (0x830c)
#define RNPGBE_GATHER_PKTS_IN_MAC_SLEN_ERR (0x8310)
#define RNPGBE_GATHER_PKTS_IN_MAC_GLEN_ERR (0x8314)
#define RNPGBE_GATHER_PKTS_IN_MAC_FCS_ERR (0x8318)
#define RNPGBE_GATHER_PKTS_IN_SMALL_64 (0x831c)
#define RNPGBE_GATHER_PKTS_IN_LARGE_64 (0x8320)
// pip parse
#define RNPGBE_PARSE_PKTS_IN           (0x8290)
#define RNPGBE_PARSE_PKTS_OUT          (0x8294)
#define RNPGBE_PARSE_PKTS_ARP_REQUEST  (0x8250)
#define RNPGBE_PARSE_PKTS_ARP_RESPONS  (0x8254)
#define RNPGBE_PARSE_PKTS_ICMP         (0x8258)
#define RNPGBE_PARSE_PKTS_UDP          (0x825c)
#define RNPGBE_PARSE_PKTS_TCP          (0x8260)
#define RNPGBE_PARSE_PKTS_ARP_CUT      (0x8264)
#define RNPGBE_PARSE_PKTS_ND_CUT       (0x8268)
#define RNPGBE_PARSE_PKTS_SCTP         (0x826c)
#define RNPGBE_PARSE_PKTS_TCP_SYN      (0x8270)
#define RNPGBE_PARSE_PKTS_FRAGMENT     (0x827c)
#define RNPGBE_PARSE_PKTS_1_VLAN       (0x8280)
#define RNPGBE_PARSE_PKTS_2_VLANS      (0x8284)
#define RNPGBE_PARSE_PKTS_IPV4         (0x8288)
#define RNPGBE_PARSE_PKTS_IPV6         (0x828c)
#define RNPGBE_PARSE_PKTS_IP_HDR_ERR   (0x8298)
#define RNPGBE_PARSE_PKTS_IP_PKT_ERR   (0x829c)
#define RNPGBE_PARSE_PKTS_L3_HDR_CHK_ERR (0x82a0)
#define RNPGBE_PARSE_PKTS_L4_HDR_CHK_ERR (0x82a4)
#define RNPGBE_PARSE_PKTS_SCTP_HDR_CHK_ERR (0x82a8)
#define RNPGBE_PARSE_PKTS_VLAN_ERR       (0x82ac)
#define RNPGBE_PARSE_PKTS_RDMA          (0x82b0)
#define RNPGBE_PARSE_PKTS_ARP_AUTO_RESP (0x82b4)
#define RNPGBE_PARSE_PKTS_ICMPV6        (0x82b8)
#define RNPGBE_PARSE_PKTS_IPV6_EXTEND   (0x82bc)
#define RNPGBE_PARSE_PKTS_8023          (0x82c0)
#define RNPGBE_PARSE_PKTS_EXCEPT_SHORT  (0x82c4)
#define RNPGBE_PARSE_PKTS_PTP           (0x82c8)
#define RNPGBE_PARSE_PKTS_NS_REQ        (0x8274)
#define RNPGBE_PARSE_PKTS_NS_NA_AUTO_RES (0x8278)

/* ==================== PTP Registers ==================== */
#define RNPGBE_ETH_PTP_TX_HTIMES (RNPGBE_ETH_BASE + 0x0404)
#define RNPGBE_ETH_PTP_TX_LTIMES (RNPGBE_ETH_BASE + 0x0408)
#define RNPGBE_ETH_PTP_TX_TSVALUE_STATUS (RNPGBE_ETH_BASE + 0x040c)
#define RNPGBE_ETH_PTP_TX_CLEAR (RNPGBE_ETH_BASE + 0x0410)

/* ================================================================== */

/* ==================== RNPGBE Global Registers ==================== */
#define RNPGBE_LEGANCY_TIME (0xd000)
#define RNPGBE_LEGANCY_ENABLE (0xd004)
/* ================================================================== */

/* ==================== GMAC Global Registers ==================== */
#define RNPGBE_MAC_BASE (0x20000)
#define GMAC_MAC_UNICAST_LOW(i) (0x44 + (i) * 0x08)
#define GMAC_MAC_UNICAST_HIGH(i) (0x40 + (i) * 0x08)
#define GMAC_CONTROL 0x00000000 /* Configuration */
#define GMAC_FRAME_FILTER 0x00000004 /* Frame Filter */
#define GMAC_HASH_HIGH 0x00000008 /* Multicast Hash Table High */
#define GMAC_HASH_LOW 0x0000000c /* Multicast Hash Table Low */
#define GMAC_MII_ADDR 0x00000010 /* MII Address */
#define GMAC_MII_DATA 0x00000014 /* MII Data */
#define GMAC_FLOW_CTRL 0x00000018 /* Flow Control */
#define GMAC_PMT 0x0000002c
#define GMAC_COUNT_CONTROL (0x0100)

enum power_event {
	pointer_reset = 0x80000000,
	global_unicast = 0x00000200,
	wake_up_rx_frame = 0x00000040,
	magic_frame = 0x00000020,
	wake_up_frame_en = 0x00000004,
	magic_pkt_en = 0x00000002,
	power_down = 0x00000001,
};

#define GMAC_VTHM_MASK BIT(19)
#define GMAC_ESVL_MASK BIT(18)
#define GMAC_VTIM_MASK BIT(17)
#define GMAC_ETV_MASK BIT(16)
#define GMAC_VLAN_TAG_CTRL 0x0000001c
#define GMAC_CONTROL_DCRS 0x00010000 /* Disable carrier sense */
#define GMAC_CONTROL_PS 0x00008000 /* Port Select 0:GMI 1:MII */
#define GMAC_CONTROL_FES 0x00004000 /* Speed 0:10 1:100 */
#define GMAC_CONTROL_DO 0x00002000 /* Disable Rx Own */
#define GMAC_CONTROL_LM 0x00001000 /* Loop-back mode */
#define GMAC_CONTROL_DM 0x00000800 /* Duplex Mode */
#define GMAC_CONTROL_IPC 0x00000400 /* Checksum Offload */
#define GMAC_CONTROL_DR 0x00000200 /* Disable Retry */
#define GMAC_CONTROL_LUD 0x00000100 /* Link up/down */
#define GMAC_CONTROL_ACS 0x00000080 /* Auto Pad/FCS Stripping */
#define GMAC_CONTROL_DC 0x00000010 /* Deferral Check */
#define GMAC_CONTROL_TE 0x00000008 /* Transmitter Enable */
#define GMAC_CONTROL_RE 0x00000004 /* Receiver Enable */
/* GMAC Frame Filter defines */
#define GMAC_FRAME_FILTER_PR 0x00000001 /* Promiscuous Mode */
#define GMAC_FRAME_FILTER_HUC 0x00000002 /* Hash Unicast */
#define GMAC_FRAME_FILTER_HMC 0x00000004 /* Hash Multicast */
#define GMAC_FRAME_FILTER_DAIF 0x00000008 /* DA Inverse Filtering */
#define GMAC_FRAME_FILTER_PM 0x00000010 /* Pass all multicast */
#define GMAC_FRAME_FILTER_DBF 0x00000020 /* Disable Broadcast frames */
#define GMAC_FRAME_FILTER_PCF 0x00000080 /* Pass Control frames */
#define GMAC_FRAME_FILTER_SAIF 0x00000100 /* Inverse Filtering */
#define GMAC_FRAME_FILTER_SAF 0x00000200 /* Source Address Filter */
#define GMAC_FRAME_FILTER_HPF 0x00000400 /* Hash or perfect Filter */
#define GMAC_FRAME_FILTER_VLAN 0x00010000 /* vlan filter open */
#define GMAC_FRAME_FILTER_RA 0x80000000 /* Receive all mode */
/* GMII ADDR  defines */
#define GMAC_MII_ADDR_WRITE 0x00000002 /* MII Write */
#define GMAC_MII_ADDR_BUSY 0x00000001 /* MII Busy */
/* GMAC FLOW CTRL defines */
#define GMAC_FLOW_CTRL_PT_MASK 0xffff0000 /* Pause Time Mask */
#define GMAC_FLOW_CTRL_PT_SHIFT 16
#define GMAC_FLOW_CTRL_UP 0x00000008 /* Unicast pause frame enable */
#define GMAC_FLOW_CTRL_RFE 0x00000004 /* Rx Flow Control Enable */
#define GMAC_FLOW_CTRL_TFE 0x00000002 /* Tx Flow Control Enable */
#define GMAC_FLOW_CTRL_FCB_BPA 0x00000001 /* Flow Control Busy ... */
/* Energy Efficient Ethernet (EEE)
 *
 * LPI status, timer and control register offset
 */
/* EEE and LPI defines */
#define CORE_IRQ_TX_PATH_IN_LPI_MODE BIT(0)
#define CORE_IRQ_TX_PATH_EXIT_LPI_MODE BIT(1)
#define CORE_IRQ_RX_PATH_IN_LPI_MODE BIT(2)
#define CORE_IRQ_RX_PATH_EXIT_LPI_MODE BIT(3)
#define GMAC_LPI_CTRL_STATUS 0x0030
#define GMAC_LPI_TIMER_CTRL 0x0034
#define GMAC_INT_STATUS 0x00000038 /* interrupt status register */
#define GMAC_INT_STATUS_PMT BIT(3)
#define GMAC_INT_STATUS_MMCIS BIT(4)
#define GMAC_INT_STATUS_MMCRIS BIT(5)
#define GMAC_INT_STATUS_MMCTIS BIT(6)
#define GMAC_INT_STATUS_MMCCSUM BIT(7)
#define GMAC_INT_STATUS_TSTAMP BIT(9)
#define GMAC_INT_STATUS_LPIIS BIT(10)
/* LPI control and status defines */
#define LPI_CTRL_STATUS_LPITXA 0x00080000 /* Enable LPI TX Automate */
#define LPI_CTRL_STATUS_PLSEN 0x00040000 /* Enable PHY Link Status */
#define LPI_CTRL_STATUS_PLS 0x00020000 /* PHY Link Status */
#define LPI_CTRL_STATUS_LPIEN 0x00010000 /* LPI Enable */
#define LPI_CTRL_STATUS_RLPIST 0x00000200 /* Receive LPI state */
#define LPI_CTRL_STATUS_TLPIST 0x00000100 /* Transmit LPI state */
#define LPI_CTRL_STATUS_RLPIEX 0x00000008 /* Receive LPI Exit */
#define LPI_CTRL_STATUS_RLPIEN 0x00000004 /* Receive LPI Entry */
#define LPI_CTRL_STATUS_TLPIEX 0x00000002 /* Transmit LPI Exit */
#define LPI_CTRL_STATUS_TLPIEN 0x00000001 /* Transmit LPI Entry */
#define GMAC_MANAGEMENT_RX_UNDERSIZE (0x01a4)
#define GMAC_MANAGEMENT_TX_PAUSE (0x170)
#define GMAC_MANAGEMENT_RX_PAUSE (0x1D0)
/* ================================================================== */

/* ==================== RNP-MSIX Global Registers ==================== */
#define RING_VECTOR(n) (0x04 * (n))
/* ================================================================== */

/* ==================== OTHER Global Registers ==================== */
/* =====  PF-VF Functions ==== */
#define VF_NUM_REG 0xa3000
/* 8bit: 7:vf_actiove 6:fun0/fun1 [5:0]:vf_num */
#define VF_NUM(vfnum, fun) ((1 << 7) | (((fun) & 0x1) << 6) | ((vfnum) & 0x3f))
#define PF_NUM(fun) (((fun) & 0x1) << 6)
#define IS_VF(vfnum) (((vfnum) & (1 << 7)) ? 1 : 0)
/* 8bit: 7:vf_actiove [6:5]:fun0/fun1 [4:0]:vf_num */
#define PF_NUM_N500(fun) (((fun) & 0x3) << 5)
/* PFC Flow Control*/
/* ================================================================== */
#define RNPGBE_MAX_VF 8
#define RNPGBE_RSS_TBL_NUM 128
#define RNPGBE_RSS_TC_TBL_NUM 8
#define RNPGBE_MAX_TX_QUEUES 8
#define RNPGBE_MAX_RX_QUEUES 8
#define NCSI_RAR_NUM (2)
#define NCSI_MC_NUM (11)
/* we reserve 2 rar for ncsi */
#define RNPGBE_RAR_ENTRIES (32 - NCSI_RAR_NUM)
#define NCSI_RAR_IDX_START (32 - NCSI_RAR_NUM)
#define RNPGBE_MC_TBL_SIZE 128
#define RNPGBE_VFT_TBL_SIZE 128
#define RNPGBE_MSIX_VECTORS 26
#define RNPGBE_MAX_LAYER2_FILTERS 16
#define RNPGBE_MAX_TUPLE5_FILTERS 128

#endif /* RNPGBE_REGS_H */
