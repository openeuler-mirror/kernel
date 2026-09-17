/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_HW_N20_H_
#define _MCEVF_HW_N20_H_

#define N20_VLAN_MAX_STRIP_CNT 2
#define N20_VLAN_DEFAULT_STRIP_CNT 1

/* ==============================N20 invariants start ====================*/
#define N20_PF_MAX_Q_CNT 512 /* pf max ring cnts */
#define N20_PF_CNT 1
#define N20_VF_CNT (N20_PF_MAX_Q_CNT / hw->ring_max_cnt - 1)
#define N20_RSS_TABLE_SIZE (hw->ring_max_cnt)
#define N20_RSS_HASH_KEY_SIZE (13 * 4)
#define N20_MAX_FDIR_CNT 32

#define N20_MBOX_IRQ_BASE 0
#define N20_NUM_MBOX_IRQS 1
#define N20_QVEC_IRQ_BASE 1
#define N20_RDMA_IRQ_BASE (hw->ring_max_cnt + N20_NUM_MBOX_IRQS)
#define N20_NUM_RDMA_IRQS 2
#define N20_MAX_IRQS (N20_RDMA_IRQ_BASE + N20_NUM_RDMA_IRQS)

#define N20_VAL_RX_TIMEOUT 1000
// #define N20_USECSTOCOUNT 250
#define N20_USECSTOCOUNT 500
/* the vf max entries is 512, setup 32 for fpga debug */
#define N20_VEB_MAX_ENTRIES 512
#define N20_VEB_BCMC_ADDR_ENTRY_OFF (N20_VEB_MAX_ENTRIES - 1)
#define N20_VEB_VF_ADDR_ENTRY_OFF (N20_VEB_BCMC_ADDR_ENTRY_OFF - N20_VF_CNT)

#define N20_VEB_VF_UC_INDEX(loc) \
	((loc) + N20_PF_CNT - N20_VEB_VF_ADDR_ENTRY_OFF)

#define N20_USE_FORCE_SETUP_RING_BASE 0
#define N20_USE_VPORT_ATTR_RING_BASE (hw->ring_max_cnt * _vfnum(hw->vfnum))

/* ==============================N20 invariants end ======================*/

#define MODIFY_BITFIELD(var, cmd, width, offset)                  \
	((var) = (((var) & ~((~(~0U << (width))) << (offset))) |     \
		  (((cmd) & ~(~0U << (width))) << (offset))))

/* NIC reg*/
#define N20_NIC_REG_BASE 0x30000
#define _NIC_F_(off) (N20_NIC_REG_BASE + (off))
#define N20_NIC_VFNUM 0x0000

#define N20_VFNUM_ISOLATED 0x30000
#define N20_VFNUM_NO_ISOLAT 0x7f000

/* Ring common REG */
#define N20_RING_BASE (0x0000)
#define _RING_F_(i) (N20_RING_BASE + (0x100 * (i)))

/* Ring Enable and interrupt status REG*/
#define N20_DMA_REG_RX_START 0x10
#define F_RX_START_FLR_EN BIT(1)
#define F_RX_START_EN BIT(0)
#define N20_DMA_REG_RX_READY 0x14
#define N20_DMA_REG_TX_START 0x18
#define F_TX_START_FLR_EN BIT(1)
#define F_TX_START_EN BIT(0)
#define N20_DMA_REG_TX_READY 0x1c
#define N20_DMA_REG_INT_STAT 0x20
#define N20_DMA_REG_INT_MASK 0x24
#define N20_DMA_REG_INT_CLEAR 0x28
#define N20_DMA_REG_INT_TRIG 0x2c
#define _F_N20_DMA_INT_SET_TRIG_TX (BIT(19) | BIT(3))
#define _F_N20_DMA_INT_CLR_TRIG_TX BIT(19)

/* Dma ring stats */
#define N20_DMA_REG_READ_CLEAD 0x90
#define N20_DMA_REG_RX_MISS_DROP 0x5c
#define N20_DMA_REG_RX_BYTES_LO 0xc0
#define N20_DMA_REG_RX_BYTES_HI 0xc4
#define N20_DMA_REG_RX_UNICAST_LO 0xc8
#define N20_DMA_REG_RX_UNICAST_HI 0xcc
#define N20_DMA_REG_RX_MULTICAST_LO 0xd0
#define N20_DMA_REG_RX_MULTICAST_HI 0xd4
#define N20_DMA_REG_RX_BROADCAST_LO 0xd8
#define N20_DMA_REG_RX_BROADCAST_HI 0xdc

#define N20_DMA_REG_TX_BYTES_LO 0xe0
#define N20_DMA_REG_TX_BYTES_HI 0xe4
#define N20_DMA_REG_TX_UNICAST_LO 0xe8
#define N20_DMA_REG_TX_UNICAST_HI 0xec
#define N20_DMA_REG_TX_MULTICAST_LO 0xf0
#define N20_DMA_REG_TX_MULTICAST_HI 0xf4
#define N20_DMA_REG_TX_BROADCAST_LO 0xf8
#define N20_DMA_REG_TX_BROADCAST_HI 0xfc

/* HW RX DIM */
#define N20_IRQ_MAX_200K 1500 /* 30 / ms 30000 /s */
#define N20_IRQ_MIN_200K 200 /* 5 / ms 5000 /s */

#define N20_IRQ_MAX_50K 50000
#define N20_DMA_REG_RX_PKT_RATE_LOW 0xA0
#define N20_DMA_REG_RX_PKT_RATE_HIGH 0xA4
#define N20_DMA_REG_RX_INT_FRAMES 0xA8
#define N20_DMA_REG_RX_INT_USECS 0xAC
/* HW TX DIM */
#define N20_DMA_REG_TX_PKT_RATE_LOW 0xB0
#define N20_DMA_REG_TX_PKT_RATE_HIGH 0xB4
#define N20_DMA_REG_TX_INT_FRAMES 0xB8
#define N20_DMA_REG_TX_INT_USECS 0xBC
#define N20_DMA_INT_INTERVAL_EN BIT(31)

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
#define F_RING_PFC_EN BIT(30)
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

/* ETH filter reg */
#define N20_ETH_FILTER_REG_BASE 0x90000
#define _ETH_FILTER_F_(off) (N20_ETH_FILTER_REG_BASE + (off))
#define N20_ETH_VM_IPORT_PVF(i) (0x0000 + (4 * (i)))
#define F_MAC_FILTER_PVF_EN BIT(14)
#define F_VLAN_FILTER_PVF_EN BIT(13)
#define N20_ETH_VEB_VLAN_PVF(i) (0x1800 + 4 * (i))
#define N20_ETH_VEB_ACT_PVF(i) _ETH_FILTER_F_(0x2800 + 4 * (i))
#define F_SET_VM_MATCH_INDEX(reg, val) MODIFY_BITFIELD(reg, val, 10, 8)

#define N20_ETH_FLTR_DMAC_RAL(i) (0x5000 + (4 * (i)))
#define N20_ETH_FLTR_DMAC_RAH(i) (0x5800 + (4 * (i)))
#define F_ETH_FLTR_DMAC_EN BIT(31)

#define N20_ETH_VM_DMAC_RAL(i) (0x0800 + (4 * (i)))
#define N20_ETH_VM_DMAC_RAH(i) (0x1000 + (4 * (i)))
#define N20_ETH_UC_HASH_TABLE(i) (0x4200 + (4 * (i)))
#define N20_ETH_MC_HASH_TABLE(i) (0x4400 + (4 * (i)))
#define N20_ETH_VLAN_HASH_TABLE(i) (0x4600 + (4 * (i)))

#define F_MAC_FILTER_EN BIT(31)

/* ETH vport attr */
#define N20_ETH_VPORT_ATTR_BASE (0x20000)
#define _ETH_VPORT_F_(off) (N20_ETH_VPORT_ATTR_BASE + (off))
#define N20_ETH_VPORT_ATTR_TABLE(i) _ETH_VPORT_F_(0x0000 + (i) * 0x0)

#define F_VPORT_TRUE_PROMISC_EN BIT(31)
#define F_VPORT_LIMIT_LEN_EN BIT(30)
#define F_SET_VPORT_MAX_LEN(val, len) MODIFY_BITFIELD(val, len, 14, 16)
#define F_SET_VPORT_DEFAULT_RING(val, len) MODIFY_BITFIELD(val, len, 9, 7)
#define F_VPORT_TUN_SELECT_INNER BIT(6)
#define F_VPORT_TUN_SELECT_INNER_OUTER_EN BIT(5)
#define F_VPORT_MC_PROMISC_EN BIT(4)
#define F_VPORT_UC_PROMISC_EN BIT(3)
#define F_VPORT_VLAN_PROMISC_EN BIT(2)
#define F_VPORT_DROP BIT(0)

#define N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) \
	(0x1000 * (((vfnum) / 32) + 1))
#define N20_ETH_VPORT_BITMAP_MEM_OFFSET(off) (4 * ((off) % 1024))
#define N20_ETH_VPORT_SET_BITMAP(vfnum, off)                  \
	_ETH_VPORT_F_(N20_ETH_VPORT_BITMAP_MEM_INDEX(vfnum) + \
		      N20_ETH_VPORT_BITMAP_MEM_OFFSET(off))

/* ETH vport attr */
#define N20_ETH_RQA_ETYPE_BASE 0xb0000

/* VF MC white lists table */
#define N20_ETH_VF_MC_FILTER_MEM_BASE(bank) (0x23000 + (bank) * 0x1000)
#define _ETH_VF_MC_F_(bank, vfnum, idx) \
	(N20_ETH_VF_MC_FILTER_MEM_BASE((bank)) + (idx) * 4)

/* RQA tuple5 filter */
#define N20_NTUPLE_REG_BASE 0xd0000
#define N20_NTUPLE_SIP(i) (0x0000 + (4 * (i)))
#define N20_NTUPLE_DIP(i) (0x0800 + (4 * (i)))
#define N20_NTUPLE_PORT(i) (0x1000 + (4 * (i)))
#define N20_NTUPLE_FILTER(i) (0x1800 + (4 * (i)))
#define N20_NTUPLE_POLICY(i) (0x2000 + (4 * (i)))

#define _NTUPLE_F_(off) (N20_NTUPLE_REG_BASE + (off))
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
#define F_T5_ACTION_DROP BIT(31)
#define F_T5_RING_EN BIT(30)
#define F_T5_VLAN_EN BIT(29)
#define F_T5_MARK_EN BIT(28)
#define F_T5_PRIO_EN BIT(27)
#define F_T5_SET_RING_ID(val, id) MODIFY_BITFIELD(val, id, 9, 18)
#define F_T5_SET_MARK(val, mr) MODIFY_BITFIELD(val, mr, 16, 0)

/* RQA RSS reg */
#define N20_RSS_HASH_ENTRY(i, f) _RSS_ENTRY_F_((0x0000 + ((i) << 2)))
#define N20_RSS_VFT_CONFIG_MEM(i) _RSS_VFT_F_(0x0000 + (4 * (i)))
#define N20_RSS_ACT_CONFIG_MEM(i) _RSS_ACT_F_(0x0000 + (4 * (i)))
#define _RSS_ENTRY_F_(off) (0x29000 + (off))
#define _RSS_VFT_F_(off) (0x2a000 + (off))
#define _RSS_ACT_F_(off) (0x2b000 + (off))

/* N20_RSS_ACT_CONFIG_MEM */
#define F_SET_VLAN_STRIP_EN(val, cmd) MODIFY_BITFIELD(val, cmd, 1, 29)
#define F_SET_VLAN_STRIP_CNT(val, cnt) MODIFY_BITFIELD(val, cnt, 2, 16)
#define F_SET_RETA_HASH_QUEUE_ID(val, id) MODIFY_BITFIELD(val, id, 9, 18)
#define F_RSS_RETA_QUEUE_EN BIT(30)
#define F_RSS_RETA_VLAN_EN BIT(29)
#define F_RSS_RETA_MASK_EN BIT(28)
#define F_RSS_RETA_RM_VLAN_TYPE BIT(16)

/* N20_RSS_HASH_ENTRY */
#define F_IPV6_HASH_SCTP_EN MCEVF_F_HASH_IPV6_SCTP
#define F_IPV4_HASH_SCTP_EN MCEVF_F_HASH_IPV4_SCTP
#define F_IPV6_HASH_UDP_EN MCEVF_F_HASH_IPV6_UDP
#define F_IPV4_HASH_UDP_EN MCEVF_F_HASH_IPV4_UDP
#define F_IPV6_HASH_TCP_EN MCEVF_F_HASH_IPV6_TCP
#define F_IPV4_HASH_TCP_EN MCEVF_F_HASH_IPV4_TCP
#define F_IPV6_HASH_EN MCEVF_F_HASH_IPV6
#define F_IPV4_HASH_EN MCEVF_F_HASH_IPV4
#define F_IPV6_HASH_TEID_EN MCEVF_F_HASH_IPV6_TEID
#define F_IPV4_HASH_TEID_EN MCEVF_F_HASH_IPV4_TEID
#define F_IPV6_HASH_SPI_EN MCEVF_F_HASH_IPV6_SPI
#define F_IPV4_HASH_SPI_EN MCEVF_F_HASH_IPV4_SPI
#define F_IPV6_HASH_FLEX_EN MCEVF_F_HASH_IPV6_FLEX
#define F_IPV4_HASH_FLEX_EN MCEVF_F_HASH_IPV4_FLEX
#define F_ONLY_HASH_FLEX_EN MCEVF_F_HASH_ONLY_FLEX
#define F_RSS_HASH_PTP_EN MCEVF_F_HASH_PTP
#define F_RSS_HASH_ORDER_EN MCEVF_F_HASH_ORDER
#define F_RSS_HASH_XOR_OR_TOP_EN MCEVF_F_HASH_XOR_OR_TOP
#define F_RSS_HASH_EN BIT(31)
#define N20_RSS_HASH_TYPE_CFG                                              \
	(F_IPV6_HASH_EN | F_IPV4_HASH_EN | F_IPV6_HASH_TCP_EN |            \
	 F_IPV4_HASH_TCP_EN | F_IPV6_HASH_UDP_EN | F_IPV4_HASH_UDP_EN |    \
	 F_IPV6_HASH_SCTP_EN | F_IPV4_HASH_SCTP_EN | F_ONLY_HASH_FLEX_EN | \
	 F_IPV6_HASH_FLEX_EN | F_IPV4_HASH_FLEX_EN)

/* MSIX reg */
#define N20_MSIX_RING_VEC 0xa800
#define N20_MSIX_BASE (0x10000 + N20_MSIX_RING_VEC)

/* ======== MBX ======= */
#define _MSIX_F_(id) (N20_MSIX_BASE + (id) * 0x4)
#define N20_MBX_BASE	 (0x20000 + 0x10000)

#define PF2VF_SHM_SIZE 32
/* === vf isolated disabled == */
/* CPU3VF_SHM,pf as CPU */
#define PF2VF_SHM_NO_ISOLATED(nr_vf) (0x4000 + (nr_vf) * PF2VF_SHM_SIZE)
/* VF2CPU_MBX_CTRL, pf as cpu */
#define PF2VF_SHM_LOCK_NO_ISOLATED(nr_vf) (0x5000 + (nr_vf) * 4)
#define PF2VF_REQ_CTRL_NO_ISOLATED(nr_vf) (0x2200 + (nr_vf) * 4)
#define PF2VF_MB_VEC_NO_ISOLATED(nr_vf)	  (0x8000 + (nr_vf) * 4)

#define VF2PF_SHM_SIZE			  64
#define VF2PF_SHM_NO_ISOLATED(nr_vf)	  (0x0000 + (nr_vf) * VF2PF_SHM_SIZE)
#define VF2PF_SHM_LOCK_NO_ISOLATED(nr_vf) (0x2000 + (nr_vf) * 4)
#define VF2PF_REQ_CTRL_NO_ISOLATED(nr_vf) (0x2000 + (nr_vf) * 4)

/* === vf isolated enabled == */
#define PF2VF_SHM_ISOLATED 0x19800 /* CPU2VF_SHM,pf as CPU */
#define PF2VF_SHM_LOCK_ISOLATED 0x1a000 /* VF2CPU_MBX_CTRL, pf as cpu */
#define PF2VF_REQ_CTRL_ISOLATED 0x19000
#define PF2VF_MB_VEC_ISOLATED 0x1c000

#define VF2PF_SHM_SIZE		64
#define VF2PF_SHM_ISOLATED 0x18000
#define VF2PF_SHM_LOCK_ISOLATED 0x18800
#define VF2PF_REQ_CTRL_ISOLATED VF2PF_SHM_LOCK_ISOLATED

/* TUNNEL RULE */
enum tunnel_policy_type {
	__TUNNEL_POLICY_TYPE_NONE,
	__TUNNEL_POLICY_TYPE_VLAN,
	__TUNNEL_POLICY_TYPE_VXLAN,
};

#endif /*_MCEVF_HW_N20_H_*/
