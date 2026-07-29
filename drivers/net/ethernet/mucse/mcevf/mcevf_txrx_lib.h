/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_TXRX_LIB_H_
#define _MCEVF_TXRX_LIB_H_

#define MCEVF_RX_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

#define MCEVF_DESC(R, i) (&(((struct mcevf_desc *)((R)->desc))[i]))
#define MCEVF_TX_DESC(R, i) (&(((struct mcevf_tx_desc *)((R)->desc))[i]))
#define MCEVF_RXDESC_DOWN(R, i) \
	(&(((struct mcevf_rx_desc_down *)((R)->desc))[i]))
#define MCEVF_RXDESC_UP(R, i) \
	(&(((struct mcevf_rx_desc_up *)((R)->desc))[i]))

/* Ring common attribute*/
#define MCEVF_TXD_COUNT (1024) // tx desc count
#define MCEVF_RXD_COUNT (4096) // rx desc count
#define MCEVF_DESC_SIZE (32)
#define MCEVF_PKT_TIMEOUT_TX (30)
#define MCEVF_PKT_TIMEOUT_RX (30)
#define MCEVF_TX_PKT_POLL_BUDGET (0x40)
#define MCEVF_RX_PKT_POLL_BUDGET (0x40)
#define MCEVF_USECSTOCOUNT (62)

/* Rx Desc */
#define MCEVF_RXD_CMD_EOP BIT(0)
#define MCEVF_RXD_CMD_DD BIT(1)
#define MCEVF_RXD_CMD_RS BIT(2)

/* Tx Desc */
#define MCEVF_TXD_CMD_EOP BIT(0)
#define MCEVF_TXD_CMD_DD BIT(1)
#define MCEVF_TXD_CMD_RS BIT(2)
#define MCEVF_TXD_CMD_VLAN_VALID BIT(26)

enum l4_type {
	L4TYPE_RES = 0,
	L4TYPE_FRAG = 1,
	L4TYPE_UDP,
	L4TYPE_TCP,
	L4TYPE_SCTP,
	L4TYPE_ICMP,
	L4TYPE_ICMPV6,
	L4TYPE_PAY,
	L4TYPE_PTPV1,
	L4TYPE_PTPV2,
	L4TYPE_ESP,
	L4TYPE_802_3,
	L4TYPE_WPI,
	L4TYPE_MAC_ERR,
};

enum l3_type {
	L3TYPE_RES = 0,
	L3TYPE_IPV4,
	L3TYPE_IPV6,
	L3TYPE_ARP,
};

enum vlan_offload {
	VLAN_NO_OFLD = 0,
	VLAN0_OFLD = 1,
	VLAN1_OFLD = 2,
	VLAN2_OFLD = 3,
};

enum tunnel_type {
	OUTTER_TYPE = 0,
	INNER_VXLAN = 1,
	INNER_GRE = 2,
	INNER_GENEVE,
	INNER_GTP_U,
	INNER_GTP_C,
	INNER_ESP,
	INNER_UDP_ENCAP_ESP,
};

#define FORM_DESC(var, cmd, width, offset)                        \
	((var) = (((var) & ~((~(~0UL << (width))) << (offset))) | \
		(((cmd) & ~(~0UL << (width))) << (offset))))
#define GET_DESC(var, width, offset) \
	(((var) & (~(~0UL << (width)) << (offset))) >> (offset))

/* tx desc config */
#define SET_CMD_EOP(var) FORM_DESC(var, 1, 1, 0)
#define SET_CMD_RS(var) FORM_DESC(var, 1, 1, 2)
#define SET_CMD_PRIO_ID(var, val) FORM_DESC(var, val, 3, 3)
#define SET_CMD_ENABLE_PRIO(var) FORM_DESC(var, 1, 1, 6)
#define SET_CMD_TSO(var) FORM_DESC(var, 1, 1, 7)
#define CMD_TSO_STATUS(var) GET_DESC(var, 1, 7)
#define SET_CMD_TYPE(var) FORM_DESC(var, 1, 1, 8)
#define SET_CMD_RPU_FLAG(var) FORM_DESC(var, 1, 1, 9)
#define SET_CMD_L4_TYPE(var, val) FORM_DESC(var, val, 4, 10)
#define SET_CMD_L3_TYPE(var, val) FORM_DESC(var, val, 2, 14)
#define SET_CMD_L3_CHK_OFLD(var) FORM_DESC(var, 1, 1, 18)
#define SET_CMD_L4_CHK_OFLD(var) FORM_DESC(var, 1, 1, 19)
#define SET_TSO_SEG_NUM(var, val) FORM_DESC(var, val, 8, 0)
#define SET_CMD_INNER_L3_CHK_OFLD(var) FORM_DESC(var, 1, 1, 20)
#define SET_CMD_INNER_L4_CHK_OFLD(var) FORM_DESC(var, 1, 1, 21)
#define SET_CMD_TUNNEL_TYPE(var, val) FORM_DESC(var, val, 3, 22)
#define SET_CMD_PTP(var) FORM_DESC(var, 1, 1, 25)
#define SET_CMD_VLAN_VALID(var) FORM_DESC(var, 1, 1, 26)
#define SET_CMD_VLAN_OUTER_TYPE(var, val) FORM_DESC(var, val, 3, 27)
#define SET_CMD_VLAN_OFLD(var, val) FORM_DESC(var, val, 2, 30)

#define SET_MAC_VLAN_CTRL_CNT(var, val) FORM_DESC(var, val, 2, 11)
#define SET_MAC_VLAN_CTRL_INNER_TYPE(var, val) FORM_DESC(var, val, 3, 0)

#define SET_INNER_L3_TYPE(var, val) FORM_DESC(var, val, 2, 8)
#define SET_INNER_L4_TYPE(var, val) FORM_DESC(var, val, 4, 12)

#define SET_L2_HDR_LEN(var, val) (var = (((var) & 0x01ff) | ((val) << 9)))
#define SET_L3_HDR_LEN(var, val) (var = (((var) & 0xfe00) | (val)))
#define SET_L4_HDR_LEN(var, val) \
	(var = (((var) & 0xff00) | ((val) & 0x00ff)))
#define SET_TUNNEL_HDR_LEN(var, val) \
	(var = (((var) & 0x00ff) | (((val) & 0xff) << 8)))

/* ======================== get rx desc info ======================= */
/* rx vlan_tpid */
#define GET_RD_VLAN_TPID_OUTER_TYPE(var) (GET_DESC(var, 3, 0))
#define GET_RD_VLAN_TPID_MIDDLE_TYPE(var) (GET_DESC(var, 3, 3))
#define GET_RD_VLAN_TPID_INNER_TYPE(var) (GET_DESC(var, 3, 6))
#define GET_RD_VLAN_TAG2(rx_desc) ((rx_desc)->timestamp_h_vlan_tag2 >> 16)
/* err_cmd */
#define RD_MAC_ERR BIT(0)
#define RD_HDR_ERR BIT(1)
#define RD_O_L3_CSM_ERR BIT(2)
#define RD_O_L4_CSM_ERR BIT(3)
#define RD_I_L3_CSM_ERR BIT(4)
#define RD_I_L4_CSM_ERR BIT(5)
#define GET_RD_ERR(var) (GET_DESC(var, 6, 0))
#define RD_MASK_VALID BIT(8)
#define RD_RSS_VALID BIT(9)
#define GET_RD_VLAN_STRIP(var) (GET_DESC(var, 2, 10))
/* cmd */
#define GET_RD_VLAN_VALID(var) (GET_DESC(var, 1, 3))
#define GET_RD_QINQ_VALID(var) (GET_DESC(var, 3, 4) & (0x5))
#define GET_RD_O_L3_TYPE(var) (GET_DESC(var, 2, 7))
#define GET_RD_O_L4_TYPE(var) (GET_DESC(var, 4, 9))
#define GET_RD_TUNNEL_TYPE(var) (GET_DESC(var, 3, 13))

static inline void mcevf_buid_ctob(struct mcevf_tx_desc *b_desc,
				   struct mcevf_tx_desc *c_desc)
{
	b_desc->outer_hdr_len = cpu_to_le16(c_desc->outer_hdr_len);
	b_desc->inner_hdr_len = cpu_to_le16(c_desc->inner_hdr_len);
	b_desc->vlan0 = cpu_to_le16(c_desc->vlan0);
	b_desc->vlan1 = cpu_to_le16(c_desc->vlan1);
	b_desc->vlan2 = cpu_to_le16(c_desc->vlan2);
	b_desc->mss = cpu_to_le16(c_desc->mss);
	b_desc->l4_hdr_len = cpu_to_le16(c_desc->l4_hdr_len);
	b_desc->mac_vlan_ctl = cpu_to_le16(c_desc->mac_vlan_ctl);
	b_desc->priv_inner_type = cpu_to_le16(c_desc->priv_inner_type);
	b_desc->cmd = cpu_to_le32(c_desc->cmd);
}

void mcevf_process_skb_fields(struct mcevf_ring *rx_ring,
			      struct mcevf_rx_desc_up *rx_desc,
			      struct sk_buff *skb);

#endif /*_MCEVF_TXRX_LIB_H_*/
