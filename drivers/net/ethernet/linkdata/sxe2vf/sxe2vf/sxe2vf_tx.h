/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_tx.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2VF_TX_H__
#define __SXE2VF_TX_H__
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
struct sxe2vf_adapter;

#define SXE2VF_TX_DESC(q, i)                                                   \
	(&(((union sxe2vf_tx_data_desc *)((q)->desc.base_addr))[i]))

#define SXE2VF_TX_CTXT_DESC(q, i)                                              \
	(&(((struct sxe2vf_tx_context_desc *)((q)->desc.base_addr))[i]))

#define SXE2VF_TX_DATA_DESC_CMD_SHIFT	 4
#define SXE2VF_TX_DATA_DESC_OFFSET_SHIFT 16
#define SXE2VF_TX_DATA_DESC_BUF_SZ_SHIFT 34
#define SXE2VF_TX_DATA_DESC_L2TAG1_SHIFT 48
#define SXE2VF_TX_DATA_DESC_CMD_MASK	 (0xFFFUL << SXE2VF_TX_DATA_DESC_CMD_SHIFT)
#define SXE2VF_TX_DATA_DESC_OFFSET_MASK                                        \
	(0x3FFFFULL << SXE2VF_TX_DATA_DESC_OFFSET_SHIFT)
#define SXE2VF_TX_DATA_DESC_BUF_SZ_MASK                                        \
	(0x3FFFULL << SXE2VF_TX_DATA_DESC_BUF_SZ_SHIFT)
#define SXE2VF_TX_DATA_DESC_L2TAG1_MASK                                        \
	(0xFFFFULL << SXE2VF_TX_DATA_DESC_L2TAG1_SHIFT)

#define SXE2VF_TX_CTXT_DESC_EIPLEN_SHIFT 2
#define SXE2VF_TX_CTXT_DESC_NATLEN_SHIFT 12
#define SXE2VF_TX_CTXT_DESC_L4T_CS_SHIFT 23
#define SXE2VF_TX_CTXT_DESC_L4TUNT_SHIFT 9
#define SXE2VF_TX_CTXT_DESC_UDP_TUNNE	 BIT_ULL(SXE2VF_TX_CTXT_DESC_L4TUNT_SHIFT)
#define SXE2VF_TX_CTXT_DESC_GRE_TUNNE                                          \
	(0x2ULL << SXE2VF_TX_CTXT_DESC_L4TUNT_SHIFT)
#define SXE2VF_TX_CTXT_DESC_L4T_CS_MASK                                        \
	BIT_ULL(SXE2VF_TX_CTXT_DESC_L4T_CS_SHIFT)

#define SXE2VF_TX_CTXT_DESC_CMD_SHIFT	  4
#define SXE2VF_TX_CTXT_DESC_TSO_LEN_SHIFT 30
#define SXE2VF_TX_CTXT_DESC_MSS_SHIFT	  50
#define SXE2VF_TX_CTXT_DESC_VSI_SHIFT	  50
#define SXE2VF_TX_CTXT_DESC_CMD_MASK	  (0x7FUL << SXE2VF_TX_CTXT_DESC_CMD_SHIFT)
#define SXE2VF_TX_CTXT_DESC_TSO_LEN_MASK                                       \
	(0x3FFFFULL << SXE2VF_TX_CTXT_DESC_TSO_LEN_SHIFT)
#define SXE2VF_TX_CTXT_DESC_VSI_MASK (0x3FFULL << SXE2VF_TX_CTXT_DESC_VSI_SHIFT)
#define SXE2VF_BYTES_PER_WORD	     2
#define SXE2VF_BYTES_PER_DWORD	     4

enum sxe2vf_txdd_offset_fields_relative_shift {
	SXE2VF_TXDD_MACLEN_S = 0,
	SXE2VF_TXDD_IPLEN_S  = 7,
	SXE2VF_TXDD_L4LEN_S  = 14
};

#define SXE2VF_TXDD_MACLEN_M (0x7FUL << SXE2VF_TXDD_MACLEN_S)
#define SXE2VF_TXDD_IPLEN_M  (0x7FUL << SXE2VF_TXDD_IPLEN_S)
#define SXE2VF_TXDD_L4LEN_M  (0xFUL << SXE2VF_TXDD_L4LEN_S)

#define SXE2VF_TXCD_QW1_IPSEC_MODE_S	    11
#define SXE2VF_TXCD_QW1_IPSEC_MODE_M	    BIT_ULL(SXE2VF_TXCD_QW1_IPSEC_MODE_S)
#define SXE2VF_TXCD_QW1_IPSEC_EN_S	    12
#define SXE2VF_TXCD_QW1_IPSEC_EN_M	    BIT_ULL(SXE2VF_TXCD_QW1_IPSEC_EN_S)
#define SXE2VF_TXCD_QW1_IPSEC_ENGINE_MODE_S 13
#define SXE2VF_TXCD_QW1_IPSEC_ENGINE_MODE_M                                    \
	BIT_ULL(SXE2VF_TXCD_QW1_IPSEC_ENGINE_MODE_S)
#define SXE2VF_TXCD_QW1_IPSEC_SA_IDX_S 16
#define SXE2VF_TXCD_QW1_IPSEC_SA_IDX_M                                         \
	(0x1FFF << SXE2VF_TXCD_QW1_IPSEC_SA_IDX_S)

#define SXE2VF_TXDD_MACLEN_MAX                                                 \
	((SXE2VF_TXDD_MACLEN_M >> SXE2VF_TXDD_MACLEN_S) * SXE2VF_BYTES_PER_WORD)
#define SXE2VF_TXDD_IPLEN_MAX                                                  \
	((SXE2VF_TXDD_IPLEN_M >> SXE2VF_TXDD_IPLEN_S) * SXE2VF_BYTES_PER_DWORD)
#define SXE2VF_TXDD_L4LEN_MAX                                                  \
	((SXE2VF_TXDD_L4LEN_M >> SXE2VF_TXDD_L4LEN_S) * SXE2VF_BYTES_PER_DWORD)
#define SXE2VF_TXCD_QW1_MSS_MIN 88

enum sxe2vf_tx_features {
	SXE2VF_TX_FEATURE_TSO		       = BIT(0),
	SXE2VF_TX_FEATURE_HW_VLAN	       = BIT(1),
	SXE2VF_TX_FEATURE_MACLEN	       = BIT(2),
	SXE2VF_TX_FEATURE_DUMMY_PKT	       = BIT(3),
	SXE2VF_TX_FEATURE_TSYN		       = BIT(4),
	SXE2VF_TX_FEATURE_IPV4		       = BIT(5),
	SXE2VF_TX_FEATURE_IPV6		       = BIT(6),
	SXE2VF_TX_FEATURE_TUNNEL	       = BIT(7),
	SXE2VF_TX_FEATURE_HW_OUTER_SINGLE_VLAN = BIT(8),
};

struct sxe2vf_tx_context_desc {
	__le32 tunneling_params;
	__le16 l2tag2;
	__le16 ipset_offset;
	__le64 qw1;
};

union sxe2vf_tx_data_desc {
	struct {
		__le64 buf_addr;
		__le64 cmd_type_offset_bsz;
	} read;
	struct {
		__le64 rsvd;
		__le64 dd;
	} wb;
};

struct sxe2vf_tx_offload_info {
	struct sxe2vf_adapter *adapter;
	u32 data_desc_cmd;
	u32 data_desc_offset;
	u32 data_desc_l2tag1;
	u32 ctxt_desc_tunnel;
	u64 ctxt_desc_qw1;
	u16 ctxt_desc_ipsec_offset;
	u16 ctxt_desc_l2tag2;
};

enum sxe2vf_tx_desc_type {
	SXE2VF_TX_DESC_DTYPE_DATA = 0x0,
	SXE2VF_TX_DESC_DTYPE_CTXT = 0x1,
	SXE2VF_TX_DESC_DTYPE_FLTR_PROG = 0x8,
	SXE2VF_TX_DESC_DTYPE_DESC_DONE = 0xF,
};

enum sxe2vf_tx_data_desc_cmd_bits {
	SXE2VF_TX_DATA_DESC_CMD_EOP	       = 0x0001,
	SXE2VF_TX_DATA_DESC_CMD_RS	       = 0x0002,
	SXE2VF_TX_DATA_DESC_CMD_MACSEC	       = 0x0004,
	SXE2VF_TX_DATA_DESC_CMD_IL2TAG1	       = 0x0008,
	SXE2VF_TX_DATA_DESC_CMD_DUMMY	       = 0x0010,
	SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV6      = 0x0020,
	SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV4      = 0x0040,
	SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV4_CSUM = 0x0060,
	SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_TCP   = 0x0100,
	SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_SCTP  = 0x0200,
	SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_UDP   = 0x0300,
	SXE2VF_TX_DATA_DESC_CMD_RE	       = 0x0400,
};

enum sxe2vf_tx_ctxt_desc_cmd_bits {
	SXE2VF_TX_CTXT_DESC_CMD_TSO	         = 0x01,
	SXE2VF_TX_CTXT_DESC_CMD_TSYN	     = 0x02,
	SXE2VF_TX_CTXT_DESC_CMD_IL2TAG2	     = 0x04,
	SXE2VF_TX_CTXT_DESC_CMD_IL2TAG2_IL2H = 0x08,
	SXE2VF_TX_CTXT_DESC_CMD_SWTCH_NOTAG  = 0x00,
	SXE2VF_TX_CTXT_DESC_CMD_SWTCH_UPLINK = 0x10,
	SXE2VF_TX_CTXT_DESC_CMD_SWTCH_LOCAL  = 0x20,
	SXE2VF_TX_CTXT_DESC_CMD_SWTCH_VSI    = 0x30,
	SXE2VF_TX_CTXT_DESC_CMD_RESERVED     = 0x40
};

enum sxe2vf_tx_ctxt_desc_eipt_bits {
	SXE2VF_TX_CTXT_DESC_EIPT_NONE	 = 0x0,
	SXE2VF_TX_CTXT_DESC_EIPT_IPV6	 = 0x1,
	SXE2VF_TX_CTXT_DESC_IPV4_NO_CSUM = 0x2,
	SXE2VF_TX_CTXT_DESC_IPV4	 = 0x3,
};

enum sxe2vf_tx_data_desc_len_fields_shift {
	SXE2VF_TX_DATA_DESC_MACLEN_SHIFT = 0,
	SXE2VF_TX_DATA_DESC_IPLEN_SHIFT  = 7,
	SXE2VF_TX_DATA_DESC_L4_LEN_SHIFT = 14
};

union sxe2vf_ip_hdr {
	struct iphdr *v4;
	struct ipv6hdr *v6;
	unsigned char *hdr;
};

union sxe2vf_l4_hdr {
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned char *hdr;
};

s32 sxe2vf_tx_cfg(struct sxe2vf_vsi *vsi);
void sxe2vf_tx_rings_res_free(struct sxe2vf_vsi *vsi);

void sxe2vf_tx_rings_clean(struct sxe2vf_vsi *vsi);

bool sxe2vf_txq_irq_clean(struct sxe2vf_queue *txq, s32 napi_budget);
s32 sxe2vf_txqs_stop(struct sxe2vf_vsi *vsi);
netdev_tx_t sxe2vf_xmit(struct sk_buff *skb, struct net_device *netdev);
void sxe2vf_tx_timeout(struct net_device *netdev,
		       __always_unused unsigned int txqueue);

s32 sxe2vf_tx_hw_cfg(struct sxe2vf_vsi *vsi);

#endif

