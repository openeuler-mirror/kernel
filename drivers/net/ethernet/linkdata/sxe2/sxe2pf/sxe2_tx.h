/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_tx.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_TX_H__
#define __SXE2_TX_H__

#include <linux/ip.h>
#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/dst_metadata.h>

#include "sxe2.h"
#include "sxe2_drv_cmd.h"

#define SXE2_BYTES_PER_WORD  (2)
#define SXE2_BYTES_PER_DWORD (4)

#define	SXE2_UCMD_TXQ_MODE_DEFAULT          0
#define	SXE2_UCMD_TXQ_MODE_TM               1
#define	SXE2_UCMD_TXQ_MODE_HIGH_PERFORMANCE 2
#define	SXE2_UCMD_TXQ_MODE_INVALID          3

#define SXE2_TXQ_LEGACY (1)
#define SXE2_TXQ_VMVF_TYPE_VF (0x0)
#define SXE2_TXQ_VMVF_TYPE_VM (0x1)
#define SXE2_TXQ_VMVF_TYPE_PF (0x2)

#define SXE2_DESC_UNUSED(R)                                                   \
	({ \
		typeof(R) __R = (R); \
		((u16)((((__R)->next_to_clean > (__R)->next_to_use) ? 0 : (__R)->depth) +   \
		       (__R)->next_to_clean - (__R)->next_to_use - 1)); \
	})
#define SXE2_TX_DESC(q, i)                                                    \
	(&(((union sxe2_tx_data_desc *)((q)->desc.base_addr))[i]))
#define SXE2_TXCD(q, i)                                                       \
	(&(((struct sxe2_tx_context_desc *)((q)->desc.base_addr))[i]))
#define SXE2_TXFD(q, i)                                                       \
	(&(((struct sxe2_tx_fnav_desc *)((q)->desc.base_addr))[i]))

#define SXE2_TXDD_CMD_S	   (4)
#define SXE2_TXDD_OFFSET_S (16)
#define SXE2_TXDD_BUF_SZ_S (34)
#define SXE2_TXDD_L2TAG1_S (48)
#define SXE2_TXDD_CMD_M	   (0xFFFUL << SXE2_TXDD_CMD_S)
#define SXE2_TXDD_OFFSET_M (0x3FFFFULL << SXE2_TXDD_OFFSET_S)
#define SXE2_TXDD_BUF_SZ_M (0x3FFFULL << SXE2_TXDD_BUF_SZ_S)
#define SXE2_TXDD_L2TAG1_M (0xFFFFULL << SXE2_TXDD_L2TAG1_S)

enum sxe2_txdd_offset_fields_relative_shift {
	SXE2_TXDD_MACLEN_S = 0,
	SXE2_TXDD_IPLEN_S  = 7,
	SXE2_TXDD_L4LEN_S  = 14
};

#define SXE2_TXDD_MACLEN_M (0x7FUL << SXE2_TXDD_MACLEN_S)
#define SXE2_TXDD_IPLEN_M  (0x7FUL << SXE2_TXDD_IPLEN_S)
#define SXE2_TXDD_L4LEN_M  (0xFUL << SXE2_TXDD_L4LEN_S)

#define SXE2_TXCD_QW0_EIPLEN_S	   (2)
#define SXE2_TXCD_QW0_L4TUNT_S	   (9)
#define SXE2_TXCD_QW0_L4TUNLEN_S   (12)
#define SXE2_TXCD_QW0_L4T_CS_S	   (23)
#define SXE2_TXCD_QW0_L4TUNT_UDP_M BIT_ULL(SXE2_TXCD_QW0_L4TUNT_S)
#define SXE2_TXCD_QW0_L4TUNT_GRE_M (0x2ULL << SXE2_TXCD_QW0_L4TUNT_S)
#define SXE2_TXCD_QW0_L4T_CS_M	   BIT_ULL(SXE2_TXCD_QW0_L4T_CS_S)

#define SXE2_TXCD_QW1_CMD_S	      (4)
#define SXE2_TXCD_QW1_TSO_TOTAL_LEN_S (30)
#define SXE2_TXCD_QW1_MSS_S	      (50)
#define SXE2_TXCD_QW1_VSI_S	      (50)
#define SXE2_TXCD_QW1_CMD_M	      (0x7FUL << SXE2_TXCD_QW1_CMD_S)
#define SXE2_TXCD_QW1_TSO_TOTAL_LEN_M                                         \
	(0x3FFFFULL << SXE2_TXCD_QW1_TSO_TOTAL_LEN_S)
#define SXE2_TXCD_QW1_VSI_M		  (0x3FFULL << SXE2_TXCD_QW1_VSI_S)
#define SXE2_TXCD_TSYN_REG_SHIFT	  (30)
#define SXE2_TXCD_QW1_IPSEC_MODE_S	  (11)
#define SXE2_TXCD_QW1_IPSEC_MODE_M	  BIT_ULL(SXE2_TXCD_QW1_IPSEC_MODE_S)
#define SXE2_TXCD_QW1_IPSEC_EN_S	  (12)
#define SXE2_TXCD_QW1_IPSEC_EN_M	  BIT_ULL(SXE2_TXCD_QW1_IPSEC_EN_S)
#define SXE2_TXCD_QW1_IPSEC_ENGINE_MODE_S (13)
#define SXE2_TXCD_QW1_IPSEC_ENGINE_MODE_M                                     \
	BIT_ULL(SXE2_TXCD_QW1_IPSEC_ENGINE_MODE_S)
#define SXE2_TXCD_QW1_IPSEC_SA_IDX_S (16)
#define SXE2_TXCD_QW1_IPSEC_SA_IDX_M (0x1FFF << SXE2_TXCD_QW1_IPSEC_SA_IDX_S)

#define SXE2_FNAV_TX_DESC_QW0_Q_INDEX_SHIFT (0)
#define SXE2_FNAV_TX_DESC_QW0_Q_INDEX_MASK                                    \
	((0x7FFULL) << SXE2_FNAV_TX_DESC_QW0_Q_INDEX_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_COMP_Q_SHIFT (11)
#define SXE2_FNAV_TX_DESC_QW0_COMP_Q_MASK                                     \
	((0x1ULL) << SXE2_FNAV_TX_DESC_QW0_COMP_Q_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_SHIFT (12)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_MASK                                   \
	((0x3ULL) << SXE2_FNAV_TX_DESC_QW0_COMP_RPT_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_NONE (0)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_FAIL (1)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_ANY  (2)
#define SXE2_FNAV_TX_DESC_QW0_COMP_RPT_RSV  (3)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_SHIFT (14)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_MASK                                   \
	((0x3ULL) << SXE2_FNAV_TX_DESC_QW0_FD_SPACE_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_GUAR (0)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_BEST (1)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_GUAR_FIRST                             \
	(2)
#define SXE2_FNAV_TX_DESC_QW0_FD_SPACE_BEST_FIRST                             \
	(3)
#define SXE2_FNAV_TX_DESC_QW0_STAT_CNT_SHIFT (16)
#define SXE2_FNAV_TX_DESC_QW0_STAT_CNT_MASK                                   \
	((0x3FFFULL) << SXE2_FNAV_TX_DESC_QW0_STAT_CNT_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_SHIFT (30)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_MASK                                   \
	((0x3ULL) << SXE2_FNAV_TX_DESC_QW0_STAT_ENA_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_NONE  (0)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_PKTS  (1)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_BYTES (2)
#define SXE2_FNAV_TX_DESC_QW0_STAT_ENA_ALL   (3)
#define SXE2_FNAV_TX_DESC_QW0_EVICT_ENA_SHIFT (32)
#define SXE2_FNAV_TX_DESC_QW0_EVICT_ENA_MASK                                  \
	((0x1ULL) << SXE2_FNAV_TX_DESC_QW0_EVICT_ENA_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_SHIFT (33)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_MASK                                        \
	((0x7ULL) << SXE2_FNAV_TX_DESC_QW0_TOQ_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_SHIFT (36)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_MASK                                   \
	((0x7ULL) << SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_ZERO  (0)
#define SXE2_FNAV_TX_DESC_QW0_TOQ_PRIO_THREE (3)
#define SXE2_FNAV_TX_DESC_QW0_DROP_SHIFT (40)
#define SXE2_FNAV_TX_DESC_QW0_DROP_MASK                                       \
	((0x1ULL) << SXE2_FNAV_TX_DESC_QW0_DROP_SHIFT)
#define SXE2_FNAV_TX_DESC_QW0_FLOW_ID_SHIFT (48)
#define SXE2_FNAV_TX_DESC_QW0_FLOW_ID_MASK                                    \
	((0xFFFFULL) << SXE2_FNAV_TX_DESC_QW0_FLOW_ID_SHIFT)

#define SXE2_FNAV_TX_DESC_QW1_DTYPE_SHIFT (0)
#define SXE2_FNAV_TX_DESC_QW1_DTYPE_MASK                                      \
	((0xF) << SXE2_FNAV_TX_DESC_QW1_DTYPE_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_SHIFT (4)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_MASK                                       \
	((0x3) << SXE2_FNAV_TX_DESC_QW1_PCMD_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_UPDATE (0)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_REMOVE (1)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_ADD                                        \
	(2)
#define SXE2_FNAV_TX_DESC_QW1_PCMD_REPLACE                                    \
	(3)
#define SXE2_FNAV_TX_DESC_QW1_FD_VSI_SHIFT (14)
#define SXE2_FNAV_TX_DESC_QW1_FD_VSI_MASK                                     \
	((0x3FFULL) << SXE2_FNAV_TX_DESC_QW1_FD_VSI_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_SWAP_SHIFT (24)
#define SXE2_FNAV_TX_DESC_QW1_SWAP_MASK                                       \
	((0x1ULL) << SXE2_FNAV_TX_DESC_QW1_SWAP_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_SHIFT (25)
#define SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_MASK                                  \
	((0x7ULL) << SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_ONE   (1)
#define SXE2_FNAV_TX_DESC_QW1_FDID_PRIO_THREE (3)
#define SXE2_FNAV_TX_DESC_QW1_FDID_MDID_SHIFT (28)
#define SXE2_FNAV_TX_DESC_QW1_FDID_MDID_MASK                                  \
	((0xFULL) << SXE2_FNAV_TX_DESC_QW1_FDID_MDID_SHIFT)
#define SXE2_FNAV_TX_DESC_QW1_FDID_MDID_FNAV (5)
#define SXE2_FNAV_TX_DESC_QW1_FDID_SHIFT (32)
#define SXE2_FNAV_TX_DESC_QW1_FDID_MASK                                       \
	((0xFFFFFFFFULL) << SXE2_FNAV_TX_DESC_QW1_FDID_SHIFT)

#define SXE2_TXDD_MACLEN_MAX                                                  \
	((SXE2_TXDD_MACLEN_M >> SXE2_TXDD_MACLEN_S) * SXE2_BYTES_PER_WORD)
#define SXE2_TXDD_IPLEN_MAX                                                   \
	((SXE2_TXDD_IPLEN_M >> SXE2_TXDD_IPLEN_S) * SXE2_BYTES_PER_DWORD)
#define SXE2_TXDD_L4LEN_MAX                                                   \
	((SXE2_TXDD_L4LEN_M >> SXE2_TXDD_L4LEN_S) * SXE2_BYTES_PER_DWORD)

#define SXE2_TXCD_QW1_MSS_MIN (88)

enum sxe2_tx_desc_type {
	SXE2_TX_DESC_DTYPE_DATA = 0x0,
	SXE2_TX_DESC_DTYPE_CTXT = 0x1,
	SXE2_TX_DESC_DTYPE_FLTR_PROG = 0x8,
	SXE2_TX_DESC_DTYPE_DESC_DONE = 0xF,
};

enum sxe2_tx_cd_cmd_bits {
	SXE2_TXCD_CMD_TSO	   = 0x01,
	SXE2_TXCD_CMD_TSYN	   = 0x02,
	SXE2_TXCD_CMD_IL2TAG2	   = 0x04,
	SXE2_TXCD_CMD_IL2TAG2_IL2H = 0x08,
	SXE2_TXCD_CMD_SWTCH_NOTAG  = 0x00,
	SXE2_TXCD_CMD_SWTCH_UPLINK = 0x10,
	SXE2_TXCD_CMD_SWTCH_LOCAL  = 0x20,
	SXE2_TXCD_CMD_SWTCH_VSI	   = 0x30,
	SXE2_TXCD_CMD_RESERVED	   = 0x40
};

enum sxe2_tx_ctxt_desc_eipt_bits {
	SXE2_TXCD_EIPT_NONE    = 0x0,
	SXE2_TXCD_EIPT_IPV6    = 0x1,
	SXE2_TXCD_IPV4_NO_CSUM = 0x2,
	SXE2_TXCD_IPV4	       = 0x3,
};

enum sxe2_tx_data_desc_cmd_bits {
	SXE2_TXDD_CMD_EOP	     = 0x0001,
	SXE2_TXDD_CMD_RS	     = 0x0002,
	SXE2_TXDD_CMD_MACSEC	     = 0x0004,
	SXE2_TXDD_CMD_IL2TAG1	     = 0x0008,
	SXE2_TXDD_CMD_DUMMY	     = 0x0010,
	SXE2_TXDD_CMD_IIPT_IPV6	     = 0x0020,
	SXE2_TXDD_CMD_IIPT_IPV4	     = 0x0040,
	SXE2_TXDD_CMD_IIPT_IPV4_CSUM = 0x0060,
	SXE2_TXDD_CMD_L4T_EOFT_TCP   = 0x0100,
	SXE2_TXDD_CMD_L4T_EOFT_SCTP  = 0x0200,
	SXE2_TXDD_CMD_L4T_EOFT_UDP   = 0x0300,
	SXE2_TXDD_CMD_RE	     = 0x0400,
};

#define SXE2_TX_FEATURE_VLAN_MASK     (0xffff0000)
#define SXE2_TX_FEATURE_VLAN_PR_MASK  (0xe0000000)
#define SXE2_TX_FEATURE_VLAN_SHIFT    (16)
#define SXE2_TX_FEATURE_VLAN_PR_SHIFT (29)
enum sxe2_tx_features {
	SXE2_TX_FEATURE_TSO		     = BIT(0),
	SXE2_TX_FEATURE_HW_VLAN		     = BIT(1),
	SXE2_TX_FEATURE_MACLEN		     = BIT(2),
	SXE2_TX_FEATURE_DUMMY_PKT	     = BIT(3),
	SXE2_TX_FEATURE_TSYN		     = BIT(4),
	SXE2_TX_FEATURE_IPV4		     = BIT(5),
	SXE2_TX_FEATURE_IPV6		     = BIT(6),
	SXE2_TX_FEATURE_TUNNEL		     = BIT(7),
	SXE2_TX_FEATURE_HW_OUTER_SINGLE_VLAN = BIT(8),
};

struct sxe2_tx_offload_info {
	struct sxe2_adapter *adapter;
	u32 data_desc_cmd;
	u32 data_desc_offset;
	u32 data_desc_l2tag1;
	u32 ctxt_desc_tunnel;
	u64 ctxt_desc_qw1;
	u16 ctxt_desc_ipsec_offset;
	u16 ctxt_desc_l2tag2;
};

union sxe2_ip_hdr {
	struct iphdr *v4;
	struct ipv6hdr *v6;
	unsigned char *hdr;
};

union sxe2_l4_hdr {
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned char *hdr;
};

struct sxe2_tx_fnav_desc {
	__le64 qidx_compq_space_stat;
	__le64 dtype_cmd_vsi_fdid;
};

struct sxe2_tx_context_desc {
	__le32 tunneling_params;
	__le16 l2tag2;
	__le16 ipset_offset;
	__le64 qw1;
};

union sxe2_tx_data_desc {
	struct {
		__le64 buf_addr;
		__le64 cmd_type_offset_bsz;
	} read;
	struct {
		__le64 rsvd;
		__le64 dd;
	} wb;
};

struct sxe2_txq_ucmd_ctxt {
	u32 sched_mode;
	u16 queue_id;
	u16 depth;
	u64 dma_addr;
};

struct sxe2_txq_ucmd_en_params {
	u16 q_cnt;
	u16 vsi_idx;
	struct sxe2_txq_ucmd_ctxt ctxts[];
};

struct sxe2_txq_ucmd_dis_params {
	u16 vsi_id;
	u16 q_idx;
	u8 sched_mode;
};

static inline void
sxe2_tx_desc_setup_for_tso(struct sxe2_tx_offload_info *offload, u64 tso_len,
			   u64 mss)
{
	offload->ctxt_desc_qw1 =
		(u64)(SXE2_TX_DESC_DTYPE_CTXT |
		      (SXE2_TXCD_CMD_TSO << SXE2_TXCD_QW1_CMD_S) |
		      (tso_len << SXE2_TXCD_QW1_TSO_TOTAL_LEN_S) |
		      (mss << SXE2_TXCD_QW1_MSS_S));
}

static inline void
sxe2_tx_desc_setup_for_csum(struct sxe2_tx_offload_info *offload, u32 l2_len,
			    u32 l3_len, u32 l4_len, u32 cmd)
{
	offload->data_desc_offset |= ((l2_len / 2) << SXE2_TXDD_MACLEN_S) |
				     ((l3_len / 4) << SXE2_TXDD_IPLEN_S) |
				     (l4_len << SXE2_TXDD_L4LEN_S);

	offload->data_desc_cmd |= cmd;
}

static inline void
sxe2_tx_desc_setup_for_ptp(struct sxe2_tx_offload_info *offload, u64 idx)
{
	offload->ctxt_desc_qw1 |= (u64)(SXE2_TX_DESC_DTYPE_CTXT |
				  (SXE2_TXCD_CMD_TSYN << SXE2_TXCD_QW1_CMD_S) |
				  (idx << SXE2_TXCD_TSYN_REG_SHIFT));
}

static inline void
sxe2_tx_desc_setup_for_vlan(struct sxe2_tx_offload_info *offload, u16 vlan_tci)
{
	offload->data_desc_l2tag1 = vlan_tci;
	offload->data_desc_cmd |= SXE2_TXDD_CMD_IL2TAG1;
}

#ifdef HAVE_METADATA_PORT_INFO
static inline void
sxe2_eswitch_tx_desc_setup(struct sxe2_tx_offload_info *offload,
			   struct sk_buff *skb)
{
	struct metadata_dst *dst = skb_metadata_dst(skb);
	u64 cd_cmd, dst_vsi;

	if (!dst) {
		cd_cmd = SXE2_TXCD_CMD_SWTCH_UPLINK << SXE2_TXCD_QW1_CMD_S;
		offload->ctxt_desc_qw1 |= (cd_cmd | SXE2_TX_DESC_DTYPE_CTXT);
	} else {
		cd_cmd	= SXE2_TXCD_CMD_SWTCH_VSI << SXE2_TXCD_QW1_CMD_S;
		dst_vsi = ((u64)dst->u.port_info.port_id
			   << SXE2_TXCD_QW1_VSI_S) &
			  SXE2_TXCD_QW1_VSI_M;
		offload->ctxt_desc_qw1 =
			cd_cmd | dst_vsi | SXE2_TX_DESC_DTYPE_CTXT;
	}
}
#else
static inline void
sxe2_eswitch_tx_desc_setup(struct sxe2_tx_offload_info *offload,
			   struct sk_buff *skb)
{
}
#endif

s32 sxe2_tx_cfg(struct sxe2_vsi *vsi);

s32 sxe2_xdp_tx_cfg(struct sxe2_vsi *vsi);

s32 sxe2_tx_hw_cfg(struct sxe2_vsi *vsi);

s32 sxe2_xdp_tx_hw_cfg(struct sxe2_vsi *vsi);

s32 sxe2_txqs_stop(struct sxe2_vsi *vsi);

s32 sxe2_xdp_txqs_stop(struct sxe2_vsi *vsi);

void sxe2_tx_rings_res_free(struct sxe2_vsi *vsi);

void sxe2_tx_ring_clean(struct sxe2_queue *txq);

s32 sxe2_tx_ring_alloc(struct sxe2_queue *txq, struct sxe2_vsi *vsi);

s32 sxe2_tx_rings_alloc(struct sxe2_vsi *vsi);

netdev_tx_t sxe2_xmit(struct sk_buff *skb, struct net_device *netdev);

s32 sxe2_hw_txqs_disable_check(struct sxe2_vsi *vsi);

s32 sxe2_prgm_fnav_fltr(struct sxe2_vsi *vsi,
			struct sxe2_tx_fnav_desc *fnav_desc, u8 *raw_packet);

void sxe2_ctrl_txq_irq_clean(struct sxe2_queue *txq);

bool sxe2_txq_irq_clean(struct sxe2_queue *txq, s32 napi_budget);

s32 sxe2_fwc_txq_stop(struct sxe2_vsi *vsi, struct sxe2_queue *txq);

s32 sxe2_txq_stop(struct sxe2_vsi *vsi, struct sxe2_queue *txq);
s32 sxe2_hw_txq_configure(struct sxe2_vsi *vsi, struct sxe2_queue *txq);

void sxe2_tx_ring_free(struct sxe2_queue *txq);

static inline void sxe2_xdp_ring_update_tail(struct sxe2_queue *xdp_ring)
{
	/* in order to force CPU ordering */
	wmb();
	writel(xdp_ring->next_to_use, xdp_ring->desc.tail);
}

static inline struct sxe2_tx_buf *
sxe2_tx_first_buffer_get(struct sk_buff *skb, struct sxe2_queue *txq)
{
	struct sxe2_tx_buf *first_buf;

	first_buf	       = &txq->tx_buf[txq->next_to_use];
	first_buf->skb	       = skb;
	first_buf->bytecount   = max_t(u32, skb->len, ETH_ZLEN);
	first_buf->gso_segs    = 1;
	first_buf->tx_features = 0;

	return first_buf;
}

#ifdef HAVE_XDP_SUPPORT
s32 sxe2_xmit_xdp_ring(void *data, u16 size, struct sxe2_queue *xdp_ring);
#endif

static inline __le64
sxe2_tx_data_desc_qword1_setup(struct sxe2_tx_offload_info *offload, u32 size)
{
	return cpu_to_le64(SXE2_TX_DESC_DTYPE_DATA |
			   ((u64)offload->data_desc_cmd << SXE2_TXDD_CMD_S) |
			   ((u64)offload->data_desc_offset << SXE2_TXDD_OFFSET_S) |
			   ((u64)size << SXE2_TXDD_BUF_SZ_S) |
			   ((u64)offload->data_desc_l2tag1 << SXE2_TXDD_L2TAG1_S));
}

void sxe2_tx_timeout(struct net_device *netdev, u32 txqueue);

void sxe2_tx_hang_check_subtask(struct sxe2_adapter *adapter);

s32 sxe2_txq_ctxt_fill(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
		       struct sxe2_txq_ctxt *ctxt);

s32 sxe2_fwc_txq_ctxt_cfg(struct sxe2_vsi *vsi,
			  struct sxe2_fwc_cfg_txq_req *req);

s32 sxe2_xmit_pkt(struct sxe2_queue *txq, struct sxe2_tx_buf *first_buf,
		  struct sxe2_tx_offload_info *offload);

s32 sxe2_txq_cfg_ena_common_handle(struct sxe2_adapter *adapter,
				   struct sxe2_txq_ucmd_en_params *params);

s32 sxe2_txq_dis_common_handle(struct sxe2_adapter *adapter,
			       struct sxe2_txq_ucmd_dis_params *params);

#endif
