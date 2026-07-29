/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_TXRX_H_
#define _MCEVF_TXRX_H_

#include "mcevf_type.h"

#define ITR_IS_SW_DYNAMIC(rc) ((rc)->dim_params.mode == ITR_SW_DYNAMIC)

#define MCEVF_DFLT_IRQ_WORK (256)
#define MCEVF_RX_HDR_SIZE (256)

#define MCEVF_CACHE_LINE_BYTES (64)
#define MCEVF_DESCS_PER_CACHE_LINE \
	(MCEVF_CACHE_LINE_BYTES / sizeof(struct mcevf_tx_desc))
#define MCEVF_DESCS_FOR_CTX_DESC (1)
#define MCEVF_DESCS_FOR_SKB_DATA_PTR (1)
/* now tx max 16k for one desc */
// feiteng use 12k can get better netperf performance
#define MCEVF_MAX_TXD_PWR (14)
#define MCEVF_MAX_DATA_PER_TXD BIT(MCEVF_MAX_TXD_PWR)
/* Tx descriptors needed, worst case */
#define DESC_NEEDED 32
#define MCEVF_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

#define MCEVF_DESC_UNUSED(R)                                        \
	((u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 :         \
							  (R)->count) + \
	       (R)->next_to_clean - (R)->next_to_use - 1))

enum mcevf_container_type {
	MCEVF_RX_CONTAINER,
	MCEVF_TX_CONTAINER,
};

struct mcevf_intr_coalesce {
	u32 usecs;
	u32 frames;
	u32 last_usecs;
	u32 last_frames;
	u32 mode;
#define ITR_STATIC 0
#define ITR_SW_DYNAMIC 1
#define ITR_HW_DYNAMIC 2
#define ITR_DYNAMIC ITR_SW_DYNAMIC
};

struct mcevf_ring_container {
	/* head of linked-list of rings */
	struct mcevf_ring *ring;
	struct dim dim; /* data for net_dim algorithm */
	struct mcevf_intr_coalesce dim_params;
	enum mcevf_container_type type;
};

struct mcevf_desc {
	__le32 desc0;
	__le32 desc1;
	__le32 desc2;
	__le32 desc3;
	__le32 desc4;
	__le32 desc5;
	__le32 desc6;
	__le32 desc7;
};

struct mcevf_tx_desc {
	__le64 addr;
	__le16 data_len;
	__le16 outer_hdr_len; // ip_hdr_len-[0:8], mac_hdr_len-[9:15]
	__le16 inner_hdr_len; // inner_ip_hdr_len-[0:8], inner_mac_hdr_len-[9:15]
	__le16 vlan0;
	__le16 vlan1;
	__le16 vlan2;
	__le16 mss;
	__le16 l4_hdr_len; // outer_l4_hdr_len-[0:7], tunnel_hdr_len-[8-15]
	__le16 mac_vlan_ctl;
	__le16 priv_inner_type; // priv_hdr_len-[0-7], inner_l3_type-[8:9], inner_l4_type-[12:15]
	__le32 cmd;
};

struct mcevf_rx_desc_down {
	__le64 addr;
	__le16 len;
	__le16 res0;
	__le16 res1;
	__le16 res3;
	__le16 res4;
	__le16 res5;
	__le16 res6;
	__le16 res7;
	__le16 res8;
	__le16 res9;
	__le16 cmd;
};

struct mcevf_rx_desc_up {
	__le32 rss_hash;
	__le16 data_len;
	__le16 padding_len;
	__le16 vlan_tag0;
	__le16 vlan_tag1;
	__le32 timestamp_l;
	__le32 timestamp_h_vlan_tag2;
	__le32 mark;
	__le16 vlan_tpid;
	__le16 err_cmd;
	__le32 cmd;
};

struct mcevf_tx_buf {
	struct mcevf_tx_desc *next_to_watch;
	union {
		struct sk_buff *skb;
		void *raw_buf; /* used for XDP */
	};
	u32 bytecount;
	u32 tx_flags;
	u32 bytecount_fifo;
#define MCEVF_TX_FLAGS_TSO BIT(0)
#define MCEVF_TX_FLAGS_HW_VLAN BIT(1)
#define MCEVF_TX_FLAGS_SW_VLAN BIT(2)
/* MCEVF_TX_FLAGS_DUMMY_PKT is used to mark dummy packets that should be
 * freed instead of returned like skb packets.
 */
#define MCEVF_TX_FLAGS_DUMMY_PKT BIT(3)

#define MCEVF_TX_FLAGS_TSYN BIT(4)
#define MCEVF_TX_FLAGS_IPV4 BIT(5)
#define MCEVF_TX_FLAGS_IPV6 BIT(6)
#define MCEVF_TX_FLAGS_TUNNEL BIT(7)
#define MCEVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN BIT(8)
	u16 gso_size;
	u16 gso_segs;
	u16 vlan_size;
	u16 head_size;
	u16 fifo_depth;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
};

struct mcevf_rx_buf {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	u16 pagecnt_bias;
};

struct mcevf_q_stats {
	u64 pkts;
	u64 bytes;
};

struct mcevf_txq_stats {
	u64 restart_q;
	u64 tx_busy;
	u64 tx_linearize;
	u64 inserted_vlan;
	u64 bytes;
	u64 pkts;
	u64 unicast;
	u64 multicast;
	u64 broadcast;
	int prev_pkt; /* negative if no pending Tx descriptors */
	u64 period_intr_drop;
};

struct mcevf_rxq_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buf_failed;
	u64 stripped_vlan;
	u64 csum_err;
	u64 csum_unnecessary;
	u64 csum_none;
	u64 bytes;
	u64 pkts;
	u64 unicast;
	u64 multicast;
	u64 broadcast;
	u64 miss_drop;
};

struct mcevf_ring_stats {
	struct rcu_head rcu; /* to avoid race on free */
	struct mcevf_q_stats stats;
	struct u64_stats_sync syncp;
	union {
		struct mcevf_txq_stats tx_stats;
		struct mcevf_rxq_stats rx_stats;
	};
};

enum mcevf_ring_state_t {
	MCEVF_TX_XPS_INIT_DONE,
	MCEVF_TX_NBITS,
};

enum mcevf_hw_ring_stats_type {
	MCEVF_HW_R_STATS_RX_BYTES,
	MCEVF_HW_R_STATS_RX_UNICAST,
	MCEVF_HW_R_STATS_RX_MULTICAST,
	MCEVF_HW_R_STATS_RX_BROADCAST,
	MCEVF_HW_R_STATS_RX_MISS_DROP,
	MCEVF_HW_R_STATS_TX_BYTES,
	MCEVF_HW_R_STATS_TX_UNICAST,
	MCEVF_HW_R_STATS_TX_MULTICAST,
	MCEVF_HW_R_STATS_TX_BROADCAST,
	MCEVF_HW_R_STATS_NBITS,
};

struct mcevf_ring {
	struct mcevf_ring *next;
	struct device *dev;
	struct net_device *netdev;
	struct mcevf_vsi *vsi; /* Backreference to associated VSI */
	struct mcevf_q_vector
		*q_vector; /* Backreference to associated vector */
	struct netdev_queue *tx_queue;
	struct mcevf_ring_stats *ring_stats;

	void *desc; /* descriptor ring memory */
	dma_addr_t dma; /* physical address of ring */
	union {
		struct mcevf_tx_buf *tx_buf;
		struct mcevf_rx_buf *rx_buf;
	};
	u8 __iomem *ring_addr;
	u8 __iomem *tail;
	u8 __iomem *head;

	struct rcu_head rcu; /* to avoid race on free */
	DECLARE_BITMAP(xps_state, MCEVF_TX_NBITS); /* XPS Config State */

	u16 q_index;
	u16 count; /* Number of descriptors */
	u32 size; /* length of descriptor ring in bytes */
	u16 rx_buf_len;
	u16 next_to_use;
	u16 next_to_clean;
	union {
		u16 next_to_alloc;
		u16 next_rs_idx;
	};
	u32 flags;
#define MCEVF_RX_FLAGS_RING_BUILD_SKB BIT(1)
} ____cacheline_internodealigned_in_smp;

static inline bool mcevf_ring_uses_build_skb(struct mcevf_ring *ring)
{
	return !!(ring->flags & MCEVF_RX_FLAGS_RING_BUILD_SKB);
}

static inline void
mcevf_set_ring_build_skb_ena(struct mcevf_ring *ring)
{
	ring->flags |= MCEVF_RX_FLAGS_RING_BUILD_SKB;
}

static inline void
mcevf_clear_ring_build_skb_ena(struct mcevf_ring *ring)
{
	ring->flags &= ~MCEVF_RX_FLAGS_RING_BUILD_SKB;
}

static inline unsigned int mcevf_rx_pg_order(struct mcevf_ring *ring)
{
#if (PAGE_SIZE < 8192)
	if (ring->rx_buf_len > (PAGE_SIZE / 2))
		return 1;
#endif
	return 0;
}

#define mcevf_rx_pg_size(_ring) (PAGE_SIZE << mcevf_rx_pg_order(_ring))

int mcevf_vsi_cfg(struct mcevf_vsi *vsi);

/* tx */
int mcevf_create_txring(struct mcevf_vsi *vsi, int index);
void mcevf_destroy_txring(struct mcevf_vsi *vsi, int index);
int mcevf_vsi_setup_tx_rings(struct mcevf_vsi *vsi);
int mcevf_setup_tx_ring(struct mcevf_ring *tx_ring);
void mcevf_clean_tx_ring(struct mcevf_ring *tx_ring);
void mcevf_free_tx_ring(struct mcevf_ring *tx_ring);
void mcevf_disable_vec_txrx_irq(struct mcevf_q_vector *vector);
void mcevf_enable_vec_txrx_irq(struct mcevf_q_vector *vector);
void mcevf_start_tx_ring(struct mcevf_ring *tx_ring);
void mcevf_stop_tx_ring(struct mcevf_ring *tx_ring);
netdev_tx_t mcevf_start_xmit(struct sk_buff *skb,
			     struct net_device *ndev);
bool mcevf_clean_tx_irq(struct mcevf_ring *tx_ring, int napi_budget);
int mcevf_vsi_start_all_tx_rings(struct mcevf_vsi *vsi);
void mcevf_update_tx_dim(struct mcevf_ring *tx_ring);

/* rx */
int mcevf_create_rxring(struct mcevf_vsi *vsi, int index);
void mcevf_destroy_rxring(struct mcevf_vsi *vsi, int index);
int mcevf_vsi_setup_rx_rings(struct mcevf_vsi *vsi);
int mcevf_setup_rx_ring(struct mcevf_ring *rx_ring);
void mcevf_free_rx_ring(struct mcevf_ring *rx_ring);
void mcevf_start_rx_ring(struct mcevf_ring *rx_ring);
void mcevf_stop_rx_ring(struct mcevf_ring *rx_ring);
void mcevf_clean_rx_ring(struct mcevf_ring *rx_ring);
int mcevf_clean_rx_irq(struct mcevf_ring *rx_ring, int budget);
int mcevf_vsi_start_all_rx_rings(struct mcevf_vsi *vsi);
void mcevf_update_rx_dim(struct mcevf_ring *rx_ring);

#endif /* _MCEVF_TXRX_H_ */
