/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_TXRX_H_
#define _MCE_TXRX_H_

#include "mce_type.h"

#define ITR_IS_SW_DYNAMIC(rc) ((rc)->dim_params.mode == ITR_SW_DYNAMIC)

#define MCE_MAX_INTRL (236)

#define MCE_DFLT_IRQ_WORK (256)
#define MCE_RX_HDR_SIZE (256)

#define MCE_CACHE_LINE_BYTES (64)
#define MCE_DESCS_PER_CACHE_LINE \
	(MCE_CACHE_LINE_BYTES / sizeof(struct mce_tx_desc))
#define MCE_DESCS_FOR_CTX_DESC (1)
#define MCE_DESCS_FOR_SKB_DATA_PTR (1)
#define MCE_RX_BUFFER_WRITE (16)

/* now tx max 16k for one desc */
/* feiteng use 12k can get better netperf performance */
#define MCE_MAX_TXD_PWR (14)
#define MCE_MAX_DATA_PER_TXD BIT(MCE_MAX_TXD_PWR)
/* Tx descriptors needed, worst case */
#define DESC_NEEDED (MAX_SKB_FRAGS + MCE_DESCS_FOR_CTX_DESC + \
		     MCE_DESCS_PER_CACHE_LINE + MCE_DESCS_FOR_SKB_DATA_PTR)

#define MCE_RX_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

#define MCE_DESC_UNUSED(R) ( \
	(u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	      (R)->next_to_clean - (R)->next_to_use - 1))

#define MCE_DESC(R, i) (&(((struct mce_desc *)((R)->desc))[i]))
#define MCE_TX_DESC(R, i) (&(((struct mce_tx_desc *)((R)->desc))[i]))
#define MCE_RXDESC_DOWN(R, i) \
	(&(((struct mce_rx_desc_down *)((R)->desc))[i]))

#define MCE_RXDESC_UP(R, i) \
	(&(((struct mce_rx_desc_up *)((R)->desc))[i]))

enum mce_container_type {
	MCE_RX_CONTAINER,
	MCE_TX_CONTAINER,
};

struct mce_intr_coalesce {
	u32 usecs;
	u32 frames;
	u32 last_usecs;
	u32 last_frames;
	u32 mode;
#define ITR_STATIC (0)
#define ITR_SW_DYNAMIC (1)
#define ITR_HW_DYNAMIC (2)

#define ITR_DYNAMIC (1)
};

struct mce_ring_container {
	/* head of linked-list of rings */
	struct mce_ring *ring;
	struct dim dim;		/* data for net_dim algorithm*/
	struct mce_intr_coalesce dim_params;
	enum mce_container_type type;
};

struct mce_desc {
	__le32 desc0;
	__le32 desc1;
	__le32 desc2;
	__le32 desc3;
	__le32 desc4;
	__le32 desc5;
	__le32 desc6;
	__le16 desc7;
	__le16 desc8;
};

struct mce_tx_desc {
	__le64 addr;
	__le16 data_len;
	__le16 outer_hdr_len;	/* ip_hdr_len-[0:8], mac_hdr_len-[9:15] */
	__le16 inner_hdr_len;	/* inner_ip_hdr_len-[0:8], inner_mac_hdr_len-[9:15] */
	__le16 vlan0;
	__le16 vlan1;
	__le16 vlan2; /* now [10:0] is the fifo depth */
	__le16 mss;
	__le16 l4_hdr_len;	/* outer_l4_hdr_len-[0:7], tunnel_hdr_len-[8-15] */
	__le16 mac_vlan_ctl;
	__le16 priv_inner_type;	/* priv_hdr_len-[0-7], inner_l3_type-[8:9], inner_l4_type-[12:15] */
	__le32 cmd;
};

/* CPU-side TX descriptor state, converted to little endian on submission. */
struct mce_tx_desc_ctx {
	u16 outer_hdr_len;
	u16 inner_hdr_len;
	u16 vlan0;
	u16 vlan1;
	u16 mss;
	u16 l4_hdr_len;
	u16 mac_vlan_ctl;
	u16 priv_inner_type;
	u32 cmd;
};

struct mce_rx_desc_down {
	__le64 addr;
	__le16 len;
	__le16 res0;
	__le16 res1;
	__le16 res2;
	__le16 res3;
	__le16 res4;
	__le16 res5;
	__le16 res6;
	__le16 res7;
	__le16 res8;
	__le16 cmd0;
	__le16 cmd1;
};

struct mce_rx_desc_up {
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

struct mce_tx_buf {
#ifndef MCE_TX_WB_COAL
	struct mce_tx_desc *next_to_watch;
#endif
	struct sk_buff *skb;
	u32 bytecount;
	u32 bytecount_fifo;
	u16 gso_size;
	u16 gso_segs;
	u16 vlan_size;
	u16 head_size;
	u16 fifo_depth;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
};

struct mce_rx_buf {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	unsigned int truesize;
	u16 pagecnt_bias;
	u16 repr_sport;
};

struct mce_q_stats {
	u64 pkts;
	u64 bytes;
};

struct mce_txq_stats {
	u64 restart_q;
	u64 tx_busy;
	u64 tx_linearize;
	u64 inserted_vlan;
	u64 tx_drop;
	u64 tx_pfc_count;
	u64 tx_tso_count;
	u64 tx_tso_count_done;
	int prev_pkt; /* negative if no pending Tx descriptors */
	u64 bytes;
	u64 pkts;
	u64 unicast;
	u64 multicast;
	u64 broadcast;
	u64 xmit_intr_drop;
	u64 poll_intr_drop;
	u64 period_intr_drop;
};

struct mce_rxq_stats {
	u64 non_eop_descs;
	u64 alloc_page_ok;
	u64 alloc_page_failed;
	u64 alloc_buf_failed;
	u64 pp_alloc_ok;
	u64 pp_alloc_fail;
	u64 pp_recycle;
	u64 pp_put;
	u64 pp_re_poll;
	u64 page_reuse_ok;
	u64 page_reuse_reserved;
	u64 page_reuse_refcnt;
	u64 page_reuse_offset;
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

struct mce_ring_stats {
	struct rcu_head rcu;	/* to avoid race on free */
	struct mce_q_stats stats;
	struct u64_stats_sync syncp;
	union {
		struct mce_txq_stats tx_stats;
		struct mce_rxq_stats rx_stats;
	};
};

enum mce_ring_state_t {
	MCE_TX_XPS_INIT_DONE,
	MCE_TX_NBITS,
};

enum mce_hw_ring_stats_type {
	MCE_HW_R_STATS_RX_BYTES,
	MCE_HW_R_STATS_RX_UNICAST,
	MCE_HW_R_STATS_RX_MULTICAST,
	MCE_HW_R_STATS_RX_BROADCAST,
	MCE_HW_R_STATS_RX_MISS_DROP,
	MCE_HW_R_STATS_TX_BYTES,
	MCE_HW_R_STATS_TX_UNICAST,
	MCE_HW_R_STATS_TX_MULTICAST,
	MCE_HW_R_STATS_TX_BROADCAST,
	MCE_HW_R_STATS_NBITS,
};

struct mce_ring_tx_timeout_jiffies {
	bool start;
	u16 next_to_clean_old;
	unsigned long jiffies;
};

struct mce_ring {
	struct mce_ring *next;
	void *desc;			/* descriptor ring memory */
	union {
		struct mce_tx_buf *tx_buf;
		struct mce_rx_buf *rx_buf;
	};
	struct mce_vsi *vsi;			/* Backreference to associated VSI */
	struct mce_q_vector *q_vector;	/* Backreference to associated vector */
	u8 __iomem *tail;
	struct device *dev;
	struct net_device *netdev;

	u16 q_index;
	u16 count;			/* Number of descriptors */
	u32 size;			/* length of descriptor ring in bytes */
	u32 idx_os;
	u16 rx_buf_len;
	u16 rx_offset;
	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_clean_old;
	struct mce_ring_tx_timeout_jiffies tx_timeout_jiffies;
	union {
		u16 next_to_alloc;
		u16 next_rs_idx;
	};
	struct mce_ring_stats *ring_stats;
	struct rcu_head rcu;				/* to avoid race on free */
	struct sk_buff *skb;
	dma_addr_t dma;			/* physical address of ring */
	u8 __iomem *ring_addr;
	u8 __iomem *head;
	struct netdev_queue *tx_queue;
	DECLARE_BITMAP(xps_state, MCE_TX_NBITS);	/* XPS Config State */

	u32 flags;
#define MCE_RX_FLAGS_RING_BUILD_SKB		BIT(1)
#define MCE_RING_FLAG_XDP			BIT(2)
} ____cacheline_internodealigned_in_smp;

static inline bool mce_ring_has_page_pool(struct mce_ring *rx_ring)
{
	return false;
}

static inline bool mce_ring_uses_build_skb(struct mce_ring *ring)
{
	return !!(ring->flags & MCE_RX_FLAGS_RING_BUILD_SKB);
}

static inline void mce_set_ring_build_skb_ena(struct mce_ring *ring)
{
	ring->flags |= MCE_RX_FLAGS_RING_BUILD_SKB;
}

static inline void mce_clear_ring_build_skb_ena(struct mce_ring *ring)
{
	ring->flags &= ~MCE_RX_FLAGS_RING_BUILD_SKB;
}

static inline unsigned int mce_rx_pg_order(struct mce_ring *ring)
{
#if (PAGE_SIZE < 8192)
#ifndef MCE_DIS_3K_BUF
	if (ring->rx_buf_len > (PAGE_SIZE / 2))
		return 1;
#endif
#endif
	return 0;
}

#define mce_rx_pg_size(_ring) (PAGE_SIZE << mce_rx_pg_order(_ring))

int mce_vsi_cfg(struct mce_vsi *vsi);

/* tx */
int mce_create_txring(struct mce_vsi *vsi, int index);
void mce_destroy_txring(struct mce_vsi *vsi, int index);
int mce_vsi_setup_tx_rings(struct mce_vsi *vsi);
int mce_setup_tx_ring(struct mce_ring *tx_ring);
void mce_clean_tx_ring(struct mce_ring *tx_ring);
void mce_free_tx_ring(struct mce_ring *tx_ring);
void mce_disable_vec_txs_irq(struct mce_q_vector *vector);
void mce_enable_vec_txs_irq(struct mce_q_vector *vector);
void mce_stop_tx_ring(struct mce_ring *tx_ring);
void mce_start_tx_ring(struct mce_ring *tx_ring);
void mce_start_rx_ring(struct mce_ring *rx_ring);
int mce_vsi_cfg_rxq(struct mce_ring *ring);
netdev_tx_t mce_start_xmit(struct sk_buff *skb, struct net_device *ndev);
netdev_tx_t __mce_hard_start_xmit(struct sk_buff *skb,
				  struct net_device *ndev,
				  struct mce_repr *repr);
bool mce_clean_tx_irq(struct mce_ring *tx_ring, int napi_budget);
int mce_vsi_start_all_tx_rings(struct mce_vsi *vsi);
void mce_update_tx_dim(struct mce_ring *tx_ring);

/* rx */
int mce_create_rxring(struct mce_vsi *vsi, int index);
void mce_destroy_rxring(struct mce_vsi *vsi, int index);
int mce_vsi_setup_rx_rings(struct mce_vsi *vsi);
int mce_setup_rx_ring(struct mce_ring *rx_ring);
void mce_free_rx_ring(struct mce_ring *rx_ring);
void mce_disable_vec_rxs_irq(struct mce_q_vector *vector);
void mce_enable_vec_rxs_irq(struct mce_q_vector *vector);
void mce_stop_rx_ring(struct mce_ring *rx_ring);
void mce_clean_rx_ring(struct mce_ring *rx_ring);
int mce_clean_rx_irq(struct mce_ring *rx_ring, int budget);
int mce_vsi_start_all_rx_rings(struct mce_vsi *vsi);
void mce_update_rx_dim(struct mce_ring *rx_ring);
/* tx-rx */
void mce_enable_vec_txrxs_irq(struct mce_q_vector *vector);
void mce_disable_vec_txrxs_irq(struct mce_q_vector *vector);
#endif /* _MCE_TXRX_H_ */
