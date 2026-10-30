/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_TXRX_H_
#define _NSEVF_TXRX_H_

/* Interrupt Throttling and Rate Limiting Goodies */
#define NSEVF_DEFAULT_IRQ_WORK 256

/* Supported Rx Buffer Sizes (a multiple of 128) */
#define NSEVF_RXBUFFER_256 256
#define NSEVF_RXBUFFER_1536 1536 /* 128B aligned standard Ethernet frame */
#define NSEVF_RXBUFFER_2048 2048
#define NSEVF_RXBUFFER_3072 3072 /* Used for large frames w/ padding */
#define NSEVF_MAX_RXBUFFER 9018 /* largest size for single descriptor */

/* NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN means we
 * reserve 2 more, and skb_shared_info adds an additional 384 bytes more,
 * this adds up to 512 bytes of extra data meaning the smallest allocation
 * we could have is 1K.
 * i.e. RXBUFFER_256 --> 960 byte skb (size-1024 slab)
 * i.e. RXBUFFER_512 --> 1216 byte skb (size-2048 slab)
 */
#define NSEVF_RX_HDR_SIZE NSEVF_RXBUFFER_256
#define NSEVF_PACKET_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define nsevf_rx_desc nse_32b_rx_desc
#define nsevf_tx_desc nse_tx_desc
#define nsevf_txcq_desc nse_lan_txcq_desc

#define NSEVF_RX_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

/* Attempt to maximize the headroom available for incoming frames.  We
 * use a 2K buffer for receives and need 1536/1534 to store the data for
 * the frame.  This leaves us with 512 bytes of room.  From that we need
 * to deduct the space needed for the shared info and the padding needed
 * to IP align the frame.
 *
 * Note: For cache line sizes 256 or larger this value is going to end
 *	 up negative.  In these cases we should fall back to the legacy
 *	 receive path.
 */
#if (PAGE_SIZE < 8192)
#define NSEVF_2K_TOO_SMALL_WITH_PADDING        \
	((NET_SKB_PAD + NSEVF_RXBUFFER_1536) > \
	 SKB_WITH_OVERHEAD(NSEVF_RXBUFFER_2048))

static inline int nsevf_compute_pad(int rx_buf_len)
{
	int page_size, pad_size;

	page_size = ALIGN(rx_buf_len, PAGE_SIZE / 2);
	pad_size = SKB_WITH_OVERHEAD(page_size) - rx_buf_len;

	return pad_size;
}

static inline int nsevf_skb_pad(void)
{
	int rx_buf_len;

	/* If a 2K buffer cannot handle a standard Ethernet frame then
	 * optimize padding for a 3K buffer instead of a 1.5K buffer.
	 *
	 * For a 3K buffer we need to add enough padding to allow for
	 * tailroom due to NET_IP_ALIGN possibly shifting us out of
	 * cache-line alignment.
	 */
	if (NSEVF_2K_TOO_SMALL_WITH_PADDING)
		rx_buf_len = NSEVF_RXBUFFER_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	else
		rx_buf_len = NSEVF_RXBUFFER_1536;

	/* if needed make room for NET_IP_ALIGN */
	rx_buf_len -= NET_IP_ALIGN;

	return nsevf_compute_pad(rx_buf_len);
}

#define NSEVF_SKB_PAD nsevf_skb_pad()
#else
#define NSEVF_2K_TOO_SMALL_WITH_PADDING false
#define NSEVF_SKB_PAD (NET_SKB_PAD + NET_IP_ALIGN)
#endif

static inline bool nsevf_test_staterr(__le16 status_err_n,
				      const u16 stat_err_bits)
{
	return !!(status_err_n & cpu_to_le16(stat_err_bits));
}

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define NSEVF_RX_INCREMENT(r, i)       \
	do {                           \
		(i)++;                 \
		if ((i) == (r)->count) \
			i = 0;         \
		r->next_to_clean = i;  \
	} while (0)

#define NSEVF_RX_NEXT_DESC(r, i, n)            \
	do {                                   \
		(i)++;                         \
		if ((i) == (r)->count)         \
			i = 0;                 \
		(n) = NSEVF_RX_DESC((r), (i)); \
	} while (0)

#define NSEVF_RX_NEXT_DESC_PREFETCH(r, i, n)       \
	do {                                       \
		NSEVF_RX_NEXT_DESC((r), (i), (n)); \
		prefetch((n));                     \
	} while (0)

#define NSEVF_MAX_BUFFER_TXD 8
#define NSEVF_MIN_TX_LEN 17

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define NSEVF_MAX_READ_REQ_SIZE 4096
#define NSEVF_MAX_DATA_PER_TXD (16 * 1024 - 1)
#define NSEVF_MAX_DATA_PER_TXD_ALIGNED \
	(NSEVF_MAX_DATA_PER_TXD & ~(NSEVF_MAX_READ_REQ_SIZE - 1))

/**
 * nsevf_txd_use_count  - estimate the number of descriptors needed for Tx
 * @size: transmit request size in bytes
 *
 * Due to hardware alignment restrictions (4K alignment), we need to
 * assume that we can have no more than 12K of data per descriptor, even
 * though each descriptor can take up to 16K - 1 bytes of aligned memory.
 * Thus, we need to divide by 12K. But division is slow! Instead,
 * we decompose the operation into shifts and one relatively cheap
 * multiply operation.
 *
 * To divide by 12K, we first divide by 4K, then divide by 3:
 *     To divide by 4K, shift right by 12 bits
 *     To divide by 3, multiply by 85, then divide by 256
 *     (Divide by 256 is done by shifting right by 8 bits)
 * Finally, we add one to round up. Because 256 isn't an exact multiple of
 * 3, we'll underestimate near each multiple of 12K. This is actually more
 * accurate as we have 4K - 1 of wiggle room that we can fit into the last
 * segment.  For our purposes this is accurate out to 1M which is orders of
 * magnitude greater than our largest possible GSO size.
 *
 * This would then be implemented as:
 *     return (((size >> 12) * 85) >> 8) + 1;
 *
 * Since multiplication and division are commutative, we can reorder
 * operations into:
 *     return ((size * 85) >> 20) + 1;
 */
static inline unsigned int nsevf_txd_use_count(unsigned int size)
{
	return ((size * 85) >> 20) + 1;
}

/* Tx Descriptors needed, worst case */
#define DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define NSEVF_MIN_DESC_PENDING 4

#define NSE_TXD_LAST_DESC_CMD (NSE_TXD_EOP_M | NSE_TXD_RS_M)

struct nsevf_tx_buffer {
	struct nsevf_tx_desc *next_to_watch;
	union {
		struct xdp_frame *xdpf;
		struct sk_buff *skb;
		void *raw_buf;
	};
	unsigned int bytecount;
	unsigned short gso_segs;

	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
#define NSEVF_TX_FLAGS_TSO BIT(0)
#define NSEVF_TX_FLAGS_HW_VLAN BIT(1)
#define NSEVF_TX_FLAGS_SW_VLAN BIT(2)
#define NSEVF_TX_FLAGS_TCSUM BIT(3) /* only tcsum, no TSO */
#define NSEVF_TX_FLAGS_TSYN BIT(4)
#define NSEVF_TX_FLAGS_IPV4 BIT(5)
#define NSEVF_TX_FLAGS_IPV6 BIT(6)
#define NSEVF_TX_FLAGS_TUNNEL BIT(7)
#define NSEVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN BIT(8)
#define NSEVF_TX_FLAGS_VLAN_MASK 0xffff0000
#define NSEVF_TX_FLAGS_VLAN_PRIO_MASK 0xe0000000
#define NSEVF_TX_FLAGS_VLAN_PRIO_SHIFT 29
#define NSEVF_TX_FLAGS_VLAN_SHIFT 16
};

struct nse_tx_offload_params {
	struct nsevf_ring *tx_ring;

	u64 td_cmd_type_offset_bsz;
	u64 td_tlen; //TLEN in cmd_type_offset_bsz

	u32 cd_tunneling_params;
	u16 cd_l2tag2;
	u16 cd_control;
	u64 cd_qw1;

	u8 header_len; /* Used by nse_tso() for length calculation. */
};

struct nsevf_rx_buffer {
	/* Saved when cleaning stops before the packet EOP is received. */
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 page_offset;
#else
	__u16 page_offset;
#endif
	__u16 pagecnt_bias;
};

struct nsevf_queue_stats {
	u64 packets;
	u64 bytes;
};

struct nsevf_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_linearize;
	u64 tx_force_wb;
	int prev_pkt_ctr;
	u64 tx_use_ctx_desc;
	u64 tx_not_use_ctx_desc;
	u64 tx_tso;
	u64 tx_tso_tnl;
	u64 tx_tso_non_tnl;
	u64 tx_tcsum;
	u64 tx_tcsum_tnl;
	u64 tx_tcsum_non_tnl;
	u64 tx_tvlan;
	u64 tx_tsyn;
	u64 tx_offload;
	u64 tx_non_offload;

	u64 tx_rs;
	u64 tx_no_rs;

	u64 clean_tx_irq_legacy_cnt;
	u64 clean_tx_irq_legacy_rs_cnt;
	u64 clean_tx_irq_legacy_rs_raw_cnt;
	u64 clean_tx_irq_legacy_rs_agg_cnt;
	u64 clean_tx_irq_zc_cnt;
	u64 clean_txcq_irq_cnt;
	u64 clean_txcq_irq_zc_cnt;
};

struct nsevf_rx_queue_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buff_failed;
	u64 page_reuse_count;
	u64 realloc_count;
	u64 rx_csum_good;
	u64 rx_csum_bad;
	u64 rsc_count;
	u64 rsc_flush;
	u64 qsrc_cnt[4];
};

struct nse_cq_stats {
	u64 pkts;
	u64 bytes;
	u64 cqe_cnt;
	u64 gen_flip_cnt;
	u64 txqe_cnt;
};

struct nsevf_txcq_ring {
	void *desc; /* Descriptor ring memory */
	dma_addr_t dma; /* physical address of ring */

	u32 next_to_clean;
	u32 generation;

	u32 count; /* Number of descriptors */

	struct device *dev; /* Used for DMA mapping */
	struct net_device *netdev; /* netdev ring maps to */
	struct nsevf_adapter *adapter;
	struct nsevf_q_vector *q_vector; /* Backreference to associated vector */

	u16 queue_index; /* Queue number of ring */

	u16 cq_abs_id; /* absolute ID in lan-channel space */

	unsigned int size; /* length of descriptor ring in bytes */

	struct u64_stats_sync syncp;
	struct nse_cq_stats stats;
} ____cacheline_internodealigned_in_smp;

enum nsevf_ring_tx_xps_state_t {
	NSEVF_TX_XPS_INIT_DONE,
	NSEVF_TX_XPS_NBITS,
};

/* struct that defines a descriptor ring, associated with a VSI */
struct nsevf_ring {
	struct nsevf_ring *next; /* pointer to next ring in q_vector */
	void *desc; /* Descriptor ring memory */
	struct device *dev; /* Used for DMA mapping */
	struct net_device *netdev; /* netdev ring maps to */
	struct nsevf_adapter *adapter;
	struct bpf_prog *xdp_prog;
	union {
		struct nsevf_tx_buffer *tx_bi;
		struct nsevf_rx_buffer *rx_bi;
	};

	u16 queue_index; /* Queue number of ring */
	u8 dcb_tc; /* Traffic class of ring */
	u8 __iomem *tail;

	/* high bit set means dynamic, use accessor routines to read/write.
	 * hardware only supports 2us resolution for the ITR registers.
	 * these values always store the USER setting, and must be converted
	 * before programming to a register.
	 */
	u16 itr_setting;

	u16 count; /* Number of descriptors */
	u16 reg_idx; /* HW register index of the ring */
	u16 rx_buf_len;

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	u16 *tx_rs_array;
	u16 tx_rs_ntu;
	u16 tx_rs_ntc;

	bool ring_active; /* is ring online or not */

	u8 rxdid; /* Rx descriptor format */

	u16 flags;
#define NSEVF_RXR_FLAGS_BUILD_SKB_ENABLED BIT(1)
#define NSEVF_TXR_FLAGS_XDP BIT(2)
#define NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1 BIT(3)
#define NSEVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2 BIT(4)
#define NSEVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2ND BIT(5)
#define NSEVF_TXR_FLAGS_BYPASS_SWITCH BIT(6)

	/* stats structs */
	struct nsevf_queue_stats stats;
	struct u64_stats_sync syncp;
	union {
		struct nsevf_tx_queue_stats tx_stats;
		struct nsevf_rx_queue_stats rx_stats;
	};

	unsigned int size; /* length of descriptor ring in bytes */
	dma_addr_t dma; /* physical address of ring */

	struct nsevf_vsi *vsi; /* Backreference to associated VSI */
	struct nsevf_q_vector *q_vector; /* Backreference to associated vector */

	struct rcu_head rcu; /* to avoid race on free */
	DECLARE_BITMAP(xps_state, NSEVF_TX_XPS_NBITS);	/* XPS Config State */

	u16 next_to_alloc;

} ____cacheline_internodealigned_in_smp;

static inline bool ring_uses_build_skb(struct nsevf_ring *ring)
{
	return !!(ring->flags & NSEVF_RXR_FLAGS_BUILD_SKB_ENABLED);
}

static inline void set_ring_build_skb_enabled(struct nsevf_ring *ring)
{
	ring->flags |= NSEVF_RXR_FLAGS_BUILD_SKB_ENABLED;
}

static inline void clear_ring_build_skb_enabled(struct nsevf_ring *ring)
{
	ring->flags &= ~NSEVF_RXR_FLAGS_BUILD_SKB_ENABLED;
}

#define NSEVF_ITR_ADAPTIVE_MIN_INC 0x0002
#define NSEVF_ITR_ADAPTIVE_MIN_USECS 0x0002
#define NSEVF_ITR_ADAPTIVE_MAX_USECS 0x007e
#define NSEVF_ITR_ADAPTIVE_LATENCY 0x8000
#define NSEVF_ITR_ADAPTIVE_BULK 0x0000
#define ITR_IS_BULK(x) (!((x) & NSEVF_ITR_ADAPTIVE_LATENCY))

static inline bool ring_is_xdp(struct nsevf_ring *ring)
{
	return !!(ring->flags & NSEVF_TXR_FLAGS_XDP);
}

static inline void set_ring_xdp(struct nsevf_ring *ring)
{
	ring->flags |= NSEVF_TXR_FLAGS_XDP;
}

struct nsevf_ring_container {
	struct nsevf_ring *ring; /* pointer to linked list of ring(s) */
	unsigned int total_bytes; /* total bytes processed this int */
	unsigned int total_packets; /* total packets processed this int */
	u16 count;
};

/* iterator for handling rings in ring container */
#define nsevf_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

static inline unsigned int nsevf_rx_pg_order(struct nsevf_ring *ring)
{
#if (PAGE_SIZE < 8192)
	if (ring->rx_buf_len > (PAGE_SIZE / 2))
		return 1;
#endif
	return 0;
}

#define nsevf_rx_pg_size(_ring) (PAGE_SIZE << nsevf_rx_pg_order(_ring))

bool nsevf_alloc_rx_buffers(struct nsevf_ring *rxr, u16 cleaned_count);
netdev_tx_t nsevf_xmit_frame(struct sk_buff *skb, struct net_device *netdev);
void nsevf_clean_tx_ring(struct nsevf_ring *tx_ring);
void nsevf_clean_rx_ring(struct nsevf_ring *rx_ring);
int nsevf_setup_tx_descriptors(struct nsevf_ring *tx_ring);
int nsevf_setup_rx_descriptors(struct nsevf_ring *rx_ring);
void nsevf_free_tx_resources(struct nsevf_ring *tx_ring);
void nsevf_free_rx_resources(struct nsevf_ring *rx_ring);
void nsevf_clean_txcq_ring(struct nsevf_txcq_ring *cq_ring);
void nsevf_free_txcq_resources(struct nsevf_txcq_ring *cq_ring);
int nsevf_setup_txcq_descriptors(struct nsevf_txcq_ring *cq_ring);
int nsevf_napi_poll(struct napi_struct *napi, int budget);
int nsevf_polling(struct nsevf_q_vector *q_vector, int budget);

u32 nsevf_get_tx_pending(struct nsevf_ring *ring, bool in_sw);
void nsevf_detect_recover_hung(struct nsevf_vsi *vsi);
int __nsevf_maybe_stop_tx(struct nsevf_ring *tx_ring, int size);
bool __nsevf_chk_linearize(struct sk_buff *skb);
void nsevf_xdp_flush(struct net_device *dev);
void nsevf_sync_tail_all_rx_rings(struct nsevf_adapter *adapter);
void nse_dump_rx_desc(struct device *dev, u16 q_idx, u16 desc_idx,
		      union nse_32b_rx_desc *rx_desc);
void nse_dump_tx_desc(struct device *dev, u16 q_idx, u16 desc_idx,
		      struct nse_tx_desc *tx_desc);
void nse_dump_lan_txcq_desc(struct device *dev, u16 q_idx, u32 desc_idx,
			    struct nse_lan_txcq_desc *desc);

/**
 * nsevf_xmit_descriptor_count - calculate number of Tx descriptors needed
 * @skb:     send buffer
 *
 * Returns number of data descriptors needed for this skb. Returns 0 to indicate
 * there is not enough descriptors available in this ring since we need at least
 * one descriptor.
 **/
static inline int nsevf_xmit_descriptor_count(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	int count = 0, size = skb_headlen(skb);

	for (;;) {
		count += nsevf_txd_use_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

/**
 * nsevf_maybe_stop_tx - 1st level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns 0 if stop is not needed
 **/
static inline int nsevf_maybe_stop_tx(struct nsevf_ring *tx_ring, int size)
{
	if (likely(NSEVF_DESC_UNUSED(tx_ring) >= size))
		return 0;
	return __nsevf_maybe_stop_tx(tx_ring, size);
}

/**
 * nsevf_chk_linearize - Check if there are more than 8 fragments per packet
 * @skb:      send buffer
 * @count:    number of buffers used
 *
 * Note: Our HW can't scatter-gather more than 8 fragments to build
 * a packet on the wire and so we need to figure out the cases where we
 * need to linearize the skb.
 **/
static inline bool nsevf_chk_linearize(struct sk_buff *skb, int count)
{
	/* Both TSO and single send will work if count is less than 8 */
	if (likely(count < NSEVF_MAX_BUFFER_TXD))
		return false;

	if (skb_is_gso(skb))
		return __nsevf_chk_linearize(skb);

	/* we can support up to 8 data buffers for a single send */
	return count != NSEVF_MAX_BUFFER_TXD;
}

/**
 * txring_txq - Find the netdev Tx ring based on the iavf Tx ring
 * @ring: Tx ring to find the netdev equivalent of
 **/
static inline struct netdev_queue *txring_txq(const struct nsevf_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}
#endif /* _NSEVF_TXRX_H_ */
