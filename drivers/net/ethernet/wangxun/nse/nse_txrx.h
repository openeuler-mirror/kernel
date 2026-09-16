/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_TXRX_H_
#define _NSE_TXRX_H_

#include "nse_type.h"

#define NSE_DFLT_IRQ_WORK	256
#define NSE_RXBUF_3072		3072
#define NSE_RXBUF_2048		2048
#define NSE_RXBUF_1536		1536
#define NSE_MAX_CHAINED_RX_BUFS	5
#define NSE_MAX_BUF_TXD		8
#define NSE_MIN_TX_LEN		17

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define NSE_MAX_READ_REQ_SIZE	4096
#define NSE_MAX_DATA_PER_TXD	(16 * 1024 - 1)
#define NSE_MAX_DATA_PER_TXD_ALIGNED \
	(~(NSE_MAX_READ_REQ_SIZE - 1) & NSE_MAX_DATA_PER_TXD)

#define NSE_RX_BUF_WRITE	16	/* Must be power of 2 */
#define NSE_MAX_TXQ_PER_TXQG	128

/* Attempt to maximize the headroom available for incoming frames. We use a 2K
 * buffer for MTUs <= 1500 and need 1536/1534 to store the data for the frame.
 * This leaves us with 512 bytes of room.  From that we need to deduct the
 * space needed for the shared info and the padding needed to IP align the
 * frame.
 *
 * Note: For cache line sizes 256 or larger this value is going to end
 *	 up negative.  In these cases we should fall back to the legacy
 *	 receive path.
 */
#if (PAGE_SIZE < 8192)
#define NSE_2K_TOO_SMALL_WITH_PADDING \
	((unsigned int)(NET_SKB_PAD + NSE_RXBUF_1536) > \
			SKB_WITH_OVERHEAD(NSE_RXBUF_2048))

/**
 * nse_compute_pad - compute the padding
 * @rx_buf_len: buffer length
 *
 * Figure out the size of half page based on given buffer length and
 * then subtract the skb_shared_info followed by subtraction of the
 * actual buffer length; this in turn results in the actual space that
 * is left for padding usage
 */
static inline int nse_compute_pad(int rx_buf_len)
{
	int half_page_size;

	half_page_size = ALIGN(rx_buf_len, PAGE_SIZE / 2);
	return SKB_WITH_OVERHEAD(half_page_size) - rx_buf_len;
}

/**
 * nse_skb_pad - determine the padding that we can supply
 *
 * Figure out the right Rx buffer size and based on that calculate the
 * padding
 */
static inline int nse_skb_pad(void)
{
	int rx_buf_len;

	/* If a 2K buffer cannot handle a standard Ethernet frame then
	 * optimize padding for a 3K buffer instead of a 1.5K buffer.
	 *
	 * For a 3K buffer we need to add enough padding to allow for
	 * tailroom due to NET_IP_ALIGN possibly shifting us out of
	 * cache-line alignment.
	 */
	if (NSE_2K_TOO_SMALL_WITH_PADDING)
		rx_buf_len = NSE_RXBUF_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	else
		rx_buf_len = NSE_RXBUF_1536;

	/* if needed make room for NET_IP_ALIGN */
	rx_buf_len -= NET_IP_ALIGN;

	return nse_compute_pad(rx_buf_len);
}

#define NSE_SKB_PAD nse_skb_pad()
#else
#define NSE_2K_TOO_SMALL_WITH_PADDING false
#define NSE_SKB_PAD (NET_SKB_PAD + NET_IP_ALIGN)
#endif

/* We are assuming that the cache line is always 64 Bytes here for ice.
 * In order to make sure that is a correct assumption there is a check in probe
 * to print a warning if the read from GLPCI_CNF2 tells us that the cache line
 * size is 128 bytes. We do it this way because we do not want to read the
 * GLPCI_CNF2 register or a variable containing the value on every pass through
 * the Tx path.
 */
#define NSE_CACHE_LINE_BYTES		64
#define NSE_DESCS_PER_CACHE_LINE	(NSE_CACHE_LINE_BYTES / \
					 sizeof(struct nse_tx_desc))
#define NSE_DESCS_FOR_CTX_DESC		1
#define NSE_DESCS_FOR_SKB_DATA_PTR	1
/* Tx descriptors needed, worst case */
#define DESC_NEEDED (MAX_SKB_FRAGS + NSE_DESCS_FOR_CTX_DESC + \
		     NSE_DESCS_PER_CACHE_LINE + NSE_DESCS_FOR_SKB_DATA_PTR)
#define NSE_DESC_UNUSED(R)	\
	((u16)((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	      (R)->next_to_clean - (R)->next_to_use - 1))

#define NSE_XDP_PASS		0
#define NSE_XDP_CONSUMED	BIT(0)
#define NSE_XDP_TX		BIT(1)
#define NSE_XDP_REDIR		BIT(2)

#define NSE_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

#define NSE_ETH_PKT_HDR_PAD	(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))

#define NSE_TXD_LAST_DESC_CMD (NSE_TXD_EOP_M | NSE_TXD_RS_M)
#define NSE_TXD_LAST_DESC_CMD_NO_RS	NSE_TXD_EOP_M

struct nse_tx_buf {
	struct nse_tx_desc *next_to_watch;
	union {
		struct sk_buff *skb;
		void *raw_buf; /* used for XDP */
	};
	unsigned int bytecount;
	unsigned short gso_segs;
	u32 tx_flags;
#define NSE_TX_FLAGS_TSO	BIT(0)
#define NSE_TX_FLAGS_HW_VLAN	BIT(1)
#define NSE_TX_FLAGS_SW_VLAN	BIT(2)
#define NSE_TX_FLAGS_TCSUM		BIT(3)	/* only tcsum, no TSO */
#define NSE_TX_FLAGS_TSYN	BIT(4)
#define NSE_TX_FLAGS_IPV4	BIT(5)
#define NSE_TX_FLAGS_IPV6	BIT(6)
#define NSE_TX_FLAGS_TUNNEL	BIT(7)
#define NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN	BIT(8)
#define NSE_TX_FLAGS_VLAN_M	0xffff0000
#define NSE_TX_FLAGS_VLAN_PR_M	0xe0000000
#define NSE_TX_FLAGS_VLAN_PR_S	29
#define NSE_TX_FLAGS_VLAN_S	16

	DEFINE_DMA_UNMAP_LEN(len);
	DEFINE_DMA_UNMAP_ADDR(dma);
};

struct nse_tx_offload_params {
	struct nse_ring *tx_ring;

	u64 td_cmd_type_offset_bsz;
	u64 td_tlen;		//TLEN in cmd_type_offset_bsz

	u32 cd_tunneling_params;
	u16 cd_l2tag2;
	u16 cd_control;
	u64 cd_qw1;

	u8 header_len;	//only used in nse_tso() for computing

#if defined(NSE_DEBUG_EXT)
	u8 tdm_desc_err_already_made;
	u8 debug_print_tx_desc;
#endif
};

struct nse_rx_buf {
	struct sk_buff *skb;
	dma_addr_t dma;
	union {
		struct {
			struct page *page;
			unsigned int page_offset;
			u16 pagecnt_bias;
		};
		struct {
			union {
				struct xdp_buff *xdp;
				void *addr;
			};
		};
	};
};

struct nse_q_stats {
	u64 pkts;
	u64 bytes;
#ifdef NSE_ADD_PROBES
	u64 napi_poll_cnt;
#endif /* NSE_ADD_PROBES */
};

struct nse_cq_stats {
	u64 pkts;
	u64 bytes;
	u64 cqe_cnt;
	u64 gen_flip_cnt;
	u64 txqe_cnt;
#ifdef NSE_ADD_PROBES
	u64 napi_poll_cnt;
#endif /* NSE_ADD_PROBES */
};

struct nse_txq_stats {
	u64 restart_q;
	u64 tx_busy;
	u64 tx_linearize;
	int prev_pkt; /* negative if no pending Tx descriptors */
#if defined(NSE_DEBUG_EXT)
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
#endif
};

struct nse_rxq_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buf_failed;

	u64 rx_csum_good;
	u64 rx_csum_bad;
	u64 qsrc_cnt[4];
	u64 rsc_merge_cnt;
	u64 rsc_flush;

#ifdef NSE_ADD_PROBES
	u64 page_reuse;
#endif /* NSE_ADD_PROBES */

#if defined(NSE_DEBUG_EXT)
	u64 rsc_cnt_desc_cnt[16];
	u64 rsc_cnt_total_accum;

	/* related to NSE_RXDID_FLEX_DBG_0 */
	u64 rxdid_dbg_0_cnt;
	u64 non_zero_poh_md_37;
	u64 rscfv_cnt[2];
#endif
};

enum nse_ring_state_t {
	NSE_TX_XPS_INIT_DONE,
	NSE_TX_NBITS,
};

/* Header split modes defined by DTYPE field of Rx RLAN context */
enum nse_rx_dtype {
	NSE_RX_DTYPE_NO_SPLIT		= 0,
	NSE_RX_DTYPE_HEADER_SPLIT	= 1,
};

enum nse_dynamic_itr {
	ITR_STATIC = 0,
	ITR_DYNAMIC = 1
};

#define ITR_IS_DYNAMIC(qvec) ((qvec)->itr_mode == ITR_DYNAMIC)
#define NSE_ITR_GRAN_S		1	/* ITR granularity is always 2us */
#define NSE_ITR_GRAN_US		BIT(NSE_ITR_GRAN_S)
#define NSE_ITR_MASK		0x1FFE	/* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & NSE_ITR_MASK)

/* Legacy or Advanced Mode Queue */
#define NSE_TX_ADVANCED	0
#define NSE_TX_LEGACY	1

#ifdef NSE_ADD_PROBES
struct nse_xdp_stats {
	u64 xdp_rx_pkts;
	u64 xdp_rx_bytes;
	u64 xdp_pass;
	u64 xdp_drop;
	u64 xdp_tx;
	u64 xdp_tx_fail;
	u64 xdp_unknown;
	u64 xdp_redirect;
	u64 xdp_redirect_fail;
};
#endif

struct nse_txcq_ring {
	void *desc;			/* Descriptor ring memory */
	struct device *dev;		/* Used for DMA mapping */
	struct net_device *netdev;	/* netdev ring maps to */
	struct nse_vsi *vsi;		/* Backreference to associated VSI */
	struct nse_pf *pf;			/* Backreference to associated VSI's owner PF */
	struct nse_q_vector *q_vector;	/* Backreference to associated vector */

	u32 flags;
#define NSE_TX_CQ_FLAGS_CFGED			0x1		/* already configured */
#define NSE_TX_CQ_FLAGS_ENABLED			0x2		/* already enabled */

	u16 q_index;			/* Queue number of ring */

	u16 cq_rel_id;			/* relative ID in PF space */
	u16 cq_abs_id;			/* absolute ID in lan-channel space */

	u32 count;			/* Number of descriptors */

	/* --- cacheline 4 boundary (256 bytes) --- */
	dma_addr_t dma;			/* physical address of ring */
	unsigned int size;		/* length of descriptor ring in bytes */

	u32 next_to_clean;
	u32 generation;

	/* stats structs */
	struct nse_cq_stats stats;
	struct u64_stats_sync syncp;

	struct rcu_head rcu;		/* to avoid race on free */

	struct nse_lan_txcq_ctx saved_txcq_ctx;

	bool need_irqll;
	u16 irqll_msix;

	bool already_in_irqll;
} ____cacheline_internodealigned_in_smp;

#if defined(NSE_DEBUG_EXT)
struct nse_tx_ring_used_record {
	u16 used_desc;
	u8 pad[6];

	u64 raw_ns;
};

#define NSE_TX_RING_USED_RECORD_LEN		2048

struct nse_tx_ring_clean_record {
	u32 clean_desc;

	u32 clean_pkt;

	u32 used_desc;

	u32 clean_all_dd_this_time;

	u64 raw_ns;
};

#define NSE_TX_RING_CLEAN_RECORD_LEN		1024
#endif

/* descriptor ring, associated with a VSI */
struct nse_ring {
	struct nse_ring *next;		/* pointer to next ring in q_vector */
	void *desc;			/* Descriptor ring memory */
	struct device *dev;		/* Used for DMA mapping */
	struct net_device *netdev;	/* netdev ring maps to */
	struct nse_vsi *vsi;		/* Backreference to associated VSI */
	struct nse_pf *pf;			/* Backreference to associated VSI's owner PF */
	struct nse_q_vector *q_vector;	/* Backreference to associated vector */
	u8 __iomem *tail;
	union {
		struct nse_tx_buf *tx_buf;
		struct nse_rx_buf *rx_buf;
	};
	/* --- cacheline 1 boundary (64 bytes) --- */
	u16 q_index;			/* Queue number of ring */
	u16 q_handle;			/* Queue handle per TC */

#define NSE_TX_FLAGS_RING_XDP			BIT(0)
#define NSE_RX_FLAGS_RING_BUILD_SKB		BIT(1)
#define NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1	BIT(2)
#define NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2	BIT(3)
#define NSE_RX_FLAGS_ALWAYS_HAVE_RXHASH		BIT(4)
	u32 flags;

	u16 count;			/* Number of descriptors */
	u16 reg_idx;		/* HW register index of the ring */
						/* also the related ID inside PF RXQ/TXQ space */
	u16 abs_id;			/* lan-channel absolute ID */

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;
	union {
		u16 next_to_alloc;
		u16 next_rs_idx;
	};

	u16 *tx_rs_array;	/* records each RS location */
	u16 tx_rs_ntu;
	u16 tx_rs_ntc;

	u16 xdp_tx_active;

	/* stats structs */
	struct nse_q_stats	stats;
	struct u64_stats_sync syncp;
	union {
		struct nse_txq_stats tx_stats;
		struct nse_rxq_stats rx_stats;
	};

#if defined(NSE_DEBUG_EXT)
	struct nse_tx_ring_used_record *txr_used_records;
	unsigned int txr_used_rec_cur_idx;

	struct nse_tx_ring_clean_record *txr_clean_records;
	unsigned int txr_clean_rec_cur_idx;
#endif

	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct rcu_head rcu;		/* to avoid race on free */
	DECLARE_BITMAP(xps_state, NSE_TX_NBITS);	/* XPS Config State */

	struct bpf_prog *xdp_prog;
#ifdef NSE_ADD_PROBES
	struct nse_xdp_stats xdp_stats;
#endif
	struct xsk_buff_pool *xsk_pool;
	/* --- cacheline 3 boundary (192 bytes) --- */
	struct xdp_rxq_info xdp_rxq;

	/* --- cacheline 4 boundary (256 bytes) --- */
	dma_addr_t dma;			/* physical address of ring */
	unsigned int size;		/* length of descriptor ring in bytes */
	u32 txq_tnid;			/* Added Tx queue TNID */

	/* some virtio fields */
	u64 vtio_dma_drv_addr;
	u64 vtio_dma_dev_addr;
	u16 vtio_head;
	u16 vtio_tail;

	u8 rx_crc_strip_dis;
	u8 dcb_tc;			/* Traffic class of ring */
	u16 rx_buf_len;
	u16 quanta_prof_id;
	struct nse_ptp_tx *tx_tstamps;
	u64 cached_phctime;
	u32 cached_phctime_sec_part;
	u32 cached_phctime_nsec_part;
	u8 ptp_rx:1;
	u8 ptp_tx:1;

	/* cacheline - the below items are only accessed infrequently and
	 * should be in their own cache line if possible
	 */

	union {
		struct nse_lan_rxq_ctx saved_lan_rxq_ctx;
		struct nse_lan_txq_ctx saved_lan_txq_ctx;
	};

	bool need_irqll;
	u16 irqll_msix;

	bool already_in_irqll;

#if defined(NSE_DEBUG_EXT)
	/* when cntdown drops to 0, dump this skb and descriptor */
	unsigned int test_tcsum_pktcnt_cntdown;
	unsigned int test_tso_pktcnt_cntdown;

	unsigned int tdm_check_desc_err_in_checking;
	unsigned int tdm_check_desc_err_tlen;
	unsigned int tdm_check_desc_err_bsize[64];
	unsigned int tdm_check_desc_err_bsize_cnt;
#endif

	atomic_t *bitmap_addr; /* for logall debug */
} ____cacheline_internodealigned_in_smp;

static inline bool nse_ring_uses_build_skb(struct nse_ring *ring)
{
	return !!(ring->flags & NSE_RX_FLAGS_RING_BUILD_SKB);
}

static inline void nse_set_ring_build_skb_ena(struct nse_ring *ring)
{
	ring->flags |= NSE_RX_FLAGS_RING_BUILD_SKB;
}

static inline void nse_clear_ring_build_skb_ena(struct nse_ring *ring)
{
	ring->flags &= ~NSE_RX_FLAGS_RING_BUILD_SKB;
}

static inline bool nse_rx_ring_rxdid_has_rss_hash(struct nse_ring *ring, u8 rxdid)
{
	if (ring->flags & NSE_RX_FLAGS_ALWAYS_HAVE_RXHASH)
		return true;

	return (rxdid == NSE_RXDID_FLEX_NIC ||
			rxdid == NSE_RXDID_FLEX_SWITCHDEV);
}

static inline bool nse_ring_is_xdp(struct nse_ring *ring)
{
	return !!(ring->flags & NSE_TX_FLAGS_RING_XDP);
}

struct nse_ring_container {
	/* head of linked-list of rings */
	struct nse_ring *ring;
};

struct nse_coalesce_stored {
	u16 itr_settings;
	u8 intrl;
	u8 valid;
};

/* iterator for handling rings in ring container */
#define nse_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

static inline unsigned int nse_rx_pg_order(struct nse_ring *ring)
{
#if (PAGE_SIZE < 8192)
	if (ring->rx_buf_len > (PAGE_SIZE / 2))
		return 1;
#endif
	return 0;
}

#define nse_rx_pg_size(_ring) (PAGE_SIZE << nse_rx_pg_order(_ring))

union nse_32b_rx_flex_desc;

bool nse_alloc_rx_bufs(struct nse_ring *rxr, u16 cleaned_count);
netdev_tx_t nse_start_xmit(struct sk_buff *skb, struct net_device *netdev);
u16 nse_select_queue(struct net_device *dev, struct sk_buff *skb,
		     struct net_device *sb_dev);
int nse_setup_tstamp_ring(struct nse_ring *tstamp_ring);

void nse_free_rx_ring(struct nse_ring *rx_ring);
void nse_free_tx_ring(struct nse_ring *tx_ring);
void nse_clean_tx_ring(struct nse_ring *tx_ring);
void nse_clean_rx_ring(struct nse_ring *rx_ring);
int nse_setup_tx_ring(struct nse_ring *tx_ring);
int nse_setup_rx_ring(struct nse_ring *rx_ring);

void nse_clean_lan_txcq_ring(struct nse_txcq_ring *cq_ring);
void nse_free_lan_txcq_ring(struct nse_txcq_ring *cq_ring);
int nse_setup_lan_txcq_ring(struct nse_txcq_ring *cq_ring);

int nse_polling(struct nse_q_vector *q_vector, int budget);

int nse_napi_poll(struct napi_struct *napi, int budget);
int nse_clean_rx_irq(struct nse_ring *rx_ring, int budget);
void nse_clean_ctrl_tx_irq(struct nse_ring *tx_ring);

#if defined(NSE_DEBUG_EXT)
extern void
nse_test_suite_rvlan(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
		     struct sk_buff *skb, u8 rx_ptype, u16 vlan_tag);

extern void
nse_test_suite_tvlan(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb,
					struct nse_tx_offload_params *offload);

extern void
nse_test_suite_tcsum_start(struct nse_ring *tx_ring,
					struct nse_tx_buf *first,
					struct sk_buff *skb);
extern void
nse_test_suite_tcsum_dump_desc(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb);
void
nse_test_suite_tcsum_end(struct nse_ring *tx_ring);

extern void
nse_test_suite_tso_start(struct nse_ring *tx_ring,
					struct nse_tx_buf *first,
					struct sk_buff *skb);
extern void
nse_test_suite_tso_dump_desc(struct nse_ring *tx_ring,
					struct nse_tx_desc *desc,
					struct nse_tx_buf *first,
					struct sk_buff *skb);
void
nse_test_suite_tso_end(struct nse_ring *tx_ring);

void
nse_test_suite_rxdid_dbg_0_desc(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc);

#endif	/* #if defined(NSE_DEBUG_EXT) */

#endif /* _NSE_TXRX_H_ */

