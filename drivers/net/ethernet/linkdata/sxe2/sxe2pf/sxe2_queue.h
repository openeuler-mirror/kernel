/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_queue.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_QUEUE_H__
#define __SXE2_QUEUE_H__

#include <linux/skbuff.h>
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_BUFF_IN_XDP_H
#include <net/xdp.h>
#else
#include <linux/filter.h>
#endif
#endif

#include <linux/types.h>
#include <linux/mutex.h>

#include "sxe2_compat.h"

#define SXE2_DPDK_QUEUE_DFLT_CNT 64
#define SXE2_DPDK_QUEUE_MAX_CNT  256

#define sxe2_for_each_queue(type, head)                            \
		for ((type) = (head).next; (type) != NULL;         \
		     (type) = (type)->next)

struct sxe2_adapter;
struct sxe2_vsi;
struct sxe2_irq_data;
struct sxe2_mqprio_channel;
struct sxe2_ptp_tx;

#define SXE2_TXRX_Q_MAX_CNT 2048
#define SXE2_TXRX_Q_MAX_INDEX 2047

#define SXE2_VSI_TXRX_Q_MAX_CNT 256

#define SXE2_Q_IDX_INVAL 0xffff
#define SXE2_IRQ_IDX_INVAL 0xffff

#define SXE2_DFLT_NUM_RX_DESC 3072
#define SXE2_DFLT_NUM_TX_DESC 256

#define SXE2_REQ_DESC_MULTIPLE 32
#define SXE2_MAX_NUM_DESC 8160
#define SXE2_MIN_NUM_DESC                                                      \
	64
#define SXE2_DESC_ALIGN_32 32

#define SXE2_PAGE_SIZE_4KB 4096
#define SXE2_PAGE_SIZE_8KB 8192

#define SXE2_XDP_MAX_CNT      (64)

#define SXE2_DESC_IDLE(queue)                                \
({                                                          \
	const typeof(queue) __q = (queue);              \
	u16 ntc = __q->next_to_clean;                       \
	u16 ntu = __q->next_to_use;                         \
	u16 depth = __q->depth;                             \
	(u16)(((ntc > ntu) ? 0 : depth) + ntc - ntu - 1);   \
})

enum sxe2_queue_flags {
	SXE2_RXQ_BUILD_SKB_ENABLED = 0,
	SXE2_RXQ_LRO_ENABLED,
	SXE2_RXQ_CRC_STRIP_DISABLED,
	SXE2_TX_FLAGS_Q_XDP,
	SXE2_RXQ_SPLIT_ENABLED,
};

enum sxe2_data_queue_type {
	SXE2_DATA_TQ = 0,
	SXE2_DATA_RQ,
	SXE2_DATA_XDP_TQ,
	SXE2_DATA_QUEUE_MAX,
};

static inline bool sxe2_desc_status0_err_test(__le16 desc_status, const u16 bit)
{
	return !!(desc_status & cpu_to_le16(bit));
}

struct sxe2_desc_ring {
	void *base_addr;
	u8 __iomem *tail;
	dma_addr_t dma;
};

struct sxe2_rx_buf {
	union {
		struct {
			dma_addr_t dma;
			struct page *page;
			u32 pg_offset;
			u16 drv_refcnt;
			struct sk_buff *skb;
		};
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef HAVE_XSK_BATCHED_RX_ALLOC
		struct {
			union {
				struct xdp_buff *xdp;
				void *addr;
			};
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			u64 handle;
#endif
		};
#endif
#endif
	};
};

struct sxe2_tx_buf {
	void *next_to_watch;
	union {
		struct sk_buff *skb;
		void *raw_buf;
	};
	u32 bytecount;
	u16 gso_segs;
	u32 tx_features;
	DEFINE_DMA_UNMAP_LEN(len);
	DEFINE_DMA_UNMAP_ADDR(dma);
};

enum sxe2_xdp_state_t {
	SXE2_TX_XPS_INIT_DONE,
	SXE2_TX_NBITS,
};

struct sxe2_txq_stats {
	u64 tx_restart;
	u64 tx_busy;
	u64 tx_linearize;
	u64 tx_tso_linearize_chk;
	u64 tx_vlan_insert;
	u64 tx_tso_packets;
	u64 tx_tso_bytes;
	u64 tx_csum_none;
	u64 tx_csum_partial;
	u64 tx_csum_partial_inner;
	u64 tx_queue_dropped;
	u64 tx_xmit_more;
};

struct sxe2_rxq_xdp_stats {
	u64 rx_xdp_drop;
	u64 rx_xdp_redirect;
	u64 rx_xdp_redirect_fail;
	u64 rx_xdp_pkts;
	u64 rx_xdp_bytes;
	u64 rx_xdp_pass;
	u64 rx_xdp_unknown;
	u64 rx_xdp_tx_xmit;
	u64 rx_xdp_tx_xmit_fail;

	u64 rx_xsk_drop;
	u64 rx_xsk_redirect;
	u64 rx_xsk_redirect_fail;
	u64 rx_xsk_packets;
	u64 rx_xsk_bytes;
	u64 rx_xsk_pass;
	u64 rx_xsk_unknown;
	u64 rx_xsk_tx_xmit;
	u64 rx_xsk_tx_xmit_fail;
};

struct sxe2_rxq_stats {
	u64 rx_lro_count;
	u64 rx_lro_packets;
	u64 rx_non_eop_descs;
	u64 rx_page_alloc;
	u64 rx_pg_alloc_fail;
	u64 rx_buff_alloc_err;
	u64 rx_csum_err;
	u64 rx_vlan_strip;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
	u64 rx_csum_complete;
	u64 rx_csum_unnecessary_inner;
	u64 rx_lro_bytes;
	u64 rx_pkts_sw_drop;

	struct sxe2_rxq_xdp_stats xdp_stats;
	u64 rx_pa_err;
};

struct sxe2_queue_ipsec_stats {
	u64 rx_error_invalid_sp;
	u64 rx_error_invalid_state;
	u64 rx_error_invalid_ptype;
	u64 rx_error_decrypt_fail;
	u64 rx_offload_success;
	u64 tx_error_invalid_sp;
	u64 tx_error_invalid_state;
	u64 tx_offload_success;
};

struct sxe2_queue_stats {
	u64 packets;
	u64 bytes;
	union {
		struct sxe2_rxq_stats rx_stats;
		struct sxe2_txq_stats tx_stats;
	};
	int prev_pkt;
	struct sxe2_queue_ipsec_stats ipsec_stats;
	struct u64_stats_sync syncp;
};

struct sxe2_queue {
	struct sxe2_queue *next;
	struct device *dev;
	struct net_device *netdev;
	struct sxe2_irq_data *irq_data;
	struct sxe2_desc_ring desc;
	union {
		struct sxe2_rx_buf *rx_buf;
		struct sxe2_tx_buf *tx_buf;
	};

	struct sxe2_vsi *vsi;
#ifdef HAVE_XDP_BUFF_RXQ
	struct xdp_rxq_info xdp_rxq;
#endif

	u16 depth;
	u16 idx_in_pf;
	u16 idx_in_vsi;

	u16 next_to_use;
	u16 next_to_clean;
	union {
		struct {
			u16 rx_offset;
			u16 rx_buf_len;
			u16 next_to_alloc;
		};

		struct {
			u16 next_rs;
			u16 next_dd;
			u16 q_handle;
		};
	};

	struct sxe2_queue_stats *stats;
	struct u64_stats_sync syncp;

	struct rcu_head rcu;

	struct sxe2_mqprio_channel *ch;
	DECLARE_BITMAP(xps_state, SXE2_TX_NBITS);
	struct bpf_prog *xdp_prog;
	union {
		struct sxe2_queue *xdp_ring;
		struct sxe2_ptp_tx *tx_tstamps;
	};

#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *xsk_pool;
#else
	struct xdp_umem *xsk_pool;
#endif

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct zero_copy_allocator zca;
#endif
#endif

	struct sk_buff *skb;

	union {
		struct {
			u64 cached_phctime;
			u8 ptp_rx;
		};

		struct {
			/* in order to protect the data */
			spinlock_t xdp_lock;
			u16 txq_teid;
			u8 ptp_tx;
		};
	};
	u8 dcb_tc;
	unsigned long flags;
	u16 xdp_tx_active;
	u32 max_lro_size;
	u32 split_type_mask;
	u16 hdr_len;
	u8 desc_size;
} ____cacheline_internodealigned_in_smp;

struct sxe2_queue_layout {
	u16 lb;
	u16 lb_offset;

	u16 ctrl;
	u16 ctrl_offset;

	u16 lan;
	u16 lan_offset;

	u16 dpdk;
	u16 dpdk_offset;

	u16 macvlan;
	u16 macvlan_offset;

	u16 xdp;
	u16 xdp_offset;

	u16 esw;
	u16 esw_offset;

	u16 dpdk_esw;
	u16 dpdk_esw_offset;

	u16 sriov;
	u16 sriov_offset;

	DECLARE_BITMAP(txq_map, SXE2_TXRX_Q_MAX_CNT);
	DECLARE_BITMAP(rxq_map, SXE2_TXRX_Q_MAX_CNT);
};

struct sxe2_queue_context {
	u16 max_txq_cnt;
	u16 max_rxq_cnt;
	u16 txq_base_idx_in_dev;
	u16 rxq_base_idx_in_dev;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_queue_layout txq_layout;
	struct sxe2_queue_layout rxq_layout;
};

struct sxe2_list {
	struct sxe2_queue *next;
	u16 cnt;
};

struct sxe2_q_id_transe {
	u16 q_id;
	u16 q_id_in_dev;
	u16 vsi_id;
	bool is_tx;
};

s32 sxe2_vsi_txrx_queues_get(struct sxe2_vsi *vsi);

void sxe2_vsi_txrx_queues_put(struct sxe2_vsi *vsi);

u16 sxe2_usable_txqs_cnt_get(struct sxe2_adapter *adapter);

u16 sxe2_usable_rxqs_cnt_get(struct sxe2_adapter *adapter);

void sxe2_queue_init(struct sxe2_adapter *adapter);

static inline void sxe2_tx_pkt_stats_update(struct sxe2_queue *txq,
					    struct sxe2_queue_stats *stats)
{
	u64_stats_update_begin(&txq->syncp);
	txq->stats->bytes += stats->bytes;
	txq->stats->packets += stats->packets;
	u64_stats_update_end(&txq->syncp);
}

static inline void sxe2_rxq_stats_update(struct sxe2_queue *rxq, u64 pkts,
					 u64 bytes)
{
	u64_stats_update_begin(&rxq->syncp);
	rxq->stats->bytes += bytes;
	rxq->stats->packets += pkts;
	u64_stats_update_end(&rxq->syncp);
}

s32 sxe2_dpdk_abs_qid_get(struct sxe2_adapter *adapter, struct sxe2_q_id_transe *params);

static inline bool sxe2_queue_depth_is_valid(u16 depth)
{
	return (depth >= SXE2_MIN_NUM_DESC && depth <= SXE2_MAX_NUM_DESC &&
		!(depth % SXE2_REQ_DESC_MULTIPLE));
}

#endif
