/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_queue.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_QUEUE_H__
#define __SXE2VF_QUEUE_H__

struct sxe2vf_irq_data;
struct sxe2vf_vsi;

#define SXE2VF_QUEUES_CNT_MAX 16

#define SXE2VF_ETH_QUEUE_CNT_MIN  1
#define SXE2VF_DPDK_QUEUE_CNT_MIN 1

#define sxe2vf_for_each_queue(type, head)                          \
		for ((type) = (head).next; (type) != NULL;         \
		     (type) = (type)->next)

#define SXE2VF_DESC_IDLE(queue) \
({ \
	typeof(queue) __q = (queue); \
	((u16)((((__q)->next_to_clean > (__q)->next_to_use) ? \
	0 : \
	(__q)->depth) + \
	((__q)->next_to_clean - (__q)->next_to_use - 1))); \
})

struct sxe2vf_desc_ring {
	void *base_addr;
	u8 __iomem *tail;
	dma_addr_t dma;
};

struct sxe2vf_rx_buf {
	dma_addr_t dma;
	struct page *page;
	u32 pg_offset;
	u32 drv_refcnt;
	struct sk_buff *skb;
};

struct sxe2vf_tx_buf {
	void *next_to_watch;
	union {
		struct sk_buff *skb;
	};
	u32 bytecount;
	u16 gso_segs;
	u32 tx_features;
	DEFINE_DMA_UNMAP_LEN(len);
	DEFINE_DMA_UNMAP_ADDR(dma);
};

struct sxe2vf_txq_stats {
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

struct sxe2vf_rxq_stats {
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
	u64 rx_pa_err;
};

struct sxe2vf_queue_ipsec_stats {
	u64 tx_error_invalid_sp;
	u64 tx_error_invalid_state;
	u64 tx_offload_success;
	u64 rx_error_invalid_sp;
	u64 rx_error_invalid_state;
	u64 rx_error_invalid_ptype;
	u64 rx_error_decrypt_fail;
	u64 rx_offload_success;
};

struct sxe2vf_queue_stats {
	u64 packets;
	u64 bytes;
	union {
		struct sxe2vf_rxq_stats rx_stats;
		struct sxe2vf_txq_stats tx_stats;
	};
	struct sxe2vf_queue_ipsec_stats ipsec_stats;
	struct rcu_head rcu;
	struct u64_stats_sync syncp;
};

struct sxe2vf_queue {
	struct sxe2vf_queue *next;
	struct device *dev;
	struct net_device *netdev;
	struct sxe2vf_irq_data *irq_data;
	struct sxe2vf_desc_ring desc;
	union {
		struct sxe2vf_rx_buf *rx_buf;
		struct sxe2vf_tx_buf *tx_buf;
	};

	struct sxe2vf_vsi *vsi;

	u16 depth;
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

	struct sxe2vf_queue_stats *stats;
	struct u64_stats_sync syncp;

	struct rcu_head rcu;

	struct sk_buff *skb;
	unsigned long flags;
} ____cacheline_internodealigned_in_smp;

struct sxe2vf_vsi_queues {
	u16 q_cnt;
	u16 depth;
	struct sxe2vf_queue **q;
};

struct sxe2vf_queue_context {
	u16 max_cnt;
	u16 q_cnt_req;
	u16 eth_q_cnt;
	u16 eth_offset;
	u16 dpdk_q_cnt;
	u16 dpdk_offset;
};

static inline bool sxe2vf_desc_status0_err_test(__le16 desc_status,
						const u16 bit)
{
	return !!(desc_status & cpu_to_le16(bit));
}

#endif
