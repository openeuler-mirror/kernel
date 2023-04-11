/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_TXRX_H_
#define _NBL_TXRX_H_

#include <linux/kernel.h>
#include <linux/device.h>

#define NBL_DEFAULT_TX_DESC_NUM 512
#define NBL_DEFAULT_RX_DESC_NUM 512
#define NBL_MAX_TX_DESC_NUM 4096
#define NBL_MAX_RX_DESC_NUM 4096
#define NBL_MIN_TX_DESC_NUM 32
#define NBL_MIN_RX_DESC_NUM 32

#define NBL_PAGE_SIZE_THRESH 8192

#define NBL_DEFAULT_RING_NUM (4)
#define NBL_VF_DEFAULT_RING_NUM (1)
#define NBL_MAX_RING_NUM (16)

#define NBL_RX_BUF_LEN 2048
#define NBL_RX_BUF_256 256
#define NBL_RX_HDR_SIZE NBL_RX_BUF_256
#define NBL_RX_BUF_WRITE 16

#define MAX_DESC_NEEDED_PER_PKT 8

#define NBL_DEFAULT_IRQ_WORK 128

#define NBL_TX_MIN_GSO_SIZE 256
#define NBL_TX_MAX_OFFLOAD_HEADER_LEN 256

enum nbl_rx_checksum_status {
	NBL_RX_CSUM_ERR,
	NBL_RX_CSUM_OK,
};

enum nbl_inner_ip_type {
	NBL_INNER_NONE,
	NBL_INNER_IPV6,
	NBL_INNER_IPV4,
	NBL_INNER_RSV,
};

enum nbl_external_ip_type {
	NBL_EXT_NONE,
	NBL_EXT_IPV6,
	NBL_EXT_IPV4,
	NBL_EXT_RSV,
};

enum nbl_tx_desc_type {
	NBL_DATA_DESC,
	NBL_TSO_DESC,
};

enum nbl_tunnel_type {
	NBL_TUN_NONE,
	NBL_TUN_VXLAN,
	NBL_TUN_NVGRE,
	NBL_TUN_RSV,
};

enum nbl_l4_type {
	NBL_FRAGMENTED_TYPE,
	NBL_TCP_TYPE,
	NBL_UDP_TYPE,
};

/* Note: keep sizeof(nbl_tso_desc) equal sizeof(nbl_tx_desc) */
struct nbl_tso_desc {
	u32 mss:14;
	u32 rsv0:2;
	u32 pkt_len:16;
	u32 dd:1;
	u32 eop:1;
	u32 sop:1;
	u32 fwd:2;
	u32 dport:1;
	u32 dport_id:7;
	u32 l3_checksum:1;
	u32 l4_checksum:1;
	u32 rss_lag:1;
	u32 l3_start_offset:6;
	u32 rsv1:8;
	u32 dtype:2;
	u32 mac_len:4;
	u32 ip_len:5;
	u32 l4_len:4;
	u32 iipt:2;
	u32 eipt:2;
	u32 eip_len:5;
	u32 l4_tunt:3;
	u32 l4_tun_len:5;
	u32 l4_type:2;
	u32 rsv2;
};

struct nbl_tx_desc {
	u32 data_len:16;
	u32 pkt_len:16;
	u32 dd:1;
	u32 eop:1;
	u32 sop:1;
	u32 fwd:2;
	u32 dport:1;
	u32 dport_id:7;
	u32 l3_checksum:1;
	u32 l4_checksum:1;
	u32 rss_lag:1;
	u32 l3_start_offset:6;
	u32 rsv1:8;
	u32 dtype:2;
	u64 buffer_addr;
};

enum nbl_txd_fwd_type {
	NBL_FWD_DROP,
	NBL_FWD_NORMAL,
	NBL_FWD_RSV,
	NBL_FWD_CPU,
};

enum nbl_txd_dst_port_type {
	NBL_TXD_DPORT_ETH,
	NBL_TXD_DPORT_HOST,
};

#define NBL_TXD_DATALEN_BITS 14
#define NBL_TXD_DATALEN_MAX ((1 << NBL_TXD_DATALEN_BITS) - 1)

struct nbl_rx_desc {
	u32 data_len:14;
	u32 rsv0:18;
	u32 dd:1;
	u32 eop:1;
	u32 sop:1;
	u32 fwd:2;
	u32 sport:1;
	u32 sport_id:7;
	u32 checksum_status:1;
	u32 ptype:8;
	u32 lag:1;
	u32 lag_id:2;
	u32 rsv1:7;
	u64 buffer_addr;
};

enum nbl_rxd_fwd_type {
	NBL_RXD_FWD_DROP,
	NBL_RXD_FWD_NORMAL,
	NBL_RXD_FWD_CPU,
	NBL_RXD_FWD_RSV,
};

enum nbl_rxd_src_port_type {
	NBL_RXD_SPORT_ETH,
	NBL_RXD_SPORT_HOST,
};

struct nbl_tx_buf {
	struct nbl_tx_desc *next_to_watch;
	struct sk_buff *skb;
	unsigned int bytes;
	unsigned short pkts;
	DEFINE_DMA_UNMAP_LEN(len);
	DEFINE_DMA_UNMAP_ADDR(dma);
};

struct nbl_rx_buf {
	dma_addr_t dma;
	struct page *page;
	u32 page_offset;
};

struct nbl_queue_stats {
	u64 packets;
	u64 bytes;
};

#define NBL_QUEUE_STAT_ENTRIES (2)

struct nbl_tx_queue_stats {
	u64 tx_busy;
	u64 tx_linearize;
	u64 tx_csum_pkts;
	u64 tx_dma_err;
};

struct nbl_rx_queue_stats {
	u64 rx_csum_pkts;
	u64 alloc_page_failed;
	u64 rx_dma_err;
	u64 alloc_skb_failed;
};

struct nbl_ring {
	struct nbl_ring *next;
	struct nbl_q_vector *q_vector;
	struct device *dev;
	struct net_device *netdev;
	void *desc;
	u8 __iomem *notify_addr;
	union {
		struct nbl_tx_buf *tx_bufs;
		struct nbl_rx_buf *rx_bufs;
	};

	u8 queue_index;
	u8 local_qid;

	u16 desc_num;

	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_alloc;
	u16 tail_ptr;

#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
	struct dma_attrs rx_buf_attrs;
#endif
#endif
	u32 buf_len;

	unsigned int size;
	dma_addr_t dma;

	struct nbl_queue_stats stats;
	struct u64_stats_sync syncp;

	union {
		struct nbl_tx_queue_stats tx_stats;
		struct nbl_rx_queue_stats rx_stats;
	};
};

struct nbl_q_vector {
	int q_vector_id;
	int global_vector_id;
	struct nbl_adapter *adapter;
	struct napi_struct napi;
	u32 num_ring_rx;
	u32 num_ring_tx;
	struct nbl_ring *tx_ring;
	struct nbl_ring *rx_ring;

	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;

	/* "-TxRx-nn" use 8 characters */
	char name[IFNAMSIZ + 8];
};

static inline u16 nbl_unused_desc_count(struct nbl_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->desc_num) + ntc - ntu - 1;
}

#define NBL_TX_DESC(tx_ring, i)  (&(((struct nbl_tx_desc *)((tx_ring)->desc))[i]))
#define NBL_RX_DESC(rx_ring, i)  (&(((struct nbl_rx_desc *)((rx_ring)->desc))[i]))
#define NBL_TX_BUF(tx_ring, i)  (&(((tx_ring)->tx_bufs)[i]))
#define NBL_RX_BUF(rx_ring, i)  (&(((rx_ring)->rx_bufs)[i]))

static inline u32 nbl_rx_page_order(struct nbl_ring *rx_ring)
{
#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
	if (rx_ring->buf_len > (PAGE_SIZE / 2))
		return 1;
#endif
	return 0;
}

#define NBL_RX_PAGE_SIZE(rx_ring) (PAGE_SIZE << nbl_rx_page_order(rx_ring))
#define NBL_RX_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

static inline void nbl_update_tail_ptr(u8 __iomem *notify_addr, u16 local_qid, u16 tail_ptr)
{
	writel((((u32)tail_ptr << 16) | (u32)local_qid), notify_addr);
}

int nbl_alloc_q_vectors(struct nbl_adapter *adapter);
void nbl_free_q_vectors(struct nbl_adapter *adapter);

int nbl_alloc_rings(struct nbl_adapter *adapter);
void nbl_free_rings(struct nbl_adapter *adapter);

void nbl_map_rings_to_vectors(struct nbl_adapter *adapter);

int nbl_setup_rings(struct nbl_adapter *adapter);
void nbl_teardown_rings(struct nbl_adapter *adapter);

void nbl_af_hw_config_tx_ring(struct nbl_hw *hw, u16 func_id, dma_addr_t dma,
			      u16 desc_num, u8 vsi_id, u8 local_queue_id);
void nbl_af_hw_config_rx_ring(struct nbl_hw *hw, u16 func_id, dma_addr_t dma,
			      u16 desc_num, u32 buf_len, u8 local_queue_id);
void nbl_hw_config_rings(struct nbl_adapter *adapter);

void nbl_alloc_all_rx_bufs(struct nbl_adapter *adapter);

void nbl_af_configure_queue_map(struct nbl_hw *hw, u16 func_id, u8 local_queue_id,
				bool rx, u16 local_vector_id, bool enable,
				bool msix_enable);

void nbl_af_control_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id, bool rx, bool enable);
int nbl_af_reset_tx_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id);
int nbl_af_reset_rx_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id);
int nbl_af_wait_rx_queue_reset_done(struct nbl_hw *hw, u16 func_id, u8 local_queue_id);

void nbl_af_configure_port_map(struct nbl_hw *hw, u16 func_id, u8 eth_port_id, u8 tx_queue_num);
void nbl_af_configure_rss_group_table(struct nbl_hw *hw, u16 func_id, u8 vsi_id, u8 rx_queue_num);

void nbl_start_all_tx_rings(struct nbl_adapter *adapter);
void nbl_start_all_rx_rings(struct nbl_adapter *adapter);
void nbl_stop_all_tx_rings(struct nbl_adapter *adapter);
void nbl_stop_all_rx_rings(struct nbl_adapter *adapter);

void nbl_af_eth_tx_enable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_af_eth_tx_disable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_af_eth_rx_enable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_af_eth_rx_disable(struct nbl_adapter *adapter, u8 eth_port_id);

void nbl_eth_tx_enable(struct nbl_adapter *adapter);
void nbl_eth_tx_disable(struct nbl_adapter *adapter);
void nbl_eth_rx_enable(struct nbl_adapter *adapter);
void nbl_eth_rx_disable(struct nbl_adapter *adapter);

netdev_tx_t nbl_start_xmit(struct sk_buff *skb, struct net_device *netdev);

bool nbl_clean_tx_irq(struct nbl_ring *tx_ring, int napi_budget);
int nbl_clean_rx_irq(struct nbl_ring *rx_ring, int budget);

void nbl_free_all_rx_bufs(struct nbl_adapter *adapter);
void nbl_free_all_tx_bufs(struct nbl_adapter *adapter);

int nbl_af_clean_forward_ring_rx_irq(struct nbl_ring *rx_ring, int budget);
bool nbl_af_clean_forward_ring_tx_irq(struct nbl_ring *tx_ring, int napi_budget);

int nbl_activate_af_forward_queue(struct nbl_adapter *adapter);
void nbl_deactivate_af_forward_queue(struct nbl_adapter *adapter);

#endif
