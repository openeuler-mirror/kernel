/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_tx.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_TX_H
#define HINIC5_TX_H

#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <linux/u64_stats_sync.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"
#include "hinic5_nic_io.h"

#define TXQ_STATS_INC(txq, field)			\
do {							\
	u64_stats_update_begin(&(txq)->txq_stats.syncp);	\
	(txq)->txq_stats.field++;				\
	u64_stats_update_end(&(txq)->txq_stats.syncp);	\
} while (0)

#ifdef HAVE_XDP_SUPPORT
#define XDP_TXQ_STATS_INC(txq, field)			\
do {							\
	u64_stats_update_begin(&(txq)->xdptxq_stats.syncp);	\
	(txq)->xdptxq_stats.field++;				\
	u64_stats_update_end(&(txq)->xdptxq_stats.syncp);	\
} while (0)
#endif

#define VXLAN_OFFLOAD_PORT_LE 0xb512 /* big end is 4789 */
#define GENEVE_OFFLOAD_PORT_LE 0xc117 /* big end is 6081 */

#define COMPACET_WQ_SKB_MAX_LEN 16383

#define IP4_VERSION 4
#define IP6_VERSION 6
#define IP_HDR_IHL_UNIT_SHIFT 2
#define TCP_HDR_DATA_OFF_UNIT_SHIFT 2

enum tx_offload_type {
	TX_OFFLOAD_TSO = BIT(0),
	TX_OFFLOAD_CSUM = BIT(1),
	TX_OFFLOAD_VLAN = BIT(2),
	TX_OFFLOAD_INVALID = BIT(3),
	TX_OFFLOAD_ESP = BIT(4),
	TX_OFFLOAD_PTP = BIT(5),
};

enum hinic5_tx_cvlan_type {
	HINIC5_TX_TPID0,
};

struct hinic5_txq_stats {
	u64	packets;
	u64	bytes;
	u64	busy;
	u64	wake;
	u64	dropped;
	u64	unfinished;

	/* Subdivision statistics show in private tool */
	u64	skb_pad_err;
	u64	frag_len_overflow;
	u64	offload_cow_skb_err;
	u64	map_frag_err;
	u64	unknown_tunnel_pkt;
	u64	frag_size_err;
	u64	rsvd1;
	u64	rsvd2;

#ifdef HAVE_NDO_GET_STATS64
	struct u64_stats_sync	syncp;
#else
	struct u64_stats_sync_empty syncp;
#endif
};

#ifdef HAVE_XDP_SUPPORT
struct hinic5_xdptxq_stats {
	u64	xdp_dropped;
	u64	xdp_xmits;
	u64	map_xdpf_err;

#ifdef HAVE_NDO_GET_STATS64
	struct u64_stats_sync	syncp;
#else
	struct u64_stats_sync_empty syncp;
#endif
};
#endif

struct hinic5_dma_info {
	dma_addr_t dma;
	u32 len;
};

#define IPV4_VERSION		4
#define IPV6_VERSION		6
#define TCP_HDR_DOFF_UNIT	2
#define TRANSPORT_OFFSET(l4_hdr, skb) ((u32)((l4_hdr) - (skb)->data))

union hinic5_ip {
	struct iphdr *v4;
	struct ipv6hdr *v6;
	unsigned char *hdr;
};

struct hinic5_tx_info {
	struct sk_buff *skb;

	u16 wqebb_cnt;
	u16 valid_nr_frags;

	int num_sge;
	u16 num_pkts;
	u16 rsvd1;
	u32 rsvd2;
	u64 num_bytes;
	struct hinic5_dma_info *dma_info;
#ifdef HAVE_XDP_SUPPORT
	struct xdp_frame *xdpf;
#endif
	u64 rsvd3;
};

struct hinic5_txq {
	struct net_device *netdev;
	struct device *dev;

	struct hinic5_txq_stats txq_stats;

#ifdef HAVE_XDP_SUPPORT
	struct hinic5_xdptxq_stats xdptxq_stats;
#endif

	u8 cos;
	u8 rsvd1;
	u16 q_id;
	u32 q_mask;
	u32 q_depth;
	u32 rsvd2;

	struct hinic5_tx_info *tx_info;
	struct hinic5_io_queue *sq;

	u64 last_moder_packets;
	u64 last_moder_bytes;
	u64 rsvd3;
} ____cacheline_aligned;

netdev_tx_t hinic5_lb_xmit_frame(struct sk_buff *skb,
				 struct net_device *netdev);

struct hinic5_dyna_txq_res {
	struct hinic5_tx_info *tx_info;
	struct hinic5_dma_info *bds;
};

netdev_tx_t hinic5_xmit_frame(struct sk_buff *skb, struct net_device *netdev);

u32 hinic5_tx_offload(struct sk_buff *skb, struct hinic5_offload_info *offload_info,
		      struct hinic5_queue_info *queue_info, struct hinic5_txq *txq);

void hinic5_txq_get_stats(struct hinic5_txq *txq,
			  struct hinic5_txq_stats *stats);

void hinic5_txq_clean_stats(struct hinic5_txq_stats *txq_stats);

#ifdef HAVE_XDP_SUPPORT
void hinic5_xdptxq_get_stats(struct hinic5_txq *txq,
			     struct hinic5_xdptxq_stats *stats);

void hinic5_xdptxq_clean_stats(struct hinic5_xdptxq_stats *xdptxq_stats);

void hinic5_xdptxq_init_stats(struct hinic5_txq *txq);
#endif

struct hinic5_nic_dev;
int hinic5_alloc_txqs_res(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res);

void hinic5_free_txqs_res(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res);

int hinic5_configure_txqs(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res);

int hinic5_alloc_txqs(struct net_device *netdev);

void hinic5_free_txqs(struct net_device *netdev);

int hinic5_tx_poll(struct hinic5_txq *txq, int budget);

int hinic5_flush_txqs(struct net_device *netdev);

void hinic5_set_txq_cos(struct hinic5_nic_dev *nic_dev, u16 start_qid,
			u16 q_num, u8 cos);

static inline __sum16 csum_magic(union hinic5_ip *ip, unsigned short proto)
{
	return (ip->v4->version == IPV4_VERSION) ?
		csum_tcpudp_magic(ip->v4->saddr, ip->v4->daddr, 0, (u8)proto, 0) :
		csum_ipv6_magic(&ip->v6->saddr, &ip->v6->daddr, 0, (u8)proto, 0);
}

void hinic5_tx_set_normal_task_offload(struct hinic5_offload_info *offload,
				       struct hinic5_sq_wqe_combo *wqe_combo);

void hinic5_tx_set_compact_task_offload(struct hinic5_offload_info *offload,
					struct hinic5_sq_wqe_combo *wqe_combo);

int hinic5_maybe_stop_tx(struct hinic5_txq *txq, u16 wqebb_cnt);
#endif
