/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_TX_H
#define SPNIC_TX_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>

#include "spnic_nic_qp.h"

#define VXLAN_OFFLOAD_PORT_BE	htons(4789)

enum tx_offload_type {
	TX_OFFLOAD_TSO = BIT(0),
	TX_OFFLOAD_CSUM = BIT(1),
	TX_OFFLOAD_VLAN = BIT(2),
	TX_OFFLOAD_INVALID = BIT(3),
	TX_OFFLOAD_ESP = BIT(4),
};

struct spnic_txq_stats {
	u64	packets;
	u64	bytes;
	u64	busy;
	u64	wake;
	u64	dropped;

	/* Subdivision statistics show in private tool */
	u64	skb_pad_err;
	u64	frag_len_overflow;
	u64	offload_cow_skb_err;
	u64	map_frag_err;
	u64	unknown_tunnel_pkt;
	u64	frag_size_err;

	struct u64_stats_sync	syncp;
};

struct spnic_dma_info {
	dma_addr_t dma;
	u32 len;
};

#define IPV4_VERSION		4
#define IPV6_VERSION		6
#define TCP_HDR_DOFF_UNIT	2
#define TRANSPORT_OFFSET(l4_hdr, skb) ((u32)((l4_hdr) - (skb)->data))

union spnic_ip {
	struct iphdr *v4;
	struct ipv6hdr *v6;
	unsigned char *hdr;
};

struct spnic_tx_info {
	struct sk_buff		*skb;

	u16			wqebb_cnt;
	u16			valid_nr_frags;

	int			num_sge;
	u16			num_pkts;
	u64			num_bytes;
	struct spnic_dma_info	*dma_info;
};

struct spnic_txq {
	struct net_device	*netdev;
	struct device		*dev;

	struct spnic_txq_stats	txq_stats;

	u8			cos;
	u16			q_id;
	u32			q_mask;
	u32			q_depth;

	struct spnic_tx_info	*tx_info;
	struct spnic_io_queue	*sq;

	u64			last_moder_packets;
	u64			last_moder_bytes;
} ____cacheline_aligned;

netdev_tx_t spnic_xmit_frame(struct sk_buff *skb, struct net_device *netdev);

netdev_tx_t spnic_lb_xmit_frame(struct sk_buff *skb, struct net_device *netdev);

struct spnic_dyna_txq_res {
	struct spnic_tx_info *tx_info;
	struct spnic_dma_info *bds;
};

void spnic_txq_get_stats(struct spnic_txq *txq, struct spnic_txq_stats *stats);

void spnic_txq_clean_stats(struct spnic_txq_stats *txq_stats);

struct spnic_nic_dev;
int spnic_alloc_txqs_res(struct spnic_nic_dev *nic_dev, u16 num_sq,
			 u32 sq_depth, struct spnic_dyna_txq_res *txqs_res);

void spnic_free_txqs_res(struct spnic_nic_dev *nic_dev, u16 num_sq,
			 u32 sq_depth, struct spnic_dyna_txq_res *txqs_res);

int spnic_configure_txqs(struct spnic_nic_dev *nic_dev, u16 num_sq,
			 u32 sq_depth, struct spnic_dyna_txq_res *txqs_res);

int spnic_alloc_txqs(struct net_device *netdev);

void spnic_free_txqs(struct net_device *netdev);

int spnic_tx_poll(struct spnic_txq *txq, int budget);

int spnic_flush_txqs(struct net_device *netdev);

void spnic_set_txq_cos(struct spnic_nic_dev *nic_dev, u16 start_qid, u16 q_num, u8 cos);

static inline __sum16 csum_magic(union spnic_ip *ip, unsigned short proto)
{
	return (ip->v4->version == IPV4_VERSION) ?
		csum_tcpudp_magic(ip->v4->saddr, ip->v4->daddr, 0, proto, 0) :
		csum_ipv6_magic(&ip->v6->saddr, &ip->v6->daddr, 0, proto, 0);
}

#endif
