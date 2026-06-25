/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_tx.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : TX queue implementation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <net/xfrm.h>
#include <net/ndisc.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/u64_stats_sync.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"
#include "hinic5_ptp.h"
#include "hinic5_tx.h"

/* 1872 FT B600 temporary solution, to be removed after config file adaptation */
#define QP_COS_MASK	7
static char qp_cos_mask = QP_COS_MASK;
module_param(qp_cos_mask, byte, 0444);
MODULE_PARM_DESC(qp_cos_mask, "QP COS mask, 0-255 (default=0)");

/* The 1823v200 product non-tso SGEs is 32, and that of the 1825v100&1872v100 is 38.
 * The number of non-tso SGEs is strictly constrained to 32.
 */
#define HINIC5_NONTSO_PKT_MAX_SGE	32

#define MIN_SKB_LEN		32

#define MAX_PAYLOAD_OFFSET	221

#define NIC_QID(q_id, nic_dev)	((q_id) & ((nic_dev)->num_qps - 1))

#define HINIC5_TX_TASK_WRAPPED		1
#define HINIC5_TX_BD_DESC_WRAPPED	2

#define NON_TSO_SKB_SIZE_MAX	0xFFFF
#define TSO_SKB_SIZE_MAX	0x3FFFF

void hinic5_txq_get_stats(struct hinic5_txq *txq,
			  struct hinic5_txq_stats *stats)
{
	struct hinic5_txq_stats *txq_stats = &txq->txq_stats;
	unsigned int start;

	u64_stats_update_begin(&stats->syncp);
	do {
		start = u64_stats_fetch_begin(&txq_stats->syncp);
		stats->bytes = txq_stats->bytes;
		stats->packets = txq_stats->packets;
		stats->busy = txq_stats->busy;
		stats->wake = txq_stats->wake;
		stats->dropped = txq_stats->dropped;
		stats->unfinished = txq_stats->unfinished;
	} while (u64_stats_fetch_retry(&txq_stats->syncp, start));
	u64_stats_update_end(&stats->syncp);
}

void hinic5_txq_clean_stats(struct hinic5_txq_stats *txq_stats)
{
	u64_stats_update_begin(&txq_stats->syncp);
	txq_stats->bytes = 0;
	txq_stats->packets = 0;
	txq_stats->busy = 0;
	txq_stats->wake = 0;
	txq_stats->dropped = 0;
	txq_stats->unfinished = 0;

	txq_stats->skb_pad_err = 0;
	txq_stats->frag_len_overflow = 0;
	txq_stats->offload_cow_skb_err = 0;
	txq_stats->map_frag_err = 0;
	txq_stats->unknown_tunnel_pkt = 0;
	txq_stats->frag_size_err = 0;
	txq_stats->rsvd1 = 0;
	txq_stats->rsvd2 = 0;
	u64_stats_update_end(&txq_stats->syncp);
}

static void txq_stats_init(struct hinic5_txq *txq)
{
	struct hinic5_txq_stats *txq_stats = &txq->txq_stats;

	u64_stats_init(&txq_stats->syncp);
	hinic5_txq_clean_stats(txq_stats);

#ifdef HAVE_XDP_SUPPORT
	hinic5_xdptxq_init_stats(txq);
#endif
}

#ifdef HAVE_XDP_SUPPORT
void hinic5_xdptxq_get_stats(struct hinic5_txq *txq,
			     struct hinic5_xdptxq_stats *stats)
{
	struct hinic5_xdptxq_stats *xdptxq_stats = &txq->xdptxq_stats;
	unsigned int start;

	u64_stats_update_begin(&stats->syncp);
	do {
		start = u64_stats_fetch_begin(&xdptxq_stats->syncp);
		stats->xdp_dropped = xdptxq_stats->xdp_dropped;
		stats->xdp_xmits = xdptxq_stats->xdp_xmits;
		stats->map_xdpf_err = xdptxq_stats->map_xdpf_err;
	} while (u64_stats_fetch_retry(&xdptxq_stats->syncp, start));
	u64_stats_update_end(&stats->syncp);
}

void hinic5_xdptxq_clean_stats(struct hinic5_xdptxq_stats *xdptxq_stats)
{
	u64_stats_update_begin(&xdptxq_stats->syncp);
	xdptxq_stats->xdp_dropped = 0;
	xdptxq_stats->xdp_xmits = 0;
	xdptxq_stats->map_xdpf_err = 0;
	u64_stats_update_end(&xdptxq_stats->syncp);
}

void hinic5_xdptxq_init_stats(struct hinic5_txq *txq)
{
	struct hinic5_xdptxq_stats *xdptxq_stats = &txq->xdptxq_stats;

	u64_stats_init(&xdptxq_stats->syncp);
	hinic5_xdptxq_clean_stats(xdptxq_stats);
}
#endif

static inline void hinic5_set_buf_desc(struct hinic5_sq_bufdesc *buf_descs,
				       dma_addr_t addr, u32 len)
{
	buf_descs->hi_addr = hinic5_hw_be32(upper_32_bits(addr));
	buf_descs->lo_addr = hinic5_hw_be32(lower_32_bits(addr));
	buf_descs->len  = hinic5_hw_be32(len);
	buf_descs->rsvd = 0;
}

static int tx_map_skb(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb,
		      u16 valid_nr_frags, struct hinic5_txq *txq,
		      struct hinic5_tx_info *tx_info,
		      struct hinic5_sq_wqe_combo *wqe_combo)
{
	struct hinic5_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;
	struct hinic5_sq_bufdesc *buf_desc = wqe_combo->bds_head;
	struct hinic5_dma_info *dma_info = tx_info->dma_info;
	struct device *dev = nic_dev->lld_dev->dev;
	skb_frag_t *frag = NULL;
	u32 j, i;
	int err;

	dma_info[0].dma = dma_map_single(dev, skb->data, skb_headlen(skb), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma_info[0].dma) != 0) {
		TXQ_STATS_INC(txq, map_frag_err);
		return -EFAULT;
	}

	dma_info[0].len = skb_headlen(skb);

	wqe_desc->hi_addr = hinic5_hw_be32(upper_32_bits(dma_info[0].dma));
	wqe_desc->lo_addr = hinic5_hw_be32(lower_32_bits(dma_info[0].dma));

	wqe_desc->ctrl_len = dma_info[0].len;

	for (i = 0; i < valid_nr_frags;) {
		frag = &(skb_shinfo(skb)->frags[i]);
		if (unlikely(i == wqe_combo->first_bds_num))
			buf_desc = wqe_combo->bds_sec2;

		i++;
		dma_info[i].dma = skb_frag_dma_map(dev, frag, 0,
						   skb_frag_size(frag),
						   DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_info[i].dma) != 0) {
			TXQ_STATS_INC(txq, map_frag_err);
			i--;
			err = -EFAULT;
			goto frag_map_err;
		}
		dma_info[i].len = skb_frag_size(frag);

		hinic5_set_buf_desc(buf_desc, dma_info[i].dma,
				    dma_info[i].len);
		buf_desc++;
	}

	return 0;

frag_map_err:
	for (j = 0; j < i;) {
		j++;
		dma_unmap_page(dev, dma_info[j].dma,
			       dma_info[j].len, DMA_TO_DEVICE);
	}
	dma_unmap_single(dev, dma_info[0].dma, dma_info[0].len,
			 DMA_TO_DEVICE);
	return err;
}

static inline void tx_unmap_skb(struct hinic5_nic_dev *nic_dev,
				struct sk_buff *skb, u16 valid_nr_frags,
				struct hinic5_dma_info *dma_info)
{
	struct device *dev = nic_dev->lld_dev->dev;
	int i;

	for (i = 0; i < valid_nr_frags;) {
		i++;
		dma_unmap_page(dev,
			       dma_info[i].dma,
			       dma_info[i].len, DMA_TO_DEVICE);
	}

	dma_unmap_single(dev, dma_info[0].dma,
			 dma_info[0].len, DMA_TO_DEVICE);
}

union hinic5_l4 {
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned char *hdr;
};

enum sq_l3_type {
	UNKNOWN_L3TYPE = 0,
	IPV6_PKT = 1,
	IPV4_PKT_NO_CHKSUM_OFFLOAD = 2,
	IPV4_PKT_WITH_CHKSUM_OFFLOAD = 3,
};

enum sq_l4offload_type {
	OFFLOAD_DISABLE   = 0,
	TCP_OFFLOAD_ENABLE  = 1,
	SCTP_OFFLOAD_ENABLE = 2,
	UDP_OFFLOAD_ENABLE  = 3,
};

/* initialize l4_len and offset */
static void get_inner_l4_info(struct sk_buff *skb, union hinic5_l4 *l4,
			      u8 l4_proto, u32 *offset,
			      enum sq_l4offload_type *l4_offload)
{
	switch (l4_proto) {
	case IPPROTO_TCP:
		*l4_offload = TCP_OFFLOAD_ENABLE;
		/* To keep same with TSO, payload offset begins from paylaod */
		*offset = (l4->tcp->doff << TCP_HDR_DATA_OFF_UNIT_SHIFT) +
			   TRANSPORT_OFFSET(l4->hdr, skb);
		break;

	case IPPROTO_UDP:
		*l4_offload = UDP_OFFLOAD_ENABLE;
		*offset = TRANSPORT_OFFSET(l4->hdr, skb);
		break;
	default:
		break;
	}
}

#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)
static inline int hinic5_check_tunnel_pkt_support(struct net_device *netdev, u8 l4_proto,
						  union hinic5_l4 l4)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	switch (l4_proto) {
	case IPPROTO_IPIP:
	case IPPROTO_IPV6:
		if (HINIC5_SUPPORT_IPXIP_OFFLOAD(nic_dev->hwdev))
			return 0;

		break;
	case IPPROTO_UDP:
		if (l4.udp->dest == VXLAN_OFFLOAD_PORT_LE &&
		    HINIC5_SUPPORT_VXLAN_OFFLOAD(nic_dev->hwdev))
			return 0;

		if (l4.udp->dest == GENEVE_OFFLOAD_PORT_LE &&
		    HINIC5_SUPPORT_GENEVE_OFFLOAD(nic_dev->hwdev))
			return 0;

		break;
	default:
		break;
	}

	return -EINVAL;
}
#endif
static void get_inner_l3_l4_type(struct sk_buff *skb, union hinic5_ip *ip,
				 union hinic5_l4 *l4,
				 enum sq_l3_type *l3_type, u8 *l4_proto)
{
	unsigned char *exthdr = NULL;

	if (ip->v4->version == IP4_VERSION) {
		*l3_type = IPV4_PKT_WITH_CHKSUM_OFFLOAD;
		*l4_proto = ip->v4->protocol;

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
		/* inner_transport_header is wrong in centos7.0 and suse12.1 */
		l4->hdr = ip->hdr + ((u8)ip->v4->ihl << IP_HDR_IHL_UNIT_SHIFT);
#endif
	} else if (ip->v4->version == IP6_VERSION) {
		*l3_type = IPV6_PKT;
		exthdr = ip->hdr + sizeof(*ip->v6);
		*l4_proto = ip->v6->nexthdr;
		if (exthdr != l4->hdr) {
			__be16 frag_off = 0;
#ifndef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			ipv6_skip_exthdr(skb, (int)(exthdr - skb->data),
					 l4_proto, &frag_off);
#else
			int pld_off = 0;

			pld_off = ipv6_skip_exthdr(skb,
						   (int)(exthdr - skb->data),
						   l4_proto, &frag_off);
			l4->hdr = skb->data + pld_off;
#endif
		}
	} else {
		*l3_type = UNKNOWN_L3TYPE;
		*l4_proto = 0;
	}
}

static u8 hinic5_get_inner_l4_type(struct sk_buff *skb)
{
	enum sq_l3_type l3_type;
	u8 l4_proto;
	union hinic5_ip ip;
	union hinic5_l4 l4;

	ip.hdr = skb_inner_network_header(skb);
	l4.hdr = skb_inner_transport_header(skb);

	get_inner_l3_l4_type(skb, &ip, &l4, &l3_type, &l4_proto);

	return l4_proto;
}

static void hinic5_set_unknown_tunnel_csum(struct sk_buff *skb)
{
	int csum_offset;
	__sum16 skb_csum;
	u8 l4_proto;

	l4_proto = hinic5_get_inner_l4_type(skb);
	/* Unsupport tunnel packet, disable csum offload */
	skb_checksum_help(skb);

	/* The value of csum is changed from 0xffff to 0 according to RFC1624. */
	if (skb->ip_summed == CHECKSUM_NONE && l4_proto != IPPROTO_UDP) {
		csum_offset = skb_checksum_start_offset(skb) + skb->csum_offset;
		skb_csum = *(__sum16 *)(skb->data + csum_offset);
		if (skb_csum == 0xffff)
			*(__sum16 *)(skb->data + csum_offset) = 0;
	}
}

static int hinic5_tx_csum(struct hinic5_txq *txq, struct sk_buff *skb,
			  struct hinic5_offload_info *offload_info,
			  struct hinic5_queue_info *queue_info)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)
	if (skb->encapsulation != 0) {
		union hinic5_ip ip;
		union hinic5_l4 l4;
		u8 l4_proto;

		offload_info->encapsulation = 1;

		ip.hdr = skb_network_header(skb);
		if (ip.v4->version == IPV4_VERSION) {
			l4_proto = ip.v4->protocol;
			l4.hdr = skb_transport_header(skb);
		} else if (ip.v4->version == IPV6_VERSION) {
			unsigned char *exthdr = NULL;
			__be16 frag_off;

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			offload_info->out_l4_en = 1;
#endif
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			l4.hdr = skb_transport_header(skb);
			if (l4.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data,
						 &l4_proto, &frag_off);
		} else {
			l4_proto = IPPROTO_RAW;
		}

		if (l4_proto == IPPROTO_UDP)
			queue_info->udp_dp_en = 1;

		if (hinic5_check_tunnel_pkt_support(txq->netdev, l4_proto, l4) != 0) {
			TXQ_STATS_INC(txq, unknown_tunnel_pkt);
			hinic5_set_unknown_tunnel_csum(skb);
			return 0;
		}
	}

	offload_info->inner_l4_en = 1;
#else
	offload_info->inner_l4_en = 1;
#endif
	return 1;
}

static void hinic5_set_tso_info(struct hinic5_offload_info *offload_info,
				struct hinic5_queue_info *queue_info,
				enum sq_l4offload_type l4_offload,
				u32 offset, u32 mss)
{
	if (l4_offload == TCP_OFFLOAD_ENABLE) {
		queue_info->tso = 1;
		offload_info->inner_l4_en = 1;
	} else if (l4_offload == UDP_OFFLOAD_ENABLE) {
		queue_info->ufo = 1;
		offload_info->inner_l4_en = 1;
	}

	/* Default enable L3 calculation */
	offload_info->inner_l3_en = 1;

	queue_info->payload_offset = (u8)(offset >> 1);

	/* set MSS value */
	queue_info->mss = (u16)mss;
}

static inline void hinic5_inner_tso_offload(struct hinic5_offload_info *offload_info,
					    struct hinic5_queue_info *queue_info,
					    struct sk_buff *skb,
					    union hinic5_ip ip, union hinic5_l4 l4)
{
	u8 l4_proto;
	u32 offset = 0;
	enum sq_l3_type l3_type;
	enum sq_l4offload_type l4_offload = OFFLOAD_DISABLE;

	get_inner_l3_l4_type(skb, &ip, &l4, &l3_type, &l4_proto);

	if (l4_proto == IPPROTO_TCP)
		l4.tcp->check = ~csum_magic(&ip, IPPROTO_TCP);
#ifdef HAVE_IP6_FRAG_ID_ENABLE_UFO
	else if (l4_proto == IPPROTO_UDP && ip.v4->version == 6)
		offload_info->ip_identify =
			be32_to_cpu(skb_shinfo(skb)->ip6_frag_id);
#endif

	get_inner_l4_info(skb, &l4, l4_proto, &offset, &l4_offload);

#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
	u32 network_hdr_len;

	if (unlikely(l3_type == UNKNOWN_L3TYPE))
		network_hdr_len = 0;
	else
		network_hdr_len = l4.hdr - ip.hdr;

	if (unlikely(!offset)) {
		if (l3_type == UNKNOWN_L3TYPE)
			offset = ip.hdr - skb->data;
		else if (l4_offload == OFFLOAD_DISABLE)
			offset = ip.hdr - skb->data + network_hdr_len;
	}
#endif

	hinic5_set_tso_info(offload_info, queue_info, l4_offload, offset,
			    skb_shinfo(skb)->gso_size);
}

static int hinic5_tso(struct hinic5_offload_info *offload_info,
		      struct hinic5_queue_info *queue_info, struct sk_buff *skb)
{
	union hinic5_ip ip;
	union hinic5_l4 l4;
	u8 l4_proto;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_cow_head(skb, 0) < 0)
		return -EINVAL;

	l4.hdr = skb_transport_header(skb);
	ip.hdr = skb_network_header(skb);
#ifdef HAVE_SK_BUFF_ENCAPSULATION
	if (skb->encapsulation != 0) {
		u32 gso_type = skb_shinfo(skb)->gso_type;
		/* L3 checksum always enable */
		offload_info->out_l3_en = 1;
		offload_info->encapsulation = 1;

		if ((gso_type & SKB_GSO_UDP_TUNNEL_CSUM) != 0) {
			l4.udp->check = ~csum_magic(&ip, IPPROTO_UDP);
			offload_info->out_l4_en = 1;
		} else if ((gso_type & SKB_GSO_UDP_TUNNEL) != 0) {
#ifdef HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
			if (ip.v4->version == 6) {
				l4.udp->check = ~csum_magic(&ip, IPPROTO_UDP);
				offload_info->out_l4_en = 1;
			}
#endif
		}

		if (ip.v4->version == IPV4_VERSION) {
			l4_proto = ip.v4->protocol;
		} else if (ip.v4->version == IPV6_VERSION) {
			union hinic5_l4 l4_ptr;
			unsigned char *exthdr = 0;
			__be16 frag_off;

			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			l4_ptr.hdr = skb_transport_header(skb);
			if (l4_ptr.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
		} else {
			l4_proto = IPPROTO_RAW;
		}

		if (l4_proto == IPPROTO_UDP)
			queue_info->udp_dp_en = 1;

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);
	}
#endif /* HAVE_SK_BUFF_ENCAPSULATION */
	hinic5_inner_tso_offload(offload_info, queue_info, skb, ip, l4);
	return 1;
}

static inline void hinic5_set_vlan_tx_offload(struct hinic5_offload_info *offload_info,
					      u16 vlan_tag, u8 vlan_type)
{
	offload_info->vlan1_tag = vlan_tag;
	offload_info->vlan_sel = vlan_type;
	offload_info->vlan_valid = 1;
}

u32 hinic5_tx_offload(struct sk_buff *skb, struct hinic5_offload_info *offload_info,
		      struct hinic5_queue_info *queue_info, struct hinic5_txq *txq)
{
	u32 offload = 0;
	int tso_cs_en;
	struct hinic5_nic_dev *nic_dev = netdev_priv(txq->netdev);

	tso_cs_en = hinic5_tso(offload_info, queue_info, skb);
	if (tso_cs_en < 0) {
		offload = TX_OFFLOAD_INVALID;
		return offload;
	} else if (tso_cs_en != 0) {
		offload |= TX_OFFLOAD_TSO;
	} else {
		tso_cs_en = hinic5_tx_csum(txq, skb, offload_info, queue_info);
		if (tso_cs_en != 0)
			offload |= TX_OFFLOAD_CSUM;
	}

	if (unlikely(skb_vlan_tag_present(skb) != 0)) {
		/* select vlan insert mode by qid, default 802.1Q Tag type */
		hinic5_set_vlan_tx_offload(offload_info, skb_vlan_tag_get(skb),
					   HINIC5_TX_TPID0);
		offload |= TX_OFFLOAD_VLAN;
	}

	if (unlikely(queue_info->payload_offset > MAX_PAYLOAD_OFFSET)) {
		offload = TX_OFFLOAD_INVALID;
		return offload;
	}
	if (unlikely((skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) != 0)) {
		offload |= TX_OFFLOAD_PTP;
		if (hinic5_ptp_tx_process(nic_dev, skb) == 0)
			offload_info->pkt_1588 = 1;
	}

	return offload;
}

static void get_pkt_stats(struct hinic5_tx_info *tx_info, struct sk_buff *skb)
{
	u32 ihs, hdr_len;

	if (skb_is_gso(skb)) {
#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)
#if (defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && \
	defined(HAVE_SK_BUFF_ENCAPSULATION))
		if (skb->encapsulation != 0) {
#ifdef HAVE_SKB_INNER_TRANSPORT_OFFSET
			ihs = skb_inner_transport_offset(skb) +
			      inner_tcp_hdrlen(skb);
#else
			ihs = (skb_inner_transport_header(skb) - skb->data) +
			      inner_tcp_hdrlen(skb);
#endif
		} else {
#endif
#endif
			ihs = (u32)(skb_transport_offset(skb)) + tcp_hdrlen(skb);
#if (KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE)
#if (defined(HAVE_SKB_INNER_TRANSPORT_HEADER) && \
	defined(HAVE_SK_BUFF_ENCAPSULATION))
		}
#endif
#endif
		hdr_len = (skb_shinfo(skb)->gso_segs - 1) * ihs;
		tx_info->num_bytes = skb->len + (u64)hdr_len;
	} else {
		tx_info->num_bytes = (skb->len > ETH_ZLEN) ? skb->len : ETH_ZLEN;
	}

	tx_info->num_pkts = 1;
}

int hinic5_maybe_stop_tx(struct hinic5_txq *txq, u16 wqebb_cnt)
{
	if (likely(hinic5_get_sq_free_wqebbs(txq->sq) >= wqebb_cnt))
		return 0;

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	netif_stop_subqueue(txq->netdev, txq->q_id);

	if (likely(hinic5_get_sq_free_wqebbs(txq->sq) < wqebb_cnt))
		return -EBUSY;

	/* there have enough wqebbs after queue is wake up */
	netif_start_subqueue(txq->netdev, txq->q_id);

	return 0;
}

static u16 hinic5_set_wqe_combo(struct hinic5_txq *txq,
				struct hinic5_sq_wqe_combo *wqe_combo,
				u16 num_sge, u16 *curr_pi)
{
	void *second_part_wqebbs_addr = NULL;
	void *wqe = NULL;
	u16 first_part_wqebbs_num, tmp_pi;

	wqe_combo->ctrl_bd0 = hinic5_get_sq_one_wqebb(txq->sq, curr_pi);
	if (wqe_combo->wqebb_cnt == 1) {
		/* compact wqe */
		wqe_combo->wqe_type = SQ_WQE_COMPACT_TYPE;
		wqe_combo->task_type = SQ_WQE_TASKSECT_4BYTES;
		wqe_combo->task = (void *)&wqe_combo->ctrl_bd0->queue_info;
		return hinic5_get_and_update_sq_owner(txq->sq, *curr_pi, 1);
	}
	/* extend normal wqe */
	wqe_combo->wqe_type = SQ_WQE_EXTENDED_TYPE;
	wqe_combo->task_type = SQ_WQE_TASKSECT_16BYTES;
	wqe_combo->task = hinic5_get_sq_one_wqebb(txq->sq, &tmp_pi);

	if (num_sge > 1) {
		/* first wqebb contain bd0, and bd size is equal to sq wqebb
		 * size, so we use (num_sge - 1) as wanted weqbb_cnt
		 */
		wqe = hinic5_get_sq_multi_wqebbs(txq->sq, num_sge - 1, &tmp_pi,
						 &second_part_wqebbs_addr,
						 &first_part_wqebbs_num);
		wqe_combo->bds_head = wqe;
		wqe_combo->bds_sec2 = second_part_wqebbs_addr;
		wqe_combo->first_bds_num = first_part_wqebbs_num;
	}

	return hinic5_get_and_update_sq_owner(txq->sq, *curr_pi, wqe_combo->wqebb_cnt);
}

void hinic5_tx_set_normal_task_offload(struct hinic5_offload_info *offload,
				       struct hinic5_sq_wqe_combo *wqe_combo)
{
	struct hinic5_sq_task *task = wqe_combo->task;

	/* if negotiation normal task, not support any offload when used 4B tasksection */
	if (wqe_combo->task_type == SQ_WQE_TASKSECT_4BYTES) {
		task->pkt_info0 = 0;
		return;
	}

	task->pkt_info0 =
			SQ_TASK_INFO0_SET(offload->inner_l4_en, INNER_L4_EN) |
			SQ_TASK_INFO0_SET(offload->inner_l3_en, INNER_L3_EN) |
			SQ_TASK_INFO0_SET(offload->encapsulation, TUNNEL_FLAG) |
			SQ_TASK_INFO0_SET(offload->out_l3_en, OUT_L3_EN) |
			SQ_TASK_INFO0_SET(offload->out_l4_en, OUT_L4_EN);
	task->ip_identify = 0;
	task->pkt_info2 = 0;

	task->vlan_offload = SQ_TASK_INFO3_SET(offload->vlan1_tag, VLAN_TAG) |
				SQ_TASK_INFO3_SET(offload->vlan_sel, VLAN_TYPE) |
				SQ_TASK_INFO3_SET(offload->vlan_valid, VLAN_TAG_VALID);
	task->pkt_info0 = hinic5_hw_be32(task->pkt_info0);
	task->vlan_offload = hinic5_hw_be32(task->vlan_offload);
}

void hinic5_tx_set_compact_task_offload(struct hinic5_offload_info *offload,
					struct hinic5_sq_wqe_combo *wqe_combo)
{
	struct hinic5_sq_task *task = wqe_combo->task;

	task->pkt_info0 =
			SQ_TASK_INFO_SET(offload->out_l3_en, OUT_L3_EN) |
			SQ_TASK_INFO_SET(offload->out_l4_en, OUT_L4_EN) |
			SQ_TASK_INFO_SET(offload->inner_l3_en, INNER_L3_EN) |
			SQ_TASK_INFO_SET(offload->inner_l4_en, INNER_L4_EN) |
			SQ_TASK_INFO_SET(offload->vlan_valid, VLAN_VALID) |
			SQ_TASK_INFO_SET(offload->vlan_sel, VLAN_SEL) |
			SQ_TASK_INFO_SET(offload->vlan1_tag, VLAN_TAG) |
			SQ_TASK_INFO_SET(offload->pkt_1588, PKT_1588);
	task->pkt_info0 = hinic5_hw_be32(task->pkt_info0);
}

static void hinic5_set_wqe_queue_info(struct hinic5_sq_wqe_combo *wqe_combo,
				      struct hinic5_queue_info *queue_info)
{
	u32 *qsf = &wqe_combo->ctrl_bd0->queue_info;
	*qsf = SQ_CTRL_QUEUE_INFO_SET(1, UC) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->sctp, SCTP) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->udp_dp_en, UDP_DP_EN) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->tso, TSO) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->ufo, UFO) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->payload_offset, PLDOFF) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->pkt_type, PKT_TYPE) |
		SQ_CTRL_QUEUE_INFO_SET(queue_info->mss, MSS);

	if (SQ_CTRL_QUEUE_INFO_GET(*qsf, MSS) == 0) {
		*qsf |= SQ_CTRL_QUEUE_INFO_SET(TX_MSS_DEFAULT, MSS);
	} else if (SQ_CTRL_QUEUE_INFO_GET(*qsf, MSS) < TX_MSS_MIN) {
		/* mss should not less than 80 */
		*qsf = SQ_CTRL_QUEUE_INFO_CLEAR(*qsf, MSS);
		*qsf |= SQ_CTRL_QUEUE_INFO_SET(TX_MSS_MIN, MSS);
	}

	*qsf = hinic5_hw_be32(*qsf);
}

/* *
 * hinic5_prepare_sq_ctrl - init sq wqe cs
 * @nr_descs: total sge_num, include bd0 in cs
 */
static void hinic5_prepare_sq_ctrl(struct hinic5_sq_wqe_combo *wqe_combo,
				   struct hinic5_queue_info *queue_info, int nr_descs, u16 owner)
{
	struct hinic5_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;

	wqe_desc->ctrl_len |=
		SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
		SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
		SQ_CTRL_SET(owner, OWNER);

	if (wqe_combo->wqe_type == SQ_WQE_EXTENDED_TYPE) {
		wqe_desc->ctrl_len |= SQ_CTRL_SET(nr_descs, BUFDESC_NUM) |
				      SQ_CTRL_SET(wqe_combo->task_type, TASKSECT_LEN);
		hinic5_set_wqe_queue_info(wqe_combo, queue_info);
	} else {
		/* compact wqe not support TSO offload */
		wqe_desc->ctrl_len |= SQ_CTRL_15BIT_QUEUE_INFO_SET(queue_info->sctp, SCTP) |
			     SQ_CTRL_15BIT_QUEUE_INFO_SET(queue_info->udp_dp_en, UDP_DP_EN) |
			     SQ_CTRL_15BIT_QUEUE_INFO_SET(queue_info->pkt_type, PKT_TYPE);
	}

	wqe_desc->ctrl_len = hinic5_hw_be32(wqe_desc->ctrl_len);
}

static netdev_tx_t hinic5_send_one_skb(struct sk_buff *skb,
				       struct net_device *netdev,
				       struct hinic5_txq *txq)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_sq_wqe_combo wqe_combo = {0};
	struct hinic5_offload_info offload_info = {0};
	struct hinic5_queue_info queue_info = {0};
	struct hinic5_tx_info *tx_info = NULL;
	u32 offload;
	u16 owner = 0, pi = 0;
	u16 wqebb_cnt, num_sge, valid_nr_frags;
	bool find_zero_sge_len = false;
	u32 total_size = 0, frag_size, max_wqe_len;
	int err, i;

	if (unlikely(skb->len < MIN_SKB_LEN)) {
		if (skb_pad(skb, (int)(MIN_SKB_LEN - skb->len)) != 0) {
			TXQ_STATS_INC(txq, skb_pad_err);
			goto tx_skb_pad_err;
		}

		skb->len = MIN_SKB_LEN;
	}

	if (unlikely(skb_shinfo(skb)->nr_frags >= HINIC5_NONTSO_PKT_MAX_SGE)) {
		if (unlikely(skb_linearize(skb) != 0)) {
			TXQ_STATS_INC(txq, offload_cow_skb_err);
			goto tx_drop_pkts;
		}
	}

	max_wqe_len = skb_is_gso(skb) ? TSO_SKB_SIZE_MAX : NON_TSO_SKB_SIZE_MAX;
	frag_size = skb_headlen(skb);
	if (unlikely(frag_size > max_wqe_len || frag_size == 0)) {
		TXQ_STATS_INC(txq, frag_size_err);
		goto tx_drop_pkts;
	}
	total_size += frag_size;

	valid_nr_frags = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		frag_size = skb_frag_size(&skb_shinfo(skb)->frags[i]);
		total_size += frag_size;
		if (unlikely(frag_size == 0)) {
			find_zero_sge_len = true;
			continue;
		} else if (unlikely((find_zero_sge_len) ||
			   (frag_size > max_wqe_len) ||
			   (total_size > max_wqe_len))) {
			TXQ_STATS_INC(txq, frag_size_err);
			goto tx_drop_pkts;
		}
		valid_nr_frags++;
	}

	num_sge = valid_nr_frags + 1;

	/* assume need normal TS format wqe, task info need 1 wqebb */
	wqebb_cnt = num_sge + 1;
	if (unlikely(hinic5_maybe_stop_tx(txq, wqebb_cnt) != 0)) {
		TXQ_STATS_INC(txq, busy);
		return NETDEV_TX_BUSY;
	}

	offload = hinic5_tx_offload(skb, &offload_info, &queue_info, txq);
	if (unlikely(offload == TX_OFFLOAD_INVALID)) {
		TXQ_STATS_INC(txq, offload_cow_skb_err);
		goto tx_drop_pkts;
	} else if (offload == 0 && num_sge == 1) {
		/* no TS in current wqe */
		wqebb_cnt -= 1;
		if (unlikely(num_sge == 1 && skb->len > COMPACET_WQ_SKB_MAX_LEN))
			goto tx_drop_pkts;
	} else if ((nic_dev->tx_wqe_compact_task != 0) &&
			   ((offload & TX_OFFLOAD_TSO) == 0) &&
			   num_sge == 1) {
		/* One more wqebb is needed for compact task under two situations:
		 * 1. TSO: MSS field is needed, no available space for compact task in compact wqe.
		 * 2. SGE number > 1: WQE is handled as extented wqe by nic.
		 */
		wqebb_cnt -= 1;
	}

	wqe_combo.wqebb_cnt = wqebb_cnt;
	wqe_combo.offload = (u8)offload;
	owner = hinic5_set_wqe_combo(txq, &wqe_combo, num_sge, &pi);
	nic_dev->tx_rx_ops.tx_set_wqe_offload(&offload_info, &wqe_combo);

	tx_info = &txq->tx_info[pi];
	tx_info->skb = skb;
	tx_info->wqebb_cnt = wqebb_cnt;
	tx_info->valid_nr_frags = valid_nr_frags;

	err = tx_map_skb(nic_dev, skb, valid_nr_frags, txq, tx_info,
			 &wqe_combo);
	if (err != 0) {
		hinic5_rollback_sq_wqebbs(txq->sq, wqebb_cnt, owner);
		goto tx_drop_pkts;
	}

	get_pkt_stats(tx_info, skb);

	hinic5_prepare_sq_ctrl(&wqe_combo, &queue_info, num_sge, owner);

	skb_tx_timestamp(skb);

	hinic5_write_db(txq->sq, (txq->cos & nic_dev->cos_mask_mode) & (u8)qp_cos_mask, SQ_CFLAG_DP,
			hinic5_get_sq_local_pi(txq->sq));

	return NETDEV_TX_OK;

tx_drop_pkts:
	dev_kfree_skb_any(skb);

tx_skb_pad_err:
	TXQ_STATS_INC(txq, dropped);

	return NETDEV_TX_OK;
}

netdev_tx_t hinic5_lb_xmit_frame(struct sk_buff *skb,
				 struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u16 q_id = skb_get_queue_mapping(skb);
	struct hinic5_txq *txq = &nic_dev->txqs[q_id];

	return hinic5_send_one_skb(skb, netdev, txq);
}

bool hinic5_check_skb_need_dual_send(struct sk_buff *skb)
{
	struct {
		struct ipv6hdr ip6;
		struct icmp6hdr icmp6;
	} *combined = NULL, _combined;

	/* ARP packet */
	if (skb->protocol == htons(ETH_P_ARP))
		return true;
	if (skb->protocol == htons(ETH_P_IPV6)) {
		combined = skb_header_pointer(skb, (int)skb_mac_header_len(skb),
					      sizeof(_combined),
					      &_combined);
		if (combined && combined->ip6.nexthdr == NEXTHDR_ICMP &&
		    (combined->icmp6.icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
		     combined->icmp6.icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT))
			return true;
	}

	return false;
}

static int txq_free_old_skbs(struct hinic5_txq *txq, int budget);
#define XMIT_CLEAN_BUDGET	1024    /* clean unused skbs as much as possible */

netdev_tx_t hinic5_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_txq *txq = NULL;
	u16 q_id = skb_get_queue_mapping(skb);

	if (unlikely(!netif_carrier_ok(netdev))) {
		dev_kfree_skb_any(skb);
		HINIC5_NIC_STATS_INC(nic_dev, tx_carrier_off_drop);
		return NETDEV_TX_OK;
	}

	/* Check if ARP dual send is needed */
	if (hinic5_check_dev_need_dual_send(nic_dev->hwdev) &&
	    hinic5_check_skb_need_dual_send(skb)) {
		skb_queue_tail(&nic_dev->arp_queue, skb_get(skb));
		queue_work(nic_dev->workq, &nic_dev->arp_dual_work);
	}

	if (unlikely(q_id >= nic_dev->q_params.num_qps)) {
		txq = &nic_dev->txqs[0];
		HINIC5_NIC_STATS_INC(nic_dev, tx_invalid_qid);
		goto tx_drop_pkts;
	}
	txq = &nic_dev->txqs[q_id];

	/* Clean up pending old skbs before queueing new ones. */
	txq_free_old_skbs(txq, XMIT_CLEAN_BUDGET);

	return hinic5_send_one_skb(skb, netdev, txq);

tx_drop_pkts:
	dev_kfree_skb_any(skb);
	u64_stats_update_begin(&txq->txq_stats.syncp);
	txq->txq_stats.dropped++;
	u64_stats_update_end(&txq->txq_stats.syncp);

	return NETDEV_TX_OK;
}

static inline void tx_free_skb(struct hinic5_nic_dev *nic_dev,
			       struct hinic5_tx_info *tx_info)
{
	if (tx_info->skb) {
		tx_unmap_skb(nic_dev, tx_info->skb, tx_info->valid_nr_frags,
			     tx_info->dma_info);
		dev_kfree_skb_any(tx_info->skb);
		tx_info->skb = NULL;
	}
#ifdef HAVE_XDP_SUPPORT
	if (tx_info->xdpf) {
		dma_unmap_single(nic_dev->lld_dev->dev, tx_info->dma_info->dma,
				 tx_info->dma_info->len, DMA_TO_DEVICE);
		tx_info->xdpf = NULL;
	}
#endif
}

static void free_all_tx_skbs(struct hinic5_nic_dev *nic_dev, u32 sq_depth,
			     struct hinic5_tx_info *tx_info_arr)
{
	struct hinic5_tx_info *tx_info = NULL;
	u32 idx;

	for (idx = 0; idx < sq_depth; idx++) {
		tx_info = &tx_info_arr[idx];
		if (tx_info->skb)
			tx_free_skb(nic_dev, tx_info);
	}
}

static int txq_free_old_skbs(struct hinic5_txq *txq, int budget)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(txq->netdev);
	struct hinic5_tx_info *tx_info = NULL;
	u64 tx_bytes = 0, nr_pkts = 0;
	int pkts = 0;
#ifdef HAVE_XDP_SUPPORT
	u32 xmit_pkts = 0;
#endif
	u16 wqebb_cnt = 0;
	u16 hw_ci, sw_ci;

	hw_ci = hinic5_get_sq_hw_ci(txq->sq);
	dma_rmb();
	sw_ci = hinic5_get_sq_local_ci(txq->sq);

	do {
		tx_info = &txq->tx_info[sw_ci];

		/* Whether all of the wqebb of this wqe is completed */
		if (hw_ci == sw_ci ||
		    ((u16)(hw_ci - sw_ci) & txq->q_mask) < tx_info->wqebb_cnt)
			break;

		sw_ci = (u16)(sw_ci + tx_info->wqebb_cnt) & (u16)txq->q_mask;
		prefetch(&txq->tx_info[sw_ci]);

		wqebb_cnt += tx_info->wqebb_cnt;

		tx_bytes += tx_info->num_bytes;
		nr_pkts += tx_info->num_pkts;
		pkts++;
#ifdef HAVE_XDP_SUPPORT
		if (tx_info->xdpf)
			xmit_pkts++;
#endif
		tx_free_skb(nic_dev, tx_info);
	} while (likely(pkts < budget));

	if (pkts == 0)
		return 0;

	hinic5_update_sq_local_ci(txq->sq, wqebb_cnt);

	u64_stats_update_begin(&txq->txq_stats.syncp);
	txq->txq_stats.bytes += tx_bytes;
	txq->txq_stats.packets += nr_pkts;
	u64_stats_update_end(&txq->txq_stats.syncp);

#ifdef HAVE_XDP_SUPPORT
	/* xmit_pkts stats will not appear simultaneously with tx_bytes stats */
	u64_stats_update_begin(&txq->xdptxq_stats.syncp);
	txq->xdptxq_stats.xdp_xmits += xmit_pkts;
	u64_stats_update_end(&txq->xdptxq_stats.syncp);
#endif

	return pkts;
}

static inline void txq_wake(struct hinic5_txq *txq)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(txq->netdev);
	const u16 q_id = txq->sq->q_id;
	struct netdev_queue *netdev_txq = NULL;
	bool need_wake, do_wake = false;

	need_wake = __netif_subqueue_stopped(nic_dev->netdev, q_id) &&
		    hinic5_get_sq_free_wqebbs(txq->sq) >= 1 &&
		    test_bit(HINIC5_INTF_UP, &nic_dev->flags);
	if (likely(!need_wake))
		return;

	netdev_txq = netdev_get_tx_queue(txq->netdev, q_id);

	__netif_tx_lock(netdev_txq, smp_processor_id());
	/* To avoid re-waking subqueue with xmit_frame */
	if (__netif_subqueue_stopped(nic_dev->netdev, q_id)) {
		netif_wake_subqueue(nic_dev->netdev, q_id);
		do_wake = true;
	}
	__netif_tx_unlock(netdev_txq);

	if (likely(do_wake))
		TXQ_STATS_INC(txq, wake);
}

int hinic5_tx_poll(struct hinic5_txq *txq, int budget)
{
	const u16 q_id = txq->sq->q_id;
	struct netdev_queue *netdev_txq = netdev_get_tx_queue(txq->netdev, q_id);
	int pkts = 0;

	if (__netif_tx_trylock(netdev_txq)) {
		pkts = txq_free_old_skbs(txq, budget);
		__netif_tx_unlock(netdev_txq);
	}

	txq_wake(txq);

	return pkts;
}

void hinic5_set_txq_cos(struct hinic5_nic_dev *nic_dev, u16 start_qid,
			u16 q_num, u8 cos)
{
	u16 idx;

	for (idx = 0; idx < q_num; idx++)
		nic_dev->txqs[idx + start_qid].cos = cos;
}

#define HINIC5_BDS_PER_SQ_WQEBB	\
	(HINIC5_SQ_WQEBB_SIZE / sizeof(struct hinic5_sq_bufdesc))

int hinic5_alloc_txqs_res(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res)
{
	struct hinic5_dyna_txq_res *tqres = NULL;
	int idx, i;
	u64 size;

	for (idx = 0; idx < num_sq; idx++) {
		tqres = &txqs_res[idx];

		size = sizeof(*tqres->tx_info) * sq_depth;
		tqres->tx_info = kzalloc(size, GFP_KERNEL);
		if (!tqres->tx_info) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc txq%d tx info\n", idx);
			goto err_out;
		}

		size = sizeof(*tqres->bds) *
			(sq_depth * HINIC5_BDS_PER_SQ_WQEBB +
			 HINIC5_MAX_SQ_SGE);
		tqres->bds = kzalloc(size, GFP_KERNEL);
		if (!tqres->bds) {
			kfree(tqres->tx_info);
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc txq%d bds info\n", idx);
			goto err_out;
		}
	}

	return 0;

err_out:
	for (i = 0; i < idx; i++) {
		tqres = &txqs_res[i];

		kfree(tqres->bds);
		tqres->bds = NULL;
		kfree(tqres->tx_info);
		tqres->tx_info = NULL;
	}

	return -ENOMEM;
}

void hinic5_free_txqs_res(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res)
{
	struct hinic5_dyna_txq_res *tqres = NULL;
	int idx;

	for (idx = 0; idx < num_sq; idx++) {
		tqres = &txqs_res[idx];

		free_all_tx_skbs(nic_dev, sq_depth, tqres->tx_info);
		kfree(tqres->bds);
		kfree(tqres->tx_info);
	}
}

int hinic5_configure_txqs(struct hinic5_nic_dev *nic_dev, u16 num_sq,
			  u32 sq_depth, struct hinic5_dyna_txq_res *txqs_res)
{
	struct hinic5_dyna_txq_res *tqres = NULL;
	struct hinic5_txq *txq = NULL;
	u16 q_id;
	u32 idx;

	for (q_id = 0; q_id < num_sq; q_id++) {
		txq = &nic_dev->txqs[q_id];
		tqres = &txqs_res[q_id];

		txq->q_depth = sq_depth;
		txq->q_mask = sq_depth - 1;

		txq->tx_info = tqres->tx_info;
		for (idx = 0; idx < sq_depth; idx++)
			txq->tx_info[idx].dma_info =
				&tqres->bds[idx * HINIC5_BDS_PER_SQ_WQEBB];

		txq->sq = hinic5_get_nic_queue(nic_dev->hwdev, q_id, HINIC5_SQ);
		if (!txq->sq) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to get %u sq\n", q_id);
			return -EFAULT;
		}
	}

	return 0;
}

int hinic5_alloc_txqs(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct device *dev = nic_dev->lld_dev->dev;
	struct hinic5_txq *txq = NULL;
	u16 q_id, num_txqs = nic_dev->max_qps;
	u64 txq_size;

	txq_size = num_txqs * sizeof(*nic_dev->txqs);
	if (txq_size == 0) {
		nic_err(dev, "Cannot allocate zero size txqs\n");
		return -EINVAL;
	}

	nic_dev->txqs = kzalloc(txq_size, GFP_KERNEL);
	if (!nic_dev->txqs)
		return -ENOMEM;

	for (q_id = 0; q_id < num_txqs; q_id++) {
		txq = &nic_dev->txqs[q_id];
		txq->netdev = netdev;
		txq->q_id = q_id;
		txq->q_depth = nic_dev->q_params.sq_depth;
		txq->q_mask = nic_dev->q_params.sq_depth - 1;
		txq->dev = dev;

		txq_stats_init(txq);
	}

	return 0;
}

void hinic5_free_txqs(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	kfree(nic_dev->txqs);
	nic_dev->txqs = NULL;
}

static bool is_hw_complete_sq_process(struct hinic5_io_queue *sq)
{
	u16 sw_pi, hw_ci;

	sw_pi = hinic5_get_sq_local_pi(sq);
	hw_ci = hinic5_get_sq_hw_ci(sq);

	return sw_pi == hw_ci;
}

#define HINIC5_FLUSH_QUEUE_TIMEOUT	1000
static int hinic5_stop_sq(struct hinic5_txq *txq)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(txq->netdev);
	u64 timeout;
	int err;

	timeout = msecs_to_jiffies(HINIC5_FLUSH_QUEUE_TIMEOUT) + jiffies;
	do {
		if (is_hw_complete_sq_process(txq->sq))
			return 0;

		usleep_range(900, 1000); /* sleep 900 us ~ 1000 us */
	} while (time_before(jiffies, (unsigned long)timeout));

	/* force hardware to drop packets */
	timeout = msecs_to_jiffies(HINIC5_FLUSH_QUEUE_TIMEOUT) + jiffies;
	do {
		if (is_hw_complete_sq_process(txq->sq))
			return 0;

		err = hinic5_force_drop_tx_pkt(nic_dev->hwdev);
		if (err != 0)
			break;

		usleep_range(9900, 10000); /* sleep 9900 us ~ 10000 us */
	} while (time_before(jiffies, (unsigned long)timeout));

	/* Avoid msleep takes too long and get a fake result */
	if (is_hw_complete_sq_process(txq->sq))
		return 0;

	return -EFAULT;
}

/* should stop transmit any packets before calling this function */
int hinic5_flush_txqs(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u16 qid;
	int err;

	for (qid = 0; qid < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; qid++) {
		err = hinic5_stop_sq(&nic_dev->txqs[qid]);
		if (err != 0)
			nicif_err(nic_dev, drv, netdev,
				  "Failed to stop sq%u\n", qid);
	}

	return 0;
}

