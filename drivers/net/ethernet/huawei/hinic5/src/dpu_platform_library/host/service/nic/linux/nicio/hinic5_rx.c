/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_rx.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : RX queue implementation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/u64_stats_sync.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/compiler.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_common.h"
#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"
#include "hinic5_nic_io.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"
#include "hinic5_rss.h"
#include "hinic5_ptp.h"
#include "hinic5_xdp.h"
#include "hinic5_rx.h"

#ifdef HAVE_XDP_SUPPORT
#include <net/xdp.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#endif

static bool rx_alloc_mapped_page(struct hinic5_nic_dev *nic_dev,
				 struct hinic5_rx_info *rx_info)
{
	struct page *page = rx_info->page;
	dma_addr_t dma = rx_info->buf_dma_addr;
	u32 page_offset = 0;

	if (likely(dma != 0))
		return true;

	/* alloc new page for storage */
#ifdef HAVE_PAGE_POOL_SUPPORT
	if (rx_info->page_pool) {
		page = page_pool_alloc_frag(rx_info->page_pool, &page_offset,
					    nic_dev->rx_buff_len,
					    GFP_ATOMIC | __GFP_COMP);
		if (unlikely(!page))
			return false;
		dma = page_pool_get_dma_addr(page);
		goto set_rx_info;
	}
#endif
	page = alloc_pages_node(NUMA_NO_NODE, GFP_ATOMIC | __GFP_COLD |
				__GFP_COMP, nic_dev->page_order);
	if (unlikely(!page))
		return false;

	/* map page for use */
	dma = dma_map_page(nic_dev->lld_dev->dev, page, 0, nic_dev->dma_rx_buff_size,
			   DMA_FROM_DEVICE);
	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (unlikely(dma_mapping_error(nic_dev->lld_dev->dev, dma) != 0)) {
		__free_pages(page, nic_dev->page_order);
		return false;
	}
	goto set_rx_info;

set_rx_info:
	rx_info->page = page;
	rx_info->buf_dma_addr = dma;
	rx_info->page_offset = page_offset;

	return true;
}

static u32 hinic5_rx_fill_wqe(struct hinic5_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	int rq_wqe_len = rxq->rq->wq.wqebb_size;
	struct hinic5_rq_wqe *rq_wqe = NULL;
	struct hinic5_rx_info *rx_info = NULL;
	u32 i;

	for (i = 0; i < rxq->q_depth; i++) {
		rx_info = &rxq->rx_info[i];
		rq_wqe = hinic5_rq_wqe_addr(rxq->rq, (u16)i);

		if (rxq->rq->wqe_type == HINIC5_EXTEND_RQ_WQE) {
				/* unit of cqe length is 16B */
			hinic5_set_sge(&rq_wqe->extend_wqe.cqe_sect.sge,
				       rx_info->cqe_dma,
				       (HINIC5_CQE_LEN >> HINIC5_CQE_SIZE_SHIFT));
			/* use fixed len */
			rq_wqe->extend_wqe.buf_desc.sge.len =
					nic_dev->rx_buff_len;
		} else if (rxq->rq->wqe_type == HINIC5_NORMAL_RQ_WQE) {
			rq_wqe->normal_wqe.cqe_hi_addr =
				upper_32_bits(rx_info->cqe_dma);
			rq_wqe->normal_wqe.cqe_lo_addr =
				lower_32_bits(rx_info->cqe_dma);
		}

		hinic5_hw_be32_len(rq_wqe, rq_wqe_len);
		rx_info->rq_wqe = rq_wqe;
	}

	return i;
}

static u32 hinic5_rx_fill_buffers(struct hinic5_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_rq_wqe *rq_wqe = NULL;
	struct hinic5_rx_info *rx_info = NULL;
	dma_addr_t dma_addr;
	u32 i, free_wqebbs = rxq->delta - 1;

	for (i = 0; i < free_wqebbs; i++) {
		rx_info = &rxq->rx_info[rxq->next_to_update];

		if (unlikely(!rx_alloc_mapped_page(nic_dev, rx_info))) {
			RXQ_STATS_INC(rxq, alloc_rx_buf_err);
			break;
		}

#ifdef HAVE_XDP_SUPPORT
		dma_addr = (rxq->xdp_headroom_flag == 0) ?
			   rx_info->buf_dma_addr + rx_info->page_offset :
			   rx_info->buf_dma_addr + rx_info->page_offset + XDP_PACKET_HEADROOM;
#else
		dma_addr = rx_info->buf_dma_addr + rx_info->page_offset;
#endif

		rq_wqe = rx_info->rq_wqe;

		/* Regardless of the WQE type, the address is located in the first 64 bits */
		rq_wqe->compact_wqe.buf_hi_addr =
			hinic5_hw_be32(upper_32_bits(dma_addr));
		rq_wqe->compact_wqe.buf_lo_addr =
			hinic5_hw_be32(lower_32_bits(dma_addr));

		rxq->next_to_update = (u16)((rxq->next_to_update + 1) & rxq->q_mask);
	}

	if (likely(i != 0)) {
		hinic5_write_db(rxq->rq,
				(rxq->q_id & 0x3),
				RQ_CFLAG_DP,
				(u16)((u32)rxq->next_to_update << rxq->rq->wqe_type));
		rxq->delta -= i;
		rxq->next_to_alloc = rxq->next_to_update;
	} else if (free_wqebbs == rxq->q_depth - 1) {
		RXQ_STATS_INC(rxq, rx_buf_empty);
	}

	return i;
}

static u32 hinic5_rx_alloc_buffers(struct hinic5_nic_dev *nic_dev, u32 rq_depth,
				   struct hinic5_rx_info *rx_info_arr)
{
	u32 free_wqebbs = rq_depth - 1;
	u32 idx;

	for (idx = 0; idx < free_wqebbs; idx++) {
		if (!rx_alloc_mapped_page(nic_dev, &rx_info_arr[idx]))
			break;
	}

	return idx;
}

static void hinic5_rx_free_buffers(struct hinic5_nic_dev *nic_dev, u32 q_depth,
				   struct hinic5_rx_info *rx_info_arr)
{
	struct hinic5_rx_info *rx_info = NULL;
	u32 i;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < q_depth; i++) {
		rx_info = &rx_info_arr[i];

#ifdef HAVE_PAGE_POOL_SUPPORT
		if (rx_info->page_pool && rx_info->page) {
			page_pool_put_page(rx_info->page_pool,
					   rx_info->page,
					   nic_dev->rx_buff_len, false);
			goto clean_info;
		}
#endif
		if (rx_info->buf_dma_addr != 0) {
			dma_unmap_page(nic_dev->lld_dev->dev,
				       rx_info->buf_dma_addr,
				       nic_dev->dma_rx_buff_size,
				       DMA_FROM_DEVICE);
			__free_pages(rx_info->page, nic_dev->page_order);
			goto clean_info;
		}
clean_info:
		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
	}
}

void hinic5_reuse_rx_page(struct hinic5_rxq *rxq,
			  struct hinic5_rx_info *old_rx_info)
{
	struct hinic5_rx_info *new_rx_info = NULL;
	u16 nta = rxq->next_to_alloc;

	new_rx_info = &rxq->rx_info[nta];

	/* update, and store next to alloc */
	nta++;
	rxq->next_to_alloc = (nta < rxq->q_depth) ? nta : 0;

	new_rx_info->page = old_rx_info->page;
	new_rx_info->page_offset = old_rx_info->page_offset;
	new_rx_info->buf_dma_addr = old_rx_info->buf_dma_addr;

	/* sync the buffer for use by the device */
	dma_sync_single_range_for_device(rxq->dev, new_rx_info->buf_dma_addr,
					 new_rx_info->page_offset,
					 rxq->buf_len,
					 DMA_FROM_DEVICE);
}

static bool hinic5_add_rx_frag(struct hinic5_rxq *rxq,
			       struct hinic5_rx_info *rx_info,
			       struct sk_buff *skb, u32 size, u8 packet_offset)
{
	struct page *page = NULL;
	u8 *va = NULL;

	page = rx_info->page;
	va = (u8 *)page_address(page) + rx_info->page_offset;
	prefetch(va);
#if L1_CACHE_BYTES < 128
	prefetch(va + L1_CACHE_BYTES);
#endif

	dma_sync_single_range_for_cpu(rxq->dev,
				      rx_info->buf_dma_addr,
				      rx_info->page_offset,
				      rxq->buf_len,
				      DMA_FROM_DEVICE);

	if (size <= HINIC5_RX_HDR_SIZE && !skb_is_nonlinear(skb)) {
		__skb_put_data(skb, va + packet_offset, size);

#ifdef HAVE_PAGE_POOL_SUPPORT
		if (rx_info->page_pool) {
			page_pool_put_page(rx_info->page_pool, page, rxq->buf_len, false);
			return false;
		}
#endif

		/* page is not reserved, we can reuse buffer as-is */
		if (likely(page_to_nid(page) == numa_node_id()))
			return true;

		/* this page cannot be reused so discard it */
		put_page(page);
		goto discard_page;
	}

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			(int)rx_info->page_offset + packet_offset, (int)size, rxq->buf_len);

#ifdef HAVE_PAGE_POOL_SUPPORT
	if (rx_info->page_pool) {
		skb_mark_for_recycle(skb);
		return false;
	}
#endif

	/* avoid re-using remote pages */
	if (unlikely(page_to_nid(page) != numa_node_id()))
		goto discard_page;

	/* if we are only owner of page we can reuse it */
	if (unlikely(page_count(page) != 1))
		goto discard_page;

	/* flip page offset to other buffer */
	rx_info->page_offset ^= rxq->buf_len;
	get_page(page);

	return true;

discard_page:
	/* we are not reusing the buffer so unmap it */
	dma_unmap_page(rxq->dev, rx_info->buf_dma_addr,
		       rxq->dma_rx_buff_size, DMA_FROM_DEVICE);
	return false;
}

static void packaging_skb(struct hinic5_rxq *rxq, struct sk_buff *head_skb,
			  u8 sge_num, u32 pkt_len, u8 packet_offset)
{
	struct hinic5_rx_info *rx_info = NULL;
	struct sk_buff *skb = NULL;
	u8 frag_num = 0;
	u32 size;
	u32 sw_ci;
	u32 temp_pkt_len = pkt_len;
	u8 temp_sge_num = sge_num;
	u8 temp_offset = packet_offset;

	sw_ci = rxq->cons_idx & rxq->q_mask;
	skb = head_skb;
	while (temp_sge_num != 0) {
		rx_info = &rxq->rx_info[sw_ci];
		sw_ci = (sw_ci + 1) & rxq->q_mask;
		if (unlikely(temp_pkt_len > rxq->buf_len - temp_offset)) {
			size = rxq->buf_len - temp_offset;
			temp_pkt_len -= (rxq->buf_len - temp_offset);
		} else {
			size = temp_pkt_len;
		}

		if (unlikely(frag_num == MAX_SKB_FRAGS)) {
			frag_num = 0;
			if (skb == head_skb)
				skb = skb_shinfo(skb)->frag_list;
			else
				skb = skb->next;
		}

		if (unlikely(skb != head_skb)) {
			head_skb->len += size;
			head_skb->data_len += size;
			head_skb->truesize += rxq->buf_len;
		}

		if (likely(hinic5_add_rx_frag(rxq, rx_info, skb, size, temp_offset)))
			hinic5_reuse_rx_page(rxq, rx_info);

		/* clear contents of buffer_info */
		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		temp_sge_num--;
		temp_offset = 0; /* only the first (compact) sge use the offset */
		frag_num++;
	}
}

struct sk_buff *hinic5_fetch_rx_buffer(struct hinic5_rxq *rxq,
				       const struct hinic5_cqe_info *cqe_info)
{
	struct sk_buff *head_skb = NULL;
	struct sk_buff *cur_skb = NULL;
	struct sk_buff *skb = NULL;
	struct net_device *netdev = rxq->netdev;
	u32 pkt_len = cqe_info->pkt_len;
	u8 packet_offset = cqe_info->packet_offset;
	u8 sge_num, skb_num;
	u16 wqebb_cnt = 0;

	head_skb = netdev_alloc_skb_ip_align(netdev, HINIC5_RX_HDR_SIZE);
	if (unlikely(!head_skb))
		return NULL;

	sge_num = HINIC5_GET_SGE_NUM(pkt_len + packet_offset, rxq);
	if (likely(sge_num <= MAX_SKB_FRAGS))
		skb_num = 1;
	else
		skb_num = (sge_num / MAX_SKB_FRAGS) +
			(((sge_num % MAX_SKB_FRAGS) != 0) ? 1 : 0);

	while (unlikely(skb_num > 1)) {
		cur_skb = netdev_alloc_skb_ip_align(netdev, HINIC5_RX_HDR_SIZE);
		if (unlikely(!cur_skb))
			goto alloc_skb_fail;

		if (!skb) {
			skb_shinfo(head_skb)->frag_list = cur_skb;
			skb = cur_skb;
		} else {
			skb->next = cur_skb;
			skb = cur_skb;
		}

		skb_num--;
	}

	prefetchw(head_skb->data);
	wqebb_cnt = sge_num;
	packaging_skb(rxq, head_skb, sge_num, pkt_len, packet_offset);
	rxq->cons_idx += wqebb_cnt;
	rxq->delta += wqebb_cnt;

	return head_skb;

alloc_skb_fail:
	dev_kfree_skb_any(head_skb);

	return NULL;
}

void hinic5_rxq_get_stats(struct hinic5_rxq *rxq,
			  struct hinic5_rxq_stats *stats)
{
	struct hinic5_rxq_stats *rxq_stats = &rxq->rxq_stats;
	unsigned int start;

	u64_stats_update_begin(&stats->syncp);
	do {
		start = u64_stats_fetch_begin(&rxq_stats->syncp);
		stats->bytes = rxq_stats->bytes;
		stats->packets = rxq_stats->packets;
		stats->errors = rxq_stats->csum_errors +
				rxq_stats->other_errors;
		stats->csum_errors = rxq_stats->csum_errors;
		stats->other_errors = rxq_stats->other_errors;
		stats->dropped = rxq_stats->dropped;
#ifdef HAVE_XDP_SUPPORT
		stats->xdp_dropped = rxq_stats->xdp_dropped;
		stats->xdp_redirected = rxq_stats->xdp_redirected;
		stats->xdp_large_pkt = rxq_stats->xdp_large_pkt;
#endif
		stats->rx_buf_empty = rxq_stats->rx_buf_empty;
	} while (u64_stats_fetch_retry(&rxq_stats->syncp, start));
	u64_stats_update_end(&stats->syncp);
}

void hinic5_rxq_clean_stats(struct hinic5_rxq_stats *rxq_stats)
{
	u64_stats_update_begin(&rxq_stats->syncp);
	rxq_stats->bytes = 0;
	rxq_stats->packets = 0;
	rxq_stats->errors = 0;
	rxq_stats->csum_errors = 0;
	rxq_stats->other_errors = 0;
	rxq_stats->dropped = 0;
	rxq_stats->rx_buf_empty = 0;

	rxq_stats->alloc_skb_err = 0;
	rxq_stats->alloc_rx_buf_err = 0;
	rxq_stats->restore_drop_sge = 0;
	rxq_stats->pkt_mc = 0;
#ifdef HAVE_XDP_SUPPORT
	rxq_stats->xdp_dropped = 0;
	rxq_stats->xdp_redirected = 0;
	rxq_stats->xdp_large_pkt = 0;
#endif
	u64_stats_update_end(&rxq_stats->syncp);
}

static void rxq_stats_init(struct hinic5_rxq *rxq)
{
	struct hinic5_rxq_stats *rxq_stats = &rxq->rxq_stats;

	u64_stats_init(&rxq_stats->syncp);
	hinic5_rxq_clean_stats(rxq_stats);
}

#ifndef HAVE_ETH_GET_HEADLEN_FUNC
static unsigned int hinic5_eth_get_headlen(unsigned char *data, unsigned int max_len)
{
#define IP_FRAG_OFFSET	0x1FFF
#define FCOE_HLEN	38
#define ETH_P_8021_AD	0x88A8
#define ETH_P_8021_Q	0x8100
#define TCP_HEAD_OFFSET	12
	union {
		unsigned char *data;
		struct ethhdr *eth;
		struct vlan_ethhdr *vlan;
		struct iphdr *ipv4;
		struct ipv6hdr *ipv6;
	} hdr;
	u16 protocol;
	u8 nexthdr = 0;
	u8 hlen;

	if (unlikely(max_len < ETH_HLEN))
		return max_len;

	hdr.data = data;
	protocol = hdr.eth->h_proto;

	/* L2 header */
	if (protocol == htons(ETH_P_8021_AD) ||
	    protocol == htons(ETH_P_8021_Q)) {
		if (unlikely(max_len < ETH_HLEN + VLAN_HLEN))
			return max_len;

		/* L3 protocol */
		protocol = hdr.vlan->h_vlan_encapsulated_proto;
		hdr.data += sizeof(struct vlan_ethhdr);
	} else {
		hdr.data += ETH_HLEN;
	}

	/* L3 header */
	switch (protocol) {
	case htons(ETH_P_IP):
		if ((int)(hdr.data - data) >
		    (int)(max_len - sizeof(struct iphdr)))
			return max_len;

		/* L3 header length = (1st byte & 0x0F) << 2 */
		hlen = (hdr.data[0] & 0x0F) << 2;

		if (hlen < sizeof(struct iphdr))
			return (unsigned int)(hdr.data - data);

		if ((hdr.ipv4->frag_off & htons(IP_FRAG_OFFSET)) == 0)
			nexthdr = hdr.ipv4->protocol;

		hdr.data += hlen;
		break;

	case htons(ETH_P_IPV6):
		if ((int)(hdr.data - data) >
		    (int)(max_len - sizeof(struct ipv6hdr)))
			return max_len;
		/* L4 protocol */
		nexthdr = hdr.ipv6->nexthdr;
		hdr.data += sizeof(struct ipv6hdr);
		break;

	case htons(ETH_P_FCOE):
		hdr.data += FCOE_HLEN;
		break;

	default:
		return (unsigned int)(hdr.data - data);
	}

	/* L4 header */
	switch (nexthdr) {
	case IPPROTO_TCP:
		if ((int)(hdr.data - data) >
		    (int)(max_len - sizeof(struct tcphdr)))
			return max_len;

		/* L4 header length = (13st byte & 0xF0) >> 2 */
		if (((hdr.data[TCP_HEAD_OFFSET] & 0xF0) >>
			 HINIC5_HEADER_DATA_UNIT) > sizeof(struct tcphdr))
			hdr.data += ((hdr.data[TCP_HEAD_OFFSET] & 0xF0) >>
						 HINIC5_HEADER_DATA_UNIT);
		else
			hdr.data += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		hdr.data += sizeof(struct udphdr);
		break;

	case IPPROTO_SCTP:
		hdr.data += sizeof(struct sctphdr);
		break;
	default:
		break;
	}

	if ((hdr.data - data) > max_len)
		return max_len;
	else
		return (unsigned int)(hdr.data - data);
}
#endif

static void hinic5_pull_tail(struct sk_buff *skb)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va = NULL;
	unsigned int pull_len;

	/* it is valid to use page_address instead of kmap since we are
	 * working with pages allocated out of the lomem pool per
	 * alloc_page(GFP_ATOMIC)
	 */
	va = skb_frag_address(frag);

#ifdef HAVE_ETH_GET_HEADLEN_FUNC
	/* we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */
#ifdef ETH_GET_HEADLEN_NEED_DEV
	pull_len = eth_get_headlen(skb->dev, va, HINIC5_RX_HDR_SIZE);
#elif defined(HAVE_ETH_GET_HEADLEN_NET_DEVICE_ARG)
	pull_len = eth_get_headlen(skb->dev, va, HINIC5_RX_HDR_SIZE);
#else
	pull_len = eth_get_headlen(va, HINIC5_RX_HDR_SIZE);
#endif

#else
	pull_len = hinic5_eth_get_headlen(va, HINIC5_RX_HDR_SIZE);
#endif

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, (int)pull_len);
	skb_frag_off_add(frag, (int)pull_len);

	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

static void hinic5_rx_csum(struct hinic5_rxq *rxq, const struct hinic5_cqe_info *cqe_info,
			   struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;

	if (unlikely(cqe_info->csum_err == HINIC5_RX_CSUM_IPSU_OTHER_ERR))
		rxq->rxq_stats.other_errors++;

	if ((netdev->features & NETIF_F_RXCSUM) == 0)
		return;

	if (unlikely(cqe_info->csum_err != 0)) {
		/* pkt type is recognized by HW, and csum is wrong */
		if ((cqe_info->csum_err & (HINIC5_RX_CSUM_HW_CHECK_NONE |
				  HINIC5_RX_CSUM_IPSU_OTHER_ERR)) == 0)
			rxq->rxq_stats.csum_errors++;
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	if (cqe_info->ip_type == HINIC5_RX_INVALID_IP_TYPE ||
	    !(cqe_info->pkt_fmt == HINIC5_RX_PKT_FORMAT_NON_TUNNEL ||
	      cqe_info->pkt_fmt == HINIC5_RX_PKT_FORMAT_VXLAN)) {
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	switch (cqe_info->pkt_type) {
	case HINIC5_RX_TCP_PKT:
	case HINIC5_RX_UDP_PKT:
	case HINIC5_RX_SCTP_PKT:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		skb->ip_summed = CHECKSUM_NONE;
		break;
	}
}

#ifdef HAVE_SKBUFF_CSUM_LEVEL
static void hinic5_rx_gro(struct hinic5_rxq *rxq, u8 pkt_fmt,
			  struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;
	bool l2_tunnel = false;

	if ((netdev->features & NETIF_F_GRO) == 0)
		return;

	l2_tunnel = (pkt_fmt == HINIC5_RX_PKT_FORMAT_VXLAN) ? 1 : 0;
	if (l2_tunnel && skb->ip_summed == CHECKSUM_UNNECESSARY)
		/* If we checked the outer header let the stack know */
		skb->csum_level = 1;
}
#endif /* HAVE_SKBUFF_CSUM_LEVEL */

static void hinic5_copy_lp_data(struct hinic5_nic_dev *nic_dev,
				struct sk_buff *skb)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 *lb_buf = nic_dev->lb_test_rx_buf;
	void *frag_data = NULL;
	int lb_len = nic_dev->lb_pkt_len;
	int pkt_offset, frag_len, i;

	if (nic_dev->lb_test_rx_idx == LP_PKT_CNT) {
		nic_dev->lb_test_rx_idx = 0;
		nicif_warn(nic_dev, rx_err, netdev, "Loopback test warning, receive too many test pkts\n");
	}

	if (skb->len != (u32)(nic_dev->lb_pkt_len)) {
		nicif_warn(nic_dev, rx_err, netdev, "Wrong packet length\n");
		nic_dev->lb_test_rx_idx++;
		return;
	}

	pkt_offset = nic_dev->lb_test_rx_idx * lb_len;
	frag_len = (int)skb_headlen(skb);
	memcpy(lb_buf + pkt_offset, skb->data, (size_t)(u32)frag_len);
	pkt_offset += frag_len;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		frag_data = skb_frag_address(&skb_shinfo(skb)->frags[i]);
		frag_len = (int)skb_frag_size(&skb_shinfo(skb)->frags[i]);
		memcpy(lb_buf + pkt_offset, frag_data, (size_t)(u32)frag_len);
		pkt_offset += frag_len;
	}
	nic_dev->lb_test_rx_idx++;
}

static inline void hinic5_lro_set_gso_params(struct sk_buff *skb, u16 num_lro)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	__be16 proto;

	proto = __vlan_get_protocol(skb, eth->h_proto, NULL);

	skb_shinfo(skb)->gso_size = (u16)DIV_ROUND_UP((skb->len - skb_headlen(skb)), num_lro);
	skb_shinfo(skb)->gso_type = (proto == htons(ETH_P_IP)) ? SKB_GSO_TCPV4 : SKB_GSO_TCPV6;
	skb_shinfo(skb)->gso_segs = num_lro;
}

static int recv_one_pkt(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info)
{
	struct sk_buff *skb = NULL;
	struct net_device *netdev = rxq->netdev;
	struct hinic5_nic_dev *nic_dev = netdev_priv(rxq->netdev);

#ifdef HAVE_XDP_SUPPORT
	if (hinic5_xdp_process_packet(rxq, cqe_info, &skb)) {
		/* The XDP program has processed the packet
		 * and does not need to be sent to the protocol stack
		 */
		return HINIC5_XDP_PROCESSED;
	}
#else
	skb = hinic5_fetch_rx_buffer(rxq, cqe_info);
#endif
	if (unlikely(!skb)) {
		RXQ_STATS_INC(rxq, alloc_skb_err);
		return -ENOMEM;
	}

	/* place header in linear portion of buffer */
	if (skb_is_nonlinear(skb))
		hinic5_pull_tail(skb);

	if (cqe_info->ts_flag != 0)
		hinic5_ptp_rx_hwtstamp(nic_dev, skb);

	hinic5_rx_csum(rxq, cqe_info, skb);

#ifdef HAVE_SKBUFF_CSUM_LEVEL
	hinic5_rx_gro(rxq, cqe_info->pkt_fmt, skb);
#endif

#if defined(NETIF_F_HW_VLAN_CTAG_RX)
	if (((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) != 0) && cqe_info->vlan_offload != 0) {
#else
	if ((netdev->features & NETIF_F_HW_VLAN_RX) && cqe_info->vlan_offload) {
#endif
		/* if the packet is a vlan pkt, the vid may be 0 */
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), cqe_info->vlan_tag);
	}

	if (unlikely(test_bit(HINIC5_LP_TEST, &nic_dev->flags) != 0))
		hinic5_copy_lp_data(nic_dev, skb);

	if (cqe_info->lro_num > 1)
		hinic5_lro_set_gso_params(skb, cqe_info->lro_num);

	skb_record_rx_queue(skb, rxq->q_id);
	skb->protocol = eth_type_trans(skb, netdev);

	if (skb_has_frag_list(skb)) {
#ifdef HAVE_NAPI_GRO_FLUSH_OLD
		napi_gro_flush(&rxq->irq_cfg->napi, false);
#else
		napi_gro_flush(&rxq->irq_cfg->napi);
#endif
	}
	napi_gro_receive(&rxq->irq_cfg->napi, skb);

	return 0;
}

#define LRO_PKT_HDR_LEN_IPV4		66
#define LRO_PKT_HDR_LEN_IPV6		86
#define LRO_PKT_HDR_LEN(ip_type)		\
	((ip_type) == HINIC5_RX_IPV6_PKT ? LRO_PKT_HDR_LEN_IPV6 : LRO_PKT_HDR_LEN_IPV4)

void hinic5_rx_get_cqe_info(struct hinic5_rq_cqe *cqe,
			    struct hinic5_cqe_info *info, u8 cqe_mode, bool enable_pfe)
{
	u32 dw0 = hinic5_hw_cpu32(cqe->status);
	u32 dw1 = hinic5_hw_cpu32(cqe->vlan_len);
	u32 dw2 = hinic5_hw_cpu32(cqe->offload_type);

	info->lro_num = RQ_CQE_STATUS_GET(dw0, NUM_LRO);
	info->csum_err = RQ_CQE_STATUS_GET(dw0, CSUM_ERR);

	info->pkt_len = RQ_CQE_SGE_GET(dw1, LEN);
	info->vlan_tag = RQ_CQE_SGE_GET(dw1, VLAN);

	info->pkt_type = RQ_CQE_OFFOLAD_TYPE_GET(dw2, PKT_TYPE);
	info->ip_type = RQ_CQE_OFFOLAD_TYPE_GET(dw2, IP_TYPE);
	info->pkt_fmt = RQ_CQE_OFFOLAD_TYPE_GET(dw2, TUNNEL_PKT_FORMAT);
	info->vlan_offload = RQ_CQE_OFFOLAD_TYPE_GET(dw2, VLAN_EN);
	info->rss_type = RQ_CQE_OFFOLAD_TYPE_GET(dw2, RSS_TYPE);
	info->pkt_mc = RQ_CQE_OFFOLAD_TYPE_GET(dw2, PKT_UMBCAST);
	info->rss_hash_value = hinic5_hw_cpu32(cqe->hash_val);
}

void hinic5_rx_get_compact_cqe_info(struct hinic5_rq_cqe *cqe,
				    struct hinic5_cqe_info *info, u8 cqe_mode, bool enable_pfe)
{
	u32 dw0, dw1, dw2, dw3;

	if (cqe_mode != HINIC5_RQ_CQE_INTEGRATE) {
		dw0 = hinic5_hw_cpu32(cqe->status);
		dw1 = hinic5_hw_cpu32(cqe->vlan_len);
		dw2 = hinic5_hw_cpu32(cqe->offload_type);
		dw3 = hinic5_hw_cpu32(cqe->hash_val);
	} else {
		/*
		 * When rx wqe is compact, cqe is integrated with packet by big endian,
		 * explicit endian conversion is needed.
		 */
		dw0 = be32_to_cpu(cqe->status);
		dw1 = be32_to_cpu(cqe->vlan_len);
		dw2 = be32_to_cpu(cqe->offload_type);
		dw3 = be32_to_cpu(cqe->hash_val);
	}

	info->cqe_type = RQ_COMPACT_CQE_STATUS_GET(dw0, CQE_TYPE);
	info->csum_err = RQ_COMPACT_CQE_STATUS_GET(dw0, CSUM_ERR);
	info->vlan_offload = RQ_COMPACT_CQE_STATUS_GET(dw0, VLAN_EN);
	info->pkt_fmt = RQ_COMPACT_CQE_STATUS_GET(dw0, PKT_FORMAT);
	info->ip_type = RQ_COMPACT_CQE_STATUS_GET(dw0, IP_TYPE);
	info->cqe_len = RQ_COMPACT_CQE_STATUS_GET(dw0, CQE_LEN);
	info->pkt_type = RQ_COMPACT_CQE_STATUS_GET(dw0, PKT_TYPE);
	info->pkt_len = RQ_COMPACT_CQE_STATUS_GET(dw0, PKT_LEN);
	info->ts_flag = RQ_COMPACT_CQE_STATUS_GET(dw0, TS_FLAG);
	info->pkt_mc = RQ_COMPACT_CQE_STATUS_GET(dw0, PKT_MC);
	info->rss_hash_value = dw1;

	switch (info->csum_err) {
	case NIC_RX_COMPACT_CSUM_OTHER_ERROR:
		info->csum_err = HINIC5_RX_CSUM_IPSU_OTHER_ERR;
		break;
	case NIC_RX_COMPACT_HW_BYPASS_ERROR:
		info->csum_err = HINIC5_RX_CSUM_HW_CHECK_NONE;
		break;
	default:
		break;
	}

	if (info->cqe_len == RQ_COMPACT_CQE_16BYTE) {
		info->lro_num = RQ_COMPACT_CQE_OFFLOAD_GET(dw2, NUM_LRO);
		info->vlan_tag = RQ_COMPACT_CQE_OFFLOAD_GET(dw2, VLAN);
		if (enable_pfe) {
			info->pfe_pkt_src = RQ_COMPACT_CQE_OFFLOAD_GET(dw2, PFE_PKT_SRC);
			info->pfe_port_id = RQ_COMPACT_CQE_OFFLOAD_GET(dw2, PFE_PORT_ID);
			info->flow_mark_vld = RQ_COMPACT_CQE_OFFLOAD_GET(dw2, FLOW_MARK_VLD);
			info->src_func_id =
				(u16)((RQ_COMPACT_CQE_OFFLOAD_GET(dw2, SRC_FUNC_ID_HIGH)
				       << RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_SHIFT) |
				      RQ_COMPACT_CQE_OFFLOAD_GET(dw3, SRC_FUNC_ID_LOW));
			info->flow_mark = RQ_COMPACT_CQE_OFFLOAD_GET(dw3, FLOW_MARK);
		}
	} else {
		info->lro_num = 0;
		info->vlan_tag = 0;
	}

	if (cqe_mode == HINIC5_RQ_CQE_INTEGRATE) {
		info->packet_offset = info->cqe_len == RQ_COMPACT_CQE_16BYTE ?
				      HINIC5_COMPACT_CQE_16B : HINIC5_COMPACT_CQE_8B;
	} else {
		info->packet_offset = 0;
	}
}

bool hinic5_rx_integrated_cqe_done(struct hinic5_rxq *rxq, struct hinic5_rq_cqe **rx_cqe)
{
	u16 sw_ci;
	u16 hw_ci;

	sw_ci = (u16)(rxq->cons_idx & rxq->q_mask);
	hw_ci = hinic5_get_rq_hw_ci(rxq->rq);
	if (hw_ci == sw_ci)
		return false;
	/* make sure we read cqe info in dma */
	dma_sync_single_range_for_cpu(rxq->dev, rxq->rx_info[sw_ci].buf_dma_addr,
				      rxq->rx_info[sw_ci].page_offset,
				      rxq->buf_len, DMA_FROM_DEVICE);
#ifdef HAVE_XDP_SUPPORT
	if (rxq->xdp_headroom_flag == 0)
		*rx_cqe = (struct hinic5_rq_cqe *)
			((u8 *)page_address(rxq->rx_info[sw_ci].page) +
			 rxq->rx_info[sw_ci].page_offset);
	else
		*rx_cqe = (struct hinic5_rq_cqe *)
			((u8 *)page_address(rxq->rx_info[sw_ci].page) +
			 rxq->rx_info[sw_ci].page_offset + XDP_PACKET_HEADROOM);
#else
	*rx_cqe = (struct hinic5_rq_cqe *)
		((u8 *)page_address(rxq->rx_info[sw_ci].page) +
		 rxq->rx_info[sw_ci].page_offset);
#endif

	return true;
}

bool hinic5_rx_separate_cqe_done(struct hinic5_rxq *rxq, struct hinic5_rq_cqe **rx_cqe)
{
	u32 sw_ci, status = 0;

	sw_ci = rxq->cons_idx & rxq->q_mask;
	*rx_cqe = rxq->rx_info[sw_ci].cqe;

	status = hinic5_hw_cpu32((*rx_cqe)->status);
	if (HINIC5_GET_RX_DONE(status) == 0)
		return false;

	return true;
}

void hinic5_rx_cqe_sendup_convert(struct hinic5_rq_cqe *rx_cqe,
				  struct hinic5_rq_cqe *rx_cqe_sendup, u8 cqe_mode)
{
	if (cqe_mode == HINIC5_RQ_CQE_INTEGRATE) {
		/*
		 * When rx wqe is compact, cqe is integrated with packet by big endian,
		 * explicit endian conversion is needed.
		 */
		rx_cqe_sendup->status = be32_to_cpu(rx_cqe->status);
		rx_cqe_sendup->vlan_len = be32_to_cpu(rx_cqe->vlan_len);
		rx_cqe_sendup->offload_type = be32_to_cpu(rx_cqe->offload_type);
		rx_cqe_sendup->hash_val = be32_to_cpu(rx_cqe->hash_val);
	} else {
		rx_cqe_sendup->status = hinic5_hw_cpu32(rx_cqe->status);
		rx_cqe_sendup->vlan_len = hinic5_hw_cpu32(rx_cqe->vlan_len);
		rx_cqe_sendup->offload_type = hinic5_hw_cpu32(rx_cqe->offload_type);
		rx_cqe_sendup->hash_val = hinic5_hw_cpu32(rx_cqe->hash_val);
	}
}

static int rx_cqe_check(struct hinic5_nic_dev *nic_dev, struct hinic5_rq_cqe *rx_cqe)
{
	struct hinic5_rq_cqe rx_cqe_sendup = {0};
	int i, ret = 0;

	for (i = 0; i < SERVICE_T_MAX; i++) {
		if (nic_dev->tx_rx_ops.cqe_cb[i] &&
		    test_bit(i, &nic_dev->tx_rx_ops.cqe_cb_state[i])) {
			hinic5_rx_cqe_sendup_convert(rx_cqe, &rx_cqe_sendup, nic_dev->cqe_mode);
			set_bit(i, &nic_dev->tx_rx_ops.cqe_cb_running[i]);
			ret = nic_dev->tx_rx_ops.cqe_cb[i](nic_dev->lld_dev, &rx_cqe_sendup);
			if (ret != 0) {
				clear_bit(i, &nic_dev->tx_rx_ops.cqe_cb_running[i]);
				break;
			}
			clear_bit(i, &nic_dev->tx_rx_ops.cqe_cb_running[i]);
		}
	}
	return ret;
}

static void rx_free_warning_wqe(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info)
{
	u8 sge_num, packet_offset;
	u32 pkt_len;

	packet_offset = cqe_info->packet_offset;
	pkt_len = cqe_info->pkt_len;
	sge_num = HINIC5_GET_SGE_NUM(pkt_len + packet_offset, rxq);

	rxq->cons_idx += sge_num;
	rxq->delta += sge_num;
}

int hinic5_rx_poll(struct hinic5_rxq *rxq, int budget)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	u32 dropped = 0;
	u64 pkt_mc = 0;
	struct hinic5_rq_cqe *rx_cqe = NULL;
	struct hinic5_cqe_info *cqe_info = NULL;
	u64 rx_bytes = 0;
	int pkts = 0;
	u16 num_wqe = 0;
	u16 sw_ci = 0;
	bool enable_pfe = HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD);
	int ret = 0;

	while (likely(pkts < budget)) {
		if (!nic_dev->tx_rx_ops.rx_cqe_done(rxq, &rx_cqe))
			break;
		/* make sure we read rx_done before packet length */
		rmb();

		sw_ci = (u16)(rxq->cons_idx & rxq->q_mask);
		cqe_info = rxq->rx_info[sw_ci].cqe_info;
		nic_dev->tx_rx_ops.rx_get_cqe_info(rx_cqe, cqe_info, nic_dev->cqe_mode, enable_pfe);

		if (nic_dev->support_htn && (rx_cqe_check(nic_dev, rx_cqe) != 0)) {
			rx_free_warning_wqe(rxq, cqe_info);
			dropped++;
			rx_cqe->status = 0;
			continue;
		}

		ret = recv_one_pkt(rxq, cqe_info);
		if (ret < 0)
			break;

		/* In separate CQE mode, the done bit needs to be cleared */
		if (nic_dev->cqe_mode == HINIC5_RQ_CQE_SEPARATE)
			rx_cqe->status = 0;

		#ifdef HAVE_XDP_SUPPORT
		if (ret == HINIC5_XDP_PROCESSED)
			continue;
		#endif

		rx_bytes += cqe_info->pkt_len;
		pkts++;

		if (cqe_info->pkt_mc == MULTICAST)
			pkt_mc++;

		if (cqe_info->lro_num > 1) {
			rx_bytes += ((cqe_info->lro_num - 1) * LRO_PKT_HDR_LEN(cqe_info->ip_type));
			num_wqe += HINIC5_GET_SGE_NUM(cqe_info->pkt_len, rxq);
		}

		if (num_wqe >= nic_dev->lro_replenish_thld)
			break;
	}

	if (rxq->delta >= HINIC5_RX_BUFFER_WRITE)
		hinic5_rx_fill_buffers(rxq);

	u64_stats_update_begin(&rxq->rxq_stats.syncp);
	rxq->rxq_stats.packets += (u64)(u32)pkts;
	rxq->rxq_stats.bytes += rx_bytes;
	rxq->rxq_stats.dropped += (u64)dropped;
	rxq->rxq_stats.pkt_mc += pkt_mc;
	u64_stats_update_end(&rxq->rxq_stats.syncp);
#ifdef HAVE_XDP_SUPPORT
	hinic5_xdp_flush_if_needed(nic_dev);
#endif
	return pkts;
}

#ifdef HAVE_PAGE_POOL_SUPPORT
static struct page_pool *hinic5_create_page_pool(struct hinic5_nic_dev *nic_dev,
						 u32 rq_depth,
						 struct hinic5_rx_info *rx_info_arr)
{
	struct page_pool_params pp_params = {
#ifdef HAVE_PP_FLAG_PAGE_FRAG
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_PAGE_FRAG | PP_FLAG_DMA_SYNC_DEV,
#else
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
#endif
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_PAGE_FRAG | PP_FLAG_DMA_SYNC_DEV,
		.order = nic_dev->page_order,
		.pool_size = rq_depth * nic_dev->rx_buff_len /
			     (PAGE_SIZE << nic_dev->page_order),
		.nid = dev_to_node(nic_dev->lld_dev->dev),
		.dev = nic_dev->lld_dev->dev,
		.dma_dir = DMA_FROM_DEVICE,
		.offset = 0,
		.max_len = PAGE_SIZE << nic_dev->page_order,
	};
	struct page_pool *page_pool = NULL;
	u32 i;

	page_pool = nic_dev->page_pool_enabled ?
		    page_pool_create(&pp_params) : NULL;
	for (i = 0; i < rq_depth; i++)
		rx_info_arr[i].page_pool = page_pool;
	return page_pool;
}
#endif

int hinic5_alloc_rxqs_res(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res)
{
	struct hinic5_dyna_rxq_res *rqres = NULL;
	u16 idx;
	u32 pkts;
	u64 size;
	u64 cqe_mem_size = sizeof(struct hinic5_rq_cqe) * rq_depth;
	u64 cqe_info_mem_size = sizeof(struct hinic5_cqe_info) * rq_depth;

	for (idx = 0; idx < num_rq; idx++) {
		rqres = &rxqs_res[idx];
		size = sizeof(*rqres->rx_info) * rq_depth;
		rqres->rx_info = kzalloc(size, GFP_KERNEL);

		if (!rqres->rx_info)
			goto err_alloc_rx_info;
		if (nic_dev->cqe_mode == HINIC5_RQ_CQE_SEPARATE) {
			rqres->cqe_start_vaddr = dma_zalloc_coherent(nic_dev->lld_dev->dev,
								     cqe_mem_size,
								     &rqres->cqe_start_paddr,
								     GFP_KERNEL);
			if (!rqres->cqe_start_vaddr) {
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Failed to alloc rxq%d cqe\n", idx);
				goto err_alloc_cqe;
			}
		}

		rqres->cqe_info = kzalloc(cqe_info_mem_size, GFP_KERNEL);
		if (!rqres->cqe_info)
			goto err_alloc_cqe_info;

#ifdef HAVE_PAGE_POOL_SUPPORT
		if (nic_dev->page_pool_enabled) {
			rqres->page_pool = hinic5_create_page_pool(nic_dev, rq_depth,
								   rqres->rx_info);
			if (!rqres->page_pool) {
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Failed to create rxq%d page pool\n", idx);
				goto err_create_page_pool;
			}
		}
#endif

		pkts = hinic5_rx_alloc_buffers(nic_dev, rq_depth, rqres->rx_info);
		if (pkts == 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc rxq%d rx buffers\n", idx);
			goto err_alloc_buffers;
		}
		rqres->next_to_alloc = (u16)pkts;
	}

	return 0;

err_alloc_buffers:
#ifdef HAVE_PAGE_POOL_SUPPORT
	page_pool_destroy(rqres->page_pool);
err_create_page_pool:
#endif
	kfree(rqres->cqe_info);
err_alloc_cqe_info:
	if (nic_dev->cqe_mode == HINIC5_RQ_CQE_SEPARATE) {
		dma_free_coherent(nic_dev->lld_dev->dev, cqe_mem_size, rqres->cqe_start_vaddr,
				  rqres->cqe_start_paddr);
	}
err_alloc_cqe:
	kfree(rqres->rx_info);
err_alloc_rx_info:
	hinic5_free_rxqs_res(nic_dev, idx, rq_depth, rxqs_res);
	return -ENOMEM;
}

void hinic5_free_rxqs_res(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res)
{
	struct hinic5_dyna_rxq_res *rqres = NULL;
	struct hinic5_rxq *rxq = NULL;
	u64 cqe_mem_size = sizeof(struct hinic5_rq_cqe) * rq_depth;
	int idx;

	for (idx = 0; idx < num_rq; idx++) {
		rxq = &nic_dev->rxqs[idx];
		rqres = &rxqs_res[idx];
		hinic5_rx_free_buffers(nic_dev, rq_depth, rqres->rx_info);
#ifdef HAVE_PAGE_POOL_SUPPORT
		if (rqres->page_pool)
			page_pool_destroy(rqres->page_pool);
#endif
		kfree(rqres->cqe_info);
		if (nic_dev->cqe_mode == HINIC5_RQ_CQE_SEPARATE) {
			dma_free_coherent(nic_dev->lld_dev->dev, cqe_mem_size,
					  rqres->cqe_start_vaddr, rqres->cqe_start_paddr);
		}
		kfree(rqres->rx_info);
	}
}

static inline void configure_rxq_init_default(struct hinic5_rxq *rxq)
{
	rxq->next_to_update = 0;
	rxq->cons_idx = 0;
	rxq->last_sw_ci = 0;
	rxq->last_hw_ci = 0;
	rxq->rx_check_err_cnt = 0;
	rxq->rxq_print_times = 0;
	rxq->last_packets = 0;
	rxq->restore_buf_num = 0;
}

void hinic5_remove_configure_rxqs(struct hinic5_nic_dev *nic_dev)
{
#ifdef HAVE_XDP_SUPPORT
	int idx = 0;
	struct hinic5_rxq *rxq = NULL;

	for (idx = 0; idx < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; idx++) {
		rxq = &nic_dev->rxqs[idx];
		rxq->xdp_prog = NULL;
		xdp_rxq_info_unreg(&rxq->xdp_rxq);
	}
#endif
}

int hinic5_configure_rxqs(struct hinic5_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic5_dyna_rxq_res *rxqs_res)
{
	struct hinic5_dyna_rxq_res *rqres = NULL;
	struct irq_info *msix_entry = NULL;
	struct hinic5_rxq *rxq = NULL;
	struct hinic5_rq_cqe *cqe_va = NULL;
	dma_addr_t cqe_pa;
	u16 q_id;
	u32 idx, pkts;
	int err = 0;

	nic_dev->rxq_get_err_times = 0;
	for (q_id = 0; q_id < num_rq; q_id++) {
		rxq = &nic_dev->rxqs[q_id];
		rqres = &rxqs_res[q_id];
		msix_entry = &nic_dev->qps_irq_info[q_id];

		configure_rxq_init_default(rxq);
		rxq->irq_id = msix_entry->irq_id;
		rxq->msix_entry_idx = msix_entry->msix_entry_idx;
		rxq->next_to_alloc = rqres->next_to_alloc;
		rxq->q_depth = rq_depth;
		rxq->delta = rxq->q_depth;
		rxq->q_mask = rxq->q_depth - 1;
		rxq->last_sw_pi = rxq->q_depth - 1;
		rxq->rx_info = rqres->rx_info;
#ifdef HAVE_XDP_SUPPORT
		rxq->xdp_headroom_flag = nic_dev->xdp_prog ? 1 : 0;
#endif

		/* fill cqe */
		if (nic_dev->cqe_mode == HINIC5_RQ_CQE_SEPARATE) {
			cqe_va = (struct hinic5_rq_cqe *)rqres->cqe_start_vaddr;
			cqe_pa = rqres->cqe_start_paddr;
			for (idx = 0; idx < rq_depth; idx++) {
				rxq->rx_info[idx].cqe = cqe_va;
				rxq->rx_info[idx].cqe_dma = cqe_pa;
				cqe_va++;
				cqe_pa += sizeof(*rxq->rx_info->cqe);
			}
		}

		for (idx = 0; idx < rq_depth; idx++)
			rxq->rx_info[idx].cqe_info = &rqres->cqe_info[idx];

		rxq->rq = hinic5_get_nic_queue(nic_dev->hwdev, rxq->q_id, HINIC5_RQ);
		if (!rxq->rq) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get rq\n");
			return -EINVAL;
		}

		pkts = hinic5_rx_fill_wqe(rxq);
		if (pkts != rxq->q_depth) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to fill rx wqe\n");
			return -EFAULT;
		}

		pkts = hinic5_rx_fill_buffers(rxq);
		if (pkts == 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to fill Rx buffer\n");
			return -ENOMEM;
		}
#ifdef HAVE_XDP_SUPPORT
		rxq->xdp_prog = nic_dev->xdp_prog;
#ifdef HAVE_XDP_RXQ_INFO_REG_NAPI_ID
		err = xdp_rxq_info_reg(&rxq->xdp_rxq, nic_dev->netdev, q_id, q_id);
#else
		err = xdp_rxq_info_reg(&rxq->xdp_rxq, nic_dev->netdev, q_id);
#endif
#endif
		if (err != 0)
			return err;
	}

	return 0;
}

void hinic5_free_rxqs(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	kfree(nic_dev->rxqs);
	nic_dev->rxqs = NULL;
}

int hinic5_alloc_rxqs(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct device *dev = nic_dev->lld_dev->dev;
	struct hinic5_rxq *rxq = NULL;
	u16 num_rxqs = nic_dev->max_qps;
	u16 q_id;
	u64 rxq_size;

	rxq_size = num_rxqs * sizeof(*nic_dev->rxqs);
	if (rxq_size == 0) {
		nic_err(dev, "Cannot allocate zero size rxqs\n");
		return -EINVAL;
	}

	nic_dev->rxqs = kzalloc(rxq_size, GFP_KERNEL);
	if (!nic_dev->rxqs)
		return -ENOMEM;

	for (q_id = 0; q_id < num_rxqs; q_id++) {
		rxq = &nic_dev->rxqs[q_id];
		rxq->netdev = netdev;
		rxq->dev = dev;
		rxq->q_id = q_id;
		rxq->buf_len = nic_dev->rx_buff_len;
		rxq->rx_buff_shift = (u32)ilog2(nic_dev->rx_buff_len);
		rxq->dma_rx_buff_size = nic_dev->dma_rx_buff_size;
		rxq->q_depth = nic_dev->q_params.rq_depth;
		rxq->q_mask = nic_dev->q_params.rq_depth - 1;

		rxq_stats_init(rxq);
	}

	return 0;
}

int hinic5_rx_configure(struct net_device *netdev, u8 dcb_en)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 rq2iq_map[HINIC5_MAX_NUM_RQ];
	int err;

	/* Set all rq mapping to all iq in default */

	memset(rq2iq_map, 0xFF, sizeof(rq2iq_map));

	if (test_bit(HINIC5_RSS_ENABLE, &nic_dev->flags) != 0) {
		err = hinic5_rss_init(nic_dev, rq2iq_map, sizeof(rq2iq_map), dcb_en);
		if (err != 0) {
			nicif_err(nic_dev, drv, netdev, "Failed to init rss\n");
			return -EFAULT;
		}
	}

	return 0;
}

void hinic5_rx_remove_configure(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if (test_bit(HINIC5_RSS_ENABLE, &nic_dev->flags) != 0)
		hinic5_rss_deinit(nic_dev);
}

int hinic5_rxq_restore(struct hinic5_nic_dev *nic_dev, u16 q_id, u16 hw_ci)
{
	struct hinic5_rxq *rxq = &nic_dev->rxqs[q_id];
	struct hinic5_rq_wqe *rq_wqe = NULL;
	struct hinic5_rx_info *rx_info = NULL;
	dma_addr_t dma_addr;
	u32 free_wqebbs = rxq->delta - rxq->restore_buf_num;
	u32 buff_pi;
	u32 i;
	int err;

	if (rxq->delta < rxq->restore_buf_num)
		return -EINVAL;

	if (rxq->restore_buf_num == 0) /* start restore process */
		rxq->restore_pi = rxq->next_to_update;

	buff_pi = rxq->restore_pi;

	if ((((rxq->cons_idx & rxq->q_mask) + rxq->q_depth -
	       rxq->next_to_update) % rxq->q_depth) != rxq->delta)
		return -EINVAL;

	for (i = 0; i < free_wqebbs; i++) {
		rx_info = &rxq->rx_info[buff_pi];

		if (unlikely(!rx_alloc_mapped_page(nic_dev, rx_info))) {
			RXQ_STATS_INC(rxq, alloc_rx_buf_err);
			rxq->restore_pi = (u16)((rxq->restore_pi + i) & rxq->q_mask);
			return -ENOMEM;
		}

		dma_addr = rx_info->buf_dma_addr + rx_info->page_offset;

		rq_wqe = rx_info->rq_wqe;

		if (rxq->rq->wqe_type == HINIC5_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr =
				hinic5_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr =
				hinic5_hw_be32(lower_32_bits(dma_addr));
		} else {
			rq_wqe->normal_wqe.buf_hi_addr =
				hinic5_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->normal_wqe.buf_lo_addr =
				hinic5_hw_be32(lower_32_bits(dma_addr));
		}
		buff_pi = (u16)((buff_pi + 1) & rxq->q_mask);
		rxq->restore_buf_num++;
	}

	nic_info(nic_dev->lld_dev->dev, "rxq %u restore_buf_num:%u\n", q_id, rxq->restore_buf_num);

	rx_info =  &rxq->rx_info[(hw_ci + rxq->q_depth - 1) & rxq->q_mask];
	if (rx_info->buf_dma_addr != 0) {
		dma_unmap_page(nic_dev->lld_dev->dev, rx_info->buf_dma_addr,
			       nic_dev->dma_rx_buff_size, DMA_FROM_DEVICE);
		rx_info->buf_dma_addr = 0;
	}

	if (rx_info->page) {
		__free_pages(rx_info->page, nic_dev->page_order);
		rx_info->page = NULL;
	}

	rxq->delta = 1;
	rxq->next_to_update = (u16)((hw_ci + rxq->q_depth - 1) & rxq->q_mask);
	rxq->cons_idx = (u16)((rxq->next_to_update + 1) & rxq->q_mask);
	rxq->restore_buf_num = 0;
	rxq->next_to_alloc = rxq->next_to_update;

	for (i = 0; i < rxq->q_depth; i++) {
		if (HINIC5_GET_RX_DONE(hinic5_hw_cpu32(rxq->rx_info[i].cqe->status)) == 0)
			continue;

		RXQ_STATS_INC(rxq, restore_drop_sge);
		rxq->rx_info[i].cqe->status = 0;
	}

	err = hinic5_cache_out_qps_res(nic_dev->hwdev);
	if (err != 0) {
		clear_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags);
		return err;
	}

	hinic5_write_db(rxq->rq, rxq->q_id & (NIC_DCB_COS_MAX - 1),
			RQ_CFLAG_DP, (u16)((u32)rxq->next_to_update << rxq->rq->wqe_type));

	return 0;
}

bool hinic5_rxq_is_normal(struct hinic5_rxq *rxq, struct rxq_check_info rxq_info)
{
	u32 status;

	if (rxq->rxq_stats.packets != rxq->last_packets || rxq_info.hw_pi != rxq_info.hw_ci ||
	    rxq_info.hw_ci != rxq->last_hw_ci || rxq->next_to_update != rxq->last_sw_pi)
		return true;

	/* hw rx no wqe and driver rx no packet recv */
	status = rxq->rx_info[rxq->cons_idx & rxq->q_mask].cqe->status;
	if (HINIC5_GET_RX_DONE(hinic5_hw_cpu32(status)) != 0)
		return true;

	if ((rxq->cons_idx & rxq->q_mask) != rxq->last_sw_ci ||
	    rxq->rxq_stats.packets != rxq->last_packets ||
	    rxq->next_to_update != rxq_info.hw_pi)
		return true;

	return false;
}

#define RXQ_CHECK_ERR_TIMES 2
#define RXQ_PRINT_MAX_TIMES 3
#define RXQ_GET_ERR_MAX_TIMES 3
void hinic5_rxq_check_work_handler(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic5_nic_dev *nic_dev = container_of(delay, struct hinic5_nic_dev, rxq_check_work);
	struct rxq_check_info *rxq_info = NULL;
	struct hinic5_rxq *rxq = NULL;
	u64 size;
	u16 qid;
	int err;

	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0)
		return;

	if (test_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags) != 0)
		queue_delayed_work(nic_dev->workq, &nic_dev->rxq_check_work, HZ);

#ifdef HAVE_PAGE_POOL_SUPPORT
	if (nic_dev->page_pool_enabled)
		return;
#endif

	size = sizeof(*rxq_info) * nic_dev->q_params.num_qps;
	if (size == 0)
		return;

	rxq_info = kzalloc(size, GFP_KERNEL);
	if (!rxq_info)
		return;

	err = hinic5_get_rxq_hw_info(nic_dev->hwdev, rxq_info, nic_dev->q_params.num_qps,
				     nic_dev->rxqs[0].rq->wqe_type);
	if (err != 0) {
		nic_dev->rxq_get_err_times++;
		if (nic_dev->rxq_get_err_times >= RXQ_GET_ERR_MAX_TIMES)
			clear_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags);
		goto free_rxq_info;
	}

	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		rxq = &nic_dev->rxqs[qid];
		if (!hinic5_rxq_is_normal(rxq, rxq_info[qid])) {
			rxq->rx_check_err_cnt++;
			if (rxq->rx_check_err_cnt < RXQ_CHECK_ERR_TIMES)
				continue;

			if (rxq->rxq_print_times <= RXQ_PRINT_MAX_TIMES) {
				nic_warn(nic_dev->lld_dev->dev, "rxq %u wqe abnormal, hw_pi:%u, hw_ci:%u, sw_pi:%u, sw_ci:%u delta:%u\n",
					 qid, rxq_info[qid].hw_pi, rxq_info[qid].hw_ci,
					 rxq->next_to_update,
					 rxq->cons_idx & rxq->q_mask, rxq->delta);
				rxq->rxq_print_times++;
			}

			if (hinic5_rxq_restore(nic_dev, qid, rxq_info[qid].hw_ci) != 0)
				continue;
		}

		rxq->rxq_print_times = 0;
		rxq->rx_check_err_cnt = 0;
		rxq->last_sw_pi = rxq->next_to_update;
		rxq->last_sw_ci = rxq->cons_idx & rxq->q_mask;
		rxq->last_hw_ci = rxq_info[qid].hw_ci;
		rxq->last_packets = rxq->rxq_stats.packets;
	}

	nic_dev->rxq_get_err_times = 0;

free_rxq_info:
	kfree(rxq_info);
}

int hinic5_register_cqe_cb(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type event,
			   hinic5_cqe_cb cqe_cb)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!lld_dev || !cqe_cb || event >= SERVICE_T_MAX ||
	    !hinic5_support_nic(lld_dev->hwdev, NULL))
		return -EINVAL;

	nic_dev = hinic5_get_uld_dev_unsafe(lld_dev, SERVICE_T_NIC);
	if (!nic_dev) {
		nic_err(lld_dev->dev, "There's no net device attached on the pci device");
		return -EINVAL;
	}

	nic_dev->tx_rx_ops.cqe_cb[event] = cqe_cb;

	set_bit(event, &nic_dev->tx_rx_ops.cqe_cb_state[event]);
	return 0;
}
EXPORT_SYMBOL(hinic5_register_cqe_cb);

void hinic5_unregister_cqe_cb(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type event)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!lld_dev || event >= SERVICE_T_MAX || !hinic5_support_nic(lld_dev->hwdev, NULL))
		return;

	nic_dev = hinic5_get_uld_dev_unsafe(lld_dev, SERVICE_T_NIC);
	if (!nic_dev)
		return;

	clear_bit(event, &nic_dev->tx_rx_ops.cqe_cb_state[event]);

	while (test_bit(event,
			&nic_dev->tx_rx_ops.cqe_cb_running[event]))
		usleep_range(HINIC5_RQ_CQE_USLEEP_LOW_BOUND, HINIC5_RQ_CQE_USLEEP_HIGH_BOUND);
	nic_dev->tx_rx_ops.cqe_cb[event] = NULL;
}
EXPORT_SYMBOL(hinic5_unregister_cqe_cb);
