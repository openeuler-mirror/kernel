// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

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
#include <linux/pci.h>
#include <linux/u64_stats_sync.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/compiler.h>

#include "ossl_knl.h"
#include "hinic3_crm.h"
#include "hinic3_common.h"
#include "hinic3_nic_qp.h"
#include "hinic3_nic_io.h"
#include "hinic3_srv_nic.h"
#include "hinic3_nic_dev.h"
#include "hinic3_rss.h"
#include "hinic3_rx.h"

static u32 rq_pi_rd_en;
module_param(rq_pi_rd_en, uint, 0644);
MODULE_PARM_DESC(rq_pi_rd_en, "Enable rq read pi from host, defaut update pi by doorbell (default=0)");

/* performance: ci addr RTE_CACHE_SIZE(64B) alignment */
#define HINIC3_RX_HDR_SIZE			256
#define HINIC3_RX_BUFFER_WRITE			16

#define HINIC3_RX_TCP_PKT			0x3
#define HINIC3_RX_UDP_PKT			0x4
#define HINIC3_RX_SCTP_PKT			0x7

#define HINIC3_RX_IPV4_PKT			0
#define HINIC3_RX_IPV6_PKT			1
#define HINIC3_RX_INVALID_IP_TYPE		2

#define HINIC3_RX_PKT_FORMAT_NON_TUNNEL		0
#define HINIC3_RX_PKT_FORMAT_VXLAN		1

#define RXQ_STATS_INC(rxq, field)			\
do {							\
	u64_stats_update_begin(&(rxq)->rxq_stats.syncp);	\
	(rxq)->rxq_stats.field++;				\
	u64_stats_update_end(&(rxq)->rxq_stats.syncp);	\
} while (0)

static bool rx_alloc_mapped_page(struct hinic3_nic_dev *nic_dev,
				 struct hinic3_rx_info *rx_info)
{
	struct pci_dev *pdev = nic_dev->pdev;
	struct page *page = rx_info->page;
	dma_addr_t dma = rx_info->buf_dma_addr;

	if (likely(dma))
		return true;

	/* alloc new page for storage */
	page = alloc_pages_node(NUMA_NO_NODE, GFP_ATOMIC | __GFP_COLD |
				__GFP_COMP, nic_dev->page_order);
	if (unlikely(!page))
		return false;

	/* map page for use */
	dma = dma_map_page(&pdev->dev, page, 0, nic_dev->dma_rx_buff_size,
			   DMA_FROM_DEVICE);
	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (unlikely(dma_mapping_error(&pdev->dev, dma))) {
		__free_pages(page, nic_dev->page_order);
		return false;
	}

	rx_info->page = page;
	rx_info->buf_dma_addr = dma;
	rx_info->page_offset = 0;

	return true;
}

static u32 hinic3_rx_fill_wqe(struct hinic3_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	int rq_wqe_len = rxq->rq->wq.wqebb_size;
	struct hinic3_rq_wqe *rq_wqe = NULL;
	struct hinic3_rx_info *rx_info = NULL;
	u32 i;

	for (i = 0; i < rxq->q_depth; i++) {
		rx_info = &rxq->rx_info[i];
		rq_wqe = hinic3_rq_wqe_addr(rxq->rq, (u16)i);

		if (rxq->rq->wqe_type == HINIC3_EXTEND_RQ_WQE) {
			/* unit of cqe length is 16B */
			hinic3_set_sge(&rq_wqe->extend_wqe.cqe_sect.sge,
				       rx_info->cqe_dma,
				       (sizeof(struct hinic3_rq_cqe) >>
					HINIC3_CQE_SIZE_SHIFT));
			/* use fixed len */
			rq_wqe->extend_wqe.buf_desc.sge.len =
					nic_dev->rx_buff_len;
		} else {
			rq_wqe->normal_wqe.cqe_hi_addr =
				upper_32_bits(rx_info->cqe_dma);
			rq_wqe->normal_wqe.cqe_lo_addr =
				lower_32_bits(rx_info->cqe_dma);
		}

		hinic3_hw_be32_len(rq_wqe, rq_wqe_len);
		rx_info->rq_wqe = rq_wqe;
	}

	return i;
}

static u32 hinic3_rx_fill_buffers(struct hinic3_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic3_rq_wqe *rq_wqe = NULL;
	struct hinic3_rx_info *rx_info = NULL;
	dma_addr_t dma_addr;
	u32 i, free_wqebbs = rxq->delta - 1;

	for (i = 0; i < free_wqebbs; i++) {
		rx_info = &rxq->rx_info[rxq->next_to_update];

		if (unlikely(!rx_alloc_mapped_page(nic_dev, rx_info))) {
			RXQ_STATS_INC(rxq, alloc_rx_buf_err);
			break;
		}

		dma_addr = rx_info->buf_dma_addr + rx_info->page_offset;

		rq_wqe = rx_info->rq_wqe;

		if (rxq->rq->wqe_type == HINIC3_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr =
				hinic3_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr =
				hinic3_hw_be32(lower_32_bits(dma_addr));
		} else {
			rq_wqe->normal_wqe.buf_hi_addr =
				hinic3_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->normal_wqe.buf_lo_addr =
				hinic3_hw_be32(lower_32_bits(dma_addr));
		}
		rxq->next_to_update = (u16)((rxq->next_to_update + 1) & rxq->q_mask);
	}

	if (likely(i)) {
		if (!rq_pi_rd_en) {
			hinic3_write_db(rxq->rq,
					rxq->q_id & (NIC_DCB_COS_MAX - 1),
					RQ_CFLAG_DP,
					(u16)((u32)rxq->next_to_update <<
					rxq->rq->wqe_type));
		} else {
			/* Write all the wqes before pi update */
			wmb();

			hinic3_update_rq_hw_pi(rxq->rq, rxq->next_to_update);
		}
		rxq->delta -= i;
		rxq->next_to_alloc = rxq->next_to_update;
	} else if (free_wqebbs == rxq->q_depth - 1) {
		RXQ_STATS_INC(rxq, rx_buf_empty);
	}

	return i;
}

static u32 hinic3_rx_alloc_buffers(struct hinic3_nic_dev *nic_dev, u32 rq_depth,
				   struct hinic3_rx_info *rx_info_arr)
{
	u32 free_wqebbs = rq_depth - 1;
	u32 idx;

	for (idx = 0; idx < free_wqebbs; idx++) {
		if (!rx_alloc_mapped_page(nic_dev, &rx_info_arr[idx]))
			break;
	}

	return idx;
}

static void hinic3_rx_free_buffers(struct hinic3_nic_dev *nic_dev, u32 q_depth,
				   struct hinic3_rx_info *rx_info_arr)
{
	struct hinic3_rx_info *rx_info = NULL;
	u32 i;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < q_depth; i++) {
		rx_info = &rx_info_arr[i];

		if (rx_info->buf_dma_addr) {
			dma_unmap_page(&nic_dev->pdev->dev,
				       rx_info->buf_dma_addr,
				       nic_dev->dma_rx_buff_size,
				       DMA_FROM_DEVICE);
			rx_info->buf_dma_addr = 0;
		}

		if (rx_info->page) {
			__free_pages(rx_info->page, nic_dev->page_order);
			rx_info->page = NULL;
		}
	}
}

static void hinic3_reuse_rx_page(struct hinic3_rxq *rxq,
				 struct hinic3_rx_info *old_rx_info)
{
	struct hinic3_rx_info *new_rx_info;
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

static bool hinic3_add_rx_frag(struct hinic3_rxq *rxq,
			       struct hinic3_rx_info *rx_info,
			       struct sk_buff *skb, u32 size)
{
	struct page *page;
	u8 *va;

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

	if (size <= HINIC3_RX_HDR_SIZE && !skb_is_nonlinear(skb)) {
		memcpy(__skb_put(skb, size), va,
		       ALIGN(size, sizeof(long))); /*lint !e666*/

		/* page is not reserved, we can reuse buffer as-is */
		if (likely(page_to_nid(page) == numa_node_id()))
			return true;

		/* this page cannot be reused so discard it */
		put_page(page);
		return false;
	}

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			(int)rx_info->page_offset, (int)size, rxq->buf_len);

	/* avoid re-using remote pages */
	if (unlikely(page_to_nid(page) != numa_node_id()))
		return false;

	/* if we are only owner of page we can reuse it */
	if (unlikely(page_count(page) != 1))
		return false;

	/* flip page offset to other buffer */
	rx_info->page_offset ^= rxq->buf_len;
	get_page(page);

	return true;
}

static void packaging_skb(struct hinic3_rxq *rxq, struct sk_buff *head_skb,
			  u8 sge_num, u32 pkt_len)
{
	struct hinic3_rx_info *rx_info = NULL;
	struct sk_buff *skb = NULL;
	u8 frag_num = 0;
	u32 size;
	u32 sw_ci;
	u32 temp_pkt_len = pkt_len;
	u8 temp_sge_num = sge_num;

	sw_ci = rxq->cons_idx & rxq->q_mask;
	skb = head_skb;
	while (temp_sge_num) {
		rx_info = &rxq->rx_info[sw_ci];
		sw_ci = (sw_ci + 1) & rxq->q_mask;
		if (unlikely(temp_pkt_len > rxq->buf_len)) {
			size = rxq->buf_len;
			temp_pkt_len -= rxq->buf_len;
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

		if (likely(hinic3_add_rx_frag(rxq, rx_info, skb, size))) {
			hinic3_reuse_rx_page(rxq, rx_info);
		} else {
			/* we are not reusing the buffer so unmap it */
			dma_unmap_page(rxq->dev, rx_info->buf_dma_addr,
				       rxq->dma_rx_buff_size, DMA_FROM_DEVICE);
		}
		/* clear contents of buffer_info */
		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		temp_sge_num--;
		frag_num++;
	}
}

#define HINIC3_GET_SGE_NUM(pkt_len, rxq)	\
		((u8)(((pkt_len) >> (rxq)->rx_buff_shift) + \
		      (((pkt_len) & ((rxq)->buf_len - 1)) ? 1 : 0)))

static struct sk_buff *hinic3_fetch_rx_buffer(struct hinic3_rxq *rxq,
					      u32 pkt_len)
{
	struct sk_buff *head_skb = NULL;
	struct sk_buff *cur_skb = NULL;
	struct sk_buff *skb = NULL;
	struct net_device *netdev = rxq->netdev;
	u8 sge_num, skb_num;
	u16 wqebb_cnt = 0;

	head_skb = netdev_alloc_skb_ip_align(netdev, HINIC3_RX_HDR_SIZE);
	if (unlikely(!head_skb))
		return NULL;

	sge_num = HINIC3_GET_SGE_NUM(pkt_len, rxq);
	if (likely(sge_num <= MAX_SKB_FRAGS))
		skb_num = 1;
	else
		skb_num = (sge_num / MAX_SKB_FRAGS) +
			((sge_num % MAX_SKB_FRAGS) ? 1 : 0);

	while (unlikely(skb_num > 1)) {
		cur_skb = netdev_alloc_skb_ip_align(netdev, HINIC3_RX_HDR_SIZE);
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

	packaging_skb(rxq, head_skb, sge_num, pkt_len);

	rxq->cons_idx += wqebb_cnt;
	rxq->delta += wqebb_cnt;

	return head_skb;

alloc_skb_fail:
	dev_kfree_skb_any(head_skb);
	return NULL;
}

void hinic3_rxq_get_stats(struct hinic3_rxq *rxq,
			  struct hinic3_rxq_stats *stats)
{
	struct hinic3_rxq_stats *rxq_stats = &rxq->rxq_stats;
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
		stats->xdp_dropped = rxq_stats->xdp_dropped;
		stats->rx_buf_empty = rxq_stats->rx_buf_empty;
	} while (u64_stats_fetch_retry(&rxq_stats->syncp, start));
	u64_stats_update_end(&stats->syncp);
}

void hinic3_rxq_clean_stats(struct hinic3_rxq_stats *rxq_stats)
{
	u64_stats_update_begin(&rxq_stats->syncp);
	rxq_stats->bytes = 0;
	rxq_stats->packets = 0;
	rxq_stats->errors = 0;
	rxq_stats->csum_errors = 0;
	rxq_stats->other_errors = 0;
	rxq_stats->dropped = 0;
	rxq_stats->xdp_dropped = 0;
	rxq_stats->rx_buf_empty = 0;

	rxq_stats->alloc_skb_err = 0;
	rxq_stats->alloc_rx_buf_err = 0;
	rxq_stats->xdp_large_pkt = 0;
	rxq_stats->restore_drop_sge = 0;
	rxq_stats->rsvd2 = 0;
	u64_stats_update_end(&rxq_stats->syncp);
}

static void rxq_stats_init(struct hinic3_rxq *rxq)
{
	struct hinic3_rxq_stats *rxq_stats = &rxq->rxq_stats;

	u64_stats_init(&rxq_stats->syncp);
	hinic3_rxq_clean_stats(rxq_stats);
}

#ifndef HAVE_ETH_GET_HEADLEN_FUNC
static unsigned int hinic3_eth_get_headlen(unsigned char *data, unsigned int max_len)
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
	/*lint -save -e778*/
	if (protocol == htons(ETH_P_8021_AD) ||
	    protocol == htons(ETH_P_8021_Q)) { /*lint -restore*/
		if (unlikely(max_len < ETH_HLEN + VLAN_HLEN))
			return max_len;

		/* L3 protocol */
		protocol = hdr.vlan->h_vlan_encapsulated_proto;
		hdr.data += sizeof(struct vlan_ethhdr);
	} else {
		hdr.data += ETH_HLEN;
	}

	/* L3 header */
	/*lint -save -e778*/
	switch (protocol) {
	case htons(ETH_P_IP): /*lint -restore*/
		if ((int)(hdr.data - data) >
		    (int)(max_len - sizeof(struct iphdr)))
			return max_len;

		/* L3 header length = (1st byte & 0x0F) << 2 */
		hlen = (hdr.data[0] & 0x0F) << 2;

		if (hlen < sizeof(struct iphdr))
			return (unsigned int)(hdr.data - data);

		if (!(hdr.ipv4->frag_off & htons(IP_FRAG_OFFSET)))
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
			 HINIC3_HEADER_DATA_UNIT) > sizeof(struct tcphdr))
			hdr.data += ((hdr.data[TCP_HEAD_OFFSET] & 0xF0) >>
						 HINIC3_HEADER_DATA_UNIT);
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

static void hinic3_pull_tail(struct sk_buff *skb)
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
	pull_len = eth_get_headlen(skb->dev, va, HINIC3_RX_HDR_SIZE);
#else
	pull_len = eth_get_headlen(va, HINIC3_RX_HDR_SIZE);
#endif

#else
	pull_len = hinic3_eth_get_headlen(va, HINIC3_RX_HDR_SIZE);
#endif

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, (int)pull_len);
	skb_frag_off_add(frag, (int)pull_len);

	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

static void hinic3_rx_csum(struct hinic3_rxq *rxq, u32 offload_type,
			   u32 status, struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;
	u32 pkt_type = HINIC3_GET_RX_PKT_TYPE(offload_type);
	u32 ip_type = HINIC3_GET_RX_IP_TYPE(offload_type);
	u32 pkt_fmt = HINIC3_GET_RX_TUNNEL_PKT_FORMAT(offload_type);

	u32 csum_err;

	csum_err = HINIC3_GET_RX_CSUM_ERR(status);
	if (unlikely(csum_err == HINIC3_RX_CSUM_IPSU_OTHER_ERR))
		rxq->rxq_stats.other_errors++;

	if (!(netdev->features & NETIF_F_RXCSUM))
		return;

	if (unlikely(csum_err)) {
		/* pkt type is recognized by HW, and csum is wrong */
		if (!(csum_err & (HINIC3_RX_CSUM_HW_CHECK_NONE |
				  HINIC3_RX_CSUM_IPSU_OTHER_ERR)))
			rxq->rxq_stats.csum_errors++;
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	if (ip_type == HINIC3_RX_INVALID_IP_TYPE ||
	    !(pkt_fmt == HINIC3_RX_PKT_FORMAT_NON_TUNNEL ||
	      pkt_fmt == HINIC3_RX_PKT_FORMAT_VXLAN)) {
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	switch (pkt_type) {
	case HINIC3_RX_TCP_PKT:
	case HINIC3_RX_UDP_PKT:
	case HINIC3_RX_SCTP_PKT:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		skb->ip_summed = CHECKSUM_NONE;
		break;
	}
}

#ifdef HAVE_SKBUFF_CSUM_LEVEL
static void hinic3_rx_gro(struct hinic3_rxq *rxq, u32 offload_type,
			  struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;
	bool l2_tunnel = false;

	if (!(netdev->features & NETIF_F_GRO))
		return;

	l2_tunnel =
		HINIC3_GET_RX_TUNNEL_PKT_FORMAT(offload_type) ==
		HINIC3_RX_PKT_FORMAT_VXLAN ? 1 : 0;
	if (l2_tunnel && skb->ip_summed == CHECKSUM_UNNECESSARY)
		/* If we checked the outer header let the stack know */
		skb->csum_level = 1;
}
#endif /* HAVE_SKBUFF_CSUM_LEVEL */

static void hinic3_copy_lp_data(struct hinic3_nic_dev *nic_dev,
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

	if (skb->len != nic_dev->lb_pkt_len) {
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

static inline void hinic3_lro_set_gso_params(struct sk_buff *skb, u16 num_lro)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	__be16 proto;

	proto = __vlan_get_protocol(skb, eth->h_proto, NULL);

	skb_shinfo(skb)->gso_size = (u16)DIV_ROUND_UP((skb->len - skb_headlen(skb)), num_lro);
	skb_shinfo(skb)->gso_type = (proto == htons(ETH_P_IP)) ? SKB_GSO_TCPV4 : SKB_GSO_TCPV6;
	skb_shinfo(skb)->gso_segs = num_lro;
}

#ifdef HAVE_XDP_SUPPORT
enum hinic3_xdp_pkt {
	HINIC3_XDP_PKT_PASS,
	HINIC3_XDP_PKT_DROP,
};

static void update_drop_rx_info(struct hinic3_rxq *rxq, u16 weqbb_num)
{
	struct hinic3_rx_info *rx_info = NULL;

	while (weqbb_num) {
		rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
		if (likely(page_to_nid(rx_info->page) == numa_node_id()))
			hinic3_reuse_rx_page(rxq, rx_info);

		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		rxq->cons_idx++;
		rxq->delta++;

		weqbb_num--;
	}
}

int hinic3_run_xdp(struct hinic3_rxq *rxq, u32 pkt_len)
{
	struct bpf_prog *xdp_prog = NULL;
	struct hinic3_rx_info *rx_info = NULL;
	struct xdp_buff xdp;
	int result = HINIC3_XDP_PKT_PASS;
	u16 weqbb_num = 1; /* xdp can only use one rx_buff */
	u8 *va = NULL;
	u32 act;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	if (!xdp_prog)
		goto unlock_rcu;

	if (unlikely(pkt_len > rxq->buf_len)) {
		RXQ_STATS_INC(rxq, xdp_large_pkt);
		weqbb_num = (u16)(pkt_len >> rxq->rx_buff_shift) +
				((pkt_len & (rxq->buf_len - 1)) ? 1 : 0);
		result = HINIC3_XDP_PKT_DROP;
		goto xdp_out;
	}

	rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
	va = (u8 *)page_address(rx_info->page) + rx_info->page_offset;
	prefetch(va);
	dma_sync_single_range_for_cpu(rxq->dev, rx_info->buf_dma_addr,
				      rx_info->page_offset,
				      rxq->buf_len, DMA_FROM_DEVICE);
	xdp.data = va;
	xdp.data_hard_start = xdp.data;
	xdp.data_end = xdp.data + pkt_len;
#ifdef HAVE_XDP_FRAME_SZ
	xdp.frame_sz = rxq->buf_len;
#endif
#ifdef HAVE_XDP_DATA_META
	xdp_set_data_meta_invalid(&xdp);
#endif
	prefetchw(xdp.data_hard_start);
	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_DROP:
		result = HINIC3_XDP_PKT_DROP;
		break;
	default:
		result = HINIC3_XDP_PKT_DROP;
		bpf_warn_invalid_xdp_action(act);
	}

xdp_out:
	if (result == HINIC3_XDP_PKT_DROP) {
		RXQ_STATS_INC(rxq, xdp_dropped);
		update_drop_rx_info(rxq, weqbb_num);
	}

unlock_rcu:
	rcu_read_unlock();

	return result;
}
#endif

static int recv_one_pkt(struct hinic3_rxq *rxq, struct hinic3_rq_cqe *rx_cqe,
			u32 pkt_len, u32 vlan_len, u32 status)
{
	struct sk_buff *skb;
	struct net_device *netdev = rxq->netdev;
	u32 offload_type;
	u16 num_lro;
	struct hinic3_nic_dev *nic_dev = netdev_priv(rxq->netdev);

#ifdef HAVE_XDP_SUPPORT
	u32 xdp_status;

	xdp_status = hinic3_run_xdp(rxq, pkt_len);
	if (xdp_status == HINIC3_XDP_PKT_DROP)
		return 0;
#endif

	skb = hinic3_fetch_rx_buffer(rxq, pkt_len);
	if (unlikely(!skb)) {
		RXQ_STATS_INC(rxq, alloc_skb_err);
		return -ENOMEM;
	}

	/* place header in linear portion of buffer */
	if (skb_is_nonlinear(skb))
		hinic3_pull_tail(skb);

	offload_type = hinic3_hw_cpu32(rx_cqe->offload_type);
	hinic3_rx_csum(rxq, offload_type, status, skb);

#ifdef HAVE_SKBUFF_CSUM_LEVEL
	hinic3_rx_gro(rxq, offload_type, skb);
#endif

#if defined(NETIF_F_HW_VLAN_CTAG_RX)
	if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    HINIC3_GET_RX_VLAN_OFFLOAD_EN(offload_type)) {
#else
	if ((netdev->features & NETIF_F_HW_VLAN_RX) &&
	    HINIC3_GET_RX_VLAN_OFFLOAD_EN(offload_type)) {
#endif
		u16 vid = HINIC3_GET_RX_VLAN_TAG(vlan_len);

		/* if the packet is a vlan pkt, the vid may be 0 */
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}

	if (unlikely(test_bit(HINIC3_LP_TEST, &nic_dev->flags)))
		hinic3_copy_lp_data(nic_dev, skb);

	num_lro = HINIC3_GET_RX_NUM_LRO(status);
	if (num_lro)
		hinic3_lro_set_gso_params(skb, num_lro);

	skb_record_rx_queue(skb, rxq->q_id);
	skb->protocol = eth_type_trans(skb, netdev);

	if (skb_has_frag_list(skb)) {
#ifdef HAVE_NAPI_GRO_FLUSH_OLD
		napi_gro_flush(&rxq->irq_cfg->napi, false);
#else
		napi_gro_flush(&rxq->irq_cfg->napi);
#endif
		netif_receive_skb(skb);
	} else {
		napi_gro_receive(&rxq->irq_cfg->napi, skb);
	}

	return 0;
}

#define LRO_PKT_HDR_LEN_IPV4		66
#define LRO_PKT_HDR_LEN_IPV6		86
#define LRO_PKT_HDR_LEN(cqe)		\
	(HINIC3_GET_RX_IP_TYPE(hinic3_hw_cpu32((cqe)->offload_type)) == \
	 HINIC3_RX_IPV6_PKT ? LRO_PKT_HDR_LEN_IPV6 : LRO_PKT_HDR_LEN_IPV4)

int hinic3_rx_poll(struct hinic3_rxq *rxq, int budget)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	u32 sw_ci, status, pkt_len, vlan_len, dropped = 0;
	struct hinic3_rq_cqe *rx_cqe = NULL;
	u64 rx_bytes = 0;
	u16 num_lro;
	int pkts = 0, nr_pkts = 0;
	u16 num_wqe = 0;

	while (likely(pkts < budget)) {
		sw_ci = rxq->cons_idx & rxq->q_mask;
		rx_cqe = rxq->rx_info[sw_ci].cqe;
		status = hinic3_hw_cpu32(rx_cqe->status);
		if (!HINIC3_GET_RX_DONE(status))
			break;

		/* make sure we read rx_done before packet length */
		rmb();

		vlan_len = hinic3_hw_cpu32(rx_cqe->vlan_len);
		pkt_len = HINIC3_GET_RX_PKT_LEN(vlan_len);
		if (recv_one_pkt(rxq, rx_cqe, pkt_len, vlan_len, status))
			break;

		rx_bytes += pkt_len;
		pkts++;
		nr_pkts++;

		num_lro = HINIC3_GET_RX_NUM_LRO(status);
		if (num_lro) {
			rx_bytes += ((num_lro - 1) * LRO_PKT_HDR_LEN(rx_cqe));

			num_wqe += HINIC3_GET_SGE_NUM(pkt_len, rxq);
		}

		rx_cqe->status = 0;

		if (num_wqe >= nic_dev->lro_replenish_thld)
			break;
	}

	if (rxq->delta >= HINIC3_RX_BUFFER_WRITE)
		hinic3_rx_fill_buffers(rxq);

	u64_stats_update_begin(&rxq->rxq_stats.syncp);
	rxq->rxq_stats.packets += (u64)(u32)nr_pkts;
	rxq->rxq_stats.bytes += rx_bytes;
	rxq->rxq_stats.dropped += (u64)dropped;
	u64_stats_update_end(&rxq->rxq_stats.syncp);
	return pkts;
}

int hinic3_alloc_rxqs_res(struct hinic3_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic3_dyna_rxq_res *rxqs_res)
{
	struct hinic3_dyna_rxq_res *rqres = NULL;
	u64 cqe_mem_size = sizeof(struct hinic3_rq_cqe) * rq_depth;
	int idx, i;
	u32 pkts;
	u64 size;

	for (idx = 0; idx < num_rq; idx++) {
		rqres = &rxqs_res[idx];
		size = sizeof(*rqres->rx_info) * rq_depth;
		rqres->rx_info = kzalloc(size, GFP_KERNEL);
		if (!rqres->rx_info) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc rxq%d rx info\n", idx);
			goto err_out;
		}

		rqres->cqe_start_vaddr =
			dma_zalloc_coherent(&nic_dev->pdev->dev, cqe_mem_size,
					    &rqres->cqe_start_paddr,
					    GFP_KERNEL);
		if (!rqres->cqe_start_vaddr) {
			kfree(rqres->rx_info);
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc rxq%d cqe\n", idx);
			goto err_out;
		}

		pkts = hinic3_rx_alloc_buffers(nic_dev, rq_depth,
					       rqres->rx_info);
		if (!pkts) {
			dma_free_coherent(&nic_dev->pdev->dev, cqe_mem_size,
					  rqres->cqe_start_vaddr,
					  rqres->cqe_start_paddr);
			kfree(rqres->rx_info);
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc rxq%d rx buffers\n", idx);
			goto err_out;
		}
		rqres->next_to_alloc = (u16)pkts;
	}
	return 0;

err_out:
	for (i = 0; i < idx; i++) {
		rqres = &rxqs_res[i];

		hinic3_rx_free_buffers(nic_dev, rq_depth, rqres->rx_info);
		dma_free_coherent(&nic_dev->pdev->dev, cqe_mem_size,
				  rqres->cqe_start_vaddr,
				  rqres->cqe_start_paddr);
		kfree(rqres->rx_info);
	}

	return -ENOMEM;
}

void hinic3_free_rxqs_res(struct hinic3_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic3_dyna_rxq_res *rxqs_res)
{
	struct hinic3_dyna_rxq_res *rqres = NULL;
	u64 cqe_mem_size = sizeof(struct hinic3_rq_cqe) * rq_depth;
	int idx;

	for (idx = 0; idx < num_rq; idx++) {
		rqres = &rxqs_res[idx];

		hinic3_rx_free_buffers(nic_dev, rq_depth, rqres->rx_info);
		dma_free_coherent(&nic_dev->pdev->dev, cqe_mem_size,
				  rqres->cqe_start_vaddr,
				  rqres->cqe_start_paddr);
		kfree(rqres->rx_info);
	}
}

int hinic3_configure_rxqs(struct hinic3_nic_dev *nic_dev, u16 num_rq,
			  u32 rq_depth, struct hinic3_dyna_rxq_res *rxqs_res)
{
	struct hinic3_dyna_rxq_res *rqres = NULL;
	struct irq_info *msix_entry = NULL;
	struct hinic3_rxq *rxq = NULL;
	struct hinic3_rq_cqe *cqe_va = NULL;
	dma_addr_t cqe_pa;
	u16 q_id;
	u32 idx;
	u32 pkts;

	nic_dev->rxq_get_err_times = 0;
	for (q_id = 0; q_id < num_rq; q_id++) {
		rxq = &nic_dev->rxqs[q_id];
		rqres = &rxqs_res[q_id];
		msix_entry = &nic_dev->qps_irq_info[q_id];

		rxq->irq_id = msix_entry->irq_id;
		rxq->msix_entry_idx = msix_entry->msix_entry_idx;
		rxq->next_to_update = 0;
		rxq->next_to_alloc = rqres->next_to_alloc;
		rxq->q_depth = rq_depth;
		rxq->delta = rxq->q_depth;
		rxq->q_mask = rxq->q_depth - 1;
		rxq->cons_idx = 0;

		rxq->last_sw_pi =  rxq->q_depth - 1;
		rxq->last_sw_ci = 0;
		rxq->last_hw_ci = 0;
		rxq->rx_check_err_cnt = 0;
		rxq->rxq_print_times = 0;
		rxq->last_packets = 0;
		rxq->restore_buf_num = 0;

		rxq->rx_info = rqres->rx_info;

		/* fill cqe */
		cqe_va = (struct hinic3_rq_cqe *)rqres->cqe_start_vaddr;
		cqe_pa = rqres->cqe_start_paddr;
		for (idx = 0; idx < rq_depth; idx++) {
			rxq->rx_info[idx].cqe = cqe_va;
			rxq->rx_info[idx].cqe_dma = cqe_pa;
			cqe_va++;
			cqe_pa += sizeof(*rxq->rx_info->cqe);
		}

		rxq->rq = hinic3_get_nic_queue(nic_dev->hwdev, rxq->q_id,
					       HINIC3_RQ);
		if (!rxq->rq) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get rq\n");
			return -EINVAL;
		}

		pkts = hinic3_rx_fill_wqe(rxq);
		if (pkts != rxq->q_depth) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to fill rx wqe\n");
			return -EFAULT;
		}

		pkts = hinic3_rx_fill_buffers(rxq);
		if (!pkts) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to fill Rx buffer\n");
			return -ENOMEM;
		}
	}

	return 0;
}

void hinic3_free_rxqs(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);

	kfree(nic_dev->rxqs);
}

int hinic3_alloc_rxqs(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	struct pci_dev *pdev = nic_dev->pdev;
	struct hinic3_rxq *rxq = NULL;
	u16 num_rxqs = nic_dev->max_qps;
	u16 q_id;
	u64 rxq_size;

	rxq_size = num_rxqs * sizeof(*nic_dev->rxqs);
	if (!rxq_size) {
		nic_err(&pdev->dev, "Cannot allocate zero size rxqs\n");
		return -EINVAL;
	}

	nic_dev->rxqs = kzalloc(rxq_size, GFP_KERNEL);
	if (!nic_dev->rxqs) {
		nic_err(&pdev->dev, "Failed to allocate rxqs\n");
		return -ENOMEM;
	}

	for (q_id = 0; q_id < num_rxqs; q_id++) {
		rxq = &nic_dev->rxqs[q_id];
		rxq->netdev = netdev;
		rxq->dev = &pdev->dev;
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

int hinic3_rx_configure(struct net_device *netdev, u8 dcb_en)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);
	u8 rq2iq_map[HINIC3_MAX_NUM_RQ];
	int err;

	/* Set all rq mapping to all iq in default */

	memset(rq2iq_map, 0xFF, sizeof(rq2iq_map));

	if (test_bit(HINIC3_RSS_ENABLE, &nic_dev->flags)) {
		err = hinic3_rss_init(nic_dev, rq2iq_map, sizeof(rq2iq_map), dcb_en);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to init rss\n");
			return -EFAULT;
		}
	}

	return 0;
}

void hinic3_rx_remove_configure(struct net_device *netdev)
{
	struct hinic3_nic_dev *nic_dev = netdev_priv(netdev);

	if (test_bit(HINIC3_RSS_ENABLE, &nic_dev->flags))
		hinic3_rss_deinit(nic_dev);
}

int rxq_restore(struct hinic3_nic_dev *nic_dev, u16 q_id, u16 hw_ci)
{
	struct hinic3_rxq *rxq = &nic_dev->rxqs[q_id];
	struct hinic3_rq_wqe *rq_wqe = NULL;
	struct hinic3_rx_info *rx_info = NULL;
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

		if (rxq->rq->wqe_type == HINIC3_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr =
				hinic3_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr =
				hinic3_hw_be32(lower_32_bits(dma_addr));
		} else {
			rq_wqe->normal_wqe.buf_hi_addr =
				hinic3_hw_be32(upper_32_bits(dma_addr));
			rq_wqe->normal_wqe.buf_lo_addr =
				hinic3_hw_be32(lower_32_bits(dma_addr));
		}
		buff_pi = (u16)((buff_pi + 1) & rxq->q_mask);
		rxq->restore_buf_num++;
	}

	nic_info(&nic_dev->pdev->dev, "rxq %u restore_buf_num:%u\n", q_id, rxq->restore_buf_num);

	rx_info =  &rxq->rx_info[(hw_ci + rxq->q_depth - 1) & rxq->q_mask];
	if (rx_info->buf_dma_addr) {
		dma_unmap_page(&nic_dev->pdev->dev, rx_info->buf_dma_addr,
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
		if (!HINIC3_GET_RX_DONE(hinic3_hw_cpu32(rxq->rx_info[i].cqe->status)))
			continue;

		RXQ_STATS_INC(rxq, restore_drop_sge);
		rxq->rx_info[i].cqe->status = 0;
	}

	err = hinic3_cache_out_qps_res(nic_dev->hwdev);
	if (err) {
		clear_bit(HINIC3_RXQ_RECOVERY, &nic_dev->flags);
		return err;
	}

	if (!rq_pi_rd_en) {
		hinic3_write_db(rxq->rq, rxq->q_id & (NIC_DCB_COS_MAX - 1),
				RQ_CFLAG_DP, (u16)((u32)rxq->next_to_update << rxq->rq->wqe_type));
	} else {
		/* Write all the wqes before pi update */
		wmb();

		hinic3_update_rq_hw_pi(rxq->rq, rxq->next_to_update);
	}

	return 0;
}

bool rxq_is_normal(struct hinic3_rxq *rxq, struct rxq_check_info rxq_info)
{
	u32 status;

	if (rxq->rxq_stats.packets != rxq->last_packets || rxq_info.hw_pi != rxq_info.hw_ci ||
	    rxq_info.hw_ci != rxq->last_hw_ci || rxq->next_to_update != rxq->last_sw_pi)
		return true;

	/* hw rx no wqe and driver rx no packet recv */
	status = rxq->rx_info[rxq->cons_idx & rxq->q_mask].cqe->status;
	if (HINIC3_GET_RX_DONE(hinic3_hw_cpu32(status)))
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
void hinic3_rxq_check_work_handler(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct hinic3_nic_dev *nic_dev = container_of(delay, struct hinic3_nic_dev,
						      rxq_check_work);
	struct rxq_check_info *rxq_info = NULL;
	struct hinic3_rxq *rxq = NULL;
	u64 size;
	u16 qid;
	int err;

	if (!test_bit(HINIC3_INTF_UP, &nic_dev->flags))
		return;

	if (test_bit(HINIC3_RXQ_RECOVERY, &nic_dev->flags))
		queue_delayed_work(nic_dev->workq, &nic_dev->rxq_check_work, HZ);

	size = sizeof(*rxq_info) * nic_dev->q_params.num_qps;
	if (!size)
		return;

	rxq_info = kzalloc(size, GFP_KERNEL);
	if (!rxq_info)
		return;

	err = hinic3_get_rxq_hw_info(nic_dev->hwdev, rxq_info, nic_dev->q_params.num_qps,
				     nic_dev->rxqs[0].rq->wqe_type);
	if (err) {
		nic_dev->rxq_get_err_times++;
		if (nic_dev->rxq_get_err_times >= RXQ_GET_ERR_MAX_TIMES)
			clear_bit(HINIC3_RXQ_RECOVERY, &nic_dev->flags);
		goto free_rxq_info;
	}

	for (qid = 0; qid < nic_dev->q_params.num_qps; qid++) {
		rxq = &nic_dev->rxqs[qid];
		if (!rxq_is_normal(rxq, rxq_info[qid])) {
			rxq->rx_check_err_cnt++;
			if (rxq->rx_check_err_cnt < RXQ_CHECK_ERR_TIMES)
				continue;

			if (rxq->rxq_print_times <= RXQ_PRINT_MAX_TIMES) {
				nic_warn(&nic_dev->pdev->dev, "rxq %u wqe abnormal, hw_pi:%u, hw_ci:%u, sw_pi:%u, sw_ci:%u delta:%u\n",
					 qid, rxq_info[qid].hw_pi, rxq_info[qid].hw_ci,
					 rxq->next_to_update,
					 rxq->cons_idx & rxq->q_mask, rxq->delta);
				rxq->rxq_print_times++;
			}

			err = rxq_restore(nic_dev, qid, rxq_info[qid].hw_ci);
			if (err)
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
