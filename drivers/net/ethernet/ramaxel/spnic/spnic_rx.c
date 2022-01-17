// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

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

#include "sphw_crm.h"
#include "sphw_common.h"
#include "spnic_nic_qp.h"
#include "spnic_nic_io.h"
#include "spnic_nic_dev.h"
#include "spnic_rx.h"
#include "spnic_rss.h"

static u32 rq_pi_rd_en;
module_param(rq_pi_rd_en, uint, 0644);
MODULE_PARM_DESC(rq_pi_rd_en, "Enable rq read pi from host, defaut update pi by doorbell (default=0)");

/* performance: ci addr RTE_CACHE_SIZE(64B) alignment */
#define SPNIC_RX_HDR_SIZE			256
#define SPNIC_RX_BUFFER_WRITE			16

#define SPNIC_RX_TCP_PKT			0x3
#define SPNIC_RX_UDP_PKT			0x4
#define SPNIC_RX_SCTP_PKT			0x7

#define SPNIC_RX_IPV4_PKT			0
#define SPNIC_RX_IPV6_PKT			1
#define SPNIC_RX_INVALID_IP_TYPE		2

#define SPNIC_RX_PKT_FORMAT_NON_TUNNEL		0
#define SPNIC_RX_PKT_FORMAT_VXLAN		1

#define RXQ_STATS_INC(rxq, field)			\
do {							\
	u64_stats_update_begin(&(rxq)->rxq_stats.syncp);	\
	(rxq)->rxq_stats.field++;				\
	u64_stats_update_end(&(rxq)->rxq_stats.syncp);	\
} while (0)

static bool rx_alloc_mapped_page(struct spnic_nic_dev *nic_dev,
				 struct spnic_rx_info *rx_info)
{
	struct pci_dev *pdev = nic_dev->pdev;
	struct page *page = rx_info->page;
	dma_addr_t dma = rx_info->buf_dma_addr;

	if (likely(dma))
		return true;

	/* alloc new page for storage */
	page = alloc_pages_node(NUMA_NO_NODE, GFP_ATOMIC | __GFP_COMP, nic_dev->page_order);
	if (unlikely(!page))
		return false;

	/* map page for use */
	dma = dma_map_page(&pdev->dev, page, 0, nic_dev->dma_rx_buff_size, DMA_FROM_DEVICE);

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

static u32 spnic_rx_fill_wqe(struct spnic_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct spnic_rx_info *rx_info = NULL;
	u32 i;

	for (i = 0; i < rxq->q_depth; i++) {
		rx_info = &rxq->rx_info[i];
		rq_wqe = spnic_rq_wqe_addr(rxq->rq, (u16)i);

		if (rxq->rq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			/* unit of cqe length is 16B */
			sphw_set_sge(&rq_wqe->extend_wqe.cqe_sect.sge, rx_info->cqe_dma,
				     (sizeof(struct spnic_rq_cqe) >> SPNIC_CQE_SIZE_SHIFT));
			/* use fixed len */
			rq_wqe->extend_wqe.buf_desc.sge.len =
					nic_dev->rx_buff_len;
		} else {
			rq_wqe->normal_wqe.cqe_hi_addr = upper_32_bits(rx_info->cqe_dma);
			rq_wqe->normal_wqe.cqe_lo_addr = lower_32_bits(rx_info->cqe_dma);
		}

		rx_info->rq_wqe = rq_wqe;
	}

	return i;
}

static struct sk_buff *stub_rx_alloc_skb(struct spnic_rxq *rxq, struct spnic_rx_info *rx_info)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	struct sk_buff *skb = NULL;
	u16 random_id;
	dma_addr_t addr;
	int err;

	get_random_bytes(&random_id, sizeof(u16));

	rx_info->skb_len = SPNIC_RX_HDR_SIZE + (random_id & 0x3EFF);
	skb = netdev_alloc_skb_ip_align(rxq->netdev, rx_info->skb_len);
	if (!skb) {
		nicif_err(nic_dev, drv, rxq->netdev, "Failed to allocate Rx SKB\n");
		return NULL;
	}

	addr = dma_map_single(&nic_dev->pdev->dev, skb->data, rx_info->skb_len,
			      DMA_FROM_DEVICE);

	err = dma_mapping_error(&nic_dev->pdev->dev, addr);
	if (err) {
		nicif_err(nic_dev, drv, rxq->netdev, "Failed to map Rx DMA, err = %d\n", err);
		goto err_rx_map;
	}

	rx_info->buf_dma_addr = addr;

	return skb;

err_rx_map:
	dev_kfree_skb_any(skb);
	return NULL;
}

static u32 stub_spnic_rx_fill_buffers(struct spnic_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u32 i, free_wqebbs = rxq->delta - 1;
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct spnic_rx_info *rx_info = NULL;
	struct sk_buff *skb = NULL;
	dma_addr_t dma_addr;

	for (i = 0; i < free_wqebbs; i++) {
		rx_info = &rxq->rx_info[rxq->next_to_update];

		skb = stub_rx_alloc_skb(rxq, rx_info);
		if (!skb) {
			nicif_err(nic_dev, drv, rxq->netdev, "Failed to alloc Rx skb\n");
			break;
		}

		rq_wqe = rx_info->rq_wqe;
		rx_info->saved_skb = skb;
		dma_addr = rx_info->buf_dma_addr;

		if (rxq->rq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr = upper_32_bits(dma_addr);
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr = lower_32_bits(dma_addr);
			rq_wqe->extend_wqe.buf_desc.sge.len = rx_info->skb_len;
		} else {
			rq_wqe->normal_wqe.buf_hi_addr = upper_32_bits(dma_addr);
			rq_wqe->normal_wqe.buf_lo_addr = lower_32_bits(dma_addr);
		}
		rxq->next_to_update = (rxq->next_to_update + 1) & rxq->q_mask;
	}

	if (likely(i)) {
		if (!rq_pi_rd_en) {
			spnic_write_db(rxq->rq, rxq->q_id & (SPNIC_DCB_COS_MAX - 1), RQ_CFLAG_DP,
				       (u16)((u32)rxq->next_to_update << rxq->rq->wqe_type));
		} else {
			/* Write all the wqes before pi update */
			wmb();

			spnic_update_rq_hw_pi(rxq->rq, rxq->next_to_update);
		}
		rxq->delta -= i;
		rxq->next_to_alloc = rxq->next_to_update;
	} else {
		nicif_err(nic_dev, drv, netdev, "Failed to allocate rx buffers, rxq id: %u\n",
			  rxq->q_id);
	}

	return i;
}

static u32 spnic_rx_fill_buffers(struct spnic_rxq *rxq)
{
	struct net_device *netdev = rxq->netdev;
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct spnic_rx_info *rx_info = NULL;
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

		if (rxq->rq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr = upper_32_bits(dma_addr);
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr = lower_32_bits(dma_addr);
		} else {
			rq_wqe->normal_wqe.buf_hi_addr = upper_32_bits(dma_addr);
			rq_wqe->normal_wqe.buf_lo_addr = lower_32_bits(dma_addr);
		}
		rxq->next_to_update = (rxq->next_to_update + 1) & rxq->q_mask;
	}

	if (likely(i)) {
		if (!rq_pi_rd_en) {
			spnic_write_db(rxq->rq, rxq->q_id & (SPNIC_DCB_COS_MAX - 1), RQ_CFLAG_DP,
				       (u16)((u32)rxq->next_to_update << rxq->rq->wqe_type));
		} else {
			/* Write all the wqes before pi update */
			wmb();

			spnic_update_rq_hw_pi(rxq->rq, rxq->next_to_update);
		}
		rxq->delta -= i;
		rxq->next_to_alloc = rxq->next_to_update;
	} else if (free_wqebbs == rxq->q_depth - 1) {
		RXQ_STATS_INC(rxq, rx_buf_empty);
	}

	return i;
}

static u32 spnic_rx_alloc_buffers(struct spnic_nic_dev *nic_dev, u32 rq_depth,
				  struct spnic_rx_info *rx_info_arr)
{
	u32 free_wqebbs = rq_depth - 1;
	u32 idx;

	for (idx = 0; idx < free_wqebbs; idx++) {
		if (!rx_alloc_mapped_page(nic_dev, &rx_info_arr[idx]))
			break;
	}

	return idx;
}

void spnic_rx_free_buffers(struct spnic_nic_dev *nic_dev, u32 q_depth,
			   struct spnic_rx_info *rx_info_arr)
{
	struct spnic_rx_info *rx_info = NULL;
	u32 i;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < q_depth; i++) {
		rx_info = &rx_info_arr[i];

		if (rx_info->buf_dma_addr) {
			dma_unmap_page(&nic_dev->pdev->dev, rx_info->buf_dma_addr,
				       nic_dev->dma_rx_buff_size, DMA_FROM_DEVICE);
			rx_info->buf_dma_addr = 0;
		}

		if (rx_info->page) {
			__free_pages(rx_info->page, nic_dev->page_order);
			rx_info->page = NULL;
		}
	}
}

void stub_spnic_rx_free_buffers(struct spnic_rxq *rxq)
{
	struct spnic_rx_info *rx_info = NULL;
	u32 i;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rxq->q_depth; i++) {
		rx_info = &rxq->rx_info[i];

		if (rx_info->buf_dma_addr) {
			dma_unmap_page(rxq->dev, rx_info->buf_dma_addr, rx_info->skb_len,
				       DMA_FROM_DEVICE);
			rx_info->buf_dma_addr = 0;
		}

		if (rx_info->saved_skb) {
			dev_kfree_skb_any(rx_info->saved_skb);
			rx_info->saved_skb = NULL;
		}
	}
}

static void spnic_reuse_rx_page(struct spnic_rxq *rxq, struct spnic_rx_info *old_rx_info)
{
	struct spnic_rx_info *new_rx_info;
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
					 new_rx_info->page_offset, rxq->buf_len,
					 DMA_FROM_DEVICE);
}

static bool spnic_add_rx_frag(struct spnic_rxq *rxq, struct spnic_rx_info *rx_info,
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

	dma_sync_single_range_for_cpu(rxq->dev, rx_info->buf_dma_addr,
				      rx_info->page_offset,
				      rxq->buf_len, DMA_FROM_DEVICE);

	if (size <= SPNIC_RX_HDR_SIZE && !skb_is_nonlinear(skb)) {
		memcpy(__skb_put(skb, size), va, ALIGN(size, sizeof(long)));

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

static void packaging_skb(struct spnic_rxq *rxq, struct sk_buff *head_skb, u8 sge_num, u32 pkt_len)
{
	struct spnic_rx_info *rx_info = NULL;
	struct sk_buff *skb = NULL;
	u8 frag_num = 0;
	u32 size;
	u32 sw_ci;

	sw_ci = rxq->cons_idx & rxq->q_mask;
	skb = head_skb;
	while (sge_num) {
		rx_info = &rxq->rx_info[sw_ci];
		sw_ci = (sw_ci + 1) & rxq->q_mask;
		if (unlikely(pkt_len > rxq->buf_len)) {
			size = rxq->buf_len;
			pkt_len -= rxq->buf_len;
		} else {
			size = pkt_len;
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

		if (likely(spnic_add_rx_frag(rxq, rx_info, skb, size))) {
			spnic_reuse_rx_page(rxq, rx_info);
		} else {
			/* we are not reusing the buffer so unmap it */
			dma_unmap_page(rxq->dev, rx_info->buf_dma_addr,
				       rxq->dma_rx_buff_size, DMA_FROM_DEVICE);
		}
		/* clear contents of buffer_info */
		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		sge_num--;
		frag_num++;
	}
}

#define SPNIC_GET_SGE_NUM(pkt_len, rxq)	\
		((u8)(((pkt_len) >> (rxq)->rx_buff_shift) + \
		      (((pkt_len) & ((rxq)->buf_len - 1)) ? 1 : 0)))

static struct sk_buff *spnic_fetch_rx_buffer(struct spnic_rxq *rxq, u32 pkt_len)
{
	struct sk_buff *head_skb = NULL;
	struct sk_buff *cur_skb = NULL;
	struct sk_buff *skb = NULL;
	struct net_device *netdev = rxq->netdev;
	u8 sge_num, skb_num;
	u16 wqebb_cnt = 0;

	head_skb = netdev_alloc_skb_ip_align(netdev, SPNIC_RX_HDR_SIZE);
	if (unlikely(!head_skb))
		return NULL;

	sge_num = SPNIC_GET_SGE_NUM(pkt_len, rxq);
	if (likely(sge_num <= MAX_SKB_FRAGS))
		skb_num = 1;
	else
		skb_num = (sge_num / MAX_SKB_FRAGS) + ((sge_num % MAX_SKB_FRAGS) ? 1 : 0);

	while (unlikely(skb_num > 1)) {
		cur_skb = netdev_alloc_skb_ip_align(netdev, SPNIC_RX_HDR_SIZE);
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

void spnic_rxq_get_stats(struct spnic_rxq *rxq, struct spnic_rxq_stats *stats)
{
	struct spnic_rxq_stats *rxq_stats = &rxq->rxq_stats;
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

void spnic_rxq_clean_stats(struct spnic_rxq_stats *rxq_stats)
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
	u64_stats_update_end(&rxq_stats->syncp);
}

static void rxq_stats_init(struct spnic_rxq *rxq)
{
	struct spnic_rxq_stats *rxq_stats = &rxq->rxq_stats;

	u64_stats_init(&rxq_stats->syncp);
	spnic_rxq_clean_stats(rxq_stats);
}

static void spnic_pull_tail(struct sk_buff *skb)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va = NULL;
	unsigned int pull_len;

	/* it is valid to use page_address instead of kmap since we are
	 * working with pages allocated out of the lomem pool per
	 * alloc_page(GFP_ATOMIC)
	 */
	va = skb_frag_address(frag);

	/* we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */
	pull_len = eth_get_headlen(skb->dev, va, SPNIC_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, (int)pull_len);
	skb_frag_off_add(frag, (int)pull_len);

	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

static void spnic_rx_csum(struct spnic_rxq *rxq, u32 offload_type, u32 status, struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;
	u32 pkt_type = SPNIC_GET_RX_PKT_TYPE(offload_type);
	u32 ip_type = SPNIC_GET_RX_IP_TYPE(offload_type);
	u32 pkt_fmt = SPNIC_GET_RX_TUNNEL_PKT_FORMAT(offload_type);

	u32 csum_err;

	csum_err = SPNIC_GET_RX_CSUM_ERR(status);

	if (unlikely(csum_err == SPNIC_RX_CSUM_IPSU_OTHER_ERR))
		rxq->rxq_stats.other_errors++;

	if (!(netdev->features & NETIF_F_RXCSUM))
		return;

	if (unlikely(csum_err)) {
		/* pkt type is recognized by HW, and csum is wrong */
		if (!(csum_err & (SPNIC_RX_CSUM_HW_CHECK_NONE | SPNIC_RX_CSUM_IPSU_OTHER_ERR)))
			rxq->rxq_stats.csum_errors++;
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	if (ip_type == SPNIC_RX_INVALID_IP_TYPE ||
	    !(pkt_fmt == SPNIC_RX_PKT_FORMAT_NON_TUNNEL ||
	      pkt_fmt == SPNIC_RX_PKT_FORMAT_VXLAN)) {
		skb->ip_summed = CHECKSUM_NONE;
		return;
	}

	switch (pkt_type) {
	case SPNIC_RX_TCP_PKT:
	case SPNIC_RX_UDP_PKT:
	case SPNIC_RX_SCTP_PKT:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		skb->ip_summed = CHECKSUM_NONE;
		break;
	}
}

static void spnic_rx_gro(struct spnic_rxq *rxq, u32 offload_type, struct sk_buff *skb)
{
	struct net_device *netdev = rxq->netdev;
	bool l2_tunnel = false;

	if (!(netdev->features & NETIF_F_GRO))
		return;

	l2_tunnel =
		SPNIC_GET_RX_TUNNEL_PKT_FORMAT(offload_type) == SPNIC_RX_PKT_FORMAT_VXLAN ? 1 : 0;

	if (l2_tunnel && skb->ip_summed == CHECKSUM_UNNECESSARY)
		/* If we checked the outer header let the stack know */
		skb->csum_level = 1;
}

static void spnic_copy_lp_data(struct spnic_nic_dev *nic_dev, struct sk_buff *skb)
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
	memcpy(lb_buf + pkt_offset, skb->data, frag_len);

	pkt_offset += frag_len;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		frag_data = skb_frag_address(&skb_shinfo(skb)->frags[i]);
		frag_len = (int)skb_frag_size(&skb_shinfo(skb)->frags[i]);
		memcpy(lb_buf + pkt_offset, frag_data, frag_len);

		pkt_offset += frag_len;
	}
	nic_dev->lb_test_rx_idx++;
}

static inline void spnic_lro_set_gso_params(struct sk_buff *skb, u16 num_lro)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	__be16 proto;

	proto = __vlan_get_protocol(skb, eth->h_proto, NULL);

	skb_shinfo(skb)->gso_size = (u16)DIV_ROUND_UP((skb->len - skb_headlen(skb)), num_lro);
	skb_shinfo(skb)->gso_type = (proto == htons(ETH_P_IP)) ? SKB_GSO_TCPV4 : SKB_GSO_TCPV6;
}

enum spnic_xdp_pkt {
	SPNIC_XDP_PKT_PASS,
	SPNIC_XDP_PKT_DROP,
};

static inline void update_drop_rx_info(struct spnic_rxq *rxq, u16 weqbb_num)
{
	struct spnic_rx_info *rx_info = NULL;

	while (weqbb_num) {
		rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
		if (likely(page_to_nid(rx_info->page) == numa_node_id()))
			spnic_reuse_rx_page(rxq, rx_info);

		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		rxq->cons_idx++;
		rxq->delta++;

		weqbb_num--;
	}
}

int spnic_run_xdp(struct spnic_rxq *rxq, u32 pkt_len)
{
	struct bpf_prog *xdp_prog = NULL;
	struct spnic_rx_info *rx_info = NULL;
	struct xdp_buff xdp;
	int result = SPNIC_XDP_PKT_PASS;
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
		result = SPNIC_XDP_PKT_DROP;
		goto xdp_out;
	}

	rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
	va = (u8 *)page_address(rx_info->page) + rx_info->page_offset;
	prefetch(va);
	dma_sync_single_range_for_cpu(rxq->dev, rx_info->buf_dma_addr, rx_info->page_offset,
				      rxq->buf_len, DMA_FROM_DEVICE);
	xdp.data = va;
	xdp.data_hard_start = xdp.data;
	xdp.data_end = xdp.data + pkt_len;
	xdp.frame_sz = rxq->buf_len;
	xdp_set_data_meta_invalid(&xdp);
	prefetchw(xdp.data_hard_start);
	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_DROP:
		result = SPNIC_XDP_PKT_DROP;
		break;
	default:
		result = SPNIC_XDP_PKT_DROP;
		bpf_warn_invalid_xdp_action(act);
	}

xdp_out:
	if (result == SPNIC_XDP_PKT_DROP) {
		RXQ_STATS_INC(rxq, xdp_dropped);
		update_drop_rx_info(rxq, weqbb_num);
	}

unlock_rcu:
	rcu_read_unlock();

	return result;
}

int recv_one_pkt(struct spnic_rxq *rxq, struct spnic_rq_cqe *rx_cqe,
		 u32 pkt_len, u32 vlan_len, u32 status)
{
	struct sk_buff *skb;
	struct net_device *netdev = rxq->netdev;
	u32 offload_type;
	u16 num_lro;
	struct spnic_nic_dev *nic_dev = netdev_priv(rxq->netdev);

	u32 xdp_status;

	xdp_status = spnic_run_xdp(rxq, pkt_len);
	if (xdp_status == SPNIC_XDP_PKT_DROP)
		return 0;

	skb = spnic_fetch_rx_buffer(rxq, pkt_len);
	if (unlikely(!skb)) {
		RXQ_STATS_INC(rxq, alloc_skb_err);
		return -ENOMEM;
	}

	/* place header in linear portion of buffer */
	if (skb_is_nonlinear(skb))
		spnic_pull_tail(skb);

	offload_type = rx_cqe->offload_type;
	spnic_rx_csum(rxq, offload_type, status, skb);

	spnic_rx_gro(rxq, offload_type, skb);

	if ((netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
	    SPNIC_GET_RX_VLAN_OFFLOAD_EN(offload_type)) {
		u16 vid = SPNIC_GET_RX_VLAN_TAG(vlan_len);

		/* if the packet is a vlan pkt, the vid may be 0 */
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}

	if (unlikely(test_bit(SPNIC_LP_TEST, &nic_dev->flags)))
		spnic_copy_lp_data(nic_dev, skb);

	num_lro = SPNIC_GET_RX_NUM_LRO(status);
	if (num_lro)
		spnic_lro_set_gso_params(skb, num_lro);

	skb_record_rx_queue(skb, rxq->q_id);
	skb->protocol = eth_type_trans(skb, netdev);

	if (skb_has_frag_list(skb)) {
		napi_gro_flush(&rxq->irq_cfg->napi, false);
		netif_receive_skb(skb);
	} else {
		napi_gro_receive(&rxq->irq_cfg->napi, skb);
	}

	return 0;
}

void rx_pass_super_cqe(struct spnic_rxq *rxq, u32 index, u32 pkt_num, struct spnic_rq_cqe *cqe)
{
	u8 sge_num = 0;
	u32 pkt_len;

	while (index < pkt_num) {
		pkt_len = spnic_get_pkt_len_for_super_cqe(cqe, index == (pkt_num - 1));
		sge_num += (u8)(pkt_len >> rxq->rx_buff_shift) +
				((pkt_len & (rxq->buf_len - 1)) ? 1 : 0);
		index++;
	}

	rxq->cons_idx += sge_num;
	rxq->delta += sge_num;
}

static inline int recv_supper_cqe(struct spnic_rxq *rxq, struct spnic_rq_cqe *rx_cqe, u32 pkt_info,
				  u32 vlan_len, u32 status, int *pkts, u64 *rx_bytes, u32 *dropped)
{
	u32 pkt_len;
	int i, pkt_num = 0;

	pkt_num = SPNIC_GET_RQ_CQE_PKT_NUM(pkt_info);
	i = 0;
	while (i < pkt_num) {
		pkt_len = ((i == (pkt_num - 1)) ?
		    RQ_CQE_PKT_LEN_GET(pkt_info, LAST_LEN) :
		    RQ_CQE_PKT_LEN_GET(pkt_info, FIRST_LEN));
		if (unlikely(recv_one_pkt(rxq, rx_cqe, pkt_len, vlan_len, status))) {
			if (i) {
				rx_pass_super_cqe(rxq, i, pkt_num, rx_cqe);
				*dropped += (pkt_num - i);
			}
			break;
		}

		*rx_bytes += pkt_len;
		(*pkts)++;
		i++;
	}

	if (!i)
		return -EFAULT;

	return 0;
}

#define LRO_PKT_HDR_LEN_IPV4		66
#define LRO_PKT_HDR_LEN_IPV6		86
#define LRO_PKT_HDR_LEN(cqe)		\
	(SPNIC_GET_RX_IP_TYPE((cqe)->offload_type) == \
	 SPNIC_RX_IPV6_PKT ? LRO_PKT_HDR_LEN_IPV6 : LRO_PKT_HDR_LEN_IPV4)

static void stub_rx_recv_jumbo_pkt(struct spnic_rxq *rxq, struct sk_buff *head_skb,
				   unsigned int left_pkt_len)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	struct sk_buff *skb = NULL;
	struct sk_buff *curr_skb = head_skb;
	struct spnic_rx_info *rx_info = NULL;
	unsigned int curr_len;

	while (left_pkt_len > 0) {
		rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
		skb = rx_info->saved_skb;

		dma_unmap_single(&nic_dev->pdev->dev, rx_info->buf_dma_addr,
				 rx_info->skb_len, DMA_FROM_DEVICE);

		rx_info->buf_dma_addr = 0;
		rx_info->saved_skb = NULL;

		prefetch(skb->data);

		curr_len = (left_pkt_len > rx_info->skb_len) ? rx_info->skb_len : left_pkt_len;

		left_pkt_len -= curr_len;

		__skb_put(skb, curr_len);

		if (curr_skb == head_skb)
			skb_shinfo(head_skb)->frag_list = skb;
		else
			curr_skb->next = skb;

		head_skb->len += skb->len;
		head_skb->data_len += skb->len;
		head_skb->truesize += skb->truesize;

		curr_skb = skb;
		rxq->cons_idx++;
		rxq->delta++;
	}
}

int stub_spnic_rx_poll(struct spnic_rxq *rxq, int budget)
{
	u32 sw_ci, status, pkt_len, vlan_len = 0;
	struct spnic_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	struct spnic_rq_cqe *rx_cqe = NULL;
	u64 rx_bytes = 0;
	int pkts = 0;
	struct sk_buff *skb = NULL;
	struct spnic_rx_info *rx_info = NULL;
	u32 offload_type;

	while (likely(pkts < budget)) {
		sw_ci = rxq->cons_idx & rxq->q_mask;
		rx_info = &rxq->rx_info[sw_ci];
		rx_cqe = rxq->rx_info[sw_ci].cqe;
		status = be32_to_cpu(rx_cqe->status);

		if (!SPNIC_GET_RX_DONE(status))
			break;

		/* make sure we read rx_done before packet length */
		rmb();

		vlan_len = be32_to_cpu(rx_cqe->vlan_len);
		pkt_len = SPNIC_GET_RX_PKT_LEN(vlan_len);
		skb = rx_info->saved_skb;

		dma_unmap_single(&nic_dev->pdev->dev, rx_info->buf_dma_addr,
				 rx_info->skb_len, DMA_FROM_DEVICE);

		rx_info->buf_dma_addr = 0;
		rx_info->saved_skb = NULL;

		rxq->cons_idx++;
		rxq->delta++;

		if (pkt_len <= rx_info->skb_len) {
			__skb_put(skb, pkt_len);
		} else {
			__skb_put(skb, rx_info->skb_len);
			stub_rx_recv_jumbo_pkt(rxq, skb, pkt_len - rx_info->skb_len);
		}

		offload_type = be32_to_cpu(rx_cqe->offload_type);
		spnic_rx_csum(rxq, offload_type, status, skb);

		spnic_rx_gro(rxq, offload_type, skb);

		skb_record_rx_queue(skb, rxq->q_id);
		skb->protocol = eth_type_trans(skb, rxq->netdev);

		if (skb_has_frag_list(skb)) {
			napi_gro_flush(&rxq->irq_cfg->napi, false);
			netif_receive_skb(skb);
		} else {
			napi_gro_receive(&rxq->irq_cfg->napi, skb);
		}
		rx_bytes += pkt_len;
		pkts++;
		rx_cqe->status = 0;
	}

	if (rxq->delta >= SPNIC_RX_BUFFER_WRITE)
		stub_spnic_rx_fill_buffers(rxq);

	u64_stats_update_begin(&rxq->rxq_stats.syncp);
	rxq->rxq_stats.packets += pkts;
	rxq->rxq_stats.bytes += rx_bytes;
	u64_stats_update_end(&rxq->rxq_stats.syncp);
	return pkts;
}

int spnic_rx_poll(struct spnic_rxq *rxq, int budget)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	u32 sw_ci, status, pkt_len, vlan_len, pkt_info, dropped = 0;
	struct spnic_rq_cqe *rx_cqe = NULL;
	u64 rx_bytes = 0;
	u16 num_lro;
	int pkts = 0, nr_pkts = 0;
	u16 num_wqe = 0;

	while (likely(pkts < budget)) {
		sw_ci = rxq->cons_idx & rxq->q_mask;
		rx_cqe = rxq->rx_info[sw_ci].cqe;
		status = rx_cqe->status;

		if (!SPNIC_GET_RX_DONE(status))
			break;

		/* make sure we read rx_done before packet length */
		rmb();

		vlan_len = rx_cqe->vlan_len;
		pkt_info = rx_cqe->pkt_info;
		pkt_len = SPNIC_GET_RX_PKT_LEN(vlan_len);

		if (unlikely(SPNIC_GET_SUPER_CQE_EN(pkt_info))) {
			if (unlikely(recv_supper_cqe(rxq, rx_cqe, pkt_info, vlan_len, status, &pkts,
						     &rx_bytes, &dropped)))
				break;
			nr_pkts += (int)SPNIC_GET_RQ_CQE_PKT_NUM(pkt_info);
		} else {
			if (recv_one_pkt(rxq, rx_cqe, pkt_len,
					 vlan_len, status))
				break;
			rx_bytes += pkt_len;
			pkts++;
			nr_pkts++;

			num_lro = SPNIC_GET_RX_NUM_LRO(status);
			if (num_lro) {
				rx_bytes += ((num_lro - 1) * LRO_PKT_HDR_LEN(rx_cqe));
				num_wqe += SPNIC_GET_SGE_NUM(pkt_len, rxq);
			}
		}

		rx_cqe->status = 0;

		if (num_wqe >= nic_dev->lro_replenish_thld)
			break;
	}

	if (rxq->delta >= SPNIC_RX_BUFFER_WRITE)
		spnic_rx_fill_buffers(rxq);

	u64_stats_update_begin(&rxq->rxq_stats.syncp);
	rxq->rxq_stats.packets += nr_pkts;
	rxq->rxq_stats.bytes += rx_bytes;
	rxq->rxq_stats.dropped += dropped;
	u64_stats_update_end(&rxq->rxq_stats.syncp);
	return pkts;
}

int spnic_alloc_rxqs_res(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res)
{
	struct spnic_dyna_rxq_res *rqres = NULL;
	u64 cqe_mem_size = sizeof(struct spnic_rq_cqe) * rq_depth;
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
			dma_alloc_coherent(&nic_dev->pdev->dev, cqe_mem_size,
					   &rqres->cqe_start_paddr, GFP_KERNEL);
		if (!rqres->cqe_start_vaddr) {
			kfree(rqres->rx_info);
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Failed to alloc rxq%d cqe\n", idx);
			goto err_out;
		}

		pkts = spnic_rx_alloc_buffers(nic_dev, rq_depth, rqres->rx_info);
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

		spnic_rx_free_buffers(nic_dev, rq_depth, rqres->rx_info);
		dma_free_coherent(&nic_dev->pdev->dev, cqe_mem_size,
				  rqres->cqe_start_vaddr, rqres->cqe_start_paddr);
		kfree(rqres->rx_info);
	}

	return -ENOMEM;
}

void spnic_free_rxqs_res(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res)
{
	struct spnic_dyna_rxq_res *rqres = NULL;
	u64 cqe_mem_size = sizeof(struct spnic_rq_cqe) * rq_depth;
	int idx;

	for (idx = 0; idx < num_rq; idx++) {
		rqres = &rxqs_res[idx];

		spnic_rx_free_buffers(nic_dev, rq_depth, rqres->rx_info);
		dma_free_coherent(&nic_dev->pdev->dev, cqe_mem_size, rqres->cqe_start_vaddr,
				  rqres->cqe_start_paddr);
		kfree(rqres->rx_info);
	}
}

int spnic_configure_rxqs(struct spnic_nic_dev *nic_dev, u16 num_rq,
			 u32 rq_depth, struct spnic_dyna_rxq_res *rxqs_res)
{
	struct spnic_dyna_rxq_res *rqres = NULL;
	struct irq_info *msix_entry = NULL;
	struct spnic_rxq *rxq = NULL;
	struct spnic_rq_cqe *cqe_va = NULL;
	dma_addr_t cqe_pa;
	u16 q_id;
	u32 idx;
	u32 pkts;

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

		rxq->rx_info = rqres->rx_info;

		/* fill cqe */
		cqe_va = (struct spnic_rq_cqe *)rqres->cqe_start_vaddr;
		cqe_pa = rqres->cqe_start_paddr;
		for (idx = 0; idx < rq_depth; idx++) {
			rxq->rx_info[idx].cqe = cqe_va;
			rxq->rx_info[idx].cqe_dma = cqe_pa;
			cqe_va++;
			cqe_pa += sizeof(*rxq->rx_info->cqe);
		}

		rxq->rq = spnic_get_nic_queue(nic_dev->hwdev, rxq->q_id, SPNIC_RQ);
		if (!rxq->rq) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get rq\n");
			return -EINVAL;
		}

		pkts = spnic_rx_fill_wqe(rxq);
		if (pkts != rxq->q_depth) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to fill rx wqe\n");
			return -EFAULT;
		}

		pkts = spnic_rx_fill_buffers(rxq);
		if (!pkts) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to fill Rx buffer\n");
			return -ENOMEM;
		}
	}

	return 0;
}

void spnic_free_rxqs(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	kfree(nic_dev->rxqs);
}

int spnic_alloc_rxqs(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct pci_dev *pdev = nic_dev->pdev;
	struct spnic_rxq *rxq = NULL;
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
		rxq->rx_buff_shift = ilog2(nic_dev->rx_buff_len);
		rxq->dma_rx_buff_size = nic_dev->dma_rx_buff_size;
		rxq->q_depth = nic_dev->q_params.rq_depth;
		rxq->q_mask = nic_dev->q_params.rq_depth - 1;

		rxq_stats_init(rxq);
	}

	return 0;
}

int spnic_rx_configure(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err;

	if (test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		err = spnic_rss_init(nic_dev);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to init rss\n");
			return -EFAULT;
		}
	}

	return 0;
}

void spnic_rx_remove_configure(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags))
		spnic_rss_deinit(nic_dev);
}
