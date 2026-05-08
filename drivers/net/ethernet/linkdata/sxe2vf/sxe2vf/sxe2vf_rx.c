// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_rx.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/if_ether.h>

#include "sxe2_compat.h"
#include "sxe2vf.h"
#include "sxe2vf_rx.h"
#include "sxe2_log.h"
#include "sxe2vf_netdev.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_regs.h"

STATIC s32 sxe2vf_rx_ring_alloc(struct sxe2vf_queue *rxq)
{
	s32 ret;
	u32 size;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	rxq->rx_buf = kcalloc(rxq->depth, sizeof(*rxq->rx_buf),
			      GFP_KERNEL | __GFP_ZERO);
	if (!rxq->rx_buf) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("rxq:%d alloc %luB buffer info failed.(err:%d)\n",
			      rxq->idx_in_vsi, rxq->depth * sizeof(*rxq->rx_buf),
			      ret);
		return ret;
	}

	size = SXE2VF_RX_DESC_SIZE(rxq);
	rxq->desc.base_addr = dma_alloc_coherent(rxq->dev, size, &rxq->desc.dma,
						 GFP_KERNEL | __GFP_ZERO);
	if (!rxq->desc.base_addr) {
		ret = -ENOMEM;
		LOG_DEV_ERR("rxq:%d alloc %uB descriptor failed.(err:%d)\n",
			    rxq->idx_in_vsi, size, ret);
		goto l_desc_alloc_failed;
	}

	rxq->next_to_use = 0;
	rxq->next_to_clean = 0;

	LOG_DEBUG_BDF("rxq[%u] depth:%u rx_buf:%p size:%lu\t"
		      "descriptor base va:%p dma:0x%llx size:%u.\n",
		      rxq->idx_in_vsi, rxq->depth, rxq->rx_buf,
		      rxq->depth * sizeof(*rxq->rx_buf), rxq->desc.base_addr,
		      rxq->desc.dma, size);

	return 0;

l_desc_alloc_failed:
	kfree(rxq->rx_buf);
	rxq->rx_buf = NULL;

	return ret;
}

void sxe2vf_rx_ring_free(struct sxe2vf_queue *rxq)
{
	kfree(rxq->rx_buf);
	rxq->rx_buf = NULL;

	if (rxq->desc.base_addr) {
		dma_free_coherent(rxq->dev, SXE2VF_RX_DESC_SIZE(rxq),
				  rxq->desc.base_addr, rxq->desc.dma);
		rxq->desc.base_addr = NULL;
	}

	LOG_DEBUG("rxq[%u] ring memory free.\n", rxq->idx_in_vsi);
}

static void sxe2vf_rx_page_free(struct sxe2vf_queue *rxq,
				struct sxe2vf_rx_buf *buf_info)
{
	dma_unmap_page_attrs(rxq->dev, buf_info->dma, SXE2VF_RX_PAGE_SIZE(rxq),
			     DMA_FROM_DEVICE, SXE2VF_RX_DMA_ATTR);

	__page_frag_cache_drain(buf_info->page, buf_info->drv_refcnt);

	buf_info->page = NULL;
	buf_info->pg_offset = 0;
}

static void sxe2vf_rx_ring_clean(struct sxe2vf_queue *rxq)
{
	struct device *dev = rxq->dev;
	struct sxe2vf_rx_buf *rx_buf_info;
	u16 i;

	if (!rxq->rx_buf)
		return;

	for (i = 0; i < rxq->depth; i++) {
		rx_buf_info = &rxq->rx_buf[i];
		if (!rx_buf_info->page)
			continue;

		dma_sync_single_range_for_cpu(dev, rx_buf_info->dma,
					      rx_buf_info->pg_offset,
					      rxq->rx_buf_len, DMA_FROM_DEVICE);
		sxe2vf_rx_page_free(rxq, rx_buf_info);
	}

	memset(rxq->rx_buf, 0, SXE2VF_RX_BUF_LEN(rxq));
	memset(rxq->desc.base_addr, 0, SXE2VF_RX_DESC_SIZE(rxq));

	rxq->next_to_alloc = 0;
	rxq->next_to_clean = 0;
	rxq->next_to_use = 0;
}

void sxe2vf_rx_rings_clean(struct sxe2vf_vsi *vsi)
{
	u16 i;

	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		sxe2vf_rx_ring_clean(vsi->rxqs.q[i]);
	}
}

STATIC void sxe2vf_rx_rings_free(struct sxe2vf_vsi *vsi)
{
	u16 i;
	struct sxe2vf_queue *rxq;

	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		rxq = vsi->rxqs.q[i];
		sxe2vf_rx_ring_free(rxq);
	}
}

static void sxe2vf_rx_ring_res_free(struct sxe2vf_queue *rxq)
{
	sxe2vf_rx_ring_clean(rxq);

	sxe2vf_rx_ring_free(rxq);
}

void sxe2vf_rx_rings_res_free(struct sxe2vf_vsi *vsi)
{
	u16 i;

	if (!vsi)
		return;

	sxe2vf_for_each_vsi_rxq(vsi, i) sxe2vf_rx_ring_res_free(vsi->rxqs.q[i]);
}

static s32 sxe2vf_rx_rings_alloc(struct sxe2vf_vsi *vsi)
{
	s32 ret;
	u16 i;
	struct sxe2vf_queue *rxq;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		rxq = vsi->rxqs.q[i];

		ret = sxe2vf_rx_ring_alloc(rxq);
		if (ret) {
			LOG_ERROR_BDF("vsi:%d rxq:%d ring alloc failed.(%d)\n",
				      vsi->vsi_id, i, ret);
			goto l_failed;
		}
	}

	return ret;

l_failed:
	while (i--)
		sxe2vf_rx_ring_free(vsi->rxqs.q[i]);

	return ret;
}

static u32 sxe2vf_rx_buf_len_set(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u32 rx_buf_len = SXE2VF_RXBUF_2048;

#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	if (!test_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags)) {
		struct net_device *netdev = adapter->netdev;

		rx_buf_len = SXE2VF_RXBUF_3072;

		if (!SXE2VF_PAD_RX_LEN_EXCEED_2K && netdev->mtu <= ETH_DATA_LEN)
			rx_buf_len = SXE2VF_RXBUF_1536 - NET_IP_ALIGN;
	}
#endif

	LOG_DEBUG_BDF("vsi:%u type:%u rx_buf_len:%u.\n", vsi->vsi_id, vsi->vsi_type,
		      rx_buf_len);

	return rx_buf_len;
}

static void sxe2vf_rxq_lro_switch(struct sxe2vf_queue *rxq)
{
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2VF_FLAG_LRO_ENABLE, adapter->flags)) {
		set_bit(SXE2VF_RXQ_LRO_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u lro enabled.\n",
			     rxq->vsi->vsi_id, rxq->vsi->vsi_type, rxq->idx_in_vsi);
	} else {
		clear_bit(SXE2VF_RXQ_LRO_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u lro disabled.\n",
			     rxq->vsi->vsi_id, rxq->vsi->vsi_type, rxq->idx_in_vsi);
	}
}

static void sxe2vf_rxq_rxfcs_switch(struct sxe2vf_queue *rxq)
{
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2VF_FLAG_RXFCS_ENABLE, adapter->flags)) {
		set_bit(SXE2VF_RXQ_RXFCS_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u rxfcs enabled.\n",
			     rxq->vsi->vsi_id, rxq->vsi->vsi_type, rxq->idx_in_vsi);
	} else {
		clear_bit(SXE2VF_RXQ_RXFCS_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u rxfcs disabled.\n",
			     rxq->vsi->vsi_id, rxq->vsi->vsi_type, rxq->idx_in_vsi);
	}
}

static void sxe2vf_rxq_skb_build_switch(struct sxe2vf_queue *rxq)
{
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2VF_FLAG_LEGACY_RX_ENABLE, adapter->flags))
		clear_bit(SXE2VF_RXQ_BUILD_SKB_ENABLED, &rxq->flags);
	else
		set_bit(SXE2VF_RXQ_BUILD_SKB_ENABLED, &rxq->flags);
}

static void sxe2vf_rxq_switch_cfg(struct sxe2vf_queue *rxq, u32 rx_buf_len)
{
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	rxq->desc.tail = (u8 __iomem *)(adapter->hw.reg_base_addr +
					(u64)SXE2VF_RXQ_TAIL((u64)rxq->idx_in_vsi));
	rxq->rx_buf_len = (u16)rx_buf_len;

	sxe2vf_rxq_lro_switch(rxq);
	sxe2vf_rxq_rxfcs_switch(rxq);
	sxe2vf_rxq_skb_build_switch(rxq);
	rxq->rx_offset = sxe2vf_rx_offset_get(rxq);
}

static bool sxe2vf_rx_page_alloc(struct sxe2vf_queue *rxq,
				 struct sxe2vf_rx_buf *buf_info)
{
	struct page *page;
	dma_addr_t dma;

	if (likely(buf_info->page)) {
		LOG_DEBUG("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p order:%u\t"
			  "dma:%llu pg_offset:%u drv_refcnt:0x%x reused.\n",
			  rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_clean,
			  rxq->next_to_alloc, buf_info->page,
			  SXE2VF_RX_PAGE_ORDER(rxq), buf_info->dma,
			  buf_info->pg_offset, buf_info->drv_refcnt);
		return true;
	}

	page = dev_alloc_pages(SXE2VF_RX_PAGE_ORDER(rxq));
	if (unlikely(!page)) {
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
		LOG_ERROR("rxq[%u] ntu:%u ntc:%u nta:%u rx pg_offset:%u\t"
			  "drv_refcnt:0x%x page alloc fail.\n",
			  rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_clean,
			  rxq->next_to_alloc, buf_info->pg_offset,
			  buf_info->drv_refcnt);
		return false;
	}

	dma = dma_map_page_attrs(rxq->dev, page, 0, SXE2VF_RX_PAGE_SIZE(rxq),
				 DMA_FROM_DEVICE, SXE2VF_RX_DMA_ATTR);

	if (dma_mapping_error(rxq->dev, dma)) {
		__free_pages(page, SXE2VF_RX_PAGE_ORDER(rxq));
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
		LOG_ERROR("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p dma:%llu\t"
			  "pg_offset:%u  drv_refcnt:0x%x dma map fail.\n",
			  rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_clean,
			  rxq->next_to_alloc, page, dma, buf_info->pg_offset,
			  buf_info->drv_refcnt);
		return false;
	}
	rxq->stats->rx_stats.rx_page_alloc++;
	buf_info->dma = dma;
	buf_info->page = page;
	buf_info->pg_offset = rxq->rx_offset;

	page_ref_add(page, USHRT_MAX - 1);
	buf_info->drv_refcnt = USHRT_MAX;

	LOG_DEBUG("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p order:%u\t"
		  "dma:%llu pg_offset:%u drv_refcnt:0x%x.\n",
		  rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_clean,
		  rxq->next_to_alloc, page, SXE2VF_RX_PAGE_ORDER(rxq), dma,
		  buf_info->pg_offset, buf_info->drv_refcnt);

	return true;
}

static void sxe2vf_rxq_tail_update(struct sxe2vf_queue *rxq, u16 new)
{
#ifndef SXE2_CFG_RELEASE
	u16 prev_ntu = rxq->next_to_use;
#endif
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	rxq->next_to_use = new;
	rxq->next_to_alloc = new;

	/* in order to force CPU ordering */
	wmb();
	writel(new, rxq->desc.tail);

	LOG_DEBUG_BDF("rxq[%u] ntu:%u nta:%u prev:%u tail:%u update read:0x%x.\n",
		      rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_alloc,
		      prev_ntu, new, readl(rxq->desc.tail));
}

bool sxe2vf_rx_buffers_alloc(struct sxe2vf_queue *rxq, u16 cnt)
{
	union sxe2vf_rx_desc *desc;
	struct sxe2vf_rx_buf *buf_info;
	u16 ntu = rxq->next_to_use;

	if (!cnt)
		return false;

	desc = SXE2VF_RX_DESC(rxq, ntu);
	buf_info = &rxq->rx_buf[ntu];

	do {
		if (!sxe2vf_rx_page_alloc(rxq, buf_info))
			break;

		dma_sync_single_range_for_device(rxq->dev, buf_info->dma,
						 buf_info->pg_offset,
						 rxq->rx_buf_len, DMA_FROM_DEVICE);
		desc->read.pkt_addr =
				cpu_to_le64(buf_info->dma + buf_info->pg_offset);

		desc++;
		buf_info++;
		ntu++;

		if (unlikely(ntu == rxq->depth)) {
			desc = SXE2VF_RX_DESC(rxq, 0);
			buf_info = rxq->rx_buf;
			ntu = 0;
		}

		desc->wb.status0_err = 0;

		cnt--;
	} while (cnt);

	if (rxq->next_to_use != ntu)
		sxe2vf_rxq_tail_update(rxq, ntu);

	return !!cnt;
}

s32 sxe2vf_rx_hw_cfg(struct sxe2vf_vsi *vsi)
{
	u16 i;
	u32 rx_buf_len;
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret;

	rx_buf_len = sxe2vf_rx_buf_len_set(vsi);

	sxe2vf_for_each_vsi_rxq(vsi, i)
	{
		sxe2vf_rxq_switch_cfg(vsi->rxqs.q[i], rx_buf_len);
	}

	ret = sxe2vf_rxq_cfg_request(adapter);
	if (!ret) {
		sxe2vf_for_each_vsi_rxq(vsi, i)
		{
			(void)sxe2vf_rx_buffers_alloc(vsi->rxqs.q[i],
					SXE2VF_DESC_IDLE(vsi->rxqs.q[i]));
		}
	}

	return ret;
}

s32 sxe2vf_rx_cfg(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	s32 ret;

	ret = sxe2vf_rx_rings_alloc(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u type:%u rx ring resource alloc\t"
			      "failed.(err:%d)\n",
			      vsi->vsi_id, vsi->vsi_type, ret);
		return ret;
	}

	ret = sxe2vf_rx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("rx hw configure failed, ret=%d\n", ret);
		sxe2vf_wait_in_resetting(adapter, false);
		goto l_rxq_cfg_failed;
	}

	return 0;

l_rxq_cfg_failed:
	sxe2vf_rx_rings_free(vsi);
	return ret;
}

static void sxe2vf_rx_first_pkt_sync(struct sxe2vf_queue *rxq, struct sk_buff *skb)
{
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2VF_RXQ_BUILD_SKB_ENABLED, &rxq->flags)) {
		unsigned long mask = (unsigned long)SXE2VF_RX_PAGE_SIZE(rxq) - 1;
		unsigned long offset = (unsigned long)(skb->data) & mask;

		dma_sync_single_range_for_cpu(rxq->dev, SXE2VF_SKB_PRIV(skb)->dma,
					      offset, skb_headlen(skb),
					      DMA_FROM_DEVICE);
	} else {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[0];

		dma_sync_single_range_for_cpu(rxq->dev, SXE2VF_SKB_PRIV(skb)->dma,
					      skb_frag_off(frag),
					      skb_frag_size(frag), DMA_FROM_DEVICE);
	}

	if (unlikely(SXE2VF_SKB_PRIV(skb)->page_released)) {
		dma_unmap_page_attrs(rxq->dev, SXE2VF_SKB_PRIV(skb)->dma,
				     SXE2VF_RX_PAGE_SIZE(rxq), DMA_FROM_DEVICE,
				     SXE2VF_RX_DMA_ATTR);
	}

	LOG_DEBUG_BDF("rxq[%u] skb:%p nr_frags:%u dma:%llu sync first packet\n",
		      rxq->idx_in_vsi, skb, skb_shinfo(skb)->nr_frags,
		      SXE2VF_SKB_PRIV(skb)->dma);
}

static struct sxe2vf_rx_buf *sxe2vf_rx_buffer_get(struct sxe2vf_queue *rxq,
						  union sxe2vf_rx_desc *rx_desc,
						  const u32 size, s32 *pg_cnt)
{
	struct sxe2vf_rx_buf *rx_buffer = &rxq->rx_buf[rxq->next_to_clean];
	struct sk_buff *skb = rx_buffer->skb;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	*pg_cnt =
#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
			page_count(rx_buffer->page);
#else
			0;
#endif

	prefetchw(rx_buffer->page);

	if (!size)
		return rx_buffer;

	if (sxe2vf_is_non_eop(rxq, rx_desc)) {
		if (!skb)
			goto l_skip_sync;
	} else {
		if (skb)
			sxe2vf_rx_first_pkt_sync(rxq, skb);
	}

	dma_sync_single_range_for_cpu(rxq->dev, rx_buffer->dma, rx_buffer->pg_offset,
				      size, DMA_FROM_DEVICE);

l_skip_sync:
	rx_buffer->drv_refcnt--;

	LOG_DEBUG_BDF("rxq[%u] ntc:%u pkt len:%u skb:%p drv_refcnt:0x%x\t"
		      "pg_offset:%u rx_buffer[%u]:%p get\n",
		      rxq->idx_in_vsi, rxq->next_to_clean, size, skb,
		      rx_buffer->drv_refcnt, rx_buffer->pg_offset,
		      rxq->next_to_clean, rx_buffer);

	return rx_buffer;
}

static void sxe2vf_rxq_stats_update(struct sxe2vf_queue *rxq, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&rxq->syncp);
	rxq->stats->bytes += bytes;
	rxq->stats->packets += pkts;
	u64_stats_update_end(&rxq->syncp);
}

static void sxe2vf_rx_page_reuse(struct sxe2vf_queue *rxq,
				 struct sxe2vf_rx_buf *old_buff)
{
	struct sxe2vf_rx_buf *new_buff;
	u16 nta = rxq->next_to_alloc;

	new_buff = &rxq->rx_buf[nta];

	nta++;
	rxq->next_to_alloc = (nta < rxq->depth) ? nta : 0;

	new_buff->dma = old_buff->dma;
	new_buff->page = old_buff->page;
	new_buff->pg_offset = old_buff->pg_offset;
	new_buff->drv_refcnt = old_buff->drv_refcnt;
}

static bool sxe2vf_page_is_reusable(struct sxe2vf_rx_buf *rx_buf, int pg_refcnt)
{
	u32 drv_refcnt = rx_buf->drv_refcnt;
	struct page *page = rx_buf->page;

	if (!dev_page_is_reusable(page))
		return false;

#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	if (unlikely((pg_refcnt - (int)drv_refcnt) > 1))
		return false;
#else
	if (rx_buf->pg_offset > SXE2VF_LAST_OFFSET)
		return false;
#endif

	if (unlikely(drv_refcnt == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		rx_buf->drv_refcnt = USHRT_MAX;
	}

	return true;
}

static void sxe2vf_rx_pg_offset_update(struct sxe2vf_rx_buf *rx_buf, u32 size)
{
#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	rx_buf->pg_offset ^= size;
#else
	rx_buf->pg_offset += size;
#endif
}

static void sxe2vf_skb_frag_add(struct sxe2vf_queue *rxq,
				struct sxe2vf_rx_buf *rx_buf, struct sk_buff *skb,
				u32 size)
{
#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	u32 truesize = SXE2VF_RX_PAGE_SIZE(rxq) / 2;
#else
	u32 truesize = SKB_DATA_ALIGN(size + rxq->rx_offset);
#endif

	if (!size)
		return;

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buf->page,
			(int)rx_buf->pg_offset, (int)size, truesize);

	sxe2vf_rx_pg_offset_update(rx_buf, truesize);
}

static void sxe2vf_rx_buffer_put(struct sxe2vf_queue *rxq,
				 union sxe2vf_rx_desc *rx_desc,
				 struct sxe2vf_rx_buf *rx_buf, struct sk_buff *skb,
				 int pg_refcnt)
{
	u16 ntc = rxq->next_to_clean + 1;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;
	u8 lro_cnt = sxe2vf_rx_desc_lro_cnt(rxq, rx_desc);

	ntc = (ntc < rxq->depth) ? ntc : 0;
	rxq->next_to_clean = ntc;

	if (!rx_buf)
		return;

	if (lro_cnt)
		SXE2VF_SKB_PRIV(skb)->lro_cnt += lro_cnt;

	if (sxe2vf_page_is_reusable(rx_buf, pg_refcnt)) {
		sxe2vf_rx_page_reuse(rxq, rx_buf);
	} else {
		if (SXE2VF_SKB_PRIV(skb)->dma == rx_buf->dma)
			SXE2VF_SKB_PRIV(skb)->page_released = true;
		else
			dma_unmap_page_attrs(rxq->dev, rx_buf->dma,
					     SXE2VF_RX_PAGE_SIZE(rxq),
					     DMA_FROM_DEVICE, SXE2VF_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_buf->page, rx_buf->drv_refcnt);
	}

	rx_buf->page = NULL;
	rx_buf->skb = NULL;

	LOG_DEBUG_BDF("rxq[%u] ntc:%u nta:%u skb:%p nr_frags:%u lro_cnt:%u\t"
		      "rx_buffer[%u]:%p put\n",
		      rxq->idx_in_vsi, rxq->next_to_clean, rxq->next_to_alloc, skb,
		      skb_shinfo(skb)->nr_frags, SXE2VF_SKB_PRIV(skb)->lro_cnt,
		      ntc - 1, rx_buf);
}

static struct sk_buff *sxe2vf_skb_build(struct sxe2vf_queue *rxq,
					struct sxe2vf_rx_buf *rx_buf, u32 size,
					union sxe2vf_rx_desc *rx_desc)
{
	void *va;
#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	u32 truesize = SXE2VF_RX_PAGE_SIZE(rxq) / 2;
#else
	u32 truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
		       SKB_DATA_ALIGN(SXE2VF_SKB_PAD_VALUE + size);
#endif
	struct sk_buff *skb;

	if (!rx_buf)
		return NULL;

	va = page_address(rx_buf->page) + rx_buf->pg_offset;
	net_prefetch(va);

	skb = napi_build_skb(va - SXE2VF_SKB_PAD_VALUE, truesize);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, SXE2VF_SKB_PAD_VALUE);
	(void)__skb_put(skb, size);

	if (sxe2vf_is_non_eop(rxq, rx_desc))
		SXE2VF_SKB_PRIV(skb)->dma = rx_buf->dma;

	sxe2vf_rx_pg_offset_update(rx_buf, truesize);

	return skb;
}

static struct sk_buff *sxe2vf_skb_construct(struct sxe2vf_queue *rxq,
					    struct sxe2vf_rx_buf *rx_buf, u32 size,
					    union sxe2vf_rx_desc *rx_desc)
{
	void *va;
	u32 headlen;
	struct sk_buff *skb;
#if (PAGE_SIZE < SXE2VF_PAGE_SIZE_8KB)
	u32 truesize = SXE2VF_RX_PAGE_SIZE(rxq) / 2;
#else
	u32 truesize = SKB_DATA_ALIGN(size);
#endif

	if (!rx_buf)
		return NULL;

	va = page_address(rx_buf->page) + rx_buf->pg_offset;
	net_prefetch(va);

	skb = __napi_alloc_skb(&rxq->irq_data->napi, SXE2VF_RX_HDR_SIZE,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	headlen = size;
	if (headlen > SXE2VF_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, va, SXE2VF_RX_HDR_SIZE);

	memcpy(__skb_put(skb, headlen), va, ALIGN(headlen, sizeof(long)));

	size -= headlen;
	if (size) {
		if (sxe2vf_is_non_eop(rxq, rx_desc))
			SXE2VF_SKB_PRIV(skb)->dma = rx_buf->dma;

		skb_add_rx_frag(skb, 0, rx_buf->page,
				(int)(rx_buf->pg_offset + headlen), (int)size,
				truesize);

		sxe2vf_rx_pg_offset_update(rx_buf, truesize);
	} else {
		rx_buf->drv_refcnt++;
	}

	return skb;
}

STATIC enum pkt_hash_types sxe2vf_hash_type_get(u16 ptype)
{
	struct sxe2vf_rx_ptype_info ptype_info = sxe2vf_rx_ptype_parse(ptype);

	if (!ptype_info.known)
		return PKT_HASH_TYPE_NONE;
	if (ptype_info.hash_layer == SXE2VF_PTYPE_PAYLOAD_LAYER_PAY4)
		return PKT_HASH_TYPE_L4;
	if (ptype_info.hash_layer == SXE2VF_PTYPE_PAYLOAD_LAYER_PAY3)
		return PKT_HASH_TYPE_L3;
	if (ptype_info.outer_ip == SXE2VF_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

static void sxe2vf_lro_stats_update(struct sxe2vf_queue *rxq, struct sk_buff *skb)
{
	u32 hdr_len;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (!SXE2VF_SKB_PRIV(skb)->lro_cnt) {
		LOG_DEBUG_BDF("rxq[%u] not lro packet\n", rxq->idx_in_vsi);
		return;
	}

	rxq->stats->rx_stats.rx_lro_count += SXE2VF_SKB_PRIV(skb)->lro_cnt - 1;
	rxq->stats->rx_stats.rx_lro_packets++;

	hdr_len = skb_headlen(skb);

	skb_shinfo(skb)->gso_size = (u16)DIV_ROUND_UP((skb->len - hdr_len),
						      SXE2VF_SKB_PRIV(skb)->lro_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	rxq->stats->rx_stats.rx_lro_bytes += skb->len;

	SXE2VF_SKB_PRIV(skb)->lro_cnt = 0;
}

STATIC void sxe2vf_skb_hash_set(struct sxe2vf_queue *rxq,
				union sxe2vf_rx_desc *rx_desc, struct sk_buff *skb,
				u16 ptype)
{
	u32 rss_hash_vld;
	u32 hash;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (!(rxq->netdev->features & NETIF_F_RXHASH)) {
		LOG_DEBUG_BDF("rxq[%u] rss hash offload off netdev\t"
			      "feature:0x%llx.\n",
			      rxq->idx_in_vsi, rxq->netdev->features);
		return;
	}

	rss_hash_vld = (le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) >>
			SXE2VF_RX_DESC_STATUS2_RSS_VLD) &
		       SXE2VF_RX_DESC_RSS_VLD_MASK;
	if (!rss_hash_vld) {
		LOG_DEBUG_BDF("rxq[%u] rss_vld:0x%x\n", rxq->idx_in_vsi,
			      rss_hash_vld);
		return;
	}

	hash = le32_to_cpu(rx_desc->wb.filter_status);

	skb_set_hash(skb, hash, sxe2vf_hash_type_get(ptype));
	LOG_DEBUG_BDF("rxq[%u] hash:0x%x ptype:%u\n", rxq->idx_in_vsi, hash, ptype);
}

static void sxe2vf_rx_csum_check(struct sxe2vf_queue *rxq,
				 union sxe2vf_rx_desc *rx_desc, struct sk_buff *skb,
				 u16 ptype)
{
	struct sxe2vf_rx_ptype_info ptype_info;
	u16 status0_err = 0;
	bool ipv4 = 0;
	bool ipv6 = 0;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;

	if (!(rxq->netdev->features & NETIF_F_RXCSUM)) {
		rxq->stats->rx_stats.rx_csum_none++;
		LOG_DEBUG_BDF("rxq[%u] rx csum offload off netdev feature:0x%llx.\n",
			      rxq->idx_in_vsi, rxq->netdev->features);
		return;
	}

	status0_err = le16_to_cpu(rx_desc->wb.status0_err);
	ptype_info = sxe2vf_rx_ptype_parse(ptype);

	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	if (!(status0_err & BIT(SXE2VF_RX_DESC_STATUS0_L3L4_P)) ||
	    !(ptype_info.known && ptype_info.outer_ip))
		goto l_out;

	ipv4 = (ptype_info.outer_ip == SXE2VF_PTYPE_OUTER_IP) &&
	       (ptype_info.outer_ip_ver == SXE2VF_PTYPE_OUTER_IPV4);

	ipv6 = (ptype_info.outer_ip == SXE2VF_PTYPE_OUTER_IP) &&
	       (ptype_info.outer_ip_ver == SXE2VF_PTYPE_OUTER_IPV6);

	if (ipv4 && (status0_err & (BIT(SXE2VF_RX_DESC_ERROR_IPE) |
				    BIT(SXE2VF_RX_DESC_ERROR_EIPE))))
		goto checksum_fail;

	if (ipv6 && (le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) &
		     (BIT(SXE2VF_RX_DESC_STATUS2_IPV6EXADD))))
		goto l_out;

	if (status0_err & BIT(SXE2VF_RX_DESC_ERROR_L4E))
		goto checksum_fail;

	if (rx_desc->wb.rxdid_src & BIT(SXE2VF_RX_DESC_EUDPE))
		goto checksum_fail;

	if (ptype_info.tunnel_type >= SXE2VF_PTYPE_TUNNEL_IP_GRENAT) {
		skb->csum_level = 1;
		rxq->stats->rx_stats.rx_csum_unnecessary_inner++;
	}

	switch (ptype_info.inner_prot) {
	case SXE2VF_PTYPE_INNER_PROT_UDP:
	case SXE2VF_PTYPE_INNER_PROT_TCP:
	case SXE2VF_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		rxq->stats->rx_stats.rx_csum_unnecessary++;
		break;
	default:
		break;
	}
	rxq->stats->rx_stats.rx_csum_complete++;

	return;

checksum_fail:
	rxq->stats->rx_stats.rx_csum_err++;

l_out:
	LOG_DEBUG_BDF("rxq[%u] rxcsum offload:0x%llx status0_err:0x%x\t"
		      "ptype:0x%x ptype_info:0x%x pktl_hdrl_status2:0x%x\n"
		      "rxdid_src:%u ipv4:%u ipv6:%u ip_summed:%d csum_level:%d\t"
		      "csum_err:0x%llx\n",
		      rxq->idx_in_vsi, rxq->netdev->features & NETIF_F_RXCSUM,
		      status0_err, ptype, *(u32 *)&ptype_info,
		      le32_to_cpu(rx_desc->wb.pktl_hdrl_status2),
		      rx_desc->wb.rxdid_src, ipv4, ipv6, skb->ip_summed,
		      skb->csum_level, rxq->stats->rx_stats.rx_csum_err);
}

static inline u16 sxe2vf_vlan_tag_get(union sxe2vf_rx_desc *rx_desc)
{
	if (le16_to_cpu(rx_desc->wb.status0_err) &
	    BIT(SXE2VF_RX_DESC_STATUS0_L2TAG1_P))
		return le16_to_cpu(rx_desc->wb.l2tag1);

	return 0;
}

static void sxe2vf_skb_vlan_tag_put(struct sxe2vf_queue *rxq,
				    union sxe2vf_rx_desc *rx_desc,
				    struct sk_buff *skb)
{
	netdev_features_t features = rxq->netdev->features;
	u16 vlan_tag = sxe2vf_vlan_tag_get(rx_desc);
	bool non_zero_vlan = !!(vlan_tag & VLAN_VID_MASK);

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) && non_zero_vlan) {
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tag);
		rxq->stats->rx_stats.rx_vlan_strip++;
	} else if ((features & NETIF_F_HW_VLAN_STAG_RX) && non_zero_vlan) {
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), vlan_tag);
	}

	LOG_INFO("rxq:%u vlan tag strip ctag:%s stag:%s vlan tag:0x%x.\n",
		 rxq->idx_in_vsi,
		 (features & NETIF_F_HW_VLAN_CTAG_RX) ? "enabled" : "disabled",
		 (features & NETIF_F_HW_VLAN_STAG_RX) ? "enabled" : "disabled",
		 vlan_tag);
}

static bool sxe2vf_rx_desc_ipsec_check(union sxe2vf_rx_desc *rx_desc)
{
	return (le32_to_cpu(rx_desc->wb.status_lrocnt_fdpf_id) >>
		SXE2VF_RX_DESC_IPSEC_PKT) &
	       0x1;
}

static void sxe2vf_skb_field_fill(struct sxe2vf_queue *rxq,
				  union sxe2vf_rx_desc *rx_desc, struct sk_buff *skb,
				  u16 ptype)
{
	sxe2vf_lro_stats_update(rxq, skb);

	sxe2vf_skb_hash_set(rxq, rx_desc, skb, ptype);

	skb->protocol = eth_type_trans(skb, rxq->netdev);

	sxe2vf_rx_csum_check(rxq, rx_desc, skb, ptype);

	skb_record_rx_queue(skb, rxq->idx_in_vsi);

	if (sxe2vf_rx_desc_ipsec_check(rx_desc))
		sxe2vf_ipsec_rx(rxq, rx_desc, skb, ptype);

	sxe2vf_skb_vlan_tag_put(rxq, rx_desc, skb);
}

int sxe2vf_rxq_irq_clean(struct sxe2vf_queue *rxq, int budget)
{
	u32 total_rx_bytes = 0;
	u32 total_rx_pkts = 0;
	u16 idle = SXE2VF_DESC_IDLE(rxq);
	u32 offset = rxq->rx_offset;
	struct sk_buff *skb = rxq->skb;
	bool failure;
	struct sxe2vf_adapter *adapter = rxq->vsi->adapter;
#ifdef SXE2_CFG_DEBUG
#define SXE2VF_LOG_STR_LEN 32
	char str[SXE2VF_LOG_STR_LEN] = {0};
#endif

#ifdef SXE2_CFG_RELEASE
	UNUSED(offset);
#endif

	LOG_DEBUG_BDF("rxq[%u] ntc:%u ntu:%u nta:%u budget:%u,\t"
		      "rxq_offset:%u descriptor idle:%u skb:%p vsi:%p\n",
		      rxq->idx_in_vsi, rxq->next_to_clean, rxq->next_to_use,
		      rxq->next_to_alloc, budget, offset, idle, skb, rxq->vsi);

	while (likely(total_rx_pkts < (u32)budget)) {
		union sxe2vf_rx_desc *rx_desc;
		struct sxe2vf_rx_buf *rx_buf;
		u32 size;
		s32 pg_refcnt;
		u16 rx_ptype;

		rx_desc = SXE2VF_RX_DESC(rxq, rxq->next_to_clean);
#ifdef SXE2_CFG_DEBUG

		(void)snprintf(str, SXE2VF_LOG_STR_LEN - 1, "rxq[%d] desc[%d]",
			       rxq->idx_in_vsi, rxq->next_to_clean);
		DATA_DUMP(rx_desc, sizeof(*rx_desc), str);
#endif

		if (!sxe2vf_desc_status0_err_test(rx_desc->wb.status0_err,
						  BIT(SXE2VF_RX_DESC_STATUS0_DD)))
			break;

		dma_rmb();

		sxe2vf_trace(rx_pkt_clean_begin, rxq);

		size = le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) &
		       SXE2VF_RX_DESC_PKT_LEN_MASK;

		rx_buf = sxe2vf_rx_buffer_get(rxq, rx_desc, size, &pg_refcnt);

		if (skb) {
			sxe2vf_skb_frag_add(rxq, rx_buf, skb, size);
		} else if (test_bit(SXE2VF_RXQ_BUILD_SKB_ENABLED,
				    &rxq->flags)) {
			skb = sxe2vf_skb_build(rxq, rx_buf, size, rx_desc);
		} else {
			skb = sxe2vf_skb_construct(rxq, rx_buf, size, rx_desc);
		}

		if (!skb) {
			rxq->stats->rx_stats.rx_buff_alloc_err++;
			if (rx_buf)
				rx_buf->drv_refcnt++;
			break;
		}

		sxe2vf_rx_buffer_put(rxq, rx_desc, rx_buf, skb, pg_refcnt);
		idle++;

		if (sxe2vf_is_non_eop(rxq, rx_desc)) {
			rxq->rx_buf[rxq->next_to_clean].skb = skb;
			rxq->stats->rx_stats.rx_non_eop_descs++;
			continue;
		}

		if (unlikely(sxe2vf_desc_status0_err_test(rx_desc->wb.status0_err,
							  BIT(SXE2VF_RX_DESC_ERROR_PA_ERR)))) {
			rxq->stats->rx_stats.rx_pa_err++;
		}

		if (unlikely(sxe2vf_desc_status0_err_test(rx_desc->wb.status0_err,
							  BIT(SXE2VF_RX_DESC_ERROR_RXE)) ||
			     sxe2vf_desc_status0_err_test(rx_desc->wb.status0_err,
							  BIT(SXE2VF_RX_DESC_ERROR_OVERSIZE)))) {
			rxq->stats->rx_stats.rx_pkts_sw_drop++;
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		total_rx_bytes += skb->len;

		rx_ptype = le16_to_cpu(rx_desc->wb.ptype_status1) &
			   SXE2VF_RX_DESC_PTYPE_MASK;

		sxe2vf_skb_field_fill(rxq, rx_desc, skb, rx_ptype);

		sxe2vf_trace(rx_pkt_clean_end, rxq);

		(void)napi_gro_receive(&rxq->irq_data->napi, skb);
		skb = NULL;

		total_rx_pkts++;
	}

	failure = sxe2vf_rx_buffers_alloc(rxq, idle);

	rxq->skb = skb;

	sxe2vf_rxq_stats_update(rxq, total_rx_pkts, total_rx_bytes);

	return failure ? budget : (int)total_rx_pkts;
}
