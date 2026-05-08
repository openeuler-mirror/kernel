// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_rx.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_macvlan.h>
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_BUFF_IN_XDP_H
#include <net/xdp.h>
#else
#include <linux/filter.h>
#endif
#endif

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_vsi.h"
#include "sxe2_queue.h"
#include "sxe2_rx.h"
#include "sxe2_common.h"
#include "sxe2_skb_dump.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_ptp.h"
#include "sxe2_xsk.h"

#define SXE2_LAST_OFFSET (SKB_WITH_OVERHEAD(PAGE_SIZE) - SXE2_RXBUF_2048)

STATIC s32 sxe2_xdp_info_get(struct sxe2_queue *rxq)
{
	s32 rc = 0;

	if (sxe2_xdp_is_enable(rxq->vsi))
		WRITE_ONCE(rxq->xdp_prog, rxq->vsi->xdp_prog);

#ifdef HAVE_XDP_BUFF_RXQ
	if (rxq->vsi->type == SXE2_VSI_T_PF && !xdp_rxq_info_is_reg(&rxq->xdp_rxq))
		if (xdp_rxq_info_reg(&rxq->xdp_rxq, rxq->netdev, rxq->idx_in_vsi,
				     rxq->irq_data->napi.napi_id))
			rc = -ENOMEM;
#endif

	return rc;
}

static void sxe2_rx_page_free(struct sxe2_queue *rxq, struct sxe2_rx_buf *buf_info)
{
	dma_unmap_page_attrs(rxq->dev, buf_info->dma, SXE2_RX_PAGE_SIZE(rxq),
			     DMA_FROM_DEVICE, SXE2_RX_DMA_ATTR);

	__page_frag_cache_drain(buf_info->page, buf_info->drv_refcnt);

	buf_info->page = NULL;
	buf_info->pg_offset = 0;
}

void sxe2_rx_ring_clean(struct sxe2_queue *rxq)
{
	struct device *dev = rxq->dev;
	struct sxe2_rx_buf *rx_buf_info;
	u16 i;

	if (!rxq->rx_buf)
		return;

	if (rxq->skb) {
		dev_kfree_skb(rxq->skb);
		rxq->skb = NULL;
	}

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (rxq->xsk_pool) {
		sxe2_xsk_clean_rx_ring(rxq);
		goto rx_skip_free;
	}
#endif

	for (i = 0; i < rxq->depth; i++) {
		rx_buf_info = &rxq->rx_buf[i];
		if (!rx_buf_info->page)
			continue;

		dma_sync_single_range_for_cpu(dev, rx_buf_info->dma,
					      rx_buf_info->pg_offset,
					      rxq->rx_buf_len, DMA_FROM_DEVICE);
		sxe2_rx_page_free(rxq, rx_buf_info);
	}

#ifdef HAVE_AF_XDP_ZC_SUPPORT
rx_skip_free:
#endif
	memset(rxq->rx_buf, 0, SXE2_RX_BUF_LEN(rxq));
	memset(rxq->desc.base_addr, 0, SXE2_RX_DESC_SIZE(rxq));

	rxq->next_to_alloc = 0;
	rxq->next_to_clean = 0;
	rxq->next_to_use = 0;
}

void sxe2_rx_ring_free(struct sxe2_queue *rxq)
{
#ifdef HAVE_XDP_BUFF_RXQ
	if (rxq->vsi->type == SXE2_VSI_T_PF)
		if (xdp_rxq_info_is_reg(&rxq->xdp_rxq))
			xdp_rxq_info_unreg(&rxq->xdp_rxq);
#endif
	rxq->xdp_prog = NULL;

	kfree(rxq->rx_buf);
	rxq->rx_buf = NULL;

	if (rxq->desc.base_addr) {
		dmam_free_coherent(rxq->dev, SXE2_RX_DESC_SIZE(rxq),
				   rxq->desc.base_addr, rxq->desc.dma);
		rxq->desc.base_addr = NULL;
	}

	LOG_DEBUG("rxq[%u] ring memory free.\n", rxq->idx_in_vsi);
}

static void sxe2_rx_rings_free(struct sxe2_vsi *vsi)
{
	u16 i;
	struct sxe2_queue *rxq;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		rxq = vsi->rxqs.q[i];
		sxe2_rx_ring_free(rxq);
	}
}

s32 sxe2_rx_ring_alloc(struct sxe2_queue *rxq)
{
	s32 ret;
	u32 size;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;

	rxq->rx_buf = kcalloc(rxq->depth, sizeof(*rxq->rx_buf), GFP_KERNEL);
	if (!rxq->rx_buf) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("rxq:%d alloc %luB buffer info failed.(err:%d)\n",
			      rxq->idx_in_pf, rxq->depth * sizeof(*rxq->rx_buf),
			      ret);
		return ret;
	}

	size = SXE2_RX_DESC_SIZE(rxq);
	rxq->desc.base_addr = dmam_alloc_coherent(rxq->dev, size, &rxq->desc.dma,
						  GFP_KERNEL);
	if (!rxq->desc.base_addr) {
		ret = -ENOMEM;
		LOG_DEV_ERR("rxq:%d alloc %uB descriptor failed.(err:%d)\n",
			    rxq->idx_in_pf, size, ret);
		goto l_desc_alloc_failed;
	}

	rxq->next_to_use = 0;
	rxq->next_to_clean = 0;

	ret = sxe2_xdp_info_get(rxq);
	if (ret) {
		LOG_ERROR_BDF("rxq:%u xdp info get fail.(err:%d)\n", rxq->idx_in_pf,
			      ret);
		goto l_xdp_failed;
	}

	LOG_DEBUG_BDF("rxq[%u][%u] depth:%u rx_buf:%p size:%lu\t"
		      "descriptor base va:%p dma:0x%llx size:%u.\n",
		      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->depth, rxq->rx_buf,
		      rxq->depth * sizeof(*rxq->rx_buf), rxq->desc.base_addr,
		      rxq->desc.dma, size);

	return ret;

l_xdp_failed:
	dmam_free_coherent(rxq->dev, size, rxq->desc.base_addr, rxq->desc.dma);
	rxq->desc.base_addr = NULL;

l_desc_alloc_failed:
	kfree(rxq->rx_buf);
	rxq->rx_buf = NULL;

	return ret;
}

static s32 sxe2_rx_rings_alloc(struct sxe2_vsi *vsi)
{
	s32 ret;
	u16 i;
	struct sxe2_queue *rxq;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		rxq = vsi->rxqs.q[i];

		if (vsi->netdev)
			rxq->netdev = vsi->netdev;

		ret = sxe2_rx_ring_alloc(rxq);
		if (ret) {
			LOG_ERROR_BDF("vsi:%d rxq:%d ring alloc failed.(%d)\n",
				      vsi->idx_in_dev, i, ret);
			goto l_failed;
		}
	}

	return ret;

l_failed:
	sxe2_rx_rings_free(vsi);
	return ret;
}

void sxe2_rx_ring_res_free(struct sxe2_queue *rxq)
{
	sxe2_rx_ring_clean(rxq);

	sxe2_rx_ring_free(rxq);
}

void sxe2_rx_rings_res_free(struct sxe2_vsi *vsi)
{
	u16 i;

	sxe2_for_each_vsi_rxq(vsi, i) sxe2_rx_ring_res_free(vsi->rxqs.q[i]);
}

void sxe2_set_rx_mode(struct net_device *netdev)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	set_bit(SXE2_VSI_S_MAC_FLTR_CHANGED, vsi->state);
	set_bit(SXE2_FLAG_FLTR_SYNC, adapter->flags);

	sxe2_monitor_work_schedule(adapter);
}

int sxe2_vsi_vlan_zero_add(struct sxe2_vsi *vsi)
{
	struct sxe2_vlan vlan;
	int ret;

	vlan = SXE2_VLAN(0, 0, 0);
	ret = sxe2_vlan_rule_add(vsi, &vlan);
	if (ret && ret != -EEXIST)
		return ret;

	vlan = SXE2_VLAN(ETH_P_8021Q, 0, 0);
	ret = sxe2_vlan_rule_add(vsi, &vlan);
	if (ret && ret != -EEXIST)
		return ret;

	return 0;
}

s32 sxe2_vlan_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;

	sxe2_hw_l2tag_accept(hw, vsi->idx_in_dev);

	sxe2_set_vlan_offload_features(vsi, 0, vsi->netdev->features);

	ret = sxe2_set_vlan_filter_features(vsi, vsi->netdev->features);
	if (ret)
		return ret;

	ret = sxe2_vsi_vlan_zero_add(vsi);

	return ret;
}

void sxe2_frame_size_set(struct sxe2_vsi *vsi)
{
	if (!vsi->netdev)
		vsi->rxqs.max_frame = SXE2_MAX_FRAME_SIZE;
	else
		vsi->rxqs.max_frame = (u16)(vsi->netdev->mtu + SXE2_ETH_DEAD_LOAD);

#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	if (!vsi->netdev ||
	    test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, vsi->adapter->flags)) {
		vsi->rxqs.rx_buf_len = SXE2_RXBUF_2048;
	} else if (!SXE2_PAD_RX_LEN_EXCEED_2K &&
		   (vsi->netdev->mtu <= ETH_DATA_LEN)) {
		vsi->rxqs.rx_buf_len = SXE2_RXBUF_1536 - NET_IP_ALIGN;
	} else {
		vsi->rxqs.rx_buf_len = SXE2_RXBUF_3072;
	}
#else
	vsi->rxqs.rx_buf_len = SXE2_RXBUF_2048;
#endif

	LOG_INFO("vsi:%u max_frame:%u rx_buf_len:%u set done.\n", vsi->idx_in_dev,
		 vsi->rxqs.max_frame, vsi->rxqs.rx_buf_len);
}

static u16 sxe2_rxq_get_lro_desc_num(u32 max_lro_pkt_size, u16 buf_size)
{
	u16 lro_desc_num_arr[] = {1, 4, 8, 16, 32, 48, 64};
	u16 desc_num;
	u16 lro_desc_num = SXE2_RX_LRO_DESC_MAX_64;
	u16 i;

	desc_num = (u16)(max_lro_pkt_size / buf_size);
	desc_num = desc_num ? desc_num : 1;

	for (i = 0; i < ARRAY_SIZE(lro_desc_num_arr); i++) {
		if (desc_num <= lro_desc_num_arr[i]) {
			lro_desc_num = lro_desc_num_arr[i];
			break;
		}
	}
	LOG_DEBUG("Rx queue max_lro_pkt_size:%u buf_size:%u lro_desc_num:%u->%u.",
		  max_lro_pkt_size, buf_size, desc_num, lro_desc_num);
	return lro_desc_num;
}

static s32 sxe2_buffer_split_set(struct sxe2_queue *rxq,
				 struct sxe2_rxq_ctxt *rx_ctx)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	s32 ret = 0;
	u32 proto_hdr;

	if (test_bit(SXE2_RXQ_SPLIT_ENABLED, &rxq->flags)) {
		proto_hdr = rxq->split_type_mask;
		if (proto_hdr == SXE2_PTYPE_UNKNOWN) {
			LOG_ERROR_BDF("Buffer split protocol must be configured\n");
			ret = -EINVAL;
			goto l_end;
		}

		rx_ctx->hbuff_len =
				cpu_to_le16(rxq->hdr_len >> SXE2_RX_HBUF_LEN_UNIT);
		switch (proto_hdr & SXE2_PTYPE_L4_MASK) {
		case SXE2_PTYPE_L4_TCP:
		case SXE2_PTYPE_L4_UDP:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_TCP_UDP;
			goto l_end;
		case SXE2_PTYPE_L4_SCTP:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_SCTP;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_L3_MASK) {
		case SXE2_PTYPE_L3_IPV4:
		case SXE2_PTYPE_L3_IPV6:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_IP;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_L2_MASK) {
		case SXE2_PTYPE_L2_ETHER:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_L2;
			rx_ctx->hsplit_1 = SXE2_RX_HSPLIT_1_SPLIT_L2;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_INNER_L4_MASK) {
		case SXE2_PTYPE_INNER_L4_TCP:
		case SXE2_PTYPE_INNER_L4_UDP:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_TCP_UDP;
			goto l_end;
		case SXE2_PTYPE_INNER_L4_SCTP:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_SCTP;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_INNER_L3_MASK) {
		case SXE2_PTYPE_INNER_L3_IPV4:
		case SXE2_PTYPE_INNER_L3_IPV6:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_IP;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_INNER_L2_MASK) {
		case SXE2_PTYPE_INNER_L2_ETHER:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_SPLIT_L2;
			goto l_end;
		}

		switch (proto_hdr & SXE2_PTYPE_TUNNEL_MASK) {
		case SXE2_PTYPE_TUNNEL_GRENAT:
			rx_ctx->hsplit_type = SXE2_RX_HSPLIT_CONDITION;
			rx_ctx->hsplit_1 = SXE2_RX_HSPLIT_1_SPLIT_ALWAYS;
			goto l_end;
		}

		LOG_ERROR_BDF("Buffer split protocol is not supported\n");
		ret = -EINVAL;
	} else {
		rx_ctx->hsplit_type = SXE2_RX_HSPLIT_NO_SPLIT;
		rx_ctx->hsplit_0 = SXE2_RX_HSPLIT_0_NO_SPLIT;
		rx_ctx->hsplit_1 = SXE2_RX_HSPLIT_1_NO_SPLIT;
	}

l_end:
	return ret;
}

static s32 sxe2_rxq_ctxt_fill(struct sxe2_queue *rxq, struct sxe2_rxq_ctxt *rxq_ctxt)
{
	u8 chain_len = SXE2_RX_BUF_CHAINED_MAX;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	s32 ret = 0;

	memset(rxq_ctxt, 0, sizeof(*rxq_ctxt));

	rxq_ctxt->base_addr =
			cpu_to_le64(rxq->desc.dma >> SXE2_RX_DESC_BASE_ADDR_UNIT);
	rxq_ctxt->depth = cpu_to_le16(rxq->depth);

	rxq_ctxt->dbuff_len = cpu_to_le16(rxq->rx_buf_len >> SXE2_RX_DBUF_LEN_UNIT);

	if (rxq->desc_size == SXE2_DESCRIPTOR_SIZE_16B)
		rxq_ctxt->desc_type = SXE2_DESCRIPTOR_16;
	else
		rxq_ctxt->desc_type = SXE2_DESCRIPTOR_32;

	if (test_bit(SXE2_RXQ_CRC_STRIP_DISABLED, &rxq->flags))
		rxq_ctxt->crc_strip = false;
	else
		rxq_ctxt->crc_strip = true;

	rxq_ctxt->l2tag1_show = 1;

	rxq_ctxt->inner_vlan_strip = 0;

	if (test_bit(SXE2_RXQ_LRO_ENABLED, &rxq->flags)) {
		rxq_ctxt->lro_enable = true;
		if (rxq->max_lro_size)
			rxq_ctxt->lro_desc_max =
			cpu_to_le16(sxe2_rxq_get_lro_desc_num(rxq->max_lro_size,
							      rxq->rx_buf_len));
		else
			rxq_ctxt->lro_desc_max =
					cpu_to_le16(SXE2_RX_LRO_DESC_MAX_16);
		rxq_ctxt->hbuff_len = cpu_to_le16(SXE2_HBUFF_LEN_MIN);
	} else {
		rxq_ctxt->lro_enable = false;
	}

	ret = sxe2_buffer_split_set(rxq, rxq_ctxt);
	if (ret)
		return ret;

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (rxq->xsk_pool)
		chain_len = 1;
#endif

	rxq_ctxt->max_frame_size =
		cpu_to_le16(min_t(u32, rxq->vsi->rxqs.max_frame,
				  (chain_len * (rxq->rx_buf_len & SXE2_RX_DBUF_LEN_MASK))));

	rxq_ctxt->low_desc_waterline = SXE2_RX_DESC_LOW_WATERLINE_1;
	rxq_ctxt->pref_enable = 1;

	if (rxq->vsi->type == SXE2_VSI_T_VF ||
	    rxq->vsi->type == SXE2_VSI_T_DPDK_VF) {
		rxq_ctxt->vfen = true;

		rxq_ctxt->vfid = cpu_to_le16(adapter->vf_ctxt.vfid_base +
					     rxq->vsi->vf_node->vf_idx);
	}
	rxq_ctxt->vsi_id = cpu_to_le16(rxq->vsi->idx_in_dev);
	rxq_ctxt->pfid = rxq->vsi->adapter->pf_idx;

	LOG_INFO_BDF("base addr:0x%llx depth:%u dbuff_len:%u desc_type:%u\t"
		     "crc_strip:%u l2_tag_flag:%u lro_enable:%u lro_max_desc:%u\t"
		     "max_frame_size:%u pfid:%u vfid:%u. chain_len:%d.\n",
		     rxq_ctxt->base_addr, rxq->depth, rxq_ctxt->dbuff_len,
		     rxq_ctxt->desc_type, rxq_ctxt->crc_strip, rxq_ctxt->l2tag1_show,
		     rxq_ctxt->lro_enable, rxq_ctxt->lro_desc_max,
		     rxq_ctxt->max_frame_size, rxq_ctxt->pfid, rxq_ctxt->vfid,
		     chain_len);
	return ret;
}

#if (PAGE_SIZE < 8192)
static u16 sxe2_skb_pad_cal(void)
{
	u16 rx_buf_len;
	u16 value;

	if (SXE2_PAD_RX_LEN_EXCEED_2K)
		rx_buf_len = SXE2_RXBUF_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	else
		rx_buf_len = SXE2_RXBUF_1536;

	rx_buf_len -= NET_IP_ALIGN;

	value = ALIGN(rx_buf_len, PAGE_SIZE / 2);

	value = SKB_WITH_OVERHEAD(value) - rx_buf_len;

	return value;
}
#endif

static u16 sxe2_rx_offset_get(struct sxe2_queue *rxq)
{
	if (test_bit(SXE2_RXQ_BUILD_SKB_ENABLED, &rxq->flags))
		return SXE2_SKB_PAD_VALUE;
#ifdef HAVE_XDP_SUPPORT
	else if (sxe2_xdp_is_enable(rxq->vsi))
		return XDP_PACKET_HEADROOM;
#endif

	return 0;
}

static bool sxe2_rx_page_alloc(struct sxe2_queue *rxq, struct sxe2_rx_buf *buf_info)
{
	struct page *page;
	dma_addr_t dma;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	if (likely(buf_info->page)) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_IRQ("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p\t"
				      "order:%u \t"
				      "dma:%llu pg_offset:%u drv_refcnt:0x%x\t"
				      "reused.\n",
				      rxq->idx_in_vsi, rxq->next_to_use,
				      rxq->next_to_clean, rxq->next_to_alloc,
				      buf_info->page, SXE2_RX_PAGE_ORDER(rxq),
				      buf_info->dma, buf_info->pg_offset,
				      buf_info->drv_refcnt);
		}
#endif
		return true;
	}

	page = dev_alloc_pages(SXE2_RX_PAGE_ORDER(rxq));
	if (unlikely(!page)) {
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_ERROR_IRQ("rxq[%u] ntu:%u ntc:%u nta:%u rx pg_offset:%u\t"
				      "drv_refcnt:0x%x page alloc fail.\n",
				      rxq->idx_in_vsi, rxq->next_to_use,
				      rxq->next_to_clean, rxq->next_to_alloc,
				      buf_info->pg_offset, buf_info->drv_refcnt);
		}
#endif
		return false;
	}

	dma = dma_map_page_attrs(rxq->dev, page, 0, SXE2_RX_PAGE_SIZE(rxq),
				 DMA_FROM_DEVICE, SXE2_RX_DMA_ATTR);

	if (dma_mapping_error(rxq->dev, dma)) {
		__free_pages(page, SXE2_RX_PAGE_ORDER(rxq));
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_ERROR_IRQ("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p\t"
				      "dma:%llu \t"
				      "pg_offset:%u  drv_refcnt:0x%x dma map\t"
				      "fail.\n",
				      rxq->idx_in_vsi, rxq->next_to_use,
				      rxq->next_to_clean, rxq->next_to_alloc, page,
				      dma, buf_info->pg_offset,
				      buf_info->drv_refcnt);
		}
#endif
		return false;
	}

	rxq->stats->rx_stats.rx_page_alloc++;
	buf_info->dma = dma;
	buf_info->page = page;
	buf_info->pg_offset = rxq->rx_offset;

	page_ref_add(page, USHRT_MAX - 1);
	buf_info->drv_refcnt = USHRT_MAX;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_IRQ("rxq[%u] ntu:%u ntc:%u nta:%u rx page:%p order:%u\t"
			      "dma:%llu\t"
			      "pg_offset:%u drv_refcnt:0x%x.\n",
			      rxq->idx_in_vsi, rxq->next_to_use, rxq->next_to_clean,
			      rxq->next_to_alloc, page, SXE2_RX_PAGE_ORDER(rxq), dma,
			      buf_info->pg_offset, buf_info->drv_refcnt);
	}
#endif

	return true;
}

void sxe2_rxq_tail_update(struct sxe2_queue *rxq, u16 new)
{
	u16 prev_ntu = rxq->next_to_use;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	rxq->next_to_use = new;
	rxq->next_to_alloc = new;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u] idx_in_pf:%u ntu:%u nta:%u tail:%u update.\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->next_to_use,
			      rxq->next_to_alloc, new);
	}
#endif

	if (prev_ntu != new) {
		/* in order to force CPU ordering */
		wmb();
		writel(new, rxq->desc.tail);
	}
}

bool sxe2_rx_buffers_alloc(struct sxe2_queue *rxq, u16 cnt)
{
	union sxe2_rx_desc *desc;
	struct sxe2_rx_buf *buf_info;
	u16 ntu = rxq->next_to_use;

	if ((!rxq->netdev && rxq->vsi->type == SXE2_VSI_T_CTRL))
		return false;

	if (!cnt)
		return false;

	desc = SXE2_RX_DESC(rxq, ntu);
	buf_info = &rxq->rx_buf[ntu];

	do {
		if (!sxe2_rx_page_alloc(rxq, buf_info))
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
			desc = SXE2_RX_DESC(rxq, 0);
			buf_info = rxq->rx_buf;
			ntu = 0;
		}

		desc->wb.status0_err = 0;

		cnt--;
	} while (cnt);

	if (rxq->next_to_use != ntu)
		sxe2_rxq_tail_update(rxq, ntu);

	return !!cnt;
}

static s32 sxe2_rx_head_tail_init(struct sxe2_queue *rxq)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	u8 __iomem *head;

	rxq->desc.tail = sxe2_reg_addr_get(hw, SXE2_RXQ_TAIL(rxq->idx_in_pf));
	head = sxe2_reg_addr_get(hw, SXE2_RXQ_HEAD(rxq->idx_in_pf));
	if (IS_ERR(rxq->desc.tail) || IS_ERR(head)) {
		LOG_ERROR_BDF("vsi:%u queue:%u tail addr: %ld head:%ld error.\n",
			      rxq->vsi->idx_in_dev, rxq->idx_in_vsi,
			      PTR_ERR(rxq->desc.tail), PTR_ERR(head));
		return -EFAULT;
	}

	writel(0, rxq->desc.tail);
	writel(0, head);
	LOG_INFO_BDF("rxq:%u head/tail init done head:0x%x tail:0x%x.\n",
		     rxq->idx_in_pf, readl(head), readl(rxq->desc.tail));

	return 0;
}

static void sxe2_rxq_lro_ctrl(struct sxe2_queue *rxq)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2_VSI_FLAG_LRO_ENABLE, rxq->vsi->flags)) {
		set_bit(SXE2_RXQ_LRO_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u idx_in_pf:%u lro\t"
			     "enabled.\n",
			     rxq->vsi->idx_in_dev, rxq->vsi->type, rxq->idx_in_vsi,
			     rxq->idx_in_pf);
	} else {
		clear_bit(SXE2_RXQ_LRO_ENABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u idx_in_pf:%u lro\t"
			     "disabled.\n",
			     rxq->vsi->idx_in_dev, rxq->vsi->type, rxq->idx_in_vsi,
			     rxq->idx_in_pf);
	}
}

static void sxe2_rxq_build_skb_ctrl(struct sxe2_vsi *vsi, struct sxe2_queue *rxq)
{
	if (!vsi->netdev ||
	    test_bit(SXE2_FLAG_LEGACY_RX_ENABLE, vsi->adapter->flags))
		clear_bit(SXE2_RXQ_BUILD_SKB_ENABLED, &rxq->flags);
	else
		set_bit(SXE2_RXQ_BUILD_SKB_ENABLED, &rxq->flags);
}

#ifdef HAVE_XDP_BUFF_RXQ
#ifdef HAVE_AF_XDP_ZC_SUPPORT
STATIC s32 sxe2_rxq_xdp_cfg(struct sxe2_queue *rxq)
{
	s32 err;
	struct sxe2_vsi *vsi = rxq->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (rxq->vsi->type == SXE2_VSI_T_PF) {
		if (!xdp_rxq_info_is_reg(&rxq->xdp_rxq))
			(void)xdp_rxq_info_reg(&rxq->xdp_rxq, rxq->netdev,
					       rxq->idx_in_vsi,
					       rxq->irq_data->napi.napi_id);

		rxq->xsk_pool = sxe2_xsk_pool(rxq);
		if (rxq->xsk_pool) {
			xdp_rxq_info_unreg_mem_model(&rxq->xdp_rxq);

			rxq->rx_buf_len =
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
					xsk_pool_get_rx_frame_size(rxq->xsk_pool);
#else
					rxq->xsk_pool->chunk_size_nohr -
					XDP_PACKET_HEADROOM;
#endif
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
			err = xdp_rxq_info_reg_mem_model(&rxq->xdp_rxq,
							 MEM_TYPE_XSK_BUFF_POOL,
							 NULL);
			if (err)
				return err;
			xsk_pool_set_rxq_info(rxq->xsk_pool, &rxq->xdp_rxq);

			LOG_DEV_INFO("Registered XDP mem model\t"
				     "MEM_TYPE_XSK_BUFF_POOL on Rx rxq %d\n",
				     rxq->idx_in_vsi);
#else
			rxq->zca.free = sxe2_zca_free;
			err = xdp_rxq_info_reg_mem_model(&rxq->xdp_rxq,
							 MEM_TYPE_ZERO_COPY,
							 &rxq->zca);
			if (err)
				return err;

			LOG_DEV_INFO("Registered XDP mem model MEM_TYPE_ZERO_COPY\t"
				     "on Rx rxq %d\n",
				     rxq->idx_in_vsi);
#endif
		} else {
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
			rxq->zca.free = NULL;
#endif
			if (!xdp_rxq_info_is_reg(&rxq->xdp_rxq))
				(void)xdp_rxq_info_reg(&rxq->xdp_rxq, rxq->netdev,
						       rxq->idx_in_vsi,
						       rxq->irq_data->napi.napi_id);

			err = xdp_rxq_info_reg_mem_model(&rxq->xdp_rxq,
							 MEM_TYPE_PAGE_SHARED, NULL);
			if (err)
				return err;
		}
	}

	return 0;
}
#endif
#endif

static void sxe2_rxq_rxfc_ctrl(struct sxe2_queue *rxq)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2_VSI_FLAG_RXFCS_ENABLE, rxq->vsi->flags)) {
		set_bit(SXE2_RXQ_CRC_STRIP_DISABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u idx_in_pf:%u rxfcs\t"
			     "enabled.\n",
			     rxq->vsi->idx_in_dev, rxq->vsi->type, rxq->idx_in_vsi,
			     rxq->idx_in_pf);
	} else {
		clear_bit(SXE2_RXQ_CRC_STRIP_DISABLED, &rxq->flags);
		LOG_INFO_BDF("vsi:%u type:%u rxq idx_in_vsi:%u idx_in_pf:%u rxfcs\t"
			     "disabled.\n",
			     rxq->vsi->idx_in_dev, rxq->vsi->type, rxq->idx_in_vsi,
			     rxq->idx_in_pf);
	}
}

void sxe2_rxq_feature_cfg(struct sxe2_queue *rxq)
{
	struct sxe2_vsi *vsi = rxq->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	rxq->rx_buf_len = vsi->rxqs.rx_buf_len;

	sxe2_rxq_lro_ctrl(rxq);

	sxe2_rxq_rxfc_ctrl(rxq);

	sxe2_rxq_build_skb_ctrl(vsi, rxq);

	rxq->rx_offset = sxe2_rx_offset_get(rxq);

	LOG_DEBUG_BDF("vsi:%u type:%u rxq[%u][%u] rx_offset:%u rx_buf_len:%u.\n",
		      vsi->idx_in_dev, vsi->type, rxq->idx_in_vsi, rxq->idx_in_pf,
		      rxq->rx_offset, rxq->rx_buf_len);
}

STATIC s32 sxe2_fwc_rxq_ctxt_cfg(struct sxe2_adapter *adapter,
				 struct sxe2_fwc_cfg_rxq_req *req)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RXQ_CFG, req, sizeof(*req), NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rxq cfg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 __sxe2_rxq_ctxt_cfg(struct sxe2_queue *rxq)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = rxq->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_fwc_cfg_rxq_req req = {0};

	req.pf_idx = adapter->pf_idx;
	req.idx_in_dev = cpu_to_le16(rxq->idx_in_pf +
				     adapter->q_ctxt.rxq_base_idx_in_dev);

	ret = sxe2_rxq_ctxt_fill(rxq, &req.rxq_ctxt);
	if (ret) {
		LOG_ERROR_BDF("rxq idx_in_pf:%u context fill failed.(err:%d)\n",
			      rxq->idx_in_pf, ret);
		return ret;
	}

	ret = sxe2_fwc_rxq_ctxt_cfg(adapter, &req);
	if (ret) {
		LOG_ERROR_BDF("rxq idx_in_pf:%u context cfg failed.(err:%d)\n",
			      rxq->idx_in_pf, ret);
		return ret;
	}

	LOG_INFO_BDF("pf_idx:%u rxq idx_in_dev:%u context cfg success.\n",
		     req.pf_idx, req.idx_in_dev);

	return sxe2_rx_head_tail_init(rxq);
}

s32 sxe2_rxqs_stop(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &vsi->adapter->hw;
	u16 reg_idx;

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		reg_idx = vsi->rxqs.q[i]->idx_in_pf;
		(void)sxe2_rxq_ctrl_set(adapter, vsi->rxqs.q[i], false, false);
	}

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		reg_idx = vsi->rxqs.q[i]->idx_in_pf;
		ret = sxe2_err_code_trans_hw(sxe2_hw_rxq_status_check(hw,
								      reg_idx,
								      false));
		if (ret) {
			LOG_ERROR_BDF("vsi:%u rxq[%u][%u] set status:%u timeout.\n",
				      vsi->idx_in_dev, i, reg_idx, false);
			break;
		}
	}

	return ret;
}

#ifdef SXE2_UNSUPPORT
static s32 sxe2_rx_fb_hw_configure(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_cmd_params cmd;
	struct sxe2_adapter *adapter = vsi->adapter;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RX_FB, NULL, 0, NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("rx frame buffer configure fail.(err:%d)\n", ret);

	return ret;
}
#endif

s32 sxe2_rxq_ctxt_cfg(struct sxe2_queue *rxq)
{
	s32 ret;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	u32 cur_val = SXE2_REG_READ(&adapter->hw, SXE2_RXQ_CTRL(rxq->idx_in_pf));

	SXE2_BUG_ON((cur_val != SXE2_REG_INVALID_VALUE) &&
		    (!!(cur_val & SXE2_RXQ_CTRL_STATUS_ACTIVE) == true));

	ret = __sxe2_rxq_ctxt_cfg(rxq);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u rxq:%u cfg failed.(err:%d)\n",
			      rxq->vsi->idx_in_dev, rxq->idx_in_vsi, ret);
		return ret;
	}

	(void)sxe2_rxq_ctrl_set(adapter, rxq, true, false);

	return ret;
}

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
STATIC s32 sxe2_alloc_rx_xsk_cfg_bufs(struct sxe2_queue *rxq, u16 count)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	bool ok;

	if (!xsk_buff_can_alloc(rxq->xsk_pool, count)) {
		LOG_DEV_WARN("XSK buffer pool does not provide enough\n"
			     "addresses to fill %d buffers on Rx ring %d\n",
			     count, rxq->idx_in_vsi);
		LOG_DEV_WARN("Change Rx ring/fill queue size to avoid performance\t"
			     "issues\n");
		return 0;
	}

	ok = sxe2_alloc_rx_bufs_zc(rxq, count);
	if (!ok) {
		LOG_DEV_INFO("Failed to allocate some buffers on XSK buffer\n"
			     "pool enabled Rx ring %d (pf_q %d)\n",
			     rxq->idx_in_vsi, rxq->idx_in_pf);
	}

	return 0;
}
#endif

s32 sxe2_vsi_cfg_rxq(struct sxe2_queue *rxq)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;

	sxe2_rxq_feature_cfg(rxq);

#ifdef HAVE_XDP_BUFF_RXQ
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	ret = sxe2_rxq_xdp_cfg(rxq);
	if (ret) {
		LOG_ERROR_BDF("rxq[%u] xdp cfg failed.(err:%d)\n", rxq->idx_in_vsi,
			      ret);
		goto l_err;
	}
#endif
#endif

	ret = sxe2_rxq_ctxt_cfg(rxq);
	if (ret) {
		LOG_ERROR_BDF("rxq[%u] context cfg failed.(err:%d)\n",
			      rxq->idx_in_pf, ret);
		goto l_err;
	}

#ifdef HAVE_AF_XDP_ZC_SUPPORT
	if (rxq->xsk_pool) {
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		(void)sxe2_alloc_rx_xsk_cfg_bufs(rxq, SXE2_DESC_IDLE(rxq));
#else
		(void)sxe2_alloc_rx_bufs_slow_zc(rxq, SXE2_DESC_IDLE(rxq));
#endif
		goto l_err;
	}
#endif
	(void)sxe2_rx_buffers_alloc(rxq, SXE2_DESC_IDLE(rxq));

l_err:
	return ret;
}

s32 sxe2_rx_hw_cfg(struct sxe2_vsi *vsi)
{
	s32 ret;
	u16 i;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (vsi->netdev && vsi->type == SXE2_VSI_T_PF) {
		sxe2_set_rx_mode(vsi->netdev);
		ret = sxe2_vlan_cfg(vsi);
		if (ret) {
			LOG_ERROR_BDF("vsi:%u type:%u vlan cfg failed.(err:%d)\n",
				      vsi->idx_in_dev, vsi->type, ret);
			return ret;
		}
	}

	sxe2_frame_size_set(vsi);

#ifdef SXE2_UNSUPPORT
	ret = sxe2_rx_fb_hw_configure(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u type:%u rx frame buffer cfg failed.(err:%d)\n",
			      vsi->idx_in_dev, vsi->type, ret);
		return ret;
	}
#endif

	sxe2_for_each_vsi_rxq(vsi, i)
	{
		ret = sxe2_vsi_cfg_rxq(vsi->rxqs.q[i]);
		if (ret)
			goto l_err;
	}

	return ret;

l_err:
	while (i--) {
		(void)sxe2_rxq_ctrl_set(adapter, vsi->rxqs.q[i], false, false);
		sxe2_rx_ring_clean(vsi->rxqs.q[i]);
	}
	return ret;
}

s32 sxe2_rx_cfg(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret;

	ret = sxe2_rx_rings_alloc(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u type:%u rx ring resource alloc\t"
			      "failed.(err:%d)\n",
			      vsi->idx_in_dev, vsi->type, ret);
		goto l_out;
	}

	ret = sxe2_rx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u type:%u rx queue cfg failed.(err:%d)\n",
			      vsi->idx_in_dev, vsi->type, ret);
		goto l_rxq_cfg_failed;
	}

	LOG_INFO_BDF("vsi:%u type:%u rx queue configure done.\n", vsi->idx_in_dev,
		     vsi->type);

	return 0;

l_rxq_cfg_failed:
	sxe2_rx_rings_free(vsi);
l_out:
	return ret;
}

static void sxe2_rx_first_pkt_sync(struct sxe2_queue *rxq, struct sk_buff *skb)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;

	if (test_bit(SXE2_RXQ_BUILD_SKB_ENABLED, &rxq->flags)) {
		unsigned long mask = (unsigned long)SXE2_RX_PAGE_SIZE(rxq) - 1;
		unsigned long offset = (unsigned long)(skb->data) & mask;

		dma_sync_single_range_for_cpu(rxq->dev, SXE2_SKB_PRIV(skb)->dma,
					      offset, skb_headlen(skb),
					      DMA_FROM_DEVICE);
	} else {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[0];

		dma_sync_single_range_for_cpu(rxq->dev, SXE2_SKB_PRIV(skb)->dma,
					      skb_frag_off(frag),
					      skb_frag_size(frag), DMA_FROM_DEVICE);
	}

	if (unlikely(SXE2_SKB_PRIV(skb)->page_released)) {
		dma_unmap_page_attrs(rxq->dev, SXE2_SKB_PRIV(skb)->dma,
				     SXE2_RX_PAGE_SIZE(rxq), DMA_FROM_DEVICE,
				     SXE2_RX_DMA_ATTR);
	}

	LOG_DEBUG_BDF("rxq[%u][%u] skb:%p nr_frags:%u dma:%llu sync first packet\n",
		      rxq->idx_in_vsi, rxq->idx_in_pf, skb,
		      skb_shinfo(skb)->nr_frags, SXE2_SKB_PRIV(skb)->dma);
}

static struct sxe2_rx_buf *sxe2_rx_buffer_get(struct sxe2_queue *rxq,
					      union sxe2_rx_desc *rx_desc,
					      const u32 size, s32 *pg_cnt)
{
	struct sxe2_rx_buf *rx_buffer = &rxq->rx_buf[rxq->next_to_clean];
	struct sk_buff *skb = rx_buffer->skb;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	*pg_cnt =
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
			page_count(rx_buffer->page);
#else
			0;
#endif

	prefetchw(rx_buffer->page);

	if (!size)
		return rx_buffer;

	if (sxe2_is_non_eop(rxq, rx_desc)) {
		if (!skb)
			goto l_skip_sync;
	} else {
		if (skb)
			sxe2_rx_first_pkt_sync(rxq, skb);
	}

	dma_sync_single_range_for_cpu(rxq->dev, rx_buffer->dma, rx_buffer->pg_offset,
				      size, DMA_FROM_DEVICE);

l_skip_sync:
	rx_buffer->drv_refcnt--;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] ntc:%u pkt len:%u skb:%p \t"
			      "drv_refcnt:0x%x pg_offset:%u rx_buffer[%u]:%p get\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->next_to_clean,
			      size, skb, rx_buffer->drv_refcnt, rx_buffer->pg_offset,
			      rxq->next_to_clean, rx_buffer);
	}
#endif

	return rx_buffer;
}

STATIC enum pkt_hash_types sxe2_hash_type_get(u16 ptype)
{
	struct sxe2_rx_ptype_info ptype_info = sxe2_rx_ptype_parse(ptype);

	if (!ptype_info.known)
		return PKT_HASH_TYPE_NONE;
	if (ptype_info.hash_layer == SXE2_PTYPE_PAYLOAD_LAYER_PAY4)
		return PKT_HASH_TYPE_L4;
	if (ptype_info.hash_layer == SXE2_PTYPE_PAYLOAD_LAYER_PAY3)
		return PKT_HASH_TYPE_L3;
	if (ptype_info.outer_ip == SXE2_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

static void sxe2_lro_stats_update(struct sxe2_queue *rxq, struct sk_buff *skb)
{
	u32 hdr_len;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	if (!SXE2_SKB_PRIV(skb)->lro_cnt) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("rxq[%u][%u] not lro packet\n",
				      rxq->idx_in_vsi, rxq->idx_in_pf);
		}
#endif
		return;
	}

	rxq->stats->rx_stats.rx_lro_count += SXE2_SKB_PRIV(skb)->lro_cnt - 1;
	rxq->stats->rx_stats.rx_lro_packets++;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] lro deal\n", rxq->idx_in_vsi,
			      rxq->idx_in_pf);
	}
#endif

	hdr_len = skb_headlen(skb);

	skb_shinfo(skb)->gso_size = (u16)DIV_ROUND_UP((skb->len - hdr_len),
						      SXE2_SKB_PRIV(skb)->lro_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	rxq->stats->rx_stats.rx_lro_bytes += skb->len;

	SXE2_SKB_PRIV(skb)->lro_cnt = 0;
}

STATIC inline bool sxe2_hash_from_arfs(u16 flow_id)
{
	return (flow_id >= SXE2_FNAV_FLOW_TYPE_ARFS_IPV4_TCP) &&
	       (flow_id <= SXE2_FNAV_FLOW_TYPE_ARFS_IPV6_UDP);
}

STATIC void sxe2_skb_hash_set(struct sxe2_queue *rxq, union sxe2_rx_desc *rx_desc,
			      struct sk_buff *skb, u16 ptype)
{
	u32 rss_hash_vld;
	u32 fnav_vld;
	u16 flow_id;
	u32 hash;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	if (!(rxq->netdev->features & NETIF_F_RXHASH)) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("rxq[%u][%u] rss hash offload off netdev\t"
				      "feature:0x%llx.\n",
				      rxq->idx_in_vsi, rxq->idx_in_pf,
				      rxq->netdev->features);
		}
#endif
		return;
	}

	rss_hash_vld = (le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) >>
			SXE2_RX_DESC_STATUS2_RSS_VLD) &
		       SXE2_RX_DESC_RSS_VLD_MASK;
	fnav_vld = rx_desc->wb.rxdid_src & SXE2_RX_DESC_FD_VLD_MASK;
	flow_id = le16_to_cpu(rx_desc->wb.flow_id);
	if (!rss_hash_vld && !(fnav_vld && sxe2_hash_from_arfs(flow_id))) {
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("rxq[%u][%u] rss_vld:0x%x, fnav_vld:0x%x,\t"
				      "flow_id:%u\n",
				      rxq->idx_in_vsi, rxq->idx_in_pf, rss_hash_vld,
				      fnav_vld, flow_id);
		}
#endif
		return;
	}

	if (rss_hash_vld)
		hash = le32_to_cpu(rx_desc->wb.filter_status);
	else
		hash = le32_to_cpu(rx_desc->wb.fd_filter_id);

	skb_set_hash(skb, hash, sxe2_hash_type_get(ptype));
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] hash:0x%x ptype:%u, rss_vld:0x%x,\n"
			      "fnav_vld:0x%x, flow_id:%u\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, hash, ptype,
			      rss_hash_vld, fnav_vld, flow_id);
	}
#endif
}

static void sxe2_rx_csum_check(struct sxe2_queue *rxq, union sxe2_rx_desc *rx_desc,
			       struct sk_buff *skb, u16 ptype)
{
	struct sxe2_rx_ptype_info ptype_info;
	u16 status0_err;
	bool ipv4 = 0;
	bool ipv6 = 0;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	if (!(rxq->netdev->features & NETIF_F_RXCSUM)) {
		rxq->stats->rx_stats.rx_csum_none++;
#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			LOG_DEBUG_BDF("rxq[%u][%u] rx csum offload off \t"
				      "netdev feature:0x%llx.\n",
				      rxq->idx_in_vsi, rxq->idx_in_pf,
				      rxq->netdev->features);
		}
#endif
		return;
	}

	status0_err = le16_to_cpu(rx_desc->wb.status0_err);
	ptype_info = sxe2_rx_ptype_parse(ptype);

	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	if (!(status0_err & BIT(SXE2_RX_DESC_STATUS0_L3L4_P)) ||
	    !(ptype_info.known && ptype_info.outer_ip))
		goto l_out;

	ipv4 = (ptype_info.outer_ip == SXE2_PTYPE_OUTER_IP) &&
	       (ptype_info.outer_ip_ver == SXE2_PTYPE_OUTER_IPV4);

	ipv6 = (ptype_info.outer_ip == SXE2_PTYPE_OUTER_IP) &&
	       (ptype_info.outer_ip_ver == SXE2_PTYPE_OUTER_IPV6);

	if (ipv4 && (status0_err &
		     (BIT(SXE2_RX_DESC_ERROR_IPE) | BIT(SXE2_RX_DESC_ERROR_EIPE))))
		goto checksum_fail;

	if (ipv6 && (le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) &
		     (BIT(SXE2_RX_DESC_STATUS2_IPV6EXADD))))
		goto l_out;

	if (status0_err & BIT(SXE2_RX_DESC_ERROR_L4E))
		goto checksum_fail;

	if (rx_desc->wb.rxdid_src & BIT(SXE2_RX_DESC_EUDPE))
		goto checksum_fail;

	if (ptype_info.tunnel_type >= SXE2_PTYPE_TUNNEL_IP_GRENAT) {
		skb->csum_level = 1;
		rxq->stats->rx_stats.rx_csum_unnecessary_inner++;
	}

	switch (ptype_info.inner_prot) {
	case SXE2_PTYPE_INNER_PROT_UDP:
	case SXE2_PTYPE_INNER_PROT_TCP:
	case SXE2_PTYPE_INNER_PROT_SCTP:
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
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] rxcsum offload:0x%llx  status0_err:0x%x\t"
			      "ptype:0x%x ptype_info:0x%x pktl_hdrl_status2:0x%x \t"
			      "rxdid_src:%u ipv4:%u ipv6:%u ip_summed:%d\t"
			      "csum_level:%d \t"
			      "rx_csum_err:0x%llx\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf,
			      rxq->netdev->features & NETIF_F_RXCSUM, status0_err,
			      ptype, *(u32 *)&ptype_info,
			      le32_to_cpu(rx_desc->wb.pktl_hdrl_status2),
			      rx_desc->wb.rxdid_src, ipv4, ipv6, skb->ip_summed,
			      skb->csum_level, rxq->stats->rx_stats.rx_csum_err);
	}
#endif
	;
}

static void sxe2_skb_hwtstamps_set(struct sxe2_queue *rxq,
				   union sxe2_rx_desc *rx_desc, struct sk_buff *skb)
{
	sxe2_ptp_rxts_request(rxq, (union sxe2_rx_desc_1588 *)rx_desc, skb);
}

static inline u16 sxe2_vlan_tag_get(union sxe2_rx_desc *rx_desc)
{
	if (le16_to_cpu(rx_desc->wb.status0_err) &
	    BIT(SXE2_RX_DESC_STATUS0_L2TAG1_P))
		return le16_to_cpu(rx_desc->wb.l2tag1);

	return 0;
}

static void sxe2_skb_vlan_tag_put(struct sxe2_queue *rxq,
				  union sxe2_rx_desc *rx_desc, struct sk_buff *skb)
{
	netdev_features_t features = rxq->netdev->features;
	u16 vlan_tag = sxe2_vlan_tag_get(rx_desc);
	bool non_zero_vlan = !!(vlan_tag & VLAN_VID_MASK);

	if ((features & NETIF_F_HW_VLAN_CTAG_RX) && non_zero_vlan) {
		rxq->stats->rx_stats.rx_vlan_strip++;
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tag);
	} else if ((features & NETIF_F_HW_VLAN_STAG_RX) && non_zero_vlan) {
		rxq->stats->rx_stats.rx_vlan_strip++;
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), vlan_tag);
	}
}

#ifdef HAVE_MACSEC_SUPPORT
static bool sxe2_rx_desc_macsec_check(union sxe2_rx_desc *rx_desc)
{
	return (le32_to_cpu(rx_desc->wb.status0_err) >>
		SXE2_RX_DESC_MACSEC_OFFLOAD) &
	       0x1;
}
#endif

static bool sxe2_rx_desc_ipsec_check(union sxe2_rx_desc *rx_desc)
{
	return (le32_to_cpu(rx_desc->wb.status_lrocnt_fdpf_id) >>
		SXE2_RX_DESC_IPSEC_PKT) &
	       0x1;
}

void sxe2_skb_field_fill(struct sxe2_queue *rxq, union sxe2_rx_desc *rx_desc,
			 struct sk_buff *skb, u16 ptype)
{
	sxe2_lro_stats_update(rxq, skb);

	sxe2_skb_hash_set(rxq, rx_desc, skb, ptype);

	skb->protocol = eth_type_trans(skb, rxq->netdev);

	sxe2_rx_csum_check(rxq, rx_desc, skb, ptype);

	sxe2_skb_hwtstamps_set(rxq, rx_desc, skb);

#ifdef HAVE_MACSEC_SUPPORT
	if (sxe2_rx_desc_macsec_check(rx_desc))
		sxe2_macsec_rx(rxq, skb);
#endif

	if (sxe2_rx_desc_ipsec_check(rx_desc))
		sxe2_ipsec_rx(rxq, rx_desc, skb, ptype);

	sxe2_skb_vlan_tag_put(rxq, rx_desc, skb);

	if (netif_is_macvlan(rxq->netdev))
		macvlan_count_rx((const struct macvlan_dev *)netdev_priv(rxq->netdev),
				 skb->len + ETH_HLEN, true, false);
}

STATIC void sxe2_rx_page_reuse(struct sxe2_queue *rxq, struct sxe2_rx_buf *old_buff)
{
	struct sxe2_rx_buf *new_buff;
	u16 nta = rxq->next_to_alloc;

	new_buff = &rxq->rx_buf[nta];

	nta++;
	rxq->next_to_alloc = (nta < rxq->depth) ? nta : 0;

	new_buff->dma = old_buff->dma;
	new_buff->page = old_buff->page;
	new_buff->pg_offset = old_buff->pg_offset;
	new_buff->drv_refcnt = old_buff->drv_refcnt;
}

static bool sxe2_page_is_reusable(struct sxe2_rx_buf *rx_buf, int pg_refcnt)
{
	u32 drv_refcnt = rx_buf->drv_refcnt;
	struct page *page = rx_buf->page;

	if (!dev_page_is_reusable(page))
		return false;

#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	if (unlikely((pg_refcnt - drv_refcnt) > 1))
		return false;
#else
	if (rx_buf->pg_offset > SXE2_LAST_OFFSET)
		return false;
#endif

	if (unlikely(drv_refcnt == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		rx_buf->drv_refcnt = USHRT_MAX;
	}

	return true;
}

static void sxe2_rx_buffer_put(struct sxe2_queue *rxq, union sxe2_rx_desc *rx_desc,
			       struct sxe2_rx_buf *rx_buf, struct sk_buff *skb,
			       int pg_refcnt)
{
	u16 ntc = rxq->next_to_clean + 1;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif
	u8 lro_cnt = sxe2_rx_desc_lro_cnt(rxq, rx_desc);

	ntc = (ntc < rxq->depth) ? ntc : 0;
	rxq->next_to_clean = ntc;

	if (!rx_buf)
		return;

	if (lro_cnt)
		SXE2_SKB_PRIV(skb)->lro_cnt += lro_cnt;

	if (sxe2_page_is_reusable(rx_buf, pg_refcnt)) {
		sxe2_rx_page_reuse(rxq, rx_buf);
	} else {
		if (!IS_ERR(skb) && SXE2_SKB_PRIV(skb)->dma == rx_buf->dma)
			SXE2_SKB_PRIV(skb)->page_released = true;
		else
			dma_unmap_page_attrs(rxq->dev, rx_buf->dma,
					     SXE2_RX_PAGE_SIZE(rxq), DMA_FROM_DEVICE,
					     SXE2_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_buf->page, rx_buf->drv_refcnt);
	}

	rx_buf->page = NULL;
	rx_buf->skb = NULL;

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] ntc:%u nta:%u skb:%p nr_frags:%u \t"
			      "lro_cnt:%u rx_buffer[%u]:%p put\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->next_to_clean,
			      rxq->next_to_alloc, skb, skb_shinfo(skb)->nr_frags,
			      SXE2_SKB_PRIV(skb)->lro_cnt, ntc - 1, rx_buf);
	}
#endif
}

STATIC void sxe2_xdp_rx_buffer_put(struct sxe2_queue *rxq,
				   struct sxe2_rx_buf *rx_buf, int pg_refcnt)
{
	u16 ntc = rxq->next_to_clean + 1;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif

	ntc = (ntc < rxq->depth) ? ntc : 0;
	rxq->next_to_clean = ntc;

	if (!rx_buf)
		return;

	if (sxe2_page_is_reusable(rx_buf, pg_refcnt)) {
		sxe2_rx_page_reuse(rxq, rx_buf);
	} else {
		dma_unmap_page_attrs(rxq->dev, rx_buf->dma, SXE2_RX_PAGE_SIZE(rxq),
				     DMA_FROM_DEVICE, SXE2_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_buf->page, rx_buf->drv_refcnt);
	}

	rx_buf->page = NULL;
	rx_buf->skb = NULL;
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] ntc:%u nta:%u rx_buffer[%u]:%p put\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->next_to_clean,
			      rxq->next_to_alloc, ntc - 1, rx_buf);
	}
#endif
}

static void sxe2_rx_pg_offset_update(struct sxe2_rx_buf *rx_buf, u32 size)
{
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	rx_buf->pg_offset ^= size;
#else
	rx_buf->pg_offset += size;
#endif
}

static void sxe2_skb_frag_add(struct sxe2_queue *rxq, struct sxe2_rx_buf *rx_buf,
			      struct sk_buff *skb, u32 size)
{
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	u32 truesize = SXE2_RX_PAGE_SIZE(rxq) / 2;
#else
	u32 truesize = SKB_DATA_ALIGN(size + rxq->rx_offset);
#endif

	if (!size)
		return;

	skb_add_rx_frag(skb, (int)skb_shinfo(skb)->nr_frags, rx_buf->page,
			(int)rx_buf->pg_offset, (int)size, truesize);

	sxe2_rx_pg_offset_update(rx_buf, truesize);
}

static struct sk_buff *sxe2_skb_build(struct sxe2_queue *rxq,
				      struct sxe2_rx_buf *rx_buf,
				      struct xdp_buff *xdp,
				      union sxe2_rx_desc *rx_desc)
{
#ifdef HAVE_XDP_BUFF_DATA_META
	u8 metasize = (u8)(xdp->data - xdp->data_meta);
#endif
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	u32 truesize = SXE2_RX_PAGE_SIZE(rxq) / 2;
#else
	u32 truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
		       SKB_DATA_ALIGN(xdp->data_end - xdp->data_hard_start);
#endif
	struct sk_buff *skb;

#ifdef HAVE_XDP_BUFF_DATA_META
	net_prefetch(xdp->data_meta);
#else
	net_prefetch(xdp->data);
#endif

	skb = napi_build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx_in_vsi);
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	(void)__skb_put(skb, (u32)(xdp->data_end - xdp->data));
#ifdef HAVE_XDP_BUFF_DATA_META
	if (metasize)
		skb_metadata_set(skb, metasize);
#endif
	if (sxe2_is_non_eop(rxq, rx_desc))
		SXE2_SKB_PRIV(skb)->dma = rx_buf->dma;

	sxe2_rx_pg_offset_update(rx_buf, truesize);

	return skb;
}

static struct sk_buff *sxe2_skb_construct(struct sxe2_queue *rxq,
					  struct sxe2_rx_buf *rx_buf,
					  struct xdp_buff *xdp,
					  union sxe2_rx_desc *rx_desc)
{
	u32 metasize = (u32)(xdp->data - xdp->data_meta);
	u32 size = (u32)(xdp->data_end - xdp->data);
	u32 headlen;
	struct sk_buff *skb;

	net_prefetch(xdp->data_meta);

	skb = __napi_alloc_skb(&rxq->irq_data->napi, SXE2_RX_HDR_SIZE + metasize,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx_in_vsi);
	headlen = size;
	if (headlen > SXE2_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data, SXE2_RX_HDR_SIZE);

	memcpy(__skb_put(skb, headlen + metasize), xdp->data_meta,
	       ALIGN(headlen + metasize, sizeof(long)));

	if (metasize) {
#ifdef HAVE_XDP_BUFF_DATA_META
		skb_metadata_set(skb, (u8)metasize);
#endif
		(void)__skb_pull(skb, metasize);
	}

	size -= headlen;
	if (size) {
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
		u32 truesize = SXE2_RX_PAGE_SIZE(rxq) / 2;
#else
		u32 truesize = SKB_DATA_ALIGN(size);
#endif
		if (sxe2_is_non_eop(rxq, rx_desc))
			SXE2_SKB_PRIV(skb)->dma = rx_buf->dma;

		skb_add_rx_frag(skb, 0, rx_buf->page,
				(int)(rx_buf->pg_offset + headlen), (int)size,
				truesize);

		sxe2_rx_pg_offset_update(rx_buf, truesize);
	} else {
		rx_buf->drv_refcnt++;
	}

	return skb;
}

#ifdef HAVE_XDP_BUFF_FRAME_SZ
static u32 sxe2_rx_frame_truesize(struct sxe2_queue *rxq, u32 __maybe_unused size)
{
	u32 truesize;

#if (PAGE_SIZE < 8192)
	truesize = SXE2_RX_PAGE_SIZE(rxq) / 2;
#else
	truesize = rxq->rx_offset ? SKB_DATA_ALIGN(rxq->rx_offset + size) +
						    SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
				  : SKB_DATA_ALIGN(size);
#endif
	return truesize;
}
#endif

#ifdef HAVE_XDP_SUPPORT
static s32 sxe2_xdp_run(struct sxe2_queue *rxq, struct xdp_buff *xdp,
			struct bpf_prog *xdp_prog)
{
	s32 err, result;
	u32 act;
	struct sxe2_queue *xdp_ring;
	u64 rx_bytes = (u64)(xdp->data_end - xdp->data);
	struct sxe2_rxq_xdp_stats *xdp_stats = &rxq->stats->rx_stats.xdp_stats;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#endif
	u32 queue_index = (smp_processor_id() %
			   rxq->vsi->num_xdp_txq);

	xdp_stats->rx_xdp_pkts++;
	xdp_stats->rx_xdp_bytes += rx_bytes;

	act = bpf_prog_run_xdp(xdp_prog, xdp);
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
		LOG_DEBUG_BDF("bpf_prog_run_xdp ret:%d\n", act);

#endif

	switch (act) {
	case XDP_PASS:
		xdp_stats->rx_xdp_pass++;
		result = SXE2_XDP_PASS;
		break;

	case XDP_TX:
		xdp_ring = rxq->vsi->xdp_rings.q[queue_index];
		result = sxe2_xmit_xdp_buff(xdp, xdp_ring);
		if (result == SXE2_XDP_TX)
			xdp_stats->rx_xdp_tx_xmit++;
		else
			xdp_stats->rx_xdp_tx_xmit_fail++;
		break;

	case XDP_REDIRECT:
		err = xdp_do_redirect(rxq->netdev, xdp, xdp_prog);
		result = !err ? SXE2_XDP_REDIR : SXE2_XDP_CONSUMED;
		if (err)
			xdp_stats->rx_xdp_redirect_fail++;
		else
			xdp_stats->rx_xdp_redirect++;

		break;

	default:
		bpf_warn_invalid_xdp_action(rxq->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		xdp_stats->rx_xdp_unknown++;
		trace_xdp_exception(rxq->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		result = SXE2_XDP_CONSUMED;
		xdp_stats->rx_xdp_drop++;
		break;
	}

	return result;
}
#endif

void sxe2_xdp_tail_update(struct sxe2_queue *rxq, u32 xdp_res)
{
	u16 tx_qid;
	struct sxe2_queue *xdp_ring = NULL;

	if (xdp_res & SXE2_XDP_REDIR)
		xdp_do_flush_map();

	if (xdp_res & SXE2_XDP_TX) {
		tx_qid = rxq->idx_in_vsi;
		if (tx_qid >= rxq->vsi->num_xdp_txq)
			tx_qid = (u16)(tx_qid - rxq->vsi->num_xdp_txq);

		xdp_ring = rxq->vsi->xdp_rings.q[tx_qid];
		/* in order to force CPU ordering */
		wmb();
		writel(xdp_ring->next_to_use, xdp_ring->desc.tail);
	}
}

int sxe2_rxq_irq_clean(struct sxe2_queue *rxq, int budget)
{
	u32 total_rx_bytes = 0;
	u32 total_rx_pkts = 0;
	u16 idle = SXE2_DESC_IDLE(rxq);
	u32 offset = rxq->rx_offset;
	struct sk_buff *skb = rxq->skb;
	u32 xdp_res = 0;
	u32 xdp_xmit = 0;
	struct bpf_prog *xdp_prog = NULL;
	struct xdp_buff xdp;
	bool failure;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
#ifdef SXE2_CFG_DEBUG
#define SXE2_LOG_STR_LEN 32
	char str[SXE2_LOG_STR_LEN] = {0};
#endif
#ifdef HAVE_XDP_BUFF_RXQ
	xdp.rxq = &rxq->xdp_rxq;
#endif
#ifdef HAVE_XDP_BUFF_FRAME_SZ
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
	xdp.frame_sz = sxe2_rx_frame_truesize(rxq, 0);
#else
	xdp.frame_sz = 0;
#endif
#endif

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("rxq[%u][%u] ntc:%u ntu:%u \t"
			      "nta:%u budget:%u rxq_offset:%u \t"
			      "descriptor idle:%u skb:%p vsi:%p\n",
			      rxq->idx_in_vsi, rxq->idx_in_pf, rxq->next_to_clean,
			      rxq->next_to_use, rxq->next_to_alloc, budget, offset,
			      idle, skb, rxq->vsi);
	}
#endif

	while (likely(total_rx_pkts < (u32)budget)) {
		union sxe2_rx_desc *rx_desc;
		union sxe2_rx_desc_fnav *rx_fnav_desc;
		struct sxe2_rx_buf *rx_buf;
		unsigned char *hard_start;
		u32 size;
		s32 pg_refcnt;
		u16 rx_ptype;

		rx_desc = SXE2_RX_DESC(rxq, rxq->next_to_clean);

#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
			(void)snprintf(str, SXE2_LOG_STR_LEN - 1,
				       "rxq[%d][%d] desc[%d]", rxq->idx_in_vsi,
				       rxq->idx_in_pf, rxq->next_to_clean);
			DATA_DUMP(rx_desc, sizeof(*rx_desc), str);
		}
#endif

		if (!sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
						BIT(SXE2_RX_DESC_STATUS0_DD)))
			break;

		dma_rmb();

		sxe2_trace(rx_pkt_clean_begin, rxq);

		if ((rx_desc->wb.rxdid_src & SXE2_RX_DESC_RXDID_MASK) ==
				    SXE2_RX_DESC_ID_FD ||
		    !rxq->netdev) {
			adapter->fnav_ctxt.pkt_err_cnt++;
			rx_fnav_desc = (union sxe2_rx_desc_fnav *)rx_desc;
#ifdef SXE2_CFG_DEBUG
			if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
				LOG_INFO_BDF("flowid=%u, fdid=%u, fd_prog_sts=%u",
					     rx_fnav_desc->wb.flowid,
					     rx_fnav_desc->wb.fdid,
					     rx_fnav_desc->wb.fd_prog_sts);
			}
#endif

			sxe2_rx_buffer_put(rxq, rx_desc, NULL, NULL, 0);
			idle++;
			continue;
		}

		size = le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) &
		       SXE2_RX_DESC_PKT_LEN_MASK;

		rx_buf = sxe2_rx_buffer_get(rxq, rx_desc, size, &pg_refcnt);

		if (!size) {
			xdp.data = NULL;
			xdp.data_end = NULL;
			xdp.data_hard_start = NULL;
			xdp.data_meta = NULL;
			goto construct_skb;
		}

		hard_start = page_address(rx_buf->page) + rx_buf->pg_offset - offset;
#ifdef HAVE_XDP_SUPPORT
		xdp_prepare_buff(&xdp, hard_start, (int)offset, (int)size, true);
#endif

#ifdef HAVE_XDP_BUFF_FRAME_SZ
#if (PAGE_SIZE > SXE2_PAGE_SIZE_4KB)
		xdp.frame_sz = sxe2_rx_frame_truesize(rxq, size);
#endif
#endif

		xdp_prog = READ_ONCE(rxq->xdp_prog);
		if (!xdp_prog)
			goto construct_skb;

#ifdef HAVE_XDP_SUPPORT
		xdp_res = (u32)sxe2_xdp_run(rxq, &xdp, xdp_prog);
		if (!xdp_res)
			goto construct_skb;
#endif

		if (xdp_res & (SXE2_XDP_TX | SXE2_XDP_REDIR)) {
#ifndef HAVE_XDP_BUFF_FRAME_SZ
			unsigned int truesize;
#if (PAGE_SIZE < SXE2_PAGE_SIZE_8KB)
			truesize = SXE2_RX_PAGE_SIZE(rxq) / 2;
#else
			truesize = SKB_DATA_ALIGN(sxe2_rx_offset_get(rxq) + size);
#endif
#endif
			xdp_xmit |= xdp_res;
#ifdef HAVE_XDP_BUFF_FRAME_SZ
			sxe2_rx_pg_offset_update(rx_buf, xdp.frame_sz);
#else
			sxe2_rx_pg_offset_update(rx_buf, truesize);
#endif
		} else {
			rx_buf->drv_refcnt++;
		}
		total_rx_bytes += size;
		total_rx_pkts++;

		idle++;
		sxe2_xdp_rx_buffer_put(rxq, rx_buf, pg_refcnt);
		continue;

construct_skb:
		if (skb) {
			sxe2_skb_frag_add(rxq, rx_buf, skb, size);
		} else if (likely(xdp.data)) {
			if (test_bit(SXE2_RXQ_BUILD_SKB_ENABLED, &rxq->flags))
				skb = sxe2_skb_build(rxq, rx_buf, &xdp, rx_desc);
			else
				skb = sxe2_skb_construct(rxq, rx_buf, &xdp, rx_desc);
		}

		if (!skb) {
			rxq->stats->rx_stats.rx_buff_alloc_err++;
			if (rx_buf)
				rx_buf->drv_refcnt++;
			break;
		}

#ifdef SXE2_CFG_DEBUG
		if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags))
			SKB_DUMP(skb);
#endif
		sxe2_rx_buffer_put(rxq, rx_desc, rx_buf, skb, pg_refcnt);
		idle++;

		if (sxe2_is_non_eop(rxq, rx_desc)) {
			rxq->rx_buf[rxq->next_to_clean].skb = skb;
			rxq->stats->rx_stats.rx_non_eop_descs++;
			continue;
		}

		if (unlikely(sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
							BIT(SXE2_RX_DESC_ERROR_PA_ERR)))) {
			rxq->stats->rx_stats.rx_pa_err++;
		}

		if (unlikely(sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
							BIT(SXE2_RX_DESC_ERROR_RXE)) ||
			     sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
							BIT(SXE2_RX_DESC_ERROR_OVERSIZE)))) {
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
			   SXE2_RX_DESC_PTYPE_MASK;

		sxe2_skb_field_fill(rxq, rx_desc, skb, rx_ptype);

		sxe2_trace(rx_pkt_clean_end, rxq);

		(void)napi_gro_receive(&rxq->irq_data->napi, skb);
		skb = NULL;

		total_rx_pkts++;
	}

	failure = sxe2_rx_buffers_alloc(rxq, idle);

	if (xdp_prog)
		sxe2_xdp_tail_update(rxq, xdp_xmit);

	rxq->skb = skb;

	sxe2_rxq_stats_update(rxq, total_rx_pkts, total_rx_bytes);

	return failure ? budget : (int)total_rx_pkts;
}

static bool sxe2_rx_buf_len_is_valid(u16 rx_buf_len)
{
	return ((rx_buf_len >= SXE2_RX_BUF_LEN_MIN) &&
		(rx_buf_len <= SXE2_RX_BUF_LEN_MAX));
}

static bool sxe2_rxq_cfg_param_is_valid(struct sxe2_adapter *adapter,
					struct sxe2_rxq_cfg_params *params)
{
	struct sxe2_ctxt_elem *ctxt;
	u16 i;
	struct sxe2_vsi *vsi;

	if (!sxe2_vsi_id_is_valid(adapter, params->vsi_id)) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	if (params->q_cnt > vsi->rxqs.q_cnt || !params->q_cnt) {
		LOG_ERROR_BDF(" rxq cnt:%u invalid max:%u vsi_id:%d.\n",
			      params->q_cnt, vsi->rxqs.q_cnt, params->vsi_id);
		return false;
	}

	for (i = 0; i < params->q_cnt; i++) {
		ctxt = &params->cfg[i];
		if (ctxt->queue_id >= vsi->rxqs.q_cnt ||
		    !sxe2_queue_depth_is_valid(ctxt->depth) ||
		    !sxe2_rx_buf_len_is_valid(ctxt->buf_len)) {
			LOG_ERROR_BDF("ctxt vsi_id:%u vsi_id_in_dev:%d\t"
				      "queue_id:%u\n"
				      "rxq cnt:%u depth:%u buf_len:%u\t"
				      "max_frame_size:%u.\n",
				      params->vsi_id, vsi->idx_in_dev,
				      ctxt->queue_id, vsi->rxqs.q_cnt, ctxt->depth,
				      ctxt->buf_len, params->max_frame_size);
			return false;
		}
	}

	return true;
}

static bool sxe2_rxq_dis_param_is_valid(struct sxe2_adapter *adapter,
					struct sxe2_rxq_dis_params *params)
{
	struct sxe2_vsi *vsi;

	if (!sxe2_vsi_id_is_valid(adapter, params->vsi_id)) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("invalid vsi id:%d.\n", params->vsi_id);
		return false;
	}

	if (params->q_idx > vsi->rxqs.q_cnt) {
		LOG_ERROR_BDF(" rxq id:%u invalid max:%u vsi_id:%d.\n",
			      params->q_idx, vsi->rxqs.q_cnt, params->vsi_id);
		return false;
	}

	return true;
}

s32 sxe2_rxq_cfg_ena_common_handle(struct sxe2_adapter *adapter,
				   struct sxe2_rxq_cfg_params *params)
{
	u16 i = 0;
	struct sxe2_ctxt_elem *ctxt;
	struct sxe2_queue *rxq;
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	if (!adapter || !params) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rx cfg enable params invalid.\n");
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (!sxe2_rxq_cfg_param_is_valid(adapter, params)) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rx cfg enable params invalid.\n");
		goto l_err;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		ret = -EINVAL;
		LOG_ERROR_BDF("vsi_id:%d vsi null.\n", params->vsi_id);
		goto l_err;
	}

	vsi->rxqs.max_frame = params->max_frame_size;
	for (i = 0; i < params->q_cnt; i++) {
		ctxt = &params->cfg[i];
		rxq = vsi->rxqs.q[ctxt->queue_id];

		rxq->depth = ctxt->depth;
		rxq->rx_buf_len = ctxt->buf_len;
		rxq->desc.dma = ctxt->dma_addr;
		rxq->desc_size = ctxt->desc_size;

		if (ctxt->keep_crc_en)
			set_bit(SXE2_RXQ_CRC_STRIP_DISABLED, &rxq->flags);
		else
			clear_bit(SXE2_RXQ_CRC_STRIP_DISABLED, &rxq->flags);

		if (ctxt->lro_en) {
			set_bit(SXE2_RXQ_LRO_ENABLED, &rxq->flags);
			rxq->max_lro_size = ctxt->max_lro_size;
		} else {
			clear_bit(SXE2_RXQ_LRO_ENABLED, &rxq->flags);
			rxq->max_lro_size = 0;
		}

		if (ctxt->split_en) {
			set_bit(SXE2_RXQ_SPLIT_ENABLED, &rxq->flags);
			rxq->split_type_mask = ctxt->split_type_mask;
			rxq->hdr_len = ctxt->hdr_len;
		} else {
			clear_bit(SXE2_RXQ_SPLIT_ENABLED, &rxq->flags);
		}

		ret = sxe2_rxq_ctxt_cfg(rxq);
		if (ret) {
			LOG_DEV_WARN("vsi:%d i:%u rxq:%u cfg enable failed.\n",
				     vsi->id_in_pf, i, ctxt->queue_id);
			ret = -SXE2_VF_ERR_HANDLE_ERROR;
			goto l_err;
		}
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
	goto l_end;

l_err:
	while (i) {
		i--;
		rxq = vsi->rxqs.q[ctxt->queue_id];
		if (sxe2_rxq_ctrl_set(adapter, rxq, false, true))
			LOG_DEV_ERR("vsi:%u i:%u rxq:%u disable failed.\n",
				    vsi->id_in_pf, i, ctxt->queue_id);
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	return ret;
}

s32 sxe2_rxq_disable_common_handle(struct sxe2_adapter *adapter,
				   struct sxe2_rxq_dis_params *params)
{
	struct sxe2_queue *rxq;
	s32 ret = 0;
	struct sxe2_vsi *vsi;
	struct sxe2_hw *hw = &adapter->hw;

	if (!adapter || !params) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rx cfg enable params invalid.\n");
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (!sxe2_rxq_dis_param_is_valid(adapter, params)) {
		ret = -EINVAL;
		LOG_ERROR_BDF("rx queue disable params invalid.\n");
		goto l_unlock;
	}

	vsi = sxe2_vsi_get_by_idx(adapter, params->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("vsi_id:%d vsi null.\n", params->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}
	rxq = vsi->rxqs.q[params->q_idx];

	(void)sxe2_rxq_ctrl_set(adapter, rxq, false, false);
	ret = sxe2_err_code_trans_hw(sxe2_hw_rxq_status_check(hw,
							      rxq->idx_in_pf,
							      false));
	if (ret)
		LOG_ERROR_BDF("vsi:%u rxq[%u][%u] set status:%u timeout.\n",
			      vsi->idx_in_dev, params->q_idx, rxq->idx_in_pf, false);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	return ret;
}

s32 sxe2_rxq_ctrl_set(struct sxe2_adapter *adapter, struct sxe2_queue *rxq,
		      bool enable, bool wait)
{
	struct sxe2_vsi *vsi;
	s32 ret = 0;
	bool rxq_cde = true;

	if (!rxq || !rxq->vsi) {
		ret = -EINVAL;
		LOG_ERROR_BDF("invalid rxq:%p vsi:%p .\n", rxq, rxq->vsi);
		goto l_out;
	}

	vsi = rxq->vsi;

	if (test_bit(SXE2_VSI_FLAG_FC_ON, vsi->flags))
		rxq_cde = false;

	(void)sxe2_hw_rxq_ctrl(&adapter->hw, rxq->idx_in_pf, enable, wait, rxq_cde);

l_out:
	return ret;
}
