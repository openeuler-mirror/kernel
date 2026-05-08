// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_tx.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/if_vlan.h>
#include <linux/if_ether.h>

#include "sxe2vf.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_queue.h"
#include "sxe2vf_netdev.h"
#include "sxe2_log.h"
#include "sxe2vf_mbx_msg.h"
#include "sxe2_mbx_public.h"
#include "sxe2vf_regs.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_ipsec.h"
#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif

#define SXE2VF_MIN_TX_LEN 17
#define SXE2VF_DFLT_IRQ_WORK 256
#define SXE2VF_CACHE_LINE_BYTES 64
#define SXE2VF_DESCS_PER_CACHE_LINE                                                 \
	(SXE2VF_CACHE_LINE_BYTES / sizeof(union sxe2vf_tx_data_desc))
#define SXE2VF_DESCS_FOR_CTXT_DESC 1
#define SXE2VF_DESCS_FOR_SKB_DATA_PTR 1
#define SXE2VF_MAX_DATA_DESC_PER_SKB 15
#define SXE2VF_DATA_DESC_USED_FOR_TSO 6

#define SXE2VF_TSO_SEG_DESC_USE_FOR_FRAGMENT 13

#define SXE2VF_TX_DESC_NEEDED                                                       \
	(MAX_SKB_FRAGS + SXE2VF_DESCS_FOR_CTXT_DESC + SXE2VF_DESCS_PER_CACHE_LINE + \
	 SXE2VF_DESCS_FOR_SKB_DATA_PTR)
#define SXE2VF_TX_WAKE_THRESHOLD (SXE2VF_TX_DESC_NEEDED * 2)
#define SXE2VF_MAX_READ_REQ_SIZE 4096
#define SXE2VF_MAX_DATA_PER_TXD (16 * 1024 - 1)
#define SXE2VF_MAX_DATA_PER_TXD_ALIGNED                                             \
	(~(SXE2VF_MAX_READ_REQ_SIZE - 1) & SXE2VF_MAX_DATA_PER_TXD)

#define SXE2VF_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(frag_size)                          \
	((((frag_size) * 85) >> 20) + 1)

static inline u16 sxe2vf_tx_desc_unused_count(struct sxe2vf_queue *txq)
{
	u16 ntc = txq->next_to_clean;
	u16 ntu = txq->next_to_use;
	u16 unused_tx_desc_cnt;

	unused_tx_desc_cnt = (u16)(((ntc > ntu) ? 0 : txq->depth) + ntc - ntu - 1);
	return unused_tx_desc_cnt;
}

static s32 sxe2vf_maybe_stop_tx(struct sxe2vf_queue *txq, u16 desc_cnt)
{
	s32 ret = 0;

	netif_stop_subqueue(txq->netdev, txq->idx_in_vsi);

	/* in order to force CPU ordering */
	smp_mb();

	if (likely(sxe2vf_tx_desc_unused_count(txq) < desc_cnt)) {
		ret = -EBUSY;
		goto l_end;
	}

	netif_start_subqueue(txq->netdev, txq->idx_in_vsi);

	++txq->stats->tx_stats.tx_restart;

l_end:
	return ret;
}

static u32 sxe2vf_tx_desc_count(struct sk_buff *skb)
{
	u32 count = 0, size = skb_headlen(skb);
	u32 nr_frags = skb_shinfo(skb)->nr_frags;
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];

	for (;;) {
		count += SXE2VF_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

static inline struct sxe2vf_tx_buf *
sxe2vf_tx_first_buffer_get(struct sk_buff *skb, struct sxe2vf_queue *txq)
{
	struct sxe2vf_tx_buf *first_buf;

	first_buf = &txq->tx_buf[txq->next_to_use];
	first_buf->skb = skb;
	first_buf->bytecount = max_t(u32, skb->len, ETH_ZLEN);
	first_buf->gso_segs = 1;
	first_buf->tx_features = 0;
	LOG_DEBUG(">>> next_to_use:%u buf:%pK skb:%pK.\n", txq->next_to_use,
		  &txq->tx_buf[txq->next_to_use], skb);
	return first_buf;
}

static void sxe2vf_tx_buffer_unmap(struct sxe2vf_queue *txq,
				   struct sxe2vf_tx_buf *tx_buf)
{
	if (tx_buf->skb) {
		dev_kfree_skb_any(tx_buf->skb);

		if (dma_unmap_len(tx_buf, len)) {
			dma_unmap_single(txq->dev, dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
		}
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(txq->dev, dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	}

	tx_buf->next_to_watch = NULL;
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
}

static bool sxe2vf_chk_linearize_for_tso(struct sk_buff *skb)
{
	u32 i;
	bool ret;
	s32 nr_frags, sum;
	const skb_frag_t *frag, *stale;

	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (SXE2VF_MAX_DATA_DESC_PER_SKB - 1)) {
		ret = false;
		goto l_end;
	}

	sum = 1 - skb_shinfo(skb)->gso_size;

	frag = &skb_shinfo(skb)->frags[0];
	for (i = 0; i < SXE2VF_TSO_SEG_DESC_USE_FOR_FRAGMENT - 1; i++)
		sum += (s32)skb_frag_size(frag++);
	nr_frags -= SXE2VF_TSO_SEG_DESC_USE_FOR_FRAGMENT;

	for (stale = &skb_shinfo(skb)->frags[0];; stale++) {
		int stale_size = (s32)skb_frag_size(stale);

		sum += (s32)skb_frag_size(frag++);

		if (stale_size > SXE2VF_MAX_DATA_PER_TXD) {
			int align_pad = -((int)skb_frag_off(stale)) &
					(SXE2VF_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= SXE2VF_MAX_DATA_PER_TXD_ALIGNED;
				stale_size -= SXE2VF_MAX_DATA_PER_TXD_ALIGNED;
			} while (stale_size > SXE2VF_MAX_DATA_PER_TXD);
		}

		if (sum < 0) {
			ret = true;
			goto l_end;
		}

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	ret = false;
l_end:
	return ret;
}

static void sxe2vf_tx_dma_err(struct sxe2vf_queue *txq,
			      struct sxe2vf_tx_buf *first_buf, u16 ntu)
{
	struct sxe2vf_tx_buf *tx_buf;

	for (;;) {
		tx_buf = &txq->tx_buf[ntu];

		sxe2vf_tx_buffer_unmap(txq, tx_buf);
		if (tx_buf == first_buf)
			break;

		if (ntu == 0)
			ntu += txq->depth;

		--ntu;
	}

	txq->next_to_use = ntu;
}

static inline void sxe2vf_tx_desc_update(struct sxe2vf_queue *txq,
					 union sxe2vf_tx_data_desc **desc, u16 *ntu)
{
	++(*ntu);
	++(*desc);
	if (txq->depth == *ntu) {
		*desc = SXE2VF_TX_DESC(txq, 0);
		*ntu = 0;
	}
}

static inline __le64
sxe2vf_tx_data_desc_qword1_setup(struct sxe2vf_tx_offload_info *offload, u32 size)
{
	return cpu_to_le64(SXE2VF_TX_DESC_DTYPE_DATA |
			   ((u64)offload->data_desc_cmd
			    << SXE2VF_TX_DATA_DESC_CMD_SHIFT) |
			   ((u64)offload->data_desc_offset
			    << SXE2VF_TX_DATA_DESC_OFFSET_SHIFT) |
			   ((u64)size << SXE2VF_TX_DATA_DESC_BUF_SZ_SHIFT) |
			   ((u64)offload->data_desc_l2tag1
			    << SXE2VF_TX_DATA_DESC_L2TAG1_SHIFT));
}

static s32 sxe2vf_tx_desc_ring_map(struct sxe2vf_queue *txq,
				   struct sxe2vf_tx_buf *first_buf,
				   struct sxe2vf_tx_offload_info *offload,
				   union sxe2vf_tx_data_desc **desc, u16 *ntu)
{
	u32 max_data;
	dma_addr_t dma;
	skb_frag_t *frag;
	struct sk_buff *skb = first_buf->skb;
	u32 map_size = skb_headlen(skb);
	u32 remaining_size = skb->data_len;
	struct sxe2vf_tx_buf *tx_buf = first_buf;
	struct sxe2vf_adapter *adapter = netdev_priv(txq->netdev);

	LOG_DEBUG_BDF("skb dma map start, line_size=%u, \t"
		      "total_frag_len=%u, skb_len=%u\n",
		      skb_headlen(skb), skb->data_len, skb->len);

	dma = dma_map_single(txq->dev, skb->data, map_size, DMA_TO_DEVICE);

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(txq->dev, dma)) {
			LOG_ERROR_BDF("tx dma map failed\n");
			goto l_dma_err;
		}

		dma_unmap_len_set(tx_buf, len, map_size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		(*desc)->read.buf_addr = cpu_to_le64(dma);

		max_data = SXE2VF_MAX_DATA_PER_TXD_ALIGNED;

		while (unlikely(map_size > SXE2VF_MAX_DATA_PER_TXD)) {
			(*desc)->read.cmd_type_offset_bsz =
					sxe2vf_tx_data_desc_qword1_setup(offload,
									 max_data);

			sxe2vf_tx_desc_update(txq, desc, ntu);
			dma += max_data;
			map_size -= max_data;
			max_data = SXE2VF_MAX_DATA_PER_TXD_ALIGNED;
			(*desc)->read.buf_addr = cpu_to_le64(dma);
		}

		if (likely(!remaining_size)) {
			offload->data_desc_cmd |= SXE2VF_TX_DATA_DESC_CMD_EOP |
						  SXE2VF_TX_DATA_DESC_CMD_RS;
			(*desc)->read.cmd_type_offset_bsz =
					sxe2vf_tx_data_desc_qword1_setup(offload,
									 map_size);
			LOG_DEBUG_BDF("skb dma map, current_map_size=%u, \t"
				      "remaining_size=%u, \t"
				      "desc_ptr=%p, dma_addr=%#llx, \t"
				      "desc.buffer_addr = %#llx, \t"
				      "cmd_type=0x%llx\n",
				      map_size, remaining_size, *desc, (u64)dma,
				      (*desc)->read.buf_addr,
				      (*desc)->read.cmd_type_offset_bsz);
			break;
		}

		(*desc)->read.cmd_type_offset_bsz =
				sxe2vf_tx_data_desc_qword1_setup(offload, map_size);

		LOG_DEBUG_BDF("skb dma map, current_map_size=%u, remaining_size=%u, \t"
			      "desc_ptr=%p, dma_addr=%#llx, desc.buffer_addr = \t"
			      "%#llx, \t"
			      "cmd_type=0x%llx\n",
			      map_size, remaining_size, *desc, (u64)dma,
			      (*desc)->read.buf_addr,
			      (*desc)->read.cmd_type_offset_bsz);
		sxe2vf_tx_desc_update(txq, desc, ntu);

		map_size = skb_frag_size(frag);
		remaining_size -= map_size;

		dma = skb_frag_dma_map(txq->dev, frag, 0, map_size, DMA_TO_DEVICE);

		tx_buf = &txq->tx_buf[*ntu];
	}

	LOG_DEBUG_BDF("skb dma map end\n");
	return 0;

l_dma_err:
	sxe2vf_tx_dma_err(txq, first_buf, *ntu);
	return -ENOMEM;
}

static inline struct netdev_queue *
sxe2vf_queue_to_netdevq(const struct sxe2vf_queue *queue)
{
	return netdev_get_tx_queue(queue->netdev, queue->idx_in_vsi);
}

static inline void
sxe2vf_tx_desc_setup_for_csum(struct sxe2vf_tx_offload_info *offload, u32 l2_len,
			      u32 l3_len, u32 l4_len, u32 cmd)
{
	offload->data_desc_offset |= ((l2_len / SXE2VF_BYTES_PER_WORD)
				      << SXE2VF_TX_DATA_DESC_MACLEN_SHIFT) |
				     ((l3_len / SXE2VF_BYTES_PER_DWORD)
				      << SXE2VF_TX_DATA_DESC_IPLEN_SHIFT) |
				     (l4_len << SXE2VF_TX_DATA_DESC_L4_LEN_SHIFT);

	offload->data_desc_cmd |= cmd;
}

static s32 sxe2vf_xmit_pkt(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first_buf,
			   struct sxe2vf_tx_offload_info *offload)
{
	s32 ret;
	u16 ntu = txq->next_to_use;
	union sxe2vf_tx_data_desc *desc = SXE2VF_TX_DESC(txq, ntu);
	struct sxe2vf_adapter *adapter = netdev_priv(txq->netdev);
	bool xmit_more;

	ret = sxe2vf_tx_desc_ring_map(txq, first_buf, offload, &desc, &ntu);
	if (ret)
		goto l_end;

	ntu++;
	if (ntu == txq->depth)
		ntu = 0;

	/* in order to force CPU ordering */
	wmb();

	first_buf->next_to_watch = desc;

	txq->next_to_use = ntu;

	if (unlikely(sxe2vf_tx_desc_unused_count(txq) < SXE2VF_TX_DESC_NEEDED)) {
		ret = sxe2vf_maybe_stop_tx(txq, SXE2VF_TX_DESC_NEEDED);
		if (ret < 0) {
			LOG_WARN_BDF("the desc is not enough in the queue[%u],\t"
				     "to stop the queue, \t"
				     "desc_cnt < SXE2VF_TX_DESC_NEEDED[%u]\n",
				     txq->idx_in_vsi, (u32)SXE2VF_TX_DESC_NEEDED);
		}
	}

	xmit_more = netdev_xmit_more();
	txq->stats->tx_stats.tx_xmit_more += xmit_more;
	if (__netdev_tx_sent_queue(sxe2vf_queue_to_netdevq(txq),
				   first_buf->bytecount, xmit_more)) {
		writel(ntu, txq->desc.tail);
	}

	return 0;

l_end:
	return ret;
}

static bool sxe2vf_chk_linearize(struct sk_buff *skb, u32 desc_needed)
{
	if (likely(desc_needed < SXE2VF_MAX_DATA_DESC_PER_SKB))
		return false;

	if (skb_is_gso(skb))
		return sxe2vf_chk_linearize_for_tso(skb);

	return desc_needed != SXE2VF_MAX_DATA_DESC_PER_SKB;
}

static inline void
sxe2vf_tx_desc_setup_for_tso(struct sxe2vf_tx_offload_info *offload, u64 tso_len,
			     u64 mss)
{
	offload->ctxt_desc_qw1 =
			(u64)(SXE2VF_TX_DESC_DTYPE_CTXT |
			      (SXE2VF_TX_CTXT_DESC_CMD_TSO
			       << SXE2VF_TX_CTXT_DESC_CMD_SHIFT) |
			      (tso_len << SXE2VF_TX_CTXT_DESC_TSO_LEN_SHIFT) |
			      (mss << SXE2VF_TX_CTXT_DESC_MSS_SHIFT));
}

static s32 sxe2vf_tso(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first_buf,
		      struct sxe2vf_tx_offload_info *offload)
{
	s32 ret;
	u32 paylen;
	union sxe2vf_ip_hdr ip;
	union sxe2vf_l4_hdr l4;
	u8 l4_start, header_len;
	u64 cd_mss, cd_tso_len;
	struct sk_buff *skb = first_buf->skb;
	struct sxe2vf_adapter *adapter = offload->adapter;

	if (skb->ip_summed != CHECKSUM_PARTIAL || !skb_is_gso(skb)) {
		ret = 0;
		goto l_end;
	}

	ret = skb_cow_head(skb, 0);
	if (ret < 0) {
		LOG_ERROR_BDF("skb cow head failed, ret=%d\n", ret);
		goto l_end;
	}

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else {
		ip.v6->payload_len = 0;
	}

	if (skb_shinfo(skb)->gso_type &
	    (SKB_GSO_GRE | SKB_GSO_GRE_CSUM | SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6 |
	     SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {
		if (!(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM)) {
			l4.udp->len = 0;
			l4_start = (u8)(l4.hdr - skb->data);

			paylen = skb->len - l4_start;
			csum_replace_by_diff(&l4.udp->check,
					     (__force __wsum)htonl(paylen));
		}

		if (ip.v4->version == 4)
			ip.v4->frag_off |= htons(IP_DF);

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);
		if (ip.v4->version == 4) {
			ip.v4->tot_len = 0;
			ip.v4->check = 0;
		} else {
			ip.v6->payload_len = 0;
		}
	}

	l4_start = (u8)(l4.hdr - skb->data);

	paylen = skb->len - l4_start;
#ifdef NETIF_F_GSO_UDP_L4
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check, (__force __wsum)htonl(paylen));

		header_len = (u8)sizeof(l4.udp) + l4_start;
	} else {
		csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(paylen));

		header_len = (u8)((l4.tcp->doff * 4) + l4_start);
	}
#else
	csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(paylen));

	header_len = (u8)((l4.tcp->doff * 4) + l4_start);
#endif
	first_buf->gso_segs = skb_shinfo(skb)->gso_segs;
	first_buf->bytecount += (first_buf->gso_segs - 1) * header_len;

	txq->stats->tx_stats.tx_tso_packets += first_buf->gso_segs;
	txq->stats->tx_stats.tx_tso_bytes += first_buf->bytecount;

	cd_tso_len = skb->len - header_len;
	cd_mss = skb_shinfo(skb)->gso_size;

	first_buf->tx_features |= SXE2VF_TX_FEATURE_TSO;

	sxe2vf_tx_desc_setup_for_tso(offload, cd_tso_len, cd_mss);

	return 0;

l_end:
	return ret;
}

static s32 sxe2vf_tx_csum(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first_buf,
			  struct sxe2vf_tx_offload_info *offload)
{
	s32 ret;
	bool gso_ena;
	u8 l4_proto = 0;
	unsigned char *exthdr;
	union sxe2vf_ip_hdr ip;
	union sxe2vf_l4_hdr l4;
	__be16 frag_off, protocol;
	u32 l4_len = 0, l3_len, l2_len;
	u32 cmd = 0, tunnel = 0;
	struct sk_buff *skb = first_buf->skb;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		txq->stats->tx_stats.tx_csum_none++;
		return 0;
	}

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	l2_len = (u32)(ip.hdr - skb->data);

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP))
		first_buf->tx_features |= SXE2VF_TX_FEATURE_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		first_buf->tx_features |= SXE2VF_TX_FEATURE_IPV6;

	if (skb->encapsulation) {
		if (first_buf->tx_features & SXE2VF_TX_FEATURE_IPV4) {
			tunnel |= (first_buf->tx_features & SXE2VF_TX_FEATURE_TSO)
						  ? SXE2VF_TX_CTXT_DESC_IPV4
						  : SXE2VF_TX_CTXT_DESC_IPV4_NO_CSUM;
			l4_proto = ip.v4->protocol;

		} else if (first_buf->tx_features & SXE2VF_TX_FEATURE_IPV6) {
			tunnel |= SXE2VF_TX_CTXT_DESC_EIPT_IPV6;
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto,
					       &frag_off);
			if (ret < 0) {
				ret = -1;
				goto l_end;
			}
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
			tunnel |= SXE2VF_TX_CTXT_DESC_UDP_TUNNE;
			first_buf->tx_features |= SXE2VF_TX_FEATURE_TUNNEL;
			break;
		case IPPROTO_GRE:
			tunnel |= SXE2VF_TX_CTXT_DESC_GRE_TUNNE;
			first_buf->tx_features |= SXE2VF_TX_FEATURE_TUNNEL;
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			first_buf->tx_features |= SXE2VF_TX_FEATURE_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
		default:
			if (first_buf->tx_features & SXE2VF_TX_FEATURE_TSO) {
				ret = -1;
				goto l_end;
			}

			(void)skb_checksum_help(skb);
			ret = 0;
			goto l_end;
		}

		tunnel |= ((l4.hdr - ip.hdr) / 4)
			  << SXE2VF_TX_CTXT_DESC_EIPLEN_SHIFT;

		ip.hdr = skb_inner_network_header(skb);

		tunnel |= ((ip.hdr - l4.hdr) / 2)
			  << SXE2VF_TX_CTXT_DESC_NATLEN_SHIFT;

		gso_ena = skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL;
		if ((first_buf->tx_features & SXE2VF_TX_FEATURE_TSO) && !gso_ena &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM)) {
			tunnel |= SXE2VF_TX_CTXT_DESC_L4T_CS_MASK;
		}

		offload->ctxt_desc_tunnel |= tunnel;
		offload->ctxt_desc_qw1 |= (u64)SXE2VF_TX_DESC_DTYPE_CTXT;

		l4.hdr = skb_inner_transport_header(skb);
		l4_proto = 0;

		first_buf->tx_features &=
				~(SXE2VF_TX_FEATURE_IPV4 | SXE2VF_TX_FEATURE_IPV6);
		if (ip.v4->version == 4)
			first_buf->tx_features |= SXE2VF_TX_FEATURE_IPV4;
		if (ip.v6->version == 6)
			first_buf->tx_features |= SXE2VF_TX_FEATURE_IPV6;
		txq->stats->tx_stats.tx_csum_partial_inner++;
	} else {
		txq->stats->tx_stats.tx_csum_partial++;
	}

	if (first_buf->tx_features & SXE2VF_TX_FEATURE_IPV4) {
		l4_proto = ip.v4->protocol;
		if (first_buf->tx_features & SXE2VF_TX_FEATURE_TSO)
			cmd |= SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV4_CSUM;
		else
			cmd |= SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV4;
	} else if (first_buf->tx_features & SXE2VF_TX_FEATURE_IPV6) {
		cmd |= SXE2VF_TX_DATA_DESC_CMD_IIPT_IPV6;
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			(void)ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto,
					       &frag_off);
	} else {
		ret = -1;
		goto l_end;
	}

	l3_len = (u32)(l4.hdr - ip.hdr);

	switch (l4_proto) {
	case IPPROTO_TCP:
		cmd |= SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_TCP;
		l4_len = l4.tcp->doff;
		break;
	case IPPROTO_UDP:
		cmd |= SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_UDP;
		l4_len = (sizeof(struct udphdr) >> 2);
		break;
#ifdef HAVE_SCTP
	case IPPROTO_SCTP:
		cmd |= SXE2VF_TX_DATA_DESC_CMD_L4T_EOFT_SCTP;
		l4_len = sizeof(struct sctphdr) >> 2;
		break;
#endif

	default:
		if (first_buf->tx_features & SXE2VF_TX_FEATURE_TSO)
			return -1;
		(void)skb_checksum_help(skb);
		ret = 0;
		goto l_end;
	}

	sxe2vf_tx_desc_setup_for_csum(offload, l2_len, l3_len, l4_len, cmd);
	first_buf->tx_features |= SXE2VF_TX_FEATURE_MACLEN;

	return 0;
l_end:
	return ret;
}

static inline void
sxe2vf_tx_desc_setup_for_vlan(struct sxe2vf_tx_offload_info *offload, u16 vlan_tci)
{
	offload->data_desc_l2tag1 = vlan_tci;
	offload->data_desc_cmd |= SXE2VF_TX_DATA_DESC_CMD_IL2TAG1;
}

static void sxe2vf_tx_vlan(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first_buf,
			   struct sxe2vf_tx_offload_info *offload)
{
	struct sk_buff *skb = first_buf->skb;
	union sxe2vf_ip_hdr ip;
	u32 l2_len;

	if (!skb_vlan_tag_present(skb) && eth_type_vlan((u16)skb->protocol))
		return;

	if (skb_vlan_tag_present(skb)) {
		txq->stats->tx_stats.tx_vlan_insert++;
		sxe2vf_tx_desc_setup_for_vlan(offload, skb_vlan_tag_get(skb));
		LOG_INFO("txq:%u vlan tag:0x%x insert offload.\n", txq->idx_in_vsi,
			 skb_vlan_tag_get(skb));
	}

	if ((offload->data_desc_cmd & SXE2VF_TX_DATA_DESC_CMD_IL2TAG1) &&
	    !(first_buf->tx_features & SXE2VF_TX_FEATURE_MACLEN)) {
		ip.hdr = skb_network_header(skb);
		l2_len = (u32)(ip.hdr - skb->data);
		offload->data_desc_offset |= ((l2_len / SXE2VF_BYTES_PER_WORD)
					      << SXE2VF_TX_DATA_DESC_MACLEN_SHIFT);
	}
}

static inline void sxe2vf_tx_port_vlan(struct sxe2vf_queue *txq,
				       struct sxe2vf_tx_buf *first_buf,
				       struct sxe2vf_tx_offload_info *offload)
{
	struct sk_buff *skb = first_buf->skb;
	union sxe2vf_ip_hdr ip;
	u32 l2_len;

	if (txq->vsi->adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist &&
	    !(first_buf->tx_features & SXE2VF_TX_FEATURE_MACLEN)) {
		ip.hdr = skb_network_header(skb);
		l2_len = (u32)(ip.hdr - skb->data);
		offload->data_desc_offset |= ((l2_len / SXE2VF_BYTES_PER_WORD)
					      << SXE2VF_TX_DATA_DESC_MACLEN_SHIFT);
	}
}

static s32 sxe2vf_tx_feature_offload(struct sxe2vf_queue *txq,
				     struct sxe2vf_tx_buf *first_buf,
				     struct sxe2vf_tx_offload_info *offload)
{
	s32 ret;
	u16 ntu = txq->next_to_use;
	struct sxe2vf_tx_context_desc *ctxt_desc;

	offload->adapter = txq->vsi->adapter;

	ret = sxe2vf_tso(txq, first_buf, offload);
	if (ret < 0)
		goto l_end;

	if (xfrm_offload(first_buf->skb)) {
		ret = sxe2vf_ipsec_tx(txq, first_buf, offload);
		if (ret)
			goto l_end;
	}

	ret = sxe2vf_tx_csum(txq, first_buf, offload);
	if (ret < 0)
		goto l_end;
	sxe2vf_tx_vlan(txq, first_buf, offload);
	sxe2vf_tx_port_vlan(txq, first_buf, offload);
	if (offload->ctxt_desc_qw1 & SXE2VF_TX_DESC_DTYPE_CTXT) {
		ctxt_desc = SXE2VF_TX_CTXT_DESC(txq, ntu);
		ntu++;
		txq->next_to_use = (ntu < txq->depth) ? ntu : 0;

		ctxt_desc->tunneling_params = cpu_to_le32(offload->ctxt_desc_tunnel);
		ctxt_desc->l2tag2 = cpu_to_le16(offload->ctxt_desc_l2tag2);
		ctxt_desc->qw1 = cpu_to_le64(offload->ctxt_desc_qw1);
		ctxt_desc->ipset_offset =
				cpu_to_le16(offload->ctxt_desc_ipsec_offset);
	}

l_end:
	return ret;
}

static netdev_tx_t sxe2vf_queue_xmit(struct sk_buff *skb, struct sxe2vf_queue *txq)
{
	netdev_tx_t ret = NETDEV_TX_OK;
	struct sxe2vf_tx_buf *first_buf = NULL;
	struct sxe2vf_tx_offload_info offload = {};
	s32 res;
	u32 need_desc_count;
	struct sxe2vf_adapter *adapter = netdev_priv(txq->netdev);

	sxe2vf_trace(queue_xmit, txq, skb);
	need_desc_count = sxe2vf_tx_desc_count(skb);
	if (sxe2vf_chk_linearize(skb, need_desc_count)) {
		if (__skb_linearize(skb))
			goto l_free;

		need_desc_count = SXE2VF_ESTIMATE_DESC_COUNT_FOR_SKB_FRAG(skb->len);
		txq->stats->tx_stats.tx_linearize++;
	}
	if (unlikely(sxe2vf_tx_desc_unused_count(txq) < need_desc_count)) {
		if (sxe2vf_maybe_stop_tx(txq, (u16)need_desc_count)) {
			txq->stats->tx_stats.tx_busy++;
			ret = NETDEV_TX_BUSY;
			LOG_WARN_BDF("txq desc is not enough, txq_idx=%d need desc \t"
				     "%u max %lu",
				     txq->idx_in_vsi, need_desc_count,
				     SXE2VF_TX_DESC_NEEDED);
			goto l_end;
		}
	}

	first_buf = sxe2vf_tx_first_buffer_get(skb, txq);

	res = sxe2vf_tx_feature_offload(txq, first_buf, &offload);
	if (res < 0) {
		LOG_ERROR_BDF("tx offload failed, tx queue->idx=%u\n",
			      txq->idx_in_vsi);
		goto l_free;
	}
	res = sxe2vf_xmit_pkt(txq, first_buf, &offload);
	if (res)
		LOG_ERROR_BDF("tx dma mapping err, queue idx=%u\n", txq->idx_in_vsi);

	return NETDEV_TX_OK;
l_free:
	dev_kfree_skb_any(skb);
	if (first_buf)
		first_buf->skb = NULL;

l_end:
	sxe2vf_trace(queue_xmit_drop, txq, skb);
	return ret;
}

netdev_tx_t sxe2vf_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	netdev_tx_t ret = NETDEV_TX_OK;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2vf_queue *txq;

	txq = vsi->txqs.q[skb->queue_mapping];
	LOG_DEBUG_BDF("skb:%pK netdev:%pK netdev_priv:%pK  \t"
		      "vsi:%pK txq:%pK idx:%u.\n",
		      skb, netdev, adapter, vsi, txq, skb->queue_mapping);
	if (!txq) {
		ret = NETDEV_TX_BUSY;
		goto l_end;
	}

	if (skb_put_padto(skb, SXE2VF_MIN_TX_LEN)) {
		ret = NETDEV_TX_OK;
		goto l_end;
	}

	return sxe2vf_queue_xmit(skb, txq);
l_end:
	return ret;
}

static s32 sxe2vf_tx_ring_alloc(struct sxe2vf_queue *txq, struct sxe2vf_vsi *vsi)
{
	u32 size;
	struct device *dev = txq->dev;
	struct sxe2vf_adapter *adapter = txq->vsi->adapter;
	struct sxe2vf_desc_ring *desc_ring = &txq->desc;

	txq->tx_buf = kcalloc(txq->depth, sizeof(struct sxe2vf_tx_buf),
			      GFP_KERNEL | __GFP_ZERO);
	if (!txq->tx_buf) {
		LOG_ERROR_BDF("unable to allocate memory for tx buf ring\n");
		goto l_end;
	}

	size = ALIGN(txq->depth * sizeof(union sxe2vf_tx_data_desc), PAGE_SIZE);
	desc_ring->base_addr = dma_alloc_coherent(dev, size, &desc_ring->dma,
						  GFP_KERNEL | __GFP_ZERO);
	if (!desc_ring->base_addr) {
		LOG_DEV_ERR("unable to allocate memory \t"
			    "for the Tx descriptor ring, size=%u\n",
			    size);
		goto l_alloc_failed;
	}

	txq->netdev = vsi->netdev;
	txq->next_to_use = 0;
	txq->next_to_clean = 0;

	LOG_DEBUG_BDF(">>>> txq[%u]:%pK tx_buf:%pK.\n", txq->idx_in_vsi, txq,
		      txq->tx_buf);
	return 0;

l_alloc_failed:
	kfree(txq->tx_buf);
	txq->tx_buf = NULL;
l_end:
	return -ENOMEM;
}

static void sxe2vf_tx_ring_free(struct sxe2vf_queue *txq)
{
	u32 size;

	kfree(txq->tx_buf);
	txq->tx_buf = NULL;

	if (txq->desc.base_addr) {
		size = ALIGN(txq->depth * sizeof(union sxe2vf_tx_data_desc),
			     PAGE_SIZE);
		dma_free_coherent(txq->dev, size, txq->desc.base_addr,
				  txq->desc.dma);
		txq->desc.base_addr = NULL;
	}
}

static s32 sxe2vf_tx_rings_alloc(struct sxe2vf_vsi *vsi)
{
	s32 ret;
	u16 i;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	sxe2vf_for_each_vsi_txq(vsi, i)
	{
		ret = sxe2vf_tx_ring_alloc(vsi->txqs.q[i], vsi);
		if (ret) {
			LOG_ERROR_BDF("txq[%d] ring alloc failed, ret=%d\n", i, ret);
			goto l_end;
		}
	}
	return 0;
l_end:
	while (i--)
		sxe2vf_tx_ring_free(vsi->txqs.q[i]);

	return ret;
}

s32 sxe2vf_tx_hw_cfg(struct sxe2vf_vsi *vsi)
{
	return sxe2vf_txq_cfg_request(vsi->adapter);
}

static void sxe2vf_tx_ring_clean(struct sxe2vf_queue *txq)
{
	u16 i;
	u32 size;

	if (!txq->tx_buf)
		return;

	for (i = 0; i < txq->depth; i++)
		sxe2vf_tx_buffer_unmap(txq, &txq->tx_buf[i]);

	(void)memset(txq->tx_buf, 0, sizeof(*txq->tx_buf) * txq->depth);

	size = ALIGN(txq->depth * sizeof(union sxe2vf_tx_data_desc), PAGE_SIZE);
	(void)memset(txq->desc.base_addr, 0, size);

	txq->next_to_use = 0;
	txq->next_to_clean = 0;

	netdev_tx_reset_queue(sxe2vf_queue_to_netdevq(txq));
}

void sxe2vf_tx_rings_clean(struct sxe2vf_vsi *vsi)
{
	u16 i;

	sxe2vf_for_each_vsi_txq(vsi, i)
	{
		sxe2vf_tx_ring_clean(vsi->txqs.q[i]);
	}
}

static void sxe2vf_tx_ring_res_free(struct sxe2vf_queue *txq)
{
	sxe2vf_tx_ring_clean(txq);
	sxe2vf_tx_ring_free(txq);
}

void sxe2vf_tx_rings_res_free(struct sxe2vf_vsi *vsi)
{
	u32 i;

	if (!vsi)
		return;

	sxe2vf_for_each_vsi_txq(vsi, i)
			sxe2vf_tx_ring_res_free(vsi->txqs.q[i]);
}

static void sxe2vf_tx_rings_free(struct sxe2vf_vsi *vsi)
{
	u32 i;

	sxe2vf_for_each_vsi_txq(vsi, i)
			sxe2vf_tx_ring_free(vsi->txqs.q[i]);
}

STATIC void sxe2vf_tx_configure_tail(struct sxe2vf_vsi *vsi)
{
	struct sxe2vf_adapter *adapter = vsi->adapter;
	u32 i;
	struct sxe2vf_queue *txq;

	for (i = 0; i < vsi->txqs.q_cnt; i++) {
		txq = vsi->txqs.q[i];
		txq->desc.tail = adapter->hw.reg_base_addr + (u32)SXE2VF_TXQ_TAIL(i);
	}
}

s32 sxe2vf_tx_cfg(struct sxe2vf_vsi *vsi)
{
	s32 ret;
	struct sxe2vf_adapter *adapter = vsi->adapter;

	ret = sxe2vf_tx_rings_alloc(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx resource alloc failed, ret=%d\n", ret);
		goto l_end;
	}
	sxe2vf_tx_configure_tail(vsi);

	ret = sxe2vf_tx_hw_cfg(vsi);
	if (ret) {
		LOG_ERROR_BDF("tx hw configure failed, ret=%d\n", ret);
		sxe2vf_wait_in_resetting(adapter, false);
		goto l_free;
	}

	return 0;

l_free:
	sxe2vf_tx_rings_free(vsi);
l_end:
	return ret;
}

static inline void sxe2vf_tx_desc_buf_update(struct sxe2vf_queue *txq,
					     struct sxe2vf_tx_buf **tx_buf,
					     union sxe2vf_tx_data_desc **tx_desc,
					     u32 *ntc)
{
	(*tx_buf)++;
	(*tx_desc)++;
	++(*ntc);
	if (unlikely(!(*ntc))) {
		*ntc -= txq->depth;
		*tx_buf = txq->tx_buf;
		*tx_desc = SXE2VF_TX_DESC(txq, 0);
	}
}

static inline void sxe2vf_tx_skb_unmap(struct sxe2vf_queue *txq,
				       struct sxe2vf_tx_buf *tx_buf)
{
	dma_unmap_single(txq->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);

	dma_unmap_len_set(tx_buf, len, 0);
}

static void sxe2vf_tx_desc_ring_unmap(struct sxe2vf_queue *txq, s32 napi_budget,
				      u16 *budget,
				      struct sxe2vf_queue_stats *queue_stats)
{
	struct sxe2vf_tx_buf *tx_buf;
	u32 ntc = txq->next_to_clean;
	union sxe2vf_tx_data_desc *tx_desc;
	union sxe2vf_tx_data_desc *eop_desc;
	struct sxe2vf_adapter *adapter = netdev_priv(txq->netdev);

	tx_buf = &txq->tx_buf[ntc];
	tx_desc = SXE2VF_TX_DESC(txq, ntc);
	ntc -= txq->depth;

	do {
		eop_desc = tx_buf->next_to_watch;

		if (!eop_desc)
			break;

		LOG_DEBUG_BDF("tx queue clean start: queue idx=%u, \t"
			      "next_to_use=%d, next_to_clean=%d, budget=%d, \t"
			      "next_to_watch=%pK, eop_desc.wb.dd=%#08llx\n",
			      txq->idx_in_vsi, txq->next_to_use, txq->next_to_clean,
			      *budget, tx_buf->next_to_watch,
			      ((union sxe2vf_tx_data_desc *)tx_buf->next_to_watch)
					      ->wb.dd);

		/* in order to force CPU ordering */
		smp_rmb();

		sxe2vf_trace(txq_irq_clean, txq, tx_desc, tx_buf);

		if (!(eop_desc->wb.dd &
		      cpu_to_le64(SXE2VF_TX_DESC_DTYPE_DESC_DONE))) {
			break;
		}

		tx_buf->next_to_watch = NULL;

		queue_stats->bytes += tx_buf->bytecount;
		queue_stats->packets += tx_buf->gso_segs;

		napi_consume_skb(tx_buf->skb, napi_budget);

		LOG_DEBUG_BDF("tx queue clean: budget=%d, bytes=%llu, packet=%llu\n",
			      *budget, queue_stats->bytes, queue_stats->packets);

		sxe2vf_tx_skb_unmap(txq, tx_buf);
		tx_buf->skb = NULL;

		while (tx_desc != eop_desc) {
			sxe2vf_trace(txq_irq_clean_unmap, txq, tx_desc, tx_buf);
			sxe2vf_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);

			if (dma_unmap_len(tx_buf, len))
				sxe2vf_tx_skb_unmap(txq, tx_buf);
		}
		sxe2vf_trace(txq_irq_clean_unmap_eop, txq, tx_desc, tx_buf);
		sxe2vf_tx_desc_buf_update(txq, &tx_buf, &tx_desc, &ntc);

		prefetch(tx_desc);

		--*budget;
	} while (likely(*budget));

	ntc += txq->depth;
	txq->next_to_clean = (u16)ntc;

	LOG_DEBUG_BDF("tx queue clean end: queue idx=%u, next_to_use=%d, \t"
		      "next_to_clean=%d, budget=%d\n",
		      txq->idx_in_vsi, txq->next_to_use, txq->next_to_clean,
		      *budget);
}

static inline void sxe2vf_tx_pkt_stats_update(struct sxe2vf_queue *txq,
					      struct sxe2vf_queue_stats *stats)
{
	u64_stats_update_begin(&txq->syncp);
	txq->stats->bytes += stats->bytes;
	txq->stats->packets += stats->packets;
	u64_stats_update_end(&txq->syncp);
}

bool sxe2vf_txq_irq_clean(struct sxe2vf_queue *txq, s32 napi_budget)
{
	u16 budget = SXE2VF_DFLT_IRQ_WORK;
	struct sxe2vf_queue_stats queue_stats = {};
	struct sxe2vf_adapter *adapter = txq->vsi->adapter;

	sxe2vf_tx_desc_ring_unmap(txq, napi_budget, &budget, &queue_stats);

	sxe2vf_tx_pkt_stats_update(txq, &queue_stats);

	netdev_tx_completed_queue(sxe2vf_queue_to_netdevq(txq),
				  (u32)queue_stats.packets, (u32)queue_stats.bytes);

	if (unlikely(queue_stats.packets && netif_carrier_ok(txq->netdev) &&
		     (sxe2vf_tx_desc_unused_count(txq) >=
		      SXE2VF_TX_WAKE_THRESHOLD))) {
		/* in order to force CPU ordering */
		smp_mb();

		if (netif_tx_queue_stopped(sxe2vf_queue_to_netdevq(txq))) {
			netif_tx_wake_queue(sxe2vf_queue_to_netdevq(txq));
			++txq->stats->tx_stats.tx_restart;
			LOG_WARN_BDF("\n\n txq idx=%u, wake_up\n\n",
				     txq->idx_in_vsi);
		}
	}

	return !!budget;
}

void sxe2vf_tx_timeout(struct net_device *netdev,
		       __always_unused unsigned int txqueue)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_VFR_REQUEST,
			     SXE2VF_RESET_NONE);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);

	LOG_WARN_BDF("vf tx timeout detected queue:%u cnt:%llu.\n", txqueue,
		     adapter->work_ctxt.tx_timeout_cnt++);
}
