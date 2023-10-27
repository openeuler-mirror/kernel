// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/net_tstamp.h>
#include "xsc_eth.h"
#include "xsc_eth_txrx.h"
#include "xsc_eth_common.h"
#include "xsc_eth_stats.h"
#include <linux/device.h>
#include "../pci/fw/xsc_tbm.h"

#define PAGE_REF_ELEV  (U16_MAX)
/* Upper bound on number of packets that share a single page */
#define PAGE_REF_THRSD (PAGE_SIZE / 64)

static inline void xsc_rq_notify_hw(struct xsc_rq *rq)
{
	struct xsc_core_device *xdev = rq->cq.xdev;
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	union xsc_recv_doorbell doorbell_value;
	u64 rqwqe_id = wq->wqe_ctr << (ilog2(xdev->caps.recv_ds_num));

	ETH_DEBUG_LOG("rq%d_db_val=0x%x, recv_ds=%d\n",
			rq->rqn, doorbell_value.recv_data,
			xdev->caps.recv_ds_num);
	/*reverse wqe index to ds index*/
	doorbell_value.next_pid = rqwqe_id;
	doorbell_value.qp_num = rq->rqn;

	/*keep order*/
	wmb();
	writel(doorbell_value.recv_data, REG_ADDR(xdev, xdev->regs.rx_db));
}

static inline void xsc_skb_set_hash(struct xsc_adapter *adapter,
					struct xsc_cqe64 *cqe,
					struct sk_buff *skb)
{
	struct xsc_rss_params *rss = &adapter->rss_params;
	u32 hash_field;
	bool l3_hash = false;
	bool l4_hash = false;
	int ht = 0;

	if (adapter->netdev->features & NETIF_F_RXHASH) {
		if (skb->protocol == htons(ETH_P_IP)) {
			hash_field = rss->rx_hash_fields[XSC_TT_IPV4_TCP];
			if (hash_field & XSC_HASH_FIELD_SEL_SRC_IP ||
				hash_field & XSC_HASH_FIELD_SEL_DST_IP)
				l3_hash = true;

			if (hash_field & XSC_HASH_FIELD_SEL_SPORT ||
				hash_field & XSC_HASH_FIELD_SEL_DPORT)
				l4_hash = true;
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			hash_field = rss->rx_hash_fields[XSC_TT_IPV6_TCP];
			if (hash_field & XSC_HASH_FIELD_SEL_SRC_IPV6 ||
				hash_field & XSC_HASH_FIELD_SEL_DST_IPV6)
				l3_hash = true;

			if (hash_field & XSC_HASH_FIELD_SEL_SPORT_V6 ||
				hash_field & XSC_HASH_FIELD_SEL_DPORT_V6)
				l4_hash = true;
		}

		if (l3_hash && l4_hash)
			ht = PKT_HASH_TYPE_L4;
		else if (l3_hash)
			ht = PKT_HASH_TYPE_L3;
		if (ht)
			skb_set_hash(skb, be32_to_cpu(cqe->vni), ht);
	}
}

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static inline unsigned int xsc_do_csum(const unsigned char *buff,
					int len, unsigned int sum, bool plus)
{
	unsigned int result = 0;
	u32 result0, result1, result2, result3, result4;

	if (len >= 4) {
		const unsigned char *end = buff + ((unsigned int)len & ~3);
		unsigned int carry = 0;

		do {
			unsigned int w = *(unsigned int *) buff;

			buff += 4;
			result += carry;
			result += w;
			carry = (w > result);
		} while (buff < end);
		result += carry;
		result0 = result;
		result = from32to16(result);
	}
	result1 = result;
	if (len & 2) {
		result += *(unsigned short *) buff;
		buff += 2;
		result2 = result;
		result = from32to16(result);
	}
	result3 = result;
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif

	if (plus) {
		result = from32to16(sum) + from32to16(result);
		result4 = result;
		result = from32to16(result);
	} else {
		result = from32to16(sum) - from32to16(result);
	}

	ETH_DEBUG_LOG("%s: len=%d, csum=0x%x -> %x -> %x -> %x -> %x\n", __func__,
		len, result0, result1, result2, result3, result4);
	return result;
}

static inline bool handle_udp_frag_csum(struct sk_buff *skb, struct epp_pph *pph)
{
#ifdef XSC_UDP_FRAG_HW_CSUM
	struct iphdr *iph;
	char *head = (char *)pph;
	u8 l3_proto = PPH_OUTER_IP_TYPE(head);
	u8 l4_proto = PPH_OUTER_TP_TYPE(head);
	u8 iph_off =  PPH_OUTER_IP_OFST(head);
	u16 iph_len = PPH_OUTER_IP_LEN(pph);
#ifndef UDP_CHECK_0
	u16 csum_off = (u16)PPH_CSUM_OFST(head);
	u8 payload_off = PPH_PAYLOAD_OFST(head);
	u32 check = PPH_CSUM_VAL(head);
#endif

	if (l4_proto != L4_PROTO_UDP && l4_proto != L4_PROTO_NONE)
		return false;

	if (l3_proto == L3_PROTO_IP) {
		iph = (struct iphdr *)(skb->data + iph_off);
		if (!ip_is_fragment(iph))
			return false;

#ifdef UDP_CHECK_0
		if (l4_proto == L4_PROTO_UDP) {
			struct udphdr *uh = (struct udphdr *)(skb->data + iph_off + iph_len);

			uh->check = 0;
		}
		return false;
#else
		if (csum_off == 0)
			csum_off = 256;
		csum_off -= XSC_PPH_HEAD_LEN;

		if (csum_off < payload_off) {
			head = (char *)(skb->data + csum_off);
			check = xsc_do_csum(head, (payload_off - csum_off), check, false);
		} else if (csum_off > payload_off) {
			head = (char *)(skb->data + payload_off);
			check = xsc_do_csum(head, (csum_off - payload_off), check, true);
		}
		skb->csum = csum_unfold((__force __sum16)check);

#ifdef UDP_CSUM_DEBUG
		int dump_len = 256;

		ETH_DEBUG_LOG(
			"ip_id=%d frag_off=0x%x l4_proto=%d l3_proto=%d iph_off=%d ip_len=%d\n",
			ntohs(iph->id), ntohs(iph->frag_off),
			l4_proto, l3_proto, iph_off, iph_len);
		ETH_DEBUG_LOG(
			"skb_len=%d csum_off=%d payload_off=%d check=0x%llx -> 0x%x -> 0x%x\n",
			skb->len, csum_off, payload_off,
			PPH_CSUM_VAL(pph), check, skb->csum);

		if (skb->len < (256 - 64))
			dump_len = skb->len + 64;
		xsc_pkt_pph_dump((char *)pph, dump_len);
#endif
#endif
		return true;
	}
#endif
	return false;
}

static inline void xsc_handle_csum(struct xsc_cqe64 *cqe, struct xsc_rq *rq,
				struct sk_buff *skb, struct xsc_wqe_frag_info *wi)
{
	struct xsc_rq_stats *stats = rq->stats;
	struct xsc_channel *c = rq->cq.channel;
	struct net_device *netdev = c->adapter->netdev;
	struct xsc_dma_info *dma_info = wi->di;
	int offset_from = wi->offset;
	struct epp_pph *hw_pph = page_address(dma_info->page) + offset_from;

	if (unlikely((netdev->features & NETIF_F_RXCSUM) == 0))
		goto csum_none;

	if (unlikely(XSC_GET_EPP2SOC_PPH_ERROR_BITMAP(hw_pph) & PACKET_UNKNOWN))
		goto csum_none;

	if (handle_udp_frag_csum(skb, hw_pph)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		stats->csum_succ++;
		goto out;
	}

	if (XSC_GET_EPP2SOC_PPH_EXT_TUNNEL_TYPE(hw_pph) &&
		(!(cqe->csum_err & OUTER_AND_INNER))) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_level = 1;
		skb->encapsulation = 1;

		stats->csum_unnecessary++;
	} else if (XSC_GET_EPP2SOC_PPH_EXT_TUNNEL_TYPE(hw_pph) &&
			(!(cqe->csum_err & OUTER_BIT) &&
			 (cqe->csum_err & INNER_BIT))) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->csum_level = 0;
		skb->encapsulation = 1;

		stats->csum_unnecessary++;
	} else if (!XSC_GET_EPP2SOC_PPH_EXT_TUNNEL_TYPE(hw_pph) &&
			(!(cqe->csum_err & OUTER_BIT))) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		stats->csum_unnecessary++;
	} else {
		stats->csum_err++;
	}

	goto out;

csum_none:
	skb->csum = 0;
	skb->ip_summed = CHECKSUM_NONE;
	stats->csum_none++;
out:
	return;
}

static inline void xsc_build_rx_skb(struct xsc_cqe64 *cqe,
				      u32 cqe_bcnt,
				      struct xsc_rq *rq,
				      struct sk_buff *skb,
				      struct xsc_wqe_frag_info *wi)
{
	struct xsc_channel *c = rq->cq.channel;
	struct net_device *netdev = c->netdev;
	struct xsc_adapter *adapter = c->adapter;

	skb->mac_len = ETH_HLEN;

	skb_record_rx_queue(skb, rq->ix);
	xsc_handle_csum(cqe, rq, skb, wi);

	skb->protocol = eth_type_trans(skb, netdev);
	xsc_skb_set_hash(adapter, cqe, skb);
}

static inline void xsc_complete_rx_cqe(struct xsc_rq *rq,
					 struct xsc_cqe64 *cqe,
					 u32 cqe_bcnt,
					 struct sk_buff *skb,
					 struct xsc_wqe_frag_info *wi)
{
	struct xsc_rq_stats *stats = rq->stats;

	stats->packets++;
	stats->bytes += cqe_bcnt;
	xsc_build_rx_skb(cqe, cqe_bcnt, rq, skb, wi);
}

static inline void xsc_add_skb_frag(struct xsc_rq *rq,
					struct sk_buff *skb,
					struct xsc_dma_info *di,
					u32 frag_offset, u32 len,
					unsigned int truesize)
{
	struct xsc_channel *c = rq->cq.channel;
	struct device *dev  = c->adapter->dev;

	dma_sync_single_for_cpu(dev, di->addr + frag_offset, len, DMA_FROM_DEVICE);
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
			di->page, frag_offset, len, truesize);

	di->refcnt_bias--;
}

static inline void xsc_copy_skb_header(struct device *dev,
					struct sk_buff *skb,
					struct xsc_dma_info *dma_info,
					int offset_from, u32 headlen)
{
	void *from = page_address(dma_info->page) + offset_from;
	/* Aligning len to sizeof(long) optimizes memcpy performance */
	unsigned int len = ALIGN(headlen, sizeof(long));

	dma_sync_single_for_cpu(dev, dma_info->addr + offset_from, len,
				DMA_FROM_DEVICE);
	skb_copy_to_linear_data(skb, from, len);
}

struct sk_buff *xsc_skb_from_cqe_nonlinear(struct xsc_rq *rq,
						struct xsc_wqe_frag_info *wi,
						u32 cqe_bcnt, u8 has_pph)
{
	struct xsc_rq_frag_info *frag_info = &rq->wqe.info.arr[0];
	struct xsc_wqe_frag_info *head_wi = wi;
	u16 headlen      = min_t(u32, XSC_RX_MAX_HEAD, cqe_bcnt);
	u16 frag_headlen = headlen;
	u16 byte_cnt     = cqe_bcnt - headlen;
	struct sk_buff *skb;
	struct xsc_channel *c = rq->cq.channel;
	struct device *dev  = c->adapter->dev;
	struct net_device *netdev  = c->adapter->netdev;
	u8 fragcnt = 0;
	u16 head_offset = head_wi->offset;

#ifndef NEED_CREATE_RX_THREAD
	skb = napi_alloc_skb(rq->cq.napi, ALIGN(XSC_RX_MAX_HEAD, sizeof(long)));
#else
	skb = netdev_alloc_skb(netdev, ALIGN(XSC_RX_MAX_HEAD, sizeof(long)));
#endif
	if (unlikely(!skb)) {
		rq->stats->buff_alloc_err++;
		return NULL;
	}

	prefetchw(skb->data);

	if (likely(has_pph)) {
		head_offset += XSC_PPH_HEAD_LEN;
		headlen -= XSC_PPH_HEAD_LEN;
	}

	while (byte_cnt) {
		/*figure out whether the first fragment can be a page ?*/
		u16 frag_consumed_bytes =
			min_t(u16, frag_info->frag_size - frag_headlen, byte_cnt);

		xsc_add_skb_frag(rq, skb, wi->di, wi->offset + frag_headlen,
				   frag_consumed_bytes, frag_info->frag_stride);
		byte_cnt -= frag_consumed_bytes;
		frag_headlen = 0;
		ETH_DEBUG_LOG("consumed=%d, frag_size=%d, byte_cnt=%d, refcnt=%d, addr=0x%llx\n",
				frag_consumed_bytes, frag_info->frag_size, byte_cnt,
				wi->di->refcnt_bias, (u64)wi->di->addr);

		/*to protect extend wqe read, drop exceed bytes*/
		fragcnt++;
		if (fragcnt == rq->wqe.info.num_frags) {
			if (byte_cnt) {
				rq->stats->oversize_pkts_sw_drop += byte_cnt;
				netdev_warn(netdev, "large packet reach the maximum rev-wqe num.\n");
				netdev_warn(netdev, "%u bytes dropped: frag_num=%d, headlen=%d, cqe_cnt=%d, frag0_bytes=%d, frag_size=%d\n",
					byte_cnt, fragcnt, headlen, cqe_bcnt,
					frag_consumed_bytes, frag_info->frag_size);
			}
			break;
		}

		frag_info++;
		wi++;
	}

	/* copy header */
	xsc_copy_skb_header(dev, skb, head_wi->di, head_offset, headlen);

	/* skb linear part was allocated with headlen and aligned to long */
	skb->tail += headlen;
	skb->len  += headlen;

	skbdata_debug_dump(skb, headlen, 0);

	return skb;
}

static inline void page_ref_elev(struct xsc_dma_info *dma_info)
{
	page_ref_add(dma_info->page, PAGE_REF_ELEV);
	dma_info->refcnt_bias += PAGE_REF_ELEV;
}

static inline bool xsc_rx_cache_is_empty(struct xsc_page_cache *cache)
{
	return cache->head < 0;
}

static inline bool xsc_rx_cache_page_busy(struct xsc_page_cache *cache, u32 i)
{
	struct xsc_dma_info *di = &cache->page_cache[i];

	return (page_ref_count(di->page) - di->refcnt_bias) != 1;
}

static inline void xsc_rx_cache_page_swap(struct xsc_page_cache *cache,
						u32 a, u32 b)
{
	struct xsc_dma_info tmp;

	tmp = cache->page_cache[a];
	cache->page_cache[a] = cache->page_cache[b];
	cache->page_cache[b] = tmp;
}

static inline void xsc_rx_cache_reduce_reset_watch(struct xsc_page_cache *cache)
{
	struct xsc_page_cache_reduce *reduce = &cache->reduce;

	reduce->next_ts = ilog2(cache->sz) == cache->log_min_sz ?
				MAX_JIFFY_OFFSET : jiffies + reduce->grace_period;
	reduce->success = 0;
}

static inline bool xsc_page_is_reserved(struct page *page)
{
	return page_is_pfmemalloc(page) || page_to_nid(page) != numa_mem_id();
}

static inline bool xsc_rx_cache_check_reduce(struct xsc_rq *rq)
{
	struct xsc_page_cache *cache = &rq->page_cache;

	if (!cache->page_cache)
		return false;

	if (unlikely(test_bit(XSC_ETH_RQ_STATE_CACHE_REDUCE_PENDING, &rq->state)))
		return false;

	if (time_before(jiffies, cache->reduce.next_ts))
		return false;

	if (likely(!xsc_rx_cache_is_empty(cache)) &&
		xsc_rx_cache_page_busy(cache, cache->head))
		goto reset_watch;

	if (ilog2(cache->sz) == cache->log_min_sz)
		goto reset_watch;

	/* would like to reduce */
	if (cache->reduce.success < XSC_PAGE_CACHE_REDUCE_SUCCESS_CNT) {
		cache->reduce.success++;
		return false;
	}

	return true;

reset_watch:
	xsc_rx_cache_reduce_reset_watch(cache);
	return false;

}

static inline void xsc_rx_cache_may_reduce(struct xsc_rq *rq)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	struct xsc_page_cache_reduce *reduce = &cache->reduce;
	int max_new_head;

	if (!xsc_rx_cache_check_reduce(rq))
		return;

	/* do reduce */
	rq->stats->cache_rdc++;
	cache->sz >>= 1;
	max_new_head = (cache->sz >> 1) - 1;
	if (cache->head > max_new_head) {
		u32 npages = cache->head - max_new_head;

		cache->head = max_new_head;
		if (cache->lrs >= cache->head)
			cache->lrs = 0;

		memcpy(reduce->pending, &cache->page_cache[cache->head + 1],
			npages * sizeof(*reduce->pending));
		reduce->npages = npages;
		set_bit(XSC_ETH_RQ_STATE_CACHE_REDUCE_PENDING, &rq->state);
	}

	xsc_rx_cache_reduce_reset_watch(cache);
}

static inline bool xsc_rx_cache_extend(struct xsc_rq *rq)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	struct xsc_page_cache_reduce *reduce = &cache->reduce;
	u8 log_limit_sz = cache->log_min_sz + XSC_PAGE_CACHE_LOG_MAX_RQ_MULT;

	if (ilog2(cache->sz) >= log_limit_sz)
		return false;

	rq->stats->cache_ext++;
	cache->sz <<= 1;

	xsc_rx_cache_reduce_reset_watch(cache);
	schedule_delayed_work_on(smp_processor_id(), &reduce->reduce_work,
				reduce->delay);
	return true;
}

static inline bool xsc_rx_cache_get(struct xsc_rq *rq,
					  struct xsc_dma_info *dma_info)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	struct xsc_rq_stats *stats = rq->stats;
	struct xsc_core_device *xdev = rq->cq.xdev;

	if (unlikely(xsc_rx_cache_is_empty(cache)))
		goto err_no_page;

	xsc_rx_cache_page_swap(cache, cache->head, cache->lrs);
	cache->lrs++;
	if (cache->lrs >= cache->head)
		cache->lrs = 0;
	if (xsc_rx_cache_page_busy(cache, cache->head))
		goto err_no_page;

	stats->cache_reuse++;
	*dma_info = cache->page_cache[cache->head--];

	dma_sync_single_for_device(&xdev->pdev->dev, dma_info->addr,
					PAGE_SIZE, DMA_FROM_DEVICE);
	if (unlikely(page_ref_count(dma_info->page) <= PAGE_REF_THRSD))
		page_ref_elev(dma_info);

	return true;

err_no_page:
	stats->cache_alloc++;
	cache->reduce.success = 0;

	return false;
}

static inline bool xsc_rx_cache_put(struct xsc_rq *rq,
				struct xsc_dma_info *dma_info)
{
	struct xsc_page_cache *cache = &rq->page_cache;
	struct xsc_rq_stats *stats = rq->stats;

	if (unlikely(cache->head == cache->sz - 1)) {
		if (!xsc_rx_cache_extend(rq)) {
			rq->stats->cache_full++;
			return false;
		}
	}

	if (unlikely(xsc_page_is_reserved(dma_info->page))) {
		stats->cache_waive++;
		return false;
	}

	cache->page_cache[++cache->head] = *dma_info;
	return true;
}

void xsc_page_dma_unmap(struct xsc_rq *rq, struct xsc_dma_info *dma_info)
{
	struct xsc_channel *c = rq->cq.channel;
	struct device *dev = c->adapter->dev;

	dma_unmap_page(dev, dma_info->addr, XSC_RX_FRAG_SZ, rq->buff.map_dir);
}

static inline void xsc_put_page(struct xsc_dma_info *dma_info)
{
	page_ref_sub(dma_info->page, dma_info->refcnt_bias);
	ETH_DEBUG_LOG("free addr=0x%llx, refcnt=(%d, %d)\n",
		dma_info->addr, page_ref_count(dma_info->page), dma_info->refcnt_bias);
	put_page(dma_info->page);
}

void xsc_page_release_dynamic(struct xsc_rq *rq,
				struct xsc_dma_info *dma_info, bool recycle)
{
	if (likely(recycle)) {
#ifdef XSC_PAGE_CACHE
		if (xsc_rx_cache_put(rq, dma_info))
			return;
#endif

		xsc_page_dma_unmap(rq, dma_info);
		page_ref_sub(dma_info->page, dma_info->refcnt_bias);
		page_pool_recycle_direct(rq->page_pool, dma_info->page);
	} else {
		xsc_page_dma_unmap(rq, dma_info);

		page_pool_release_page(rq->page_pool, dma_info->page);

		xsc_put_page(dma_info);
	}
}

static inline void xsc_put_rx_frag(struct xsc_rq *rq,
				struct xsc_wqe_frag_info *frag, bool recycle)
{
	if (frag->last_in_page)
		xsc_page_release_dynamic(rq, frag->di, recycle);
}

static inline void xsc_free_rx_wqe(struct xsc_rq *rq,
				     struct xsc_wqe_frag_info *wi, bool recycle)
{
	int i;

	for (i = 0; i < rq->wqe.info.num_frags; i++, wi++) {
		if (i < rq->frags_reuse_num || !recycle)
			xsc_put_rx_frag(rq, wi, recycle);
	}
}

static inline void xsc_free_rx_wqe_reserve_ds(struct xsc_rq *rq,
				     struct xsc_wqe_frag_info *wi)
{
	int i;

	for (i = 0; i < rq->wqe.info.num_frags; i++, wi++) {
		if (i >= rq->frags_reuse_num) {
#ifdef XSC_DEBUG
			if (page_ref_count(wi->di->page) - wi->di->refcnt_bias > 1)
				ETH_DEBUG_LOG("frag%d, last_in_page=%d, refcnt=%d, bias=%d\n",
					i, wi->last_in_page,
					page_ref_count(wi->di->page), wi->di->refcnt_bias);
#endif
			xsc_put_rx_frag(rq, wi, false);
		}
	}
}

static inline struct xsc_wqe_frag_info *get_frag(struct xsc_rq *rq, u16 ix)
{
	return &rq->wqe.frags[ix << rq->wqe.info.log_num_frags];
}

void xsc_eth_handle_rx_cqe(struct xsc_cqwq *cqwq,
			struct xsc_rq *rq, struct xsc_cqe64 *cqe)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	struct xsc_channel *c = rq->cq.channel;
	struct xsc_wqe_frag_info *wi;
	struct sk_buff *skb;
	u32 cqe_bcnt;
	u16 ci;
	u8 cqe_opcode = get_cqe_opcode(cqe);

	ci = xsc_wq_cyc_ctr2ix(wq, cqwq->cc);
	wi  = get_frag(rq, ci);
	if (unlikely(cqe_opcode & BIT(7))) {
		rq->stats->wqe_err++;
		goto free_wqe;
	}

	cqe_bcnt = le32_to_cpu(cqe->msg_len);
	ETH_DEBUG_LOG("data_len=%d, cc=%d", cqe_bcnt, ci);

	/* Check packet size. */
	if (unlikely(cqe_bcnt > rq->hw_mtu)) {
		if (!XSC_GET_PFLAG(&c->adapter->nic_param, XSC_PFLAG_DROPLESS_RQ)) {
			rq->stats->oversize_pkts_sw_drop++;
			goto free_wqe;
		}
	}

	skb = rq->wqe.skb_from_cqe(rq, wi, cqe_bcnt, cqe->has_pph);
	if (!skb)
		goto free_wqe;

	xsc_complete_rx_cqe(rq, cqe, cqe_bcnt, skb, wi);

#ifdef NEED_CREATE_RX_THREAD
	netif_rx_ni(skb);
#else
	napi_gro_receive(rq->cq.napi, skb);
#endif

free_wqe:
	xsc_free_rx_wqe(rq, wi, true);
	xsc_wq_cyc_pop(wq);
}

static void xsc_dump_error_rqcqe(struct xsc_rq *rq,
				 struct xsc_cqe64 *cqe)
{
	struct xsc_channel *c = rq->cq.channel;
	struct net_device *netdev  = c->adapter->netdev;
	u32 ci = xsc_cqwq_get_ci(&rq->cq.wq);

	net_err_ratelimited(
		"Error cqe on dev=%s, cqn=%d, ci=%d, rqn=%d, qpn=%d, error_code=0x%x\n",
		netdev->name, rq->cq.xcq.cqn, ci,
		rq->rqn, cqe->qp_id, get_cqe_opcode(cqe));

#ifdef XSC_DEBUG
	xsc_dump_err_cqe(rq->cq.xdev, cqe);
#endif
}

int xsc_poll_rx_cq(struct xsc_cq *cq, int budget)
{
	struct xsc_rq *rq = container_of(cq, struct xsc_rq, cq);
	struct xsc_cqwq *cqwq = &cq->wq;
	struct xsc_cqe64 *cqe;
	int work_done = 0;
	struct xsc_ch_stats *ch_stats = cq->channel->stats;

	if (!test_bit(XSC_ETH_RQ_STATE_ENABLED, &rq->state))
		return 0;

	while ((work_done < budget) && (cqe = xsc_cqwq_get_cqe(cqwq))) {
		if (unlikely(get_cqe_opcode(cqe) & BIT(7))) {
			xsc_dump_error_rqcqe(rq, cqe);
			rq->stats->cqe_err++;
			break;
		}

		rq->stats->cqes++;

		rq->handle_rx_cqe(cqwq, rq, cqe);
		++work_done;

		xsc_cqwq_pop(cqwq);
	}

	if (!work_done)
		return 0;

	xsc_cq_notify_hw(cq);
	/* ensure cq space is freed before enabling more cqes */
	wmb();

	rq->post_wqes(rq);

	ch_stats->poll += work_done;
	if (work_done < budget) {
		if (ch_stats->poll == 0)
			ch_stats->poll_0++;
		else if (ch_stats->poll <= 64)
			ch_stats->poll_1_64++;
		else if (ch_stats->poll < 512)
			ch_stats->poll_65_511++;
		else if (ch_stats->poll < 1024)
			ch_stats->poll_512_1023++;
		else if (ch_stats->poll >= 1024)
			cq->channel->stats->poll_1024++;
	}

	return work_done;
}

static inline int xsc_page_alloc_mapped(struct xsc_rq *rq,
					struct xsc_dma_info *dma_info)
{
	struct xsc_channel *c = rq->cq.channel;
	struct device *dev  = c->adapter->dev;

#ifdef XSC_PAGE_CACHE
	if (xsc_rx_cache_get(rq, dma_info))
		return 0;
#endif

	dma_info->page = page_pool_dev_alloc_pages(rq->page_pool);
	if (unlikely(!dma_info->page))
		return -ENOMEM;

	dma_info->refcnt_bias = 0;
	page_ref_elev(dma_info);

	dma_info->addr = dma_map_page(dev, dma_info->page, 0,
				XSC_RX_FRAG_SZ, rq->buff.map_dir);
	if (unlikely(dma_mapping_error(dev, dma_info->addr))) {
		page_ref_sub(dma_info->page, dma_info->refcnt_bias);
		page_pool_recycle_direct(rq->page_pool, dma_info->page);
		dma_info->page = NULL;
		return -ENOMEM;
	}

	return 0;
}

static inline int xsc_get_rx_frag(struct xsc_rq *rq,
				    struct xsc_wqe_frag_info *frag)
{
	int err = 0;

	if (!frag->offset)
		/* On first frag (offset == 0), replenish page (dma_info actually).
		 * Other frags that point to the same dma_info (with a different
		 * offset) should just use the new one without replenishing again
		 * by themselves.
		 */
		err = xsc_page_alloc_mapped(rq, frag->di);

	return err;
}

static int xsc_alloc_rx_wqe(struct xsc_rq *rq, struct xsc_eth_rx_wqe_cyc *wqe, u16 ix)
{
	struct xsc_wqe_frag_info *frag = get_frag(rq, ix);
	u64 addr;
	int i;
	int err;

	for (i = 0; i < rq->wqe.info.num_frags; i++, frag++) {
		if (i >= rq->frags_reuse_num && wqe->data[i].va != 0)
			continue;

		err = xsc_get_rx_frag(rq, frag);
		if (unlikely(err))
			goto free_frags;

		addr = cpu_to_le64(frag->di->addr + frag->offset + rq->buff.headroom);
		wqe->data[i].va = addr;
		wqe->data[i].seg_len = cpu_to_le32(XSC_RX_FRAG_SZ);
		ETH_DEBUG_LOG(
			"rq%d_wqe%d->frag%d, off=%d, last_in_page=%d, refcnt=(%d, %d), addr=0x%llx\n",
			rq->rqn, ix, i, frag->offset, frag->last_in_page,
			page_ref_count(frag->di->page), frag->di->refcnt_bias, addr);
	}

	return 0;

free_frags:
	while (--i >= 0)
		xsc_put_rx_frag(rq, --frag, true);

	return err;
}

void xsc_eth_dealloc_rx_wqe(struct xsc_rq *rq, u16 ix, bool resv_ds)
{
	struct xsc_wqe_frag_info *wi = get_frag(rq, ix);

	if (!resv_ds)
		xsc_free_rx_wqe(rq, wi, false);
	else
		xsc_free_rx_wqe_reserve_ds(rq, wi);
}

void xsc_eth_free_rx_wqes(struct xsc_rq *rq)
{
	u16 wqe_ix;
	u16 wqe_ix_head, wqe_ix_tail;
	struct xsc_wq_cyc *wq = &rq->wqe.wq;

	wqe_ix_tail =  xsc_wq_cyc_get_tail(wq);
	wqe_ix_head =  xsc_wq_cyc_get_head(wq);

	for (wqe_ix = wqe_ix_head; wqe_ix < wqe_ix_tail; wqe_ix++)
		xsc_eth_dealloc_rx_wqe(rq, wqe_ix, true);

	while (!xsc_wq_cyc_is_empty(wq)) {
		wqe_ix = xsc_wq_cyc_get_tail(wq);
		xsc_eth_dealloc_rx_wqe(rq, wqe_ix, false);
		xsc_wq_cyc_pop(wq);
	}
}

static int xsc_alloc_rx_wqes(struct xsc_rq *rq, u16 ix, u8 wqe_bulk)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	struct xsc_eth_rx_wqe_cyc *wqe;
	int err;
	int i;
	int idx;

	for (i = 0; i < wqe_bulk; i++) {
		idx = xsc_wq_cyc_ctr2ix(wq, (ix + i));
		wqe = xsc_wq_cyc_get_wqe(wq, idx);

		err = xsc_alloc_rx_wqe(rq, wqe, idx);
		if (unlikely(err)) {
			rq->stats->buff_alloc_err++;
			goto free_wqes;
		}
	}

	return 0;

free_wqes:
	while (--i >= 0)
		xsc_eth_dealloc_rx_wqe(rq, ix + i, false);

	return err;
}

bool xsc_eth_post_rx_wqes(struct xsc_rq *rq)
{
	struct xsc_wq_cyc *wq = &rq->wqe.wq;
	int left = xsc_wq_cyc_missing(wq);
	u8 wqe_bulk;
	u16 head;
	int alloc;
	int err;

	wqe_bulk = rq->wqe.info.wqe_bulk;
	if (xsc_wq_cyc_missing(wq) < wqe_bulk)
		return false;

	do {
		alloc = min_t(int, wqe_bulk, left);
		head = xsc_wq_cyc_get_head(wq);

		err = xsc_alloc_rx_wqes(rq, head, alloc);
		if (unlikely(err))
			break;

		xsc_wq_cyc_push_n(wq, alloc);
		rq->stats->wqes += alloc;
		left -= alloc;
	} while (left > 0);

	dma_wmb();

	/* ensure wqes are visible to device before updating doorbell record */
	xsc_rq_notify_hw(rq);

	xsc_rx_cache_may_reduce(rq);

	return !!err;
}
