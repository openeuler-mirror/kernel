// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/tcp.h>
#include <linux/skbuff.h>
#include "xsc_eth_stats.h"
#include "xsc_eth_common.h"
#include "common/xsc_hsi.h"
#include "common/qp.h"
#include "xsc_eth.h"
#include "xsc_eth_txrx.h"

#define XSC_OPCODE_RAW     0x7

static inline void *xsc_sq_fetch_wqe(struct xsc_sq *sq, size_t size, u16 *pi)
{
	struct xsc_wq_cyc *wq = &sq->wq;
	void *wqe;

	/*caution, sp->pc is default to be zero*/
	*pi  = xsc_wq_cyc_ctr2ix(wq, sq->pc);
	wqe = xsc_wq_cyc_get_wqe(wq, *pi);
	memset(wqe, 0, size);

	return wqe;
}

u16 xsc_tx_get_gso_ihs(struct xsc_sq *sq, struct sk_buff *skb)
{
	struct xsc_sq_stats *stats = sq->stats;
	u16 ihs;

	if (skb->encapsulation) {
		ihs = skb_inner_transport_offset(skb) + inner_tcp_hdrlen(skb);
		stats->tso_inner_packets++;
		stats->tso_inner_bytes += skb->len - ihs;
	} else {
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			ihs = skb_transport_offset(skb) + sizeof(struct udphdr);
		else
			ihs = skb_transport_offset(skb) + tcp_hdrlen(skb);
		stats->tso_packets++;
		stats->tso_bytes += skb->len - ihs;
	}

	return ihs;
}

void xsc_txwqe_build_cseg_csum(struct xsc_sq *sq,
			       struct sk_buff *skb,
			       struct xsc_send_wqe_ctrl_seg *cseg)
{
	if (likely(skb->ip_summed == CHECKSUM_PARTIAL)) {
		if (skb->encapsulation) {
			cseg->csum_en = XSC_ETH_WQE_INNER_AND_OUTER_CSUM;
			sq->stats->csum_partial_inner++;
		} else {
			cseg->csum_en = XSC_ETH_WQE_OUTER_CSUM;
			sq->stats->csum_partial++;
		}
	} else {
		cseg->csum_en = XSC_ETH_WQE_NONE_CSUM;
		sq->stats->csum_none++;
	}
}

static inline struct xsc_sq_dma *xsc_dma_get(struct xsc_sq *sq, u32 i)
{
	return &sq->db.dma_fifo[i & sq->dma_fifo_mask];
}

static inline void xsc_dma_push(struct xsc_sq *sq, dma_addr_t addr, u32 size,
				enum xsc_dma_map_type map_type)
{
	struct xsc_sq_dma *dma = xsc_dma_get(sq, sq->dma_fifo_pc++);

	dma->addr = addr;
	dma->size = size;
	dma->type = map_type;
	ETH_DEBUG_LOG("dma = %p, dma->addr = %#llx\n", dma, dma->addr);
}

static inline void xsc_tx_dma_unmap(struct device *dev, struct xsc_sq_dma *dma)
{
	switch (dma->type) {
	case XSC_DMA_MAP_SINGLE:
		dma_unmap_single(dev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	case XSC_DMA_MAP_PAGE:
		dma_unmap_page(dev, dma->addr, dma->size, DMA_TO_DEVICE);
		break;
	default:
		ETH_DEBUG_LOG("%s\n", "xsc_tx_dma_unmap unknown DMA type!\n");
	}
}

static void xsc_dma_unmap_wqe_err(struct xsc_sq *sq, u8 num_dma)
{
	struct xsc_adapter *adapter = sq->channel->adapter;
	struct device *dev  = adapter->dev;

	int i;

	for (i = 0; i < num_dma; i++) {
		struct xsc_sq_dma *last_pushed_dma = xsc_dma_get(sq, --sq->dma_fifo_pc);

		xsc_tx_dma_unmap(dev, last_pushed_dma);
	}
}

static void xsc_txwqe_build_csegs(struct xsc_sq *sq, struct sk_buff *skb,
				  u16 mss, u16 ihs, u16 headlen,
				  u8 opcode, u16 ds_cnt, u32 num_bytes,
				  struct xsc_send_wqe_ctrl_seg *cseg)
{
	struct xsc_core_device *xdev = sq->cq.xdev;
	int send_wqe_ds_num_log = ilog2(xdev->caps.send_ds_num);

	xsc_txwqe_build_cseg_csum(sq, skb, cseg);

	if (mss != 0) {
		cseg->has_pph = 0;
		cseg->so_type = 1;
		cseg->so_hdr_len = ihs;
		cseg->so_data_size = cpu_to_le16(mss);
	}

	cseg->msg_opcode =  opcode;
	cseg->wqe_id = cpu_to_le16(sq->pc << send_wqe_ds_num_log);
	cseg->ds_data_num = ds_cnt - XSC_SEND_WQEBB_CTRL_NUM_DS;
	cseg->msg_len = cpu_to_le32(num_bytes);

	cseg->ce = 1;

	WQE_CSEG_DUMP("cseg", cseg);
}

static int xsc_txwqe_build_dsegs(struct xsc_sq *sq, struct sk_buff *skb,
				 u16 ihs, u16 headlen,
				 struct xsc_wqe_data_seg *dseg)
{
	dma_addr_t dma_addr = 0;
	u8 num_dma = 0;
	int i;
	struct xsc_adapter *adapter = sq->channel->adapter;
	struct device *dev  = adapter->dev;

	if (headlen) {
		dma_addr = dma_map_single(dev, skb->data, headlen, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->va = cpu_to_le64(dma_addr);
		dseg->mkey  = cpu_to_le32(sq->mkey_be);
		dseg->seg_len = cpu_to_le32(headlen);

		WQE_DSEG_DUMP("dseg-headlen", dseg);

		xsc_dma_push(sq, dma_addr, headlen, XSC_DMA_MAP_SINGLE);
		num_dma++;
		dseg++;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		int fsz = skb_frag_size(frag);

		dma_addr = skb_frag_dma_map(dev, frag, 0, fsz, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->va = cpu_to_le64(dma_addr);
		dseg->mkey = cpu_to_le32(sq->mkey_be);
		dseg->seg_len = cpu_to_le32(fsz);

		WQE_DSEG_DUMP("dseg-frag", dseg);

		xsc_dma_push(sq, dma_addr, fsz, XSC_DMA_MAP_PAGE);
		num_dma++;
		dseg++;
	}

	return num_dma;

dma_unmap_wqe_err:
	xsc_dma_unmap_wqe_err(sq, num_dma);
	return -ENOMEM;
}

static inline bool xsc_wqc_has_room_for(struct xsc_wq_cyc *wq,
					u16 cc, u16 pc, u16 n)
{
	return (xsc_wq_cyc_ctr2ix(wq, cc - pc) >= n) || (cc == pc);
}

static inline void xsc_sq_notify_hw(struct xsc_wq_cyc *wq, u16 pc,
				    struct xsc_sq *sq)
{
	struct xsc_adapter *adapter = sq->channel->adapter;
	struct xsc_core_device *xdev  = adapter->xdev;
	union xsc_send_doorbell doorbell_value;
	int send_ds_num_log = ilog2(xdev->caps.send_ds_num);

	/*reverse wqe index to ds index*/
	doorbell_value.next_pid = pc << send_ds_num_log;
	doorbell_value.qp_num = sq->sqn;

	/* Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	wmb();
	ETH_DEBUG_LOG("pc = %d sqn = %d\n", pc, sq->sqn);
	ETH_DEBUG_LOG("doorbell_value = %#x\n", doorbell_value.send_data);
	writel(doorbell_value.send_data, REG_ADDR(xdev, xdev->regs.tx_db));
}

void xsc_txwqe_complete(struct xsc_sq *sq, struct sk_buff *skb,
			u8 opcode, u16 ds_cnt, u8 num_wqebbs, u32 num_bytes, u8 num_dma,
			struct xsc_tx_wqe_info *wi)
{
	struct xsc_wq_cyc *wq = &sq->wq;

	wi->num_bytes = num_bytes;
	wi->num_dma = num_dma;
	wi->num_wqebbs = num_wqebbs;
	wi->skb = skb;

#ifdef XSC_BQL_SUPPORT
	ETH_SQ_STATE(sq);
	netdev_tx_sent_queue(sq->txq, num_bytes);
	ETH_SQ_STATE(sq);
#endif

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		ETH_DEBUG_LOG("%s\n", "hw tstamp\n");
	}

	/*1*/
	sq->pc += wi->num_wqebbs;
	ETH_DEBUG_LOG("%d\n", sq->pc);

	if (unlikely(!xsc_wqc_has_room_for(wq, sq->cc, sq->pc, sq->stop_room))) {
		netif_tx_stop_queue(sq->txq);
		sq->stats->stopped++;
		ETH_DEBUG_LOG("%p %d %d %d\n", wq, sq->cc, sq->pc, sq->stop_room);
	}

	ETH_DEBUG_LOG("%d %d\n", xsc_netdev_xmit_more(skb), netif_xmit_stopped(sq->txq));

	if (!xsc_netdev_xmit_more(skb) || netif_xmit_stopped(sq->txq))
		xsc_sq_notify_hw(wq, sq->pc, sq);
}

static void xsc_dump_error_sqcqe(struct xsc_sq *sq,
				 struct xsc_cqe *cqe)
{
	u32 ci = xsc_cqwq_get_ci(&sq->cq.wq);
	struct net_device *netdev  = sq->channel->netdev;

	net_err_ratelimited("Err cqe on dev %s cqn=0x%x ci=0x%x sqn=0x%x err_code=0x%x qpid=0x%x\n",
			    netdev->name, sq->cq.xcq.cqn, ci,
			    sq->sqn, get_cqe_opcode(cqe), cqe->qp_id);

#ifdef XSC_DEBUG
	xsc_dump_err_cqe(sq->cq.xdev, cqe);
#endif
}

void xsc_free_tx_wqe(struct device *dev, struct xsc_sq *sq)
{
	struct xsc_tx_wqe_info *wi;
	struct sk_buff *skb;
	u16 ci, npkts = 0;
	u32 nbytes = 0;
	int i;

	while (sq->cc != sq->pc) {
		ci = xsc_wq_cyc_ctr2ix(&sq->wq, sq->cc);
		wi = &sq->db.wqe_info[ci];
		skb = wi->skb;

		if (!skb) { /* nop */
			sq->cc++;
			continue;
		}

		for (i = 0; i < wi->num_dma; i++) {
			struct xsc_sq_dma *dma =
				xsc_dma_get(sq, sq->dma_fifo_cc++);

			xsc_tx_dma_unmap(dev, dma);
		}

		dev_kfree_skb_any(skb);
		npkts++;
		nbytes += wi->num_bytes;
		sq->cc += wi->num_wqebbs;
	}

#ifdef XSC_BQL_SUPPORT
	netdev_tx_completed_queue(sq->txq, npkts, nbytes);
#endif
}

#ifdef NEED_CREATE_RX_THREAD
	DECLARE_PER_CPU(bool, txcqe_get);
#endif

bool xsc_poll_tx_cq(struct xsc_cq *cq, int napi_budget)
{
	struct xsc_adapter *adapter;
	struct device *dev;
	struct xsc_sq_stats *stats;
	struct xsc_sq *sq;
	struct xsc_cqe *cqe;
	u32 dma_fifo_cc;
	u32 nbytes = 0;
	u16 npkts = 0;
	u16 sqcc;
	int i = 0;

	sq = container_of(cq, struct xsc_sq, cq);
	if (!test_bit(XSC_ETH_SQ_STATE_ENABLED, &sq->state))
		return false;

	adapter = sq->channel->adapter;
	dev = adapter->dev;

	cqe = xsc_cqwq_get_cqe(&cq->wq);
	if (!cqe)
		goto out;

	stats = sq->stats;

	if (unlikely(get_cqe_opcode(cqe) & BIT(7))) {
		xsc_dump_error_sqcqe(sq, cqe);
		stats->cqe_err++;
		return false;
	}

#ifdef NEED_CREATE_RX_THREAD
	__this_cpu_write(txcqe_get, true);
#endif

	sqcc = sq->cc;

	/* avoid dirtying sq cache line every cqe */
	dma_fifo_cc = sq->dma_fifo_cc;
	i = 0;
	do {
		struct xsc_tx_wqe_info *wi;
		struct sk_buff *skb;
		int j;
		u16 ci;

		xsc_cqwq_pop(&cq->wq);

		ci = xsc_wq_cyc_ctr2ix(&sq->wq, sqcc);
		wi = &sq->db.wqe_info[ci];
		skb = wi->skb;

		/*cqe may be overstanding in real test, not by nop in other*/
		if (unlikely(!skb)) {
			stats->txdone_skb_null++;
			continue;
		}

		for (j = 0; j < wi->num_dma; j++) {
			struct xsc_sq_dma *dma = xsc_dma_get(sq, dma_fifo_cc++);

			xsc_tx_dma_unmap(dev, dma);
		}

#ifndef NEED_CREATE_RX_THREAD
		npkts++;
		nbytes += wi->num_bytes;
		sqcc += wi->num_wqebbs;
		napi_consume_skb(skb, napi_budget);
#else
		npkts++;
		nbytes += wi->num_bytes;
		sqcc += wi->num_wqebbs;
		if (refcount_read(&skb->users) < 1)
			stats->txdone_skb_refcnt_err++;
		napi_consume_skb(skb, 0);
#endif
		ETH_DEBUG_LOG("ci=%d, sqcc=%d, pkts=%d\n", ci, sqcc, npkts);

	} while ((++i <= XSC_TX_POLL_BUDGET) && (cqe = xsc_cqwq_get_cqe(&cq->wq)));

	stats->cqes += i;

	xsc_cq_notify_hw(cq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;
	ETH_DEBUG_LOG("dma_fifo_cc=%d, sqcc=%d\n", dma_fifo_cc, sqcc);

#ifdef XSC_BQL_SUPPORT
	ETH_SQ_STATE(sq);
	netdev_tx_completed_queue(sq->txq, npkts, nbytes);
	ETH_SQ_STATE(sq);
#endif

	if (netif_tx_queue_stopped(sq->txq) &&
	    xsc_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, sq->stop_room)) {
		netif_tx_wake_queue(sq->txq);
		stats->wake++;
	}

out:
	return (i == napi_budget);
}

static uint32_t xsc_eth_xmit_frame(struct sk_buff *skb,
				   struct xsc_sq *sq,
				   struct xsc_tx_wqe *wqe,
				   u16 pi)
{
	struct xsc_send_wqe_ctrl_seg *cseg;
	struct xsc_wqe_data_seg *dseg;
	struct xsc_tx_wqe_info *wi;
	struct xsc_sq_stats *stats = sq->stats;
	struct xsc_core_device *xdev = sq->cq.xdev;
	u16 ds_cnt;
	u16 mss, ihs, headlen;
	u8 opcode;
	u32 num_bytes, num_dma;
	u8 num_wqebbs;

retry_send:
	/* Calc ihs and ds cnt, no writes to wqe yet */
	/*ctrl-ds, it would be reduce in ds_data_num*/
	ds_cnt = XSC_SEND_WQEBB_CTRL_NUM_DS;

	/*in andes inline is bonding with gso*/
	if (skb_is_gso(skb)) {
		opcode    = XSC_OPCODE_RAW;
		mss       = skb_shinfo(skb)->gso_size;
		ihs       = xsc_tx_get_gso_ihs(sq, skb);
		num_bytes = skb->len;
		stats->packets += skb_shinfo(skb)->gso_segs;
	} else {
		opcode    = XSC_OPCODE_RAW;
		mss       = 0;
		ihs       = 0;
		num_bytes = skb->len;
		stats->packets++;
	}

	/*linear data in skb*/
	headlen = skb->len - skb->data_len;
	ds_cnt += !!headlen;
	ds_cnt += skb_shinfo(skb)->nr_frags;
	ETH_DEBUG_LOG("skb_len=%d data_len=%d nr_frags=%d mss=%d ihs=%d headlen=%d ds_cnt=%d\n",
		      skb->len, skb->data_len, skb_shinfo(skb)->nr_frags,
		      mss, ihs, headlen, ds_cnt);

	/*to make the connection, only linear data is present*/
	skbdata_debug_dump(skb, headlen, 1);

	/* Check packet size. */
	if (unlikely(mss == 0 && num_bytes > sq->hw_mtu)) {
		sq->stats->oversize_pkts_sw_drop++;
		goto err_drop;
	}

	num_wqebbs = DIV_ROUND_UP(ds_cnt, xdev->caps.send_ds_num);
	/*if ds_cnt exceed one wqe, drop it*/
	if (num_wqebbs != 1) {
		sq->stats->skb_linear++;
		if (skb_linearize(skb))
			goto err_drop;
		goto retry_send;
	}

	/* fill wqe */
	wi   = (struct xsc_tx_wqe_info *)&sq->db.wqe_info[pi];
	cseg = &wqe->ctrl;
	dseg = &wqe->data[0];

	xsc_txwqe_build_csegs(sq, skb, mss, ihs, headlen,
			      opcode, ds_cnt, num_bytes, cseg);

	/*inline header is also use dma to transport*/
	num_dma = xsc_txwqe_build_dsegs(sq, skb, ihs, headlen, dseg);
	if (unlikely(num_dma < 0))
		goto err_drop;

	xsc_txwqe_complete(sq, skb, opcode, ds_cnt, num_wqebbs, num_bytes,
			   num_dma, wi);

	stats->bytes     += num_bytes;
	stats->xmit_more += xsc_netdev_xmit_more(skb);
	return NETDEV_TX_OK;

err_drop:
	ETH_DEBUG_LOG("%s: drop skb, ds_cnt=%d, num_wqebbs=%d, num_dma=%d\n",
		      __func__, ds_cnt, num_wqebbs, num_dma);
	stats->dropped++;
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

netdev_tx_t xsc_eth_xmit_start(struct sk_buff *skb, struct net_device *netdev)
{
	u32 ret;
	u32 queue_id;
	struct xsc_sq *sq;
	struct xsc_tx_wqe *wqe;
	u16 pi;
	struct xsc_adapter *adapter = netdev_priv(netdev);
	struct xsc_core_device *xdev = adapter->xdev;

	if (!skb) {
		ETH_DEBUG_LOG("skb == NULL\n");
		return NETDEV_TX_OK;
	}

	if (!adapter) {
		ETH_DEBUG_LOG("adapter == NULL\n");
		return NETDEV_TX_BUSY;
	}

	if (adapter->status != XSCALE_ETH_DRIVER_OK) {
		ETH_DEBUG_LOG("adapter->status = %d\n", adapter->status);
		return NETDEV_TX_BUSY;
	}

	queue_id = skb_get_queue_mapping(skb);
	ETH_DEBUG_LOG("queue_id = %d\n", queue_id);
	assert(adapter->xdev, queue_id < XSC_ETH_MAX_TC_TOTAL);

	sq = adapter->txq2sq[queue_id];
	if (!sq) {
		ETH_DEBUG_LOG("sq = NULL\n");
		return NETDEV_TX_BUSY;
	}
	ETH_DEBUG_LOG("sqn = %d\n", sq->sqn);

	wqe = xsc_sq_fetch_wqe(sq, xdev->caps.send_ds_num * XSC_SEND_WQE_DS, &pi);
	ETH_DEBUG_LOG("wqe = %p pi = %d\n", wqe, pi);
	assert(adapter->xdev, wqe);

#ifndef ANDES_DRIVER
	skb = xsc_accel_handle_tx(skb);
#endif

	ret = xsc_eth_xmit_frame(skb, sq, wqe, pi);

	ETH_DEBUG_LOG("ret = %d\n", ret);

	return ret;
}
