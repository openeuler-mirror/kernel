/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_xdp.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : XDP implementation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"

#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#include "hinic5_crm.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"
#include "hinic5_rx.h"
#include "hinic5_tx.h"
#include "hinic5_xdp.h"

int tx_map_xdpf(struct hinic5_nic_dev *nic_dev, struct hinic5_txq *txq, u16 pi,
		struct hinic5_sq_wqe_combo *wqe_combo)
{
	struct hinic5_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;
	struct hinic5_dma_info *dma_info = txq->tx_info[pi].dma_info;
	struct xdp_frame *xdpf = txq->tx_info[pi].xdpf;
	struct device *dev = nic_dev->lld_dev->dev;

	dma_info->dma = dma_map_single(dev, xdpf->data, xdpf->len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma_info->dma) != 0) {
		XDP_TXQ_STATS_INC(txq, map_xdpf_err);
		return -EFAULT;
	}
	dma_info->len = xdpf->len;

	wqe_desc->hi_addr = hinic5_hw_be32(upper_32_bits(dma_info->dma));
	wqe_desc->lo_addr = hinic5_hw_be32(lower_32_bits(dma_info->dma));

	wqe_desc->ctrl_len = dma_info->len;

	return 0;
}

void hinic5_prepare_xdp_sq_ctrl(struct hinic5_sq_wqe_combo *wqe_combo, u16 owner)
{
	struct hinic5_sq_wqe_desc *wqe_desc = wqe_combo->ctrl_bd0;

	wqe_desc->ctrl_len |=
			SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
			SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
			SQ_CTRL_SET(owner, OWNER);

	wqe_desc->ctrl_len = hinic5_hw_be32(wqe_desc->ctrl_len);
	wqe_desc->queue_info = 0;
}

int hinic5_xdp_xmit_frame(struct hinic5_nic_dev *nic_dev, struct hinic5_txq *txq,
			  struct xdp_frame *xdpf)
{
	struct hinic5_sq_wqe_combo wqe_combo = {0};
	u16 pi = 0, owner = 0;
	/* Always use compact wqe for xdp */
	if (unlikely(hinic5_maybe_stop_tx(txq, 1) != 0)) {
		TXQ_STATS_INC(txq, busy);
		return NETDEV_TX_BUSY;
	}

	wqe_combo.ctrl_bd0 = hinic5_get_sq_one_wqebb(txq->sq, &pi);
	wqe_combo.task_type = SQ_WQE_TASKSECT_4BYTES;
	wqe_combo.wqe_type = SQ_WQE_COMPACT_TYPE;
	owner = hinic5_get_and_update_sq_owner(txq->sq, pi, 1);

	txq->tx_info[pi].xdpf = xdpf;
	txq->tx_info[pi].wqebb_cnt = 1;

	if (tx_map_xdpf(nic_dev, txq, pi, &wqe_combo) != 0) {
		txq->tx_info[pi].xdpf = NULL;
		hinic5_rollback_sq_wqebbs(txq->sq, 1, owner);
		return -EIO;
	}
	hinic5_prepare_xdp_sq_ctrl(&wqe_combo, owner);

	return 0;
}

int hinic5_xdp_xmit_frames(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(dev);
	struct hinic5_txq *txq = NULL;
	u16 q_id, drops = 0;
	int i;

	if (unlikely(!netif_carrier_ok(dev))) {
		HINIC5_NIC_STATS_INC(nic_dev, tx_carrier_off_drop);
		return NETDEV_TX_BUSY;
	}

	if (unlikely((flags & ~XDP_XMIT_FLAGS_MASK) != 0))
		return -EINVAL;

	if (unlikely(nic_dev->q_params.xdp_qps == 0))
		return -EINVAL;

	/* XDP queue is isolated from kernel TX queue, XDP uses the second half of queues */
	q_id = raw_smp_processor_id() % nic_dev->q_params.xdp_qps + nic_dev->q_params.num_qps;

	txq = &nic_dev->txqs[q_id];

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];

		if (unlikely(hinic5_xdp_xmit_frame(nic_dev, txq, xdpf) != 0)) {
			xdp_return_frame(xdpf);
			XDP_TXQ_STATS_INC(txq, xdp_dropped);
			drops++;
		}
	}

	if ((flags & XDP_XMIT_FLUSH) != 0) {
		hinic5_write_db(txq->sq, (txq->cos & nic_dev->cos_mask_mode), SQ_CFLAG_DP,
				hinic5_get_sq_local_pi(txq->sq));
	}
	return n - drops;
}

struct xdp_frame *xdp_convert_to_frame(struct xdp_buff *xdp, struct hinic5_nic_dev *nic_dev)
{
	struct xdp_frame *xdp_frame = NULL;
	int metasize, headroom;

#if (KERNEL_VERSION(5, 8, 0) < LINUX_VERSION_CODE)
	if (xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL)
		return xdp_convert_zc_to_xdp_frame(xdp);

#endif
	xdp_frame = xdp->data_hard_start;
	headroom = xdp->data - xdp->data_hard_start;
	metasize = xdp->data - xdp->data_meta;
	metasize = metasize > 0 ? metasize : 0;

	if (unlikely((headroom - metasize) < sizeof(*xdp_frame)))
		return NULL;
#ifdef HAVE_XDP_FRAME_SZ
	if (unlikely(xdp->data_end > xdp_data_hard_end(xdp)))
		return NULL;
	xdp_frame->frame_sz = xdp->frame_sz;
#endif
	xdp_frame->data = xdp->data;
	xdp_frame->len  = xdp->data_end - xdp->data;
	xdp_frame->headroom = (u16)(headroom - sizeof(*xdp_frame));
#ifdef HAVE_XDP_DATA_META
	xdp_frame->metasize = (u32)metasize;
	xdp_frame->mem = xdp->rxq->mem;
#endif

	return xdp_frame;
}

bool hinic5_xmit_xdp_buff(struct net_device *netdev, u16 q_id, struct xdp_buff *xdp)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_txq *txq = NULL;
	struct xdp_frame *xdpf = NULL;
	u16 dst_qid;

	/* XDP queue is isolated from kernel TX queue, XDP uses the second half of queues */
	dst_qid = q_id + nic_dev->q_params.num_qps;
	txq = &nic_dev->txqs[dst_qid];
	xdpf = xdp_convert_to_frame(xdp, nic_dev);
	if (!xdpf) {
		XDP_TXQ_STATS_INC(txq, xdp_dropped);
		return false;
	}

	if (unlikely(hinic5_xdp_xmit_frame(nic_dev, txq, xdpf) != 0)) {
		xdp_return_frame(xdpf);
		XDP_TXQ_STATS_INC(txq, xdp_dropped);
		return false;
	}
	hinic5_write_db(txq->sq, (txq->cos & nic_dev->cos_mask_mode), SQ_CFLAG_DP,
			hinic5_get_sq_local_pi(txq->sq));

	return true;
}

static void update_drop_rx_info(struct hinic5_rxq *rxq, u16 weqbb_num)
{
	struct hinic5_rx_info *rx_info = NULL;
	u16 weqbb_num_tmp = weqbb_num;
	struct net_device *netdev = rxq->netdev;
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	while (weqbb_num_tmp != 0) {
		rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
		if (likely(page_to_nid(rx_info->page) == numa_node_id())) {
			hinic5_reuse_rx_page(rxq, rx_info);
		} else {
			if (rx_info->buf_dma_addr != 0) {
				dma_unmap_page(rxq->dev, rx_info->buf_dma_addr,
					       rxq->dma_rx_buff_size, DMA_FROM_DEVICE);
			}

			if (rx_info->page)
				__free_pages(rx_info->page, nic_dev->page_order);
		}

		rx_info->buf_dma_addr = 0;
		rx_info->page = NULL;
		rxq->cons_idx++;
		rxq->delta++;

		weqbb_num_tmp--;
	}
}

static bool hinic5_add_rx_frag_with_xdp(struct hinic5_rxq *rxq, u32 pkt_len,
					struct hinic5_rx_info *rx_info,
					struct sk_buff *skb, struct xdp_buff *xdp)
{
	struct page *page = rx_info->page;

	if (pkt_len <= HINIC5_RX_HDR_SIZE) {
		__skb_put_data(skb, xdp->data, pkt_len);

		if (likely(page_to_nid(page) == numa_node_id()))
			return true;

		put_page(page);
		goto umap_page;
	}

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			(int)(rx_info->page_offset + (xdp->data - xdp->data_hard_start)),
			(int)pkt_len, rxq->buf_len);

	if (unlikely(page_to_nid(page) != numa_node_id()))
		goto umap_page;
	if (unlikely(page_count(page) != 1))
		goto umap_page;

	rx_info->page_offset ^= rxq->buf_len;
	get_page(page);

	return true;
umap_page:
	dma_unmap_page(rxq->dev, rx_info->buf_dma_addr,
		       rxq->dma_rx_buff_size, DMA_FROM_DEVICE);
	return false;
}

static void hinic5_xdp_set_data(struct hinic5_rxq *rxq, struct xdp_buff *xdp,
				u8 *va, u32 pkt_len, u32 packet_offset)
{
	xdp->data = (void *)((uintptr_t)va + packet_offset);
	xdp->data_hard_start = va;
	xdp->data_end = xdp->data + pkt_len;
	xdp->rxq = &rxq->xdp_rxq;
}

static int hinic5_run_xdp_prog(struct hinic5_rxq *rxq, struct bpf_prog *xdp_prog,
			       struct xdp_buff *xdp, u32 *pkt_len)
{
	u32 act;
	int err;
	int result = HINIC5_XDP_PKT_DROP;
	struct net_device *netdev = rxq->netdev;
	struct hinic5_rx_info *rx_info = NULL;

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		*pkt_len = xdp->data_end - xdp->data;
		result = HINIC5_XDP_PKT_PASS;
		break;
	case XDP_TX:
		if (unlikely(!hinic5_xmit_xdp_buff(netdev, rxq->q_id, xdp)))
			goto out_failure;
		result = HINIC5_XDP_PKT_TX;
		break;
	case XDP_REDIRECT:
		rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
		get_page(rx_info->page);
#ifdef HAVE_XDP_FRAME_SZ
		if (unlikely(xdp->data_end > xdp_data_hard_end(xdp)))
			goto out_failure;
#endif
		err = xdp_do_redirect(netdev, xdp, xdp_prog);
		if (unlikely(err != 0)) {
			put_page(rx_info->page);
			goto out_failure;
		}
		result = HINIC5_XDP_PKT_REDIRECT;
		break;
	case XDP_ABORTED:
		goto out_failure;
	case XDP_DROP:
		break;
	default:
		bpf_warn_invalid_xdp_action(netdev, xdp_prog, act);

out_failure:
		trace_xdp_exception(netdev, xdp_prog, act);
	}

	return result;
}

static void hinic5_prepare_xdp_buff(struct hinic5_rxq *rxq, struct xdp_buff *xdp,
				    u32 pkt_len, u32 packet_offset)
{
	u8 *va;
	struct hinic5_rx_info *rx_info = NULL;

	rx_info = &rxq->rx_info[rxq->cons_idx & rxq->q_mask];
	va = (u8 *)page_address(rx_info->page) + rx_info->page_offset;
	prefetch(va);
	dma_sync_single_range_for_cpu(rxq->dev, rx_info->buf_dma_addr,
				      rx_info->page_offset,
				      rxq->buf_len, DMA_FROM_DEVICE);
	hinic5_xdp_set_data(rxq, xdp, va, pkt_len, packet_offset);

#ifdef HAVE_XDP_FRAME_SZ
	xdp->frame_sz = rxq->buf_len;
#endif
#ifdef HAVE_XDP_DATA_META
	xdp_set_data_meta_invalid(xdp);
#endif
	prefetchw(xdp->data_hard_start);
}

static void hinic5_handle_xdp_result(struct hinic5_rxq *rxq, int result, u16 weqbb_num)
{
	switch (result) {
	case HINIC5_XDP_PKT_DROP:
		RXQ_STATS_INC(rxq, xdp_dropped);
		break;
	case HINIC5_XDP_PKT_REDIRECT:
		RXQ_STATS_INC(rxq, xdp_redirected);
		break;
	default:
		break;
	}
	if (result != HINIC5_XDP_PKT_PASS)
		update_drop_rx_info(rxq, weqbb_num);
}

int hinic5_run_xdp(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info, struct xdp_buff *xdp)
{
	struct bpf_prog *xdp_prog = NULL;
	struct hinic5_nic_dev *nic_dev = NULL;
	int result = HINIC5_XDP_PKT_PASS;
	u16 weqbb_num = 1; /* xdp can only use one rx_buff */
	u32 pkt_len = cqe_info->pkt_len;
	u32 packet_offset = cqe_info->packet_offset + XDP_PACKET_HEADROOM;

	nic_dev = netdev_priv(rxq->netdev);

	rcu_read_lock();
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	if (!xdp_prog) {
		result = HINIC5_XDP_PROG_EMPTY;
		goto unlock_rcu;
	}
	if (unlikely(pkt_len + packet_offset > rxq->buf_len)) {
		RXQ_STATS_INC(rxq, xdp_large_pkt);
		weqbb_num = HINIC5_GET_SGE_NUM(pkt_len + packet_offset, rxq);
		result = HINIC5_XDP_PKT_DROP;
		goto xdp_out;
	}

#ifdef HAVE_PAGE_POOL_SUPPORT
	if (nic_dev->page_pool_enabled) {
		result = HINIC5_XDP_PROG_EMPTY;
		goto unlock_rcu;
	}
#endif
	hinic5_prepare_xdp_buff(rxq, xdp, pkt_len, packet_offset);
	result = hinic5_run_xdp_prog(rxq, xdp_prog, xdp, &pkt_len);
	cqe_info->pkt_len = (u16)pkt_len;
xdp_out:
	hinic5_handle_xdp_result(rxq, result, weqbb_num);
unlock_rcu:
	rcu_read_unlock();
	return result;
}

struct sk_buff *hinic5_fetch_rx_buffer_xdp(struct hinic5_rxq *rxq, u32 pkt_len,
					   struct xdp_buff *xdp)
{
	struct sk_buff *skb = NULL;
	struct hinic5_rx_info *rx_info = NULL;
	u32 sw_ci;
	bool reuse;

	sw_ci = rxq->cons_idx & rxq->q_mask;
	rx_info = &rxq->rx_info[sw_ci];

	skb = netdev_alloc_skb_ip_align(rxq->netdev, HINIC5_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	reuse = hinic5_add_rx_frag_with_xdp(rxq, pkt_len, rx_info, skb, xdp);
	if (likely(reuse))
		hinic5_reuse_rx_page(rxq, rx_info);

	rx_info->buf_dma_addr = 0;
	rx_info->page = NULL;

	rxq->cons_idx += 1;
	rxq->delta += 1;

	return skb;
}

void hinic5_xdp_flush_if_needed(const struct hinic5_nic_dev *nic_dev)
{
	if (unlikely(rcu_access_pointer(nic_dev->xdp_prog))) {
#ifdef HAVE_XDP_DO_FLUSH_MAP
		xdp_do_flush_map();
#else
		xdp_do_flush();
#endif
	}
}

/* Function to determine XDP status and build skb accordingly */
bool hinic5_xdp_process_packet(struct hinic5_rxq *rxq, struct hinic5_cqe_info *cqe_info,
			       struct sk_buff **skb)
{
	u32 xdp_status;
	struct xdp_buff xdp = { 0 };

	xdp_status = (u32)(hinic5_run_xdp(rxq, cqe_info, &xdp));
	/* Check XDP status for redirect, TX, or drop */
	if (xdp_status == HINIC5_XDP_PKT_REDIRECT ||
	    xdp_status == HINIC5_XDP_PKT_TX ||
	    xdp_status == HINIC5_XDP_PKT_DROP) {
		/* if packet is redirected, TX, or dropped, there is no need to build skb */
		return 1;
	}

	/* Build skb based on XDP program configuration */
	if (xdp_status != HINIC5_XDP_PROG_EMPTY)
		*skb = hinic5_fetch_rx_buffer_xdp(rxq, cqe_info->pkt_len, &xdp);
	else
		*skb = hinic5_fetch_rx_buffer(rxq, cqe_info);

	return 0;
}

#endif
