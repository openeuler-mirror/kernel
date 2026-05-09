// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_xsk.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/types.h>
#include <linux/compiler.h>
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_BUFF_IN_XDP_H
#include <net/xdp.h>
#else
#include <linux/filter.h>
#endif
#endif

#include "sxe2_compat.h"
#include "sxe2_common.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_tx.h"
#include "sxe2_rx.h"
#include "sxe2_xsk.h"
#include "sxe2_netdev.h"

#ifdef HAVE_AF_XDP_ZC_SUPPORT
STATIC void sxe2_qp_reset_stats(struct sxe2_vsi *vsi, u16 q_idx)
{
	memset(vsi->rxqs.q[q_idx]->stats, 0, sizeof(*vsi->rxqs.q[q_idx]->stats));
	memset(vsi->txqs.q[q_idx]->stats, 0, sizeof(*vsi->txqs.q[q_idx]->stats));
	if (sxe2_xdp_is_enable(vsi))
		memset(vsi->xdp_rings.q[q_idx]->stats, 0,
		       sizeof(*vsi->xdp_rings.q[q_idx]->stats));
}

STATIC void sxe2_qp_clean_rings(struct sxe2_vsi *vsi, u16 q_idx)
{
	sxe2_tx_ring_clean(vsi->txqs.q[q_idx]);
	if (sxe2_xdp_is_enable(vsi)) {
		synchronize_rcu();
		sxe2_tx_ring_clean(vsi->xdp_rings.q[q_idx]);
	}
	sxe2_rx_ring_clean(vsi->rxqs.q[q_idx]);
}

STATIC void sxe2_qvec_toggle_napi(struct sxe2_vsi *vsi,
				  struct sxe2_irq_data *q_vector, bool enable)
{
	if (!vsi->netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

STATIC void sxe2_qvec_dis_irq(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			      struct sxe2_queue *rxq, struct sxe2_irq_data *q_vector)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;

	sxe2_hw_txq_irq_cause_switch(hw, txq->idx_in_pf, false);
	sxe2_hw_rxq_irq_cause_switch(hw, rxq->idx_in_pf, false);

	if (q_vector) {
		synchronize_irq(adapter->irq_ctxt.msix_entries[q_vector->idx_in_pf]
						.vector);
		sxe2_hw_irq_disable(hw, q_vector->idx_in_pf);
		sxe2_flush(hw);
	}
}

STATIC void sxe2_qvec_cfg_msix(struct sxe2_vsi *vsi, struct sxe2_queue *txq,
			       struct sxe2_queue *rxq,
			       struct sxe2_irq_data *q_vector)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;

	sxe2_irq_itr_init(q_vector);

	sxe2_hw_txq_irq_cause_setup(hw, txq->idx_in_pf, q_vector->tx.itr_idx,
				    q_vector->idx_in_pf);

	sxe2_hw_rxq_irq_cause_setup(hw, rxq->idx_in_pf, q_vector->rx.itr_idx,
				    q_vector->idx_in_pf);

	sxe2_flush(hw);
}

STATIC s32 sxe2_qp_dis(struct sxe2_vsi *vsi, u16 q_idx)
{
	struct sxe2_queue *txq, *rxq;
	struct sxe2_irq_data *q_vector;
	struct sxe2_adapter *adapter = vsi->adapter;

	s32 err;

	if (q_idx >= vsi->txqs.q_cnt || q_idx >= vsi->rxqs.q_cnt)
		return -EINVAL;

	txq = vsi->txqs.q[q_idx];
	rxq = vsi->txqs.q[q_idx];
	q_vector = rxq->irq_data;

	netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

	err = sxe2_rxq_ctrl_set(adapter, rxq, false, true);
	if (err)
		LOG_DEV_INFO("sxe2 stop rx error = %d\n", err);

	err = sxe2_txq_stop(vsi, txq);
	if (err) {
		LOG_DEV_INFO("sxe2 stop tx error = %d\n", err);
		return err;
	}

	if (sxe2_xdp_is_enable(vsi)) {
		struct sxe2_queue *xdp_ring = vsi->xdp_rings.q[q_idx];

		err = sxe2_txq_stop(vsi, xdp_ring);
		if (err) {
			LOG_DEV_INFO("sxe2 stop xdp tx error = %d\n", err);
			return err;
		}
	}

	sxe2_qvec_dis_irq(vsi, txq, rxq, q_vector);

	sxe2_qvec_toggle_napi(vsi, q_vector, false);
	sxe2_qp_clean_rings(vsi, q_idx);
	sxe2_qp_reset_stats(vsi, q_idx);

	return 0;
}

static void sxe2_qvec_ena_irq(struct sxe2_vsi *vsi, struct sxe2_irq_data *q_vector)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;

	if (vsi)
		if (test_bit(SXE2_VSI_S_DOWN, vsi->state))
			return;

	sxe2_hw_irq_enable(hw, q_vector->idx_in_pf);
	sxe2_hw_irq_trigger(hw, q_vector->idx_in_pf);

	sxe2_flush(hw);
}

STATIC void sxe2_xsk_remove_pool(struct sxe2_vsi *vsi, u16 q_idx)
{
	struct sxe2_queue *rxq;
	struct sxe2_queue *xdp_ring;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (q_idx >= vsi->txqs.q_cnt || q_idx >= vsi->rxqs.q_cnt) {
		LOG_WARN_BDF("queue(%d) is illegal.\n", q_idx);
		return;
	}

	rxq = vsi->rxqs.q[q_idx];
	rxq->xsk_pool = NULL;
	if (sxe2_xdp_is_enable(vsi)) {
		xdp_ring = vsi->xdp_rings.q[q_idx];
		xdp_ring->xsk_pool = NULL;
	}
}

STATIC s32 sxe2_qp_ena(struct sxe2_vsi *vsi, u16 q_idx, bool pool_present)
{
	struct sxe2_queue *txq, *rxq;
	struct sxe2_irq_data *q_vector;
	s32 err;

	if (q_idx >= vsi->txqs.q_cnt || q_idx >= vsi->rxqs.q_cnt)
		return -EINVAL;

	txq = vsi->txqs.q[q_idx];
	rxq = vsi->rxqs.q[q_idx];
	q_vector = rxq->irq_data;

	err = sxe2_hw_txq_configure(vsi, txq);
	if (err)
		goto end;

#ifdef HAVE_XDP_SUPPORT
	if (sxe2_xdp_is_enable(vsi)) {
		struct sxe2_queue *xdp_ring = vsi->xdp_rings.q[q_idx];

		err = sxe2_hw_txq_configure(vsi, xdp_ring);
		if (err)
			goto end;
		sxe2_set_ring_xdp(xdp_ring);
		xdp_ring->xsk_pool = sxe2_xsk_pool(xdp_ring);
	}
#endif

	err = sxe2_vsi_cfg_rxq(rxq);
	if (err)
		goto end;

	sxe2_qvec_cfg_msix(vsi, txq, rxq, q_vector);

	err = sxe2_rxq_ctrl_set(vsi->adapter, rxq, true, true);
	if (err)
		goto end;

	sxe2_qvec_toggle_napi(vsi, q_vector, true);
	sxe2_qvec_ena_irq(vsi, q_vector);

	netif_tx_start_queue(netdev_get_tx_queue(vsi->netdev, q_idx));
end:
	if (!pool_present)
		sxe2_xsk_remove_pool(vsi, q_idx);

	return err;
}

#ifndef HAVE_AF_XDP_NETDEV_UMEM
STATIC int sxe2_xsk_alloc_umems(struct sxe2_vsi *vsi)
{
	if (vsi->xsk_umems)
		return 0;

	vsi->xsk_umems = kcalloc(vsi->num_xsk_umems, sizeof(*vsi->xsk_umems),
				 GFP_KERNEL);

	if (!vsi->xsk_umems) {
		vsi->num_xsk_umems = 0;
		return -ENOMEM;
	}

	return 0;
}

STATIC void sxe2_xsk_remove_umem(struct sxe2_vsi *vsi, u16 qid)
{
	vsi->xsk_umems[qid] = NULL;
	vsi->num_xsk_umems_used--;

	if (vsi->num_xsk_umems_used == 0) {
		kfree(vsi->xsk_umems);
		vsi->xsk_umems = NULL;
		vsi->num_xsk_umems = 0;
	}
}
#endif

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
bool sxe2_alloc_rx_bufs_zc(struct sxe2_queue *rxq, u16 count)
#else
static bool sxe2_alloc_rx_bufs_zc(struct sxe2_queue *rxq, u16 count,
				  bool (*alloc)(struct sxe2_queue *,
						struct sxe2_rx_buf *))
#endif
{
	union sxe2_rx_desc *rx_desc;
	u16 ntu = rxq->next_to_use;
	struct sxe2_rx_buf *rx_buf;
	bool ok = true;
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	dma_addr_t dma;
#endif

	if (!count)
		return true;

	rx_desc = SXE2_RX_DESC(rxq, ntu);
	rx_buf = &rxq->rx_buf[ntu];

	do {
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		rx_buf->xdp = xsk_buff_alloc(rxq->xsk_pool);
		if (!rx_buf->xdp) {
#else
	if (!alloc(rxq, rx_buf)) {
#endif
		ok = false;
		break;
	}

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		dma = xsk_buff_xdp_get_dma(rx_buf->xdp);
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
#else
		dma_sync_single_range_for_device(rxq->dev, rx_buf->dma, 0,
						 rxq->rx_buf_len, DMA_BIDIRECTIONAL);
		rx_desc->read.pkt_addr = cpu_to_le64(rx_buf->dma);
#endif
		rx_desc->wb.status0_err = 0;
		rx_desc++;
		rx_buf++;
		ntu++;
		if (unlikely(ntu == rxq->depth)) {
			rx_desc = SXE2_RX_DESC(rxq, 0);
			rx_buf = rxq->rx_buf;
			ntu = 0;
		}
	} while (--count);

	if (rxq->next_to_use != ntu) {
		rx_desc->wb.status0_err = 0;
		sxe2_rxq_tail_update(rxq, ntu);
	}

	return ok;
}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
static s32 sxe2_xsk_umem_dma_map(struct sxe2_vsi *vsi, struct xdp_umem *umem)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 i;

	for (i = 0; i < umem->npgs; i++) {
		dma_addr_t dma =
		 dma_map_page_attrs(dev,
				    umem->pgs[i], 0, PAGE_SIZE, DMA_BIDIRECTIONAL,
				    DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING);
		if (dma_mapping_error(dev, dma)) {
			LOG_DEV_DEBUG("XSK UMEM DMA mapping error on page num %d/n",
				      i);
			goto out_unmap;
		}

		umem->pages[i].dma = dma;
	}

	return 0;

out_unmap:
	for (; i > 0; i--) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL,
				     DMA_ATTR_SKIP_CPU_SYNC |
						     DMA_ATTR_WEAK_ORDERING);
		umem->pages[i].dma = 0;
	}

	return -EFAULT;
}

static void sxe2_xsk_umem_dma_unmap(struct sxe2_vsi *vsi, struct xdp_umem *umem)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 i;

	for (i = 0; i < umem->npgs; i++) {
		dma_unmap_page_attrs(dev, umem->pages[i].dma, PAGE_SIZE,
				     DMA_BIDIRECTIONAL,
				     DMA_ATTR_SKIP_CPU_SYNC |
						     DMA_ATTR_WEAK_ORDERING);

		umem->pages[i].dma = 0;
	}
}

void sxe2_zca_free(struct zero_copy_allocator *alloc, unsigned long handle_addr)
{
	struct sxe2_queue *rxq;
	struct sxe2_rx_buf *rx_buf;
	struct xdp_umem *umem;
	u64 hr, mask;
	u16 nta;

	rxq = container_of(alloc, struct sxe2_queue, zca);
	umem = rxq->xsk_pool;
	hr = umem->headroom + XDP_PACKET_HEADROOM;

#ifndef HAVE_XDP_UMEM_PROPS
	mask = umem->chunk_mask;
#else
	mask = umem->props.chunk_mask;
#endif

	nta = rxq->next_to_alloc;
	rx_buf = &rxq->rx_buf[nta];

	nta++;
	rxq->next_to_alloc = (nta < rxq->depth) ? nta : 0;

	handle_addr &= mask;

	rx_buf->dma = xdp_umem_get_dma(umem, handle_addr);
	rx_buf->dma += hr;

	rx_buf->addr = xdp_umem_get_data(umem, handle_addr);
	rx_buf->addr += hr;

	rx_buf->handle = (u64)handle_addr + umem->headroom;
}

static __always_inline bool sxe2_alloc_buf_fast_zc(struct sxe2_queue *rxq,
						   struct sxe2_rx_buf *rx_buf)
{
	struct xdp_umem *umem = rxq->xsk_pool;
	void *addr = rx_buf->addr;
	u64 handle, hr;

	if (addr)
		return true;

	if (!xsk_umem_peek_addr(umem, &handle)) {
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
		return false;
	}

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	rx_buf->dma = xdp_umem_get_dma(umem, handle);
	rx_buf->dma += hr;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += hr;

	rx_buf->handle = handle + umem->headroom;

	xsk_umem_release_addr(umem);
	return true;
}

static __always_inline bool sxe2_alloc_buf_slow_zc(struct sxe2_queue *rxq,
						   struct sxe2_rx_buf *rx_buf)
{
	struct xdp_umem *umem = rxq->xsk_pool;
	u64 handle, headroom;

	if (!xsk_umem_peek_addr_rq(umem, &handle)) {
		rxq->stats->rx_stats.rx_pg_alloc_fail++;
		return false;
	}

	handle &= umem->chunk_mask;
	headroom = umem->headroom + XDP_PACKET_HEADROOM;

	rx_buf->dma = xdp_umem_get_dma(umem, handle);
	rx_buf->dma += headroom;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += headroom;

	rx_buf->handle = handle + umem->headroom;

	xsk_umem_release_addr_rq(umem);
	return true;
}

static bool sxe2_alloc_rx_bufs_fast_zc(struct sxe2_queue *rxq, u16 count)
{
	return sxe2_alloc_rx_bufs_zc(rxq, count, sxe2_alloc_buf_fast_zc);
}

bool sxe2_alloc_rx_bufs_slow_zc(struct sxe2_queue *rxq, u16 count)
{
	return sxe2_alloc_rx_bufs_zc(rxq, count, sxe2_alloc_buf_slow_zc);
}

static struct sxe2_rx_buf *sxe2_get_rx_buf_zc(struct sxe2_queue *rxq, int size)
{
	struct sxe2_rx_buf *rx_buf;

	rx_buf = &rxq->rx_buf[rxq->next_to_clean];

	dma_sync_single_range_for_cpu(rxq->dev, rx_buf->dma, 0, size,
				      DMA_BIDIRECTIONAL);

	return rx_buf;
}

static void sxe2_reuse_rx_buf_zc(struct sxe2_queue *rxq, struct sxe2_rx_buf *old_buf)
{
#ifdef HAVE_XDP_UMEM_PROPS
	unsigned long mask = (unsigned long)rxq->xsk_pool->props.chunk_mask;
#else
	unsigned long mask = (unsigned long)rxq->xsk_pool->chunk_mask;
#endif
	u64 hr = rxq->xsk_pool->headroom + XDP_PACKET_HEADROOM;
	u16 nta = rxq->next_to_alloc;
	struct sxe2_rx_buf *new_buf;

	new_buf = &rxq->rx_buf[nta++];
	rxq->next_to_alloc = (nta < rxq->depth) ? nta : 0;

	new_buf->dma = old_buf->dma & mask;
	new_buf->dma += hr;

	new_buf->addr = (void *)((unsigned long)old_buf->addr & mask);
	new_buf->addr += hr;

	new_buf->handle = old_buf->handle & mask;
	new_buf->handle += rxq->xsk_pool->headroom;

	old_buf->addr = NULL;
}
#endif

STATIC s32 sxe2_xsk_pool_disable(struct sxe2_vsi *vsi, u16 qid)
{
#ifdef HAVE_AF_XDP_NETDEV_UMEM
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *pool = xsk_get_pool_from_qid(vsi->netdev, qid);
#else
	struct xdp_umem *pool = xsk_get_pool_from_qid(vsi->netdev, qid);
#endif
#else
	struct xdp_umem *pool;

	if (!vsi->xsk_umems || qid >= vsi->num_xsk_umems)
		return -EINVAL;

	pool = vsi->xsk_umems[qid];
#endif

	if (!pool)
		return -EINVAL;

	clear_bit(qid, vsi->af_xdp_zc_qps);

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xsk_pool_dma_unmap(pool, SXE2_RX_DMA_ATTR);
#else
	sxe2_xsk_umem_dma_unmap(vsi, pool);
#endif

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	sxe2_xsk_remove_umem(vsi, qid);
#endif

	return 0;
}

STATIC s32
#ifdef HAVE_NETDEV_BPF_XSK_POOL
sxe2_xsk_pool_enable(struct sxe2_vsi *vsi, struct xsk_buff_pool *pool, u16 qid)
#else
sxe2_xsk_pool_enable(struct sxe2_vsi *vsi, struct xdp_umem *pool, u16 qid)
#endif
{
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	struct xdp_umem_fq_reuse *reuseq;
#endif
	s32 err;

	if (vsi->type != SXE2_VSI_T_PF)
		return -EINVAL;

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (!vsi->num_xsk_umems)
		vsi->num_xsk_umems = min_t(u16, vsi->rxqs.q_cnt, vsi->txqs.q_cnt);
	if (qid >= vsi->num_xsk_umems)
		return -EINVAL;

	err = sxe2_xsk_alloc_umems(vsi);
	if (err)
		return err;

	if (vsi->xsk_umems && vsi->xsk_umems[qid])
		return -EBUSY;

	vsi->xsk_umems[qid] = pool;
	vsi->num_xsk_umems_used++;
#endif

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	err = xsk_pool_dma_map(pool, SXE2_ADAPTER_TO_DEV(vsi->adapter),
			       SXE2_RX_DMA_ATTR);
#else
	reuseq = xsk_reuseq_prepare(vsi->rxqs.q[0]->depth);
	if (!reuseq)
		return -ENOMEM;

	xsk_reuseq_free(xsk_reuseq_swap(pool, reuseq));
	err = sxe2_xsk_umem_dma_map(vsi, pool);
#endif
	if (err)
		return err;

	set_bit(qid, vsi->af_xdp_zc_qps);

	return 0;
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
s32 sxe2_xsk_pool_setup(struct sxe2_vsi *vsi, struct xsk_buff_pool *pool, u16 qid)
#else
s32 sxe2_xsk_umem_setup(struct sxe2_vsi *vsi, struct xdp_umem *pool, u16 qid)
#endif
{
	struct sxe2_adapter *adapter = vsi->adapter;
	bool if_running, pool_present = !!pool;
	s32 ret = 0, pool_failure = 0;
	struct net_device *netdev = vsi->netdev;

	if (qid >= vsi->rxqs.q_cnt || qid >= vsi->txqs.q_cnt) {
		LOG_DEV_ERR("please use queue id in scope of combined queues \t"
			    "count.\n");
		pool_failure = -EINVAL;
		goto failure;
	}

	if (sxe2_xdp_is_enable(vsi) && qid >= vsi->num_xdp_txq) {
		LOG_DEV_ERR("please use queue id in scope of xdp queues count.\n");
		pool_failure = -EINVAL;
		goto failure;
	}

	if_running = netif_running(netdev) && sxe2_xdp_is_enable(vsi);

	if (if_running) {
		ret = sxe2_qp_dis(vsi, qid);
		if (ret) {
			LOG_NETDEV_ERR("sxe2_qp_dis error = %d\n", ret);
			if (pool_present)
				goto xsk_pool_if_up;
		}
	}

	pool_failure = pool_present ? sxe2_xsk_pool_enable(vsi, pool, qid)
				    : sxe2_xsk_pool_disable(vsi, qid);

xsk_pool_if_up:
	if (if_running) {
		ret = sxe2_qp_ena(vsi, qid, pool_present);
		if (!ret && pool_present)
			napi_schedule(&vsi->xdp_rings.q[qid]->irq_data->napi);
		else if (ret)
			LOG_NETDEV_ERR("sxe2_qp_ena error = %d\n", ret);
	}

failure:
	if (pool_failure) {
		LOG_NETDEV_ERR("Could not %sable buffer pool, error = %d\n",
			       pool_present ? "en" : "dis", pool_failure);
		return pool_failure;
	}

	return ret;
}

STATIC bool sxe2_xmit_zc(struct sxe2_queue *xdp_ring, s32 budget)
{
	union sxe2_tx_data_desc *tx_desc = NULL;
	bool work_done = true;
#ifdef XSK_UMEM_RETURNS_XDP_DESC
	struct xdp_desc desc;
#endif
	dma_addr_t dma;
#ifndef XSK_UMEM_RETURNS_XDP_DESC
	u32 len;
#endif
	struct sxe2_tx_offload_info offload;

	while (likely(budget-- > 0)) {
		struct sxe2_tx_buf *tx_buf;

		if (unlikely(!SXE2_DESC_UNUSED(xdp_ring))) {
			xdp_ring->stats->tx_stats.tx_busy++;
			work_done = false;
			break;
		}

		tx_buf = &xdp_ring->tx_buf[xdp_ring->next_to_use];

#ifdef XSK_UMEM_RETURNS_XDP_DESC
		if (!xsk_tx_peek_desc(xdp_ring->xsk_pool, &desc))
			break;
#endif

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, desc.len);
#else
		dma = xdp_umem_get_dma(xdp_ring->xsk_pool, desc.addr);
		dma_sync_single_for_device(xdp_ring->dev, dma, desc.len,
					   DMA_BIDIRECTIONAL);
#endif
		tx_buf->bytecount = (u32)desc.len;

		offload.adapter = xdp_ring->vsi->adapter;
		offload.data_desc_cmd = SXE2_TXDD_CMD_EOP | SXE2_TXDD_CMD_RS;
		offload.data_desc_offset = 0;
		offload.data_desc_l2tag1 = 0;

		tx_desc = SXE2_TX_DESC(xdp_ring, xdp_ring->next_to_use);
		tx_desc->read.buf_addr = cpu_to_le64(dma);
		tx_desc->read.cmd_type_offset_bsz =
#ifdef XSK_UMEM_RETURNS_XDP_DESC
				sxe2_tx_data_desc_qword1_setup(&offload,
							       (u32)desc.len);
#else
				sxe2_tx_data_desc_qword1_setup(&offload, len);
#endif

		xdp_ring->next_to_use++;
		if (xdp_ring->next_to_use == xdp_ring->depth)
			xdp_ring->next_to_use = 0;
	}

	if (tx_desc) {
		sxe2_xdp_ring_update_tail(xdp_ring);
		xsk_tx_release(xdp_ring->xsk_pool);
	}

	return budget > 0 && work_done;
}

STATIC void sxe2_clean_xdp_tx_buf(struct sxe2_queue *xdp_ring,
				  struct sxe2_tx_buf *tx_buf)
{
	xdp_return_frame((struct xdp_frame *)tx_buf->raw_buf);
	dma_unmap_single(xdp_ring->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buf, len, 0);
}

bool sxe2_txq_irq_clean_zc(struct sxe2_queue *xdp_ring, s32 budget)
{
	s32 ntc = xdp_ring->next_to_clean;
	union sxe2_tx_data_desc *tx_desc;
	struct sxe2_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	bool xmit_done;
	struct sxe2_queue_stats queue_stats = {};

	tx_desc = SXE2_TX_DESC(xdp_ring, ntc);
	tx_buf = &xdp_ring->tx_buf[ntc];
	ntc -= xdp_ring->depth;

	do {
		if (!(tx_desc->wb.dd & cpu_to_le64(SXE2_TX_DESC_DTYPE_DESC_DONE)))
			break;

		queue_stats.bytes += tx_buf->bytecount;
		queue_stats.packets++;

		if (tx_buf->raw_buf) {
			sxe2_clean_xdp_tx_buf(xdp_ring, tx_buf);
			tx_buf->raw_buf = NULL;
		} else {
			xsk_frames++;
		}

		tx_desc->read.cmd_type_offset_bsz = 0;
		tx_buf++;
		tx_desc++;
		ntc++;

		if (unlikely(!ntc)) {
			ntc -= xdp_ring->depth;
			tx_buf = xdp_ring->tx_buf;
			tx_desc = SXE2_TX_DESC(xdp_ring, 0);
		}

		prefetch(tx_desc);

	} while (likely(--budget));

	ntc += xdp_ring->depth;
	xdp_ring->next_to_clean = (u16)ntc;

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);

#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		(void)xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);
#endif

	sxe2_tx_pkt_stats_update(xdp_ring, &queue_stats);
	xmit_done = sxe2_xmit_zc(xdp_ring, NAPI_POLL_WEIGHT);

	return budget > 0 && xmit_done;
}

STATIC void sxe2_bump_ntc(struct sxe2_queue *rxq)
{
	u16 ntc = rxq->next_to_clean + 1;

	ntc = (ntc < rxq->depth) ? ntc : 0;
	rxq->next_to_clean = ntc;
	prefetch(SXE2_RX_DESC(rxq, ntc));
}

STATIC struct sk_buff *sxe2_construct_skb_zc(struct sxe2_queue *rxq,
					     struct sxe2_rx_buf *rx_buf)
{
	s32 metasize = rx_buf->xdp->data - rx_buf->xdp->data_meta;
	s32 datasize = rx_buf->xdp->data_end - rx_buf->xdp->data;
	s32 datasize_hard = rx_buf->xdp->data_end - rx_buf->xdp->data_hard_start;
	struct sk_buff *skb;

	if (datasize < 0 || datasize_hard < 0)
		return NULL;

	skb = __napi_alloc_skb(&rxq->irq_data->napi, (u32)datasize_hard,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, rx_buf->xdp->data - rx_buf->xdp->data_hard_start);
	memcpy(__skb_put(skb, (u32)datasize), rx_buf->xdp->data, (size_t)datasize);
	if (metasize)
		skb_metadata_set(skb, (u8)metasize);

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xsk_buff_free(rx_buf->xdp);
	rx_buf->xdp = NULL;
#else
	sxe2_reuse_rx_buf_zc(rxq, rx_buf);
#endif

	return skb;
}

#ifdef HAVE_XDP_SUPPORT
STATIC s32 sxe2_run_xdp_zc(struct sxe2_queue *rxq, struct xdp_buff *xdp)
{
	s32 err, result;
	struct bpf_prog *xdp_prog;
	struct sxe2_queue *xdp_ring;
	u32 act;
	u64 rx_bytes = (u64)(xdp->data_end - xdp->data);
	struct sxe2_rxq_xdp_stats *xdp_stats = &rxq->stats->rx_stats.xdp_stats;
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	u16 tx_qid;

	xdp_stats->rx_xsk_packets++;
	xdp_stats->rx_xsk_bytes += rx_bytes;

	xdp_prog = READ_ONCE(rxq->xdp_prog);

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	LOG_DEBUG_BDF("bpf_prog_run_xdp ret:%d\n", act);

	if (likely(act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rxq->netdev, xdp, xdp_prog);
		result = !err ? SXE2_XDP_REDIR : SXE2_XDP_CONSUMED;
		if (err)
			xdp_stats->rx_xsk_redirect_fail++;
		else
			xdp_stats->rx_xsk_redirect++;

		goto l_end;
	}

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
	xdp->handle += xdp->data - xdp->data_hard_start;
#endif

	switch (act) {
	case XDP_PASS:
		xdp_stats->rx_xsk_pass++;
		result = SXE2_XDP_PASS;
		break;
	case XDP_TX:
		tx_qid = rxq->idx_in_vsi;
		if (tx_qid >= rxq->vsi->num_xdp_txq)
			tx_qid = (u16)(tx_qid % rxq->vsi->num_xdp_txq);

		xdp_ring = rxq->vsi->xdp_rings.q[tx_qid];
		result = sxe2_xmit_xdp_buff(xdp, xdp_ring);
		if (result == SXE2_XDP_TX)
			xdp_stats->rx_xsk_tx_xmit++;
		else
			xdp_stats->rx_xsk_tx_xmit_fail++;
		break;

	default:
		bpf_warn_invalid_xdp_action(rxq->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		xdp_stats->rx_xsk_unknown++;
		trace_xdp_exception(rxq->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		result = SXE2_XDP_CONSUMED;
		xdp_stats->rx_xsk_drop++;
		break;
	}

l_end:
	return result;
}
#endif

s32 sxe2_rx_irq_clean_zc(struct sxe2_queue *rxq, s32 budget)
{
	u32 total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = SXE2_DESC_UNUSED(rxq);
	u32 xdp_xmit = 0;
	bool failure = false;
#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_XDP_SUPPORT
	struct xdp_buff xdp;

	xdp.rxq = &rxq->xdp_rxq;
#endif
#endif

	while (likely(total_rx_packets < (u32)budget)) {
		union sxe2_rx_desc *rx_desc;
		u32 size = 0;
		s32 xdp_res = 0;
		struct sxe2_rx_buf *rx_buf;
		struct sk_buff *skb;
		u16 rx_ptype;

		rx_desc = SXE2_RX_DESC(rxq, rxq->next_to_clean);

		if (!sxe2_desc_status0_err_test(rx_desc->wb.status0_err,
						BIT(SXE2_RX_DESC_STATUS0_DD)))
			break;

		dma_rmb();

		size = le32_to_cpu(rx_desc->wb.pktl_hdrl_status2) &
		       SXE2_RX_DESC_PKT_LEN_MASK;

#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#ifdef HAVE_XDP_SUPPORT
		rx_buf = &rxq->rx_buf[rxq->next_to_clean];
		rx_buf->xdp->data_end = rx_buf->xdp->data + size;
#ifdef XSK_BUFF_DMA_SYNC_API_NEED_1_PARAM
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp);
#else
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp, rxq->xsk_pool);
#endif
		xdp_res = sxe2_run_xdp_zc(rxq, rx_buf->xdp);
#endif
#else
		rx_buf = sxe2_get_rx_buf_zc(rxq, size);
		if (!rx_buf->addr)
			break;

#ifdef HAVE_XDP_SUPPORT
		xdp.data = rx_buf->addr;
		xdp.data_meta = xdp.data;
		xdp.data_hard_start = (u8 *)xdp.data - XDP_PACKET_HEADROOM;
		xdp.data_end = (u8 *)xdp.data + size;
		xdp.handle = rx_buf->handle;

		xdp_res = sxe2_run_xdp_zc(rxq, &xdp);
#endif
#endif
		if (xdp_res) {
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
			if (xdp_res & (SXE2_XDP_TX | SXE2_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
			} else {
				xsk_buff_free(rx_buf->xdp);
				rx_buf->xdp = NULL;
			}
#else
			if (xdp_res & (SXE2_XDP_TX | SXE2_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
				rx_buf->addr = NULL;
			} else {
				sxe2_reuse_rx_buf_zc(rxq, rx_buf);
			}
#endif

			total_rx_bytes += size;
			total_rx_packets++;
			cleaned_count++;

			sxe2_bump_ntc(rxq);
			continue;
		}

		skb = sxe2_construct_skb_zc(rxq, rx_buf);
		if (!skb) {
			rxq->stats->rx_stats.rx_buff_alloc_err++;
			break;
		}

		cleaned_count++;
		sxe2_bump_ntc(rxq);

		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		total_rx_bytes += skb->len;

		rx_ptype = le16_to_cpu(rx_desc->wb.ptype_status1) &
			   SXE2_RX_DESC_PTYPE_MASK;

		sxe2_skb_field_fill(rxq, rx_desc, skb, rx_ptype);

		(void)napi_gro_receive(&rxq->irq_data->napi, skb);

		total_rx_packets++;
	}

	if (cleaned_count >= SXE2_RX_BUF_WRITE)
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		failure = !sxe2_alloc_rx_bufs_zc(rxq, cleaned_count);
#else
		failure = !sxe2_alloc_rx_bufs_fast_zc(rxq, cleaned_count);
#endif

	sxe2_xdp_tail_update(rxq, xdp_xmit);

	sxe2_rxq_stats_update(rxq, total_rx_packets, total_rx_bytes);

#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return (s32)total_rx_packets;
	}
#endif

	return failure ? budget : (s32)total_rx_packets;
}

void sxe2_xsk_clean_rx_ring(struct sxe2_queue *rx_ring)
{
	u16 i;

	for (i = 0; i < rx_ring->depth; i++) {
		struct sxe2_rx_buf *rx_buf = &rx_ring->rx_buf[i];

		if (!rx_buf->xdp)
			continue;

#ifndef HAVE_MEM_TYPE_XSK_BUFF_POOL
		xsk_umem_fq_reuse(rx_ring->xsk_pool, rx_buf->handle);
#endif
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
		xsk_buff_free(rx_buf->xdp);
#endif
		rx_buf->xdp = NULL;
	}
}

void sxe2_xsk_clean_xdp_ring(struct sxe2_queue *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean, ntu = xdp_ring->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct sxe2_tx_buf *tx_buf = &xdp_ring->tx_buf[ntc];

		if (tx_buf->raw_buf)
			sxe2_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		tx_buf->raw_buf = NULL;

		ntc++;
		if (ntc >= xdp_ring->depth)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
struct xsk_buff_pool *sxe2_xsk_pool(struct sxe2_queue *ring)
#else
struct xdp_umem *sxe2_xsk_pool(struct sxe2_queue *ring)
#endif
{
	struct sxe2_vsi *vsi = ring->vsi;
	u16 qid = ring->idx_in_vsi;
#ifndef HAVE_AF_XDP_NETDEV_UMEM
	struct xdp_umem **umems = vsi->xsk_umems;
#endif

	if (sxe2_queue_is_xdp(ring))
		qid -= vsi->num_xdp_txq;

	if (!sxe2_xdp_is_enable(vsi) || !test_bit(qid, vsi->af_xdp_zc_qps))
		return NULL;

#ifndef HAVE_AF_XDP_NETDEV_UMEM
	if (qid >= vsi->num_xsk_umems || !umems || !umems[qid])
		return NULL;

	return umems[qid];
#else
	return xsk_get_pool_from_qid(vsi->netdev, qid);
#endif
}

#endif
