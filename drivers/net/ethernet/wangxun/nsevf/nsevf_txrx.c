// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"
#include "nsevf_trace.h"
#include "nsevf_prototype.h"
#include <linux/filter.h>

static inline __le64 nse_build_ctob(u64 cmd_type_offset_bsz, u64 td_tlen,
				    unsigned int size,
				    bool __maybe_unused first_td)
{
	return cpu_to_le64((NSE_TX_DESC_DTYPE_DATA << NSE_TXD_DTYPE_S) |
			   cmd_type_offset_bsz |
			   ((td_tlen << NSE_TXD_TLEN_S) & NSE_TXD_TLEN_M) |
			   (((u64)size << NSE_TXD_BSIZE_S) & NSE_TXD_BSIZE_M));
}

/**
 * nsevf_unmap_and_free_tx_resource - Release a Tx buffer
 * @ring:      the ring that owns the buffer
 * @tx_buffer: the buffer to free
 **/
static void nsevf_unmap_and_free_tx_resource(struct nsevf_ring *ring,
					     struct nsevf_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);

		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev, dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len), DMA_TO_DEVICE);
	}

	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
	/* tx_buffer must be completely set up in the transmit path */
}

/**
 * nsevf_clean_tx_ring - Free any empty Tx buffers
 * @tx_ring: ring to be cleaned
 **/
void nsevf_clean_tx_ring(struct nsevf_ring *tx_ring)
{
	unsigned long bi_size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_bi)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++)
		nsevf_unmap_and_free_tx_resource(tx_ring, &tx_ring->tx_bi[i]);

	bi_size = sizeof(struct nsevf_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_bi, 0, bi_size);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	tx_ring->tx_rs_ntu = 0;
	tx_ring->tx_rs_ntc = 0;

	if (!tx_ring->netdev)
		return;

	/* cleanup Tx queue statistics */
	netdev_tx_reset_queue(txring_txq(tx_ring));
}

/**
 * nsevf_free_tx_resources - Free Tx resources per queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void nsevf_free_tx_resources(struct nsevf_ring *tx_ring)
{
	nsevf_clean_tx_ring(tx_ring);

	kfree(tx_ring->tx_bi);
	tx_ring->tx_bi = NULL;

	if (tx_ring->desc) {
		dma_free_coherent(tx_ring->dev, tx_ring->size, tx_ring->desc,
				  tx_ring->dma);
		tx_ring->desc = NULL;
	}

	kfree(tx_ring->tx_rs_array);
	tx_ring->tx_rs_array = NULL;
}

/**
 * nsevf_get_tx_pending - how many Tx descriptors not processed
 * @ring: the ring of descriptors
 * @in_sw: is tx_pending being checked in SW or HW
 **/
u32 nsevf_get_tx_pending(struct nsevf_ring *ring, bool in_sw)
{
	u32 head, tail;

	/* underlying hardware might not allow access and/or always return
	 * 0 for the head/tail registers so just use the cached values
	 */
	head = ring->next_to_clean;
	tail = ring->next_to_use;

	if (head != tail)
		return (head < tail) ? tail - head :
				       (tail + ring->count - head);

	return 0;
}

/**
 * nsevf_detect_recover_hung - Function to detect and recover hung_queues
 * @vsi:  pointer to vsi struct with tx queues
 *
 * VSI has netdev and netdev has TX queues. This function is to check each of
 * those TX queues if they are hung, trigger recovery by issuing SW interrupt.
 **/
void nsevf_detect_recover_hung(struct nsevf_vsi *vsi)
{
	struct net_device *netdev;
	unsigned int i;
	int packets;

	if (!vsi)
		return;

	if (test_bit(__NSEVF_VSI_DOWN, vsi->state))
		return;

	netdev = vsi->netdev;
	if (!netdev)
		return;

	if (!netif_carrier_ok(netdev))
		return;

	for (i = 0; i < vsi->back->num_active_queues; i++) {
		struct nsevf_ring *tx_ring = &vsi->back->tx_rings[i];

		if (!tx_ring || !tx_ring->q_vector)
			continue;

		if (tx_ring->desc) {
			/* If packet counter has not changed the queue is
			 * likely stalled, so force an interrupt for this
			 * queue.
			 *
			 * prev_pkt_ctr would be negative if there was no
			 * pending work.
			 */
			packets = tx_ring->stats.packets & INT_MAX;
			if (tx_ring->tx_stats.prev_pkt_ctr == packets) {
				nsevf_force_wb(vsi, tx_ring->q_vector);
				continue;
			}

			/* Memory barrier between read of packet count and call
			 * to nsevf_get_tx_pending()
			 */
			smp_rmb();
			tx_ring->tx_stats.prev_pkt_ctr =
				nsevf_get_tx_pending(tx_ring, true) ? packets :
								      -1;
		}
	}
}

#define WB_STRIDE 4

/**
 * nsevf_clean_tx_irq_legacy - Reclaim resources after transmit completes
 * @vsi: the VSI we care about
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 **/
static bool nsevf_clean_tx_irq_legacy(struct nsevf_vsi *vsi,
				      struct nsevf_ring *tx_ring,
				      int napi_budget)
{
	int i = tx_ring->next_to_clean;
	struct nsevf_tx_buffer *tx_buf;
	struct nsevf_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = NSEVF_DEFAULT_IRQ_WORK;

	tx_buf = &tx_ring->tx_bi[i];
	tx_desc = NSEVF_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		struct nsevf_tx_desc *eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		nsevf_trace(clean_tx_irq, tx_ring, tx_desc, tx_buf);
		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->cmd_type_offset_bsz &
		      cpu_to_le64(NSE_TXD_DD_M)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_packets += tx_buf->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev, dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);

		/* clear tx_buffer data */
		tx_buf->skb = NULL;
		dma_unmap_len_set(tx_buf, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			nsevf_trace(clean_tx_irq_unmap, tx_ring, tx_desc,
				    tx_buf);

			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_bi;
				tx_desc = NSEVF_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_bi;
			tx_desc = NSEVF_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;

	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->syncp);
	tx_ring->q_vector->tx.total_bytes += total_bytes;
	tx_ring->q_vector->tx.total_packets += total_packets;

	if (total_packets)
		tx_ring->tx_stats.clean_tx_irq_legacy_cnt++;

	if (ring_is_xdp(tx_ring))
		return !!budget;

	/* notify netdev of completed buffers */
	if (!nse_lan_tx_no_bql) {
		netdev_tx_completed_queue(txring_txq(tx_ring), total_packets,
					  total_bytes);
	}

#define TX_WAKE_THRESHOLD ((s16)(DESC_NEEDED * 2))
	if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
		     (NSEVF_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
		    !test_bit(__NSEVF_VSI_DOWN, vsi->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);
			++tx_ring->tx_stats.restart_queue;
		}
	}

	return !!budget;
}

static int nsevf_clean_tx_irq_on_hw_head(struct nsevf_ring *tx_ring, u16 head,
					 int napi_budget,
					 struct nsevf_txcq_ring *cq_ring);

static bool nsevf_clean_tx_irq_legacy_rs(struct nsevf_vsi *vsi,
					 struct nsevf_ring *tx_ring,
					 int napi_budget)
{
	struct nsevf_tx_desc *next_rs_desc = NULL;
	u16 tx_rs;
	u16 tx_rs_ntc = tx_ring->tx_rs_ntc;
	u16 head;
	bool head_determined = false;
	int cleaned_pkts = 0;
	int i;

	for (i = 0; i < napi_budget; i++) {
		if (tx_rs_ntc == tx_ring->tx_rs_ntu)
			break;

		tx_rs = tx_ring->tx_rs_array[tx_rs_ntc];

		next_rs_desc = NSEVF_TX_DESC(tx_ring, tx_rs);

		/* if the descriptor isn't done, no work yet to do */
		if (!(next_rs_desc->cmd_type_offset_bsz &
		      cpu_to_le64(NSE_TXD_DD_M)))
			break;

		/* i > 0 means the head has been observed at least twice.
		 * so we increase this debug counter ( means "aggreate head").
		 *
		 * but we should increase this debug counter by 1 in this func.
		 *
		 * so we use if (i == 1) as condition to increase debug counter.
		 */
		tx_ring->tx_stats.clean_tx_irq_legacy_rs_raw_cnt++;

		if (i == 1)
			tx_ring->tx_stats.clean_tx_irq_legacy_rs_agg_cnt++;

		head_determined = true;

		head = tx_rs + 1;
		if (head == tx_ring->count)
			head = 0;

		tx_rs_ntc++;
		if (tx_rs_ntc >= tx_ring->count)
			tx_rs_ntc = 0;
	}

	if (head_determined)
		cleaned_pkts = nsevf_clean_tx_irq_on_hw_head(tx_ring, head,
							     napi_budget, NULL);

	tx_ring->tx_rs_ntc = tx_rs_ntc;

	if (cleaned_pkts)
		tx_ring->tx_stats.clean_tx_irq_legacy_rs_cnt++;

	return (i < napi_budget);
}

static bool nsevf_clean_tx_irq(struct nsevf_vsi *vsi,
			       struct nsevf_ring *tx_ring, int napi_budget)
{
	if (nsevf_lan_tx_rs_optimize)
		return nsevf_clean_tx_irq_legacy_rs(vsi, tx_ring, napi_budget);
	else
		return nsevf_clean_tx_irq_legacy(vsi, tx_ring, napi_budget);
}

static void nsevf_update_txcq_ring_stats(struct nsevf_txcq_ring *ring, u64 pkts,
					 u64 bytes, u64 txqe_cnt)
{
	u64_stats_update_begin(&ring->syncp);
	ring->stats.pkts += pkts;
	ring->stats.bytes += bytes;
	ring->stats.cqe_cnt++;
	ring->stats.txqe_cnt += txqe_cnt;
	u64_stats_update_end(&ring->syncp);
}

static int nsevf_clean_tx_irq_on_hw_head(struct nsevf_ring *tx_ring, u16 head,
					 int napi_budget,
					 struct nsevf_txcq_ring *cq_ring)
{
	int total_bytes = 0, total_pkts = 0;
	struct nsevf_vsi *vsi = tx_ring->vsi;
	u16 ntc = tx_ring->next_to_clean;
	u16 ntc_to_update = ntc;
	struct nsevf_tx_desc *tx_desc;
	struct nsevf_tx_buffer *tx_buf;
	struct sk_buff *skb = NULL;
	struct nsevf_tx_desc *eop_desc = NULL;
	u32 eop_desc_idx;
	u64 clean_txqe_cnt = 0;

	tx_buf = &tx_ring->tx_bi[ntc];
	tx_desc = NSEVF_TX_DESC(tx_ring, ntc);

	eop_desc = tx_buf->next_to_watch;
	eop_desc_idx = (eop_desc - (struct nsevf_tx_desc *)tx_ring->desc);

	while (ntc != head) {
		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc) {
			/* this is not right,
			 * tx_buf always points to the first buffer of a packet.
			 * packet, which have next_to_watch set.
			 */
			nsevf_debug(&tx_ring->adapter->hw, NSEVF_DBG_LAN,
				    "[%s, %d] tx-ring (idx=%d), first tx_buf (idx=%ld) does not have next_to_watch eop_desc set?\n",
				__func__, __LINE__, tx_ring->queue_index,
				(long)(tx_buf - tx_ring->tx_bi));
			break;
		}

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb(); /* prevent any other reads prior to eop_desc */

		clean_txqe_cnt++;

		if (ntc == eop_desc_idx) {
			/* a packet is all done */

			/* clear next_to_watch to prevent false hangs */
			tx_buf->next_to_watch = NULL;

			/* update the statistics for this packet */
			total_bytes += tx_buf->bytecount;
			total_pkts += tx_buf->gso_segs;

			skb = tx_buf->skb;

			/* unmap skb header data */
			dma_unmap_single(tx_ring->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);

			/* clear tx_buf data */
			tx_buf->skb = NULL;
			dma_unmap_len_set(tx_buf, len, 0);

			/* unmap remaining buffers */
			while (tx_desc != eop_desc) {
				tx_buf++;
				tx_desc++;

				if (tx_buf ==
				    (tx_ring->tx_bi + tx_ring->count)) {
					tx_buf = tx_ring->tx_bi;
					tx_desc = NSEVF_TX_DESC(tx_ring, 0);
				}

				/* unmap any remaining paged data */
				if (dma_unmap_len(tx_buf, len)) {
					dma_unmap_page(tx_ring->dev,
						       dma_unmap_addr(tx_buf, dma),
						dma_unmap_len(tx_buf, len),
						DMA_TO_DEVICE);
					dma_unmap_len_set(tx_buf, len, 0);
				}
			}

			napi_consume_skb(skb, napi_budget);

			/* move us one more past the eop_desc for start of next pkt */
			tx_buf++;
			tx_desc++;

			ntc++;
			if (ntc == tx_ring->count) {
				ntc = 0;
				tx_buf = tx_ring->tx_bi;
				tx_desc = NSEVF_TX_DESC(tx_ring, 0);
			}

			eop_desc = tx_buf->next_to_watch;
			eop_desc_idx = (eop_desc -
					(struct nsevf_tx_desc *)tx_ring->desc);

			ntc_to_update = ntc;

			prefetch(tx_desc);
		} else { /* !if (ntc == eop_desc_idx) */

			ntc++;
			if (ntc == tx_ring->count) {
				ntc = 0;
				/* don't update tx_buf and tx_desc
				 *
				 * we expect at each iteration start of this while loop,
				 *		tx_buf pointing to first tx_buf of a packet.
				 *		tx_desc pointing to first desc of a packet.
				 */
			}
		}
	}

	tx_ring->next_to_clean = ntc_to_update;

	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_pkts;
	u64_stats_update_end(&tx_ring->syncp);
	tx_ring->q_vector->tx.total_bytes += total_bytes;
	tx_ring->q_vector->tx.total_packets += total_pkts;

	if (cq_ring)
		nsevf_update_txcq_ring_stats(cq_ring, total_pkts, total_bytes,
					     clean_txqe_cnt);

	if (!nse_lan_tx_no_bql) {
		netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts,
					  total_bytes);
	}

	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (NSEVF_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
		    !test_bit(__NSEVF_VSI_DOWN, vsi->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);
			++tx_ring->tx_stats.restart_queue;
		}
	}

	return total_pkts;
}

static int nsevf_clean_txcq_irq_one_cqd(struct nsevf_txcq_ring *cq_ring,
					u32 cqd, int napi_budget)
{
	u16 cqd_txq_q_index = (u16)(cqd & NSE_LAN_TXCQD_TXQ_ID_M);
	u16 cqd_txq_head = (u16)((cqd & NSE_LAN_TXCQD_TX_HEAD_M) >>
				 NSE_LAN_TXCQD_TX_HEAD_S);
	struct nsevf_adapter *adapter = cq_ring->adapter;
	struct nsevf_ring *tx_ring = NULL;
	struct device *dev = cq_ring->dev;
	int clean_pkts = 0;

	if (cqd_txq_q_index < adapter->num_active_queues)
		tx_ring = &adapter->tx_rings[cqd_txq_q_index];

	if (!tx_ring) {
		dev_err(dev,
			"[%s, %d] BAD: TX-CQ report a non-exist TXQ (q_index = %d) of this VSI\n",
			__func__, __LINE__, cqd_txq_q_index);
		return 0;
	}

	clean_pkts = nsevf_clean_tx_irq_on_hw_head(tx_ring, cqd_txq_head,
						   napi_budget, cq_ring);

	if (clean_pkts)
		tx_ring->tx_stats.clean_txcq_irq_cnt++;

	return clean_pkts;
}

static bool nsevf_clean_txcq_irq(struct nsevf_txcq_ring *cq_ring,
				 int napi_budget)
{
	struct nse_lan_txcq_desc *cq_desc = NULL;
	u32 cqd;
	u32 cqd_generation;
	u32 i;
	u32 ntc = cq_ring->next_to_clean;
	unsigned int total_budget;
	int cleaned_pkts = 0;

	total_budget = napi_budget * cq_ring->q_vector->num_ringpairs;

	for (i = 0; i < total_budget; i++) {
		cq_desc = NSEVF_TXCQ_DESC(cq_ring, ntc);
		cqd = le32_to_cpu(cq_desc->data);
		cqd_generation = (cqd & NSE_LAN_TXCQD_GENERATION_M) >>
				 NSE_LAN_TXCQD_GENERATION_S;

		if (cqd_generation == cq_ring->generation)
			break;

		cleaned_pkts +=
			nsevf_clean_txcq_irq_one_cqd(cq_ring, cqd, napi_budget);

		ntc++;
		if (ntc == cq_ring->count) {
			ntc = 0;
			cq_ring->generation = !cq_ring->generation;

			cq_ring->stats.gen_flip_cnt++;
		}
	}

	cq_ring->next_to_clean = ntc;

	return (i < total_budget);
}

/**
 * nsevf_enable_wb_on_itr - Arm hardware to do a wb, interrupts are not enabled
 * @vsi: the VSI we care about
 * @q_vector: the vector on which to enable writeback
 *
 **/
static void nsevf_enable_wb_on_itr(struct nsevf_vsi *vsi,
				   struct nsevf_q_vector *q_vector)
{
	u32 val;

	if (q_vector->wb_on_itr)
		return;

	/* INTMSK_VLD=1, INTMSK=1
	 *
	 *	when this func is called, INTMSK should be already 1.
	 *	but we still explicitly set it, for clearness.
	 **/
	val = NSEVF_REG_INT_DYN_CTLN_WB_ON_ITR_M |
	      NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M |
	      NSEVF_REG_INT_DYN_CTLN_INTMSK_M;

	wr32(&vsi->back->hw, INT_DYN_CTLN(&vsi->back->hw, q_vector->reg_idx),
	     val);

	q_vector->wb_on_itr = true;
}

/**
 * nsevf_setup_tx_descriptors - Allocate the Tx descriptors
 * @tx_ring: the tx ring to set up
 *
 * Return 0 on success, negative on error
 **/
int nsevf_setup_tx_descriptors(struct nsevf_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;
	int bi_size;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(tx_ring->tx_bi);
	bi_size = sizeof(struct nsevf_tx_buffer) * tx_ring->count;
	tx_ring->tx_bi = kzalloc(bi_size, GFP_KERNEL);
	if (!tx_ring->tx_bi)
		goto err;

	tx_ring->tx_rs_array = NULL;
	if (nsevf_lan_tx_rs_optimize) {
		bi_size = sizeof(u16) * tx_ring->count;
		tx_ring->tx_rs_array = kzalloc(bi_size, GFP_KERNEL);
		if (!tx_ring->tx_rs_array)
			goto err;
	}

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(struct nse_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);
	tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size, &tx_ring->dma,
					   GFP_KERNEL);
	if (!tx_ring->desc)
		goto err;

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	tx_ring->tx_rs_ntu = 0;
	tx_ring->tx_rs_ntc = 0;

	tx_ring->tx_stats.prev_pkt_ctr = -1;

	return 0;

err:
	kfree(tx_ring->tx_bi);
	tx_ring->tx_bi = NULL;

	kfree(tx_ring->tx_rs_array);
	tx_ring->tx_rs_array = NULL;

	return -ENOMEM;
}

/**
 * nsevf_clean_rx_ring - Free Rx buffers
 * @rx_ring: ring to be cleaned
 **/
void nsevf_clean_rx_ring(struct nsevf_ring *rx_ring)
{
	unsigned long bi_size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_bi)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct nsevf_rx_buffer *rx_bi = &rx_ring->rx_bi[i];

		if (rx_bi->skb) {
			dev_kfree_skb(rx_bi->skb);
			rx_bi->skb = NULL;
		}

		if (!rx_bi->page)
			continue;

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(rx_ring->dev, rx_bi->dma,
					      rx_bi->page_offset,
					      rx_ring->rx_buf_len,
					      DMA_FROM_DEVICE);

		/* free resources associated with mapping */
		dma_unmap_page_attrs(rx_ring->dev, rx_bi->dma,
				     nsevf_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				     NSEVF_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_bi->page, rx_bi->pagecnt_bias);

		rx_bi->page = NULL;
		rx_bi->page_offset = 0;
	}

	bi_size = sizeof(struct nsevf_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_bi, 0, bi_size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * nsevf_free_rx_resources - Free Rx resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void nsevf_free_rx_resources(struct nsevf_ring *rx_ring)
{
	nsevf_clean_rx_ring(rx_ring);
	rx_ring->xdp_prog = NULL;
	kfree(rx_ring->rx_bi);
	rx_ring->rx_bi = NULL;

	if (rx_ring->desc) {
		dma_free_coherent(rx_ring->dev, rx_ring->size, rx_ring->desc,
				  rx_ring->dma);
		rx_ring->desc = NULL;
	}
}

/**
 * nsevf_setup_rx_descriptors - Allocate Rx descriptors
 * @rx_ring: Rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int nsevf_setup_rx_descriptors(struct nsevf_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	int err = -ENOMEM;
	int bi_size;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(rx_ring->rx_bi);
	bi_size = sizeof(struct nsevf_rx_buffer) * rx_ring->count;
	rx_ring->rx_bi = kzalloc(bi_size, GFP_KERNEL);
	if (!rx_ring->rx_bi)
		goto err;

	u64_stats_init(&rx_ring->syncp);

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union nsevf_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);
	rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size, &rx_ring->dma,
					   GFP_KERNEL);

	if (!rx_ring->desc)
		goto err;

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	return 0;
err:
	kfree(rx_ring->rx_bi);
	rx_ring->rx_bi = NULL;
	return err;
}

void nsevf_clean_txcq_ring(struct nsevf_txcq_ring *cq_ring)
{
	if (!cq_ring || !cq_ring->desc)
		return;

	cq_ring->next_to_clean = 0;

	if (cq_ring->adapter->vf_res->lan_txcq_initial_hw_gen) {
		memset(cq_ring->desc, 0, cq_ring->size);
		cq_ring->generation = 0;
	} else {
		memset(cq_ring->desc, 0xFF, cq_ring->size);
		cq_ring->generation = 1;
	}
}

void nsevf_free_txcq_resources(struct nsevf_txcq_ring *cq_ring)
{
	if (!cq_ring)
		return;

	nsevf_clean_txcq_ring(cq_ring);

	if (cq_ring->desc) {
		dma_free_coherent(cq_ring->dev, cq_ring->size, cq_ring->desc,
				  cq_ring->dma);
		cq_ring->desc = NULL;
	}
}

int nsevf_setup_txcq_descriptors(struct nsevf_txcq_ring *cq_ring)
{
	struct device *dev = cq_ring->dev;
	int err = -ENOMEM;

	if (!dev)
		goto out;

	u64_stats_init(&cq_ring->syncp);

	/* round up to nearest page */
	cq_ring->size = ALIGN(cq_ring->count * sizeof(struct nsevf_txcq_desc),
			      PAGE_SIZE);
	cq_ring->desc = dma_alloc_coherent(dev, cq_ring->size, &cq_ring->dma,
					   GFP_KERNEL);
	if (!cq_ring->desc)
		goto out;

	cq_ring->next_to_clean = 0;

	if (cq_ring->adapter->vf_res->lan_txcq_initial_hw_gen) {
		memset(cq_ring->desc, 0, cq_ring->size);
		cq_ring->generation = 0;
	} else {
		memset(cq_ring->desc, 0xFF, cq_ring->size);
		cq_ring->generation = 1;
	}

	err = 0;

out:
	return err;
}

/**
 * nsevf_release_rx_desc - Store the new tail and head values
 * @rx_ring: ring to bump
 * @val: new head index
 **/
static void nsevf_release_rx_desc(struct nsevf_ring *rx_ring, u32 val)
{
	rx_ring->next_to_use = val;

	/* update next to alloc since we have filled the ring */
	rx_ring->next_to_alloc = val;

	/* don't actually write HW doorbell when happen in reset */
	if (nsevf_is_reset_in_progress(rx_ring->adapter))
		return;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	writel(val, rx_ring->tail);
}

/**
 * nsevf_rx_offset - Return expected offset into page to access data
 * @rx_ring: Ring we are requesting offset of
 *
 * Returns the offset value for ring into the data buffer.
 */
static unsigned int nsevf_rx_offset(struct nsevf_ring *rx_ring)
{
	return ring_uses_build_skb(rx_ring) ? NSEVF_SKB_PAD : 0;
}

/**
 * nsevf_alloc_mapped_page - recycle or make a new page
 * @rx_ring: ring to use
 * @bi: rx_buffer struct to modify
 *
 * Returns true if the page was successfully allocated or
 * reused.
 **/
static bool nsevf_alloc_mapped_page(struct nsevf_ring *rx_ring,
				    struct nsevf_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page)) {
		rx_ring->rx_stats.page_reuse_count++;
		return true;
	}

	/* alloc new page for storage */
	page = dev_alloc_pages(nsevf_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page_attrs(rx_ring->dev, page, 0,
				 nsevf_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				 NSEVF_RX_DMA_ATTR);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, nsevf_rx_pg_order(rx_ring));
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = nsevf_rx_offset(rx_ring);

	/* initialize pagecnt_bias to 1 representing we fully own page */
	bi->pagecnt_bias = 1;

	return true;
}

/**
 * nsevf_receive_skb - Send a completed packet up the stack
 * @rx_ring:  rx ring in play
 * @skb: packet to send up
 * @vlan_tag: vlan tag for packet
 **/
static void nsevf_receive_skb(struct nsevf_ring *rx_ring, struct sk_buff *skb,
			      u16 vlan_tag)
{
	struct nsevf_q_vector *q_vector = rx_ring->q_vector;

	if (vlan_tag & VLAN_VID_MASK) {
		if (rx_ring->netdev->features & NSEVF_NETIF_F_HW_VLAN_CTAG_RX) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag);
		} else if (rx_ring->netdev->features &
			   NETIF_F_HW_VLAN_STAG_RX) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag);
		}
	}

	if (!nsevf_polling_mod)
		napi_gro_receive(&q_vector->napi, skb);
	else
		netif_receive_skb(skb);
}

/**
 * nsevf_alloc_rx_buffers - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail
 **/
bool nsevf_alloc_rx_buffers(struct nsevf_ring *rx_ring, u16 cleaned_count)
{
	u16 ntu = rx_ring->next_to_use;
	union nsevf_rx_desc *rx_desc;
	struct nsevf_rx_buffer *bi;

	/* do nothing if no valid netdev defined */
	if (!rx_ring->netdev || !cleaned_count)
		return false;

	rx_desc = NSEVF_RX_DESC(rx_ring, ntu);
	bi = &rx_ring->rx_bi[ntu];

	do {
		if (!nsevf_alloc_mapped_page(rx_ring, bi))
			goto no_buffers;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
						 bi->page_offset,
						 rx_ring->rx_buf_len,
						 DMA_FROM_DEVICE);

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);

		rx_desc++;
		bi++;
		ntu++;
		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = NSEVF_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_bi;
			ntu = 0;
		}

		/* clear the status bits for the next_to_use descriptor */
		rx_desc->wb.status_error0 = 0;

		cleaned_count--;
	} while (cleaned_count);

	if (rx_ring->next_to_use != ntu)
		nsevf_release_rx_desc(rx_ring, ntu);

	return false;

no_buffers:
	if (rx_ring->next_to_use != ntu)
		nsevf_release_rx_desc(rx_ring, ntu);

	/* make sure to come back via polling to try again after
	 * allocation failure
	 */
	return true;
}

static void nsevf_rx_ring_sync_tail_after_enable(struct nsevf_ring *rx_ring)
{
	writel_relaxed(rx_ring->next_to_use, rx_ring->tail);
}

void nsevf_sync_tail_all_rx_rings(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	int i;

	nsevf_debug(hw, NSEVF_DBG_LAN, "[%s] is_reset_in_progress()=%d\n",
		    __func__, nsevf_is_reset_in_progress(adapter));

	for (i = 0; i < adapter->num_active_queues; i++) {
		struct nsevf_ring *rx_ring = &adapter->rx_rings[i];

		if (rx_ring)
			nsevf_rx_ring_sync_tail_after_enable(rx_ring);
	}
}

/**
 * nsevf_ptype_to_htype - get a hash type
 * @ptype: the ptype value from the descriptor
 * @vsi_rss_ctl: VSI RSS control settings
 *
 * Returns appropriate hash type (such as PKT_HASH_TYPE_L2/L3/L4) to be used by
 * skb_set_hash based on PTYPE as parsed by HW Rx pipeline and is part of
 * Rx desc.
 */
static enum pkt_hash_types nsevf_ptype_to_htype(u8 ptype, u32 vsi_rss_ctl)
{
	struct nse_rx_ptype_decoded decoded = nse_decode_rx_desc_ptype(ptype);

	if (!decoded.known)
		return PKT_HASH_TYPE_NONE;

	if (decoded.payload_layer == NSE_RX_PTYPE_PAYLOAD_LAYER_PAY4) {
		if (decoded.inner_prot == NSE_RX_PTYPE_INNER_PROT_TCP &&
		    ((vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_TCP) ||
		     (vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_TCP))) {
			return PKT_HASH_TYPE_L4;
		} else if (decoded.inner_prot == NSE_RX_PTYPE_INNER_PROT_UDP &&
			   ((vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV4_UDP) ||
			    (vsi_rss_ctl & NSE_VSI_RSS_CTL_ALG_IPV6_UDP))) {
			return PKT_HASH_TYPE_L4;
		}
		return PKT_HASH_TYPE_L3;
	}
	if (decoded.payload_layer == NSE_RX_PTYPE_PAYLOAD_LAYER_PAY3)
		return PKT_HASH_TYPE_L3;
	if (decoded.outer_ip == NSE_RX_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

/**
 * nsevf_rx_csum - Indicate in skb if checksum is good
 * @rx_ring: the ring we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: the packet type decoded by hardware
 *
 * skb->protocol must be set before this function is called
 */
static void nsevf_rx_csum(struct nsevf_ring *rx_ring, struct sk_buff *skb,
			  union nsevf_rx_desc *rx_desc, u8 ptype)
{
	struct nsevf_vsi *vsi = rx_ring->vsi;
	struct nse_rx_ptype_decoded decoded;
	u16 rx_status0;
	bool ipv4, ipv6;

	rx_status0 = le16_to_cpu(rx_desc->wb.status_error0);

	decoded = nse_decode_rx_desc_ptype(ptype);

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if (!(vsi->netdev->features & NETIF_F_RXCSUM))
		return;

	/* not a L3 IPv4/IPv6 packet */
	if (!(decoded.known && decoded.outer_ip))
		return;

	ipv4 = (decoded.outer_ip == NSE_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == NSE_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded.outer_ip == NSE_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == NSE_RX_PTYPE_OUTER_IPV6);

	if (ipv4 && (rx_status0 & (BIT(NSE_RXD_STATUS0_XSUM_IPE_S) |
				   BIT(NSE_RXD_STATUS0_XSUM_EIPE_S))))
		goto checksum_fail;

	if (ipv6 && (rx_status0 & (BIT(NSE_RXD_STATUS0_IPV6EXADD_S))))
		goto checksum_fail;

	/* check for L4 errors and handle packets that were not able to be
	 * checksummed due to arrival speed
	 */
	if (rx_status0 & BIT(NSE_RXD_STATUS0_XSUM_L4E_S))
		goto checksum_fail;

	/* check for outer UDP checksum error in tunneled packets */
	if (rx_status0 & BIT(NSE_RXD_STATUS0_XSUM_EUDPE_S))
		goto checksum_fail;

	/* If there is an outer header present that might contain a checksum
	 * we need to bump the checksum level by 1 to reflect the fact that
	 * we are indicating we validated the inner checksum.
	 */
	if (decoded.tunnel_type >= NSE_RX_PTYPE_TUNNEL_IP_GRENAT)
		skb->csum_level = 1;

	/* Only report checksum unnecessary for TCP, UDP, or SCTP */
	switch (decoded.inner_prot) {
	case NSE_RX_PTYPE_INNER_PROT_TCP:
	case NSE_RX_PTYPE_INNER_PROT_UDP:
	case NSE_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		break;
	default:
		break;
	}
	rx_ring->rx_stats.rx_csum_good++;
	return;

checksum_fail:
	rx_ring->rx_stats.rx_csum_bad++;
}

/**
 * nsevf_rx_hash - set the hash value in the skb
 * @ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: skb currently being received and modified
 * @rx_ptype: Rx packet type
 *
 **/
static void nsevf_rx_hash(struct nsevf_ring *ring, union nsevf_rx_desc *rx_desc,
			  struct sk_buff *skb, u8 rx_ptype)
{
	struct nse_32b_rx_desc_nic *rx_desc_nic =
		(struct nse_32b_rx_desc_nic *)rx_desc;
	u32 hash;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	if (!nse_rxdid_has_rss_hash(rx_desc->wb.rxdid))
		return;

	/* not enqueued by RSS */
	if ((rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M) !=
	    NSE_RXD_QSRC_RSS)
		return;

	hash = le32_to_cpu(rx_desc_nic->rss_hash);

	skb_set_hash(skb, hash,
		     nsevf_ptype_to_htype(rx_ptype,
					  ring->vsi->back->rss_ctl_alg));
}

static void nsevf_set_rsc_gso_size(struct nsevf_ring __maybe_unused *ring,
				   struct sk_buff *skb)
{
	u16 hdr_len = skb_headlen(skb);

	/* set gso_size to avoid messing up TCP MSS */
	skb_shinfo(skb)->gso_size =
		DIV_ROUND_UP((skb->len - hdr_len), NSEVF_CB(skb)->append_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
}

static void nsevf_rx_rsc(struct nsevf_ring *rx_ring, struct sk_buff *skb)
{
	/* if append_cnt is 0 then frame is not RSC */
	if (!NSEVF_CB(skb)->append_cnt)
		return;

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	rx_ring->rx_stats.rsc_count += NSEVF_CB(skb)->append_cnt;
	rx_ring->rx_stats.rsc_flush++;

	nsevf_set_rsc_gso_size(rx_ring, skb);

	/* gso_size is computed using append_cnt so always clear it last */
	NSEVF_CB(skb)->append_cnt = 0;
}

/**
 * nsevf_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 * @rx_ptype: the packet type decoded by hardware
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 **/
static void nsevf_process_skb_fields(struct nsevf_ring *rx_ring,
				     union nsevf_rx_desc *rx_desc,
				     struct sk_buff *skb, u8 rx_ptype)
{
	int qsrc;

	qsrc = (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M) >>
	       NSE_RXD_QSRC_S;
	rx_ring->rx_stats.qsrc_cnt[qsrc]++;

	nsevf_rx_hash(rx_ring, rx_desc, skb, rx_ptype);

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);

	nsevf_rx_csum(rx_ring, skb, rx_desc, rx_ptype);

	nsevf_rx_rsc(rx_ring, skb);

	skb_record_rx_queue(skb, rx_ring->queue_index);
}

/**
 * nsevf_cleanup_headers - Correct empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being fixed
 * @rx_desc: pointer to the EOP Rx descriptor
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 **/
static bool nsevf_cleanup_headers(struct nsevf_ring *rx_ring,
				  struct sk_buff *skb,
				  union nsevf_rx_desc *rx_desc)
{
	/* XDP packets use error pointer so abort at this point */
	if (IS_ERR(skb))
		return true;

	/* ERR_MASK will only have valid bits if EOP set, and
	 * what we are doing here is actually checking
	 * NSEVF_RX_DESC_ERROR_RXE_SHIFT, since it is the zeroth bit in
	 * the error field
	 */
	if (unlikely(nsevf_test_staterr(rx_desc->wb.status_error0,
					BIT(NSE_RXD_STATUS0_RXE_S)))) {
		dev_kfree_skb_any(skb);
		return true;
	}

	/* if eth_skb_pad returns an error the skb was freed */
	if (eth_skb_pad(skb))
		return true;

	return false;
}

/**
 * nsevf_page_is_reusable - check if any reuse is possible
 * @page: page struct to check
 *
 * A page is not reusable if it was allocated under low memory
 * conditions, or it's not in the same NUMA node as this CPU.
 */
static bool nsevf_page_is_reusable(struct page *page)
{
	return (page_to_nid(page) == numa_mem_id()) &&
	       !page_is_pfmemalloc(page);
}

/**
 * nsevf_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 **/
static void nsevf_reuse_rx_page(struct nsevf_ring *rx_ring,
				struct nsevf_rx_buffer *old_buff)
{
	struct nsevf_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_bi[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->dma = old_buff->dma;
	new_buff->page = old_buff->page;
	new_buff->page_offset = old_buff->page_offset;
	new_buff->pagecnt_bias = old_buff->pagecnt_bias;
}

/**
 * nsevf_can_reuse_rx_page - Determine if this page can be reused by
 * the adapter for another receive
 *
 * @rx_buffer: buffer containing the page
 *
 * If page is reusable, rx_buffer->page_offset is adjusted to point to
 * an unused region in the page.
 *
 * For small pages, @truesize will be a constant value, half the size
 * of the memory at page.  We'll attempt to alternate between high and
 * low halves of the page, with one half ready for use by the hardware
 * and the other half being consumed by the stack.  We use the page
 * ref count to determine whether the stack has finished consuming the
 * portion of this page that was passed up with a previous packet.  If
 * the page ref count is >1, we'll assume the "other" half page is
 * still busy, and this page cannot be reused.
 *
 * For larger pages, @truesize will be the actual space used by the
 * received packet (adjusted upward to an even multiple of the cache
 * line size).  This will advance through the page by the amount
 * actually consumed by the received packets while there is still
 * space for a buffer.  Each region of larger pages will be used at
 * most once, after which the page will not be reused.
 *
 * In either case, if the page is reusable its refcount is increased.
 **/
static bool nsevf_can_reuse_rx_page(struct nsevf_rx_buffer *rx_buffer)
{
	unsigned int pagecnt_bias = rx_buffer->pagecnt_bias;
	struct page *page = rx_buffer->page;

	/* Is any reuse possible? */
	if (unlikely(!nsevf_page_is_reusable(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely((page_count(page) - pagecnt_bias) > 1))
		return false;
#else
#define NSEVF_LAST_OFFSET (SKB_WITH_OVERHEAD(PAGE_SIZE) - NSEVF_RXBUFFER_2048)
	if (rx_buffer->page_offset > NSEVF_LAST_OFFSET)
		return false;
#endif

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
	if (unlikely(!pagecnt_bias)) {
		page_ref_add(page, USHRT_MAX);
		rx_buffer->pagecnt_bias = USHRT_MAX;
	}
	return true;
}

/**
 * nsevf_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 * It will just attach the page as a frag to the skb.
 *
 * The function will then update the page offset.
 **/
static void nsevf_add_rx_frag(struct nsevf_ring *rx_ring,
			      struct nsevf_rx_buffer *rx_buffer,
			      struct sk_buff *skb, unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = nsevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(size + nsevf_rx_offset(rx_ring));
#endif

	if (!size)
		return;

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->page,
			rx_buffer->page_offset, size, truesize);

	/* page is being used so we must update the page offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif
}

/**
 * nsevf_get_rx_buffer - Fetch Rx buffer and synchronize data for use
 * @rx_ring: rx descriptor ring to transact packets on
 * @skb: pointer to the skb being constructed
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct nsevf_rx_buffer *nsevf_get_rx_buffer(struct nsevf_ring *rx_ring,
						   struct sk_buff **skb,
						   const unsigned int size)
{
	struct nsevf_rx_buffer *rx_buffer;

	rx_buffer = &rx_ring->rx_bi[rx_ring->next_to_clean];
	prefetchw(rx_buffer->page);

	*skb = rx_buffer->skb;

	if (!size)
		return rx_buffer;

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buffer->dma,
				      rx_buffer->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	rx_buffer->pagecnt_bias--;

	return rx_buffer;
}

/**
 * nsevf_construct_skb - Allocate skb and populate it
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 * @size: size of data to add to the skb
 *
 * This function allocates an skb.  It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
static struct sk_buff *nsevf_construct_skb(struct nsevf_ring *rx_ring,
					   struct nsevf_rx_buffer *rx_buffer,
					   unsigned int size)
{
	void *va;

#if (PAGE_SIZE < 8192)
	unsigned int truesize = nsevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(size);
#endif
	unsigned int headlen;
	struct sk_buff *skb;

	if (!rx_buffer)
		return NULL;
	/* prefetch first cache line of first page */
	va = page_address(rx_buffer->page) + rx_buffer->page_offset;
	net_prefetch(va);

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rx_ring->q_vector->napi, NSEVF_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > NSEVF_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, va, NSEVF_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), va, ALIGN(headlen, sizeof(long)));

	/* update all of the pointers */
	size -= headlen;
	if (size) {
		skb_add_rx_frag(skb, 0, rx_buffer->page,
				rx_buffer->page_offset + headlen, size,
				truesize);

		/* buffer is used by skb, update page_offset */
#if (PAGE_SIZE < 8192)
		rx_buffer->page_offset ^= truesize;
#else
		rx_buffer->page_offset += truesize;
#endif
	} else {
		/* buffer is unused, reset bias back to rx_buffer */
		rx_buffer->pagecnt_bias++;
	}

	return skb;
}

/**
 * nsevf_build_skb - Build skb around an existing buffer
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 * @size: size of data to add to the skb
 *
 * This function builds an skb around an existing Rx buffer, taking care
 * to set up the skb correctly and avoid any memcpy overhead.
 */
static struct sk_buff *nsevf_build_skb(struct nsevf_ring *rx_ring,
				       struct nsevf_rx_buffer *rx_buffer,
				       unsigned int size)
{
	void *va;

#if (PAGE_SIZE < 8192)
	unsigned int truesize = nsevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(NSEVF_SKB_PAD + size);
#endif
	struct sk_buff *skb;

	if (!rx_buffer || !size)
		return NULL;

	/* prefetch first cache line of first page */
	va = page_address(rx_buffer->page) + rx_buffer->page_offset;
	net_prefetch(va);

	/* build an skb around the page buffer */
	skb = napi_build_skb(va - NSEVF_SKB_PAD, truesize);
	if (unlikely(!skb))
		return NULL;

	/* update pointers within the skb to store the data */
	skb_reserve(skb, NSEVF_SKB_PAD);
	__skb_put(skb, size);

	/* buffer is used by skb, update page_offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif

	return skb;
}

/**
 * nsevf_put_rx_buffer - Clean up used buffer and either recycle or free
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buffer.  It will
 * either recycle the buffer or unmap it and free the associated resources.
 */
static void nsevf_put_rx_buffer(struct nsevf_ring *rx_ring,
				struct nsevf_rx_buffer *rx_buffer)
{
	if (!rx_buffer)
		return;

	if (nsevf_can_reuse_rx_page(rx_buffer)) {
		/* hand second half of page back to the ring */
		nsevf_reuse_rx_page(rx_ring, rx_buffer);
		rx_ring->rx_stats.page_reuse_count++;
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page_attrs(rx_ring->dev, rx_buffer->dma,
				     nsevf_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				     NSEVF_RX_DMA_ATTR);
		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	rx_buffer->page = NULL;
	rx_buffer->skb = NULL;
}

/**
 * nsevf_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool nsevf_is_non_eop(struct nsevf_ring *rx_ring,
			     union nsevf_rx_desc *rx_desc, struct sk_buff *skb)
{
	u16 rsccnt, nextp;
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(NSEVF_RX_DESC(rx_ring, ntc));

	rsccnt = (le16_to_cpu(rx_desc->wb.hdrlen_rsccnt) & NSE_RXD_RSCCNT_M);
	if (rsccnt) {
		nextp = le16_to_cpu(rx_desc->wb.l2tag1_nextp);

		NSEVF_CB(skb)->append_cnt += (rsccnt - 1);
	}

	/* if we are the last buffer then there is nothing else to do */
#define NSEVF_RXD_EOF BIT(NSE_RXD_STATUS0_EOP_S)
	if (likely(nsevf_test_staterr(rx_desc->wb.status_error0,
				      NSEVF_RXD_EOF)))
		return false;

	if (rsccnt)
		rx_ring->rx_bi[nextp].skb = skb;
	else
		rx_ring->rx_bi[rx_ring->next_to_clean].skb = skb;

	rx_ring->rx_stats.non_eop_descs++;

	return true;
}

struct nsevf_rx_extracted {
	unsigned int size;
	u16 vlan_tag;
	u8 rx_ptype;
};

static void nsevf_extract_rx_fields(struct nsevf_ring *rx_ring,
				    union nsevf_rx_desc *rx_desc,
				    struct nsevf_rx_extracted *fields)
{
	u16 status0;
	u8 status1;

	fields->size = le16_to_cpu(rx_desc->wb.pktlen_sph_reentry) &
		       NSE_RXD_PKT_LEN_M;
	fields->rx_ptype = rx_desc->wb.ptype;

	status0 = le16_to_cpu(rx_desc->wb.status_error0);
	if ((status0 & BIT(NSE_RXD_STATUS0_L2TAG1P_S)) &&
	    rx_ring->flags & NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1) {
		fields->vlan_tag = le16_to_cpu(rx_desc->wb.l2tag1_nextp);
	}

	status1 = rx_desc->wb.status_error1;
	if ((status1 & BIT(NSE_RXD_STATUS1_L2TAG2P_S)) &&
	    rx_ring->flags & NSEVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2ND) {
		fields->vlan_tag = le16_to_cpu(rx_desc->wb.l2tag2_2nd);
	}
}

/**
 * nsevf_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 **/
static int nsevf_clean_rx_irq(struct nsevf_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct sk_buff *skb = NULL;
	u16 cleaned_count = NSEVF_DESC_UNUSED(rx_ring);
	bool failure = false;

	while (likely(total_rx_packets < (unsigned int)budget)) {
		struct nsevf_rx_extracted fields = {};
		struct nsevf_rx_buffer *rx_buffer;
		union nsevf_rx_desc *rx_desc;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= NSEVF_RX_BUFFER_WRITE) {
			failure =
				failure ||
				nsevf_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = NSEVF_RX_DESC(rx_ring, rx_ring->next_to_clean);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();
#define NSEVF_RXD_DD BIT(NSE_RXD_STATUS0_DD_S)
		if (!nsevf_test_staterr(rx_desc->wb.status_error0,
					NSEVF_RXD_DD))
			break;

		nsevf_extract_rx_fields(rx_ring, rx_desc, &fields);

		rx_buffer = nsevf_get_rx_buffer(rx_ring, &skb, fields.size);

		nsevf_trace(clean_rx_irq, rx_ring, rx_desc, skb);

		/* retrieve a buffer from the ring */
		if (skb)
			nsevf_add_rx_frag(rx_ring, rx_buffer, skb, fields.size);
		else if (ring_uses_build_skb(rx_ring))
			skb = nsevf_build_skb(rx_ring, rx_buffer, fields.size);
		else
			skb = nsevf_construct_skb(rx_ring, rx_buffer,
						  fields.size);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_buff_failed++;
			if (rx_buffer)
				rx_buffer->pagecnt_bias++;
			break;
		}

		nsevf_put_rx_buffer(rx_ring, rx_buffer);
		cleaned_count++;

		if (nsevf_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		if (nsevf_cleanup_headers(rx_ring, skb, rx_desc)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, VLAN, and protocol */
		nsevf_process_skb_fields(rx_ring, rx_desc, skb,
					 fields.rx_ptype);

		nsevf_trace(clean_rx_irq_rx, rx_ring, rx_desc, skb);

		nsevf_receive_skb(rx_ring, skb, fields.vlan_tag);
		skb = NULL;

		/* update budget accounting */
		total_rx_packets++;
	}

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);

	rx_ring->q_vector->rx.total_packets += total_rx_packets;
	rx_ring->q_vector->rx.total_bytes += total_rx_bytes;

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_packets;
}

static void __nsevf_update_sample(struct nsevf_q_vector *q_vector,
				  struct dim_sample *sample)
{
	u64 packets = 0, bytes = 0;
	struct nsevf_ring_container *rc;
	struct nsevf_ring *ring;

	rc = &q_vector->rx;
	nsevf_for_each_ring(ring, *rc) {
		packets += ring->stats.packets;
		bytes += ring->stats.bytes;
	}

	rc = &q_vector->tx;
	nsevf_for_each_ring(ring, *rc) {
		packets += ring->stats.packets;
		bytes += ring->stats.bytes;
	}

	dim_update_sample(q_vector->total_events, packets, bytes, sample);
	sample->comp_ctr = 0;

	/* if dim settings get stale, like when not updated for 1
	 * second or longer, force it to start again. This addresses the
	 * frequent case of an idle queue being switched to by the
	 * scheduler. The 1,000 here means 1,000 milliseconds.
	 */
	if (ktime_ms_delta(sample->time, q_vector->dim.start_sample.time) >=
	    1000)
		q_vector->dim.state = DIM_START_MEASURE;
}

/**
 * nsevf_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void nsevf_net_dim(struct nsevf_q_vector *q_vector)
{
	if (ITR_IS_DYNAMIC(q_vector)) {
		struct dim_sample dim_sample;

		__nsevf_update_sample(q_vector, &dim_sample);
		net_dim(&q_vector->dim, dim_sample);
	}
}

/**
 * nsevf_buildreg_itr - build value for writing to the INT_DYN_CTLN register
 * @update_itr: whether to update the interrupt throttling value
 * @itr: interrupt throttling value in usecs
 */
static u32 nsevf_buildreg_itr(bool update_itr, u16 itr)
{
	u32 val;

	val = NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M; /* intmask_vld=1, intmsk=0 -- unmask this irq */

	if (update_itr) {
		val |= NSEVF_REG_INT_DYN_CTLN_ITR_VALID_M;

		if (!itr || nsevf_lan_min_itr_no_intrl)
			itr = (NSE_ITR_INTERVAL_MIN_USEC >> 1);

		val |= ((itr << NSEVF_REG_INT_DYN_CTLN_ITR_INTERVAL_S) &
			NSEVF_REG_INT_DYN_CTLN_ITR_INTERVAL_M);
	}

	return val;
}

#define ITR_COUNTDOWN_START 3

/**
 * nsevf_update_enable_itr - Update itr and re-enable MSIX interrupt
 * @vsi: the VSI we care about
 * @q_vector: q_vector for which itr is being updated and interrupt enabled
 *
 **/
static void nsevf_update_enable_itr(struct nsevf_vsi *vsi,
				    struct nsevf_q_vector *q_vector)
{
	struct nsevf_hw *hw = &vsi->back->hw;
	bool wb_en = q_vector->wb_on_itr;
	u32 reg_val;

	if (test_bit(__NSEVF_VSI_DOWN, vsi->state))
		return;

	if (!wb_en) {
		reg_val = nsevf_buildreg_itr(false, 0);
	} else {
		q_vector->wb_on_itr = false;

		/* do two things here with a single write. Set up the third ITR
		 * index to be used for software interrupt moderation, and then
		 * trigger a software interrupt with a rate limit of 20K on
		 * software interrupts, this will help avoid high interrupt
		 * loads due to frequently polling and exiting polling.
		 */
		if (q_vector->dyn_itr_refresh) {
			reg_val =
				nsevf_buildreg_itr(true, q_vector->dyn_itr_val);
			q_vector->dyn_itr_refresh = false;
		} else {
			reg_val = nsevf_buildreg_itr(true, (NSE_ITR_INTERVAL_20K >> 1));
		}
		reg_val |= NSEVF_REG_INT_DYN_CTLN_SWINT_TRIG_M;
	}

	wr32(hw, INT_DYN_CTLN(hw, q_vector->reg_idx), reg_val);
}

int nsevf_polling(struct nsevf_q_vector *q_vector, int budget)
{
	struct nsevf_vsi *vsi = q_vector->vsi;
	bool clean_complete = true;
	struct nsevf_ring *ring;
	int budget_per_ring;
	int work_done = 0;

	if (test_bit(__NSEVF_VSI_DOWN, vsi->state))
		return 0;

	if (!q_vector->txcq) {
		/* Since the actual Tx work is minimal, we can give the Tx a larger
		 * budget and be more aggressive about cleaning up the Tx descriptors.
		 */
		nsevf_for_each_ring(ring, q_vector->tx) {
			if (!nsevf_clean_tx_irq(vsi, ring, budget)) {
				clean_complete = false;
				continue;
			}
		}
	} else { /* LAN-TX-CQ logic */

		if (!nsevf_clean_txcq_irq(q_vector->txcq, budget))
			clean_complete = false;
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0)
		return budget;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	budget_per_ring = max(budget / q_vector->num_ringpairs, 1);

	nsevf_for_each_ring(ring, q_vector->rx) {
		int cleaned = nsevf_clean_rx_irq(ring, budget_per_ring);

		work_done += cleaned;
		/* if we clean as many as budgeted, we must not be done */
		if (cleaned >= budget_per_ring)
			clean_complete = false;
	}

	/* if netdev is disabled we need to stop polling */
	if (!netif_running(vsi->netdev))
		clean_complete = true;

	/* If work not completed, return budget and polling will return */
	if (!clean_complete)
		return budget;

	return min_t(int, work_done, budget - 1);
}

#define NSEVF_NAPI_POLL_BUDGET_PER_RXQ 32

/**
 * nsevf_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 **/
int nsevf_napi_poll(struct napi_struct *napi, int budget)
{
	struct nsevf_q_vector *q_vector =
		container_of(napi, struct nsevf_q_vector, napi);
	struct nsevf_vsi *vsi = q_vector->vsi;
	struct nsevf_adapter *adapter = vsi->back;
	bool clean_complete = true;
	struct nsevf_ring *ring;
	int budget_per_ring;
	int work_done = 0;
	bool wd;
	int cpu_id;
	u64 poll_ns;

	if (test_bit(__NSEVF_VSI_DOWN, vsi->state) ||
	    nsevf_is_reset_in_progress(adapter)) {
		napi_complete(napi);
		return 0;
	}

	poll_ns = ktime_get_real_ns();

	q_vector->dbg_stats.napi_poll_total_cnt++;
	q_vector->dbg_stats.napi_poll_last_ns = poll_ns;

	if (!q_vector->txcq) {
		/* Since the actual Tx work is minimal, we can give the Tx a larger
		 * budget and be more aggressive about cleaning up the Tx descriptors.
		 */
		nsevf_for_each_ring(ring, q_vector->tx) {
			wd = nsevf_clean_tx_irq(vsi, ring, budget);

			if (!wd) {
				clean_complete = false;

				q_vector->dbg_stats
					.napi_poll_txq_clean_not_done_cnt++;
			} else {
				q_vector->dbg_stats
					.napi_poll_txq_clean_done_cnt++;
			}
		}
	} else { /* LAN-TX-CQ logic */

		wd = nsevf_clean_txcq_irq(q_vector->txcq, budget);

		if (!wd) {
			clean_complete = false;

			q_vector->dbg_stats.napi_poll_txcq_clean_not_done_cnt++;
		} else {
			q_vector->dbg_stats.napi_poll_txcq_clean_done_cnt++;
		}
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(budget <= 0)) {
		q_vector->dbg_stats.napi_poll_budeget_less_0_cnt++;
		q_vector->dbg_stats.napi_poll_budeget_less_0_last_poll_cnt =
			q_vector->dbg_stats.napi_poll_total_cnt;
		q_vector->dbg_stats.napi_poll_budeget_less_0_last_ns = poll_ns;

		goto tx_only;
	}

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	budget_per_ring = max(budget / q_vector->num_ringpairs,
			      NSEVF_NAPI_POLL_BUDGET_PER_RXQ);

	nsevf_for_each_ring(ring, q_vector->rx) {
		int cleaned = nsevf_clean_rx_irq(ring, budget_per_ring);

		work_done += cleaned;

		/* if we clean as many as budgeted, we must not be done */
		if (work_done >= budget || cleaned >= budget_per_ring) {
			clean_complete = false;

			q_vector->dbg_stats.napi_poll_rxq_clean_not_done_cnt++;
		} else {
			q_vector->dbg_stats.napi_poll_rxq_clean_done_cnt++;
		}
	}

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		q_vector->dbg_stats.napi_poll_clean_not_done_cnt++;

		cpu_id = smp_processor_id();

		/* It is possible that the interrupt affinity has changed but,
		 * if the cpu is pegged at 100%, polling will never exit while
		 * traffic continues and the interrupt will be stuck on this
		 * cpu.  We check to make sure affinity is correct before we
		 * continue to poll, otherwise we must stop polling so the
		 * interrupt can move to the correct cpu.
		 */
		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			/* Tell napi that we are done polling */
			napi_complete_done(napi, work_done);

			/* Force an interrupt */
			nsevf_force_wb(vsi, q_vector);

			q_vector->dbg_stats.napi_poll_cpu_change_cnt++;

			q_vector->dbg_stats.napi_poll_cpu_change_last_poll_cnt =
				q_vector->dbg_stats.napi_poll_total_cnt;
			q_vector->dbg_stats.napi_poll_cpu_change_last_ns =
				poll_ns;

			q_vector->dbg_stats.napi_poll_last_ret_event =
				1; /* !clean_complete && cpu_change */

			/* Return budget-1 so that polling stops */
			return budget - 1;
		}

tx_only:

		nsevf_enable_wb_on_itr(vsi, q_vector);

		q_vector->dbg_stats.napi_poll_last_ret_event =
			2; /* !clean_complete && !cpu_change */

		return budget;
	}

	q_vector->dbg_stats.napi_poll_clean_done_cnt++;

	/* Work is done so exit the polling mode and re-enable the interrupt */
	if (likely(napi_complete_done(napi, work_done))) {
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is TRUE, enable device interrupt
		 * but there are condition/optimization, where it can be
		 * optimized. Bascially, if napi_complete_done returns true buti
		 * last time Rx packets were cleaned, then most likely, consumer
		 * thread will come back to do busy_polling where cleaning of
		 * Tx/Rx queue will happen normally. Hence no reason to arm the
		 * interrupt.
		 *
		 * If for some reason, consumer thread/context doesn't comeback
		 * to busy_poll:napi_poll, there is bail-out mechanism to kick
		 * start the state machine thru' SW triggered interrupt from
		 * service task.
		 */

		q_vector->dbg_stats.napi_poll_clean_done_unmask_irq_cnt++;

		q_vector->dbg_stats.napi_poll_last_ret_event =
			3; /* clean_complete, enable_interrupt() */

		nsevf_net_dim(q_vector);

		nsevf_update_enable_itr(vsi, q_vector);

	} else {
		q_vector->dbg_stats.napi_poll_clean_done_keep_wb_on_itr_cnt++;

		q_vector->dbg_stats.napi_poll_last_ret_event =
			4; /* clean_complete, set_wb_on_itr() */

		nsevf_enable_wb_on_itr(vsi, q_vector);
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * nsevf_tso - computes mss and TSO length to prepare for TSO
 * @tx_ring: Tx ring used for the packet
 * @first: pointer to struct nsevf_tx_buf
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if TSO can't happen, 1 otherwise.
 */
static int nsevf_tso(struct nsevf_ring *tx_ring, struct nsevf_tx_buffer *first,
		     struct nse_tx_offload_params *off)
{
	struct sk_buff *skb = first->skb;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	u64 cd_mss, td_tlen_tso;
	u32 paylen;
	u8 l4_start;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	tx_ring->tx_stats.tx_tso++;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize outer IP header fields */
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

			/* determine offset of outer transport header */
			l4_start = (u8)(l4.hdr - skb->data);

			/* remove payload length from outer checksum */
			paylen = skb->len - l4_start;
			csum_replace_by_diff(&l4.udp->check,
					     (__force __wsum)htonl(paylen));
		}

		/* reset pointers to inner headers */

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		/* initialize inner IP header fields */
		if (ip.v4->version == 4) {
			ip.v4->tot_len = 0;
			ip.v4->check = 0;
		} else {
			ip.v6->payload_len = 0;
		}

		tx_ring->tx_stats.tx_tso_tnl++;

	} else {
		tx_ring->tx_stats.tx_tso_non_tnl++;
	}

	/* determine offset of transport header */
	l4_start = (u8)(l4.hdr - skb->data);

	/* remove payload length from checksum */
	paylen = skb->len - l4_start;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of UDP segmentation header */
		off->header_len = (u8)sizeof(l4.udp) + l4_start;
	} else {
		csum_replace_by_diff(&l4.tcp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of TCP segmentation header */
		off->header_len = (u8)((l4.tcp->doff * 4) + l4_start);
	}

	/* update gso_segs and bytecount */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * off->header_len;

	td_tlen_tso = skb->len - off->header_len;
	cd_mss = skb_shinfo(skb)->gso_size;

	/* record cdesc_qw1 with TSO parameters */
	off->cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
			NSE_TXD_CTX_TSO_M |
			((cd_mss << NSE_TXD_CTX_MSS_S) & NSE_TXD_CTX_MSS_M));

	off->td_tlen = td_tlen_tso;

	first->tx_flags |= NSEVF_TX_FLAGS_TSO;
	return 1;
}

/**
 * nsevf_tx_csum - Enable Tx checksum offloads
 * @tx_ring: Tx ring used for the packet
 * @first: pointer to the first descriptor
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if checksum offload can't happen, 1 otherwise.
 */
static int nsevf_tx_csum(struct nsevf_ring *tx_ring,
			 struct nsevf_tx_buffer *first,
			 struct nse_tx_offload_params *off)
{
	u64 l4_len = 0, l3_len = 0, l2_len = 0;
	struct sk_buff *skb = first->skb;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		unsigned char *hdr;
	} l4;
	__be16 frag_off, protocol;
	unsigned char *exthdr;
	u8 l4_proto = 0;
	/* modify these local var, and set to 'off' at the end */
	u64 td_cmd_type_offset_bsz = off->td_cmd_type_offset_bsz;
	u32 cd_tunneling_params = off->cd_tunneling_params;
	u64 cd_qw1 = off->cd_qw1;
	u32 tx_flags = first->tx_flags;
	int func_ret;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* compute outer L2 header size */
	l2_len = (u64)(ip.hdr - skb->data);
	td_cmd_type_offset_bsz |=
		(((l2_len >> 1) << NSE_TXD_MACLEN_S) & NSE_TXD_MACLEN_M);

	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP))
		tx_flags |= NSEVF_TX_FLAGS_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		tx_flags |= NSEVF_TX_FLAGS_IPV6;

	if (skb->encapsulation) {
		bool gso_partial_ena = false;

		/* define outer network header type */
		if (tx_flags & NSEVF_TX_FLAGS_IPV4) {
			/* EIPT is first in tunneling_params, so no shift is needed. */
			cd_tunneling_params |=
				(tx_flags & NSEVF_TX_FLAGS_TSO) ?
					(NSE_TXD_CTX_EIPT_IPV4_CSUM
					 << NSE_TXD_CTX_EIPT_S) :
					(NSE_TXD_CTX_EIPT_IPV4_NO_CSUM
					 << NSE_TXD_CTX_EIPT_S);
			l4_proto = ip.v4->protocol;

		} else if (tx_flags & NSEVF_TX_FLAGS_IPV6) {
			cd_tunneling_params |=
				(NSE_TXD_CTX_EIPT_IPV6 << NSE_TXD_CTX_EIPT_S);

			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			func_ret = ipv6_skip_exthdr(skb, exthdr - skb->data,
						    &l4_proto, &frag_off);
			if (func_ret < 0)
				return -1;
		}

		/* define outer transport */
		switch (l4_proto) {
		case IPPROTO_UDP:
			cd_tunneling_params |= (NSE_TXD_CTX_L4TUNT_UDP
						<< NSE_TXD_CTX_L4TUNT_S);
			tx_flags |= NSEVF_TX_FLAGS_TUNNEL;
			break;
		case IPPROTO_GRE:
			cd_tunneling_params |= (NSE_TXD_CTX_L4TUNT_GRE
						<< NSE_TXD_CTX_L4TUNT_S);
			tx_flags |= NSEVF_TX_FLAGS_TUNNEL;
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			tx_flags |= NSEVF_TX_FLAGS_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
		default:
			if (tx_flags & NSEVF_TX_FLAGS_TSO)
				return -1;

			skb_checksum_help(skb);
			return 0;
		}

		/* compute outer L3 header size */
		cd_tunneling_params |=
			((((l4.hdr - ip.hdr) >> 2) << NSE_TXD_CTX_EIPLEN_S) &
			 NSE_TXD_CTX_EIPLEN_M);

		/* switch IP header pointer from outer to inner header */
		ip.hdr = skb_inner_network_header(skb);

		/* compute tunnel header size */
		cd_tunneling_params |=
			((((ip.hdr - l4.hdr) >> 1) << NSE_TXD_CTX_L4TUNLEN_S) &
			 NSE_TXD_CTX_L4TUNLEN_M);

		gso_partial_ena = skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL;

		/* indicate if we need to offload outer UDP header */
		if ((tx_flags & NSEVF_TX_FLAGS_TSO) && !gso_partial_ena &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM))
			cd_tunneling_params |= NSE_TXD_CTX_L4T_CS_M;

		/* set DTYP=1 to indicate that it's an Tx context descriptor
		 * in IPsec tunnel mode with Tx offloads in Quad word 1
		 */
		cd_qw1 |= (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S);

		/* switch L4 header pointer from outer to inner */
		l4.hdr = skb_inner_transport_header(skb);
		l4_proto = 0;

		/* reset type as we transition from outer to inner headers */
		tx_flags &= ~(NSEVF_TX_FLAGS_IPV4 | NSEVF_TX_FLAGS_IPV6);
		if (ip.v4->version == 4)
			tx_flags |= NSEVF_TX_FLAGS_IPV4;
		if (ip.v6->version == 6)
			tx_flags |= NSEVF_TX_FLAGS_IPV6;
	}

	/* Enable IP checksum offloads */
	if (tx_flags & NSEVF_TX_FLAGS_IPV4) {
		l4_proto = ip.v4->protocol;
		/* the stack computes the IP header already, the only time we
		 * need the hardware to recompute it is in the case of TSO.
		 */

		if (tx_flags & NSEVF_TX_FLAGS_TSO)
			td_cmd_type_offset_bsz |=
				(NSE_TXD_IIPT_IPV4_CSUM << NSE_TXD_IIPT_S);
		else
			td_cmd_type_offset_bsz |=
				(NSE_TXD_IIPT_IPV4_NO_CSUM << NSE_TXD_IIPT_S);

	} else if (tx_flags & NSEVF_TX_FLAGS_IPV6) {
		td_cmd_type_offset_bsz |= (NSE_TXD_IIPT_IPV6 << NSE_TXD_IIPT_S);

		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr) {
			func_ret = ipv6_skip_exthdr(skb, exthdr - skb->data,
						    &l4_proto, &frag_off);
			if (func_ret < 0)
				return -1;
		}

	} else {
		return -1;
	}

	/* compute inner L3 header size */
	l3_len = l4.hdr - ip.hdr;
	td_cmd_type_offset_bsz |=
		(((l3_len >> 2) << NSE_TXD_IPLEN_S) & NSE_TXD_IPLEN_M);

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* enable checksum offloads */
		td_cmd_type_offset_bsz |=
			(NSE_TXD_L4TYPE_TCP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = l4.tcp->doff;
		td_cmd_type_offset_bsz |=
			((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

		break;

	case IPPROTO_UDP:
		/* enable UDP checksum offload */
		td_cmd_type_offset_bsz |=
			(NSE_TXD_L4TYPE_UDP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = (sizeof(struct udphdr) >> 2);
		td_cmd_type_offset_bsz |=
			((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

		break;

	case IPPROTO_SCTP:
		/* enable SCTP checksum offload */
		td_cmd_type_offset_bsz |=
			(NSE_TXD_L4TYPE_SCTP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = sizeof(struct sctphdr) >> 2;
		td_cmd_type_offset_bsz |=
			((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

		break;

	default:
		if (tx_flags & NSEVF_TX_FLAGS_TSO)
			return -1;

		skb_checksum_help(skb);
		return 0;
	}

	if (!(tx_flags & NSEVF_TX_FLAGS_TSO)) {
		tx_flags |= NSEVF_TX_FLAGS_TCSUM;

		tx_ring->tx_stats.tx_tcsum++;
		if (tx_flags & NSEVF_TX_FLAGS_TUNNEL)
			tx_ring->tx_stats.tx_tcsum_tnl++;
		else
			tx_ring->tx_stats.tx_tcsum_non_tnl++;
	}

	off->td_cmd_type_offset_bsz = td_cmd_type_offset_bsz;
	off->cd_tunneling_params = cd_tunneling_params;
	off->cd_qw1 = cd_qw1;
	first->tx_flags = tx_flags;

	return 1;
}

/**
 * nsevf_create_tx_ctx - Build the Tx context descriptor
 * @tx_ring:  ring to create the descriptor on
 * @offload: offload parameters used to build the context descriptor
 **/
static void nsevf_create_tx_ctx(struct nsevf_ring *tx_ring,
				struct nse_tx_offload_params *offload)
{
	struct nse_tx_ctx_desc *cdesc;
	u16 i = tx_ring->next_to_use;

	if (offload->cd_qw1 & (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S)) {
		/* grab the next descriptor */
		cdesc = NSEVF_TX_CTXTDESC(tx_ring, i);

		i++;
		tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

		/* setup context descriptor */
		cdesc->tunneling_params =
			cpu_to_le32(offload->cd_tunneling_params);
		cdesc->l2tag2 = cpu_to_le16(offload->cd_l2tag2);
		cdesc->control = cpu_to_le16(offload->cd_control);
		cdesc->qw1 = cpu_to_le64(offload->cd_qw1);

		tx_ring->tx_stats.tx_use_ctx_desc++;

	} else {
		tx_ring->tx_stats.tx_not_use_ctx_desc++;
	}
}

/**
 * __nsevf_chk_linearize - Check if there are more than 8 buffers per packet
 * @skb:      send buffer
 *
 * Note: Our HW can't DMA more than 8 buffers to build a packet on the wire
 * and so we need to figure out the cases where we need to linearize the skb.
 *
 * For TSO we need to count the TSO header and segment payload separately.
 * As such we need to check cases where we have 7 fragments or more as we
 * can potentially require 9 DMA transactions, 1 for the TSO header, 1 for
 * the segment payload in the first descriptor, and another 7 for the
 * fragments.
 **/
bool __nsevf_chk_linearize(struct sk_buff *skb)
{
	const skb_frag_t *frag, *stale;
	int nr_frags, sum;

	/* no need to check if number of frags is less than 7 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (NSEVF_MAX_BUFFER_TXD - 1))
		return false;

	/* We need to walk through the list and validate that each group
	 * of 6 fragments totals at least gso_size.
	 */
	nr_frags -= NSEVF_MAX_BUFFER_TXD - 2;
	frag = &skb_shinfo(skb)->frags[0];

	/* Initialize size to the negative value of gso_size minus 1.  We
	 * use this as the worst case scenerio in which the frag ahead
	 * of us only provides one byte which is why we are limited to 6
	 * descriptors for a single transmit as the header and previous
	 * fragment are already consuming 2 descriptors.
	 */
	sum = 1 - skb_shinfo(skb)->gso_size;

	/* Add size of frags 0 through 4 to create our initial sum */
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);

	/* Walk through fragments adding latest fragment, testing it, and
	 * then removing stale fragments from the sum.
	 */
	for (stale = &skb_shinfo(skb)->frags[0];; stale++) {
		int stale_size = skb_frag_size(stale);

		sum += skb_frag_size(frag++);

		/* The stale fragment may present us with a smaller
		 * descriptor than the actual fragment size. To account
		 * for that we need to remove all the data on the front and
		 * figure out what the remainder would be in the last
		 * descriptor associated with the fragment.
		 */
		if (stale_size > NSEVF_MAX_DATA_PER_TXD) {
			int align_pad = -(skb_frag_off(stale)) &
					(NSEVF_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= NSEVF_MAX_DATA_PER_TXD_ALIGNED;
				stale_size -= NSEVF_MAX_DATA_PER_TXD_ALIGNED;
			} while (stale_size > NSEVF_MAX_DATA_PER_TXD);
		}

		/* if sum is negative we failed to make sufficient progress */
		if (sum < 0)
			return true;

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	return false;
}

/**
 * nsevf_tx_prepare_vlan_flags - prepare generic TX VLAN tagging flags for HW
 * @skb:     send buffer
 * @tx_ring: ring to send buffer on
 * @first: first Tx buffer whose flags are prepared
 *
 * Checks the skb and set up correspondingly several generic transmit flags
 * related to VLAN tagging for the HW, such as VLAN, DCB, etc.
 *
 * Returns error code indicate the frame should be dropped upon error and the
 * otherwise  returns 0 to indicate the flags has been set properly.
 **/
static void nsevf_tx_prepare_vlan_flags(struct sk_buff *skb,
					struct nsevf_ring *tx_ring,
					struct nsevf_tx_buffer *first)
{
	u32 tx_flags = 0;

	/* stack will only request hardware VLAN insertion offload for protocols
	 * that the driver supports and has enabled
	 */
	if (!skb_vlan_tag_present(skb))
		return;

	tx_flags |= skb_vlan_tag_get(skb) << NSEVF_TX_FLAGS_VLAN_SHIFT;
	if (tx_ring->flags & NSEVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2) {
		tx_flags |= NSEVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN;
	} else if (tx_ring->flags & NSEVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1) {
		tx_flags |= NSEVF_TX_FLAGS_HW_VLAN;
	} else {
		dev_dbg(tx_ring->dev,
			"Unsupported Tx VLAN tag location requested\n");
		return;
	}

	first->tx_flags = tx_flags;
}

/**
 * __nsevf_maybe_stop_tx - 2nd level check for tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 **/
int __nsevf_maybe_stop_tx(struct nsevf_ring *tx_ring, int size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);
	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(NSEVF_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);
	++tx_ring->tx_stats.restart_queue;
	return 0;
}

/**
 * nsevf_tx_map - Build the Tx descriptor
 * @tx_ring: ring to send buffer on
 * @first: first buffer info buffer to use
 * @off: pointer to struct that holds offload parameters
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit descriptor.
 */
static void nsevf_tx_map(struct nsevf_ring *tx_ring,
			 struct nsevf_tx_buffer *first,
			 struct nse_tx_offload_params *off)
{
	bool first_td = true;
	u64 td_cmd_type_offset_bsz, td_tlen;
	u16 i = tx_ring->next_to_use;
	u16 tx_rs_ntu = tx_ring->tx_rs_ntu;
	u16 tx_rs = 0;
	bool record_tx_rs = false;
	unsigned int data_len, size;
	struct nsevf_tx_desc *tx_desc;
	struct nsevf_tx_buffer *tx_buf;
	struct sk_buff *skb = first->skb;
	skb_frag_t *frag;
	dma_addr_t dma;

	if (!(off->td_cmd_type_offset_bsz & NSE_TXD_MACLEN_M)) {
		/* MAC_LEN unset, set it.... */
		u64 mac_len = (u64)skb_network_offset(skb);

		off->td_cmd_type_offset_bsz |=
			(((mac_len >> 1) << NSE_TXD_MACLEN_S) &
			 NSE_TXD_MACLEN_M);
	}

	if (off->cd_qw1 & (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S))
		off->td_cmd_type_offset_bsz |= NSE_TXD_CC_M;

	td_cmd_type_offset_bsz = off->td_cmd_type_offset_bsz;
	td_tlen = off->td_tlen;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = NSEVF_TX_DESC(tx_ring, i);

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = NSEVF_MAX_DATA_PER_TXD_ALIGNED;

		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (NSEVF_MAX_READ_REQ_SIZE - 1);
		tx_desc->buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		while (unlikely(size > NSEVF_MAX_DATA_PER_TXD)) {
			tx_desc->cmd_type_offset_bsz =
				nse_build_ctob(td_cmd_type_offset_bsz, td_tlen,
					       max_data, first_td);

			first_td = false;

			tx_desc++;
			i++;

			if (i == tx_ring->count) {
				tx_desc = NSEVF_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = NSEVF_MAX_DATA_PER_TXD_ALIGNED;
			tx_desc->buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->cmd_type_offset_bsz =
			nse_build_ctob(td_cmd_type_offset_bsz, td_tlen, size,
				       first_td);

		first_td = false;

		tx_desc++;
		i++;

		if (i == tx_ring->count) {
			tx_desc = NSEVF_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buf = &tx_ring->tx_bi[i];
	}

	if (!nse_lan_tx_no_bql)
		netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(first->skb);

	/* write last descriptor with RS and EOP bits */
	td_cmd_type_offset_bsz |= (u64)NSE_TXD_EOP_M;

	if (nsevf_lan_tx_rs_optimize) {
		if (!netdev_xmit_more() ||
		    (NSEVF_DESC_UNUSED(tx_ring) <= (tx_ring->count >> 1))) {
			td_cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;

			record_tx_rs = true;
			tx_rs = i;
		}
	} else {
		td_cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;
	}

	tx_desc->cmd_type_offset_bsz =
		nse_build_ctob(td_cmd_type_offset_bsz, td_tlen, size, first_td);

	if (td_cmd_type_offset_bsz & (u64)NSE_TXD_RS_M)
		tx_ring->tx_stats.tx_rs++;
	else
		tx_ring->tx_stats.tx_no_rs++;

	i++;
	if (i == tx_ring->count)
		i = 0;

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.
	 *
	 * We also use this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	tx_ring->next_to_use = i;

	if (nsevf_lan_tx_rs_optimize && record_tx_rs) {
		tx_ring->tx_rs_array[tx_rs_ntu] = tx_rs;

		tx_rs_ntu++;
		if (tx_rs_ntu == tx_ring->count)
			tx_rs_ntu = 0;

		tx_ring->tx_rs_ntu = tx_rs_ntu;
	}

	nsevf_maybe_stop_tx(tx_ring, DESC_NEEDED);

	/* don't actually write HW doorbell when happen in reset */
	if (nsevf_is_reset_in_progress(tx_ring->adapter))
		return;

	wmb(); /* memory barrier before kick TAIL doorbell */

	/* notify HW of packet */
	if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more())
		writel(i, tx_ring->tail);

	return;

dma_error:
	dev_info(tx_ring->dev, "TX DMA map failed\n");

	/* clear DMA mappings for failed tx_buf map */
	for (;;) {
		tx_buf = &tx_ring->tx_bi[i];
		nsevf_unmap_and_free_tx_resource(tx_ring, tx_buf);
		if (tx_buf == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
}

/**
 * nsevf_xmit_frame_ring - Sends buffer on Tx ring
 * @skb:     send buffer
 * @tx_ring: ring to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 **/
static netdev_tx_t nsevf_xmit_frame_ring(struct sk_buff *skb,
					 struct nsevf_ring *tx_ring)
{
	struct nse_tx_offload_params offload = { 0 };
	struct nsevf_tx_buffer *first;
	unsigned int count;
	int tso, csum;

	/* prefetch the data, we'll need it later */
	prefetch(skb->data);

	nsevf_trace(xmit_frame_ring, skb, tx_ring);

	count = nsevf_xmit_descriptor_count(skb);
	if (nsevf_chk_linearize(skb, count)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		count = nsevf_txd_use_count(skb->len);
		tx_ring->tx_stats.tx_linearize++;
	}

	/* need: 1 descriptor per page * PAGE_SIZE/NSEVF_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_head_len/NSEVF_MAX_DATA_PER_TXD,
	 *       + 4 desc gap to avoid the cache line where head is,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	if (nsevf_maybe_stop_tx(tx_ring, count + 4 + 1)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	offload.tx_ring = tx_ring;

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_bi[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;
	first->tx_flags = 0;

	/* prepare the xmit flags */
	nsevf_tx_prepare_vlan_flags(skb, tx_ring, first);
	if (first->tx_flags & NSEVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN) {
		offload.cd_qw1 |=
			(NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S);
		offload.cd_qw1 |= NSE_TXD_CTX_IL2TAG2_M;

		offload.cd_l2tag2 =
			(first->tx_flags & NSEVF_TX_FLAGS_VLAN_MASK) >>
			NSEVF_TX_FLAGS_VLAN_SHIFT;

		tx_ring->tx_stats.tx_tvlan++;
	} else if (first->tx_flags & NSEVF_TX_FLAGS_HW_VLAN) {
		u64 cd_l2tag1 = (first->tx_flags & NSEVF_TX_FLAGS_VLAN_MASK) >>
				NSEVF_TX_FLAGS_VLAN_SHIFT;

		offload.cd_qw1 |=
			(NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S);
		offload.cd_qw1 |= NSE_TXD_CTX_IL2TAG1_M;

		offload.cd_qw1 |= (cd_l2tag1 << NSE_TXD_CTX_L2TAG1_S) &
				  NSE_TXD_CTX_L2TAG1_M;

		tx_ring->tx_stats.tx_tvlan++;
	}

	offload.td_tlen = skb->len;

	/* set up TSO offload */
	tso = nsevf_tso(tx_ring, first, &offload);
	if (tso < 0)
		goto out_drop;

	/* Always offload the checksum, since it's in the data descriptor */
	csum = nsevf_tx_csum(tx_ring, first, &offload);
	if (csum < 0)
		goto out_drop;

	nsevf_create_tx_ctx(tx_ring, &offload);

	if (first->tx_flags &
	    (NSEVF_TX_FLAGS_TSO | NSEVF_TX_FLAGS_TCSUM | NSEVF_TX_FLAGS_TSYN |
	     NSEVF_TX_FLAGS_HW_VLAN | NSEVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN))
		tx_ring->tx_stats.tx_offload++;
	else
		tx_ring->tx_stats.tx_non_offload++;

	nsevf_tx_map(tx_ring, first, &offload);

	return NETDEV_TX_OK;

out_drop:
	nsevf_trace(xmit_frame_ring_drop, first->skb, tx_ring);
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	return NETDEV_TX_OK;
}

/**
 * nsevf_xmit_frame - Selects the correct VSI and Tx queue to send buffer
 * @skb:    send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 **/
netdev_tx_t nsevf_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct nsevf_adapter *adapter = netdev_priv(netdev);
	struct nsevf_ring *tx_ring = &adapter->tx_rings[skb->queue_mapping];

	if (adapter->debug_lan_no_xmit) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (nsevf_is_reset_in_progress(adapter)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, NSEVF_MIN_TX_LEN))
		return NETDEV_TX_OK;

	return nsevf_xmit_frame_ring(skb, tx_ring);
}

void nse_dump_rx_desc(struct device *dev, u16 q_idx, u16 desc_idx,
		      union nse_32b_rx_desc *rx_desc)
{
	u16 val;
	u32 *raw_val32_ptr;
	int i;

	if (q_idx != NSEVF_INVAL_Q_INDEX && desc_idx < NSEVF_MAX_RXD)
		dev_info(dev, "------ rx_desc[q_idx=%d][desc_idx=%d]\n", q_idx,
			 desc_idx);
	else if (q_idx != NSEVF_INVAL_Q_INDEX)
		dev_info(dev, "------ rx_desc[q_idx=%d][desc_idx=N]\n", q_idx);
	else if (desc_idx < NSEVF_MAX_RXD)
		dev_info(dev, "------ rx_desc[q_idx=N][desc_idx=%d]\n",
			 desc_idx);
	else
		dev_info(dev, "------ rx_desc\n");

	dev_info(dev, "raw content:\n");
	raw_val32_ptr = (u32 *)rx_desc;
	for (i = 0; i < (sizeof(*rx_desc) / sizeof(u32)); i++) {
		dev_info(dev, "\t %08X\n", *raw_val32_ptr);
		raw_val32_ptr++;
	}

	if (!(rx_desc->wb.status_error0 & cpu_to_le16(NSE_RXD_STATUS0_DD_M))) {
		dev_info(dev, "DD = false\n");
		dev_info(dev, "pkt_addr = %lX\n",
			 (unsigned long)le64_to_cpu(rx_desc->read.pkt_addr));
	} else {
		dev_info(dev, "DD = true\n");

		dev_info(dev, "rxdid = %X\n", rx_desc->wb.rxdid);

		dev_info(dev, "qsrc_sport_md01valid = %X\n",
			 rx_desc->wb.qsrc_sport_md01valid);
		dev_info(dev, "\t qsrc = %X\n",
			 (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_QSRC_M));
		dev_info(dev, "\t sport = %X\n",
			 (rx_desc->wb.qsrc_sport_md01valid & NSE_RXD_SPORT_M) >>
				 NSE_RXD_SPORT_S);
		dev_info(dev, "\t md0_valid = %X\n",
			 !!(rx_desc->wb.qsrc_sport_md01valid &
			    NSE_RXD_MD0_VALID_M));
		dev_info(dev, "\t md0_valid = %X\n",
			 !!(rx_desc->wb.qsrc_sport_md01valid &
			    NSE_RXD_MD1_VALID_M));

		dev_info(dev, "l2tag1_nextp = %X\n",
			 le16_to_cpu(rx_desc->wb.l2tag1_nextp));

		dev_info(dev, "md0 = %X\n", le16_to_cpu(rx_desc->wb.md0));

		dev_info(dev, "md1 = %X\n", le16_to_cpu(rx_desc->wb.md1));

		val = le16_to_cpu(rx_desc->wb.status_error0);
		dev_info(dev, "status_error0 = %X\n", val);
		dev_info(dev, "\t DD = %X\n", !!(val & NSE_RXD_STATUS0_DD_M));
		dev_info(dev, "\t EOP = %X\n", !!(val & NSE_RXD_STATUS0_EOP_M));
		dev_info(dev, "\t HBO = %X\n", !!(val & NSE_RXD_STATUS0_HBO_M));
		dev_info(dev, "\t EIPV6EX = %X\n",
			 !!(val & NSE_RXD_STATUS0_EIPV6EX_M));
		dev_info(dev, "\t XSUM_IPE = %X\n",
			 !!(val & NSE_RXD_STATUS0_XSUM_IPE_M));
		dev_info(dev, "\t XSUM_L4E = %X\n",
			 !!(val & NSE_RXD_STATUS0_XSUM_L4E_M));
		dev_info(dev, "\t XSUM_EIPE = %X\n",
			 !!(val & NSE_RXD_STATUS0_XSUM_EIPE_M));
		dev_info(dev, "\t XSUM_EUDPE = %X\n",
			 !!(val & NSE_RXD_STATUS0_XSUM_EUDPE_M));
		dev_info(dev, "\t MIRR = %X\n",
			 !!(val & NSE_RXD_STATUS0_MIRR_M));
		dev_info(dev, "\t IPV6EXADD = %X\n",
			 !!(val & NSE_RXD_STATUS0_IPV6EXADD_M));
		dev_info(dev, "\t RXE = %X\n", !!(val & NSE_RXD_STATUS0_RXE_M));
		dev_info(dev, "\t CRCP = %X\n",
			 !!(val & NSE_RXD_STATUS0_CRCP_M));
		dev_info(dev, "\t PTP = %X\n", !!(val & NSE_RXD_STATUS0_PTP_M));
		dev_info(dev, "\t L2TAG1P = %X\n",
			 !!(val & NSE_RXD_STATUS0_L2TAG1P_M));
		dev_info(dev, "\t EXT_UDP_0 = %X\n",
			 !!(val & NSE_RXD_STATUS0_EXT_UDP_0_M));
		dev_info(dev, "\t INT_UDP_0 = %X\n",
			 !!(val & NSE_RXD_STATUS0_INT_UDP_0_M));

		dev_info(dev, "ptype = %X\n", rx_desc->wb.ptype);

		dev_info(dev, "misc = %X\n", rx_desc->wb.misc);

		val = le16_to_cpu(rx_desc->wb.pktlen_sph_reentry);
		dev_info(dev, "pktlen_sph_reentry = %X\n", val);
		dev_info(dev, "\t pktlen = %X(%d)\n", (val & NSE_RXD_PKT_LEN_M),
			 (val & NSE_RXD_PKT_LEN_M));
		dev_info(dev, "\t sph = %X\n", !!(val & NSE_RXD_SPH_M));
		dev_info(dev, "\t reentry = %X\n", !!(val & NSE_RXD_REENTRY_M));

		val = le16_to_cpu(rx_desc->wb.hdrlen_rsccnt);
		dev_info(dev, "hdrlen_rsccnt = %X\n", val);
		dev_info(dev, "\t hdrlen = %X(%d)\n", (val & NSE_RXD_HDR_LEN_M),
			 (val & NSE_RXD_HDR_LEN_M));
		dev_info(dev, "\t rsccnt = %X(%d)\n",
			 (val & NSE_RXD_RSCCNT_M) >> NSE_RXD_RSCCNT_S,
			 (val & NSE_RXD_RSCCNT_M) >> NSE_RXD_RSCCNT_S);

		dev_info(dev, "status_error1 = %X\n",
			 rx_desc->wb.status_error1);
		dev_info(dev, "\t V6M = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_V6M_M));
		dev_info(dev, "\t TLS = %X\n",
			 !!(rx_desc->wb.status_error1 & NSE_RXD_STATUS1_TLS_M));
		dev_info(dev, "\t L2TAG2P = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_L2TAG2P_M));
		dev_info(dev, "\t MD2_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_MD2_VALID_M));
		dev_info(dev, "\t MD3_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_MD3_VALID_M));
		dev_info(dev, "\t MD4_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_MD4_VALID_M));
		dev_info(dev, "\t MD5_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_MD5_VALID_M));
		dev_info(dev, "\t MD6_VALID = %X\n",
			 !!(rx_desc->wb.status_error1 &
			    NSE_RXD_STATUS1_MD6_VALID_M));

		dev_info(dev, "ts_low = %X\n", rx_desc->wb.ts_low);

		dev_info(dev, "md6 = %X\n", le16_to_cpu(rx_desc->wb.md6));

		dev_info(dev, "l2tag2_1st = %X\n",
			 le16_to_cpu(rx_desc->wb.l2tag2_1st));

		dev_info(dev, "l2tag2_2nd = %X\n",
			 le16_to_cpu(rx_desc->wb.l2tag2_2nd));

		dev_info(dev, "md2 = %X\n", le16_to_cpu(rx_desc->wb.md2));

		dev_info(dev, "md3 = %X\n", le16_to_cpu(rx_desc->wb.md3));

		dev_info(dev, "md4 = %X\n", le16_to_cpu(rx_desc->wb.md4));

		dev_info(dev, "md5 = %X\n", le16_to_cpu(rx_desc->wb.md5));
	}
}

void nse_dump_tx_desc(struct device *dev, u16 q_idx, u16 desc_idx,
		      struct nse_tx_desc *tx_desc)
{
	struct nse_tx_ctx_desc *cd = NULL;
	u16 val16;
	u32 val32;
	u64 val64;
	u32 *raw_val32_ptr;
	int i;
	char *desc_type = NULL;

	if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DD_M)) {
		desc_type = "WRITE-BACK";
	} else if (tx_desc->cmd_type_offset_bsz &
		   cpu_to_le64(NSE_TXD_DTYPE_M)) {
		desc_type = "tx-context-desc";
	} else {
		desc_type = "tx-data-desc";
	}

	if (q_idx != NSEVF_INVAL_Q_INDEX && desc_idx < NSEVF_MAX_TXD)
		dev_info(dev, "------ tx_desc[q_idx=%d][desc_idx=%d]: %s\n",
			 q_idx, desc_idx, desc_type);
	else if (q_idx != NSEVF_INVAL_Q_INDEX)
		dev_info(dev, "------ tx_desc[q_idx=%d][desc_idx=N]: %s\n",
			 q_idx, desc_type);
	else if (desc_idx < NSEVF_MAX_TXD)
		dev_info(dev, "------ tx_desc[q_idx=N][desc_idx=%d]: %s\n",
			 desc_idx, desc_type);
	else
		dev_info(dev, "------ tx_desc: %s\n", desc_type);

	dev_info(dev, "raw content:\n");
	raw_val32_ptr = (u32 *)tx_desc;
	for (i = 0; i < (sizeof(*tx_desc) / sizeof(u32)); i++) {
		dev_info(dev, "\t %08X\n", *raw_val32_ptr);
		raw_val32_ptr++;
	}

	if (tx_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DD_M)) {
		dev_info(dev, "DD = true\n");

		dev_info(dev, "buf_addr = %lX\n",
			 (unsigned long)le64_to_cpu(tx_desc->buf_addr));
		dev_info(dev, "cmd_type_offset_bsz = %lX\n",
			 (unsigned long)le64_to_cpu(tx_desc->cmd_type_offset_bsz));
	} else {
		dev_info(dev, "DD = false\n");

		if (tx_desc->cmd_type_offset_bsz &
		    cpu_to_le64(NSE_TXD_DTYPE_M)) {
			cd = (struct nse_tx_ctx_desc *)tx_desc;

			val32 = le32_to_cpu(cd->tunneling_params);
			dev_info(dev, "tunneling_params = %X\n", val32);
			dev_info(dev, "\t EIPT: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_EIPT_M) >>
						NSE_TXD_CTX_EIPT_S));
			dev_info(dev, "\t EIPLEN: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_EIPLEN_M) >>
					       NSE_TXD_CTX_EIPLEN_S));
			dev_info(dev, "\t L4TUNT: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_L4TUNT_M) >>
					       NSE_TXD_CTX_L4TUNT_S));
			dev_info(dev, "\t L4TUNLEN: %X\n",
				 (unsigned int)((val32 &
						 NSE_TXD_CTX_L4TUNLEN_M) >>
						NSE_TXD_CTX_L4TUNLEN_S));
			dev_info(dev, "\t DECTTL: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_DECTTL_M) >>
					       NSE_TXD_CTX_DECTTL_S));
			dev_info(dev, "\t L4T_CS: %X\n",
				 (unsigned int)((val32 & NSE_TXD_CTX_L4T_CS_M) >>
					       NSE_TXD_CTX_L4T_CS_S));

			dev_info(dev, "l2tag2 = %X\n", le16_to_cpu(cd->l2tag2));

			val16 = le16_to_cpu(cd->control);
			dev_info(dev, "control = %X\n", val16);
			dev_info(dev, "\t TSEC: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TSEC_M) >>
						NSE_TXD_CTX_TSEC_S));
			dev_info(dev, "\t PORTID: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_PORTID_M) >>
					       NSE_TXD_CTX_PORTID_S));
			dev_info(dev, "\t CRCP: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_CRCP_M) >>
						NSE_TXD_CTX_CRCP_S));
			dev_info(dev, "\t TLS: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TLS_M) >>
						NSE_TXD_CTX_TLS_S));
			dev_info(dev, "\t TX_MD: %X\n",
				 (unsigned int)((val16 & NSE_TXD_CTX_TX_MD_M) >>
						NSE_TXD_CTX_TX_MD_S));
			dev_info(dev, "\t TSYN_REG: %X\n",
				 (unsigned int)((val16 &
						 NSE_TXD_CTX_TSYN_REG_M) >>
						NSE_TXD_CTX_TSYN_REG_S));

			val64 = le64_to_cpu(cd->qw1);
			dev_info(dev, "qw1 = %lX\n", (unsigned long)val64);
			dev_info(dev, "\t PORT_VLD: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXQ_CTX_PORT_VLD_M) >>
						NSE_TXQ_CTX_PORT_VLD_S));
			dev_info(dev, "\t PORT_LOCK: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXQ_CTX_PORT_LOCK_M) >>
						NSE_TXQ_CTX_PORT_LOCK_S));
			dev_info(dev, "\t TSO: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_TSO_M) >>
						NSE_TXD_CTX_TSO_S));
			dev_info(dev, "\t TSYN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_TSYN_M) >>
						NSE_TXD_CTX_TSYN_S));
			dev_info(dev, "\t IL2TAG2: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXD_CTX_IL2TAG2_M) >>
						NSE_TXD_CTX_IL2TAG2_S));
			dev_info(dev, "\t IL2TAG_IL2H: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXD_CTX_IL2TAG_IL2H_M) >>
						NSE_TXD_CTX_IL2TAG_IL2H_S));
			dev_info(dev, "\t SWITCH: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_SWITCH_M) >>
					       NSE_TXD_CTX_SWITCH_S));
			dev_info(dev, "\t DEST_QUEUE_VLD: %X\n",
				 (unsigned int)((val64 &
						NSE_TXD_CTX_DEST_QUEUE_VLD_M) >>
					       NSE_TXD_CTX_DEST_QUEUE_VLD_S));
			dev_info(dev, "\t DEST_QUEUE: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXD_CTX_DEST_QUEUE_M) >>
						NSE_TXD_CTX_DEST_QUEUE_S));
			dev_info(dev, "\t DEST_VSI: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXD_CTX_DEST_VSI_M) >>
						NSE_TXD_CTX_DEST_VSI_S));
			dev_info(dev, "\t L2TAG1: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_L2TAG1_M) >>
					       NSE_TXD_CTX_L2TAG1_S));
			dev_info(dev, "\t IL2TAG1: %X\n",
				 (unsigned int)((val64 &
						 NSE_TXD_CTX_IL2TAG1_M) >>
						NSE_TXD_CTX_IL2TAG1_S));
			dev_info(dev, "\t MSS: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CTX_MSS_M) >>
						NSE_TXD_CTX_MSS_S));
		} else {
			dev_info(dev, "type: tx-data-desc\n");

			dev_info(dev, "buf_addr = %lX\n",
				 (unsigned long)le64_to_cpu(tx_desc->buf_addr));

			val64 = le64_to_cpu(tx_desc->cmd_type_offset_bsz);
			dev_info(dev, "cmd_type_offset_bsz = %lX\n",
				 (unsigned long)val64);
			dev_info(dev, "\t L4TYPE: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4TYPE_M) >>
						NSE_TXD_L4TYPE_S));
			dev_info(dev, "\t IIPT: %X\n",
				 (unsigned int)((val64 & NSE_TXD_IIPT_M) >>
						NSE_TXD_IIPT_S));
			dev_info(dev, "\t L4LEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4LEN_M) >>
						NSE_TXD_L4LEN_S));
			dev_info(dev, "\t EOP: %X\n",
				 (unsigned int)((val64 & NSE_TXD_EOP_M) >>
						NSE_TXD_EOP_S));
			dev_info(dev, "\t RS: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RS_M) >>
						NSE_TXD_RS_S));
			dev_info(dev, "\t L4CSUM: %X\n",
				 (unsigned int)((val64 & NSE_TXD_L4CSUM_M) >>
						NSE_TXD_L4CSUM_S));
			dev_info(dev, "\t RSV_1: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RSV_1_M) >>
						NSE_TXD_RSV_1_S));
			dev_info(dev, "\t LOCAL_DATA: %X\n",
				 (unsigned int)((val64 & NSE_TXD_LOCAL_DATA_M) >>
					       NSE_TXD_LOCAL_DATA_S));
			dev_info(dev, "\t CC: %X\n",
				 (unsigned int)((val64 & NSE_TXD_CC_M) >>
						NSE_TXD_CC_S));
			dev_info(dev, "\t TLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_TLEN_M) >>
						NSE_TXD_TLEN_S));
			dev_info(dev, "\t MACLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_MACLEN_M) >>
						NSE_TXD_MACLEN_S));
			dev_info(dev, "\t IPLEN: %X\n",
				 (unsigned int)((val64 & NSE_TXD_IPLEN_M) >>
						NSE_TXD_IPLEN_S));
			dev_info(dev, "\t RSV_2: %X\n",
				 (unsigned int)((val64 & NSE_TXD_RSV_2_M) >>
						NSE_TXD_RSV_2_S));
			dev_info(dev, "\t BSIZE: %X\n",
				 (unsigned int)((val64 & NSE_TXD_BSIZE_M) >>
						NSE_TXD_BSIZE_S));
		}
	}
}

void nse_dump_lan_txcq_desc(struct device *dev, u16 q_idx, u32 desc_idx,
			    struct nse_lan_txcq_desc *desc)
{
	u32 val32 = le32_to_cpu(desc->data);

	if (q_idx != NSEVF_INVAL_Q_INDEX && desc_idx < NSE_DFLT_NUM_CQ_DESC)
		dev_info(dev, "------ cq_desc[q_idx=%d][desc_idx=%d]\n", q_idx,
			 desc_idx);
	else if (q_idx != NSEVF_INVAL_Q_INDEX)
		dev_info(dev, "------ cq_desc[q_idx=%d][desc_idx=N]\n", q_idx);
	else if (desc_idx < NSE_DFLT_NUM_CQ_DESC)
		dev_info(dev, "------ cq_desc[q_idx=N][desc_idx=%d]\n",
			 desc_idx);
	else
		dev_info(dev, "------ cq_desc\n");

	dev_info(dev, "raw content:\n");
	dev_info(dev, "\t %08X\n", val32);

	dev_info(dev, "TXQ_ID: %d\n",
		 (val32 & NSE_LAN_TXCQD_TXQ_ID_M) >> NSE_LAN_TXCQD_TXQ_ID_S);
	dev_info(dev, "GENERATION: %d\n",
		 (u32)((val32 & NSE_LAN_TXCQD_GENERATION_M) >>
		       NSE_LAN_TXCQD_GENERATION_S));
	dev_info(dev, "TX_HEAD: %d\n",
		 (val32 & NSE_LAN_TXCQD_TX_HEAD_M) >> NSE_LAN_TXCQD_TX_HEAD_S);
	dev_info(dev, "COMPLETION_TYPE: %d\n",
		 (val32 & NSE_LAN_TXCQD_COMPLETION_TYPE_M) >>
			 NSE_LAN_TXCQD_COMPLETION_TYPE_S);
}
