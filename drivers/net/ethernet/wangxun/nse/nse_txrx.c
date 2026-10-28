// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* The driver transmit and receive code */

#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/prefetch.h>
#include "nse_txrx_lib.h"
#include "nse_lib.h"
#include "nse.h"
#include "nse_dcb_lib.h"
#include "nse_irq.h"
#include <net/dsfield.h>
#include "nse_xsk.h"
#include <linux/bpf_trace.h>
#include <net/xdp.h>
#include "nse_eswitch.h"
#include <net/busy_poll.h>

#define NSE_RX_HDR_SIZE		256

/**
 * nse_unmap_and_free_tx_buf - Release a Tx buffer
 * @ring: the ring that owns the buffer
 * @tx_buf: the buffer to free
 */
static void
nse_unmap_and_free_tx_buf(struct nse_ring *ring, struct nse_tx_buf *tx_buf)
{
	if (tx_buf->skb) {
		if (nse_ring_is_xdp(ring))
			page_frag_free(tx_buf->raw_buf);
		else
			dev_kfree_skb_any(tx_buf->skb);

		if (dma_unmap_len(tx_buf, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len),
			       DMA_TO_DEVICE);
	}

	tx_buf->next_to_watch = NULL;
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
	/* tx_buf must be completely set up in the transmit path */
}

static struct netdev_queue *txring_txq(const struct nse_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->q_index);
}

/**
 * nse_clean_tx_ring - Free any empty Tx buffers
 * @tx_ring: ring to be cleaned
 */
void nse_clean_tx_ring(struct nse_ring *tx_ring)
{
	u16 i;

	if (nse_ring_is_xdp(tx_ring) && tx_ring->xsk_pool) {
		nse_xsk_clean_xdp_ring(tx_ring);
		goto tx_skip_free;
	}

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_buf)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++)
		nse_unmap_and_free_tx_buf(tx_ring, &tx_ring->tx_buf[i]);

tx_skip_free:

	memset(tx_ring->tx_buf, 0, sizeof(*tx_ring->tx_buf) * tx_ring->count);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	tx_ring->tx_rs_ntu = 0;
	tx_ring->tx_rs_ntc = 0;

#if defined(NSE_DEBUG_EXT)
	kfree(tx_ring->txr_used_records);

	tx_ring->txr_used_records = NULL;

	kfree(tx_ring->txr_clean_records);

	tx_ring->txr_clean_records = NULL;
#endif

	if (!tx_ring->netdev)
		return;

	/* cleanup Tx queue statistics */
	netdev_tx_reset_queue(txring_txq(tx_ring));
}

/**
 * nse_free_tx_ring - Free Tx resources per queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 */
void nse_free_tx_ring(struct nse_ring *tx_ring)
{
	nse_clean_tx_ring(tx_ring);

	if (tx_ring->tx_buf) {
		devm_kfree(tx_ring->dev, tx_ring->tx_buf);
		tx_ring->tx_buf = NULL;
	}

	if (tx_ring->desc) {
		dmam_free_coherent(tx_ring->dev, tx_ring->size,
				   tx_ring->desc, tx_ring->dma);
		tx_ring->desc = NULL;
	}

	if (tx_ring->tx_rs_array) {
		devm_kfree(tx_ring->dev, tx_ring->tx_rs_array);
		tx_ring->tx_rs_array = NULL;
	}
}

static bool nse_clean_tx_irq_pmd(struct nse_ring *tx_ring, int napi_budget)
{
	struct nse_vsi *vsi = NULL;
	s16 i;
	struct nse_tx_desc *tx_desc, *eop_desc;
	struct nse_tx_buf *tx_buf;
	unsigned int total_bytes = 0, total_pkts = 0;
	unsigned int budget = NSE_DFLT_IRQ_WORK;

	if (tx_ring == NULL)
		return true;

	vsi = tx_ring->vsi;
	i = tx_ring->next_to_clean;

	if (txring_txq(tx_ring))
		netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));
	else
		return true;

	if (tx_ring->tx_buf == NULL)
		return true;
	if (tx_ring->desc == NULL)
		return true;

	tx_buf = &tx_ring->tx_buf[i];
	tx_desc = NSE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	if ((vsi == NULL) || (tx_buf == NULL) || (tx_desc == NULL))
		return true;

	prefetch(&vsi->state);

	do {
		if ((vsi == NULL) || (tx_buf == NULL) || (tx_desc == NULL))
			break;

		eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb();	/* prevent any other reads prior to eop_desc */

		nse_trace(clean_tx_irq, tx_ring, tx_desc, tx_buf);
		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->cmd_type_offset_bsz &
		      cpu_to_le64(NSE_TXD_DD_M)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

		/* free the skb */
		if (tx_buf->skb == NULL)
			break;
		napi_consume_skb(tx_buf->skb, napi_budget);
//		consume_skb(tx_buf->skb);

		/* unmap skb header data */
		if (tx_ring->dev == NULL)
			break;
//#if 0
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len),
				 DMA_TO_DEVICE);
//#endif
		/* clear tx_buf data */
		tx_buf->skb = NULL;
		dma_unmap_len_set(tx_buf, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			nse_trace(clean_tx_irq_unmap, tx_ring, tx_desc, tx_buf);
			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_buf;
				tx_desc = NSE_TX_DESC(tx_ring, 0);
			}

			if ((vsi == NULL) || (tx_buf == NULL) || (tx_desc == NULL))
				break;
//#if 0
			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				if (tx_ring->dev == NULL)
					break;

				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
			}
//#endif
		}
		if ((vsi == NULL) || (tx_buf == NULL) || (tx_desc == NULL))
			break;

		nse_trace(clean_tx_irq_unmap_eop, tx_ring, tx_desc, tx_buf);

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_buf;
			tx_desc = NSE_TX_DESC(tx_ring, 0);
		}
		if ((vsi == NULL) || (tx_buf == NULL) || (tx_desc == NULL))
			break;

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;

	nse_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);

	return !!budget;
}

/**
 * nse_clean_tx_irq - Reclaim resources after transmit completes
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
bool nse_clean_tx_irq_legacy(struct nse_ring *tx_ring, int napi_budget)
{
	unsigned int total_bytes = 0, total_pkts = 0;
	unsigned int budget = NSE_DFLT_IRQ_WORK;
	struct nse_vsi *vsi = tx_ring->vsi;
	s16 i = tx_ring->next_to_clean;
	struct nse_tx_desc *tx_desc, *eop_desc;
	struct nse_tx_buf *tx_buf;
#if defined(NSE_DEBUG_EXT)
	u32 cleaned_desc_cnt = 0;
#endif

	/* get the bql data ready */
	if (!nse_ring_is_xdp(tx_ring))
		netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));

	tx_buf = &tx_ring->tx_buf[i];
	tx_desc = NSE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	prefetch(&vsi->state);

	do {
		eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb();	/* prevent any other reads prior to eop_desc */

		nse_trace(clean_tx_irq, tx_ring, tx_desc, tx_buf);
		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->cmd_type_offset_bsz &
		      cpu_to_le64(NSE_TXD_DD_M)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

		if (nse_ring_is_xdp(tx_ring))
			page_frag_free(tx_buf->raw_buf);
		else
			/* free the skb */
			napi_consume_skb(tx_buf->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len),
				 DMA_TO_DEVICE);

		/* clear tx_buf data */
		tx_buf->skb = NULL;
		dma_unmap_len_set(tx_buf, len, 0);

#if defined(NSE_DEBUG_EXT)
		if (nse_lan_tdm_check_desc_err) {
			memset(tx_desc, (unsigned char)(tx_ring->reg_idx +
			       vsi->back->lan_txq_space_start + 1), sizeof(*tx_desc));
		}
#endif

#if defined(NSE_DEBUG_EXT)
		cleaned_desc_cnt++;
#endif

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			nse_trace(clean_tx_irq_unmap, tx_ring, tx_desc, tx_buf);
			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_buf;
				tx_desc = NSE_TX_DESC(tx_ring, 0);
			}

#if defined(NSE_DEBUG_EXT)
			if (nse_lan_tdm_check_desc_err) {
				memset(tx_desc, (unsigned char)(tx_ring->reg_idx +
				       vsi->back->lan_txq_space_start + 1), sizeof(*tx_desc));
			}
#endif

#if defined(NSE_DEBUG_EXT)
			cleaned_desc_cnt++;
#endif

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
			}
		}

		nse_trace(clean_tx_irq_unmap_eop, tx_ring, tx_desc, tx_buf);

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_buf;
			tx_desc = NSE_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;

#if defined(NSE_DEBUG_EXT)
	if (total_pkts)
		tx_ring->tx_stats.clean_tx_irq_legacy_cnt++;

	if (tx_ring->txr_clean_records) {
		i = tx_ring->txr_clean_rec_cur_idx;

		tx_ring->txr_clean_records[i].clean_desc = cleaned_desc_cnt;

		tx_ring->txr_clean_records[i].clean_pkt = total_pkts;

		tx_ring->txr_clean_records[i].used_desc = tx_ring->count - NSE_DESC_UNUSED(tx_ring);

		tx_ring->txr_clean_records[i].raw_ns = ktime_get_real_ns();

		if (budget)
			tx_ring->txr_clean_records[i].clean_all_dd_this_time = 1;
		else
			tx_ring->txr_clean_records[i].clean_all_dd_this_time = 0;

		i++;
		if (i == NSE_TX_RING_CLEAN_RECORD_LEN)
			i = 0;

		tx_ring->txr_clean_rec_cur_idx = i;
	}
#endif

	nse_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);

	if (nse_ring_is_xdp(tx_ring))
		return !!budget;

	if (!nse_lan_tx_no_bql)
		netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts, total_bytes);

#define TX_WAKE_THRESHOLD ((s16)(DESC_NEEDED * 2))
	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (NSE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_tx_queue_stopped(txring_txq(tx_ring)) &&
		    !test_bit(NSE_VSI_DOWN, vsi->state)) {
			netif_tx_wake_queue(txring_txq(tx_ring));
			++tx_ring->tx_stats.restart_q;
		}
	}

	return !!budget;
}

/**
 * nse_setup_tx_ring - Allocate the Tx descriptors
 * @tx_ring: the Tx ring to set up
 *
 * Return 0 on success, negative on error
 */
int nse_setup_tx_ring(struct nse_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(tx_ring->tx_buf);
	tx_ring->tx_buf =
		devm_kcalloc(dev, sizeof(*tx_ring->tx_buf), tx_ring->count,
			     GFP_KERNEL);
	if (!tx_ring->tx_buf)
		return -ENOMEM;

	tx_ring->tx_rs_array = NULL;
	if (nse_lan_tx_rs_optimize) {
		tx_ring->tx_rs_array = devm_kcalloc(dev, sizeof(u16), tx_ring->count, GFP_KERNEL);
		if (!tx_ring->tx_rs_array)
			goto err;
	}

	/* round up to nearest page */
	tx_ring->size = ALIGN(tx_ring->count * sizeof(struct nse_tx_desc),
			      PAGE_SIZE);
	tx_ring->desc = dmam_alloc_coherent(dev, tx_ring->size, &tx_ring->dma,
					    GFP_KERNEL);
	if (!tx_ring->desc) {
		dev_err(dev, "Unable to allocate memory for the Tx descriptor ring, size=%d\n",
			tx_ring->size);
		goto err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	tx_ring->tx_rs_ntu = 0;
	tx_ring->tx_rs_ntc = 0;

	tx_ring->tx_stats.prev_pkt = -1;

#if defined(NSE_DEBUG_EXT)
	if (nse_lan_tdm_check_desc_err) {
		memset(tx_ring->desc, (unsigned char)(tx_ring->reg_idx +
		       tx_ring->vsi->back->lan_txq_space_start + 1), tx_ring->size);
	}
#endif

#if defined(NSE_DEBUG_EXT)
	tx_ring->txr_used_records =
		kcalloc(NSE_TX_RING_USED_RECORD_LEN,
			sizeof(struct nse_tx_ring_used_record), GFP_KERNEL);
	tx_ring->txr_used_rec_cur_idx = 0;

	tx_ring->txr_clean_records =
		kcalloc(NSE_TX_RING_USED_RECORD_LEN,
			sizeof(struct nse_tx_ring_clean_record), GFP_KERNEL);
	tx_ring->txr_clean_rec_cur_idx = 0;
#endif

	return 0;

err:
	if (tx_ring->tx_rs_array) {
		devm_kfree(dev, tx_ring->tx_rs_array);
		tx_ring->tx_rs_array = NULL;
	}

	if (tx_ring->tx_buf) {
		devm_kfree(dev, tx_ring->tx_buf);
		tx_ring->tx_buf = NULL;
	}

	return -ENOMEM;
}

/**
 * nse_clean_rx_ring - Free Rx buffers
 * @rx_ring: ring to be cleaned
 */
void nse_clean_rx_ring(struct nse_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_buf)
		return;

	if (rx_ring->xsk_pool) {
		nse_xsk_clean_rx_ring(rx_ring);
		goto rx_skip_free;
	}

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct nse_rx_buf *rx_buf = &rx_ring->rx_buf[i];

		if (rx_buf->skb) {
			dev_kfree_skb(rx_buf->skb);
			rx_buf->skb = NULL;
		}
		if (!rx_buf->page)
			continue;

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(dev, rx_buf->dma,
					      rx_buf->page_offset,
					      rx_ring->rx_buf_len,
					      DMA_FROM_DEVICE);

		/* free resources associated with mapping */
		dma_unmap_page_attrs(dev, rx_buf->dma, nse_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE, NSE_RX_DMA_ATTR);
		__page_frag_cache_drain(rx_buf->page, rx_buf->pagecnt_bias);

		rx_buf->page = NULL;
		rx_buf->page_offset = 0;
	}

rx_skip_free:

	memset(rx_ring->rx_buf, 0, sizeof(*rx_ring->rx_buf) * rx_ring->count);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * nse_free_rx_ring - Free Rx resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 */
void nse_free_rx_ring(struct nse_ring *rx_ring)
{
	nse_clean_rx_ring(rx_ring);

	if (rx_ring->vsi->type == NSE_VSI_PF)
		if (xdp_rxq_info_is_reg(&rx_ring->xdp_rxq))
			xdp_rxq_info_unreg(&rx_ring->xdp_rxq);
	rx_ring->xdp_prog = NULL;

	if (rx_ring->rx_buf) {
		devm_kfree(rx_ring->dev, rx_ring->rx_buf);
		rx_ring->rx_buf = NULL;
	}

	if (rx_ring->desc) {
		dmam_free_coherent(rx_ring->dev, rx_ring->size,
				   rx_ring->desc, rx_ring->dma);
		rx_ring->desc = NULL;
	}
}

/**
 * nse_setup_rx_ring - Allocate the Rx descriptors
 * @rx_ring: the Rx ring to set up
 *
 * Return 0 on success, negative on error
 */
int nse_setup_rx_ring(struct nse_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(rx_ring->rx_buf);
	rx_ring->rx_buf =
		devm_kcalloc(dev, sizeof(*rx_ring->rx_buf), rx_ring->count,
			     GFP_KERNEL);
	if (!rx_ring->rx_buf)
		return -ENOMEM;

	/* round up to nearest page */
	rx_ring->size = ALIGN(rx_ring->count * sizeof(union nse_32b_rx_desc),
			      PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dev, rx_ring->size, &rx_ring->dma,
					    GFP_KERNEL);
	if (!rx_ring->desc) {
		dev_err(dev, "Unable to allocate memory for the Rx descriptor ring, size=%d\n",
			rx_ring->size);
		goto err;
	}

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;

	if (nse_is_xdp_ena_vsi(rx_ring->vsi))
		WRITE_ONCE(rx_ring->xdp_prog, rx_ring->vsi->xdp_prog);

	if (rx_ring->vsi->type == NSE_VSI_PF &&
	    !xdp_rxq_info_is_reg(&rx_ring->xdp_rxq))
		if (xdp_rxq_info_reg(&rx_ring->xdp_rxq, rx_ring->netdev,
				     rx_ring->q_index, rx_ring->q_vector->napi.napi_id))
			goto err;

	return 0;

err:
	if (rx_ring->rx_buf) {
		devm_kfree(dev, rx_ring->rx_buf);
		rx_ring->rx_buf = NULL;
	}

	if (rx_ring->desc) {
		dmam_free_coherent(rx_ring->dev, rx_ring->size,
				   rx_ring->desc, rx_ring->dma);
		rx_ring->desc = NULL;
	}

	return -ENOMEM;
}

void nse_clean_lan_txcq_ring(struct nse_txcq_ring *cq_ring)
{
	if (!cq_ring || !cq_ring->desc)
		return;

	cq_ring->next_to_clean = 0;

	if (nse_lan_txcq_initial_hw_gen) {
		memset(cq_ring->desc, 0, cq_ring->size);
		cq_ring->generation = 0;
	} else {
		memset(cq_ring->desc, 0xFF, cq_ring->size);
		cq_ring->generation = 1;
	}
}

void nse_free_lan_txcq_ring(struct nse_txcq_ring *cq_ring)
{
	nse_clean_lan_txcq_ring(cq_ring);

	if (cq_ring->desc) {
		dmam_free_coherent(cq_ring->dev, cq_ring->size,
							cq_ring->desc, cq_ring->dma);
		cq_ring->desc = NULL;
	}
}

int nse_setup_lan_txcq_ring(struct nse_txcq_ring *cq_ring)
{
	struct device *dev = cq_ring->dev;

	if (!dev)
		return -ENOMEM;

	/* round up to nearest page */
	cq_ring->size = ALIGN(cq_ring->count * sizeof(struct nse_lan_txcq_desc),
			      PAGE_SIZE);
	cq_ring->desc = dmam_alloc_coherent(dev, cq_ring->size, &cq_ring->dma,
					    GFP_KERNEL);
	if (!cq_ring->desc)
		return -ENOMEM;

	cq_ring->next_to_clean = 0;

	if (nse_lan_txcq_initial_hw_gen) {
		memset(cq_ring->desc, 0, cq_ring->size);
		cq_ring->generation = 0;
	} else {
		memset(cq_ring->desc, 0xFF, cq_ring->size);
		cq_ring->generation = 1;
	}

	return 0;
}

int nse_clean_tx_irq_on_hw_head(struct nse_ring *tx_ring, u16 head,
				int napi_budget, struct nse_txcq_ring *cq_ring)
{
	int total_bytes = 0, total_pkts = 0;
	struct nse_vsi *vsi = tx_ring->vsi;
	u16 ntc = tx_ring->next_to_clean;
	u16 ntc_to_update = ntc;
	struct nse_tx_desc *tx_desc;
	struct nse_tx_buf *tx_buf;
	struct sk_buff *skb = NULL;
	void *raw_buf = NULL;
	struct nse_tx_desc *eop_desc = NULL;
	u32 eop_desc_idx;
	u64 clean_txqe_cnt = 0;

	/* get the bql data ready */
	if (!nse_ring_is_xdp(tx_ring))
		netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));

	tx_buf = &tx_ring->tx_buf[ntc];
	tx_desc = NSE_TX_DESC(tx_ring, ntc);

	eop_desc = tx_buf->next_to_watch;
	eop_desc_idx = (eop_desc - (struct nse_tx_desc *)tx_ring->desc);

	while (ntc != head) {
		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc) {
			/* this is not right,
			 *  in this logic, local var: 'tx_buf' should be always pointing to first
			 * tx_buf of a
			 * packet, which have next_to_watch set.
			 */
			nse_debug(&vsi->back->hw, NSE_DBG_LAN, "[%s, %d] tx-ring (idx=%d), first tx_buf (idx=%td) does not have next_to_watch eop_desc set?\n",
				  __func__, __LINE__,
				  tx_ring->q_index, (tx_buf - tx_ring->tx_buf));
			break;
		}

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb();	/* prevent any other reads prior to eop_desc */

		clean_txqe_cnt++;

		if (ntc == eop_desc_idx) {
		/* a packet is all done */

			/* clear next_to_watch to prevent false hangs */
			tx_buf->next_to_watch = NULL;

			/* update the statistics for this packet */
			total_bytes += tx_buf->bytecount;
			total_pkts += tx_buf->gso_segs;

			if (nse_ring_is_xdp(tx_ring))
				raw_buf = tx_buf->raw_buf;
			else
				skb = tx_buf->skb;

			/* unmap skb header data */
			dma_unmap_single(tx_ring->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);

			/* clear tx_buf data */
			tx_buf->skb = NULL;
			dma_unmap_len_set(tx_buf, len, 0);

#if defined(NSE_DEBUG_EXT)
			if (nse_lan_tdm_check_desc_err) {
				memset(tx_desc, (unsigned char)(tx_ring->reg_idx +
				       vsi->back->lan_txq_space_start + 1), sizeof(*tx_desc));
			}
#endif

			/* unmap remaining buffers */
			while (tx_desc != eop_desc) {
				tx_buf++;
				tx_desc++;

				if (tx_buf == (tx_ring->tx_buf + tx_ring->count)) {
					tx_buf = tx_ring->tx_buf;
					tx_desc = NSE_TX_DESC(tx_ring, 0);
				}

#if defined(NSE_DEBUG_EXT)
				if (nse_lan_tdm_check_desc_err) {
					memset(tx_desc, (unsigned char)(tx_ring->reg_idx +
					       vsi->back->lan_txq_space_start +
						1), sizeof(*tx_desc));
				}
#endif

				/* unmap any remaining paged data */
				if (dma_unmap_len(tx_buf, len)) {
					dma_unmap_page(tx_ring->dev,
						       dma_unmap_addr(tx_buf, dma),
						       dma_unmap_len(tx_buf, len),
						       DMA_TO_DEVICE);
					dma_unmap_len_set(tx_buf, len, 0);
				}
			}

			if (nse_ring_is_xdp(tx_ring))
				page_frag_free(raw_buf);
			else
				napi_consume_skb(skb, napi_budget);

			/* move us one more past the eop_desc for start of next pkt */
			tx_buf++;
			tx_desc++;

			/*  here ntc++ is necessary, it was ntc == eop_desc_idx, now we are going
			 * to next pkt
			 */
			ntc++;
			if (ntc == tx_ring->count) {
				ntc = 0;
				tx_buf = tx_ring->tx_buf;
				tx_desc = NSE_TX_DESC(tx_ring, 0);
			}

			eop_desc = tx_buf->next_to_watch;
			eop_desc_idx = (eop_desc - (struct nse_tx_desc *)tx_ring->desc);

			ntc_to_update = ntc;

			prefetch(tx_desc);
		} else {		/* !if (ntc == eop_desc_idx) */

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

	nse_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);

	if (cq_ring)
		nse_update_txcq_ring_stats(cq_ring, total_pkts, total_bytes, clean_txqe_cnt);

	if (nse_ring_is_xdp(tx_ring))
		/* return early because XDP-TXQ does not need the following logic */
		return total_pkts;

	if (!nse_lan_tx_no_bql)
		netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts, total_bytes);

	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (NSE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_tx_queue_stopped(txring_txq(tx_ring)) &&
		    !test_bit(NSE_VSI_DOWN, vsi->state)) {
			netif_tx_wake_queue(txring_txq(tx_ring));
			++tx_ring->tx_stats.restart_q;
		}
	}

	return total_pkts;
}

int nse_clean_txcq_irq_one_cqd(struct nse_txcq_ring *cq_ring, u32 cqd, int napi_budget)
{
	u16 cqd_txq_q_index = (u16)(cqd & NSE_LAN_TXCQD_TXQ_ID_M);
	u16 cqd_txq_head = (u16)((cqd & NSE_LAN_TXCQD_TX_HEAD_M) >> NSE_LAN_TXCQD_TX_HEAD_S);
	struct nse_vsi *vsi = cq_ring->vsi;
	struct nse_ring *tx_ring = NULL;
	struct device *dev = cq_ring->dev;
	int clean_pkts = 0;

	if (cqd_txq_q_index < vsi->alloc_txq) {
		tx_ring = vsi->tx_rings[cqd_txq_q_index];
	} else if (cqd_txq_q_index < (vsi->alloc_txq + vsi->num_xdp_txq)) {
		/* see nse_xdp_alloc_setup_rings(), how XDP_TXQ's q_index is set.
		 */
		tx_ring = vsi->xdp_rings[(cqd_txq_q_index - vsi->alloc_txq)];
	}

	if (!tx_ring) {
		dev_err(dev, "[%s, %d] BAD: TX-CQ report a non-exist TXQ (q_index = %d) of this VSI\n",
					__func__, __LINE__,
					cqd_txq_q_index);
		return 0;
	}

	if (tx_ring->xsk_pool)
		clean_pkts = nse_clean_tx_irq_zc_on_hw_head(tx_ring, cqd_txq_head, cq_ring);
	else
		clean_pkts = nse_clean_tx_irq_on_hw_head(tx_ring, cqd_txq_head,
							 napi_budget, cq_ring);

#if defined(NSE_DEBUG_EXT)
	if (clean_pkts) {
		if (tx_ring->xsk_pool)
			tx_ring->tx_stats.clean_txcq_irq_zc_cnt++;
		else
			tx_ring->tx_stats.clean_txcq_irq_cnt++;
	}
#endif

	return clean_pkts;
}

bool nse_clean_txcq_irq(struct nse_txcq_ring *cq_ring, int napi_budget)
{
	struct nse_vsi *vsi = cq_ring->vsi;
	struct nse_lan_txcq_desc *cq_desc = NULL;
	u32 cqd;
	u32 cqd_generation;
	u32 i;
	u32 ntc = cq_ring->next_to_clean;
	unsigned int total_budget;
	int cleaned_pkts = 0;

	total_budget = napi_budget * cq_ring->q_vector->num_ring_tx;
	if (vsi->num_xdp_txq)
		total_budget <<= 1;

	for (i = 0; i < total_budget; i++) {
		cq_desc = NSE_TXCQ_DESC(cq_ring, ntc);
		cqd = le32_to_cpu(cq_desc->data);
		cqd_generation = (cqd & NSE_LAN_TXCQD_GENERATION_M) >> NSE_LAN_TXCQD_GENERATION_S;

		if (cqd_generation == cq_ring->generation)
			break;

		cleaned_pkts += nse_clean_txcq_irq_one_cqd(cq_ring, cqd, napi_budget);

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

bool nse_clean_tx_irq_legacy_rs(struct nse_ring *tx_ring, int napi_budget)
{
	struct nse_tx_desc *next_rs_desc = NULL;
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

		next_rs_desc = NSE_TX_DESC(tx_ring, tx_rs);

		/* if the descriptor isn't done, no work yet to do */
		if (!(next_rs_desc->cmd_type_offset_bsz & cpu_to_le64(NSE_TXD_DD_M)))
			break;

#if defined(NSE_DEBUG_EXT)
		/*  if i > 0, means we have get to know head for at least 2 time ( 1st time is i =
		 * 0, 2nd time is i = 1 )
		 * so we increase this debug counter ( means "aggreate head").
		 *
		 * but we should increase this debug counter by 1 in this func.
		 *
		 * so we use if (i == 1) as condition to increase debug counter.
		 */
		tx_ring->tx_stats.clean_tx_irq_legacy_rs_raw_cnt++;

		if (i == 1)
			tx_ring->tx_stats.clean_tx_irq_legacy_rs_agg_cnt++;
#endif

		head_determined = true;

		head = tx_rs + 1;
		if (head == tx_ring->count)
			head = 0;

		tx_rs_ntc++;
		if (tx_rs_ntc >= tx_ring->count)
			tx_rs_ntc = 0;
	}

	if (head_determined)
		cleaned_pkts = nse_clean_tx_irq_on_hw_head(tx_ring, head, napi_budget, NULL);

	tx_ring->tx_rs_ntc = tx_rs_ntc;

#if defined(NSE_DEBUG_EXT)
	if (cleaned_pkts)
		tx_ring->tx_stats.clean_tx_irq_legacy_rs_cnt++;
#endif

	return (i < napi_budget);
}

bool nse_clean_tx_irq(struct nse_ring *tx_ring, int napi_budget)
{
	if (nse_lan_tx_rs_optimize)
		return nse_clean_tx_irq_legacy_rs(tx_ring, napi_budget);
	else
		return nse_clean_tx_irq_legacy(tx_ring, napi_budget);
}

/**
 * nse_rx_offset - Return expected offset into page to access data
 * @rx_ring: Ring we are requesting offset of
 *
 * Returns the offset value for ring into the data buffer.
 */
static unsigned int nse_rx_offset(struct nse_ring *rx_ring)
{
	if (nse_ring_uses_build_skb(rx_ring))
		return NSE_SKB_PAD;
	else if (nse_is_xdp_ena_vsi(rx_ring->vsi))
		return XDP_PACKET_HEADROOM;

	return 0;
}

/**
 * nse_rx_frame_truesize - Returns an actual size of Rx frame in memory
 * @rx_ring: Rx ring we are requesting the frame size of
 * @size: Packet length from rx_desc
 *
 * Returns an actual size of Rx frame in memory, considering page size
 * and SKB data alignment.
 */
static unsigned int
nse_rx_frame_truesize(struct nse_ring *rx_ring, unsigned int __maybe_unused size)
{
	unsigned int truesize;

#if (PAGE_SIZE < 8192)
	truesize = nse_rx_pg_size(rx_ring) / 2; /* Must be power-of-2 */
#else
	truesize = nse_rx_offset(rx_ring) ?
		SKB_DATA_ALIGN(nse_rx_offset(rx_ring) + size) +
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) :
		SKB_DATA_ALIGN(size);
#endif
	return truesize;
}

/**
 * nse_run_xdp - Executes an XDP program on initialized xdp_buff
 * @rx_ring: Rx ring
 * @xdp: xdp_buff used as input to the XDP program
 * @xdp_prog: XDP program to run
 *
 * Returns any of NSE_XDP_{PASS, CONSUMED, TX, REDIR}
 */
static int
nse_run_xdp(struct nse_ring *rx_ring, struct xdp_buff *xdp,
	    struct bpf_prog *xdp_prog)
{
	int err, result = NSE_XDP_PASS;
	struct nse_ring *xdp_ring;
	u32 act;
#ifdef NSE_ADD_PROBES
	u64 rx_bytes = (u64)(xdp->data_end - xdp->data);

	rx_ring->xdp_stats.xdp_rx_pkts++;
	rx_ring->xdp_stats.xdp_rx_bytes += rx_bytes;
#endif

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
#ifdef NSE_ADD_PROBES
		rx_ring->xdp_stats.xdp_pass++;
#endif
		break;
	case XDP_TX:
		xdp_ring = rx_ring->vsi->xdp_rings[rx_ring->q_index];
		result = nse_xmit_xdp_buff(xdp, xdp_ring);
#ifdef NSE_ADD_PROBES
		if (result == NSE_XDP_TX)
			rx_ring->xdp_stats.xdp_tx++;
		else
			rx_ring->xdp_stats.xdp_tx_fail++;
#endif
		break;
	case XDP_REDIRECT:
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		result = !err ? NSE_XDP_REDIR : NSE_XDP_CONSUMED;
#ifdef NSE_ADD_PROBES
		if (!err)
			rx_ring->xdp_stats.xdp_redirect++;
		else
			rx_ring->xdp_stats.xdp_redirect_fail++;
#endif
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, act);
		fallthrough; /* not supported action */

	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
#ifdef NSE_ADD_PROBES
		rx_ring->xdp_stats.xdp_unknown++;
#endif
		fallthrough; /* handle aborts by dropping frame */

	case XDP_DROP:
		result = NSE_XDP_CONSUMED;
#ifdef NSE_ADD_PROBES
		rx_ring->xdp_stats.xdp_drop++;
#endif
		break;
	}

	return result;
}

/**
 * nse_xdp_xmit - submit packets to XDP ring for transmission
 * @dev: netdev
 * @n: number of XDP frames to be transmitted
 * @frames: XDP frames to be transmitted
 * @flags: transmit flags
 *
 * Returns number of frames successfully sent. Frames that fail are
 * free'ed via XDP return API.
 * For error cases, a negative errno code is returned and no-frames
 * are transmitted (caller must handle freeing frames).
 */
int
nse_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
	     u32 flags)
{
	struct nse_netdev_priv *np = netdev_priv(dev);
	unsigned int queue_index = smp_processor_id();
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *xdp_ring;
	int drops = 0, i;

	if (nse_is_reset_in_progress(pf->state))
		return -ENXIO;

	if (test_bit(NSE_VSI_DOWN, vsi->state))
		return -ENETDOWN;

	if (!nse_is_xdp_ena_vsi(vsi) || queue_index >= vsi->num_xdp_txq)
		return -ENXIO;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	xdp_ring = vsi->xdp_rings[queue_index];
	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];
		int err;

		err = nse_xmit_xdp_ring(xdpf->data, xdpf->len, xdp_ring, (i != (n-1)));
		if (err != NSE_XDP_TX) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
		}
	}

	if (unlikely(flags & XDP_XMIT_FLUSH))
		nse_xdp_ring_update_tail(xdp_ring);

	return n - drops;
}

/**
 * nse_alloc_mapped_page - recycle or make a new page
 * @rx_ring: ring to use
 * @bi: rx_buf struct to modify
 *
 * Returns true if the page was successfully allocated or
 * reused.
 */
static bool
nse_alloc_mapped_page(struct nse_ring *rx_ring, struct nse_rx_buf *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page)) {
#ifdef NSE_ADD_PROBES
		rx_ring->rx_stats.page_reuse++;
#endif /* NSE_ADD_PROBES */
		return true;
	}

	/* alloc new page for storage */
	page = dev_alloc_pages(nse_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page_attrs(rx_ring->dev, page, 0, nse_rx_pg_size(rx_ring),
				 DMA_FROM_DEVICE, NSE_RX_DMA_ATTR);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, nse_rx_pg_order(rx_ring));
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = nse_rx_offset(rx_ring);
	page_ref_add(page, USHRT_MAX - 1);
	bi->pagecnt_bias = USHRT_MAX;

	return true;
}

/**
 * nse_alloc_rx_bufs - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail. Returning
 * true signals to the caller that we didn't replace cleaned_count buffers and
 * there is more work to do.
 *
 * First, try to clean "cleaned_count" Rx buffers. Then refill the cleaned Rx
 * buffers. Then bump tail at most one time. Grouping like this lets us avoid
 * multiple tail writes per call.
 */
bool nse_alloc_rx_bufs(struct nse_ring *rx_ring, u16 cleaned_count)
{
	union nse_32b_rx_desc *rx_desc;
	u16 ntu = rx_ring->next_to_use;
	struct nse_rx_buf *bi;

	/* do nothing if no valid netdev defined */
	if (!rx_ring->netdev ||
	    !cleaned_count)
		return false;

	/* get the Rx descriptor and buffer based on next_to_use */
	rx_desc = NSE_RX_DESC(rx_ring, ntu);
	bi = &rx_ring->rx_buf[ntu];

	do {
		/* if we fail here, we have work remaining */
		if (!nse_alloc_mapped_page(rx_ring, bi))
			break;

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
			rx_desc = NSE_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buf;
			ntu = 0;
		}

		/* clear the status bits for the next_to_use descriptor */
		rx_desc->wb.status_error0 = 0;

		cleaned_count--;
	} while (cleaned_count);

	if (rx_ring->next_to_use != ntu)
		nse_release_rx_desc(rx_ring, ntu);

	return !!cleaned_count;
}

/**
 * nse_page_is_reserved - check if reuse is possible
 * @page: page struct to check
 */
static bool nse_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

/**
 * nse_rx_buf_adjust_pg_offset - Prepare Rx buffer for reuse
 * @rx_buf: Rx buffer to adjust
 * @size: Size of adjustment
 *
 * Update the offset within page so that Rx buf will be ready to be reused.
 * For systems with PAGE_SIZE < 8192 this function will flip the page offset
 * so the second half of page assigned to Rx buffer will be used, otherwise
 * the offset is moved by "size" bytes
 */
static void
nse_rx_buf_adjust_pg_offset(struct nse_rx_buf *rx_buf, unsigned int size)
{
#if (PAGE_SIZE < 8192)
	/* flip page offset to other buffer */
	rx_buf->page_offset ^= size;
#else
	/* move offset up to the next cache line */
	rx_buf->page_offset += size;
#endif
}

/**
 * nse_can_reuse_rx_page - Determine if page can be reused for another Rx
 * @rx_buf: buffer containing the page
 *
 * If page is reusable, we have a green light for calling nse_reuse_rx_page,
 * which will assign the current buffer to the buffer that next_to_alloc is
 * pointing to; otherwise, the DMA mapping needs to be destroyed and
 * page freed
 */
static bool nse_can_reuse_rx_page(struct nse_rx_buf *rx_buf)
{
	unsigned int pagecnt_bias = rx_buf->pagecnt_bias;
	struct page *page = rx_buf->page;

	/* avoid re-using remote pages */
	if (unlikely(nse_page_is_reserved(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely((page_count(page) - pagecnt_bias) > 1))
		return false;
#else
#define NSE_LAST_OFFSET \
	(SKB_WITH_OVERHEAD(PAGE_SIZE) - NSE_RXBUF_2048)
	if (rx_buf->page_offset > NSE_LAST_OFFSET)
		return false;
#endif /* PAGE_SIZE < 8192) */

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
	if (unlikely(pagecnt_bias == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		rx_buf->pagecnt_bias = USHRT_MAX;
	}

	return true;
}

/**
 * nse_add_rx_frag - Add contents of Rx buffer to sk_buff as a frag
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buf->page to the skb.
 * It will just attach the page as a frag to the skb.
 * The function will then update the page offset.
 */
static void
nse_add_rx_frag(struct nse_ring *rx_ring, struct nse_rx_buf *rx_buf,
		struct sk_buff *skb, unsigned int size)
{
#if (PAGE_SIZE >= 8192)
	unsigned int truesize = SKB_DATA_ALIGN(size + nse_rx_offset(rx_ring));
#else
	unsigned int truesize = nse_rx_pg_size(rx_ring) / 2;
#endif

	if (!size)
		return;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buf->page,
			rx_buf->page_offset, size, truesize);

	/* page is being used so we must update the page offset */
	nse_rx_buf_adjust_pg_offset(rx_buf, truesize);
}

/**
 * nse_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: Rx descriptor ring to store buffers on
 * @old_buf: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 */
static void
nse_reuse_rx_page(struct nse_ring *rx_ring, struct nse_rx_buf *old_buf)
{
	u16 nta = rx_ring->next_to_alloc;
	struct nse_rx_buf *new_buf;

	new_buf = &rx_ring->rx_buf[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* Transfer page from old buffer to new buffer.
	 * Move each member individually to avoid possible store
	 * forwarding stalls and unnecessary copy of skb.
	 */
	new_buf->dma = old_buf->dma;
	new_buf->page = old_buf->page;
	new_buf->page_offset = old_buf->page_offset;
	new_buf->pagecnt_bias = old_buf->pagecnt_bias;
}

/**
 * nse_get_rx_buf - Fetch Rx buffer and synchronize data for use
 * @rx_ring: Rx descriptor ring to transact packets on
 * @skb: skb to be used
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct nse_rx_buf *
nse_get_rx_buf(struct nse_ring *rx_ring, struct sk_buff **skb,
	       const unsigned int size)
{
	struct nse_rx_buf *rx_buf;

	rx_buf = &rx_ring->rx_buf[rx_ring->next_to_clean];
	prefetchw(rx_buf->page);
	*skb = rx_buf->skb;

	if (!size)
		return rx_buf;
	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma,
				      rx_buf->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	rx_buf->pagecnt_bias--;

	return rx_buf;
}

/**
 * nse_build_skb - Build skb around an existing buffer
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function builds an skb around an existing Rx buffer, taking care
 * to set up the skb correctly and avoid any memcpy overhead.
 */
static struct sk_buff *
nse_build_skb(struct nse_ring *rx_ring, struct nse_rx_buf *rx_buf,
	      struct xdp_buff *xdp)
{
	u8 metasize = xdp->data - xdp->data_meta;
#if (PAGE_SIZE < 8192)
	unsigned int truesize = nse_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	struct sk_buff *skb;

	/* Prefetch first cache line of first page. If xdp->data_meta
	 * is unused, this points exactly as xdp->data, otherwise we
	 * likely have a consumer accessing first few bytes of meta
	 * data, and then actual data.
	 */
	net_prefetch(xdp->data_meta);
	/* build an skb around the page buffer */
	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	/* must to record Rx queue, otherwise OS features such as
	 * symmetric queue won't work
	 */
	skb_record_rx_queue(skb, rx_ring->q_index);

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, xdp->data_end - xdp->data);
	if (metasize)
		skb_metadata_set(skb, metasize);

	/* buffer is used by skb, update page_offset */
	nse_rx_buf_adjust_pg_offset(rx_buf, truesize);

	return skb;
}

/**
 * nse_construct_skb - Allocate skb and populate it
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function allocates an skb. It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
static struct sk_buff *
nse_construct_skb(struct nse_ring *rx_ring, struct nse_rx_buf *rx_buf,
		  struct xdp_buff *xdp)
{
	unsigned int size = xdp->data_end - xdp->data;
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	net_prefetch(xdp->data);

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rx_ring->q_vector->napi, NSE_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rx_ring->q_index);
	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > NSE_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data, NSE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data, ALIGN(headlen,
							 sizeof(long)));

	/* if we exhaust the linear part then add what is left as a frag */
	size -= headlen;
	if (size) {
#if (PAGE_SIZE >= 8192)
		unsigned int truesize = SKB_DATA_ALIGN(size);
#else
		unsigned int truesize = nse_rx_pg_size(rx_ring) / 2;
#endif
		skb_add_rx_frag(skb, 0, rx_buf->page,
				rx_buf->page_offset + headlen, size, truesize);
		/* buffer is used by skb, update page_offset */
		nse_rx_buf_adjust_pg_offset(rx_buf, truesize);
	} else {
		/* buffer is unused, reset bias back to rx_buf; data was copied
		 * onto skb's linear part so there's no need for adjusting
		 * page offset and we can reuse this buffer as-is
		 */
		rx_buf->pagecnt_bias++;
	}

	return skb;
}

/**
 * nse_put_rx_buf - Clean up used buffer and either recycle or free
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will update next_to_clean and then clean up the contents
 * of the rx_buf. It will either recycle the buffer or unmap it and free
 * the associated resources.
 */
static void nse_put_rx_buf(struct nse_ring *rx_ring, struct nse_rx_buf *rx_buf)
{
	u16 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	if (!rx_buf)
		return;

	if (nse_can_reuse_rx_page(rx_buf)) {
		/* hand second half of page back to the ring */
		nse_reuse_rx_page(rx_ring, rx_buf);
#ifdef NSE_ADD_PROBES
		rx_ring->rx_stats.page_reuse++;
#endif /* NSE_ADD_PROBES */
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma,
				     nse_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				     NSE_RX_DMA_ATTR);
		__page_frag_cache_drain(rx_buf->page, rx_buf->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	rx_buf->page = NULL;
	rx_buf->skb = NULL;
}

/**
 * nse_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * If the buffer is an EOP buffer, this function exits returning false,
 * otherwise return true indicating that this is in fact a non-EOP buffer.
 */
static bool
nse_is_non_eop(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
	       struct sk_buff *skb)
{
	u16 rsccnt, nextp;

	rsccnt = ((le16_to_cpu(rx_desc->wb.hdrlen_rsccnt) & NSE_RXD_RSCCNT_M) >> NSE_RXD_RSCCNT_S);
	if (rsccnt) {
		nextp = le16_to_cpu(rx_desc->wb.l2tag1_nextp);

		NSE_CB(skb)->append_cnt += (rsccnt - 1);

#if defined(NSE_DEBUG_EXT)
		rx_ring->rx_stats.rsc_cnt_desc_cnt[rsccnt]++;
		rx_ring->rx_stats.rsc_cnt_total_accum += rsccnt;
#endif
	}

	/* if we are the last buffer then there is nothing else to do */
#define NSE_RXD_EOF BIT(NSE_RXD_STATUS0_EOP_S)
	if (likely(nse_test_staterr(rx_desc->wb.status_error0, NSE_RXD_EOF)))
		return false;

	if (rsccnt)
		rx_ring->rx_buf[nextp].skb = skb;
	else
		rx_ring->rx_buf[rx_ring->next_to_clean].skb = skb;

	rx_ring->rx_stats.non_eop_descs++;

	return true;
}

/**
 * nse_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: Rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing. The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 */
int nse_clean_rx_irq(struct nse_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	u16 cleaned_count = NSE_DESC_UNUSED(rx_ring);
	unsigned int xdp_res, xdp_xmit = 0;
	struct bpf_prog *xdp_prog = NULL;
	struct xdp_buff xdp;
	bool failure;

	xdp.rxq = &rx_ring->xdp_rxq;
	/* Frame size depend on rx_ring setup when PAGE_SIZE=4K */
#if (PAGE_SIZE < 8192)
	xdp.frame_sz = nse_rx_frame_truesize(rx_ring, 0);
#endif

	/* start the loop to process Rx packets bounded by 'budget' */
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		union nse_32b_rx_desc *rx_desc;
		struct nse_rx_buf *rx_buf;
		struct sk_buff *skb;
		unsigned int size;
		u16 stat_err_bits;
		u16 vlan_tag = 0;
		u8 rx_ptype;
		u8 has_vlan_flags = 0;

		/* get the Rx desc from Rx ring based on 'next_to_clean' */
		rx_desc = NSE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		/* status_error_len will always be zero for unused descriptors
		 * because it's cleared in cleanup, and overlaps with hdr_addr
		 * which is always zero because packet split isn't used, if the
		 * hardware wrote DD then it will be non-zero
		 */
		stat_err_bits = BIT(NSE_RXD_STATUS0_DD_S);
		if (!nse_test_staterr(rx_desc->wb.status_error0, stat_err_bits))
			break;

#if defined(NSE_DEBUG_EXT)
		nse_test_suite_rxdid_dbg_0_desc(rx_ring, rx_desc);
#endif

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * DD bit is set.
		 */
		dma_rmb();

		nse_trace(clean_rx_irq, rx_ring, rx_desc);
		if (!rx_ring->netdev) {
			nse_put_rx_buf(rx_ring, NULL);
			cleaned_count++;
			continue;
		}

		size = le16_to_cpu(rx_desc->wb.pktlen_sph_reentry) &
			NSE_RXD_PKT_LEN_M;

		/* retrieve a buffer from the ring */
		rx_buf = nse_get_rx_buf(rx_ring, &skb, size);
		if (!size) {
			xdp.data = NULL;
			xdp.data_end = NULL;
			xdp.data_hard_start = NULL;
			xdp.data_meta = NULL;
			goto construct_skb;
		}

		xdp.data = page_address(rx_buf->page) + rx_buf->page_offset;
		xdp.data_hard_start = xdp.data - nse_rx_offset(rx_ring);
		xdp.data_meta = xdp.data;
		xdp.data_end = xdp.data + size;
#if (PAGE_SIZE > 4096)
		/* At larger PAGE_SIZE, frame_sz depend on len size */
		xdp.frame_sz = nse_rx_frame_truesize(rx_ring, size);
#endif

		rcu_read_lock();
		xdp_prog = READ_ONCE(rx_ring->xdp_prog);
		if (!xdp_prog) {
			rcu_read_unlock();
			goto construct_skb;
		}

		xdp_res = nse_run_xdp(rx_ring, &xdp, xdp_prog);
		rcu_read_unlock();
		if (!xdp_res)
			goto construct_skb;
		if (xdp_res & (NSE_XDP_TX | NSE_XDP_REDIR)) {
			xdp_xmit |= xdp_res;
			nse_rx_buf_adjust_pg_offset(rx_buf, xdp.frame_sz);
		} else {
			rx_buf->pagecnt_bias++;
		}
		total_rx_bytes += size;
		total_rx_pkts++;

		cleaned_count++;
		nse_put_rx_buf(rx_ring, rx_buf);
		continue;
construct_skb:
		if (skb) {
			nse_add_rx_frag(rx_ring, rx_buf, skb, size);
		} else if (likely(xdp.data)) {
			if (nse_ring_uses_build_skb(rx_ring))
				skb = nse_build_skb(rx_ring, rx_buf, &xdp);
			else
				skb = nse_construct_skb(rx_ring, rx_buf, &xdp);
		}
		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_buf_failed++;
			if (rx_buf)
				rx_buf->pagecnt_bias++;
			break;
		}

		nse_put_rx_buf(rx_ring, rx_buf);
		cleaned_count++;

		/* skip if it is NOP desc */
		if (nse_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		stat_err_bits = BIT(NSE_RXD_STATUS0_RXE_S);
		if (unlikely(nse_test_staterr(rx_desc->wb.status_error0,
					      stat_err_bits))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		vlan_tag = nse_get_vlan_tag_from_rx_desc(rx_desc, &has_vlan_flags);

		/* pad the skb if needed, to make a valid ethernet frame */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* update budget accounting */
		total_rx_pkts++;

		/* populate checksum, VLAN, and protocol */
		rx_ptype = rx_desc->wb.ptype;

		if (nse_process_skb_fields(rx_ring, rx_desc, skb, rx_ptype)) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		nse_trace(clean_rx_irq_indicate, rx_ring, rx_desc, skb);

#if defined(NSE_DEBUG_EXT)
		nse_test_suite_rvlan(rx_ring, rx_desc, skb, rx_ptype, vlan_tag);
#endif

		/* send completed skb up the stack */
		nse_receive_skb(rx_ring, skb, vlan_tag, has_vlan_flags);
	}

	/* return up to cleaned_count buffers to hardware */
	failure = nse_alloc_rx_bufs(rx_ring, cleaned_count);

	if (xdp_prog)
		nse_finalize_xdp_rx(rx_ring, xdp_xmit);

	nse_update_rx_ring_stats(rx_ring, total_rx_pkts, total_rx_bytes);

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}

static void __nse_update_sample(struct nse_q_vector *q_vector,
				struct dim_sample *sample)
{
	u64 packets = 0, bytes = 0;
	struct nse_ring_container *rc;
	struct nse_ring *ring;

	rc = &q_vector->rx;
	nse_for_each_ring(ring, *rc) {
		packets += ring->stats.pkts;
		bytes += ring->stats.bytes;
	}

	rc = &q_vector->tx;
	nse_for_each_ring(ring, *rc) {
		packets += ring->stats.pkts;
		bytes += ring->stats.bytes;
	}

	dim_update_sample(q_vector->total_events, packets, bytes, sample);
	sample->comp_ctr = 0;

	/* if dim settings get stale, like when not updated for 1
	 * second or longer, force it to start again. This addresses the
	 * frequent case of an idle queue being switched to by the
	 * scheduler. The 1,000 here means 1,000 milliseconds.
	 */
	if (ktime_ms_delta(sample->time, q_vector->dim.start_sample.time) >= 1000)
		q_vector->dim.state = DIM_START_MEASURE;
}

/**
 * nse_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void nse_net_dim(struct nse_q_vector *q_vector)
{
	if (ITR_IS_DYNAMIC(q_vector)) {
		struct dim_sample dim_sample;

		__nse_update_sample(q_vector, &dim_sample);
		net_dim(&q_vector->dim, dim_sample);
	}
}

/**
 * nse_buildreg_itr - build value for writing to the INT_DYN_CTLN register
 * @itr: interrupt throttling value in usecs
 */
static u32 nse_buildreg_itr(struct nse_pf *pf, bool update_itr, u16 itr)
{
	u32 val;

	val = NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M; /* intmask_vld=1, intmsk=0 -- unmask this irq */

	if (update_itr) {
		if (!itr || pf->sw_conf.min_itr_no_intrl)
			itr = (NSE_ITR_INTERVAL_MIN_USEC >> 1);

		val |= NSE_REG_INT_DYN_CTLN_ITR_VALID_M;
		val |= ((itr <<
			NSE_REG_INT_DYN_CTLN_ITR_INTERVAL_S) & NSE_REG_INT_DYN_CTLN_ITR_INTERVAL_M);
	}

	return val;
}

/**
 * nse_enable_interrupt - re-enable MSI-X interrupt
 * @q_vector: the vector associated with the interrupt to enable
 *
 * If the VSI is down, the interrupt will not be re-enabled. Also,
 * when enabling the interrupt always reset the wb_on_itr to false
 * and trigger a software interrupt to clean out internal state.
 */
static void nse_enable_interrupt(struct nse_q_vector *q_vector)
{
	struct nse_vsi *vsi = q_vector->vsi;
	bool wb_en = q_vector->wb_on_itr;
	u32 reg_val;

	if (test_bit(NSE_VSI_DOWN, vsi->state))
		return;

	/* trigger an ITR delayed software interrupt when exiting busy poll, to
	 * make sure to catch any pending cleanups that might have been missed
	 * due to interrupt state transition. If busy poll or poll isn't
	 * enabled, then don't update ITR, and just enable the interrupt.
	 */
	if (!wb_en) {
		reg_val = nse_buildreg_itr(vsi->back, false, 0);
	} else {
		q_vector->wb_on_itr = false;

		/* do two things here with a single write. Set up the third ITR
		 * index to be used for software interrupt moderation, and then
		 * trigger a software interrupt with a rate limit of 20K on
		 * software interrupts, this will help avoid high interrupt
		 * loads due to frequently polling and exiting polling.
		 */
		if (q_vector->dyn_itr_refresh) {
			reg_val = nse_buildreg_itr(vsi->back, true, q_vector->dyn_itr_val);
			q_vector->dyn_itr_refresh = false;
		} else {
			reg_val = nse_buildreg_itr(vsi->back, true, (NSE_ITR_INTERVAL_20K >> 1));
		}
		reg_val |= NSE_REG_INT_DYN_CTLN_SWINT_TRIG_M;
	}

	wr32(&vsi->back->hw, NSE_REG_INT_DYN_CTLN(q_vector->reg_idx), reg_val);
}

static void nse_enable_interrupt_force_and_trig(struct nse_q_vector *q_vector)
{
	u32 reg_val;

	q_vector->wb_on_itr = false;

	/* intmask_vld=1, intmsk=0 -- unmask this irq */
	reg_val = nse_buildreg_itr(q_vector->vsi->back, false, 0);

	reg_val |= NSE_REG_INT_DYN_CTLN_SWINT_TRIG_M;

	wr32(&q_vector->vsi->back->hw, NSE_REG_INT_DYN_CTLN(q_vector->reg_idx), reg_val);

	nse_flush(&q_vector->vsi->back->hw);
}

/**
 * nse_set_wb_on_itr - set WB_ON_ITR for this q_vector
 * @q_vector: q_vector to set WB_ON_ITR on
 *
 * We need to tell hardware to write-back completed descriptors even when
 * interrupts are disabled. Descriptors will be written back on cache line
 * boundaries without WB_ON_ITR enabled, but if we don't enable WB_ON_ITR
 * descriptors may not be written back if they don't fill a cache line until
 * the next interrupt.
 *
 * This sets the write-back frequency to whatever was set previously for the
 * ITR indices. Also, set the INTENA_MSK bit to make sure hardware knows we
 * aren't meddling with the INTENA_M bit.
 */
static void nse_set_wb_on_itr(struct nse_q_vector *q_vector)
{
	struct nse_vsi *vsi = q_vector->vsi;

	/* already in wb_on_itr mode no need to change it */
	if (q_vector->wb_on_itr)
		return;

	/* use previously set ITR values
	 * which will vary in adaptive (AIM) mode and
	 * be static in non-adaptive mode (user configured)
	 */
	wr32(&vsi->back->hw, NSE_REG_INT_DYN_CTLN(q_vector->reg_idx),
		(NSE_REG_INT_DYN_CTLN_WB_ON_ITR_M |
			NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M | NSE_REG_INT_DYN_CTLN_INTMSK_M));

	q_vector->wb_on_itr = true;
}

int nse_polling(struct nse_q_vector *q_vector, int budget)
{
	bool clean_complete = true;
	struct nse_ring *ring;
	int budget_per_ring;
	int work_done = 0;
	bool wd;

	if (!q_vector->txcq) {	/* default, non-TX-CQ logic */

		/* Since the actual Tx work is minimal, we can give the Tx a larger
		 * budget and be more aggressive about cleaning up the Tx descriptors.
		 */
		nse_for_each_ring(ring, q_vector->tx) {
			if (ring == NULL)
				continue;
			wd = nse_clean_tx_irq_pmd(ring, budget);

			if (!wd)
				clean_complete = false;
		}
	} else {		/* TX-CQ logic */

		wd = nse_clean_txcq_irq(q_vector->txcq, budget);

		if (!wd) {
			clean_complete = false;

#ifdef NSE_ADD_PROBES
			/* if we are reporting that we are not done, then we
			 * know napi is going to continue so increment the
			 * count
			 */
			q_vector->txcq->stats.napi_poll_cnt++;
#endif
		}
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(budget <= 0))
		return budget;

	/* normally we have 1 Rx ring per q_vector */
	if (unlikely(q_vector->num_ring_rx > 1))
		/* We attempt to distribute budget to each Rx queue fairly, but
		 * don't allow the budget to go below 1 because that would exit
		 * polling early.
		 */
		budget_per_ring = max_t(int, budget / q_vector->num_ring_rx, 1);
	else
		/* Max of 1 Rx ring in this q_vector so give it the budget */
		budget_per_ring = budget;

	nse_for_each_ring(ring, q_vector->rx) {
		int cleaned;

		if (ring == NULL)
			continue;

		cleaned = nse_clean_rx_irq(ring, budget_per_ring);

		work_done += cleaned;

		/* if we clean as many as budgeted, we must not be done */
		if (cleaned >= budget_per_ring)
			clean_complete = false;

	} /* end for nse_for_each_ring */

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		/* Set the writeback on ITR so partial completions of
		 * cache-lines will still continue even if we're polling.
		 */
//		nse_set_wb_on_itr(q_vector);

		return budget;
	}

	return min_t(int, work_done, budget - 1);
}

#define NSE_NAPI_POLL_BUDGET_PER_RXQ	32

/**
 * nse_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 */
int nse_napi_poll(struct napi_struct *napi, int budget)
{
	struct nse_q_vector *q_vector =
				container_of(napi, struct nse_q_vector, napi);
	bool clean_complete = true;
	struct nse_ring *ring;
	int budget_per_ring;
	int work_done = 0;
	bool wd;
	int cpu_id;
	u64 poll_ns;

#if defined(NSE_DEBUG_EXT)
	poll_ns = ktime_get_real_ns();

	q_vector->dbg_stats.napi_poll_total_cnt++;
	q_vector->dbg_stats.napi_poll_last_ns = poll_ns;
#endif

	if (!q_vector->txcq) {	/* default, non-TX-CQ logic */

		/* Since the actual Tx work is minimal, we can give the Tx a larger
		 * budget and be more aggressive about cleaning up the Tx descriptors.
		 */
		nse_for_each_ring(ring, q_vector->tx) {
			wd = ring->xsk_pool ?
				  nse_clean_tx_irq_zc(ring) :
				  nse_clean_tx_irq(ring, budget);

			if (!wd) {
				clean_complete = false;

#ifdef NSE_ADD_PROBES
				/* if we are reporting that we are not done, then we
				 * know napi is going to continue so increment the
				 * count
				 */
				ring->stats.napi_poll_cnt++;
#endif

#if defined(NSE_DEBUG_EXT)
				q_vector->dbg_stats.napi_poll_txq_clean_not_done_cnt++;
			} else {
				q_vector->dbg_stats.napi_poll_txq_clean_done_cnt++;
#endif
			}
		}
	} else {		/* TX-CQ logic */

		wd = nse_clean_txcq_irq(q_vector->txcq, budget);

		if (!wd) {
			clean_complete = false;

#ifdef NSE_ADD_PROBES
			/* if we are reporting that we are not done, then we
			 * know napi is going to continue so increment the
			 * count
			 */
			q_vector->txcq->stats.napi_poll_cnt++;
#endif

#if defined(NSE_DEBUG_EXT)
			q_vector->dbg_stats.napi_poll_txcq_clean_not_done_cnt++;
		} else {
			q_vector->dbg_stats.napi_poll_txcq_clean_done_cnt++;
#endif
		}
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (unlikely(budget <= 0)) {
#if defined(NSE_DEBUG_EXT)
		q_vector->dbg_stats.napi_poll_budeget_less_0_cnt++;
		q_vector->dbg_stats.napi_poll_budeget_less_0_last_poll_cnt =
			q_vector->dbg_stats.napi_poll_total_cnt;
		q_vector->dbg_stats.napi_poll_budeget_less_0_last_ns = poll_ns;
#endif

		goto tx_only;
	}

	/* normally we have 1 Rx ring per q_vector */
	if (unlikely(q_vector->num_ring_rx > 1))
		/* We attempt to distribute budget to each Rx queue fairly, but
		 * don't allow the budget to go below 1 because that would exit
		 * polling early.
		 */
		budget_per_ring = max_t(int, budget / q_vector->num_ring_rx,
					NSE_NAPI_POLL_BUDGET_PER_RXQ);
	else
		/* Max of 1 Rx ring in this q_vector so give it the budget */
		budget_per_ring = budget;

	nse_for_each_ring(ring, q_vector->rx) {
		int cleaned;

		/* A dedicated path for zero-copy allows making a single
		 * comparison in the irq context instead of many inside the
		 * nse_clean_rx_irq function and makes the codebase cleaner.
		 */
		cleaned = ring->xsk_pool ?
			  nse_clean_rx_irq_zc(ring, budget_per_ring) :
			  nse_clean_rx_irq(ring, budget_per_ring);

		work_done += cleaned;

		/* if we clean as many as budgeted, we must not be done */
		if (work_done >= budget || cleaned >= budget_per_ring) {
			clean_complete = false;

#ifdef NSE_ADD_PROBES
			/* if we are reporting that we are not done, then we
			 * know napi is going to continue so increment the
			 * count
			 */
			ring->stats.napi_poll_cnt++;
#endif

#if defined(NSE_DEBUG_EXT)
			q_vector->dbg_stats.napi_poll_rxq_clean_not_done_cnt++;
		} else {
			q_vector->dbg_stats.napi_poll_rxq_clean_done_cnt++;
#endif
		}

	} /* end for nse_for_each_ring */

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
#if defined(NSE_DEBUG_EXT)
		q_vector->dbg_stats.napi_poll_clean_not_done_cnt++;
#endif

		cpu_id = smp_processor_id();

		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			/* Tell napi that we are done polling */
			napi_complete_done(napi, work_done);

			/* Force an interrupt */
			nse_enable_interrupt_force_and_trig(q_vector);

#if defined(NSE_DEBUG_EXT)
			q_vector->dbg_stats.napi_poll_cpu_change_cnt++;

			q_vector->dbg_stats.napi_poll_cpu_change_last_poll_cnt =
				q_vector->dbg_stats.napi_poll_total_cnt;
			q_vector->dbg_stats.napi_poll_cpu_change_last_ns = poll_ns;

			/* !clean_complete && cpu_change */
			q_vector->dbg_stats.napi_poll_last_ret_event = 1;
#endif

			/* Return budget-1 so that polling stops */
			return budget - 1;
		}

tx_only:

		/* Set the writeback on ITR so partial completions of
		 * cache-lines will still continue even if we're polling.
		 */
		nse_set_wb_on_itr(q_vector);

#if defined(NSE_DEBUG_EXT)
		/* !clean_complete && !cpu_change */
		q_vector->dbg_stats.napi_poll_last_ret_event = 2;
#endif

		return budget;
	}

#if defined(NSE_DEBUG_EXT)
	q_vector->dbg_stats.napi_poll_clean_done_cnt++;
#endif

	/* Work is done so exit the polling mode and re-enable the interrupt */
	if (likely(napi_complete_done(napi, work_done))) {
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is true, enable device interrupt
		 * but there are condition/optimization, where it can be
		 * optimized. Basically, if napi_complete_done returns true.
		 * But if it is last time Rx packets were cleaned,
		 * then most likely, consumer thread will come back to do
		 * busy_polling where cleaning of  Tx/Rx queue will happen
		 * normally. Hence no reason to arm the interrupt.
		 *
		 * If for some reason, consumer thread/context doesn't comeback
		 * to busy_poll:napi_poll, there is bail-out mechanism to kick
		 * start the state machine thru' SW triggered interrupt from
		 * service task.
		 */

#if defined(NSE_DEBUG_EXT)
		q_vector->dbg_stats.napi_poll_clean_done_unmask_irq_cnt++;

		/* clean_complete, enable_interrupt() */
		q_vector->dbg_stats.napi_poll_last_ret_event = 3;
#endif

		nse_net_dim(q_vector);
		nse_enable_interrupt(q_vector);

	} else {
#if defined(NSE_DEBUG_EXT)
		q_vector->dbg_stats.napi_poll_clean_done_keep_wb_on_itr_cnt++;

		/* clean_complete, set_wb_on_itr() */
		q_vector->dbg_stats.napi_poll_last_ret_event = 4;
#endif

		nse_set_wb_on_itr(q_vector);
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * __nse_maybe_stop_tx - 2nd level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size: the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 */
static int __nse_maybe_stop_tx(struct nse_ring *tx_ring, unsigned int size)
{
	netif_tx_stop_queue(txring_txq(tx_ring));
	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(NSE_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_tx_start_queue(txring_txq(tx_ring));
	++tx_ring->tx_stats.restart_q;
	return 0;
}

/**
 * nse_maybe_stop_tx - 1st level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns 0 if stop is not needed
 */
static int nse_maybe_stop_tx(struct nse_ring *tx_ring, unsigned int size)
{
	if (likely(NSE_DESC_UNUSED(tx_ring) >= size))
		return 0;

	return __nse_maybe_stop_tx(tx_ring, size);
}

/**
 * nse_tx_map - Build the Tx descriptor
 * @tx_ring: ring to send buffer on
 * @first: first buffer info buffer to use
 * @off: pointer to struct that holds offload parameters
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit descriptor.
 */
static void
nse_tx_map(struct nse_ring *tx_ring, struct nse_tx_buf *first,
	   struct nse_tx_offload_params *off)
{
	bool first_td = true;
	u64 td_cmd_type_offset_bsz, td_tlen;
	u16 i = tx_ring->next_to_use;
	u16 tx_rs_ntu = tx_ring->tx_rs_ntu;
	u16 tx_rs;
	bool record_tx_rs = false;
	unsigned int data_len, size;
	struct nse_tx_desc *tx_desc;
	struct nse_tx_buf *tx_buf;
	struct device *dev = tx_ring->dev;
	struct sk_buff *skb = first->skb;
	skb_frag_t *frag;
	dma_addr_t dma;
	bool kick;

	if (!(off->td_cmd_type_offset_bsz & NSE_TXD_MACLEN_M)) {
		/* MAC_LEN unset, set it.... */
		u64 mac_len = (u64)skb_network_offset(skb);

		off->td_cmd_type_offset_bsz |= (((mac_len >> 1) << NSE_TXD_MACLEN_S) & NSE_TXD_MACLEN_M);
	}

	if (off->cd_qw1 & (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S))
		off->td_cmd_type_offset_bsz |= NSE_TXD_CC_M;

	td_cmd_type_offset_bsz = off->td_cmd_type_offset_bsz;
	td_tlen = off->td_tlen;

#if defined(NSE_DEBUG_EXT)
	if (nse_lan_tdm_check_desc_err) {
		tx_ring->tdm_check_desc_err_in_checking = 1;

		tx_ring->tdm_check_desc_err_tlen = td_tlen;
		tx_ring->tdm_check_desc_err_bsize_cnt = 0;
		memset(tx_ring->tdm_check_desc_err_bsize, 0,
		       sizeof(tx_ring->tdm_check_desc_err_bsize));
	}
#endif

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = NSE_TX_DESC(tx_ring, i);

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = NSE_MAX_DATA_PER_TXD_ALIGNED;

		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (NSE_MAX_READ_REQ_SIZE - 1);
		tx_desc->buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		while (unlikely(size > NSE_MAX_DATA_PER_TXD)) {
			tx_desc->cmd_type_offset_bsz =
				nse_build_ctob(tx_ring, td_cmd_type_offset_bsz,
					       td_tlen, max_data, first_td);

			first_td = false;

#if defined(NSE_DEBUG_EXT)

			if (off->debug_print_tx_desc)
				nse_dump_tx_desc(dev, tx_ring->q_index, i, tx_desc);

			if (tx_ring->tdm_check_desc_err_in_checking) {
				tx_ring->tdm_check_desc_err_bsize[tx_ring->tdm_check_desc_err_bsize_cnt] = max_data;
				tx_ring->tdm_check_desc_err_bsize_cnt++;
			}

			nse_test_suite_tvlan(tx_ring, tx_desc, first, skb, off);

			nse_test_suite_tcsum_dump_desc(tx_ring, tx_desc, first, skb);
			nse_test_suite_tso_dump_desc(tx_ring, tx_desc, first, skb);
#endif

			tx_desc++;
			i++;

			if (i == tx_ring->count) {
				tx_desc = NSE_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = NSE_MAX_DATA_PER_TXD_ALIGNED;
			tx_desc->buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->cmd_type_offset_bsz = nse_build_ctob(tx_ring,
							      td_cmd_type_offset_bsz, td_tlen,
							      size, first_td);

		first_td = false;

#if defined(NSE_DEBUG_EXT)
		if (off->debug_print_tx_desc)
			nse_dump_tx_desc(dev, tx_ring->q_index, i, tx_desc);

		if (tx_ring->tdm_check_desc_err_in_checking) {
			tx_ring->tdm_check_desc_err_bsize[tx_ring->tdm_check_desc_err_bsize_cnt] =
				size;
			tx_ring->tdm_check_desc_err_bsize_cnt++;
		}

		nse_test_suite_tvlan(tx_ring, tx_desc, first, skb, off);

		nse_test_suite_tcsum_dump_desc(tx_ring, tx_desc, first, skb);
		nse_test_suite_tso_dump_desc(tx_ring, tx_desc, first, skb);
#endif

		tx_desc++;
		i++;

		if (i == tx_ring->count) {
			tx_desc = NSE_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buf = &tx_ring->tx_buf[i];
	}

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(first->skb);

	/* write last descriptor with RS and EOP bits */
	td_cmd_type_offset_bsz |= (u64)NSE_TXD_EOP_M;

	if (nse_lan_tx_rs_optimize) {
		if (!netdev_xmit_more() ||
		    (NSE_DESC_UNUSED(tx_ring) <= (tx_ring->count >> 1)) ||
				(first->tx_flags & NSE_TX_FLAGS_TSYN)) {
			td_cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;

			record_tx_rs = true;
			tx_rs = i;
		}
	} else
		td_cmd_type_offset_bsz |= (u64)NSE_TXD_RS_M;

	tx_desc->cmd_type_offset_bsz =
			nse_build_ctob(tx_ring, td_cmd_type_offset_bsz, td_tlen, size, first_td);

#if defined(NSE_DEBUG_EXT)

	if (td_cmd_type_offset_bsz & (u64)NSE_TXD_RS_M)
		tx_ring->tx_stats.tx_rs++;
	else
		tx_ring->tx_stats.tx_no_rs++;

	if (off->debug_print_tx_desc)
		nse_dump_tx_desc(dev, tx_ring->q_index, i, tx_desc);

	if (tx_ring->tdm_check_desc_err_in_checking) {
		tx_ring->tdm_check_desc_err_bsize[tx_ring->tdm_check_desc_err_bsize_cnt] = size;
		tx_ring->tdm_check_desc_err_bsize_cnt++;
	}

	nse_test_suite_tvlan(tx_ring, tx_desc, first, skb, off);

	nse_test_suite_tcsum_dump_desc(tx_ring, tx_desc, first, skb);
	nse_test_suite_tso_dump_desc(tx_ring, tx_desc, first, skb);

	nse_test_suite_tcsum_end(tx_ring);
	nse_test_suite_tso_end(tx_ring);

	if (tx_ring->tdm_check_desc_err_in_checking) {
		unsigned int my_idx = 0;
		unsigned int sum_bsize = 0;

		if (!tx_ring->tdm_check_desc_err_tlen)
			dev_err(tx_ring->dev, "tdm_desc_fatal_err: data_desc TLEN==0\n");

		/* error: 2'd3: ddesc bsize is zero */
		for (my_idx = 0; my_idx < tx_ring->tdm_check_desc_err_bsize_cnt; my_idx++) {
			if (!tx_ring->tdm_check_desc_err_bsize[my_idx]) {
				dev_err(tx_ring->dev, "tdm_desc_fatal_err: data_desc[%d] BSIZE==0\n",
								my_idx);
			}
		}

		if (!(first->tx_flags & NSE_TX_FLAGS_TSO)) {
		/* For non-TSO packet (single-send), should
		 *
		 *		TLEN = sum of (BSIZE)
		 */

			for (my_idx = 0; my_idx < tx_ring->tdm_check_desc_err_bsize_cnt; my_idx++)
				sum_bsize += tx_ring->tdm_check_desc_err_bsize[my_idx];

			if (sum_bsize != tx_ring->tdm_check_desc_err_tlen) {
				dev_err(tx_ring->dev, "tdm_desc_fatal_err: non-TSO packet, TLEN != sum of all BSIZE\n");

				dev_err(tx_ring->dev, "\t TLEN = %d\n",
					tx_ring->tdm_check_desc_err_tlen);

				for (my_idx =
				     0; my_idx < tx_ring->tdm_check_desc_err_bsize_cnt; my_idx++) {
					dev_err(tx_ring->dev, "\t BSIZE[%d] = %d\n",
								my_idx,
						tx_ring->tdm_check_desc_err_bsize[my_idx]);
				}
			}
		}
	}

	tx_ring->tdm_check_desc_err_in_checking = 0;	//end for this pkt

#endif

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

	if (nse_lan_tx_rs_optimize && record_tx_rs) {
		tx_ring->tx_rs_array[tx_rs_ntu] = tx_rs;

		tx_rs_ntu++;
		if (tx_rs_ntu == tx_ring->count)
			tx_rs_ntu = 0;

		tx_ring->tx_rs_ntu = tx_rs_ntu;
	}

	nse_maybe_stop_tx(tx_ring, DESC_NEEDED);

	/* notify HW of packet */
	if (nse_lan_tx_no_bql) {
		kick = true;
	} else {
		kick = __netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount,
					      netdev_xmit_more());
	}

	/* don't write TAIL if in reset */
	if (nse_is_reset_in_progress(tx_ring->pf->state))
		kick = false;

	if (kick) {
		/* Make sure the descriptor writes above complete before the
		 * hardware is notified of the new tail.
		 */
		wmb();

		/* notify HW of packet */
		writel_relaxed(i, tx_ring->tail);

#if defined(NSE_DEBUG_EXT)
		if (tx_ring->txr_used_records) {
			i = tx_ring->txr_used_rec_cur_idx;

			tx_ring->txr_used_records[i].used_desc =
				tx_ring->count - NSE_DESC_UNUSED(tx_ring);
			tx_ring->txr_used_records[i].raw_ns = ktime_get_real_ns();

			i++;
			if (i == NSE_TX_RING_USED_RECORD_LEN)
				i = 0;

			tx_ring->txr_used_rec_cur_idx = i;
		}
#endif
	}

	return;

dma_error:
	/* clear DMA mappings for failed tx_buf map */
	for (;;) {
		tx_buf = &tx_ring->tx_buf[i];
		nse_unmap_and_free_tx_buf(tx_ring, tx_buf);
		if (tx_buf == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	dev_kfree_skb_any(skb);
	first->skb = NULL;

	tx_ring->next_to_use = i;
}

/**
 * nse_tx_csum - Enable Tx checksum offloads
 * @first: pointer to the first descriptor
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if checksum offload can't happen, 1 otherwise.
 */
static
int nse_tx_csum(struct nse_ring *tx_ring, struct nse_tx_buf *first,
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
	td_cmd_type_offset_bsz |= (((l2_len >> 1) << NSE_TXD_MACLEN_S) & NSE_TXD_MACLEN_M);

	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP))
		tx_flags |= NSE_TX_FLAGS_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		tx_flags |= NSE_TX_FLAGS_IPV6;

	if (skb->encapsulation) {
		bool gso_partial_ena = false;

		/* define outer network header type */
		if (tx_flags & NSE_TX_FLAGS_IPV4) {
#if defined(NSE_DEBUG_EXT)
			if (nse_lan_tcsum_force_l3) {
				ip.v4->check = 0;
				cd_tunneling_params |= (NSE_TXD_CTX_EIPT_IPV4_CSUM <<
							NSE_TXD_CTX_EIPT_S);
			} else
#endif
				/*  no need to use NSE_TXD_CTX_EIPT_S, because we are first in
				 * nse_tx_ctx_desc->tunneling_params
				 */
				cd_tunneling_params |= (tx_flags & NSE_TX_FLAGS_TSO) ?
					(NSE_TXD_CTX_EIPT_IPV4_CSUM << NSE_TXD_CTX_EIPT_S) :
					(NSE_TXD_CTX_EIPT_IPV4_NO_CSUM << NSE_TXD_CTX_EIPT_S);

			l4_proto = ip.v4->protocol;
		} else if (tx_flags & NSE_TX_FLAGS_IPV6) {
			cd_tunneling_params |= (NSE_TXD_CTX_EIPT_IPV6 << NSE_TXD_CTX_EIPT_S);

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
			cd_tunneling_params |= (NSE_TXD_CTX_L4TUNT_UDP << NSE_TXD_CTX_L4TUNT_S);
			tx_flags |= NSE_TX_FLAGS_TUNNEL;
			break;
		case IPPROTO_GRE:
			cd_tunneling_params |= (NSE_TXD_CTX_L4TUNT_GRE << NSE_TXD_CTX_L4TUNT_S);
			tx_flags |= NSE_TX_FLAGS_TUNNEL;
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			tx_flags |= NSE_TX_FLAGS_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
		default:
			if (tx_flags & NSE_TX_FLAGS_TSO)
				return -1;

			skb_checksum_help(skb);
			return 0;
		}

#ifdef NSE_ADD_PROBES
		if (protocol == htons(ETH_P_IP))
			tx_ring->vsi->back->tx_ip4_cso++;
#endif
		/* compute outer L3 header size */
		cd_tunneling_params |= ((((l4.hdr - ip.hdr) >> 2) << NSE_TXD_CTX_EIPLEN_S)
						& NSE_TXD_CTX_EIPLEN_M);

		/* switch IP header pointer from outer to inner header */
		ip.hdr = skb_inner_network_header(skb);

		/* compute tunnel header size */
		cd_tunneling_params |= ((((ip.hdr - l4.hdr) >> 1) << NSE_TXD_CTX_L4TUNLEN_S)
						& NSE_TXD_CTX_L4TUNLEN_M);

		gso_partial_ena = skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL;
		/* indicate if we need to offload outer UDP header */
		if ((tx_flags & NSE_TX_FLAGS_TSO) && !gso_partial_ena &&
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
		tx_flags &= ~(NSE_TX_FLAGS_IPV4 | NSE_TX_FLAGS_IPV6);
		if (ip.v4->version == 4)
			tx_flags |= NSE_TX_FLAGS_IPV4;
		if (ip.v6->version == 6)
			tx_flags |= NSE_TX_FLAGS_IPV6;
	}

	/* Enable IP checksum offloads */
	if (tx_flags & NSE_TX_FLAGS_IPV4) {
		l4_proto = ip.v4->protocol;
		/* the stack computes the IP header already, the only time we
		 * need the hardware to recompute it is in the case of TSO.
		 */

#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_ip4_cso++;
#endif

		if (tx_flags & NSE_TX_FLAGS_TSO)
			td_cmd_type_offset_bsz |= (NSE_TXD_IIPT_IPV4_CSUM << NSE_TXD_IIPT_S);
#if defined(NSE_DEBUG_EXT)
		else if (nse_lan_tcsum_force_l3) {
			ip.v4->check = 0;
			td_cmd_type_offset_bsz |= (NSE_TXD_IIPT_IPV4_CSUM << NSE_TXD_IIPT_S);
		}
#endif
		else
			td_cmd_type_offset_bsz |= (NSE_TXD_IIPT_IPV4_NO_CSUM << NSE_TXD_IIPT_S);

	} else if (tx_flags & NSE_TX_FLAGS_IPV6) {
		td_cmd_type_offset_bsz |= (NSE_TXD_IIPT_IPV6 << NSE_TXD_IIPT_S);

		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr) {
			func_ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto,
					 &frag_off);
			if (func_ret < 0)
				return -1;
		}
	} else {
#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_l3_cso_err++;
#endif
		return -1;
	}

	/* compute inner L3 header size */
	l3_len = l4.hdr - ip.hdr;
	td_cmd_type_offset_bsz |= (((l3_len >> 2) << NSE_TXD_IPLEN_S) & NSE_TXD_IPLEN_M);

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* enable checksum offloads */
		td_cmd_type_offset_bsz |= (NSE_TXD_L4TYPE_TCP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = l4.tcp->doff;
		td_cmd_type_offset_bsz |= ((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_tcp_cso++;
#endif
		break;

	case IPPROTO_UDP:
		/* enable UDP checksum offload */
		td_cmd_type_offset_bsz |= (NSE_TXD_L4TYPE_UDP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = (sizeof(struct udphdr) >> 2);
		td_cmd_type_offset_bsz |= ((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_udp_cso++;
#endif

		break;

	case IPPROTO_SCTP:
		/* enable SCTP checksum offload */
		td_cmd_type_offset_bsz |= (NSE_TXD_L4TYPE_SCTP << NSE_TXD_L4TYPE_S);

		td_cmd_type_offset_bsz |= NSE_TXD_L4CSUM_M;

		l4_len = sizeof(struct sctphdr) >> 2;
		td_cmd_type_offset_bsz |= ((l4_len << NSE_TXD_L4LEN_S) & NSE_TXD_L4LEN_M);

#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_sctp_cso++;
#endif
		break;

	default:
#ifdef NSE_ADD_PROBES
		tx_ring->vsi->back->tx_l4_cso_err++;
#endif
		if (tx_flags & NSE_TX_FLAGS_TSO)
			return -1;

		skb_checksum_help(skb);
		return 0;
	}

	if (!(tx_flags & NSE_TX_FLAGS_TSO)) {
		tx_flags |= NSE_TX_FLAGS_TCSUM;

#if defined(NSE_DEBUG_EXT)
		tx_ring->tx_stats.tx_tcsum++;
		if (tx_flags & NSE_TX_FLAGS_TUNNEL)
			tx_ring->tx_stats.tx_tcsum_tnl++;
		else
			tx_ring->tx_stats.tx_tcsum_non_tnl++;
#endif
	}

	off->td_cmd_type_offset_bsz = td_cmd_type_offset_bsz;
	off->cd_tunneling_params = cd_tunneling_params;
	off->cd_qw1 = cd_qw1;
	first->tx_flags = tx_flags;

	return 1;
}

/**
 * nse_tx_prepare_vlan_flags - prepare generic Tx VLAN tagging flags for HW
 * @tx_ring: ring to send buffer on
 * @first: pointer to struct nse_tx_buf
 *
 * Checks the skb and set up correspondingly several generic transmit flags
 * related to VLAN tagging for the HW, such as VLAN, DCB, etc.
 */
static void
nse_tx_prepare_vlan_flags(struct nse_ring *tx_ring, struct nse_tx_buf *first)
{
	struct sk_buff *skb = first->skb;

	/* nothing left to do, software offloaded VLAN */
	if (!skb_vlan_tag_present(skb) && eth_type_vlan(skb->protocol))
		return;

	/* the VLAN ethertype/tpid is determined by VSI configuration and netdev
	 * feature flags, which the driver only allows either 802.1Q or 802.1ad
	 * VLAN offloads exclusively so we only care about the VLAN ID here
	 */
	if (skb_vlan_tag_present(skb)) {
		first->tx_flags |= skb_vlan_tag_get(skb) << NSE_TX_FLAGS_VLAN_S;
		if (tx_ring->flags & NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2)
			first->tx_flags |= NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN;
		else
			first->tx_flags |= NSE_TX_FLAGS_HW_VLAN;

#ifdef NSE_ADD_PROBES
		if (tx_ring->netdev->features & NETIF_F_HW_VLAN_CTAG_TX)
			tx_ring->vsi->back->tx_q_vlano++;
		else
			tx_ring->vsi->back->tx_ad_vlano++;
#endif
	}

	nse_tx_prepare_vlan_flags_dcb(tx_ring, first);
}

#ifdef NSE_ADD_PROBES
/**
 * nse_update_gso_cntr - update TSO/USO counter
 * @tx_buf: Tx buffer with necessary data to update counter
 */
static void nse_update_gso_cntr(struct nse_tx_buf *tx_buf)
{
	struct sk_buff *skb = tx_buf->skb;
	struct nse_netdev_priv *np =
		netdev_priv(skb->dev);

	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
		np->vsi->back->udp_segs += tx_buf->gso_segs;
	else
		np->vsi->back->tcp_segs += tx_buf->gso_segs;
}
#endif /* NSE_ADD_PROBES */

/**
 * nse_tso - computes mss and TSO length to prepare for TSO
 * @first: pointer to struct nse_tx_buf
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if TSO can't happen, 1 otherwise.
 */
static
int nse_tso(struct nse_ring *tx_ring, struct nse_tx_buf *first, struct nse_tx_offload_params *off)
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

#if defined(NSE_DEBUG_EXT)
	tx_ring->tx_stats.tx_tso++;
#endif

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize outer IP header fields */
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else {
		ip.v6->payload_len = 0;
	}

	if (skb_shinfo(skb)->gso_type & (SKB_GSO_GRE |
					 SKB_GSO_GRE_CSUM |
					 SKB_GSO_IPXIP4 |
					 SKB_GSO_IPXIP6 |
					 SKB_GSO_UDP_TUNNEL |
					 SKB_GSO_UDP_TUNNEL_CSUM)) {
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

#if defined(NSE_DEBUG_EXT)
		tx_ring->tx_stats.tx_tso_tnl++;

	} else {
		tx_ring->tx_stats.tx_tso_non_tnl++;
#endif
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

	first->tx_flags |= NSE_TX_FLAGS_TSO;
#ifdef NSE_ADD_PROBES
	nse_update_gso_cntr(first);
#endif
	return 1;
}

/**
 * nse_txd_use_count  - estimate the number of descriptors needed for Tx
 * @size: transmit request size in bytes
 *
 * Due to hardware alignment restrictions (4K alignment), we need to
 * assume that we can have no more than 12K of data per descriptor, even
 * though each descriptor can take up to 16K - 1 bytes of aligned memory.
 * Thus, we need to divide by 12K. But division is slow! Instead,
 * we decompose the operation into shifts and one relatively cheap
 * multiply operation.
 *
 * To divide by 12K, we first divide by 4K, then divide by 3:
 *     To divide by 4K, shift right by 12 bits
 *     To divide by 3, multiply by 85, then divide by 256
 *     (Divide by 256 is done by shifting right by 8 bits)
 * Finally, we add one to round up. Because 256 isn't an exact multiple of
 * 3, we'll underestimate near each multiple of 12K. This is actually more
 * accurate as we have 4K - 1 of wiggle room that we can fit into the last
 * segment. For our purposes this is accurate out to 1M which is orders of
 * magnitude greater than our largest possible GSO size.
 *
 * This would then be implemented as:
 *     return (((size >> 12) * 85) >> 8) + NSE_DESCS_FOR_SKB_DATA_PTR;
 *
 * Since multiplication and division are commutative, we can reorder
 * operations into:
 *     return ((size * 85) >> 20) + NSE_DESCS_FOR_SKB_DATA_PTR;
 */
static unsigned int nse_txd_use_count(unsigned int size)
{
	return ((size * 85) >> 20) + NSE_DESCS_FOR_SKB_DATA_PTR;
}

/**
 * nse_xmit_desc_count - calculate number of Tx descriptors needed
 * @skb: send buffer
 *
 * Returns number of data descriptors needed for this skb.
 */
static unsigned int nse_xmit_desc_count(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	unsigned int count = 0, size = skb_headlen(skb);

	for (;;) {
		count += nse_txd_use_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

/**
 * __nse_chk_linearize - Check if there are more than 8 buffers per packet
 * @skb: send buffer
 *
 * Note: This HW can't DMA more than 8 buffers to build a packet on the wire
 * and so we need to figure out the cases where we need to linearize the skb.
 *
 * For TSO we need to count the TSO header and segment payload separately.
 * As such we need to check cases where we have 7 fragments or more as we
 * can potentially require 9 DMA transactions, 1 for the TSO header, 1 for
 * the segment payload in the first descriptor, and another 7 for the
 * fragments.
 */
static bool __nse_chk_linearize(struct sk_buff *skb)
{
	const skb_frag_t *frag, *stale;
	int nr_frags, sum;

	/* no need to check if number of frags is less than 7 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (NSE_MAX_BUF_TXD - 1))
		return false;

	/* We need to walk through the list and validate that each group
	 * of 6 fragments totals at least gso_size.
	 */
	nr_frags -= NSE_MAX_BUF_TXD - 2;
	frag = &skb_shinfo(skb)->frags[0];

	/* Initialize size to the negative value of gso_size minus 1. We
	 * use this as the worst case scenario in which the frag ahead
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
		if (stale_size > NSE_MAX_DATA_PER_TXD) {
			int align_pad = -(skb_frag_off(stale)) &
					(NSE_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= NSE_MAX_DATA_PER_TXD_ALIGNED;
				stale_size -= NSE_MAX_DATA_PER_TXD_ALIGNED;
			} while (stale_size > NSE_MAX_DATA_PER_TXD);
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
 * nse_chk_linearize - Check if there are more than 8 fragments per packet
 * @skb:      send buffer
 * @count:    number of buffers used
 *
 * Note: Our HW can't scatter-gather more than 8 fragments to build
 * a packet on the wire and so we need to figure out the cases where we
 * need to linearize the skb.
 */
static bool nse_chk_linearize(struct sk_buff *skb, unsigned int count)
{
	/* Both TSO and single send will work if count is less than 8 */
	if (likely(count < NSE_MAX_BUF_TXD))
		return false;

	if (skb_is_gso(skb))
		return __nse_chk_linearize(skb);

	/* we can support up to 8 data buffers for a single send */
	return count != NSE_MAX_BUF_TXD;
}

/**
 * nse_tstamp - set up context descriptor for hardware timestamp
 * @tx_ring: pointer to the Tx ring to send buffer on
 * @skb: pointer to the SKB we're sending
 * @first: Tx buffer
 * @off: Tx offload parameters
 */
static void
nse_tstamp(struct nse_ring *tx_ring, struct sk_buff *skb,
	   struct nse_tx_buf *first, struct nse_tx_offload_params *off)
{
	struct nse_hw *hw = &tx_ring->pf->hw;
	s8 idx;

	/* only timestamp the outbound packet if the user has requested it */
	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)))
		return;

	if (!tx_ring->ptp_tx)
		return;

	/* Tx timestamps cannot be sampled when doing TSO */
	if (first->tx_flags & NSE_TX_FLAGS_TSO)
		return;

	/* Grab an open timestamp slot */
	idx = nse_ptp_request_ts(tx_ring->tx_tstamps, skb);

	nse_debug(hw, NSE_DBG_PTP, "[%s] ptp_request_ts() return %d\n", __func__, idx);

	if (idx < 0)
		return;

	off->cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
			     NSE_TXD_CTX_TSYN_M);

	off->cd_control |= (((u16)idx << NSE_TXD_CTX_TSYN_REG_S) & NSE_TXD_CTX_TSYN_REG_M);

	first->tx_flags |= NSE_TX_FLAGS_TSYN;

#if defined(NSE_DEBUG_EXT)
	tx_ring->tx_stats.tx_tsyn++;
#endif
}

/**
 * nse_xmit_frame_ring - Sends buffer on Tx ring
 * @skb: send buffer
 * @tx_ring: ring to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t
nse_xmit_frame_ring(struct sk_buff *skb, struct nse_ring *tx_ring)
{
	struct nse_tx_offload_params offload = { 0 };
	struct nse_vsi *vsi = tx_ring->vsi;
	struct device *dev = tx_ring->dev;
	struct nse_tx_buf *first = NULL;
	struct ethhdr *eth;
	unsigned int count;
	int tso, csum;

	nse_trace(xmit_frame_ring, tx_ring, skb);

	count = nse_xmit_desc_count(skb);
	if (nse_chk_linearize(skb, count)) {
		if (__skb_linearize(skb))
			goto out_drop;
		count = nse_txd_use_count(skb->len);
		tx_ring->tx_stats.tx_linearize++;
	}

	/* need: 1 descriptor per page * PAGE_SIZE/NSE_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_head_len/nse_MAX_DATA_PER_TXD,
	 *       + 4 desc gap to avoid the cache line where head is,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	if (nse_maybe_stop_tx(tx_ring, count + NSE_DESCS_PER_CACHE_LINE +
			      NSE_DESCS_FOR_CTX_DESC)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* prefetch for bql data which is infrequently used */
	netdev_txq_bql_enqueue_prefetchw(txring_txq(tx_ring));

	offload.tx_ring = tx_ring;

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buf[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	first->gso_segs = 1;
	first->tx_flags = 0;

	/* prepare the VLAN tagging flags for Tx */
	nse_tx_prepare_vlan_flags(tx_ring, first);
	if (first->tx_flags & NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN) {
		offload.cd_qw1 |= (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S);
		offload.cd_qw1 |= NSE_TXD_CTX_IL2TAG2_M;

		offload.cd_l2tag2 = (first->tx_flags & NSE_TX_FLAGS_VLAN_M) >> NSE_TX_FLAGS_VLAN_S;

#if defined(NSE_DEBUG_EXT)
		tx_ring->tx_stats.tx_tvlan++;
#endif
	} else if (first->tx_flags & NSE_TX_FLAGS_HW_VLAN) {
		u64 cd_l2tag1 = (first->tx_flags & NSE_TX_FLAGS_VLAN_M) >> NSE_TX_FLAGS_VLAN_S;

		offload.cd_qw1 |= (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S);
		offload.cd_qw1 |= NSE_TXD_CTX_IL2TAG1_M;

		offload.cd_qw1 |= ((cd_l2tag1 << NSE_TXD_CTX_L2TAG1_S) & NSE_TXD_CTX_L2TAG1_M);

#if defined(NSE_DEBUG_EXT)
		tx_ring->tx_stats.tx_tvlan++;
#endif
	}

	offload.td_tlen = skb->len;

	/* set up TSO offload */
	tso = nse_tso(tx_ring, first, &offload);
	if (tso < 0)
		goto out_drop;

	/* always set up Tx checksum offload */
	csum = nse_tx_csum(tx_ring, first, &offload);
	if (csum < 0)
		goto out_drop;

#if defined(NSE_DEBUG_EXT)
	nse_test_suite_tcsum_start(tx_ring, first, skb);

	nse_test_suite_tso_start(tx_ring, first, skb);
#endif

	/* allow CONTROL frames egress from main VSI if FW LLDP disabled */
	eth = (struct ethhdr *)skb_mac_header(skb);
	if (unlikely((skb->priority == TC_PRIO_CONTROL ||
		      eth->h_proto == htons(ETH_P_LLDP)) &&
		     vsi->type == NSE_VSI_PF &&
		     vsi->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_HOST)) {
		offload.cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
					(NSE_TXD_CTX_SWITCH_UPLINK << NSE_TXD_CTX_SWITCH_S));

		nse_debug(&tx_ring->pf->hw, NSE_DBG_LAN, "[%s, %d] sending a LLDP packet or skb->priority == TC_PRIO_CONTROL\n",
						__func__, __LINE__);
	}

	if (nse_loopback_mode == NSE_LOOPBACK_MODE_SWITCH) {
		offload.cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
						(NSE_TXD_CTX_SWITCH_VSI << NSE_TXD_CTX_SWITCH_S) |
						((vsi->vsi_abs_num <<
						 NSE_TXD_CTX_DEST_VSI_S) & NSE_TXD_CTX_DEST_VSI_M));
	}

	nse_tstamp(tx_ring, skb, first, &offload);

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	if (nse_is_switchdev_running(vsi->back))
		nse_eswitch_set_target_vsi(skb, &offload);
#endif /* CONFIG_NET_DEVLINK */

	if (nse_lan_tx_not_use_ctx_desc &&
	    (offload.cd_qw1 & (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S))) {
		nse_debug(&tx_ring->pf->hw, NSE_DBG_LAN, "[%s, %d] BAD: send a packet need tx-context-desc, drop it\n",
						__func__, __LINE__);

		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (offload.cd_qw1 & (NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S)) {
		struct nse_tx_ctx_desc *cdesc;
		u16 i = tx_ring->next_to_use, dump_desc_idx;

		dump_desc_idx = i;

		/* grab the next descriptor */
		cdesc = NSE_TX_CTX_DESC(tx_ring, i);
		i++;
		tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

#if defined(NSE_DEBUG_EXT)
		if (nse_lan_tdm_check_desc_err) {
			u64 qabs = tx_ring->reg_idx + vsi->back->lan_txq_space_start;

			if (!(offload.cd_qw1 & NSE_TXD_CTX_IL2TAG2_M))
				offload.cd_l2tag2 = (u16)qabs;

			if (!(offload.cd_qw1 & NSE_TXD_CTX_IL2TAG1_M)) {
				offload.cd_qw1 |= ((qabs <<
						   NSE_TXD_CTX_L2TAG1_S) & NSE_TXD_CTX_L2TAG1_M);
			}
		}
#endif

		/* setup context descriptor */
		cdesc->tunneling_params = cpu_to_le32(offload.cd_tunneling_params);
		cdesc->l2tag2 = cpu_to_le16(offload.cd_l2tag2);
		cdesc->control = cpu_to_le16(offload.cd_control);
		cdesc->qw1 = cpu_to_le64(offload.cd_qw1);

#if defined(NSE_DEBUG_EXT)

		tx_ring->tx_stats.tx_use_ctx_desc++;

		nse_test_suite_tvlan(tx_ring, (struct nse_tx_desc *)cdesc, first, skb, &offload);

		nse_test_suite_tcsum_dump_desc(tx_ring, (struct nse_tx_desc *)cdesc, first, skb);
		nse_test_suite_tso_dump_desc(tx_ring, (struct nse_tx_desc *)cdesc, first, skb);

		if (offload.debug_print_tx_desc)
			nse_dump_tx_desc(dev, tx_ring->q_index, dump_desc_idx,
					 (struct nse_tx_desc *)cdesc);
	} else {
		tx_ring->tx_stats.tx_not_use_ctx_desc++;
#endif
	}

#if defined(NSE_DEBUG_EXT)
	if (first->tx_flags &
		(NSE_TX_FLAGS_TSO | NSE_TX_FLAGS_TCSUM | NSE_TX_FLAGS_TSYN |
		NSE_TX_FLAGS_HW_VLAN | NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN))
		tx_ring->tx_stats.tx_offload++;
	else
		tx_ring->tx_stats.tx_non_offload++;
#endif

	nse_tx_map(tx_ring, first, &offload);
	return NETDEV_TX_OK;

out_drop:
	nse_trace(xmit_frame_ring_drop, tx_ring, skb);
	dev_kfree_skb_any(skb);
	if (first && first->skb)
		first->skb = NULL;

	return NETDEV_TX_OK;
}

/**
 * nse_start_xmit - Selects the correct VSI and Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t nse_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_ring *tx_ring;

	if (nse_is_reset_in_progress(pf->state)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	tx_ring = vsi->tx_rings[skb->queue_mapping];

#if defined(NSE_DEBUG_EXT)
	/* when running VMDQ macvlan_offload.
	 *
	 * netdev is PF_netdev and np->vsi is PF-main-VSI, but
	 * selected tx_ring might be macvlan-VSI (type == NSE_VSI_OFFLOAD_MACVLAN )
	 * which is logically save to PF_netdev/PF-main-VSI.
	 *
	 * so we need to get real VSI from tx_ring->vsi.
	 */
	vsi = tx_ring->vsi;

	if (vsi->debug_lan_no_xmit) {
		dev_kfree_skb_any(skb);

		return NETDEV_TX_OK;
	}
#endif

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, NSE_MIN_TX_LEN))
		return NETDEV_TX_OK;

	return nse_xmit_frame_ring(skb, tx_ring);
}

