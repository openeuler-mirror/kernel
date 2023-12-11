// SPDX-License-Identifier: GPL-2.0
#include "ys_k2_core.h"

int ysk2_create_tx_ring(struct ysk2_port *k2port, u32 index, u32 size,
			u8 max_frags)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);
	struct ysk2_desc_ring *tx_ring;
	int size_tx_info;
	int ret;

	tx_ring = kzalloc(sizeof(*tx_ring), GFP_KERNEL);
	if (!tx_ring)
		return -ENOMEM;

	/* sg support */
	max_frags = min_t(u8, roundup_pow_of_two(max_frags), YSK2_MAX_FRAGS);
	tx_ring->tx_max_sg_frags = max_frags - 1;
	tx_ring->ring.k2port = k2port;
	ret = ysk2_alloc_ring(&tx_ring->ring, size, YSK2_DESC_SIZE * max_frags);
	if (ret)
		goto err_with_ring;

	size_tx_info = sizeof(struct ysk2_tx_info);
	tx_ring->tx_info = kzalloc(size_tx_info * tx_ring->ring.size,
				   GFP_KERNEL);

	if (!tx_ring->tx_info) {
		ret = -ENOMEM;
		goto err_with_alloc;
	}

	tx_ring->is_txring = 1;
	tx_ring->ring.qid = ndev_priv->qbase + index;
	tx_ring->ring.hw_addr = k2port->k2nic->hw_addr +
				YSK2_CHN_TXQ_BASE(tx_ring->ring.qid);

	k2port->qps[index].tx_ring = tx_ring;

	return 0;

err_with_alloc:
	ysk2_free_ring(&tx_ring->ring);
err_with_ring:
	kfree(tx_ring);

	return ret;
}

void ysk2_destroy_tx_ring(struct ysk2_desc_ring **ring_ptr)
{
	struct ysk2_desc_ring *tx_ring = *ring_ptr;
	*ring_ptr = NULL;

	kvfree(tx_ring->tx_info);
	ysk2_free_ring(&tx_ring->ring);
	kfree(tx_ring);
}

static int ysk2_map_skb(struct ysk2_ring *ring, struct ysk2_tx_info *tx_info,
			struct ysk2_desc *tx_desc, struct sk_buff *skb)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ring->k2port->ndev);
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	const skb_frag_t *frag;
	dma_addr_t dma_addr;
	u32 i, len;

	/* update tx_info */
	tx_info->skb = skb;
	tx_info->frag_count = 0;

	for (i = 0; i < shinfo->nr_frags; i++) {
		frag = &shinfo->frags[i];
		len = skb_frag_size(frag);
		/* Map and refresh */
		dma_addr = skb_frag_dma_map(ring->k2port->dev, frag, 0, len,
					    DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(ring->k2port->dev, dma_addr)))
			goto err_with_map;

		/* write descriptor */
		tx_desc[i + 1].len = cpu_to_le32(len);
		tx_desc[i + 1].addr = cpu_to_le64(dma_addr);

		/* update tx_info */
		tx_info->frag_count = i + 1;
		tx_info->frags[i].len = len;
		tx_info->frags[i].dma_addr = dma_addr;
	}

	/* clear unused descs */
	for (i = tx_info->frag_count; i < (ring->stride / YSK2_DESC_SIZE) - 1;
	     i++) {
		tx_desc[i + 1].len = 0;
		tx_desc[i + 1].addr = 0;
	}

	/* map skb linear area */
	len = skb_headlen(skb);
	dma_addr = dma_map_single(ring->k2port->dev,
				  skb->data, len, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(ring->k2port->dev, dma_addr)))
		goto err_with_map;

	/* write descriptor */
	tx_desc[0].len = cpu_to_le32(len);
	tx_desc[0].addr = cpu_to_le64(dma_addr);

	/* update tx_info */
	tx_info->dma_addr = dma_addr;
	tx_info->len = len;

	return 0;

err_with_map:
	ys_net_err("DMA mapping failed\n");

	/* unmap frags */
	for (i = 0; i < tx_info->frag_count; i++)
		dma_unmap_page(ring->k2port->dev, tx_info->frags[i].dma_addr,
			       tx_info->frags[i].len, DMA_TO_DEVICE);

	/* update tx_info */
	tx_info->skb = NULL;
	tx_info->frag_count = 0;

	return -ENOMEM;
}

netdev_tx_t ysk2_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	struct ysk2_port *k2port = ndev_priv->adp_priv;
	struct ysk2_desc_ring *tx_ring;
	u32 desc_index, clean_tail_ptr;
	struct ysk2_tx_info *tx_info;
	struct ysk2_desc *tx_desc;
	bool stop_queue;
	u16 txq_index;

	if (unlikely(!(ndev->flags & IFF_UP)))
		goto tx_drop;

	txq_index = skb_get_queue_mapping(skb);
	tx_ring = k2port->qps[txq_index].tx_ring;

	clean_tail_ptr = READ_ONCE(tx_ring->ring.clean_tail_ptr);

	desc_index = tx_ring->ring.head_ptr & tx_ring->ring.size_mask;

	tx_desc = (struct ysk2_desc *)(tx_ring->ring.buf +
				       desc_index * tx_ring->ring.stride);

	tx_info = &tx_ring->tx_info[desc_index];

	/* too many frags or very short data portion; linearize */
	if (shinfo->nr_frags > tx_ring->tx_max_sg_frags ||
	    (skb->data_len && skb->data_len < 32)) {
		if (skb_linearize(skb))
			goto tx_drop_count;
	}

	/* Refresh the cache through streaming mapping */
	if (ysk2_map_skb(&tx_ring->ring, tx_info, tx_desc, skb))
		goto tx_drop_count;

	/* count packet */
	tx_ring->packets++;
	tx_ring->bytes += skb->len;

	/* enqueue */
	tx_ring->ring.head_ptr++;

	skb_tx_timestamp(skb);

	/* if the tx_ring is full now, stop the tx queue */
	stop_queue = ysk2_is_ring_full(&tx_ring->ring);
	if (unlikely(stop_queue)) {
		ys_net_debug("TX ring %d full\n", txq_index);
		netif_tx_stop_queue(tx_ring->tx_queue);
	}

	/* enqueue on NIC */
	if (unlikely(!netdev_xmit_more() || stop_queue))
		ysk2_write_head_ptr(&tx_ring->ring);

	/* check if queue restarted */
	if (unlikely(stop_queue)) {
		clean_tail_ptr = READ_ONCE(tx_ring->ring.clean_tail_ptr);

		if (unlikely(!ysk2_is_ring_full(&tx_ring->ring)))
			netif_tx_wake_queue(tx_ring->tx_queue);
	}

	return NETDEV_TX_OK;

tx_drop_count:
	tx_ring->dropped_packets++;
tx_drop:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/* unmap and release skb */
static void ysk2_free_tx_desc(struct ysk2_desc_ring *tx_ring, int index,
			      int napi_budget)
{
	struct ysk2_tx_info *tx_info = &tx_ring->tx_info[index];
	struct sk_buff *skb = tx_info->skb;
	u32 i;

	prefetchw(&skb->users);

	/* unmap skb linear area */
	dma_unmap_single(tx_ring->ring.k2port->dev, tx_info->dma_addr,
			 tx_info->len, DMA_TO_DEVICE);

	/* unmap frags */
	for (i = 0; i < tx_info->frag_count; i++)
		dma_unmap_page(tx_ring->ring.k2port->dev,
			       tx_info->frags[i].dma_addr,
			       tx_info->frags[i].len, DMA_TO_DEVICE);

	napi_consume_skb(skb, napi_budget);

	/* skb have been consumed */
	tx_info->skb = NULL;
}

int ysk2_free_tx_buf(struct ysk2_desc_ring *tx_ring)
{
	int cnt = 0;
	u32 index;

	while (!ysk2_is_ring_empty(&tx_ring->ring)) {
		index = tx_ring->ring.clean_tail_ptr & tx_ring->ring.size_mask;
		ysk2_free_tx_desc(tx_ring, index, 0);
		tx_ring->ring.clean_tail_ptr++;
		cnt++;
	}
	tx_ring->ring.head_ptr = 0;
	tx_ring->ring.tail_ptr = 0;
	tx_ring->ring.clean_tail_ptr = 0;

	return cnt;
}

int ysk2_process_tx_cq(struct ysk2_cq_ring *cq_ring, int napi_budget)
{
	struct ysk2_desc_ring *tx_ring = cq_ring->src_ring;
	struct skb_shared_hwtstamps hwts;
	struct ys_ndev_priv *ndev_priv;
	struct ysk2_tx_info *tx_info;
	struct ysk2_port *k2port;
	u32 ring_clean_tail_ptr;
	struct ysk2_cpl *cpl;
	u32 cq_tail_ptr;
	u32 desc_index;
	u32 cq_index;
	int done = 0;

	k2port = tx_ring->ring.k2port;
	if (unlikely(!k2port))
		return done;

	ndev_priv = netdev_priv(k2port->ndev);
	if (unlikely(!(ndev_priv->ndev->flags & IFF_UP)))
		return done;

	/* read head pointer from NIC */
	ysk2_read_head_ptr(&cq_ring->ring);

	cq_tail_ptr = cq_ring->ring.tail_ptr;
	cq_index = cq_tail_ptr & cq_ring->ring.size_mask;

	while (cq_ring->ring.head_ptr != cq_tail_ptr && done < napi_budget) {
		cpl = (struct ysk2_cpl *)cq_ring->ring.buf + cq_index;
		desc_index = le16_to_cpu(cpl->index) & tx_ring->ring.size_mask;
		tx_info = &tx_ring->tx_info[desc_index];

		/* TX hardware timestamp */
		if (unlikely(tx_info->ts_requested)) {
			ys_net_debug("TX TS requested\n");
			skb_tstamp_tx(tx_info->skb, &hwts);
		}

		/* free TX descriptor */
		ysk2_free_tx_desc(tx_ring, desc_index, napi_budget);

		done++;
		cq_tail_ptr++;
		cq_index = cq_tail_ptr & cq_ring->ring.size_mask;
	}

	/* update CQ tail */
	cq_ring->ring.tail_ptr = cq_tail_ptr;
	ysk2_write_tail_ptr(&cq_ring->ring);

	/* process tx ring, update clean tail */
	ysk2_read_tail_ptr(&tx_ring->ring);

	ring_clean_tail_ptr = READ_ONCE(tx_ring->ring.clean_tail_ptr);
	desc_index = ring_clean_tail_ptr & tx_ring->ring.size_mask;

	while (ring_clean_tail_ptr != tx_ring->ring.tail_ptr) {
		tx_info = &tx_ring->tx_info[desc_index];

		/* napi weight less than packet to process */
		if (unlikely(tx_info->skb))
			break;

		ring_clean_tail_ptr++;
		desc_index = ring_clean_tail_ptr & tx_ring->ring.size_mask;
	}

	/* update ring tail */
	WRITE_ONCE(tx_ring->ring.clean_tail_ptr, ring_clean_tail_ptr);

	/* wake queue if it is stopped */
	if (netif_tx_queue_stopped(tx_ring->tx_queue) &&
	    !ysk2_is_ring_full(&tx_ring->ring))
		netif_tx_wake_queue(tx_ring->tx_queue);

	return done;
}
