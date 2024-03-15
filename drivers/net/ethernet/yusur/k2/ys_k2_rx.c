// SPDX-License-Identifier: GPL-2.0

#include "ys_k2_core.h"

int ysk2_create_rx_ring(struct ysk2_port *k2port, u32 index, u32 size)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2port->ndev);
	struct ysk2_desc_ring *rx_ring;
	int size_rx_info;
	int ret;

	rx_ring = kzalloc(sizeof(*rx_ring), GFP_KERNEL);
	if (!rx_ring)
		return -ENOMEM;

	rx_ring->ring.k2port = k2port;
	ret = ysk2_alloc_ring(&rx_ring->ring, size, YSK2_DESC_SIZE);
	if (ret)
		goto err_with_ring;

	size_rx_info = sizeof(struct ysk2_rx_info);
	rx_ring->rx_info = kzalloc(size_rx_info * rx_ring->ring.size,
				   GFP_KERNEL);

	if (!rx_ring->rx_info) {
		ret = -ENOMEM;
		goto err_with_alloc;
	}

	rx_ring->ring.qid = ndev_priv->qbase + index;
	rx_ring->ring.hw_addr = k2port->k2nic->hw_addr +
				YSK2_CHN_RXQ_BASE(rx_ring->ring.qid);

	k2port->qps[index].rx_ring = rx_ring;

	return 0;

err_with_alloc:
	ysk2_free_ring(&rx_ring->ring);
err_with_ring:
	kfree(rx_ring);

	return ret;
}

void ysk2_destroy_rx_ring(struct ysk2_desc_ring **ring_ptr)
{
	struct ysk2_desc_ring *rx_ring = *ring_ptr;
	*ring_ptr = NULL;

	kvfree(rx_ring->rx_info);
	ysk2_free_ring(&rx_ring->ring);
	kfree(rx_ring);
}

static int ysk2_prepare_rx_desc(struct ysk2_desc_ring *rx_ring, u32 index)
{
	struct ysk2_rx_info *rx_info = &rx_ring->rx_info[index];
	struct ysk2_port *k2port = rx_ring->ring.k2port;
	u32 page_order = rx_ring->page_order;
	u32 len = PAGE_SIZE << page_order;
	struct page *page = rx_info->page;
	struct ys_ndev_priv *ndev_priv;
	struct ysk2_desc *rx_desc;
	dma_addr_t dma_addr;
	int ret;

	ndev_priv = netdev_priv(k2port->ndev);

	/* old page must be ownered by network stack */
	if (unlikely(page)) {
		ys_net_err("skb not yet processed!\n");
		return -EINVAL;
	}

	/* alloc frag page */
	page = dev_alloc_pages(page_order);
	if (unlikely(!page)) {
		ys_net_warn("failed to alloc memory page_order: %u, qid: %u, index: %d\n",
			    page_order, rx_ring->ring.qid, index);
		return -ENOMEM;
	}

	/* map page */
	dma_addr = dma_map_page(k2port->dev, page, 0, len, DMA_FROM_DEVICE);
	if (unlikely(dma_mapping_error(k2port->dev, dma_addr))) {
		ys_net_err("DMA mapping failed!\n");
		ret = -ENOMEM;
		goto err_with_page;
	}

	/* write descriptor */
	rx_desc = (struct ysk2_desc *)(rx_ring->ring.buf +
				       index * rx_ring->ring.stride);
	rx_desc->len = cpu_to_le32(len);
	rx_desc->addr = cpu_to_le64(dma_addr);

	/* update rx_info */
	rx_info->page = page;
	rx_info->page_order = page_order;
	rx_info->page_offset = 0;
	rx_info->dma_addr = dma_addr;
	rx_info->len = len;

	return 0;

err_with_page:
	__free_pages(page, page_order);

	return ret;
}

static void ysk2_free_rx_desc(struct ysk2_desc_ring *rx_ring, u32 index)
{
	struct ysk2_rx_info *rx_info = &rx_ring->rx_info[index];
	struct page *page = rx_info->page;

	dma_unmap_page(rx_ring->ring.k2port->dev, rx_info->dma_addr,
		       rx_info->len, DMA_FROM_DEVICE);
	__free_pages(page, rx_info->page_order);

	/* page must be set to NULL for next refill */
	rx_info->page = NULL;
}

static void ysk2_refill_rx_buffers(struct ysk2_desc_ring *rx_ring)
{
	u32 missing, index;

	missing = rx_ring->ring.size -
		  (rx_ring->ring.head_ptr - rx_ring->ring.clean_tail_ptr);
	if (missing < 8)
		return;

	while (missing) {
		index = rx_ring->ring.head_ptr & rx_ring->ring.size_mask;
		if (ysk2_prepare_rx_desc(rx_ring, index))
			break;
		rx_ring->ring.head_ptr++;
		missing--;
	}

	/* enqueue on NIC */
	ysk2_write_head_ptr(&rx_ring->ring);
}

int ysk2_init_rx_buf(struct ysk2_desc_ring *rx_ring)
{
	ysk2_refill_rx_buffers(rx_ring);

	return !ysk2_is_ring_full(&rx_ring->ring);
}

int ysk2_free_rx_buf(struct ysk2_desc_ring *rx_ring)
{
	int cnt = 0;
	u32 index;

	while (!ysk2_is_ring_empty(&rx_ring->ring)) {
		index = rx_ring->ring.clean_tail_ptr & rx_ring->ring.size_mask;
		ysk2_free_rx_desc(rx_ring, index);
		rx_ring->ring.clean_tail_ptr++;
		cnt++;
	}

	rx_ring->ring.head_ptr = 0;
	rx_ring->ring.tail_ptr = 0;
	rx_ring->ring.clean_tail_ptr = 0;

	return cnt;
}

int ysk2_process_rx_cq(struct ysk2_cq_ring *cq_ring, int napi_budget)
{
	struct ysk2_desc_ring *rx_ring = cq_ring->src_ring;
	struct ys_ndev_priv *ndev_priv;
	struct ysk2_rx_info *rx_info;
	struct ysk2_port *k2port;
	u32 ring_clean_tail_ptr;
	struct ysk2_cpl *cpl;
	struct sk_buff *skb;
	struct page *page;
	u32 cq_index;
	u32 cq_tail_ptr;
	u32 desc_index;
	int done = 0;
	u32 len;

	k2port = rx_ring->ring.k2port;
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
		desc_index = le16_to_cpu(cpl->index) & rx_ring->ring.size_mask;
		rx_info = &rx_ring->rx_info[desc_index];
		page = rx_info->page;

		if (unlikely(!page)) {
			ys_net_err("rxcq ring %d get null page at index %d\n",
				   cq_ring->ring.qid, desc_index);
			break;
		}

		/* alloc skb */
		skb = napi_get_frags(&cq_ring->napi);
		if (unlikely(!skb)) {
			ys_net_err("ring %d failed to allocate skb\n",
				   cq_ring->ring.qid);
			break;
		}

		/* skb record queue index */
		skb_record_rx_queue(skb, rx_ring->ring.qid - ndev_priv->qbase);

		/* unmap */
		dma_unmap_page(&ndev_priv->pdev->dev, rx_info->dma_addr,
			       rx_info->len, DMA_FROM_DEVICE);
		rx_info->dma_addr = 0;

		len = min_t(u32, le16_to_cpu(cpl->len), rx_info->len);
		if (len == 0) {
			/* recv err len */
			ys_net_err("packet len err\n");
			break;
		}

		__skb_fill_page_desc(skb, 0, page, rx_info->page_offset, len);
		rx_info->page = NULL;

		skb_shinfo(skb)->nr_frags = 1;
		skb->len = len;
		skb->data_len = len;
		skb->truesize += rx_info->len;

		/* hand off SKB */
		napi_gro_frags(&cq_ring->napi);

		rx_ring->packets++;
		rx_ring->bytes += le16_to_cpu(cpl->len);

		done++;

		cq_tail_ptr++;
		cq_index = cq_tail_ptr & cq_ring->ring.size_mask;
	}

	/* update CQ tail */
	cq_ring->ring.tail_ptr = cq_tail_ptr;
	ysk2_write_tail_ptr(&cq_ring->ring);

	/* process rx ring, update clean tail */
	ysk2_read_tail_ptr(&rx_ring->ring);

	ring_clean_tail_ptr = READ_ONCE(rx_ring->ring.clean_tail_ptr);
	desc_index = ring_clean_tail_ptr & rx_ring->ring.size_mask;

	while (ring_clean_tail_ptr != rx_ring->ring.tail_ptr) {
		rx_info = &rx_ring->rx_info[desc_index];

		/* napi weight less than packet to process */
		if (unlikely(rx_info->page))
			break;

		ring_clean_tail_ptr++;
		desc_index = ring_clean_tail_ptr & rx_ring->ring.size_mask;
	}

	/* update ring tail */
	WRITE_ONCE(rx_ring->ring.clean_tail_ptr, ring_clean_tail_ptr);

	/* replenish buffers */
	ysk2_refill_rx_buffers(rx_ring);

	return done;
}
