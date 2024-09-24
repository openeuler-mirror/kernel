// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/sctp.h>
#include <net/page_pool/helpers.h>

#include "nbl_txrx.h"

int nbl_alloc_tx_rings(struct nbl_resource_mgt *res_mgt, struct net_device *netdev,
		       u16 tx_num, u16 desc_num)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_tx_ring *ring;
	u32 ring_index;

	if (txrx_mgt->tx_rings) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to allocate tx_rings which already exists\n");
		return -EINVAL;
	}

	txrx_mgt->tx_ring_num = tx_num;

	txrx_mgt->tx_rings = devm_kcalloc(dev, tx_num,
					  sizeof(struct nbl_res_tx_ring *), GFP_KERNEL);
	if (!txrx_mgt->tx_rings)
		return -ENOMEM;

	for (ring_index = 0; ring_index < tx_num; ring_index++) {
		ring = txrx_mgt->tx_rings[ring_index];
		WARN_ON(ring);
		ring = devm_kzalloc(dev, sizeof(struct nbl_res_tx_ring), GFP_KERNEL);
		if (!ring)
			goto alloc_tx_ring_failed;

		ring->dma_dev = common->dma_dev;
		ring->product_type = common->product_type;
		ring->eth_id = common->eth_id;
		ring->queue_index = ring_index;
		ring->notify_addr = phy_ops->get_tail_ptr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
		ring->notify_qid = NBL_RES_NOFITY_QID(res_mgt, ring_index * 2 + 1);
		ring->netdev = netdev;
		ring->desc_num = desc_num;
		ring->used_wrap_counter = 1;
		ring->avail_used_flags |= BIT(NBL_PACKED_DESC_F_AVAIL);
		WRITE_ONCE(txrx_mgt->tx_rings[ring_index], ring);
	}

	return 0;

alloc_tx_ring_failed:
	while (ring_index--)
		devm_kfree(dev, txrx_mgt->tx_rings[ring_index]);
	devm_kfree(dev, txrx_mgt->tx_rings);
	txrx_mgt->tx_rings = NULL;
	return -ENOMEM;
}

static void nbl_free_tx_rings(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct nbl_res_tx_ring *ring;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u16 ring_count;
	u16 ring_index;

	ring_count = txrx_mgt->tx_ring_num;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = txrx_mgt->tx_rings[ring_index];
		devm_kfree(dev, ring);
	}
	devm_kfree(dev, txrx_mgt->tx_rings);
	txrx_mgt->tx_rings = NULL;
}

static int nbl_alloc_rx_rings(struct nbl_resource_mgt *res_mgt, struct net_device *netdev,
			      u16 rx_num, u16 desc_num)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_rx_ring *ring;
	u32 ring_index;

	if (txrx_mgt->rx_rings) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to allocate rx_rings which already exists\n");
		return -EINVAL;
	}

	txrx_mgt->rx_ring_num = rx_num;

	txrx_mgt->rx_rings = devm_kcalloc(dev, rx_num,
					  sizeof(struct nbl_res_rx_ring *), GFP_KERNEL);
	if (!txrx_mgt->rx_rings)
		return -ENOMEM;

	for (ring_index = 0; ring_index < rx_num; ring_index++) {
		ring = txrx_mgt->rx_rings[ring_index];
		WARN_ON(ring);
		ring = devm_kzalloc(dev, sizeof(struct nbl_res_rx_ring), GFP_KERNEL);
		if (!ring)
			goto alloc_rx_ring_failed;

		ring->common = common;
		ring->txrx_mgt = txrx_mgt;
		ring->dma_dev = common->dma_dev;
		ring->queue_index = ring_index;
		ring->notify_qid = NBL_RES_NOFITY_QID(res_mgt, ring_index * 2);
		ring->netdev = netdev;
		ring->desc_num = desc_num;
		/* TODO: maybe TX buffer length should be determined by other factors */
		ring->buf_len = NBL_RX_BUFSZ - NBL_RX_PAD;

		ring->used_wrap_counter = 1;
		ring->avail_used_flags |= BIT(NBL_PACKED_DESC_F_AVAIL);
		WRITE_ONCE(txrx_mgt->rx_rings[ring_index], ring);
	}

	return 0;

alloc_rx_ring_failed:
	while (ring_index--)
		devm_kfree(dev, txrx_mgt->rx_rings[ring_index]);
	devm_kfree(dev, txrx_mgt->rx_rings);
	txrx_mgt->rx_rings = NULL;
	return -ENOMEM;
}

static void nbl_free_rx_rings(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct nbl_res_rx_ring *ring;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u16 ring_count;
	u16 ring_index;

	ring_count = txrx_mgt->rx_ring_num;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = txrx_mgt->rx_rings[ring_index];
		devm_kfree(dev, ring);
	}
	devm_kfree(dev, txrx_mgt->rx_rings);
	txrx_mgt->rx_rings = NULL;
}

static int nbl_alloc_vectors(struct nbl_resource_mgt *res_mgt, u16 num)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_vector *vector;
	u32 index;

	if (txrx_mgt->vectors) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to allocate vectors which already exists\n");
		return -EINVAL;
	}

	txrx_mgt->vectors = devm_kcalloc(dev, num, sizeof(struct nbl_res_vector *), GFP_KERNEL);
	if (!txrx_mgt->vectors)
		return -ENOMEM;

	for (index = 0; index < num; index++) {
		vector = txrx_mgt->vectors[index];
		WARN_ON(vector);
		vector = devm_kzalloc(dev, sizeof(struct nbl_res_vector), GFP_KERNEL);
		if (!vector)
			goto alloc_vector_failed;

		vector->rx_ring = txrx_mgt->rx_rings[index];
		vector->tx_ring = txrx_mgt->tx_rings[index];
		WRITE_ONCE(txrx_mgt->vectors[index], vector);
	}

	return 0;

alloc_vector_failed:
	while (index--)
		devm_kfree(dev, txrx_mgt->vectors[index]);
	devm_kfree(dev, txrx_mgt->vectors);
	txrx_mgt->vectors = NULL;
	return -ENOMEM;
}

static void nbl_free_vectors(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct nbl_res_vector *vector;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	u16 count, index;

	count = txrx_mgt->rx_ring_num;
	for (index = 0; index < count; index++) {
		vector = txrx_mgt->vectors[index];
		devm_kfree(dev, vector);
	}
	devm_kfree(dev, txrx_mgt->vectors);
	txrx_mgt->vectors = NULL;
}

static int nbl_res_txrx_alloc_rings(void *priv, struct net_device *netdev, u16 tx_num,
				    u16 rx_num, u16 tx_desc_num, u16 rx_desc_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int err = 0;

	err = nbl_alloc_tx_rings(res_mgt, netdev, tx_num, tx_desc_num);
	if (err)
		return err;

	err = nbl_alloc_rx_rings(res_mgt, netdev, rx_num, rx_desc_num);
	if (err)
		goto alloc_rx_rings_err;

	err = nbl_alloc_vectors(res_mgt, rx_num);
	if (err)
		goto alloc_vectors_err;

	nbl_info(res_mgt->common, NBL_DEBUG_RESOURCE,
		 "Alloc rings for %d tx, %d rx, %d tx_desc %d rx_desc\n",
		 tx_num, rx_num, tx_desc_num, rx_desc_num);
	return 0;

alloc_vectors_err:
	nbl_free_rx_rings(res_mgt);
alloc_rx_rings_err:
	nbl_free_tx_rings(res_mgt);
	return err;
}

static void nbl_res_txrx_remove_rings(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	nbl_free_vectors(res_mgt);
	nbl_free_tx_rings(res_mgt);
	nbl_free_rx_rings(res_mgt);
	nbl_info(res_mgt->common, NBL_DEBUG_RESOURCE, "Remove rings");
}

static dma_addr_t nbl_res_txrx_start_tx_ring(void *priv, u8 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index);

	if (tx_ring->tx_bufs) {
		nbl_err(res_mgt->common, NBL_DEBUG_RESOURCE,
			"Try to setup a TX ring with buffer management array already allocated\n");
		return (dma_addr_t)NULL;
	}

	tx_ring->tx_bufs = devm_kcalloc(dev, tx_ring->desc_num, sizeof(*tx_ring->tx_bufs),
					GFP_KERNEL);
	if (!tx_ring->tx_bufs)
		return (dma_addr_t)NULL;

	/* Alloc twice memory, and second half is used to back up the desc for desc checking */
	tx_ring->size = ALIGN(tx_ring->desc_num * sizeof(struct nbl_ring_desc), PAGE_SIZE);
	tx_ring->desc = dmam_alloc_coherent(dma_dev, tx_ring->size, &tx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);
	if (!tx_ring->desc)
		goto alloc_dma_err;

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->tail_ptr = 0;

	tx_ring->valid = true;
	nbl_debug(res_mgt->common, NBL_DEBUG_RESOURCE, "Start tx ring %d", ring_index);
	return tx_ring->dma;

alloc_dma_err:
	devm_kfree(dev, tx_ring->tx_bufs);
	tx_ring->tx_bufs = NULL;
	tx_ring->size = 0;
	return (dma_addr_t)NULL;
}

static inline bool nbl_rx_cache_get(struct nbl_res_rx_ring *rx_ring, struct nbl_dma_info *dma_info)
{
	struct nbl_page_cache *cache = &rx_ring->page_cache;
	struct nbl_rx_queue_stats *stats = &rx_ring->rx_stats;

	if (unlikely(cache->head == cache->tail)) {
		stats->rx_cache_empty++;
		return false;
	}

	if (page_ref_count(cache->page_cache[cache->head].page) != 1) {
		stats->rx_cache_busy++;
		return false;
	}

	*dma_info = cache->page_cache[cache->head];
	cache->head = (cache->head + 1) & (NBL_MAX_CACHE_SIZE - 1);
	stats->rx_cache_reuse++;

	dma_sync_single_for_device(rx_ring->dma_dev, dma_info->addr, PAGE_SIZE, DMA_FROM_DEVICE);
	return true;
}

static inline int nbl_page_alloc_pool(struct nbl_res_rx_ring *rx_ring,
				      struct nbl_dma_info *dma_info)
{
	if (nbl_rx_cache_get(rx_ring, dma_info))
		return 0;

	dma_info->page = page_pool_dev_alloc_pages(rx_ring->page_pool);
	if (unlikely(!dma_info->page))
		return -ENOMEM;

	dma_info->addr = dma_map_page_attrs(rx_ring->dma_dev, dma_info->page, 0, PAGE_SIZE,
					    DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);

	if (unlikely(dma_mapping_error(rx_ring->dma_dev, dma_info->addr))) {
		page_pool_recycle_direct(rx_ring->page_pool, dma_info->page);
		dma_info->page = NULL;
		return -ENOMEM;
	}

	return 0;
}

static inline int nbl_get_rx_frag(struct nbl_res_rx_ring *rx_ring, struct nbl_rx_buffer *buffer)
{
	int err = 0;

	/* first buffer alloc page */
	if (buffer->offset == NBL_RX_PAD)
		err = nbl_page_alloc_pool(rx_ring, buffer->di);

	return err;
}

static inline bool nbl_alloc_rx_bufs(struct nbl_res_rx_ring *rx_ring, u16 count)
{
	u32 buf_len;
	u16 next_to_use, head;
	__le16 head_flags = 0;
	struct nbl_ring_desc *rx_desc, *head_desc;
	struct nbl_rx_buffer *rx_buf;
	int i;

	if (unlikely(!rx_ring || !count)) {
		nbl_warn(NBL_RING_TO_COMMON(rx_ring), NBL_DEBUG_RESOURCE,
			 "invalid input parameters, rx_ring is %p, count is %d.\n", rx_ring, count);
		return -EINVAL;
	}

	buf_len = rx_ring->buf_len;
	next_to_use = rx_ring->next_to_use;

	head = next_to_use;
	head_desc = NBL_RX_DESC(rx_ring, next_to_use);
	rx_desc = NBL_RX_DESC(rx_ring, next_to_use);
	rx_buf = NBL_RX_BUF(rx_ring, next_to_use);

	if (unlikely(!rx_desc || !rx_buf)) {
		nbl_warn(NBL_RING_TO_COMMON(rx_ring), NBL_DEBUG_RESOURCE,
			 "invalid input parameters, next_to_use:%d, rx_desc is %p, rx_buf is %p.\n",
			 next_to_use, rx_desc, rx_buf);
		return -EINVAL;
	}

	do {
		if (nbl_get_rx_frag(rx_ring, rx_buf))
			break;

		for (i = 0; i < NBL_RX_PAGE_PER_FRAGS; i++, rx_desc++, rx_buf++) {
			rx_desc->addr = cpu_to_le64(rx_buf->di->addr + rx_buf->offset);
			rx_desc->len = cpu_to_le32(buf_len);
			rx_desc->id = cpu_to_le16(next_to_use);

			if (likely(head != next_to_use || i))
				rx_desc->flags = cpu_to_le16(rx_ring->avail_used_flags |
							     NBL_PACKED_DESC_F_WRITE);
			else
				head_flags = cpu_to_le16(rx_ring->avail_used_flags |
							 NBL_PACKED_DESC_F_WRITE);
		}

		next_to_use += NBL_RX_PAGE_PER_FRAGS;
		rx_ring->tail_ptr += NBL_RX_PAGE_PER_FRAGS;
		count -= NBL_RX_PAGE_PER_FRAGS;
		if (next_to_use == rx_ring->desc_num) {
			next_to_use = 0;
			rx_desc = NBL_RX_DESC(rx_ring, next_to_use);
			rx_buf = NBL_RX_BUF(rx_ring, next_to_use);
			rx_ring->avail_used_flags ^=
				BIT(NBL_PACKED_DESC_F_AVAIL) |
				BIT(NBL_PACKED_DESC_F_USED);
		}
	} while (count);

	if (next_to_use != head) {
		/* wmb */
		wmb();
		head_desc->flags = head_flags;
		rx_ring->next_to_use = next_to_use;
	}

	return !!count;
}

static dma_addr_t nbl_res_txrx_start_rx_ring(void *priv, u8 ring_index, bool use_napi)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);
	struct page_pool_params pp_params = {0};
	int i, j;

	if (rx_ring->rx_bufs) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to setup a RX ring with buffer management array already allocated\n");
		return (dma_addr_t)NULL;
	}

	pp_params.order = 0;
	pp_params.flags = 0;
	pp_params.pool_size = rx_ring->desc_num;
	pp_params.nid = dev_to_node(dev);
	pp_params.dev = dev;
	pp_params.dma_dir = DMA_FROM_DEVICE;

	rx_ring->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(rx_ring->page_pool)) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Page_pool Allocate %u Failed failed\n",
			rx_ring->queue_index);
		return (dma_addr_t)NULL;
	}

	rx_ring->di = kvzalloc_node(array_size(rx_ring->desc_num / NBL_RX_PAGE_PER_FRAGS,
					       sizeof(struct nbl_dma_info)),
					       GFP_KERNEL, dev_to_node(dev));
	if (!rx_ring->di) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Dma info Allocate %u Failed failed\n",
			rx_ring->queue_index);
		goto alloc_di_err;
	}

	rx_ring->rx_bufs = devm_kcalloc(dev, rx_ring->desc_num, sizeof(*rx_ring->rx_bufs),
					GFP_KERNEL);
	if (!rx_ring->rx_bufs)
		goto alloc_buffers_err;

	/* Alloc twice memory, and second half is used to back up the desc for desc checking */
	rx_ring->size = ALIGN(rx_ring->desc_num * sizeof(struct nbl_ring_desc), PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dma_dev, rx_ring->size, &rx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);
	if (!rx_ring->desc)
		goto alloc_dma_err;

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->tail_ptr = 0;

	j = 0;
	for (i = 0; i < rx_ring->desc_num / NBL_RX_PAGE_PER_FRAGS; i++) {
		struct nbl_dma_info *di = &rx_ring->di[i];
		struct nbl_rx_buffer *buffer;
		int f;

		for (f = 0; f < NBL_RX_PAGE_PER_FRAGS; f++, j++) {
			buffer = &rx_ring->rx_bufs[j];
			buffer->di = di;
			buffer->offset = NBL_RX_PAD + f * NBL_RX_BUFSZ;
			buffer->last_in_page = false;
		}

		buffer->last_in_page = true;
	}

	if (nbl_alloc_rx_bufs(rx_ring, rx_ring->desc_num - NBL_MAX_BATCH_DESC))
		goto alloc_rx_bufs_err;

	rx_ring->valid = true;
	if (use_napi)
		vector->started = true;

	nbl_debug(common, NBL_DEBUG_RESOURCE, "Start rx ring %d", ring_index);
	return rx_ring->dma;

alloc_rx_bufs_err:
	dmam_free_coherent(dma_dev, rx_ring->size, rx_ring->desc, rx_ring->dma);
	rx_ring->desc = NULL;
	rx_ring->dma = (dma_addr_t)NULL;
alloc_dma_err:
	devm_kfree(dev, rx_ring->rx_bufs);
	rx_ring->rx_bufs = NULL;
alloc_buffers_err:
	kvfree(rx_ring->di);
alloc_di_err:
	page_pool_destroy(rx_ring->page_pool);
	rx_ring->size = 0;
	return (dma_addr_t)NULL;
}

static void nbl_unmap_and_free_tx_resource(struct nbl_res_tx_ring *ring,
					   struct nbl_tx_buffer *tx_buffer,
					   bool free_skb, bool in_napi)
{
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(ring);

	if (tx_buffer->skb) {
		if (likely(free_skb)) {
			if (in_napi)
				napi_consume_skb(tx_buffer->skb, NBL_TX_POLL_WEIGHT);
			else
				dev_kfree_skb_any(tx_buffer->skb);
		}

		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(dma_dev, dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (tx_buffer->page && dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(dma_dev, dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len),
			       DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_single(dma_dev, dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);
	}

	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	tx_buffer->page = 0;
	dma_unmap_len_set(tx_buffer, len, 0);
}

static void nbl_free_tx_ring_bufs(struct nbl_res_tx_ring *tx_ring)
{
	struct nbl_tx_buffer *tx_buffer;
	u16 i;

	i = tx_ring->next_to_clean;
	tx_buffer = NBL_TX_BUF(tx_ring, i);
	while (i != tx_ring->next_to_use) {
		nbl_unmap_and_free_tx_resource(tx_ring, tx_buffer, true, false);
		i++;
		tx_buffer++;
		if (i == tx_ring->desc_num) {
			i = 0;
			tx_buffer = NBL_TX_BUF(tx_ring, i);
		}
	}

	tx_ring->next_to_clean = 0;
	tx_ring->next_to_use = 0;
	tx_ring->tail_ptr = 0;

	tx_ring->used_wrap_counter = 1;
	tx_ring->avail_used_flags = BIT(NBL_PACKED_DESC_F_AVAIL);
	memset(tx_ring->desc, 0, tx_ring->size);
}

static void nbl_res_txrx_stop_tx_ring(void *priv, u8 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index);
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	vector->started = false;
	/* Flush napi task, to ensue the sched napi finish. So napi will no to access the
	 * ring memory(wild point), bacause the vector->started has set false.
	 */
	napi_synchronize(&vector->napi);

	tx_ring->valid = false;

	nbl_free_tx_ring_bufs(tx_ring);
	WRITE_ONCE(NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index), tx_ring);

	devm_kfree(dev, tx_ring->tx_bufs);
	tx_ring->tx_bufs = NULL;

	dmam_free_coherent(dma_dev, tx_ring->size, tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
	tx_ring->dma = (dma_addr_t)NULL;
	tx_ring->size = 0;

	nbl_debug(res_mgt->common, NBL_DEBUG_RESOURCE, "Stop tx ring %d", ring_index);
}

static inline bool nbl_rx_cache_put(struct nbl_res_rx_ring *rx_ring, struct nbl_dma_info *dma_info)
{
	struct nbl_page_cache *cache = &rx_ring->page_cache;
	u32 tail_next = (cache->tail + 1) & (NBL_MAX_CACHE_SIZE - 1);
	struct nbl_rx_queue_stats *stats = &rx_ring->rx_stats;

	if (tail_next == cache->head) {
		stats->rx_cache_full++;
		return false;
	}

	if (!dev_page_is_reusable(dma_info->page)) {
		stats->rx_cache_waive++;
		return false;
	}

	cache->page_cache[cache->tail] = *dma_info;
	cache->tail = tail_next;

	return true;
}

static inline void nbl_page_release_dynamic(struct nbl_res_rx_ring *rx_ring,
					    struct nbl_dma_info *dma_info, bool recycle)
{
	if (likely(recycle)) {
		if (nbl_rx_cache_put(rx_ring, dma_info))
			return;
		dma_unmap_page_attrs(rx_ring->dma_dev, dma_info->addr, PAGE_SIZE,
				     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
		page_pool_recycle_direct(rx_ring->page_pool, dma_info->page);
	} else {
		dma_unmap_page_attrs(rx_ring->dma_dev, dma_info->addr, PAGE_SIZE,
				     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
		page_pool_put_page(rx_ring->page_pool, dma_info->page, PAGE_SIZE, true);
	}
}

static inline void nbl_put_rx_frag(struct nbl_res_rx_ring *rx_ring,
				   struct nbl_rx_buffer *buffer, bool recycle)
{
	if (buffer->last_in_page)
		nbl_page_release_dynamic(rx_ring, buffer->di, recycle);
}

static void nbl_free_rx_ring_bufs(struct nbl_res_rx_ring *rx_ring)
{
	struct nbl_rx_buffer *rx_buf;
	u16 i;

	i = rx_ring->next_to_clean;
	rx_buf = NBL_RX_BUF(rx_ring, i);
	while (i != rx_ring->next_to_use) {
		nbl_put_rx_frag(rx_ring, rx_buf, false);
		i++;
		rx_buf++;
		if (i == rx_ring->desc_num) {
			i = 0;
			rx_buf = NBL_RX_BUF(rx_ring, i);
		}
	}

	for (i = rx_ring->page_cache.head; i != rx_ring->page_cache.tail;
	     i = (i + 1) & (NBL_MAX_CACHE_SIZE - 1)) {
		struct nbl_dma_info *dma_info = &rx_ring->page_cache.page_cache[i];

		nbl_page_release_dynamic(rx_ring, dma_info, false);
	}

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->tail_ptr = 0;
	rx_ring->page_cache.head = 0;
	rx_ring->page_cache.tail = 0;

	rx_ring->used_wrap_counter = 1;
	rx_ring->avail_used_flags = BIT(NBL_PACKED_DESC_F_AVAIL);
	memset(rx_ring->desc, 0, rx_ring->size);
}

static void nbl_res_txrx_stop_rx_ring(void *priv, u8 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);

	rx_ring->valid = false;

	nbl_free_rx_ring_bufs(rx_ring);
	WRITE_ONCE(NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index), rx_ring);

	devm_kfree(dev, rx_ring->rx_bufs);
	kvfree(rx_ring->di);
	rx_ring->rx_bufs = NULL;

	dmam_free_coherent(dma_dev, rx_ring->size, rx_ring->desc, rx_ring->dma);
	rx_ring->desc = NULL;
	rx_ring->dma = (dma_addr_t)NULL;
	rx_ring->size = 0;

	page_pool_destroy(rx_ring->page_pool);

	nbl_debug(res_mgt->common, NBL_DEBUG_RESOURCE, "Stop rx ring %d", ring_index);
}

static inline bool nbl_ring_desc_used(struct nbl_ring_desc *ring_desc, bool used_wrap_counter)
{
	bool avail;
	bool used;
	u16 flags;

	flags = le16_to_cpu(ring_desc->flags);
	avail = !!(flags & BIT(NBL_PACKED_DESC_F_AVAIL));
	used = !!(flags & BIT(NBL_PACKED_DESC_F_USED));

	return avail == used && used == used_wrap_counter;
}

static int nbl_res_txrx_clean_tx_irq(struct nbl_res_tx_ring *tx_ring)
{
	struct nbl_tx_buffer *tx_buffer;
	struct nbl_ring_desc *tx_desc;
	unsigned int i = tx_ring->next_to_clean;
	unsigned int total_tx_pkts = 0;
	unsigned int total_tx_bytes = 0;
	unsigned int total_tx_descs = 0;
	int count = 64;

	tx_buffer = NBL_TX_BUF(tx_ring, i);
	tx_desc = NBL_TX_DESC(tx_ring, i);
	i -= tx_ring->desc_num;

	do {
		struct nbl_ring_desc *end_desc = tx_buffer->next_to_watch;

		if (!end_desc)
			break;

		/* smp_rmb */
		smp_rmb();

		if (!nbl_ring_desc_used(tx_desc, tx_ring->used_wrap_counter))
			break;

		total_tx_pkts += tx_buffer->gso_segs;
		total_tx_bytes += tx_buffer->bytecount;

		while (true) {
			total_tx_descs++;
			nbl_unmap_and_free_tx_resource(tx_ring, tx_buffer, true, true);
			if (tx_desc == end_desc)
				break;
			i++;
			tx_buffer++;
			tx_desc++;
			if (unlikely(!i)) {
				i -= tx_ring->desc_num;
				tx_buffer = NBL_TX_BUF(tx_ring, 0);
				tx_desc = NBL_TX_DESC(tx_ring, 0);
				tx_ring->used_wrap_counter ^= 1;
			}
		}

		tx_buffer++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->desc_num;
			tx_buffer = NBL_TX_BUF(tx_ring, 0);
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			tx_ring->used_wrap_counter ^= 1;
		}

		prefetch(tx_desc);

	} while (--count);

	i += tx_ring->desc_num;

	tx_ring->next_to_clean = i;

	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_tx_bytes;
	tx_ring->stats.packets += total_tx_pkts;
	tx_ring->stats.descs += total_tx_descs;
	u64_stats_update_end(&tx_ring->syncp);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_tx_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     tx_ring->queue_index < NBL_DEFAULT_PF_HW_QUEUE_NUM &&
		     (nbl_unused_tx_desc_count(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (__netif_subqueue_stopped(tx_ring->netdev, tx_ring->queue_index)) {
			netif_wake_subqueue(tx_ring->netdev, tx_ring->queue_index);
			dev_dbg(NBL_RING_TO_DEV(tx_ring), "wake queue %u\n", tx_ring->queue_index);
		}
	}

	return count;
}

static void nbl_rx_csum(struct nbl_res_rx_ring *rx_ring, struct sk_buff *skb,
			struct nbl_rx_extend_head *hdr)
{
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* if user disable RX Checksum Offload, then stack verify the rx checksum */
	if (!(rx_ring->netdev->features & NETIF_F_RXCSUM))
		return;

	if (!hdr->checksum_status)
		return;

	if (hdr->error_code) {
		rx_ring->rx_stats.rx_csum_errors++;
		return;
	}

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	rx_ring->rx_stats.rx_csum_packets++;
}

static inline void nbl_add_rx_frag(struct nbl_rx_buffer *rx_buffer,
				   struct sk_buff *skb, unsigned int size)
{
	page_ref_inc(rx_buffer->di->page);
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->di->page,
			rx_buffer->offset, size, NBL_RX_BUFSZ);
}

static void nbl_txrx_register_vsi_ring(void *priv, u16 vsi_index, u16 ring_offset, u16 ring_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	txrx_mgt->vsi_info[vsi_index].ring_offset = ring_offset;
	txrx_mgt->vsi_info[vsi_index].ring_num = ring_num;
}

/**
 * Current version support merging multiple descriptor for one packet.
 */
static struct sk_buff *nbl_construct_skb(struct nbl_res_rx_ring *rx_ring, struct napi_struct *napi,
					 struct nbl_rx_buffer *rx_buf, unsigned int size)
{
	struct sk_buff *skb;
	char *p, *buf;
	int tailroom, shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	unsigned int truesize = NBL_RX_BUFSZ;
	unsigned int headlen;

	/* p point dma buff start, buf point whole buffer start*/
	p = page_address(rx_buf->di->page) + rx_buf->offset;
	buf = p - NBL_RX_PAD;

	/* p point pkt start */
	p += NBL_BUFFER_HDR_LEN;
	tailroom = truesize - size - NBL_RX_PAD;
	size -= NBL_BUFFER_HDR_LEN;

	if (size > NBL_RX_HDR_SIZE && tailroom >= shinfo_size) {
		skb = build_skb(buf, truesize);
		if (unlikely(!skb))
			return NULL;

		page_ref_inc(rx_buf->di->page);
		skb_reserve(skb, p - buf);
		skb_put(skb, size);
		goto ok;
	}

	skb = napi_alloc_skb(napi, NBL_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	headlen = size;
	if (headlen > NBL_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, p, NBL_RX_HDR_SIZE);

	memcpy(__skb_put(skb, headlen), p, ALIGN(headlen, sizeof(long)));
	size -= headlen;
	if (size) {
		page_ref_inc(rx_buf->di->page);
		skb_add_rx_frag(skb, 0, rx_buf->di->page,
				rx_buf->offset + NBL_BUFFER_HDR_LEN + headlen,
				size, truesize);
	}
ok:
	skb_record_rx_queue(skb, rx_ring->queue_index);

	return skb;
}

static inline struct nbl_rx_buffer *nbl_get_rx_buf(struct nbl_res_rx_ring *rx_ring)
{
	struct nbl_rx_buffer *rx_buf;

	rx_buf = NBL_RX_BUF(rx_ring, rx_ring->next_to_clean);
	prefetchw(rx_buf->di->page);

	dma_sync_single_range_for_cpu(rx_ring->dma_dev, rx_buf->di->addr, rx_buf->offset,
				      rx_ring->buf_len, DMA_FROM_DEVICE);

	return rx_buf;
}

static inline void nbl_put_rx_buf(struct nbl_res_rx_ring *rx_ring, struct nbl_rx_buffer *rx_buf)
{
	u16 ntc = rx_ring->next_to_clean + 1;

	/* if at the end of the ring, reset ntc and flip used wrap bit */
	if (unlikely(ntc >= rx_ring->desc_num)) {
		ntc = 0;
		rx_ring->used_wrap_counter ^= 1;
	}

	rx_ring->next_to_clean = ntc;
	prefetch(NBL_RX_DESC(rx_ring, ntc));

	nbl_put_rx_frag(rx_ring, rx_buf, true);
}

static int nbl_res_txrx_clean_rx_irq(struct nbl_res_rx_ring *rx_ring,
				     struct napi_struct *napi,
				     int budget)
{
	struct nbl_ring_desc *rx_desc;
	struct nbl_rx_buffer *rx_buf;
	struct nbl_rx_extend_head *hdr;
	struct sk_buff *skb = NULL;
	unsigned int total_rx_pkts = 0;
	unsigned int total_rx_bytes = 0;
	unsigned int size;
	u16 desc_count = 0;
	u16 num_buffers = 0;
	u32 rx_multicast_packets = 0;
	u32 rx_unicast_packets = 0;
	u16 cleaned_count = nbl_unused_rx_desc_count(rx_ring);
	u16 sport_id;
	bool failure = 0;

	while (likely(total_rx_pkts < budget)) {
		rx_desc = NBL_RX_DESC(rx_ring, rx_ring->next_to_clean);
		if (!nbl_ring_desc_used(rx_desc, rx_ring->used_wrap_counter))
			break;

		// nbl_trace(clean_rx_irq, rx_ring, rx_desc);

		dma_rmb();
		size = le32_to_cpu(rx_desc->len);
		rx_buf = nbl_get_rx_buf(rx_ring);

		desc_count++;

		if (skb) {
			nbl_add_rx_frag(rx_buf, skb, size);
		} else {
			hdr = page_address(rx_buf->di->page) + rx_buf->offset;
			net_prefetch(hdr);
			skb = nbl_construct_skb(rx_ring, napi, rx_buf, size);
			if (unlikely(!skb)) {
				rx_ring->rx_stats.rx_alloc_buf_err_cnt++;
				break;
			}

			num_buffers = le16_to_cpu(hdr->num_buffers);
			sport_id = hdr->sport_id;
			nbl_rx_csum(rx_ring, skb, hdr);
		}

		cleaned_count++;
		nbl_put_rx_buf(rx_ring, rx_buf);
		if (desc_count < num_buffers)
			continue;
		desc_count = 0;

		if (unlikely(eth_skb_pad(skb))) {
			skb = NULL;
			continue;
		}

		skb->protocol = eth_type_trans(skb, rx_ring->netdev);
		if (unlikely(skb->pkt_type == PACKET_BROADCAST ||
			     skb->pkt_type == PACKET_MULTICAST))
			rx_multicast_packets++;
		else
			rx_unicast_packets++;

		total_rx_bytes += skb->len;

		// nbl_trace(clean_rx_irq_indicate, rx_ring, rx_desc, skb);
		napi_gro_receive(napi, skb);
		skb = NULL;
		total_rx_pkts++;
	}

	if (cleaned_count & (~(NBL_MAX_BATCH_DESC - 1)))
		failure = nbl_alloc_rx_bufs(rx_ring, cleaned_count & (~(NBL_MAX_BATCH_DESC - 1)));

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_pkts;
	rx_ring->stats.bytes += total_rx_bytes;
	rx_ring->rx_stats.rx_multicast_packets += rx_multicast_packets;
	rx_ring->rx_stats.rx_unicast_packets += rx_unicast_packets;
	u64_stats_update_end(&rx_ring->syncp);

	return failure ? budget : total_rx_pkts;
}

static int nbl_res_napi_poll(struct napi_struct *napi, int budget)
{
	struct nbl_res_vector *vector = container_of(napi, struct nbl_res_vector, napi);
	struct nbl_res_tx_ring *tx_ring;
	struct nbl_res_rx_ring *rx_ring;
	int complete = 1, cleaned = 0, tx_done = 1;

	tx_ring = vector->tx_ring;
	rx_ring = vector->rx_ring;

	if (vector->started) {
		tx_done = nbl_res_txrx_clean_tx_irq(tx_ring);
		cleaned = nbl_res_txrx_clean_rx_irq(rx_ring, napi, budget);
	}

	if (!tx_done)
		complete = 0;

	if (cleaned >= budget)
		complete = 0;

	if (!complete)
		return budget;

	if (!napi_complete_done(napi, cleaned))
		return min_t(int, cleaned, budget - 1);

	/* unmask irq passthrough for performace */
	if (vector->net_msix_mask_en)
		writel(vector->irq_data, vector->irq_enable_base);

	return min_t(int, cleaned, budget - 1);
}

static inline unsigned int nbl_txd_use_count(unsigned int size)
{
	/* TODO: how to compute tx desc needed more efficiently */
	return DIV_ROUND_UP(size, NBL_TXD_DATALEN_MAX);
}

static unsigned int nbl_xmit_desc_count(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	unsigned int size;
	unsigned int count;

	/* We need: 1 descriptor per page * PAGE_SIZE/NBL_MAX_DATA_PER_TX_DESC,
	 *          + 1 desc for skb_headlen/NBL_MAX_DATA_PER_TX_DESC,
	 *          + 2 desc gap to keep tail from touching head,
	 * otherwise try next time.
	 */
	size = skb_headlen(skb);
	count = 2;
	for (;;) {
		count += nbl_txd_use_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

static inline int nbl_maybe_stop_tx(struct nbl_res_tx_ring *tx_ring, unsigned int size)
{
	if (likely(nbl_unused_tx_desc_count(tx_ring) >= size))
		return 0;

	if (tx_ring->queue_index >= NBL_DEFAULT_PF_HW_QUEUE_NUM)
		return -EBUSY;

	dev_dbg(NBL_RING_TO_DEV(tx_ring), "unused_desc_count:%u, size:%u, stop queue %u\n",
		nbl_unused_tx_desc_count(tx_ring), size, tx_ring->queue_index);
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);

	/* smp_mb */
	smp_mb();

	if (likely(nbl_unused_tx_desc_count(tx_ring) < size))
		return -EBUSY;

	dev_dbg(NBL_RING_TO_DEV(tx_ring), "unused_desc_count:%u, size:%u, start queue %u\n",
		nbl_unused_tx_desc_count(tx_ring), size, tx_ring->queue_index);
	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);

	return 0;
}

/* set up TSO(TCP Segmentation Offload) */
static int nbl_tx_tso(struct nbl_tx_buffer *first, struct nbl_tx_hdr_param *hdr_param)
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
	u8 l4_start;
	u32 payload_len;
	u8 header_len = 0;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 1;

	if (!skb_is_gso(skb))
		return 1;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize IP header fields*/
	if (ip.v4->version == IP_VERSION_V4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else {
		ip.v6->payload_len = 0;
	}

	/* length of (MAC + IP) header */
	l4_start = (u8)(l4.hdr - skb->data);

	/* l4 packet length */
	payload_len = skb->len - l4_start;

	/* remove l4 packet length from L4 pseudo-header checksum */
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check, (__force __wsum)htonl(payload_len));
		/* compute length of UDP segmentation header */
		header_len = (u8)sizeof(l4.udp) + l4_start;
	} else {
		csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(payload_len));
		/* compute length of TCP segmentation header */
		header_len = (u8)(l4.tcp->doff * 4 + l4_start);
	}

	hdr_param->tso = 1;
	hdr_param->mss = skb_shinfo(skb)->gso_size;
	hdr_param->total_hlen = header_len;

	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * header_len;
	first->tx_flags = NBL_TX_FLAGS_TSO;

	return first->gso_segs;
}

/* set up Tx checksum offload */
static int nbl_tx_csum(struct nbl_tx_buffer *first, struct nbl_tx_hdr_param *hdr_param)
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
	__be16 frag_off, protocol;
	u8 inner_ip_type = 0, l4_type = 0, l4_csum = 0, l4_proto = 0;
	u32 l2_len = 0, l3_len = 0, l4_len = 0;
	unsigned char *exthdr;
	int ret;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* compute outer L2 header size */
	l2_len = ip.hdr - skb->data;

	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP)) {
		inner_ip_type = NBL_TX_IIPT_IPV4;
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		inner_ip_type = NBL_TX_IIPT_IPV6;
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;

		if (l4.hdr != exthdr) {
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
			if (ret < 0)
				return -1;
		}
	} else {
		return -1;
	}

	l3_len = l4.hdr - ip.hdr;

	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_type = NBL_TX_L4T_TCP;
		l4_len = l4.tcp->doff;
		l4_csum = 1;
		break;
	case IPPROTO_UDP:
		l4_type = NBL_TX_L4T_UDP;
		l4_len = (sizeof(struct udphdr) >> 2);
		l4_csum = 1;
		break;
	case IPPROTO_SCTP:
		if (first->tx_flags & NBL_TX_FLAGS_TSO)
			return -1;
		l4_type = NBL_TX_L4T_RSV;
		l4_len = (sizeof(struct sctphdr) >> 2);
		l4_csum = 1;
		break;
	default:
		if (first->tx_flags & NBL_TX_FLAGS_TSO)
			return -2;

		/* unsopported L4 protocol, device cannot offload L4 checksum,
		 * so software compute L4 checskum
		 */
		skb_checksum_help(skb);
		return 0;
	}

	hdr_param->mac_len = l2_len >> 1;
	hdr_param->ip_len = l3_len >> 2;
	hdr_param->l4_len = l4_len;
	hdr_param->l4_type = l4_type;
	hdr_param->inner_ip_type = inner_ip_type;
	hdr_param->l3_csum_en = 0;
	hdr_param->l4_csum_en = l4_csum;

	return 1;
}

static int nbl_map_skb(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb,
		       u16 first, u16 *desc_index)
{
	u16 index = *desc_index;
	const skb_frag_t *frag;
	unsigned int frag_num = skb_shinfo(skb)->nr_frags;
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(tx_ring);
	struct nbl_tx_buffer *tx_buffer = NBL_TX_BUF(tx_ring, index);
	struct nbl_ring_desc *tx_desc = NBL_TX_DESC(tx_ring, index);
	unsigned int i;
	unsigned int size;
	dma_addr_t dma;

	size = skb_headlen(skb);
	dma = dma_map_single(dma_dev, skb->data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, dma))
		return -1;

	tx_buffer->dma = dma;
	tx_buffer->len = size;

	tx_desc->addr = cpu_to_le64(dma);
	tx_desc->len = size;
	if (!first)
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	index++;
	tx_desc++;
	tx_buffer++;
	if (index == tx_ring->desc_num) {
		index = 0;
		tx_ring->avail_used_flags ^=
			1 << NBL_PACKED_DESC_F_AVAIL |
			1 << NBL_PACKED_DESC_F_USED;
		tx_desc = NBL_TX_DESC(tx_ring, 0);
		tx_buffer = NBL_TX_BUF(tx_ring, 0);
	}

	if (!frag_num) {
		*desc_index = index;
		return 0;
	}

	frag = &skb_shinfo(skb)->frags[0];
	for (i = 0; i < frag_num; i++) {
		size = skb_frag_size(frag);
		dma = skb_frag_dma_map(dma_dev, frag, 0, size, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, dma)) {
			*desc_index = index;
			return -1;
		}

		tx_buffer->dma = dma;
		tx_buffer->len = size;
		tx_buffer->page = 1;

		tx_desc->addr = cpu_to_le64(dma);
		tx_desc->len = size;
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);
		index++;
		tx_desc++;
		tx_buffer++;
		if (index == tx_ring->desc_num) {
			index = 0;
			tx_ring->avail_used_flags ^=
				1 << NBL_PACKED_DESC_F_AVAIL |
				1 << NBL_PACKED_DESC_F_USED;
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			tx_buffer = NBL_TX_BUF(tx_ring, 0);
		}
		frag++;
	}

	*desc_index = index;
	return 0;
}

static inline void nbl_tx_fill_tx_extend_header_leonis(union nbl_tx_extend_head *pkthdr,
						       struct nbl_tx_hdr_param *param)
{
	pkthdr->mac_len = param->mac_len;
	pkthdr->ip_len = param->ip_len;
	pkthdr->l4_len = param->l4_len;
	pkthdr->l4_type = param->l4_type;
	pkthdr->inner_ip_type = param->inner_ip_type;

	pkthdr->l4s_sid = param->l4s_sid;
	pkthdr->l4s_sync_ind = param->l4s_sync_ind;
	pkthdr->l4s_hdl_ind = param->l4s_hdl_ind;
	pkthdr->l4s_pbrac_mode = param->l4s_pbrac_mode;

	pkthdr->mss = param->mss;
	pkthdr->tso = param->tso;

	pkthdr->fwd = param->fwd;
	pkthdr->rss_lag_en = param->rss_lag_en;
	pkthdr->dport = param->dport;
	pkthdr->dport_id = param->dport_id;

	pkthdr->l3_csum_en = param->l3_csum_en;
	pkthdr->l4_csum_en = param->l4_csum_en;
}

static bool nbl_skb_is_lacp_or_lldp(struct sk_buff *skb)
{
	__be16 protocol;

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_SLOW) || protocol == htons(ETH_P_LLDP))
		return true;

	return false;
}

static int nbl_tx_map(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb,
		      struct nbl_tx_hdr_param *hdr_param)
{
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(tx_ring);
	struct nbl_tx_buffer *first;
	struct nbl_ring_desc *first_desc;
	struct nbl_ring_desc *tx_desc;
	union nbl_tx_extend_head *pkthdr;
	dma_addr_t hdrdma;
	int tso, csum;
	u16 desc_index = tx_ring->next_to_use;
	u16 head = desc_index;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	u32 pkthdr_len;
	bool can_push;

	first_desc = NBL_TX_DESC(tx_ring, desc_index);
	first = NBL_TX_BUF(tx_ring, desc_index);
	first->gso_segs = 1;
	first->bytecount = skb->len;
	first->tx_flags = 0;
	first->skb = skb;
	skb_tx_timestamp(skb);

	can_push = !skb_header_cloned(skb) && skb_headroom(skb) >= sizeof(*pkthdr);

	if (can_push)
		pkthdr = (union nbl_tx_extend_head *)(skb->data - sizeof(*pkthdr));
	else
		pkthdr = (union nbl_tx_extend_head *)(skb->cb);

	tso = nbl_tx_tso(first, hdr_param);
	if (tso < 0) {
		netdev_err(tx_ring->netdev, "tso ret:%d\n", tso);
		goto out_drop;
	}

	csum = nbl_tx_csum(first, hdr_param);
	if (csum < 0) {
		netdev_err(tx_ring->netdev, "csum ret:%d\n", csum);
		goto out_drop;
	}

	memset(pkthdr, 0, sizeof(*pkthdr));
	switch (tx_ring->product_type) {
	case NBL_LEONIS_TYPE:
		nbl_tx_fill_tx_extend_header_leonis(pkthdr, hdr_param);
		break;
	default:
		netdev_err(tx_ring->netdev, "fill tx extend header failed, product type: %d, eth: %u.\n",
			   tx_ring->product_type, hdr_param->dport_id);
		goto out_drop;
	}

	pkthdr_len = sizeof(union nbl_tx_extend_head);

	if (can_push) {
		__skb_push(skb, pkthdr_len);
		if (nbl_map_skb(tx_ring, skb, 1, &desc_index))
			goto dma_map_error;
		__skb_pull(skb, pkthdr_len);
	} else {
		hdrdma = dma_map_single(dma_dev, pkthdr, pkthdr_len, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, hdrdma)) {
			tx_ring->tx_stats.tx_dma_busy++;
			return NETDEV_TX_BUSY;
		}

		first_desc->addr = cpu_to_le64(hdrdma);
		first_desc->len = pkthdr_len;

		first->dma = hdrdma;
		first->len = pkthdr_len;

		desc_index++;
		if (desc_index == tx_ring->desc_num) {
			desc_index = 0;
			tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
						     1 << NBL_PACKED_DESC_F_USED;
		}
		if (nbl_map_skb(tx_ring, skb, 0, &desc_index))
			goto dma_map_error;
	}

	/* stats */
	if (is_multicast_ether_addr(skb->data))
		tx_ring->tx_stats.tx_multicast_packets += tso;
	else
		tx_ring->tx_stats.tx_unicast_packets += tso;

	if (tso > 1) {
		tx_ring->tx_stats.tso_packets++;
		tx_ring->tx_stats.tso_bytes += skb->len;
	}
	tx_ring->tx_stats.tx_csum_packets += csum;

	tx_desc = NBL_TX_DESC(tx_ring, (desc_index == 0 ? tx_ring->desc_num : desc_index) - 1);
	tx_desc->flags &= cpu_to_le16(~NBL_PACKED_DESC_F_NEXT);
	first->next_to_watch = tx_desc;
	first_desc->len += (hdr_param->total_hlen << NBL_TX_TOTAL_HEADERLEN_SHIFT);
	first_desc->id = cpu_to_le16(skb_shinfo(skb)->gso_size);

	/* wmb */
	wmb();

	/* first desc last set flag */
	if (first_desc == tx_desc)
		first_desc->flags = cpu_to_le16(avail_used_flags);
	else
		first_desc->flags = cpu_to_le16(avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	tx_ring->next_to_use = desc_index;

	nbl_maybe_stop_tx(tx_ring, DESC_NEEDED);
	/* kick doorbell passthrough for performace */
	writel(tx_ring->notify_qid, tx_ring->notify_addr);

	// nbl_trace(tx_map_ok, tx_ring, skb, head, first_desc, pkthdr);

	return NETDEV_TX_OK;

dma_map_error:
	while (desc_index != head) {
		if (unlikely(!desc_index))
			desc_index = tx_ring->desc_num;
		desc_index--;
		nbl_unmap_and_free_tx_resource(tx_ring, NBL_TX_BUF(tx_ring, desc_index),
					       false, false);
	}

	tx_ring->avail_used_flags = avail_used_flags;
	tx_ring->tx_stats.tx_dma_busy++;
	return NETDEV_TX_BUSY;

out_drop:
	netdev_err(tx_ring->netdev, "tx_map, free_skb\n");
	tx_ring->tx_stats.tx_skb_free++;
	// nbl_trace(tx_map_drop, tx_ring, skb);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static netdev_tx_t nbl_res_txrx_rep_xmit(struct sk_buff *skb,
					 struct net_device *netdev)
{
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	struct nbl_tx_hdr_param hdr_param = {
		.mac_len = 14 >> 1,
		.ip_len = 20 >> 2,
		.l4_len = 20 >> 2,
		.mss = 256,
	};
	unsigned int count;
	int ret = 0;

	count = nbl_xmit_desc_count(skb);
	/* TODO: we can not tranmit a packet with more than 32 descriptors */
	WARN_ON(count > MAX_DESC_NUM_PER_PKT);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_warn(NBL_RING_TO_DEV(tx_ring), "There is not enough descriptor to transmit packet in queue %u\n",
				 tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	eth_skb_pad(skb);

	hdr_param.dport_id = *(u16 *)(&skb->cb[NBL_SKB_FILL_VSI_ID_OFF]);
	hdr_param.dport = NBL_TX_DPORT_HOST;
	hdr_param.rss_lag_en = 1;
	hdr_param.fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED;

	ret = nbl_tx_map(tx_ring, skb, &hdr_param);

	return ret;
}

static netdev_tx_t nbl_res_txrx_self_test_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	struct nbl_tx_hdr_param hdr_param = {
		.mac_len = 14 >> 1,
		.ip_len = 20 >> 2,
		.l4_len = 20 >> 2,
		.mss = 256,
	};
	unsigned int count;

	count = nbl_xmit_desc_count(skb);
	/* TODO: we can not tranmit a packet with more than 32 descriptors */
	WARN_ON(count > MAX_DESC_NUM_PER_PKT);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_warn(NBL_RING_TO_DEV(tx_ring), "There is not enough descriptor to transmit packet in queue %u\n",
				 tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* for dstore and eth, min packet len is 60 */
	eth_skb_pad(skb);

	hdr_param.fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED;
	hdr_param.dport = NBL_TX_DPORT_ETH;
	hdr_param.dport_id = tx_ring->eth_id;
	hdr_param.rss_lag_en = 0;

	return nbl_tx_map(tx_ring, skb, &hdr_param);
}

static netdev_tx_t nbl_res_txrx_start_xmit(struct sk_buff *skb,
					   struct net_device *netdev)
{
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	struct nbl_tx_hdr_param hdr_param = {
		.mac_len = 14 >> 1,
		.ip_len = 20 >> 2,
		.l4_len = 20 >> 2,
		.mss = 256,
	};
	unsigned int count;
	int ret = 0;

	// nbl_trace(xmit_frame_ring, tx_ring, skb);

	count = nbl_xmit_desc_count(skb);
	/* TODO: we can not tranmit a packet with more than 32 descriptors */
	WARN_ON(count > MAX_DESC_NUM_PER_PKT);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_warn(NBL_RING_TO_DEV(tx_ring), "There is not enough descriptor to transmit packet in queue %u\n",
				 tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* for dstore and eth, min packet len is 60 */
	eth_skb_pad(skb);

	hdr_param.dport_id = tx_ring->eth_id;
	hdr_param.fwd = 1;
	hdr_param.rss_lag_en = 0;

	if (nbl_skb_is_lacp_or_lldp(skb)) {
		hdr_param.fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED;
		hdr_param.dport = NBL_TX_DPORT_ETH;
	}

	ret = nbl_tx_map(tx_ring, skb, &hdr_param);

	return ret;
}

static void nbl_res_txrx_kick_rx_ring(void *priv, u16 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_notify_param notify_param = {0};
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, index);

	notify_param.notify_qid = rx_ring->notify_qid;
	notify_param.tail_ptr = rx_ring->tail_ptr;
	phy_ops->update_tail_ptr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &notify_param);
}

static int nbl_res_txring_is_invalid(struct nbl_resource_mgt *res_mgt,
				     struct seq_file *m, int index)
{
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring;
	u8 ring_num = txrx_mgt->tx_ring_num;

	if (index >= ring_num) {
		seq_printf(m, "Invalid tx index %d, max ring num is %d\n", index, ring_num);
		return -EINVAL;
	}

	tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, index);
	if (!tx_ring || !tx_ring->valid) {
		seq_puts(m, "Ring doesn't exist, wrong index or the netdev might be stopped\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_res_rxring_is_invalid(struct nbl_resource_mgt *res_mgt,
				     struct seq_file *m, int index)
{
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring;
	u8 ring_num = txrx_mgt->rx_ring_num;

	if (index >= ring_num) {
		seq_printf(m, "Invalid rx index %d, max ring num is %d\n", index, ring_num);
		return -EINVAL;
	}

	rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, index);
	if (!rx_ring || !rx_ring->valid) {
		seq_puts(m, "Ring doesn't exist, wrong index or the netdev might be stopped\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_res_rx_dump_ring(struct nbl_resource_mgt *res_mgt, struct seq_file *m, int index)
{
	struct nbl_res_rx_ring *ring = NBL_RES_MGT_TO_RX_RING(res_mgt, index);
	struct nbl_ring_desc *desc;
	int i;

	if (nbl_res_rxring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "queue_index %d desc_num %d used_wrap_counter 0x%x avail_used_flags 0x%x\n",
		   ring->queue_index, ring->desc_num,
		   ring->used_wrap_counter, ring->avail_used_flags);
	seq_printf(m, "ntu 0x%x, ntc 0x%x, tail_ptr 0x%x\n",
		   ring->next_to_use, ring->next_to_clean, ring->tail_ptr);
	seq_printf(m, "desc dma 0x%llx, HZ %u\n", ring->dma, HZ);

	seq_puts(m, "desc:\n");
	for (i = 0; i < ring->desc_num; i++) {
		desc = ring->desc + i;
		seq_printf(m, "desc id %d, addr 0x%llx len %d flag 0x%x\n",
			   desc->id, desc->addr, desc->len, desc->flags);
	}

	return 0;
}

static int nbl_res_tx_dump_ring(struct nbl_resource_mgt *res_mgt, struct seq_file *m, int index)
{
	struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, index);
	struct nbl_ring_desc *desc;
	u32 total_header_len;
	u32 desc_len;
	int i;

	if (nbl_res_txring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "queue_index %d desc_num %d used_wrap_counter 0x%x avail_used_flags 0x%x\n",
		   ring->queue_index, ring->desc_num,
		   ring->used_wrap_counter, ring->avail_used_flags);
	seq_printf(m, "ntu 0x%x, ntc 0x%x tail_ptr 0x%x\n",
		   ring->next_to_use, ring->next_to_clean, ring->tail_ptr);
	seq_printf(m, "desc dma 0x%llx, HZ %u\n", ring->dma, HZ);
	seq_printf(m, "tx_skb_free %llu\n", ring->tx_stats.tx_skb_free);

	seq_puts(m, "desc:\n");
	for (i = 0; i < ring->desc_num; i++) {
		desc = ring->desc + i;
		total_header_len = desc->len >> NBL_TX_TOTAL_HEADERLEN_SHIFT;
		desc_len = desc->len & 0xFFFFFF;
		seq_printf(m, "desc %d: id/gso_size %d, addr 0x%llx len %d header_len %d flag 0x%x\n",
			   i, desc->id, desc->addr, desc_len, total_header_len, desc->flags);
	}

	return 0;
}

static int nbl_res_txrx_dump_ring(void *priv, struct seq_file *m, bool is_tx, int index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	if (is_tx)
		return nbl_res_tx_dump_ring(res_mgt, m, index);
	else
		return nbl_res_rx_dump_ring(res_mgt, m, index);
}

static int nbl_res_tx_dump_ring_stats(struct nbl_resource_mgt *res_mgt,
				      struct seq_file *m, int index)
{
	struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, index);

	if (nbl_res_txring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "pkts: %lld, bytes: %lld, descs: %lld\n",
		   ring->stats.packets, ring->stats.bytes, ring->stats.descs);
	seq_printf(m, "tso_pkts: %lld, tso_bytes: %lld, tx_checksum_pkts: %lld\n",
		   ring->tx_stats.tso_packets, ring->tx_stats.tso_bytes,
		   ring->tx_stats.tx_csum_packets);
	seq_printf(m, "tx_busy: %lld, tx_dma_busy: %lld\n",
		   ring->tx_stats.tx_busy, ring->tx_stats.tx_dma_busy);
	seq_printf(m, "tx_multicast_pkts: %lld, tx_unicast_pkts: %lld\n",
		   ring->tx_stats.tx_multicast_packets,
		   ring->tx_stats.tx_unicast_packets);
	seq_printf(m, "tx_skb_free: %lld, tx_desc_addr_err: %lld, tx_desc_len_err: %lld\n",
		   ring->tx_stats.tx_skb_free, ring->tx_stats.tx_desc_addr_err_cnt,
		   ring->tx_stats.tx_desc_len_err_cnt);
	return 0;
}

static int nbl_res_rx_dump_ring_stats(struct nbl_resource_mgt *res_mgt,
				      struct seq_file *m, int index)
{
	struct nbl_res_rx_ring *ring = NBL_RES_MGT_TO_RX_RING(res_mgt, index);

	if (nbl_res_rxring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "rx_checksum_pkts: %lld, rx_checksum_errors: %lld\n",
		   ring->rx_stats.rx_csum_packets, ring->rx_stats.rx_csum_errors);
	seq_printf(m, "rx_multicast_pkts: %lld, rx_unicast_pkts: %lld\n",
		   ring->rx_stats.rx_multicast_packets,
		   ring->rx_stats.rx_unicast_packets);
	seq_printf(m, "rx_desc_addr_err: %lld\n",
		   ring->rx_stats.rx_desc_addr_err_cnt);
	seq_printf(m, "rx_alloc_buf_err_cnt: %lld\n",
		   ring->rx_stats.rx_alloc_buf_err_cnt);

	return 0;
}

static int nbl_res_txrx_dump_ring_stats(void *priv, struct seq_file *m, bool is_tx, int index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	if (is_tx)
		return nbl_res_tx_dump_ring_stats(res_mgt, m, index);
	else
		return nbl_res_rx_dump_ring_stats(res_mgt, m, index);
}

static struct napi_struct *nbl_res_txrx_get_vector_napi(void *priv, u16 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;

	if (!txrx_mgt->vectors || index >= txrx_mgt->rx_ring_num) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "vectors not allocated\n");
		return NULL;
	}

	return &txrx_mgt->vectors[index]->napi;
}

static void nbl_res_txrx_set_vector_info(void *priv, u8 *irq_enable_base,
					 u32 irq_data, u16 index, bool mask_en)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;

	if (!txrx_mgt->vectors || index >= txrx_mgt->rx_ring_num) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "vectors not allocated\n");
		return;
	}

	txrx_mgt->vectors[index]->irq_enable_base = irq_enable_base;
	txrx_mgt->vectors[index]->irq_data = irq_data;
	txrx_mgt->vectors[index]->net_msix_mask_en = mask_en;
}

static void nbl_res_get_pt_ops(void *priv, struct nbl_resource_pt_ops *pt_ops)
{
	pt_ops->start_xmit = nbl_res_txrx_start_xmit;
	pt_ops->rep_xmit = nbl_res_txrx_rep_xmit;
	pt_ops->self_test_xmit = nbl_res_txrx_self_test_start_xmit;
	pt_ops->napi_poll = nbl_res_napi_poll;
}

static u32 nbl_res_txrx_get_tx_headroom(void *priv)
{
	return sizeof(union nbl_tx_extend_head);
}

static void nbl_res_txrx_get_queue_stats(void *priv, u8 queue_id,
					 struct nbl_queue_stats *queue_stats, bool is_tx)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct u64_stats_sync *syncp;
	struct nbl_queue_stats *stats;
	unsigned int start;

	if (is_tx) {
		struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, queue_id);

		syncp = &ring->syncp;
		stats = &ring->stats;
	} else {
		struct nbl_res_rx_ring *ring = NBL_RES_MGT_TO_RX_RING(res_mgt, queue_id);

		syncp = &ring->syncp;
		stats = &ring->stats;
	}

	do {
		start = u64_stats_fetch_begin(syncp);
		memcpy(queue_stats, stats, sizeof(*stats));
	} while (u64_stats_fetch_retry(syncp, start));
}

static void nbl_res_txrx_get_net_stats(void *priv, struct nbl_stats *net_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	int i;
	u64 bytes = 0, packets = 0;
	u64 tso_packets = 0, tso_bytes = 0;
	u64 tx_csum_packets = 0;
	u64 rx_csum_packets = 0, rx_csum_errors = 0;
	u64 tx_multicast_packets = 0, tx_unicast_packets = 0;
	u64 rx_multicast_packets = 0, rx_unicast_packets = 0;
	u64 tx_busy = 0, tx_dma_busy = 0;
	u64 tx_desc_addr_err_cnt = 0;
	u64 tx_desc_len_err_cnt = 0;
	u64 rx_desc_addr_err_cnt = 0;
	u64 rx_alloc_buf_err_cnt = 0;
	u64 rx_cache_reuse = 0;
	u64 rx_cache_full = 0;
	u64 rx_cache_empty = 0;
	u64 rx_cache_busy = 0;
	u64 rx_cache_waive = 0;
	u64 tx_skb_free = 0;
	unsigned int start;

	rcu_read_lock();
	for (i = 0; i < txrx_mgt->rx_ring_num; i++) {
		struct nbl_res_rx_ring *ring = NBL_RES_MGT_TO_RX_RING(res_mgt, i);

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			bytes += ring->stats.bytes;
			packets += ring->stats.packets;
			rx_csum_packets += ring->rx_stats.rx_csum_packets;
			rx_csum_errors += ring->rx_stats.rx_csum_errors;
			rx_multicast_packets += ring->rx_stats.rx_multicast_packets;
			rx_unicast_packets += ring->rx_stats.rx_unicast_packets;
			rx_desc_addr_err_cnt += ring->rx_stats.rx_desc_addr_err_cnt;
			rx_alloc_buf_err_cnt += ring->rx_stats.rx_alloc_buf_err_cnt;
			rx_cache_reuse += ring->rx_stats.rx_cache_reuse;
			rx_cache_full += ring->rx_stats.rx_cache_full;
			rx_cache_empty += ring->rx_stats.rx_cache_empty;
			rx_cache_busy += ring->rx_stats.rx_cache_busy;
			rx_cache_waive += ring->rx_stats.rx_cache_waive;
		} while (u64_stats_fetch_retry(&ring->syncp, start));
	}

	net_stats->rx_packets = packets;
	net_stats->rx_bytes = bytes;

	net_stats->rx_csum_packets = rx_csum_packets;
	net_stats->rx_csum_errors = rx_csum_errors;
	net_stats->rx_multicast_packets = rx_multicast_packets;
	net_stats->rx_unicast_packets = rx_unicast_packets;

	bytes = 0;
	packets = 0;

	for (i = 0; i < txrx_mgt->tx_ring_num; i++) {
		struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, i);

		do {
			start = u64_stats_fetch_begin(&ring->syncp);
			bytes += ring->stats.bytes;
			packets += ring->stats.packets;
			tso_packets += ring->tx_stats.tso_packets;
			tso_bytes += ring->tx_stats.tso_bytes;
			tx_csum_packets += ring->tx_stats.tx_csum_packets;
			tx_busy += ring->tx_stats.tx_busy;
			tx_dma_busy += ring->tx_stats.tx_dma_busy;
			tx_multicast_packets += ring->tx_stats.tx_multicast_packets;
			tx_unicast_packets += ring->tx_stats.tx_unicast_packets;
			tx_skb_free += ring->tx_stats.tx_skb_free;
			tx_desc_addr_err_cnt += ring->tx_stats.tx_desc_addr_err_cnt;
			tx_desc_len_err_cnt += ring->tx_stats.tx_desc_len_err_cnt;
		} while (u64_stats_fetch_retry(&ring->syncp, start));
	}

	rcu_read_unlock();

	net_stats->tx_bytes = bytes;
	net_stats->tx_packets = packets;
	net_stats->tso_packets = tso_packets;
	net_stats->tso_bytes = tso_bytes;
	net_stats->tx_csum_packets = tx_csum_packets;
	net_stats->tx_busy = tx_busy;
	net_stats->tx_dma_busy = tx_dma_busy;
	net_stats->tx_multicast_packets = tx_multicast_packets;
	net_stats->tx_unicast_packets = tx_unicast_packets;
	net_stats->tx_skb_free = tx_skb_free;
	net_stats->tx_desc_addr_err_cnt = tx_desc_addr_err_cnt;
	net_stats->tx_desc_len_err_cnt = tx_desc_len_err_cnt;
	net_stats->rx_desc_addr_err_cnt = rx_desc_addr_err_cnt;
	net_stats->rx_alloc_buf_err_cnt = rx_alloc_buf_err_cnt;
	net_stats->rx_cache_reuse = rx_cache_reuse;
	net_stats->rx_cache_full = rx_cache_full;
	net_stats->rx_cache_empty = rx_cache_empty;
	net_stats->rx_cache_busy = rx_cache_busy;
	net_stats->rx_cache_waive = rx_cache_waive;
}

static u16 nbl_res_txrx_get_max_desc_num(void)
{
	return NBL_MAX_DESC_NUM;
}

static u16 nbl_res_txrx_get_min_desc_num(void)
{
	return NBL_MIN_DESC_NUM;
}

static u16 nbl_res_txrx_get_tx_desc_num(void *priv, u32 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *ring = txrx_mgt->tx_rings[ring_index];

	return ring->desc_num;
}

static u16 nbl_res_txrx_get_rx_desc_num(void *priv, u32 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *ring = txrx_mgt->rx_rings[ring_index];

	return ring->desc_num;
}

static void nbl_res_txrx_set_tx_desc_num(void *priv, u32 ring_index, u16 desc_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *ring = txrx_mgt->tx_rings[ring_index];

	ring->desc_num = desc_num;
}

static void nbl_res_txrx_set_rx_desc_num(void *priv, u32 ring_index, u16 desc_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *ring = txrx_mgt->rx_rings[ring_index];

	ring->desc_num = desc_num;
}

static struct sk_buff *nbl_fetch_rx_buffer_lb_test(struct nbl_res_rx_ring *rx_ring,
						   const struct nbl_ring_desc *rx_desc,
						   u16 *num_buffers)
{
	struct nbl_rx_buffer *rx_buf;
	struct sk_buff *skb;
	const struct page *page;
	const void *page_addr;
	struct nbl_rx_extend_head *hdr;
	u32 size = 256;

	rx_buf = nbl_get_rx_buf(rx_ring);
	page = rx_buf->di->page;
	prefetchw(page);

	page_addr = page_address(page) + rx_buf->offset;
	prefetch(page_addr);

	skb = alloc_skb(size, GFP_KERNEL);
	if (unlikely(!skb))
		return NULL;

	prefetchw(skb->data);
	/* get number of buffers */
	hdr = (struct nbl_rx_extend_head *)page_addr;
	*num_buffers = le16_to_cpu(hdr->num_buffers);
	nbl_rx_csum(rx_ring, skb, hdr);

	memcpy(__skb_put(skb, size), page_addr + sizeof(*hdr), ALIGN(size, sizeof(long)));

	nbl_put_rx_buf(rx_ring, rx_buf);

	return skb;
}

static struct sk_buff *nbl_res_txrx_clean_rx_lb_test(void *priv, u32 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring = txrx_mgt->rx_rings[ring_index];
	struct nbl_ring_desc *rx_desc;
	struct sk_buff *skb;
	u16 num_buffers = 0;
	u16 cleaned_count = nbl_unused_rx_desc_count(rx_ring);

	if (cleaned_count & (~(NBL_MAX_BATCH_DESC - 1))) {
		nbl_alloc_rx_bufs(rx_ring, cleaned_count & (~(NBL_MAX_BATCH_DESC - 1)));
		cleaned_count = 0;
	}

	rx_desc = NBL_RX_DESC(rx_ring, rx_ring->next_to_clean);
	if (!nbl_ring_desc_used(rx_desc, rx_ring->used_wrap_counter))
		return NULL;

	/* rmb for read desc */
	rmb();

	skb = nbl_fetch_rx_buffer_lb_test(rx_ring, rx_desc, &num_buffers);
	if (!skb)
		return NULL;

	cleaned_count++;

	if (num_buffers > 1)
		nbl_err(common, NBL_DEBUG_RESOURCE, "More than one desc in lb rx, not supported\n");

	if (cleaned_count & (~(NBL_MAX_BATCH_DESC - 1)))
		nbl_alloc_rx_bufs(rx_ring, cleaned_count & (~(NBL_MAX_BATCH_DESC - 1)));

	return skb;
}

static dma_addr_t nbl_res_txrx_restore_abnormal_ring(void *priv, int ring_index, int type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	vector->started = false;
	napi_synchronize(&vector->napi);

	switch (type) {
	case NBL_TX:
		nbl_res_txrx_stop_tx_ring(res_mgt, ring_index);
		return nbl_res_txrx_start_tx_ring(res_mgt, ring_index);
	case NBL_RX:
		nbl_res_txrx_stop_rx_ring(res_mgt, ring_index);
		return nbl_res_txrx_start_rx_ring(res_mgt, ring_index, true);
	default:
		break;
	}

	return -EINVAL;
}

static int nbl_res_txrx_restart_abnormal_ring(void *priv, int ring_index, int type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index);
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	switch (type) {
	case NBL_TX:
		writel(tx_ring->notify_qid, tx_ring->notify_addr);
		break;
	case NBL_RX:
		nbl_res_txrx_kick_rx_ring(res_mgt, ring_index);
		break;
	default:
		break;
	}

	vector->started = true;

	return 0;
}

/* NBL_TXRX_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_TXRX_OPS_TBL								\
do {											\
	NBL_TXRX_SET_OPS(get_resource_pt_ops, nbl_res_get_pt_ops);			\
	NBL_TXRX_SET_OPS(alloc_rings, nbl_res_txrx_alloc_rings);			\
	NBL_TXRX_SET_OPS(remove_rings, nbl_res_txrx_remove_rings);			\
	NBL_TXRX_SET_OPS(start_tx_ring, nbl_res_txrx_start_tx_ring);			\
	NBL_TXRX_SET_OPS(stop_tx_ring, nbl_res_txrx_stop_tx_ring);			\
	NBL_TXRX_SET_OPS(start_rx_ring, nbl_res_txrx_start_rx_ring);			\
	NBL_TXRX_SET_OPS(stop_rx_ring, nbl_res_txrx_stop_rx_ring);			\
	NBL_TXRX_SET_OPS(kick_rx_ring, nbl_res_txrx_kick_rx_ring);			\
	NBL_TXRX_SET_OPS(dump_ring, nbl_res_txrx_dump_ring);				\
	NBL_TXRX_SET_OPS(dump_ring_stats, nbl_res_txrx_dump_ring_stats);		\
	NBL_TXRX_SET_OPS(get_vector_napi, nbl_res_txrx_get_vector_napi);		\
	NBL_TXRX_SET_OPS(set_vector_info, nbl_res_txrx_set_vector_info);		\
	NBL_TXRX_SET_OPS(get_tx_headroom, nbl_res_txrx_get_tx_headroom);		\
	NBL_TXRX_SET_OPS(get_queue_stats, nbl_res_txrx_get_queue_stats);		\
	NBL_TXRX_SET_OPS(get_net_stats, nbl_res_txrx_get_net_stats);			\
	NBL_TXRX_SET_OPS(get_max_desc_num, nbl_res_txrx_get_max_desc_num);		\
	NBL_TXRX_SET_OPS(get_min_desc_num, nbl_res_txrx_get_min_desc_num);		\
	NBL_TXRX_SET_OPS(get_tx_desc_num, nbl_res_txrx_get_tx_desc_num);		\
	NBL_TXRX_SET_OPS(get_rx_desc_num, nbl_res_txrx_get_rx_desc_num);		\
	NBL_TXRX_SET_OPS(set_tx_desc_num, nbl_res_txrx_set_tx_desc_num);		\
	NBL_TXRX_SET_OPS(set_rx_desc_num, nbl_res_txrx_set_rx_desc_num);		\
	NBL_TXRX_SET_OPS(clean_rx_lb_test, nbl_res_txrx_clean_rx_lb_test);		\
	NBL_TXRX_SET_OPS(restore_abnormal_ring, nbl_res_txrx_restore_abnormal_ring);	\
	NBL_TXRX_SET_OPS(restart_abnormal_ring, nbl_res_txrx_restart_abnormal_ring);	\
	NBL_TXRX_SET_OPS(register_vsi_ring, nbl_txrx_register_vsi_ring);		\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_txrx_setup_mgt(struct device *dev, struct nbl_txrx_mgt **txrx_mgt)
{
	*txrx_mgt = devm_kzalloc(dev, sizeof(struct nbl_txrx_mgt), GFP_KERNEL);
	if (!*txrx_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_txrx_remove_mgt(struct device *dev, struct nbl_txrx_mgt **txrx_mgt)
{
	devm_kfree(dev, *txrx_mgt);
	*txrx_mgt = NULL;
}

int nbl_txrx_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_txrx_mgt **txrx_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	txrx_mgt = &NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	return nbl_txrx_setup_mgt(dev, txrx_mgt);
}

void nbl_txrx_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_txrx_mgt **txrx_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	txrx_mgt = &NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	if (!(*txrx_mgt))
		return;

	nbl_txrx_remove_mgt(dev, txrx_mgt);
}

int nbl_txrx_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_TXRX_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_TXRX_OPS_TBL;
#undef  NBL_TXRX_SET_OPS

	return 0;
}

void nbl_txrx_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_TXRX_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_TXRX_OPS_TBL;
#undef  NBL_TXRX_SET_OPS
}
