// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_txrx.h"
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/vxlan.h>
#include <net/geneve.h>
#include <linux/sctp.h>
#include <linux/if_vlan.h>
#include <net/page_pool/helpers.h>
#include <linux/bpf_trace.h>

DEFINE_STATIC_KEY_FALSE(nbl_xdp_locking_key);
#define NBL_OFFLOAD_MAX_L2_LEN (ETH_HLEN + VLAN_HLEN * 2)

static enum nbl_vsi_type nbl_txrx_get_vsi_type(struct nbl_txrx_mgt *txrx_mgt, u16 ring_index)
{
	struct nbl_txrx_vsi_info *vsi_info;
	u32 i;

	for (i = 0; i < NBL_VSI_MAX; i++) {
		vsi_info = &txrx_mgt->vsi_info[i];
		if (ring_index >= vsi_info->ring_offset &&
		    ring_index < vsi_info->ring_offset + vsi_info->ring_num)
			return i;
	}

	WARN_ON(1);
	return NBL_VSI_MAX;
}

static struct netdev_queue *txring_txq(const struct nbl_res_tx_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}

static void nbl_res_tx_set_dport(struct nbl_resource_mgt *res_mgt,
				 struct nbl_res_tx_ring *tx_ring)
{
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	u16 *offset = tx_ring->cfg_offset;
	u32 *hdr = (u32 *)tx_ring->default_hdr;
	u16 mode = NBL_ESWITCH_NONE;
	u8 dport_id, fwd;

	memset(tx_ring->default_hdr, 0, tx_ring->extheader_tx_len);

	if (tx_ring->vsi_type == NBL_VSI_CTRL) {
		HDR_CFG(hdr, FIELD_POS(offset[NBL_FWD]), FIELD_OFFSET(offset[NBL_FWD]),
			FIELD_VLD(offset[NBL_FWD]), NBL_TX_FWD_TYPE_CPU_ASSIGNED_RSS_LAG);
		HDR_CFG(hdr, FIELD_POS(offset[NBL_DPORT]), FIELD_OFFSET(offset[NBL_DPORT]),
			FIELD_VLD(offset[NBL_DPORT]), NBL_TX_DPORT_HOST);

		hdr[0] =  NBL_TX_DEFAULT_HDR_LEN;

		return;
	} else if (tx_ring->vsi_type == NBL_VSI_XDP) {
		HDR_CFG(hdr, FIELD_POS(offset[NBL_FWD]),
			FIELD_OFFSET(offset[NBL_FWD]),
			FIELD_VLD(offset[NBL_FWD]), NBL_TX_FWD_TYPE_NORMAL);

		return;
	}

	dport_id = tx_ring->eth_id;
	if (txrx_mgt->novirtual)
		fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED;
	else
		fwd = NBL_TX_FWD_TYPE_NORMAL;

	if (res_mgt->resource_info->eswitch_info)
		mode = res_mgt->resource_info->eswitch_info->mode;
	tx_ring->bond = txrx_mgt->bond_info.bond_enable;

	if (mode == NBL_ESWITCH_OFFLOADS && tx_ring->bond) {
		fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED_RSS_LAG;
		dport_id = txrx_mgt->bond_info.lag_id << NBL_TX_DPORT_ID_LAG_OFFSET;
	} else if (mode == NBL_ESWITCH_OFFLOADS) {
		fwd = NBL_TX_FWD_TYPE_CPU_ASSIGNED;
	}

	if (tx_ring->bond) {
		if (tx_ring->eth_id == txrx_mgt->bond_info.eth_id[0])
			tx_ring->dport_id2 = txrx_mgt->bond_info.eth_id[1];
		else
			tx_ring->dport_id2 = txrx_mgt->bond_info.eth_id[0];
	}

	hdr[0] = NBL_TX_DEFAULT_HDR_LEN;
	HDR_CFG(hdr, FIELD_POS(offset[NBL_FWD]), FIELD_OFFSET(offset[NBL_FWD]),
		FIELD_VLD(offset[NBL_FWD]), fwd);
	HDR_CFG(hdr, FIELD_POS(offset[NBL_DPORT_ID]),
		FIELD_OFFSET(offset[NBL_DPORT_ID]),
		FIELD_VLD(offset[NBL_DPORT_ID]), dport_id);

	if (txrx_mgt->offload_type == NBL_VLAN_HW_OFFLOAD && tx_ring->vlan_proto)
		hdr[3] = ((1 << NBL_TX_VLAN_VID_OFFSET)) |
			  ((tx_ring->vlan_proto == ETH_P_8021AD) << NBL_TX_VLAN_TYPE_OFFSET) |
			  tx_ring->vlan_tci;
}

static struct nbl_res_tx_ring *
nbl_alloc_tx_ring(struct nbl_resource_mgt *res_mgt, struct net_device *netdev, u16 ring_index)
{
	enum nbl_fix_cap_type cap_type = NBL_QUEUE_NOTIFY_USE_LOCAL_CAP;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_tx_ring *ring;

	ring = devm_kzalloc(dev, sizeof(struct nbl_res_tx_ring), GFP_KERNEL);
	if (!ring)
		return NULL;

	ring->dma_dev = common->dma_dev;
	ring->eth_id = common->eth_id;
	ring->extheader_tx_len = txrx_mgt->extheader_tx_len;
	ring->ktls_inithdr_len = txrx_mgt->ktls_inithdr_len;
	ring->ktls_synchdr_len = txrx_mgt->ktls_synchdr_len;
	ring->queue_index = ring_index;
	ring->vsi_type = nbl_txrx_get_vsi_type(txrx_mgt, ring_index);
	ring->notify_addr = phy_ops->get_tail_ptr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (nbl_res_get_fix_capability(res_mgt, &cap_type))
		ring->notify_qid = (u16)(ring_index * 2 + 1);
	else
		ring->notify_qid = NBL_RES_NOFITY_QID(res_mgt, ring_index * 2 + 1);
	ring->netdev = netdev;
	ring->used_wrap_counter = 1;
	spin_lock_init(&ring->xmit_lock);
	ring->avail_used_flags |= BIT(NBL_PACKED_DESC_F_AVAIL);
	ring->fill_ktls_init_payload =
				NBL_RES_MGT_TO_PROD_OPS(res_mgt)->fill_ktls_init_payload;
	ring->simple_fwd = txrx_mgt->simple_fwd;
	ring->support_ptr = txrx_mgt->support_ptr;
	WARN_ON(!NBL_RES_MGT_TO_PROD_OPS(res_mgt)->tx_exthdr_offset);
	memcpy(ring->cfg_offset, NBL_RES_MGT_TO_PROD_OPS(res_mgt)->tx_exthdr_offset,
	       sizeof(ring->cfg_offset));

	return ring;
}

static int nbl_alloc_tx_rings(struct nbl_resource_mgt *res_mgt,
			      struct net_device *netdev, u16 tx_num)
{
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_tx_ring *ring;
	u16 ring_index;

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
		ring = nbl_alloc_tx_ring(res_mgt, netdev, ring_index);
		if (!ring)
			goto alloc_tx_ring_failed;

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
			      u16 rx_num)
{
	enum nbl_fix_cap_type cap_type = NBL_QUEUE_NOTIFY_USE_LOCAL_CAP;
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

	if (!NBL_RES_MGT_TO_PROD_OPS(res_mgt)->parse_rx_extend_header) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Rx header paser function not assigned.\n");
		return -EINVAL;
	}

	txrx_mgt->rx_ring_num = rx_num;
	txrx_mgt->extheader_rx_len = NBL_RX_EXTHEADER_LEN_DEFAULT;

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
		/* set netdev features after this function, so half_offload_en 0,
		 * set half_offload_en 1 when after set netdev features rx hash.
		 */
		ring->extheader_rx_len = txrx_mgt->extheader_rx_len;
		ring->txrx_mgt = txrx_mgt;
		ring->dma_dev = common->dma_dev;
		ring->queue_index = ring_index;
		ring->vsi_type = nbl_txrx_get_vsi_type(txrx_mgt, ring_index);
		if (nbl_res_get_fix_capability(res_mgt, &cap_type))
			ring->notify_qid = (u16)(ring_index * 2);
		else
			ring->notify_qid = NBL_RES_NOFITY_QID(res_mgt, ring_index * 2);
		ring->netdev = netdev;
		/* RX buffer length is determined by mtu,
		 * when netdev up we will set buf_len according to its mtu
		 */
		ring->buf_len = PAGE_SIZE / 2 - NBL_RX_PAD;

		ring->used_wrap_counter = 1;
		ring->avail_used_flags |= BIT(NBL_PACKED_DESC_F_AVAIL);
		ring->parse_rx_extend_header =
				NBL_RES_MGT_TO_PROD_OPS(res_mgt)->parse_rx_extend_header;
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

static int nbl_alloc_vectors(struct nbl_resource_mgt *res_mgt, u16 total_num, u16 xdp_ring_offset)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_vector *vector;
	u32 index;
	u16 xdp_ring_num;

	if (txrx_mgt->vectors) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to allocate vectors which already exists\n");
		return -EINVAL;
	}

	txrx_mgt->vectors = devm_kcalloc(dev, xdp_ring_offset, sizeof(struct nbl_res_vector *),
					 GFP_KERNEL);
	if (!txrx_mgt->vectors)
		return -ENOMEM;

	for (index = 0; index < xdp_ring_offset; index++) {
		vector = txrx_mgt->vectors[index];
		WARN_ON(vector);
		vector = devm_kzalloc(dev, sizeof(struct nbl_res_vector), GFP_KERNEL);
		if (!vector)
			goto alloc_vector_failed;

		vector->rx_ring = txrx_mgt->rx_rings[index];
		vector->tx_ring = txrx_mgt->tx_rings[index];
		WRITE_ONCE(txrx_mgt->vectors[index], vector);
	}

	xdp_ring_num = total_num - xdp_ring_offset;
	for (index = 0; index < xdp_ring_num; index++) {
		vector = txrx_mgt->vectors[index];
		vector->xdp_ring = txrx_mgt->tx_rings[index + xdp_ring_offset];
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

	count = txrx_mgt->xdp_ring_offset;
	for (index = 0; index < count; index++) {
		vector = txrx_mgt->vectors[index];
		devm_kfree(dev, vector);
	}
	devm_kfree(dev, txrx_mgt->vectors);
	txrx_mgt->vectors = NULL;
}

static int nbl_res_txrx_alloc_rings(void *priv, struct nbl_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;
	int err = 0;

	err = nbl_alloc_tx_rings(res_mgt, param->netdev, param->tx_ring_num);
	if (err)
		return err;

	err = nbl_alloc_rx_rings(res_mgt, param->netdev, param->rx_ring_num);
	if (err)
		goto alloc_rx_rings_err;

	err = nbl_alloc_vectors(res_mgt, param->tx_ring_num, param->xdp_ring_offset);
	if (err)
		goto alloc_vectors_err;

	txrx_mgt->xdp_ring_offset = param->xdp_ring_offset;
	txrx_mgt->xdp_ring_num = param->tx_ring_num - param->xdp_ring_offset;

	if (txrx_mgt->xdp_ring_num && num_online_cpus() > txrx_mgt->xdp_ring_num)
		static_branch_inc(&nbl_xdp_locking_key);

	nbl_info(res_mgt->common, NBL_DEBUG_RESOURCE,
		 "Alloc rings for %d tx, %d rx, %d xdp_offset\n",
		 param->tx_ring_num, param->rx_ring_num, param->xdp_ring_offset);
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
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;

	if (txrx_mgt->xdp_ring_num && num_online_cpus() > txrx_mgt->xdp_ring_num &&
	    static_key_enabled(&nbl_xdp_locking_key))
		static_branch_dec(&nbl_xdp_locking_key);

	nbl_free_vectors(res_mgt);
	nbl_free_tx_rings(res_mgt);
	nbl_free_rx_rings(res_mgt);
	nbl_info(res_mgt->common, NBL_DEBUG_RESOURCE, "Remove rings");
}

static dma_addr_t nbl_res_txrx_start_tx_ring(void *priv, struct nbl_tx_ring_start_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, param->ring_index);

	if (tx_ring->tx_bufs) {
		nbl_err(res_mgt->common, NBL_DEBUG_RESOURCE,
			"Try to setup a TX ring with buffer management array already allocated\n");
		return (dma_addr_t)NULL;
	}

	tx_ring->desc_num = param->queue_size;
	tx_ring->tx_bufs = devm_kcalloc(dev, tx_ring->desc_num, sizeof(*tx_ring->tx_bufs),
					GFP_KERNEL);
	if (!tx_ring->tx_bufs)
		return (dma_addr_t)NULL;

	/* Alloc twice memory, and second half is used to back up the desc for desc checking */
	tx_ring->size = ALIGN(tx_ring->desc_num * sizeof(struct nbl_ring_desc), PAGE_SIZE);
	tx_ring->desc = dmam_alloc_coherent(dma_dev, tx_ring->size, &tx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);
	if (!tx_ring->desc) {
		nbl_err(res_mgt->common, NBL_DEBUG_RESOURCE,
			"Allocate %u bytes descriptor DMA memory for TX queue %u failed\n",
			tx_ring->size, tx_ring->queue_index);
		goto alloc_dma_err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	tx_ring->valid = true;
	tx_ring->interleave_seg_disable = param->interleave_seg_disable;
	tx_ring->max_payload_size = pcie_get_mps(pdev);
	nbl_res_tx_set_dport(res_mgt, tx_ring);
	nbl_debug(res_mgt->common, NBL_DEBUG_RESOURCE, "Start tx ring %d", param->ring_index);
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

	if (page_ref_count(cache->page_cache[cache->head].page) !=
	    cache->page_cache[cache->head].pagecnt_bias) {
		stats->rx_cache_busy++;
		return false;
	}

	*dma_info = cache->page_cache[cache->head];
	if (dma_info->pagecnt_bias <= NBL_MAX_BATCH_DESC) {
		page_ref_add(cache->page_cache[cache->head].page, U16_MAX - dma_info->pagecnt_bias);
		dma_info->pagecnt_bias = U16_MAX;
	}
	cache->head = (cache->head + 1) & (cache->size - 1);
	stats->rx_cache_reuse++;

	dma_sync_single_for_device(rx_ring->dma_dev, dma_info->addr,
				   dma_info->size, DMA_FROM_DEVICE);
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

	dma_info->addr = dma_map_page_attrs(rx_ring->dma_dev, dma_info->page, 0, dma_info->size,
					    DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);

	if (unlikely(dma_mapping_error(rx_ring->dma_dev, dma_info->addr))) {
		page_pool_recycle_direct(rx_ring->page_pool, dma_info->page);
		dma_info->page = NULL;
		return -ENOMEM;
	}

	dma_info->pagecnt_bias = U16_MAX;
	page_ref_add(dma_info->page, U16_MAX - 1);

	return 0;
}

static inline int nbl_get_rx_frag(struct nbl_res_rx_ring *rx_ring, struct nbl_rx_buffer *buffer)
{
	int err = 0;

	/* first buffer alloc page */
	if (buffer->first_in_page)
		err = nbl_page_alloc_pool(rx_ring, buffer->di);

	return err;
}

static inline bool nbl_alloc_rx_bufs(struct nbl_res_rx_ring *rx_ring, u16 count)
{
	u32 buf_len;
	u16 next_to_use, head, add = 0;
	__le16 head_flags = 0;
	struct nbl_ring_desc *rx_desc, *head_desc;
	struct nbl_rx_buffer *rx_buf;
	int i;

	buf_len = rx_ring->buf_len;
	next_to_use = rx_ring->next_to_use;

	head = next_to_use;
	head_desc = NBL_RX_DESC(rx_ring, next_to_use);
	rx_desc = NBL_RX_DESC(rx_ring, next_to_use);
	rx_buf = NBL_RX_BUF(rx_ring, next_to_use);

	do {
		if (nbl_get_rx_frag(rx_ring, rx_buf))
			break;

		for (i = 0; i < rx_ring->frags_num_per_page; i++, rx_desc++, rx_buf++) {
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

		next_to_use += rx_ring->frags_num_per_page;
		add += rx_ring->frags_num_per_page;
		count -= rx_ring->frags_num_per_page;
	} while (count);

	if (add) {
		/* wmb */
		dma_wmb();
		head_desc->flags = head_flags;
		if (next_to_use == rx_ring->desc_num) {
			next_to_use = 0;
			rx_ring->avail_used_flags ^=
				BIT(NBL_PACKED_DESC_F_AVAIL) |
				BIT(NBL_PACKED_DESC_F_USED);
		}
		rx_ring->next_to_use = next_to_use;
		rx_ring->vq_free_cnt -= add;
	}

	return !!count;
}

static void nbl_unmap_and_free_tx_resource(struct nbl_res_tx_ring *ring,
					   struct nbl_tx_buffer *tx_buffer,
					   bool free, bool in_napi)
{
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(ring);

	if (tx_buffer->skb) {
		if (likely(!nbl_res_txrx_is_xdp_ring(ring))) {
			if (likely(free)) {
				if (in_napi)
					napi_consume_skb(tx_buffer->skb, NBL_TX_POLL_WEIGHT);
				else
					dev_kfree_skb_any(tx_buffer->skb);
			}
		} else {
			if (likely(free))
				page_frag_free(tx_buffer->raw_buff);
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

	kfree(tx_buffer->tls_pkthdr);
	tx_buffer->tls_pkthdr = NULL;
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	tx_buffer->page = 0;
	tx_buffer->bytecount = 0;
	tx_buffer->gso_segs = 0;
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
	struct nbl_res_vector *vector = NULL;

	if (tx_ring->vsi_type != NBL_VSI_XDP)
		vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	if (vector && vector->started) {
		vector->started = false;
		/* Flush napi task, to ensue the sched napi finish. So napi will no to access the
		 * ring memory(wild point), bacause the vector->started has set false.
		 */
		napi_synchronize(&vector->nbl_napi.napi);
		napi_disable(&vector->nbl_napi.napi);
	}

	tx_ring->valid = false;

	nbl_free_tx_ring_bufs(tx_ring);
	WRITE_ONCE(NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index), tx_ring);

	devm_kfree(dev, tx_ring->tx_bufs);
	tx_ring->tx_bufs = NULL;

	dmam_free_coherent(dma_dev, tx_ring->size, tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
	tx_ring->dma = (dma_addr_t)NULL;
	tx_ring->size = 0;

	if (tx_ring->vsi_type == NBL_VSI_DATA)
		netdev_tx_reset_queue(txring_txq(tx_ring));

	nbl_debug(res_mgt->common, NBL_DEBUG_RESOURCE, "Stop tx ring %d", ring_index);
}

static inline bool nbl_dev_page_is_reusable(struct page *page, u8 nid)
{
	return likely(page_to_nid(page) == nid && !page_is_pfmemalloc(page));
}

static inline int nbl_rx_cache_put(struct nbl_res_rx_ring *rx_ring, struct nbl_dma_info *dma_info)
{
	struct nbl_page_cache *cache = &rx_ring->page_cache;
	u32 tail_next = (cache->tail + 1) & (cache->size - 1);
	struct nbl_rx_queue_stats *stats = &rx_ring->rx_stats;

	if (tail_next == cache->head) {
		stats->rx_cache_full++;
		return 0;
	}

	if (!nbl_dev_page_is_reusable(dma_info->page, rx_ring->nid)) {
		stats->rx_cache_waive++;
		return 1;
	}

	cache->page_cache[cache->tail] = *dma_info;
	cache->tail = tail_next;

	return 2;
}

static inline void nbl_page_release_dynamic(struct nbl_res_rx_ring *rx_ring,
					    struct nbl_dma_info *dma_info, bool recycle)
{
	u32 ret;

	if (likely(recycle)) {
		ret = nbl_rx_cache_put(rx_ring, dma_info);
		if (ret == 2)
			return;
		if (ret == 1)
			goto free_page;
		dma_unmap_page_attrs(rx_ring->dma_dev, dma_info->addr, dma_info->size,
				     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
		/**
		 * This page almost must recycle failed.
		 * Unless the packet is small packet, and construct from alloc_skb,
		 * and page_cache is full.
		 * The page_pool function __page_pool_put_page:
		 * (likely(page_ref_count(page)) == 1) maybe true.
		 * So the code "not recycle waive page maybe pointless."
		 */
		__page_frag_cache_drain(dma_info->page, dma_info->pagecnt_bias - 1);
		page_pool_recycle_direct(rx_ring->page_pool, dma_info->page);

		return;
	}

free_page:
	dma_unmap_page_attrs(rx_ring->dma_dev, dma_info->addr, dma_info->size,
			     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
	__page_frag_cache_drain(dma_info->page, dma_info->pagecnt_bias - 1);
	page_pool_put_page(rx_ring->page_pool, dma_info->page, dma_info->size, recycle);
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

	for (i = 0; i < rx_ring->desc_num; i++) {
		rx_buf = NBL_RX_BUF(rx_ring, i);
		nbl_put_rx_frag(rx_ring, rx_buf, false);
	}

	for (i = rx_ring->page_cache.head; i != rx_ring->page_cache.tail;
	     i = (i + 1) & (rx_ring->page_cache.size - 1)) {
		struct nbl_dma_info *dma_info = &rx_ring->page_cache.page_cache[i];

		nbl_page_release_dynamic(rx_ring, dma_info, false);
	}

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->next_to_free = 0;
	rx_ring->vq_free_cnt = 0;
	rx_ring->page_cache.head = 0;
	rx_ring->page_cache.tail = 0;

	rx_ring->used_wrap_counter = 1;
	rx_ring->avail_used_flags = BIT(NBL_PACKED_DESC_F_AVAIL);
	memset(rx_ring->desc, 0, rx_ring->size);
}

static void nbl_free_rx_ring_init_bufs(struct nbl_res_rx_ring *rx_ring)
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

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->next_to_free = 0;
	rx_ring->vq_free_cnt = 0;
	rx_ring->page_cache.head = 0;
	rx_ring->page_cache.tail = 0;

	rx_ring->used_wrap_counter = 1;
	rx_ring->avail_used_flags = BIT(NBL_PACKED_DESC_F_AVAIL);
	memset(rx_ring->desc, 0, rx_ring->size);
}

static int nbl_rx_alloc_page_cache(struct nbl_res_rx_ring *rx_ring, int node)
{
	struct nbl_page_cache *cache = &rx_ring->page_cache;

	//maybe size equals (rx_ring->desc_num/rx_ring->frags_num_per_page) * 2
	//to optimization on 64kb PAGE_SIZE environment.
	cache->size = rx_ring->desc_num;
	if (rx_ring->frags_num_per_page == 1)
		cache->size *= 2;

	cache->page_cache = kvzalloc_node(cache->size * sizeof(*cache->page_cache),
					  GFP_KERNEL, node);
	if (!cache->page_cache)
		return -ENOMEM;

	return 0;
}

static void nbl_rx_free_page_cache(struct nbl_res_rx_ring *rx_ring)
{
	kvfree(rx_ring->page_cache.page_cache);
}

static dma_addr_t nbl_res_txrx_start_rx_ring(void *priv, struct nbl_rx_ring_start_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, param->ring_index);
	struct nbl_res_vector *vector = NULL;
	struct page_pool_params pp_params = {0};
	int pkt_len, hw_mtu, max_linear_len;
	int buf_size;
	int order = 0;
	int i, j;
	u16 rx_pad, tailroom;
	u16 mtu = U16_MAX;

	if (rx_ring->rx_bufs) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Try to setup a RX ring with buffer management array already allocated\n");
		return (dma_addr_t)NULL;
	}

	if (rx_ring->vsi_type != NBL_VSI_XDP)
		vector = NBL_RES_MGT_TO_VECTOR(res_mgt, param->ring_index);

	/* only data_vsi drop pkt > mtu */
	if (rx_ring->vsi_type == NBL_VSI_DATA)
		mtu = rx_ring->netdev->mtu + NBL_PKT_HDR_PAD;

	rx_ring->desc_num = param->queue_size;
	rx_ring->vq_free_cnt = param->queue_size;
	rx_ring->max_pkt_len = mtu;
	hw_mtu = rx_ring->netdev->mtu + NBL_PKT_HDR_PAD + NBL_BUFFER_HDR_LEN(rx_ring);
	if (param->rxq_large_buf && hw_mtu > NBL_4K_FRAME_SIZE)
		rx_ring->rxq_large_buf = true;
	else
		rx_ring->rxq_large_buf = false;
	tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	rx_pad = NBL_RX_PAD;

	max_linear_len = rx_ring->rxq_large_buf ? NBL_RX_BUFSZ_LARGE : NBL_RX_BUFSZ;
	if (rx_ring->xdp_prog) {
		if (!rx_ring->xdp_enhance)
			rx_pad = XDP_PACKET_HEADROOM;
		else
			rx_pad = NBL_XDP_HEADROM_SIZE;
		max_linear_len = PAGE_SIZE;
	}
	pkt_len = SKB_DATA_ALIGN(hw_mtu + rx_pad) + tailroom;
	rx_ring->linear_skb = true;

	if (pkt_len > max_linear_len) {
		if (rx_ring->xdp_prog)
			return (dma_addr_t)NULL;
		rx_ring->linear_skb = false;
		rx_pad = 0;
		tailroom = 0;
		pkt_len = SKB_DATA_ALIGN(hw_mtu);
	}

	buf_size = rx_ring->rxq_large_buf ? NBL_RX_BUFSZ_LARGE : NBL_RX_BUFSZ;
	if (rx_ring->xdp_prog)
		buf_size = roundup_pow_of_two(pkt_len);
	WARN_ON(buf_size > PAGE_SIZE);
	rx_ring->frags_num_per_page = (PAGE_SIZE * (1 << order)) / buf_size;
	WARN_ON(rx_ring->frags_num_per_page > NBL_MAX_BATCH_DESC);
	rx_ring->buf_len = buf_size - rx_pad - tailroom;

	pp_params.order = order;
	pp_params.flags = 0;
	/**
	 * Page_pool has two units stored pages.
	 * One call ptr_ring, the producer is page_pool_recycle_* API.
	 * ptr_ring depth equals pool_size.
	 * The consumer is page_pool_alloc_pages.
	 *
	 * One call pp_alloc_cache, a lockless page_pool cache.
	 * pp_alloc_cache depth is PP_ALLOC_CACHE_SIZE, that is 128.
	 * The use priority preferred ptr_ring.
	 * The producer is page_pool_recycle_direct_* API or alloc_pages_bulk_array in slow path.
	 * The consumer is page_pool_alloc_pages.
	 *
	 * Because we not use skb_mark_for_recycle.(different linux version compat complexly.)
	 * Almost nobody call page_pool_recycle except drivers called in low-probability scenarios.
	 *
	 * Now page_pool only affect page_cache busy or empty scene.
	 * Driver will call page_pool_alloc_pages, but ptr_ring has no pages.
	 * Slow path will alloc PP_ALLOC_CACHE_REFILL, that is 64, by alloc_pages_bulk_array.
	 *
	 * So pool_size almost pointless.
	 * Now we always use ring depth, not consider mtu.
	 * If we consider use skb_mark_for_recycle in the future, we need consider pool_size again.
	 */
	pp_params.pool_size = rx_ring->desc_num;
	pp_params.nid = dev_to_node(dev);
	pp_params.dev = dev;
	pp_params.dma_dir = DMA_FROM_DEVICE;

	if (dev_to_node(dev) == NUMA_NO_NODE)
		rx_ring->nid = 0;
	else
		rx_ring->nid = dev_to_node(dev);

	rx_ring->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(rx_ring->page_pool)) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Page_pool Allocate %u Failed failed\n",
			rx_ring->queue_index);
		return (dma_addr_t)NULL;
	}

	rx_ring->di = kvzalloc_node(array_size(rx_ring->desc_num / rx_ring->frags_num_per_page,
					       sizeof(struct nbl_dma_info)),
					       GFP_KERNEL, dev_to_node(dev));
	if (!rx_ring->di) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Dma info Allocate %u Failed failed\n",
			rx_ring->queue_index);
		goto alloc_di_err;
	}

	if (nbl_rx_alloc_page_cache(rx_ring, dev_to_node(dev)))
		goto alloc_page_cache_failed;

	rx_ring->rx_bufs = devm_kcalloc(dev, rx_ring->desc_num, sizeof(*rx_ring->rx_bufs),
					GFP_KERNEL);
	if (!rx_ring->rx_bufs)
		goto alloc_buffers_err;

	/* Alloc twice memory, and second half is used to back up the desc for desc checking */
	rx_ring->size = ALIGN(rx_ring->desc_num * sizeof(struct nbl_ring_desc), PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dma_dev, rx_ring->size, &rx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);
	if (!rx_ring->desc) {
		nbl_err(common, NBL_DEBUG_RESOURCE,
			"Allocate %u bytes descriptor DMA memory for RX queue %u failed\n",
			rx_ring->size, rx_ring->queue_index);
		goto alloc_dma_err;
	}

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;

	j = 0;
	for (i = 0; i < rx_ring->desc_num / rx_ring->frags_num_per_page; i++) {
		struct nbl_dma_info *di = &rx_ring->di[i];
		struct nbl_rx_buffer *buffer = &rx_ring->rx_bufs[j];
		int f;

		di->size = (PAGE_SIZE * (1 << order));
		for (f = 0; f < rx_ring->frags_num_per_page; f++, j++) {
			buffer = &rx_ring->rx_bufs[j];
			buffer->di = di;
			buffer->size = buf_size;
			buffer->offset = rx_pad + f * buf_size;
			buffer->rx_pad = rx_pad;
			buffer->last_in_page = false;
			if (f)
				buffer->first_in_page = false;
			else
				buffer->first_in_page = true;
		}

		buffer->last_in_page = true;
	}

	if (nbl_alloc_rx_bufs(rx_ring, rx_ring->desc_num))
		goto alloc_rx_bufs_err;

	rx_ring->valid = true;
	if (param->use_napi && vector && !vector->started) {
		vector->started = true;
		napi_enable(&vector->nbl_napi.napi);
		if (vector->net_msix_mask_en)
			writel(vector->irq_data, vector->irq_enable_base);
	}

	nbl_debug(common, NBL_DEBUG_RESOURCE, "Start rx ring %d", param->ring_index);
	return rx_ring->dma;

alloc_rx_bufs_err:
	nbl_free_rx_ring_init_bufs(rx_ring);
	dmam_free_coherent(dma_dev, rx_ring->size, rx_ring->desc, rx_ring->dma);
	rx_ring->desc = NULL;
	rx_ring->dma = (dma_addr_t)NULL;
alloc_dma_err:
	devm_kfree(dev, rx_ring->rx_bufs);
	rx_ring->rx_bufs = NULL;
alloc_buffers_err:
	nbl_rx_free_page_cache(rx_ring);
alloc_page_cache_failed:
	kvfree(rx_ring->di);
alloc_di_err:
	page_pool_destroy(rx_ring->page_pool);
	rx_ring->size = 0;
	return (dma_addr_t)NULL;
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
	nbl_rx_free_page_cache(rx_ring);
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

static inline void nbl_write_doorbell(struct nbl_res_tx_ring *tx_ring)
{
	u32 notify_val = 0;

	notify_val = (!!((tx_ring->avail_used_flags & BIT(NBL_PACKED_DESC_F_AVAIL))) << 31) |
			((tx_ring->next_to_use) << 16) | tx_ring->notify_qid;
	writel(notify_val, tx_ring->notify_addr);
}

static inline void nbl_rep_update_tx_stats(struct net_device *netdev, struct nbl_tx_buffer *buffer)
{
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	u16 rep_data_index = 0, rep_vsi_id;

	if (!eswitch_info || eswitch_info->mode != NBL_ESWITCH_OFFLOADS)
		return;

	if (!buffer->skb)
		return;

	rep_vsi_id = *(u16 *)&buffer->skb->cb[NBL_SKB_FILL_VSI_ID_OFF];
	rep_data_index = nbl_res_get_rep_idx(eswitch_info, rep_vsi_id);
	if (rep_data_index >= eswitch_info->num_vfs)
		return;

	if (eswitch_info->rep_data[rep_data_index].rep_vsi_id == rep_vsi_id) {
		u64_stats_update_begin(&eswitch_info->rep_data[rep_data_index].rep_syncp);
		eswitch_info->rep_data[rep_data_index].tx_packets += buffer->gso_segs;
		eswitch_info->rep_data[rep_data_index].tx_bytes += buffer->bytecount;
		u64_stats_update_end(&eswitch_info->rep_data[rep_data_index].rep_syncp);
	}
}

static struct net_device *nbl_get_rep_netdev(struct nbl_resource_mgt *res_mgt, u16 rep_vsi_id)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	u16 rep_data_index = 0;

	rep_data_index = nbl_res_get_rep_idx(eswitch_info, rep_vsi_id);
	if (rep_data_index >= eswitch_info->num_vfs)
		return NULL;
	if (eswitch_info->rep_data[rep_data_index].rep_vsi_id == rep_vsi_id)
		return eswitch_info->rep_data[rep_data_index].netdev;
	nbl_info(common, NBL_DEBUG_RESOURCE, "get rep netdev error rep_vsi_id:%d\n", rep_vsi_id);
	return NULL;
}

static inline void nbl_rep_update_rx_stats(struct net_device *netdev,
					   struct sk_buff *skb, u16 sport_id)
{
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_eswitch_info *eswitch_info = NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct net_device *rep_netdev = NULL;
	u16 rep_data_index = 0;

	if (!eswitch_info || eswitch_info->mode != NBL_ESWITCH_OFFLOADS)
		return;

	rep_data_index = nbl_res_get_rep_idx(eswitch_info, sport_id);
	if (rep_data_index >= eswitch_info->num_vfs)
		return;

	rep_netdev = nbl_get_rep_netdev(res_mgt, sport_id);
	if (!rep_netdev) {
		/* it's a common case when switchdev mode is opening */
		nbl_info(common, NBL_DEBUG_RESOURCE,
			 "rep update netdev fail. sport_id:%d\n", sport_id);
		return;
	}
	skb->dev = rep_netdev;

	if (eswitch_info->rep_data[rep_data_index].rep_vsi_id == sport_id) {
		u64_stats_update_begin(&eswitch_info->rep_data[rep_data_index].rep_syncp);
		eswitch_info->rep_data[rep_data_index].rx_packets += 1;
		eswitch_info->rep_data[rep_data_index].rx_bytes += skb->len;
		u64_stats_update_end(&eswitch_info->rep_data[rep_data_index].rep_syncp);
	}
}

static int nbl_res_txrx_clean_tx_irq(struct nbl_res_tx_ring *tx_ring)
{
	struct nbl_tx_buffer *tx_buffer;
	struct nbl_ring_desc *tx_desc;
	unsigned int i = tx_ring->next_to_clean;
	unsigned int total_tx_pkts = 0;
	unsigned int total_tx_bytes = 0;
	unsigned int total_tx_descs = 0;
	int count = 128;

	tx_buffer = NBL_TX_BUF(tx_ring, i);
	tx_desc = NBL_TX_DESC(tx_ring, i);
	i -= tx_ring->desc_num;

	do {
		struct nbl_ring_desc *end_desc = tx_buffer->next_to_watch;

		if (!nbl_ring_desc_used(tx_desc, tx_ring->used_wrap_counter))
			break;

		/* smp_rmb */
		smp_rmb();

		if (unlikely(!end_desc))
			break;
		total_tx_pkts += tx_buffer->gso_segs;
		total_tx_bytes += tx_buffer->bytecount;

		if (tx_ring->vsi_type == NBL_VSI_CTRL)
			nbl_rep_update_tx_stats(tx_ring->netdev, tx_buffer);

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

	tx_ring->stats.bytes += total_tx_bytes;
	tx_ring->stats.packets += total_tx_pkts;
	tx_ring->stats.descs += total_tx_descs;
	if (tx_ring->vsi_type == NBL_VSI_DATA)
		netdev_tx_completed_queue(txring_txq(tx_ring), total_tx_pkts, total_tx_bytes);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_tx_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     tx_ring->vsi_type == NBL_VSI_DATA &&
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

static inline void nbl_add_rx_frag(struct nbl_rx_buffer *rx_buffer,
				   struct sk_buff *skb, unsigned int size)
{
	rx_buffer->di->pagecnt_bias--;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->di->page,
			rx_buffer->offset, size, rx_buffer->size);
}

static void nbl_txrx_register_vsi_ring(void *priv, struct nbl_vsi_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	txrx_mgt->vsi_info[param->vsi_index].ring_offset = param->ring_offset;
	txrx_mgt->vsi_info[param->vsi_index].ring_num = param->ring_num;
}

static int nbl_res_txrx_cfg_rx_half_offload(void *priv,
					    struct nbl_cfg_rx_half_offload_param *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_txrx_vsi_info *vsi_info = &txrx_mgt->vsi_info[prm->vsi_index];
	struct nbl_res_rx_ring *rx_ring;
	u16 i, header_len;

	if (!txrx_mgt->tx_rings || !txrx_mgt->rx_rings)
		return 0;

	if (prm->half_offload_en)
		header_len = NBL_RX_EXTHEADER_LEN_DRACO_HALF_OFFLOAD;
	else
		header_len = NBL_RX_EXTHEADER_LEN_DEFAULT;

	for (i = vsi_info->ring_offset; i < vsi_info->ring_offset + vsi_info->ring_num; i++) {
		rx_ring = txrx_mgt->rx_rings[i];
		if (rx_ring)
			rx_ring->extheader_rx_len = header_len;
	}

	return 0;
}

static int nbl_res_txrx_cfg_rx_vlan_parse(void *priv, struct nbl_ch_prm_cfg_rx_vlan_parse *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 en;

	if (prm->rx_vlan_mode > RX_VLAN_PARSE_OFF)
		en = true;
	else
		en = false;

	NBL_OPS_CALL(phy_ops->cfg_rx_vlan_parse,
		     (NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
		      prm->vsi_id, en, prm->rx_vlan_mode));

	return 0;
}

static int nbl_res_txrx_cfg_rss_hash(void *priv, struct nbl_ch_prm_cfg_rss_hash *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	NBL_OPS_CALL(phy_ops->cfg_rss_hash,
		     (NBL_RES_MGT_TO_PHY_PRIV(res_mgt), prm->vsi_id, prm->rss_hash_mode));

	return 0;
}

static int nbl_res_txrx_cfg_txrx_vlan(void *priv, struct nbl_cfg_txrx_vlan_param *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_txrx_vsi_info *vsi_info = &txrx_mgt->vsi_info[prm->vsi_index];
	struct nbl_res_tx_ring *tx_ring;
	struct nbl_res_rx_ring *rx_ring;
	u16 i;

	if (!txrx_mgt->tx_rings || !txrx_mgt->rx_rings)
		return 0;

	for (i = vsi_info->ring_offset; i < vsi_info->ring_offset + vsi_info->ring_num; i++) {
		tx_ring = txrx_mgt->tx_rings[i];
		rx_ring = txrx_mgt->rx_rings[i];

		if (tx_ring) {
			tx_ring->vlan_tci = prm->vlan_tci;
			tx_ring->vlan_proto = prm->vlan_proto;
			nbl_res_tx_set_dport(res_mgt, tx_ring);
		}

		if (rx_ring) {
			rx_ring->vlan_tci = prm->vlan_tci & VLAN_VID_MASK;
			rx_ring->vlan_proto = prm->vlan_proto;
		}
	}

	return 0;
}

static inline struct nbl_rx_buffer *nbl_get_rx_buf(struct nbl_res_rx_ring *rx_ring)
{
	struct nbl_rx_buffer *rx_buf;

	rx_buf = NBL_RX_BUF(rx_ring, rx_ring->next_to_clean);
	dma_sync_single_range_for_cpu(rx_ring->dma_dev, rx_buf->di->addr, rx_buf->offset,
				      rx_ring->buf_len, DMA_FROM_DEVICE);

	return rx_buf;
}

static struct sk_buff *nbl_construct_skb(struct nbl_rx_buffer *rx_buf, struct xdp_buff *xdp)
{
	struct sk_buff *skb;
	unsigned int truesize = rx_buf->size;
	u8 metasize = xdp->data - xdp->data_meta;

	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	rx_buf->di->pagecnt_bias--;
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	skb_put(skb, xdp->data_end - xdp->data);
	if (metasize)
		skb_metadata_set(skb, metasize);

	return skb;
}

static struct sk_buff *nbl_construct_skb_nolinear(struct nbl_res_rx_ring *rx_ring,
						  struct napi_struct *napi,
						  struct nbl_rx_buffer *rx_buf,
						  struct xdp_buff *xdp)
{
	struct sk_buff *skb;
	u16 truesize = rx_buf->size;
	u16 size = xdp->data_end - xdp->data;
	u16 headlen;

	skb = napi_alloc_skb(napi, NBL_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	headlen = size;
	if (headlen > NBL_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data, NBL_RX_HDR_SIZE);
	memcpy(__skb_put(skb, headlen), xdp->data, ALIGN(headlen, sizeof(long)));
	size -= headlen;
	if (size) {
		rx_buf->di->pagecnt_bias--;
		skb_add_rx_frag(skb, 0, rx_buf->di->page,
				rx_buf->offset + NBL_BUFFER_HDR_LEN(rx_ring) + headlen,
				size, truesize);
	}

	return skb;
}

static inline int nbl_maybe_stop_tx(struct nbl_res_tx_ring *tx_ring, unsigned int size)
{
	if (likely(nbl_unused_tx_desc_count(tx_ring) >= size))
		return 0;

	if (tx_ring->vsi_type != NBL_VSI_DATA)
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

static int nbl_res_txrx_xmit_xdp_ring(struct nbl_res_tx_ring *xdp_ring, struct xdp_frame *xdpf)
{
	u16 index  = xdp_ring->next_to_use;
	u16 avail_used_flags = xdp_ring->avail_used_flags;
	unsigned int size;
	dma_addr_t dma;
	u8 *hdr;
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(xdp_ring);
	struct nbl_tx_buffer *tx_buffer = NBL_TX_BUF(xdp_ring, index);
	struct nbl_ring_desc *tx_desc = NBL_TX_DESC(xdp_ring, index);
	const struct ethhdr *eth;

	if (xdpf->headroom < xdp_ring->extheader_tx_len)
		return -EOVERFLOW;

	if (unlikely(nbl_maybe_stop_tx(xdp_ring, 1))) {
		xdp_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	size = xdpf->len;
	eth = (struct ethhdr *)xdpf->data;
	xdpf->headroom -= xdp_ring->extheader_tx_len;
	xdpf->data -= xdp_ring->extheader_tx_len;
	hdr = xdpf->data;
	memcpy(hdr, xdp_ring->default_hdr, xdp_ring->extheader_tx_len);
	xdpf->len += xdp_ring->extheader_tx_len;
	dma = dma_map_single(dma_dev, xdpf->data, xdpf->len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, dma)) {
		xdp_ring->tx_stats.tx_dma_busy++;
		return NETDEV_TX_BUSY;
	}

	dma_unmap_addr_set(tx_buffer, dma, dma);
	dma_unmap_len_set(tx_buffer, len, xdpf->len);
	tx_buffer->raw_buff = xdpf->data;
	tx_buffer->gso_segs = 1;
	tx_buffer->bytecount = size;
	tx_desc->addr = cpu_to_le64(dma);
	tx_desc->len = xdpf->len;
	tx_desc->id = 0;
	index++;
	if (index == xdp_ring->desc_num) {
		index = 0;
		xdp_ring->avail_used_flags ^=
			1 << NBL_PACKED_DESC_F_AVAIL |
			1 << NBL_PACKED_DESC_F_USED;
	}

	/* todo:xdp add multicast case */
	xdp_ring->tx_stats.tx_unicast_packets++;
	tx_buffer->next_to_watch = tx_desc;

	/* wmb */
	wmb();

	xdp_ring->next_to_use = index;
	tx_desc->flags = cpu_to_le16(avail_used_flags);

	return NETDEV_TX_OK;
}

static int nbl_res_txrx_xmit_xdp_buff(struct nbl_res_rx_ring *rx_ring, struct xdp_buff *xdp_buff)
{
	int ret;
	struct nbl_res_tx_ring *xdp_ring;
	struct xdp_frame *xdpf;
	struct nbl_txrx_mgt *txrx_mgt = rx_ring->txrx_mgt;

	xdpf = xdp_convert_buff_to_frame(xdp_buff);
	if (unlikely(!xdpf))
		goto buff_to_frame_failed;

	xdp_ring = nbl_res_txrx_select_xdp_ring(txrx_mgt);
	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_lock(&xdp_ring->xmit_lock);

	ret = nbl_res_txrx_xmit_xdp_ring(xdp_ring, xdpf);
	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_unlock(&xdp_ring->xmit_lock);

	return ret;
buff_to_frame_failed:
	return -1;
}

static int
nbl_res_txrx_run_xdp(struct nbl_res_rx_ring *rx_ring, struct nbl_rx_buffer *rx_buf,
		     struct xdp_buff *xdp_buff)
{
	const struct ethhdr *eth;
	int err;
	enum xdp_action act;
	u8 *hdr = page_address(rx_buf->di->page) + rx_buf->offset;

	if (unlikely(((xdp_buff->data_end - xdp_buff->data) >=
		      (rx_ring->buf_len - rx_ring->extheader_rx_len)) &&
		     *(u8 *)(hdr + NBL_RX_EXT_HDR_NUM_BUFFERS_OFFSET) > 1))
		return 0;

	xdp_init_buff(xdp_buff, rx_buf->size, &rx_ring->xdp_rxq);
	act = bpf_prog_run_xdp(rx_ring->xdp_prog, xdp_buff);
	switch (act) {
	case XDP_PASS:
		return 0;
	case XDP_TX:
		rx_buf->di->pagecnt_bias--;
		err = nbl_res_txrx_xmit_xdp_buff(rx_ring, xdp_buff);
		if (unlikely(err)) {
			rx_buf->di->pagecnt_bias++;
			goto xdp_aborted;
		}
		__set_bit(NBL_RQ_FLAGS_XDP_XMIT, rx_ring->flags);
		rx_ring->rx_stats.xdp_tx_packets++;
		break;
	case XDP_REDIRECT:
		rx_buf->di->pagecnt_bias--;
		err = xdp_do_redirect(rx_ring->netdev, xdp_buff, rx_ring->xdp_prog);
		if (unlikely(err)) {
			rx_buf->di->pagecnt_bias++;
			goto xdp_aborted;
		}
		__set_bit(NBL_RQ_FLAGS_XDP_REDIRECT, rx_ring->flags);
		rx_ring->rx_stats.xdp_redirect_packets++;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, rx_ring->xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
xdp_aborted:
		trace_xdp_exception(rx_ring->netdev, rx_ring->xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		rx_ring->rx_stats.xdp_drop_packets++;
		break;
	}

	rx_ring->next_to_clean++;
	rx_ring->vq_free_cnt++;
	if (rx_ring->next_to_clean >= rx_ring->desc_num) {
		rx_ring->next_to_clean -= rx_ring->desc_num;
		rx_ring->used_wrap_counter ^= 1;
	}
	prefetch(NBL_RX_DESC(rx_ring, rx_ring->next_to_clean));
	rx_ring->stats.bytes += (xdp_buff->data_end - xdp_buff->data);
	eth = (struct ethhdr *)(xdp_buff->data);
	if (is_multicast_ether_addr(eth->h_dest))
		rx_ring->rx_stats.rx_multicast_packets++;
	else
		rx_ring->rx_stats.rx_unicast_packets++;

	return 1;
}

static int
nbl_res_txrx_xdp_xmit(struct net_device *netdev, int n, struct xdp_frame **frame, u32 flags)
{
	int ret;
	int i;
	int nxmit = 0;
	struct nbl_res_tx_ring *xdp_ring;
	struct nbl_resource_mgt *res_mgt =
				NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	xdp_ring = nbl_res_txrx_select_xdp_ring(txrx_mgt);
	if (unlikely(!xdp_ring))
		return -ENXIO;

	if (unlikely(!xdp_ring->valid))
		return -ENETDOWN;

	if (unlikely(!nbl_res_txrx_is_xdp_ring(xdp_ring)))
		return -ENXIO;

	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_lock(&xdp_ring->xmit_lock);

	for (i = 0; i < n; i++) {
		ret = nbl_res_txrx_xmit_xdp_ring(xdp_ring, frame[i]);
		if (ret)
			break;

		nxmit++;
	}

	if (unlikely(flags & XDP_XMIT_FLUSH))
		nbl_write_doorbell(xdp_ring);

	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_unlock(&xdp_ring->xmit_lock);

	return nxmit;
}

static void
nbl_res_txrx_update_xdp_tail_locked(struct nbl_res_rx_ring *rx_ring)
{
	struct nbl_res_tx_ring *xdp_ring;
	struct nbl_txrx_mgt *txrx_mgt = rx_ring->txrx_mgt;

	xdp_ring = nbl_res_txrx_select_xdp_ring(txrx_mgt);
	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_lock(&xdp_ring->xmit_lock);

	nbl_write_doorbell(xdp_ring);

	if (static_branch_unlikely(&nbl_xdp_locking_key))
		spin_unlock(&xdp_ring->xmit_lock);
}

static int nbl_res_txrx_register_xdp_rxq(void *priv, u8 ring_index)
{
	int err;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);

	err = xdp_rxq_info_reg(&rx_ring->xdp_rxq, rx_ring->netdev, rx_ring->queue_index,
			       vector->nbl_napi.napi.napi_id);
	if (err < 0) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Register xdp rxq err\n");
		return -1;
	}

	err = xdp_rxq_info_reg_mem_model(&rx_ring->xdp_rxq, MEM_TYPE_PAGE_SHARED, NULL);
	if (err < 0) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "Register xdp rxq mem model err\n");
		xdp_rxq_info_unreg(&rx_ring->xdp_rxq);
		return -1;
	}

	return 0;
}

static void nbl_res_txrx_unregister_xdp_rxq(void *priv, u8 ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);

	xdp_rxq_info_unreg(&rx_ring->xdp_rxq);
}

static inline void nbl_res_txrx_build_xdp_buff(struct nbl_rx_buffer *rx_buf,
					       struct xdp_buff *xdp,
					       u16 size,
					       u8 pkt_hdr_len)
{
	char *p, *buf;

	p = page_address(rx_buf->di->page) + rx_buf->offset;
	buf = p - rx_buf->rx_pad;
	size -= pkt_hdr_len;
	xdp_prepare_buff(xdp, buf, rx_buf->rx_pad + pkt_hdr_len, size, true);
}

static int nbl_res_txrx_clean_rx_irq(struct nbl_res_rx_ring *rx_ring,
				     struct napi_struct *napi,
				     int budget)
{
	u16 total_rx_pkts = 0;
	u16 vq_free_cnt;
	u8 pkt_hdr_len = NBL_BUFFER_HDR_LEN(rx_ring);

	while (likely(total_rx_pkts < budget)) {
		struct xdp_buff xdp;
		struct nbl_ring_desc *rx_desc = NBL_RX_DESC(rx_ring, rx_ring->next_to_clean);
		struct nbl_rx_buffer *rx_buf = nbl_get_rx_buf(rx_ring);
		u8 *hdr;
		struct sk_buff *skb = NULL;
		unsigned int size;
		u16 sport_id, i;
		u8 num_buffers;

		if (!nbl_ring_desc_used(rx_desc, rx_ring->used_wrap_counter))
			break;

		// nbl_trace(clean_rx_irq, rx_ring, rx_desc);

		dma_rmb();
		hdr = page_address(rx_buf->di->page) + rx_buf->offset;
		net_prefetch(hdr);

		size = le32_to_cpu(rx_desc->len);
		nbl_res_txrx_build_xdp_buff(rx_buf, &xdp, size, pkt_hdr_len);
		if (rx_ring->linear_skb && size < rx_ring->buf_len) {
			if (READ_ONCE(rx_ring->xdp_prog) &&
			    nbl_res_txrx_run_xdp(rx_ring, rx_buf, &xdp)) {
				total_rx_pkts++;
				continue;
			}
			skb = nbl_construct_skb(rx_buf, &xdp);
		} else {
			skb = nbl_construct_skb_nolinear(rx_ring, napi, rx_buf, &xdp);
		}

		if (unlikely(!skb)) {
			rx_ring->rx_stats.rx_alloc_buf_err_cnt++;
			break;
		}

		rx_ring->next_to_clean++;
		rx_ring->vq_free_cnt++;
		if (rx_ring->next_to_clean >= rx_ring->desc_num) {
			rx_ring->next_to_clean -= rx_ring->desc_num;
			rx_ring->used_wrap_counter ^= 1;
		}
		prefetch(NBL_RX_DESC(rx_ring, rx_ring->next_to_clean));
		skb_record_rx_queue(skb, rx_ring->queue_index);
		sport_id = NBL_CALL_RX_PARSE(rx_ring->parse_rx_extend_header,
					     rx_ring, hdr, skb);
		num_buffers = *(u8 *)(hdr + NBL_RX_EXT_HDR_NUM_BUFFERS_OFFSET);
		for (i = 1; i < num_buffers; i++) {
			struct nbl_rx_buffer *rx_buf = nbl_get_rx_buf(rx_ring);
			struct nbl_ring_desc *rx_desc = NBL_RX_DESC(rx_ring,
								    rx_ring->next_to_clean);

			size = le32_to_cpu(rx_desc->len);
			rx_buf->di->pagecnt_bias--;
			skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buf->di->page,
					rx_buf->offset, size, rx_buf->size);
			rx_ring->next_to_clean++;
			rx_ring->vq_free_cnt++;
			if (rx_ring->next_to_clean >= rx_ring->desc_num) {
				rx_ring->next_to_clean -= rx_ring->desc_num;
				rx_ring->used_wrap_counter ^= 1;
			}
			prefetch(NBL_RX_DESC(rx_ring, rx_ring->next_to_clean));
		}
		if (unlikely(eth_skb_pad(skb)))
			continue;

		if (unlikely(skb->len > rx_ring->max_pkt_len)) {
			rx_ring->rx_stats.rx_oversize_pkts_sw_drop++;
			dev_kfree_skb_any(skb);
			continue;
		}

		if (unlikely(sport_id == U16_MAX)) {
			dev_kfree_skb_any(skb);
			continue;
		}

		total_rx_pkts++;
		rx_ring->stats.bytes += skb->len;
		skb->protocol = eth_type_trans(skb, rx_ring->netdev);
		if (unlikely(skb->pkt_type == PACKET_BROADCAST ||
			     skb->pkt_type == PACKET_MULTICAST))
			rx_ring->rx_stats.rx_multicast_packets++;
		else
			rx_ring->rx_stats.rx_unicast_packets++;

		if (rx_ring->vsi_type == NBL_VSI_CTRL)
			nbl_rep_update_rx_stats(rx_ring->netdev, skb, sport_id);

		// nbl_trace(clean_rx_irq_indicate, rx_ring, rx_desc, skb);
		napi_gro_receive(napi, skb);
	}

	rx_ring->stats.packets += total_rx_pkts;
	if (__test_and_clear_bit(NBL_RQ_FLAGS_XDP_REDIRECT, rx_ring->flags))
		xdp_do_flush();

	if (__test_and_clear_bit(NBL_RQ_FLAGS_XDP_XMIT, rx_ring->flags))
		nbl_res_txrx_update_xdp_tail_locked(rx_ring);

	vq_free_cnt = rx_ring->vq_free_cnt & (~(NBL_MAX_BATCH_DESC - 1));
	if (vq_free_cnt) {
		u16 next_to_use = rx_ring->next_to_use;
		u16 next_to_free = rx_ring->next_to_free;
		u16 desc_num = rx_ring->desc_num;
		u16 free_gap, release_cnt, i;
		bool failure = 0;

		if ((next_to_use + vq_free_cnt) > desc_num)
			vq_free_cnt = desc_num - next_to_use;

		/* After a partial refill failure, next_to_free runs ahead of
		 * next_to_use: those pages were already recycled but the
		 * descriptors were not refilled. Release only what is left
		 * in the consumed window and never rewind next_to_free, or
		 * the same page gets recycled twice.
		 */
		free_gap = (next_to_free + desc_num - next_to_use) % desc_num;
		release_cnt = vq_free_cnt - min(vq_free_cnt, free_gap);
		if ((next_to_free + release_cnt) > desc_num)
			release_cnt = desc_num - next_to_free;

		for (i = next_to_free; i < next_to_free + release_cnt; i++)
			nbl_put_rx_frag(rx_ring, NBL_RX_BUF(rx_ring, i), 1);

		next_to_free += release_cnt;
		if (next_to_free == desc_num)
			next_to_free = 0;
		rx_ring->next_to_free = next_to_free;

		failure = nbl_alloc_rx_bufs(rx_ring, vq_free_cnt);

		return failure ? budget : total_rx_pkts;
	}

	return total_rx_pkts;
}

static int nbl_res_napi_poll(struct napi_struct *napi, int budget)
{
	struct nbl_napi_struct *nbl_napi = container_of(napi, struct nbl_napi_struct, napi);
	struct nbl_res_vector *vector = container_of(nbl_napi, struct nbl_res_vector, nbl_napi);
	struct nbl_res_tx_ring *tx_ring;
	struct nbl_res_tx_ring *xdp_ring;
	struct nbl_res_rx_ring *rx_ring;
	int complete = 1, cleaned = 0, tx_done = 1, xdp_done = 1;

	tx_ring = vector->tx_ring;
	rx_ring = vector->rx_ring;
	xdp_ring = vector->xdp_ring;

	if (vector->started) {
		tx_done = nbl_res_txrx_clean_tx_irq(tx_ring);
		if (xdp_ring && xdp_ring->valid)
			xdp_done = nbl_res_txrx_clean_tx_irq(xdp_ring);

		cleaned = nbl_res_txrx_clean_rx_irq(rx_ring, napi, budget);
	}

	if (!tx_done || !xdp_done)
		complete = 0;

	if (cleaned >= budget)
		complete = 0;

	if (!complete)
		return budget;

	if (!napi_complete_done(napi, cleaned))
		return min_t(int, cleaned, budget - 1);

	/* unmask irq passthrough for performace */
	nbl_napi->complete_cnt++;
	if (vector->net_msix_mask_en && atomic_cmpxchg_acquire(&nbl_napi->is_irq, 1, 0) == 1) {
		writel(vector->irq_data, vector->irq_enable_base);
		nbl_napi->unmask_cnt++;
	}

	return min_t(int, cleaned, budget - 1);
}

static inline unsigned int nbl_xmit_desc_count(struct sk_buff *skb, bool interleave_seg_disable)
{
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;

	if (interleave_seg_disable)
		return (nr_frags + 1) * 2;
	else
		return nr_frags + 1;
}

/* set up TSO(TCP Segmentation Offload) */
static u32 nbl_tx_tso(struct nbl_res_tx_ring *tx_ring, struct nbl_tx_buffer *first, u32 *pkthdr)
{
	struct sk_buff *skb = first->skb;
	u16 *offset = tx_ring->cfg_offset;
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
	u32 pkt_info;
	u16 tso_info;
	u8 header_len = 0;
	u8 l4_start;

	if (skb->ip_summed != CHECKSUM_PARTIAL || !skb_is_gso(skb))
		return 1;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	pkt_info = (ip.hdr - skb->data) >> 1;

	if (skb->encapsulation) {
		/* only draco support */
		if (ip.v4->version == 4)
			pkt_info |= (NBL_TX_OIPT_IPV4 << NBL_TX_DRACO_OUTER_L3_TYPE_OFFSET);
		else if (ip.v6->version == 6)
			pkt_info |= (NBL_TX_OIPT_IPV6 << NBL_TX_DRACO_OUTER_L3_TYPE_OFFSET);

		if (skb_shinfo(skb)->gso_type & (SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)) {
			pkthdr[1] |= NBL_TX_L4TUNT_UDP_TUNNEL;
		} else if (skb_shinfo(skb)->gso_type & (SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6)) {
			pkthdr[1] |= NBL_TX_L4TUNT_GRE_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
		} else {
			pkthdr[1] |= NBL_TX_L4TUNT_GRE_TUNNEL;
		}

		pkt_info |= (((l4.hdr - ip.hdr) >> 2) << NBL_TX_DRACO_OUTER_L3_LEN_OFFSET);
		ip.hdr = skb_inner_network_header(skb);
		pkt_info |= (((ip.hdr - l4.hdr) >> 1) << NBL_TX_DRACO_TNL_LEN_OFFSET);
		l4.hdr = skb_inner_transport_header(skb);
		pkthdr[2] |= (0x3 << NBL_TX_DRACO_INNER_CSUM_OFFSET);
		tx_ring->tx_stats.tso_inner_packets++;
		tx_ring->tx_stats.tso_inner_bytes += skb->len;
		tx_ring->tx_stats.tx_csum_inner_packets++;
	} else {
		tx_ring->tx_stats.tso_packets++;
		tx_ring->tx_stats.tso_bytes += skb->len;
		tx_ring->tx_stats.tx_csum_packets++;
	}

	/* length of (MAC + IP) header */
	l4_start = (u8)(l4.hdr - skb->data);
	pkt_info |= ((l4.hdr - ip.hdr) >> 2) << NBL_TX_DRACO_L3_LEN_OFFSET;
	if (ip.v4->version == 4)
		pkt_info |= (NBL_TX_IIPT_IPV4 << NBL_TX_DRACO_L3_TYPE_OFFSET);
	else if (ip.v6->version == 6)
		pkt_info |= (NBL_TX_IIPT_IPV6 << NBL_TX_DRACO_L3_TYPE_OFFSET);

	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		header_len = (u8)sizeof(l4.udp) + l4_start;
		pkt_info |= (NBL_TX_L4T_UDP << NBL_TX_DRACO_L4_TYPE_OFFSET);
		pkt_info |= ((sizeof(struct udphdr) >> 2) << NBL_TX_DRACO_L4_LEN_OFFSET);
	} else {
		header_len = (u8)(l4.tcp->doff * 4 + l4_start);
		pkt_info |= (NBL_TX_L4T_TCP << NBL_TX_DRACO_L4_TYPE_OFFSET);
		pkt_info |= (l4.tcp->doff << NBL_TX_DRACO_L4_LEN_OFFSET);
	}

	pkthdr[0] = pkt_info;
	tso_info = 1 << NBL_TSO_OFFSET | skb_shinfo(skb)->gso_size;
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_MSS]), FIELD_OFFSET(offset[NBL_MSS]),
		FIELD_VLD(offset[NBL_MSS]), tso_info);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_CSUM]), FIELD_OFFSET(offset[NBL_CSUM]),
		FIELD_VLD(offset[NBL_CSUM]), 0x3);

	first->hlen = header_len;
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * header_len;

	return first->gso_segs;
}

/* set up Tx checksum offload */
static u32 nbl_tx_csum(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb, u32 *pkthdr)
{
	u16 *offset = tx_ring->cfg_offset;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (skb_is_gso(skb))
		return 1;

	/* in skb csum offload, only support offload one layer csum,
	 * except SKB_GSO_UDP_TUNNEL_CSUM.
	 * in non-tso scene, see udp_set_csum code,
	 * select inner or outer according to nocheck config.
	 * drivers can juge it according to csum_start and csum_offset, but too trouble.
	 * So we both offload inner and outer like mlx5_core.
	 */
	if (skb->encapsulation) {
		pkthdr[2] |= (0x5 << NBL_TX_DRACO_INNER_CSUM_OFFSET);
		tx_ring->tx_stats.tx_csum_inner_packets++;
	} else {
		HDR_CFG(pkthdr, FIELD_POS(offset[NBL_CSUM]), FIELD_OFFSET(offset[NBL_CSUM]),
			FIELD_VLD(offset[NBL_CSUM]), 0x1);
		tx_ring->tx_stats.tx_csum_packets++;
	}

	return 1;
}

static inline int nbl_tx_fill_desc(struct nbl_res_tx_ring *tx_ring, u64 dma, u32 size,
				   u16 index, bool first, bool page)
{
	struct nbl_tx_buffer *tx_buffer = NBL_TX_BUF(tx_ring, index);
	struct nbl_ring_desc *tx_desc = NBL_TX_DESC(tx_ring, index);
	u16 mask = (tx_ring->max_payload_size - 1);
	u32 align_size = (tx_ring->max_payload_size - (dma & mask)) & mask;

	if (align_size >= size || !tx_ring->interleave_seg_disable)
		align_size = 0;

	tx_buffer->dma = dma;
	tx_buffer->len = size;
	tx_buffer->page = page;

	tx_desc->addr = dma;
	tx_desc->len = align_size ? align_size : size;
	if (!first)
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	index++;
	if (index == tx_ring->desc_num) {
		index = 0;
		tx_ring->avail_used_flags ^=
			1 << NBL_PACKED_DESC_F_AVAIL |
			1 << NBL_PACKED_DESC_F_USED;
	}

	if (!align_size)
		return index;

	tx_buffer = NBL_TX_BUF(tx_ring, index);
	tx_desc = NBL_TX_DESC(tx_ring, index);
	tx_buffer->dma = 0;
	tx_buffer->len = 0;

	tx_desc->addr = dma + align_size;
	tx_desc->len = size - align_size;
	tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	index++;
	if (index == tx_ring->desc_num) {
		index = 0;
		tx_ring->avail_used_flags ^=
			1 << NBL_PACKED_DESC_F_AVAIL |
			1 << NBL_PACKED_DESC_F_USED;
	}

	return index;
}

static int nbl_map_skb(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb,
		       u16 first, u16 *desc_index)
{
	u16 index = *desc_index;
	const skb_frag_t *frag;
	unsigned int frag_num = skb_shinfo(skb)->nr_frags;
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(tx_ring);
	unsigned int i;
	unsigned int size;
	dma_addr_t dma;

	size = skb_headlen(skb);
	dma = dma_map_single(dma_dev, skb->data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, dma))
		return -1;

	index = nbl_tx_fill_desc(tx_ring, dma, size, index, first, 0);

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

		index = nbl_tx_fill_desc(tx_ring, dma, size, index, 0, 1);
		frag++;
	}

	*desc_index = index;
	return 0;
}

#if IS_ENABLED(CONFIG_TLS_DEVICE)
#define NBL_KTLS_INIT_PACKET_FLAGS	(0x9)
static bool nbl_ktls_send_init_packet(struct nbl_resource_mgt *res_mgt,
				      struct nbl_res_tx_ring *tx_ring,
				      struct nbl_ktls_offload_context_tx *priv_tx)
{
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	u16 *offset = tx_ring->cfg_offset;
	struct nbl_tx_buffer *first;
	struct nbl_ring_desc *first_desc;
	u32 *pkthdr;
	u8 *init_payload;
	dma_addr_t hdrdma;
	u32 pkthdr_len = tx_ring->extheader_tx_len;
	u32 inithdr_len = tx_ring->ktls_inithdr_len;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	u16 head = tx_ring->next_to_use;
	u16 i = head;

	first = NBL_TX_BUF(tx_ring, head);
	first_desc = NBL_TX_DESC(tx_ring, head);

	pkthdr = kzalloc(pkthdr_len + inithdr_len, GFP_KERNEL);
	if (!pkthdr)
		return false;

	memset(pkthdr, 0, pkthdr_len);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_TLS_IDX]), FIELD_OFFSET(offset[NBL_TLS_IDX]),
		FIELD_VLD(offset[NBL_TLS_IDX]), priv_tx->index);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_TLS_FLAG]), FIELD_OFFSET(offset[NBL_TLS_FLAG]),
		FIELD_VLD(offset[NBL_TLS_FLAG]), NBL_KTLS_INIT_PACKET_FLAGS);

	init_payload = (u8 *)pkthdr + pkthdr_len;
	NBL_CALL_KTLS_INIT(tx_ring->fill_ktls_init_payload, init_payload, priv_tx);

	hdrdma = dma_map_single(dma_dev, pkthdr, pkthdr_len + inithdr_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, hdrdma)) {
		kfree(pkthdr);
		return false;
	}

	first_desc->len = cpu_to_le32(pkthdr_len + inithdr_len);
	first_desc->addr = cpu_to_le64(hdrdma);
	first_desc->id = cpu_to_le16(head);
	first_desc->flags = cpu_to_le16(avail_used_flags);

	first->dma = hdrdma;
	first->len = pkthdr_len + inithdr_len;
	first->tls_pkthdr = (u8 *)pkthdr;
	i++;
	if (i == tx_ring->desc_num) {
		i = 0;
		tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
			1 << NBL_PACKED_DESC_F_USED;
	}

	first->next_to_watch = first_desc;
	tx_ring->next_to_use = i;

	nbl_write_doorbell(tx_ring);

	return true;
}

static enum nbl_ktls_sync_retval
nbl_tls_resync_info_get(struct nbl_ktls_offload_context_tx *priv_tx, u32 seq,
			int datalen, struct nbl_tx_resync_info *info)
{
	int remaining = 0;
	int i = 0;
	enum nbl_ktls_sync_retval ret = NBL_KTLS_SYNC_DONE;
	struct tls_record_info  *record;
	struct tls_offload_context_tx *tx_ctx;
	unsigned long flags;
	bool ends_before;

	tx_ctx = priv_tx->tx_ctx;

	spin_lock_irqsave(&tx_ctx->lock, flags);
	record = tls_get_record(tx_ctx, seq, &info->rec_num);
	if (!record) {
		ret = NBL_KTLS_SYNC_FAIL;
		goto out;
	}

	ends_before = before(seq + datalen - 1, tls_record_start_seq(record));

	if (unlikely(tls_record_is_start_marker(record))) {
		ret = ends_before ? NBL_KTLS_SYNC_SKIP_NO_DATA : NBL_KTLS_SYNC_FAIL;
		goto out;
	} else if (ends_before) {
		ret = NBL_KTLS_SYNC_FAIL;
		goto out;
	}

	info->resync_len = seq - tls_record_start_seq(record);
	remaining = info->resync_len;

	while (remaining > 0) {
		skb_frag_t *frag = &record->frags[i];

		remaining -= skb_frag_size(frag);
		info->frags[i++] = *frag;
	}

	if (remaining < 0)
		skb_frag_size_add(&info->frags[i - 1], remaining);

	info->nr_frags = i;
out:
	spin_unlock_irqrestore(&tx_ctx->lock, flags);
	return ret;
}

static bool nbl_ktls_send_resync_one(struct nbl_resource_mgt *res_mgt,
				     struct nbl_res_tx_ring *tx_ring,
				     struct nbl_ktls_sync_packet *sync_packet,
				     struct nbl_tx_resync_info *info)
{
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_tx_buffer *tx_buffer;
	struct nbl_ring_desc *tx_desc;
	dma_addr_t hdrdma;
	u16 head = tx_ring->next_to_use;
	u32 red_off = 0;
	int len, k;

	tx_buffer = NBL_TX_BUF(tx_ring, head);
	tx_desc = NBL_TX_DESC(tx_ring, head);

	dev_dbg(NBL_RING_TO_DEV(tx_ring), "send one resync packet.\n");
	for (k = 0; k < info->nr_frags; k++) {
		skb_frag_t *f = &info->frags[k];
		u32 fsz = skb_frag_size(f);

		memcpy(sync_packet->redata + red_off, skb_frag_address(f), fsz);
		red_off += fsz;
	}

	len = info->resync_len + NBL_KTLS_SYNC_PKT_LEN;

	hdrdma = dma_map_single(dma_dev, sync_packet, len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, hdrdma)) {
		kfree(sync_packet);
		return false;
	}

	tx_desc->addr = cpu_to_le64(hdrdma);
	tx_desc->len = cpu_to_le32(len);
	tx_desc->id = cpu_to_le16(head);
	tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags);

	tx_buffer->dma = hdrdma;
	tx_buffer->len = len;
	tx_buffer->next_to_watch = tx_desc;
	tx_buffer->tls_pkthdr = (u8 *)&sync_packet->pkthdr;

	tx_ring->next_to_use = head + 1;
	if (tx_ring->next_to_use == tx_ring->desc_num) {
		tx_ring->next_to_use = 0;
		tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
					     1 << NBL_PACKED_DESC_F_USED;
	}

	nbl_write_doorbell(tx_ring);

	return true;
}

static bool nbl_ktls_send_resync_mul(struct nbl_resource_mgt *res_mgt,
				     struct nbl_res_tx_ring *tx_ring,
				     struct nbl_ktls_sync_packet *sync_packet,
				     struct nbl_tx_resync_info *info)
{
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_tx_extend_head_leonis *pkthdr;
	struct nbl_tx_buffer *head_buffer;
	struct nbl_ring_desc *head_desc;
	struct nbl_tx_buffer *tx_buffer = NBL_TX_BUF(tx_ring, tx_ring->next_to_use);
	struct nbl_ring_desc *tx_desc = NBL_TX_DESC(tx_ring, tx_ring->next_to_use);
	dma_addr_t hdrdma;
	dma_addr_t bufdma;
	dma_addr_t firstdma = 0;
	skb_frag_t *frag;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	u16 head = tx_ring->next_to_use;
	u16 index = head;
	u32 total_len = 0;
	u32 remain_len;
	int last_len;
	int len, k;
	unsigned int fsz;

	last_len = info->resync_len % NBL_KTLS_PER_CELL_LEN + NBL_KTLS_PER_CELL_LEN;
	if (last_len > NBL_KTLS_MAX_CELL_LEN)
		last_len -= NBL_KTLS_PER_CELL_LEN;

	dev_dbg(NBL_RING_TO_DEV(tx_ring), "send mul resync packet.\n");
	/* Each packet in the middle is 512 bytes */
	remain_len = info->resync_len - last_len;

	head_buffer = NBL_TX_BUF(tx_ring, head);
	head_desc = NBL_TX_DESC(tx_ring, head);

	hdrdma = dma_map_single(dma_dev, sync_packet, NBL_KTLS_SYNC_PKT_LEN, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, hdrdma)) {
		kfree(sync_packet);
		goto dma_map_error;
	}

	head_desc->addr = cpu_to_le64(hdrdma);
	head_desc->len = cpu_to_le32(NBL_KTLS_SYNC_PKT_LEN);
	head_desc->id = cpu_to_le16(head);

	head_buffer->dma = hdrdma;
	head_buffer->len = NBL_KTLS_SYNC_PKT_LEN;
	head_buffer->tls_pkthdr = (u8 *)&sync_packet->pkthdr;

	for (k = 0; k < info->nr_frags; k++) {
		frag = &info->frags[k];
		fsz = skb_frag_size(frag);
		dev_dbg(NBL_RING_TO_DEV(tx_ring), "send frag %d len %u.\n", k, fsz);
		bufdma = skb_frag_dma_map(dma_dev, frag, 0, fsz, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, bufdma)) {
			index++;
			goto dma_map_error;
		}
		firstdma = bufdma;
		total_len = fsz;
		while (fsz) {
			index++;
			if (index == tx_ring->desc_num) {
				index = 0;
				tx_buffer = NBL_TX_BUF(tx_ring, 0);
				tx_desc = NBL_TX_DESC(tx_ring, 0);
				tx_ring->avail_used_flags ^=
					1 << NBL_PACKED_DESC_F_AVAIL |
					1 << NBL_PACKED_DESC_F_USED;
			} else {
				tx_buffer = NBL_TX_BUF(tx_ring, index);
				tx_desc = NBL_TX_DESC(tx_ring, index);
			}

			len = remain_len % NBL_KTLS_PER_CELL_LEN;
			len = (len) ? (len) : min_t(unsigned int, fsz, NBL_KTLS_PER_CELL_LEN);
			if (fsz < len || remain_len == 0)
				len = fsz;

			tx_desc->addr = cpu_to_le64(bufdma);
			tx_desc->len = cpu_to_le32(len);
			tx_desc->id = cpu_to_le16(head);
			tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags);
			dev_dbg(NBL_RING_TO_DEV(tx_ring),
				"send %u packet len %d remain_len %u.\n", head, len, remain_len);

			bufdma += len;
			fsz -= len;
			if (remain_len == 0) {
				last_len -= len;
				if (last_len > 0)
					tx_desc->flags = cpu_to_le16(le16_to_cpu(tx_desc->flags) |
								     NBL_PACKED_DESC_F_NEXT);
				continue;
			}

			remain_len -= len;
			if (remain_len % NBL_KTLS_PER_CELL_LEN) {
				tx_desc->flags = cpu_to_le16(le16_to_cpu(tx_desc->flags) |
							     NBL_PACKED_DESC_F_NEXT);
				continue;
			}

			head_buffer->next_to_watch = tx_desc;
			head_desc->flags = cpu_to_le16(avail_used_flags | NBL_PACKED_DESC_F_NEXT);

			index++;
			if (index == tx_ring->desc_num) {
				index = 0;
				head = 0;
				head_buffer = NBL_TX_BUF(tx_ring, 0);
				head_desc = NBL_TX_DESC(tx_ring, 0);
				tx_ring->avail_used_flags ^=
					1 << NBL_PACKED_DESC_F_AVAIL |
					1 << NBL_PACKED_DESC_F_USED;
			} else {
				head = index;
				head_buffer = NBL_TX_BUF(tx_ring, head);
				head_desc = NBL_TX_DESC(tx_ring, head);
			}
			avail_used_flags = tx_ring->avail_used_flags;

			pkthdr = kzalloc(sizeof(*pkthdr), GFP_KERNEL);
			if (!pkthdr)
				goto dma_map_error;

			pkthdr->l4s_sid = sync_packet->pkthdr.l4s_sid;
			pkthdr->l4s_redun_ind = 1;
			pkthdr->l4s_hdl_ind = 1;
			hdrdma = dma_map_single(dma_dev, pkthdr,
						sizeof(struct nbl_tx_extend_head_leonis),
						DMA_TO_DEVICE);
			if (dma_mapping_error(dma_dev, hdrdma)) {
				kfree(pkthdr);
				goto dma_map_error;
			}

			head_desc->addr = cpu_to_le64(hdrdma);
			head_desc->len = cpu_to_le32(sizeof(struct nbl_tx_extend_head_leonis));
			head_desc->id = cpu_to_le16(head);

			head_buffer->dma = hdrdma;
			head_buffer->len = sizeof(struct nbl_tx_extend_head_leonis);
			head_buffer->tls_pkthdr = (u8 *)pkthdr;
		}
		tx_buffer->dma = firstdma;
		tx_buffer->len = total_len;
		tx_buffer->page = 1;
	}

	/* write barrier to ensure tx buffers are set up before the descriptor flags */
	wmb();

	head_buffer->next_to_watch = tx_desc;
	head_desc->flags = cpu_to_le16(avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	tx_ring->next_to_use = index + 1;
	if (tx_ring->next_to_use == tx_ring->desc_num) {
		tx_ring->next_to_use = 0;
		tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
					     1 << NBL_PACKED_DESC_F_USED;
	}

	nbl_write_doorbell(tx_ring);

	return true;

dma_map_error:
	while (index != tx_ring->next_to_use) {
		if (unlikely(!index))
			index = tx_ring->desc_num;
		index--;
		nbl_unmap_and_free_tx_resource(tx_ring, NBL_TX_BUF(tx_ring, index), false, false);
	}
	tx_ring->avail_used_flags = avail_used_flags;

	return false;
}

/* Set the maximum packet length to 6144 bytes and occur in the first or last packets.
 * The middle packets are all 4096 bytes long bacause the hardware cell is 4096 bytes.
 * If pkt_len > 6144, pkt_len -= 4096, make sure the packet is greater than 2048 bytes.
 */
bool nbl_ktls_send_resync_packet_leonis(struct nbl_resource_mgt *res_mgt,
					struct nbl_res_tx_ring *tx_ring,
					struct nbl_ktls_offload_context_tx *priv_tx,
					struct nbl_tx_resync_info *info)
{
	struct nbl_ktls_sync_packet *sync_packet;
	__be64 rec_num;

	sync_packet = kzalloc(sizeof(*sync_packet), GFP_KERNEL);
	if (!sync_packet)
		return false;

	sync_packet->pkthdr.l4s_sid = priv_tx->index;
	sync_packet->pkthdr.l4s_redun_ind = 1;
	sync_packet->pkthdr.l4s_redun_head_ind = 1;
	sync_packet->pkthdr.l4s_hdl_ind = 1;
	sync_packet->sync_payload.sync = 1;
	sync_packet->sync_payload.sid = priv_tx->index;

	if (info->resync_len == 0)
		info->rec_num = info->rec_num - 1;
	rec_num = cpu_to_be64(info->rec_num);
	memcpy(sync_packet->sync_payload.rec_num, &rec_num, NBL_KTLS_REC_LEN);

	if (info->resync_len <= NBL_KTLS_MAX_CELL_LEN) {
		sync_packet->sync_payload.redlen = htons(info->resync_len);
		return nbl_ktls_send_resync_one(res_mgt, tx_ring, sync_packet, info);
	}

	sync_packet->sync_payload.redlen = htons(NBL_KTLS_PER_CELL_LEN);
	return nbl_ktls_send_resync_mul(res_mgt, tx_ring, sync_packet, info);
}

#define NBL_KTLS_DRACO_RESYNC_PACKET_FLAG	(0xE)
bool nbl_ktls_send_resync_packet_draco(struct nbl_resource_mgt *res_mgt,
				       struct nbl_res_tx_ring *tx_ring,
				       struct nbl_ktls_offload_context_tx *priv_tx,
				       struct nbl_tx_resync_info *info)
{
	struct device *dma_dev = NBL_RES_MGT_TO_DMA_DEV(res_mgt);
	struct nbl_tx_buffer *head_buffer = NULL;
	struct nbl_ring_desc *head_desc = NULL;
	struct nbl_tx_buffer *tx_buffer = NULL;
	struct nbl_ring_desc *tx_desc = NULL;
	/* Ensure that the total length of tls resync head is 58 */
	u32 *pkthdr;
	u8 *sync_payload;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	u16 head = tx_ring->next_to_use;
	u16 index = head;
	u32 pkthdr_len = tx_ring->extheader_tx_len;
	u32 synchdr_len = tx_ring->ktls_synchdr_len;
	dma_addr_t hdrdma;
	dma_addr_t bufdma;
	skb_frag_t *frag;
	unsigned int fsz, k;

	pkthdr = kzalloc(pkthdr_len + synchdr_len, GFP_KERNEL);
	if (!pkthdr)
		return false;

	memset(pkthdr, 0, pkthdr_len);
	pkthdr[0] = NBL_TX_DEFAULT_HDR_LEN;
	pkthdr[2] |= (priv_tx->index << NBL_TX_DRACO_TLS_OFFSET) +
		     (NBL_KTLS_DRACO_RESYNC_PACKET_FLAG << NBL_TX_DRACO_TLS_FLAG_OFFSET);
	sync_payload = (u8 *)pkthdr + pkthdr_len;
	priv_tx->sync_rec_num = cpu_to_be64(info->rec_num);
	priv_tx->sync_iv = cpu_to_be64(be64_to_cpu(*(__be64 *)priv_tx->iv) +
			   info->rec_num - be64_to_cpu(*(__be64 *)priv_tx->rec_num));
	priv_tx->sync_redlen = htons(info->resync_len);
	nbl_res_fill_ktls_sync_payload_draco(sync_payload, priv_tx);

	head_buffer = NBL_TX_BUF(tx_ring, head);
	head_desc = NBL_TX_DESC(tx_ring, head);

	hdrdma = dma_map_single(dma_dev, pkthdr, pkthdr_len + synchdr_len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, hdrdma)) {
		kfree(pkthdr);
		goto dma_map_error;
	}

	head_desc->addr = cpu_to_le64(hdrdma);
	head_desc->len = cpu_to_le32(pkthdr_len + synchdr_len);
	head_desc->id = cpu_to_le16(head);

	head_buffer->dma = hdrdma;
	head_buffer->len = pkthdr_len + synchdr_len;
	head_buffer->tls_pkthdr = (u8 *)pkthdr;

	for (k = 0; k < info->nr_frags; k++) {
		frag = &info->frags[k];
		fsz = skb_frag_size(frag);
		dev_dbg(NBL_RING_TO_DEV(tx_ring), "send frag %d len %u.\n", k, fsz);
		bufdma = skb_frag_dma_map(dma_dev, frag, 0, fsz, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, bufdma)) {
			index++;
			goto dma_map_error;
		}

		index++;
		if (index == tx_ring->desc_num) {
			index = 0;
			tx_buffer = NBL_TX_BUF(tx_ring, 0);
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			tx_ring->avail_used_flags ^=
				1 << NBL_PACKED_DESC_F_AVAIL |
				1 << NBL_PACKED_DESC_F_USED;
		} else {
			tx_buffer = NBL_TX_BUF(tx_ring, index);
			tx_desc = NBL_TX_DESC(tx_ring, index);
		}

		tx_desc->addr = cpu_to_le64(bufdma);
		tx_desc->len = cpu_to_le32(fsz);
		tx_desc->id = cpu_to_le16(head);
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);

		tx_buffer->dma = bufdma;
		tx_buffer->len = fsz;
		tx_buffer->page = 1;
	}

	/* wmb */
	wmb();

	if (info->nr_frags == 0) {
		head_buffer->next_to_watch = head_desc;
		head_desc->flags = cpu_to_le16(avail_used_flags);
	} else {
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags);
		head_buffer->next_to_watch = tx_desc;
		head_desc->flags = cpu_to_le16(avail_used_flags | NBL_PACKED_DESC_F_NEXT);
	}

	if (index + 1 == tx_ring->desc_num) {
		tx_ring->next_to_use = 0;
		tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
					     1 << NBL_PACKED_DESC_F_USED;
	} else {
		tx_ring->next_to_use = index + 1;
	}

	nbl_write_doorbell(tx_ring);

	return true;

dma_map_error:
	while (index != tx_ring->next_to_use) {
		if (unlikely(!index))
			index = tx_ring->desc_num;
		index--;
		nbl_unmap_and_free_tx_resource(tx_ring, NBL_TX_BUF(tx_ring, index), false, false);
	}
	tx_ring->avail_used_flags = avail_used_flags;

	return false;
}

/* Handle packet out-of-order function */
static enum nbl_ktls_sync_retval
nbl_ktls_tx_handle_ooo(struct nbl_resource_mgt *res_mgt, struct nbl_res_tx_ring *tx_ring,
		       struct nbl_ktls_offload_context_tx *priv_tx,
		       u32 tcp_seq, int datalen)
{
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	enum nbl_ktls_sync_retval ret;
	struct nbl_tx_resync_info resync_info = {0};

	ret = nbl_tls_resync_info_get(priv_tx, tcp_seq, datalen, &resync_info);
	if (unlikely(ret != NBL_KTLS_SYNC_DONE))
		return ret;

	dev_dbg(NBL_RING_TO_DEV(tx_ring), "rec_num %llu, resync_len %u, nr_frags %u.\n",
		resync_info.rec_num, resync_info.resync_len, resync_info.nr_frags);

	if (unlikely(NBL_OPS_CALL(product_ops->ktls_send_resync_packet,
				  (res_mgt, tx_ring, priv_tx, &resync_info))))
		return NBL_KTLS_SYNC_FAIL;

	return NBL_KTLS_SYNC_DONE;
}

#define NBL_TLS_TX_VALID_FLAG	(0x8)
static bool nbl_ktls_tx_offload_handle(struct nbl_res_tx_ring *tx_ring,
				       struct sk_buff *skb,
				       u32 *pkthdr)
{
	struct net_device *netdev = tx_ring->netdev;
	u16 *offset = tx_ring->cfg_offset;
	struct nbl_resource_mgt *res_mgt = NBL_ADAPTER_TO_RES_MGT(NBL_NETDEV_TO_ADAPTER(netdev));
	struct tls_context *tls_ctx;
	struct nbl_ktls_offload_context_tx **ctx;
	struct nbl_ktls_offload_context_tx *priv_tx;
	enum nbl_ktls_sync_retval ret;
	u32 tcp_seq = 0;
	int datalen = 0;

	datalen = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	if (!datalen)
		return 0;

	tls_ctx = tls_get_ctx(skb->sk);
	if (WARN_ON_ONCE(tls_ctx->netdev != netdev))
		goto err_out;

	ctx = __tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_TX);
	priv_tx = *ctx;
	/* config data to hardware */
	if (priv_tx->ctx_post_pending) {
		priv_tx->ctx_post_pending = false;
		if (!nbl_ktls_send_init_packet(res_mgt, tx_ring, priv_tx))
			goto err_out;
	}

	tcp_seq = ntohl(tcp_hdr(skb)->seq);
	dev_dbg(NBL_RING_TO_DEV(tx_ring), "ktls tx tcp_seq %u.\n", tcp_seq);
	if (unlikely(priv_tx->expected_tcp != tcp_seq)) {
		dev_dbg(NBL_RING_TO_DEV(tx_ring), "ktls tx tcp_seq %u, but expected_tcp %u.\n",
			tcp_seq, priv_tx->expected_tcp);
		ret = nbl_ktls_tx_handle_ooo(res_mgt, tx_ring, priv_tx, tcp_seq, datalen);
		tx_ring->tx_stats.tls_ooo_packets++;
		switch (ret) {
		case NBL_KTLS_SYNC_DONE:
			break;
		case NBL_KTLS_SYNC_SKIP_NO_DATA:
			if (likely(!skb->decrypted))
				goto out;
			WARN_ON_ONCE(1);
			goto err_out;
		case NBL_KTLS_SYNC_FAIL:
			goto err_out;
		}
	}

	priv_tx->expected_tcp = tcp_seq + datalen;
	HDR_CFG((u32 *)pkthdr, FIELD_POS(offset[NBL_TLS_IDX]), FIELD_OFFSET(offset[NBL_TLS_IDX]),
		FIELD_VLD(offset[NBL_TLS_IDX]), priv_tx->index);
	HDR_CFG((u32 *)pkthdr, FIELD_POS(offset[NBL_TLS_FLAG]), FIELD_OFFSET(offset[NBL_TLS_FLAG]),
		FIELD_VLD(offset[NBL_TLS_FLAG]), NBL_TLS_TX_VALID_FLAG);

	tx_ring->tx_stats.tls_encrypted_packets += skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	tx_ring->tx_stats.tls_encrypted_bytes += datalen;

out:
	return 0;

err_out:
	dev_kfree_skb_any(skb);
	return 1;
}
#endif

static int nbl_tx_map_with_ptr(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb, u32 *pkthdr)
{
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(tx_ring);
	struct nbl_tx_buffer *tx_buffer, *first;
	struct nbl_ring_desc *tx_desc;
	dma_addr_t dma;
	u32 tso, size;
	unsigned int i;
	u16 desc_index = tx_ring->next_to_use;
	u16 head = desc_index;
	u16 last_index;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	unsigned int frag_num = skb_shinfo(skb)->nr_frags;
	u8 pkthdr_len = tx_ring->extheader_tx_len;
	bool doorbell = true;

	tx_desc = NBL_TX_DESC(tx_ring, desc_index);
	first = NBL_TX_BUF(tx_ring, desc_index);
	first->gso_segs = 1;
	first->hlen = 0;
	first->bytecount = skb->len;
	first->skb = skb;
	tx_buffer = first;
	skb_tx_timestamp(skb);

	tso = nbl_tx_tso(tx_ring, first, pkthdr);
	nbl_tx_csum(tx_ring, skb, pkthdr);
	last_index = head + frag_num;

	if (pkthdr == (u32 *)skb->cb) {
		dma = dma_map_single(dma_dev, pkthdr, pkthdr_len, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, dma)) {
			tx_ring->tx_stats.tx_dma_busy++;
			return NETDEV_TX_BUSY;
		}

		tx_desc->addr = cpu_to_le64(dma);
		tx_desc->len = pkthdr_len + (first->hlen << NBL_TX_TOTAL_HEADERLEN_SHIFT);
		tx_desc->id = cpu_to_le16((tso > 1) << NBL_TX_TSO_SHIFT) |
			      cpu_to_le16(skb_shinfo(skb)->gso_size);
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | NBL_PACKED_DESC_F_NEXT);

		tx_buffer->dma = dma;
		tx_buffer->len = pkthdr_len;

		desc_index++;
		tx_desc++;
		tx_buffer++;
		if (desc_index == tx_ring->desc_num) {
			desc_index = 0;
			tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
						     1 << NBL_PACKED_DESC_F_USED;
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			tx_buffer = NBL_TX_BUF(tx_ring, 0);
		}
		pkthdr_len = 0;
		last_index++;
	}

	last_index = last_index % tx_ring->desc_num;
	size = skb_headlen(skb) + pkthdr_len;
	dma = dma_map_single(dma_dev, skb->data - pkthdr_len, size, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, dma))
		goto dma_map_error;

	tx_desc->addr = cpu_to_le64(dma);
	tx_desc->len = size + (first->hlen << NBL_TX_TOTAL_HEADERLEN_SHIFT);
	tx_desc->id = cpu_to_le16((tso > 1) << NBL_TX_TSO_SHIFT) |
		      cpu_to_le16(skb_shinfo(skb)->gso_size);
	tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags | (desc_index != last_index));

	tx_buffer->dma = dma;
	tx_buffer->len = size;
	desc_index++;
	tx_desc++;
	tx_buffer++;
	if (desc_index == tx_ring->desc_num) {
		desc_index = 0;
		tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
					     1 << NBL_PACKED_DESC_F_USED;
		tx_desc = NBL_TX_DESC(tx_ring, 0);
		tx_buffer = NBL_TX_BUF(tx_ring, 0);
	}

	for (i = 0; i < frag_num; i++) {
		const skb_frag_t *frag;

		frag = &skb_shinfo(skb)->frags[i];
		size = skb_frag_size(frag);
		dma = skb_frag_dma_map(dma_dev, frag, 0, size, DMA_TO_DEVICE);
		if (dma_mapping_error(dma_dev, dma))
			goto dma_map_error;

		frag++;
		tx_desc->addr = cpu_to_le64(dma);
		tx_desc->len = size;
		tx_desc->flags = cpu_to_le16(tx_ring->avail_used_flags |
					     (desc_index != last_index));

		tx_buffer->dma = dma;
		tx_buffer->len = size;
		tx_buffer->page = 1;
		desc_index++;
		tx_desc++;
		tx_buffer++;
		if (desc_index == tx_ring->desc_num) {
			desc_index = 0;
			tx_ring->avail_used_flags ^= 1 << NBL_PACKED_DESC_F_AVAIL |
						     1 << NBL_PACKED_DESC_F_USED;
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			tx_buffer = NBL_TX_BUF(tx_ring, 0);
		}
	}

	/* stats */
	if (is_multicast_ether_addr(skb->data))
		tx_ring->tx_stats.tx_multicast_packets += tso;
	else
		tx_ring->tx_stats.tx_unicast_packets += tso;

	tx_ring->next_to_use = desc_index;
	nbl_maybe_stop_tx(tx_ring, DESC_NEEDED);
	if (tx_ring->vsi_type == NBL_VSI_DATA)
		doorbell = __netdev_tx_sent_queue(txring_txq(tx_ring),
						  first->bytecount, netdev_xmit_more());
	first->next_to_watch = NBL_TX_DESC(tx_ring, last_index);
	/* wmb */
	wmb();

	/* kick doorbell passthrough for performace */
	if (doorbell)
		nbl_write_doorbell(tx_ring);

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
}

static int nbl_tx_map(struct nbl_res_tx_ring *tx_ring, struct sk_buff *skb, u32 *pkthdr)
{
	struct device *dma_dev = NBL_RING_TO_DMA_DEV(tx_ring);
	struct nbl_tx_buffer *first;
	struct nbl_ring_desc *first_desc;
	struct nbl_ring_desc *tx_desc;
	dma_addr_t hdrdma;
	u32 tso;
	u16 desc_index = tx_ring->next_to_use;
	u16 head = desc_index;
	u16 avail_used_flags = tx_ring->avail_used_flags;
	u8 pkthdr_len = tx_ring->extheader_tx_len;
	bool doorbell = true;

	first_desc = NBL_TX_DESC(tx_ring, desc_index);
	first = NBL_TX_BUF(tx_ring, desc_index);
	first->gso_segs = 1;
	first->hlen = 0;
	first->bytecount = skb->len - skb->cb[NBL_SKB_HAS_VLAN_OFF];
	first->skb = skb;
	skb_tx_timestamp(skb);

	tso = nbl_tx_tso(tx_ring, first, pkthdr);
	nbl_tx_csum(tx_ring, skb, pkthdr);

	if (pkthdr != (u32 *)skb->cb) {
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

	tx_desc = NBL_TX_DESC(tx_ring, (desc_index == 0 ? tx_ring->desc_num : desc_index) - 1);
	tx_desc->flags &= cpu_to_le16(~NBL_PACKED_DESC_F_NEXT);
	first_desc->len += (first->hlen << NBL_TX_TOTAL_HEADERLEN_SHIFT);
	first_desc->id = cpu_to_le16(skb_shinfo(skb)->gso_size);
	first->next_to_watch = tx_desc;

	tx_ring->next_to_use = desc_index;
	nbl_maybe_stop_tx(tx_ring, DESC_NEEDED);
	if (tx_ring->vsi_type == NBL_VSI_DATA)
		doorbell = __netdev_tx_sent_queue(txring_txq(tx_ring),
						  first->bytecount, netdev_xmit_more());
	/* wmb */
	wmb();

	/* first desc last set flag */
	if (first_desc == tx_desc)
		first_desc->flags = cpu_to_le16(avail_used_flags);
	else
		first_desc->flags = cpu_to_le16(avail_used_flags | NBL_PACKED_DESC_F_NEXT);

	/* kick doorbell passthrough for performace */
	if (doorbell)
		nbl_write_doorbell(tx_ring);

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
}

static inline void nbl_txrx_dport_cfg(struct nbl_res_tx_ring *tx_ring,
				      struct sk_buff *skb, u32 *pkthdr)
{
	struct sk_buff *skb2 = NULL;
	struct icmp6hdr *hdr;
	u16 *offset = tx_ring->cfg_offset;
	int ret;
	__be16 protocol;

	protocol = vlan_get_protocol(skb);
	switch (protocol) {
	case htons(ETH_P_SLOW):
	case htons(ETH_P_LLDP):
		break;
	case htons(ETH_P_ARP):
		if (!tx_ring->bond)
			return;
		skb2 = skb_copy(skb, GFP_ATOMIC);
		break;
	case htons(ETH_P_IPV6):
		if (!tx_ring->bond ||
		    !pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) ||
		    ipv6_hdr(skb)->nexthdr != IPPROTO_ICMPV6)
			return;

		hdr = (struct icmp6hdr *)icmp6_hdr(skb);
		if (hdr->icmp6_code ||
		    (hdr->icmp6_type != NDISC_NEIGHBOUR_SOLICITATION &&
		     hdr->icmp6_type != NDISC_NEIGHBOUR_ADVERTISEMENT))
			return;

		skb2 = skb_copy(skb, GFP_ATOMIC);
		break;
	default:
		return;
	}

	HDR_CLR(pkthdr, FIELD_POS(offset[NBL_FWD]),
		FIELD_OFFSET(offset[NBL_FWD]),
		FIELD_VLD(offset[NBL_FWD]), 0x7);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_FWD]), FIELD_OFFSET(offset[NBL_FWD]),
		FIELD_VLD(offset[NBL_FWD]), NBL_TX_FWD_TYPE_CPU_ASSIGNED);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_DPORT_ID]), FIELD_OFFSET(offset[NBL_DPORT_ID]),
		FIELD_VLD(offset[NBL_DPORT_ID]), tx_ring->eth_id);

	if (skb2) {
		u32 *pkthdr2;

		if (!skb_header_cloned(skb2) &&
		    skb_headroom(skb2) >= tx_ring->extheader_tx_len)
			pkthdr2 = (u32 *)(skb2->data - tx_ring->extheader_tx_len);
		else
			pkthdr2 = (u32 *)skb2->cb;
		memcpy(pkthdr2, pkthdr, tx_ring->extheader_tx_len);
		HDR_CLR(pkthdr2, FIELD_POS(offset[NBL_DPORT_ID]),
			FIELD_OFFSET(offset[NBL_DPORT_ID]),
			FIELD_VLD(offset[NBL_DPORT_ID]), 0x3);
		HDR_CFG(pkthdr2, FIELD_POS(offset[NBL_DPORT_ID]),
			FIELD_OFFSET(offset[NBL_DPORT_ID]),
			FIELD_VLD(offset[NBL_DPORT_ID]), tx_ring->dport_id2);

		if (tx_ring->support_ptr)
			ret = nbl_tx_map_with_ptr(tx_ring, skb2, pkthdr2);
		else
			ret = nbl_tx_map(tx_ring, skb2, pkthdr2);
		if (ret)
			dev_kfree_skb_any(skb2);
	}
}

static netdev_tx_t nbl_res_txrx_rep_xmit(struct sk_buff *skb,
					 struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_txrx_mgt *txrx_mgt = (struct nbl_txrx_mgt *)(priv->txrx_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	u32 *pkthdr;
	u16 *offset = tx_ring->cfg_offset;
	unsigned int count;
	u8 pkthdr_len = tx_ring->extheader_tx_len;
	u16 dport_id;

	count = nbl_xmit_desc_count(skb, tx_ring->interleave_seg_disable);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_dbg(NBL_RING_TO_DEV(tx_ring), "There is no enough descriptor to transmit packet in queue %u\n",
				tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	eth_skb_pad(skb);

	if (!skb_header_cloned(skb) && skb_headroom(skb) >= pkthdr_len)
		pkthdr = (u32 *)(skb->data - pkthdr_len);
	else
		pkthdr = (u32 *)skb->cb;

	memcpy(pkthdr, tx_ring->default_hdr, pkthdr_len);
	dport_id = *(u16 *)(&skb->cb[NBL_SKB_FILL_VSI_ID_OFF]);
	HDR_CFG(pkthdr, FIELD_POS(offset[NBL_DPORT_ID]), FIELD_OFFSET(offset[NBL_DPORT_ID]),
		FIELD_VLD(offset[NBL_DPORT_ID]), dport_id);
	skb->cb[NBL_SKB_HAS_VLAN_OFF] = 0;
	if (tx_ring->support_ptr)
		return nbl_tx_map_with_ptr(tx_ring, skb, pkthdr);
	else
		return nbl_tx_map(tx_ring, skb, pkthdr);
}

static netdev_tx_t nbl_res_txrx_self_test_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_txrx_mgt *txrx_mgt = (struct nbl_txrx_mgt *)(priv->txrx_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	u32 *pkthdr;
	u16 *offset = tx_ring->cfg_offset;
	u8 pkthdr_len = tx_ring->extheader_tx_len;
	unsigned int count;

	count = nbl_xmit_desc_count(skb, tx_ring->interleave_seg_disable);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_dbg(NBL_RING_TO_DEV(tx_ring), "There is no enough descriptor to transmit packet in queue %u\n",
				tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* for dstore and eth, min packet len is 60 */
	eth_skb_pad(skb);
	if (!skb_header_cloned(skb) && skb_headroom(skb) >= pkthdr_len)
		pkthdr = (u32 *)(skb->data - pkthdr_len);
	else
		pkthdr = (u32 *)skb->cb;

	memcpy(pkthdr, tx_ring->default_hdr, pkthdr_len);
	if (!tx_ring->simple_fwd) {
		HDR_CFG(pkthdr, FIELD_POS(offset[NBL_FWD]), FIELD_OFFSET(offset[NBL_FWD]),
			FIELD_VLD(offset[NBL_FWD]), NBL_TX_FWD_TYPE_CPU_ASSIGNED);
		HDR_CFG(pkthdr, FIELD_POS(offset[NBL_DPORT_ID]), FIELD_OFFSET(offset[NBL_DPORT_ID]),
			FIELD_VLD(offset[NBL_DPORT_ID]), tx_ring->eth_id);
	}
	skb->cb[NBL_SKB_HAS_VLAN_OFF] = 0;
	if (tx_ring->support_ptr)
		return nbl_tx_map_with_ptr(tx_ring, skb, pkthdr);
	else
		return nbl_tx_map(tx_ring, skb, pkthdr);
}

static netdev_tx_t nbl_res_txrx_start_xmit(struct sk_buff *skb,
					   struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_txrx_mgt *txrx_mgt = (struct nbl_txrx_mgt *)(priv->txrx_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	u32 *pkthdr;
	unsigned int count;

	// nbl_trace(xmit_frame_ring, tx_ring, skb);

	count = nbl_xmit_desc_count(skb, tx_ring->interleave_seg_disable);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_dbg(NBL_RING_TO_DEV(tx_ring), "There is no enough descriptor to transmit packet in queue %u\n",
				tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}
	skb->cb[NBL_SKB_HAS_VLAN_OFF] = 0;
	if (tx_ring->vlan_proto || skb_vlan_tag_present(skb)) {
		u16 vlan_tci;
		u16 vlan_proto;

		if (tx_ring->vlan_proto) {
			vlan_proto = htons(tx_ring->vlan_proto);
			vlan_tci = tx_ring->vlan_tci;
		} else {
			vlan_proto = skb->vlan_proto;
			vlan_tci = skb_vlan_tag_get(skb);
		}

		skb = vlan_insert_tag_set_proto(skb, vlan_proto, vlan_tci);
		if (!skb)
			return NETDEV_TX_OK;
		if (!tx_ring->vlan_proto)
			tx_ring->tx_stats.tx_added_vlan_packets++;
		skb->cb[NBL_SKB_HAS_VLAN_OFF] = 4;
	}

	/* for dstore and eth, min packet len is 60 */
	eth_skb_pad(skb);
	if (!skb_header_cloned(skb) && skb_headroom(skb) >= tx_ring->extheader_tx_len)
		pkthdr = (u32 *)(skb->data - tx_ring->extheader_tx_len);
	else
		pkthdr = (u32 *)skb->cb;

	memcpy(pkthdr, tx_ring->default_hdr, tx_ring->extheader_tx_len);

#if IS_ENABLED(CONFIG_TLS_DEVICE)
	if (nbl_ktls_device_offload(skb) &&
	    nbl_ktls_tx_offload_handle(tx_ring, skb, pkthdr))
		return NETDEV_TX_OK;
#endif

	if (!tx_ring->simple_fwd)
		nbl_txrx_dport_cfg(tx_ring, skb, pkthdr);

	return nbl_tx_map(tx_ring, skb, pkthdr);
}

static netdev_tx_t nbl_res_txrx_start_xmit_draco(struct sk_buff *skb,
						 struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_txrx_mgt *txrx_mgt = (struct nbl_txrx_mgt *)(priv->txrx_mgt);
	struct nbl_res_tx_ring *tx_ring = txrx_mgt->tx_rings[skb_get_queue_mapping(skb)];
	u32 *pkthdr;
	unsigned int count;

	// nbl_trace(xmit_frame_ring, tx_ring, skb);

	count = nbl_xmit_desc_count(skb, 0);
	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		if (net_ratelimit())
			dev_dbg(NBL_RING_TO_DEV(tx_ring), "There is no enough descriptor to transmit packet in queue %u\n",
				tx_ring->queue_index);
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* for dstore and eth, min packet len is 60 */
	eth_skb_pad(skb);
	if (!skb_header_cloned(skb) && skb_headroom(skb) >= tx_ring->extheader_tx_len)
		pkthdr = (u32 *)(skb->data - tx_ring->extheader_tx_len);
	else
		pkthdr = (u32 *)skb->cb;

	memcpy(pkthdr, tx_ring->default_hdr, tx_ring->extheader_tx_len);

#if IS_ENABLED(CONFIG_TLS_DEVICE)
	if (nbl_ktls_device_offload(skb) &&
	    nbl_ktls_tx_offload_handle(tx_ring, skb, pkthdr))
		return NETDEV_TX_OK;
#endif

	if (skb_vlan_tag_present(skb)) {
		u16 vlan_tci;
		u16 vlan_proto;

		vlan_proto = skb->vlan_proto;
		vlan_tci = skb_vlan_tag_get(skb);
		pkthdr[3] = ((1 << NBL_TX_VLAN_VID_OFFSET)) |
			    ((vlan_proto == cpu_to_be16(ETH_P_8021AD)) << NBL_TX_VLAN_TYPE_OFFSET) |
			    vlan_tci;
		tx_ring->tx_stats.tx_added_vlan_packets++;
	}

	nbl_txrx_dport_cfg(tx_ring, skb, pkthdr);

	return nbl_tx_map_with_ptr(tx_ring, skb, pkthdr);
}

static void nbl_res_txrx_kick_rx_ring(void *priv, u16 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_notify_param notify_param = {0};
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, index);

	notify_param.notify_qid = rx_ring->notify_qid;
	phy_ops->update_tail_ptr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), &notify_param);
}

static int nbl_res_txring_is_invalid(struct nbl_resource_mgt *res_mgt,
				     struct seq_file *m, int index)
{
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring;
	u16 ring_num = txrx_mgt->tx_ring_num;

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
	u16 ring_num = txrx_mgt->rx_ring_num;

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
	struct nbl_res_vector *vector = NBL_RES_MGT_TO_VECTOR(res_mgt, index);
	struct nbl_napi_struct *napi;
	struct nbl_ring_desc *desc;
	int i;

	if (nbl_res_rxring_is_invalid(res_mgt, m, index))
		return 0;

	napi = &vector->nbl_napi;
	seq_printf(m, "queue_index %d desc_num %d used_wrap_counter 0x%x avail_used_flags 0x%x\n",
		   ring->queue_index, ring->desc_num,
		   ring->used_wrap_counter, ring->avail_used_flags);
	seq_printf(m, "ntu 0x%x, ntc 0x%x\n", ring->next_to_use, ring->next_to_clean);
	seq_printf(m, "desc dma 0x%pad, HZ %u\n", &ring->dma, HZ);
	seq_printf(m, "napi irq status %u, irq cnt %u, mask cnt %u, unmask cnt %u, complete_cnt %u\n",
		   atomic_read(&napi->is_irq), napi->irq_cnt, napi->mask_cnt,
		   napi->unmask_cnt, napi->complete_cnt);

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
	struct nbl_tx_buffer *tx_buffer;
	u32 total_header_len;
	u32 desc_len;
	int i;

	if (nbl_res_txring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "queue_index %d desc_num %d used_wrap_counter 0x%x avail_used_flags 0x%x\n",
		   ring->queue_index, ring->desc_num,
		   ring->used_wrap_counter, ring->avail_used_flags);
	seq_printf(m, "ntu 0x%x, ntc 0x%x\n", ring->next_to_use, ring->next_to_clean);
	seq_printf(m, "desc dma 0x%pad, HZ %u\n", &ring->dma, HZ);
	seq_printf(m, "tx_skb_free %llu\n", ring->tx_stats.tx_skb_free);

	seq_puts(m, "desc:\n");
	for (i = 0; i < ring->desc_num; i++) {
		desc = ring->desc + i;
		total_header_len = desc->len >> NBL_TX_TOTAL_HEADERLEN_SHIFT;
		desc_len = desc->len & 0xFFFFFF;
		tx_buffer = NBL_TX_BUF(ring, i);
		seq_printf(m, "desc %d: id/gso_size %d, addr 0x%llx len %d header_len %d flag 0x%x tls_hdr %p\n",
			   i, desc->id, desc->addr, desc_len,
			   total_header_len, desc->flags, tx_buffer->tls_pkthdr);
	}

	return 0;
}

static int nbl_res_txrx_dump_ring(void *priv, struct nbl_dump_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	if (param->is_tx)
		return nbl_res_tx_dump_ring(res_mgt, param->m, param->index);
	else
		return nbl_res_rx_dump_ring(res_mgt, param->m, param->index);
}

static int nbl_res_tx_dump_ring_stats(struct nbl_resource_mgt *res_mgt,
				      struct seq_file *m, int index)
{
	struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, index);

	if (nbl_res_txring_is_invalid(res_mgt, m, index))
		return 0;

	seq_printf(m, "pkts: %lld, bytes: %lld, descs: %lld\n",
		   ring->stats.packets, ring->stats.bytes, ring->stats.descs);
	seq_printf(m, "tso_pkts: %lld, tso_bytes: %lld, tx_checksum_pkts: %lld, tso_inner_packets:%lld, tso_inner_bytes：%lld, tx_csum_inner_packets: %lld\n",
		   ring->tx_stats.tso_packets, ring->tx_stats.tso_bytes,
		   ring->tx_stats.tx_csum_packets,
		   ring->tx_stats.tso_inner_packets,
		   ring->tx_stats.tso_inner_bytes,
		   ring->tx_stats.tx_csum_inner_packets);
	seq_printf(m, "tx_added_vlan_packets: %lld\n", ring->tx_stats.tx_added_vlan_packets);
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

	seq_printf(m, "rx_checksum_pkts: %lld, rx_csum_inner_packets: %lld, rx_checksum_errors: %lld\n",
		   ring->rx_stats.rx_csum_packets, ring->rx_stats.rx_csum_inner_packets,
		   ring->rx_stats.rx_csum_errors);
	seq_printf(m, "rx_removed_vlan_packets: %lld, rx_rss_hash_packets: %lld\n",
		   ring->rx_stats.rx_removed_vlan_packets, ring->rx_stats.rx_rss_hash_packets);
	seq_printf(m, "rx_multicast_pkts: %lld, rx_unicast_pkts: %lld\n",
		   ring->rx_stats.rx_multicast_packets,
		   ring->rx_stats.rx_unicast_packets);
	seq_printf(m, "rx_desc_addr_err: %lld\n",
		   ring->rx_stats.rx_desc_addr_err_cnt);
	seq_printf(m, "rx_alloc_buf_err_cnt: %lld\n",
		   ring->rx_stats.rx_alloc_buf_err_cnt);
	seq_printf(m, "rx_oversize_pkts_sw_drop: %lld\n",
		   ring->rx_stats.rx_oversize_pkts_sw_drop);
	return 0;
}

static int nbl_res_txrx_dump_ring_stats(void *priv, struct nbl_dump_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	if (param->is_tx)
		return nbl_res_tx_dump_ring_stats(res_mgt, param->m, param->index);
	else
		return nbl_res_rx_dump_ring_stats(res_mgt,  param->m, param->index);
}

static struct nbl_napi_struct *nbl_res_txrx_get_vector_napi(void *priv, u16 index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;

	if (!txrx_mgt->vectors || index >= txrx_mgt->rx_ring_num) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "vectors not allocated\n");
		return NULL;
	}

	return &txrx_mgt->vectors[index]->nbl_napi;
}

static void nbl_res_txrx_set_vector_info(void *priv, struct nbl_vec_info_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = res_mgt->txrx_mgt;

	if (!txrx_mgt->vectors || param->index >= txrx_mgt->rx_ring_num) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "vectors not allocated\n");
		return;
	}

	txrx_mgt->vectors[param->index]->irq_enable_base = param->irq_enable_base;
	txrx_mgt->vectors[param->index]->irq_data = param->irq_data;
	txrx_mgt->vectors[param->index]->net_msix_mask_en = param->mask_en;
}

static int nbl_serv_ipv6_exthdr_num(struct sk_buff *skb, int start, u8 nexthdr)
{
	int exthdr_num = 0;
	struct ipv6_opt_hdr _hdr, *hp;
	unsigned int hdrlen;

	while (ipv6_ext_hdr(nexthdr)) {
		if (nexthdr == NEXTHDR_NONE)
			return -1;

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (!hp)
			return -1;

		exthdr_num++;

		if (nexthdr == NEXTHDR_FRAGMENT)
			hdrlen = 8;
		else if (nexthdr == NEXTHDR_AUTH)
			hdrlen = ipv6_authlen(hp);
		else
			hdrlen = ipv6_optlen(hp);

		nexthdr = hp->nexthdr;
		start += hdrlen;
	}

	return exthdr_num;
}

netdev_features_t
nbl_res_txrx_features_check_leonis(struct sk_buff *skb,
				   struct net_device *dev,
				   netdev_features_t features)
{
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
	u32 total_hrd_len = 0;
	__be16 protocol, frag_off;
	u8 l4_proto = 0;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL.
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	if (skb->encapsulation)
		goto out_rm_features;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		unsigned char *exthdr;
		unsigned int offset = 0;
		int nexthdr = 0;
		int exthdr_num = 0;
		int ret;

		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr) {
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
			if (ret < 0)
				goto out_rm_features;
			/* IPV6 extension headers
			 * (1) donot support routing and destination extension headers
			 * (2) support 2 extension headers mostly
			 */
			nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_ROUTING, NULL, NULL);
			if (nexthdr == NEXTHDR_ROUTING)
				goto out_rm_features;

			nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_DEST, NULL, NULL);
			if (nexthdr == NEXTHDR_DEST)
				goto out_rm_features;

			exthdr_num = nbl_serv_ipv6_exthdr_num(skb, exthdr - skb->data,
							      ip.v6->nexthdr);
			if (exthdr_num < 0 || exthdr_num > 2)
				goto out_rm_features;
		}
	} else {
		goto out_rm_features;
	}

	total_hrd_len = (u32)(skb_transport_header(skb) - skb->data);
	switch (l4_proto) {
	case IPPROTO_TCP:
		total_hrd_len += (l4.tcp->doff) * 4;
		break;
	case IPPROTO_UDP:
		total_hrd_len += sizeof(struct udphdr);
		break;
	default:
		goto out_rm_features;
	}

	// TX checksum offload support total header len is [0, 255]
	if (total_hrd_len > NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX)
		goto out_rm_features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 256 bytes or bigger than 16383 bytes. If it is then we need to drop support for GSO.
	 * TSO support total header len is [42, 128]
	 */
	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_size < NBL_TX_TSO_MSS_MIN ||
				skb_shinfo(skb)->gso_size > NBL_TX_TSO_MSS_MAX ||
				total_hrd_len < NBL_TX_TSO_L2L3L4_HDR_LEN_MIN ||
				total_hrd_len > NBL_TX_TSO_L2L3L4_HDR_LEN_MAX))
		features &= ~NETIF_F_GSO_MASK;

	return features;

out_rm_features:
	return features & ~(NETIF_F_IP_CSUM |
			    NETIF_F_IPV6_CSUM |
			    NETIF_F_SCTP_CRC |
			    NETIF_F_GSO_MASK);
}

static u8 nbl_ipv6_check_exthdr(struct sk_buff *skb, bool tunnel)
{
	unsigned char *exthdr;
	union {
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	int ret;
	__be16 frag_off;
	u8 l4_proto;

	if (tunnel)
		ip.hdr = skb_inner_network_header(skb);
	else
		ip.hdr = skb_network_header(skb);

	exthdr = ip.hdr + sizeof(*ip.v6);
	l4_proto = ip.v6->nexthdr;
	ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
	if (ret < 0)
		return U8_MAX;

	if (ret > (exthdr - skb->data)) {
		int exthdr_num;

		/* IPV6 inner extension headers
		 * (1) only support nexthdr_hop 1 hop extension headers mostly
		 */
		exthdr_num = nbl_serv_ipv6_exthdr_num(skb, exthdr - skb->data, ip.v6->nexthdr);
		if (exthdr_num > 1 || ip.v6->nexthdr != NEXTHDR_HOP)
			return U8_MAX;
	}

	return l4_proto;
}

static inline u8 nbl_l2_tunnel_check(struct sk_buff *skb)
{
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;

	if ((skb_inner_network_header(skb) - skb_inner_mac_header(skb)) > NBL_OFFLOAD_MAX_L2_LEN)
		return U8_MAX;

	ip.hdr = skb_inner_network_header(skb);
	if (ip.v4->version == 4)
		return ip.v4->protocol;
	else if (ip.v6->version == 6)
		return nbl_ipv6_check_exthdr(skb, 1);

	return U8_MAX;
}

netdev_features_t nbl_res_txrx_features_check_draco(struct sk_buff *skb,
						    struct net_device *dev,
						    netdev_features_t features)
{
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct gre_base_hdr *greh;
		unsigned char *hdr;
	} l4;
	int depth = 0;
	u32 hlen;
	__be16 protocol;
	u8 l4_proto;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	protocol = __vlan_get_protocol(skb, skb->protocol, &depth);
	if (skb_vlan_tag_present(skb))
		depth += VLAN_HLEN;

	if (depth > NBL_OFFLOAD_MAX_L2_LEN)
		goto out_rm_features;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	switch (protocol) {
	case htons(ETH_P_IP):
		l4_proto = ip.v4->protocol;
		break;
	case htons(ETH_P_IPV6):
		l4_proto = nbl_ipv6_check_exthdr(skb, 0);
		break;
	default:
		goto out_rm_features;
	}

	if (skb->encapsulation) {
		switch (l4_proto) {
		case IPPROTO_IPIP:
			ip.hdr = skb_inner_network_header(skb);
			l4_proto = ip.v4->protocol;
			break;
		case IPPROTO_IPV6:
			ip.hdr = skb_inner_network_header(skb);
			l4_proto = nbl_ipv6_check_exthdr(skb, 1);
			break;
		case IPPROTO_UDP:
			if (l4.udp->dest != htons(GENEVE_UDP_PORT) &&
			    l4.udp->dest != htons(IANA_VXLAN_UDP_PORT))
				goto out_rm_features;
			l4_proto = nbl_l2_tunnel_check(skb);
			break;
		case IPPROTO_GRE:
			if (((l4.greh->flags & (GRE_KEY | GRE_CSUM | GRE_SEQ)) != GRE_KEY) ||
			    l4.greh->protocol != htons(ETH_P_TEB))
				goto out_rm_features;
			l4_proto = nbl_l2_tunnel_check(skb);
			break;
		default:
			goto out_rm_features;
		}
		l4.hdr = skb_inner_transport_header(skb);
	}

	hlen = (u32)(l4.hdr - skb->data);
	switch (l4_proto) {
	case IPPROTO_TCP:
		hlen += (l4.tcp->doff) * 4;
		break;
	case IPPROTO_UDP:
		hlen += sizeof(struct udphdr);
		break;
	default:
		goto out_rm_features;
	}

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes or bigger than 9622 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) && skb_shinfo(skb)->gso_size < NBL_DRACO_TX_TSO_MSS_MIN)
		features &= ~NETIF_F_GSO_MASK;

	/* TX checksum offload support total header len is [0, 255] */
	if (hlen > NBL_DRACO_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX)
		goto out_rm_features;

	return features;

out_rm_features:
	return features & ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_GSO_MASK);
}

netdev_features_t nbl_res_txrx_features_check_df200_common(struct sk_buff *skb,
							   struct net_device *dev,
							   netdev_features_t features)
{
	u32 l2_l3_hrd_len = 0, l4_hrd_len = 0, total_hrd_len = 0;
	u8 l4_proto = 0;
	__be16 protocol, frag_off;
	int ret;
	unsigned char *exthdr;
	unsigned int offset = 0;
	int nexthdr = 0;
	int exthdr_num = 0;
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

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL.
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 256 bytes or bigger than 64k bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_size < NBL_TX_TSO_MSS_MIN ||
				skb_shinfo(skb)->gso_size > NBL_MAX_JUMBO_FRAME_SIZE))
		features &= ~NETIF_F_GSO_MASK;

	l2_l3_hrd_len = (u32)(skb_transport_header(skb) - skb->data);

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);
	protocol = vlan_get_protocol(skb);

	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr) {
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto, &frag_off);
			if (ret < 0)
				goto out_rm_features;
		}

		/* IPV6 extension headers
		 * (1) donot support routing and destination extension headers
		 * (2) support 2 extension headers mostly
		 */
		nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_ROUTING, NULL, NULL);
		if (nexthdr == NEXTHDR_ROUTING) {
			netdev_info(dev, "skb contain ipv6 routing ext header\n");
			goto out_rm_features;
		}

		nexthdr = ipv6_find_hdr(skb, &offset, NEXTHDR_DEST, NULL, NULL);
		if (nexthdr == NEXTHDR_DEST) {
			netdev_info(dev, "skb contain ipv6 routing dest header\n");
			goto out_rm_features;
		}

		exthdr_num = nbl_serv_ipv6_exthdr_num(skb, exthdr - skb->data, ip.v6->nexthdr);
		if (exthdr_num < 0 || exthdr_num > 2) {
			netdev_info(dev, "skb ipv6 exthdr_num:%d\n", exthdr_num);
			goto out_rm_features;
		}
	} else {
		goto out_rm_features;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_hrd_len = (l4.tcp->doff) * 4;
		break;
	case IPPROTO_UDP:
		l4_hrd_len = sizeof(struct udphdr);
		break;
	case IPPROTO_SCTP:
		l4_hrd_len = sizeof(struct sctphdr);
		break;
	default:
		goto out_rm_features;
	}

	total_hrd_len = l2_l3_hrd_len + l4_hrd_len;

	// TX checksum offload support total header len is [0, 128]
	if (total_hrd_len > NBL_TX_TSO_L2L3L4_HDR_LEN_MAX)
		goto out_rm_features;

	// TSO support total header len is [42, 128]
	if (total_hrd_len < NBL_TX_TSO_L2L3L4_HDR_LEN_MIN ||
	    total_hrd_len > NBL_TX_TSO_L2L3L4_HDR_LEN_MAX)
		features &= ~NETIF_F_GSO_MASK;

	if (skb->encapsulation)
		goto out_rm_features;

	return features;

out_rm_features:
	return features & ~(NETIF_F_IP_CSUM |
			    NETIF_F_IPV6_CSUM |
			    NETIF_F_SCTP_CRC |
			    NETIF_F_GSO_MASK);
}

static void nbl_res_get_pt_tbl(void *priv, struct nbl_resource_pt_tbl *pt_tbl)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	pt_tbl->pt_ops.start_xmit = nbl_res_txrx_start_xmit;
	pt_tbl->pt_ops.start_xmit_draco = nbl_res_txrx_start_xmit_draco;
	pt_tbl->pt_ops.rep_xmit = nbl_res_txrx_rep_xmit;
	pt_tbl->pt_ops.self_test_xmit = nbl_res_txrx_self_test_start_xmit;
	pt_tbl->pt_ops.napi_poll = nbl_res_napi_poll;
	pt_tbl->pt_ops.features_check = NBL_RES_MGT_TO_PROD_OPS(res_mgt)->features_check;
	pt_tbl->pt_ops.xdp_xmit = nbl_res_txrx_xdp_xmit;
	pt_tbl->txrx_mgt = res_mgt->txrx_mgt;
}

static u32 nbl_res_txrx_get_tx_headroom(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	return txrx_mgt->extheader_tx_len;
}

static void nbl_res_txrx_get_queue_stats(void *priv,
					 struct nbl_get_queue_stats_param *param,
					 struct nbl_queue_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_stats *stats;

	if (param->is_tx) {
		struct nbl_res_tx_ring *ring = NBL_RES_MGT_TO_TX_RING(res_mgt, param->queue_id);

		stats = &ring->stats;
	} else {
		struct nbl_res_rx_ring *ring = NBL_RES_MGT_TO_RX_RING(res_mgt, param->queue_id);

		stats = &ring->stats;
	}

	memcpy(output, stats, sizeof(*stats));
}

static bool nbl_res_is_ctrlq(struct nbl_txrx_mgt *txrx_mgt, u16 qid)
{
	u16 ring_num = txrx_mgt->vsi_info[NBL_VSI_CTRL].ring_num;
	u16 ring_offset = txrx_mgt->vsi_info[NBL_VSI_CTRL].ring_offset;

	if (qid >= ring_offset && qid < ring_offset + ring_num)
		return true;

	return false;
}

static void nbl_res_txrx_get_net_stats(void *priv, struct nbl_stats *net_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring;
	struct nbl_res_tx_ring *tx_ring;
	int i;
	u64 bytes = 0, packets = 0;
	u64 tso_packets = 0, tso_bytes = 0;
	u64 tso_inner_packets = 0, tso_inner_bytes = 0;
	u64 tx_csum_packets = 0, tx_csum_inner_packets = 0;
	u64 rx_csum_packets = 0, rx_csum_inner_packets = 0, rx_csum_errors = 0;
	u64 tx_multicast_packets = 0, tx_unicast_packets = 0;
	u64 rx_multicast_packets = 0, rx_unicast_packets = 0;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	u64 tls_encrypted_packets = 0;
	u64 tls_encrypted_bytes = 0;
	u64 tls_ooo_packets = 0;
	u64 tls_decrypted_packets = 0;
	u64 tls_resync_req_num = 0;
#endif
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
	u64 tx_added_vlan_packets = 0;
	u64 rx_removed_vlan_packets = 0;
	u64 rx_rss_hash_packets = 0;
	u64 xdp_tx_packets = 0;
	u64 xdp_redirect_packets = 0;
	u64 xdp_drop_packets = 0;
	u64 rx_oversize_pkts_sw_drop = 0;

	for (i = 0; i < txrx_mgt->rx_ring_num; i++) {
		if (nbl_res_is_ctrlq(txrx_mgt, i))
			continue;

		rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, i);
		bytes += rx_ring->stats.bytes;
		packets += rx_ring->stats.packets;
		rx_csum_packets += rx_ring->rx_stats.rx_csum_packets;
		rx_csum_inner_packets += rx_ring->rx_stats.rx_csum_inner_packets;
		rx_csum_errors += rx_ring->rx_stats.rx_csum_errors;
		rx_multicast_packets += rx_ring->rx_stats.rx_multicast_packets;
		rx_unicast_packets += rx_ring->rx_stats.rx_unicast_packets;
		rx_desc_addr_err_cnt += rx_ring->rx_stats.rx_desc_addr_err_cnt;
		rx_alloc_buf_err_cnt += rx_ring->rx_stats.rx_alloc_buf_err_cnt;
		rx_cache_reuse += rx_ring->rx_stats.rx_cache_reuse;
		rx_cache_full += rx_ring->rx_stats.rx_cache_full;
		rx_cache_empty += rx_ring->rx_stats.rx_cache_empty;
		rx_cache_busy += rx_ring->rx_stats.rx_cache_busy;
		rx_cache_waive += rx_ring->rx_stats.rx_cache_waive;
		xdp_tx_packets += rx_ring->rx_stats.xdp_tx_packets;
		xdp_redirect_packets += rx_ring->rx_stats.xdp_redirect_packets;
		xdp_drop_packets += rx_ring->rx_stats.xdp_drop_packets;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
		tls_decrypted_packets += rx_ring->rx_stats.tls_decrypted_packets;
		tls_resync_req_num += rx_ring->rx_stats.tls_resync_req_num;
#endif
		rx_removed_vlan_packets += rx_ring->rx_stats.rx_removed_vlan_packets;
		rx_rss_hash_packets += rx_ring->rx_stats.rx_rss_hash_packets;
		rx_oversize_pkts_sw_drop += rx_ring->rx_stats.rx_oversize_pkts_sw_drop;
	}

	net_stats->rx_packets = packets;
	net_stats->rx_bytes = bytes;

	net_stats->rx_csum_packets = rx_csum_packets;
	net_stats->rx_csum_inner_packets = rx_csum_inner_packets;
	net_stats->rx_csum_errors = rx_csum_errors;
	net_stats->rx_multicast_packets = rx_multicast_packets;
	net_stats->rx_unicast_packets = rx_unicast_packets;
	net_stats->xdp_tx_packets = xdp_tx_packets;
	net_stats->xdp_redirect_packets = xdp_redirect_packets;
	net_stats->xdp_drop_packets = xdp_drop_packets;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	net_stats->tls_decrypted_packets = tls_decrypted_packets;
	net_stats->tls_resync_req_num = tls_resync_req_num;
#endif
	net_stats->rx_removed_vlan_packets = rx_removed_vlan_packets;
	net_stats->rx_rss_hash_packets = rx_rss_hash_packets;
	net_stats->rx_oversize_pkts_sw_drop = rx_oversize_pkts_sw_drop;

	bytes = 0;
	packets = 0;

	for (i = 0; i < txrx_mgt->tx_ring_num; i++) {
		if (nbl_res_is_ctrlq(txrx_mgt, i))
			continue;

		tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, i);
		bytes += tx_ring->stats.bytes;
		packets += tx_ring->stats.packets;
		tso_packets += tx_ring->tx_stats.tso_packets;
		tso_bytes += tx_ring->tx_stats.tso_bytes;
		tso_inner_packets += tx_ring->tx_stats.tso_inner_packets;
		tso_inner_bytes += tx_ring->tx_stats.tso_inner_bytes;
		tx_csum_packets += tx_ring->tx_stats.tx_csum_packets;
		tx_csum_inner_packets += tx_ring->tx_stats.tx_csum_inner_packets;
		tx_busy += tx_ring->tx_stats.tx_busy;
		tx_dma_busy += tx_ring->tx_stats.tx_dma_busy;
		tx_multicast_packets += tx_ring->tx_stats.tx_multicast_packets;
		tx_unicast_packets += tx_ring->tx_stats.tx_unicast_packets;
		tx_skb_free += tx_ring->tx_stats.tx_skb_free;
		tx_desc_addr_err_cnt += tx_ring->tx_stats.tx_desc_addr_err_cnt;
		tx_desc_len_err_cnt += tx_ring->tx_stats.tx_desc_len_err_cnt;
#if IS_ENABLED(CONFIG_TLS_DEVICE)
		tls_encrypted_packets += tx_ring->tx_stats.tls_encrypted_packets;
		tls_encrypted_bytes += tx_ring->tx_stats.tls_encrypted_bytes;
		tls_ooo_packets += tx_ring->tx_stats.tls_ooo_packets;
#endif
		tx_added_vlan_packets += tx_ring->tx_stats.tx_added_vlan_packets;
	}

	net_stats->tx_bytes = bytes;
	net_stats->tx_packets = packets;
	net_stats->tso_packets = tso_packets;
	net_stats->tso_bytes = tso_bytes;
	net_stats->tso_inner_packets = tso_inner_packets;
	net_stats->tso_inner_bytes = tso_inner_bytes;
	net_stats->tx_csum_packets = tx_csum_packets;
	net_stats->tx_csum_inner_packets = tx_csum_inner_packets;
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
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	net_stats->tls_encrypted_packets = tls_encrypted_packets;
	net_stats->tls_encrypted_bytes = tls_encrypted_bytes;
	net_stats->tls_ooo_packets = tls_ooo_packets;
#endif
	net_stats->tx_added_vlan_packets = tx_added_vlan_packets;
}

static u16 nbl_res_txrx_get_max_desc_num(void)
{
	return NBL_MAX_DESC_NUM;
}

static u16 nbl_res_txrx_get_min_desc_num(void)
{
	return NBL_MIN_DESC_NUM;
}

static struct sk_buff *nbl_fetch_rx_buffer_lb_test(struct nbl_resource_mgt *res_mgt,
						   struct nbl_res_rx_ring *rx_ring,
						   const struct nbl_ring_desc *rx_desc,
						   u16 *num_buffers)
{
	struct nbl_rx_buffer *rx_buf;
	struct sk_buff *skb;
	const struct page *page;
	void *page_addr;
	u32 size = 256;
	u32 pkt_len = 0;

	rx_buf = nbl_get_rx_buf(rx_ring);
	page = rx_buf->di->page;
	prefetchw(page);

	page_addr = page_address(page) + rx_buf->offset;
	prefetch(page_addr);

	skb = alloc_skb(size, GFP_KERNEL);
	if (unlikely(!skb))
		return NULL;

	NBL_CALL_RX_PARSE(rx_ring->parse_rx_extend_header, rx_ring, page_addr, skb);

	prefetchw(skb->data);
	/* get number of buffers */
	*num_buffers = *(u8 *)((u8 *)page_addr + NBL_RX_EXT_HDR_NUM_BUFFERS_OFFSET);

	pkt_len = rx_desc->len - NBL_BUFFER_HDR_LEN(rx_ring);
	memcpy(__skb_put(skb, pkt_len), page_addr + NBL_BUFFER_HDR_LEN(rx_ring),
	       ALIGN(pkt_len, sizeof(long)));

	rx_ring->next_to_clean++;
	if (rx_ring->next_to_clean >= rx_ring->desc_num) {
		rx_ring->next_to_clean -= rx_ring->desc_num;
		rx_ring->used_wrap_counter ^= 1;
	}

	return skb;
}

static struct sk_buff *nbl_res_txrx_clean_rx_lb_test(void *priv,
						     u32 *ring_index)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring = txrx_mgt->rx_rings[*ring_index];
	struct nbl_ring_desc *rx_desc;
	struct sk_buff *skb;
	u16 num_buffers = 0;
	u16 vq_free_cnt;

	vq_free_cnt = rx_ring->vq_free_cnt & (~(NBL_MAX_BATCH_DESC - 1));
	if (vq_free_cnt) {
		u16 next_to_use = rx_ring->next_to_use;
		u16 next_to_free = rx_ring->next_to_free;
		u16 desc_num = rx_ring->desc_num;
		u16 free_gap, release_cnt, i;

		if ((next_to_use + vq_free_cnt) > desc_num)
			vq_free_cnt = desc_num - next_to_use;

		/* After a partial refill failure, next_to_free runs ahead of
		 * next_to_use: those pages were already recycled but the
		 * descriptors were not refilled. Release only what is left
		 * in the consumed window and never rewind next_to_free, or
		 * the same page gets recycled twice.
		 */
		free_gap = (next_to_free + desc_num - next_to_use) % desc_num;
		release_cnt = vq_free_cnt - min(vq_free_cnt, free_gap);
		if ((next_to_free + release_cnt) > desc_num)
			release_cnt = desc_num - next_to_free;

		for (i = next_to_free; i < next_to_free + release_cnt; i++)
			nbl_put_rx_frag(rx_ring, NBL_RX_BUF(rx_ring, i), 1);

		next_to_free += release_cnt;
		if (next_to_free == desc_num)
			next_to_free = 0;
		rx_ring->next_to_free = next_to_free;

		nbl_alloc_rx_bufs(rx_ring, vq_free_cnt);
	}

	rx_desc = NBL_RX_DESC(rx_ring, rx_ring->next_to_clean);
	if (!nbl_ring_desc_used(rx_desc, rx_ring->used_wrap_counter))
		return NULL;

	/* read barrier to order the used flag check before descriptor reads */
	rmb();

	skb = nbl_fetch_rx_buffer_lb_test(res_mgt, rx_ring, rx_desc, &num_buffers);
	if (!skb)
		return NULL;

	rx_ring->vq_free_cnt += num_buffers;

	if (num_buffers > 1)
		nbl_err(common, NBL_DEBUG_RESOURCE, "More than one desc in lb rx, not supported\n");

	vq_free_cnt = rx_ring->vq_free_cnt & (~(NBL_MAX_BATCH_DESC - 1));
	if (vq_free_cnt) {
		u16 next_to_use = rx_ring->next_to_use;
		u16 next_to_free = rx_ring->next_to_free;
		u16 desc_num = rx_ring->desc_num;
		u16 free_gap, release_cnt, i;

		if ((next_to_use + vq_free_cnt) > desc_num)
			vq_free_cnt = desc_num - next_to_use;

		/* After a partial refill failure, next_to_free runs ahead of
		 * next_to_use: those pages were already recycled but the
		 * descriptors were not refilled. Release only what is left
		 * in the consumed window and never rewind next_to_free, or
		 * the same page gets recycled twice.
		 */
		free_gap = (next_to_free + desc_num - next_to_use) % desc_num;
		release_cnt = vq_free_cnt - min(vq_free_cnt, free_gap);
		if ((next_to_free + release_cnt) > desc_num)
			release_cnt = desc_num - next_to_free;

		for (i = next_to_free; i < next_to_free + release_cnt; i++)
			nbl_put_rx_frag(rx_ring, NBL_RX_BUF(rx_ring, i), 1);

		next_to_free += release_cnt;
		if (next_to_free == desc_num)
			next_to_free = 0;
		rx_ring->next_to_free = next_to_free;

		nbl_alloc_rx_bufs(rx_ring, vq_free_cnt);
	}

	return skb;
}

static int nbl_res_txrx_cfg_duppkt_info(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_txrx_bond_info *bond_info = &txrx_mgt->bond_info;
	struct nbl_res_tx_ring *tx_ring;
	int i = 0;

	if (!param->duppkt_enable) {
		memset(bond_info, 0, sizeof(*bond_info));
	} else if (param->lag_num > 1) {
		for (i = 0; i < param->lag_num && i < NBL_LAG_MAX_PORTS; i++)
			bond_info->eth_id[i] = param->member_list[i].eth_id;
		bond_info->bond_enable = 1;
		bond_info->lag_id = param->lag_id;
	}

	for (i = 0; i < txrx_mgt->rx_ring_num; i++) {
		tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, i);
		nbl_res_tx_set_dport(res_mgt, tx_ring);
	}

	return 0;
}

static int nbl_res_queue_stop_abnormal_sw_queue(void *priv,
						struct nbl_stop_abnormal_sw_queue_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 local_queue_id = param->local_queue_id;
	int type = param->type;
	struct nbl_res_vector *vector =  NULL;
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, local_queue_id);

	if (type != NBL_TX)
		return 0;

	if (tx_ring && tx_ring->vsi_type != NBL_VSI_XDP)
		vector = NBL_RES_MGT_TO_VECTOR(res_mgt, local_queue_id);

	if (!tx_ring->valid)
		return -EINVAL;

	if (vector && vector->started) {
		vector->started = false;
		napi_synchronize(&vector->nbl_napi.napi);
		napi_disable(&vector->nbl_napi.napi);
		netif_stop_subqueue(tx_ring->netdev, local_queue_id);
	}

	return 0;
}

static dma_addr_t nbl_res_txrx_restore_abnormal_ring(void *priv,
						     struct nbl_abnormal_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int ring_index = param->ring_index;
	int type = param->type;
	struct nbl_res_vector *vector =  NULL;
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);
	struct nbl_tx_ring_start_param tx_ring_prm;
	struct nbl_rx_ring_start_param rx_ring_prm;

	if (tx_ring && tx_ring->vsi_type != NBL_VSI_XDP)
		vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	switch (type) {
	case NBL_TX:
		if (tx_ring && tx_ring->valid) {
			nbl_res_txrx_stop_tx_ring(res_mgt, ring_index);
			tx_ring_prm.interleave_seg_disable = tx_ring->interleave_seg_disable;
			tx_ring_prm.ring_index = ring_index;
			tx_ring_prm.queue_size = tx_ring->desc_num;
			return nbl_res_txrx_start_tx_ring(res_mgt, &tx_ring_prm);
		} else {
			return (dma_addr_t)NULL;
		}
		break;
	case NBL_RX:
		if (rx_ring && rx_ring->valid) {
			rx_ring_prm.queue_size = rx_ring->desc_num;
			rx_ring_prm.ring_index = ring_index;
			rx_ring_prm.rxq_large_buf = rx_ring->rxq_large_buf;
			rx_ring_prm.use_napi = true;
			nbl_res_txrx_stop_rx_ring(res_mgt, ring_index);
			return nbl_res_txrx_start_rx_ring(res_mgt, &rx_ring_prm);
		} else {
			return (dma_addr_t)NULL;
		}
		break;
	default:
		break;
	}

	return (dma_addr_t)NULL;
}

static int nbl_res_txrx_restart_abnormal_ring(void *priv,
					      struct nbl_abnormal_ring_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int ring_index = param->ring_index;
	int type = param->type;
	struct nbl_res_tx_ring *tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, ring_index);
	struct nbl_res_rx_ring *rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, ring_index);
	struct nbl_res_vector *vector = NULL;
	int ret = 0;

	if (tx_ring && tx_ring->vsi_type != NBL_VSI_XDP)
		vector = NBL_RES_MGT_TO_VECTOR(res_mgt, ring_index);

	switch (type) {
	case NBL_TX:
		if (tx_ring && tx_ring->valid) {
			nbl_write_doorbell(tx_ring);
			netif_start_subqueue(tx_ring->netdev, ring_index);
		} else {
			ret = -EINVAL;
		}
		break;
	case NBL_RX:
		if (rx_ring && rx_ring->valid)
			nbl_res_txrx_kick_rx_ring(res_mgt, ring_index);
		else
			ret = -EINVAL;
		break;
	default:
		break;
	}

	if (vector && !vector->started) {
		vector->started = true;
		napi_enable(&vector->nbl_napi.napi);
		if (vector->net_msix_mask_en)
			writel(vector->irq_data, vector->irq_enable_base);
	}

	return ret;
}

static void nbl_res_txrx_set_xdp_prog(void *priv, void *prog)
{
	u16 data_vsi_ring_num;
	int i;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring;
	struct nbl_res_tx_ring *tx_ring;

	data_vsi_ring_num = txrx_mgt->vsi_info[NBL_VSI_DATA].ring_num;
	for (i = 0; i < data_vsi_ring_num; i++) {
		rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, i);
		if (!rx_ring)
			continue;

		WRITE_ONCE(rx_ring->xdp_prog, prog);
	}

	for (i = 0; i < txrx_mgt->xdp_ring_num; i++) {
		tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, i + txrx_mgt->xdp_ring_offset);
		if (!tx_ring)
			continue;

		WRITE_ONCE(tx_ring->xdp_prog, prog);
	}
}

static int nbl_res_check_mtu(void *priv, bool force_xdp, int new_mtu, int *max_mtu)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring;
	u16 headroom, tailroom;

	if (!txrx_mgt->need_check_mtu)
		return 0;

	*max_mtu = NBL_MAX_JUMBO_FRAME_SIZE - NBL_PKT_HDR_PAD;

	rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, 0);

	if ((!!(txrx_mgt->xdp_ring_num) && rx_ring->xdp_prog) || force_xdp) {
		headroom = XDP_PACKET_HEADROOM + NBL_BUFFER_HDR_LEN(rx_ring) + NBL_PKT_HDR_PAD;
		tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

		*max_mtu = PAGE_SIZE - headroom - tailroom;
	}

	if (new_mtu > *max_mtu)
		return -EINVAL;

	return 0;
}

static void nbl_res_txrx_set_xdp_enhance(void *priv, bool enable)
{
	u16 data_vsi_ring_num;
	int i;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_rx_ring *rx_ring;

	data_vsi_ring_num = txrx_mgt->vsi_info[NBL_VSI_DATA].ring_num;
	for (i = 0; i < data_vsi_ring_num; i++) {
		rx_ring = NBL_RES_MGT_TO_RX_RING(res_mgt, i);
		if (!rx_ring)
			continue;

		rx_ring->xdp_enhance = enable;
	}
}

static int nbl_res_set_eswitch_mode(void *priv, u16 *switch_mode)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);
	struct nbl_res_tx_ring *tx_ring;
	int i;

	resource_info->eswitch_info->mode = *switch_mode;
	/* set ring info switch_mode */
	for (i = 0; i < txrx_mgt->rx_ring_num; i++) {
		tx_ring = NBL_RES_MGT_TO_TX_RING(res_mgt, i);
		nbl_res_tx_set_dport(res_mgt, tx_ring);
	}

	return 0;
}

static u16 nbl_res_get_eswitch_mode(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	if (resource_info->eswitch_info)
		return resource_info->eswitch_info->mode;
	else
		return NBL_ESWITCH_NONE;
}

/* NBL_TXRX_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_TXRX_OPS_TBL								\
do {											\
	NBL_TXRX_SET_OPS(get_res_pt_tbl, nbl_res_get_pt_tbl);			\
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
	NBL_TXRX_SET_OPS(clean_rx_lb_test, nbl_res_txrx_clean_rx_lb_test);		\
	NBL_TXRX_SET_OPS(cfg_duppkt_info, nbl_res_txrx_cfg_duppkt_info);		\
	NBL_TXRX_SET_OPS(stop_abnormal_sw_queue, nbl_res_queue_stop_abnormal_sw_queue);	\
	NBL_TXRX_SET_OPS(restore_abnormal_ring, nbl_res_txrx_restore_abnormal_ring);	\
	NBL_TXRX_SET_OPS(restart_abnormal_ring, nbl_res_txrx_restart_abnormal_ring);	\
	NBL_TXRX_SET_OPS(register_vsi_ring, nbl_txrx_register_vsi_ring);		\
	NBL_TXRX_SET_OPS(cfg_rx_half_offload, nbl_res_txrx_cfg_rx_half_offload);	\
	NBL_TXRX_SET_OPS(cfg_rx_vlan_parse, nbl_res_txrx_cfg_rx_vlan_parse);		\
	NBL_TXRX_SET_OPS(cfg_rss_hash, nbl_res_txrx_cfg_rss_hash);			\
	NBL_TXRX_SET_OPS(cfg_txrx_vlan, nbl_res_txrx_cfg_txrx_vlan);			\
	NBL_TXRX_SET_OPS(set_rings_xdp_prog, nbl_res_txrx_set_xdp_prog);		\
	NBL_TXRX_SET_OPS(register_xdp_rxq, nbl_res_txrx_register_xdp_rxq);		\
	NBL_TXRX_SET_OPS(unregister_xdp_rxq, nbl_res_txrx_unregister_xdp_rxq);		\
	NBL_TXRX_SET_OPS(check_mtu, nbl_res_check_mtu);					\
	NBL_TXRX_SET_OPS(set_xdp_enhance, nbl_res_txrx_set_xdp_enhance);		\
	NBL_TXRX_SET_OPS(set_eswitch_mode, nbl_res_set_eswitch_mode);			\
	NBL_TXRX_SET_OPS(get_eswitch_mode, nbl_res_get_eswitch_mode);			\
} while (0)

int nbl_txrx_mgt_init_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	txrx_mgt->extheader_tx_len = NBL_TX_EXTHEADER_LEN_DEFAULT;
	txrx_mgt->ktls_inithdr_len = NBL_KTLS_INIT_LEN_LEONIS;
	txrx_mgt->ktls_synchdr_len = NBL_KTLS_SYNC_LEN_LEONIS;
	txrx_mgt->need_check_mtu = 1;
	txrx_mgt->offload_type = NBL_VLAN_SW_OFFLOAD;
	txrx_mgt->simple_fwd = 0;
	txrx_mgt->novirtual = 0;
	return 0;
}

int nbl_txrx_mgt_init_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_txrx_mgt *txrx_mgt = NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	txrx_mgt->offload_type = NBL_VLAN_HW_OFFLOAD;
	txrx_mgt->extheader_tx_len = NBL_TX_EXTHEADER_LEN_DRACO;
	txrx_mgt->ktls_inithdr_len = NBL_KTLS_INIT_LEN_DRACO;
	txrx_mgt->ktls_synchdr_len = NBL_KTLS_SYNC_LEN_DRACO;
	txrx_mgt->need_check_mtu = 1;
	txrx_mgt->simple_fwd = 0;
	txrx_mgt->novirtual = 0;
	txrx_mgt->support_ptr = 1;

	return 0;
}

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
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct device *dev;
	struct nbl_txrx_mgt **txrx_mgt;
	int ret = 0;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	txrx_mgt = &NBL_RES_MGT_TO_TXRX_MGT(res_mgt);

	ret = nbl_txrx_setup_mgt(dev, txrx_mgt);
	if (ret)
		return ret;

	ret = NBL_OPS_CALL(product_ops->txrx_mgt_init, (res_mgt));

	return ret;
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
