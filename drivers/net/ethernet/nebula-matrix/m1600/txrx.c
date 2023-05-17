// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#include "common.h"
#include "interrupt.h"
#include "mailbox.h"
#include "txrx.h"

static int nbl_alloc_q_vector(struct nbl_adapter *adapter, u16 q_vector_id)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;

	q_vector = devm_kzalloc(dev, sizeof(struct nbl_q_vector), GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	q_vector->adapter = adapter;
	q_vector->q_vector_id = q_vector_id;
	q_vector->global_vector_id = adapter->hw.vsi_id *
				     adapter->num_q_vectors + q_vector_id;

	netif_napi_add(adapter->netdev, &q_vector->napi, nbl_napi_poll, NAPI_POLL_WEIGHT);

	adapter->q_vectors[q_vector_id] = q_vector;

	return 0;
}

static void nbl_free_q_vector(struct nbl_adapter *adapter, u16 q_vector_id)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;

	q_vector = adapter->q_vectors[q_vector_id];
	if (!q_vector) {
		pr_warn("Try to free queue vector %u which is not allocated", q_vector_id);
		return;
	}

	netif_napi_del(&q_vector->napi);

	devm_kfree(dev, q_vector);
	adapter->q_vectors[q_vector_id] = NULL;
}

int nbl_alloc_q_vectors(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_hw *hw = &adapter->hw;
	u16 q_vector_num;
	u16 q_vector_id;
	int err;

	q_vector_num = adapter->num_q_vectors;
	/* AF has an additional forward queue */
	q_vector_num += is_af(hw) ? 1 : 0;
	adapter->q_vectors = devm_kcalloc(dev, q_vector_num, sizeof(*adapter->q_vectors),
					  GFP_KERNEL);
	if (!adapter->q_vectors)
		return -ENOMEM;

	for (q_vector_id = 0; q_vector_id < q_vector_num; q_vector_id++) {
		err = nbl_alloc_q_vector(adapter, q_vector_id);
		if (err) {
			pr_err("Failed to allocate memory for queue vector %d\n", q_vector_id);
			goto err_out;
		}
	}

	return 0;

err_out:
	while (q_vector_id--)
		nbl_free_q_vector(adapter, q_vector_id);
	devm_kfree(dev, adapter->q_vectors);
	adapter->num_q_vectors = 0;
	return err;
}

void nbl_free_q_vectors(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct device *dev = nbl_adapter_to_dev(adapter);
	u16 q_vector_num;
	u16 q_vector_id;

	q_vector_num = adapter->num_q_vectors;
	/* AF has an additional forward queue */
	q_vector_num += is_af(hw) ? 1 : 0;
	for (q_vector_id = 0; q_vector_id < q_vector_num; q_vector_id++)
		nbl_free_q_vector(adapter, q_vector_id);
	devm_kfree(dev, adapter->q_vectors);
	adapter->q_vectors = NULL;
	adapter->num_q_vectors = 0;
}

static int nbl_alloc_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *ring;
	struct device *dev;
	u8 __iomem *notify_addr;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_txq;
	/* AF has an additional forward queue */
	ring_count += is_af(hw) ? 1 : 0;
	dev = nbl_adapter_to_dev(adapter);

	if (adapter->tx_rings) {
		pr_err("Try to allocate tx_rings which already exists\n");
		return -EINVAL;
	}

	adapter->tx_rings = devm_kcalloc(dev, ring_count, sizeof(*adapter->tx_rings),
					 GFP_KERNEL);
	if (!adapter->tx_rings)
		return -ENOMEM;

	if (is_af(hw))
		notify_addr = hw->hw_addr + NBL_PCOMPLETER_AF_NOTIFY_REG;
	else
		notify_addr = hw->hw_addr;

	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = adapter->tx_rings[ring_index];
		ring = devm_kzalloc(dev, sizeof(struct nbl_ring), GFP_KERNEL);
		if (!ring) {
			pr_err("Allocate the %xth tx ring failed\n", ring_index);
			goto alloc_tx_ring_failed;
		}

		ring->queue_index = ring_index;
		ring->dev = dev;
		ring->netdev = adapter->netdev;
		ring->desc_num = adapter->tx_desc_num;
		ring->local_qid = ring_index * 2 + 1;
		ring->notify_addr = notify_addr;
		WRITE_ONCE(adapter->tx_rings[ring_index], ring);
	}

	return 0;

alloc_tx_ring_failed:
	while (ring_index--)
		devm_kfree(dev, adapter->tx_rings[ring_index]);
	devm_kfree(dev, adapter->tx_rings);
	adapter->tx_rings = NULL;
	return -ENOMEM;
}

static void nbl_free_tx_rings(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_txq;
	/* AF has an additional forward queue */
	ring_count += is_af(hw) ? 1 : 0;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = adapter->tx_rings[ring_index];
		devm_kfree(dev, ring);
	}
	devm_kfree(dev, adapter->tx_rings);
	adapter->tx_rings = NULL;
}

static int nbl_alloc_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *ring;
	struct device *dev;
	u8 __iomem *notify_addr;
	u8 ring_count;
	u8 ring_index;
#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
	struct dma_attrs attrs = { 0 };

	dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &attrs);
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
#endif
#endif

	ring_count = adapter->num_rxq;
	/* AF has an additional forward queue */
	ring_count += is_af(hw) ? 1 : 0;
	dev = nbl_adapter_to_dev(adapter);

	if (adapter->rx_rings) {
		pr_err("Try to allocate rx_rings which already exists\n");
		return -EINVAL;
	}

	adapter->rx_rings = devm_kcalloc(dev, ring_count, sizeof(*adapter->rx_rings),
					 GFP_KERNEL);
	if (!adapter->rx_rings)
		return -ENOMEM;

	if (is_af(hw))
		notify_addr = hw->hw_addr + NBL_PCOMPLETER_AF_NOTIFY_REG;
	else
		notify_addr = hw->hw_addr;

	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = adapter->rx_rings[ring_index];
		ring = devm_kzalloc(dev, sizeof(struct nbl_ring), GFP_KERNEL);
		if (!ring) {
			pr_err("Allocate the %xth rx ring failed\n", ring_index);
			goto alloc_rx_ring_failed;
		}

		ring->queue_index = ring_index;
		ring->dev = dev;
		ring->netdev = adapter->netdev;
		ring->desc_num = adapter->rx_desc_num;
		ring->local_qid = 2 * ring_index;
		ring->notify_addr = notify_addr;
#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
		memcpy(&ring->rx_buf_attrs, &attrs, sizeof(attrs));
#endif
#endif
		ring->buf_len = NBL_RX_BUF_LEN;
		WRITE_ONCE(adapter->rx_rings[ring_index], ring);
	}

	return 0;

alloc_rx_ring_failed:
	while (ring_index--)
		devm_kfree(dev, adapter->rx_rings[ring_index]);
	devm_kfree(dev, adapter->rx_rings);
	adapter->rx_rings = NULL;
	return -ENOMEM;
}

static void nbl_free_rx_rings(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_rxq;
	/* AF has an additional forward queue */
	ring_count += is_af(hw) ? 1 : 0;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		ring = adapter->rx_rings[ring_index];
		devm_kfree(dev, ring);
	}
	devm_kfree(dev, adapter->rx_rings);
	adapter->rx_rings = NULL;
}

int nbl_alloc_rings(struct nbl_adapter *adapter)
{
	int err = 0;

	err = nbl_alloc_tx_rings(adapter);
	if (err)
		return err;

	err = nbl_alloc_rx_rings(adapter);
	if (err)
		goto alloc_rx_rings_err;

	return 0;

alloc_rx_rings_err:
	nbl_free_tx_rings(adapter);
	return err;
}

void nbl_free_rings(struct nbl_adapter *adapter)
{
	nbl_free_tx_rings(adapter);
	nbl_free_rx_rings(adapter);
}

void nbl_map_rings_to_vectors(struct nbl_adapter *adapter)
{
	u16 tx_rings_rem;
	u16 rx_rings_rem;
	u16 q_vector_num;
	u16 q_vector_id;

	tx_rings_rem = adapter->num_txq;
	rx_rings_rem = adapter->num_rxq;
	q_vector_num = adapter->num_q_vectors;

	for (q_vector_id = 0; q_vector_id < q_vector_num; q_vector_id++) {
		struct nbl_q_vector *q_vector = adapter->q_vectors[q_vector_id];
		u16 tx_rings_per_vector;
		u16 rx_rings_per_vector;
		u16 ring_base;
		u32 ring_end;
		u16 ring_id;
		struct nbl_ring *ring;

		tx_rings_per_vector = DIV_ROUND_UP(tx_rings_rem, q_vector_num - q_vector_id);
		q_vector->num_ring_tx = tx_rings_per_vector;
		q_vector->tx_ring = NULL;
		ring_base = adapter->num_txq - tx_rings_rem;
		ring_end = ring_base + tx_rings_per_vector;

		for (ring_id = ring_base; ring_id < ring_end; ring_id++) {
			ring = adapter->tx_rings[ring_id];
			ring->next = q_vector->tx_ring;
			ring->q_vector = q_vector;
			q_vector->tx_ring = ring;
		}
		tx_rings_rem = tx_rings_rem - tx_rings_per_vector;

		rx_rings_per_vector = DIV_ROUND_UP(rx_rings_rem, q_vector_num - q_vector_id);
		q_vector->num_ring_rx = rx_rings_per_vector;
		q_vector->rx_ring = NULL;
		ring_base = adapter->num_rxq - rx_rings_rem;
		ring_end = ring_base + rx_rings_per_vector;

		for (ring_id = ring_base; ring_id < ring_end; ring_id++) {
			ring = adapter->rx_rings[ring_id];
			ring->next = q_vector->rx_ring;
			ring->q_vector = q_vector;
			q_vector->rx_ring = ring;
		}
		rx_rings_rem = rx_rings_rem - rx_rings_per_vector;
	}
}

static int nbl_setup_tx_ring(struct nbl_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;

	if (tx_ring->tx_bufs) {
		pr_err("Try to setup a TX ring with buffer management array already allocated\n");
		return -EINVAL;
	}

	tx_ring->tx_bufs = devm_kcalloc(dev, tx_ring->desc_num, sizeof(*tx_ring->tx_bufs),
					GFP_KERNEL);
	if (!tx_ring->tx_bufs)
		return -ENOMEM;

	tx_ring->size = ALIGN(tx_ring->desc_num * sizeof(struct nbl_tx_desc), PAGE_SIZE);
	tx_ring->desc = dmam_alloc_coherent(dev, tx_ring->size, &tx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);

	if (!tx_ring->desc) {
		pr_err("Allocate %u bytes descriptor DMA memory for TX queue %u failed\n",
		       tx_ring->size, tx_ring->queue_index);
		goto alloc_dma_err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->next_to_alloc = 0;
	tx_ring->tail_ptr = 0;

	return 0;

alloc_dma_err:
	devm_kfree(dev, tx_ring->tx_bufs);
	tx_ring->tx_bufs = NULL;
	tx_ring->size = 0;
	return -ENOMEM;
}

static void nbl_teardown_tx_ring(struct nbl_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;

	devm_kfree(dev, tx_ring->tx_bufs);
	tx_ring->tx_bufs = NULL;

	dmam_free_coherent(dev, tx_ring->size, tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
	tx_ring->dma = (dma_addr_t)NULL;
	tx_ring->size = 0;
}

static int nbl_setup_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *tx_ring;
	u8 ring_count;
	u8 ring_index;
	int err;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		tx_ring = adapter->tx_rings[ring_index];
		WARN_ON(!tx_ring);

		err = nbl_setup_tx_ring(tx_ring);
		if (err)
			goto err;
	}

	return 0;

err:
	while (ring_index--) {
		tx_ring = adapter->tx_rings[ring_index];
		nbl_teardown_tx_ring(tx_ring);
	}
	return err;
}

static void nbl_teardown_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *tx_ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		tx_ring = adapter->tx_rings[ring_index];
		WARN_ON(!tx_ring);

		nbl_teardown_tx_ring(tx_ring);
	}
}

static int nbl_setup_rx_ring(struct nbl_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;

	if (rx_ring->rx_bufs) {
		pr_err("Try to setup a TX ring with buffer management array already allocated\n");
		return -EINVAL;
	}

	rx_ring->rx_bufs = devm_kcalloc(dev, rx_ring->desc_num, sizeof(*rx_ring->rx_bufs),
					GFP_KERNEL);
	if (!rx_ring->rx_bufs)
		return -ENOMEM;

	rx_ring->size = ALIGN(rx_ring->desc_num * sizeof(struct nbl_rx_desc), PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dev, rx_ring->size, &rx_ring->dma,
					    GFP_KERNEL | __GFP_ZERO);

	if (!rx_ring->desc) {
		pr_err("Allocate %u bytes descriptor DMA memory for TX queue %u failed\n",
		       rx_ring->size, rx_ring->queue_index);
		goto alloc_dma_err;
	}

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_alloc = 0;
	rx_ring->tail_ptr = 0;

	return 0;

alloc_dma_err:
	devm_kfree(dev, rx_ring->rx_bufs);
	rx_ring->rx_bufs = NULL;
	rx_ring->size = 0;
	return -ENOMEM;
}

static void nbl_teardown_rx_ring(struct nbl_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;

	devm_kfree(dev, rx_ring->rx_bufs);
	rx_ring->rx_bufs = NULL;

	dmam_free_coherent(dev, rx_ring->size, rx_ring->desc, rx_ring->dma);
	rx_ring->desc = NULL;
	rx_ring->dma = (dma_addr_t)NULL;
	rx_ring->size = 0;
}

static int nbl_setup_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *rx_ring;
	u8 ring_count;
	u8 ring_index;
	int err;

	ring_count = adapter->num_rxq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];
		WARN_ON(!rx_ring);

		err = nbl_setup_rx_ring(rx_ring);
		if (err)
			goto err;
	}

	return 0;

err:
	while (ring_index--) {
		rx_ring = adapter->rx_rings[ring_index];
		nbl_teardown_rx_ring(rx_ring);
	}
	return err;
}

static void nbl_teardown_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *rx_ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_rxq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];
		WARN_ON(!rx_ring);

		nbl_teardown_rx_ring(rx_ring);
	}
}

int nbl_setup_rings(struct nbl_adapter *adapter)
{
	int err;

	err = nbl_setup_tx_rings(adapter);
	if (err)
		return err;

	err = nbl_setup_rx_rings(adapter);
	if (err)
		goto setup_rx_rings_err;

	return 0;

setup_rx_rings_err:
	nbl_teardown_tx_rings(adapter);
	return err;
}

void nbl_teardown_rings(struct nbl_adapter *adapter)
{
	nbl_teardown_tx_rings(adapter);
	nbl_teardown_rx_rings(adapter);
}

static int nbl_wait_tx_queue_idle(struct nbl_hw *hw, u8 global_queue_id)
{
	u8 index;
	u8 offset;
	u32 bitmap;
	u16 i;

	index = global_queue_id / BITS_PER_DWORD;
	offset = global_queue_id % BITS_PER_DWORD;
	i = 0;

	bitmap = rd32(hw, NBL_DSCH_NOTIFY_BITMAP_ARR(index));
	bitmap |= rd32(hw, NBL_DSCH_FLY_BITMAP_ARR(index));
	while (bitmap & (1 << offset)) {
		i++;
		if (i == 2000) {
			pr_warn("Wait too long for tx queue %u to be idle\n", global_queue_id);
			return -EBUSY;
		}

		udelay(5);

		bitmap = rd32(hw, NBL_DSCH_NOTIFY_BITMAP_ARR(index));
		bitmap |= rd32(hw, NBL_DSCH_FLY_BITMAP_ARR(index));
	}

	return 0;
}

void nbl_af_hw_config_tx_ring(struct nbl_hw *hw, u16 func_id, dma_addr_t dma,
			      u16 desc_num, u8 vsi_id, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct tx_queue_info info = { 0 };
	u8 global_queue_id;

	if (!func_res || local_queue_id >= func_res->num_txrx_queues)
		return;

	global_queue_id = func_res->txrx_queues[local_queue_id];

	info.base_addr_l = (u32)(dma & 0xFFFFFFFF);
	info.base_addr_h = (u32)(dma >> 32);
	info.log2_size = ilog2(desc_num);
	/* use the same vsi id for src vsi and dest vsi */
	info.src_vsi_idx = vsi_id;
	info.priority = 7;
	info.enable = 0;

	wr32_for_each(hw, NBL_DVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
}

static void nbl_hw_config_tx_ring(struct nbl_ring *tx_ring)
{
	struct nbl_adapter *adapter = netdev_priv(tx_ring->netdev);
	struct nbl_hw *hw = &adapter->hw;
	dma_addr_t dma = tx_ring->dma;
	u16 desc_num = tx_ring->desc_num;
	u8 vsi_id = hw->vsi_id;
	u8 local_queue_id = tx_ring->queue_index;

	if (is_af(hw))
		nbl_af_hw_config_tx_ring(hw, 0, dma, desc_num, vsi_id, local_queue_id);
	else
		nbl_mailbox_req_cfg_tx_ring(hw, dma, desc_num, vsi_id, local_queue_id);
}

static int nbl_wait_rx_queue_idle(struct nbl_hw *hw, u8 global_queue_id)
{
	u32 value;
	u8 offset;
	u8 rem;
	u16 i;

	i = 0;

	offset = global_queue_id / BITS_PER_DWORD;
	rem = global_queue_id % BITS_PER_DWORD;
	value = rd32(hw, NBL_UVN_QUEUE_STATE_REG_ARR(offset));
	while (value & (1 << rem)) {
		i++;
		if (i == 2000) {
			pr_warn("Wait too long for rx queue %u to be idle\n", global_queue_id);
			return -EBUSY;
		}

		udelay(5);
		value = rd32(hw, NBL_UVN_QUEUE_STATE_REG_ARR(offset));
	}

	return 0;
}

static int nbl_wait_rx_queue_reset_usable(struct nbl_hw *hw)
{
	struct nbl_rx_queue_reset queue_reset;
	u16 i;

	i = 0;
	rd32_for_each(hw, NBL_UVN_QUEUE_RESET_REG, (u32 *)&queue_reset,
		      sizeof(queue_reset));
	while (unlikely(queue_reset.valid)) {
		i++;
		if (i == 2000) {
			pr_warn("Wait too long for rx queue reset to be usable\n");
			return -EBUSY;
		}

		udelay(5);
		rd32_for_each(hw, NBL_UVN_QUEUE_RESET_REG, (u32 *)&queue_reset,
			      sizeof(queue_reset));
	}

	return 0;
}

void nbl_af_hw_config_rx_ring(struct nbl_hw *hw, u16 func_id, dma_addr_t dma,
			      u16 desc_num, u32 buf_len, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct rx_queue_info info = { 0 };
	u8 global_queue_id;

	if (!func_res || local_queue_id >= func_res->num_txrx_queues)
		return;

	global_queue_id = func_res->txrx_queues[local_queue_id];

	info.base_addr_l = (u32)(dma & 0xFFFFFFFF);
	info.base_addr_h = (u32)(dma >> 32);
	info.log2_size = ilog2(desc_num);
	info.buf_length_pow = ilog2(buf_len / 2048);
	info.enable = 0;

	/* There is no need to write whole rx_queue_info structure
	 * for head_ptr and tail_ptr are read only.
	 */
	wr32_for_each(hw, NBL_UVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
}

static void nbl_hw_config_rx_ring(struct nbl_ring *rx_ring)
{
	struct nbl_adapter *adapter = netdev_priv(rx_ring->netdev);
	struct nbl_hw *hw = &adapter->hw;
	dma_addr_t dma = rx_ring->dma;
	u16 desc_num = rx_ring->desc_num;
	u32 buf_len = rx_ring->buf_len;
	u8 local_queue_id = rx_ring->queue_index;

	if (is_af(hw))
		nbl_af_hw_config_rx_ring(hw, 0, dma, desc_num, buf_len, local_queue_id);
	else
		nbl_mailbox_req_cfg_rx_ring(hw, dma, desc_num, buf_len, local_queue_id);
}

static void nbl_hw_config_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *tx_ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_rxq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		tx_ring = adapter->tx_rings[ring_index];

		nbl_hw_config_tx_ring(tx_ring);
	}
}

static void nbl_hw_config_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_ring *rx_ring;
	u8 ring_count;
	u8 ring_index;

	ring_count = adapter->num_rxq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];

		nbl_hw_config_rx_ring(rx_ring);
	}
}

void nbl_hw_config_rings(struct nbl_adapter *adapter)
{
	nbl_hw_config_tx_rings(adapter);
	nbl_hw_config_rx_rings(adapter);
}

static bool nbl_alloc_mapped_page(struct nbl_ring *rx_ring,
				  struct nbl_rx_buf *rx_buf)
{
	struct page *page = rx_buf->page;
	dma_addr_t dma;

	if (likely(page))
		return true;

	page = dev_alloc_pages(nbl_rx_page_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
	dma = dma_map_page_attrs(rx_ring->dev, page, 0, NBL_RX_PAGE_SIZE(rx_ring),
				 DMA_FROM_DEVICE, &rx_ring->rx_buf_attrs);
#else
	dma = dma_map_page_attrs(rx_ring->dev, page, 0, NBL_RX_PAGE_SIZE(rx_ring),
				 DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
#else
	dma = dma_map_page_attrs(rx_ring->dev, page, 0, NBL_RX_PAGE_SIZE(rx_ring),
				 DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, nbl_rx_page_order(rx_ring));
		rx_ring->rx_stats.rx_dma_err++;
		return false;
	}

	rx_buf->dma = dma;
	rx_buf->page = page;
	rx_buf->page_offset = 0;

	return true;
}

static bool nbl_alloc_rx_bufs(struct nbl_ring *rx_ring, u16 count)
{
	u32 buf_len;
	u16 next_to_use;
	u16 head;
	struct nbl_rx_desc *rx_desc;
	struct nbl_rx_buf *rx_buf;

	if (unlikely(!count)) {
		pr_warn("Try to allocate zero buffer for RX ring %u\n",
			rx_ring->queue_index);
		return true;
	}

	buf_len = rx_ring->buf_len;
	next_to_use = rx_ring->next_to_use;

	head = next_to_use;
	rx_desc = NBL_RX_DESC(rx_ring, next_to_use);
	rx_buf = NBL_RX_BUF(rx_ring, next_to_use);
	do {
		if (!nbl_alloc_mapped_page(rx_ring, rx_buf))
			break;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, rx_buf->dma, rx_buf->page_offset,
						 buf_len, DMA_FROM_DEVICE);

		rx_desc->buffer_addr = cpu_to_le64(rx_buf->dma + rx_buf->page_offset);
		rx_desc->dd = 0;

		rx_desc++;
		rx_buf++;
		next_to_use++;
		rx_ring->tail_ptr++;
		if (next_to_use == rx_ring->desc_num) {
			next_to_use = 0;
			rx_desc = NBL_RX_DESC(rx_ring, next_to_use);
			rx_buf = NBL_RX_BUF(rx_ring, next_to_use);
		}

		count--;
	} while (count);

	if (next_to_use != head) {
		/* Make sure descriptor has been written */
		wmb();
		rx_ring->next_to_use = next_to_use;
		rx_ring->next_to_alloc = next_to_use;

		nbl_update_tail_ptr(rx_ring->notify_addr, rx_ring->local_qid, rx_ring->tail_ptr);
	}

	return !count;
}

void nbl_alloc_all_rx_bufs(struct nbl_adapter *adapter)
{
	struct nbl_ring *rx_ring;
	u16 ring_count;
	u16 ring_index;
	u16 desc_count;

	ring_count = adapter->num_rxq;
	for (ring_index = 0; ring_index < adapter->num_rxq; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];
		desc_count = nbl_unused_desc_count(rx_ring);
		if (unlikely(!nbl_alloc_rx_bufs(rx_ring, desc_count))) {
			pr_warn("Allocate RX bufs for ring %u failed with desc count %u\n",
				ring_index, desc_count);
		}
	}
}

void nbl_af_configure_queue_map(struct nbl_hw *hw, u16 func_id, u8 local_queue_id,
				bool rx, u16 local_vector_id, bool enable,
				bool msix_enable)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u16 global_queue_id;
	u16 txrx_queue_id;
	u16 global_vector_id;
	struct nbl_queue_map queue_map;
	u8 bus;
	u8 devid;
	u8 function;

	if (!func_res)
		return;

	if (msix_enable) {
		WARN_ON(local_vector_id >= func_res->num_interrupts);
		global_vector_id = func_res->interrupts[local_vector_id];
	}

	WARN_ON(local_queue_id >= func_res->num_txrx_queues);
	global_queue_id = func_res->txrx_queues[local_queue_id];
	if (rx)
		txrx_queue_id = 2 * global_queue_id;
	else
		txrx_queue_id = 2 * global_queue_id + 1;

	nbl_af_compute_bdf(hw, func_id, &bus, &devid, &function);

	memset(&queue_map, 0, sizeof(queue_map));
	queue_map.function = function;
	queue_map.devid = devid;
	queue_map.bus = bus;

	if (enable) {
		if (msix_enable) {
			queue_map.msix_idx = global_vector_id;
			queue_map.msix_idx_valid = 1;
		}
		queue_map.valid = 1;
	} else {
		queue_map.msix_idx_valid = 0;
		queue_map.valid = 0;
	}

	wr32_for_each(hw, NBL_PADPT_QUEUE_MAP_REG_ARR(txrx_queue_id),
		      (u32 *)&queue_map, sizeof(queue_map));
}

static void nbl_configure_queue_map(struct nbl_hw *hw, u8 local_queue_id, bool rx,
				    u16 local_vector_id, bool enable)
{
	if (is_af(hw))
		nbl_af_configure_queue_map(hw, 0, local_queue_id, rx, local_vector_id,
					   enable, true);
	else
		nbl_mailbox_req_cfg_queue_map(hw, local_queue_id, rx, local_vector_id,
					      enable, true);
}

static void nbl_af_control_tx_queue(struct nbl_hw *hw, u8 global_queue_id, bool enable)
{
	struct tx_queue_info info;

	/* No need to read head and tail pointer */
	rd32_for_each(hw, NBL_DVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
	if (enable)
		info.enable = 1;
	else
		info.enable = 0;
	wr32_for_each(hw, NBL_DVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
}

static void nbl_af_control_rx_queue(struct nbl_hw *hw, u8 global_queue_id, bool enable)
{
	struct rx_queue_info info;

	/* No need to read head and tail pointer */
	rd32_for_each(hw, NBL_UVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
	if (enable)
		info.enable = 1;
	else
		info.enable = 0;
	wr32_for_each(hw, NBL_UVN_QUEUE_INFO_ARR(global_queue_id),
		      (u32 *)&info, sizeof(info) - 4);
}

void nbl_af_control_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id, bool rx, bool enable)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u8 global_queue_id;

	WARN_ON(!func_res);
	WARN_ON(local_queue_id >= func_res->num_txrx_queues);
	global_queue_id = func_res->txrx_queues[local_queue_id];
	if (rx)
		nbl_af_control_rx_queue(hw, global_queue_id, enable);
	else
		nbl_af_control_tx_queue(hw, global_queue_id, enable);
}

static void nbl_control_queue(struct nbl_hw *hw, u8 local_queue_id, bool rx, bool enable)
{
	if (is_af(hw))
		nbl_af_control_queue(hw, 0, local_queue_id, rx, enable);
	else
		nbl_mailbox_req_control_queue(hw, local_queue_id, rx, enable);
}

static inline void nbl_enable_tx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	nbl_control_queue(hw, local_queue_id, false, true);
}

static inline void nbl_disable_tx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	nbl_control_queue(hw, local_queue_id, false, false);
}

static inline void nbl_enable_rx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	nbl_control_queue(hw, local_queue_id, true, true);
}

static inline void nbl_disable_rx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	nbl_control_queue(hw, local_queue_id, true, false);
}

int nbl_af_reset_tx_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_queue_reset queue_reset = { 0 };
	u8 global_queue_id;
	int err;

	WARN_ON(!func_res);
	WARN_ON(local_queue_id >= func_res->num_txrx_queues);
	global_queue_id = func_res->txrx_queues[local_queue_id];

	err = nbl_wait_tx_queue_idle(hw, global_queue_id);
	if (err)
		return err;

	queue_reset.queue_rst_id = global_queue_id;
	wr32_for_each(hw, NBL_DVN_QUEUE_RESET_REG, (u32 *)&queue_reset, sizeof(queue_reset));

	/* clear tx queue statistics manually */
	wr32_zero_for_each(hw, NBL_DVN_QUEUE_STAT_REG_ARR(global_queue_id),
			   sizeof(struct nbl_tx_queue_stat));

	return 0;
}

static int nbl_reset_tx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	int err;

	if (is_af(hw))
		err = nbl_af_reset_tx_queue(hw, 0, local_queue_id);
	else
		err = nbl_mailbox_req_reset_tx_queue(hw, local_queue_id);

	return err;
}

int nbl_af_reset_rx_queue(struct nbl_hw *hw, u16 func_id, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_rx_queue_reset queue_reset = { 0 };
	u8 global_queue_id;
	int err;

	WARN_ON(!func_res);
	WARN_ON(local_queue_id >= func_res->num_txrx_queues);
	global_queue_id = func_res->txrx_queues[local_queue_id];

	err = nbl_wait_rx_queue_idle(hw, global_queue_id);
	if (err)
		return err;

	err = nbl_wait_rx_queue_reset_usable(hw);
	if (err)
		return err;

	queue_reset.queue_rst_id = global_queue_id;
	queue_reset.valid = 1;
	wr32_for_each(hw, NBL_UVN_QUEUE_RESET_REG, (u32 *)&queue_reset,
		      sizeof(queue_reset));

	return 0;
}

static int nbl_reset_rx_queue(struct nbl_hw *hw, u8 local_queue_id)
{
	int err;

	if (is_af(hw))
		err = nbl_af_reset_rx_queue(hw, 0, local_queue_id);
	else
		err = nbl_mailbox_req_reset_rx_queue(hw, local_queue_id);

	return 0;
}

int nbl_af_wait_rx_queue_reset_done(struct nbl_hw *hw, u16 func_id, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_rx_queue_reset queue_reset = { 0 };
	u8 global_queue_id;
	u16 i;

	WARN_ON(!func_res);
	WARN_ON(local_queue_id >= func_res->num_txrx_queues);
	global_queue_id = func_res->txrx_queues[local_queue_id];

	i = 0;
	rd32_for_each(hw, NBL_UVN_QUEUE_RESET_REG, (u32 *)&queue_reset,
		      sizeof(queue_reset));
	while ((queue_reset.queue_rst_id == global_queue_id) && queue_reset.valid) {
		i++;
		if (i == 2000) {
			pr_warn("Wait too long for rx queue %u reset to be done\n",
				global_queue_id);
			return -ETIMEDOUT;
		}

		udelay(5);
		rd32_for_each(hw, NBL_UVN_QUEUE_RESET_REG, (u32 *)&queue_reset,
			      sizeof(queue_reset));
	}

	return 0;
}

static int nbl_wait_rx_queue_reset_done(struct nbl_hw *hw, u8 local_queue_id)
{
	int err;

	if (is_af(hw))
		err = nbl_af_wait_rx_queue_reset_done(hw, 0, local_queue_id);
	else
		err = nbl_mailbox_req_wait_rx_queue_reset_done(hw, local_queue_id);

	return err;
}

void nbl_af_configure_port_map(struct nbl_hw *hw, u16 func_id, u8 eth_port_id, u8 local_queue_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_port_map port_map;
	u8 global_queue_id;

	if (!func_res || local_queue_id >= func_res->num_txrx_queues) {
		pr_alert("Cannot configure port map relationship for severe errors\n");
		return;
	}
	memset(&port_map, 0, sizeof(port_map));
	port_map.port_id = eth_port_id;
	global_queue_id = func_res->txrx_queues[local_queue_id];
	wr32_for_each(hw, NBL_DSCH_PORT_MAP_REG_ARR(global_queue_id),
		      (u32 *)&port_map, sizeof(port_map));
}

static void nbl_configure_port_map(struct nbl_hw *hw, u8 eth_port_id, u8 local_queue_id)
{
	if (is_af(hw))
		nbl_af_configure_port_map(hw, 0, eth_port_id, local_queue_id);
	else
		nbl_mailbox_req_cfg_port_map(hw, eth_port_id, local_queue_id);
}

void nbl_af_configure_rss_group_table(struct nbl_hw *hw, u16 func_id, u8 vsi_id, u8 rx_queue_num)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_rss_entry rss_entry;
	int i;
	u8 local_id;

	WARN_ON(!func_res);
	WARN_ON(rx_queue_num > func_res->num_txrx_queues);
	memset(&rss_entry, 0, sizeof(rss_entry));
	for (i = 0; i < RSS_ENTRIES_PER_VSI; i++) {
		local_id = i % rx_queue_num;
		rss_entry.rx_queue_id = func_res->txrx_queues[local_id];
		wr32_for_each(hw, NBL_PRO_RSS_GROUP_REG_ARR(vsi_id, i),
			      (u32 *)&rss_entry, sizeof(rss_entry));
	}
}

static void nbl_configure_rss_group_table(struct nbl_hw *hw, u8 vsi_id, u8 rx_queue_num)
{
	if (is_af(hw))
		nbl_af_configure_rss_group_table(hw, 0, vsi_id, rx_queue_num);
	else
		nbl_mailbox_req_cfg_rss_group_table(hw, vsi_id, rx_queue_num);
}

void nbl_start_all_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *tx_ring;
	struct nbl_q_vector *q_vector;
	u16 local_vector_id;
	u8 ring_index;
	u8 ring_count;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		tx_ring = adapter->tx_rings[ring_index];
		q_vector = tx_ring->q_vector;
		local_vector_id = q_vector->q_vector_id;
		nbl_configure_port_map(hw, hw->eth_port_id, ring_index);
		nbl_configure_queue_map(hw, ring_index, false, local_vector_id, true);
		nbl_enable_tx_queue(hw, ring_index);
	}
}

void nbl_start_all_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *rx_ring;
	struct nbl_q_vector *q_vector;
	u16 local_vector_id;
	u8 ring_index;
	u8 ring_count;

	ring_count = adapter->num_txq;

	nbl_configure_rss_group_table(hw, hw->vsi_id, ring_count);

	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];
		q_vector = rx_ring->q_vector;
		local_vector_id = q_vector->q_vector_id;
		nbl_configure_queue_map(hw, ring_index, true, local_vector_id, true);
		nbl_enable_rx_queue(hw, ring_index);
	}
}

void nbl_stop_all_tx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 ring_index;
	u8 ring_count;
	int err;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		nbl_disable_tx_queue(hw, ring_index);
		usleep_range(3000, 6000);
		nbl_configure_queue_map(hw, ring_index, false, 0, false);
		err = nbl_reset_tx_queue(hw, ring_index);
		if (unlikely(err))
			pr_err("Reset tx queue %hhu failed with error %d\n", ring_index, err);
		usleep_range(2000, 4000);
	}
}

void nbl_stop_all_rx_rings(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 ring_index;
	u8 ring_count;
	int err;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		nbl_disable_rx_queue(hw, ring_index);
		usleep_range(3000, 6000);
		nbl_configure_queue_map(hw, ring_index, true, 0, false);
		err = nbl_reset_rx_queue(hw, ring_index);
		if (unlikely(err)) {
			pr_err("Reset rx queue %u failed with error %d\n", ring_index, err);
			continue;
		}
		usleep_range(2000, 4000);
		err = nbl_wait_rx_queue_reset_done(hw, ring_index);
		if (unlikely(err))
			pr_err("Wait rx queue %hhu reset done failed with error %d\n",
			       ring_index, err);
	}
}

void nbl_af_eth_tx_enable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_tx_ctrl tx_ctrl;

	if (atomic_inc_return(&af_res->eth_port_tx_refcount[eth_port_id]) == 1) {
		rd32_for_each(hw, NBL_ETH_TX_CTRL_REG(eth_port_id),
			      (u32 *)&tx_ctrl, sizeof(tx_ctrl));
		tx_ctrl.tx_ipg_value = 0x8;
		tx_ctrl.tx_enable = 1;
		wr32_for_each(hw, NBL_ETH_TX_CTRL_REG(eth_port_id),
			      (u32 *)&tx_ctrl, sizeof(tx_ctrl));
	}
}

void nbl_eth_tx_enable(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id;

	eth_port_id = hw->eth_port_id;
	if (is_af(hw))
		nbl_af_eth_tx_enable(adapter, eth_port_id);
	else
		nbl_mailbox_req_eth_tx_enable(adapter, eth_port_id);
}

void nbl_af_eth_tx_disable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_tx_ctrl tx_ctrl;

	if (!atomic_dec_return(&af_res->eth_port_tx_refcount[eth_port_id])) {
		rd32_for_each(hw, NBL_ETH_TX_CTRL_REG(eth_port_id),
			      (u32 *)&tx_ctrl, sizeof(tx_ctrl));
		tx_ctrl.tx_enable = 0;
		wr32_for_each(hw, NBL_ETH_TX_CTRL_REG(eth_port_id),
			      (u32 *)&tx_ctrl, sizeof(tx_ctrl));
	}
}

void nbl_eth_tx_disable(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id;

	eth_port_id = hw->eth_port_id;
	if (is_af(hw))
		nbl_af_eth_tx_disable(adapter, eth_port_id);
	else
		nbl_mailbox_req_eth_tx_disable(adapter, eth_port_id);
}

void nbl_af_eth_rx_enable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_rx_ctrl rx_ctrl;

	if (atomic_inc_return(&af_res->eth_port_rx_refcount[eth_port_id]) == 1) {
		rd32_for_each(hw, NBL_ETH_RX_CTRL_REG(eth_port_id),
			      (u32 *)&rx_ctrl, sizeof(rx_ctrl));
		rx_ctrl.rx_enable = 1;
		wr32_for_each(hw, NBL_ETH_RX_CTRL_REG(eth_port_id),
			      (u32 *)&rx_ctrl, sizeof(rx_ctrl));
	}
}

void nbl_eth_rx_enable(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id;

	eth_port_id = hw->eth_port_id;
	if (is_af(hw))
		nbl_af_eth_rx_enable(adapter, eth_port_id);
	else
		nbl_mailbox_req_eth_rx_enable(adapter, eth_port_id);
}

void nbl_af_eth_rx_disable(struct nbl_adapter *adapter, u8 eth_port_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_rx_ctrl rx_ctrl;

	if (!atomic_dec_return(&af_res->eth_port_rx_refcount[eth_port_id])) {
		rd32_for_each(hw, NBL_ETH_RX_CTRL_REG(eth_port_id),
			      (u32 *)&rx_ctrl, sizeof(rx_ctrl));
		rx_ctrl.rx_enable = 0;
		wr32_for_each(hw, NBL_ETH_RX_CTRL_REG(eth_port_id),
			      (u32 *)&rx_ctrl, sizeof(rx_ctrl));
	}
}

void nbl_eth_rx_disable(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id;

	eth_port_id = hw->eth_port_id;
	if (is_af(hw))
		nbl_af_eth_rx_disable(adapter, eth_port_id);
	else
		nbl_mailbox_req_eth_rx_disable(adapter, eth_port_id);
}

static inline unsigned int nbl_txd_use_count(unsigned int size)
{
	return DIV_ROUND_UP(size, NBL_TXD_DATALEN_MAX);
}

static unsigned int nbl_xmit_desc_count(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	unsigned int size;
	unsigned int count;

	size = skb_headlen(skb);
	count = 0;
	for (;;) {
		count += nbl_txd_use_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

static int __nbl_maybe_stop_tx(struct nbl_ring *tx_ring, unsigned int size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);

	/* Memory barrier before checking head and tail */
	smp_mb();

	if (likely(nbl_unused_desc_count(tx_ring) < size))
		return -EBUSY;

	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);

	return 0;
}

static inline int nbl_maybe_stop_tx(struct nbl_ring *tx_ring, unsigned int size)
{
	if (likely(nbl_unused_desc_count(tx_ring) >= size))
		return 0;

	return __nbl_maybe_stop_tx(tx_ring, size);
}

static void nbl_unmap_and_free_tx_resource(struct nbl_ring *ring,
					   struct nbl_tx_buf *tx_buf,
					   int napi_budget)
{
	if (tx_buf->skb) {
		napi_consume_skb(tx_buf->skb, napi_budget);
		if (dma_unmap_len(tx_buf, len))
			dma_unmap_single(ring->dev, dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(ring->dev, dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	}

	tx_buf->next_to_watch = NULL;
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
}

static int nbl_tx_tso(struct nbl_tx_desc *tx_desc, struct nbl_ring *tx_ring,
		      struct sk_buff *skb, bool *tso)
{
#ifdef NBL_TSO
	struct nbl_tso_desc *desc = tx_desc;
	int err;
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
	unsigned char *exthdr;
	__be16 protocol, frag_off;
	u8 l3_start_offset, l4_proto, mac_len, ip_len, l4_len;
	u8 iipt, eipt = 0, eip_len = 0, l4_tunt = 0, l4_tun_len = 0, l4_type = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	mac_len = ip.hdr - skb->data;

	protocol = vlan_get_protocol(skb);

	if (skb->encapsulation) {
		if (protocol == htons(ETH_P_IP)) {
			eipt = NBL_EXT_IPV4;
			l4_proto = ip.v4->protocol;
		} else if (protocol == htons(ETH_P_IPV6)) {
			eipt = NBL_EXT_IPV6;
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			err = ipv6_skip_exthdr(skb, exthdr - skb->data,
					       &l4_proto, &frag_off);
			if (err < 0)
				return err;
		} else {
			return -EIO;
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
		case IPPROTO_GRE:
			l4_tunt = NBL_TUN_NVGRE;
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			l4_tunt = NBL_TUN_VXLAN;
			l4.hdr = skb_inner_network_header(skb);
			break;
		default:
			skb_checksum_help(skb);
			return 0;
		}

		eip_len = l4.hdr - ip.hdr;

		ip.hdr = skb_inner_network_header(skb);
		/* todo */
		l4_tun_len = ip.hdr - l4.hdr;

		l4.hdr = skb_inner_transport_header(skb);
		if (ip.v4->version == 4)
			protocol = htons(ETH_P_IP);

		if (ip.v6->version == 6)
			protocol = htons(ETH_P_IPV6);
	}

	l3_start_offset = ip.hdr - skb->data;

	if (protocol == htons(ETH_P_IP)) {
		iipt = NBL_INNER_IPV4;
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		iipt = NBL_INNER_IPV6;
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			ipv6_skip_exthdr(skb, exthdr - skb->data,
					 &l4_proto, &frag_off);
	} else {
		return -EIO;
	}

	ip_len = l4.hdr - ip.hdr;
	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_len = l4.tcp->doff >> 2;
		l4_type = NBL_TCP_TYPE;
		break;
	case IPPROTO_UDP:
		l4_len = sizeof(struct udphdr);
		l4_type = NBL_UDP_TYPE;
		break;
	default:
		skb_checksum_help(skb);
		return 0;
	}

	desc->mss = skb_shinfo(skb)->gso_size;
	desc->dd = 0;
	desc->l3_checksum = 1;
	desc->l4_checksum = 1;
	desc->l3_start_offset = l3_start_offset;
	desc->dtype = NBL_TSO_DESC;
	desc->mac_len = mac_len >> 1;
	desc->ip_len = ip_len >> 2;
	desc->l4_len = l4_len >> 2;
	desc->iipt = iipt;
	desc->eipt = eipt;
	desc->eip_len = eip_len >> 2;
	desc->l4_tunt = l4_tunt;
	desc->l4_tun_len = l4_tun_len >> 1;
	desc->l4_type = l4_type;
	*tso = true;

	return 1;
#else
	return 0;
#endif
}

static int nbl_tx_csum(struct nbl_tx_desc *desc, struct nbl_ring *tx_ring,
		       struct sk_buff *skb)
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
	unsigned char *exthdr;
	__be16 protocol, frag_off;
	u8 l3_start_offset, l4_proto;
	int ret;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	l3_start_offset = ip.hdr - skb->data;

	protocol = vlan_get_protocol(skb);

	if (skb->encapsulation) {
		if (protocol == htons(ETH_P_IP)) {
			l4_proto = ip.v4->protocol;
		} else if (protocol == htons(ETH_P_IPV6)) {
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data,
					       &l4_proto, &frag_off);
			if (ret < 0)
				return ret;
		} else {
			return -EIO;
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
		case IPPROTO_GRE:
			break;
		default:
			skb_checksum_help(skb);
			return 0;
		}

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		if (ip.v4->version == 4)
			protocol = htons(ETH_P_IP);

		if (ip.v6->version == 6)
			protocol = htons(ETH_P_IPV6);
	}

	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			ipv6_skip_exthdr(skb, exthdr - skb->data,
					 &l4_proto, &frag_off);
	} else {
		return -EIO;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		break;
	default:
		skb_checksum_help(skb);
		return 0;
	}

	desc->dd = 0;
	desc->l3_checksum = 1;
	desc->l4_checksum = 1;
	desc->l3_start_offset = l3_start_offset;
	tx_ring->tx_stats.tx_csum_pkts++;

	return 1;
}

static int nbl_tx_map(struct sk_buff *skb, struct nbl_ring *tx_ring,
		      const struct nbl_adapter *adapter)
{
	struct nbl_tx_buf *first_buf;
	struct nbl_tx_desc *first_desc;
	struct nbl_tx_buf *tx_buf;
	struct nbl_tx_desc *tx_desc;
	unsigned int data_len;
	unsigned int size;
	dma_addr_t dma;
	const skb_frag_t *frag;
	u16 i;
	int ret;
	bool tso = false;

	i = tx_ring->next_to_use;
	first_buf = NBL_TX_BUF(tx_ring, i);
	first_buf->skb = skb;
	first_buf->bytes = skb->len;
	first_buf->pkts = 1;

	first_desc = NBL_TX_DESC(tx_ring, i);
	first_desc->pkt_len = skb->len;
	first_desc->sop = 1;
	first_desc->fwd = NBL_FWD_NORMAL;

	ret = nbl_tx_tso(first_desc, tx_ring, skb, &tso);
	if (ret > 0) {
		i++;
		first_desc++;
		tx_ring->tail_ptr++;
		if (unlikely(i == tx_ring->desc_num)) {
			first_desc = NBL_TX_DESC(tx_ring, 0);
			i = 0;
		}
		first_buf = NBL_TX_BUF(tx_ring, i);
		first_buf->skb = skb;
		first_buf->bytes = skb->len;
		first_buf->pkts = 1;

		first_desc->pkt_len = skb->len;
		first_desc->sop = 1;
		first_desc->fwd = NBL_FWD_NORMAL;
	} else if (ret < 0) {
		dev_kfree_skb_any(skb);
		first_buf->skb = NULL;
		return NETDEV_TX_OK;
	}

	if (!tso) {
		ret = nbl_tx_csum(first_desc, tx_ring, skb);
		if (unlikely(ret < 0)) {
			dev_kfree_skb_any(skb);
			first_buf->skb = NULL;
			return NETDEV_TX_OK;
		}
	}

	tx_buf = first_buf;
	tx_desc = first_desc;

	data_len = skb->data_len;
	size = skb_headlen(skb);
	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (unlikely(dma_mapping_error(tx_ring->dev, dma))) {
			dev_warn(tx_ring->dev, "Allocate DMA to transmit skb failed\n");
			goto dma_error;
		}

		tx_buf->dma = dma;
		tx_buf->len = size;

		tx_desc->dtype = NBL_DATA_DESC;
		tx_desc->buffer_addr = dma;
		tx_desc->dd = 0;

		while (unlikely(size > NBL_TXD_DATALEN_MAX)) {
			tx_desc->data_len = NBL_TXD_DATALEN_MAX;

			dma += NBL_TXD_DATALEN_MAX;
			size -= NBL_TXD_DATALEN_MAX;

			i++;
			tx_desc++;
			tx_ring->tail_ptr++;
			if (unlikely(i == tx_ring->desc_num)) {
				tx_desc = NBL_TX_DESC(tx_ring, 0);
				i = 0;
			}

			tx_desc->buffer_addr = dma;
			tx_desc->dd = 0;
		}

		tx_desc->data_len = size;

		if (likely(!data_len))
			break;

		i++;
		tx_desc++;
		tx_ring->tail_ptr++;
		if (unlikely(i == tx_ring->desc_num)) {
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size, DMA_TO_DEVICE);
		tx_buf = NBL_TX_BUF(tx_ring, i);
	}

	tx_desc->eop = 1;
	/* Memory barrier before write tail ptr */
	wmb();

	i++;
	tx_ring->tail_ptr++;
	if (unlikely(i == tx_ring->desc_num))
		i = 0;
	first_buf->next_to_watch = tx_desc;
	tx_ring->next_to_use = i;

	skb_tx_timestamp(skb);

	nbl_update_tail_ptr(tx_ring->notify_addr, tx_ring->local_qid, tx_ring->tail_ptr);

	return NETDEV_TX_OK;

dma_error:
	tx_ring->tx_stats.tx_dma_err++;
	for (;;) {
		tx_buf = NBL_TX_BUF(tx_ring, i);
		nbl_unmap_and_free_tx_resource(tx_ring, tx_buf, 0);
		if (tx_buf == first_buf)
			break;
		if (unlikely(!i))
			i = tx_ring->desc_num;
		i--;
		tx_ring->tail_ptr--;
	}
	first_desc->sop = 0;
	first_desc->l3_checksum = 0;
	first_desc->l4_checksum = 0;

	return NETDEV_TX_OK;
}

static netdev_tx_t nbl_xmit_frame_ring(struct sk_buff *skb, struct nbl_ring *tx_ring,
				       const struct nbl_adapter *adapter)
{
	unsigned int count;

	count = nbl_xmit_desc_count(skb);
	if (unlikely(count > 8)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		count = nbl_xmit_desc_count(skb);
		tx_ring->tx_stats.tx_linearize++;
	}

	if (unlikely(nbl_maybe_stop_tx(tx_ring, count))) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	return nbl_tx_map(skb, tx_ring, adapter);
}

netdev_tx_t nbl_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_ring *tx_ring;

	tx_ring = adapter->tx_rings[skb_get_queue_mapping(skb)];

	return nbl_xmit_frame_ring(skb, tx_ring, adapter);
}

static inline int nbl_tx_desc_used(struct nbl_tx_desc *tx_desc)
{
	return tx_desc->dd;
}

static inline int nbl_rx_desc_used(struct nbl_rx_desc *rx_desc)
{
	return rx_desc->dd;
}

bool nbl_clean_tx_irq(struct nbl_ring *tx_ring, int napi_budget)
{
	struct nbl_tx_buf *tx_buf;
	struct nbl_tx_desc *tx_desc;
	unsigned int budget = NBL_DEFAULT_IRQ_WORK;
	unsigned int total_tx_pkts = 0;
	unsigned int total_tx_bytes = 0;
	s16 i = tx_ring->next_to_clean;

	tx_buf = NBL_TX_BUF(tx_ring, i);
	tx_desc = NBL_TX_DESC(tx_ring, i);
	i -= tx_ring->desc_num;
	do {
		struct nbl_tx_desc *end_desc = tx_buf->next_to_watch;

		if (!end_desc)
			break;

		/* prevent any other reads prior to end_desc */
		smp_rmb();

		if (!nbl_tx_desc_used(tx_desc))
			break;

		total_tx_bytes += tx_buf->bytes;
		total_tx_pkts += tx_buf->pkts;
		while (true) {
			nbl_unmap_and_free_tx_resource(tx_ring, tx_buf, napi_budget);
			tx_desc->sop = 0;
			tx_desc->eop = 0;
			tx_desc->l3_checksum = 0;
			tx_desc->l4_checksum = 0;
			if (tx_desc == end_desc)
				break;
			i++;
			tx_buf++;
			tx_desc++;
			if (unlikely(!i)) {
				i -= tx_ring->desc_num;
				tx_buf = NBL_TX_BUF(tx_ring, 0);
				tx_desc = NBL_TX_DESC(tx_ring, 0);
			}
		}

		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->desc_num;
			tx_buf = NBL_TX_BUF(tx_ring, 0);
			tx_desc = NBL_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		budget--;
	} while (likely(budget));

	i += tx_ring->desc_num;

	tx_ring->next_to_clean = i;

	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_tx_bytes;
	tx_ring->stats.packets += total_tx_pkts;
	u64_stats_update_end(&tx_ring->syncp);

#define TX_WAKE_THRESHOLD (MAX_DESC_NEEDED_PER_PKT * 2)
	if (unlikely(total_tx_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (nbl_unused_desc_count(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (__netif_subqueue_stopped(tx_ring->netdev, tx_ring->queue_index))
			netif_wake_subqueue(tx_ring->netdev, tx_ring->queue_index);
	}

	return !!budget;
}

static void nbl_rx_csum(struct nbl_ring *rx_ring, struct sk_buff *skb,
			struct nbl_rx_desc *rx_desc)
{
	/* Init with no checksum in device */
	skb->ip_summed = CHECKSUM_NONE;

	if (!(rx_ring->netdev->features & NETIF_F_RXCSUM))
		return;

	if (rx_desc->checksum_status == NBL_RX_CSUM_ERR)
		return;

	rx_ring->rx_stats.rx_csum_pkts++;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

static struct sk_buff *nbl_construct_skb(struct nbl_ring *rx_ring,
					 struct nbl_rx_buf *rx_buf,
					 struct nbl_rx_desc *rx_desc,
					 u16 data_len, bool *add_to_skb)
{
	unsigned int truesize;
	const char *va;
	struct sk_buff *skb;
	struct page *page;

#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
	truesize = NBL_RX_PAGE_SIZE(rx_ring) / 2;
#else
	truesize = rx_ring->buf_len;
#endif

	skb = napi_alloc_skb(&rx_ring->q_vector->napi, NBL_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma, rx_buf->page_offset,
				      data_len, DMA_FROM_DEVICE);
	page = rx_buf->page;
	nbl_rx_csum(rx_ring, skb, rx_desc);
	if (data_len <= NBL_RX_HDR_SIZE) {
		va = page_address(page) + rx_buf->page_offset;
		memcpy(__skb_put(skb, data_len), va, ALIGN(data_len, sizeof(long)));
		*add_to_skb = false;
	} else {
		skb_add_rx_frag(skb, 0, page, rx_buf->page_offset, data_len, truesize);
#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
		rx_buf->page_offset ^= truesize;
#else
		rx_buf->page_offset += truesize;
#endif
	}

	return skb;
}

static bool nbl_page_is_reusable(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

static void nbl_add_rx_frag(struct nbl_ring *rx_ring, struct nbl_rx_buf *rx_buf,
			    struct sk_buff *skb, u16 data_len)
{
	unsigned int truesize;
	struct page *page;

#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
	truesize = NBL_RX_PAGE_SIZE(rx_ring) / 2;
#else
	truesize = rx_ring->buf_len;
#endif

	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma, rx_buf->page_offset,
				      data_len, DMA_FROM_DEVICE);
	page = rx_buf->page;
	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			rx_buf->page_offset, data_len, truesize);
#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
	rx_buf->page_offset ^= truesize;
#else
	rx_buf->page_offset += truesize;
#endif
}

static bool nbl_can_reuse_rx_page(struct nbl_ring *rx_ring, struct nbl_rx_buf *rx_buf,
				  bool add_to_skb)
{
	struct page *page = rx_buf->page;
#if (PAGE_SIZE >= NBL_PAGE_SIZE_THRESH)
	unsigned int last_offset;

	last_offset = NBL_RX_PAGE_SIZE(rx_ring) - rx_ring->buf_len;
#endif

	if (!nbl_page_is_reusable(page))
		return false;

#if (PAGE_SIZE < NBL_PAGE_SIZE_THRESH)
	if (unlikely(page_count(page) != 1))
		return false;

	/* Since we are the only owner of the page and we need to
	 * increment it, just set the value to 2 in order to avoid
	 * an unnecessary locked operation
	 */
	if (add_to_skb)
#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) <= RHEL_RELEASE_CODE)
		atomic_set(&page->_refcount, 2);
#else
		set_page_count(page, 2);
#endif
#else
		atomic_set(&page->_refcount, 2);
#endif

#else
	if (rx_buf->page_offset > last_offset)
		return false;

	if (add_to_skb)
		get_page(page);
#endif

	return true;
}

static void nbl_reuse_rx_page(struct nbl_ring *rx_ring, struct nbl_rx_buf *old_buff)
{
	struct nbl_rx_buf *new_buff;
	u16 next_to_alloc = rx_ring->next_to_alloc;

	new_buff = NBL_RX_BUF(rx_ring, next_to_alloc);

	next_to_alloc++;
	rx_ring->next_to_alloc = (next_to_alloc < rx_ring->desc_num) ? next_to_alloc : 0;

	new_buff->page = old_buff->page;
	new_buff->dma = old_buff->dma;
	new_buff->page_offset = old_buff->page_offset;
}

static void nbl_put_rx_buf(struct nbl_ring *rx_ring, struct nbl_rx_buf *rx_buf,
			   struct nbl_rx_desc *rx_desc, bool add_to_skb)
{
	if (nbl_can_reuse_rx_page(rx_ring, rx_buf, add_to_skb)) {
		nbl_reuse_rx_page(rx_ring, rx_buf);
	} else {
#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
				     DMA_FROM_DEVICE, &rx_ring->rx_buf_attrs);
#else
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
				     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
#else
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
				     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
		if (!add_to_skb)
			put_page(rx_buf->page);
	}

	rx_buf->page = NULL;
	rx_desc->dd = 0;
}

static void nbl_pull_tail(struct sk_buff *skb)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va;
	unsigned int pull_len;

	va = skb_frag_address(frag);

	/* we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */
	pull_len = eth_get_headlen(skb->dev, va, NBL_RX_HDR_SIZE);
	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, pull_len);
	skb_frag_off_add(frag, pull_len);
	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

static bool nbl_cleanup_headers(struct sk_buff *skb)
{
	if (!skb_headlen(skb))
		nbl_pull_tail(skb);

	if (eth_skb_pad(skb))
		return true;

	return false;
}

static void nbl_process_skb_fields(struct nbl_ring *rx_ring, struct sk_buff *skb)
{
	struct net_device *dev = rx_ring->netdev;

	skb_record_rx_queue(skb, rx_ring->queue_index);

	skb->protocol = eth_type_trans(skb, dev);
}

int nbl_clean_rx_irq(struct nbl_ring *rx_ring, int budget)
{
	struct nbl_q_vector *q_vector = rx_ring->q_vector;
	struct nbl_rx_desc *rx_desc;
	struct nbl_rx_buf *rx_buf;
	struct sk_buff *skb;
	unsigned int total_rx_pkts;
	unsigned int total_rx_bytes;
	u16 cleaned_count;
	u16 data_len;
	u16 buf_len;
	u16 sync_len;
	bool add_to_skb;
	u16 i;

	cleaned_count = nbl_unused_desc_count(rx_ring);
	if (cleaned_count >= NBL_RX_BUF_WRITE) {
		nbl_alloc_rx_bufs(rx_ring, cleaned_count);
		cleaned_count = 0;
	}

	skb = NULL;
	total_rx_pkts = 0;
	total_rx_bytes = 0;
	buf_len = (u16)rx_ring->buf_len;

	i = rx_ring->next_to_clean;
	rx_desc = NBL_RX_DESC(rx_ring, i);
	rx_buf = NBL_RX_BUF(rx_ring, i);
	if (!nbl_rx_desc_used(rx_desc))
		return total_rx_pkts;
	/* This memory barrier is needed to keep us from reading
	 * any other fields out of the rx_desc until we know the
	 * descriptor has been written back
	 */
	dma_rmb();
	data_len = rx_desc->data_len;

	while (likely(total_rx_pkts < budget)) {
		sync_len = (data_len > buf_len) ? buf_len : data_len;
		add_to_skb = true;
		if (!skb)
			skb = nbl_construct_skb(rx_ring, rx_buf, rx_desc, sync_len, &add_to_skb);
		else
			nbl_add_rx_frag(rx_ring, rx_buf, skb, sync_len);

		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_skb_failed++;
			break;
		}

		nbl_put_rx_buf(rx_ring, rx_buf, rx_desc, add_to_skb);

		cleaned_count++;
		i++;
		rx_buf++;
		rx_desc++;
		if (i == rx_ring->desc_num) {
			i = 0;
			rx_buf = NBL_RX_BUF(rx_ring, 0);
			rx_desc = NBL_RX_DESC(rx_ring, 0);
		}
		data_len -= sync_len;
		if (data_len)
			continue;

		if (likely(!nbl_cleanup_headers(skb))) {
			total_rx_bytes += skb->len;
			nbl_process_skb_fields(rx_ring, skb);
			napi_gro_receive(&q_vector->napi, skb);
			total_rx_pkts++;
		}

		skb = NULL;

		if (!nbl_rx_desc_used(rx_desc))
			break;

		dma_rmb();
		data_len = rx_desc->data_len;
	}

	if (cleaned_count)
		nbl_alloc_rx_bufs(rx_ring, cleaned_count);

	rx_ring->next_to_clean = i;

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_pkts;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);

	return total_rx_pkts;
}

static void nbl_free_tx_ring_bufs(struct nbl_ring *tx_ring)
{
	struct nbl_tx_buf *tx_buf;
	u16 i;

	i = tx_ring->next_to_clean;
	tx_buf = NBL_TX_BUF(tx_ring, i);
	while (i != tx_ring->next_to_use) {
		nbl_unmap_and_free_tx_resource(tx_ring, tx_buf, 0);
		i++;
		tx_buf++;
		if (i == tx_ring->desc_num) {
			i = 0;
			tx_buf = NBL_TX_BUF(tx_ring, i);
		}
	}

	tx_ring->next_to_clean = 0;
	tx_ring->next_to_use = 0;
	tx_ring->tail_ptr = 0;
}

void nbl_free_all_tx_bufs(struct nbl_adapter *adapter)
{
	struct nbl_ring *tx_ring;
	u16 ring_count;
	u16 ring_index;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		tx_ring = adapter->tx_rings[ring_index];
		nbl_free_tx_ring_bufs(tx_ring);
	}
}

static void nbl_unmap_and_free_rx_resource(struct nbl_ring *rx_ring, struct nbl_rx_buf *rx_buf)
{
	u32 buf_len = rx_ring->buf_len;

	/* Invalidate cache lines that may have been written by device to avoid
	 * memory corruption.
	 */
	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma, rx_buf->page_offset,
				      buf_len, DMA_FROM_DEVICE);
#ifdef RHEL_RELEASE
#if (RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 7) < RHEL_RELEASE_CODE)
	dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
			     DMA_FROM_DEVICE, &rx_ring->rx_buf_attrs);
#else
	dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
			     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
#else
	dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma, NBL_RX_PAGE_SIZE(rx_ring),
			     DMA_FROM_DEVICE, NBL_RX_DMA_ATTR);
#endif
	put_page(rx_buf->page);
	rx_buf->page = NULL;
}

static void nbl_free_rx_ring_bufs(struct nbl_ring *rx_ring)
{
	struct nbl_rx_buf *rx_buf;
	u16 i;

	i = rx_ring->next_to_clean;
	rx_buf = NBL_RX_BUF(rx_ring, i);
	while (i != rx_ring->next_to_alloc) {
		nbl_unmap_and_free_rx_resource(rx_ring, rx_buf);
		i++;
		rx_buf++;
		if (i == rx_ring->desc_num) {
			i = 0;
			rx_buf = NBL_RX_BUF(rx_ring, i);
		}
	}

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->next_to_alloc = 0;
	rx_ring->tail_ptr = 0;
}

void nbl_free_all_rx_bufs(struct nbl_adapter *adapter)
{
	struct nbl_ring *rx_ring;
	u16 ring_count;
	u16 ring_index;

	ring_count = adapter->num_txq;
	for (ring_index = 0; ring_index < ring_count; ring_index++) {
		rx_ring = adapter->rx_rings[ring_index];
		nbl_free_rx_ring_bufs(rx_ring);
	}
}

static void nbl_af_forward_ring_tx_map(struct nbl_adapter *adapter, struct nbl_ring *tx_ring,
				       struct sk_buff *skb, unsigned int dport,
				       unsigned int dport_id)
{
	struct nbl_tx_buf *first_buf;
	struct nbl_tx_desc *first_desc;
	struct nbl_tx_buf *tx_buf;
	struct nbl_tx_desc *tx_desc;
	unsigned int data_len;
	unsigned int size;
	dma_addr_t dma;
	const skb_frag_t *frag;
	u16 i;

	i = tx_ring->next_to_use;
	first_buf = NBL_TX_BUF(tx_ring, i);
	first_buf->skb = skb;
	first_buf->bytes = skb->len;
	first_buf->pkts = 1;

	first_desc = NBL_TX_DESC(tx_ring, i);
	first_desc->pkt_len = skb->len;
	first_desc->sop = 1;
	first_desc->fwd = NBL_FWD_CPU;
	first_desc->dport = dport;
	first_desc->dport_id = dport_id;

	tx_buf = first_buf;
	tx_desc = first_desc;

	data_len = skb->data_len;
	size = skb_headlen(skb);
	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (unlikely(dma_mapping_error(tx_ring->dev, dma))) {
			dev_warn(tx_ring->dev, "AF forward ring allocate DMA to transmit skb failed\n");
			goto dma_error;
		}

		tx_buf->dma = dma;
		tx_buf->len = size;

		tx_desc->buffer_addr = dma;
		tx_desc->dd = 0;
		while (unlikely(size > NBL_TXD_DATALEN_MAX)) {
			tx_desc->data_len = NBL_TXD_DATALEN_MAX;

			dma += NBL_TXD_DATALEN_MAX;
			size -= NBL_TXD_DATALEN_MAX;

			i++;
			tx_desc++;
			tx_ring->tail_ptr++;
			if (unlikely(i == tx_ring->desc_num)) {
				tx_desc = NBL_TX_DESC(tx_ring, 0);
				i = 0;
			}

			tx_desc->buffer_addr = dma;
			tx_desc->dd = 0;
		}

		tx_desc->data_len = size;

		if (likely(!data_len))
			break;

		i++;
		tx_desc++;
		tx_ring->tail_ptr++;
		if (unlikely(i == tx_ring->desc_num)) {
			tx_desc = NBL_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size, DMA_TO_DEVICE);
		tx_buf = NBL_TX_BUF(tx_ring, i);
	}

	tx_desc->eop = 1;
	/* Make sure descriptor has been written before write tail_ptr  */
	wmb();

	i++;
	tx_ring->tail_ptr++;
	if (unlikely(i == tx_ring->desc_num))
		i = 0;
	first_buf->next_to_watch = tx_desc;
	tx_ring->next_to_use = i;

	skb_tx_timestamp(skb);

	nbl_update_tail_ptr(tx_ring->notify_addr, tx_ring->local_qid, tx_ring->tail_ptr);

	return;

dma_error:
	for (;;) {
		tx_buf = NBL_TX_BUF(tx_ring, i);
		nbl_unmap_and_free_tx_resource(tx_ring, tx_buf, 0);
		if (tx_buf == first_buf)
			break;
		if (unlikely(!i))
			i = tx_ring->desc_num;
		i--;
		tx_ring->tail_ptr--;
	}
	first_desc->sop = 0;
}

static void nbl_af_forward_ring_xmit_frame(struct nbl_adapter *adapter, struct nbl_ring *tx_ring,
					   struct sk_buff *skb, unsigned int dport,
					   unsigned int dport_id)
{
	unsigned int count;

	count = nbl_xmit_desc_count(skb);
	if (unlikely(count > 8)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return;
		}
		count = nbl_xmit_desc_count(skb);
		tx_ring->tx_stats.tx_linearize++;
	}

	if (unlikely(nbl_unused_desc_count(tx_ring) < count)) {
		tx_ring->tx_stats.tx_busy++;
		dev_kfree_skb_any(skb);
		return;
	}

	nbl_af_forward_ring_tx_map(adapter, tx_ring, skb, dport, dport_id);
}

static void nbl_af_software_forward_eth_captured_packet(struct nbl_adapter *adapter,
							struct sk_buff *skb,
							unsigned int sport_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct sk_buff *new_skb;
	u8 txq_index;
	struct nbl_ring *tx_ring;
	struct nbl_func_res *func_res;
	unsigned int vf_vsi_id_start;
	unsigned int vf_vsi_id_end;
	unsigned int vsi_id;

	if (sport_id >= NBL_MAX_PF_FUNC) {
		pr_err("Receive captured packet from invalid ETH port id %u\n", sport_id);
		return;
	}

	txq_index = adapter->num_txq;
	tx_ring = adapter->tx_rings[txq_index];
	/* Forward captured packet to PF */
	func_res = af_res->res_record[sport_id];
	if (unlikely(!func_res)) {
		pr_err("Receive captured packet from ETH port, but there is no corresponding PF\n");
	} else {
		new_skb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!new_skb))
			pr_warn("There is no memory to copy captured packet for PF\n");
		else
			nbl_af_forward_ring_xmit_frame(adapter, tx_ring, new_skb,
						       NBL_TXD_DPORT_HOST, sport_id);
	}

	/* Forward captured packet to VFs */
	vf_vsi_id_start = NBL_MAX_PF_FUNC + sport_id * NBL_MAX_VF_PER_PF;
	vf_vsi_id_end = vf_vsi_id_start + NBL_MAX_VF_PER_PF;
	for (vsi_id = vf_vsi_id_start; vsi_id < vf_vsi_id_end; vsi_id++) {
		func_res = af_res->res_record[vsi_id];
		if (!func_res)
			break;
		new_skb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!new_skb))
			pr_warn("There is no memory to copy captured packet for VF\n");
		else
			nbl_af_forward_ring_xmit_frame(adapter, tx_ring, new_skb,
						       NBL_TXD_DPORT_HOST, vsi_id);
	}
}

static void nbl_af_software_forward_host_captured_packet(struct nbl_adapter *adapter,
							 struct sk_buff *skb,
							 unsigned int sport_id)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct sk_buff *new_skb;
	u8 txq_index;
	struct nbl_ring *tx_ring;
	struct nbl_func_res *func_res;
	unsigned int pf_vsi_id;
	unsigned int vf_vsi_id_start;
	unsigned int vf_vsi_id_end;
	unsigned int vsi_id;

	if (sport_id >= NBL_MAX_FUNC) {
		pr_err("Receive captured packet from invalid vsi port id %u\n", sport_id);
		return;
	}

	if (sport_id >= NBL_MAX_PF_FUNC)
		pf_vsi_id = (sport_id - NBL_MAX_PF_FUNC) / NBL_MAX_VF_PER_PF;
	else
		pf_vsi_id = sport_id;

	txq_index = adapter->num_txq;
	tx_ring = adapter->tx_rings[txq_index];
	/* Forward captured packet to ETH port */
	new_skb = skb_copy(skb, GFP_ATOMIC);
	if (unlikely(!new_skb))
		pr_warn("There is no memory to copy captured packet for ETH port\n");
	else
		nbl_af_forward_ring_xmit_frame(adapter, tx_ring, new_skb,
					       NBL_TXD_DPORT_ETH, pf_vsi_id);

	/* Forward captured packet to PF */
	func_res = af_res->res_record[pf_vsi_id];
	if (unlikely(!func_res)) {
		pr_err("Receive captured packet from ETH port, but there is no corresponding PF\n");
	} else if (pf_vsi_id != sport_id) {
		new_skb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!new_skb))
			pr_warn("There is no memory to copy captured packet for PF\n");
		else
			nbl_af_forward_ring_xmit_frame(adapter, tx_ring, new_skb,
						       NBL_TXD_DPORT_HOST, pf_vsi_id);
	}

	/* Forward captured packet to VFs */
	vf_vsi_id_start = NBL_MAX_PF_FUNC + pf_vsi_id * NBL_MAX_VF_PER_PF;
	vf_vsi_id_end = vf_vsi_id_start + NBL_MAX_VF_PER_PF;
	for (vsi_id = vf_vsi_id_start; vsi_id < vf_vsi_id_end; vsi_id++) {
		if (vsi_id == sport_id)
			continue;

		func_res = af_res->res_record[vsi_id];
		if (!func_res)
			break;
		new_skb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!new_skb))
			pr_warn("There is no memory to copy captured packet for VF\n");
		else
			nbl_af_forward_ring_xmit_frame(adapter, tx_ring, new_skb,
						       NBL_TXD_DPORT_HOST, vsi_id);
	}
}

static void nbl_af_software_forward_captured_packet(struct nbl_adapter *adapter,
						    struct sk_buff *skb,
						    unsigned int sport_type,
						    unsigned int sport_id)
{
	if (sport_type == NBL_RXD_SPORT_ETH)
		nbl_af_software_forward_eth_captured_packet(adapter, skb, sport_id);
	else
		nbl_af_software_forward_host_captured_packet(adapter, skb, sport_id);

	kfree_skb(skb);
}

int nbl_af_clean_forward_ring_rx_irq(struct nbl_ring *rx_ring, int budget)
{
	struct nbl_q_vector *q_vector = rx_ring->q_vector;
	struct nbl_adapter *adapter = q_vector->adapter;
	struct nbl_rx_desc *rx_desc;
	struct nbl_rx_buf *rx_buf;
	struct sk_buff *skb;
	unsigned int total_rx_pkts;
	unsigned int total_rx_bytes;
	u16 cleaned_count;
	u16 data_len;
	u16 buf_len;
	unsigned int fwd_mode;
	unsigned int sport_type;
	unsigned int sport_id;
	u16 sync_len;
	bool add_to_skb;
	u16 i;

	cleaned_count = nbl_unused_desc_count(rx_ring);
	if (cleaned_count >= NBL_RX_BUF_WRITE) {
		nbl_alloc_rx_bufs(rx_ring, cleaned_count);
		cleaned_count = 0;
	}

	skb = NULL;
	total_rx_pkts = 0;
	total_rx_bytes = 0;
	buf_len = (u16)rx_ring->buf_len;

	i = rx_ring->next_to_clean;
	rx_desc = NBL_RX_DESC(rx_ring, i);
	rx_buf = NBL_RX_BUF(rx_ring, i);
	if (!nbl_rx_desc_used(rx_desc))
		return total_rx_pkts;
	/* This memory barrier is needed to keep us from reading
	 * any other fields out of the rx_desc until we know the
	 * descriptor has been written back
	 */
	dma_rmb();
	data_len = rx_desc->data_len;
	fwd_mode = rx_desc->fwd;
	sport_type = rx_desc->sport;
	sport_id = rx_desc->sport_id;

	while (likely(total_rx_pkts < budget)) {
		sync_len = (data_len > buf_len) ? buf_len : data_len;
		add_to_skb = true;
		if (!skb)
			skb = nbl_construct_skb(rx_ring, rx_buf, rx_desc, sync_len, &add_to_skb);
		else
			nbl_add_rx_frag(rx_ring, rx_buf, skb, sync_len);

		if (unlikely(!skb)) {
			pr_warn("Allocate for RX packets failed\n");
			break;
		}

		nbl_put_rx_buf(rx_ring, rx_buf, rx_desc, add_to_skb);

		cleaned_count++;
		i++;
		rx_buf++;
		rx_desc++;
		if (i == rx_ring->desc_num) {
			i = 0;
			rx_buf = NBL_RX_BUF(rx_ring, 0);
			rx_desc = NBL_RX_DESC(rx_ring, 0);
		}
		data_len -= sync_len;
		if (data_len)
			continue;

		if (likely(!nbl_cleanup_headers(skb))) {
			if (unlikely(fwd_mode != NBL_RXD_FWD_CPU)) {
				pr_err("AF forwrad ring received non-captured packet\n");
				kfree_skb(skb);
			} else {
				total_rx_bytes += skb->len;
				nbl_af_software_forward_captured_packet(adapter, skb,
									sport_type, sport_id);
				total_rx_pkts++;
			}
		}

		skb = NULL;

		if (!nbl_rx_desc_used(rx_desc))
			break;

		dma_rmb();
		data_len = rx_desc->data_len;
		fwd_mode = rx_desc->fwd;
		sport_type = rx_desc->sport;
		sport_id = rx_desc->sport_id;
	}

	if (cleaned_count)
		nbl_alloc_rx_bufs(rx_ring, cleaned_count);

	rx_ring->next_to_clean = i;

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_pkts;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);

	return total_rx_pkts;
}

bool nbl_af_clean_forward_ring_tx_irq(struct nbl_ring *tx_ring, int napi_budget)
{
	struct nbl_tx_buf *tx_buf;
	struct nbl_tx_desc *tx_desc;
	unsigned int budget = NBL_DEFAULT_IRQ_WORK;
	unsigned int total_tx_pkts = 0;
	unsigned int total_tx_bytes = 0;
	s16 i = tx_ring->next_to_clean;

	tx_buf = NBL_TX_BUF(tx_ring, i);
	tx_desc = NBL_TX_DESC(tx_ring, i);
	i -= tx_ring->desc_num;
	do {
		struct nbl_tx_desc *end_desc = tx_buf->next_to_watch;

		if (!end_desc)
			break;

		/* ensure end_desc is read and checked first */
		smp_rmb();

		if (!nbl_tx_desc_used(tx_desc))
			break;

		total_tx_bytes += tx_buf->bytes;
		total_tx_pkts += tx_buf->pkts;
		while (true) {
			nbl_unmap_and_free_tx_resource(tx_ring, tx_buf, napi_budget);
			tx_desc->sop = 0;
			tx_desc->eop = 0;
			if (tx_desc == end_desc)
				break;
			i++;
			tx_buf++;
			tx_desc++;
			if (unlikely(!i)) {
				i -= tx_ring->desc_num;
				tx_buf = NBL_TX_BUF(tx_ring, 0);
				tx_desc = NBL_TX_DESC(tx_ring, 0);
			}
		}

		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->desc_num;
			tx_buf = NBL_TX_BUF(tx_ring, 0);
			tx_desc = NBL_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		budget--;
	} while (likely(budget));

	i += tx_ring->desc_num;

	tx_ring->next_to_clean = i;

	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_tx_bytes;
	tx_ring->stats.packets += total_tx_pkts;
	u64_stats_update_end(&tx_ring->syncp);

	return !!budget;
}

static void nbl_af_forward_ring_q_vector_fixup(struct nbl_adapter *adapter)
{
	struct nbl_q_vector *q_vector;
	u16 q_vector_id;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];
	netif_napi_del(&q_vector->napi);
	netif_napi_add(adapter->netdev, &q_vector->napi,
		       nbl_af_forward_ring_napi_poll, NAPI_POLL_WEIGHT);
}

static void nbl_af_map_forward_ring_to_vector(struct nbl_adapter *adapter)
{
	struct nbl_q_vector *q_vector;
	struct nbl_ring *ring;
	u16 txq_index = adapter->num_txq;
	u16 rxq_index = adapter->num_rxq;
	u16 q_vector_id = adapter->num_q_vectors;

	q_vector = adapter->q_vectors[q_vector_id];

	q_vector->num_ring_tx = 1;
	q_vector->tx_ring = NULL;
	ring = adapter->tx_rings[txq_index];
	ring->next = q_vector->tx_ring;
	ring->q_vector = q_vector;
	q_vector->tx_ring = ring;

	q_vector->num_ring_rx = 1;
	q_vector->rx_ring = NULL;
	ring = adapter->rx_rings[rxq_index];
	ring->next = q_vector->rx_ring;
	ring->q_vector = q_vector;
	q_vector->rx_ring = ring;
}

static int nbl_af_setup_forward_tx_ring(struct nbl_adapter *adapter)
{
	u16 txq_index = adapter->num_txq;
	struct nbl_ring *tx_ring;

	tx_ring = adapter->tx_rings[txq_index];

	return nbl_setup_tx_ring(tx_ring);
}

static void nbl_af_teardown_forward_tx_ring(struct nbl_adapter *adapter)
{
	u16 txq_index = adapter->num_txq;
	struct nbl_ring *tx_ring;

	tx_ring = adapter->tx_rings[txq_index];

	nbl_teardown_tx_ring(tx_ring);
}

static int nbl_af_setup_forward_rx_ring(struct nbl_adapter *adapter)
{
	u16 rxq_index = adapter->num_rxq;
	struct nbl_ring *rx_ring;

	rx_ring = adapter->rx_rings[rxq_index];

	return nbl_setup_rx_ring(rx_ring);
}

static void nbl_af_teardown_forward_rx_ring(struct nbl_adapter *adapter)
{
	u16 rxq_index = adapter->num_rxq;
	struct nbl_ring *rx_ring;

	rx_ring = adapter->rx_rings[rxq_index];

	nbl_teardown_rx_ring(rx_ring);
}

static int nbl_af_setup_forward_ring(struct nbl_adapter *adapter)
{
	int err;

	err = nbl_af_setup_forward_tx_ring(adapter);
	if (err) {
		pr_err("Setup AF forward tx ring failed with error %d\n", err);
		return err;
	}

	err = nbl_af_setup_forward_rx_ring(adapter);
	if (err) {
		pr_err("Setup AF forward rx ring failed with error %d\n", err);
		goto setup_forward_rx_ring_err;
	}

	return 0;

setup_forward_rx_ring_err:
	nbl_af_teardown_forward_tx_ring(adapter);
	return err;
}

static void nbl_af_teardown_forward_ring(struct nbl_adapter *adapter)
{
	nbl_af_teardown_forward_tx_ring(adapter);
	nbl_af_teardown_forward_rx_ring(adapter);
}

static void nbl_af_hw_config_forward_tx_ring(struct nbl_adapter *adapter)
{
	u16 txq_index = adapter->num_txq;
	struct nbl_ring *tx_ring;

	tx_ring = adapter->tx_rings[txq_index];

	nbl_hw_config_tx_ring(tx_ring);
}

static void nbl_af_hw_config_forward_rx_ring(struct nbl_adapter *adapter)
{
	u16 rxq_index = adapter->num_rxq;
	struct nbl_ring *rx_ring;

	rx_ring = adapter->rx_rings[rxq_index];

	nbl_hw_config_rx_ring(rx_ring);
}

static void nbl_af_hw_config_forward_ring(struct nbl_adapter *adapter)
{
	nbl_af_hw_config_forward_tx_ring(adapter);
	nbl_af_hw_config_forward_rx_ring(adapter);
}

static void nbl_af_forward_ring_alloc_all_rx_bufs(struct nbl_adapter *adapter)
{
	u16 rxq_index = adapter->num_rxq;
	struct nbl_ring *rx_ring;
	u16 desc_count;

	rx_ring = adapter->rx_rings[rxq_index];
	desc_count = nbl_unused_desc_count(rx_ring);
	if (unlikely(!nbl_alloc_rx_bufs(rx_ring, desc_count)))
		pr_warn("Allocate RX bufs for AF forward ring failed\n");
}

static void nbl_af_forward_ring_free_all_rx_bufs(struct nbl_adapter *adapter)
{
	u16 rxq_index = adapter->num_rxq;
	struct nbl_ring *rx_ring;

	rx_ring = adapter->rx_rings[rxq_index];
	nbl_free_rx_ring_bufs(rx_ring);
}

static void nbl_af_forward_ring_free_all_tx_bufs(struct nbl_adapter *adapter)
{
	u16 txq_index = adapter->num_txq;
	struct nbl_ring *tx_ring;

	tx_ring = adapter->tx_rings[txq_index];
	nbl_free_tx_ring_bufs(tx_ring);
}

static void nbl_af_start_forward_tx_ring(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *tx_ring;
	struct nbl_q_vector *q_vector;
	u16 local_vector_id;
	u8 ring_index;

	ring_index = adapter->num_txq;
	tx_ring = adapter->tx_rings[ring_index];
	q_vector = tx_ring->q_vector;
	local_vector_id = q_vector->q_vector_id;
	nbl_configure_port_map(hw, hw->eth_port_id, ring_index);
	nbl_configure_queue_map(hw, ring_index, false, local_vector_id, true);
	nbl_enable_tx_queue(hw, ring_index);
}

static void nbl_af_start_forward_rx_ring(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_ring *rx_ring;
	struct nbl_q_vector *q_vector;
	u16 local_vector_id;
	u8 ring_index;

	ring_index = adapter->num_txq;
	rx_ring = adapter->rx_rings[ring_index];
	q_vector = rx_ring->q_vector;
	local_vector_id = q_vector->q_vector_id;
	nbl_configure_queue_map(hw, ring_index, true, local_vector_id, true);
	nbl_enable_rx_queue(hw, ring_index);
}

static void nbl_af_stop_forward_tx_ring(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 ring_index;
	int err;

	ring_index = adapter->num_txq;
	nbl_disable_tx_queue(hw, ring_index);
	usleep_range(3000, 6000);
	nbl_configure_queue_map(hw, ring_index, false, 0, false);
	err = nbl_reset_tx_queue(hw, ring_index);
	if (unlikely(err))
		pr_err("Reset AF forward tx queue %hhu failed with error %d\n", ring_index, err);
	usleep_range(2000, 4000);
}

static void nbl_af_stop_forward_rx_ring(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 ring_index;
	int err;

	ring_index = adapter->num_txq;
	nbl_disable_rx_queue(hw, ring_index);
	usleep_range(3000, 6000);
	nbl_configure_queue_map(hw, ring_index, true, 0, false);
	err = nbl_reset_rx_queue(hw, ring_index);
	if (unlikely(err)) {
		pr_err("Reset AF forward rx queue %u failed with error %d\n", ring_index, err);
		return;
	}
	usleep_range(2000, 4000);
	err = nbl_wait_rx_queue_reset_done(hw, ring_index);
	if (unlikely(err))
		pr_err("Wait AF forward rx queue %hhu reset done failed with error %d\n",
		       ring_index, err);
}

static void nbl_af_register_forward_ring(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[0];
	u8 local_ring_index;
	u8 global_ring_index;

	local_ring_index = adapter->num_rxq;
	global_ring_index = func_res->txrx_queues[local_ring_index];
	af_res->forward_ring_index = global_ring_index;
}

int nbl_activate_af_forward_queue(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	int err;

	if (!is_af(hw))
		return 0;

	nbl_af_forward_ring_q_vector_fixup(adapter);

	nbl_af_map_forward_ring_to_vector(adapter);

	err = nbl_af_setup_forward_ring(adapter);
	if (err)
		return err;

	nbl_af_hw_config_forward_ring(adapter);

	nbl_af_forward_ring_alloc_all_rx_bufs(adapter);

	err = nbl_af_forward_ring_request_irq(adapter);
	if (err) {
		pr_err("AF forward ring requests irq failed with error %d\n", err);
		goto forward_ring_request_irq_err;
	}

	nbl_af_start_forward_tx_ring(adapter);
	nbl_af_start_forward_rx_ring(adapter);

	nbl_af_enable_forward_ring_napi(adapter);

	nbl_af_configure_forward_ring_irq(adapter);

	nbl_af_register_forward_ring(adapter);

	return 0;

forward_ring_request_irq_err:
	nbl_af_forward_ring_free_all_rx_bufs(adapter);
	nbl_af_teardown_forward_ring(adapter);
	return err;
}

void nbl_deactivate_af_forward_queue(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;

	if (!is_af(hw))
		return;

	nbl_af_clear_forward_ring_irq_conf(adapter);

	nbl_af_disable_forward_ring_napi(adapter);

	nbl_af_stop_forward_tx_ring(adapter);
	nbl_af_stop_forward_rx_ring(adapter);

	nbl_af_forward_ring_free_irq(adapter);

	nbl_af_forward_ring_free_all_tx_bufs(adapter);
	nbl_af_forward_ring_free_all_rx_bufs(adapter);

	nbl_af_teardown_forward_ring(adapter);
}
