// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include "rnpgbe.h"
#include "rnpgbe_sriov.h"
#include "rnpgbe_common.h"

/**
 * rnpgbe_cache_ring_sriov - Descriptor ring to register mapping for sriov
 * @adapter: board private structure to initialize
 *
 * SR-IOV doesn't use any descriptor rings but changes the default if
 * no other mapping is used.
 *
 */
static bool rnpgbe_cache_ring_sriov(struct rnpgbe_adapter *adapter)
{
	/* only proceed if VMDq is enabled */
	if (!(adapter->flags & RNP_FLAG_VMDQ_ENABLED))
		return false;
	return true;
}

/**
 * rnpgbe_cache_ring_rss - Descriptor ring to register mapping for RSS
 * @adapter: board private structure to initialize
 *
 * Cache the descriptor ring offsets for RSS to the assigned rings.
 *
 **/
static bool rnpgbe_cache_ring_rss(struct rnpgbe_adapter *adapter)
{
	struct rnpgbe_hw *hw = &adapter->hw;
	struct rnpgbe_dma_info *dma = &hw->dma;
	struct rnpgbe_ring *ring;
	int ring_step = 1;
	int i;

	/* some ring alloc rules can be added here */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->tx_ring[i];
		ring->rnpgbe_queue_idx = i * ring_step;
		ring->ring_addr = dma->dma_ring_addr +
				  RING_OFFSET(ring->rnpgbe_queue_idx);

		ring->dma_int_stat = ring->ring_addr + RNP_DMA_INT_STAT;
		ring->dma_int_mask = ring->ring_addr + RNP_DMA_INT_MASK;
		ring->dma_int_clr = ring->ring_addr + RNP_DMA_INT_CLR;
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->rx_ring[i];
		ring->rnpgbe_queue_idx = i * ring_step;
		ring->ring_addr = dma->dma_ring_addr +
				  RING_OFFSET(ring->rnpgbe_queue_idx);
		ring->dma_int_stat = ring->ring_addr + RNP_DMA_INT_STAT;
		ring->dma_int_mask = ring->ring_addr + RNP_DMA_INT_MASK;
		ring->dma_int_clr = ring->ring_addr + RNP_DMA_INT_CLR;
	}

	return true;
}

/**
 * rnpgbe_cache_ring_register - Descriptor ring to register mapping
 * @adapter: board private structure to initialize
 *
 * Once we know the feature-set enabled for the device, we'll cache
 * the register offset the descriptor ring is assigned to.
 *
 * Note, the order the various feature calls is important.  It must start with
 * the "most" features enabled at the same time, then trickle down to the
 * least amount of features turned on at once.
 **/
static void rnpgbe_cache_ring_register(struct rnpgbe_adapter *adapter)
{
	/* sriov ring alloc is added before, this maybe no use */
	if (rnpgbe_cache_ring_sriov(adapter))
		return;

	rnpgbe_cache_ring_rss(adapter);
}

#define RNP_RSS_8Q_MASK 0x7
#define RNP_RSS_DISABLED_MASK 0x0

/**
 * rnpgbe_set_sriov_queues - Allocate queues for SR-IOV devices
 * @adapter: board private structure to initialize
 *
 * When SR-IOV (Single Root IO Virtualiztion) is enabled, allocate queues
 * and VM pools where appropriate.  If RSS is available, then also try and
 * enable RSS and map accordingly.
 *
 **/
static bool rnpgbe_set_sriov_queues(struct rnpgbe_adapter *adapter)
{
	u16 rss_i = adapter->ring_feature[RING_F_RSS].limit;
	struct rnpgbe_hw *hw = &adapter->hw;
	u16 rss_m = RNP_RSS_DISABLED_MASK;
	u16 vmdq_m = 0;

	/* only proceed if SR-IOV is enabled */
	if (!(adapter->flags & RNP_FLAG_SRIOV_ENABLED))
		return false;

	/* save features for later use */
	adapter->ring_feature[RING_F_VMDQ].indices =
		adapter->max_ring_pair_counts - 1;
	adapter->ring_feature[RING_F_VMDQ].mask = vmdq_m;

	/* limit RSS based on user input and save for later use */
	adapter->ring_feature[RING_F_RSS].indices = rss_i;
	adapter->ring_feature[RING_F_RSS].mask = rss_m;
	adapter->num_rx_queues = hw->sriov_ring_limit;
	adapter->num_tx_queues = hw->sriov_ring_limit;
	/* disable ATR as it is not supported when VMDq is enabled */
	adapter->flags &= ~RNP_FLAG_FDIR_HASH_CAPABLE;

	return true;
}

/**
 * rnpgbe_rss_indir_tbl_entries - return indir_tlb_entries
 * @adapter: board private structure to initialize
 *
 */
u32 rnpgbe_rss_indir_tbl_entries(struct rnpgbe_adapter *adapter)
{
	if (adapter->hw.rss_type == rnpgbe_rss_n500)
		return 128;
	else
		return 128;
}

/**
 * rnpgbe_set_rss_queues - Allocate queues for RSS
 * @adapter: board private structure to initialize
 *
 * This is our "base" multiqueue mode.  RSS (Receive Side Scaling) will try
 * to allocate one Rx queue per CPU, and if available, one Tx queue per CPU.
 *
 **/
static bool rnpgbe_set_rss_queues(struct rnpgbe_adapter *adapter)
{
	struct rnpgbe_ring_feature *f;
	u16 rss_i;

	f = &adapter->ring_feature[RING_F_RSS];
	/* use this to change ring num */
	rss_i = f->limit;
	/* set limit -> indices */
	f->indices = rss_i;

	/* should init rss mask */
	switch (adapter->hw.rss_type) {
		/* maybe not good */
	case rnpgbe_rss_n500:
		f->mask = RNP_RSS_8Q_MASK;
		break;
	default:
		f->mask = 0;

		break;
	}

	/* set rss_i -> adapter->num_tx_queues */
	/* should not more than irq */
	adapter->num_tx_queues =
		min_t(int, rss_i, adapter->max_ring_pair_counts);
	adapter->num_rx_queues = adapter->num_tx_queues;

	rnpgbe_dbg("[%s] limit:%d indices:%d queues:%d\n", adapter->name,
		   f->limit, f->indices, adapter->num_tx_queues);

	return true;
}

/**
 * rnpgbe_set_num_queues - Allocate queues for device, feature dependent
 * @adapter: board private structure to initialize
 *
 * This is the top level queue allocation routine.  The order here is very
 * important, starting with the "most" number of features turned on at once,
 * and ending with the smallest set of features.  This way large combinations
 * can be allocated if they're turned on.
 *
 **/
static void rnpgbe_set_num_queues(struct rnpgbe_adapter *adapter)
{
	/* Start with base case */
	adapter->num_tx_queues = 1;
	adapter->num_rx_queues = 1;

	if (rnpgbe_set_sriov_queues(adapter))
		return;
	/* at last we support rss */
	rnpgbe_set_rss_queues(adapter);
}

static int rnpgbe_acquire_msix_vectors(struct rnpgbe_adapter *adapter,
				       int vectors)
{
	int err;

	err = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
				    vectors, vectors);
	if (err < 0) {
		rnpgbe_err("pci_enable_msix failed: req:%d err:%d\n", vectors,
			   err);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
		return -EINVAL;
	}
	/*
	 * Adjust for only the vectors we'll use, which is minimum
	 * of max_msix_q_vectors + NON_Q_VECTORS, or the number of
	 * vectors we were allocated.
	 */
	vectors -= adapter->num_other_vectors;
	adapter->num_q_vectors = min(vectors, adapter->max_q_vectors);

	return 0;
}

static void rnpgbe_add_ring(struct rnpgbe_ring *ring,
			    struct rnpgbe_ring_container *head)
{
	ring->next = head->ring;
	head->ring = ring;
	head->count++;
}

/*
 * get cpu with specified node and index
 * return CPU index on success, return -1 on failure.
 */
static int rnpgbe_get_cpu_on_node(int node, int index, unsigned int offset)
{
	int cpu_count = 0;
	int target;
	int cpu;

	if (node == NUMA_NO_NODE || node < 0)
		return -1;

	for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask)
		cpu_count++;

	if (cpu_count == 0)
		return -1;

	target = (offset + index) % cpu_count;

	for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask) {
		if (target-- == 0)
			return cpu;
	}

	return -1;
}

/**
 * rnpgbe_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @eth_queue_idx: queue_index idx for this q_vector
 * @v_idx: index of vector used for this q_vector
 * @r_idx: total number of Tx rings to allocate
 * @r_count: ring count
 * @step: ring step
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 **/
static int rnpgbe_alloc_q_vector(struct rnpgbe_adapter *adapter,
				 int eth_queue_idx, int v_idx, int r_idx,
				 int r_count, int step)
{
	struct rnpgbe_hw *hw = &adapter->hw;
	struct rnpgbe_dma_info *dma = &hw->dma;
	int rxr_idx = r_idx, txr_idx = r_idx;
	struct rnpgbe_q_vector *q_vector;
	int txr_count, rxr_count, idx;
	struct rnpgbe_ring *ring;
	int node = NUMA_NO_NODE;
	int ring_count, size;
	int cpu_offset = 0;
	int cpu = -1;
	struct device *dev = &adapter->pdev->dev;
	int orig_node = dev_to_node(dev);
	int queue_index = v_idx - adapter->q_vector_off;

	DPRINTK(PROBE, INFO,
		"eth_queue_idx:%d v_idx:%d(off:%d) ring:%d ring_cnt:%d, step:%d\n",
		eth_queue_idx, v_idx, adapter->q_vector_off, r_idx, r_count,
		step);

	txr_count = r_count;
	rxr_count = r_count;

	ring_count = txr_count + rxr_count;
	size = sizeof(struct rnpgbe_q_vector) +
	       (sizeof(struct rnpgbe_ring) * ring_count);

	/* Find the first online CPU on the same NUMA node as the NIC.
	 * Then assign q_vectors to CPUs on this node in a round-robin fashion.
	 */
	cpu = rnpgbe_get_cpu_on_node(orig_node, queue_index, cpu_offset);
	if (cpu >= 0) {
		node = orig_node;
		pr_debug("RNPGBE: q_vector[%d] attached to CPU %d on NUMA node %d\n",
			 v_idx, cpu, node);
	} else {
		pr_warn("RNPGBE: WARNING: No online CPUs on NIC's NUMA node %d!\n",
			orig_node);
		cpu = -1;
		node = NUMA_NO_NODE;
	}

	/* allocate q_vector and rings */
	q_vector = kzalloc_node(size, GFP_KERNEL, node);
	if (!q_vector)
		q_vector = kzalloc(size, GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	/* setup affinity mask and node */
	if (cpu != -1)
		cpumask_set_cpu(cpu, &q_vector->affinity_mask);
	q_vector->numa_node = node;

	netif_napi_add_weight(adapter->netdev, &q_vector->napi, rnpgbe_poll,
			      adapter->napi_budge);
	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx - adapter->q_vector_off] = q_vector;
	q_vector->adapter = adapter;
	q_vector->v_idx = v_idx;

	/* initialize work limits */
	q_vector->tx.work_limit = adapter->tx_work_limit;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	for (idx = 0; idx < txr_count; idx++) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		rnpgbe_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_item_count;
		ring->queue_index = eth_queue_idx + idx;
		/* rnpgbe_queue_idx can be changed after */
		/* it is used to location hw reg */
		ring->rnpgbe_queue_idx = txr_idx;
		ring->ring_addr = dma->dma_ring_addr + RING_OFFSET(txr_idx);
		ring->dma_int_stat = ring->ring_addr + RNP_DMA_INT_STAT;
		ring->dma_int_mask = ring->ring_addr + RNP_DMA_INT_MASK;
		ring->dma_int_clr = ring->ring_addr + RNP_DMA_INT_CLR;
		ring->device_id = adapter->pdev->device;
		ring->pfvfnum = hw->pfvfnum;
		/* not support tunnel */
		ring->ring_flags |= RNP_RING_NO_TUNNEL_SUPPORT;
		/* assign ring to adapter */
		adapter->tx_ring[ring->queue_index] = ring;

		/* update count and index */
		txr_idx += step;

		rnpgbe_dbg("\t\t%s:vector[%d] <--RNP TxRing:%d, eth_queue:%d\n",
			   adapter->name, v_idx, ring->rnpgbe_queue_idx,
			   ring->queue_index);

		/* push pointer to next ring */
		ring++;
	}

	for (idx = 0; idx < rxr_count; idx++) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		rnpgbe_add_ring(ring, &q_vector->rx);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_item_count;
		/* rnpgbe_queue_idx can be changed after */
		/* it is used to location hw reg */
		ring->queue_index = eth_queue_idx + idx;
		ring->rnpgbe_queue_idx = rxr_idx;
		ring->ring_addr = dma->dma_ring_addr + RING_OFFSET(rxr_idx);
		ring->dma_int_stat = ring->ring_addr + RNP_DMA_INT_STAT;
		ring->dma_int_mask = ring->ring_addr + RNP_DMA_INT_MASK;
		ring->dma_int_clr = ring->ring_addr + RNP_DMA_INT_CLR;
		ring->device_id = adapter->pdev->device;
		ring->pfvfnum = hw->pfvfnum;

		ring->ring_flags |= RNP_RING_NO_TUNNEL_SUPPORT;
		ring->ring_flags |= RNP_RING_STAGS_SUPPORT;

		/* assign ring to adapter */
		adapter->rx_ring[ring->queue_index] = ring;
		rnpgbe_dbg("\t\t%s:vector[%d] <--RNP RxRing:%d, eth_queue:%d\n",
			   adapter->name, v_idx, ring->rnpgbe_queue_idx,
			   ring->queue_index);

		/* update count and index */
		rxr_idx += step;

		/* push pointer to next ring */
		ring++;
	}

	q_vector->vector_flags |= RNP_QVECTOR_FLAG_ITR_FEATURE;
	q_vector->new_rx_count = adapter->rx_frames;
	q_vector->old_rx_count = adapter->rx_frames;
	q_vector->itr_rx = adapter->rx_usecs;
	q_vector->rx.itr = adapter->rx_usecs;

	return 0;
}

/**
 * rnpgbe_free_q_vector - Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: Index of vector to be freed
 *
 * This function frees the memory allocated to the q_vector.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void rnpgbe_free_q_vector(struct rnpgbe_adapter *adapter, int v_idx)
{
	struct rnpgbe_q_vector *q_vector = adapter->q_vector[v_idx];
	struct rnpgbe_ring *ring;

	rnpgbe_dbg("v_idx:%d\n", v_idx);

	rnpgbe_for_each_ring(ring, q_vector->tx)
		adapter->tx_ring[ring->queue_index] = NULL;

	rnpgbe_for_each_ring(ring, q_vector->rx)
		adapter->rx_ring[ring->queue_index] = NULL;

	adapter->q_vector[v_idx] = NULL;
	netif_napi_del(&q_vector->napi);

	if (q_vector->vector_flags & RNP_QVECTOR_FLAG_IRQ_MISS_CHECK)
		hrtimer_cancel(&q_vector->irq_miss_check_timer);

	/*
	 * rnpgbe_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	kfree_rcu(q_vector, rcu);
}

/**
 * rnpgbe_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int rnpgbe_alloc_q_vectors(struct rnpgbe_adapter *adapter)
{
	int r_remaing =
		min_t(int, adapter->num_tx_queues, adapter->num_rx_queues);
	int err, ring_cnt, v_remaing = adapter->num_q_vectors;
	struct rnpgbe_hw *hw = &adapter->hw;
	int v_idx = adapter->q_vector_off;
	int q_vector_nums = 0;
	int ring_step = 1;
	int ring_idx = 0;

	if (adapter->flags & RNP_FLAG_SRIOV_ENABLED) {
		ring_idx = 0;
		/* only 2 rings when sriov enabled */
		/* from back */
		if (hw->feature_flags & RNP_NET_FEATURE_VF_FIXED) {
			// this mode pf use vf 0 ring
			ring_idx = 0;
			r_remaing = hw->sriov_ring_limit;

		} else {
			ring_idx = adapter->max_ring_pair_counts -
				   ring_step * hw->sriov_ring_limit;
			r_remaing = hw->sriov_ring_limit;
		}
	}

	adapter->eth_queue_idx = 0;
	BUG_ON(adapter->num_q_vectors == 0);

	rnpgbe_dbg("r_remaing:%d, ring_step:%d num_q_vectors:%d\n", r_remaing,
		   ring_step, v_remaing);

	/* can support multi rings in one q_vector */
	for (; r_remaing > 0 && v_remaing > 0; v_remaing--) {
		ring_cnt = DIV_ROUND_UP(r_remaing, v_remaing);

		err = rnpgbe_alloc_q_vector(adapter, adapter->eth_queue_idx,
					    v_idx, ring_idx, ring_cnt,
					    ring_step);
		if (err)
			goto err_out;
		ring_idx += ring_step * ring_cnt;
		r_remaing -= ring_cnt;
		v_idx++;
		q_vector_nums++;
		adapter->eth_queue_idx += ring_cnt;
	}
	/* should fix the real used q_vectors_nums */
	adapter->num_q_vectors = q_vector_nums;

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		rnpgbe_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

/**
 * rnpgbe_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void rnpgbe_free_q_vectors(struct rnpgbe_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	adapter->num_rx_queues = 0;
	adapter->num_tx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		rnpgbe_free_q_vector(adapter, v_idx);
}

static void rnpgbe_reset_interrupt_capability(struct rnpgbe_adapter *adapter)
{
	if (adapter->flags & RNP_FLAG_MSIX_ENABLED)
		pci_disable_msix(adapter->pdev);
	else if (adapter->flags & RNP_FLAG_MSI_CAPABLE)
		pci_disable_msi(adapter->pdev);

	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	adapter->q_vector_off = 0;

	/* first clean msix flags */
	adapter->flags &= (~RNP_FLAG_MSIX_ENABLED);
	adapter->flags &= (~RNP_FLAG_MSI_ENABLED);
}

/**
 * rnpgbe_set_interrupt_capability - set MSI-X or MSI if supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 **/
static int rnpgbe_set_interrupt_capability(struct rnpgbe_adapter *adapter)
{
	int irq_mode_back = adapter->irq_mode;
	struct rnpgbe_hw *hw = &adapter->hw;
	int vector, v_budget, err = 0;

	v_budget = min_t(int, adapter->num_tx_queues, adapter->num_rx_queues);

	/* in one ring mode should reset v_budget */
	v_budget = min_t(int, v_budget, num_online_cpus());
	v_budget += adapter->num_other_vectors;

	v_budget = min_t(int, v_budget, hw->mac.max_msix_vectors);

	if (adapter->irq_mode == irq_mode_msix) {
		adapter->msix_entries = kcalloc(v_budget, sizeof(struct msix_entry), GFP_KERNEL);

		if (!adapter->msix_entries)
			return -EINVAL;

		for (vector = 0; vector < v_budget; vector++)
			adapter->msix_entries[vector].entry = vector;

		err = rnpgbe_acquire_msix_vectors(adapter, v_budget);
		if (!err) {
			if (adapter->num_other_vectors)
				adapter->q_vector_off = 1;
			rnpgbe_dbg("adapter%d alloc vectors: cnt:%d [%d~%d] num_q_vectors:%d\n",
				   adapter->bd_number, v_budget,
				   adapter->q_vector_off,
				   adapter->q_vector_off + v_budget - 1,
				   adapter->num_q_vectors);
			adapter->flags |= RNP_FLAG_MSIX_ENABLED;

			goto out;
		}
		/* if has msi capability try it */
		if (adapter->flags & RNP_FLAG_MSI_CAPABLE)
			adapter->irq_mode = irq_mode_msi;
		kfree(adapter->msix_entries);
		pr_info("acquire msix failed, try to use msi\n");
	} else {
		rnpgbe_dbg("adapter%d not in msix mode\n", adapter->bd_number);
	}
	/* if has msi capability or set irq_mode */
	if (adapter->irq_mode == irq_mode_msi) {
		err = pci_enable_msi(adapter->pdev);
		if (err) {
			pr_info("Failed to allocate MSI interrupt, falling back to legacy. Error");
		} else {
			/* msi mode use only 1 irq */
			adapter->flags |= RNP_FLAG_MSI_ENABLED;
		}
	}
	/* write back origin irq_mode */
	adapter->irq_mode = irq_mode_back;
	/* legacy and msi only 1 vectors */
	adapter->num_q_vectors = 1;
	err = 0;

out:
	return err;
}

static void rnpgbe_print_ring_info(struct rnpgbe_adapter *adapter)
{
	struct rnpgbe_q_vector *q_vector;
	struct rnpgbe_ring *ring;
	int i;

	rnpgbe_dbg("tx_queue count %d\n", adapter->num_tx_queues);
	rnpgbe_dbg("queue-mapping :\n");
	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		rnpgbe_dbg(" queue %d , physical ring %d\n", i,
			   ring->rnpgbe_queue_idx);
	}
	rnpgbe_dbg("rx_queue count %d\n", adapter->num_rx_queues);
	rnpgbe_dbg("queue-mapping :\n");
	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		rnpgbe_dbg(" queue %d , physical ring %d\n", i,
			   ring->rnpgbe_queue_idx);
	}
	rnpgbe_dbg("q_vector count %d\n", adapter->num_q_vectors);
	rnpgbe_dbg("vector-queue mapping:\n");
	for (i = 0; i < adapter->num_q_vectors; i++) {
		q_vector = adapter->q_vector[i];
		rnpgbe_dbg("vector %d\n", i);
		rnpgbe_for_each_ring(ring, q_vector->tx) {
			rnpgbe_dbg(" tx physical ring %d\n",
				   ring->rnpgbe_queue_idx);
		}
		rnpgbe_for_each_ring(ring, q_vector->rx) {
			rnpgbe_dbg(" rx physical ring %d\n",
				   ring->rnpgbe_queue_idx);
		}
	}
}

static void update_ring_count(struct rnpgbe_adapter *adapter)
{
	if (adapter->flags2 & RNP_FLAG2_INSMOD)
		return;

	adapter->flags2 |= RNP_FLAG2_INSMOD;

	/* limit ring count if in msi or legacy mode */
	if (!(adapter->flags & RNP_FLAG_MSIX_ENABLED)) {
		adapter->num_tx_queues = 1;
		adapter->num_rx_queues = 1;
		adapter->ring_feature[RING_F_RSS].limit = 1;
		adapter->ring_feature[RING_F_FDIR].limit = 1;
		adapter->ring_feature[RING_F_RSS].indices = 1;
	}
}

/**
 * rnpgbe_init_interrupt_scheme - Determine proper interrupt scheme
 * @adapter: board private structure to initialize
 *
 * We determine which interrupt scheme to use based on...
 * - Hardware queue count (num_*_queues)
 *   - defined by miscellaneous hardware support/features (RSS, etc.)
 **/
int rnpgbe_init_interrupt_scheme(struct rnpgbe_adapter *adapter)
{
	int err;

	/* Number of supported queues */
	rnpgbe_set_num_queues(adapter);

	/* Set interrupt mode */
	err = rnpgbe_set_interrupt_capability(adapter);
	if (err) {
		e_dev_err("Unable to get interrupt\n");
		goto err_set_interrupt;
	}
	/* update ring num only init */
	update_ring_count(adapter);

	err = rnpgbe_alloc_q_vectors(adapter);
	if (err) {
		e_dev_err("Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}
	rnpgbe_cache_ring_register(adapter);

	DPRINTK(PROBE, INFO,
		"Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n\n",
		(adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
		adapter->num_rx_queues, adapter->num_tx_queues);
	rnpgbe_print_ring_info(adapter);

	set_bit(__RNP_DOWN, &adapter->state);

	return 0;

err_alloc_q_vectors:
	rnpgbe_reset_interrupt_capability(adapter);
err_set_interrupt:;
	return err;
}

/**
 * rnpgbe_clear_interrupt_scheme - Clear the current interrupt scheme settings
 * @adapter: board private structure to clear interrupt scheme on
 *
 * We go through and clear interrupt specific resources and reset the structure
 * to pre-load conditions
 **/
void rnpgbe_clear_interrupt_scheme(struct rnpgbe_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	rnpgbe_free_q_vectors(adapter);
	rnpgbe_reset_interrupt_capability(adapter);
}

/**
 * rnpgbe_tx_ctxtdesc - Send a control desc to hw
 * @tx_ring: target ring of this control desc
 * @mss_len_vf_num: mss vf num
 * @inner_vlan_tunnel_len: inner vlan length
 * @ignore_vlan: ignore vlan flags
 * @crc_pad: crc pad or not
 *
 **/
static void rnpgbe_tx_ctxtdesc(struct rnpgbe_ring *tx_ring,
			       u32 mss_len_vf_num,
			       u32 inner_vlan_tunnel_len,
			       int ignore_vlan,
			       bool crc_pad)
{
	struct rnpgbe_adapter *adapter = RING2ADAPT(tx_ring);
	struct rnpgbe_tx_ctx_desc *context_desc;
	u16 i = tx_ring->next_to_use;
	u32 type_tucmd = 0;

	context_desc = RNP_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* set bits to identify this as an advanced context descriptor */
	type_tucmd |= RNP_TXD_CTX_CTRL_DESC;

	/* set mac padding status if set priv_flags */
	if (adapter->priv_flags & RNP_PRIV_FLAG_TX_PADDING) {
		if (!crc_pad)
			type_tucmd |= RNP_TXD_MTI_CRC_PAD_CTRL;
	}

#define VLAN_MASK (0x0000ffff)
#define VLAN_INSERT (0x00800000)
	if (inner_vlan_tunnel_len & VLAN_MASK)
		type_tucmd |= VLAN_INSERT;

	context_desc->mss_len_vf_num = cpu_to_le32(mss_len_vf_num);
	context_desc->inner_vlan_tunnel_len =
		cpu_to_le32(inner_vlan_tunnel_len);
	context_desc->resv_cmd = cpu_to_le32(type_tucmd);
	context_desc->resv = 0;
	if (tx_ring->q_vector->adapter->flags & RNP_FLAG_SRIOV_ENABLED) {
		if (ignore_vlan)
			context_desc->inner_vlan_tunnel_len |=
				cpu_to_le32(VF_VEB_IGNORE_VLAN);
	}
	buf_dump_line("ctx  ", __LINE__, context_desc, sizeof(*context_desc));
}

void rnpgbe_maybe_tx_ctxtdesc(struct rnpgbe_ring *tx_ring,
			      struct rnpgbe_tx_buffer *first, u32 ignore_vlan)
{
	/* sriov mode pf use the last vf */
	if (first->ctx_flag) {
		rnpgbe_tx_ctxtdesc(tx_ring, first->mss_len_vf_num,
				   first->inner_vlan_tunnel_len, ignore_vlan,
				   first->gso_need_padding);
	}
}

void rnpgbe_store_reta(struct rnpgbe_adapter *adapter)
{
	u32 i, reta_entries = rnpgbe_rss_indir_tbl_entries(adapter);
	struct rnpgbe_hw *hw = &adapter->hw;
	struct rnpgbe_ring *rx_ring;
	u32 reta = 0;

	/* Write redirection table to HW */
	for (i = 0; i < reta_entries; i++) {
		if (adapter->flags & RNP_FLAG_SRIOV_ENABLED) {
			reta = adapter->rss_indir_tbl[i];
		} else {
			rx_ring = adapter->rx_ring[adapter->rss_indir_tbl[i]];
			reta = rx_ring->rnpgbe_queue_idx;
		}
		hw->rss_indir_tbl[i] = reta;
	}
	hw->ops.set_rss_table(hw);
}

void rnpgbe_store_key(struct rnpgbe_adapter *adapter)
{
	bool sriov_flag = !!(adapter->flags & RNP_FLAG_SRIOV_ENABLED);
	struct rnpgbe_hw *hw = &adapter->hw;

	hw->ops.set_rss_key(hw, sriov_flag);
}

int rnpgbe_init_rss_key(struct rnpgbe_adapter *adapter)
{
	bool sriov_flag = !!(adapter->flags & RNP_FLAG_SRIOV_ENABLED);
	struct rnpgbe_hw *hw = &adapter->hw;

	/* only init rss key once */
	/* no change rss key if user input one */
	if (!adapter->rss_key_setup_flag) {
		netdev_rss_key_fill(adapter->rss_key, RNP_RSS_KEY_SIZE);
		adapter->rss_key_setup_flag = 1;
	}
	hw->ops.set_rss_key(hw, sriov_flag);

	return 0;
}

int rnpgbe_init_rss_table(struct rnpgbe_adapter *adapter)
{
	u32 reta_entries = rnpgbe_rss_indir_tbl_entries(adapter);
	int rx_nums = adapter->num_rx_queues;
	struct rnpgbe_hw *hw = &adapter->hw;
	struct rnpgbe_ring *rx_ring;
	u32 reta = 0;
	int i, j;

	for (i = 0, j = 0; i < 8; i++) {
		hw->rss_tc_tbl[i] = 0;
		adapter->rss_tc_tbl[i] = 0;
	}

	/* adapter->num_q_vectors is not correct */
	for (i = 0, j = 0; i < reta_entries; i++) {
		/* init with default value */
		if (!adapter->rss_tbl_setup_flag)
			adapter->rss_indir_tbl[i] = j;

		if (adapter->flags & RNP_FLAG_SRIOV_ENABLED) {
			/* in sriov mode reta in [0, rx_nums] */
			reta = j;
		} else {
			/* in no sriov, reta is real ring number */
			rx_ring = adapter->rx_ring[adapter->rss_indir_tbl[i]];
			reta = rx_ring->rnpgbe_queue_idx;
		}
		/* store rss_indir_tbl */
		hw->rss_indir_tbl[i] = reta;

		j = (j + 1) % rx_nums;
	}
	/* tbl only init once */
	adapter->rss_tbl_setup_flag = 1;
	hw->ops.set_rss_table(hw);
	return 0;
}

/* setup to the hw  */
s32 rnpgbe_fdir_write_perfect_filter(int fdir_mode, struct rnpgbe_hw *hw,
				     union rnpgbe_atr_input *filter, u16 hw_id,
				     u8 queue, bool prio_flag)
{
	if (filter->formatted.flow_type == RNP_ATR_FLOW_TYPE_ETHER) {
		hw->ops.set_layer2_remapping(hw, filter, hw_id, queue,
					     prio_flag);
	} else {
		hw->ops.set_tuple5_remapping(hw, filter, hw_id, queue,
					     prio_flag);
	}

	return 0;
}

s32 rnpgbe_fdir_erase_perfect_filter(int fdir_mode, struct rnpgbe_hw *hw,
				     union rnpgbe_atr_input *input, u16 pri_id)
{
	/* just disable filter */
	if (input->formatted.flow_type == RNP_ATR_FLOW_TYPE_ETHER)
		hw->ops.clr_layer2_remapping(hw, pri_id);
	else
		hw->ops.clr_tuple5_remapping(hw, pri_id);

	return 0;
}
