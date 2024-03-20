// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */
#include "rnpm.h"
#include "rnpm_sriov.h"
#include "rnpm_common.h"

#ifdef CONFIG_RNPM_DCB
/**
 * rnpm_cache_ring_dcb_sriov - Descriptor ring to register mapping for SR-IOV
 * @adapter: board private structure to initialize
 *
 * Cache the descriptor ring offsets for SR-IOV to the assigned rings.  It
 * will also try to cache the proper offsets if RSS/FCoE are enabled along
 * with VMDq.
 *
 **/
static bool rnpm_cache_ring_dcb_sriov(struct rnpm_adapter *adapter)
{
	struct rnpm_ring_feature *vmdq = &adapter->ring_feature[RING_F_VMDQ];
	int i;
	u8 tcs = netdev_get_num_tc(adapter->netdev);

	/* verify we have DCB queueing enabled before proceeding */
	if (tcs <= 1)
		return false;

	/* verify we have VMDq enabled before proceeding */
	if (!(adapter->flags & RNPM_FLAG_SRIOV_ENABLED))
		return false;

	return true;
}

/* rnpm_get_first_reg_idx - Return first register index associated with ring */
static void rnpm_get_first_reg_idx(struct rnpm_adapter *adapter, u8 tc,
				   unsigned int *tx, unsigned int *rx)
{
	struct net_device *dev = adapter->netdev;
	struct rnpm_hw *hw = &adapter->hw;
	u8 num_tcs = netdev_get_num_tc(dev);

	*tx = 0;
	*rx = 0;

	switch (hw->mac.type) {
	case rnpm_mac_82598EB:
		/* TxQs/TC: 4	RxQs/TC: 8 */
		*tx = tc << 2; /* 0, 4,  8, 12, 16, 20, 24, 28 */
		*rx = tc << 3; /* 0, 8, 16, 24, 32, 40, 48, 56 */
		break;
	case rnpm_mac_n10EB:
	case rnpm_mac_X540:
		if (num_tcs > 4) {
			/* TCs    : TC0/1 TC2/3 TC4-7
			 * TxQs/TC:    32    16     8
			 * RxQs/TC:    16    16    16
			 */
			*rx = tc << 4;
			if (tc < 3)
				*tx = tc << 5; /*   0,  32,  64 */
			else if (tc < 5)
				*tx = (tc + 2) << 4; /*  80,  96 */
			else
				*tx = (tc + 8) << 3; /* 104, 112, 120 */
		} else {
			/* TCs    : TC0 TC1 TC2/3
			 * TxQs/TC:  64  32    16
			 * RxQs/TC:  32  32    32
			 */
			*rx = tc << 5;
			if (tc < 2)
				*tx = tc << 6; /*  0,  64 */
			else
				*tx = (tc + 4) << 4; /* 96, 112 */
		}
	default:
		break;
	}
}

/**
 * rnpm_cache_ring_dcb - Descriptor ring to register mapping for DCB
 * @adapter: board private structure to initialize
 *
 * Cache the descriptor ring offsets for DCB to the assigned rings.
 *
 **/
static bool rnpm_cache_ring_dcb(struct rnpm_adapter *adapter)
{
	struct net_device *dev = adapter->netdev;
	unsigned int tx_idx, rx_idx;
	int tc, offset, rss_i, i;
	u8 num_tcs = netdev_get_num_tc(dev);

	return true;
}

#endif
/**
 * rnpm_cache_ring_sriov - Descriptor ring to register mapping for sriov
 * @adapter: board private structure to initialize
 *
 * SR-IOV doesn't use any descriptor rings but changes the default if
 * no other mapping is used.
 *
 */
static bool rnpm_cache_ring_sriov(struct rnpm_adapter *adapter)
{
	/* only proceed if VMDq is enabled */
	if (!(adapter->flags & RNPM_FLAG_VMDQ_ENABLED))
		return false;

	return true;
}

/**
 * rnpm_cache_ring_rss - Descriptor ring to register mapping for RSS
 * @adapter: board private structure to initialize
 *
 * Cache the descriptor ring offsets for RSS to the assigned rings.
 *
 **/
static bool rnpm_cache_ring_rss(struct rnpm_adapter *adapter)
{
	int i;
	int ring_step = 1;
	int ring_start = 0;
	int ring_alloc = 1;
	struct rnpm_ring *ring;
	struct rnpm_hw *hw = &adapter->hw;

	switch (hw->mode) {
	case MODE_NIC_MODE_1PORT:
		ring_step = 1;
		ring_start = adapter->port;
		ring_alloc = 1;
		break;
	case MODE_NIC_MODE_1PORT_40G:
		ring_step = 1;
		ring_start = adapter->port;
		ring_alloc = 1;
		break;
	case MODE_NIC_MODE_2PORT:
		ring_step = 4;
		ring_start = adapter->port * 2;
		ring_alloc = 2;
		break;
	case MODE_NIC_MODE_4PORT:
		ring_step = 4;
		ring_start = adapter->port;
		ring_alloc = 1;
		break;
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		/* reset ring vars */
		ring->rnpm_queue_idx =
			ring_start + (i / ring_alloc) * ring_step +
			((ring_alloc == 1) ? 0 : ((i % 2) ? 1 : 0));
		ring->dma_hw_addr = hw->hw_addr;
		ring->dma_int_stat =
			hw->hw_addr + RNPM_DMA_INT_STAT(ring->rnpm_queue_idx);
		ring->dma_int_mask = ring->dma_int_stat + 4;
		ring->dma_int_clr = ring->dma_int_stat + 8;
	}

	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		/* reset ring vars */
		ring->rnpm_queue_idx =
			ring_start + (i / ring_alloc) * ring_step +
			((ring_alloc == 1) ? 0 : ((i % 2) ? 1 : 0));
		ring->dma_hw_addr = hw->hw_addr;
		ring->dma_int_stat =
			hw->hw_addr + RNPM_DMA_INT_STAT(ring->rnpm_queue_idx);
		ring->dma_int_mask = ring->dma_int_stat + 4;
		ring->dma_int_clr = ring->dma_int_stat + 8;
	}

	return true;
}

/**
 * rnpm_cache_ring_register - Descriptor ring to register mapping
 * @adapter: board private structure to initialize
 *
 * Once we know the feature-set enabled for the device, we'll cache
 * the register offset the descriptor ring is assigned to.
 *
 * Note, the order the various feature calls is important.  It must start with
 * the "most" features enabled at the same time, then trickle down to the
 * least amount of features turned on at once.
 **/
static void rnpm_cache_ring_register(struct rnpm_adapter *adapter)
{
	/* start with default case */

#ifdef CONFIG_RNPM_DCB
	if (rnpm_cache_ring_dcb_sriov(adapter))
		return;

	if (rnpm_cache_ring_dcb(adapter))
		return;

#endif
	/* sriov ring alloc is added before, this maybe no use */
	if (rnpm_cache_ring_sriov(adapter))
		return;

	rnpm_cache_ring_rss(adapter);
}

#define RNPM_RSS_64Q_MASK 0x3F
#define RNPM_RSS_16Q_MASK 0xF
#define RNPM_RSS_8Q_MASK 0x7
#define RNPM_RSS_4Q_MASK 0x3
#define RNPM_RSS_2Q_MASK 0x1
#define RNPM_RSS_DISABLED_MASK 0x0

#ifdef CONFIG_RNPM_DCB
/**
 * rnpm_set_dcb_sriov_queues: Allocate queues for SR-IOV devices w/ DCB
 * @adapter: board private structure to initialize
 *
 * When SR-IOV (Single Root IO Virtualiztion) is enabled, allocate queues
 * and VM pools where appropriate.  Also assign queues based on DCB
 * priorities and map accordingly..
 *
 **/
static bool rnpm_set_dcb_sriov_queues(struct rnpm_adapter *adapter)
{
	int i;
	u16 vmdq_i = adapter->ring_feature[RING_F_VMDQ].limit;
	u16 vmdq_m = 0;
	u8 tcs = netdev_get_num_tc(adapter->netdev);

	/* verify we have DCB queueing enabled before proceeding */
	if (tcs <= 1)
		return false;

	/* verify we have VMDq enabled before proceeding */
	if (!(adapter->flags & RNPM_FLAG_SRIOV_ENABLED))
		return false;

	/* Add starting offset to total pool count */
	vmdq_i += adapter->ring_feature[RING_F_VMDQ].offset;

	/* 16 pools w/ 8 TC per pool */
	if (tcs > 4) {
		vmdq_i = min_t(u16, vmdq_i, 16);
		vmdq_m = RNPM_n10_VMDQ_8Q_MASK;
		/* 32 pools w/ 4 TC per pool */
	} else {
		vmdq_i = min_t(u16, vmdq_i, 32);
		vmdq_m = RNPM_n10_VMDQ_4Q_MASK;
	}

	/* remove the starting offset from the pool count */
	vmdq_i -= adapter->ring_feature[RING_F_VMDQ].offset;

	/* save features for later use */
	adapter->ring_feature[RING_F_VMDQ].indices = vmdq_i;
	adapter->ring_feature[RING_F_VMDQ].mask = vmdq_m;

	/* We do not support DCB, VMDq, and RSS all simultaneously
	 * so we will disable RSS since it is the lowest priority
	 */
	adapter->ring_feature[RING_F_RSS].indices = 2;
	adapter->ring_feature[RING_F_RSS].mask = RNPM_RSS_DISABLED_MASK;

	/* disable ATR as it is not supported when VMDq is enabled */
	adapter->flags &= ~RNPM_FLAG_FDIR_HASH_CAPABLE;

	adapter->num_tx_queues = vmdq_i * tcs;
	adapter->num_rx_queues = vmdq_i * tcs;

	/* configure TC to queue mapping */
	for (i = 0; i < tcs; i++)
		netdev_set_tc_queue(adapter->netdev, i, 1, i);

	return true;
}

static bool rnpm_set_dcb_queues(struct rnpm_adapter *adapter)
{
	struct net_device *dev = adapter->netdev;
	struct rnpm_ring_feature *f;
	int rss_i, rss_m, i;
	int tcs;

	/* Map queue offset and counts onto allocated tx queues */
	tcs = netdev_get_num_tc(dev);

	/* verify we have DCB queueing enabled before proceeding */
	if (tcs <= 1)
		return false;
	return true;
}

#endif
/**
 * rnpm_set_sriov_queues - Allocate queues for SR-IOV devices
 * @adapter: board private structure to initialize
 *
 * When SR-IOV (Single Root IO Virtualiztion) is enabled, allocate queues
 * and VM pools where appropriate.  If RSS is available, then also try and
 * enable RSS and map accordingly.
 *
 **/
static bool rnpm_set_sriov_queues(struct rnpm_adapter *adapter)
{
	// u16 vmdq_i = adapter->ring_feature[RING_F_VMDQ].limit;
	u16 vmdq_m = 0;
	u16 rss_i = adapter->ring_feature[RING_F_RSS].limit;
	u16 rss_m = RNPM_RSS_DISABLED_MASK;

	/* only proceed if SR-IOV is enabled */
	if (!(adapter->flags & RNPM_FLAG_SRIOV_ENABLED))
		return false;

	/* save features for later use */
	adapter->ring_feature[RING_F_VMDQ].indices =
		adapter->max_ring_pair_counts - 1;
	adapter->ring_feature[RING_F_VMDQ].mask = vmdq_m;

	/* limit RSS based on user input and save for later use */
	adapter->ring_feature[RING_F_RSS].indices = rss_i;
	adapter->ring_feature[RING_F_RSS].mask = rss_m;

	adapter->num_rx_queues = PF_RING_CNT_WHEN_IOV_ENABLED;
	adapter->num_tx_queues = PF_RING_CNT_WHEN_IOV_ENABLED;

	/* disable ATR as it is not supported when VMDq is enabled */
	adapter->flags &= ~RNPM_FLAG_FDIR_HASH_CAPABLE;

	return true;
}

u32 rnpm_rss_indir_tbl_entries(struct rnpm_adapter *adapter)
{
	if (adapter->hw.rss_type == rnpm_rss_uv3p)
		return 8;
	else if (adapter->hw.rss_type == rnpm_rss_uv440)
		return 128;
	else if (adapter->hw.rss_type == rnpm_rss_n10)
		return 128;
	else
		return 128;
}
/**
 * rnpm_set_rss_queues - Allocate queues for RSS
 * @adapter: board private structure to initialize
 *
 * This is our "base" multiqueue mode.  RSS (Receive Side Scaling) will try
 * to allocate one Rx queue per CPU, and if available, one Tx queue per CPU.
 *
 **/
static bool rnpm_set_rss_queues(struct rnpm_adapter *adapter)
{
	struct rnpm_ring_feature *f;
	u16 rss_i;

	f = &adapter->ring_feature[RING_F_RSS];
	rss_i = f->limit;
	/* set limit -> indices */
	f->indices = rss_i;
	/* should init rss mask */
	if (adapter->hw.rss_type == rnpm_rss_uv3p) {
		f->mask = RNPM_RSS_8Q_MASK;
	} else if (adapter->hw.rss_type == rnpm_rss_uv440) {
		f->mask = RNPM_RSS_64Q_MASK;
		/* maybe not good */
	} else if (adapter->hw.rss_type == rnpm_rss_n10) {
		f->mask = RNPM_RSS_64Q_MASK;
		/* maybe not good */
	}

	/* set rss_i -> adapter->num_tx_queues */
	adapter->num_tx_queues =
		min_t(int, rss_i, adapter->max_ring_pair_counts);
	adapter->num_rx_queues = adapter->num_tx_queues;

	rnpm_dbg("[%s] limit:%d indices:%d queues:%d\n", adapter->netdev->name,
		 f->limit, f->indices, adapter->num_tx_queues);

	return true;
}

static void rnpm_set_num_queues(struct rnpm_adapter *adapter)
{
	/* Start with base case */
	adapter->num_tx_queues = 1;
	adapter->num_rx_queues = 1;

#ifdef CONFIG_RNPM_DCB
	if (rnpm_set_dcb_sriov_queues(adapter))
		return;

	if (rnpm_set_dcb_queues(adapter))
		return;

#endif
	if (rnpm_set_sriov_queues(adapter))
		return;
	/* at last we support rss */
	rnpm_set_rss_queues(adapter);
}

int rnpm_acquire_msix_vectors(struct rnpm_adapter *adapter, int vectors)
{
	int err;
	int vectors_per_port = 0;
	struct rnpm_hw *hw = &adapter->hw;
	struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;

	dbg("%s %d\n", __func__, vectors);

	switch (hw->mode) {
	case MODE_NIC_MODE_1PORT:
		vectors_per_port = vectors - adapter->num_other_vectors;
		break;
	case MODE_NIC_MODE_1PORT_40G:
		vectors_per_port = vectors - adapter->num_other_vectors;
		break;
	case MODE_NIC_MODE_2PORT:
		vectors_per_port = (vectors - adapter->num_other_vectors) / 2;
		break;
	case MODE_NIC_MODE_4PORT:
		vectors_per_port = (vectors - adapter->num_other_vectors) / 4;
		break;
	}
	/* if msix is init before, return here */
	adapter->num_q_vectors = min(vectors_per_port, adapter->max_q_vectors);
	if (pf_adapter->msix_entries)
		return 0;

	err = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
				    vectors, vectors);
	if (err < 0) {
		rnpm_err("pci_enable_msix failed: req:%d err:%d\n", vectors,
			 err);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
		return -EINVAL;
	}
	/* Adjust for only the vectors we'll use, which is minimum
	 * of max_msix_q_vectors + NON_Q_VECTORS, or the number of
	 * vectors we were allocated.
	 */

	return 0;
}

static void rnpm_add_ring(struct rnpm_ring *ring,
			  struct rnpm_ring_container *head)
{
	ring->next = head->ring;
	head->ring = ring;
	head->count++;
}

static inline void rnpm_irq_disable_queues(struct rnpm_q_vector *q_vector)
{
	struct rnpm_ring *ring;

	rnpm_for_each_ring(ring, q_vector->tx) {
		// update usecs
		rnpm_wr_reg(ring->dma_int_mask, (RX_INT_MASK | TX_INT_MASK));
	}
}

static enum hrtimer_restart irq_miss_check(struct hrtimer *hrtimer)
{
	struct rnpm_q_vector *q_vector;
	struct rnpm_ring *ring;
	struct rnpm_tx_desc *eop_desc;
	struct rnpm_adapter *adapter;

	int tx_next_to_clean;
	int tx_next_to_use;

	struct rnpm_tx_buffer *tx_buffer;
	union rnpm_rx_desc *rx_desc;

	q_vector = container_of(hrtimer, struct rnpm_q_vector,
				irq_miss_check_timer);
	adapter = q_vector->adapter;

	if (test_bit(__RNPM_DOWN, &adapter->state) ||
	    test_bit(__RNPM_RESETTING, &adapter->state))
		goto do_self_napi;
	set_bit(RNPM_IRQ_MISS_HANDLE_DONE, &q_vector->flags);
	// check tx irq miss
	rnpm_for_each_ring(ring, q_vector->tx) {
		tx_next_to_clean = ring->next_to_clean;
		tx_next_to_use = ring->next_to_use;
		// have work to do
		if (tx_next_to_use != tx_next_to_clean) {
			tx_buffer = &ring->tx_buffer_info[tx_next_to_clean];
			eop_desc = tx_buffer->next_to_watch;
			// have tx done
			// next_to_watch maybe null in some condition
			if (eop_desc) {
				if ((eop_desc->vlan_cmd &
				     cpu_to_le32(RNPM_TXD_STAT_DD))) {
					// close irq
					// printk("call irq self\n");
					rnpm_irq_disable_queues(q_vector);
					napi_schedule_irqoff(&q_vector->napi);
					goto do_self_napi;
				}
			}
		}
	}

	// check rx irq
	rnpm_for_each_ring(ring, q_vector->rx) {
		rx_desc = RNPM_RX_DESC(ring, ring->next_to_clean);
		if (rx_desc == NULL) {
			/* if one desc is null, mybe the verctor is freed, exit directly */
			goto do_self_napi;
		}

		if (rnpm_test_staterr(rx_desc, RNPM_RXD_STAT_DD)) {
			// should check rx not zero
			int size;

			size = le16_to_cpu(rx_desc->wb.len);
			if (size) {
				rnpm_irq_disable_queues(q_vector);
				napi_schedule_irqoff(&q_vector->napi);
			} else {
				// try to reset pf
				struct rnpm_pf_adapter *pf_adapter =
					adapter->pf_adapter;
				set_bit(RNPM_PF_RESET, &pf_adapter->flags);
			}
			goto do_self_napi;
		}
	}

do_self_napi:
	clear_bit(RNPM_IRQ_MISS_HANDLE_DONE, &q_vector->flags);
	return HRTIMER_NORESTART;
}

/**
 * rnpm_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @v_count: q_vectors allocated on adapter, used for ring interleaving
 * @v_idx: index of vector in adapter struct
 * @txr_count: total number of Tx rings to allocate
 * @txr_idx: index of first Tx ring to allocate
 * @rxr_count: total number of Rx rings to allocate
 * @rxr_idx: index of first Rx ring to allocate
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 **/
static int rnpm_alloc_q_vector(struct rnpm_adapter *adapter, int eth_queue_idx,
			       int v_idx, int r_idx, int r_count, int step)
{
	struct rnpm_q_vector *q_vector;
	struct rnpm_ring *ring;
	struct rnpm_hw *hw = &adapter->hw;
	int node = NUMA_NO_NODE;
	int cpu = -1;
	int ring_count, size;
	int txr_count, rxr_count, idx;
	int rxr_idx = r_idx, txr_idx = r_idx;

	DPRINTK(PROBE, INFO,
		"eth_queue_idx:%d v_idx:%d(off:%d) ring:%d ring_cnt:%d step:%d\n",
		eth_queue_idx, v_idx, adapter->vector_off, r_idx, r_count,
		step);

	txr_count = rxr_count = r_count;

	ring_count = txr_count + rxr_count;

	/* alloc ring memory together with q_vector */
	size = sizeof(struct rnpm_q_vector) +
	       (sizeof(struct rnpm_ring) * ring_count);

	/* should minis adapter->vector_off */
	if (cpu_online(v_idx - adapter->vector_off)) {
		/* test feiteng, assign Manually */
		/* cpu 48 - 55 */
		/* node 6 */

		/* cpu 1 - 7 */
		//cpu = 1 + v_idx - adapter->vector_off;
		cpu = v_idx - adapter->vector_off;
		node = cpu_to_node(cpu);
	}

	/* allocate q_vector and rings */
	q_vector = kzalloc_node(size, GFP_KERNEL, node);
	if (!q_vector)
		q_vector = kzalloc(size, GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	cpumask_copy(&q_vector->affinity_mask, cpu_possible_mask);
	/* setup affinity mask and node */
	q_vector->numa_node = node;
	/* initialize timer */
	q_vector->irq_check_usecs = RNPM_IRQ_CHECK_USEC;
	//q_vector->new_rx_count = RNPM_PKT_TIMEOUT;
	//q_vector->old_rx_count = RNPM_PKT_TIMEOUT;

	hrtimer_init(&q_vector->irq_miss_check_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_PINNED);
	q_vector->irq_miss_check_timer.function = irq_miss_check;

	/* initialize NAPI */
	netif_napi_add_weight(adapter->netdev, &q_vector->napi, rnpm_poll,
			      adapter->napi_budge);
	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx - adapter->vector_off] = q_vector;
	q_vector->adapter = adapter;
	/* this indicate vector table */
	q_vector->v_idx = v_idx;

	/* initialize work limits */
	q_vector->tx.work_limit = adapter->tx_work_limit;

	q_vector->rx.itr = q_vector->itr = adapter->rx_frames;
#ifdef CONFIG_HZ
	q_vector->factor = DIV_ROUND_UP(1000, CONFIG_HZ);
#else
	q_vector->factor = 1;
#endif

	/* initialize pointer to rings */
	ring = q_vector->ring;

	for (idx = 0; idx < txr_count; idx++) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		rnpm_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_item_count;
		ring->queue_index = eth_queue_idx + idx;

		/* rnpm_queue_idx can be changed after */
		/* it is used to location hw reg */
		ring->rnpm_queue_idx = txr_idx;
		ring->dma_int_stat =
			hw->hw_addr + RNPM_DMA_INT_STAT(ring->rnpm_queue_idx);
		ring->dma_int_mask = ring->dma_int_stat + 4;
		ring->dma_int_clr = ring->dma_int_stat + 8;
		ring->device_id = adapter->pdev->device;
		ring->pfvfnum = hw->pfvfnum;

		/* assign ring to adapter */
		adapter->tx_ring[ring->queue_index] = ring;

		/* update count and index */
		txr_idx += step;

		rnpm_dbg("\t\t%s:vector[%d] <--RNPM TxRing:%d, eth_queue:%d\n",
			 adapter->netdev->name, v_idx, ring->rnpm_queue_idx,
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
		rnpm_add_ring(ring, &q_vector->rx);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_item_count;
		/* rnpm_queue_idx can be changed after */
		/* it is used to location hw reg */
		ring->queue_index = eth_queue_idx + idx;
		ring->rnpm_queue_idx = rxr_idx;
		ring->dma_int_stat =
			hw->hw_addr + RNPM_DMA_INT_STAT(ring->rnpm_queue_idx);
		ring->dma_int_mask = ring->dma_int_stat + 4;
		ring->dma_int_clr = ring->dma_int_stat + 8;
		ring->device_id = adapter->pdev->device;
		ring->pfvfnum = hw->pfvfnum;

		/* assign ring to adapter */
		adapter->rx_ring[ring->queue_index] = ring;
		rnpm_dbg("\t\t%s:vector[%d] <--RNPM RxRing:%d, eth_queue:%d\n",
			 adapter->netdev->name, v_idx, ring->rnpm_queue_idx,
			 ring->queue_index);

		/* update count and index */
		rxr_idx += step;

		/* push pointer to next ring */
		ring++;
	}

	return 0;
}

/**
 * rnpm_free_q_vector - Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: Index of vector to be freed
 *
 * This function frees the memory allocated to the q_vector.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void rnpm_free_q_vector(struct rnpm_adapter *adapter, int v_idx)
{
	struct rnpm_q_vector *q_vector = adapter->q_vector[v_idx];
	struct rnpm_ring *ring;

	dbg("v_idx:%d\n", v_idx);

	hrtimer_cancel(&q_vector->irq_miss_check_timer);

	rnpm_for_each_ring(ring, q_vector->tx)
		adapter->tx_ring[ring->queue_index] = NULL;

	rnpm_for_each_ring(ring, q_vector->rx)
		adapter->rx_ring[ring->queue_index] = NULL;

	adapter->q_vector[v_idx] = NULL;
	netif_napi_del(&q_vector->napi);

	/* rnpm_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	kfree_rcu(q_vector, rcu);
}

/**
 * rnpm_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int rnpm_alloc_q_vectors(struct rnpm_adapter *adapter)
{
	int v_idx = adapter->vector_off;
	struct rnpm_hw *hw = &adapter->hw;
	int ring_idx = 0;
	int r_remaing =
		min_t(int, adapter->num_tx_queues, adapter->num_rx_queues);
	int ring_step = 1;
	int err, ring_cnt, v_remaing = adapter->num_q_vectors;
	int q_vector_nums = 0;

	if ((adapter->flags & RNPM_FLAG_SRIOV_ENABLED)) {
		ring_idx = 0;
		// use 1ring  when vf  enabled
		/* only 2 rings when sriov enabled */
		/* from back */
		ring_idx = adapter->max_ring_pair_counts -
			   ring_step * PF_RING_CNT_WHEN_IOV_ENABLED;
		r_remaing = PF_RING_CNT_WHEN_IOV_ENABLED;
	}
	BUG_ON(adapter->num_q_vectors == 0);
	/* start from port num */
	ring_idx = adapter->port;
	/* eth_queue_idx always start from 0 */
	adapter->eth_queue_idx = 0;
	switch (hw->mode) {
	case MODE_NIC_MODE_1PORT:
		ring_step = 1;
		break;
	case MODE_NIC_MODE_1PORT_40G:
		ring_step = 1;
		break;
	case MODE_NIC_MODE_2PORT:
		ring_step = 2;
		break;
	case MODE_NIC_MODE_4PORT:
		ring_step = 4;
		break;
	}

	rnpm_dbg("r_remaing:%d, ring_step:%d num_q_vectors:%d\n", r_remaing,
		 ring_step, v_remaing);

	/* can support muti rings in one q_vector */
	for (; r_remaing > 0 && v_remaing > 0; v_remaing--) {
		ring_cnt = DIV_ROUND_UP(r_remaing, v_remaing);
		err = rnpm_alloc_q_vector(adapter, adapter->eth_queue_idx,
					  v_idx, ring_idx, ring_cnt, ring_step);
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
		rnpm_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

/**
 * rnpm_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void rnpm_free_q_vectors(struct rnpm_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	adapter->num_rx_queues = 0;
	adapter->num_tx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		rnpm_free_q_vector(adapter, v_idx);
}

static void rnpm_reset_interrupt_capability(struct rnpm_adapter *adapter)
{
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
}

/**
 * rnpm_set_interrupt_capability - set MSI-X or MSI if supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 **/
static int rnpm_set_interrupt_capability(struct rnpm_adapter *adapter)
{
	struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;
	int v_budget, err = 0;
	int msix_offset;

	v_budget = adapter->max_ring_pair_counts;
	/* in one ring mode should reset v_budget */
	v_budget = min_t(int, v_budget, num_online_cpus());
	v_budget = min_t(int, v_budget, adapter->max_msix_counts);

	/* muti port use only one other vector */
	/* add one other vectors */
	adapter->msix_entries =
		kcalloc(v_budget, sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->msix_entries) {
		rnpm_err("alloc msix_entries failed!\n");
		return -EINVAL;
	}
	dbg("[%s] adapter:%p msix_entry:%p vector:%d\n", __func__, adapter,
	    adapter->msix_entries, adapter->vector_off);

	msix_offset = adapter->vector_off;
	memcpy((u8 *)adapter->msix_entries,
	       (u8 *)pf_adapter->msix_entries +
		       sizeof(struct msix_entry) * msix_offset,
	       sizeof(struct msix_entry) * v_budget);

	adapter->num_q_vectors = min(v_budget, adapter->max_q_vectors);

	rnpm_dbg(
		"adapter%d alloc vectors: cnt:%d [%d~%d] num_q_vectors:%d msix_offset %d\n",
		adapter->bd_number, v_budget, adapter->vector_off,
		adapter->vector_off + v_budget - 1, adapter->num_q_vectors,
		msix_offset);

	return err;
}

/**
 * rnpm_init_interrupt_scheme - Determine proper interrupt scheme
 * @adapter: board private structure to initialize
 *
 * We determine which interrupt scheme to use based on...
 * - Hardware queue count (num_*_queues)
 *   - defined by miscellaneous hardware support/features (RSS, etc.)
 **/
int rnpm_init_interrupt_scheme(struct rnpm_adapter *adapter)
{
	int err;
	// struct net_device *netdev = adapter->netdev;

	/* Number of supported queues */
	rnpm_set_num_queues(adapter);

	/* Set interrupt mode */
	rnpm_set_interrupt_capability(adapter);

	err = rnpm_alloc_q_vectors(adapter);
	if (err) {
		e_dev_err("Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}
	rnpm_cache_ring_register(adapter);

	DPRINTK(PROBE, INFO,
		"Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n\n",
		(adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
		adapter->num_rx_queues, adapter->num_tx_queues);

	set_bit(__RNPM_DOWN, &adapter->state);
	return 0;

err_alloc_q_vectors:
	rnpm_reset_interrupt_capability(adapter);
	return err;
}

/**
 * rnpm_clear_interrupt_scheme - Clear the current interrupt scheme settings
 * @adapter: board private structure to clear interrupt scheme on
 *
 * We go through and clear interrupt specific resources and reset the structure
 * to pre-load conditions
 **/
void rnpm_clear_interrupt_scheme(struct rnpm_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	rnpm_free_q_vectors(adapter);
	rnpm_reset_interrupt_capability(adapter);
}

/**
 * rnpm_tx_ctxtdesc - Send a control desc to hw
 * @tx_ring: target ring of this control desc
 * @mss_seg_len: mss length
 * @l4_hdr_len:  l4 length
 * @tunnel_hdr_len: tunnel_hdr_len
 * @inner_vlan_tag: inner_vlan_tag
 * @type_tucmd: cmd
 *
 **/

void rnpm_tx_ctxtdesc(struct rnpm_ring *tx_ring, u32 mss_len_vf_num,
		      u32 inner_vlan_tunnel_len, u32 type_tucmd)
{
	struct rnpm_tx_ctx_desc *context_desc;
	u16 i = tx_ring->next_to_use;
	// struct rnpm_adapter *adapter = RING2ADAPT(tx_ring);

	context_desc = RNPM_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* set bits to identify this as an advanced context descriptor */
	//type_tucmd |= RNPM_TXD_CMD_RS | RNPM_TXD_CTX_CTRL_DESC;
	type_tucmd |= RNPM_TXD_CTX_CTRL_DESC;

	if (inner_vlan_tunnel_len & 0x00ffff00) {
		/* if a inner vlan */
		type_tucmd |= RNPM_TXD_CMD_INNER_VLAN;
	}

	context_desc->mss_len_vf_num = cpu_to_le32(mss_len_vf_num);
	context_desc->inner_vlan_tunnel_len =
		cpu_to_le32(inner_vlan_tunnel_len);
	context_desc->resv_cmd = cpu_to_le32(type_tucmd);
#ifdef RNPM_IOV_VEB_BUG_NOT_FIXED
	if (tx_ring->q_vector->adapter->flags & RNPM_FLAG_SRIOV_ENABLED) {
		context_desc->inner_vlan_tunnel_len |= VF_VEB_MARK;
		//((u8*)&context_desc->mss_len_vf_num)[2] =
		//	tx_ring->q_vector->adapter->veb_vfnum;
	}
#endif
	buf_dump_line("ctx  ", __LINE__, context_desc, sizeof(*context_desc));
}

void rnpm_maybe_tx_ctxtdesc(struct rnpm_ring *tx_ring,
			    struct rnpm_tx_buffer *first, u32 type_tucmd)
{
	struct rnpm_adapter *adapter = netdev_priv((tx_ring)->netdev);
	/* sriov mode pf use the last vf */
	if (first->ctx_flag) {
		if (adapter->priv_flags & RNPM_PRIV_FLAG_TX_PADDING) {
			if (!first->gso_need_padding)
				type_tucmd |= RNPM_TXD_MTI_CRC_PAD_CTRL;
			first->gso_need_padding = false;
		}

		rnpm_tx_ctxtdesc(tx_ring, first->mss_len_vf_num,
				 first->inner_vlan_tunnel_len, type_tucmd);
	}
}

void rnpm_store_reta(struct rnpm_adapter *adapter)
{
	u32 i, reta_entries = rnpm_rss_indir_tbl_entries(adapter);
	struct rnpm_hw *hw = &adapter->hw;
	u32 reta = 0;
	// u8 *indir_tbl = adapter->rss_indir_tbl;
	/* relative with rss table */
	u32 port = adapter->port;
	struct rnpm_ring *rx_ring;

	/* Write redirection table to HW */
	for (i = 0; i < reta_entries; i++) {
		if (adapter->flags & RNPM_FLAG_SRIOV_ENABLED) {
			reta = adapter->rss_indir_tbl[i];
		} else {
			rx_ring = adapter->rx_ring[adapter->rss_indir_tbl[i]];
			if (adapter->flags & RNPM_FLAG_RXHASH_DISABLE) {
				/* clean table to zero */
				reta = adapter->port;
			} else {
				int port_offset =
					rd32(hw, RNPM_ETH_TC_PORT_OFFSET_TABLE(
							 adapter->port));

				reta = rx_ring->rnpm_queue_idx - port_offset;
			}
		}
		if (hw->rss_type == rnpm_rss_uv3p)
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL_UV3P(i), reta);
		else if (hw->rss_type == rnpm_rss_uv440)
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL(port, i), reta);
		else if (hw->rss_type == rnpm_rss_n10)
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL(port, i), reta);
	}
}

void rnpm_store_key(struct rnpm_pf_adapter *pf_adapter)
{
	u8 *key = pf_adapter->rss_key;
	int key_len = RNPM_RSS_KEY_SIZE;
	u8 *key_temp;
	int i;
	u32 *value;

	key_temp = kmalloc(key_len, GFP_KERNEL);
	for (i = 0; i < key_len; i++)
		*(key_temp + key_len - i - 1) = *(key + i);
	value = (u32 *)key_temp;
	for (i = 0; i < key_len; i = i + 4)
		rnpm_wr_reg(pf_adapter->hw_addr + RNPM_ETH_RSS_KEY + i,
			    *(value + i / 4));
	kfree(key_temp);
}

int rnpm_init_rss_key(struct rnpm_pf_adapter *pf_adapter)
{
	// int i;
	//struct rnpm_hw *hw = &adapter->hw;
	//struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;
	unsigned long flags;
// for test only
//#define DEBUG_RSS
#ifdef DEBUG_RSS
	u8 temp[] = { 0xca, 0xf9, 0x8f, 0x24, 0xc2, 0x10, 0x50, 0x22,
		      0x1f, 0x6c, 0xec, 0xc8, 0xd5, 0x9d, 0x8c, 0xa6,
		      0x96, 0x0b, 0x50, 0xf9, 0x24, 0x89, 0x74, 0x96,
		      0xf2, 0xbd, 0xbe, 0xbc, 0x5c, 0x81, 0xb2, 0x06,
		      0x3d, 0xb4, 0x08, 0x56, 0xca, 0x0c, 0x62, 0x1a };
#endif
	//u32 iov_en = (adapter->flags & RNPM_FLAG_SRIOV_ENABLED)
	//	? RNPM_IOV_ENABLED : 0;
	u32 iov_en = 0;

	/* only init rss key once */
	/* no change rss key if user input one */
	/* get the key */
	spin_lock_irqsave(&pf_adapter->key_setup_lock, flags);
	if (!pf_adapter->rss_key_setup_flag) {
		//netdev_rss_key_fill(pf_adapter->rss_key, RNPM_RSS_KEY_SIZE);
#ifdef DEBUG_RSS
		memcpy(pf_adapter->rss_key, temp, RNPM_RSS_KEY_SIZE);
#else
		netdev_rss_key_fill(pf_adapter->rss_key, RNPM_RSS_KEY_SIZE);
#endif
		pf_adapter->rss_key_setup_flag = 1;
	}
	rnpm_store_key(pf_adapter);
	/* open rss if rx hash is open ? */
	wr32(pf_adapter, RNPM_ETH_RSS_CONTROL,
	     RNPM_ETH_ENABLE_RSS_ONLY | iov_en);
	spin_unlock_irqrestore(&pf_adapter->key_setup_lock, flags);

	return 0;
}

int rnpm_init_rss_table(struct rnpm_adapter *adapter)
{
	int rx_nums = adapter->num_rx_queues;
	int i, j;
	struct rnpm_hw *hw = &adapter->hw;
	struct rnpm_ring *rx_ring;
	u32 reta = 0;
	u32 reta_entries = rnpm_rss_indir_tbl_entries(adapter);
	u32 port = adapter->port;

	/* adapter->num_q_vectors is not correct */
	for (i = 0, j = 0; i < reta_entries; i++) {
		/* init with default value */
		if (!adapter->rss_tbl_setup_flag)
			adapter->rss_indir_tbl[i] = j;
		/* in sriov mode reta in [0, rx_nums] */
		if (adapter->flags & RNPM_FLAG_SRIOV_ENABLED)
			reta = j;
		else {
			/* in no sriov, reta is real ring number */
			rx_ring = adapter->rx_ring[adapter->rss_indir_tbl[i]];
			if (adapter->flags & RNPM_FLAG_RXHASH_DISABLE) {
				/* clean table to zero if rx hash off */
				reta = adapter->port;
			} else {
				int port_offset =
					rd32(hw, RNPM_ETH_TC_PORT_OFFSET_TABLE(
							 adapter->port));
				/* we use port_offset + rss_table to
				 * real ring
				 */
				reta = rx_ring->rnpm_queue_idx - port_offset;
			}
		}
		/* rss table should add ring_offset */
		if (hw->rss_type == rnpm_rss_uv3p) {
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL_UV3P(i), reta);
			wr32(hw, RNPM_ETH_RSS_MODE, 6);
		} else if (hw->rss_type == rnpm_rss_uv440) {
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL(port, i), reta);
		} else if (hw->rss_type == rnpm_rss_n10) {
			wr32(hw, RNPM_ETH_RSS_INDIR_TBL(port, i), reta);
		}
		j = (j + 1) % rx_nums;
	}
	/* tbl only init once */
	adapter->rss_tbl_setup_flag = 1;

	for (i = 0, j = 0; i < reta_entries; i++) {
		dbg("indir %d table is %d\n", i, adapter->rss_indir_tbl[i]);
		if (hw->rss_type == rnpm_rss_uv3p) {
			dbg("reg %x is %d\n", RNPM_ETH_RSS_INDIR_TBL_UV3P(i),
			    rd32(hw, RNPM_ETH_RSS_INDIR_TBL_UV3P(i)));
		} else {
			dbg("reg %x is %d\n", RNPM_ETH_RSS_INDIR_TBL(port, i),
			    rd32(hw, RNPM_ETH_RSS_INDIR_TBL(port, i)));
		}
	}
	return 0;
}

void rnpm_setup_dma_rx(struct rnpm_adapter *adapter, int count_in_dw)
{
	struct rnpm_hw *hw = &adapter->hw;
	u32 data;

	data = rd32(hw, RNPM_DMA_CONFIG);
	data &= (0x00000ffff);
	data |= (count_in_dw << 16);
	wr32(hw, RNPM_DMA_CONFIG, data);
}

void rnpm_setup_layer2_remapping(struct rnpm_hw *hw,
				 union rnpm_atr_input *input, u16 hw_id,
				 u8 queue)
{
	struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	u8 offset = adapter->port;

	drection_dbg("try to eable layer2 %x\n", input->layer2_formate.proto);
	/* enable l2 proto setup */
	//rnpm_set_reg_bit(hw, RNPM_ETH_VLAN_FILTER_ENABLE, 31);
	/* enable layer2 */
	wr32(hw, RNPM_ETH_LAYER2_ETQF(hw_id),
	     (0x1 << 31) | (ntohs(input->layer2_formate.proto)));
	/* setup action */
	if (queue == RNPM_FDIR_DROP_QUEUE) {
		wr32(hw, RNPM_ETH_LAYER2_ETQS(hw_id), (0x1 << 31));
	} else {
		/* setup ring_number */
		/* in multiple mode queue must sub port offset */
		wr32(hw, RNPM_ETH_LAYER2_ETQS(hw_id),
		     (0x1 << 30) | ((queue - offset) << 20));
	}
}

void rnpm_setup_tuple5_remapping(struct rnpm_hw *hw,
				 union rnpm_atr_input *input, u16 hw_id,
				 u8 queue)
{
	u32 port = 0;
	u8 mask_temp = 0;
	u8 l4_proto_type = 0;
	struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	u8 offset = adapter->port;

	drection_dbg("try to eable tuple 5 %x\n", hw_id);
	if (input->formatted.src_ip[0] != 0)
		wr32(hw, RNPM_ETH_TUPLE5_SAQF(hw_id),
		     htonl(input->formatted.src_ip[0]));
	else
		mask_temp |= RNPM_SRC_IP_MASK;

	if (input->formatted.dst_ip[0] != 0) {
		wr32(hw, RNPM_ETH_TUPLE5_DAQF(hw_id),
		     htonl(input->formatted.dst_ip[0]));
	} else
		mask_temp |= RNPM_DST_IP_MASK;

	if (input->formatted.src_port != 0)
		port |= (htons(input->formatted.src_port));
	else
		mask_temp |= RNPM_SRC_PORT_MASK;

	if (input->formatted.dst_port != 0)
		port |= (htons(input->formatted.dst_port) << 16);
	else
		mask_temp |= RNPM_DST_PORT_MASK;

	if (port != 0)
		wr32(hw, RNPM_ETH_TUPLE5_SDPQF(hw_id), port);

	switch (input->formatted.flow_type) {
	case RNPM_ATR_FLOW_TYPE_TCPV4:
		l4_proto_type = IPPROTO_TCP;
		break;
	case RNPM_ATR_FLOW_TYPE_UDPV4:
		l4_proto_type = IPPROTO_UDP;
		break;
	case RNPM_ATR_FLOW_TYPE_SCTPV4:
		l4_proto_type = IPPROTO_SCTP;
		break;
	case RNPM_ATR_FLOW_TYPE_IPV4:
		l4_proto_type = input->formatted.inner_mac[0];
		break;
	default:
		l4_proto_type = 0;
	}

	if (l4_proto_type == 0)
		mask_temp |= RNPM_L4_PROTO_MASK;

	/* setup ftqf*/
	/* always set 0x3 */
	wr32(hw, RNPM_ETH_TUPLE5_FTQF(hw_id),
	     (1 << 31) | (mask_temp << 25) | (l4_proto_type << 16) | 0x3);

	/* setup action */
	if (queue == RNPM_FDIR_DROP_QUEUE) {
		wr32(hw, RNPM_ETH_TUPLE5_POLICY(hw_id), (0x1 << 31));
	} else {
		/* setup ring_number */
		wr32(hw, RNPM_ETH_TUPLE5_POLICY(hw_id),
		     ((0x1 << 30) | ((queue - offset) << 20)));
	}
}

void rnpm_setup_tuple5_remapping_tcam(struct rnpm_hw *hw,
				      union rnpm_atr_input *input, u16 hw_id,
				      u8 queue)
{
	u32 port = 0;
	u32 port_mask = 0;
	u8 l4_proto_type = 0;
	u8 l4_proto_mask = 0xff;
	u32 action = 0;
	u32 mark = 0;
	struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	u8 offset = adapter->port;

	wr32(hw, RNPM_TCAM_MODE, 2);
	//wr32(hw, RNPM_TCAM_CACHE_ENABLE, 1);
	drection_dbg("try to eable tcam %x\n", hw_id);
	if (input->formatted.src_ip[0] != 0) {
		wr32(hw, RNPM_TCAM_SAQF(hw_id),
		     htonl(input->formatted.src_ip[0]));
		wr32(hw, RNPM_TCAM_SAQF_MASK(hw_id),
		     htonl(input->formatted.src_ip_mask[0]));
	} else {
		wr32(hw, RNPM_TCAM_SAQF(hw_id), 0);
		wr32(hw, RNPM_TCAM_SAQF_MASK(hw_id), 0);
	}
	if (input->formatted.dst_ip[0] != 0) {
		wr32(hw, RNPM_TCAM_DAQF(hw_id),
		     htonl(input->formatted.dst_ip[0]));
		wr32(hw, RNPM_TCAM_DAQF_MASK(hw_id),
		     htonl(input->formatted.dst_ip_mask[0]));
	} else {
		wr32(hw, RNPM_TCAM_DAQF(hw_id), 0);
		wr32(hw, RNPM_TCAM_DAQF_MASK(hw_id), 0);
	}
	if (input->formatted.src_port != 0) {
		port |= (htons(input->formatted.src_port) << 16);
		port_mask |= (htons(input->formatted.src_port_mask) << 16);
	} else {
	}
	if (input->formatted.dst_port != 0) {
		port |= (htons(input->formatted.dst_port));
		port_mask |= (htons(input->formatted.src_port_mask));
	}

	/* setup src & dst port */
	if (port != 0) {
		wr32(hw, RNPM_TCAM_SDPQF(hw_id), port);
		wr32(hw, RNPM_TCAM_SDPQF_MASK(hw_id), port_mask);
	} else {
		wr32(hw, RNPM_TCAM_SDPQF(hw_id), 0);
		wr32(hw, RNPM_TCAM_SDPQF_MASK(hw_id), 0);
	}

	switch (input->formatted.flow_type) {
	case RNPM_ATR_FLOW_TYPE_TCPV4:
		l4_proto_type = IPPROTO_TCP;
		break;
	case RNPM_ATR_FLOW_TYPE_UDPV4:
		l4_proto_type = IPPROTO_UDP;
		break;
	case RNPM_ATR_FLOW_TYPE_SCTPV4:
		l4_proto_type = IPPROTO_SCTP;
		break;
	case RNPM_ATR_FLOW_TYPE_IPV4:
		l4_proto_type = input->formatted.inner_mac[0];
		l4_proto_mask = input->formatted.inner_mac_mask[0];
		break;
	default:
		l4_proto_type = 0;
		l4_proto_mask = 0;
	}

	if (l4_proto_type != 0) {
		action |= l4_proto_type;
		mark |= l4_proto_mask;
	} else {
	}

	/* setup action */
	if (queue == RNPM_FDIR_DROP_QUEUE) {
		wr32(hw, RNPM_TCAM_APQF(hw_id), (0x1 << 31) | action);
		wr32(hw, RNPM_TCAM_APQF_MASK(hw_id), mark);
	} else {
		/* setup ring_number */
		wr32(hw, RNPM_TCAM_APQF(hw_id),
		     ((0x1 << 30) | ((queue - offset) << 16) | action));
		wr32(hw, RNPM_TCAM_APQF_MASK(hw_id), mark);
	}
	wr32(hw, RNPM_TCAM_MODE, 1);
}

/* setup to the hw  */
s32 rnpm_fdir_write_perfect_filter(int fdir_mode, struct rnpm_hw *hw,
				   union rnpm_atr_input *filter, u16 hw_id,
				   u8 queue)
{
	if (filter->formatted.flow_type == RNPM_ATR_FLOW_TYPE_ETHER) {
		rnpm_setup_layer2_remapping(hw, filter, hw_id, queue);
	} else {
		if (fdir_mode != fdir_mode_tcam)
			rnpm_setup_tuple5_remapping(hw, filter, hw_id, queue);
		else
			rnpm_setup_tuple5_remapping_tcam(hw, filter, hw_id,
							 queue);
	}

	return 0;
}

int rnpm_card_partially_supported_10g_1g_sfp(struct rnpm_pf_adapter *pf_adapter)
{
	if (pf_adapter && (pf_adapter->hw.ablity_speed == SPEED_10000) &&
	    (pf_adapter->adapter_cnt == 2)) {
		return 1;
	}

	return 0;
}

s32 rnpm_fdir_erase_perfect_filter(int fdir_mode, struct rnpm_hw *hw,
				   union rnpm_atr_input *input, u16 hw_id)
{
	/* just disable filter */
	if (input->formatted.flow_type == RNPM_ATR_FLOW_TYPE_ETHER) {
		wr32(hw, RNPM_ETH_LAYER2_ETQF(hw_id), 0);
		dbg("disable layer2 %d\n", hw_id);
	} else {
		if (fdir_mode != fdir_mode_tcam) {
			wr32(hw, RNPM_ETH_TUPLE5_FTQF(hw_id), 0);
			dbg("disable tuple5 %d\n", hw_id);
		} else {
			/* earase tcam */
			wr32(hw, RNPM_TCAM_MODE, 2);
			//wr32(hw, RNPM_TCAM_CACHE_ENABLE, 1);
			wr32(hw, RNPM_TCAM_SAQF(hw_id), 0);
			wr32(hw, RNPM_TCAM_SAQF_MASK(hw_id), 0);
			wr32(hw, RNPM_TCAM_DAQF(hw_id), 0);
			wr32(hw, RNPM_TCAM_DAQF_MASK(hw_id), 0);
			wr32(hw, RNPM_TCAM_SDPQF(hw_id), 0);
			wr32(hw, RNPM_TCAM_SDPQF_MASK(hw_id), 0);
			wr32(hw, RNPM_TCAM_APQF(hw_id), 0);
			wr32(hw, RNPM_TCAM_APQF_MASK(hw_id), 0);
			wr32(hw, RNPM_TCAM_MODE, 1);
			/* update tcam cache */
			wr32(hw, RNPM_TCAM_CACHE_ADDR_CLR, 0);
			wr32(hw, RNPM_TCAM_CACHE_REQ_CLR, 0);
		}
	}

	return 0;
}

u32 rnpm_tx_desc_unused_sw(struct rnpm_ring *tx_ring)
{
	u16 ntu = tx_ring->next_to_use;
	u16 ntc = tx_ring->next_to_clean;
	u16 count = tx_ring->count;

	return ((ntu >= ntc) ? (count - ntu + ntc) : (ntc - ntu));
}

u32 rnpm_rx_desc_used_hw(struct rnpm_hw *hw, struct rnpm_ring *rx_ring)
{
	u32 head = rd32(hw,
			RNPM_DMA_REG_RX_DESC_BUF_HEAD(rx_ring->rnpm_queue_idx));
	u32 tail = rd32(hw,
			RNPM_DMA_REG_RX_DESC_BUF_TAIL(rx_ring->rnpm_queue_idx));
	u16 count = rx_ring->count;

	return ((tail >= head) ? (count - tail + head) : (head - tail));
}

u32 rnpm_tx_desc_unused_hw(struct rnpm_hw *hw, struct rnpm_ring *tx_ring)
{
	u32 head = rd32(hw,
			RNPM_DMA_REG_TX_DESC_BUF_HEAD(tx_ring->rnpm_queue_idx));
	u32 tail = rd32(hw,
			RNPM_DMA_REG_TX_DESC_BUF_TAIL(tx_ring->rnpm_queue_idx));
	u16 count = tx_ring->count;

	return ((tail >= head) ? (count - tail + head) : (head - tail));
}

s32 rnpm_disable_rxr_maxrate(struct net_device *netdev, u8 queue_index)
{
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	struct rnpm_ring *rx_ring = adapter->rx_ring[queue_index];
	u32 reg_idx = rx_ring->rnpm_queue_idx;

	/* disable which dma ring in maxrate limit mode */
	wr32(hw, RNPM_SELECT_RING_EN(reg_idx), 0);
	/* Clear Tx Ring maxrate */
	wr32(hw, RNPM_RX_RING_MAXRATE(reg_idx), 0);

	return 0;
}

s32 rnpm_enable_rxr_maxrate(struct net_device *netdev, u8 queue_index,
			    u32 maxrate)
{
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	struct rnpm_ring *rx_ring = adapter->rx_ring[queue_index];
	u32 reg_idx = rx_ring->rnpm_queue_idx;
	u32 real_rate = maxrate / 16;

	if (!real_rate)
		return -EINVAL;

	wr32(hw, RNPM_RING_FC_ENABLE, true);
	/* disable which dma ring in maxrate limit mode */
	wr32(hw, RNPM_SELECT_RING_EN(reg_idx), true);
	/* Clear Tx Ring maxrate */
	wr32(hw, RNPM_RX_RING_MAXRATE(reg_idx), real_rate);

	return 0;
}
