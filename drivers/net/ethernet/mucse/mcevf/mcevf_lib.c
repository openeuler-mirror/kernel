// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_base.h"
#include "mcevf_irq.h"
#include "mcevf_lib.h"

/**
 * mcevf_get_num_local_cpus - Get number of local cpus
 * @dev: pointer to device
 *
 * Return number of local cpus
 */
int mcevf_get_num_local_cpus(struct device *dev)
{
	int node = dev_to_node(dev);

	if (node == NUMA_NO_NODE)
		return cpumask_weight(cpu_online_mask);
	else
		return cpumask_weight(cpumask_of_node(node));
}

/* mcevf_normalize_cpu_count - normalize the cpu count.
 * @num_cpus: number of cpu cores
 *
 * Returns the cpu count limited to a predefined
 * range of [MIN_DEFAULT_VECTORS, MAX_DEFAULT_VECTORS].
 */
int mcevf_normalize_cpu_count(int num_cpus)
{
	if (num_cpus > MAX_DEFAULT_VECTORS)
		num_cpus = MAX_DEFAULT_VECTORS;
	//else if (num_cpus < MIN_DEFAULT_VECTORS)
	//	num_cpus = MIN_DEFAULT_VECTORS;
	return num_cpus;
}

/**
 * mcevf_vsi_set_num_desc - Set number of descriptors for queues on this VSI
 * @vsi: the VSI being configured
 */
static void mcevf_vsi_set_num_desc(struct mcevf_vsi *vsi)
{
	/* A user could change the values of num_[tr]x_desc using ethtool -G,
	 * so keep those values instead of overwriting them with the defaults.
	 */
	if (!vsi->num_rx_desc)
		vsi->num_rx_desc = MCEVF_MAX_NUM_DESC;
	if (!vsi->num_tx_desc)
		vsi->num_tx_desc = MCEVF_MAX_NUM_DESC;
}

static void mcevf_vsi_set_num_qs(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	u16 q_irq_cnt = 0;

	vsi->base_vector = pf->qvec_irq_base;

	q_irq_cnt = pf->num_msix_cnt - pf->num_mbox_irqs - pf->num_rdma_irqs;
	vsi->num_q_vectors = q_irq_cnt;
	vsi->alloc_txq = pf->max_pf_txqs;
	vsi->alloc_rxq = pf->max_pf_rxqs;

	if (vsi->req_txq)
		vsi->num_txq = vsi->req_txq;
	else
		vsi->num_txq = min_t(u16, q_irq_cnt, vsi->alloc_txq);

	/* only 1 Rx queue unless RSS is enabled */
	if (!test_bit(MCEVF_FLAG_RSS_ENA, pf->flags)) {
		vsi->alloc_rxq = 1;
	} else {
		if (vsi->req_rxq)
			vsi->num_rxq = vsi->req_rxq;
		else
			vsi->num_rxq = min_t(u16, q_irq_cnt, vsi->alloc_rxq);
	}
	mcevf_vsi_set_num_desc(vsi);
}

/**
 * mcevf_vsi_alloc_arrays - Allocate queue and vector pointer arrays for the VSI
 * @vsi: VSI pointer
 *
 * On error: returns error code (negative)
 * On success: returns 0
 */
static int mcevf_vsi_alloc_arrays(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	struct device *dev = mcevf_pf_to_dev(pf);

	/* allocate memory for both Tx and Rx ring pointers */
	vsi->tx_rings = devm_kcalloc(dev, vsi->alloc_txq,
				     sizeof(*vsi->tx_rings), GFP_KERNEL);
	if (!vsi->tx_rings)
		return -ENOMEM;

	vsi->rx_rings = devm_kcalloc(dev, vsi->alloc_rxq,
				     sizeof(*vsi->rx_rings), GFP_KERNEL);
	if (!vsi->rx_rings)
		goto err_rings;

	vsi->txq_map = devm_kcalloc(dev, vsi->alloc_txq, sizeof(*vsi->txq_map),
				    GFP_KERNEL);
	if (!vsi->txq_map)
		goto err_txq_map;

	vsi->rxq_map = devm_kcalloc(dev, vsi->alloc_rxq, sizeof(*vsi->rxq_map),
				    GFP_KERNEL);
	if (!vsi->rxq_map)
		goto err_rxq_map;

	/* allocate memory for q_vector pointers */
	vsi->q_vectors = devm_kcalloc(dev, vsi->num_q_vectors,
				      sizeof(*vsi->q_vectors), GFP_KERNEL);
	if (!vsi->q_vectors)
		goto err_vectors;

	return 0;

err_vectors:
	devm_kfree(dev, vsi->rxq_map);
	vsi->rxq_map = NULL;
err_rxq_map:
	devm_kfree(dev, vsi->txq_map);
	vsi->txq_map = NULL;
err_txq_map:
	devm_kfree(dev, vsi->rx_rings);
	vsi->rx_rings = NULL;
err_rings:
	devm_kfree(dev, vsi->tx_rings);
	vsi->tx_rings = NULL;
	return -ENOMEM;
}

/**
 * mcevf_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
irqreturn_t mcevf_msix_clean_rings(int __always_unused irq, void *data)
{
	struct mcevf_q_vector *q_vector = data;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;
	q_vector->total_events++;
	mcevf_disable_vec_txrx_irq(q_vector);
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * mcevf_vsi_alloc_stat_arrays - Allocate statistics arrays
 * @vsi: VSI pointer
 */
static int mcevf_vsi_alloc_stat_arrays(struct mcevf_vsi *vsi)
{
	struct mcevf_vsi_stats *vsi_stat;
	struct mcevf_pf *pf = vsi->back;
	struct device *dev;
	u16 alloc_qps;

	dev = mcevf_pf_to_dev(pf);

	if (!pf->vsi_stats)
		return -ENOENT;

	vsi_stat = devm_kzalloc(dev, sizeof(*vsi_stat), GFP_KERNEL);

	if (!vsi_stat)
		return -ENOMEM;

	alloc_qps = vsi->alloc_txq;

	vsi_stat->tx_ring_stats = devm_kcalloc(dev, alloc_qps,
					       sizeof(*vsi_stat->tx_ring_stats), GFP_KERNEL);

	vsi_stat->rx_ring_stats = devm_kcalloc(dev, alloc_qps,
					       sizeof(*vsi_stat->rx_ring_stats), GFP_KERNEL);

	if (!vsi_stat->tx_ring_stats || !vsi_stat->rx_ring_stats)
		goto err_alloc;

	pf->vsi_stats[vsi->idx] = vsi_stat;

	return 0;

err_alloc:
	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat->tx_ring_stats);
	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat->rx_ring_stats);
	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat);
	return -ENOMEM;
}

/**
 * mcevf_get_free_slot - get the next available free slot in array
 * @array: array to search
 * @size: size of the array
 * @curr: last known occupied index to be used as a search hint
 *
 * void * is being used to keep the functionality generic. This lets us use this
 * function on any array of pointers.
 */
static int mcevf_get_free_slot(void *array, int size, int curr)
{
	int **tmp_array = array;
	int next;

	if (curr < (size - 1) && !tmp_array[curr + 1]) {
		next = curr + 1;
	} else {
		int i = 0;

		while ((i < size) && (tmp_array[i]))
			i++;
		if (i == size)
			next = MCEVF_NO_VSI;
		else
			next = i;
	}
	return next;
}

static struct mcevf_vsi *mcevf_vsi_alloc(struct mcevf_pf *pf)
{
	struct device *dev = mcevf_pf_to_dev(pf);
	struct mcevf_vsi *vsi = NULL;

	mutex_lock(&pf->sw_mutex);

	if (pf->next_vsi == MCEVF_NO_VSI) {
		dev_err(dev, "out of VSI slots!\n");
		goto unlock_pf;
	}

	if (pf->vsi[pf->next_vsi]) {
		dev_err(dev, "VSI slot %u already in use!\n", pf->next_vsi);
		goto unlock_pf;
	}

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi)
		goto unlock_pf;

	vsi->back = pf;
	vsi->idx = pf->next_vsi;
	spin_lock_init(&vsi->stats_lock);

	mcevf_vsi_set_num_qs(vsi);
	if (mcevf_vsi_alloc_arrays(vsi))
		goto err_rings;
	/* Setup default MSIX irq handler for VSI */
	vsi->irq_handler = mcevf_msix_clean_rings;
	/* allocate memory for Tx/Rx ring stat pointers */
	if (mcevf_vsi_alloc_stat_arrays(vsi))
		goto err_rings;

	pf->vsi[vsi->idx] = vsi;
	pf->next_vsi =
		mcevf_get_free_slot(pf->vsi, pf->num_alloc_vsi, pf->next_vsi);

	goto unlock_pf;

err_rings:
	devm_kfree(dev, vsi);
	vsi = NULL;
unlock_pf:
	mutex_unlock(&pf->sw_mutex);
	return vsi;
}

/**
 * mcevf_vsi_free_arrays - De-allocate queue and vector pointer arrays for the VSI
 * @vsi: pointer to VSI being cleared
 */
static void mcevf_vsi_free_arrays(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	struct device *dev;

	dev = mcevf_pf_to_dev(pf);

	/* free the ring and vector containers */
	if (vsi->q_vectors) {
		devm_kfree(dev, vsi->q_vectors);
		vsi->q_vectors = NULL;
	}
	spin_lock_bh(&vsi->stats_lock);
	if (vsi->tx_rings) {
		devm_kfree(dev, vsi->tx_rings);
		vsi->tx_rings = NULL;
	}
	if (vsi->rx_rings) {
		devm_kfree(dev, vsi->rx_rings);
		vsi->rx_rings = NULL;
	}
	spin_unlock_bh(&vsi->stats_lock);
	if (vsi->txq_map) {
		devm_kfree(dev, vsi->txq_map);
		vsi->txq_map = NULL;
	}
	if (vsi->rxq_map) {
		devm_kfree(dev, vsi->rxq_map);
		vsi->rxq_map = NULL;
	}
}

/**
 * mcevf_vsi_clear_rings - Deallocates the Tx and Rx rings for VSI
 * @vsi: the VSI having rings deallocated
 */
static void mcevf_vsi_clear_rings(struct mcevf_vsi *vsi)
{
	int i;

	/* Avoid stale references by clearing map from vector to ring */
	if (vsi->q_vectors) {
		mcevf_for_each_q_vector(vsi, i) {
			struct mcevf_q_vector *q_vector = vsi->q_vectors[i];

			if (q_vector) {
				q_vector->tx.ring = NULL;
				q_vector->rx.ring = NULL;
			}
		}
	}

	if (vsi->tx_rings)
		for (i = 0; i < vsi->alloc_txq; i++)
			mcevf_destroy_txring(vsi, i);
	if (vsi->rx_rings)
		for (i = 0; i < vsi->alloc_rxq; i++)
			mcevf_destroy_rxring(vsi, i);
}

/**
 * mcevf_vsi_alloc_rings - Allocates Tx and Rx rings for the VSI
 * @vsi: VSI which is having rings allocated
 */
static int mcevf_vsi_alloc_rings(struct mcevf_vsi *vsi)
{
	u16 i;

	/* Allocate Tx rings */
	for (i = 0; i < vsi->alloc_txq; i++) {
		if (mcevf_create_txring(vsi, i))
			goto err_out;
	}

	/* Allocate Rx rings */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		if (mcevf_create_rxring(vsi, i))
			goto err_out;
	}

	return 0;

err_out:
	mcevf_vsi_clear_rings(vsi);
	return -ENOMEM;
}

/**
 * mcevf_vsi_free_stats - Free the ring statistics structures
 * @vsi: VSI pointer
 */
static void mcevf_vsi_free_stats(struct mcevf_vsi *vsi)
{
	struct mcevf_vsi_stats *vsi_stat;
	struct mcevf_pf *pf = vsi->back;
	int i;

	if (!pf->vsi_stats)
		return;

	vsi_stat = pf->vsi_stats[vsi->idx];

	if (!vsi_stat)
		return;

	for (i = 0; i < vsi->alloc_txq; i++) {
		if (vsi_stat->tx_ring_stats[i]) {
			kfree_rcu(vsi_stat->tx_ring_stats[i], rcu);
			WRITE_ONCE(vsi_stat->tx_ring_stats[i], NULL);
		}
	}

	for (i = 0; i < vsi->alloc_rxq; i++) {
		if (vsi_stat->rx_ring_stats[i]) {
			kfree_rcu(vsi_stat->rx_ring_stats[i], rcu);
			WRITE_ONCE(vsi_stat->rx_ring_stats[i], NULL);
		}
	}

	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat->tx_ring_stats);
	vsi_stat->tx_ring_stats = NULL;
	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat->rx_ring_stats);
	vsi_stat->rx_ring_stats = NULL;
	devm_kfree(mcevf_pf_to_dev(pf), vsi_stat);
	pf->vsi_stats[vsi->idx] = NULL;
}

/**
 * mcevf_vsi_map_rings_to_vectors - Map VSI rings to interrupt vectors
 * @vsi: the VSI being configured
 *
 * This function maps descriptor rings to the queue-specific vectors allotted
 * through the MSI-X enabling code. On a constrained vector budget, we map Tx
 * and Rx rings to the vector as "efficiently" as possible.
 */
static void mcevf_vsi_map_rings_to_vectors(struct mcevf_vsi *vsi)
{
	int q_vectors = vsi->num_q_vectors;
	u16 tx_rings_rem, rx_rings_rem;
	int v_id;

	/* initially assigning remaining rings count to VSIs num queue value */
	tx_rings_rem = vsi->num_txq;
	rx_rings_rem = vsi->num_rxq;

	for (v_id = 0; v_id < q_vectors; v_id++) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[v_id];
		u8 tx_rings_per_v, rx_rings_per_v;
		u16 q_id, q_base;

		/* Tx rings mapping to vector */
		tx_rings_per_v =
			(u8)DIV_ROUND_UP(tx_rings_rem, q_vectors - v_id);
		q_vector->num_ring_tx = tx_rings_per_v;
		q_vector->tx.ring = NULL;
		q_base = vsi->num_txq - tx_rings_rem;

		for (q_id = q_base; q_id < (q_base + tx_rings_per_v); q_id++) {
			struct mcevf_ring *tx_ring = vsi->tx_rings[q_id];

			if (tx_ring) {
				tx_ring->q_vector = q_vector;
				tx_ring->next = q_vector->tx.ring;
				q_vector->tx.ring = tx_ring;
			} else {
				dev_err(mcevf_pf_to_dev(vsi->back),
					"NULL Tx ring found\n");
				break;
			}
		}
		tx_rings_rem -= tx_rings_per_v;

		/* Rx rings mapping to vector */
		rx_rings_per_v =
			(u8)DIV_ROUND_UP(rx_rings_rem, q_vectors - v_id);
		q_vector->num_ring_rx = rx_rings_per_v;
		q_vector->rx.ring = NULL;
		q_base = vsi->num_rxq - rx_rings_rem;

		for (q_id = q_base; q_id < (q_base + rx_rings_per_v); q_id++) {
			struct mcevf_ring *rx_ring = vsi->rx_rings[q_id];

			if (rx_ring) {
				rx_ring->q_vector = q_vector;
				rx_ring->next = q_vector->rx.ring;
				q_vector->rx.ring = rx_ring;
			} else {
				dev_err(mcevf_pf_to_dev(vsi->back),
					"NULL Rx ring found\n");
				break;
			}
		}
		rx_rings_rem -= rx_rings_per_v;
	}
}

/**
 * mcevf_vsi_alloc_ring_stats - Allocates Tx and Rx ring stats for the VSI
 * @vsi: VSI which is having stats allocated
 */
static int mcevf_vsi_alloc_ring_stats(struct mcevf_vsi *vsi)
{
	struct mcevf_ring_stats **tx_ring_stats;
	struct mcevf_ring_stats **rx_ring_stats;
	struct mcevf_vsi_stats *vsi_stats;
	struct mcevf_pf *pf = vsi->back;
	u16 i;

	if (!pf->vsi_stats)
		return -ENOENT;

	vsi_stats = pf->vsi_stats[vsi->idx];

	if (!vsi_stats) {
		dev_err(&pf->pdev->dev, "vsi_stats is NULL\n");
		return -ENOENT;
	}

	tx_ring_stats = vsi_stats->tx_ring_stats;

	if (!tx_ring_stats) {
		dev_err(&pf->pdev->dev, "tx_ring_stats is NULL\n");
		return -ENOENT;
	}

	rx_ring_stats = vsi_stats->rx_ring_stats;

	if (!rx_ring_stats) {
		dev_err(&pf->pdev->dev, "rx_ring_stats is NULL\n");
		return -ENOENT;
	}

	/* Allocate Tx ring stats */
	for (i = 0; i < vsi->alloc_txq; i++) {
		struct mcevf_ring_stats *ring_stats;
		struct mcevf_ring *ring;

		ring = vsi->tx_rings[i];
		ring_stats = tx_ring_stats[i];

		if (!ring_stats) {
			ring_stats = kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(tx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	/* Allocate Rx ring stats */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		struct mcevf_ring_stats *ring_stats;
		struct mcevf_ring *ring;

		ring = vsi->rx_rings[i];
		ring_stats = rx_ring_stats[i];

		if (!ring_stats) {
			ring_stats = kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(rx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	return 0;

err_out:
	mcevf_vsi_free_stats(vsi);
	return -ENOMEM;
}

/**
 * mcevf_vsi_clear - clean up and deallocate the provided VSI
 * @vsi: pointer to VSI being cleared
 *
 * This deallocates the VSI's queue resources, removes it from the PF's
 * VSI array if necessary, and deallocates the VSI
 *
 * Returns 0 on success, negative on failure
 */
static int mcevf_vsi_clear(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = NULL;
	struct device *dev;

	if (!vsi)
		return 0;

	if (!vsi->back)
		return -EINVAL;

	pf = vsi->back;
	dev = mcevf_pf_to_dev(pf);

	if (!pf->vsi[vsi->idx] || pf->vsi[vsi->idx] != vsi) {
		dev_dbg(dev, "vsi does not exist at pf->vsi[%d]\n", vsi->idx);
		return -EINVAL;
	}

	mutex_lock(&pf->sw_mutex);
	/* updates the PF for this cleared VSI */

	pf->vsi[vsi->idx] = NULL;
	if (vsi->idx < pf->next_vsi)
		pf->next_vsi = vsi->idx;

	mcevf_vsi_free_arrays(vsi);
	mutex_unlock(&pf->sw_mutex);
	devm_kfree(dev, vsi);

	return 0;
}

int mcevf_free_irq_res(struct mcevf_res_tracker *res, u16 needed, u16 start)
{
	u16 i = start;

	if (!res || needed >= res->end || start > res->end ||
	    start + needed > res->end)
		return -EINVAL;

	while (needed--)
		res->list[i++] = 0;

	return 0;
}

int mcevf_get_irq_res(struct mcevf_pf *pf, struct mcevf_res_tracker *res,
		      u16 needed, u16 start)
{
	u16 end = 0;

	if (!res || !pf)
		return -EINVAL;

	if (!needed || needed > res->num_entries) {
		dev_err(mcevf_pf_to_dev(pf),
			"param err: needed=%d, num_entries = %d\n", needed,
			res->num_entries);
		return -EINVAL;
	}
	if (needed > res->end || start > res->end || start + needed > res->end)
		return -ENOMEM;
	do {
		/* skip already allocated entries */
		if (res->list[end++] & MCEVF_RES_VALID_BIT) {
			start = end;
			if ((start + needed) > res->end)
				break;
		}

		if (end == (start + needed)) {
			int i = start;

			/* there was enough, so assign it to the requester */
			while (i != end)
				res->list[i++] = MCEVF_RES_VALID_BIT;

			return 0;
		}
	} while (end < res->end);
	return -ENOMEM;
}

static int mcevf_vsi_alloc_q_irq_res(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	u16 need_cnt = vsi->num_q_vectors;
	u16 start_id = vsi->base_vector;
	int ret = 0;

	ret = mcevf_get_irq_res(pf, pf->irq_tracker, need_cnt, start_id);
	if (ret == 0)
		pf->num_avail_msix -= need_cnt;

	return ret;
}

static void mcevf_vsi_free_q_irq_res(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	u16 need_cnt = vsi->num_q_vectors;
	u16 start_id = vsi->base_vector;
	int ret = 0;

	ret = mcevf_free_irq_res(pf->irq_tracker, need_cnt, start_id);
	if (ret)
		dev_err(mcevf_pf_to_dev(pf), "free_q_irq_res err\n");
	else
		pf->num_avail_msix += need_cnt;
}

/**
 * mcevf_vsi_cfg_qvec_irq - assign irq_vector to ring
 * @vsi: VSI being configured
 */
static void mcevf_vsi_cfg_qvec_irq(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw = &pf->hw;
	struct mcevf_q_vector *q_vector = NULL;
	struct mcevf_ring *tx_ring = NULL;
	struct mcevf_ring *rx_ring = NULL;
	u16 qvec_base = vsi->base_vector;
	int i = 0, j = 0;

	mcevf_for_each_q_vector(vsi, i) {
		q_vector = vsi->q_vectors[i];
		j = q_vector->v_idx;

		mcevf_rc_for_each_ring(tx_ring, q_vector->tx) {
			if (!tx_ring)
				continue;

			hw->ops->cfg_vec2tqirq(hw,
					       tx_ring->q_index + hw->ring_base_addr,
					       j + qvec_base);
		}

		mcevf_rc_for_each_ring(rx_ring, q_vector->rx) {
			if (!rx_ring)
				continue;

			hw->ops->cfg_vec2rqirq(hw,
					       rx_ring->q_index + hw->ring_base_addr,
					       j + qvec_base);
		}
	}
}

struct mcevf_vsi *mcevf_vsi_setup(struct mcevf_pf *pf)
{
	struct device *dev = mcevf_pf_to_dev(pf);
	struct mcevf_vsi *vsi = NULL;
	struct mcevf_hw *hw = &pf->hw;
	int ret = 0;

	vsi = mcevf_vsi_alloc(pf);
	if (!vsi) {
		dev_err(dev, "could not allocate VSI\n");
		return NULL;
	}
	/* force vsi down, maybe NetworkManager is off */
	set_bit(MCEVF_VSI_DOWN, vsi->state);
	vsi->port_info = hw->port_info;

	ret = mcevf_vsi_alloc_q_vectors(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc q_vectors\n");
		goto unroll_vsi_alloc;
	}

	ret = mcevf_vsi_alloc_q_irq_res(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc vector irq res\n");
		goto unroll_alloc_q_vector;
	}

	ret = mcevf_vsi_alloc_rings(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc rings\n");
		goto unroll_vector_base;
	}

	mcevf_vsi_map_rings_to_vectors(vsi);
	mcevf_vsi_cfg_qvec_irq(vsi);
	ret = mcevf_vsi_alloc_ring_stats(vsi);
	if (ret) {
		dev_err(dev, "VSI failed to alloc rings stats\n");
		goto unroll_clear_rings;
	}

	return vsi;

unroll_clear_rings:
	mcevf_vsi_clear_rings(vsi);
unroll_vector_base:
	/* reclaim SW interrupts back to the common pool */
	mcevf_vsi_free_q_irq_res(vsi);
unroll_alloc_q_vector:
	mcevf_vsi_free_q_vectors(vsi);
	mcevf_vsi_free_stats(vsi);
unroll_vsi_alloc:
	mcevf_vsi_clear(vsi);

	return NULL;
}

/**
 * mcevf_vsi_cfg_frame_size - setup max frame size and Rx buffer length
 * @vsi: VSI
 */
void mcevf_vsi_cfg_frame_size(struct mcevf_vsi *vsi)
{
	if (!vsi->netdev || test_bit(MCEVF_FLAG_LEGACY_RX, vsi->back->flags)) {
		vsi->max_frame = MCEVF_ETH_DFT_FRAME_MAX_LEN;
		vsi->rx_buf_len = MCEVF_RXBUF_2048;
#if (PAGE_SIZE < 8192)
	} else if (!MCEVF_2K_TOO_SMALL_WITH_PADDING &&
		   (vsi->netdev->mtu <= ETH_DATA_LEN)) {
		vsi->max_frame = MCEVF_RXBUF_1536 - NET_IP_ALIGN;
		vsi->rx_buf_len = MCEVF_RXBUF_1536 - NET_IP_ALIGN;
#endif
	} else {
		int scatter_len;

		vsi->max_frame = MCEVF_ETH_DFT_FRAME_MAX_LEN;
#if (PAGE_SIZE < 8192)
		// scatter_len = MCE_RXBUF_1536 - NET_IP_ALIGN;
		scatter_len = MCEVF_RXBUF_3072;
#else
		scatter_len =
			SKB_WITH_OVERHEAD(PAGE_SIZE) - MCEVF_SKB_PAD(vsi->back);
		scatter_len = min_t(int, scatter_len,
				    vsi->netdev->mtu + MCEVF_ETH_PKT_HDR_PAD);
		scatter_len = min_t(int, round_up(scatter_len, 64),
				    MCEVF_DMA_RING_RX_SCATTER_MAX_LEN);
#endif
		vsi->rx_buf_len = scatter_len;
	}
}

/**
 * mcevf_vsi_free_irq - Free the IRQ association with the OS
 * @vsi: the VSI being configured
 */
static void mcevf_vsi_free_irq(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf = vsi->back;
	int base = vsi->base_vector;
	int i;

	if (!vsi->q_vectors || !vsi->irqs_ready)
		return;

	vsi->irqs_ready = false;

	mcevf_for_each_q_vector(vsi, i) {
		u16 vector = i + base;
		int irq_num;

		irq_num = mcevf_get_irq_num(pf, vector);

		/* free only the irqs that were actually requested */
		if (!vsi->q_vectors[i] || !(vsi->q_vectors[i]->num_ring_tx ||
					    vsi->q_vectors[i]->num_ring_rx))
			continue;

		/* clear the affinity notifier in the IRQ descriptor */
		// if (!IS_ENABLED(CONFIG_RFS_ACCEL))
		if (1)
			irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);

		/* clear the affinity_mask in the IRQ descriptor */
		synchronize_irq(irq_num);
		devm_free_irq(mcevf_pf_to_dev(pf), irq_num, vsi->q_vectors[i]);
	}
}

/**
 * mcevf_vsi_dis_irq - Mask off queue interrupt generation on the VSI
 * @vsi: the VSI being un-configured
 */
static void mcevf_vsi_dis_irq(struct mcevf_vsi *vsi)
{
	int base = vsi->base_vector;
	int i;

	/* disable each interrupt */
	mcevf_for_each_q_vector(vsi, i) {
		if (!vsi->q_vectors[i])
			continue;

		mcevf_disable_vec_txrx_irq(vsi->q_vectors[i]);
	}

	/* don't call synchronize_irq() for VF's from the host */
	mcevf_for_each_q_vector(vsi, i)
		synchronize_irq(mcevf_get_irq_num(vsi->back, i + base));
}

/**
 * mcevf_vsi_stop_lan_tx_rings - Disable Tx rings
 * @vsi: the VSI being configured
 */
static int mcevf_vsi_stop_lan_tx_rings(struct mcevf_vsi *vsi)
{
	u16 q_idx;

	mcevf_for_each_txq(vsi, q_idx) {
		mcevf_stop_tx_ring(vsi->tx_rings[q_idx]);
	}

	return 0;
}

/**
 * mcevf_vsi_stop_all_rx_rings - stop/disable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be disabled
 *
 * Returns 0 on success and a negative value on error
 */
static int mcevf_vsi_stop_all_rx_rings(struct mcevf_vsi *vsi)
{
	u16 q_idx;

	mcevf_for_each_rxq(vsi, q_idx)
		mcevf_stop_rx_ring(vsi->rx_rings[q_idx]);

	return 0;
}

/**
 * mcevf_napi_disable_all - Disable NAPI for all q_vectors in the VSI
 * @vsi: VSI having NAPI disabled
 */
static void mcevf_napi_disable_all(struct mcevf_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	mcevf_for_each_q_vector(vsi, q_idx) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_disable(&q_vector->napi);
		cancel_work_sync(&q_vector->tx.dim.work);
		cancel_work_sync(&q_vector->rx.dim.work);
	}
}

/**
 * mcevf_down - Shutdown the connection
 * @vsi: The VSI being stopped
 *
 * Caller of this function is expected to set the vsi->state MCEVF_DOWN bit
 */
int mcevf_down(struct mcevf_vsi *vsi)
{
	int link_err = 0, vlan_err = 0;
	int i, tx_err, rx_err;

	WARN_ON(!test_bit(MCEVF_VSI_DOWN, vsi->state));

	netif_carrier_off(vsi->netdev);
	netif_tx_disable(vsi->netdev);

	mcevf_vsi_dis_irq(vsi);

	tx_err = mcevf_vsi_stop_lan_tx_rings(vsi);
	if (tx_err)
		netdev_err(vsi->netdev,
			   "Failed stop Tx rings, VSI %d error %d\n", vsi->idx,
			   tx_err);

	rx_err = mcevf_vsi_stop_all_rx_rings(vsi);
	if (rx_err)
		netdev_err(vsi->netdev,
			   "Failed stop Rx rings, VSI %d error %d\n", vsi->idx,
			   rx_err);

	mcevf_napi_disable_all(vsi);

	mcevf_for_each_txq(vsi, i)
		mcevf_clean_tx_ring(vsi->tx_rings[i]);

	mcevf_for_each_rxq(vsi, i)
		mcevf_clean_rx_ring(vsi->rx_rings[i]);

	if (tx_err || rx_err || link_err || vlan_err) {
		netdev_err(vsi->netdev, "Failed to close VSI 0x%04X\n",
			   vsi->idx);
		return -EIO;
	}

	return 0;
}

/**
 * mcevf_vsi_close - Shut down a VSI
 * @vsi: the VSI being shut down
 */
void mcevf_vsi_close(struct mcevf_vsi *vsi)
{
	struct mcevf_hw *hw = &vsi->back->hw;

	if (!test_and_set_bit(MCEVF_VSI_DOWN, vsi->state))
		mcevf_down(vsi);
	hw->ops->init_vport_hw_attr(hw, false);

	mcevf_vsi_free_irq(vsi);
	mcevf_vsi_free_tx_rings(vsi);
	mcevf_vsi_free_rx_rings(vsi);
}

/**
 * mcevf_vsi_release - Delete a VSI and free its resources
 * @vsi: the VSI being removed
 *
 * Returns 0 on success or < 0 on error
 */
int mcevf_vsi_release(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf;

	if (!vsi->back)
		return -ENODEV;
	pf = vsi->back;

	/* Do not unregister while driver is in the reset recovery pending state.
	 * Since reset/rebuild happens through the PF service task workqueue, it
	 * is not a good idea to unregister a netdev associated with the PF that
	 * is running the work queue items. This avoids a
	 * check_flush_dependency() warning on this workqueue.
	 */
	if (vsi->netdev &&
	    (test_bit(MCEVF_VSI_NETDEV_REGISTERED, vsi->state))) {
		unregister_netdev(vsi->netdev);
		clear_bit(MCEVF_VSI_NETDEV_REGISTERED, vsi->state);
	}

	/* Disable VSI and free resources */
	//mcevf_vsi_close(vsi);

	/* reclaim SW interrupts back to the common pool */
	/* reclaim SW interrupts back to the common pool */
	mcevf_free_irq_res(pf->irq_tracker, vsi->num_q_vectors,
			   vsi->base_vector);
	pf->num_avail_msix += vsi->num_q_vectors;

	mcevf_vsi_free_q_vectors(vsi);

	if (vsi->netdev) {
		if (test_bit(MCEVF_VSI_NETDEV_REGISTERED, vsi->state)) {
			unregister_netdev(vsi->netdev);
			clear_bit(MCEVF_VSI_NETDEV_REGISTERED, vsi->state);
		}
		if (test_bit(MCEVF_VSI_NETDEV_ALLOCD, vsi->state)) {
			free_netdev(vsi->netdev);
			vsi->netdev = NULL;
			clear_bit(MCEVF_VSI_NETDEV_ALLOCD, vsi->state);
		}
	}

	mcevf_vsi_clear_rings(vsi);
	mcevf_vsi_free_stats(vsi);

	mcevf_vsi_clear(vsi);

	return 0;
}

/**
 * mcevf_vsi_release_all - Delete all VSIs
 * @pf: PF from which all VSIs are being removed
 */
void mcevf_vsi_release_all(struct mcevf_pf *pf)
{
	int err, i;

	if (!pf->vsi)
		return;

	mcevf_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;

		err = mcevf_vsi_release(pf->vsi[i]);
		if (err) {
			dev_dbg(mcevf_pf_to_dev(pf),
				"Failed to release pf->vsi[%d], err %d, idx = %d\n",
				i, err, pf->vsi[i]->idx);
		} else {
			pf->vsi[i] = NULL;
		}
	}
}

/**
 * mcevf_vsi_free_tx_rings - Free Tx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void mcevf_vsi_free_tx_rings(struct mcevf_vsi *vsi)
{
	int i;

	if (!vsi->tx_rings)
		return;

	mcevf_for_each_txq(vsi, i)
		if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc)
			mcevf_free_tx_ring(vsi->tx_rings[i]);
}

/**
 * mcevf_vsi_free_rx_rings - Free Rx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void mcevf_vsi_free_rx_rings(struct mcevf_vsi *vsi)
{
	int i;

	if (!vsi->rx_rings)
		return;

	mcevf_for_each_rxq(vsi, i)
		if (vsi->rx_rings[i] && vsi->rx_rings[i]->desc)
			mcevf_free_rx_ring(vsi->rx_rings[i]);
}

/**
 * mcevf_vsi_ena_irq - Enable IRQ for the given VSI
 * @vsi: the VSI being configured
 */
static void mcevf_vsi_ena_irq(struct mcevf_vsi *vsi)
{
	int i;

	mcevf_for_each_q_vector(vsi, i) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[i];

		mcevf_enable_vec_txrx_irq(q_vector);
	}
}

static void mcevf_tx_dim_work(struct work_struct *work)
{
	struct mcevf_ring_container *rc;
	struct dim *dim;
	struct mcevf_hw *hw = NULL;
	struct mcevf_ring *tx_ring;
	struct dim_cq_moder cur_moder;

	dim = container_of(work, struct dim, work);
	rc = (struct mcevf_ring_container *)dim->priv;
	hw = &rc->ring->vsi->back->hw;

	cur_moder = net_dim_get_tx_moderation(dim->mode, dim->profile_ix);

	mcevf_rc_for_each_ring(tx_ring, (*rc)) {
		tx_ring->q_vector->tx.dim_params.usecs = cur_moder.usec;
		tx_ring->q_vector->tx.dim_params.frames = cur_moder.pkts;
		hw->ops->set_txring_intr_coal(tx_ring);
	}

	dim->state = DIM_START_MEASURE;
}

static void mcevf_rx_dim_work(struct work_struct *work)
{
	struct mcevf_ring_container *rc;
	struct dim *dim;
	struct mcevf_hw *hw = NULL;
	struct mcevf_ring *rx_ring;
	struct dim_cq_moder cur_moder;

	dim = container_of(work, struct dim, work);
	rc = (struct mcevf_ring_container *)dim->priv;
	hw = &rc->ring->vsi->back->hw;

	cur_moder = net_dim_get_rx_moderation(dim->mode, dim->profile_ix);

	mcevf_rc_for_each_ring(rx_ring, (*rc)) {
		rx_ring->q_vector->rx.dim_params.frames = cur_moder.pkts;
		rx_ring->q_vector->rx.dim_params.usecs = cur_moder.usec;
		hw->ops->set_rxring_intr_coal(rx_ring);
	}

	dim->state = DIM_START_MEASURE;
}

static void mcevf_init_moderation(struct mcevf_q_vector *q_vector)
{
	struct mcevf_ring_container *rc;

	rc = &q_vector->tx;
	rc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	rc->dim.profile_ix = 0;
	rc->dim.priv = rc;
	INIT_WORK(&rc->dim.work, mcevf_tx_dim_work);

	rc = &q_vector->rx;
	rc->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_CQE;
	rc->dim.profile_ix = 0;
	rc->dim.priv = rc;
	INIT_WORK(&rc->dim.work, mcevf_rx_dim_work);
}

/**
 * mcevf_napi_enable - Enable NAPI for a single q_vector of a VSI
 * @q_vector: a queue interrupt vector being configured
 */
static void mcevf_napi_enable(struct mcevf_q_vector *q_vector)
{
	mcevf_init_moderation(q_vector);
	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_enable(&q_vector->napi);
}

/**
 * mcevf_napi_enable_all - Enable NAPI for all q_vectors in the VSI
 * @vsi: the VSI being configured
 */
static void mcevf_napi_enable_all(struct mcevf_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	mcevf_for_each_q_vector(vsi, v_idx)
		mcevf_napi_enable(vsi->q_vectors[v_idx]);
}

static int mcevf_vsi_update_hw(struct mcevf_vsi *vsi)
{
	struct mcevf_hw *hw = &vsi->back->hw;
	struct net_device *netdev = vsi->netdev;
	netdev_features_t features = netdev->features;
	int err = 0;

	err = hw->ops->set_unicast_addr(hw, hw->mac.addr);
	if (err) {
		netdev_err(netdev, "Failed to update mac addr");
		return err;
	}

	hw->ops->init_vport_hw_attr(hw, true);

	hw->ops->set_rx_csumofld(hw, features);
	hw->ops->set_vlan_strip(hw, features);
	hw->ops->set_vlan_filter(hw, features);
	hw->ops->set_rss_key(hw);
	hw->ops->set_rss_table(hw, vsi->num_rxq);
	hw->ops->set_rss_hash_type(hw);
	hw->ops->set_rss_hash(hw, features);
	hw->ops->set_max_pktlen(hw, netdev->mtu);

	return err;
}

static int mcevf_clear_hw_ring_stats(struct mcevf_vsi *vsi)
{
	struct mcevf_hw *hw = &vsi->back->hw;

	hw->ops->clear_hw_ring_stats(hw);
	return 0;
}

/**
 * mcevf_up_complete - Finish the last steps of bringing up a connection
 * @vsi: The VSI being configured
 *
 * Return 0 on success and negative value on error
 */
static int mcevf_up_complete(struct mcevf_vsi *vsi)
{
	mcevf_vsi_start_all_tx_rings(vsi);
	mcevf_vsi_start_all_rx_rings(vsi);

	clear_bit(MCEVF_VSI_DOWN, vsi->state);
	mcevf_napi_enable_all(vsi);
	mcevf_vsi_ena_irq(vsi);

	mcevf_vsi_update_hw(vsi);

	mcevf_clear_hw_ring_stats(vsi);
	set_bit(MCEVF_FLAG_PF_UPDATE_LINK, vsi->back->flags);
	mcevf_service_task_schedule(vsi->back);
	return 0;
}

/**
 * mcevf_vsi_open - Called when a network interface is made active
 * @vsi: the VSI to open
 *
 * Initialization of the VSI
 *
 * Returns 0 on success, negative value on error
 */
int mcevf_vsi_open(struct mcevf_vsi *vsi)
{
	char int_name[MCEVF_INT_NAME_STR_LEN];
	struct mcevf_pf *pf = vsi->back;
	int err;

	/* allocate descriptors */
	err = mcevf_vsi_setup_tx_rings(vsi);
	if (err)
		goto err_setup_tx;

	err = mcevf_vsi_setup_rx_rings(vsi);
	if (err)
		goto err_setup_rx;

	err = mcevf_vsi_cfg(vsi);
	if (err)
		goto err_setup_rx;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
		 dev_driver_string(mcevf_pf_to_dev(pf)), vsi->netdev->name);
	err = mcevf_vsi_req_irq_msix(vsi, int_name);
	if (err)
		goto err_setup_rx;

	/* Notify the stack of the actual queue counts. */
	err = netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
	if (err)
		goto err_set_qs;

	err = netif_set_real_num_rx_queues(vsi->netdev, vsi->num_rxq);
	if (err)
		goto err_set_qs;

	err = mcevf_up_complete(vsi);
	if (err)
		goto err_up_complete;
	return 0;

err_up_complete:
	mcevf_down(vsi);
err_set_qs:
	mcevf_vsi_free_irq(vsi);
err_setup_rx:
	mcevf_vsi_free_rx_rings(vsi);
err_setup_tx:
	mcevf_vsi_free_tx_rings(vsi);

	return err;
}

/**
 * mcevf_up - Bring the connection back up after being down
 * @vsi: VSI being configured
 */
int mcevf_up(struct mcevf_vsi *vsi)
{
	int err;

	err = mcevf_vsi_cfg(vsi);
	if (!err)
		err = mcevf_up_complete(vsi);

	return err;
}

/**
 * mcevf_vsi_get_q_vector_q_base - get vector's base numbers of Tx and Rx queues
 * @vsi: related VSI
 * @vector_id: index of the vector in VSI
 * @txq: pointer to a return value of Tx base queue number
 * @rxq: pointer to a return value of Rx base queue number
 */
void mcevf_vsi_get_q_vector_q_base(struct mcevf_vsi *vsi, u16 vector_id,
				   u16 *txq, u16 *rxq)
{
	int i;

	*txq = 0;
	*rxq = 0;

	for (i = 0; i < vector_id; i++) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[i];

		*txq += q_vector->num_ring_tx;
		*rxq += q_vector->num_ring_rx;
	}
}

/**
 * mcevf_update_ring_stats - Update ring statistics
 * @ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void mcevf_update_ring_stats(struct mcevf_ring *ring, u64 pkts,
				    u64 bytes)
{
	ring->ring_stats->stats.bytes += bytes;
	ring->ring_stats->stats.pkts += pkts;
}

/**
 * mcevf_update_tx_ring_stats - Update Tx ring specific counters
 * @tx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void mcevf_update_tx_ring_stats(struct mcevf_ring *tx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&tx_ring->ring_stats->syncp);
	mcevf_update_ring_stats(tx_ring, pkts, bytes);
	u64_stats_update_end(&tx_ring->ring_stats->syncp);
}

/**
 * mcevf_update_rx_ring_stats - Update Rx ring specific counters
 * @rx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void mcevf_update_rx_ring_stats(struct mcevf_ring *rx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&rx_ring->ring_stats->syncp);
	mcevf_update_ring_stats(rx_ring, pkts, bytes);
	u64_stats_update_end(&rx_ring->ring_stats->syncp);
}

static void mcevf_reinit_rss_table(struct mcevf_pf *pf)
{
	/* reset rss table when rebuild */
	clear_bit(MCEVF_FLAG_RSS_TBL_INITED, pf->flags);
}

/**
 * mcevf_vsi_rebuild - Rebuild VSI after reset
 * @vsi: VSI to be rebuild
 *
 * Returns 0 on success and negative value on failure
 */
int mcevf_vsi_rebuild(struct mcevf_vsi *vsi)
{
	struct mcevf_pf *pf;
	int ret;

	if (!vsi)
		return -EINVAL;

	pf = vsi->back;

	mcevf_vsi_free_q_vectors(vsi);
	mcevf_vsi_free_q_irq_res(vsi);

	mcevf_vsi_clear_rings(vsi);
	mcevf_vsi_free_arrays(vsi);
	mcevf_vsi_set_num_qs(vsi);

	ret = mcevf_vsi_alloc_arrays(vsi);
	if (ret < 0)
		goto err_vsi_alloc_arrays;

	ret = mcevf_vsi_alloc_q_vectors(vsi);
	if (ret)
		goto err_vsi_alloc_q_vectors;

	ret = mcevf_vsi_alloc_q_irq_res(vsi);
	if (ret)
		goto err_vsi_alloc_q_irq_res;

	ret = mcevf_vsi_alloc_rings(vsi);
	if (ret)
		goto err_vsi_alloc_rings;

	mcevf_vsi_map_rings_to_vectors(vsi);

	ret = mcevf_vsi_alloc_ring_stats(vsi);
	if (ret)
		goto err_vsi_alloc_ring_stats;
	mcevf_reinit_rss_table(pf);
	return 0;

err_vsi_alloc_ring_stats:
	mcevf_vsi_clear_rings(vsi);
err_vsi_alloc_rings:
	mcevf_vsi_free_q_irq_res(vsi);
err_vsi_alloc_q_irq_res:
	mcevf_vsi_free_q_vectors(vsi);
err_vsi_alloc_q_vectors:
	mcevf_vsi_free_arrays(vsi);
err_vsi_alloc_arrays:
	set_bit(MCEVF_RESET_FAILED, pf->state);
	return ret;
}

static int __mcevf_get_valid_rss_size(struct mcevf_pf *pf, int new_size)
{
	return min_t(int, new_size, pf->max_pf_rxqs);
}

/**
 * mcevf_vsi_set_dflt_rss_lut - set default RSS LUT with requested RSS size
 * @vsi: VSI to reconfigure RSS LUT on
 * @req_rss_size: requested range of queue numbers for hashing
 *
 * Set the VSI's RSS parameters, configure the RSS LUT based on these.
 */
int mcevf_vsi_set_dflt_rss_lut(struct mcevf_vsi *vsi, int req_rss_size)
{
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_hw *hw;
	int rss_size = 1;

	hw = &pf->hw;

	if (!req_rss_size)
		return -EINVAL;

	if (!test_bit(MCEVF_FLAG_RSS_ENA, pf->flags))
		rss_size = 1;
	else
		rss_size = __mcevf_get_valid_rss_size(pf, req_rss_size);

	hw->ops->set_rss_table(hw, rss_size);

	return 0;
}

int mcevf_mbx_handle_pf_vlan(struct mcevf_hw *hw, u32 vtag)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	struct net_device *netdev = mcevf_hw_to_netdev(hw);

	MCEVF_SET_USED(netdev);
	if (!!vtag)
		set_bit(MCEVF_FLAG_PF_SET_VLAN, pf->flags);
	else
		clear_bit(MCEVF_FLAG_PF_SET_VLAN, pf->flags);
	return 0;
}

void mcevf_pf_flags_reset_set(struct mcevf_pf *pf)
{
	set_bit(MCEVF_FLAG_FORCE_CLOSE, pf->flags);
	set_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
}

bool mcevf_pf_flags_reset_get(struct mcevf_pf *pf)
{
	return test_bit(MCEVF_FLAG_FORCE_CLOSE, pf->flags) ||
	       test_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
}
