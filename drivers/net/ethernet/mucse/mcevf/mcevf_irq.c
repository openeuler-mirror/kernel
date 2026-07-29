// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_lib.h"
#include "mcevf_irq.h"

static void __mcevf_update_dim(u16 total_events, u64 packets, u64 bytes,
			       struct dim *dim)
{
	struct dim_sample dim_sample = {};

	dim_update_sample(total_events, packets, bytes, &dim_sample);
	dim_sample.comp_ctr = 0;

	/* if dim settings get stale, like when not updated for 1
	 * second or longer, force it to start again. This addresses the
	 * frequent case of an idle queue being switched to by the
	 * scheduler. The 1,000 here means 1,000 milliseconds.
	 */
	if (ktime_to_ms(ktime_sub(dim_sample.time, dim->start_sample.time)) >= 1000)
		dim->state = DIM_START_MEASURE;

	net_dim(dim, dim_sample);
}

/**
 * mcevf_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void mcevf_net_dim(struct mcevf_q_vector *q_vector)
{
	struct mcevf_ring_container *tx = &q_vector->tx;
	struct mcevf_ring_container *rx = &q_vector->rx;

	if (ITR_IS_SW_DYNAMIC(tx)) {
		u64 packets = 0, bytes = 0;
		struct mcevf_ring *tx_ring;

		mcevf_rc_for_each_ring(tx_ring, q_vector->tx) {
			packets += tx_ring->ring_stats->stats.pkts;
			bytes += tx_ring->ring_stats->stats.bytes;
		}

		__mcevf_update_dim(q_vector->total_events, packets, bytes,
				   &tx->dim);
	}

	if (ITR_IS_SW_DYNAMIC(rx)) {
		u64 packets = 0, bytes = 0;
		struct mcevf_ring *rx_ring;

		mcevf_rc_for_each_ring(rx_ring, q_vector->rx) {
			packets += rx_ring->ring_stats->stats.pkts;
			bytes += rx_ring->ring_stats->stats.bytes;
		}
		__mcevf_update_dim(q_vector->total_events, packets, bytes,
				   &rx->dim);
	}
}

/**
 * mcevf_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 */
int mcevf_napi_poll(struct napi_struct *napi, int budget)
{
	struct mcevf_q_vector *q_vector =
		container_of(napi, struct mcevf_q_vector, napi);
	struct mcevf_ring *ring;
	bool clean_complete = true;
	int budget_per_ring = 0;
	int work_done = 0;

	q_vector->ticks++;
	/* Since the actual Tx work is minimal, we can give the Tx a larger
	 * budget and be more aggressive about cleaning up the Tx descriptors.
	 */
	mcevf_for_each_ring(ring, q_vector->tx) {
		clean_complete = mcevf_clean_tx_irq(ring, budget);
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

	mcevf_for_each_ring(ring, q_vector->rx) {
		int cleaned;

		cleaned = mcevf_clean_rx_irq(ring, budget_per_ring);
		work_done += cleaned;
		if (cleaned >= budget_per_ring)
			clean_complete = false;
	}

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
		int cpu_id = smp_processor_id();

		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			/* Tell napi that we are done polling */
			napi_complete_done(napi, work_done);
			/* Force an interrupt */
			mcevf_for_each_ring(ring, q_vector->tx) {
				struct mcevf_vsi *vsi = ring->vsi;
				struct mcevf_hw *hw = &vsi->back->hw;

				hw->ops->set_txring_trig_intr(ring);
				hw_logd(LOG_QUEUE_INFO,
					"cpuid:%d change irq affinity\n",
					cpu_id);
			}
			/* Return budget-1 so that polling stops */
			return budget - 1;
		}
		/* Update DIM while NAPI stays scheduled under sustained load. */
		mcevf_net_dim(q_vector);
		return budget;
	}

	/* Work is done so exit the polling mode and re-enable the interrupt */
	if (likely(napi_complete_done(napi, work_done))) {
		mcevf_net_dim(q_vector);
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is TRUE, enable device interrupt
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
		mcevf_enable_vec_txrx_irq(q_vector);
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * mcevf_get_irq_num - get system irq number based on index from driver
 * @pf: board private structure
 * @idx: driver irq index
 */
int mcevf_get_irq_num(struct mcevf_pf *pf, int idx)
{
	return pci_irq_vector(pf->pdev, idx);
}

static int mcevf_alloc_and_fill_msix_entries(struct mcevf_pf *pf, int nvec)
{
	int i;

	pf->msix_entries = kcalloc(nvec, sizeof(*pf->msix_entries), GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < nvec; i++) {
		pf->msix_entries[i].entry = i;
		pf->msix_entries[i].vector = mcevf_get_irq_num(pf, i);
	}

	return 0;
}

static int mcevf_ena_msix(struct mcevf_pf *pf, int nvec)
{
	return pci_alloc_irq_vectors(pf->pdev, MCEVF_MIN_MSIX, nvec,
				     PCI_IRQ_MSIX);
}

static void mcevf_dis_msix(struct mcevf_pf *pf)
{
	pci_free_irq_vectors(pf->pdev);
}

static int mcevf_ena_msix_range(struct mcevf_pf *pf)
{
	//struct device *dev = mcevf_pf_to_dev(pf);
	//int num_local_cpus = mcevf_get_num_local_cpus(dev);
	int num_local_cpus = num_online_cpus();
	int needed = mcevf_normalize_cpu_count(num_local_cpus);
	int v_actual = 0;
	int err = -ENOSPC;

	needed = min_t(int, needed, pf->max_pf_txqs);
	pf->rdma_irq_base = pf->num_mbox_irqs + needed;
	needed += pf->num_mbox_irqs + pf->num_rdma_irqs;
	needed = min_t(int, needed, pf->num_msix_cnt);

	v_actual = mcevf_ena_msix(pf, needed);
	if (v_actual < 0) {
		err = v_actual;
		goto err;
	} else if (v_actual < needed) {
		mcevf_dis_msix(pf);
		goto err;
	}

	pf_logd(LOG_QUEUE_INFO,
		"%s num_local_cpus:%d max_pf_txqs:%d needed:%d v_actual:%d\n",
		__func__, num_local_cpus, pf->max_pf_txqs, needed, v_actual);

	return v_actual;
err:
	dev_err(mcevf_pf_to_dev(pf), "Failed to enable MSI-X vectors\n");
	return err;
}

/**
 * mcevf_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
int mcevf_init_interrupt_scheme(struct mcevf_pf *pf)
{
	int vectors = mcevf_ena_msix_range(pf);

	if (vectors < 0)
		return vectors;

	/* pf->msix_entries is used by IDC. */
	if (mcevf_alloc_and_fill_msix_entries(pf, vectors)) {
		mcevf_dis_msix(pf);
		return -ENOMEM;
	}

	/* set up vector assignment tracking */
	pf->irq_tracker = devm_kzalloc(mcevf_pf_to_dev(pf),
				       struct_size(pf->irq_tracker, list, vectors), GFP_KERNEL);
	if (!pf->irq_tracker) {
		mcevf_dis_msix(pf);
		return -ENOMEM;
	}

	/* populate SW interrupts pool with number of OS granted IRQs. */
	pf->num_msix_cnt = vectors;
	pf->num_avail_msix = vectors;
	pf->irq_tracker->num_entries = vectors;
	pf->irq_tracker->end = pf->irq_tracker->num_entries;

	return 0;
}

/**
 * mcevf_clear_interrupt_scheme - Undo things done by mcevf_init_interrupt_scheme
 * @pf: board private structure
 */
void mcevf_clear_interrupt_scheme(struct mcevf_pf *pf)
{
	kfree(pf->msix_entries);
	pf->msix_entries = NULL;

	mcevf_dis_msix(pf);

	if (pf->irq_tracker) {
		devm_kfree(mcevf_pf_to_dev(pf), pf->irq_tracker);
		pf->irq_tracker = NULL;
	}
}

/**
 * mcevf_napi_add - register NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be registered
 *
 * This function is only called in the driver's load path. Registering the NAPI
 * handler is done in mcevf_vsi_alloc_q_vector() for all other cases (i.e. resume,
 * reset/rebuild, etc.)
 */
void mcevf_napi_add(struct mcevf_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	mcevf_for_each_q_vector(vsi, v_idx)
		netif_napi_add(vsi->netdev, &vsi->q_vectors[v_idx]->napi,
			       mcevf_napi_poll, NAPI_POLL_WEIGHT);
}

/**
 * mcevf_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * so that we may register to receive changes to the irq affinity masks.
 */
static void mcevf_irq_affinity_notify(struct irq_affinity_notify *notify,
				      const cpumask_t *mask)
{
	struct mcevf_q_vector *q_vector =
		container_of(notify, struct mcevf_q_vector, affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

/**
 * mcevf_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * to inform the current notification subscriber that they will no longer
 * receive notifications.
 */
static void mcevf_irq_affinity_release(struct kref __always_unused *ref)
{
}

/**
 * mcevf_vsi_req_single_irq_msix - get a single MSI-X vector from the OS for VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 * @vector_id: index of the vector in VSI
 */
static int mcevf_vsi_req_single_irq_msix(struct mcevf_vsi *vsi, char *basename,
					 u16 vector_id)
{
	struct mcevf_q_vector *q_vector = vsi->q_vectors[vector_id];
	struct mcevf_pf *pf = vsi->back;
	int base = vsi->base_vector;
	u16 rx_irq_idx, tx_irq_idx;
	struct device *dev;
	int irq_num, err;

	dev = mcevf_pf_to_dev(pf);
	irq_num = mcevf_get_irq_num(pf, base + vector_id);

	mcevf_vsi_get_q_vector_q_base(vsi, vector_id, &tx_irq_idx, &rx_irq_idx);

	if (q_vector->tx.ring && q_vector->rx.ring) {
		if (q_vector->num_ring_rx == 1) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-%s-%u", basename, "TxRx", rx_irq_idx);
		} else {
			u32 num_rx = q_vector->num_ring_rx;

			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-%s-%u-%u", basename, "TxRx", rx_irq_idx,
				 rx_irq_idx + num_rx - 1);
		}
	} else if (q_vector->rx.ring) {
		snprintf(q_vector->name, sizeof(q_vector->name), "%s-%s-%u",
			 basename, "rx", rx_irq_idx);
	} else if (q_vector->tx.ring) {
		snprintf(q_vector->name, sizeof(q_vector->name), "%s-%s-%u",
			 basename, "tx", tx_irq_idx);
	} else {
		/* skip this unused q_vector */
		return 0;
	}

	err = devm_request_irq(dev, irq_num, vsi->irq_handler, 0,
			       q_vector->name, q_vector);
	if (err) {
		netdev_err(vsi->netdev, "MSIX request_irq failed, error: %d\n",
			   err);
		return err;
	}
	/* register for affinity change notifications */
	// if (!IS_ENABLED(CONFIG_RFS_ACCEL)) {
	if (1) {
		struct irq_affinity_notify *affinity_notify;

		affinity_notify = &q_vector->affinity_notify;
		affinity_notify->notify = mcevf_irq_affinity_notify;
		affinity_notify->release = mcevf_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, affinity_notify);
	}
	irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);

	return 0;
}

/**
 * mcevf_vsi_req_irq_msix - get MSI-X vectors from the OS for the VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 */
int mcevf_vsi_req_irq_msix(struct mcevf_vsi *vsi, char *basename)
{
	struct mcevf_pf *pf = vsi->back;
	int base = vsi->base_vector;
	struct device *dev;
	int vector, err;
	int irq_num;

	dev = mcevf_pf_to_dev(pf);
	mcevf_for_each_q_vector(vsi, vector) {
		err = mcevf_vsi_req_single_irq_msix(vsi, basename, vector);
		if (err)
			goto free_q_irqs;
	}

	// err = mcevf_set_cpu_rx_rmap(vsi);
	// if (err) {
	//	netdev_err(vsi->netdev, "Failed to setup CPU RMAP on VSI %u: %pe\n",
	//		   vsi->idx, ERR_PTR(err));
	//	goto free_q_irqs;
	// }

	vsi->irqs_ready = true;
	return 0;

free_q_irqs:
	while (vector) {
		vector--;
		irq_num = mcevf_get_irq_num(pf, base + vector);
		// if (!IS_ENABLED(CONFIG_RFS_ACCEL))
		if (1)
			irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, vsi->q_vectors[vector]);
	}
	return err;
}
