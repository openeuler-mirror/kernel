// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>

#include "hw.h"
#include "common.h"
#include "interrupt.h"
#include "txrx.h"
#include "mailbox.h"

static int nbl_alloc_msix_entries(struct nbl_adapter *adapter, u16 num_entries)
{
	u16 i;

	adapter->msix_entries = devm_kcalloc(nbl_adapter_to_dev(adapter), num_entries,
					     sizeof(*adapter->msix_entries), GFP_KERNEL);
	if (!adapter->msix_entries)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		adapter->msix_entries[i].entry = i;

	return 0;
}

static void nbl_free_msix_entries(struct nbl_adapter *adapter)
{
	devm_kfree(nbl_adapter_to_dev(adapter), adapter->msix_entries);
	adapter->msix_entries = NULL;
}

static int nbl_alloc_msix_intr(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	int needed;
	int err;

	needed = adapter->num_lan_msix + adapter->num_mailbox_msix;
	/* An additional interrupt is needed by AF to process
	 * protocol packets such as ARP broadcast packets.
	 */
	needed += is_af(hw) ? 1 : 0;
	err = nbl_alloc_msix_entries(adapter, (u16)needed);
	if (err) {
		pr_err("Allocate msix entries failed\n");
		return err;
	}

	err = pci_enable_msix_range(adapter->pdev, adapter->msix_entries, needed, needed);
	if (err < 0)
		goto enable_msix_failed;

	return needed;

enable_msix_failed:
	nbl_free_msix_entries(adapter);
	return err;
}

static void nbl_free_msix_intr(struct nbl_adapter *adapter)
{
	pci_disable_msix(adapter->pdev);
	nbl_free_msix_entries(adapter);
}

int nbl_init_interrupt_scheme(struct nbl_adapter *adapter)
{
	int err;
	struct device *dev = nbl_adapter_to_dev(adapter);

	err = nbl_alloc_msix_intr(adapter);
	if (err < 0) {
		dev_err(dev, "Failed to enable MSI-X vectors\n");
		return err;
	}

	return 0;
}

void nbl_fini_interrupt_scheme(struct nbl_adapter *adapter)
{
	nbl_free_msix_intr(adapter);
}

static void nbl_irq_affinity_notify(struct irq_affinity_notify *notify, const cpumask_t *mask)
{
	struct nbl_q_vector *q_vector = container_of(notify, struct nbl_q_vector, affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

static void nbl_irq_affinity_release(struct kref __always_unused *ref)
{
}

int nbl_napi_poll(struct napi_struct *napi, int budget)
{
	struct nbl_q_vector *q_vector = container_of(napi, struct nbl_q_vector, napi);
	struct nbl_adapter *adapter = q_vector->adapter;
	struct nbl_hw *hw = &adapter->hw;
	bool clean_complete = true;
	struct nbl_ring *ring;
	int budget_per_ring;
	int work_done;
	int cleaned;
	bool wd;

	for (ring = q_vector->tx_ring; ring; ring = ring->next) {
		wd = nbl_clean_tx_irq(ring, budget);
		if (!wd)
			clean_complete = false;
	}

	if (unlikely(q_vector->num_ring_rx > 1))
		budget_per_ring = max_t(int, budget / q_vector->num_ring_rx, 1);
	else
		budget_per_ring = budget;

	work_done = 0;
	for (ring = q_vector->rx_ring; ring; ring = ring->next) {
		cleaned = nbl_clean_rx_irq(ring, budget_per_ring);

		if (cleaned >= budget_per_ring)
			clean_complete = false;
		work_done += cleaned;
	}

	if (!clean_complete) {
		int cpu_id = smp_processor_id();

		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			napi_complete_done(napi, work_done);

			nbl_enable_msix_irq(hw, q_vector);

			return budget - 1;
		}

		return budget;
	}

	if (likely(napi_complete_done(napi, work_done)))
		nbl_enable_msix_irq(hw, q_vector);

	return min_t(int, work_done, budget - 1);
}

static irqreturn_t nbl_msix_clean_rings(int __always_unused irq, void *data)
{
	struct nbl_q_vector *q_vector = (struct nbl_q_vector *)data;

	if (!q_vector->tx_ring && !q_vector->rx_ring)
		return IRQ_HANDLED;

	napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

int nbl_request_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;
	u16 q_vector_id;
	u16 rx_intr_index;
	u16 tx_intr_index;
	u32 irq_num;
	int cpu;
	int err;

	rx_intr_index = 0;
	tx_intr_index = 0;
	for (q_vector_id = 0; q_vector_id < adapter->num_q_vectors; q_vector_id++) {
		q_vector = adapter->q_vectors[q_vector_id];
		irq_num = adapter->msix_entries[q_vector_id].vector;

		if (q_vector->tx_ring && q_vector->rx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%02u", adapter->netdev->name, "TxRx", rx_intr_index);
			rx_intr_index++;
			tx_intr_index++;
		} else if (q_vector->rx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%02u", adapter->netdev->name, "Rx", rx_intr_index);
			rx_intr_index++;
		} else if (q_vector->tx_ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%02u", adapter->netdev->name, "Tx", tx_intr_index);
			tx_intr_index++;
		} else {
			pr_notice("Queue vector %u is not used now\n", q_vector_id);
			WARN_ON(1);
		}

		err = devm_request_irq(dev, irq_num, nbl_msix_clean_rings,
				       0, q_vector->name, q_vector);
		if (err) {
			netdev_err(adapter->netdev, "Queue vector %u requests MSIX irq failed with error %d\n",
				   q_vector_id, err);
			goto request_irq_err;
		}

		q_vector->affinity_notify.notify = nbl_irq_affinity_notify;
		q_vector->affinity_notify.release = nbl_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, &q_vector->affinity_notify);

		cpu = cpumask_local_spread(q_vector->global_vector_id,
					   dev_to_node(dev));
		irq_set_affinity_hint(irq_num, get_cpu_mask(cpu));
	}

	return 0;

request_irq_err:
	while (q_vector_id--) {
		irq_num = adapter->msix_entries[q_vector_id].vector;
		irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, adapter->q_vectors[q_vector_id]);
	}
	return err;
}

void nbl_free_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;
	u16 q_vector_id;
	u32 irq_num;

	for (q_vector_id = 0; q_vector_id < adapter->num_q_vectors; q_vector_id++) {
		q_vector = adapter->q_vectors[q_vector_id];

		WARN_ON(!q_vector || !(q_vector->tx_ring || q_vector->rx_ring));
		irq_num = adapter->msix_entries[q_vector_id].vector;
		irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);
		devm_free_irq(dev, irq_num, adapter->q_vectors[q_vector_id]);
	}
}

void nbl_enable_all_napis(struct nbl_adapter *adapter)
{
	int q_vector_id;
	struct nbl_q_vector *q_vector;

	for (q_vector_id = 0; q_vector_id < adapter->num_q_vectors; q_vector_id++) {
		q_vector = adapter->q_vectors[q_vector_id];

		if (q_vector->tx_ring || q_vector->rx_ring)
			napi_enable(&q_vector->napi);
	}
}

void nbl_disable_all_napis(struct nbl_adapter *adapter)
{
	int q_vector_id;
	struct nbl_q_vector *q_vector;

	for (q_vector_id = 0; q_vector_id < adapter->num_q_vectors; q_vector_id++) {
		q_vector = adapter->q_vectors[q_vector_id];

		if (q_vector->tx_ring || q_vector->rx_ring)
			napi_disable(&q_vector->napi);
	}
}

void nbl_af_configure_msix_irq(struct nbl_hw *hw, u16 func_id, u16 local_vector_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_msix_info msix_info;
	u16 global_vector_id;
	u8 bus;
	u8 devid;
	u8 function;

	WARN_ON(!func_res);
	WARN_ON(local_vector_id >= func_res->num_interrupts);
	global_vector_id = func_res->interrupts[local_vector_id];
	nbl_af_compute_bdf(hw, func_id, &bus, &devid, &function);

	memset(&msix_info, 0, sizeof(msix_info));
	msix_info.intrl_pnum = 0;
	msix_info.intrl_rate = 0;
	msix_info.function = function;
	msix_info.devid = devid;
	msix_info.bus = bus;
	msix_info.valid = 1;
	if (func_id < NBL_MAX_PF_FUNC)
		msix_info.msix_mask_en = 1;
	else
		msix_info.msix_mask_en = 0;

	wr32_for_each(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id),
		      (u32 *)&msix_info, sizeof(msix_info));
}

static void nbl_configure_msix_irq(struct nbl_hw *hw, struct nbl_q_vector *q_vector)
{
	u16 local_vector_id;

	local_vector_id = q_vector->q_vector_id;
	if (is_af(hw))
		nbl_af_configure_msix_irq(hw, 0, local_vector_id);
	else
		nbl_mailbox_req_cfg_msix_irq(hw, local_vector_id);
}

void nbl_configure_msix_irqs(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_q_vector *q_vector;
	u16 i;

	for (i = 0; i < adapter->num_q_vectors; i++) {
		q_vector = adapter->q_vectors[i];
		nbl_configure_msix_irq(hw, q_vector);
	}
}

void nbl_af_clear_msix_irq_conf(struct nbl_hw *hw, u16 func_id, u16 local_vector_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	struct nbl_msix_info msix_info;
	u16 global_vector_id;

	if (!func_res || local_vector_id >= func_res->num_interrupts) {
		pr_err("Severe error occurred when clear MSIX irq configuration\n");
		return;
	}
	global_vector_id = func_res->interrupts[local_vector_id];

	memset(&msix_info, 0, sizeof(msix_info));
	wr32_for_each(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id),
		      (u32 *)&msix_info, sizeof(msix_info));
}

static void nbl_clear_msix_irq_conf(struct nbl_hw *hw, struct nbl_q_vector *q_vector)
{
	u16 local_vector_id;

	local_vector_id = q_vector->q_vector_id;
	if (is_af(hw))
		nbl_af_clear_msix_irq_conf(hw, 0, local_vector_id);
	else
		nbl_mailbox_req_clear_msix_irq_conf(hw, local_vector_id);
}

void nbl_clear_msix_irqs_conf(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_q_vector *q_vector;
	u16 i;

	for (i = 0; i < adapter->num_q_vectors; i++) {
		q_vector = adapter->q_vectors[i];
		nbl_clear_msix_irq_conf(hw, q_vector);
	}
}

/* NOTICE: maybe we can write to MSIX bar directly to unmask irq */
void nbl_enable_msix_irq(struct nbl_hw *hw, struct nbl_q_vector *q_vector)
{
	u16 local_vector_id;

	local_vector_id = q_vector->q_vector_id;
	msix_wr32(hw, NBL_MSIX_VECTOR_TABLE_MASK_FIELD_ARR(local_vector_id), 0);
}

int nbl_af_forward_ring_napi_poll(struct napi_struct *napi, int budget)
{
	struct nbl_q_vector *q_vector = container_of(napi, struct nbl_q_vector, napi);
	struct nbl_adapter *adapter = q_vector->adapter;
	struct nbl_hw *hw = &adapter->hw;
	bool clean_complete = true;
	struct nbl_ring *ring;
	int budget_per_ring;
	int work_done;
	int cleaned;
	bool wd;

	for (ring = q_vector->tx_ring; ring; ring = ring->next) {
		wd = nbl_af_clean_forward_ring_tx_irq(ring, budget);
		if (!wd)
			clean_complete = false;
	}

	if (unlikely(q_vector->num_ring_rx > 1))
		budget_per_ring = max_t(int, budget / q_vector->num_ring_rx, 1);
	else
		budget_per_ring = budget;

	work_done = 0;
	for (ring = q_vector->rx_ring; ring; ring = ring->next) {
		cleaned = nbl_af_clean_forward_ring_rx_irq(ring, budget_per_ring);

		if (cleaned >= budget_per_ring)
			clean_complete = false;
		work_done += cleaned;
	}

	if (!clean_complete) {
		int cpu_id = smp_processor_id();

		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			napi_complete_done(napi, work_done);

			nbl_enable_msix_irq(hw, q_vector);

			return budget - 1;
		}

		return budget;
	}

	if (likely(napi_complete_done(napi, work_done)))
		nbl_enable_msix_irq(hw, q_vector);

	return min_t(int, work_done, budget - 1);
}

int nbl_af_forward_ring_request_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;
	u16 q_vector_id;
	u32 irq_num;
	int cpu;
	int err;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];

	irq_num = adapter->msix_entries[q_vector_id].vector;
	snprintf(q_vector->name, sizeof(q_vector->name) - 1,
		 "%s-%s", adapter->netdev->name, "forward_ring");

	err = devm_request_irq(dev, irq_num, nbl_msix_clean_rings,
			       0, q_vector->name, q_vector);
	if (err) {
		pr_err("AF request irq for forward ring failed with error %d\n", err);
		return err;
	}

	q_vector->affinity_notify.notify = nbl_irq_affinity_notify;
	q_vector->affinity_notify.release = nbl_irq_affinity_release;
	irq_set_affinity_notifier(irq_num, &q_vector->affinity_notify);

	cpu = cpumask_local_spread(q_vector->global_vector_id, -1);
	irq_set_affinity_hint(irq_num, get_cpu_mask(cpu));

	return 0;
}

void nbl_af_forward_ring_free_irq(struct nbl_adapter *adapter)
{
	struct device *dev = nbl_adapter_to_dev(adapter);
	struct nbl_q_vector *q_vector;
	u16 q_vector_id;
	u32 irq_num;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];

	irq_num = adapter->msix_entries[q_vector_id].vector;

	irq_set_affinity_notifier(irq_num, NULL);
	irq_set_affinity_hint(irq_num, NULL);
	devm_free_irq(dev, irq_num, q_vector);
}

void nbl_af_enable_forward_ring_napi(struct nbl_adapter *adapter)
{
	int q_vector_id;
	struct nbl_q_vector *q_vector;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];
	napi_enable(&q_vector->napi);
}

void nbl_af_disable_forward_ring_napi(struct nbl_adapter *adapter)
{
	int q_vector_id;
	struct nbl_q_vector *q_vector;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];
	napi_disable(&q_vector->napi);
}

void nbl_af_configure_forward_ring_irq(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_q_vector *q_vector;
	int q_vector_id;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];
	nbl_configure_msix_irq(hw, q_vector);
}

void nbl_af_clear_forward_ring_irq_conf(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct nbl_q_vector *q_vector;
	int q_vector_id;

	q_vector_id = adapter->num_q_vectors;
	q_vector = adapter->q_vectors[q_vector_id];
	nbl_clear_msix_irq_conf(hw, q_vector);
}
