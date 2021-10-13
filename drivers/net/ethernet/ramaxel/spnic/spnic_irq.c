// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>

#include "sphw_hw.h"
#include "sphw_crm.h"
#include "spnic_nic_io.h"
#include "spnic_nic_dev.h"
#include "spnic_tx.h"
#include "spnic_rx.h"

int spnic_poll(struct napi_struct *napi, int budget)
{
	struct spnic_irq *irq_cfg = container_of(napi, struct spnic_irq, napi);
	struct spnic_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);
	int tx_pkts, rx_pkts;

	rx_pkts = spnic_rx_poll(irq_cfg->rxq, budget);

	tx_pkts = spnic_tx_poll(irq_cfg->txq, budget);

	if (tx_pkts >= budget || rx_pkts >= budget)
		return budget;

	napi_complete(napi);

	sphw_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, SPHW_MSIX_ENABLE);

	return max(tx_pkts, rx_pkts);
}

static void qp_add_napi(struct spnic_irq *irq_cfg)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	netif_napi_add(nic_dev->netdev, &irq_cfg->napi, spnic_poll, nic_dev->poll_weight);
	napi_enable(&irq_cfg->napi);
}

static void qp_del_napi(struct spnic_irq *irq_cfg)
{
	napi_disable(&irq_cfg->napi);
	netif_napi_del(&irq_cfg->napi);
}

static irqreturn_t qp_irq(int irq, void *data)
{
	struct spnic_irq *irq_cfg = (struct spnic_irq *)data;
	struct spnic_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	/* 1 is resend_timer */
	sphw_misx_intr_clear_resend_bit(nic_dev->hwdev, irq_cfg->msix_entry_idx, 1);

	napi_schedule(&irq_cfg->napi);
	return IRQ_HANDLED;
}

static int spnic_request_irq(struct spnic_irq *irq_cfg, u16 q_id)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);
	struct interrupt_info info = {0};
	int err;

	qp_add_napi(irq_cfg);

	info.msix_index = irq_cfg->msix_entry_idx;
	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = nic_dev->intr_coalesce[q_id].pending_limt;
	info.coalesc_timer_cfg = nic_dev->intr_coalesce[q_id].coalesce_timer_cfg;
	info.resend_timer_cfg = nic_dev->intr_coalesce[q_id].resend_timer_cfg;
	nic_dev->rxqs[q_id].last_coalesc_timer_cfg =
			nic_dev->intr_coalesce[q_id].coalesce_timer_cfg;
	nic_dev->rxqs[q_id].last_pending_limt = nic_dev->intr_coalesce[q_id].pending_limt;
	err = sphw_set_interrupt_cfg(nic_dev->hwdev, info, SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, irq_cfg->netdev,
			  "Failed to set RX interrupt coalescing attribute.\n");
		qp_del_napi(irq_cfg);
		return err;
	}

	err = request_irq(irq_cfg->irq_id, &qp_irq, 0, irq_cfg->irq_name, irq_cfg);
	if (err) {
		nicif_err(nic_dev, drv, irq_cfg->netdev, "Failed to request Rx irq\n");
		qp_del_napi(irq_cfg);
		return err;
	}

	irq_set_affinity_hint(irq_cfg->irq_id, &irq_cfg->affinity_mask);

	return 0;
}

static void spnic_release_irq(struct spnic_irq *irq_cfg)
{
	irq_set_affinity_hint(irq_cfg->irq_id, NULL);
	synchronize_irq(irq_cfg->irq_id);
	free_irq(irq_cfg->irq_id, irq_cfg);
	qp_del_napi(irq_cfg);
}

int spnic_qps_irq_init(struct spnic_nic_dev *nic_dev)
{
	struct pci_dev *pdev = nic_dev->pdev;
	struct irq_info *qp_irq_info = NULL;
	struct spnic_irq *irq_cfg = NULL;
	u16 q_id, i;
	u32 local_cpu;
	int err;

	for (q_id = 0; q_id < nic_dev->q_params.num_qps; q_id++) {
		qp_irq_info = &nic_dev->qps_irq_info[q_id];
		irq_cfg = &nic_dev->q_params.irq_cfg[q_id];

		irq_cfg->irq_id = qp_irq_info->irq_id;
		irq_cfg->msix_entry_idx = qp_irq_info->msix_entry_idx;
		irq_cfg->netdev = nic_dev->netdev;
		irq_cfg->txq = &nic_dev->txqs[q_id];
		irq_cfg->rxq = &nic_dev->rxqs[q_id];
		nic_dev->rxqs[q_id].irq_cfg = irq_cfg;

		local_cpu = cpumask_local_spread(q_id, dev_to_node(&pdev->dev));
		cpumask_set_cpu(local_cpu, &irq_cfg->affinity_mask);

		snprintf(irq_cfg->irq_name, sizeof(irq_cfg->irq_name),
			 "%s_qp%u", nic_dev->netdev->name, q_id);

		err = spnic_request_irq(irq_cfg, q_id);
		if (err) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to request Rx irq\n");
			goto req_tx_irq_err;
		}

		sphw_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
					      SPHW_SET_MSIX_AUTO_MASK);
		sphw_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, SPHW_MSIX_ENABLE);
	}

	INIT_DELAYED_WORK(&nic_dev->moderation_task, spnic_auto_moderation_work);

	return 0;

req_tx_irq_err:
	for (i = 0; i < q_id; i++) {
		irq_cfg = &nic_dev->q_params.irq_cfg[i];
		sphw_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, SPHW_MSIX_DISABLE);
		sphw_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
					      SPHW_CLR_MSIX_AUTO_MASK);
		spnic_release_irq(irq_cfg);
	}

	return err;
}

void spnic_qps_irq_deinit(struct spnic_nic_dev *nic_dev)
{
	struct spnic_irq *irq_cfg = NULL;
	u16 q_id;

	for (q_id = 0; q_id < nic_dev->q_params.num_qps; q_id++) {
		irq_cfg = &nic_dev->q_params.irq_cfg[q_id];
		sphw_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, SPHW_MSIX_DISABLE);
		sphw_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
					      SPHW_CLR_MSIX_AUTO_MASK);
		spnic_release_irq(irq_cfg);
	}
}
