/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_irq.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"

int hinic5_poll(struct napi_struct *napi, int budget)
{
	int tx_pkts, rx_pkts;
	struct hinic5_irq *irq_cfg =
		container_of(napi, struct hinic5_irq, napi);
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	rx_pkts = hinic5_rx_poll(irq_cfg->rxq, budget);

	tx_pkts = hinic5_tx_poll(irq_cfg->txq, budget);
	if (tx_pkts >= budget || rx_pkts >= budget)
		return budget;

	napi_complete(napi);

	hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
			      HINIC5_MSIX_ENABLE);

	return max(tx_pkts, rx_pkts);
}

static void qp_add_napi(struct hinic5_irq *irq_cfg)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	netif_napi_add(nic_dev->netdev, &irq_cfg->napi, hinic5_poll, nic_dev->poll_weight);
	napi_enable(&irq_cfg->napi);
}

static void qp_del_napi(struct hinic5_irq *irq_cfg)
{
	napi_disable(&irq_cfg->napi);
	netif_napi_del(&irq_cfg->napi);
}

static irqreturn_t qp_irq(int irq, void *data)
{
	struct hinic5_irq *irq_cfg = (struct hinic5_irq *)data;
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	hinic5_misx_intr_clear_resend_bit(nic_dev->hwdev, irq_cfg->msix_entry_idx, 1);

	napi_schedule(&irq_cfg->napi);

	return IRQ_HANDLED;
}

static int hinic5_request_irq(struct hinic5_irq *irq_cfg, u16 q_id)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);
	struct interrupt_info info = {0};
	int err;

	qp_add_napi(irq_cfg);
	info.msix_index = irq_cfg->msix_entry_idx;
	/* bind the msix_entry to this function */
	err = hinic5_set_interrupt_cfg(nic_dev->hwdev, info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, irq_cfg->netdev, "Failed to set RX interrupt cfg.\n");
		qp_del_napi(irq_cfg);
		return err;
	}

	nic_dev->rxqs[q_id].last_coalesc_timer_cfg =
			nic_dev->intr_coalesce[q_id].rx_coalesce_timer_cfg;
	nic_dev->rxqs[q_id].last_pending_limt =
			nic_dev->intr_coalesce[q_id].rx_pending_limt;
	err = hinic5_set_sq_rq_coalesce_cfg(nic_dev->hwdev, q_id, HINIC5_SQ_RQ_COALESCE,
					    &nic_dev->intr_coalesce[q_id]);
	if (err != 0) {
		nicif_err(nic_dev, drv, irq_cfg->netdev,
			  "Failed to set RX interrupt coalescing attribute.\n");
		qp_del_napi(irq_cfg);
		return err;
	}

	err = request_irq(irq_cfg->irq_id, &qp_irq, 0, irq_cfg->irq_name, irq_cfg);
	if (err != 0) {
		nicif_err(nic_dev, drv, irq_cfg->netdev, "Failed to request Rx irq\n");
		qp_del_napi(irq_cfg);
		return err;
	}

	irq_set_affinity_hint(irq_cfg->irq_id, &irq_cfg->affinity_mask);

	return 0;
}

static void hinic5_release_irq(struct hinic5_irq *irq_cfg, u32 nic_dev_state)
{
	irq_set_affinity_hint(irq_cfg->irq_id, NULL);
	synchronize_irq(irq_cfg->irq_id);
	free_irq(irq_cfg->irq_id, irq_cfg);

	/*
	 * During sdinanoos-hotreplace, the netif-napi does not need to be deleted.
	 * (The ETH device is disabled by netif_carrier_off on the 'hinic5_vport_down' interface)
	 */
	if (nic_dev_state == 0)
		qp_del_napi(irq_cfg);
}

int hinic5_qps_irq_init(struct hinic5_nic_dev *nic_dev)
{
	struct irq_info *qp_irq_info = NULL;
	struct hinic5_irq *irq_cfg = NULL;
	u16 q_id, i;
	u32 local_cpu;
	int err;

	for (q_id = 0; q_id < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; q_id++) {
		qp_irq_info = &nic_dev->qps_irq_info[q_id];
		irq_cfg = &nic_dev->q_params.irq_cfg[q_id];

		irq_cfg->irq_id = qp_irq_info->irq_id;
		irq_cfg->msix_entry_idx = qp_irq_info->msix_entry_idx;
		irq_cfg->netdev = nic_dev->netdev;
		irq_cfg->txq = &nic_dev->txqs[q_id];
		irq_cfg->rxq = &nic_dev->rxqs[q_id];
		nic_dev->rxqs[q_id].irq_cfg = irq_cfg;

		local_cpu = cpumask_local_spread(q_id, dev_to_node(nic_dev->lld_dev->dev));
		cpumask_set_cpu(local_cpu, &irq_cfg->affinity_mask);

		err = snprintf(irq_cfg->irq_name, sizeof(irq_cfg->irq_name),
			       "%s_qp%u", nic_dev->netdev->name, q_id);
		if (err < 0) {
			err = -EINVAL;
			goto req_tx_irq_err;
		}

		err = hinic5_request_irq(irq_cfg, q_id);
		if (err != 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to request Rx irq\n");
			goto req_tx_irq_err;
		}

		hinic5_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
						HINIC5_SET_MSIX_AUTO_MASK);
		hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, HINIC5_MSIX_ENABLE);
	}

	INIT_DELAYED_WORK(&nic_dev->moderation_task, hinic5_auto_moderation_work);

	return 0;

req_tx_irq_err:
	for (i = 0; i < q_id; i++) {
		irq_cfg = &nic_dev->q_params.irq_cfg[i];
		hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, HINIC5_MSIX_DISABLE);
		hinic5_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
						HINIC5_CLR_MSIX_AUTO_MASK);
		hinic5_release_irq(irq_cfg, nic_dev->state);
	}

	return err;
}

void hinic5_qps_irq_deinit(struct hinic5_nic_dev *nic_dev)
{
	struct hinic5_irq *irq_cfg = NULL;
	u16 q_id;

	for (q_id = 0; q_id < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; q_id++) {
		irq_cfg = &nic_dev->q_params.irq_cfg[q_id];
		hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
				      HINIC5_MSIX_DISABLE);
		hinic5_set_msix_auto_mask_state(nic_dev->hwdev,
						irq_cfg->msix_entry_idx,
						HINIC5_CLR_MSIX_AUTO_MASK);
		hinic5_release_irq(irq_cfg, nic_dev->state);
	}
}
