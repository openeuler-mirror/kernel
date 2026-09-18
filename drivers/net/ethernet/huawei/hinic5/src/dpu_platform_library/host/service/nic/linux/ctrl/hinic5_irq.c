/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_irq.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : HINIC5 IRQ (interrupt) control implementation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/atomic.h>
#include <linux/debugfs.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_dev.h"
#include "hinic5_ethtool.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_irq.h"

#ifdef HAVE_DIM_SUPPORT

/* dim profiles */

#define HINIC5_DIM_PARAMS_NUM_PROFILES  5
#define HINIC5_DIM_DEFAULT_RX_PKTS  256

struct hinic5_dim_moder {
	u16 usec;
	u16 pkts;
};

enum hinic5_dim_period_mode {
	HINIC5_DIM_PERIOD_MODE_START_FROM_EQE = 0x0,
	HINIC5_DIM_PERIOD_NUM_MODES
};

#define HINIC5_DIM_RX_PROFILES  { \
	{.usec = 1, .pkts = 0}, \
	{.usec = 4, .pkts = 0}, \
	{.usec = 64, .pkts = HINIC5_DIM_DEFAULT_RX_PKTS}, \
	{.usec = 128, .pkts = HINIC5_DIM_DEFAULT_RX_PKTS}, \
	{.usec = 256, .pkts = HINIC5_DIM_DEFAULT_RX_PKTS}  \
}

static inline struct hinic5_dim_moder
hinic5_dim_get_rx_moderation(u8 period_mode, int idx)
{
	static const struct hinic5_dim_moder
	rx_profiles[HINIC5_DIM_PERIOD_NUM_MODES][HINIC5_DIM_PARAMS_NUM_PROFILES] = {
		HINIC5_DIM_RX_PROFILES,
	};
	return rx_profiles[period_mode][idx];
}

#define DIM_START_MODE HINIC5_DIM_PERIOD_MODE_START_FROM_EQE

/* Interrupt coalescing conversion macros */
#define HINIC5_USEC_TO_TIMER(usec)    ((u8)((usec) / COALESCE_TIMER_CFG_UNIT))
#define HINIC5_PKTS_TO_PENDING(pkts)  ((u8)((pkts) / COALESCE_PENDING_LIMIT_UNIT))

static void hinic5_rx_dim_work(struct work_struct *work)
{
#if defined(HAVE_DIM)
	struct dim *dim = container_of(work, struct dim, work);
#elif defined(HAVE_NET_DIM)
	struct net_dim *dim = container_of(work, struct net_dim, work);
#endif
	struct hinic5_rxq *rxq = container_of(dim, struct hinic5_rxq, dim);
	struct hinic5_nic_dev *nic_dev = netdev_priv(rxq->netdev);
	struct hinic5_dim_moder cur_moder = hinic5_dim_get_rx_moderation(dim->mode, dim->profile_ix);
	struct hinic5_qp_coalesce_info coal = {0};
	u8 timer_cfg = HINIC5_USEC_TO_TIMER(cur_moder.usec);
	u8 pending_limit = HINIC5_PKTS_TO_PENDING(cur_moder.pkts);
	u16 q_id = rxq->q_id;
	int err;

	atomic_inc(&rxq->dim_applying);

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev) || q_id >= nic_dev->q_params.num_qps)
		goto out;
	if (timer_cfg == nic_dev->rxqs[q_id].last_coalesc_timer_cfg &&
		pending_limit == nic_dev->rxqs[q_id].last_pending_limt)
		goto out;

	coal.rx_coalesce_timer_cfg = timer_cfg;
	coal.rx_pending_limt = pending_limit;

	err = hinic5_set_intr_coalesce_cfg(nic_dev->hwdev, q_id, &coal);
	if (err != 0)
		nicif_err(nic_dev, drv, rxq->netdev, "Failed to set receive queue%u coalesce\n", q_id);
	else {
		nic_dev->rxqs[q_id].last_coalesc_timer_cfg = timer_cfg;
		nic_dev->rxqs[q_id].last_pending_limt = pending_limit;
	}
out:
	dim->state = DIM_START_MEASURE;
	atomic_dec(&rxq->dim_applying);
}

static void hinic5_handle_rx_dim(struct hinic5_irq *irq_cfg)
{
	struct hinic5_rxq *rxq = irq_cfg->rxq;
#if defined(HAVE_DIM)
	struct dim_sample dim_sample = {0};
	dim_update_sample(irq_cfg->event_ctr, rxq->rxq_stats.packets, rxq->rxq_stats.bytes, &dim_sample);
#elif defined(HAVE_NET_DIM)
	struct net_dim_sample dim_sample = {0};
	net_dim_sample(irq_cfg->event_ctr, rxq->rxq_stats.packets, rxq->rxq_stats.bytes, &dim_sample);
#endif
#ifdef HAVE_NET_DIM_SAMPLE_PTR
	net_dim(&rxq->dim, &dim_sample);
#else
	net_dim(&rxq->dim, dim_sample);
#endif
}

static void hinic5_handle_dim(struct hinic5_irq *irq_cfg)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);
	struct hinic5_rxq *rxq = irq_cfg->rxq;

	if (nic_dev == NULL || nic_dev->adaptive_rx_coal == 0 || atomic_read(&rxq->dim_applying) != 0)
		return;

	hinic5_handle_rx_dim(irq_cfg);
}

#endif

// here use KERNEL_VERSION cause the performance has not been well adapted
// after enabling busy poll (4.19 and below kernel), leading to anomalies.
/// use KERNEL_VERSION only to minimize the impact scope of this change.
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
int hinic5_poll(struct napi_struct *napi, int budget)
{
	int tx_pkts, rx_pkts;
	struct hinic5_irq *irq_cfg =
		container_of(napi, struct hinic5_irq, napi);
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);

	if (unlikely(!budget))
		return 0;

	rx_pkts = hinic5_rx_poll(irq_cfg->rxq, budget);

	tx_pkts = hinic5_tx_poll(irq_cfg->txq, budget);
	if (tx_pkts >= budget || rx_pkts >= budget) {
		if (!cpumask_test_cpu(smp_processor_id(), &(irq_cfg->affinity_mask))) {
			if (unlikely(!napi_complete_done(napi, budget - 1))) {
				return budget - 1;
			}
			hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
					HINIC5_MSIX_ENABLE);
			return budget - 1;
		}
		return budget;

	}

	if (unlikely(!napi_complete_done(napi, max(tx_pkts, rx_pkts)))) {
		return max(tx_pkts, rx_pkts);
	}
#ifdef HAVE_DIM_SUPPORT
	if (HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev))
		hinic5_handle_dim(irq_cfg);
#endif

	hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
			      HINIC5_MSIX_ENABLE);

	return max(tx_pkts, rx_pkts);
}
#else
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
#ifdef HAVE_DIM_SUPPORT
	if (HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev))
		hinic5_handle_dim(irq_cfg);
#endif

	hinic5_set_msix_state(nic_dev->hwdev, irq_cfg->msix_entry_idx,
			      HINIC5_MSIX_ENABLE);

	return max(tx_pkts, rx_pkts);
}
#endif

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
#ifdef HAVE_DIM_SUPPORT
	irq_cfg->event_ctr++;
#endif
	hinic5_misx_intr_clear_resend_bit(nic_dev->hwdev, irq_cfg->msix_entry_idx, 1);

	napi_schedule(&irq_cfg->napi);

	return IRQ_HANDLED;
}

static int hinic5_request_irq(struct hinic5_irq *irq_cfg, u16 q_id)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(irq_cfg->netdev);
	struct hinic5_qp_coalesce_info *intr_coal = &nic_dev->intr_coalesce[q_id];
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
#ifdef HAVE_DIM_SUPPORT
	if (nic_dev->adaptive_rx_coal && HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev)) {
		struct hinic5_dim_moder rx_moder;
		rx_moder = hinic5_dim_get_rx_moderation(DIM_START_MODE, DIM_START_PROFILE);

		intr_coal->rx_coalesce_timer_cfg = HINIC5_USEC_TO_TIMER(rx_moder.usec);
		intr_coal->rx_pending_limt = HINIC5_PKTS_TO_PENDING(rx_moder.pkts);
	}
#endif

	nic_dev->rxqs[q_id].last_coalesc_timer_cfg = intr_coal->rx_coalesce_timer_cfg;
	nic_dev->rxqs[q_id].last_pending_limt = intr_coal->rx_pending_limt;
	err = hinic5_set_intr_coalesce_cfg(nic_dev->hwdev, q_id, intr_coal);
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

#ifdef HAVE_DIM_SUPPORT
		irq_cfg->event_ctr = 0;
#endif
		irq_cfg->irq_id = qp_irq_info->irq_id;
		irq_cfg->msix_entry_idx = qp_irq_info->msix_entry_idx;
		irq_cfg->netdev = nic_dev->netdev;
		irq_cfg->txq = &nic_dev->txqs[q_id];
		irq_cfg->rxq = &nic_dev->rxqs[q_id];
		nic_dev->rxqs[q_id].irq_cfg = irq_cfg;

#ifdef HAVE_DIM_SUPPORT
		if (HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev)) {
			INIT_WORK(&nic_dev->rxqs[q_id].dim.work, hinic5_rx_dim_work);
			nic_dev->rxqs[q_id].dim.mode = DIM_START_MODE;
			nic_dev->rxqs[q_id].dim.profile_ix = DIM_START_PROFILE;
			atomic_set(&nic_dev->rxqs[q_id].dim_applying, 0);
		}
#endif

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

		hinic5_set_msix_auto_mask_state(nic_dev->hwdev, irq_cfg->msix_entry_idx, HINIC5_SET_MSIX_AUTO_MASK);
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

#ifdef HAVE_DIM_SUPPORT
		if (HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev))
			cancel_work_sync(&nic_dev->rxqs[i].dim.work);
#endif
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
#ifdef HAVE_DIM_SUPPORT
		if (HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev))
			cancel_work_sync(&nic_dev->rxqs[q_id].dim.work);
#endif
	}
}
