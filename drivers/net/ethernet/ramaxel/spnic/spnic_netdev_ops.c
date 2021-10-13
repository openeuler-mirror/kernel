// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/debugfs.h>
#include <linux/ip.h>
#include <linux/bpf.h>

#include "sphw_hw.h"
#include "sphw_crm.h"
#include "spnic_nic_io.h"
#include "spnic_nic_dev.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_dcb.h"

#define SPNIC_DEFAULT_RX_CSUM_OFFLOAD			0xFFF

#define SPNIC_LRO_DEFAULT_COAL_PKT_SIZE			32
#define SPNIC_LRO_DEFAULT_TIME_LIMIT			16
#define SPNIC_WAIT_FLUSH_QP_RESOURCE_TIMEOUT		2000
static void spnic_nic_set_rx_mode(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (netdev_uc_count(netdev) != nic_dev->netdev_uc_cnt ||
	    netdev_mc_count(netdev) != nic_dev->netdev_mc_cnt) {
		set_bit(SPNIC_UPDATE_MAC_FILTER, &nic_dev->flags);
		nic_dev->netdev_uc_cnt = netdev_uc_count(netdev);
		nic_dev->netdev_mc_cnt = netdev_mc_count(netdev);
	}

	queue_work(nic_dev->workq, &nic_dev->rx_mode_work);
}

int spnic_alloc_txrxq_resources(struct spnic_nic_dev *nic_dev,
				struct spnic_dyna_txrxq_params *q_params)
{
	u32 size;
	int err;

	size = sizeof(*q_params->txqs_res) * q_params->num_qps;
	q_params->txqs_res = kzalloc(size, GFP_KERNEL);
	if (!q_params->txqs_res) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc txqs resources array\n");
		return -ENOMEM;
	}

	size = sizeof(*q_params->rxqs_res) * q_params->num_qps;
	q_params->rxqs_res = kzalloc(size, GFP_KERNEL);
	if (!q_params->rxqs_res) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc rxqs resource array\n");
		err = -ENOMEM;
		goto alloc_rxqs_res_arr_err;
	}

	size = sizeof(*q_params->irq_cfg) * q_params->num_qps;
	q_params->irq_cfg = kzalloc(size, GFP_KERNEL);
	if (!q_params->irq_cfg) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc irq resource array\n");
		err = -ENOMEM;
		goto alloc_irq_cfg_err;
	}

	err = spnic_alloc_txqs_res(nic_dev, q_params->num_qps,
				   q_params->sq_depth, q_params->txqs_res);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to alloc txqs resource\n");
		goto alloc_txqs_res_err;
	}

	err = spnic_alloc_rxqs_res(nic_dev, q_params->num_qps,
				   q_params->rq_depth, q_params->rxqs_res);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc rxqs resource\n");
		goto alloc_rxqs_res_err;
	}

	return 0;

alloc_rxqs_res_err:
	spnic_free_txqs_res(nic_dev, q_params->num_qps, q_params->sq_depth,
			    q_params->txqs_res);

alloc_txqs_res_err:
	kfree(q_params->irq_cfg);
	q_params->irq_cfg = NULL;

alloc_irq_cfg_err:
	kfree(q_params->rxqs_res);
	q_params->rxqs_res = NULL;

alloc_rxqs_res_arr_err:
	kfree(q_params->txqs_res);
	q_params->txqs_res = NULL;

	return err;
}

void spnic_free_txrxq_resources(struct spnic_nic_dev *nic_dev,
				struct spnic_dyna_txrxq_params *q_params)
{
	spnic_free_rxqs_res(nic_dev, q_params->num_qps, q_params->rq_depth, q_params->rxqs_res);
	spnic_free_txqs_res(nic_dev, q_params->num_qps, q_params->sq_depth, q_params->txqs_res);

	kfree(q_params->irq_cfg);
	q_params->irq_cfg = NULL;

	kfree(q_params->rxqs_res);
	q_params->rxqs_res = NULL;

	kfree(q_params->txqs_res);
	q_params->txqs_res = NULL;
}

int spnic_configure_txrxqs(struct spnic_nic_dev *nic_dev,
			   struct spnic_dyna_txrxq_params *q_params)
{
	int err;

	err = spnic_configure_txqs(nic_dev, q_params->num_qps,
				   q_params->sq_depth, q_params->txqs_res);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to configure txqs\n");
		return err;
	}

	err = spnic_configure_rxqs(nic_dev, q_params->num_qps,
				   q_params->rq_depth, q_params->rxqs_res);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to configure rxqs\n");
		return err;
	}

	return 0;
}

static void config_dcb_qps_map(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 i, num_tcs;
	u16 num_rss;

	if (!test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		spnic_update_tx_db_cos(nic_dev);
		return;
	}

	num_tcs = (u8)netdev_get_num_tc(netdev);
	/* For now, we don't support to change num_tcs */
	if (num_tcs != nic_dev->hw_dcb_cfg.max_cos ||
	    nic_dev->q_params.num_qps < num_tcs ||
	    !test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, netdev, "Invalid num_tcs: %u or num_qps: %u, disable DCB\n",
			  num_tcs, nic_dev->q_params.num_qps);
		netdev_reset_tc(netdev);
		nic_dev->q_params.num_tc = 0;
		clear_bit(SPNIC_DCB_ENABLE, &nic_dev->flags);
		/* if we can't enable rss or get enough num_qps,
		 * need to sync default configure to hw
		 */
		spnic_configure_dcb(netdev);
	} else {
		/* use 0~max_cos-1 as tc for netdev */
		num_rss = nic_dev->q_params.num_rss;
		for (i = 0; i < num_tcs; i++)
			netdev_set_tc_queue(netdev, i, num_rss, (u16)(num_rss * i));
	}

	spnic_update_tx_db_cos(nic_dev);
}

static int spnic_configure(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int err;

	err = spnic_set_port_mtu(nic_dev->hwdev, (u16)netdev->mtu);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to set mtu\n");
		return err;
	}

	config_dcb_qps_map(nic_dev);

	/* rx rss init */
	err = spnic_rx_configure(netdev);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to configure rx\n");
		return err;
	}

	return 0;
}

static void spnic_remove_configure(struct spnic_nic_dev *nic_dev)
{
	spnic_rx_remove_configure(nic_dev->netdev);
}

/* try to modify the number of irq to the target number,
 * and return the actual number of irq.
 */
static u16 spnic_qp_irq_change(struct spnic_nic_dev *nic_dev, u16 dst_num_qp_irq)
{
	struct irq_info *qps_irq_info = nic_dev->qps_irq_info;
	u16 resp_irq_num, irq_num_gap, i;
	u16 idx;
	int err;

	if (dst_num_qp_irq > nic_dev->num_qp_irq) {
		irq_num_gap = dst_num_qp_irq - nic_dev->num_qp_irq;
		err = sphw_alloc_irqs(nic_dev->hwdev, SERVICE_T_NIC, irq_num_gap,
				      &qps_irq_info[nic_dev->num_qp_irq], &resp_irq_num);
		if (err) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc irqs\n");
			return nic_dev->num_qp_irq;
		}

		nic_dev->num_qp_irq += resp_irq_num;
	} else if (dst_num_qp_irq < nic_dev->num_qp_irq) {
		irq_num_gap = nic_dev->num_qp_irq - dst_num_qp_irq;
		for (i = 0; i < irq_num_gap; i++) {
			idx = (nic_dev->num_qp_irq - i) - 1;
			sphw_free_irq(nic_dev->hwdev, SERVICE_T_NIC, qps_irq_info[idx].irq_id);
			qps_irq_info[idx].irq_id = 0;
			qps_irq_info[idx].msix_entry_idx = 0;
		}
		nic_dev->num_qp_irq = dst_num_qp_irq;
	}

	return nic_dev->num_qp_irq;
}

static void config_dcb_num_qps(struct spnic_nic_dev *nic_dev,
			       struct spnic_dyna_txrxq_params *q_params,
			       u16 max_qps)
{
	u8 num_tcs = q_params->num_tc;
	u16 num_rss;

	if (!num_tcs || !test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags))
		return;

	if (num_tcs == nic_dev->hw_dcb_cfg.max_cos && max_qps >= num_tcs) {
		num_rss = max_qps / num_tcs;
		num_rss = min_t(u16, num_rss, q_params->rss_limit);
		q_params->num_rss = num_rss;
		q_params->num_qps = (u16)(num_tcs * num_rss);
	} /* else will disable DCB in config_dcb_qps_map() */
}

static void spnic_config_num_qps(struct spnic_nic_dev *nic_dev,
				 struct spnic_dyna_txrxq_params *q_params)
{
	u16 alloc_num_irq, cur_num_irq;
	u16 dst_num_irq;

	if (test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		q_params->num_rss = q_params->rss_limit;
		q_params->num_qps = q_params->rss_limit;
	} else {
		q_params->num_rss = 0;
		q_params->num_qps = 1;
	}

	config_dcb_num_qps(nic_dev, q_params, nic_dev->max_qps);

	if (nic_dev->num_qp_irq >= q_params->num_qps)
		goto out;

	cur_num_irq = nic_dev->num_qp_irq;

	alloc_num_irq = spnic_qp_irq_change(nic_dev, q_params->num_qps);
	if (alloc_num_irq < q_params->num_qps) {
		q_params->num_qps = alloc_num_irq;
		q_params->num_rss = q_params->num_qps;
		config_dcb_num_qps(nic_dev, q_params, q_params->num_qps);
		nicif_warn(nic_dev, drv, nic_dev->netdev,
			   "Can not get enough irqs, adjust num_qps to %u\n",
			   q_params->num_qps);

		/* The current irq may be in use, we must keep it */
		dst_num_irq = max_t(u16, cur_num_irq, q_params->num_qps);
		spnic_qp_irq_change(nic_dev, dst_num_irq);
	}

out:
	nicif_info(nic_dev, drv, nic_dev->netdev, "Finally num_qps: %u, num_rss: %u\n",
		   q_params->num_qps, q_params->num_rss);
}

/* determin num_qps from rss_tmpl_id/irq_num/dcb_en */
int spnic_setup_num_qps(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u32 irq_size;

	nic_dev->num_qp_irq = 0;

	irq_size = sizeof(*nic_dev->qps_irq_info) * nic_dev->max_qps;
	if (!irq_size) {
		nicif_err(nic_dev, drv, netdev, "Cannot allocate zero size entries\n");
		return -EINVAL;
	}
	nic_dev->qps_irq_info = kzalloc(irq_size, GFP_KERNEL);
	if (!nic_dev->qps_irq_info) {
		nicif_err(nic_dev, drv, netdev, "Failed to alloc qps_irq_info\n");
		return -ENOMEM;
	}

	spnic_config_num_qps(nic_dev, &nic_dev->q_params);

	return 0;
}

static void spnic_destroy_num_qps(struct spnic_nic_dev *nic_dev)
{
	u16 i;

	for (i = 0; i < nic_dev->num_qp_irq; i++)
		sphw_free_irq(nic_dev->hwdev, SERVICE_T_NIC, nic_dev->qps_irq_info[i].irq_id);

	kfree(nic_dev->qps_irq_info);
}

int spnic_force_port_disable(struct spnic_nic_dev *nic_dev)
{
	int err;

	down(&nic_dev->port_state_sem);

	err = spnic_set_port_enable(nic_dev->hwdev, false, SPHW_CHANNEL_NIC);
	if (!err)
		nic_dev->force_port_disable = true;

	up(&nic_dev->port_state_sem);

	return err;
}

int spnic_force_set_port_state(struct spnic_nic_dev *nic_dev, bool enable)
{
	int err = 0;

	down(&nic_dev->port_state_sem);

	nic_dev->force_port_disable = false;
	err = spnic_set_port_enable(nic_dev->hwdev, enable, SPHW_CHANNEL_NIC);

	up(&nic_dev->port_state_sem);

	return err;
}

int spnic_maybe_set_port_state(struct spnic_nic_dev *nic_dev, bool enable)
{
	int err;

	down(&nic_dev->port_state_sem);

	/* Do nothing when force disable
	 * Port will disable when call force port disable
	 * and should not enable port when in force mode
	 */
	if (nic_dev->force_port_disable) {
		up(&nic_dev->port_state_sem);
		return 0;
	}

	err = spnic_set_port_enable(nic_dev->hwdev, enable, SPHW_CHANNEL_NIC);

	up(&nic_dev->port_state_sem);

	return err;
}

static void spnic_print_link_message(struct spnic_nic_dev *nic_dev, u8 link_status)
{
	if (nic_dev->link_status == link_status)
		return;

	nic_dev->link_status = link_status;

	nicif_info(nic_dev, link, nic_dev->netdev, "Link is %s\n",
		   (link_status ? "up" : "down"));
}

int spnic_alloc_channel_resources(struct spnic_nic_dev *nic_dev,
				  struct spnic_dyna_qp_params *qp_params,
				  struct spnic_dyna_txrxq_params *trxq_params)
{
	int err;

	qp_params->num_qps = trxq_params->num_qps;
	qp_params->sq_depth = trxq_params->sq_depth;
	qp_params->rq_depth = trxq_params->rq_depth;

	err = spnic_alloc_qps(nic_dev->hwdev, nic_dev->qps_irq_info, qp_params);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc qps\n");
		return err;
	}

	err = spnic_alloc_txrxq_resources(nic_dev, trxq_params);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc txrxq resources\n");
		spnic_free_qps(nic_dev->hwdev, qp_params);
		return err;
	}

	return 0;
}

void spnic_free_channel_resources(struct spnic_nic_dev *nic_dev,
				  struct spnic_dyna_qp_params *qp_params,
				  struct spnic_dyna_txrxq_params *trxq_params)
{
	mutex_lock(&nic_dev->nic_mutex);
	spnic_free_txrxq_resources(nic_dev, trxq_params);
	spnic_free_qps(nic_dev->hwdev, qp_params);
	mutex_unlock(&nic_dev->nic_mutex);
}

int spnic_open_channel(struct spnic_nic_dev *nic_dev, struct spnic_dyna_qp_params *qp_params,
		       struct spnic_dyna_txrxq_params *trxq_params)
{
	int err;

	err = spnic_init_qps(nic_dev->hwdev, qp_params);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init qps\n");
		return err;
	}

	err = spnic_configure_txrxqs(nic_dev, trxq_params);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to configure txrxqs\n");
		goto cfg_txrxqs_err;
	}

	err = spnic_qps_irq_init(nic_dev);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init txrxq irq\n");
		goto init_qp_irq_err;
	}

	err = spnic_configure(nic_dev);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init txrxq irq\n");
		goto configure_err;
	}

	return 0;

configure_err:
	spnic_qps_irq_deinit(nic_dev);

init_qp_irq_err:
cfg_txrxqs_err:
	spnic_deinit_qps(nic_dev->hwdev, qp_params);

	return err;
}

void spnic_close_channel(struct spnic_nic_dev *nic_dev,
			 struct spnic_dyna_qp_params *qp_params)
{
	spnic_remove_configure(nic_dev);
	spnic_qps_irq_deinit(nic_dev);
	spnic_deinit_qps(nic_dev->hwdev, qp_params);
}

int spnic_vport_up(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 link_status = 0;
	u16 glb_func_id;
	int err;

	glb_func_id = sphw_global_func_id(nic_dev->hwdev);
	err = spnic_set_vport_enable(nic_dev->hwdev, glb_func_id, true,
				     SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to enable vport\n");
		goto vport_enable_err;
	}

	err = spnic_maybe_set_port_state(nic_dev, true);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to enable port\n");
		goto port_enable_err;
	}

	netif_set_real_num_tx_queues(netdev, nic_dev->q_params.num_qps);
	netif_set_real_num_rx_queues(netdev, nic_dev->q_params.num_qps);
	netif_tx_wake_all_queues(netdev);

	err = spnic_get_link_state(nic_dev->hwdev, &link_status);
	if (!err && link_status)
		netif_carrier_on(netdev);

	queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task, SPNIC_MODERATONE_DELAY);

	spnic_print_link_message(nic_dev, link_status);

	if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev))
		spnic_notify_all_vfs_link_changed(nic_dev->hwdev, link_status);

	return 0;

port_enable_err:
	spnic_set_vport_enable(nic_dev->hwdev, glb_func_id, false, SPHW_CHANNEL_NIC);

vport_enable_err:
	spnic_flush_qps_res(nic_dev->hwdev);
	/* After set vport disable 100ms, no packets will be send to host */
	msleep(100);

	return err;
}

void spnic_vport_down(struct spnic_nic_dev *nic_dev)
{
	u16 glb_func_id;

	netif_carrier_off(nic_dev->netdev);
	netif_tx_disable(nic_dev->netdev);

	cancel_delayed_work_sync(&nic_dev->moderation_task);

	if (sphw_get_chip_present_flag(nic_dev->hwdev)) {
		if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev))
			spnic_notify_all_vfs_link_changed(nic_dev->hwdev, 0);

		spnic_maybe_set_port_state(nic_dev, false);

		glb_func_id = sphw_global_func_id(nic_dev->hwdev);
		spnic_set_vport_enable(nic_dev->hwdev, glb_func_id, false, SPHW_CHANNEL_NIC);

		spnic_flush_txqs(nic_dev->netdev);
		spnic_flush_qps_res(nic_dev->hwdev);
		/* After set vport disable 100ms,
		 * no packets will be send to host
		 * FPGA set 2000ms
		 */
		msleep(SPNIC_WAIT_FLUSH_QP_RESOURCE_TIMEOUT);
	}
}

int spnic_change_channel_settings(struct spnic_nic_dev *nic_dev,
				  struct spnic_dyna_txrxq_params *trxq_params,
				  spnic_reopen_handler reopen_handler, const void *priv_data)
{
	struct spnic_dyna_qp_params new_qp_params = {0};
	struct spnic_dyna_qp_params cur_qp_params = {0};
	int err;

	spnic_config_num_qps(nic_dev, trxq_params);

	err = spnic_alloc_channel_resources(nic_dev, &new_qp_params, trxq_params);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to alloc channel resources\n");
		return err;
	}

	if (!test_and_set_bit(SPNIC_CHANGE_RES_INVALID, &nic_dev->flags)) {
		spnic_vport_down(nic_dev);
		spnic_close_channel(nic_dev, &cur_qp_params);
		spnic_free_channel_resources(nic_dev, &cur_qp_params, &nic_dev->q_params);
	}

	if (nic_dev->num_qp_irq > trxq_params->num_qps)
		spnic_qp_irq_change(nic_dev, trxq_params->num_qps);
	nic_dev->q_params = *trxq_params;

	if (reopen_handler)
		reopen_handler(nic_dev, priv_data);

	err = spnic_open_channel(nic_dev, &new_qp_params, trxq_params);
	if (err)
		goto open_channel_err;

	err = spnic_vport_up(nic_dev);
	if (err)
		goto vport_up_err;

	clear_bit(SPNIC_CHANGE_RES_INVALID, &nic_dev->flags);
	nicif_info(nic_dev, drv, nic_dev->netdev, "Change channel settings success\n");

	return 0;

vport_up_err:
	spnic_close_channel(nic_dev, &new_qp_params);

open_channel_err:
	spnic_free_channel_resources(nic_dev, &new_qp_params, trxq_params);

	return err;
}

int spnic_open(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_dyna_qp_params qp_params = {0};
	int err;

	if (test_bit(SPNIC_INTF_UP, &nic_dev->flags)) {
		nicif_info(nic_dev, drv, netdev, "Netdev already open, do nothing\n");
		return 0;
	}

	err = spnic_init_nicio_res(nic_dev->hwdev);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to init nicio resources\n");
		return err;
	}

	err = spnic_setup_num_qps(nic_dev);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to setup num_qps\n");
		goto setup_qps_err;
	}

	err = spnic_alloc_channel_resources(nic_dev, &qp_params, &nic_dev->q_params);
	if (err)
		goto alloc_channel_res_err;

	err = spnic_open_channel(nic_dev, &qp_params, &nic_dev->q_params);
	if (err)
		goto open_channel_err;

	err = spnic_vport_up(nic_dev);
	if (err)
		goto vport_up_err;

	set_bit(SPNIC_INTF_UP, &nic_dev->flags);
	nicif_info(nic_dev, drv, nic_dev->netdev, "Netdev is up\n");

	return 0;

vport_up_err:
	spnic_close_channel(nic_dev, &qp_params);

open_channel_err:
	spnic_free_channel_resources(nic_dev, &qp_params, &nic_dev->q_params);

alloc_channel_res_err:
	spnic_destroy_num_qps(nic_dev);

setup_qps_err:
	spnic_deinit_nicio_res(nic_dev->hwdev);

	return err;
}

int spnic_close(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_dyna_qp_params qp_params = {0};

	if (!test_and_clear_bit(SPNIC_INTF_UP, &nic_dev->flags)) {
		nicif_info(nic_dev, drv, netdev, "Netdev already close, do nothing\n");
		return 0;
	}

	if (test_and_clear_bit(SPNIC_CHANGE_RES_INVALID, &nic_dev->flags))
		goto out;

	spnic_vport_down(nic_dev);
	spnic_close_channel(nic_dev, &qp_params);
	spnic_free_channel_resources(nic_dev, &qp_params, &nic_dev->q_params);

out:
	spnic_deinit_nicio_res(nic_dev->hwdev);
	spnic_destroy_num_qps(nic_dev);

	nicif_info(nic_dev, drv, nic_dev->netdev, "Netdev is down\n");

	return 0;
}

#define IPV6_ADDR_LEN  4
#define PKT_INFO_LEN   9
#define BITS_PER_TUPLE 32
static u32 calc_xor_rss(u8 *rss_tunple, u32 len)
{
	u32 hash_value;
	u32 i;

	hash_value = rss_tunple[0];
	for (i = 1; i < len; i++)
		hash_value = hash_value ^ rss_tunple[i];

	return hash_value;
}

static u32 calc_toep_rss(u32 *rss_tunple, u32 len, const u32 *rss_key)
{
	u32 rss = 0;
	u32 i, j;

	for (i = 1; i <= len; i++) {
		for (j = 0; j < BITS_PER_TUPLE; j++)
			if (rss_tunple[i - 1] & ((u32)1 <<
			    (u32)((BITS_PER_TUPLE - 1) - j)))
				rss ^= (rss_key[i - 1] << j) |
					(u32)((u64)rss_key[i] >> (BITS_PER_TUPLE - j));
	}

	return rss;
}

#define RSS_VAL(val, type)		\
	(((type) == SPNIC_RSS_HASH_ENGINE_TYPE_TOEP) ? ntohl(val) : (val))

static u8 parse_ipv6_info(struct sk_buff *skb, u32 *rss_tunple, u8 hash_engine, u32 *len)
{
	struct ipv6hdr *ipv6hdr = ipv6_hdr(skb);
	u32 *saddr = (u32 *)&ipv6hdr->saddr;
	u32 *daddr = (u32 *)&ipv6hdr->daddr;
	u8 i;

	for (i = 0; i < IPV6_ADDR_LEN; i++) {
		rss_tunple[i] = RSS_VAL(daddr[i], hash_engine);
		/* The offset of the sport relative to the dport is 4 */
		rss_tunple[(u32)(i + IPV6_ADDR_LEN)] = RSS_VAL(saddr[i], hash_engine);
	}
	*len = IPV6_ADDR_LEN + IPV6_ADDR_LEN;

	if (skb_network_header(skb) + sizeof(*ipv6hdr) == skb_transport_header(skb))
		return ipv6hdr->nexthdr;
	return 0;
}

u16 select_queue_by_hash_func(struct net_device *dev, struct sk_buff *skb,
			      unsigned int num_tx_queues)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(dev);
	struct nic_rss_type rss_type = nic_dev->rss_type;
	struct iphdr *iphdr = NULL;
	u32 rss_tunple[PKT_INFO_LEN] = {0};
	u32 len = 0;
	u32 hash = 0;
	u8 hash_engine = nic_dev->rss_hash_engine;
	u8 l4_proto;
	unsigned char *l4_hdr = NULL;

	if (skb_rx_queue_recorded(skb)) {
		hash = skb_get_rx_queue(skb);

		if (unlikely(hash >= num_tx_queues))
			hash %= num_tx_queues;
		return (u16)hash;
	}

	iphdr = ip_hdr(skb);
	if (iphdr->version == IPV4_VERSION) {
		rss_tunple[len++] = RSS_VAL(iphdr->daddr, hash_engine);
		rss_tunple[len++] = RSS_VAL(iphdr->saddr, hash_engine);
		l4_proto = iphdr->protocol;
	} else if (iphdr->version == IPV6_VERSION) {
		l4_proto = parse_ipv6_info(skb, (u32 *)rss_tunple, hash_engine, &len);
	} else {
		return (u16)hash;
	}

	if ((iphdr->version == IPV4_VERSION &&
	     ((l4_proto == IPPROTO_UDP && rss_type.udp_ipv4) ||
	     (l4_proto == IPPROTO_TCP && rss_type.tcp_ipv4))) ||
	    (iphdr->version == IPV6_VERSION &&
	     ((l4_proto == IPPROTO_UDP && rss_type.udp_ipv6) ||
	     (l4_proto == IPPROTO_TCP && rss_type.tcp_ipv6)))) {
		l4_hdr = skb_transport_header(skb);
		/* High 16 bits are dport, low 16 bits are sport. */
		rss_tunple[len++] = ((u32)ntohs(*((u16 *)l4_hdr + 1U)) << 16) |
			ntohs(*(u16 *)l4_hdr);
	} /* rss_type.ipv4 and rss_type.ipv6 default on. */

	if (hash_engine == SPNIC_RSS_HASH_ENGINE_TYPE_TOEP)
		hash = calc_toep_rss((u32 *)rss_tunple, len, nic_dev->rss_hkey_be);
	else
		hash = calc_xor_rss((u8 *)rss_tunple, len * (u32)sizeof(u32));

	return (u16)nic_dev->rss_indir[hash & 0xFF];
}

static u16 spnic_select_queue(struct net_device *netdev, struct sk_buff *skb,
			      struct net_device *sb_dev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (skb->vlan_tci)
		skb->priority = skb->vlan_tci >> VLAN_PRIO_SHIFT;

	if (netdev_get_num_tc(netdev))
		goto fall_back;

	if (test_bit(SPNIC_SAME_RXTX, &nic_dev->flags))
		return select_queue_by_hash_func(netdev, skb, netdev->real_num_tx_queues);

fall_back:
	return netdev_pick_tx(netdev, skb, NULL);
}

static void spnic_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)

{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_txq_stats *txq_stats = NULL;
	struct spnic_rxq_stats *rxq_stats = NULL;
	struct spnic_txq *txq = NULL;
	struct spnic_rxq *rxq = NULL;
	u64 bytes, packets, dropped, errors;
	unsigned int start;
	int i;

	bytes = 0;
	packets = 0;
	dropped = 0;
	for (i = 0; i < nic_dev->max_qps; i++) {
		if (!nic_dev->txqs)
			break;

		txq = &nic_dev->txqs[i];
		txq_stats = &txq->txq_stats;
		do {
			start = u64_stats_fetch_begin(&txq_stats->syncp);
			bytes += txq_stats->bytes;
			packets += txq_stats->packets;
			dropped += txq_stats->dropped;
		} while (u64_stats_fetch_retry(&txq_stats->syncp, start));
	}
	stats->tx_packets = packets;
	stats->tx_bytes   = bytes;
	stats->tx_dropped = dropped;

	bytes = 0;
	packets = 0;
	errors = 0;
	dropped = 0;
	for (i = 0; i < nic_dev->max_qps; i++) {
		if (!nic_dev->rxqs)
			break;

		rxq = &nic_dev->rxqs[i];
		rxq_stats = &rxq->rxq_stats;
		do {
			start = u64_stats_fetch_begin(&rxq_stats->syncp);
			bytes += rxq_stats->bytes;
			packets += rxq_stats->packets;
			errors += rxq_stats->csum_errors + rxq_stats->other_errors;
			dropped += rxq_stats->dropped;
		} while (u64_stats_fetch_retry(&rxq_stats->syncp, start));
	}
	stats->rx_packets = packets;
	stats->rx_bytes   = bytes;
	stats->rx_errors  = errors;
	stats->rx_dropped = dropped;
}

static void spnic_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_io_queue *sq = NULL;
	bool hw_err = false;
	u32 sw_pi, hw_ci;
	u8 q_id;

	SPNIC_NIC_STATS_INC(nic_dev, netdev_tx_timeout);
	nicif_err(nic_dev, drv, netdev, "Tx timeout\n");

	for (q_id = 0; q_id < nic_dev->q_params.num_qps; q_id++) {
		if (!netif_xmit_stopped(netdev_get_tx_queue(netdev, q_id)))
			continue;

		sq = nic_dev->txqs[q_id].sq;
		sw_pi = spnic_get_sq_local_pi(sq);
		hw_ci = spnic_get_sq_hw_ci(sq);
		nicif_info(nic_dev, drv, netdev, "txq%u: sw_pi: %hu, hw_ci: %u, sw_ci: %u, napi->state: 0x%lx\n",
			   q_id, sw_pi, hw_ci, spnic_get_sq_local_ci(sq),
			   nic_dev->q_params.irq_cfg[q_id].napi.state);

		if (sw_pi != hw_ci)
			hw_err = true;
	}

	if (hw_err)
		set_bit(EVENT_WORK_TX_TIMEOUT, &nic_dev->event_flag);
}

static int spnic_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u32 mtu = (u32)new_mtu;
	int err = 0;

	u32 xdp_max_mtu;

	if (spnic_is_xdp_enable(nic_dev)) {
		xdp_max_mtu = spnic_xdp_max_mtu(nic_dev);
		if (mtu > xdp_max_mtu) {
			nicif_err(nic_dev, drv, netdev, "Max MTU for xdp usage is %d\n",
				  xdp_max_mtu);
			return -EINVAL;
		}
	}

	err = spnic_set_port_mtu(nic_dev->hwdev, (u16)mtu);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to change port mtu to %d\n",
			  new_mtu);
	} else {
		nicif_info(nic_dev, drv, nic_dev->netdev, "Change mtu from %u to %d\n",
			   netdev->mtu, new_mtu);
		netdev->mtu = mtu;
	}

	return err;
}

static int spnic_set_mac_addr(struct net_device *netdev, void *addr)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct sockaddr *saddr = addr;
	int err;

	if (!is_valid_ether_addr(saddr->sa_data))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, saddr->sa_data)) {
		nicif_info(nic_dev, drv, netdev, "Already using mac address %pM\n",
			   saddr->sa_data);
		return 0;
	}

	err = spnic_update_mac(nic_dev->hwdev, netdev->dev_addr, saddr->sa_data, 0,
			       sphw_global_func_id(nic_dev->hwdev));
	if (err)
		return err;

	ether_addr_copy(netdev->dev_addr, saddr->sa_data);

	nicif_info(nic_dev, drv, netdev, "Set new mac address %pM\n", saddr->sa_data);

	return 0;
}

static int spnic_vlan_rx_add_vid(struct net_device *netdev, __always_unused __be16 proto, u16 vid)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	unsigned long *vlan_bitmap = nic_dev->vlan_bitmap;
	u16 func_id;
	u32 col, line;
	int err = 0;

	/* VLAN 0 donot be added, which is the same as VLAN 0 deleted. */
	if (vid == 0)
		goto end;

	col = VID_COL(nic_dev, vid);
	line = VID_LINE(nic_dev, vid);

	func_id = sphw_global_func_id(nic_dev->hwdev);

	err = spnic_add_vlan(nic_dev->hwdev, vid, func_id);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to add vlan %u\n", vid);
		goto end;
	}

	set_bit(col, &vlan_bitmap[line]);

	nicif_info(nic_dev, drv, netdev, "Add vlan %u\n", vid);

end:
	return err;
}

static int spnic_vlan_rx_kill_vid(struct net_device *netdev, __always_unused __be16 proto, u16 vid)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	unsigned long *vlan_bitmap = nic_dev->vlan_bitmap;
	u16 func_id;
	int col, line;
	int err = 0;

	col  = VID_COL(nic_dev, vid);
	line = VID_LINE(nic_dev, vid);

	/* In the broadcast scenario, ucode finds the corresponding function
	 * based on VLAN 0 of vlan table. If we delete VLAN 0, the VLAN function
	 * is affected.
	 */
	if (vid == 0)
		goto end;

	func_id = sphw_global_func_id(nic_dev->hwdev);
	err = spnic_del_vlan(nic_dev->hwdev, vid, func_id);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to delete vlan\n");
		goto end;
	}

	clear_bit(col, &vlan_bitmap[line]);

	nicif_info(nic_dev, drv, netdev, "Remove vlan %u\n", vid);

end:
	return err;
}

#define SET_FEATURES_OP_STR(op)		((op) ? "Enable" : "Disable")

static int set_feature_rx_csum(struct spnic_nic_dev *nic_dev, netdev_features_t wanted_features,
			       netdev_features_t features, netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;

	if (changed & NETIF_F_RXCSUM)
		spnic_info(nic_dev, drv, "%s rx csum success\n",
			   SET_FEATURES_OP_STR(wanted_features & NETIF_F_RXCSUM));

	return 0;
}

static int set_feature_tso(struct spnic_nic_dev *nic_dev, netdev_features_t wanted_features,
			   netdev_features_t features, netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;

	if (changed & NETIF_F_TSO)
		spnic_info(nic_dev, drv, "%s tso success\n",
			   SET_FEATURES_OP_STR(wanted_features & NETIF_F_TSO));

	return 0;
}

static int set_feature_lro(struct spnic_nic_dev *nic_dev, netdev_features_t wanted_features,
			   netdev_features_t features, netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
	bool en = !!(wanted_features & NETIF_F_LRO);
	int err;

	if (!(changed & NETIF_F_LRO))
		return 0;

	if (en && spnic_is_xdp_enable(nic_dev)) {
		spnic_err(nic_dev, drv, "Can not enable LRO when xdp is enable\n");
		*failed_features |= NETIF_F_LRO;
		return -EINVAL;
	}

	err = spnic_set_rx_lro_state(nic_dev->hwdev, en, SPNIC_LRO_DEFAULT_TIME_LIMIT,
				     SPNIC_LRO_DEFAULT_COAL_PKT_SIZE);
	if (err) {
		spnic_err(nic_dev, drv, "%s lro failed\n", SET_FEATURES_OP_STR(en));
		*failed_features |= NETIF_F_LRO;
	} else {
		spnic_info(nic_dev, drv, "%s lro success\n", SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_feature_rx_cvlan(struct spnic_nic_dev *nic_dev, netdev_features_t wanted_features,
				netdev_features_t features, netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
	netdev_features_t vlan_feature = NETIF_F_HW_VLAN_CTAG_RX;
	bool en = !!(wanted_features & vlan_feature);
	int err;

	if (!(changed & vlan_feature))
		return 0;

	err = spnic_set_rx_vlan_offload(nic_dev->hwdev, en);
	if (err) {
		spnic_err(nic_dev, drv, "%s rxvlan failed\n", SET_FEATURES_OP_STR(en));
		*failed_features |= vlan_feature;
	} else {
		spnic_info(nic_dev, drv, "%s rxvlan success\n", SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_feature_vlan_filter(struct spnic_nic_dev *nic_dev, netdev_features_t wanted_features,
				   netdev_features_t features, netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
	netdev_features_t vlan_filter_feature = NETIF_F_HW_VLAN_CTAG_FILTER;
	bool en = !!(wanted_features & vlan_filter_feature);
	int err = 0;

	if (!(changed & vlan_filter_feature))
		return 0;

	if (err == 0)
		err = spnic_set_vlan_fliter(nic_dev->hwdev, en);
	if (err) {
		spnic_err(nic_dev, drv, "%s rx vlan filter failed\n", SET_FEATURES_OP_STR(en));
		*failed_features |= vlan_filter_feature;
	} else {
		spnic_info(nic_dev, drv, "%s rx vlan filter success\n", SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_features(struct spnic_nic_dev *nic_dev, netdev_features_t pre_features,
			netdev_features_t features)
{
	netdev_features_t failed_features = 0;
	u32 err = 0;

	err |= (u32)set_feature_rx_csum(nic_dev, features, pre_features, &failed_features);
	err |= (u32)set_feature_tso(nic_dev, features, pre_features, &failed_features);
	err |= (u32)set_feature_lro(nic_dev, features, pre_features, &failed_features);
	err |= (u32)set_feature_rx_cvlan(nic_dev, features, pre_features, &failed_features);
	err |= (u32)set_feature_vlan_filter(nic_dev, features, pre_features, &failed_features);
	if (err) {
		nic_dev->netdev->features = features ^ failed_features;
		return -EIO;
	}

	return 0;
}

static int spnic_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	return set_features(nic_dev, nic_dev->netdev->features, features);
}

int spnic_set_hw_features(struct spnic_nic_dev *nic_dev)
{
	/* enable all hw features in netdev->features */
	return set_features(nic_dev, ~nic_dev->netdev->features, nic_dev->netdev->features);
}

static netdev_features_t spnic_fix_features(struct net_device *netdev, netdev_features_t features)
{
	/* If Rx checksum is disabled, then LRO should also be disabled */
	if (!(features & NETIF_F_RXCSUM))
		features &= ~NETIF_F_LRO;

	return features;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void spnic_netpoll(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u16 i;

	for (i = 0; i < nic_dev->q_params.num_qps; i++)
		napi_schedule(&nic_dev->q_params.irq_cfg[i].napi);
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

static int spnic_ndo_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	int err;

	if (is_multicast_ether_addr(mac) || vf >= pci_num_vf(adapter->pdev))
		return -EINVAL;

	err = spnic_set_vf_mac(adapter->hwdev, OS_VF_ID_TO_HW(vf), mac);
	if (err)
		return err;

	if (!is_zero_ether_addr(mac))
		nic_info(&adapter->pdev->dev, "Setting MAC %pM on VF %d\n", mac, vf);
	else
		nic_info(&adapter->pdev->dev, "Deleting MAC on VF %d\n", vf);

	nic_info(&adapter->pdev->dev, "Please reload the VF driver to make this change effective.");

	return 0;
}

static int set_hw_vf_vlan(void *hwdev, u16 cur_vlanprio, int vf, u16 vlan, u8 qos)
{
	int err = 0;
	u16 old_vlan = cur_vlanprio & VLAN_VID_MASK;

	if (vlan || qos) {
		if (cur_vlanprio) {
			err = spnic_kill_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf));
			if (err)
				return err;
		}
		err = spnic_add_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf), vlan, qos);
	} else {
		err = spnic_kill_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf));
	}

	if (err)
		return err;

	return spnic_update_mac_vlan(hwdev, old_vlan, vlan, OS_VF_ID_TO_HW(vf));
}

#define SPNIC_MAX_VLAN_ID	4094
#define SPNIC_MAX_QOS_NUM	7

static int spnic_ndo_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan,
				 u8 qos, __be16 vlan_proto)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	u16 vlanprio, cur_vlanprio;

	if (vf >= pci_num_vf(adapter->pdev) || vlan > SPNIC_MAX_VLAN_ID || qos > SPNIC_MAX_QOS_NUM)
		return -EINVAL;
	if (vlan_proto != htons(ETH_P_8021Q))
		return -EPROTONOSUPPORT;
	vlanprio = vlan | qos << SPNIC_VLAN_PRIORITY_SHIFT;
	cur_vlanprio = spnic_vf_info_vlanprio(adapter->hwdev, OS_VF_ID_TO_HW(vf));
	/* duplicate request, so just return success */
	if (vlanprio == cur_vlanprio)
		return 0;

	return set_hw_vf_vlan(adapter->hwdev, cur_vlanprio, vf, vlan, qos);
}

static int spnic_ndo_set_vf_spoofchk(struct net_device *netdev, int vf, bool setting)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	int err = 0;
	bool cur_spoofchk = false;

	if (vf >= pci_num_vf(adapter->pdev))
		return -EINVAL;

	cur_spoofchk = spnic_vf_info_spoofchk(adapter->hwdev, OS_VF_ID_TO_HW(vf));
	/* same request, so just return success */
	if ((setting && cur_spoofchk) || (!setting && !cur_spoofchk))
		return 0;

	err = spnic_set_vf_spoofchk(adapter->hwdev, OS_VF_ID_TO_HW(vf), setting);
	if (!err)
		nicif_info(adapter, drv, netdev, "Set VF %d spoofchk %s\n",
			   vf, setting ? "on" : "off");

	return err;
}

int spnic_ndo_set_vf_trust(struct net_device *netdev, int vf, bool setting)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	int err;
	bool cur_trust;

	if (vf >= pci_num_vf(adapter->pdev))
		return -EINVAL;

	cur_trust = spnic_get_vf_trust(adapter->hwdev, OS_VF_ID_TO_HW(vf));
	/* same request, so just return success */
	if ((setting && cur_trust) || (!setting && !cur_trust))
		return 0;

	err = spnic_set_vf_trust(adapter->hwdev, OS_VF_ID_TO_HW(vf), setting);
	if (!err)
		nicif_info(adapter, drv, netdev, "Set VF %d trusted %s successfully\n",
			   vf, setting ? "on" : "off");
	else
		nicif_err(adapter, drv, netdev, "Failed set VF %d trusted %s\n",
			  vf, setting ? "on" : "off");

	return err;
}

static int spnic_ndo_get_vf_config(struct net_device *netdev, int vf, struct ifla_vf_info *ivi)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);

	if (vf >= pci_num_vf(adapter->pdev))
		return -EINVAL;

	spnic_get_vf_config(adapter->hwdev, OS_VF_ID_TO_HW(vf), ivi);

	return 0;
}

/**
 * spnic_ndo_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link: required link state
 *
 * Set the link state of a specified VF, regardless of physical link state
 **/
int spnic_ndo_set_vf_link_state(struct net_device *netdev, int vf_id, int link)
{
	static const char * const vf_link[] = {"auto", "enable", "disable"};
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	int err;

	/* validate the request */
	if (vf_id >= pci_num_vf(adapter->pdev)) {
		nicif_err(adapter, drv, netdev, "Invalid VF Identifier %d\n", vf_id);
		return -EINVAL;
	}

	err = spnic_set_vf_link_state(adapter->hwdev, OS_VF_ID_TO_HW(vf_id), link);
	if (!err)
		nicif_info(adapter, drv, netdev, "Set VF %d link state: %s\n",
			   vf_id, vf_link[link]);

	return err;
}

static int is_set_vf_bw_param_valid(const struct spnic_nic_dev *adapter,
				    int vf, int min_tx_rate, int max_tx_rate)
{
	/* verify VF is active */
	if (vf >= pci_num_vf(adapter->pdev)) {
		nicif_err(adapter, drv, adapter->netdev, "VF number must be less than %d\n",
			  pci_num_vf(adapter->pdev));
		return -EINVAL;
	}

	if (max_tx_rate < min_tx_rate) {
		nicif_err(adapter, drv, adapter->netdev, "Invalid rate, max rate %d must greater than min rate %d\n",
			  max_tx_rate, min_tx_rate);
		return -EINVAL;
	}

	return 0;
}

#define SPNIC_TX_RATE_TABLE_FULL	12

static int spnic_ndo_set_vf_bw(struct net_device *netdev, int vf, int min_tx_rate, int max_tx_rate)
{
	struct spnic_nic_dev *adapter = netdev_priv(netdev);
	struct nic_port_info port_info = {0};
	u8 link_status = 0;
	u32 speeds[] = {0, SPEED_10, SPEED_100, SPEED_1000, SPEED_10000,
			SPEED_25000, SPEED_40000, SPEED_50000, SPEED_100000,
			SPEED_200000};
	int err = 0;

	err = is_set_vf_bw_param_valid(adapter, vf, min_tx_rate, max_tx_rate);
	if (err)
		return err;

	err = spnic_get_link_state(adapter->hwdev, &link_status);
	if (err) {
		nicif_err(adapter, drv, netdev, "Get link status failed when set vf tx rate\n");
		return -EIO;
	}

	if (!link_status) {
		nicif_err(adapter, drv, netdev, "Link status must be up when set vf tx rate\n");
		return -EINVAL;
	}

	err = spnic_get_port_info(adapter->hwdev, &port_info, SPHW_CHANNEL_NIC);
	if (err || port_info.speed >= PORT_SPEED_UNKNOWN)
		return -EIO;

	/* rate limit cannot be less than 0 and greater than link speed */
	if (max_tx_rate < 0 || max_tx_rate > speeds[port_info.speed]) {
		nicif_err(adapter, drv, netdev, "Set vf max tx rate must be in [0 - %u]\n",
			  speeds[port_info.speed]);
		return -EINVAL;
	}

	err = spnic_set_vf_tx_rate(adapter->hwdev, OS_VF_ID_TO_HW(vf), max_tx_rate, min_tx_rate);
	if (err) {
		nicif_err(adapter, drv, netdev, "Unable to set VF %d max rate %d min rate %d%s\n",
			  vf, max_tx_rate, min_tx_rate,
			  err == SPNIC_TX_RATE_TABLE_FULL ? ", tx rate profile is full" : "");
		return -EIO;
	}

	nicif_info(adapter, drv, netdev, "Set VF %d max tx rate %d min tx rate %d successfully\n",
		   vf, max_tx_rate, min_tx_rate);

	return 0;
}

bool spnic_is_xdp_enable(struct spnic_nic_dev *nic_dev)
{
	return !!nic_dev->xdp_prog;
}

int spnic_xdp_max_mtu(struct spnic_nic_dev *nic_dev)
{
	return nic_dev->rx_buff_len - (ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN);
}

static int spnic_xdp_setup(struct spnic_nic_dev *nic_dev, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack)
{
	struct bpf_prog *old_prog = NULL;
	int max_mtu = spnic_xdp_max_mtu(nic_dev);
	int q_id;

	if (nic_dev->netdev->mtu > max_mtu) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to setup xdp program, the current MTU %d is larger than max allowed MTU %d\n",
			  nic_dev->netdev->mtu, max_mtu);
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading xdp program");
		return -EINVAL;
	}

	if (nic_dev->netdev->features & NETIF_F_LRO) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to setup xdp program while LRO is on\n");
		NL_SET_ERR_MSG_MOD(extack, "Failed to setup xdp program while LRO is on\n");
		return -EINVAL;
	}

	old_prog = xchg(&nic_dev->xdp_prog, prog);
	for (q_id = 0; q_id < nic_dev->max_qps; q_id++)
		xchg(&nic_dev->rxqs[q_id].xdp_prog, nic_dev->xdp_prog);

	if (old_prog)
		bpf_prog_put(old_prog);

	return 0;
}

static int spnic_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return spnic_xdp_setup(nic_dev, xdp->prog, xdp->extack);
	default:
		return -EINVAL;
	}
}

static const struct net_device_ops spnic_netdev_ops = {
	.ndo_open		= spnic_open,
	.ndo_stop		= spnic_close,
	.ndo_start_xmit		= spnic_xmit_frame,

	.ndo_get_stats64	=  spnic_get_stats64,

	.ndo_tx_timeout		= spnic_tx_timeout,
	.ndo_select_queue	= spnic_select_queue,
	.ndo_change_mtu		= spnic_change_mtu,
	.ndo_set_mac_address	= spnic_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,

	.ndo_vlan_rx_add_vid	= spnic_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= spnic_vlan_rx_kill_vid,

	.ndo_set_vf_mac		= spnic_ndo_set_vf_mac,
	.ndo_set_vf_vlan	= spnic_ndo_set_vf_vlan,
	.ndo_set_vf_rate	= spnic_ndo_set_vf_bw,
	.ndo_set_vf_spoofchk	= spnic_ndo_set_vf_spoofchk,

	.ndo_set_vf_trust	= spnic_ndo_set_vf_trust,

	.ndo_get_vf_config	= spnic_ndo_get_vf_config,

#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= spnic_netpoll,
#endif /* CONFIG_NET_POLL_CONTROLLER */

	.ndo_set_rx_mode	= spnic_nic_set_rx_mode,

	.ndo_bpf		= spnic_xdp,

	.ndo_set_vf_link_state	= spnic_ndo_set_vf_link_state,

	.ndo_fix_features	= spnic_fix_features,
	.ndo_set_features	= spnic_set_features,
};

static const struct net_device_ops spnicvf_netdev_ops = {
	.ndo_open		= spnic_open,
	.ndo_stop		= spnic_close,
	.ndo_start_xmit		= spnic_xmit_frame,

	.ndo_get_stats64	=  spnic_get_stats64,

	.ndo_tx_timeout		= spnic_tx_timeout,
	.ndo_select_queue	= spnic_select_queue,

	.ndo_change_mtu		= spnic_change_mtu,
	.ndo_set_mac_address	= spnic_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,

	.ndo_vlan_rx_add_vid	= spnic_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= spnic_vlan_rx_kill_vid,

#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= spnic_netpoll,
#endif /* CONFIG_NET_POLL_CONTROLLER */

	.ndo_set_rx_mode	= spnic_nic_set_rx_mode,

	.ndo_bpf		= spnic_xdp,

	.ndo_fix_features	= spnic_fix_features,
	.ndo_set_features	= spnic_set_features,
};

void spnic_set_netdev_ops(struct spnic_nic_dev *nic_dev)
{
	if (!SPNIC_FUNC_IS_VF(nic_dev->hwdev))
		nic_dev->netdev->netdev_ops = &spnic_netdev_ops;
	else
		nic_dev->netdev->netdev_ops = &spnicvf_netdev_ops;
}
