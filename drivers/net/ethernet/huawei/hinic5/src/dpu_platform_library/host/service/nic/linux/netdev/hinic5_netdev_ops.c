/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_netdev_ops.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Netdev operations implementation
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt
#include <net/dsfield.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/netlink.h>
#include <linux/debugfs.h>
#include <linux/net_tstamp.h>
#include <linux/ip.h>

#include "ossl_knl.h"
#include "drv_nic_api.h"
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#endif
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_vram_common.h"
#include "nic_cfg_comm.h"
#include "hinic5_hinic5_vram.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_dev.h"
#include "hinic5_srv_nic.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_xdp.h"
#include "hinic5_dcb.h"
#include "hinic5_irq.h"
#include "hinic5_ptp.h"
#include "hinic5_tc.h"
#include "hinic5_mag_cfg.h"
#include "hinic5_netdev_ops.h"

#if defined(HAVE_NDO_UDP_TUNNEL_ADD) || defined(HAVE_UDP_TUNNEL_NIC_INFO)
#include <net/udp_tunnel.h>
#endif /* HAVE_NDO_UDP_TUNNEL_ADD || HAVE_UDP_TUNNEL_NIC_INFO */

static void hinic5_nic_set_rx_mode(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if (netdev_uc_count(netdev) != nic_dev->netdev_uc_cnt ||
	    netdev_mc_count(netdev) != nic_dev->netdev_mc_cnt) {
		set_bit(HINIC5_UPDATE_MAC_FILTER, &nic_dev->flags);
		nic_dev->netdev_uc_cnt = netdev_uc_count(netdev);
		nic_dev->netdev_mc_cnt = netdev_mc_count(netdev);
	}

	queue_work(nic_dev->workq, &nic_dev->rx_mode_work);
}

static int hinic5_alloc_txrxq_resources(struct hinic5_nic_dev *nic_dev,
					struct hinic5_dyna_txrxq_params *q_params)
{
	u32 size;
	int err;
	u16 total_num_qps = q_params->num_qps + q_params->xdp_qps;

	size = sizeof(*q_params->txqs_res) * (total_num_qps);
	q_params->txqs_res = kzalloc(size, GFP_KERNEL);
	if (!q_params->txqs_res) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc txqs resources array\n");
		return -ENOMEM;
	}

	size = sizeof(*q_params->rxqs_res) * (total_num_qps);
	q_params->rxqs_res = kzalloc(size, GFP_KERNEL);
	if (!q_params->rxqs_res) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc rxqs resource array\n");
		err = -ENOMEM;
		goto alloc_rxqs_res_arr_err;
	}

	size = sizeof(*q_params->irq_cfg) * (total_num_qps);
	q_params->irq_cfg = kzalloc(size, GFP_KERNEL);
	if (!q_params->irq_cfg) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc irq resource array\n");
		err = -ENOMEM;
		goto alloc_irq_cfg_err;
	}

	err = hinic5_alloc_txqs_res(nic_dev, total_num_qps,
				    q_params->sq_depth, q_params->txqs_res);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc txqs resource\n");
		goto alloc_txqs_res_err;
	}

	err = hinic5_alloc_rxqs_res(nic_dev, total_num_qps,
				    q_params->rq_depth, q_params->rxqs_res);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc rxqs resource\n");
		goto alloc_rxqs_res_err;
	}

	return 0;

alloc_rxqs_res_err:
	hinic5_free_txqs_res(nic_dev, q_params->num_qps, q_params->sq_depth,
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

static void hinic5_free_txrxq_resources(struct hinic5_nic_dev *nic_dev,
					struct hinic5_dyna_txrxq_params *q_params)
{
	u16 total_num_qps = q_params->num_qps + q_params->xdp_qps;

	hinic5_free_rxqs_res(nic_dev, total_num_qps, q_params->rq_depth,
			     q_params->rxqs_res);
	hinic5_free_txqs_res(nic_dev, total_num_qps, q_params->sq_depth,
			     q_params->txqs_res);

	kfree(q_params->irq_cfg);
	q_params->irq_cfg = NULL;

	kfree(q_params->rxqs_res);
	q_params->rxqs_res = NULL;

	kfree(q_params->txqs_res);
	q_params->txqs_res = NULL;
}

static void hinic5_remove_configure_txrxqs(struct hinic5_nic_dev *nic_dev)
{
	hinic5_remove_configure_rxqs(nic_dev);
}

static int hinic5_configure_txrxqs(struct hinic5_nic_dev *nic_dev,
				   struct hinic5_dyna_txrxq_params *q_params)
{
	int err;
	u16 total_num_qps = q_params->num_qps + q_params->xdp_qps;

	err = hinic5_configure_txqs(nic_dev, total_num_qps,
				    q_params->sq_depth, q_params->txqs_res);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to configure txqs\n");
		return err;
	}

	err = hinic5_configure_rxqs(nic_dev, total_num_qps,
				    q_params->rq_depth, q_params->rxqs_res);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to configure rxqs\n");
		return err;
	}

	return 0;
}

static void config_dcb_qps_map(struct hinic5_nic_dev *nic_dev)
{
	u8 num_cos = hinic5_get_dev_user_cos_num(nic_dev);
	struct net_device *netdev = nic_dev->netdev;

	if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) == 0) {
		hinic5_update_tx_db_cos(nic_dev, 0);
		return;
	}

	hinic5_update_qp_cos_cfg(nic_dev);
	/* For now, we don't support to change num_cos */
	if (num_cos > nic_dev->cos_config_num_max ||
	    nic_dev->q_params.num_qps < num_cos) {
		nicif_err(nic_dev, drv, netdev, "Invalid num_cos: %u or num_qps: %u, disable DCB\n",
			  num_cos, nic_dev->q_params.num_qps);
		nic_dev->q_params.num_cos = 0;
		clear_bit(HINIC5_DCB_ENABLE, &nic_dev->flags);
		clear_bit(HINIC5_DCB_ENABLE, &nic_dev->nic_hinic5_vram->flags);
		/* if we can't enable rss or get enough num_qps,
		 * need to sync default configure to hw
		 */
		hinic5_configure_dcb(netdev);
	}

	hinic5_update_tx_db_cos(nic_dev, 1);
}

static int hinic5_configure(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	int err;
	int is_in_kexec = hinic5_vram_get_kexec_flag();

	if (is_in_kexec == 0) {
		err = hinic5_set_port_mtu(nic_dev->hwdev, (u16)netdev->mtu);
		if (err != 0) {
			nicif_err(nic_dev, drv, netdev, "Failed to set mtu\n");
			return err;
		}
	}

	config_dcb_qps_map(nic_dev);

	/* rx rss init */
	err = hinic5_rx_configure(netdev, test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) ? 1 : 0);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to configure rx\n");
		return err;
	}

	return 0;
}

static void hinic5_remove_configure(struct hinic5_nic_dev *nic_dev)
{
	hinic5_rx_remove_configure(nic_dev->netdev);
}

/* try to modify the number of irq to the target number,
 * and return the actual number of irq.
 */
static u16 hinic5_qp_irq_change(struct hinic5_nic_dev *nic_dev,
				u16 dst_num_qp_irq)
{
	struct irq_info *qps_irq_info = nic_dev->qps_irq_info;
	u16 resp_irq_num, irq_num_gap, i;
	u16 idx;
	int err;

	if (dst_num_qp_irq > nic_dev->num_qp_irq) {
		irq_num_gap = dst_num_qp_irq - nic_dev->num_qp_irq;
		err = hinic5_alloc_irqs(nic_dev->hwdev, SERVICE_T_NIC,
					irq_num_gap,
					&qps_irq_info[nic_dev->num_qp_irq],
					&resp_irq_num);
		if (err != 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc irqs\n");
			return nic_dev->num_qp_irq;
		}

		nic_dev->num_qp_irq += resp_irq_num;
	} else if (dst_num_qp_irq < nic_dev->num_qp_irq) {
		irq_num_gap = nic_dev->num_qp_irq - dst_num_qp_irq;
		for (i = 0; i < irq_num_gap; i++) {
			idx = (nic_dev->num_qp_irq - i) - 1;
			hinic5_free_irq(nic_dev->hwdev, SERVICE_T_NIC,
					qps_irq_info[idx].irq_id);
			qps_irq_info[idx].irq_id = 0;
			qps_irq_info[idx].msix_entry_idx = 0;
		}
		nic_dev->num_qp_irq = dst_num_qp_irq;
	}

	return nic_dev->num_qp_irq;
}

static void config_dcb_num_qps(struct hinic5_nic_dev *nic_dev,
			       const struct hinic5_dyna_txrxq_params *q_params,
			       u16 max_qps)
{
	u8 num_cos = q_params->num_cos;

	if (num_cos == 0 || num_cos > nic_dev->cos_config_num_max || num_cos > max_qps)
		return; /* will disable DCB in config_dcb_qps_map() */

	hinic5_update_qp_cos_cfg(nic_dev);
}

int hinic5_set_usr_qps_num(struct net_device *netdev, u16 usr_qps_num)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if (usr_qps_num + nic_dev->q_params.num_qps > nic_dev->max_qps) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "The usr qps num is too big, usr qps num: %u, knl qps num: %u\n",
			  usr_qps_num, nic_dev->q_params.num_qps);
		return -EINVAL;
	}
	nic_dev->usr_qps_num = usr_qps_num;
	return 0;
}

static void hinic5_knl_qps_num_check(struct hinic5_nic_dev *nic_dev)
{
	/* nic_dev->usr_qps_num is configured by product side */
	if (nic_dev->usr_qps_num == 0)
		return;
	if (nic_dev->usr_qps_num + nic_dev->q_params.num_qps > nic_dev->max_qps) {
		nic_dev->q_params.num_qps = nic_dev->max_qps - nic_dev->usr_qps_num;
		nicif_warn(nic_dev, drv, nic_dev->netdev,
			   "Can not get enough knl qps, adjust kernel qps num to %u\n",
			   nic_dev->q_params.num_qps);
	}
}

static void hinic5_config_num_qps(struct hinic5_nic_dev *nic_dev,
				  struct hinic5_dyna_txrxq_params *q_params)
{
	u16 alloc_num_irq, cur_num_irq;
	u16 dst_num_irq;

	/* Validate knl qps based on usr qps */
	(void)hinic5_knl_qps_num_check(nic_dev);

	if (test_bit(HINIC5_RSS_ENABLE, &nic_dev->flags) == 0)
		q_params->num_qps = 1;
	config_dcb_num_qps(nic_dev, q_params, q_params->num_qps);

	if (nic_dev->num_qp_irq >= q_params->num_qps + q_params->xdp_qps)
		goto out;

	cur_num_irq = nic_dev->num_qp_irq;

	alloc_num_irq = hinic5_qp_irq_change(nic_dev, q_params->num_qps + q_params->xdp_qps);
	if (alloc_num_irq < q_params->num_qps + q_params->xdp_qps) {
		if (q_params->xdp_qps != 0) {
			/* Enabling XDP and the number of XDP and kernel-equalized queues. */
			q_params->num_qps = alloc_num_irq / XDP_QPS_NUM_EXPANSION;
			q_params->xdp_qps = alloc_num_irq / XDP_QPS_NUM_EXPANSION;
		} else {
			q_params->num_qps = alloc_num_irq;
		}
		config_dcb_num_qps(nic_dev, q_params, q_params->num_qps);
		nicif_warn(nic_dev, drv, nic_dev->netdev,
			   "Can not get enough irqs, adjust num_qps to %u\n", q_params->num_qps);

		/* The current irq may be in use, we must keep it */
		dst_num_irq = (u16)max_t(u16, cur_num_irq, q_params->num_qps + q_params->xdp_qps);
		hinic5_qp_irq_change(nic_dev, dst_num_irq);
	}

out:
	nicif_info(nic_dev, drv, nic_dev->netdev, "Finally num_qps: %u\n",
		   q_params->num_qps);
}

/* determin num_qps from rss_tmpl_id/irq_num/dcb_en */
static int hinic5_setup_num_qps(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u32 irq_size;

	nic_dev->num_qp_irq = 0;

	irq_size = sizeof(*nic_dev->qps_irq_info) * nic_dev->max_qps;
	if (irq_size == 0) {
		nicif_err(nic_dev, drv, netdev, "Cannot allocate zero size entries\n");
		return -EINVAL;
	}
	nic_dev->qps_irq_info = kzalloc(irq_size, GFP_KERNEL);
	if (!nic_dev->qps_irq_info)
		return -ENOMEM;

	hinic5_config_num_qps(nic_dev, &nic_dev->q_params);

	return 0;
}

static void hinic5_destroy_num_qps(struct hinic5_nic_dev *nic_dev)
{
	u16 i;

	for (i = 0; i < nic_dev->num_qp_irq; i++)
		hinic5_free_irq(nic_dev->hwdev, SERVICE_T_NIC,
				nic_dev->qps_irq_info[i].irq_id);

	kfree(nic_dev->qps_irq_info);
}

int hinic5_set_flow_bifurcation_group_num(struct net_device *netdev, u8 group_num)
{
	int err;
	u8 enable_queue_pooling;
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!netdev)
		return -ENODEV;

	nic_dev = netdev_priv(netdev);
	if (group_num < HINIC5_GROUP_NUMBER_MIN || group_num > HINIC5_GROUP_NUMBER_MAX) {
		nicif_err(nic_dev, drv, netdev, "The group number: %d is out of [%d, %d].\n",
			  group_num, HINIC5_GROUP_NUMBER_MIN, HINIC5_GROUP_NUMBER_MAX);
		return -EINVAL;
	}
	nic_dev->flow_bifur_group_num = (u8)roundup_pow_of_two(group_num);

	if (nic_dev->flow_bifur_group_num == 0) {
		nicif_err(nic_dev, drv, netdev, "The value of flow_bifur_group_num: %d is 0\n",
			  nic_dev->flow_bifur_group_num);
		return -EINVAL;
	}
	enable_queue_pooling = nic_dev->flow_bifur_group_num > HINIC5_GROUP_NUMBER_MIN ? 1 : 0;
	hinic5_set_queue_pooling(nic_dev->hwdev, enable_queue_pooling);

	if (nic_dev->q_params.num_qps > (nic_dev->max_qps / nic_dev->flow_bifur_group_num)) {
		nicif_err(nic_dev, drv, netdev,
			  "The value of qp_nums: %d in use is greater than (max_qps / group_num): %d\n",
			  nic_dev->q_params.num_qps,
			  (nic_dev->max_qps / nic_dev->flow_bifur_group_num));
		return -EINVAL;
	}

	nic_dev->usr_qps_num = nic_dev->max_qps - nic_dev->max_qps / nic_dev->flow_bifur_group_num;

	err = hinic5_rx_configure(netdev, test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) ? 1 : 0);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to configure rx when switch flow bifur group num.\n");
		return err;
	}
	return 0;
}
EXPORT_SYMBOL(hinic5_set_flow_bifurcation_group_num);

int hinic5_cfg_flow_bifurcation_paras(struct net_device *netdev, u8 op_code,
				      u8 group_id, u32 *indir, u16 indir_length)
{
	int err;
	u16 expect_indir_length;
	u16 indir_start;
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!netdev)
		return -ENODEV;

	nic_dev = netdev_priv(netdev);
	if (group_id < HINIC5_GROUP_NUMBER_MIN || group_id > nic_dev->flow_bifur_group_num) {
		nicif_err(nic_dev, drv, netdev,
			  "The group id: %u is invalid, current group num: %u\n",
			  group_id, nic_dev->flow_bifur_group_num);
		return -EINVAL;
	}

	if (!indir) {
		nicif_err(nic_dev, drv, netdev, "The indir is NULL\n");
		return -EINVAL;
	}

	expect_indir_length = NIC_RSS_INDIR_SIZE / nic_dev->flow_bifur_group_num;
	if (indir_length != expect_indir_length) {
		nicif_err(nic_dev, drv, netdev,
			  "The indir_length: %u is invalid, expect_indir_length: %u\n",
			  indir_length, expect_indir_length);
		return -EINVAL;
	}

	indir_start = group_id * indir_length;
	if (op_code == 0) {
		memcpy(indir, nic_dev->rss_indir + indir_start, sizeof(u32) * indir_length);
		return 0;
	}

	memcpy(nic_dev->rss_indir + indir_start, indir, sizeof(u32) * indir_length);
	err = hinic5_rss_set_indir_tbl(nic_dev->hwdev, nic_dev->rss_indir);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to set rss indir table when cfg flow bifur.\n");
		return -EFAULT;
	}
	return 0;
}
EXPORT_SYMBOL(hinic5_cfg_flow_bifurcation_paras);

int hinic5_force_port_disable(struct hinic5_nic_dev *nic_dev)
{
	int err;

	down(&nic_dev->port_state_sem);

	err = hinic5_set_port_enable(nic_dev->hwdev, false, HINIC5_CHANNEL_NIC);
	if (err == 0)
		nic_dev->force_port_disable = true;

	up(&nic_dev->port_state_sem);

	return err;
}

int hinic5_force_set_port_state(struct hinic5_nic_dev *nic_dev, bool enable)
{
	int err = 0;

	down(&nic_dev->port_state_sem);

	nic_dev->force_port_disable = false;
	err = hinic5_set_port_enable(nic_dev->hwdev, enable,
				     HINIC5_CHANNEL_NIC);

	up(&nic_dev->port_state_sem);

	return err;
}

int hinic5_maybe_set_port_state(struct hinic5_nic_dev *nic_dev, bool enable)
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

	err = hinic5_set_port_enable(nic_dev->hwdev, enable,
				     HINIC5_CHANNEL_NIC);

	up(&nic_dev->port_state_sem);

	return err;
}

static void hinic5_print_link_message(struct hinic5_nic_dev *nic_dev,
				      u8 link_status)
{
	if (nic_dev->link_status == link_status)
		return;

	nic_dev->link_status = link_status;

	nicif_info(nic_dev, link, nic_dev->netdev, "Link is %s\n",
		   ((link_status != 0) ? "up" : "down"));
}

static int hinic5_alloc_channel_resources(struct hinic5_nic_dev *nic_dev,
					  struct hinic5_dyna_qp_params *qp_params,
					  struct hinic5_dyna_txrxq_params *trxq_params)
{
	int err;

	qp_params->num_qps = trxq_params->num_qps;
	qp_params->xdp_qps = trxq_params->xdp_qps;
	qp_params->sq_depth = trxq_params->sq_depth;
	qp_params->rq_depth = trxq_params->rq_depth;

	err = hinic5_alloc_qps(nic_dev->hwdev, nic_dev->qps_irq_info,
			       qp_params);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc qps\n");
		return err;
	}

	err = hinic5_alloc_txrxq_resources(nic_dev, trxq_params);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc txrxq resources\n");
		hinic5_free_qps(nic_dev->hwdev, qp_params);
		return err;
	}

	return 0;
}

static void hinic5_free_channel_resources(struct hinic5_nic_dev *nic_dev,
					  struct hinic5_dyna_qp_params *qp_params,
					  struct hinic5_dyna_txrxq_params *trxq_params)
{
	mutex_lock(&nic_dev->nic_mutex);
	hinic5_free_txrxq_resources(nic_dev, trxq_params);
	hinic5_free_qps(nic_dev->hwdev, qp_params);
	mutex_unlock(&nic_dev->nic_mutex);
}

static int hinic5_open_channel(struct hinic5_nic_dev *nic_dev,
			       struct hinic5_dyna_qp_params *qp_params,
			       struct hinic5_dyna_txrxq_params *trxq_params)
{
	int err;

	err = hinic5_init_qps(nic_dev->hwdev, qp_params);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init qps\n");
		return err;
	}

	err = hinic5_configure_txrxqs(nic_dev, trxq_params);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to configure txrxqs\n");
		goto cfg_txrxqs_err;
	}

	err = hinic5_qps_irq_init(nic_dev);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init txrxq irq\n");
		goto init_qp_irq_err;
	}

	err = hinic5_configure(nic_dev);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to init txrxq irq\n");
		goto configure_err;
	}

	return 0;

configure_err:
	hinic5_qps_irq_deinit(nic_dev);

init_qp_irq_err:
	hinic5_remove_configure_txrxqs(nic_dev);

cfg_txrxqs_err:
	hinic5_deinit_qps(nic_dev->hwdev, qp_params);

	return err;
}

static void hinic5_close_channel(struct hinic5_nic_dev *nic_dev,
				 struct hinic5_dyna_qp_params *qp_params)
{
	hinic5_remove_configure(nic_dev);
	hinic5_qps_irq_deinit(nic_dev);
	hinic5_remove_configure_txrxqs(nic_dev);
	hinic5_deinit_qps(nic_dev->hwdev, qp_params);
}

int hinic5_vport_up(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 link_status = 0;
	u16 glb_func_id;
	int err;

	err = hinic5_cache_out_qps_res(nic_dev->hwdev);
	if (err != 0)
		return err;

	glb_func_id = hinic5_global_func_id(nic_dev->hwdev);
	err = hinic5_set_vport_enable(nic_dev->hwdev, glb_func_id, true,
				      HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to enable vport\n");
		goto vport_enable_err;
	}

	err = hinic5_maybe_set_port_state(nic_dev, true);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to enable port\n");
		goto port_enable_err;
	}

	netif_set_real_num_tx_queues(netdev, nic_dev->q_params.num_qps);
	netif_set_real_num_rx_queues(netdev, nic_dev->q_params.num_qps);
	netif_tx_wake_all_queues(netdev);

	if (test_bit(HINIC5_FORCE_LINK_UP, &nic_dev->flags) != 0) {
		link_status = true;
		netif_carrier_on(netdev);
	} else {
		err = hinic5_get_link_state(nic_dev->hwdev, &link_status);
		if (err == 0 && link_status != 0)
			netif_carrier_on(netdev);
	}

	queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task,
			   HINIC5_MODERATONE_DELAY);
	if (test_bit(HINIC5_RXQ_RECOVERY, &nic_dev->flags) != 0)
		queue_delayed_work(nic_dev->workq, &nic_dev->rxq_check_work, HZ);

	hinic5_print_link_message(nic_dev, link_status);

	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
		hinic5_notify_all_vfs_link_changed(nic_dev->hwdev, link_status);

	return 0;

port_enable_err:
	hinic5_set_vport_enable(nic_dev->hwdev, glb_func_id, false,
				HINIC5_CHANNEL_NIC);

vport_enable_err:
	hinic5_flush_qps_res(nic_dev->hwdev);
	/* After set vport disable 100ms, no packets will be send to host */
	msleep(100);

	return err;
}

void hinic5_vport_down(struct hinic5_nic_dev *nic_dev)
{
	u16 glb_func_id;

	netif_carrier_off(nic_dev->netdev);
	netif_tx_disable(nic_dev->netdev);

	cancel_delayed_work_sync(&nic_dev->rxq_check_work);

	cancel_delayed_work_sync(&nic_dev->moderation_task);

	if (hinic5_get_chip_present_flag(nic_dev->hwdev) != 0) {
		if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
			hinic5_notify_all_vfs_link_changed(nic_dev->hwdev, 0);

		if (nic_dev->state != 0)
			nicif_info(nic_dev, drv, nic_dev->netdev, "Skip changing mag status!\n");
		else
			hinic5_maybe_set_port_state(nic_dev, false);

		glb_func_id = hinic5_global_func_id(nic_dev->hwdev);
		hinic5_set_vport_enable(nic_dev->hwdev, glb_func_id, false,
					HINIC5_CHANNEL_NIC);

		hinic5_flush_txqs(nic_dev->netdev);
		/* After set vport disable 100ms,
		 * no packets will be send to host
		 * FPGA set 2000ms
		 */
		msleep(nic_dev->timeout.wait_flush_qp_res_timeout);

		if (nic_dev->usr_qps_num > 0)
			hinic5_flush_qps_res_by_nums(nic_dev->hwdev,
						     nic_dev->max_qps - nic_dev->usr_qps_num);
		else
			hinic5_flush_qps_res(nic_dev->hwdev);
	}
}

int hinic5_change_channel_settings(struct hinic5_nic_dev *nic_dev,
				   struct hinic5_dyna_txrxq_params *trxq_params,
				   hinic5_reopen_handler reopen_handler,
				   const void *priv_data)
{
	struct hinic5_dyna_qp_params new_qp_params = {0};
	struct hinic5_dyna_qp_params cur_qp_params = {0};
	int err;
	u16 num_qps;

	hinic5_config_num_qps(nic_dev, trxq_params);

	err = hinic5_alloc_channel_resources(nic_dev, &new_qp_params,
					     trxq_params);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to alloc channel resources\n");
		return err;
	}

	if (test_and_set_bit(HINIC5_CHANGE_RES_INVALID, &nic_dev->flags) == 0) {
		hinic5_vport_down(nic_dev);
		hinic5_close_channel(nic_dev, &cur_qp_params);
		hinic5_free_channel_resources(nic_dev, &cur_qp_params,
					      &nic_dev->q_params);
	}
	num_qps = trxq_params->num_qps + trxq_params->xdp_qps;
	if (nic_dev->num_qp_irq > num_qps)
		hinic5_qp_irq_change(nic_dev, num_qps);
	nic_dev->q_params = *trxq_params;

	err = hinic5_open_channel(nic_dev, &new_qp_params, trxq_params);
	if (err != 0)
		goto open_channel_err;

	err = hinic5_vport_up(nic_dev);
	if (err != 0)
		goto vport_up_err;

	clear_bit(HINIC5_CHANGE_RES_INVALID, &nic_dev->flags);
	nicif_info(nic_dev, drv, nic_dev->netdev, "Change channel settings success\n");

	return 0;

vport_up_err:
	hinic5_close_channel(nic_dev, &new_qp_params);

open_channel_err:
	hinic5_free_channel_resources(nic_dev, &new_qp_params, trxq_params);

	return err;
}

int hinic5_open(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_dyna_qp_params qp_params = {0};
	int err;

	err = hinic5_wait_for_devices_flush(NULL, 0, NULL);
	if (err != 0)
		return err;

	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) != 0) {
		nicif_info(nic_dev, drv, netdev, "Netdev already open, do nothing\n");
		return 0;
	}

	err = hinic5_init_nicio_res(nic_dev->hwdev, nic_dev->usr_qps_num);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to init nicio resources\n");
		return err;
	}

	err = hinic5_setup_num_qps(nic_dev);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to setup num_qps\n");
		goto setup_qps_err;
	}

	err = hinic5_alloc_channel_resources(nic_dev, &qp_params,
					     &nic_dev->q_params);
	if (err != 0)
		goto alloc_channel_res_err;

	err = hinic5_open_channel(nic_dev, &qp_params, &nic_dev->q_params);
	if (err != 0)
		goto open_channel_err;

	err = hinic5_vport_up(nic_dev);
	if (err != 0)
		goto vport_up_err;

	set_bit(HINIC5_INTF_UP, &nic_dev->flags);
	nicif_info(nic_dev, drv, nic_dev->netdev, "Netdev is up\n");

	return 0;

vport_up_err:
	hinic5_close_channel(nic_dev, &qp_params);

open_channel_err:
	hinic5_free_channel_resources(nic_dev, &qp_params, &nic_dev->q_params);

alloc_channel_res_err:
	hinic5_destroy_num_qps(nic_dev);

setup_qps_err:
	hinic5_deinit_nicio_res(nic_dev->hwdev);

	return err;
}

#ifdef HAVE_XDP_SUPPORT
int hinic5_set_xdp_num(struct hinic5_nic_dev *nic_dev, struct hinic5_dyna_txrxq_params *trxq_params)
{
	if (hinic5_is_xdp_enable(nic_dev)) {
		trxq_params->xdp_qps = trxq_params->num_qps;
		/* When XDP is enabled,
		 * check that kernel queue num plus XDP queue num is less than max queue num
		 */
		if (trxq_params->num_qps + trxq_params->xdp_qps > nic_dev->max_qps) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to change num qps\n");
			return -EINVAL;
		}
	} else {
		trxq_params->xdp_qps = 0;
	}

	return 0;
}

int hinic5_safe_switch_channels(struct hinic5_nic_dev *nic_dev)
{
	int err;
	struct hinic5_dyna_txrxq_params q_params = {0};

	q_params = nic_dev->q_params;
	q_params.sq_depth = nic_dev->q_params.sq_depth;
	q_params.rq_depth = nic_dev->q_params.rq_depth;
	q_params.txqs_res = NULL;
	q_params.rxqs_res = NULL;
	q_params.irq_cfg = NULL;

	err = hinic5_set_xdp_num(nic_dev, &q_params);
	if (err != 0)
		return err;
	return hinic5_change_channel_settings(nic_dev, &q_params, NULL, NULL);
}
#endif

int hinic5_close(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_dyna_qp_params qp_params = {0};

	if (test_and_clear_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0) {
		nicif_info(nic_dev, drv, netdev, "Netdev already close, do nothing\n");
		return 0;
	}

	if (test_and_clear_bit(HINIC5_CHANGE_RES_INVALID, &nic_dev->flags) != 0)
		goto out;

	hinic5_vport_down(nic_dev);
	hinic5_close_channel(nic_dev, &qp_params);
	hinic5_free_channel_resources(nic_dev, &qp_params, &nic_dev->q_params);

out:
	hinic5_deinit_nicio_res(nic_dev->hwdev);
	hinic5_destroy_num_qps(nic_dev);

	nicif_info(nic_dev, drv, nic_dev->netdev, "Netdev is down\n");

	return 0;
}

/*
 * Currently, hinic5_close is resued to flush nic devices during sdinanoos-hotrepalce.
 */
int hinic5_flush_nic_dev(void *priv_data)
{
	struct hinic5_lld_dev *lld_dev = priv_data;
	struct net_device *net_dev = NULL;
	struct hinic5_nic_dev *nic_dev = NULL;
	int is_in_kexec;
	int err;

	net_dev = hinic5_get_netdev_by_lld(lld_dev);
	if (!net_dev)
		return -ENODEV;

	is_in_kexec = hinic5_vram_get_kexec_flag();

	nic_dev = netdev_priv(net_dev);

	nic_dev->state = (u32)is_in_kexec;
	err = hinic5_close(net_dev);
	nic_dev->state = 0;

	return err;
}

#define IPV6_ADDR_LEN  4
#define PKT_INFO_LEN   9
#define BITS_PER_TUPLE 32
static u32 calc_xor_rss(u8 *rss_tuple, u32 len)
{
	u32 hash_value;
	u32 i;

	hash_value = rss_tuple[0];
	for (i = 1; i < len; i++)
		hash_value = hash_value ^ rss_tuple[i];

	return hash_value;
}

static u32 calc_toep_rss(const u32 *rss_tuple, u32 len, const u32 *rss_key)
{
	u32 rss = 0;
	u32 i, j;

	for (i = 1; i <= len; i++) {
		for (j = 0; j < BITS_PER_TUPLE; j++)
			if ((rss_tuple[i - 1] & ((u32)1 <<
			    (u32)((BITS_PER_TUPLE - 1) - j))) != 0)
				rss ^= (rss_key[i - 1] << j) |
					(u32)((u64)rss_key[i] >>
					(BITS_PER_TUPLE - j));
	}

	return rss;
}

#define RSS_VAL(val, type)		\
	(((type) == HINIC5_RSS_HASH_ENGINE_TYPE_TOEP) ? ntohl(val) : (val))

static u8 parse_ipv6_info(struct sk_buff *skb, u32 *rss_tuple,
			  u8 hash_engine, u32 *len, unsigned char *l3_hdr)
{
	unsigned char *l4_hdr = (skb->encapsulation != 0) ?
		skb_inner_transport_header(skb) : skb_transport_header(skb);
	struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)l3_hdr;
	u32 *saddr = (u32 *)(u8 *)&ipv6hdr->saddr;
	u32 *daddr = (u32 *)(u8 *)&ipv6hdr->daddr;
	u8 i;

	for (i = 0; i < IPV6_ADDR_LEN; i++) {
		rss_tuple[i] = RSS_VAL(daddr[i], hash_engine);
		/* The offset of the sport relative to the dport is 4 */
		rss_tuple[(u32)(i + IPV6_ADDR_LEN)] =
			RSS_VAL(saddr[i], hash_engine);
	}
	*len = IPV6_ADDR_LEN + IPV6_ADDR_LEN;

	/* IPv6 packets with extension headers(include IPv6 fragment packets)
	 * re hashed according to L3(s_ip&d_ip), align with ucode RSS.
	 */
	if ((uintptr_t)l3_hdr + sizeof(*ipv6hdr) == (uintptr_t)l4_hdr)
		return ipv6hdr->nexthdr;
	return 0;
}

static u32 calc_rss_prepare(struct sk_buff *skb, u32 *rss_tuple, struct hinic5_nic_dev *nic_dev)
{
	u32 len = 0;
	u8 l4_proto = 0;
	unsigned char *l3_hdr = NULL;
	unsigned char *l4_hdr = NULL;
	struct iphdr *iphdr = NULL;
	u8 tunnel_flag = skb->encapsulation;
	struct nic_rss_type rss_type = nic_dev->rss_type;
	u8 hash_engine = nic_dev->rss_hash_engine;

	l3_hdr = (tunnel_flag != 0) ? skb_inner_network_header(skb) : skb_network_header(skb);
	iphdr = (struct iphdr *)l3_hdr;

	if (iphdr->version == IPV4_VERSION) {
		rss_tuple[len++] = RSS_VAL(iphdr->daddr, hash_engine);
		rss_tuple[len++] = RSS_VAL(iphdr->saddr, hash_engine);

		/* IP fragmented packets are hashed according to L3(s_ip&d_ip),
		 * align with ucode RSS.
		 */
		l4_proto = ip_is_fragment(iphdr) ? 0 : iphdr->protocol;
	} else if (iphdr->version == IPV6_VERSION) {
		l4_proto = parse_ipv6_info(skb, (u32 *)rss_tuple, hash_engine, &len, l3_hdr);
	} else {
		return len;
	}

	if ((iphdr->version == IPV4_VERSION &&
	     ((l4_proto == IPPROTO_UDP && rss_type.udp_ipv4 != 0) ||
	      (l4_proto == IPPROTO_TCP && rss_type.tcp_ipv4 != 0))) ||
	    (iphdr->version == IPV6_VERSION &&
	     ((l4_proto == IPPROTO_UDP && rss_type.udp_ipv6 != 0) ||
		(l4_proto == IPPROTO_TCP && rss_type.tcp_ipv6 != 0)))) {
		l4_hdr = (tunnel_flag != 0) ?
			skb_inner_transport_header(skb) : skb_transport_header(skb);
		/* High 16 bits are dport, low 16 bits are sport. */
		rss_tuple[len++] = ((u32)ntohs(*((u16 *)l4_hdr + 1U)) << 16) |
			ntohs(*(u16 *)l4_hdr);
	} /* rss_type.ipv4 and rss_type.ipv6 default on. */
	return len;
}

static u16 select_queue_by_hash_func(struct net_device *dev, struct sk_buff *skb,
				     unsigned int num_tx_queues)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(dev);
	struct iphdr *iphdr = NULL;
	struct ipv6hdr *ipv6hdr = NULL;
	u32 rss_tuple[PKT_INFO_LEN] = {0};
	u32 len = 0;
	u32 hash = 0;
	u32 *saddr = NULL;
	u32 *daddr = NULL;
	u8 hash_engine = nic_dev->rss_hash_engine;

	if (skb_rx_queue_recorded(skb)) {
		hash = skb_get_rx_queue(skb);
		if (unlikely(hash >= num_tx_queues))
			hash %= num_tx_queues;

		return (u16)hash;
	}

	iphdr = ip_hdr(skb);

	/* If the tunnel packet has outer IP fragmentation or an IPv6 extension header,
	 * it should be hashed directly at the L3.
	 */
	if (skb->encapsulation != 0) {
		if (iphdr->version == IPV4_VERSION) {
			if (ip_is_fragment(iphdr)) {
				rss_tuple[len++] = RSS_VAL(iphdr->daddr, hash_engine);
				rss_tuple[len++] = RSS_VAL(iphdr->saddr, hash_engine);
				goto hash_by_l3;
			}
		} else if (iphdr->version == IPV6_VERSION) {
			ipv6hdr = ipv6_hdr(skb);
			saddr = (u32 *)(u8 *)&ipv6hdr->saddr;
			daddr = (u32 *)(u8 *)&ipv6hdr->daddr;
			if (skb_network_header(skb) + sizeof(*ipv6hdr) !=
			    skb_transport_header(skb)) {
				for (len = 0; len < IPV6_ADDR_LEN; len++) {
					rss_tuple[len] = RSS_VAL(daddr[len], hash_engine);
					/* The offset of the sport relative to the dport is 4 */
					rss_tuple[(u32)(len + IPV6_ADDR_LEN)] =
						RSS_VAL(saddr[len], hash_engine);
				}
				len += IPV6_ADDR_LEN;
				goto hash_by_l3;
			}
		} else {
			return HINIC5_INVALID_QUEUE;
		}
	}

	/* Calculate the RSS tuple and length for
	 * the inner layer of tunnel packets or non-tunnel packets.
	 */
	len = calc_rss_prepare(skb, (u32 *)rss_tuple, nic_dev);
	if (len == 0)
		return HINIC5_INVALID_QUEUE;

hash_by_l3:
	if (hash_engine == HINIC5_RSS_HASH_ENGINE_TYPE_TOEP)
		hash = calc_toep_rss((u32 *)rss_tuple, len,
				     nic_dev->rss_hkey_be);
	else
		hash = calc_xor_rss((u8 *)rss_tuple, len * (u32)sizeof(u32));

	return (u16)nic_dev->rss_indir[hash & 0xFF];
}

#define GET_DSCP_PRI_OFFSET 2
static u8 hinic5_get_dscp_up(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb)
{
	int dscp_cp;

	if (skb->protocol == htons(ETH_P_IP))
		dscp_cp = ipv4_get_dsfield(ip_hdr(skb)) >> GET_DSCP_PRI_OFFSET;
	else if (skb->protocol == htons(ETH_P_IPV6))
		dscp_cp = ipv6_get_dsfield(ipv6_hdr(skb)) >> GET_DSCP_PRI_OFFSET;
	else
		return nic_dev->hw_dcb_cfg.default_cos;
	return nic_dev->hw_dcb_cfg.dscp2cos[dscp_cp];
}

#if defined(HAVE_NDO_SELECT_QUEUE_SB_DEV_ONLY)
static u16 hinic5_select_queue(struct net_device *netdev, struct sk_buff *skb,
			       struct net_device *sb_dev)
#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
#if defined(HAVE_NDO_SELECT_QUEUE_SB_DEV)
static u16 hinic5_select_queue(struct net_device *netdev, struct sk_buff *skb,
			       struct net_device *sb_dev,
			       select_queue_fallback_t fallback)
#else
static u16 hinic5_select_queue(struct net_device *netdev, struct sk_buff *skb,
			       __always_unused void *accel,
			       select_queue_fallback_t fallback)
#endif

#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL)
static u16 hinic5_select_queue(struct net_device *netdev, struct sk_buff *skb,
			       __always_unused void *accel)

#else
static u16 hinic5_select_queue(struct net_device *netdev, struct sk_buff *skb)
#endif /* end of HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK */
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u16 txq;
	u8 cos, qp_num;

	if (test_bit(HINIC5_SAME_RXTX, &nic_dev->flags) != 0) {
		txq = select_queue_by_hash_func(netdev, skb, netdev->real_num_tx_queues);
		if (txq != HINIC5_INVALID_QUEUE)
			return txq;
	}

	txq =
#if defined(HAVE_NDO_SELECT_QUEUE_SB_DEV_ONLY)
		netdev_pick_tx(netdev, skb, NULL);
#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
#ifdef HAVE_NDO_SELECT_QUEUE_SB_DEV
		fallback(netdev, skb, sb_dev);
#else
		fallback(netdev, skb);
#endif
#else
		skb_tx_hash(netdev, skb);
#endif

	if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) != 0) {
		if (nic_dev->hw_dcb_cfg.trust == DCB_PCP) {
			if (skb->vlan_tci != 0)
				cos = nic_dev->hw_dcb_cfg.pcp2cos[skb->vlan_tci >> VLAN_PRIO_SHIFT];
			else
				cos = nic_dev->hw_dcb_cfg.default_cos;
		} else {
			cos = hinic5_get_dscp_up(nic_dev, skb);
		}

		qp_num = (nic_dev->hw_dcb_cfg.cos_qp_num[cos] != 0) ?
			txq % nic_dev->hw_dcb_cfg.cos_qp_num[cos] : 0;
		txq = nic_dev->hw_dcb_cfg.cos_qp_offset[cos] + qp_num;
	}

	return txq;
}

static void hinic5_get_tx_stats64(struct hinic5_nic_dev *nic_dev,
				  u64 *bytes, u64 *packets, u64 *dropped, unsigned int *start)
{
	struct hinic5_txq_stats *txq_stats = NULL;
	struct hinic5_txq *txq = NULL;
	int i;

	for (i = 0; i < nic_dev->max_qps; i++) {
		if (!nic_dev->txqs)
			break;

		txq = &nic_dev->txqs[i];
		txq_stats = &txq->txq_stats;
		do {
			*start = u64_stats_fetch_begin(&txq_stats->syncp);
			*bytes += txq_stats->bytes;
			*packets += txq_stats->packets;
			*dropped += txq_stats->dropped;
		} while (u64_stats_fetch_retry(&txq_stats->syncp, *start));
	}
}

#ifdef HAVE_NDO_GET_STATS64
#ifdef HAVE_VOID_NDO_GET_STATS64
static void hinic5_get_stats64(struct net_device *netdev,
			       struct rtnl_link_stats64 *stats)
#else
static struct rtnl_link_stats64 *hinic5_get_stats64(struct net_device *netdev,
						    struct rtnl_link_stats64 *stats)
#endif

#else /* !HAVE_NDO_GET_STATS64 */
static struct net_device_stats *hinic5_get_stats(struct net_device *netdev)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
#ifndef HAVE_NDO_GET_STATS64
#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats *stats = &netdev->stats;
#else
	struct net_device_stats *stats = &nic_dev->net_stats;
#endif /* HAVE_NETDEV_STATS_IN_NETDEV */
#endif /* HAVE_NDO_GET_STATS64 */
	struct hinic5_rxq_stats *rxq_stats = NULL;
	struct hinic5_rxq *rxq = NULL;
	u64 bytes, packets, dropped, errors, multi_cast;
	unsigned int start;
	int i;

	bytes = 0;
	packets = 0;
	dropped = 0;

	hinic5_get_tx_stats64(nic_dev, &bytes, &packets, &dropped, &start);
	/* Consistent with 1823V100, PF only to reduce channel pressure */
	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		queue_work(nic_dev->workq, &nic_dev->update_stats_work);
	}

	stats->tx_packets = packets;
	stats->tx_bytes   = bytes;
	stats->tx_dropped = dropped;

	bytes = 0;
	packets = 0;
	errors = 0;
	dropped = 0;
	multi_cast = 0;
	for (i = 0; i < nic_dev->max_qps; i++) {
		if (!nic_dev->rxqs)
			break;

		rxq = &nic_dev->rxqs[i];
		rxq_stats = &rxq->rxq_stats;
		do {
			start = u64_stats_fetch_begin(&rxq_stats->syncp);
			bytes += rxq_stats->bytes;
			packets += rxq_stats->packets;
			errors += rxq_stats->csum_errors +
				rxq_stats->other_errors;
			dropped += rxq_stats->dropped;
			multi_cast += rxq_stats->pkt_mc;
		} while (u64_stats_fetch_retry(&rxq_stats->syncp, start));
	}
	stats->rx_packets = packets;
	stats->rx_bytes   = bytes;
	stats->rx_errors  = errors;
	stats->rx_dropped = dropped + nic_dev->vport_stats.rx_discard_vport;
	stats->multicast = multi_cast;

#ifndef HAVE_VOID_NDO_GET_STATS64
	return stats;
#endif
}

#ifdef HAVE_NDO_TX_TIMEOUT_TXQ
static void hinic5_tx_timeout(struct net_device *netdev, unsigned int txqueue)
#else
static void hinic5_tx_timeout(struct net_device *netdev)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_io_queue *sq = NULL;
	struct hinic5_txq *txq = NULL;
	bool hw_err = false;
	u32 sw_pi, hw_ci;
	u8 q_id;

	HINIC5_NIC_STATS_INC(nic_dev, netdev_tx_timeout);
	nicif_err(nic_dev, drv, netdev, "Tx timeout\n");

	for (q_id = 0; q_id < nic_dev->q_params.num_qps + nic_dev->q_params.xdp_qps; q_id++) {
		if (!netif_xmit_stopped(netdev_get_tx_queue(netdev, q_id)))
			continue;
		txq = &nic_dev->txqs[q_id];
		sq = nic_dev->txqs[q_id].sq;
		sw_pi = hinic5_get_sq_local_pi(sq);
		hw_ci = hinic5_get_sq_hw_ci(sq);
		nicif_info(nic_dev, drv, netdev,
			   "txq%u: sw_pi: %u, hw_ci: %u, sw_ci: %u, napi->state: 0x%lx.\n",
			   q_id, sw_pi, hw_ci, hinic5_get_sq_local_ci(sq),
			   nic_dev->q_params.irq_cfg[q_id].napi.state);

		if (sw_pi != hw_ci) {
			hw_err = true;
			TXQ_STATS_INC(txq, unfinished);
		}
	}

	if (hw_err)
		set_bit(EVENT_WORK_TX_TIMEOUT, &nic_dev->event_flag);
}

__weak int hinic5_change_mtu_pre_hook(struct net_device *netdev, int new_mtu)
{
	return 0;
}

static int hinic5_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u32 mtu = (u32)new_mtu;
	int err = 0;
	int is_in_kexec = hinic5_vram_get_kexec_flag();
#if defined(HAVE_XDP_SUPPORT) && (defined(HAVE_NDO_BPF) || defined(HAVE_NDO_XDP))
	u32 xdp_max_mtu;
#endif

	err = hinic5_change_mtu_pre_hook(netdev, new_mtu);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Skip mtu config\n");
		return err;
	}

	if (is_in_kexec != 0) {
		nicif_info(nic_dev, drv, netdev, "Hotreplace skip change mtu\n");
		return err;
	}

#if defined(HAVE_XDP_SUPPORT) && (defined(HAVE_NDO_BPF) || defined(HAVE_NDO_XDP))
	if (hinic5_is_xdp_enable(nic_dev)) {
		xdp_max_mtu = (u32)hinic5_xdp_max_mtu(nic_dev);
		if (mtu > xdp_max_mtu) {
			nicif_err(nic_dev, drv, netdev,
				  "Max MTU for xdp usage is %u\n", xdp_max_mtu);
			return -EINVAL;
		}
	}
#endif

	err = hinic5_set_port_mtu(nic_dev->hwdev, (u16)mtu);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to change port mtu to %d\n",
			  new_mtu);
	} else {
		nicif_info(nic_dev, drv, nic_dev->netdev, "Change mtu from %u to %d\n",
			   netdev->mtu, new_mtu);
		netdev->mtu = mtu;
		nic_dev->nic_hinic5_vram->hinic5_vram_mtu = mtu;
	}

	return err;
}

__weak int hinic5_set_mac_addr_pre_hook(struct net_device *netdev, void *addr)
{
	return 0;
}

static int hinic5_set_mac_addr(struct net_device *netdev, void *addr)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct sockaddr *saddr = addr;
	int err;

	err = hinic5_set_mac_addr_pre_hook(netdev, addr);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Skip mac config\n");
		return err;
	}

	if (!is_valid_ether_addr((const u8 *)saddr->sa_data))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, (const u8 *)saddr->sa_data)) {
		nicif_info(nic_dev, drv, netdev,
			   "Already using mac address %pM\n",
			   saddr->sa_data);
		return 0;
	}

	err = hinic5_update_mac(nic_dev->hwdev, nic_dev->netdev->dev_addr, (u8 *)saddr->sa_data, 0,
				hinic5_global_func_id(nic_dev->hwdev));
	if (err != 0)
		return err;

	hinic5_eth_hw_addr_set(netdev, saddr->sa_data);

	nicif_info(nic_dev, drv, netdev, "Set new mac address %pM\n",
		   saddr->sa_data);

	return 0;
}

#if defined(HAVE_NDO_UDP_TUNNEL_ADD) || defined(HAVE_UDP_TUNNEL_NIC_INFO)
static int hinic5_udp_tunnel_port_config(struct net_device *netdev,
					 struct udp_tunnel_info *ti, u8 action)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u16 func_id = hinic5_global_func_id(nic_dev->hwdev);
	u16 dst_port;
	int ret = 0;

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		dst_port = ntohs(ti->port);
		ret = hinic5_vxlan_port_config(nic_dev->hwdev, func_id,
					       dst_port, action, 0);
		if (ret != 0 && ret != -EOPNOTSUPP) {
			nicif_warn(nic_dev, drv, netdev, "Setting vxlan port %u to device not supported\n",
				   dst_port);
			break;
		}
		fallthrough;
	default:
		ret = -EINVAL;
	}
	return ret;
}
#endif /* HAVE_NDO_UDP_TUNNEL_ADD || HAVE_UDP_TUNNEL_NIC_INFO */

#ifdef HAVE_NDO_UDP_TUNNEL_ADD
static void hinic5_udp_tunnel_add(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	if (ti->sa_family != AF_INET && ti->sa_family != AF_INET6)
		return;
	hinic5_udp_tunnel_port_config(netdev, ti, HINIC5_CMD_OP_ADD);
}

static void hinic5_udp_tunnel_del(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	if (ti->sa_family != AF_INET && ti->sa_family != AF_INET6)
		return;

	hinic5_udp_tunnel_port_config(netdev, ti, HINIC5_CMD_OP_DEL);
}
#endif /* HAVE_NDO_UDP_TUNNEL_ADD */

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
int hinic5_udp_tunnel_set_port(struct net_device *netdev, unsigned int table,
			       unsigned int entry, struct udp_tunnel_info *ti)
{
	return hinic5_udp_tunnel_port_config(netdev, ti, HINIC5_CMD_OP_ADD);
}

int hinic5_udp_tunnel_unset_port(struct net_device *netdev, unsigned int table,
				 unsigned int entry, struct udp_tunnel_info *ti)
{
	return hinic5_udp_tunnel_port_config(netdev, ti, HINIC5_CMD_OP_DEL);
}
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */

#if (KERNEL_VERSION(3, 3, 0) > LINUX_VERSION_CODE)
static void
#else
static int
#endif
hinic5_vlan_rx_add_vid(struct net_device *netdev,
		       #if (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE)
		       __always_unused __be16 proto,
		       #endif
		       u16 vid)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	unsigned long *vlan_bitmap = nic_dev->vlan_bitmap;
	u16 func_id;
	u32 col, line;
	int err = 0;

	/* VLAN 0 donot be added, which is the same as VLAN 0 deleted. */
	if (vid == 0)
		goto end;

	col = VID_COL(nic_dev, vid);
	line = VID_LINE(nic_dev, vid);

	func_id = hinic5_global_func_id(nic_dev->hwdev);

	err = hinic5_add_vlan(nic_dev->hwdev, vid, func_id);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to add vlan %u\n", vid);
		goto end;
	}

	set_bit(col, &vlan_bitmap[line]);

	nicif_info(nic_dev, drv, netdev, "Add vlan %u\n", vid);

end:
#if (KERNEL_VERSION(3, 3, 0) <= LINUX_VERSION_CODE)
	return err;
#else
	return;
#endif
}

#if (KERNEL_VERSION(3, 3, 0) > LINUX_VERSION_CODE)
static void
#else
static int
#endif
hinic5_vlan_rx_kill_vid(struct net_device *netdev,
			#if (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE)
			__always_unused __be16 proto,
			#endif
			u16 vid)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	unsigned long *vlan_bitmap = nic_dev->vlan_bitmap;
	u16 func_id;
	int col, line;
	int err = 0;

	col  = VID_COL(nic_dev, vid);
	line = (int)(VID_LINE(nic_dev, vid));

	/* In the broadcast scenario, ucode finds the corresponding function
	 * based on VLAN 0 of vlan table. If we delete VLAN 0, the VLAN function
	 * is affected.
	 */
	if (vid == 0)
		goto end;

	func_id = hinic5_global_func_id(nic_dev->hwdev);
	err = hinic5_del_vlan(nic_dev->hwdev, vid, func_id);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to delete vlan\n");
		goto end;
	}

	clear_bit(col, &vlan_bitmap[line]);

	nicif_info(nic_dev, drv, netdev, "Remove vlan %u\n", vid);

end:
#if (KERNEL_VERSION(3, 3, 0) <= LINUX_VERSION_CODE)
	return err;
#else
	return;
#endif
}

#ifdef NEED_VLAN_RESTORE
static int hinic5_vlan_restore(struct net_device *netdev)
{
	int err = 0;
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
	struct net_device *vlandev = NULL;
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	unsigned long *vlan_bitmap = nic_dev->vlan_bitmap;
	u32 col, line;
	u16 i;

	if (!netdev->netdev_ops->ndo_vlan_rx_add_vid)
		return -EFAULT;
	rcu_read_lock();
	for (i = 0; i < VLAN_N_VID; i++) {
#ifdef HAVE_VLAN_FIND_DEV_DEEP_RCU
		vlandev =
			__vlan_find_dev_deep_rcu(netdev, htons(ETH_P_8021Q), i);
#else
		vlandev = __vlan_find_dev_deep(netdev, htons(ETH_P_8021Q), i);
#endif
		col = VID_COL(nic_dev, i);
		line = VID_LINE(nic_dev, i);
		if (!vlandev && (vlan_bitmap[line] & (1UL << col)) != 0) {
#if (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE)
			err = netdev->netdev_ops->ndo_vlan_rx_kill_vid(netdev,
				htons(ETH_P_8021Q), i);
			if (err != 0) {
				hinic5_err(nic_dev, drv, "delete vlan %u failed, err code %d\n",
					   i, err);
				break;
			}
#else
			netdev->netdev_ops->ndo_vlan_rx_kill_vid(netdev, i);
#endif
		} else if (vlandev && (vlan_bitmap[line] & (1UL << col)) == 0) {
#if (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE)
			err = netdev->netdev_ops->ndo_vlan_rx_add_vid(netdev,
				htons(ETH_P_8021Q), i);
			if (err != 0) {
				hinic5_err(nic_dev, drv, "restore vlan %u failed, err code %d\n",
					   i, err);
				break;
			}
#else
			netdev->netdev_ops->ndo_vlan_rx_add_vid(netdev, i);
#endif
		}
	}
	rcu_read_unlock();
#endif

	return err;
}
#endif

#define SET_FEATURES_OP_STR(op)		(((op) != 0) ? "Enable" : "Disable")

static int set_feature_rx_csum(struct hinic5_nic_dev *nic_dev,
			       netdev_features_t wanted_features,
			       netdev_features_t features,
			       netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;

	if ((changed & NETIF_F_RXCSUM) != 0)
		hinic5_info(nic_dev, drv, "%s rx csum success\n",
			    SET_FEATURES_OP_STR(wanted_features &
						NETIF_F_RXCSUM));

	return 0;
}

static int set_feature_tso(struct hinic5_nic_dev *nic_dev,
			   netdev_features_t wanted_features,
			   netdev_features_t features,
			   netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;

	if ((changed & NETIF_F_TSO) != 0)
		hinic5_info(nic_dev, drv, "%s tso success\n",
			    SET_FEATURES_OP_STR(wanted_features & NETIF_F_TSO));

	return 0;
}

#ifdef NETIF_F_UFO
static int set_feature_ufo(struct hinic5_nic_dev *nic_dev,
			   netdev_features_t wanted_features,
			   netdev_features_t features,
			   netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;

	if (changed & NETIF_F_UFO)
		hinic5_info(nic_dev, drv, "%s ufo success\n",
			    SET_FEATURES_OP_STR(wanted_features & NETIF_F_UFO));

	return 0;
}
#endif

static int set_feature_lro(struct hinic5_nic_dev *nic_dev,
			   netdev_features_t wanted_features,
			   netdev_features_t features,
			   netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
	bool en = (wanted_features & NETIF_F_LRO) != 0;
	int err;

	if ((changed & NETIF_F_LRO) == 0)
		return 0;

#if defined(HAVE_XDP_SUPPORT) && (defined(HAVE_NDO_BPF) || defined(HAVE_NDO_XDP))
	if (en && hinic5_is_xdp_enable(nic_dev)) {
		hinic5_err(nic_dev, drv, "Can not enable LRO when xdp is enable\n");
		*failed_features |= NETIF_F_LRO;
		return -EINVAL;
	}
#endif

	err = hinic5_set_rx_lro_state(nic_dev->hwdev, en,
				      HINIC5_LRO_DEFAULT_TIME_LIMIT,
				      HINIC5_LRO_DEFAULT_COAL_PKT_SIZE);
	if (err != 0) {
		hinic5_err(nic_dev, drv, "%s lro failed\n",
			   SET_FEATURES_OP_STR(en));
		*failed_features |= NETIF_F_LRO;
	} else {
		hinic5_info(nic_dev, drv, "%s lro success\n",
			    SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_feature_rx_cvlan(struct hinic5_nic_dev *nic_dev,
				netdev_features_t wanted_features,
				netdev_features_t features,
				netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	netdev_features_t vlan_feature = NETIF_F_HW_VLAN_CTAG_RX;
#else
	netdev_features_t vlan_feature = NETIF_F_HW_VLAN_RX;
#endif
	bool en = (wanted_features & vlan_feature) != 0;
	int err;

	if ((changed & vlan_feature) == 0)
		return 0;

	err = hinic5_set_rx_vlan_offload(nic_dev->hwdev, en);
	if (err != 0) {
		hinic5_err(nic_dev, drv, "%s rxvlan failed\n",
			   SET_FEATURES_OP_STR(en));
		*failed_features |= vlan_feature;
	} else {
		hinic5_info(nic_dev, drv, "%s rxvlan success\n",
			    SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_feature_vlan_filter(struct hinic5_nic_dev *nic_dev,
				   netdev_features_t wanted_features,
				   netdev_features_t features,
				   netdev_features_t *failed_features)
{
	netdev_features_t changed = wanted_features ^ features;
#if defined(NETIF_F_HW_VLAN_CTAG_FILTER)
	netdev_features_t vlan_filter_feature = NETIF_F_HW_VLAN_CTAG_FILTER;
#elif defined(NETIF_F_HW_VLAN_FILTER)
	netdev_features_t vlan_filter_feature = NETIF_F_HW_VLAN_FILTER;
#endif
	bool en = (wanted_features & vlan_filter_feature) != 0;
	int err = 0;

	if ((changed & vlan_filter_feature) == 0)
		return 0;

#ifdef NEED_VLAN_RESTORE
	if (en != 0) {
		err = hinic5_vlan_restore(nic_dev->netdev);
		if (err != 0) {
			hinic5_err(nic_dev, drv, "vlan restore failed\n");
			*failed_features |= vlan_filter_feature;
			return err;
		}
	}
#endif

	err = hinic5_set_vlan_fliter(nic_dev->hwdev, en);
	if (err != 0) {
		hinic5_err(nic_dev, drv, "%s rx vlan filter failed\n",
			   SET_FEATURES_OP_STR(en));
		*failed_features |= vlan_filter_feature;
	} else {
		hinic5_info(nic_dev, drv, "%s rx vlan filter success\n",
			    SET_FEATURES_OP_STR(en));
	}

	return err;
}

static int set_features(struct hinic5_nic_dev *nic_dev,
			netdev_features_t pre_features,
			netdev_features_t features)
{
	netdev_features_t failed_features = 0;
	u32 err = 0;

	err |= (u32)set_feature_rx_csum(nic_dev, features, pre_features,
					&failed_features);
	err |= (u32)set_feature_tso(nic_dev, features, pre_features,
				    &failed_features);
	err |= (u32)set_feature_lro(nic_dev, features, pre_features,
				    &failed_features);
#ifdef NETIF_F_UFO
	err |= (u32)set_feature_ufo(nic_dev, features, pre_features,
				    &failed_features);
#endif
	err |= (u32)set_feature_rx_cvlan(nic_dev, features, pre_features,
					 &failed_features);
	err |= (u32)set_feature_vlan_filter(nic_dev, features, pre_features,
					    &failed_features);
	if (err != 0) {
		nic_dev->netdev->features = features ^ failed_features;
		return -EIO;
	}

	return 0;
}

#ifdef HAVE_NDO_SET_U32_FEATURES
static int hinic5_set_features(struct net_device *netdev, u32 features)
#else
static int hinic5_set_features(struct net_device *netdev,
			       netdev_features_t features)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	return set_features(nic_dev, nic_dev->netdev->features,
			    features);
}

int hinic5_set_hw_features(struct hinic5_nic_dev *nic_dev)
{
	/* enable all hw features in netdev->features */
	return set_features(nic_dev, ~nic_dev->netdev->features,
			    nic_dev->netdev->features);
}

#ifdef HAVE_NDO_SET_U32_FEATURES
static u32 hinic5_fix_features(struct net_device *netdev, u32 features)
#else
static netdev_features_t hinic5_fix_features(struct net_device *netdev,
					     netdev_features_t features)
#endif
{
	netdev_features_t features_tmp = features;

	/* If Rx checksum is disabled, then LRO should also be disabled */
	if ((features_tmp & NETIF_F_RXCSUM) == 0)
		features_tmp &= ~NETIF_F_LRO;

	return features_tmp;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void hinic5_netpoll(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u16 i;

	for (i = 0; i < nic_dev->q_params.num_qps; i++)
		napi_schedule(&nic_dev->q_params.irq_cfg[i].napi);
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

static int hinic5_ndo_set_vf_mac(struct net_device *netdev, int vf, u8 *mac)
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);
	int err;

	if (is_multicast_ether_addr(mac) || vf >= hinic5_get_vf_num(adapter->lld_dev))
		return -EINVAL;

	err = hinic5_set_vf_mac(adapter->hwdev, OS_VF_ID_TO_HW(vf), mac);
	if (err != 0)
		return err;

	if (!is_zero_ether_addr(mac))
		nic_info(adapter->lld_dev->dev, "Setting MAC %pM on VF %d\n",
			 mac, vf);
	else
		nic_info(adapter->lld_dev->dev, "Deleting MAC on VF %d\n", vf);

	nic_info(adapter->lld_dev->dev, "Please reload the VF driver to make this change effective.");

	return 0;
}

#ifdef IFLA_VF_MAX
static int set_hw_vf_vlan(void *hwdev, u16 cur_vlanprio, int vf,
			  u16 vlan, u8 qos)
{
	int err = 0;
	u16 old_vlan = cur_vlanprio & VLAN_VID_MASK;

	if (vlan != 0 || qos != 0) {
		if (cur_vlanprio != 0) {
			err = hinic5_kill_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf));
			if (err != 0)
				return err;
		}
		err = hinic5_add_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf), vlan, qos);
	} else {
		err = hinic5_kill_vf_vlan(hwdev, OS_VF_ID_TO_HW(vf));
	}

	if (err == 0)
		err = hinic5_update_mac_vlan(hwdev, old_vlan, vlan, OS_VF_ID_TO_HW(vf));

	return err;
}

#define HINIC5_MAX_VLAN_ID	4094
#define HINIC5_MAX_QOS_NUM	7

#ifdef IFLA_VF_VLAN_INFO_MAX
static int hinic5_ndo_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan,
				  u8 qos, __be16 vlan_proto)
#else
static int hinic5_ndo_set_vf_vlan(struct net_device *netdev, int vf, u16 vlan,
				  u8 qos)
#endif
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);

	u16 vlanprio, cur_vlanprio;

	if (vf >= hinic5_get_vf_num(adapter->lld_dev) ||
	    vlan > HINIC5_MAX_VLAN_ID || qos > HINIC5_MAX_QOS_NUM)
		return -EINVAL;
#ifdef IFLA_VF_VLAN_INFO_MAX
	if (vlan_proto != htons(ETH_P_8021Q))
		return -EPROTONOSUPPORT;
#endif
	vlanprio = vlan | (qos << HINIC5_VLAN_PRIORITY_SHIFT);
	cur_vlanprio = hinic5_vf_info_vlanprio(adapter->hwdev,
					       OS_VF_ID_TO_HW(vf));
	/* duplicate request, so just return success */
	if (vlanprio == cur_vlanprio)
		return 0;

	return set_hw_vf_vlan(adapter->hwdev, cur_vlanprio, vf, vlan, qos);
}
#endif

#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
static int hinic5_ndo_set_vf_spoofchk(struct net_device *netdev, int vf,
				      bool setting)
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);
	int err = 0;
	bool cur_spoofchk = false;

	if (vf >= hinic5_get_vf_num(adapter->lld_dev))
		return -EINVAL;

	cur_spoofchk = hinic5_vf_info_spoofchk(adapter->hwdev,
					       OS_VF_ID_TO_HW(vf));
	/* same request, so just return success */
	if ((setting && cur_spoofchk) || (!setting && !cur_spoofchk))
		return 0;

	err = hinic5_set_vf_spoofchk(adapter->hwdev,
				     (u16)OS_VF_ID_TO_HW(vf), setting);
	if (err == 0)
		nicif_info(adapter, drv, netdev, "Set VF %d spoofchk %s\n",
			   vf, setting ? "on" : "off");

	return err;
}
#endif

#ifdef HAVE_NDO_SET_VF_TRUST
static int hinic5_ndo_set_vf_trust(struct net_device *netdev, int vf, bool setting)
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);
	int err;
	bool cur_trust;

	if (vf >= hinic5_get_vf_num(adapter->lld_dev))
		return -EINVAL;

	cur_trust = hinic5_get_vf_trust(adapter->hwdev,
					OS_VF_ID_TO_HW(vf));
	/* same request, so just return success */
	if ((setting && cur_trust) || (!setting && !cur_trust))
		return 0;

	err = hinic5_set_vf_trust(adapter->hwdev,
				  (u16)OS_VF_ID_TO_HW(vf), setting);
	if (err == 0)
		nicif_info(adapter, drv, netdev, "Set VF %d trusted %s successfully\n",
			   vf, setting ? "on" : "off");
	else
		nicif_err(adapter, drv, netdev, "Failed set VF %d trusted %s\n",
			  vf, setting ? "on" : "off");

	return err;
}
#endif

static int hinic5_ndo_get_vf_config(struct net_device *netdev,
				    int vf, struct ifla_vf_info *ivi)
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);

	if (vf >= hinic5_get_vf_num(adapter->lld_dev))
		return -EINVAL;

	hinic5_get_vf_config(adapter->hwdev, (u16)OS_VF_ID_TO_HW(vf), ivi);

	return 0;
}

/**
 * hinic5_ndo_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link: required link state
 *
 * Set the link state of a specified VF, regardless of physical link state
 **/
int hinic5_ndo_set_vf_link_state(struct net_device *netdev, int vf_id, int link)
{
	static const char * const vf_link[] = {"auto", "enable", "disable"};
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);
	int err;

	/* validate the request */
	if (vf_id >= hinic5_get_vf_num(adapter->lld_dev)) {
		nicif_err(adapter, drv, netdev,
			  "Invalid VF Identifier %d\n", vf_id);
		return -EINVAL;
	}

	err = hinic5_set_vf_link_state(adapter->hwdev,
				       (u16)OS_VF_ID_TO_HW(vf_id), link);
	if (err == 0)
		nicif_info(adapter, drv, netdev, "Set VF %d link state: %s\n",
			   vf_id, vf_link[link]);

	return err;
}

static int is_set_vf_bw_param_valid(const struct hinic5_nic_dev *adapter,
				    int vf, int min_tx_rate, int max_tx_rate)
{
	int enable_vf_num = hinic5_get_vf_num(adapter->lld_dev);

	if (!HINIC5_SUPPORT_RATE_LIMIT(adapter->hwdev)) {
		nicif_err(adapter, drv, adapter->netdev, "Current function doesn't support to set vf rate limit\n");
		return -EOPNOTSUPP;
	}

	/* verify VF is active */
	if (vf >= enable_vf_num) {
		nicif_err(adapter, drv, adapter->netdev,
			  "VF number must be less than %d\n", enable_vf_num);
		return -EINVAL;
	}

	if (max_tx_rate < min_tx_rate) {
		nicif_err(adapter, drv, adapter->netdev, "Invalid rate, max rate %d must greater than min rate %d\n",
			  max_tx_rate, min_tx_rate);
		return -EINVAL;
	}

	return 0;
}

#define HINIC5_TX_RATE_TABLE_FULL	12

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
static int hinic5_ndo_set_vf_bw(struct net_device *netdev,
				int vf, int min_tx_rate, int max_tx_rate)
#else
static int hinic5_ndo_set_vf_bw(struct net_device *netdev, int vf,
				int max_tx_rate)
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */
{
	struct hinic5_nic_dev *adapter = netdev_priv(netdev);
	struct mag_port_info port_info = {0};
#ifndef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	int min_tx_rate = 0;
#endif
	u8 link_status = 0;
	u32 speeds[] = {0, SPEED_10, SPEED_100, SPEED_1000, SPEED_10000,
			SPEED_25000, SPEED_40000, SPEED_50000, SPEED_100000, SPEED_200000,
			SPEED_400000, SPEED_400000};
	int err = 0;

	err = is_set_vf_bw_param_valid(adapter, vf, min_tx_rate, max_tx_rate);
	if (err != 0)
		return err;

	err = hinic5_get_link_state(adapter->hwdev, &link_status);
	if (err != 0) {
		nicif_err(adapter, drv, netdev, "Get link status failed when set vf tx rate\n");
		return -EIO;
	}

	if (link_status == 0) {
		nicif_err(adapter, drv, netdev, "Link status must be up when set vf tx rate\n");
		return -EINVAL;
	}

	err = hinic5_get_port_info(adapter->hwdev, &port_info,
				   HINIC5_CHANNEL_NIC);
	if (err != 0 || port_info.speed >= PORT_SPEED_UNKNOWN)
		return -EIO;

	/* rate limit cannot be less than 0 and greater than link speed */
	if (max_tx_rate < 0 || max_tx_rate > (int)(speeds[port_info.speed])) {
		nicif_err(adapter, drv, netdev, "Set vf max tx rate must be in [0 - %u]\n",
			  speeds[port_info.speed]);
		return -EINVAL;
	}

	err = hinic5_set_vf_tx_rate(adapter->hwdev, (u16)OS_VF_ID_TO_HW(vf),
				    (u32)max_tx_rate, (u32)min_tx_rate);
	if (err != 0) {
		nicif_err(adapter, drv, netdev,
			  "Unable to set VF %d max rate %d min rate %d%s\n",
			  vf, max_tx_rate, min_tx_rate,
			  err == HINIC5_TX_RATE_TABLE_FULL ?
			  ", tx rate profile is full" : "");
		return -EIO;
	}

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	nicif_info(adapter, drv, netdev,
		   "Set VF %d max tx rate %d min tx rate %d successfully\n",
		   vf, max_tx_rate, min_tx_rate);
#else
	nicif_info(adapter, drv, netdev, "Set VF %d tx rate %d successfully\n", vf, max_tx_rate);
#endif

	return 0;
}

#if defined(HAVE_XDP_SUPPORT) && (defined(HAVE_NDO_BPF) || defined(HAVE_NDO_XDP))
bool hinic5_is_xdp_enable(struct hinic5_nic_dev *nic_dev)
{
	return !!nic_dev->xdp_prog;
}

int hinic5_xdp_max_mtu(struct hinic5_nic_dev *nic_dev)
{
	/* To Check MTU, support use integreted cqe, XDP_PACKET_HEADROOM and skb_shared_info */
	return nic_dev->rx_buff_len - (ETH_HLEN + ETH_FCS_LEN +
	       VLAN_HLEN + VLAN_HLEN) - HINIC5_COMPACT_CQE_16B -
	       XDP_PACKET_HEADROOM - SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
}

#if (defined(HAVE_NDO_BPF) || defined(HAVE_NDO_XDP))
static int hinic5_xdp_setup(struct hinic5_nic_dev *nic_dev,
			    struct bpf_prog *prog,
			    struct netlink_ext_ack *extack)
{
	struct bpf_prog *old_prog = NULL;
	int max_mtu = hinic5_xdp_max_mtu(nic_dev);
	int q_id, err = 0;

	if ((XDP_QPS_NUM_EXPANSION * nic_dev->q_params.num_qps) > nic_dev->max_qps) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to setup xdp program, max qps %u is less than double of current qps %u, please reduce current num qps\n",
			  nic_dev->max_qps, nic_dev->q_params.num_qps);
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to setup xdp program, max qps is less than double of current qps");
		return -EINVAL;
	}

	if (nic_dev->netdev->mtu > (u32)max_mtu) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to setup xdp program, the current MTU %u is larger than max allowed MTU %d\n",
			  nic_dev->netdev->mtu, max_mtu);
		NL_SET_ERR_MSG_MOD(extack,
				   "MTU too large for loading xdp program");
		return -EINVAL;
	}

	if ((nic_dev->netdev->features & NETIF_F_LRO) != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to setup xdp program while LRO is on\n");
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to setup xdp program while LRO is on");
		return -EINVAL;
	}

	old_prog = xchg(&nic_dev->xdp_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	if (!nic_dev->remove_flag && netif_running(nic_dev->netdev)) {
		err = hinic5_safe_switch_channels(nic_dev);
		if (err)
			return err;
	}

	for (q_id = 0; q_id < nic_dev->max_qps; q_id++)
		xchg(&nic_dev->rxqs[q_id].xdp_prog, nic_dev->xdp_prog);

	return 0;
}

#if defined(HAVE_NDO_BPF)
static int hinic5_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
#elif defined(HAVE_NDO_XDP)
static int hinic5_xdp(struct net_device *netdev, struct netdev_xdp *xdp)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return hinic5_xdp_setup(nic_dev, xdp->prog, xdp->extack);
#ifdef HAVE_XDP_QUERY_PROG
	case XDP_QUERY_PROG:
		xdp->prog_id = nic_dev->xdp_prog ?
			nic_dev->xdp_prog->aux->id : 0;
		return 0;
#endif
	default:
		return -EINVAL;
	}
}
#endif
#endif

static int hinic5_netdev_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	switch (cmd) {
	case SIOCGHWTSTAMP:
		return hinic5_ptp_get_ts_config(nic_dev, ifr);
	case SIOCSHWTSTAMP:
		return hinic5_ptp_set_ts_config(nic_dev, ifr);
	default:
		return -EOPNOTSUPP;
	}
}

static const struct net_device_ops hinic5_netdev_ops = {
	.ndo_open = hinic5_open,
	.ndo_stop = hinic5_close,
	.ndo_start_xmit = hinic5_xmit_frame,
#if (KERNEL_VERSION(5, 1, 1) <= LINUX_VERSION_CODE)
	.ndo_setup_tc = hinic5_setup_tc,
#endif
#ifdef HAVE_NDO_GET_STATS64
	.ndo_get_stats64 =  hinic5_get_stats64,
#else
	.ndo_get_stats = hinic5_get_stats,
#endif /* HAVE_NDO_GET_STATS64 */

#ifdef HAVE_NDO_ETH_IOCTL
	.ndo_eth_ioctl = hinic5_netdev_ioctl,
#else
	.ndo_do_ioctl = hinic5_netdev_ioctl,
#endif
	.ndo_tx_timeout = hinic5_tx_timeout,
	.ndo_select_queue = hinic5_select_queue,
#ifdef HAVE_NET_DEV_OPS_EXT_NDO_CHANGE_MTU
	.extended.ndo_change_mtu = hinic5_change_mtu,
#else
	.ndo_change_mtu = hinic5_change_mtu,
#endif
	.ndo_set_mac_address = hinic5_set_mac_addr,
	.ndo_validate_addr = eth_validate_addr,

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	.ndo_vlan_rx_add_vid = hinic5_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = hinic5_vlan_rx_kill_vid,
#endif

#ifdef HAVE_NET_DEVICE_OPS_EXTENDED
	/* RHEL7 requires this to be defined to enable extended ops.  RHEL7
	 * uses the function get_ndo_ext to retrieve offsets for extended
	 * fields from with the net_device_ops struct and ndo_size is checked
	 * to determine whether or not the offset is valid.
	 */
	.ndo_size		= sizeof(const struct net_device_ops),
#endif

#ifdef IFLA_VF_MAX
	.ndo_set_vf_mac		= hinic5_ndo_set_vf_mac,
#ifdef HAVE_NET_DEV_OPS_EXT_NDO_SET_VF_VLAN
	.extended.ndo_set_vf_vlan = hinic5_ndo_set_vf_vlan,
#else
	.ndo_set_vf_vlan	= hinic5_ndo_set_vf_vlan,
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	.ndo_set_vf_rate	= hinic5_ndo_set_vf_bw,
#else
	.ndo_set_vf_tx_rate	= hinic5_ndo_set_vf_bw,
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	.ndo_set_vf_spoofchk	= hinic5_ndo_set_vf_spoofchk,
#endif

#ifdef HAVE_NDO_SET_VF_TRUST
#ifdef HAVE_NET_DEVICE_OPS_EXTENDED
	.extended.ndo_set_vf_trust = hinic5_ndo_set_vf_trust,
#else
	.ndo_set_vf_trust	= hinic5_ndo_set_vf_trust,
#endif /* HAVE_NET_DEVICE_OPS_EXTENDED */
#endif /* HAVE_NDO_SET_VF_TRUST */

	.ndo_get_vf_config	= hinic5_ndo_get_vf_config,
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = hinic5_netpoll,
#endif /* CONFIG_NET_POLL_CONTROLLER */

	.ndo_set_rx_mode = hinic5_nic_set_rx_mode,

#ifdef HAVE_XDP_SUPPORT
	.ndo_xdp_xmit = hinic5_xdp_xmit_frames,
#if defined(HAVE_NDO_BPF)
	.ndo_bpf = hinic5_xdp,
#elif defined(HAVE_NDO_XDP)
	.ndo_xdp = hinic5_xdp,
#endif
#endif
#ifdef HAVE_NDO_UDP_TUNNEL_ADD
	.ndo_udp_tunnel_add = hinic5_udp_tunnel_add,
	.ndo_udp_tunnel_del = hinic5_udp_tunnel_del,
#endif /* HAVE_NDO_UDP_TUNNEL_ADD */
#ifdef HAVE_NET_DEVICE_OPS_EXT
};

/* RHEL6 keeps these operations in a separate structure */
static const struct net_device_ops_ext hinic5_netdev_ops_ext = {
	.size = sizeof(struct net_device_ops_ext),
#endif /* HAVE_NET_DEVICE_OPS_EXT */

#ifdef HAVE_NDO_SET_VF_LINK_STATE
	.ndo_set_vf_link_state	= hinic5_ndo_set_vf_link_state,
#endif

#ifdef HAVE_NDO_SET_FEATURES
	.ndo_fix_features = hinic5_fix_features,
	.ndo_set_features = hinic5_set_features,
#endif /* HAVE_NDO_SET_FEATURES */
};

static const struct net_device_ops hinic5vf_netdev_ops = {
	.ndo_open = hinic5_open,
	.ndo_stop = hinic5_close,
	.ndo_start_xmit = hinic5_xmit_frame,

#ifdef HAVE_NDO_GET_STATS64
	.ndo_get_stats64 =  hinic5_get_stats64,
#else
	.ndo_get_stats = hinic5_get_stats,
#endif /* HAVE_NDO_GET_STATS64 */

	.ndo_tx_timeout = hinic5_tx_timeout,
	.ndo_select_queue = hinic5_select_queue,

#ifdef HAVE_NET_DEVICE_OPS_EXTENDED
	/* RHEL7 requires this to be defined to enable extended ops.  RHEL7
	 * uses the function get_ndo_ext to retrieve offsets for extended
	 * fields from with the net_device_ops struct and ndo_size is checked
	 * to determine whether or not the offset is valid.
	 */
	.ndo_size = sizeof(const struct net_device_ops),
#endif

#ifdef HAVE_NET_DEV_OPS_EXT_NDO_CHANGE_MTU
	.extended.ndo_change_mtu = hinic5_change_mtu,
#else
	.ndo_change_mtu = hinic5_change_mtu,
#endif
	.ndo_set_mac_address = hinic5_set_mac_addr,
	.ndo_validate_addr = eth_validate_addr,

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	.ndo_vlan_rx_add_vid = hinic5_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = hinic5_vlan_rx_kill_vid,
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = hinic5_netpoll,
#endif /* CONFIG_NET_POLL_CONTROLLER */

	.ndo_set_rx_mode = hinic5_nic_set_rx_mode,

#ifdef HAVE_XDP_SUPPORT
	.ndo_xdp_xmit = hinic5_xdp_xmit_frames,
#if defined(HAVE_NDO_BPF)
	.ndo_bpf = hinic5_xdp,
#elif defined(HAVE_NDO_XDP)
	.ndo_xdp = hinic5_xdp,
#endif
#endif
#ifdef HAVE_NET_DEVICE_OPS_EXT
};

/* RHEL6 keeps these operations in a separate structure */
static const struct net_device_ops_ext hinic5vf_netdev_ops_ext = {
	.size = sizeof(struct net_device_ops_ext),
#endif /* HAVE_NET_DEVICE_OPS_EXT */

#ifdef HAVE_NDO_SET_FEATURES
	.ndo_fix_features = hinic5_fix_features,
	.ndo_set_features = hinic5_set_features,
#endif /* HAVE_NDO_SET_FEATURES */
};

void hinic5_set_netdev_ops(struct hinic5_nic_dev *nic_dev)
{
	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		nic_dev->netdev->netdev_ops = &hinic5_netdev_ops;
#ifdef HAVE_NET_DEVICE_OPS_EXT
		set_netdev_ops_ext(nic_dev->netdev, &hinic5_netdev_ops_ext);
#endif /* HAVE_NET_DEVICE_OPS_EXT */
	} else {
		nic_dev->netdev->netdev_ops = &hinic5vf_netdev_ops;
#ifdef HAVE_NET_DEVICE_OPS_EXT
		set_netdev_ops_ext(nic_dev->netdev, &hinic5vf_netdev_ops_ext);
#endif /* HAVE_NET_DEVICE_OPS_EXT */
	}
}

bool hinic5_is_netdev_ops_match(const struct net_device *netdev)
{
	return netdev->netdev_ops == &hinic5_netdev_ops ||
		netdev->netdev_ops == &hinic5vf_netdev_ops;
}
