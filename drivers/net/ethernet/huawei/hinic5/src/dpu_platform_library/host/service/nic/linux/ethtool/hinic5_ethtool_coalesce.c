/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_coalesce.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>

#include "drv_nic_api.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_ethtool.h"
#include "hinic5_ethtool_coalesce.h"

#define CHECK_COALESCE_ALIGN(coal, item, unit)				\
do {									\
	if ((coal)->item % (unit) != 0)					\
		nicif_warn(nic_dev, drv, netdev,			\
			   "%s in %d units, change to %u\n",		\
			   #item, (unit), ((coal)->item -		\
					   (coal)->item % (unit)));	\
} while (0)

#define CHECK_COALESCE_CHANGED(coal, item, unit, ori_val, obj_str)	\
do {									\
	if (((coal)->item / (unit)) != (ori_val))			\
		nicif_info(nic_dev, drv, netdev,			\
			   "Change %s from %d to %u %s\n",		\
			   #item, (ori_val) * (unit),			\
			   ((coal)->item - (coal)->item % (unit)),	\
			    (obj_str));					\
} while (0)

#define CHECK_PKT_RATE_CHANGED(coal, item, ori_val, obj_str)		\
do {									\
	if ((coal)->item != (ori_val))					\
		nicif_info(nic_dev, drv, netdev,			\
			   "Change %s from %llu to %u %s\n",		\
			   #item, (ori_val), (coal)->item, (obj_str));	\
} while (0)

int get_coalesce(struct net_device *netdev,
		 struct ethtool_coalesce *coal, u16 queue)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_qp_coalesce_info *interrupt_info = NULL;

	if (queue == COALESCE_ALL_QUEUE) {
		/* get tx/rx irq0 as default parameters */
		interrupt_info = &nic_dev->intr_coalesce[0];
	} else {
		if (queue >= nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, netdev,
				  "Invalid queue_id: %u\n", queue);
			return -EINVAL;
		}
		interrupt_info = &nic_dev->intr_coalesce[queue];
	}

	/* coalescs_timer is in unit of 5us */
	coal->rx_coalesce_usecs = interrupt_info->rx_coalesce_timer_cfg *
			COALESCE_TIMER_CFG_UNIT;
	/* coalescs_frams is in unit of 8 */
	coal->rx_max_coalesced_frames = interrupt_info->rx_pending_limt *
			COALESCE_PENDING_LIMIT_UNIT;

	/* tx/rx use the same interrupt */
	/* coalescs_timer is in unit of 5us */
	coal->tx_coalesce_usecs = interrupt_info->tx_coalesce_timer_cfg *
			COALESCE_TIMER_CFG_UNIT;
	/* coalescs_frams is in unit of 8 */
	coal->tx_max_coalesced_frames = interrupt_info->tx_pending_limt *
			COALESCE_PENDING_LIMIT_UNIT;
	coal->use_adaptive_rx_coalesce = nic_dev->adaptive_rx_coal;

	coal->pkt_rate_high = (u32)interrupt_info->pkt_rate_high;
	coal->rx_coalesce_usecs_high = interrupt_info->rx_usecs_high *
				       COALESCE_TIMER_CFG_UNIT;
	coal->rx_max_coalesced_frames_high =
				interrupt_info->rx_pending_limt_high *
				COALESCE_PENDING_LIMIT_UNIT;

	coal->pkt_rate_low = (u32)interrupt_info->pkt_rate_low;
	coal->rx_coalesce_usecs_low = interrupt_info->rx_usecs_low *
				      COALESCE_TIMER_CFG_UNIT;
	coal->rx_max_coalesced_frames_low =
				interrupt_info->rx_pending_limt_low *
				COALESCE_PENDING_LIMIT_UNIT;

	return 0;
}

int set_queue_coalesce(struct hinic5_nic_dev *nic_dev, u16 q_id,
		       const struct hinic5_qp_coalesce_info *coal)
{
	struct hinic5_qp_coalesce_info *intr_coal = NULL;
	struct net_device *netdev = nic_dev->netdev;
	int err;

	intr_coal = &nic_dev->intr_coalesce[q_id];
	*intr_coal = *coal;

	/* netdev not running or qp not in using,
	 * don't need to set coalesce to hw
	 */
	if ((test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0) ||
	    q_id >= nic_dev->q_params.num_qps || nic_dev->adaptive_rx_coal != 0)
		return 0;

	nic_dev->rxqs[q_id].last_coalesc_timer_cfg = intr_coal->rx_coalesce_timer_cfg;
	nic_dev->rxqs[q_id].last_pending_limt = intr_coal->rx_pending_limt;
	err = hinic5_set_sq_rq_coalesce_cfg(nic_dev->hwdev, q_id, HINIC5_SQ_RQ_COALESCE, intr_coal);
	if (err != 0)
		nicif_warn(nic_dev, drv, netdev,
			   "Failed to set queue%u coalesce", q_id);

	return err;
}

int is_coalesce_exceed_limit(struct net_device *netdev,
			     const struct ethtool_coalesce *coal)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if (coal->rx_coalesce_usecs > COALESCE_MAX_TIMER_CFG ||
	    coal->tx_coalesce_usecs > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_coalesce_usecs out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames > COALESCE_MAX_PENDING_LIMIT ||
	    coal->tx_max_coalesced_frames > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_max_coalesced_frames out of range[%d-%d]\n", 0,
			  COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	if (coal->rx_coalesce_usecs_low > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_coalesce_usecs_low out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames_low > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_max_coalesced_frames_low out of range[%d-%d]\n",
			  0, COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	if (coal->rx_coalesce_usecs_high > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_coalesce_usecs_high out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames_high > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev,
			  "rx_max_coalesced_frames_high out of range[%d-%d]\n",
			  0, COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	return 0;
}

void tmp_coal_init(struct ethtool_coalesce *tmp_coal, const struct ethtool_coalesce *coal)
{
	tmp_coal->cmd = coal->cmd;
	tmp_coal->rx_coalesce_usecs = coal->rx_coalesce_usecs;
	tmp_coal->rx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	tmp_coal->tx_coalesce_usecs = coal->tx_coalesce_usecs;
	tmp_coal->tx_max_coalesced_frames = coal->tx_max_coalesced_frames;
	tmp_coal->use_adaptive_rx_coalesce = coal->use_adaptive_rx_coalesce;

	tmp_coal->pkt_rate_low = coal->pkt_rate_low;
	tmp_coal->rx_coalesce_usecs_low = coal->rx_coalesce_usecs_low;
	tmp_coal->rx_max_coalesced_frames_low = coal->rx_max_coalesced_frames_low;

	tmp_coal->pkt_rate_high = coal->pkt_rate_high;
	tmp_coal->rx_coalesce_usecs_high = coal->rx_coalesce_usecs_high;
	tmp_coal->rx_max_coalesced_frames_high = coal->rx_max_coalesced_frames_high;
}

int is_coalesce_legal(struct net_device *netdev,
		      const struct ethtool_coalesce *coal)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct ethtool_coalesce tmp_coal = {0};

	if (!HINIC5_SUPPORT_SQ_RQ_CI_COALESCE(nic_dev->hwdev)) {
		if (coal->rx_coalesce_usecs != coal->tx_coalesce_usecs) {
			nicif_err(nic_dev, drv, netdev,
				  "tx-usecs must be equal to rx-usecs\n");
			return -EINVAL;
		}

		if (coal->rx_max_coalesced_frames != coal->tx_max_coalesced_frames) {
			nicif_err(nic_dev, drv, netdev,
				  "tx-frames must be equal to rx-frames\n");
			return -EINVAL;
		}
	}

	tmp_coal_init(&tmp_coal, coal);

	if (memcmp(coal, &tmp_coal, sizeof(struct ethtool_coalesce)) != 0) {
		nicif_err(nic_dev, drv, netdev,
			  "Only support to change rx/tx-usecs and rx/tx-frames\n");
		return -EOPNOTSUPP;
	}

	if (is_coalesce_exceed_limit(netdev, coal) != 0)
		return -EOPNOTSUPP;

	if (coal->rx_coalesce_usecs_low / COALESCE_TIMER_CFG_UNIT >=
	    coal->rx_coalesce_usecs_high / COALESCE_TIMER_CFG_UNIT) {
		nicif_err(nic_dev, drv, netdev,
			  "coalesce_usecs_high(%u) must more than coalesce_usecs_low(%u), after dividing %d usecs unit\n",
			  coal->rx_coalesce_usecs_high,
			  coal->rx_coalesce_usecs_low,
			  COALESCE_TIMER_CFG_UNIT);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames_low / COALESCE_PENDING_LIMIT_UNIT >=
	    coal->rx_max_coalesced_frames_high / COALESCE_PENDING_LIMIT_UNIT) {
		nicif_err(nic_dev, drv, netdev,
			  "coalesced_frames_high(%u) must more than coalesced_frames_low(%u),after dividing %d frames unit\n",
			  coal->rx_max_coalesced_frames_high,
			  coal->rx_max_coalesced_frames_low,
			  COALESCE_PENDING_LIMIT_UNIT);
		return -EOPNOTSUPP;
	}

	if (coal->pkt_rate_low >= coal->pkt_rate_high) {
		nicif_err(nic_dev, drv, netdev,
			  "pkt_rate_high(%u) must more than pkt_rate_low(%u)\n",
			  coal->pkt_rate_high,
			  coal->pkt_rate_low);
		return -EOPNOTSUPP;
	}

	return 0;
}

int set_hw_coal_param(struct hinic5_nic_dev *nic_dev,
		      struct hinic5_qp_coalesce_info *intr_coal, u16 queue)
{
	u16 i;

	if (queue == COALESCE_ALL_QUEUE) {
		for (i = 0; i < nic_dev->max_qps; i++)
			set_queue_coalesce(nic_dev, i, intr_coal);
	} else {
		if (queue >= nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Invalid queue_id: %u\n", queue);
			return -EINVAL;
		}
		set_queue_coalesce(nic_dev, queue, intr_coal);
	}

	return 0;
}

void check_coalesce_align(struct net_device *netdev,
			  const struct ethtool_coalesce *coal)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs, COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames,
			     COALESCE_PENDING_LIMIT_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs_high,
			     COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames_high,
			     COALESCE_PENDING_LIMIT_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs_low,
			     COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames_low,
			     COALESCE_PENDING_LIMIT_UNIT);
}

int check_coalesce_change(struct net_device *netdev,
			  u16 queue, const struct ethtool_coalesce *coal)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_qp_coalesce_info *ori_intr_coal = NULL;
	char obj_str[32] = {0};
	int ret;

	if (queue == COALESCE_ALL_QUEUE) {
		ori_intr_coal = &nic_dev->intr_coalesce[0];
		ret = snprintf(obj_str, sizeof(obj_str), "for netdev");
		if (ret < 0) {
			nicif_err(nic_dev, drv, netdev, "Copy intr coalesce failed.\n");
			return -EINVAL;
		}
	} else {
		ori_intr_coal = &nic_dev->intr_coalesce[queue];
		ret = snprintf(obj_str, sizeof(obj_str), "for queue %u", queue);
		if (ret < 0) {
			nicif_err(nic_dev, drv, netdev, "Copy intr coalesce failed.\n");
			return -EINVAL;
		}
	}
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs, COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->coalesce_timer_cfg, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames,
			       COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->pending_limt, obj_str);
	CHECK_PKT_RATE_CHANGED(coal, pkt_rate_high,
			       ori_intr_coal->pkt_rate_high, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs_high,
			       COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->rx_usecs_high, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames_high,
			       COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->rx_pending_limt_high, obj_str);
	CHECK_PKT_RATE_CHANGED(coal, pkt_rate_low,
			       ori_intr_coal->pkt_rate_low, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs_low,
			       COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->rx_usecs_low, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames_low,
			       COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->rx_pending_limt_low, obj_str);

	return 0;
}

void init_intr_coal_params(struct hinic5_qp_coalesce_info *intr_coal,
			   struct ethtool_coalesce *coal)
{
	intr_coal->tx_coalesce_timer_cfg =
		(u8)(coal->tx_coalesce_usecs / COALESCE_TIMER_CFG_UNIT);
	intr_coal->tx_pending_limt = (u8)(coal->tx_max_coalesced_frames /
					  COALESCE_PENDING_LIMIT_UNIT);

	intr_coal->rx_coalesce_timer_cfg =
		(u8)(coal->rx_coalesce_usecs / COALESCE_TIMER_CFG_UNIT);
	intr_coal->rx_pending_limt = (u8)(coal->rx_max_coalesced_frames /
					  COALESCE_PENDING_LIMIT_UNIT);

	intr_coal->pkt_rate_high = coal->pkt_rate_high;
	intr_coal->rx_usecs_high =
		(u8)(coal->rx_coalesce_usecs_high / COALESCE_TIMER_CFG_UNIT);
	intr_coal->rx_pending_limt_high =
		(u8)(coal->rx_max_coalesced_frames_high /
		     COALESCE_PENDING_LIMIT_UNIT);

	intr_coal->pkt_rate_low = coal->pkt_rate_low;
	intr_coal->rx_usecs_low =
		(u8)(coal->rx_coalesce_usecs_low / COALESCE_TIMER_CFG_UNIT);
	intr_coal->rx_pending_limt_low =
		(u8)(coal->rx_max_coalesced_frames_low /
		     COALESCE_PENDING_LIMIT_UNIT);
}

int set_coalesce(struct net_device *netdev,
		 struct ethtool_coalesce *coal, u16 queue)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_qp_coalesce_info intr_coal;
	u32 last_adaptive_rx;
	int err = 0;

	err = is_coalesce_legal(netdev, coal);
	if (err != 0)
		return err;

	check_coalesce_align(netdev, coal);

	err = check_coalesce_change(netdev, queue, coal);
	if (err != 0)
		return err;

	memset(&intr_coal, 0, sizeof(intr_coal));
	init_intr_coal_params(&intr_coal, coal);

	last_adaptive_rx = nic_dev->adaptive_rx_coal;
	nic_dev->adaptive_rx_coal = coal->use_adaptive_rx_coalesce;

	/* coalesce timer or pending set to zero will disable coalesce */
	if (nic_dev->adaptive_rx_coal == 0 &&
	    (intr_coal.coalesce_timer_cfg == 0 || intr_coal.pending_limt == 0))
		nicif_warn(nic_dev, drv, netdev, "Coalesce will be disabled\n");

	/* ensure coalesce paramester will not be changed in auto
	 * moderation work
	 */
	if (HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		if (nic_dev->adaptive_rx_coal == 0)
			cancel_delayed_work_sync(&nic_dev->moderation_task);
		else if (last_adaptive_rx == 0)
			queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task,
					   HINIC5_MODERATONE_DELAY);
	}

	return set_hw_coal_param(nic_dev, &intr_coal, queue);
}
