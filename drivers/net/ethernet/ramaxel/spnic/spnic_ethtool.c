// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>

#include "sphw_hw.h"
#include "sphw_crm.h"
#include "spnic_nic_dev.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_rss.h"

#define COALESCE_ALL_QUEUE		0xFFFF
#define COALESCE_PENDING_LIMIT_UNIT	8
#define	COALESCE_TIMER_CFG_UNIT		5
#define COALESCE_MAX_PENDING_LIMIT	(255 * COALESCE_PENDING_LIMIT_UNIT)
#define COALESCE_MAX_TIMER_CFG		(255 * COALESCE_TIMER_CFG_UNIT)

static void spnic_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *info)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct pci_dev *pdev = nic_dev->pdev;
	u8 mgmt_ver[SPHW_MGMT_VERSION_MAX_LEN] = {0};
	int err;

	strlcpy(info->driver, SPNIC_NIC_DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, SPNIC_DRV_VERSION, sizeof(info->version));
	strlcpy(info->bus_info, pci_name(pdev), sizeof(info->bus_info));

	err = sphw_get_mgmt_version(nic_dev->hwdev, mgmt_ver, SPHW_MGMT_VERSION_MAX_LEN,
				    SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to get fw version\n");
		return;
	}

	snprintf(info->fw_version, sizeof(info->fw_version), "%s", mgmt_ver);
}

static u32 spnic_get_msglevel(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	return nic_dev->msg_enable;
}

static void spnic_set_msglevel(struct net_device *netdev, u32 data)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	nic_dev->msg_enable = data;

	nicif_info(nic_dev, drv, netdev, "Set message level: 0x%x\n", data);
}

int spnic_nway_reset(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct nic_port_info port_info = {0};
	int err;

	err = spnic_get_port_info(nic_dev->hwdev, &port_info, SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, netdev,
			  "Get port info failed\n");
		return -EFAULT;
	}

	if (!port_info.autoneg_state) {
		nicif_err(nic_dev, drv, netdev, "Autonegotiation is off, don't support to restart it\n");
		return -EINVAL;
	}

	err = spnic_set_autoneg(nic_dev->hwdev, true);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Restart autonegotiation failed\n");
		return -EFAULT;
	}

	nicif_info(nic_dev, drv, netdev, "Restart autonegotiation successfully\n");

	return 0;
}

static void spnic_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	ring->rx_max_pending = SPNIC_MAX_RX_QUEUE_DEPTH;
	ring->tx_max_pending = SPNIC_MAX_TX_QUEUE_DEPTH;
	ring->rx_pending = nic_dev->rxqs[0].q_depth;
	ring->tx_pending = nic_dev->txqs[0].q_depth;
}

static void spnic_update_qp_depth(struct spnic_nic_dev *nic_dev, u32 sq_depth, u32 rq_depth)
{
	u16 i;

	nic_dev->q_params.sq_depth = sq_depth;
	nic_dev->q_params.rq_depth = rq_depth;
	for (i = 0; i < nic_dev->max_qps; i++) {
		nic_dev->txqs[i].q_depth = sq_depth;
		nic_dev->txqs[i].q_mask = sq_depth - 1;
		nic_dev->rxqs[i].q_depth = rq_depth;
		nic_dev->rxqs[i].q_mask = rq_depth - 1;
	}
}

static int check_ringparam_valid(struct net_device *netdev, struct ethtool_ringparam *ring)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (ring->rx_jumbo_pending || ring->rx_mini_pending) {
		nicif_err(nic_dev, drv, netdev,
			  "Unsupported rx_jumbo_pending/rx_mini_pending\n");
		return -EINVAL;
	}

	if (ring->tx_pending > SPNIC_MAX_TX_QUEUE_DEPTH ||
	    ring->tx_pending < SPNIC_MIN_QUEUE_DEPTH ||
	    ring->rx_pending > SPNIC_MAX_RX_QUEUE_DEPTH ||
	    ring->rx_pending < SPNIC_MIN_QUEUE_DEPTH) {
		nicif_err(nic_dev, drv, netdev, "Queue depth out of rang tx[%d-%d] rx[%d-%d]\n",
			  SPNIC_MIN_QUEUE_DEPTH, SPNIC_MAX_TX_QUEUE_DEPTH,
			  SPNIC_MIN_QUEUE_DEPTH, SPNIC_MAX_RX_QUEUE_DEPTH);
		return -EINVAL;
	}

	return 0;
}

static int spnic_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_dyna_txrxq_params q_params = {0};
	u32 new_sq_depth, new_rq_depth;
	int err;

	err = check_ringparam_valid(netdev, ring);
	if (err)
		return err;

	new_sq_depth = (u32)(1U << (u16)ilog2(ring->tx_pending));
	new_rq_depth = (u32)(1U << (u16)ilog2(ring->rx_pending));

	if (new_sq_depth == nic_dev->q_params.sq_depth &&
	    new_rq_depth == nic_dev->q_params.rq_depth)
		return 0;	/* nothing to do */

	nicif_info(nic_dev, drv, netdev, "Change Tx/Rx ring depth from %u/%u to %u/%u\n",
		   nic_dev->q_params.sq_depth, nic_dev->q_params.rq_depth,
		   new_sq_depth, new_rq_depth);

	if (!netif_running(netdev)) {
		spnic_update_qp_depth(nic_dev, new_sq_depth, new_rq_depth);
	} else {
		q_params = nic_dev->q_params;
		q_params.sq_depth = new_sq_depth;
		q_params.rq_depth = new_rq_depth;
		q_params.txqs_res = NULL;
		q_params.rxqs_res = NULL;
		q_params.irq_cfg = NULL;

		nicif_info(nic_dev, drv, netdev, "Restarting channel\n");
		err = spnic_change_channel_settings(nic_dev, &q_params, NULL, NULL);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to change channel settings\n");
			return -EFAULT;
		}
	}

	return 0;
}

static int get_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal, u16 queue)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_intr_coal_info *interrupt_info = NULL;

	if (queue == COALESCE_ALL_QUEUE) {
		/* get tx/rx irq0 as default parameters */
		interrupt_info = &nic_dev->intr_coalesce[0];
	} else {
		if (queue >= nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, netdev, "Invalid queue_id: %u\n", queue);
			return -EINVAL;
		}
		interrupt_info = &nic_dev->intr_coalesce[queue];
	}

	/* coalescs_timer is in unit of 5us */
	coal->rx_coalesce_usecs = interrupt_info->coalesce_timer_cfg * COALESCE_TIMER_CFG_UNIT;
	/* coalescs_frams is in unit of 8 */
	coal->rx_max_coalesced_frames = interrupt_info->pending_limt * COALESCE_PENDING_LIMIT_UNIT;

	/* tx/rx use the same interrupt */
	coal->tx_coalesce_usecs = coal->rx_coalesce_usecs;
	coal->tx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	coal->use_adaptive_rx_coalesce = nic_dev->adaptive_rx_coal;

	coal->pkt_rate_high = (u32)interrupt_info->pkt_rate_high;
	coal->rx_coalesce_usecs_high = interrupt_info->rx_usecs_high * COALESCE_TIMER_CFG_UNIT;
	coal->rx_max_coalesced_frames_high = interrupt_info->rx_pending_limt_high *
						COALESCE_PENDING_LIMIT_UNIT;

	coal->pkt_rate_low = (u32)interrupt_info->pkt_rate_low;
	coal->rx_coalesce_usecs_low = interrupt_info->rx_usecs_low *
				      COALESCE_TIMER_CFG_UNIT;
	coal->rx_max_coalesced_frames_low = interrupt_info->rx_pending_limt_low *
						COALESCE_PENDING_LIMIT_UNIT;

	return 0;
}

static int set_queue_coalesce(struct spnic_nic_dev *nic_dev, u16 q_id,
			      struct spnic_intr_coal_info *coal)
{
	struct spnic_intr_coal_info *intr_coal;
	struct interrupt_info info = {0};
	struct net_device *netdev = nic_dev->netdev;
	int err;

	intr_coal = &nic_dev->intr_coalesce[q_id];
	if (intr_coal->coalesce_timer_cfg != coal->coalesce_timer_cfg ||
	    intr_coal->pending_limt != coal->pending_limt)
		intr_coal->user_set_intr_coal_flag = 1;

	intr_coal->coalesce_timer_cfg = coal->coalesce_timer_cfg;
	intr_coal->pending_limt = coal->pending_limt;
	intr_coal->pkt_rate_low = coal->pkt_rate_low;
	intr_coal->rx_usecs_low = coal->rx_usecs_low;
	intr_coal->rx_pending_limt_low = coal->rx_pending_limt_low;
	intr_coal->pkt_rate_high = coal->pkt_rate_high;
	intr_coal->rx_usecs_high = coal->rx_usecs_high;
	intr_coal->rx_pending_limt_high = coal->rx_pending_limt_high;

	/* netdev not running or qp not in using,
	 * don't need to set coalesce to hw
	 */
	if (!test_bit(SPNIC_INTF_UP, &nic_dev->flags) ||
	    q_id >= nic_dev->q_params.num_qps || nic_dev->adaptive_rx_coal)
		return 0;

	info.msix_index = nic_dev->q_params.irq_cfg[q_id].msix_entry_idx;
	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.coalesc_timer_cfg = intr_coal->coalesce_timer_cfg;
	info.pending_limt = intr_coal->pending_limt;
	info.resend_timer_cfg = intr_coal->resend_timer_cfg;
	nic_dev->rxqs[q_id].last_coalesc_timer_cfg = intr_coal->coalesce_timer_cfg;
	nic_dev->rxqs[q_id].last_pending_limt = intr_coal->pending_limt;
	err = sphw_set_interrupt_cfg(nic_dev->hwdev, info, SPHW_CHANNEL_NIC);
	if (err)
		nicif_warn(nic_dev, drv, netdev, "Failed to set queue%u coalesce", q_id);

	return err;
}

static int is_coalesce_exceed_limit(struct net_device *netdev,
				    const struct ethtool_coalesce *coal)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (coal->rx_coalesce_usecs > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev, "rx_coalesce_usecs out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev, "rx_max_coalesced_frames out of range[%d-%d]\n", 0,
			  COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	if (coal->rx_coalesce_usecs_low > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev, "rx_coalesce_usecs_low out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames_low > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev, "rx_max_coalesced_frames_low out of range[%d-%d]\n",
			  0, COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	if (coal->rx_coalesce_usecs_high > COALESCE_MAX_TIMER_CFG) {
		nicif_err(nic_dev, drv, netdev, "rx_coalesce_usecs_high out of range[%d-%d]\n", 0,
			  COALESCE_MAX_TIMER_CFG);
		return -EOPNOTSUPP;
	}

	if (coal->rx_max_coalesced_frames_high > COALESCE_MAX_PENDING_LIMIT) {
		nicif_err(nic_dev, drv, netdev, "rx_max_coalesced_frames_high out of range[%d-%d]\n",
			  0, COALESCE_MAX_PENDING_LIMIT);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int is_coalesce_legal(struct net_device *netdev,
			     const struct ethtool_coalesce *coal)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct ethtool_coalesce tmp_coal = {0};
	int err;

	if (coal->rx_coalesce_usecs != coal->tx_coalesce_usecs) {
		nicif_err(nic_dev, drv, netdev, "tx-usecs must be equal to rx-usecs\n");
		return -EINVAL;
	}

	if (coal->rx_max_coalesced_frames != coal->tx_max_coalesced_frames) {
		nicif_err(nic_dev, drv, netdev, "tx-frames must be equal to rx-frames\n");
		return -EINVAL;
	}

	tmp_coal.cmd = coal->cmd;
	tmp_coal.rx_coalesce_usecs = coal->rx_coalesce_usecs;
	tmp_coal.rx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	tmp_coal.tx_coalesce_usecs = coal->tx_coalesce_usecs;
	tmp_coal.tx_max_coalesced_frames = coal->tx_max_coalesced_frames;
	tmp_coal.use_adaptive_rx_coalesce = coal->use_adaptive_rx_coalesce;

	tmp_coal.pkt_rate_low = coal->pkt_rate_low;
	tmp_coal.rx_coalesce_usecs_low = coal->rx_coalesce_usecs_low;
	tmp_coal.rx_max_coalesced_frames_low = coal->rx_max_coalesced_frames_low;

	tmp_coal.pkt_rate_high = coal->pkt_rate_high;
	tmp_coal.rx_coalesce_usecs_high = coal->rx_coalesce_usecs_high;
	tmp_coal.rx_max_coalesced_frames_high = coal->rx_max_coalesced_frames_high;

	if (memcmp(coal, &tmp_coal, sizeof(struct ethtool_coalesce))) {
		nicif_err(nic_dev, drv, netdev, "Only support to change rx/tx-usecs and rx/tx-frames\n");
		return -EOPNOTSUPP;
	}

	err = is_coalesce_exceed_limit(netdev, coal);
	if (err)
		return err;

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
		nicif_err(nic_dev, drv, netdev, "pkt_rate_high(%u) must more than pkt_rate_low(%u)\n",
			  coal->pkt_rate_high,
			  coal->pkt_rate_low);
		return -EOPNOTSUPP;
	}

	return 0;
}

#define CHECK_COALESCE_ALIGN(coal, item, unit)				\
do {									\
	if ((coal)->item % (unit))					\
		nicif_warn(nic_dev, drv, netdev,			\
			   "%s in %d units, change to %u\n",		\
			   #item, (unit), ((coal)->item -	\
					   (coal)->item % (unit))); \
} while (0)

#define CHECK_COALESCE_CHANGED(coal, item, unit, ori_val, obj_str)	\
do {									\
	if (((coal)->item / (unit)) != (ori_val))			\
		nicif_info(nic_dev, drv, netdev,			\
			   "Change %s from %d to %u %s\n",		\
			   #item, (ori_val) * (unit),			\
			   ((coal)->item - (coal)->item % (unit)),	\
			    (obj_str));			\
} while (0)

#define CHECK_PKT_RATE_CHANGED(coal, item, ori_val, obj_str)		\
do {									\
	if ((coal)->item != (ori_val))					\
		nicif_info(nic_dev, drv, netdev,			\
			   "Change %s from %llu to %u %s\n",		\
			   #item, (ori_val), (coal)->item, (obj_str));	\
} while (0)

static int set_hw_coal_param(struct spnic_nic_dev *nic_dev, struct spnic_intr_coal_info *intr_coal,
			     u16 queue)
{
	u16 i;

	if (queue == COALESCE_ALL_QUEUE) {
		for (i = 0; i < nic_dev->max_qps; i++)
			set_queue_coalesce(nic_dev, i, intr_coal);
	} else {
		if (queue >= nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid queue_id: %u\n", queue);
			return -EINVAL;
		}
		set_queue_coalesce(nic_dev, queue, intr_coal);
	}

	return 0;
}

static int set_coalesce(struct net_device *netdev, struct ethtool_coalesce *coal, u16 queue)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_intr_coal_info intr_coal = {0};
	struct spnic_intr_coal_info *ori_intr_coal = NULL;
	u32 last_adaptive_rx;
	char obj_str[32] = {0};
	int err = 0;

	err = is_coalesce_legal(netdev, coal);
	if (err)
		return err;

	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs, COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames, COALESCE_PENDING_LIMIT_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs_high, COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames_high, COALESCE_PENDING_LIMIT_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_coalesce_usecs_low, COALESCE_TIMER_CFG_UNIT);
	CHECK_COALESCE_ALIGN(coal, rx_max_coalesced_frames_low, COALESCE_PENDING_LIMIT_UNIT);

	if (queue == COALESCE_ALL_QUEUE) {
		ori_intr_coal = &nic_dev->intr_coalesce[0];
		snprintf(obj_str, sizeof(obj_str), "for netdev");
	} else {
		ori_intr_coal = &nic_dev->intr_coalesce[queue];
		snprintf(obj_str, sizeof(obj_str), "for queue %u", queue);
	}
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs, COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->coalesce_timer_cfg, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames, COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->pending_limt, obj_str);
	CHECK_PKT_RATE_CHANGED(coal, pkt_rate_high, ori_intr_coal->pkt_rate_high, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs_high, COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->rx_usecs_high, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames_high, COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->rx_pending_limt_high, obj_str);
	CHECK_PKT_RATE_CHANGED(coal, pkt_rate_low, ori_intr_coal->pkt_rate_low, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_coalesce_usecs_low, COALESCE_TIMER_CFG_UNIT,
			       ori_intr_coal->rx_usecs_low, obj_str);
	CHECK_COALESCE_CHANGED(coal, rx_max_coalesced_frames_low, COALESCE_PENDING_LIMIT_UNIT,
			       ori_intr_coal->rx_pending_limt_low, obj_str);

	intr_coal.coalesce_timer_cfg = (u8)(coal->rx_coalesce_usecs / COALESCE_TIMER_CFG_UNIT);
	intr_coal.pending_limt = (u8)(coal->rx_max_coalesced_frames / COALESCE_PENDING_LIMIT_UNIT);

	last_adaptive_rx = nic_dev->adaptive_rx_coal;
	nic_dev->adaptive_rx_coal = coal->use_adaptive_rx_coalesce;

	intr_coal.pkt_rate_high = coal->pkt_rate_high;
	intr_coal.rx_usecs_high = (u8)(coal->rx_coalesce_usecs_high / COALESCE_TIMER_CFG_UNIT);
	intr_coal.rx_pending_limt_high = (u8)(coal->rx_max_coalesced_frames_high /
					      COALESCE_PENDING_LIMIT_UNIT);

	intr_coal.pkt_rate_low = coal->pkt_rate_low;
	intr_coal.rx_usecs_low = (u8)(coal->rx_coalesce_usecs_low / COALESCE_TIMER_CFG_UNIT);
	intr_coal.rx_pending_limt_low = (u8)(coal->rx_max_coalesced_frames_low /
					     COALESCE_PENDING_LIMIT_UNIT);

	/* coalesce timer or pending set to zero will disable coalesce */
	if (!nic_dev->adaptive_rx_coal &&
	    (!intr_coal.coalesce_timer_cfg || !intr_coal.pending_limt))
		nicif_warn(nic_dev, drv, netdev, "Coalesce will be disabled\n");

	/* ensure coalesce paramester will not be changed in auto
	 * moderation work
	 */
	if (SPHW_CHANNEL_RES_VALID(nic_dev)) {
		if (!nic_dev->adaptive_rx_coal)
			cancel_delayed_work_sync(&nic_dev->moderation_task);
		else if (!last_adaptive_rx)
			queue_delayed_work(nic_dev->workq, &nic_dev->moderation_task,
					   SPNIC_MODERATONE_DELAY);
	}

	return set_hw_coal_param(nic_dev, &intr_coal, queue);
}

static int spnic_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *ext_ack)
{
	return get_coalesce(netdev, coal, COALESCE_ALL_QUEUE);
}

static int spnic_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *ext_ack)
{
	return set_coalesce(netdev, coal, COALESCE_ALL_QUEUE);
}

static int spnic_get_per_queue_coalesce(struct net_device *netdev, u32 queue,
					struct ethtool_coalesce *coal)
{
	return get_coalesce(netdev, coal, queue);
}

static int spnic_set_per_queue_coalesce(struct net_device *netdev, u32 queue,
					struct ethtool_coalesce *coal)
{
	return set_coalesce(netdev, coal, queue);
}

static int spnic_set_phys_id(struct net_device *netdev, enum ethtool_phys_id_state state)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		err = spnic_set_led_status(nic_dev->hwdev, MAG_CMD_LED_TYPE_ALARM,
					   MAG_CMD_LED_MODE_FORCE_BLINK_2HZ);
		if (err)
			nicif_err(nic_dev, drv, netdev, "Set LED blinking in 2HZ failed\n");
		else
			nicif_info(nic_dev, drv, netdev, "Set LED blinking in 2HZ success\n");
		break;

	case ETHTOOL_ID_INACTIVE:
		err = spnic_set_led_status(nic_dev->hwdev, MAG_CMD_LED_TYPE_ALARM,
					   MAG_CMD_LED_MODE_DEFAULT);
		if (err)
			nicif_err(nic_dev, drv, netdev, "Reset LED to original status failed\n");
		else
			nicif_info(nic_dev, drv, netdev, "Reset LED to original status success\n");
		break;

	default:
		return -EOPNOTSUPP;
	}

	return err;
}

static void spnic_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct nic_pause_config nic_pause = {0};
	int err;

	err = spnic_get_pause_info(nic_dev->hwdev, &nic_pause);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to get pauseparam from hw\n");
	} else {
		pause->autoneg = nic_pause.auto_neg;
		pause->rx_pause = nic_pause.rx_pause;
		pause->tx_pause = nic_pause.tx_pause;
	}
}

static int spnic_set_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct nic_pause_config nic_pause = {0};
	struct nic_port_info port_info = {0};
	int err;

	err = spnic_get_port_info(nic_dev->hwdev, &port_info, SPHW_CHANNEL_NIC);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to get auto-negotiation state\n");
		return -EFAULT;
	}

	if (pause->autoneg != port_info.autoneg_state) {
		nicif_err(nic_dev, drv, netdev, "To change autoneg please use: ethtool -s <dev> autoneg <on|off>\n");
		return -EOPNOTSUPP;
	}

	if (nic_dev->hw_dcb_cfg.pfc_state) {
		nicif_err(nic_dev, drv, netdev, "Can not set pause when pfc is enable\n");
		return -EPERM;
	}

	nic_pause.auto_neg = (u8)pause->autoneg;
	nic_pause.rx_pause = (u8)pause->rx_pause;
	nic_pause.tx_pause = (u8)pause->tx_pause;

	err = spnic_set_pause_info(nic_dev->hwdev, nic_pause);
	if (err) {
		nicif_err(nic_dev, drv, netdev, "Failed to set pauseparam\n");
		return -EFAULT;
	}

	nicif_info(nic_dev, drv, netdev, "Set pause options, tx: %s, rx: %s\n",
		   pause->tx_pause ? "on" : "off",
		   pause->rx_pause ? "on" : "off");

	return 0;
}

static int spnic_get_module_info(struct net_device *netdev, struct ethtool_modinfo *modinfo)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u8 sfp_type = 0;
	u8 sfp_type_ext = 0;
	int err;

	err = spnic_get_sfp_type(nic_dev->hwdev, &sfp_type, &sfp_type_ext);
	if (err)
		return err;

	switch (sfp_type) {
	case MODULE_TYPE_SFP:
		modinfo->type = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
		break;
	case MODULE_TYPE_QSFP:
		modinfo->type = ETH_MODULE_SFF_8436;
		modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		break;
	case MODULE_TYPE_QSFP_PLUS:
		if (sfp_type_ext >= 0x3) {
			modinfo->type = ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;

		} else {
			modinfo->type = ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = ETH_MODULE_SFF_8436_MAX_LEN;
		}
		break;
	case MODULE_TYPE_QSFP28:
		modinfo->type = ETH_MODULE_SFF_8636;
		modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		break;
	default:
		nicif_warn(nic_dev, drv, netdev, "Optical module unknown: 0x%x\n", sfp_type);
		return -EINVAL;
	}

	return 0;
}

static int spnic_get_module_eeprom(struct net_device *netdev, struct ethtool_eeprom *ee, u8 *data)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u8 sfp_data[STD_SFP_INFO_MAX_SIZE];
	int err;

	if (!ee->len || ((ee->len + ee->offset) > STD_SFP_INFO_MAX_SIZE))
		return -EINVAL;

	memset(data, 0, ee->len);

	err = spnic_get_sfp_eeprom(nic_dev->hwdev, (u8 *)sfp_data, ee->len);
	if (err)
		return err;

	memcpy(data, sfp_data + ee->offset, ee->len);

	return 0;
}

#define SPNIC_PRIV_FLAGS_SYMM_RSS	BIT(0)

static u32 spnic_get_priv_flags(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u32 priv_flags = 0;

	if (test_bit(SPNIC_SAME_RXTX, &nic_dev->flags))
		priv_flags |= SPNIC_PRIV_FLAGS_SYMM_RSS;

	return priv_flags;
}

static int spnic_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (priv_flags & SPNIC_PRIV_FLAGS_SYMM_RSS) {
		if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
			nicif_err(nic_dev, drv, netdev, "Failed to open Symmetric RSS while DCB is enabled\n");
			return -EOPNOTSUPP;
		}
		set_bit(SPNIC_SAME_RXTX, &nic_dev->flags);
	} else {
		clear_bit(SPNIC_SAME_RXTX, &nic_dev->flags);
	}

	return 0;
}

#define BROADCAST_PACKET_SIM   0xFF
#define UNICAST_PACKET_SIM     0xFE
#define IP_PROTOCOL_TYPE       0x08
#define IP_PROTOCOL_COMPLEMENT 0x00

#define PORT_DOWN_ERR_IDX  0
#define LP_DEFAULT_TIME    5 /* seconds */
#define LP_PKT_LEN         1514

#define TEST_TIME_MULTIPLE 5
static int spnic_run_lp_test(struct spnic_nic_dev *nic_dev, u32 test_time)
{
	u32 cnt = test_time * TEST_TIME_MULTIPLE;
	struct sk_buff *skb = NULL;
	struct sk_buff *skb_tmp = NULL;
	u8 *test_data = NULL;
	u8 *lb_test_rx_buf = nic_dev->lb_test_rx_buf;
	struct net_device *netdev = nic_dev->netdev;
	u32 i;
	u8 j;

	skb_tmp = alloc_skb(LP_PKT_LEN, GFP_ATOMIC);
	if (!skb_tmp) {
		nicif_err(nic_dev, drv, netdev, "Alloc xmit skb template failed for loopback test\n");
		return -ENOMEM;
	}

	test_data = __skb_put(skb_tmp, LP_PKT_LEN);

	memset(test_data, BROADCAST_PACKET_SIM, ETH_ALEN + ETH_ALEN);

	test_data[ETH_ALEN] = UNICAST_PACKET_SIM;
	test_data[ETH_ALEN + ETH_ALEN] = IP_PROTOCOL_TYPE;
	test_data[ETH_ALEN + ETH_ALEN + 1] = IP_PROTOCOL_COMPLEMENT;

	for (i = ETH_HLEN; i < LP_PKT_LEN; i++)
		test_data[i] = i & 0xFF;

	skb_tmp->queue_mapping = 0;
	skb_tmp->ip_summed = CHECKSUM_COMPLETE;
	skb_tmp->dev = netdev;

	for (i = 0; i < cnt; i++) {
		nic_dev->lb_test_rx_idx = 0;
		memset(lb_test_rx_buf, 0, LP_PKT_CNT * LP_PKT_LEN);

		for (j = 0; j < LP_PKT_CNT; j++) {
			skb = pskb_copy(skb_tmp, GFP_ATOMIC);
			if (!skb) {
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev, "Copy skb failed for loopback test\n");
				return -ENOMEM;
			}

			/* mark index for every pkt */
			skb->data[LP_PKT_LEN - 1] = j;

			if (spnic_lb_xmit_frame(skb, netdev)) {
				dev_kfree_skb_any(skb);
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev, "Xmit pkt failed for loopback test\n");
				return -EBUSY;
			}
		}

		/* wait till all pkts received to RX buffer */
		msleep(200);

		for (j = 0; j < LP_PKT_CNT; j++) {
			if (memcmp((lb_test_rx_buf + (j * LP_PKT_LEN)),
				   skb_tmp->data, (LP_PKT_LEN - 1)) ||
				   (*(lb_test_rx_buf + ((j * LP_PKT_LEN) +
				   (LP_PKT_LEN - 1))) != j)) {
				dev_kfree_skb_any(skb_tmp);
				nicif_err(nic_dev, drv, netdev,
					  "Compare pkt failed in loopback test(index=0x%02x, data[%d]=0x%02x)\n",
					  (j + (i * LP_PKT_CNT)), (LP_PKT_LEN - 1),
					  *(lb_test_rx_buf +
					    ((j * LP_PKT_LEN) + (LP_PKT_LEN - 1))));
				return -EIO;
			}
		}
	}

	dev_kfree_skb_any(skb_tmp);
	nicif_info(nic_dev, drv, netdev, "Loopback test succeed.\n");
	return 0;
}

enum diag_test_index {
	INTERNAL_LP_TEST = 0,
	EXTERNAL_LP_TEST = 1,
	DIAG_TEST_MAX = 2,
};

#define SPNIC_INTERNAL_LP_MODE 5
static int do_lp_test(struct spnic_nic_dev *nic_dev, u32 *flags, u32 test_time,
		      enum diag_test_index *test_index)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 *lb_test_rx_buf = NULL;
	int err = 0;

	if (!(*flags & ETH_TEST_FL_EXTERNAL_LB)) {
		*test_index = INTERNAL_LP_TEST;
		if (spnic_set_loopback_mode(nic_dev->hwdev, SPNIC_INTERNAL_LP_MODE, true)) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to set port loopback mode before loopback test\n");
			return -EFAULT;
		}
	} else {
		*test_index = EXTERNAL_LP_TEST;
	}

	lb_test_rx_buf = vmalloc(LP_PKT_CNT * LP_PKT_LEN);
	if (!lb_test_rx_buf) {
		nicif_err(nic_dev, drv, netdev, "Failed to alloc RX buffer for loopback test\n");
		err = -ENOMEM;
	} else {
		nic_dev->lb_test_rx_buf = lb_test_rx_buf;
		nic_dev->lb_pkt_len = LP_PKT_LEN;
		set_bit(SPNIC_LP_TEST, &nic_dev->flags);

		if (spnic_run_lp_test(nic_dev, test_time))
			err = -EFAULT;

		clear_bit(SPNIC_LP_TEST, &nic_dev->flags);
		msleep(100);
		vfree(lb_test_rx_buf);
		nic_dev->lb_test_rx_buf = NULL;
	}

	if (!(*flags & ETH_TEST_FL_EXTERNAL_LB)) {
		if (spnic_set_loopback_mode(nic_dev->hwdev, SPNIC_INTERNAL_LP_MODE, false)) {
			nicif_err(nic_dev, drv, netdev,
				  "Failed to cancel port loopback mode after loopback test\n");
			err = -EFAULT;
		}
	} else {
		*flags |= ETH_TEST_FL_EXTERNAL_LB_DONE;
	}

	return err;
}

void spnic_lp_test(struct net_device *netdev, struct ethtool_test *eth_test,
		   u64 *data, u32 test_time)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	enum diag_test_index test_index = 0;
	u8 link_status = 0;
	int err;

	/* don't support loopback test when netdev is closed. */
	if (!test_bit(SPNIC_INTF_UP, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, netdev,
			  "Do not support loopback test when netdev is closed\n");
		eth_test->flags |= ETH_TEST_FL_FAILED;
		data[PORT_DOWN_ERR_IDX] = 1;
		return;
	}

	if (test_time == 0)
		test_time = LP_DEFAULT_TIME;

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	err = do_lp_test(nic_dev, &eth_test->flags, test_time, &test_index);
	if (err) {
		eth_test->flags |= ETH_TEST_FL_FAILED;
		data[test_index] = 1;
	}

	netif_tx_wake_all_queues(netdev);

	err = spnic_get_link_state(nic_dev->hwdev, &link_status);
	if (!err && link_status)
		netif_carrier_on(netdev);
}

static void spnic_diag_test(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data)
{
	memset(data, 0, DIAG_TEST_MAX * sizeof(u64));

	spnic_lp_test(netdev, eth_test, data, 0);
}

static const struct ethtool_ops spnic_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_PKT_RATE_RX_USECS,
	.get_link_ksettings	= spnic_get_link_ksettings,
	.set_link_ksettings	= spnic_set_link_ksettings,

	.get_drvinfo		= spnic_get_drvinfo,
	.get_msglevel		= spnic_get_msglevel,
	.set_msglevel		= spnic_set_msglevel,
	.nway_reset		= spnic_nway_reset,
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= spnic_get_ringparam,
	.set_ringparam		= spnic_set_ringparam,
	.get_pauseparam		= spnic_get_pauseparam,
	.set_pauseparam		= spnic_set_pauseparam,
	.get_sset_count		= spnic_get_sset_count,
	.get_ethtool_stats	= spnic_get_ethtool_stats,
	.get_strings		= spnic_get_strings,

	.self_test		= spnic_diag_test,
	.set_phys_id		= spnic_set_phys_id,

	.get_coalesce		= spnic_get_coalesce,
	.set_coalesce		= spnic_set_coalesce,
	.get_per_queue_coalesce	= spnic_get_per_queue_coalesce,
	.set_per_queue_coalesce	= spnic_set_per_queue_coalesce,

	.get_rxnfc		= spnic_get_rxnfc,
	.set_rxnfc		= spnic_set_rxnfc,
	.get_priv_flags		= spnic_get_priv_flags,
	.set_priv_flags		= spnic_set_priv_flags,

	.get_channels		= spnic_get_channels,
	.set_channels		= spnic_set_channels,

	.get_module_info	= spnic_get_module_info,
	.get_module_eeprom	= spnic_get_module_eeprom,

	.get_rxfh_indir_size    = spnic_get_rxfh_indir_size,
	.get_rxfh_key_size	= spnic_get_rxfh_key_size,
	.get_rxfh		= spnic_get_rxfh,
	.set_rxfh		= spnic_set_rxfh,
};

static const struct ethtool_ops spnicvf_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_PKT_RATE_RX_USECS,
	.get_link_ksettings	= spnic_get_link_ksettings,
	.get_drvinfo		= spnic_get_drvinfo,
	.get_msglevel		= spnic_get_msglevel,
	.set_msglevel		= spnic_set_msglevel,
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= spnic_get_ringparam,

	.set_ringparam		= spnic_set_ringparam,
	.get_sset_count		= spnic_get_sset_count,
	.get_ethtool_stats	= spnic_get_ethtool_stats,
	.get_strings		= spnic_get_strings,

	.get_coalesce		= spnic_get_coalesce,
	.set_coalesce		= spnic_set_coalesce,
	.get_per_queue_coalesce	= spnic_get_per_queue_coalesce,
	.set_per_queue_coalesce	= spnic_set_per_queue_coalesce,

	.get_rxnfc		= spnic_get_rxnfc,
	.set_rxnfc		= spnic_set_rxnfc,
	.get_priv_flags		= spnic_get_priv_flags,
	.set_priv_flags		= spnic_set_priv_flags,

	.get_channels		= spnic_get_channels,
	.set_channels		= spnic_set_channels,

	.get_rxfh_indir_size	= spnic_get_rxfh_indir_size,
	.get_rxfh_key_size	= spnic_get_rxfh_key_size,
	.get_rxfh		= spnic_get_rxfh,
	.set_rxfh		= spnic_set_rxfh,
};

void spnic_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &spnic_ethtool_ops;
}

void spnicvf_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &spnicvf_ethtool_ops;
}
