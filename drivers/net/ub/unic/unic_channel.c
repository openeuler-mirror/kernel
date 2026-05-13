// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include "unic_channel.h"
#include "unic_dev.h"
#include "unic_netdev.h"

void unic_get_channels(struct net_device *ndev,
		       struct ethtool_channels *ch)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	ch->max_combined = unic_channels_max_num(unic_dev->comdev.adev);
	ch->combined_count = unic_dev->channels.rss_size;
}

static int unic_check_rss_size_param(struct unic_dev *unic_dev, u32 new_rss_size,
				     u32 org_rss_size)
{
	u32 max_rss_size;

	if (org_rss_size == new_rss_size) {
		unic_err(unic_dev,
			 "old num and new num are the same, rss_size = %u.\n",
			 org_rss_size);
		return -EINVAL;
	}

	max_rss_size = unic_get_max_rss_size(unic_dev);
	if (new_rss_size < 1 || new_rss_size > max_rss_size) {
		unic_err(unic_dev,
			 "the rss_size(%u) is out of the range [1, %u].\n",
			 new_rss_size, max_rss_size);
		return -EINVAL;
	}

	if (max_rss_size % new_rss_size) {
		unic_err(unic_dev,
			 "the rss_size(%u) can't divisible by max_rss_size(%u).\n",
			 new_rss_size, max_rss_size);
		return -EINVAL;
	}

	return 0;
}

static int unic_check_set_channels_available(struct net_device *ndev)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (netif_running(ndev)) {
		unic_err(unic_dev,
			 "failed to set channels, due to network interface is up, please down it first and try again.\n");
		return -EBUSY;
	}

	if (unic_resetting(ndev)) {
		unic_err(unic_dev,
			 "failed to set channels, due to dev resetting.\n");
		return -EBUSY;
	}

	return 0;
}

int unic_set_channels(struct net_device *ndev,
		      struct ethtool_channels *ch)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	u32 org_rss_size = unic_dev->channels.rss_size;
	u32 new_rss_size = ch->combined_count;
	int ret, ret1;

	ret = unic_check_set_channels_available(ndev);
	if (ret)
		return ret;

	ret = unic_check_rss_size_param(unic_dev, new_rss_size, org_rss_size);
	if (ret)
		return ret;

	ret = unic_change_rss_size(unic_dev, new_rss_size, org_rss_size);
	if (ret) {
		unic_err(unic_dev,
			 "failed to change rss_size, revert to old rss_size, ret = %d.\n",
			 ret);

		ret1 = unic_change_rss_size(unic_dev, org_rss_size, org_rss_size);
		if (ret1) {
			unic_err(unic_dev,
				 "failed to revert to old rss_size, ret1 = %d.\n",
				 ret1);
			return ret1;
		}
	}

	return ret;
}

static bool unic_is_channels_param_changed(struct unic_dev *unic_dev,
					   struct ethtool_ringparam *param,
					   struct kernel_ethtool_ringparam *kernel_param,
					   struct unic_channel_param *channels_param)
{
	channels_param->sqebb_depth = roundup_pow_of_two(param->tx_pending);
	channels_param->rqe_depth = roundup_pow_of_two(param->rx_pending);
	channels_param->rx_buff_len = kernel_param->rx_buf_len;

	if (unic_dev->channels.sqebb_depth != channels_param->sqebb_depth)
		set_bit(UNIC_TX_CHANGED, &unic_dev->channels.state);

	if (unic_dev->channels.rx_buff_len != channels_param->rx_buff_len ||
	    unic_dev->channels.rqe_depth != channels_param->rqe_depth)
		set_bit(UNIC_RX_CHANGED, &unic_dev->channels.state);

	return unic_tx_changed(unic_dev) || unic_rx_changed(unic_dev);
}

static int unic_check_channels_param(struct unic_dev *unic_dev,
				     struct ethtool_ringparam *param,
				     struct kernel_ethtool_ringparam *kernel_param)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_adev_caps *unic_caps = ubase_get_unic_caps(adev);
	struct net_device *netdev = unic_dev->comdev.netdev;
	u32 i;

	if (netif_running(netdev)) {
		unic_err(unic_dev,
			 "failed to set channels param, due to netdev is up, down it first and try again.\n");
		return -EBUSY;
	}

	if (__unic_resetting(unic_dev) || !unic_dev->channels.c) {
		unic_err(unic_dev,
			 "failed to check param value, due to dev resetting or uninited\n");
		return -EBUSY;
	}

	for (i = 0; i < unic_dev->channels.num; i++) {
		if (!unic_dev->channels.c[i].sq ||
		    !unic_dev->channels.c[i].rq) {
			unic_err(unic_dev, "channel(%u) sq or rq is null.\n", i);
			return -ENXIO;
		}
	}

	if (param->rx_mini_pending || param->rx_jumbo_pending)
		return -EINVAL;

	if (param->tx_pending > unic_caps->jfs.depth ||
	    param->tx_pending < UNIC_TXRX_MIN_DEPTH) {
		unic_err(unic_dev,
			 "tx queue depth = %u out of range [%d, %u].\n",
			 param->tx_pending, UNIC_TXRX_MIN_DEPTH,
			 unic_caps->jfs.depth);
		return -EINVAL;
	}

	if (param->rx_pending > unic_caps->jfr.depth ||
	    param->rx_pending < UNIC_TXRX_MIN_DEPTH) {
		unic_err(unic_dev,
			 "rx queue depth = %u out of range [%d, %u].\n",
			 param->rx_pending, UNIC_TXRX_MIN_DEPTH,
			 unic_caps->jfr.depth);
		return -EINVAL;
	}

	if (kernel_param->rx_buf_len != UNIC_RX_BUF_LEN_2K &&
	    kernel_param->rx_buf_len != UNIC_RX_BUF_LEN_4K) {
		unic_err(unic_dev,
			 "rx buf len(%u) is not equal to %d or %d.\n",
			 kernel_param->rx_buf_len, UNIC_RX_BUF_LEN_2K,
			 UNIC_RX_BUF_LEN_4K);
		return -EINVAL;
	}

	return 0;
}

static void unic_dev_change_channels_param(struct unic_dev *unic_dev,
					   struct unic_channel_param param)
{
	struct unic_channels *channels = &unic_dev->channels;

	channels->sqebb_depth = param.sqebb_depth;
	channels->rqe_depth = param.rqe_depth;
	channels->sq_cqe_depth = param.sqebb_depth;
	channels->rq_cqe_depth = param.rqe_depth;

	channels->rx_buff_len = param.rx_buff_len;
	channels->sqebb_shift = ilog2(roundup_pow_of_two(channels->sqebb_depth));
	channels->sq_jfc_shift = ilog2(roundup_pow_of_two(channels->sq_cqe_depth));
	channels->rq_jfc_shift = ilog2(roundup_pow_of_two(channels->rq_cqe_depth));
}

static void unic_clear_txrx_channels_state(struct unic_dev *unic_dev)
{
	clear_bit(UNIC_TX_CHANGED, &unic_dev->channels.state);
	clear_bit(UNIC_RX_CHANGED, &unic_dev->channels.state);
}

static void unic_uninit_changed_channels(struct unic_dev *unic_dev)
{
	struct unic_channels *channels = &unic_dev->channels;

	if (unic_tx_changed(unic_dev))
		unic_destroy_tx(unic_dev, channels->num);

	if (unic_rx_changed(unic_dev))
		unic_destroy_rx(unic_dev, channels->num);
}

static int unic_init_changed_channels(struct unic_dev *unic_dev)
{
	struct unic_channels *channels = &unic_dev->channels;
	int ret = 0;

	if (unic_tx_changed(unic_dev)) {
		ret = unic_init_tx(unic_dev, channels->num);
		if (ret)
			goto out;
	}

	if (unic_rx_changed(unic_dev)) {
		ret = unic_init_rx(unic_dev, channels->num);
		if (ret)
			goto err_init_rx_channels;
	}

	goto out;

err_init_rx_channels:
	if (unic_tx_changed(unic_dev))
		unic_destroy_tx(unic_dev, channels->num);
out:
	return ret;
}

static int unic_modify_channels(struct unic_dev *unic_dev,
				struct unic_channel_param new_param)
{
	struct unic_channels *channels = &unic_dev->channels;
	int ret;

	mutex_lock(&channels->mutex);
	set_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);
	unic_uninit_changed_channels(unic_dev);

	unic_dev_change_channels_param(unic_dev, new_param);

	ret = unic_init_changed_channels(unic_dev);
	if (!ret)
		clear_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);

	mutex_unlock(&channels->mutex);
	return ret;
}

static void unic_backup_channels_param(struct unic_dev *unic_dev,
				       struct unic_channel_param *channels_param)
{
	channels_param->sqebb_depth = unic_dev->channels.sqebb_depth;
	channels_param->rqe_depth = unic_dev->channels.rqe_depth;
	channels_param->rx_buff_len = unic_dev->channels.rx_buff_len;
}

static int unic_alloc_txrx_stats(struct unic_dev *unic_dev,
				 struct unic_sq_stats **sq_stats,
				 struct unic_rq_stats **rq_stats)
{
	if (unic_tx_changed(unic_dev)) {
		*sq_stats = kcalloc(unic_dev->channels.num, sizeof(**sq_stats),
				    GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(*sq_stats))
			return -ENOMEM;
	}

	if (unic_rx_changed(unic_dev)) {
		*rq_stats = kcalloc(unic_dev->channels.num, sizeof(**rq_stats),
				    GFP_KERNEL);
		if (ZERO_OR_NULL_PTR(*rq_stats)) {
			if (unic_tx_changed(unic_dev))
				kfree(*sq_stats);
			return -ENOMEM;
		}
	}

	return 0;
}

static void unic_free_txrx_stats(struct unic_dev *unic_dev,
				 struct unic_sq_stats *sq_stats,
				 struct unic_rq_stats *rq_stats)
{
	if (unic_tx_changed(unic_dev))
		kfree(sq_stats);

	if (unic_rx_changed(unic_dev))
		kfree(rq_stats);
}

static void unic_backup_sqrq_stats(struct unic_dev *unic_dev,
				   struct unic_sq_stats *sq_stats,
				   struct unic_rq_stats *rq_stats)
{
	u32 i;

	for (i = 0; i < unic_dev->channels.num; i++) {
		if (unic_tx_changed(unic_dev))
			memcpy(&sq_stats[i], &unic_dev->channels.c[i].sq->stats,
			       sizeof(struct unic_sq_stats));
		if (unic_rx_changed(unic_dev))
			memcpy(&rq_stats[i], &unic_dev->channels.c[i].rq->stats,
			       sizeof(struct unic_rq_stats));
	}
}

static void unic_backup_param_and_stats(struct unic_dev *unic_dev,
					struct unic_channel_param *channels_param,
					struct unic_sq_stats *sq_stats,
					struct unic_rq_stats *rq_stats)
{
	unic_backup_channels_param(unic_dev, channels_param);
	unic_backup_sqrq_stats(unic_dev, sq_stats, rq_stats);
}

static void unic_restore_sqrq_stats(struct unic_dev *unic_dev,
				    struct unic_sq_stats *sq_stats,
				    struct unic_rq_stats *rq_stats)
{
	u32 i;

	for (i = 0; i < unic_dev->channels.num; i++) {
		if (unic_rx_changed(unic_dev))
			memcpy(&unic_dev->channels.c[i].rq->stats, &rq_stats[i],
			       sizeof(struct unic_rq_stats));
		if (unic_tx_changed(unic_dev))
			memcpy(&unic_dev->channels.c[i].sq->stats, &sq_stats[i],
			       sizeof(struct unic_sq_stats));
	}
}

int unic_set_channels_param(struct net_device *ndev,
			    struct ethtool_ringparam *param,
			    struct kernel_ethtool_ringparam *kernel_param,
			    struct netlink_ext_ack *extack)
{
	struct unic_channel_param new_param, org_param;
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_sq_stats *sq_stats;
	struct unic_rq_stats *rq_stats;
	int ret, ret1;

	ret = unic_check_channels_param(unic_dev, param, kernel_param);
	if (ret)
		return ret;

	if (!unic_is_channels_param_changed(unic_dev, param, kernel_param,
					    &new_param))
		return 0;

	ret = unic_alloc_txrx_stats(unic_dev, &sq_stats, &rq_stats);
	if (ret) {
		unic_err(unic_dev, "failed to alloc txrx stats, ret = %d.\n", ret);
		goto out;
	}

	unic_backup_param_and_stats(unic_dev, &org_param, sq_stats, rq_stats);

	unic_info(unic_dev,
		  "changing tx/rx depth from %u/%u to %u/%u, changing rx buffer len from %u to %u.\n",
		  unic_dev->channels.sqebb_depth, unic_dev->channels.rqe_depth,
		  new_param.sqebb_depth, new_param.rqe_depth,
		  unic_dev->channels.rx_buff_len, new_param.rx_buff_len);

	ret = unic_modify_channels(unic_dev, new_param);
	if (ret) {
		unic_err(unic_dev,
			 "failed to modify channels, revert to old value, ret = %d.\n",
			 ret);
		ret1 = unic_modify_channels(unic_dev, org_param);
		if (ret1) {
			unic_err(unic_dev,
				 "failed to revert to old value, ret1 = %d.\n",
				 ret1);
			unic_free_txrx_stats(unic_dev, sq_stats, rq_stats);
			unic_clear_txrx_channels_state(unic_dev);
			return ret1;
		}
	}

	unic_restore_sqrq_stats(unic_dev, sq_stats, rq_stats);
	unic_free_txrx_stats(unic_dev, sq_stats, rq_stats);

out:
	unic_clear_txrx_channels_state(unic_dev);

	return ret;
}

void unic_get_channels_param(struct net_device *ndev,
			     struct ethtool_ringparam *param,
			     struct kernel_ethtool_ringparam *kernel_param,
			     struct netlink_ext_ack *extack)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_adev_caps *unic_caps = ubase_get_unic_caps(adev);

	param->tx_max_pending = unic_caps->jfs.depth;
	param->rx_max_pending = unic_caps->jfr.depth;

	param->tx_pending = unic_dev->channels.sqebb_depth;
	param->rx_pending = unic_dev->channels.rqe_depth;
	kernel_param->rx_buf_len = unic_dev->channels.rx_buff_len;
}
