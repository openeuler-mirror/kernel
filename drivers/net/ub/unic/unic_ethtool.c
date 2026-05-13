// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/phy.h>
#include <ub/ubase/ubase_comm_cmd.h>

#include "unic.h"
#include "unic_channel.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_lb.h"
#include "unic_netdev.h"
#include "unic_stats.h"
#include "unic_ethtool.h"

static u32 unic_get_link_status(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	unic_link_status_update(unic_dev);

	return unic_dev->sw_link_status;
}

static void unic_get_port_type(struct unic_dev *unic_dev,
			       struct ethtool_link_ksettings *cmd)
{
	u8 module_type = unic_dev->hw.mac.module_type;
	u8 media_type = unic_dev->hw.mac.media_type;

	switch (media_type) {
	case UNIC_MEDIA_TYPE_NONE:
	case UNIC_MEDIA_TYPE_BACKPLANE:
		cmd->base.port = PORT_NONE;
		break;
	case UNIC_MEDIA_TYPE_FIBER:
		if (module_type == UNIC_MODULE_TYPE_CR)
			cmd->base.port = PORT_DA;
		else
			cmd->base.port = PORT_FIBRE;
		break;
	default:
		cmd->base.port = PORT_NONE;
		break;
	}
}

static void unic_get_ksettings(struct unic_dev *unic_dev,
			       struct ethtool_link_ksettings *cmd)
{
	struct unic_mac *mac = &unic_dev->hw.mac;

	unic_get_port_type(unic_dev, cmd);

	cmd->base.speed = mac->speed;
	cmd->base.duplex = mac->duplex;
	cmd->base.autoneg = mac->autoneg;

	linkmode_copy(cmd->link_modes.supported, mac->supported);
	linkmode_copy(cmd->link_modes.advertising, mac->advertising);

	cmd->lanes = mac->lanes;
}

static int unic_get_link_ksettings(struct net_device *netdev,
				   struct ethtool_link_ksettings *cmd)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	/* Ensure that the latest information is obtained. */
	unic_update_port_info(unic_dev);

	unic_get_ksettings(unic_dev, cmd);

	if (!unic_get_link_status(netdev)) {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
	}

	return 0;
}

static bool unic_speed_supported(struct unic_dev *unic_dev, u32 speed, u32 lanes)
{
	u32 speed_bit = 0;

	if (unic_get_speed_bit(speed, lanes, &speed_bit))
		return false;

	return !!(speed_bit & unic_dev->hw.mac.speed_ability);
}

static int unic_check_ksettings_param(struct net_device *netdev,
				      const struct ethtool_link_ksettings *cmd)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_mac *mac = &unic_dev->hw.mac;
	u32 lanes;

	if (cmd->base.autoneg && !mac->support_autoneg) {
		unic_err(unic_dev, "hw not support autoneg.\n");
		return -EINVAL;
	}

	/* when autoneg is on, hw not support specified speed params,
	 * unnecessary to check them.
	 */
	if (cmd->base.autoneg)
		return 0;

	/* if user not specify lanes, use current lanes */
	lanes = cmd->lanes ? cmd->lanes : mac->lanes;
	if (!unic_speed_supported(unic_dev, cmd->base.speed, lanes)) {
		unic_err(unic_dev,
			 "speed(%uMbps) and lanes(%u) is not supported.\n",
			 cmd->base.speed, lanes);
		return -EINVAL;
	}

	if (cmd->base.duplex != DUPLEX_FULL) {
		unic_err(unic_dev, "only support full duplex.\n");
		return -EINVAL;
	}

	return 0;
}

static bool unic_link_ksettings_changed(struct unic_mac *mac,
					const struct ethtool_link_ksettings *cmd)
{
	/* when autoneg is disabled and lanes not specified, lanes is 0. */
	if (cmd->base.autoneg == mac->autoneg &&
	    cmd->base.duplex == mac->duplex &&
	    cmd->base.speed == mac->speed &&
	    (cmd->lanes == mac->lanes || (!cmd->lanes && !cmd->base.autoneg)))
		return false;

	return true;
}

static int unic_set_link_ksettings(struct net_device *netdev,
				   const struct ethtool_link_ksettings *cmd)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_mac *mac = &unic_dev->hw.mac;
	int ret;

	if (!unic_link_ksettings_changed(mac, cmd))
		return 0;

	ret = unic_check_ksettings_param(netdev, cmd);
	if (ret)
		return ret;

	unic_info(unic_dev,
		  "set link: autoneg = %u, speed = %uMbps, duplex = %u, lanes = %u.\n",
		  cmd->base.autoneg, cmd->base.speed,
		  cmd->base.duplex, cmd->lanes);

	return unic_set_mac_link_ksettings(unic_dev, cmd);
}

static void unic_get_driver_info(struct net_device *netdev,
				 struct ethtool_drvinfo *drvinfo)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct ubase_caps *caps = ubase_get_dev_caps(unic_dev->comdev.adev);
	u32 fw_version = 0;

	if (!caps)
		unic_err(unic_dev,
			 "failed to get fw version, use default value 0.\n");
	else
		fw_version = caps->fw_version;

	strscpy(drvinfo->version, UNIC_MOD_VERSION, sizeof(drvinfo->version));
	strscpy(drvinfo->driver, unic_dev->comdev.adev->name,
		sizeof(drvinfo->driver));
	strscpy(drvinfo->bus_info, dev_name(unic_dev->comdev.adev->dev.parent),
		sizeof(drvinfo->bus_info));

	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version), "%u.%u.%u.%u",
		 u32_get_bits(fw_version, UBASE_FW_VERSION_BYTE3_MASK),
		 u32_get_bits(fw_version, UBASE_FW_VERSION_BYTE2_MASK),
		 u32_get_bits(fw_version, UBASE_FW_VERSION_BYTE1_MASK),
		 u32_get_bits(fw_version, UBASE_FW_VERSION_BYTE0_MASK));
}

static void unic_update_pause_state(u8 pause_mode,
				    struct ethtool_pauseparam *eth_pauseparam)
{
	eth_pauseparam->rx_pause = UNIC_RX_TX_PAUSE_OFF;
	eth_pauseparam->tx_pause = UNIC_RX_TX_PAUSE_OFF;

	if (pause_mode & UNIC_TX_PAUSE_EN)
		eth_pauseparam->tx_pause = UNIC_RX_TX_PAUSE_ON;

	if (pause_mode & UNIC_RX_PAUSE_EN)
		eth_pauseparam->rx_pause = UNIC_RX_TX_PAUSE_ON;
}

static void unic_record_user_pauseparam(struct unic_dev *unic_dev,
					struct ethtool_pauseparam *eth_pauseparam)
{
	struct unic_pfc_info *pfc_info = &unic_dev->channels.vl.pfc_info;
	u32 rx_en = eth_pauseparam->rx_pause;
	u32 tx_en = eth_pauseparam->tx_pause;

	pfc_info->fc_mode = 0;

	if (tx_en)
		pfc_info->fc_mode = UNIC_TX_PAUSE_EN;

	if (rx_en)
		pfc_info->fc_mode |= UNIC_RX_PAUSE_EN;
}

static void unic_get_pauseparam(struct net_device *ndev,
				struct ethtool_pauseparam *eth_pauseparam)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (!unic_dev_pause_supported(unic_dev))
		return;

	eth_pauseparam->autoneg = unic_dev->hw.mac.autoneg;

	if (unic_dev->channels.vl.pfc_info.fc_mode & UNIC_FC_PFC_EN) {
		eth_pauseparam->rx_pause = UNIC_RX_TX_PAUSE_OFF;
		eth_pauseparam->tx_pause = UNIC_RX_TX_PAUSE_OFF;
		return;
	}

	unic_update_pause_state(unic_dev->channels.vl.pfc_info.fc_mode,
				eth_pauseparam);
}

static int unic_set_pauseparam(struct net_device *ndev,
			       struct ethtool_pauseparam *eth_pauseparam)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	int ret;

	if (!unic_dev_pause_supported(unic_dev))
		return -EOPNOTSUPP;

	if (unic_resetting(ndev))
		return -EBUSY;

	if (eth_pauseparam->autoneg && !unic_dev->hw.mac.support_autoneg) {
		unic_err(unic_dev,
			 "failed to set pause, autoneg not supported.\n");
		return -EOPNOTSUPP;
	}

	if (unic_dev->hw.mac.autoneg != eth_pauseparam->autoneg &&
	    unic_dev->hw.mac.support_autoneg) {
		unic_err(unic_dev,
			 "to change autoneg, please use: ethtool -s <dev> autoneg <on|off>\n");
		return -EOPNOTSUPP;
	}

	if (unic_dev->channels.vl.pfc_info.fc_mode & UNIC_FC_PFC_EN) {
		unic_err(unic_dev,
			 "failed to set pause, priority flow control enabled.\n");
		return -EOPNOTSUPP;
	}

	ret = unic_mac_pause_en_cfg(unic_dev, eth_pauseparam->tx_pause,
				    eth_pauseparam->rx_pause);
	if (ret)
		return ret;

	unic_record_user_pauseparam(unic_dev, eth_pauseparam);

	return ret;
}

static int unic_get_fecparam(struct net_device *ndev,
			     struct ethtool_fecparam *fec)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_mac *mac = &unic_dev->hw.mac;

	fec->fec = mac->fec_ability;
	fec->active_fec = mac->fec_mode;

	return 0;
}

static int unic_set_fecparam(struct net_device *ndev,
			     struct ethtool_fecparam *fec)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_mac *mac = &unic_dev->hw.mac;
	u32 fec_mode;
	int ret;

	if (!unic_dev_fec_supported(unic_dev))
		return -EOPNOTSUPP;

	fec_mode = fec->fec;
	if (!(mac->fec_ability & fec_mode)) {
		unic_err(unic_dev,
			 "unsupported fec mode, fec mode = %u.\n", fec_mode);
		return -EINVAL;
	}

	if (mac->fec_mode == fec_mode)
		return 0;

	if (netif_msg_ifdown(unic_dev))
		unic_info(unic_dev, "set fec mode = %u.\n", fec_mode);

	ret = unic_set_fec_mode(unic_dev, fec_mode);
	if (ret)
		return ret;

	return 0;
}

static int unic_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *cmd,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_coalesce *tx_coal = &unic_dev->channels.unic_coal.tx_coal;
	struct unic_coalesce *rx_coal = &unic_dev->channels.unic_coal.rx_coal;

	if (unic_resetting(netdev))
		return -EBUSY;

	cmd->tx_coalesce_usecs = tx_coal->int_gl;
	cmd->rx_coalesce_usecs = rx_coal->int_gl;

	cmd->tx_max_coalesced_frames = tx_coal->int_ql;
	cmd->rx_max_coalesced_frames = rx_coal->int_ql;

	return 0;
}

static int unic_check_gl_coalesce_para(struct net_device *netdev,
				       struct ethtool_coalesce *cmd)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u32 rx_gl, tx_gl;

	if (cmd->rx_coalesce_usecs > unic_dev->caps.max_int_gl) {
		unic_err(unic_dev,
			 "invalid rx-usecs value(%u), rx-usecs range is [0, %u].\n",
			 cmd->rx_coalesce_usecs, unic_dev->caps.max_int_gl);
		return -EINVAL;
	}

	if (cmd->tx_coalesce_usecs > unic_dev->caps.max_int_gl) {
		unic_err(unic_dev,
			 "invalid tx-usecs value(%u), tx-usecs range is [0, %u].\n",
			 cmd->tx_coalesce_usecs, unic_dev->caps.max_int_gl);
		return -EINVAL;
	}

	rx_gl = unic_cqe_period_round_down(cmd->rx_coalesce_usecs);
	if (rx_gl != cmd->rx_coalesce_usecs) {
		unic_err(unic_dev,
			 "invalid rx_usecs(%u), because it must be power of 4.\n",
			 cmd->rx_coalesce_usecs);
		return -EINVAL;
	}

	tx_gl = unic_cqe_period_round_down(cmd->tx_coalesce_usecs);
	if (tx_gl != cmd->tx_coalesce_usecs) {
		unic_err(unic_dev,
			 "invalid tx_usecs(%u), because it must be power of 4.\n",
			 cmd->tx_coalesce_usecs);
		return -EINVAL;
	}

	return 0;
}

static int unic_check_ql_coalesce_para(struct net_device *netdev,
				       struct ethtool_coalesce *cmd)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	if ((cmd->tx_max_coalesced_frames || cmd->rx_max_coalesced_frames) &&
	    !unic_dev->caps.max_int_ql) {
		unic_err(unic_dev, "coalesced frames is not supported.\n");
		return -EOPNOTSUPP;
	}

	if (cmd->tx_max_coalesced_frames > unic_dev->caps.max_int_ql ||
	    cmd->rx_max_coalesced_frames > unic_dev->caps.max_int_ql) {
		unic_err(unic_dev,
			 "invalid coalesced frames value(tx = %u, rx = %u), range is [0, %u].\n",
			 cmd->tx_max_coalesced_frames,
			 cmd->rx_max_coalesced_frames,
			 unic_dev->caps.max_int_ql);
		return -ERANGE;
	}

	return 0;
}

static int
unic_check_coalesce_para(struct net_device *netdev,
			 struct ethtool_coalesce *cmd,
			 struct kernel_ethtool_coalesce *kernel_coal)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	int ret;

	if (cmd->use_adaptive_rx_coalesce || cmd->use_adaptive_tx_coalesce) {
		unic_err(unic_dev,
			 "not support to enable adaptive coalesce.\n");
		return -EINVAL;
	}

	ret = unic_check_gl_coalesce_para(netdev, cmd);
	if (ret) {
		unic_err(unic_dev,
			 "failed to check gl coalesce param, ret = %d.\n", ret);
		return ret;
	}

	ret = unic_check_ql_coalesce_para(netdev, cmd);
	if (ret)
		unic_err(unic_dev,
			 "failed to check ql coalesce param, ret = %d.\n", ret);

	return ret;
}

static int unic_backup_stats(struct unic_dev *unic_dev,
			     struct unic_sq_stats **sq_stats,
			     struct unic_rq_stats **rq_stats)
{
	struct unic_sq_stats *tx_stats;
	struct unic_rq_stats *rx_stats;
	u32 i;

	if (!unic_dev->channels.c)
		return -EEXIST;

	tx_stats = kcalloc(unic_dev->channels.num, sizeof(*tx_stats),
			   GFP_KERNEL);
	if (!tx_stats)
		return -ENOMEM;

	rx_stats = kcalloc(unic_dev->channels.num, sizeof(*rx_stats),
			   GFP_KERNEL);
	if (!rx_stats) {
		kfree(tx_stats);
		return -ENOMEM;
	}

	for (i = 0; i < unic_dev->channels.num; i++) {
		memcpy(&tx_stats[i], &unic_dev->channels.c[i].sq->stats,
		       sizeof(struct unic_sq_stats));
		memcpy(&rx_stats[i], &unic_dev->channels.c[i].rq->stats,
		       sizeof(struct unic_rq_stats));
	}

	*sq_stats = tx_stats;
	*rq_stats = rx_stats;

	return 0;
}

static void unic_restore_stats(struct unic_dev *unic_dev,
			       struct unic_sq_stats *sq_stats,
			       struct unic_rq_stats *rq_stats)
{
	u32 i;

	for (i = 0; i < unic_dev->channels.num; i++) {
		memcpy(&unic_dev->channels.c[i].rq->stats, &rq_stats[i],
		       sizeof(struct unic_rq_stats));
		memcpy(&unic_dev->channels.c[i].sq->stats, &sq_stats[i],
		       sizeof(struct unic_sq_stats));
	}
}

static int unic_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *cmd,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_coal_txrx *unic_coal = &unic_dev->channels.unic_coal;
	struct unic_coalesce *tx_coal = &unic_coal->tx_coal;
	struct unic_coalesce *rx_coal = &unic_coal->rx_coal;
	struct unic_coalesce old_tx_coal, old_rx_coal;
	struct unic_sq_stats *sq_stats;
	struct unic_rq_stats *rq_stats;
	int ret, ret1;

	if (netif_running(netdev)) {
		unic_err(unic_dev,
			 "failed to set coalesce param, due to network interface is up, please down it first and try again.\n");
		return -EBUSY;
	}

	if (unic_resetting(netdev))
		return -EBUSY;

	ret = unic_check_coalesce_para(netdev, cmd, kernel_coal);
	if (ret)
		return ret;

	ret = unic_backup_stats(unic_dev, &sq_stats, &rq_stats);
	if (ret) {
		unic_err(unic_dev, "failed to backup txrx stats, ret = %d.\n",
			 ret);
		return ret;
	}

	memcpy(&old_tx_coal, tx_coal, sizeof(struct unic_coalesce));
	memcpy(&old_rx_coal, rx_coal, sizeof(struct unic_coalesce));

	tx_coal->int_gl = cmd->tx_coalesce_usecs;
	rx_coal->int_gl = cmd->rx_coalesce_usecs;

	tx_coal->int_ql = cmd->tx_max_coalesced_frames;
	rx_coal->int_ql = cmd->rx_max_coalesced_frames;

	unic_uninit_channels(unic_dev);

	ret = unic_init_channels(unic_dev, unic_dev->channels.num);
	if (ret) {
		netdev_err(netdev, "failed to init channels, ret = %d.\n", ret);
		memcpy(tx_coal, &old_tx_coal, sizeof(struct unic_coalesce));
		memcpy(rx_coal, &old_rx_coal, sizeof(struct unic_coalesce));
		ret1 = unic_init_channels(unic_dev, unic_dev->channels.num);
		if (ret1) {
			unic_err(unic_dev,
				 "failed to recover old channels, ret = %d.\n",
				 ret1);
			goto err_recover_channels;
		}
	}

	unic_restore_stats(unic_dev, sq_stats, rq_stats);

err_recover_channels:
	kfree(sq_stats);
	kfree(rq_stats);

	return ret;
}

static const struct unic_reset_type_map unic_ethtool_reset_map[] = {
	{ETH_RESET_DEDICATED, UBASE_UE_RESET},
};

static int unic_reset(struct net_device *ndev, u32 *flags)
{
	enum ubase_reset_type reset_type = UBASE_NO_RESET;
	struct unic_dev *unic_dev = netdev_priv(ndev);
	enum ethtool_reset_flags reset_flags;
	u32 i;

	if (unic_resetting(ndev)) {
		unic_err(unic_dev, "failed to reset, due to dev resetting.\n");
		return -EBUSY;
	}

	for (i = 0; i < ARRAY_SIZE(unic_ethtool_reset_map); i++) {
		if (unic_ethtool_reset_map[i].reset_flags == *flags) {
			reset_type = unic_ethtool_reset_map[i].reset_type;
			reset_flags = unic_ethtool_reset_map[i].reset_flags;
			break;
		}
	}

	if (reset_type == UBASE_NO_RESET)
		return -EOPNOTSUPP;

	unic_info(unic_dev,
		  "ethtool setting reset type, type = %u.\n", reset_type);

	ubase_reset_event(unic_dev->comdev.adev, reset_type);
	*flags &= ~reset_flags;

	return 0;
}

struct unic_ethtool_link_ext_state_mapping {
	u32 status_code;
	enum ethtool_link_ext_state link_ext_state;
	u8 link_ext_substate;
};

static const struct unic_ethtool_link_ext_state_mapping
unic_link_ext_state_map[] = {
	{516, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK},
	{768, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS},
	{770, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS},
	{1024, ETHTOOL_LINK_EXT_STATE_NO_CABLE, 0},
};

static int unic_get_link_ext_state(struct net_device *netdev,
				   struct ethtool_link_ext_state_info *info)
{
	const struct unic_ethtool_link_ext_state_mapping *map;
	struct unic_query_link_diagnosis_resp resp = {0};
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct ubase_cmd_buf in, out;
	u32 status_code;
	int ret;
	u8 i;

	if (netif_carrier_ok(netdev))
		return -ENODATA;

	if (unic_dev_ubl_supported(unic_dev))
		return -EOPNOTSUPP;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_LINK_DIAGNOSIS, true, 0, NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_LINK_DIAGNOSIS, false,
			     sizeof(resp), &resp);

	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		unic_err(unic_dev, "failed to query link diagnosis, ret = %d.\n",
			 ret);
		return ret;
	}

	status_code = le32_to_cpu(resp.status_code);
	if (!status_code)
		return -ENODATA;

	for (i = 0; i < ARRAY_SIZE(unic_link_ext_state_map); i++) {
		map = &unic_link_ext_state_map[i];
		if (map->status_code == status_code) {
			info->link_ext_state = map->link_ext_state;
			info->__link_ext_substate = map->link_ext_substate;
			return 0;
		}
	}

	unic_warn(unic_dev, "unknown link failure status_code = %u.\n",
		  status_code);

	return -ENODATA;
}

#define UNIC_ETHTOOL_RING	(ETHTOOL_RING_USE_RX_BUF_LEN | \
				 ETHTOOL_RING_USE_TX_PUSH)
#define UNIC_ETHTOOL_COALESCE	(ETHTOOL_COALESCE_USECS | \
				 ETHTOOL_COALESCE_USE_ADAPTIVE | \
				 ETHTOOL_COALESCE_MAX_FRAMES)

static const struct ethtool_ops unic_ethtool_ops = {
	.supported_ring_params = UNIC_ETHTOOL_RING,
	.cap_link_lanes_supported = true,
	.supported_coalesce_params = UNIC_ETHTOOL_COALESCE,
	.get_link = unic_get_link_status,
	.get_link_ksettings = unic_get_link_ksettings,
	.set_link_ksettings = unic_set_link_ksettings,
	.get_drvinfo = unic_get_driver_info,
	.get_pauseparam = unic_get_pauseparam,
	.set_pauseparam = unic_set_pauseparam,
	.get_regs_len = unic_get_regs_len,
	.get_regs = unic_get_regs,
	.get_ethtool_stats = unic_get_stats,
	.get_strings = unic_get_stats_strings,
	.get_sset_count = unic_get_sset_count,
	.get_channels = unic_get_channels,
	.set_channels = unic_set_channels,
	.get_ringparam = unic_get_channels_param,
	.set_ringparam = unic_set_channels_param,
	.self_test = unic_self_test,
	.get_fecparam = unic_get_fecparam,
	.set_fecparam = unic_set_fecparam,
	.get_fec_stats = unic_get_fec_stats,
	.get_coalesce = unic_get_coalesce,
	.set_coalesce = unic_set_coalesce,
	.reset = unic_reset,
	.get_link_ext_state = unic_get_link_ext_state,
};

void unic_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &unic_ethtool_ops;
}
