/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool.c
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
#include <linux/vmalloc.h>

#include "drv_nic_api.h"
#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_rss.h"
#include "hinic5_ethtool_coalesce.h"
#include "hinic5_ethtool_lb_test.h"
#include "hinic5_ethtool_priv_flags.h"
#include "hinic5_ethtool.h"

static void hinic5_get_drvinfo(struct net_device *netdev,
			       struct ethtool_drvinfo *info)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 mgmt_ver[HINIC5_MGMT_VERSION_MAX_LEN] = {0};
	int err;

	strscpy(info->driver, HINIC5_NIC_DRV_NAME, sizeof(info->driver));
	strscpy(info->version, HINIC5_NIC_DRV_VERSION, sizeof(info->version));
	strscpy(info->bus_info, dev_name(nic_dev->lld_dev->dev), sizeof(info->bus_info));

	err = hinic5_get_mgmt_version(nic_dev->hwdev, mgmt_ver,
				      HINIC5_MGMT_VERSION_MAX_LEN,
				      HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to get fw version\n");
		return;
	}

	err = snprintf(info->fw_version, sizeof(info->fw_version), "%s", mgmt_ver);
	if (err < 0)
		nicif_err(nic_dev, drv, netdev, "Failed to snprintf_s fw version\n");
}

static u32 hinic5_get_msglevel(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	return nic_dev->msg_enable;
}

static void hinic5_set_msglevel(struct net_device *netdev, u32 data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	nic_dev->msg_enable = data;

	nicif_info(nic_dev, drv, netdev, "Set message level: 0x%x\n", data);
}

static int hinic5_nway_reset(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct mag_port_info port_info = {0};
	int err;

	while (test_and_set_bit(HINIC5_AUTONEG_RESET, &nic_dev->flags))
		msleep(100); /* sleep 100 ms, waiting for another autoneg restart progress done */

	err = hinic5_get_port_info(nic_dev->hwdev, &port_info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Get port info failed\n");
		err = -EFAULT;
		goto reset_err;
	}

	if (port_info.autoneg_state != PORT_CFG_AN_ON) {
		nicif_err(nic_dev, drv, netdev, "Autonegotiation is not on, don't support to restart it\n");
		err = -EOPNOTSUPP;
		goto reset_err;
	}

	err = hinic5_set_autoneg(nic_dev->hwdev, false);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Set autonegotiation off failed\n");
		err = -EFAULT;
		goto reset_err;
	}

	msleep(200); /* sleep 200 ms, waiting for status polling finished */

	err = hinic5_set_autoneg(nic_dev->hwdev, true);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Set autonegotiation on failed\n");
		err = -EFAULT;
		goto reset_err;
	}

	msleep(200); /* sleep 200 ms, waiting for status polling finished */
	nicif_info(nic_dev, drv, netdev, "Restart autonegotiation successfully\n");

reset_err:
	clear_bit(HINIC5_AUTONEG_RESET, &nic_dev->flags);
	return err;
}

#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static void hinic5_get_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ring,
				 struct kernel_ethtool_ringparam *kernel_ring,
				 struct netlink_ext_ack *extack)
#else
static void hinic5_get_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ring)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	ring->rx_max_pending = HINIC5_MAX_RX_QUEUE_DEPTH;
	ring->tx_max_pending = HINIC5_MAX_TX_QUEUE_DEPTH;
	ring->rx_pending = nic_dev->rxqs[0].q_depth;
	ring->tx_pending = nic_dev->txqs[0].q_depth;
}

static void hinic5_update_qp_depth(struct hinic5_nic_dev *nic_dev,
				   u32 sq_depth, u32 rq_depth)
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

static int check_ringparam_valid(struct net_device *netdev,
				 const struct ethtool_ringparam *ring)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	if (ring->rx_jumbo_pending != 0 || ring->rx_mini_pending != 0) {
		nicif_err(nic_dev, drv, netdev,
			  "Unsupported rx_jumbo_pending/rx_mini_pending\n");
		return -EINVAL;
	}

	if (ring->tx_pending > HINIC5_MAX_TX_QUEUE_DEPTH ||
	    ring->tx_pending < HINIC5_MIN_QUEUE_DEPTH ||
	    ring->rx_pending > HINIC5_MAX_RX_QUEUE_DEPTH ||
	    ring->rx_pending < HINIC5_MIN_QUEUE_DEPTH) {
		nicif_err(nic_dev, drv, netdev,
			  "Queue depth out of rang tx[%d-%d] rx[%d-%d]\n",
			  HINIC5_MIN_QUEUE_DEPTH, HINIC5_MAX_TX_QUEUE_DEPTH,
			  HINIC5_MIN_QUEUE_DEPTH, HINIC5_MAX_RX_QUEUE_DEPTH);
		return -EINVAL;
	}

	return 0;
}

__weak int hinic5_set_ringparam_pre_hook(struct net_device *netdev,
					 struct ethtool_ringparam *ring)
{
	return 0;
}

#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static int hinic5_set_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *ring,
				struct kernel_ethtool_ringparam *kernel_ring,
				struct netlink_ext_ack *extack)
#else
static int hinic5_set_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *ring)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct hinic5_dyna_txrxq_params q_params = {0};
	u32 new_sq_depth, new_rq_depth;
	int err;

	if (nic_dev->flow_bifur_group_num > HINIC5_GROUP_NUMBER_MIN) {
		nicif_err(nic_dev, drv, netdev, "Cannot be modified after queue groups are configured.\n");
		return -EOPNOTSUPP;
	}

	err = hinic5_set_ringparam_pre_hook(netdev, ring);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Skip ringparam config\n");
		return err;
	}

	err = check_ringparam_valid(netdev, ring);
	if (err != 0)
		return err;

	new_sq_depth = (u32)(1U << (u16)ilog2(ring->tx_pending));
	new_rq_depth = (u32)(1U << (u16)ilog2(ring->rx_pending));
	if (new_sq_depth == nic_dev->q_params.sq_depth &&
	    new_rq_depth == nic_dev->q_params.rq_depth)
		return 0; /* nothing to do */

	nicif_info(nic_dev, drv, netdev,
		   "Change Tx/Rx ring depth from %u/%u to %u/%u\n",
		   nic_dev->q_params.sq_depth, nic_dev->q_params.rq_depth,
		   new_sq_depth, new_rq_depth);

	if (!netif_running(netdev)) {
		hinic5_update_qp_depth(nic_dev, new_sq_depth, new_rq_depth);
	} else {
		q_params = nic_dev->q_params;
		q_params.sq_depth = new_sq_depth;
		q_params.rq_depth = new_rq_depth;
		q_params.txqs_res = NULL;
		q_params.rxqs_res = NULL;
		q_params.irq_cfg = NULL;

#ifdef HAVE_XDP_SUPPORT
		err = hinic5_set_xdp_num(nic_dev, &q_params);
		if (err != 0)
			return err;
#endif

		nicif_info(nic_dev, drv, netdev, "Restarting channel\n");
		err = hinic5_change_channel_settings(nic_dev, &q_params,
						     NULL, NULL);
		if (err != 0) {
			nicif_err(nic_dev, drv, netdev, "Failed to change channel settings\n");
			return -EFAULT;
		}
	}

	return 0;
}

#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
static int hinic5_get_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *coal,
			       struct kernel_ethtool_coalesce *kernel_coal,
			       struct netlink_ext_ack *extack)
#else
static int hinic5_get_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *coal)
#endif
{
	return get_coalesce(netdev, coal, COALESCE_ALL_QUEUE);
}

#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
static int hinic5_set_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *coal,
			       struct kernel_ethtool_coalesce *kernel_coal,
			       struct netlink_ext_ack *extack)
#else
static int hinic5_set_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *coal)
#endif
{
	return set_coalesce(netdev, coal, COALESCE_ALL_QUEUE);
}

#if defined(ETHTOOL_PERQUEUE) && defined(ETHTOOL_GCOALESCE)
static int hinic5_get_per_queue_coalesce(struct net_device *netdev, u32 queue,
					 struct ethtool_coalesce *coal)
{
	return get_coalesce(netdev, coal, (u16)queue);
}

static int hinic5_set_per_queue_coalesce(struct net_device *netdev, u32 queue,
					 struct ethtool_coalesce *coal)
{
	return set_coalesce(netdev, coal, (u16)queue);
}
#endif

#ifdef HAVE_ETHTOOL_SET_PHYS_ID
static int hinic5_set_phys_id(struct net_device *netdev,
			      enum ethtool_phys_id_state state)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	int err;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		err = hinic5_set_led_status(nic_dev->hwdev,
					    MAG_CMD_LED_TYPE_ALARM,
					    MAG_CMD_LED_MODE_FORCE_BLINK_2HZ);
		if (err != 0)
			nicif_err(nic_dev, drv, netdev,
				  "Set LED blinking in 2HZ failed\n");
		else
			nicif_info(nic_dev, drv, netdev,
				   "Set LED blinking in 2HZ success\n");
		break;

	case ETHTOOL_ID_INACTIVE:
		err = hinic5_set_led_status(nic_dev->hwdev,
					    MAG_CMD_LED_TYPE_ALARM,
					    MAG_CMD_LED_MODE_DEFAULT);
		if (err != 0)
			nicif_err(nic_dev, drv, netdev,
				  "Reset LED to original status failed\n");
		else
			nicif_info(nic_dev, drv, netdev,
				   "Reset LED to original status success\n");
		break;

	default:
		return -EOPNOTSUPP;
	}

	return err;
}
#else
static int hinic5_phys_id(struct net_device *netdev, u32 data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	nicif_err(nic_dev, drv, netdev, "Not support to set phys id\n");

	return -EOPNOTSUPP;
}
#endif

static void hinic5_get_pauseparam(struct net_device *netdev,
				  struct ethtool_pauseparam *pause)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct nic_pause_config nic_pause = {0};
	int err;

	err = hinic5_get_pause_info(nic_dev->hwdev, &nic_pause);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev,
			  "Failed to get pauseparam from hw\n");
	} else {
		/* For compatibility with 23v200,
		 * the retrieved auto_neg is port rate autonegotiation (may be on),
		 * but the actual auto_neg that should be retrieved is pause frame autonegotiation (off),
		 * so it is directly set to off on the driver side
		 */
		pause->autoneg = AUTONEG_DISABLE;
		pause->rx_pause = nic_pause.rx_pause;
		pause->tx_pause = nic_pause.tx_pause;
	}
}

static int hinic5_set_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pause)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct nic_pause_config nic_pause = {0};
	struct mag_port_info port_info = {0};
	int err;

	if (pause->autoneg != AUTONEG_DISABLE) {
		nicif_warn(nic_dev, drv, netdev,
			   "The current version does not support enabling pause frame auto-negotiation.\n");
	}

	err = hinic5_get_port_info(nic_dev->hwdev, &port_info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to get auto-negotiation state\n");
		return -EFAULT;
	}

	/* For compatibility with old version, configure according to port rate autonegotiation state */
	nic_pause.auto_neg = port_info.autoneg_state;
	nic_pause.rx_pause = (u8)pause->rx_pause;
	nic_pause.tx_pause = (u8)pause->tx_pause;

	err = hinic5_set_pause_info(nic_dev->hwdev, nic_pause);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to set pauseparam\n");
		return err;
	}

	nicif_info(nic_dev, drv, netdev, "Set pause options, autoneg: %s, tx: %s, rx: %s\n",
		   "off", (pause->tx_pause != 0) ? "on" : "off",
		   (pause->rx_pause != 0) ? "on" : "off");

	return 0;
}

#ifdef ETHTOOL_GMODULEEEPROM
static int hinic5_get_module_info(struct net_device *netdev,
				  struct ethtool_modinfo *modinfo)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 sfp_type = 0;
	u8 sfp_type_ext = 0;
	int err;

	err = hinic5_get_sfp_cmis_type(nic_dev->hwdev, &sfp_type, &sfp_type_ext);
	if (err != 0)
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
	case MODULE_TYPE_SFF8024_ID_QSFP_PLUS_CMIS:
		modinfo->type = ETH_MODULE_SFF_8636;
		modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		break;
	case MODULE_TYPE_SFF8024_ID_DSFP:
		modinfo->type = ETH_MODULE_SFF_8636;
		modinfo->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		break;
	default:
		nicif_warn(nic_dev, drv, netdev,
			   "Optical module unknown: 0x%x\n", sfp_type);
		return -EINVAL;
	}

	return 0;
}

static int hinic5_get_module_eeprom(struct net_device *netdev,
				    struct ethtool_eeprom *ee, u8 *data)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u8 sfp_data[STD_SFP_INFO_MAX_SIZE];
	int err;

	if (ee->len == 0 ||
	    ((ee->len + ee->offset) > STD_SFP_INFO_MAX_SIZE) || ee->len > PAGE_SIZE)
		return -EINVAL;

	memset(data, 0, ee->len);

	err = hinic5_get_sfp_eeprom(nic_dev->hwdev, (u8 *)sfp_data, ee->len, ee->offset);
	if (err != 0)
		return err;

	memcpy(data, sfp_data, ee->len);

	return err == 0 ? 0 : -ENOMEM;
}
#endif /* ETHTOOL_GMODULEEEPROM */

#ifdef HAVE_ETHTOOL_GET_MODULE_EEPROM_BY_PAGE
static int hinic5_get_module_eeprom_by_page(struct net_device *dev,
					    const struct ethtool_module_eeprom *page_data,
					    struct netlink_ext_ack *extack)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(dev);
	u8 page_id;
	u8 i2c_address;
	u32 offset;
	u32 len;
	int ret;

	if (!page_data || !page_data->data)
		return -EINVAL;

	page_id = page_data->page;
	offset = page_data->offset;
	len = page_data->length;
	i2c_address = page_data->i2c_address;

	if (i2c_address == SFF8079_I2C_ADDRESS_HIGH)
		page_id = HINIC5_ETHTOOL_PAGE_A2H;
	memset(page_data->data, 0, len);

	ret = hinic5_eeprom_page_check(page_id, offset, len);
	if (ret != 0)
		return ret;

	ret = hinic5_get_cmis_eeprom_by_page(nic_dev->hwdev, page_id, offset, page_data->data, len);
	if (ret != 0)
		return ret;
	return len;
}
#endif /* HAVE_ETHTOOL_GET_MODULE_EEPROM_BY_PAGE */

#ifdef HAVE_DEVLINK_PARAM_SET_EXTACK
static int hinic5_get_ts_info(struct net_device *netdev, struct kernel_ethtool_ts_info *info)
#else
static int hinic5_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *info)
#endif
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);

	/* only report HW timestamping if PTP is enabled */
	if (test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0) {
		info->so_timestamping = 0;
		info->phc_index = -1;
		return 0;
	}

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	if (nic_dev->ptp_ctrl.ptp_clock)
		info->phc_index = ptp_clock_index(nic_dev->ptp_ctrl.ptp_clock);
	else
		info->phc_index = -1;

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) | BIT(HWTSTAMP_FILTER_PTP_V2_EVENT);

	return 0;
}

static const struct ethtool_ops hinic5_ethtool_ops = {
#ifdef SUPPORTED_COALESCE_PARAMS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				    ETHTOOL_COALESCE_PKT_RATE_RX_USECS |
				    ETHTOOL_COALESCE_MAX_FRAMES |
				    ETHTOOL_COALESCE_USECS_LOW_HIGH |
				    ETHTOOL_COALESCE_MAX_FRAMES_LOW_HIGH,
#endif
#ifdef ETHTOOL_GLINKSETTINGS
#ifndef XENSERVER_HAVE_NEW_ETHTOOL_OPS
	.get_link_ksettings = hinic5_get_link_ksettings,
	.set_link_ksettings = hinic5_set_link_ksettings,
#endif
#endif
#ifndef HAVE_NEW_ETHTOOL_LINK_SETTINGS_ONLY
	.get_settings = hinic5_get_settings,
	.set_settings = hinic5_set_settings,
#endif

	.get_drvinfo = hinic5_get_drvinfo,
	.get_msglevel = hinic5_get_msglevel,
	.set_msglevel = hinic5_set_msglevel,
	.nway_reset = hinic5_nway_reset,
	.get_link = ethtool_op_get_link,
	.get_ringparam = hinic5_get_ringparam,
	.set_ringparam = hinic5_set_ringparam,
	.get_pauseparam = hinic5_get_pauseparam,
	.set_pauseparam = hinic5_set_pauseparam,
	.get_sset_count = hinic5_get_sset_count,
	.get_ethtool_stats = hinic5_get_ethtool_stats,
	.get_strings = hinic5_get_strings,

	.self_test = hinic5_diag_test,

#ifndef HAVE_ETHTOOL_OPS_EXT
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
	.set_phys_id = hinic5_set_phys_id,
#else
	.phys_id = hinic5_phys_id,
#endif
#endif

	.get_coalesce = hinic5_get_coalesce,
	.set_coalesce = hinic5_set_coalesce,
#if defined(ETHTOOL_PERQUEUE) && defined(ETHTOOL_GCOALESCE)
	.get_per_queue_coalesce = hinic5_get_per_queue_coalesce,
	.set_per_queue_coalesce = hinic5_set_per_queue_coalesce,
#endif

#if defined(ETHTOOL_GFECPARAM) && defined(ETHTOOL_SFECPARAM)
	.get_fecparam = hinic5_get_fecparam,
	.set_fecparam = hinic5_set_fecparam,
#endif

	.get_rxnfc = hinic5_get_rxnfc,
	.set_rxnfc = hinic5_set_rxnfc,
	.get_priv_flags = hinic5_get_priv_flags,
	.set_priv_flags = hinic5_set_priv_flags,
	.get_ts_info = hinic5_get_ts_info,

#ifndef HAVE_ETHTOOL_OPS_EXT
	.get_channels = hinic5_get_channels,
	.set_channels = hinic5_set_channels,

#ifdef ETHTOOL_GMODULEEEPROM
	.get_module_info = hinic5_get_module_info,
	.get_module_eeprom = hinic5_get_module_eeprom,
#endif
#ifdef HAVE_ETHTOOL_GET_MODULE_EEPROM_BY_PAGE
	.get_module_eeprom_by_page = hinic5_get_module_eeprom_by_page,
#endif

#ifdef HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE
	.get_rxfh_indir_size = hinic5_get_rxfh_indir_size,
#endif

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = hinic5_get_rxfh_key_size,
	.get_rxfh = hinic5_get_rxfh,
	.set_rxfh = hinic5_set_rxfh,
#else
	.get_rxfh_indir = hinic5_get_rxfh_indir,
	.set_rxfh_indir = hinic5_set_rxfh_indir,
#endif

#endif /* HAVE_ETHTOOL_OPS_EXT */
};

#ifdef HAVE_ETHTOOL_OPS_EXT
static const struct ethtool_ops_ext hinic5_ethtool_ops_ext = {
	.size	= sizeof(struct ethtool_ops_ext),
	.set_phys_id = hinic5_set_phys_id,
	.get_channels = hinic5_get_channels,
	.set_channels = hinic5_set_channels,
#ifdef ETHTOOL_GMODULEEEPROM
	.get_module_info = hinic5_get_module_info,
	.get_module_eeprom = hinic5_get_module_eeprom,
#endif
#ifdef HAVE_ETHTOOL_GET_MODULE_EEPROM_BY_PAGE
	.get_module_eeprom_by_page = hinic5_get_module_eeprom_by_page,
#endif

#ifdef HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE
	.get_rxfh_indir_size = hinic5_get_rxfh_indir_size,
#endif

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = hinic5_get_rxfh_key_size,
	.get_rxfh = hinic5_get_rxfh,
	.set_rxfh = hinic5_set_rxfh,
#else
	.get_rxfh_indir = hinic5_get_rxfh_indir,
	.set_rxfh_indir = hinic5_set_rxfh_indir,
#endif

};
#endif /* HAVE_ETHTOOL_OPS_EXT */

static const struct ethtool_ops hinic5vf_ethtool_ops = {
#ifdef SUPPORTED_COALESCE_PARAMS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_PKT_RATE_RX_USECS |
				     ETHTOOL_COALESCE_MAX_FRAMES |
				     ETHTOOL_COALESCE_USECS_LOW_HIGH |
				     ETHTOOL_COALESCE_MAX_FRAMES_LOW_HIGH,
#endif
#ifdef ETHTOOL_GLINKSETTINGS
#ifndef XENSERVER_HAVE_NEW_ETHTOOL_OPS
	.get_link_ksettings = hinic5_get_link_ksettings,
#endif
#else
	.get_settings = hinic5_get_settings,
#endif
	.get_drvinfo = hinic5_get_drvinfo,
	.get_msglevel = hinic5_get_msglevel,
	.set_msglevel = hinic5_set_msglevel,
	.get_link = ethtool_op_get_link,
	.get_ringparam = hinic5_get_ringparam,

	.set_ringparam = hinic5_set_ringparam,
	.get_sset_count = hinic5_get_sset_count,
	.get_ethtool_stats = hinic5_get_ethtool_stats,
	.get_strings = hinic5_get_strings,

	.get_coalesce = hinic5_get_coalesce,
	.set_coalesce = hinic5_set_coalesce,
#if defined(ETHTOOL_PERQUEUE) && defined(ETHTOOL_GCOALESCE)
	.get_per_queue_coalesce = hinic5_get_per_queue_coalesce,
	.set_per_queue_coalesce = hinic5_set_per_queue_coalesce,
#endif

#if defined(ETHTOOL_GFECPARAM) && defined(ETHTOOL_SFECPARAM)
	.get_fecparam = hinic5_get_fecparam,
	.set_fecparam = hinic5_set_fecparam,
#endif

	.get_rxnfc = hinic5_get_rxnfc,
	.set_rxnfc = hinic5_set_rxnfc,
	.get_priv_flags = hinic5_get_priv_flags,
	.set_priv_flags = hinic5_set_priv_flags,

#ifndef HAVE_ETHTOOL_OPS_EXT
	.get_channels = hinic5_get_channels,
	.set_channels = hinic5_set_channels,

#ifdef HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE
	.get_rxfh_indir_size = hinic5_get_rxfh_indir_size,
#endif

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = hinic5_get_rxfh_key_size,
	.get_rxfh = hinic5_get_rxfh,
	.set_rxfh = hinic5_set_rxfh,
#else
	.get_rxfh_indir = hinic5_get_rxfh_indir,
	.set_rxfh_indir = hinic5_set_rxfh_indir,
#endif

#endif /* HAVE_ETHTOOL_OPS_EXT */
};

#ifdef HAVE_ETHTOOL_OPS_EXT
static const struct ethtool_ops_ext hinic5vf_ethtool_ops_ext = {
	.size	= sizeof(struct ethtool_ops_ext),
	.get_channels = hinic5_get_channels,
	.set_channels = hinic5_set_channels,

#ifdef HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE
	.get_rxfh_indir_size = hinic5_get_rxfh_indir_size,
#endif

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size = hinic5_get_rxfh_key_size,
	.get_rxfh = hinic5_get_rxfh,
	.set_rxfh = hinic5_set_rxfh,
#else
	.get_rxfh_indir = hinic5_get_rxfh_indir,
	.set_rxfh_indir = hinic5_set_rxfh_indir,
#endif

};
#endif /* HAVE_ETHTOOL_OPS_EXT */

void hinic5_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &hinic5_ethtool_ops);
#ifdef HAVE_ETHTOOL_OPS_EXT
	set_ethtool_ops_ext(netdev, &hinic5_ethtool_ops_ext);
#endif /* HAVE_ETHTOOL_OPS_EXT */
}

void hinic5vf_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &hinic5vf_ethtool_ops);
#ifdef HAVE_ETHTOOL_OPS_EXT
	set_ethtool_ops_ext(netdev, &hinic5vf_ethtool_ops_ext);
#endif /* HAVE_ETHTOOL_OPS_EXT */
}
