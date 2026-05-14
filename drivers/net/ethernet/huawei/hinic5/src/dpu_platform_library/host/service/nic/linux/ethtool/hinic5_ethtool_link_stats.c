/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_link_stats.c
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
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_crm.h"
#include "hinic5_mt.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_nic_dev.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_ethtool_link_stats.h"

#define HINIC_ETHTOOL_FEC_INFO_LEN      6
#define HINIC_SUPPORTED_FEC_CMD         0
#define HINIC_ADVERTISED_FEC_CMD        1

struct hinic5_ethtool_fec {
	u8 hinic_fec_offset;
	u8 ethtool_bit_offset;
};

static struct hinic5_ethtool_fec hinic5_ethtool_fec_info[HINIC_ETHTOOL_FEC_INFO_LEN] = {
	{PORT_FEC_NOT_SET,  0xFF},  /* The ethtool does not have the
				     * corresponding enumeration variable
				     */
	{PORT_FEC_RSFEC,    0x32},  /* ETHTOOL_LINK_MODE_FEC_RS_BIT */
	{PORT_FEC_BASEFEC,  0x33},  /* ETHTOOL_LINK_MODE_FEC_BASER_BIT */
	{PORT_FEC_NOFEC,    0x31},  /* ETHTOOL_LINK_MODE_FEC_NONE_BIT */
	{PORT_FEC_LLRSFEC,  0x4A},  /* ETHTOOL_LINK_MODE_FEC_LLRS_BIT:
				     * Available only in later versions
				     */
	{PORT_FEC_AUTO,     0XFF}   /* The ethtool does not have the
				     * corresponding enumeration variable
				     */
};

static const u32 hinic5_mag_link_mode_ge[] = {
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT,
};

static const u32 hinic5_mag_link_mode_10ge_base_r[] = {
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT,
};

static const u32 hinic5_mag_link_mode_25ge_base_r[] = {
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,
};

static const u32 hinic5_mag_link_mode_40ge_base_r4[] = {
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,
};

static const u32 hinic5_mag_link_mode_50ge_base_r[] = {
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,
};

static const u32 hinic5_mag_link_mode_50ge_base_r2[] = {
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,
};

static const u32 hinic5_mag_link_mode_100ge_base_r[] = {
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT,
};

static const u32 hinic5_mag_link_mode_100ge_base_r2[] = {
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,
};

static const u32 hinic5_mag_link_mode_100ge_base_r4[] = {
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,
};

static const u32 hinic5_mag_link_mode_200ge_base_r2[] = {
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT,
};

static const u32 hinic5_mag_link_mode_200ge_base_r4[] = {
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,
};

static const u32 hinic5_mag_link_mode_400ge_base_r4[] = {
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT,
};

static const u32 hinic5_mag_link_mode_800ge_base_r8[] = {
	ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT,
	ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT,
	ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT,
};

static const struct hw2ethtool_link_mode
	hw2ethtool_link_mode_table[LINK_MODE_MAX_NUMBERS] = {
	[LINK_MODE_GE] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_ge,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_ge),
		.speed = SPEED_1000,
	},
	[LINK_MODE_10GE_BASE_R] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_10ge_base_r,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_10ge_base_r),
		.speed = SPEED_10000,
	},
	[LINK_MODE_25GE_BASE_R] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_25ge_base_r,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_25ge_base_r),
		.speed = SPEED_25000,
	},
	[LINK_MODE_40GE_BASE_R4] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_40ge_base_r4,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_40ge_base_r4),
		.speed = SPEED_40000,
	},
	[LINK_MODE_50GE_BASE_R] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_50ge_base_r,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_50ge_base_r),
		.speed = SPEED_50000,
	},
	[LINK_MODE_50GE_BASE_R2] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_50ge_base_r2,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_50ge_base_r2),
		.speed = SPEED_50000,
	},
	[LINK_MODE_100GE_BASE_R] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_100ge_base_r,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_100ge_base_r),
		.speed = SPEED_100000,
	},
	[LINK_MODE_100GE_BASE_R2] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_100ge_base_r2,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_100ge_base_r2),
		.speed = SPEED_100000,
	},
	[LINK_MODE_100GE_BASE_R4] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_100ge_base_r4,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_100ge_base_r4),
		.speed = SPEED_100000,
	},
	[LINK_MODE_200GE_BASE_R2] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_200ge_base_r2,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_200ge_base_r2),
		.speed = SPEED_200000,
	},
	[LINK_MODE_200GE_BASE_R4] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_200ge_base_r4,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_200ge_base_r4),
		.speed = SPEED_200000,
	},
	[LINK_MODE_400GE_BASE_R4] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_400ge_base_r4,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_400ge_base_r4),
		.speed = SPEED_400000,
	},
	[LINK_MODE_800GE_BASE_R8] = {
		.link_mode_bit_arr = hinic5_mag_link_mode_800ge_base_r8,
		.arr_size = ARRAY_LEN(hinic5_mag_link_mode_800ge_base_r8),
		.speed = SPEED_800000,
	},
};

static void ethtool_add_supported_speed_link_mode(struct cmd_link_settings *link_settings,
						  u32 mode)
{
	u32 i;

	for (i = 0; i < hw2ethtool_link_mode_table[mode].arr_size; i++) {
		if (hw2ethtool_link_mode_table[mode].link_mode_bit_arr[i] >=
			__ETHTOOL_LINK_MODE_MASK_NBITS)
			continue;
		set_bit(hw2ethtool_link_mode_table[mode].link_mode_bit_arr[i],
			link_settings->supported);
	}
}

static void ethtool_add_advertised_speed_link_mode(struct cmd_link_settings *link_settings,
						   u32 mode)
{
	u32 i;

	for (i = 0; i < hw2ethtool_link_mode_table[mode].arr_size; i++) {
		if (hw2ethtool_link_mode_table[mode].link_mode_bit_arr[i] >=
			__ETHTOOL_LINK_MODE_MASK_NBITS)
			continue;
		set_bit(hw2ethtool_link_mode_table[mode].link_mode_bit_arr[i],
			link_settings->advertising);
	}
}

/* Related to enum mag_cmd_port_speed */
static u32 hw_to_ethtool_speed[] = {
	(u32)SPEED_UNKNOWN, SPEED_10, SPEED_100, SPEED_1000, SPEED_10000,
	SPEED_25000, SPEED_40000, SPEED_50000, SPEED_100000, SPEED_200000,
	SPEED_400000, SPEED_800000,
};

static int hinic5_ethtool_to_hw_speed_level(u32 speed)
{
	int i;

	for (i = 0; i < ARRAY_LEN(hw_to_ethtool_speed); i++) {
		if (hw_to_ethtool_speed[i] == speed)
			break;
	}

	return i;
}

static void hinic5_add_ethtool_link_mode(struct cmd_link_settings *link_settings,
					 u32 hw_link_mode, u32 name)
{
	u32 link_mode;

	for (link_mode = 0; link_mode < LINK_MODE_MAX_NUMBERS; link_mode++) {
		if ((hw_link_mode & BIT(link_mode)) != 0) {
			if (name == GET_SUPPORTED_MODE)
				ethtool_add_supported_speed_link_mode(link_settings, link_mode);
			else
				ethtool_add_advertised_speed_link_mode(link_settings, link_mode);
		}
	}
}

static int hinic5_link_speed_set(struct hinic5_nic_dev *nic_dev,
				 struct cmd_link_settings *link_settings,
				 struct mag_port_info *port_info)
{
	u8 link_state = 0;
	int err;

	if (port_info->supported_mode != LINK_MODE_UNKNOWN)
		hinic5_add_ethtool_link_mode(link_settings,
					     port_info->supported_mode,
					     GET_SUPPORTED_MODE);
	if (port_info->advertised_mode != LINK_MODE_UNKNOWN)
		hinic5_add_ethtool_link_mode(link_settings,
					     port_info->advertised_mode,
					     GET_ADVERTISED_MODE);

	err = hinic5_get_link_state(nic_dev->hwdev, &link_state);
	if (err == 0 && link_state != 0) {
		link_settings->speed =
			port_info->speed < ARRAY_LEN(hw_to_ethtool_speed) ?
			hw_to_ethtool_speed[port_info->speed] :
			(u32)SPEED_UNKNOWN;

		link_settings->duplex = port_info->duplex;
	} else {
		link_settings->speed = (u32)SPEED_UNKNOWN;
		link_settings->duplex = DUPLEX_UNKNOWN;
	}

	return 0;
}

static void hinic5_link_port_type(struct cmd_link_settings *link_settings,
				  u8 port_type)
{
	switch (port_type) {
	case MAG_CMD_WIRE_TYPE_ELECTRIC:
		ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, TP);
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, TP);
		link_settings->port = PORT_TP;
		break;

	case MAG_CMD_WIRE_TYPE_AOC:
	case MAG_CMD_WIRE_TYPE_MM:
	case MAG_CMD_WIRE_TYPE_SM:
		ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, FIBRE);
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, FIBRE);
		link_settings->port = PORT_FIBRE;
		break;

	case MAG_CMD_WIRE_TYPE_COPPER:
		ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, FIBRE);
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, FIBRE);
		link_settings->port = PORT_DA;
		break;

	case MAG_CMD_WIRE_TYPE_BACKPLANE:
		ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, Backplane);
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Backplane);
		link_settings->port = PORT_NONE;
		break;

	default:
		link_settings->port = PORT_OTHER;
		break;
	}
}

static int get_link_pause_settings(struct hinic5_nic_dev *nic_dev,
				   struct cmd_link_settings *link_settings)
{
	struct nic_pause_config nic_pause = {0};
	int err;

	err = hinic5_get_pause_info(nic_dev->hwdev, &nic_pause);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to get pauseparam from hw\n");
		return err;
	}

	ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, Pause);
	if (nic_pause.rx_pause != 0 && nic_pause.tx_pause != 0) {
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Pause);
	} else if (nic_pause.tx_pause != 0) {
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Asym_Pause);
	} else if (nic_pause.rx_pause != 0) {
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Pause);
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Asym_Pause);
	}

	return 0;
}

static bool is_bit_offset_defined(u8 bit_offset)
{
	if (bit_offset < __ETHTOOL_LINK_MODE_MASK_NBITS)
		return true;
	return false;
}

static void ethtool_add_supported_advertised_fec(struct cmd_link_settings *link_settings,
						 u32 fec, u8 cmd)
{
	u8 i;

	for (i = 0; i < HINIC_ETHTOOL_FEC_INFO_LEN; i++) {
		if ((fec & BIT(hinic5_ethtool_fec_info[i].hinic_fec_offset)) == 0)
			continue;
		if (is_bit_offset_defined(hinic5_ethtool_fec_info[i].ethtool_bit_offset) &&
		    cmd == HINIC_ADVERTISED_FEC_CMD) {
			set_bit(hinic5_ethtool_fec_info[i].ethtool_bit_offset,
				link_settings->advertising);
			return; /* There can be only one advertised fec mode. */
		}
		if (is_bit_offset_defined(hinic5_ethtool_fec_info[i].ethtool_bit_offset) &&
		    cmd == HINIC_SUPPORTED_FEC_CMD)
			set_bit(hinic5_ethtool_fec_info[i].ethtool_bit_offset,
				link_settings->supported);
	}
}

static void hinic5_link_fec_type(struct cmd_link_settings *link_settings,
				 u32 fec, u32 supported_fec)
{
	ethtool_add_supported_advertised_fec(link_settings, supported_fec, HINIC_SUPPORTED_FEC_CMD);
	ethtool_add_supported_advertised_fec(link_settings, fec, HINIC_ADVERTISED_FEC_CMD);
}

static int get_link_settings(struct net_device *netdev,
			     struct cmd_link_settings *link_settings)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	struct mag_port_info port_info = {0};
	int err;

	err = hinic5_get_port_info(nic_dev->hwdev, &port_info,
				   HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, netdev, "Failed to get port info\n");
		return err;
	}

	err = hinic5_link_speed_set(nic_dev, link_settings, &port_info);
	if (err != 0)
		return err;

	hinic5_link_port_type(link_settings, port_info.port_type);

	/* port_info.fec is bit offset, value is BIT(port_info.fec);
	 * but port_info.supported_fec_mode is bit value
	 */
	hinic5_link_fec_type(link_settings, BIT(port_info.fec), port_info.supported_fec_mode);

	link_settings->autoneg = port_info.autoneg_state == PORT_CFG_AN_ON ?
					AUTONEG_ENABLE : AUTONEG_DISABLE;
	if (port_info.autoneg_cap != 0)
		ETHTOOL_ADD_SUPPORTED_LINK_MODE(link_settings, Autoneg);
	if (port_info.autoneg_state == PORT_CFG_AN_ON)
		ETHTOOL_ADD_ADVERTISED_LINK_MODE(link_settings, Autoneg);

	if (!HINIC5_FUNC_IS_VF(nic_dev->hwdev))
		err = get_link_pause_settings(nic_dev, link_settings);

	return err;
}

#ifdef ETHTOOL_GLINKSETTINGS
#ifndef XENSERVER_HAVE_NEW_ETHTOOL_OPS
int hinic5_get_link_ksettings(struct net_device *netdev,
			      struct ethtool_link_ksettings *link_settings)
{
	struct cmd_link_settings settings = { { 0 } };
	struct ethtool_link_settings *base = &link_settings->base;
	int err;

	ethtool_link_ksettings_zero_link_mode(link_settings, supported);
	ethtool_link_ksettings_zero_link_mode(link_settings, advertising);

	err = get_link_settings(netdev, &settings);
	if (err != 0)
		return err;

	bitmap_copy(link_settings->link_modes.supported, settings.supported,
		    __ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_copy(link_settings->link_modes.advertising, settings.advertising,
		    __ETHTOOL_LINK_MODE_MASK_NBITS);

	base->autoneg = settings.autoneg;
	base->speed = settings.speed;
	base->duplex = settings.duplex;
	base->port = settings.port;

	return 0;
}
#endif
#endif

static bool hinic5_is_support_speed(u32 supported_link, u32 speed)
{
	u32 link_mode;

	for (link_mode = 0; link_mode < LINK_MODE_MAX_NUMBERS; link_mode++) {
		if ((supported_link & BIT(link_mode)) == 0)
			continue;

		if (hw2ethtool_link_mode_table[link_mode].speed == speed)
			return true;
	}

	return false;
}

static int hinic5_is_speed_legal(struct hinic5_nic_dev *nic_dev,
				 struct mag_port_info *port_info, u32 speed)
{
	struct net_device *netdev = nic_dev->netdev;
	int speed_level = 0;

	if (port_info->supported_mode == LINK_MODE_UNKNOWN ||
	    port_info->advertised_mode == LINK_MODE_UNKNOWN) {
		nicif_err(nic_dev, drv, netdev, "Unknown supported link modes\n");
		return -EAGAIN;
	}

	speed_level = hinic5_ethtool_to_hw_speed_level(speed);
	if (speed_level >= PORT_SPEED_UNKNOWN ||
	    !hinic5_is_support_speed(port_info->supported_mode, speed)) {
		nicif_err(nic_dev, drv, netdev,
			  "Not supported speed: %u\n", speed);
		return -EINVAL;
	}

	return 0;
}

static int get_link_settings_type(struct hinic5_nic_dev *nic_dev,
				  u8 autoneg, u32 speed, u32 *set_settings)
{
	struct mag_port_info port_info = {0};
	int err;

	err = hinic5_get_port_info(nic_dev->hwdev, &port_info,
				   HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get current settings\n");
		return -EAGAIN;
	}

	/* Alwayse set autonegation */
	if (port_info.autoneg_cap != 0)
		*set_settings |= HILINK_LINK_SET_AUTONEG;

	if (autoneg == AUTONEG_ENABLE) {
		if (port_info.autoneg_cap == 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Not support autoneg\n");
			return -EOPNOTSUPP;
		}
	} else if (speed != (u32)SPEED_UNKNOWN) {
		/* Set speed only when autoneg is disable */
		err = hinic5_is_speed_legal(nic_dev, &port_info, speed);
		if (err != 0)
			return err;

		*set_settings |= HILINK_LINK_SET_SPEED;
	} else {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Need to set speed when autoneg is off\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int hinic5_set_settings_to_hw(struct hinic5_nic_dev *nic_dev,
				     u32 set_settings, u8 autoneg, u32 speed)
{
	struct net_device *netdev = nic_dev->netdev;
	struct hinic5_link_ksettings settings = {0};
	int speed_level = 0;
	char set_link_str[128] = {0};
	char link_info[128] = {0};
	int err = 0;

	err = snprintf(link_info, sizeof(link_info), "%s",
		       (bool)(set_settings & HILINK_LINK_SET_AUTONEG) ?
		       ((bool)autoneg ? "autong enable " : "autong disable ") : "");
	if (err < 0)
		return -EINVAL;

	if ((set_settings & HILINK_LINK_SET_SPEED) != 0) {
		speed_level = hinic5_ethtool_to_hw_speed_level(speed);
		err = snprintf(set_link_str, sizeof(set_link_str),
			       "%s speed %u ", link_info, speed);
		if (err < 0)
			return -EINVAL;
	}

	settings.valid_bitmap = set_settings;
	settings.autoneg = (bool)autoneg ? PORT_CFG_AN_ON : PORT_CFG_AN_OFF;
	settings.speed = (u8)speed_level;

	err = hinic5_set_link_settings(nic_dev->hwdev, &settings);
	if (err != 0)
		nicif_err(nic_dev, drv, netdev, "Set %s failed\n",
			  set_link_str);
	else
		nicif_info(nic_dev, drv, netdev, "Set %s success\n",
			   set_link_str);

	return err;
}

static int set_link_settings(struct net_device *netdev, u8 autoneg, u32 speed)
{
	struct hinic5_nic_dev *nic_dev = netdev_priv(netdev);
	u32 set_settings = 0;
	int err = 0;

	err = get_link_settings_type(nic_dev, autoneg, speed, &set_settings);
	if (err != 0)
		return err;

	if (set_settings != 0)
		err = hinic5_set_settings_to_hw(nic_dev, set_settings,
						autoneg, speed);
	else
		nicif_info(nic_dev, drv, netdev, "Nothing changed, exiting without setting anything\n");

	return err;
}

#ifdef ETHTOOL_GLINKSETTINGS
#ifndef XENSERVER_HAVE_NEW_ETHTOOL_OPS
int hinic5_set_link_ksettings(struct net_device *netdev,
			      const struct ethtool_link_ksettings *link_settings)
{
	/* Only support to set autoneg and speed */
	return set_link_settings(netdev, link_settings->base.autoneg,
				 link_settings->base.speed);
}
#endif
#endif

#ifndef HAVE_NEW_ETHTOOL_LINK_SETTINGS_ONLY
int hinic5_get_settings(struct net_device *netdev, struct ethtool_cmd *ep)
{
	struct cmd_link_settings settings = { { 0 } };
	int err;

	err = get_link_settings(netdev, &settings);
	if (err != 0)
		return err;

	ep->supported = settings.supported[0] & ((u32)~0);
	ep->advertising = settings.advertising[0] & ((u32)~0);

	ep->autoneg = settings.autoneg;
	ethtool_cmd_speed_set(ep, settings.speed);
	ep->duplex = settings.duplex;
	ep->port = settings.port;
	ep->transceiver = XCVR_INTERNAL;

	return 0;
}

int hinic5_set_settings(struct net_device *netdev,
			struct ethtool_cmd *link_settings)
{
	/* Only support to set autoneg and speed */
	return set_link_settings(netdev, link_settings->autoneg,
				 ethtool_cmd_speed(link_settings));
}
#endif
