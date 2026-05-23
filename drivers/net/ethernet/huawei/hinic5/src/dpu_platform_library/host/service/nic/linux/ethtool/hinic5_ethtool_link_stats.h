/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_link_stats.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_ETHTOOL_LINK_STATS_H
#define	HINIC5_ETHTOOL_LINK_STATS_H

#include <linux/types.h>
#include <linux/ethtool.h>

struct hw2ethtool_link_mode {
	const u32 *link_mode_bit_arr;
	u32 arr_size;
	u32 speed;
};

#define GET_SUPPORTED_MODE	0
#define GET_ADVERTISED_MODE	1

struct cmd_link_settings {
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);

	u32	speed;
	u8	duplex;
	u8	port;
	u8	autoneg;
};

#define ETHTOOL_ADD_SUPPORTED_LINK_MODE(ecmd, mode)	\
		set_bit(ETHTOOL_LINK_MODE_##mode##_BIT, (ecmd)->supported)
#define ETHTOOL_ADD_ADVERTISED_LINK_MODE(ecmd, mode)	\
		set_bit(ETHTOOL_LINK_MODE_##mode##_BIT, (ecmd)->advertising)

#endif
