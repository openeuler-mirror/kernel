/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_UIPRO_LAYOUT_H
#define NBL_UIPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_UIPRO_ETH_PORT_OFF			0x010c
#define NBL_UIPRO_ETH_PORT_STRIDE		0x4
#define NBL_UIPRO_DOT1Q_COS_MAP_REG0_OFF	0x114
#define NBL_UIPRO_DOT1Q_COS_MAP_REG1_OFF	0x120
#define NBL_UIPRO_DSCP_COS_MAP_REG0_OFF		0x11c
#define NBL_UIPRO_DSCP_COS_MAP_REG1_OFF		0x128
/* RNIC400 uses different DSCP cos map offsets */
#define NBL_UIPRO_DSCP_COS_MAP_REG0_OFF_V4	0x140
#define NBL_UIPRO_DSCP_COS_MAP_REG1_OFF_V4	0x160
#define NBL_UIPRO_GLB_LLC_EN_OFF		0x012c

/* Register address macro */
#define NBL_UIPRO_REG_ADDR(base, off)		((base) + (off))

/* ETH port table register address */
#define NBL_UIPRO_ETH_PORT_ADDR(base, id) \
	(NBL_UIPRO_REG_ADDR((base), NBL_UIPRO_ETH_PORT_OFF) + \
	 NBL_UIPRO_ETH_PORT_STRIDE * (id))

/* GRC-side absolute addresses (V3/V4 base from nbl_reg_base.h) */
#define NBL_REG_UP_ETH_PORT_REG(eth_id) \
	NBL_UIPRO_ETH_PORT_ADDR(NBL_REG_UIPRO_V3, (eth_id))
#define NBL_REG_UP_DOT1Q_COS_MAP_REG0 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_V3, NBL_UIPRO_DOT1Q_COS_MAP_REG0_OFF)
#define NBL_REG_UP_DOT1Q_COS_MAP_REG1 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_V3, NBL_UIPRO_DOT1Q_COS_MAP_REG1_OFF)
#define NBL_REG_UP_DSCP_COS_MAP_REG0 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_V3, NBL_UIPRO_DSCP_COS_MAP_REG0_OFF)
#define NBL_REG_UP_DSCP_COS_MAP_REG1 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_V3, NBL_UIPRO_DSCP_COS_MAP_REG1_OFF)
#define NBL_REG_UP_DSCP_COS_MAP_REG0_V4 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_BASE_V4, NBL_UIPRO_DSCP_COS_MAP_REG0_OFF_V4)
#define NBL_REG_UP_DSCP_COS_MAP_REG1_V4 \
	NBL_UIPRO_REG_ADDR(NBL_REG_UIPRO_BASE_V4, NBL_UIPRO_DSCP_COS_MAP_REG1_OFF_V4)

enum cos_map_mode_table {
	NBL_COS_MAP_MODE_DEF = 0,
	NBL_COS_MAP_MODE_8021P = 1,
	NBL_COS_MAP_MODE_DSCP = 2,
	NBL_COS_MAP_MODE_TOS = 3,
	NBL_COS_MAP_MODE_CPU = 4,
	NBL_COS_MAP_MODE_MAX,
};

/* uipro dipro pkt_cos_map */
union eth_port_reg_table {
	u32 data[1];
	struct {
		u32 rsv1 : 18;
		u32 cos_map_mode : 3;
		u32 rsv2 : 11;
	};
};

_Static_assert(sizeof(union eth_port_reg_table) == 4,
	      "eth_port_reg_table size must be 4 bytes");

union pkt_cos_map_table {
	u32 data[1];
	struct {
		u32 pri0 : 3;
		u32 rsv0 : 1;
		u32 pri1 : 3;
		u32 rsv1 : 1;
		u32 pri2 : 3;
		u32 rsv2 : 1;
		u32 pri3 : 3;
		u32 rsv3 : 1;
		u32 pri4 : 3;
		u32 rsv4 : 1;
		u32 pri5 : 3;
		u32 rsv5 : 1;
		u32 pri6 : 3;
		u32 rsv6 : 1;
		u32 pri7 : 3;
		u32 rsv7 : 1;
	};
};

_Static_assert(sizeof(union pkt_cos_map_table) == 4,
	      "pkt_cos_map_table size must be 4 bytes");

#endif /* NBL_UIPRO_LAYOUT_H */
