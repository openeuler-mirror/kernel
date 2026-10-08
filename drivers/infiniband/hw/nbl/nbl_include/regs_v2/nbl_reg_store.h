/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_STORE_LAYOUT_H
#define NBL_STORE_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_STORE_ETH_COS_FC_OFF		0x0200
#define NBL_STORE_ETH_COS_FC_DPORT_STRIDE	0x20
#define NBL_STORE_ETH_COS_FC_PRI_STRIDE		0x4
#define NBL_STORE_PRI_CONF_OFF			0x0790
#define NBL_STORE_PRI_CONF_STRIDE		0x4
#define NBL_STORE_TBL_PRI_CONF_OFF		0x3E00
#define NBL_STORE_TBL_PRI_CONF_STRIDE		0x20

/* Register address macro */
#define NBL_STORE_REG_ADDR(base, off)		((base) + (off))

/* Eth cos fc register address */
#define NBL_STORE_ETH_COS_FC_ADDR(base, dport_id, pri) \
	(NBL_STORE_REG_ADDR((base), NBL_STORE_ETH_COS_FC_OFF) + \
	 NBL_STORE_ETH_COS_FC_DPORT_STRIDE * (dport_id) + \
	 NBL_STORE_ETH_COS_FC_PRI_STRIDE * (pri))

/* Pri conf register address */
#define NBL_STORE_PRI_CONF_ADDR(base, dport_id) \
	(NBL_STORE_REG_ADDR((base), NBL_STORE_PRI_CONF_OFF) + \
	 NBL_STORE_PRI_CONF_STRIDE * (dport_id))

/* Tbl pri conf register address */
#define NBL_STORE_TBL_PRI_CONF_ADDR(base, dport_id) \
	(NBL_STORE_REG_ADDR((base), NBL_STORE_TBL_PRI_CONF_OFF) + \
	 NBL_STORE_TBL_PRI_CONF_STRIDE * (dport_id))

/* GRC-side absolute addresses (V2 base from nbl_reg_base.h) */
#define NBL_REG_STORE_PRI_CONF_V2(dport_id) \
	NBL_STORE_PRI_CONF_ADDR(NBL_REG_STORE_BASE_V2, (dport_id))
#define NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id) \
	NBL_STORE_TBL_PRI_CONF_ADDR(NBL_REG_STORE_BASE_V2, (dport_id))
#define NBL_STORE_ETH_COS_FC_V2(dport_id, pri) \
	NBL_STORE_ETH_COS_FC_ADDR(NBL_REG_STORE_BASE_V2, (dport_id), (pri))

enum store_pri_conf_sel_table {
	STORE_PRI_CONF_SEL_8021P = 0,
	STORE_PRI_CONF_SEL_DSCP = 1,
	STORE_PRI_CONF_SEL_MAX,
};

/* Draco PFC */
union store_up_fc_mode {
	u32 data[1];
	struct {
		u32 link : 1;
		u32 pfc : 1;
		u32 rsv : 30;
	};
};

_Static_assert(sizeof(union store_up_fc_mode) == 4,
	      "store_up_fc_mode size must be 4 bytes");

/* Draco DSCP */
union store_pri_conf {
	u32 data[1];
	struct {
		u32 sel : 1;
		u32 cpu_set : 3;
		u32 en : 1;
		u32 rsv : 27;
	};
};

_Static_assert(sizeof(union store_pri_conf) == 4,
	      "store_pri_conf size must be 4 bytes");

union store_tbl_pri_conf {
	u32 data[1];
	struct {
		u32 pri0 : 4;
		u32 pri1 : 4;
		u32 pri2 : 4;
		u32 pri3 : 4;
		u32 pri4 : 4;
		u32 pri5 : 4;
		u32 pri6 : 4;
		u32 pri7 : 4;
	};
};

_Static_assert(sizeof(union store_tbl_pri_conf) == 4,
	      "store_tbl_pri_conf size must be 4 bytes");

union store_eth_cos_fc {
	u32 data[1];
	struct {
		u32 xoff_th : 12;
		u32 rsv1 : 4;
		u32 xon_th : 12;
		u32 rsv2 : 2;
		u32 fc_set : 1;
		u32 fc_en : 1;
	};
};

_Static_assert(sizeof(union store_eth_cos_fc) == 4,
	      "store_eth_cos_fc size must be 4 bytes");

#endif /* NBL_STORE_LAYOUT_H */
