/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_DIPRO_LAYOUT_H
#define NBL_DIPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_DIPRO_DN_DOT1Q_COS_MAP_REG0_OFF     0x108
#define NBL_DIPRO_DN_DOT1Q_COS_MAP_REG1_OFF     0x118
#define NBL_DIPRO_DN_DSCP_COS_MAP_REG0_OFF      0x110
#define NBL_DIPRO_DN_DSCP_COS_MAP_REG1_OFF      0x120
#define NBL_DIPRO_DN_DSCP_COS_MAP_REG0_V4_OFF   0x140
#define NBL_DIPRO_DN_DSCP_COS_MAP_REG1_V4_OFF   0x160
#define NBL_DIPRO_DN_GLB_LLC_EN_OFF             0x130
#define NBL_DIPRO_VSI_PORT_TBL_OFF              0x1000
#define NBL_DIPRO_VSI_PORT_TBL_STRIDE           0x4
#define NBL_DIPRO_VSI_MTU_TBL_OFF_V3            0x9000 /* DF200 */
#define NBL_DIPRO_VSI_MTU_TBL_OFF_V4            0x1100 /* RNIC400 */
#define NBL_DIPRO_VSI_MTU_TBL_STRIDE            0x4

/* Register address macro */
#define NBL_DIPRO_REG_ADDR(base, off)           ((base) + (off))

/* VSI port table register address */
#define NBL_DIPRO_VSI_PORT_TBL_ADDR(base, idx) \
	(NBL_DIPRO_REG_ADDR((base), NBL_DIPRO_VSI_PORT_TBL_OFF) + \
	 NBL_DIPRO_VSI_PORT_TBL_STRIDE * (idx))

/* VSI MTU table register address (offset is version specific) */
#define NBL_DIPRO_VSI_MTU_TBL_ADDR(base, off, idx) \
	(NBL_DIPRO_REG_ADDR((base), (off)) + \
	 NBL_DIPRO_VSI_MTU_TBL_STRIDE * (idx))

/* GRC-side absolute addresses (DF200 V3 base from nbl_reg_base.h) */
#define NBL_REG_VSI_PORT_REG(vsi_id) \
	NBL_DIPRO_VSI_PORT_TBL_ADDR(NBL_REG_DIPRO_V3, (vsi_id))
#define NBL_REG_DN_DOT1Q_COS_MAP_REG0 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DOT1Q_COS_MAP_REG0_OFF)
#define NBL_REG_DN_DOT1Q_COS_MAP_REG1 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DOT1Q_COS_MAP_REG1_OFF)
#define NBL_REG_DN_DSCP_COS_MAP_REG0 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DSCP_COS_MAP_REG0_OFF)
#define NBL_REG_DN_DSCP_COS_MAP_REG1 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DSCP_COS_MAP_REG1_OFF)
#define NBL_REG_DN_DSCP_COS_MAP_REG0_V4 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DSCP_COS_MAP_REG0_V4_OFF)
#define NBL_REG_DN_DSCP_COS_MAP_REG1_V4 \
	NBL_DIPRO_REG_ADDR(NBL_REG_DIPRO_V3, NBL_DIPRO_DN_DSCP_COS_MAP_REG1_V4_OFF)

/* 32-bit VSI port table entry */
union nbl_dipro_vsi_port_tbl_reg {
	struct {
		u32 default_vlanid : 12;
		u32 vlan_type : 2;
		u32 vlan_check_en : 1;
		u32 mirror : 1;
		u32 mirror_id : 2;
		u32 cos_map_mode : 3;
		u32 default_pri : 3;
		u32 straight : 1;
		u32 lag : 1;
		u32 dport_id : 2;
		u32 mac_lut_en : 1;
		u32 default_vlan_en : 1;
		u32 rdma_dump_en : 1;
		u32 rsv : 1;
	};
	u32 data;
};

_Static_assert(sizeof(union nbl_dipro_vsi_port_tbl_reg) ==
	       NBL_DIPRO_VSI_PORT_TBL_STRIDE,
	       "nbl_dipro_vsi_port_tbl_reg size must match VSI port table stride");

#endif /* NBL_DIPRO_LAYOUT_H */
