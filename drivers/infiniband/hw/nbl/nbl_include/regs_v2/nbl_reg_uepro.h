/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_UEPRO_LAYOUT_H
#define NBL_UEPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_UEPRO_VSI_PORT_TBL_OFF		0x00002000
#define NBL_UEPRO_VSI_PORT_TBL_STRIDE		0x4
#define NBL_UEPRO_MIRROR_TBL_OFF		0x00004000
#define NBL_UEPRO_MIRROR_TBL_STRIDE		0x4

/* Register address macro */
#define NBL_UEPRO_REG_ADDR(base, off)		((base) + (off))

/* VSI port table register address */
#define NBL_UEPRO_VSI_PORT_TBL_ADDR(base, idx) \
	(NBL_UEPRO_REG_ADDR((base), NBL_UEPRO_VSI_PORT_TBL_OFF) + \
	 NBL_UEPRO_VSI_PORT_TBL_STRIDE * (idx))

/* Mirror table register address */
#define NBL_UEPRO_MIRROR_TBL_ADDR(base, idx) \
	(NBL_UEPRO_REG_ADDR((base), NBL_UEPRO_MIRROR_TBL_OFF) + \
	 NBL_UEPRO_MIRROR_TBL_STRIDE * (idx))

/* 32-bit mirror table entry */
union nbl_uepro_mirror_tbl_reg {
	struct {
		u32 dport : 3;
		u32 dport_id : 11;
		u32 dport_info : 11;
		u32 mirror_type : 2;
		u32 rsv : 5;
	};
	u32 data;
};

_Static_assert(sizeof(union nbl_uepro_mirror_tbl_reg) ==
	       NBL_UEPRO_MIRROR_TBL_STRIDE,
	       "nbl_uepro_mirror_tbl_reg size must match mirror table stride");

/* 32-bit VSI port table entry */
union nbl_uepro_vsi_port_tbl_reg {
	struct {
		u32 fwd : 1;
		u32 mirror : 1;
		u32 mirror_id : 2;
		u32 rdma_dump_en : 1;
		u32 rsv : 27;
	};
	u32 data;
};

_Static_assert(sizeof(union nbl_uepro_vsi_port_tbl_reg) ==
	       NBL_UEPRO_VSI_PORT_TBL_STRIDE,
	       "nbl_uepro_vsi_port_tbl_reg size must match VSI port table stride");

#endif /* NBL_UEPRO_LAYOUT_H */
