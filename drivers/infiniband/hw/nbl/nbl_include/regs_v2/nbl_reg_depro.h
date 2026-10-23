/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_DEPRO_LAYOUT_H
#define NBL_DEPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_DEPRO_MIRROR_TBL_OFF                0x2000
#define NBL_DEPRO_MIRROR_TBL_STRIDE              0x4

/* Register address macro */
#define NBL_DEPRO_REG_ADDR(base, off)           ((base) + (off))

/* Mirror table register address */
#define NBL_DEPRO_MIRROR_TBL_ADDR(base, idx) \
	(NBL_DEPRO_REG_ADDR((base), NBL_DEPRO_MIRROR_TBL_OFF) + \
	 NBL_DEPRO_MIRROR_TBL_STRIDE * (idx))

/* 32-bit mirror table entry */
union nbl_depro_mirror_tbl_reg {
	struct {
		u32 dport : 3;
		u32 dport_id : 11;
		u32 dport_info : 11;
		u32 mirror_type : 2;
		u32 rsv : 5;
	};
	u32 data;
};

_Static_assert(sizeof(union nbl_depro_mirror_tbl_reg) ==
	       NBL_DEPRO_MIRROR_TBL_STRIDE,
	       "nbl_depro_mirror_tbl_reg size must match mirror table stride");

#endif /* NBL_DEPRO_LAYOUT_H */
