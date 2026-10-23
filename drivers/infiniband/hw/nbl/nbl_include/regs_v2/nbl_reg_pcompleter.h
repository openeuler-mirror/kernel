/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_PCOMP_LAYOUT_H
#define NBL_PCOMP_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_PCOMP_RDMA_TBL_READY_OFF		0x00001114
#define NBL_PCOMP_RDMA_TBL_SEL_OFF		0x00001118
#define NBL_PCOMP_FID_TBL_OFF			0x00015000
#define NBL_PCOMP_FID_TBL_STRIDE		0x4

/* Register address macro */
#define NBL_PCOMP_REG_ADDR(base, off)		((base) + (off))

/* PFID/FID map table register address */
#define NBL_PCOMP_FID_TBL_ADDR(base, idx) \
	(NBL_PCOMP_REG_ADDR((base), NBL_PCOMP_FID_TBL_OFF) + \
	 NBL_PCOMP_FID_TBL_STRIDE * (idx))

/* 32-bit PFID/FID map entry: rdma_fid:8 + valid:1 + rsv:23 */
union nbl_pcomp_fid_tbl_reg {
	struct {
		u32 rdma_fid : 8;
		u32 valid : 1;
		u32 rsv : 23;
	};
	u32 data;
};

_Static_assert(sizeof(union nbl_pcomp_fid_tbl_reg) ==
	       NBL_PCOMP_FID_TBL_STRIDE,
	       "nbl_pcomp_fid_tbl_reg size must match FID table stride");

/* RDMA table ready register */
union nbl_rdma_tbl_ready_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_ready : 1;
		u32 rsv : 31;
	};
};

/* RDMA table select register */
union nbl_rdma_tbl_sel_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_sel : 1;
		u32 rsv : 31;
	};
};

#endif /* NBL_PCOMP_LAYOUT_H */
