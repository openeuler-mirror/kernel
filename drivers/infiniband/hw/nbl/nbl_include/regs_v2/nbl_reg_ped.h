/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_PED_LAYOUT_H
#define NBL_PED_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_PED_QPN_UDF_EXT_OFF		0x0128
#define NBL_PED_TBL_MIRR_ENC_OFF	0xA000

/* Table strides */
#define NBL_PED_TBL_MIRR_ENC_STRIDE	0x8

/* RDMA dump mode for mirror encode table */
#define NBL_PED_RDMA_DUMP_MODE	1

/* QPN extract config in UDF */
#define QPN_OFT_IN_UDF		104
#define PED_QPN_OFT_UNIT	4

/* Register address macro */
#define NBL_PED_REG_ADDR(base, off)	((base) + (off))

/* QPN UDF extract register address */
#define NBL_PED_QPN_UDF_EXT_ADDR(base) \
	NBL_PED_REG_ADDR((base), NBL_PED_QPN_UDF_EXT_OFF)

/* Mirror encode table entry address */
#define NBL_PED_MIRR_ENC_TBL_ADDR(base, mirror_id) \
	(NBL_PED_REG_ADDR((base), NBL_PED_TBL_MIRR_ENC_OFF) + \
	 NBL_PED_TBL_MIRR_ENC_STRIDE * (mirror_id))

union nbl_ped_qpn_udf_ext_reg {
	u32 data[1];
	struct {
		u32 oft : 6;
		u32 rsv : 1;
		u32 vld : 1;
		u32 rsv1 : 24;
	};

};

union nbl_ped_tbl_mirr_enc {
	struct {
		u32 mir_info_low : 32;

		u32 mir_info_high : 4;
		u32 mode : 2;
		u32 rsv : 26;
	};

	u32 data[2];
};

_Static_assert(sizeof(union nbl_ped_qpn_udf_ext_reg) == 4,
	       "nbl_ped_qpn_udf_ext_reg size must be 4 bytes");

_Static_assert(sizeof(union nbl_ped_tbl_mirr_enc) == NBL_PED_TBL_MIRR_ENC_STRIDE,
	       "nbl_ped_tbl_mirr_enc size must match table stride");

#endif /* NBL_PED_LAYOUT_H */
