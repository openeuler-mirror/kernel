/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_EPRO_LAYOUT_H
#define NBL_EPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base (base NBL_GRC_EPRO_BASE kept in grc_hw_rdma.h) */
#define NBL_EPRO_INT_MASK_OFF		0x00000004
#define NBL_EPRO_AM_UDF_PRF_TBL_OFF	0x00000180
#define NBL_EPRO_MIRROR_PROF_TBL_OFF	0x00001800
#define NBL_EPRO_EVSI_TBL_OFF		0x00002000

/* Table strides */
#define NBL_EPRO_AM_UDF_PRF_TBL_STRIDE	0x4
#define NBL_EPRO_MIRROR_PROF_TBL_STRIDE	0x10
#define NBL_EPRO_EVSI_TBL_STRIDE		0x20

/* Int mask cfg err bit */
#define EPRO_INT_MASK_CFG_ERR	5

/* AM UDF config */
#define AM_UDF_VLD			BIT(7)
#define EPRO_AM_UDF_QPN_LOW_OFT		0x1a /* oft = 0x1a * 4 = 104 */
#define EPRO_AM_UDF_QPN_HIGH_OFT	0x1c /* oft = 0x1c * 4 = 112 */

/* rdma_flag in bit158, so relative 4bit oft to 159 is 0 */
#define EPRO_AM_UDF_RDMA_FLAG_OFT	0
#define AM_UDF_MIRROR_ID_OFT		0xf
#define AM_UDF_MIRROR_ID_IDX		6
#define AM_UDF_QPN_IDX			5

enum set_udf_sz_unit {
	ONLY_DATA_8BIT,
	DATA_WITH_MASK_8BIT,
	ONLY_DATA_16BIT,
	ONLY_DATA_32BIT,
};

/* Register address macro */
#define NBL_EPRO_REG_ADDR(base, off)	((base) + (off))

/* Int mask register address */
#define NBL_EPRO_INT_MASK_ADDR(base) \
	NBL_EPRO_REG_ADDR((base), NBL_EPRO_INT_MASK_OFF)

/* AM UDF profile table entry address */
#define NBL_EPRO_AM_UDF_PRF_TBL_ADDR(base, idx) \
	(NBL_EPRO_REG_ADDR((base), NBL_EPRO_AM_UDF_PRF_TBL_OFF) + \
	 NBL_EPRO_AM_UDF_PRF_TBL_STRIDE * (idx))

/* Mirror profile table entry address */
#define NBL_EPRO_MIRROR_PROF_TBL_ADDR(base, mirror_id) \
	(NBL_EPRO_REG_ADDR((base), NBL_EPRO_MIRROR_PROF_TBL_OFF) + \
	 NBL_EPRO_MIRROR_PROF_TBL_STRIDE * (mirror_id))

/* EVSI table entry address */
#define NBL_EPRO_EVSI_TBL_ADDR(base, vsi_id) \
	(NBL_EPRO_REG_ADDR((base), NBL_EPRO_EVSI_TBL_OFF) + \
	 NBL_EPRO_EVSI_TBL_STRIDE * (vsi_id))

/* GRC-side absolute address (original name kept) */
#define EPRO_INT_MASK \
	NBL_EPRO_INT_MASK_ADDR(NBL_GRC_EPRO_BASE)

/* Table offsets from base (original names kept, add base at use sites) */
#define EPRO_MIRROR_PROF_TBL(mirror_id) \
	(NBL_EPRO_MIRROR_PROF_TBL_OFF + \
	 NBL_EPRO_MIRROR_PROF_TBL_STRIDE * (mirror_id))
#define EPRO_AM_UDF_PRF_TBL(idx) \
	(NBL_EPRO_AM_UDF_PRF_TBL_OFF + \
	 NBL_EPRO_AM_UDF_PRF_TBL_STRIDE * (idx))
#define NBL_EPRO_EVSI_TBL(vsi_id) \
	(NBL_EPRO_EVSI_TBL_OFF + \
	 NBL_EPRO_EVSI_TBL_STRIDE * (vsi_id))

union epro_mirror_prof_tbl {
	struct {
		u64 base_ad : 64;

		u64 base_ab : 8;
		u64 udp_sport_en : 1;
		u64 pfc_mode : 2;
		u64 rsv : 1;
		u64 vld : 1;
		u64 rsv1 : 51;
	};

	u64 data[2];
};

union nbl_am_udf_prf_tbl {
	struct {
		u32 set_udf0 : 8;
		u32 set_udf1 : 8;
		u32 set_udf2 : 8;
		u32 set_udf3 : 8;
	};

	u32 data;
};

union nbl_epro_evsi_tbl {
	struct {
		u64 base_ad : 64;

		u64 base_ab : 8;
		u64 mtu : 16;
		u64 act_mode : 2;
		u64 port_mac_low : 38;

		u64 port_mac_high : 10;
		u64 prune_mc : 2;
		u64 prune_uc : 2;
		u64 vld : 1;
		u64 rsv1 : 49;

		u64 rsv2 : 64;
	};

	u64 data[4];
};

_Static_assert(sizeof(union nbl_am_udf_prf_tbl) == NBL_EPRO_AM_UDF_PRF_TBL_STRIDE,
	       "nbl_am_udf_prf_tbl size must match table stride");

_Static_assert(sizeof(union epro_mirror_prof_tbl) == NBL_EPRO_MIRROR_PROF_TBL_STRIDE,
	       "epro_mirror_prof_tbl size must match table stride");

_Static_assert(sizeof(union nbl_epro_evsi_tbl) == NBL_EPRO_EVSI_TBL_STRIDE,
	       "nbl_epro_evsi_tbl size must match table stride");

#endif /* NBL_EPRO_LAYOUT_H */
