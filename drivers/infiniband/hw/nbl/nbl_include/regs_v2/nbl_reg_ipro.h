/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IPRO_LAYOUT_H
#define NBL_IPRO_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base (base NBL_GRC_IPRO_BASE kept in grc_hw_rdma.h) */
#define NBL_IPRO_AM_UDF_PRF_TBL_OFF	0x00000180
#define NBL_IPRO_IVSI_TBL_OFF		0x00008000

/* Table strides */
#define NBL_IPRO_AM_UDF_PRF_TBL_STRIDE	0x4
#define NBL_IPRO_IVSI_TBL_STRIDE		0x20

/* Register address macro */
#define NBL_IPRO_REG_ADDR(base, off)	((base) + (off))

/* AM UDF profile table entry address */
#define NBL_IPRO_AM_UDF_PRF_TBL_ADDR(base, idx) \
	(NBL_IPRO_REG_ADDR((base), NBL_IPRO_AM_UDF_PRF_TBL_OFF) + \
	 NBL_IPRO_AM_UDF_PRF_TBL_STRIDE * (idx))

/* IVSI table entry address */
#define NBL_IPRO_IVSI_TBL_ADDR(base, vsi_id) \
	(NBL_IPRO_REG_ADDR((base), NBL_IPRO_IVSI_TBL_OFF) + \
	 NBL_IPRO_IVSI_TBL_STRIDE * (vsi_id))

/* Table offsets from base (original names kept, add base at use sites) */
#define IPRO_AM_UDF_PRF_TBL(idx) \
	(NBL_IPRO_AM_UDF_PRF_TBL_OFF + \
	 NBL_IPRO_AM_UDF_PRF_TBL_STRIDE * (idx))
#define IPRO_IVSI_TBL(vsi_id) \
	(NBL_IPRO_IVSI_TBL_OFF + \
	 NBL_IPRO_IVSI_TBL_STRIDE * (vsi_id))

union nbl_ipro_ivsi_tbl {
	struct {
		u64 base_ad : 64;

		u64 base_ab : 8;
		u64 not_use1 : 1;
		u64 t_lx_sel : 1;
		u64 vlan_lmt : 2;
		u64 sw_id : 2;
		u64 not_use0 : 1;
		u64 smac_vld : 1;
		u64 smac : 48;

		u64 mtu : 16;
		u64 cpu_nstg : 3;
		u64 cpu_bps : 1;
		u64 phy_flow : 1;
		u64 t_s3 : 3;
		u64 vld : 1;
		u64 rsv1 : 39;

		u64 rsv2 : 64;
	};

	u64 data[4];
};

_Static_assert(sizeof(union nbl_ipro_ivsi_tbl) == NBL_IPRO_IVSI_TBL_STRIDE,
	       "nbl_ipro_ivsi_tbl size must match table stride");

#endif /* NBL_IPRO_LAYOUT_H */
