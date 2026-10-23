/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TOP_CTRL_LAYOUT_H
#define NBL_TOP_CTRL_LAYOUT_H

#include <linux/types.h>

/* Register offsets from base */
#define NBL_TOP_CTL_LB_RST_OFF		0x0104
#define NBL_TOP_CTL_SOFTDEF_TBL_OFF	0x0498
#define NBL_TOP_CTL_SOFTDEF_TBL_STRIDE	0x4
#define NBL_TOP_CTL_PROTO_VERSION_DATE_OFF	0x0904

/* LB rst/release values */
#define NBL_RDMA_LB_RST_VALUE	0x0FF
#define NBL_RDMA_LB_RELEASE_VALUE	0x1FF

/* QPN range default values */
#define NBL_FUNCTION0_QPN_RANGE (0xffff0000)
#define NBL_FUNCTION1_QPN_RANGE (0xffff0000)
#define NBL_FUNCTION2_QPN_RANGE (0xffff0000)
#define NBL_FUNCTION3_QPN_RANGE (0xffff0000)

/* Register address macro */
#define NBL_TOP_CTRL_REG_ADDR(base, off)	((base) + (off))

/* LB rst register address */
#define NBL_TOP_CTRL_LB_RST_ADDR(base) \
	NBL_TOP_CTRL_REG_ADDR((base), NBL_TOP_CTL_LB_RST_OFF)

/* Softdef tbl register address */
#define NBL_TOP_CTL_SOFTDEF_TBL_ADDR(base, vf_id) \
	(NBL_TOP_CTRL_REG_ADDR((base), NBL_TOP_CTL_SOFTDEF_TBL_OFF) + \
	 NBL_TOP_CTL_SOFTDEF_TBL_STRIDE * (vf_id))

#define NBL_RDMA_LB_RST_ADDR_V2	NBL_TOP_CTRL_LB_RST_ADDR(NBL_REG_TOP_CTRL_BASE_V2)

union nbl_qpn_range_tbl_reg {
	u32 data[1];
	struct {
		u32 start_idx : 16;
		u32 end_idx : 16;
	};

};

_Static_assert(sizeof(union nbl_qpn_range_tbl_reg) == 4,
	      "nbl_qpn_range_tbl_reg size must be 4 bytes");

#endif /* NBL_TOP_CTRL_LAYOUT_H */
