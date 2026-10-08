/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_SHAPING_LAYOUT_H
#define NBL_SHAPING_LAYOUT_H

#include <linux/types.h>

#define NBL_SHAPING_DPT_TBL_OFF			0x00021000
#define NBL_SHAPING_DPT_TBL_STRIDE		0x20
#define NBL_SHAPING_DPT_TBL_DW_SIZE		8

#define NBL_SHAPING_DPT_TBL_ADDR(base, id) \
	((base) + NBL_SHAPING_DPT_TBL_OFF + \
	 NBL_SHAPING_DPT_TBL_STRIDE * (id))

/* RNIC400 shaping to 399.6G at 433M for ETS accurate */
#define NBL_SHAPING_DPORT_DFT_CIR		0x617bc
#define NBL_SHAPING_DPORT_DFT_PIR		0x617bc
#define NBL_SHAPING_DPORT_DFT_CBS		0x74faf
#define NBL_SHAPING_DPORT_DFT_PBS		0x74faf
#define NBL_SHAPING_DPORT_DFT_CB_TOKEN		0x617bc
#define NBL_SHAPING_DPORT_DFT_PB_TOKEN		0x617bc

/* RNIC2*200 shaping to 199.6G each eth */
#define NBL_SHAPING_DPORT_DFT_CIR_RNIC2X200	0x34c03
#define NBL_SHAPING_DPORT_DFT_PIR_RNIC2X200	0x34c03
#define NBL_SHAPING_DPORT_DFT_CBS_RNIC2X200	0x3f4d0
#define NBL_SHAPING_DPORT_DFT_PBS_RNIC2X200	0x3f4d0
#define NBL_SHAPING_DPORT_DFT_CB_TOKEN_RNIC2X200	0x34c03
#define NBL_SHAPING_DPORT_DFT_PB_TOKEN_RNIC2X200	0x34c03

/* RNIC2*200 lag shaping to 399G */
#define NBL_SHAPING_DPORT_DFT_CIR_RNIC2X200_LAG	0x6972d
#define NBL_SHAPING_DPORT_DFT_PIR_RNIC2X200_LAG	0x6972d
#define NBL_SHAPING_DPORT_DFT_CBS_RNIC2X200_LAG	0x7e89d
#define NBL_SHAPING_DPORT_DFT_PBS_RNIC2X200_LAG	0x7e89d
#define NBL_SHAPING_DPORT_DFT_CB_TOKEN_RNIC2X200_LAG	0x6972d
#define NBL_SHAPING_DPORT_DFT_PB_TOKEN_RNIC2X200_LAG	0x6972d

union nbl_shaping_dpt_tbl {
	struct {
		u32 valid : 1;
		u32 rsv : 3;
		u32 cir : 21;
		u32 rsv1 : 7;
		u32 pir : 21;
		u32 rsv2 : 11;
		u32 cbs : 21;
		u32 rsv3 : 11;
		u32 pbs : 21;
		u32 rsv4 : 11;
		u32 cb_token : 22;
		u32 rsv5 : 10;
		u32 pb_token : 22;
		u32 rsv6 : 10;
		u32 rsv7 : 32;
		u32 rsv8 : 32;
	};
	u32 data[NBL_SHAPING_DPT_TBL_DW_SIZE];
};

_Static_assert(sizeof(union nbl_shaping_dpt_tbl) ==
	       NBL_SHAPING_DPT_TBL_STRIDE,
	       "nbl_shaping_dpt_tbl size must match SHAPING stride");

#endif /* NBL_SHAPING_LAYOUT_H */
