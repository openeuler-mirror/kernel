/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_RXP_LAYOUT_H
#define NBL_RXP_LAYOUT_H

#include <linux/types.h>

#define NBL_RXP_RNRTIME_SET_OFF			0x013c
#define NBL_RXP_SET_SLOW_PATH_EN_OFF		0x01c0

#define NBL_RXP_TIMEVAL_U1M			3 /* 1-5M */
#define NBL_RXP_TIMEVAL_U5M			4 /* 5-10M */
#define NBL_RXP_TIMEVAL_U10M			5 /* 10-20M */
#define NBL_RXP_TIMEVAL_U20M			6 /* 20-30M */
#define NBL_RXP_TIMEVAL_U30M			7 /* 30-40M */
#define NBL_RXP_TIMEVAL_U100M			8 /* 40-200M */
#define NBL_RXP_TIMEVAL_U200M			9 /* > 200M */

#define NBL_RXP_FREQ_5M				5
#define NBL_RXP_FREQ_10M			10
#define NBL_RXP_FREQ_20M			20
#define NBL_RXP_FREQ_30M			30
#define NBL_RXP_FREQ_100M			100
#define NBL_RXP_FREQ_200M			200

#define NBL_RXP_REG_ADDR(base, off)		((base) + (off))

union nbl_rxp_rnrtime_set_reg {
	struct {
		u32 rnrtime_lsb : 4;
		u32 rsv0 : 28;
	};
	u32 data;
};

#endif /* NBL_RXP_LAYOUT_H */
