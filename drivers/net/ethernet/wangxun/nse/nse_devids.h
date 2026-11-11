/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_DEVIDS_H_
#define _NSE_DEVIDS_H_

/* Device IDs */

/* Amber Series */
/* 2023.11.22 - today's HW image change PF to this, and 4001 become VF */
#define NSE_DEV_ID_AMBER_FPGA	0x4000
										/*  so 0x4001 as PF
										 * become deprecated
										 * now
										 */

#define NSE_DEV_ID_AMBER_FDBTACXX	0x4103		/* 2 x 100G QSFP */
#define NSE_DEV_ID_AMBER_FDBTACRX	0x4101		/* 2 x 100G QSFP */

#define NSE_DEV_ID_AMBER_DDATACRX	0x4025		/* 2 x 25G SFP */
#define NSE_DEV_ID_AMBER_DDATAIRX	0x4125		/* 2 x 25G SFP */

#define NSE_DEV_ID_AMBER_FQATACRX	0x4425		/* 4 x 25G SFP */

#define NSE_DEV_ID_AMBER_DQATACXX	0x4010		/* 4 x 10G SFP */

/* Moonstone Series */
#define NSE_DEV_ID_MOONSTONE	0x6000

#endif /* _NSE_DEVIDS_H_ */

