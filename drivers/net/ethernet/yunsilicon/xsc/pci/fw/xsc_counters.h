/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_COUNTERS_H__
#define __XSC_COUNTERS_H__

/* From E-tile Hard User Guide */
#define NIF_ETH_TX_PFC_LOW        0x83c
#define NIF_ETH_TX_PFC_HIGH       0x83d
#define NIF_ETH_RX_PFC_LOW        0x93c
#define NIF_ETH_RX_PFC_HIGH       0x93d
#define NIF_ETH_TX_CNTR_CONFIG    0x845
#define NIF_ETH_RX_CNTR_CONFIG    0x945
#define NIF_ETH_RX_FCSERR_LOW     0x904
#define NIF_ETH_RX_FCSERR_HIGH    0x905

#define XSC_CNT_WIDTH_32_BIT    32
#define XSC_CNT_WIDTH_64_BIT    64
#define XSC_CNT_MASK_32    0xffffffff
#define XSC_CNT_MASK_64    0xffffffffffffffff

struct cnt_value_64 {
	u32 va_l;
	u32 va_h;
};

struct cnt_value_96 {
	u32 va_l;
	u32 va_m;
	u32 va_h;
};

enum {
	XSC_CNT_TYPE_TX_PAUSE = 0,
	XSC_CNT_TYPE_RX_PAUSE,
};

#endif
