/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_ETH_LAYOUT_H
#define NBL_ETH_LAYOUT_H

#include <linux/types.h>

/* Retry quanta values */
#define NBL_VAL_RETRY_QUANTA_DEFAULT 0xC792
#define NBL_VAL_RETRY_QUANTA_PFC 0x8000

/* Retry quanta offset from ETH base (V3) */
#define NBL_REG_ETH_BASE_OFFSET 0x200000

/* Register offsets from base */
#define NBL_ETH_PAUSE_PFC_EN_OFF	0x001c
#define NBL_ETH_PAUSE_PFC_EN_V4_OFF	0x00C0
#define NBL_ETH_RETRY_QUANTA_OFF		0x1830

/* Pause pfc en register address */
#define NBL_ETH_PAUSE_PFC_EN_ADDR(base) \
	((base) + NBL_ETH_PAUSE_PFC_EN_OFF)
#define NBL_ETH_PAUSE_PFC_EN_V4_ADDR(base) \
	((base) + NBL_ETH_PAUSE_PFC_EN_V4_OFF)

/* Retry quanta register address */
#define NBL_ETH_RETRY_QUANTA_ADDR(base) \
	((base) + NBL_REG_ETH_BASE_OFFSET + NBL_ETH_RETRY_QUANTA_OFF)

/* Absolute addresses (original names kept, bases from nbl_reg_base.h) */
#define NBL_REG_ETH0_PAUSE_PFC_EN \
	NBL_ETH_PAUSE_PFC_EN_ADDR(NBL_REG_ETH0_BASE_V3)
#define NBL_REG_ETH1_PAUSE_PFC_EN \
	NBL_ETH_PAUSE_PFC_EN_ADDR(NBL_REG_ETH1_BASE_V3)
#define NBL_REG_ETH0_RETRY_QUANTA \
	NBL_ETH_RETRY_QUANTA_ADDR(NBL_REG_ETH0_BASE_V3)
#define NBL_REG_ETH1_RETRY_QUANTA \
	NBL_ETH_RETRY_QUANTA_ADDR(NBL_REG_ETH1_BASE_V3)
#define NBL_REG_ETH0_PAUSE_PFC_EN_V4 \
	NBL_ETH_PAUSE_PFC_EN_V4_ADDR(NBL_REG_ETH0_BASE_V4)
#define NBL_REG_ETH1_PAUSE_PFC_EN_V4 \
	NBL_ETH_PAUSE_PFC_EN_V4_ADDR(NBL_REG_ETH1_BASE_V4)
#define NBL_REG_ETH2_PAUSE_PFC_EN_V4 \
	NBL_ETH_PAUSE_PFC_EN_V4_ADDR(NBL_REG_ETH2_BASE_V4)
#define NBL_REG_ETH3_PAUSE_PFC_EN_V4 \
	NBL_ETH_PAUSE_PFC_EN_V4_ADDR(NBL_REG_ETH3_BASE_V4)

/* eth_pause_pfc_en */
union eth_pause_pfc_en_table {
	u32 data[1];
	struct {
		u32 cfg_pause_en : 1;
		u32 cfg_pfc_en : 1;
		u32 rsv1 : 30;
	};
};

_Static_assert(sizeof(union eth_pause_pfc_en_table) == 4,
	       "eth_pause_pfc_en_table size must be 4 bytes");

/* eth_fc_cfg_table_v4 */
union eth_fc_cfg_table_v4 {
	u32 data[1];
	struct {
		u32 cfg_rx_pause_en : 1;
		u32 cfg_rx_pfc_en : 1;
		u32 cfg_tx_pause_en : 1;
		u32 cfg_tx_pfc_en : 1;
		u32 rsv1 : 12;
		u32 cfg_force_pause : 9;
		u32 rsv2 : 7;
	};
};

_Static_assert(sizeof(union eth_fc_cfg_table_v4) == 4,
	       "eth_fc_cfg_table_v4 size must be 4 bytes");

#endif /* NBL_ETH_LAYOUT_H */
