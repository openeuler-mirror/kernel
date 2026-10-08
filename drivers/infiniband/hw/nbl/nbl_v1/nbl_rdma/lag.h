/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2023, NEBULARMATRIX */

#ifndef NBL_LAG_V1_H
#define NBL_LAG_V1_H

#define NBL_REG_TXP_BASE_ADDR	0x01130000
#define NBL_REG_TXP_LAG_CFG_0	(NBL_REG_TXP_BASE_ADDR + 0x0430)
#define NBL_REG_TXP_LAG_CFG_1	(NBL_REG_TXP_BASE_ADDR + 0x0434)
#define NBL_REG_TXP_LAG_EN		(NBL_REG_TXP_BASE_ADDR + 0x0438)

#define NBL_MAX_LAG_ID		1
#define NBL_MAX_PORT_ID		3

#define NBL_CPU_FWD         0x3
#define NBL_ETH_DPORT       0x0

int nbl_init_lag_v1(struct nbl_device *nbl_dev,
			struct nbl_core_export *core_info);
void nbl_deinit_lag_v1(struct nbl_device *nbl_dev,
			   struct nbl_core_export *core_info);

#endif /* NBL_LAG_V1_H */
