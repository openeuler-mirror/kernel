/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __HLLC_REGS_C_UNION_DEFINE_H__
#define __HLLC_REGS_C_UNION_DEFINE_H__

/* Define the union hllc_regs_u_inject_ecc_type */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int inject_ecc_err_type : 2   ; /* [1..0]  */
		unsigned int reserved_0		 : 30  ; /* [31..2]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_regs_u_inject_ecc_type;

/* Define the union hllc_regs_u_inject_ecc_en */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hydra_rx_inject_ecc_err_en : 3   ; /* [2..0]  */
		unsigned int reserved_0		 : 1   ; /* [3]  */
		unsigned int phy_tx_retry_inject_ecc_err_en : 1   ; /* [4]  */
		unsigned int reserved_1		 : 3   ; /* [7..5]  */
		unsigned int hydra_tx_inject_ecc_err_en : 3   ; /* [10..8]  */
		unsigned int reserved_2		 : 1   ; /* [11]  */
		unsigned int reserved_3		 : 20  ; /* [31..12]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_regs_u_inject_ecc_en;

#endif /* __HLLC_REGS_C_UNION_DEFINE_H__ */
