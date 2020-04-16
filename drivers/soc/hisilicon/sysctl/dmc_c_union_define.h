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

#ifndef __DMC_C_UNION_DEFINE_H__
#define __DMC_C_UNION_DEFINE_H__

/* Define the union dmc_ddrc_u_cfg_ecc */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int ecc_en : 1   ; /* [0]  */
		unsigned int reserved_0		 : 3   ; /* [3..1]  */
		unsigned int eccwb_en : 1   ; /* [4]  */
		unsigned int reserved_1		 : 3   ; /* [7..5]  */
		unsigned int ecc_byp : 1   ; /* [8]  */
		unsigned int ecc_msk : 1   ; /* [9]  */
		unsigned int reserved_2		 : 2   ; /* [11..10]  */
		unsigned int ras_en : 1   ; /* [12]  */
		unsigned int ras_bps : 1   ; /* [13]  */
		unsigned int poison_en : 1   ; /* [14]  */
		unsigned int poison_chk_type : 1   ; /* [15]  */
		unsigned int reserved_3		 : 16  ; /* [31..16]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} dmc_ddrc_u_cfg_ecc;

#endif /* __DMC_C_UNION_DEFINE_H__ */
