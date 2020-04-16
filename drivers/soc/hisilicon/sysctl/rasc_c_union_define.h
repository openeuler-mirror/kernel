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

#ifndef __RASC_C_UNION_DEFINE_H__
#define __RASC_C_UNION_DEFINE_H__

/* Define the union ddrc_rasc_u_cfg_clr */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int all_errcnt_clr : 1   ; /* [0]  */
		unsigned int ha_errcnt_clr : 1   ; /* [1]  */
		unsigned int vls_errcnt_clr : 1   ; /* [2]  */
		unsigned int rvls_errcnt_clr : 1   ; /* [3]  */
		unsigned int pa_errcnt_clr : 1   ; /* [4]  */
		unsigned int sp_errcnt_clr : 1   ; /* [5]  */
		unsigned int sp_rberrcnt_clr : 1   ; /* [6]  */
		unsigned int reserved_0		 : 1   ; /* [7]  */
		unsigned int corr_errcnt_clr : 1   ; /* [8]  */
		unsigned int uncorr_errcnt_clr : 1   ; /* [9]  */
		unsigned int reserved_1		 : 22  ; /* [31..10]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} ddrc_rasc_u_cfg_clr;

/* Define the union ddrc_rasc_u_cfg_info_rnk */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int idx_rnk : 4   ; /* [3..0]  */
		unsigned int rnk_sel_mode : 1   ; /* [4]  */
		unsigned int reserved_0		 : 27  ; /* [31..5]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} ddrc_rasc_u_cfg_info_rnk;

/* Define the union ddrc_rasc_u_his_ha_rankcnt_inf */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int ha_rnk_funnel_corr_cnt : 16  ; /* [15..0]  */
		unsigned int ha_rnk_corr_cnt : 16  ; /* [31..16]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} ddrc_rasc_u_his_ha_rankcnt_inf;

#endif /* __RASC_C_UNION_DEFINE_H__ */
