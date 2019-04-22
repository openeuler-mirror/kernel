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
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#ifndef __ARM_RAS_C_UNION_DEFINE_H__
#define __ARM_RAS_C_UNION_DEFINE_H__

/* Define the union arer_u_err_fr_l */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int err_fr_ed : 2   ; /* [1..0]  */
		unsigned int reserved_0			: 2   ; /* [3..2]  */
		unsigned int err_fr_ui : 2   ; /* [5..4]  */
		unsigned int err_fr_fi : 2   ; /* [7..6]  */
		unsigned int err_fr_ue : 2   ; /* [9..8]  */
		unsigned int err_fr_cfi : 2   ; /* [11..10]  */
		unsigned int err_fr_cec : 3   ; /* [14..12]  */
		unsigned int err_fr_rp : 1   ; /* [15]  */
		unsigned int err_fr_dui : 2   ; /* [17..16]  */
		unsigned int err_fr_ceo : 2   ; /* [19..18]  */
		unsigned int reserved_1			: 12  ; /* [31..20]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} arer_u_err_fr_l;

/* Define the union arer_u_err_ctlr_l */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int err_ctrl_ed : 1   ; /* [0]  */
		unsigned int reserved_0			: 1   ; /* [1]  */
		unsigned int err_ctrl_ui : 1   ; /* [2]  */
		unsigned int err_ctrl_fi : 1   ; /* [3]  */
		unsigned int err_ctrl_ue : 1   ; /* [4]  */
		unsigned int reserved_1			: 3   ; /* [7..5]  */
		unsigned int err_ctrl_cfi : 1   ; /* [8]  */
		unsigned int reserved_2			: 1   ; /* [9]  */
		unsigned int err_ctrl_dui : 1   ; /* [10]  */
		unsigned int reserved_3			: 21  ; /* [31..11]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;

} arer_u_err_ctlr_l;

/* Define the union arer_u_err_status_l */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int err_status_serr : 8   ; /* [7..0]  */
		unsigned int err_status_ierr : 8   ; /* [15..8]  */
		unsigned int reserved_0			: 4   ; /* [19..16]  */
		unsigned int err_status_uet : 2   ; /* [21..20]  */
		unsigned int err_status_pn : 1   ; /* [22]  */
		unsigned int err_status_de : 1   ; /* [23]  */
		unsigned int err_status_ce : 2   ; /* [25..24]  */
		unsigned int err_status_mv : 1   ; /* [26]  */
		unsigned int err_status_of : 1   ; /* [27]  */
		unsigned int err_status_er : 1   ; /* [28]  */
		unsigned int err_status_ue : 1   ; /* [29]  */
		unsigned int err_status_v : 1   ; /* [30]  */
		unsigned int err_status_av : 1   ; /* [31]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;

} arer_u_err_status_l;

/* Define the union arer_u_err_addr_h */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int err_addr_paddr_h : 24  ; /* [23..0]  */
		unsigned int reserved_0			: 5   ; /* [28..24]  */
		unsigned int err_addr_ai : 1   ; /* [29]  */
		unsigned int err_addr_si : 1   ; /* [30]  */
		unsigned int err_addr_ns : 1   ; /* [31]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;

} arer_u_err_addr_h;

/* Define the global struct */
typedef struct {
	volatile arer_u_err_fr_l arer_err_fr_l;
	volatile unsigned int arer_err_fr_h;
	volatile arer_u_err_ctlr_l arer_err_ctlr_l;
	volatile unsigned int arer_err_ctlr_h;
	volatile arer_u_err_status_l arer_err_status_l;
	volatile unsigned int arer_err_status_h;
	volatile unsigned int arer_err_addr_l;
	volatile arer_u_err_addr_h arer_err_addr_h;
	volatile unsigned int arer_err_misc0_l;
	volatile unsigned int arer_err_misc0_h;
	volatile unsigned int arer_err_misc1_l;
	volatile unsigned int arer_err_misc1_h;

} S_ARM_RAS_REGS_TYPE;

/* Declare the struct pointor of the module ARM_RAS */
extern volatile S_ARM_RAS_REGS_TYPE *gopARM_RASAllReg;

/* Declare the functions that set the member value */
int iSetARER_ERR_CTLR_Lerr_ctrl_ed(unsigned int uerr_ctrl_ed);
int iSetARER_ERR_CTLR_Lerr_ctrl_ui(unsigned int uerr_ctrl_ui);
int iSetARER_ERR_CTLR_Lerr_ctrl_fi(unsigned int uerr_ctrl_fi);
int iSetARER_ERR_CTLR_Lerr_ctrl_ue(unsigned int uerr_ctrl_ue);
int iSetARER_ERR_CTLR_Lerr_ctrl_cfi(unsigned int uerr_ctrl_cfi);
int iSetARER_ERR_CTLR_Lerr_ctrl_dui(unsigned int uerr_ctrl_dui);

#endif /* __ARM_RAS_C_UNION_DEFINE_H__ */
