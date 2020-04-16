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

#ifndef __PA_C_UNION_DEFINE_H__
#define __PA_C_UNION_DEFINE_H__

/* Define the union pa_u_global_cfg */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int intlv_mode_cfg : 3   ; /* [2..0]  */
		unsigned int nimbus_extend_en_cfg : 1   ; /* [3]  */
		unsigned int rsv1				 : 4   ; /* [7..4]  */
		unsigned int wb_norely_en_cfg : 1   ; /* [8]  */
		unsigned int rsv2				 : 7   ; /* [15..9]  */
		unsigned int hydra_port_en_cfg : 3   ; /* [18..16]  */
		unsigned int rsv3				 : 1   ; /* [19]  */
		unsigned int ewa_dis_cfg : 1   ; /* [20]  */
		unsigned int rsv4				 : 3   ; /* [23..21]  */
		unsigned int dvm_retry_en_cfg : 1   ; /* [24]  */
		unsigned int rsv5				 : 3   ; /* [27..25]  */
		unsigned int compdata_err_poison_en : 1   ; /* [28]  */
		unsigned int reg_goto_pcie_en_cfg : 1   ; /* [29]  */
		unsigned int nc_lpid_seq_en_cfg : 1   ; /* [30]  */
		unsigned int nc_non_order_en_cfg : 1   ; /* [31]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} pa_u_global_cfg;

#endif /* __PA_C_UNION_DEFINE_H__ */
