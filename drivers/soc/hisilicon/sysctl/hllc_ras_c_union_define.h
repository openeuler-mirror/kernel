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

#ifndef __HLLC_RAS_C_UNION_DEFINE_H__
#define __HLLC_RAS_C_UNION_DEFINE_H__

/* Define the union hllc_ras_u_err_misc1l */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hydra_tx_ch0_2bit_ecc_err : 1   ; /* [0]  */
		unsigned int hydra_tx_ch1_2bit_ecc_err : 1   ; /* [1]  */
		unsigned int hydra_tx_ch2_2bit_ecc_err : 1   ; /* [2]  */
		unsigned int phy_tx_retry_2bit_ecc_err : 1   ; /* [3]  */
		unsigned int hydra_rx_ch0_2bit_ecc_err : 1   ; /* [4]  */
		unsigned int hydra_rx_ch1_2bit_ecc_err : 1   ; /* [5]  */
		unsigned int hydra_rx_ch2_2bit_ecc_err : 1   ; /* [6]  */
		unsigned int reserved_0		 : 1   ; /* [7]  */
		unsigned int phy_rx_retry_ptr_err : 1   ; /* [8]  */
		unsigned int phy_tx_retry_buf_ptr_err : 1   ; /* [9]  */
		unsigned int phy_tx_retry_ptr_err : 1   ; /* [10]  */
		unsigned int reserved_1		 : 5   ; /* [15..11]  */
		unsigned int hydra_tx_ch0_ovf : 1   ; /* [16]  */
		unsigned int hydra_tx_ch1_ovf : 1   ; /* [17]  */
		unsigned int hydra_tx_ch2_ovf : 1   ; /* [18]  */
		unsigned int phy_tx_retry_buf_ovf : 1   ; /* [19]  */
		unsigned int hydra_rx_ch0_ovf : 1   ; /* [20]  */
		unsigned int hydra_rx_ch1_ovf : 1   ; /* [21]  */
		unsigned int hydra_rx_ch2_ovf : 1   ; /* [22]  */
		unsigned int reserved_2		 : 1   ; /* [23]  */
		unsigned int hydra_pcs_err0	 : 1   ; /* [24]  */
		unsigned int hydra_pcs_err1	 : 1   ; /* [25]  */
		unsigned int hydra_pcs_err2	 : 1   ; /* [26]  */
		unsigned int hydra_pcs_err3	 : 1   ; /* [27]  */
		unsigned int hydra_pcs_err4	 : 1   ; /* [28]  */
		unsigned int hydra_pcs_err5	 : 1   ; /* [29]  */
		unsigned int hydra_pcs_err6	 : 1   ; /* [30]  */
		unsigned int hydra_pcs_err7	 : 1   ; /* [31]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_ras_u_err_misc1l;

/* Define the union hllc_ras_u_err_misc1h */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int hydra_tx_ch0_1bit_ecc_err : 1   ; /* [0]  */
		unsigned int hydra_tx_ch1_1bit_ecc_err : 1   ; /* [1]  */
		unsigned int hydra_tx_ch2_1bit_ecc_err : 1   ; /* [2]  */
		unsigned int phy_tx_retry_1bit_ecc_err : 1   ; /* [3]  */
		unsigned int hydra_rx_ch0_1bit_ecc_err : 1   ; /* [4]  */
		unsigned int hydra_rx_ch1_1bit_ecc_err : 1   ; /* [5]  */
		unsigned int hydra_rx_ch2_1bit_ecc_err : 1   ; /* [6]  */
		unsigned int reserved_0		 : 1   ; /* [7]  */
		unsigned int phy_rx_flit_crc_err : 1   ; /* [8]  */
		unsigned int reserved_1		 : 23  ; /* [31..9]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} hllc_ras_u_err_misc1h;

#endif /* __C_UNION_DEFINE_HLLC_RAS_H__ */
