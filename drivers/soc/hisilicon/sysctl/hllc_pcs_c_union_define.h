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

#ifndef __HLLC_PCS_C_UNION_DEFINE_H__
#define __HLLC_PCS_C_UNION_DEFINE_H__

/* Define the union pcs_u_tx_training_sts */
typedef union {
	/* Define the struct bits */
	struct {
		unsigned int tx_curr_st : 7   ; /* [6..0]  */
		unsigned int ts1_ack_send_over : 1   ; /* [7]  */
		unsigned int ts1_ack_received : 1   ; /* [8]  */
		unsigned int ts1_received : 1   ; /* [9]  */
		unsigned int ts0_ack_send_over : 1   ; /* [10]  */
		unsigned int ts0_ack_received : 1   ; /* [11]  */
		unsigned int ts0_received : 1   ; /* [12]  */
		unsigned int tx_training_succeed : 1   ; /* [13]  */
		unsigned int tx_training_done : 1   ; /* [14]  */
		unsigned int tx_training_over : 1   ; /* [15]  */
		unsigned int snd_training_done : 1   ; /* [16]  */
		unsigned int tx_asyn_fifo_full : 1   ; /* [17]  */
		unsigned int tx_asyn_fifo_afull : 1   ; /* [18]  */
		unsigned int tx_asyn_push_word_cnt : 5   ; /* [23..19]  */
		unsigned int reserved_0		 : 8   ; /* [31..24]  */
	} bits;

	/* Define an unsigned member */
	unsigned int u32;
} pcs_u_tx_training_sts;

#endif /* __HLLC_PCS_C_UNION_DEFINE_H__ */
