/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_HW_PTP_H_
#define _MCE_HW_PTP_H_
void n20_get_systime(struct mce_hw *hw, u64 *systime);
int n20_ptp_init_counter(struct mce_hw *hw);
int n20_init_systime(struct mce_hw *hw, u32 sec, u32 nsec);
int n20_adjust_systime(struct mce_hw *hw, u32 sec, u32 nsec, int add_sub);
int n20_adjfine(struct mce_hw *hw, long scaled_ppm);
int n20_ptp_set_ts_config(struct mce_hw *hw, struct hwtstamp_config *config);
int n20_ptp_tx_status(struct mce_hw *hw);
int n20_ptp_tx_stamp(struct mce_hw *hw, u64 *sec, u64 *nsec);

#endif
