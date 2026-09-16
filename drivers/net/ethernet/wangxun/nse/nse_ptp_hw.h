/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_PTP_HW_H_
#define _NSE_PTP_HW_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include <linux/highuid.h>

bool nse_ptp_lock(struct nse_hw *hw);
void nse_ptp_unlock(struct nse_hw *hw);
enum nse_status nse_ptp_init_time(struct nse_hw *hw, struct timespec64 *ts);
enum nse_status nse_ptp_write_incval_sec_subnsec(struct nse_hw *hw,
						 u32 nsec_part, u32 subnsec_part);
enum nse_status nse_ptp_write_incval_sec_subnsec_locked(struct nse_hw *hw,
							u32 nsec_part, u32 subnsec_part);
enum nse_status nse_ptp_write_incval_raw_locked(struct nse_hw *hw, u32 raw_value);
enum nse_status nse_ptp_write_addend(struct nse_hw *hw, u32 addend);
enum nse_status nse_ptp_write_addend_locked(struct nse_hw *hw, u32 addend);
enum nse_status nse_ptp_adj_clock(struct nse_hw *hw, s64 adj);
enum nse_status
nse_read_phy_tstamp(struct nse_hw *hw, u8 idx, u32 *sec_part, u32 *nsec_part);
enum nse_status
nse_clear_phy_tstamp(struct nse_hw *hw, u8 idx);
enum nse_status
nse_clear_all_phy_tstamp(struct nse_hw *hw);

enum nse_status nse_ptp_init_phc(struct nse_hw *hw);

#endif /* _NSE_PTP_HW_H_ */

