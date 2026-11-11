// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/kernel.h>

#include "nse_type.h"
#include "nse_sched_internal.h"

u16 nse_sched_factor_val_to_idx(struct nse_port_info *pi, u16 fint, u16 dfint, u16 dfdf)
{
	u16 min, max, mid;
	u64 target_param = ((u64)fint << 32) |
						((u64)dfint << 16) |
						((u64)dfdf);
	bool found_exact = false;

	if (!target_param)
		return 0;
	else if (target_param > pi->sched_info.factor_tbl[0])
		return 1;
	else if (target_param < pi->sched_info.factor_tbl[(NSE_SCHED_FACTOR_TBL_LEN - 1)])
		return NSE_SCHED_FACTOR_TBL_LEN;

	min = 0;
	max = NSE_SCHED_FACTOR_TBL_LEN - 1;

	while (min <= max) {
		mid = (min + max) / 2;

		if (target_param == pi->sched_info.factor_tbl[mid]) {
			found_exact = true;
			break;
		} else if (target_param > pi->sched_info.factor_tbl[mid]) {
			max = mid - 1;
		} else {
			min = mid + 1;
		}
	}

	if (found_exact)
		return mid + 1;
	else
		return min + 1;	/* no exact match, fall back to closest one */
}

void nse_sched_init_factor_tbl(struct nse_port_info *pi)
{
	struct nse_hw *hw = pi->hw;
	struct nse_sched_info *si = &pi->sched_info;

	unsigned int clock_in_mhz;
	unsigned int bandwidth_in_mbps;

	unsigned long long time_tick_multi_100;
	unsigned long long res, res_i, df, df_i, df_df;
	unsigned long long f_int, f_df_int, f_df_df;
	unsigned int i;
	u64 val64;

	si->max_bandwidth_per_lan_channel = hw->hw_conf.max_bandwidth_per_lan_channel;
	if (hw->is_only_lan_in_chan)
		si->max_bandwidth_per_lan_port = hw->hw_conf.max_bandwidth_per_lan_channel;
	else
		si->max_bandwidth_per_lan_port = hw->hw_conf.max_bandwidth_per_lan_channel / 2;

	clock_in_mhz = hw->hw_conf.main_clock_freq / 1000000;
	bandwidth_in_mbps = hw->hw_conf.max_bandwidth_per_lan_channel / 1000;

	time_tick_multi_100 = div_u64((unsigned long long)clock_in_mhz * 4096ULL *
				      8ULL * 100ULL, bandwidth_in_mbps);

	for (i = 1; i <= NSE_SCHED_FACTOR_TBL_LEN; i++) {
		res = div_u64((unsigned long long)NSE_SCHED_FACTOR_TBL_LEN * 10000ULL, i);

		f_int = div_u64(res, 10000);

		res_i = f_int * 10000ULL;

		df = (res - res_i) * time_tick_multi_100;

		f_df_int = div_u64(df, 10000 * 100);

		df_i = f_df_int * 10000ULL * 100ULL;

		df_df = (df - df_i);

		f_df_df = div_u64(df_df + 50000, 100 * 100);

		if (i == NSE_SCHED_FACTOR_TBL_LEN)	/* fix largest one, should be {1, 0, 0}*/
			f_df_df = 0;

		val64 = (f_int << 32) | (f_df_int << 16) | f_df_df;

		pi->sched_info.factor_tbl[i - 1] = val64;
	}
}
