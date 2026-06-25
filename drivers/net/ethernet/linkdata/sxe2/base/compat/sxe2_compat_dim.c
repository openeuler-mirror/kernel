// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat_dim.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include "sxe2_compat_dim.h"
#ifdef NEED_COMPAT_DIM
#include <linux/ktime.h>
#include <linux/time64.h>

bool dim_on_top(struct dim *dim)
{
	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
	case DIM_PARKING_TIRED:
		return true;
	case DIM_GOING_RIGHT:
		return (dim->steps_left > 1) && (dim->steps_right == 1);
	default:
		return (dim->steps_right > 1) && (dim->steps_left == 1);
	}
}

void dim_turn(struct dim *dim)
{
	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
	case DIM_PARKING_TIRED:
		break;
	case DIM_GOING_RIGHT:
		dim->tune_state = DIM_GOING_LEFT;
		dim->steps_left = 0;
		break;
	case DIM_GOING_LEFT:
		dim->tune_state = DIM_GOING_RIGHT;
		dim->steps_right = 0;
		break;
	}
}

void dim_park_on_top(struct dim *dim)
{
	dim->steps_right  = 0;
	dim->steps_left   = 0;
	dim->tired        = 0;
	dim->tune_state   = DIM_PARKING_ON_TOP;
}

void dim_park_tired(struct dim *dim)
{
	dim->steps_right  = 0;
	dim->steps_left   = 0;
	dim->tune_state   = DIM_PARKING_TIRED;
}

void dim_calc_stats(struct dim_sample *start, const struct dim_sample *end,
		    struct dim_stats *curr_stats)
{
	u32 delta_us = ktime_us_delta(end->time, start->time);
	u32 npkts = BIT_GAP(BITS_PER_TYPE(u32), end->pkt_ctr, start->pkt_ctr);
	u32 nbytes = BIT_GAP(BITS_PER_TYPE(u32), end->byte_ctr,
			     start->byte_ctr);
	u32 ncomps = BIT_GAP(BITS_PER_TYPE(u32), end->comp_ctr,
			     start->comp_ctr);

	if (!delta_us)
		return;

	curr_stats->ppms = DIV_ROUND_UP(npkts * USEC_PER_MSEC, delta_us);
	curr_stats->bpms = DIV_ROUND_UP(nbytes * USEC_PER_MSEC, delta_us);
	curr_stats->epms = DIV_ROUND_UP(DIM_NEVENTS * USEC_PER_MSEC,
					delta_us);
	curr_stats->cpms = DIV_ROUND_UP(ncomps * USEC_PER_MSEC, delta_us);
	if (curr_stats->epms != 0)
		curr_stats->cpe_ratio = DIV_ROUND_DOWN_ULL(curr_stats->cpms * 100,
							   curr_stats->epms);
	else
		curr_stats->cpe_ratio = 0;
}

static int net_dim_step(struct dim *dim)
{
	if (dim->tired == (NET_DIM_PARAMS_NUM_PROFILES * 2))
		return DIM_TOO_TIRED;

	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
	case DIM_PARKING_TIRED:
		break;
	case DIM_GOING_RIGHT:
		if (dim->profile_ix == (NET_DIM_PARAMS_NUM_PROFILES - 1))
			return DIM_ON_EDGE;
		dim->profile_ix++;
		dim->steps_right++;
		break;
	case DIM_GOING_LEFT:
		if (dim->profile_ix == 0)
			return DIM_ON_EDGE;
		dim->profile_ix--;
		dim->steps_left++;
		break;
	}

	dim->tired++;
	return DIM_STEPPED;
}

static void net_dim_exit_parking(struct dim *dim)
{
	dim->tune_state = dim->profile_ix ? DIM_GOING_LEFT : DIM_GOING_RIGHT;
	net_dim_step(dim);
}

static int net_dim_stats_compare(struct dim_stats *curr,
				 struct dim_stats *prev)
{
	if (!prev->bpms)
		return curr->bpms ? DIM_STATS_BETTER : DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->bpms, prev->bpms))
		return (curr->bpms > prev->bpms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	if (!prev->ppms)
		return curr->ppms ? DIM_STATS_BETTER :
				    DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->ppms, prev->ppms))
		return (curr->ppms > prev->ppms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	if (!prev->epms)
		return DIM_STATS_SAME;

	if (IS_SIGNIFICANT_DIFF(curr->epms, prev->epms))
		return (curr->epms < prev->epms) ? DIM_STATS_BETTER :
						   DIM_STATS_WORSE;

	return DIM_STATS_SAME;
}

static bool net_dim_decision(struct dim_stats *curr_stats, struct dim *dim)
{
	int prev_state = dim->tune_state;
	int prev_ix = dim->profile_ix;
	int stats_res;
	int step_res;

	switch (dim->tune_state) {
	case DIM_PARKING_ON_TOP:
		stats_res = net_dim_stats_compare(curr_stats,
						  &dim->prev_stats);
		if (stats_res != DIM_STATS_SAME)
			net_dim_exit_parking(dim);
		break;

	case DIM_PARKING_TIRED:
		dim->tired--;
		if (!dim->tired)
			net_dim_exit_parking(dim);
		break;

	case DIM_GOING_RIGHT:
	case DIM_GOING_LEFT:
		stats_res = net_dim_stats_compare(curr_stats,
						  &dim->prev_stats);
		if (stats_res != DIM_STATS_BETTER)
			dim_turn(dim);

		if (dim_on_top(dim)) {
			dim_park_on_top(dim);
			break;
		}

		step_res = net_dim_step(dim);
		switch (step_res) {
		case DIM_ON_EDGE:
			dim_park_on_top(dim);
			break;
		case DIM_TOO_TIRED:
			dim_park_tired(dim);
			break;
		}

		break;
	}

	if (prev_state != DIM_PARKING_ON_TOP ||
	    dim->tune_state != DIM_PARKING_ON_TOP)
		dim->prev_stats = *curr_stats;

	return dim->profile_ix != prev_ix;
}

void net_dim(struct dim *dim, const struct dim_sample end_sample)
{
	struct dim_stats curr_stats;
	u16 nevents;

	switch (dim->state) {
	case DIM_MEASURE_IN_PROGRESS:
		nevents = BIT_GAP(BITS_PER_TYPE(u16),
				  end_sample.event_ctr,
				  dim->start_sample.event_ctr);
		if (nevents < DIM_NEVENTS)
			break;
		dim_calc_stats(&dim->start_sample, &end_sample, &curr_stats);
		if (net_dim_decision(&curr_stats, dim)) {
			dim->state = DIM_APPLY_NEW_PROFILE;
			schedule_work(&dim->work);
			break;
		}
		fallthrough;
	case DIM_START_MEASURE:
		dim_update_sample(end_sample.event_ctr, end_sample.pkt_ctr,
				  end_sample.byte_ctr, &dim->start_sample);
		dim->state = DIM_MEASURE_IN_PROGRESS;
		break;
	case DIM_APPLY_NEW_PROFILE:
		break;
	}
}
#endif

