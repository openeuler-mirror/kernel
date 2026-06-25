/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_compat_dim.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_COMAPT_DIM_H_
#define _SXE2_COMAPT_DIM_H_

#ifdef NEED_COMPAT_DIM
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#define NET_DIM_PARAMS_NUM_PROFILES 5

#define IS_SIGNIFICANT_DIFF(val, ref) ({ \
	typeof(val) _val = (val); \
	typeof(ref) _ref = (ref); \
	(_ref != 0) ? ((((100UL * abs(_val - _ref))) / _ref) > 10) : 0; \
})

#define DIM_NEVENTS 64

#define BIT_GAP(bits, end, start) ({ \
	typeof(bits) _bits = (bits); \
	typeof(end) _end = (end); \
	typeof(start) _start = (start); \
	(((_end) - (_start)) + BIT_ULL(_bits)) & (BIT_ULL(_bits) - 1); \
})

struct dim_sample {
	ktime_t time;
	u32 pkt_ctr;
	u32 byte_ctr;
	u16 event_ctr;
	u32 comp_ctr;
};

struct dim_stats {
	int ppms;
	int bpms;
	int epms;
	int cpms;
	int cpe_ratio;
};

struct dim {
	u8 state;
	struct dim_stats prev_stats;
	struct dim_sample start_sample;
	struct dim_sample measuring_sample;
	struct work_struct work;
	void *priv;
	u8 profile_ix;
	u8 mode;
	u8 tune_state;
	u8 steps_right;
	u8 steps_left;
	u8 tired;
};

enum dim_tune_state {
	DIM_PARKING_ON_TOP,
	DIM_PARKING_TIRED,
	DIM_GOING_RIGHT,
	DIM_GOING_LEFT,
};

enum dim_stats_state {
	DIM_STATS_WORSE,
	DIM_STATS_SAME,
	DIM_STATS_BETTER,
};

enum dim_step_result {
	DIM_STEPPED,
	DIM_TOO_TIRED,
	DIM_ON_EDGE,
};

enum dim_cq_period_mode {
	DIM_CQ_PERIOD_MODE_START_FROM_EQE = 0x0,
	DIM_CQ_PERIOD_MODE_START_FROM_CQE = 0x1,
	DIM_CQ_PERIOD_NUM_MODES
};

enum dim_state {
	DIM_START_MEASURE,
	DIM_MEASURE_IN_PROGRESS,
	DIM_APPLY_NEW_PROFILE,
};

bool dim_on_top(struct dim *dim);

void dim_turn(struct dim *dim);

void dim_park_on_top(struct dim *dim);

void dim_park_tired(struct dim *dim);

void dim_calc_stats(struct dim_sample *start, const struct dim_sample *end,
		    struct dim_stats *curr_stats);

static inline void
dim_update_sample(u16 event_ctr, u64 packets, u64 bytes, struct dim_sample *s)
{
	s->time	     = ktime_get();
	s->pkt_ctr   = packets;
	s->byte_ctr  = bytes;
	s->event_ctr = event_ctr;
}

void net_dim(struct dim *dim, const struct dim_sample end_sample);
#endif
#endif

