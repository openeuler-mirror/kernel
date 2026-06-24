// SPDX-License-Identifier: GPL-2.0
/*
 * DisplayPort Link training and link policy functions
 *
 * Copyright (c) 2019-2026, New H3C Semiconductor Technologies Co., Ltd.
 */

#include <drm/drm_print.h>
#include <drm/drm_probe_helper.h>
#include "egt_dp.h"
#include "egt_dp_phy.h"

#define SET_BIT_FIELD(val, field, shift, mask) (((val) & (~mask)) | ((field) << (shift)))

struct egt_tr_patttern_mode pat_mode[] = {
	{DP_TRAINING_PATTERN_DISABLE,	EGT_TX_TP_0},
	{DP_TRAINING_PATTERN_1,			EGT_TX_TP_1},
	{DP_TRAINING_PATTERN_2,			EGT_TX_TP_2},
	{DP_TRAINING_PATTERN_3,			EGT_TX_TP_3},
	{DP_TRAINING_PATTERN_4,			EGT_TX_TP_4},
};

static int egt_dpcd_read(struct egt_displayport *dp)
{
	int ret = 0;

	ret = drm_dp_dpcd_read(&dp->aux, DP_DPCD_REV, dp->dpcd, sizeof(dp->dpcd));
	if (ret < 0) {
		pr_warn("drm dpcd read fail 1");
		ret = drm_dp_dpcd_read(&dp->aux, DP_DPCD_REV, dp->dpcd, sizeof(dp->dpcd));
		if (ret < 0)
			pr_warn("drm dpcd read fail 2");
	}

	if (dp->dpcd[DP_MAX_LINK_RATE] != DP_LINK_BW_5_4 &&
		dp->dpcd[DP_MAX_LINK_RATE] != DP_LINK_BW_2_7 &&
		dp->dpcd[DP_MAX_LINK_RATE] != DP_LINK_BW_1_62)
		dp->dpcd[DP_MAX_LINK_RATE] = DP_LINK_BW_5_4;

	return ret;
}

static void egt_dp_reconfig_analog(struct egt_displayport *dp)
{
	egt_dp_write(1, DP_SOURCE_RECONFIG, dp);
}

static void egt_dp_reconfig_link_rate(struct egt_displayport *dp)
{
	egt_dp_write(2, DP_SOURCE_RECONFIG, dp);
}

static u32 egt_caclu_cr_time(struct egt_displayport *dp, u32 type)
{
	u32 time = 0;
	u32 val = 0;

	val = (dp->dpcd[DP_TRAINING_AUX_RD_INTERVAL] & DP_TRAINING_AUX_RD_MASK);
	if ((val > 0) && (val < 5)) {
		if (dp->dpcd[DP_DPCD_REV] < DP_DPCD_REV_14)
			time = 4000 * val;
	}

	if (type == EGT_TX_CE_TIME) {
		val = (dp->dpcd[DP_TRAINING_AUX_RD_INTERVAL] & DP_TRAINING_AUX_RD_MASK);
		if ((val > 0) && (val < 5))
			time = 4000 * val;
		else
			time = 400;
	}

	return time;

}

static int egt_dp_set_sink_d0(struct egt_displayport *dp)
{
	int ret = 0;
	int i = 0;
	u8 value = 0;

	/* Sink power cycle */
	for (i = 0; i < 3; i++) {
		ret = drm_dp_dpcd_readb(&dp->aux, DP_SET_POWER, &value);
		value = SET_BIT_FIELD(value, DP_SET_POWER_D3, 0, DP_SET_POWER_MASK);
		ret = drm_dp_dpcd_writeb(&dp->aux, DP_SET_POWER, value);
		usleep_range(300, 400);

		value = SET_BIT_FIELD(value, DP_SET_POWER_D0, 0, DP_SET_POWER_MASK);
		ret = drm_dp_dpcd_writeb(&dp->aux, DP_SET_POWER, value);
		usleep_range(300, 400);
		ret = drm_dp_dpcd_writeb(&dp->aux, DP_SET_POWER, value);
		if (ret == 1)
			break;
		usleep_range(3000, 4000);
	}

	if (ret < 0) {
		dev_err(dp->dev, "DP AUX failed\n");
		return ret;
	}

	return 0;
}

static int egt_dp_set_fec(struct egt_displayport *dp)
{
	int retry = 10;
	int ret = 0;
	u32 value = 0;

	value = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	value &= ~(BIT(29) | BIT(4));
	egt_dp_write(value, DP_SOURCE_TX_CONTROL, dp);

	value = BIT(4);
	while (value & BIT(4) && retry--) {
		value = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
		usleep_range(100, 200);
	}

	if (retry < 0) {
		pr_err("FEC disable timeout\n");
		return -ETIMEDOUT;
	}

	return ret;
}

static int egt_dp_check_link_ready(struct egt_displayport *dp)
{
	int ret = 0;
	int try = 0;
	u8 link_sts[DP_LINK_STATUS_SIZE] = {0};

	for (try = 0; try < 6; try++) {
		ret = drm_dp_dpcd_read_link_status(&dp->aux, link_sts);
		if (ret < 0)
			return ret;

		pr_debug("training link status: [%#x] [%#x] [%#x] [%#x] [%#x] [%#x]\n",
					link_sts[0], link_sts[1], link_sts[2],
					link_sts[3], link_sts[4], link_sts[5]);

		if (drm_dp_clock_recovery_ok(link_sts, dp->lane_cnt) &&
			drm_dp_channel_eq_ok(link_sts, dp->lane_cnt))
			return 0;
	}

	return -EINVAL;
}

static int egt_dp_dpcd_cap_config(struct egt_displayport *dp)
{
	int ret = 0;
	u8 msg[1] = {0};
	u8 data = 0;
	bool enhanced = 0;
	u32 txctlreg = 0;

	if (dp->dpcd[DP_DPCD_REV] >= EGT_TX_V1_2) {
		ret = drm_dp_dpcd_read(&dp->aux, DP_MSTM_CAP, msg, 1);
		if (ret) {
			if (msg[0] & DP_MST_CAP) {
				dev_dbg(dp->dev, "sink is MST capable\n");
				/* Disable MST mode */
				ret = drm_dp_dpcd_writeb(&dp->aux, DP_MSTM_CTRL, 0);
				if (ret < 0) {
					dev_dbg(dp->dev, "DPCD write failed");
					return ret;
				}
			}
		}
	}

	drm_dp_dpcd_readb(&dp->aux, DP_DOWNSPREAD_CTRL, &data);
	data &= ~DP_SPREAD_AMP_0_5;
	drm_dp_dpcd_writeb(&dp->aux, DP_DOWNSPREAD_CTRL, data);

	drm_dp_dpcd_readb(&dp->aux, DP_LANE_COUNT_SET, &data);
	enhanced = drm_dp_enhanced_frame_cap(dp->dpcd);
	if (enhanced) {
		txctlreg = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
		txctlreg |= EGT_TX_ENHANCED_MASK;
		egt_dp_write(txctlreg, DP_SOURCE_TX_CONTROL, dp);

		data |= DP_LANE_COUNT_ENHANCED_FRAME_EN;
	}
	ret = drm_dp_dpcd_writeb(&dp->aux, DP_LANE_COUNT_SET, data);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd lane count failed\n");
		return -EIO;
	}

	ret = drm_dp_dpcd_writeb(&dp->aux, DP_MAIN_LINK_CHANNEL_CODING_SET, DP_SET_ANSI_8B10B);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd 8B10B failed\n");
		return -EIO;
	}

	return ret;
}

static int egt_dp_check_cr_ready(struct egt_displayport *dp,
					u8 num_lanes, u8 link_sts[DP_LINK_STATUS_SIZE])
{
	struct egt_displayport_link_config *link_config = &dp->train_cfg;

	switch (num_lanes) {
	case 0x1:
		if (!(link_sts[0] & 0x01)) {
			link_config->cr_done_cnt = 0x0;
			return -EIO;
		}
		link_config->cr_done_cnt = 0x1;
		fallthrough;
	default:
		pr_debug("DP-TX only have 1 lane\n");
		break;
	}

	pr_debug("check cr ready\n");

	return 0;
}

static int egt_dp_set_volt_pre(struct egt_displayport *dp, u8 link_sts[6])
{
	u8 volt = 0;
	u8 pre = 0;
	u8 get_v = 0;
	u8 get_p = 0;
	u8 i = 0;
	u32 reg = 0;
	ssize_t ret = 0;

	ret = drm_dp_dpcd_write(&dp->aux, DP_TRAINING_LANE0_SET, dp->train_set, dp->lane_cnt);
	if (ret < 0)
		return ret;

	reg = DP_SOURCE_PRE_VOLT0 + i * 4;
	get_v = drm_dp_get_adjust_request_voltage(link_sts, i);
	get_p = drm_dp_get_adjust_request_pre_emphasis(link_sts, i);

	if (get_v > volt)
		volt = get_v;

	if (get_p > pre)
		pre = get_p;

	pr_debug("tx-reg: 0x%08x, val = 0x%08x\n", reg, pre >> 1 | get_v);
	egt_dp_write(pre >> 1 | get_v, reg, dp);

	egt_dp_reconfig_analog(dp);

	return 0;
}

static ssize_t egt_dp_update_train_vp(struct egt_displayport *dp, u8 v, u8 p)
{
	ssize_t ret = 0;
	int i = 0;

	if (v >= DP_TRAIN_VOLTAGE_SWING_LEVEL_3)
		v |= DP_TRAIN_MAX_SWING_REACHED;

	if (p >= DP_TRAIN_PRE_EMPH_LEVEL_2)
		p |= DP_TRAIN_MAX_PRE_EMPHASIS_REACHED;

	for (i = 0; i < dp->lane_cnt; i++)
		dp->train_set[i] = v | p;

	ret = drm_dp_dpcd_write(&dp->aux, DP_TRAINING_LANE0_SET, dp->train_set, dp->lane_cnt);
	if (ret < 0)
		return ret;

	return ret;
}

static int egt_dp_set_rate(struct egt_displayport *dp, u8 rate)
{
	int ret = 0;
	int try = 0;
	u32 val = 0;
	u32 sts = 0;

	for (try = 0; try <= 5; try++) {
		sts = egt_dp_read(DP_SOURCE_TX_STATUS, dp) & EGT_TX_HPD_LEVEL;
		if (sts != 0)
			break;

		usleep_range(1000, 1100);
	}

	if (try > 5) {
		dev_dbg(dp->dev, "dp is not connected");
		return connector_status_disconnected;
	}

	dp->bw_code = rate;

	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val = SET_BIT_FIELD(val, rate, 21, EGT_TX_LINK_RATE_MASK);
	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);
	pr_debug("val[0x%08x] = 0x%08x\n", DP_SOURCE_TX_CONTROL, val);

	egt_dp_reconfig_link_rate(dp);

	ret = drm_dp_dpcd_writeb(&dp->aux, DP_LINK_BW_SET, rate);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd rate failed\n");
		return ret;
	}

	egt_dp_set_phy(dp, rate);

	return 0;
}

static int egt_dp_set_num_lanes(struct egt_displayport *dp, u8 num_lanes)
{
	int ret = 0;
	u8 val = 0;
	u32 reg_data = 0;

	if (num_lanes > 1)
		return -EIO;

	dp->lane_cnt = num_lanes;

	reg_data = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	reg_data = SET_BIT_FIELD(reg_data, (num_lanes & 0x07), 5, EGT_TX_LANE_CNT_MASK);
	egt_dp_write(reg_data, DP_SOURCE_TX_CONTROL, dp);

	pr_debug("num_lanes is %d, reg_val is 0x%x\n", num_lanes, reg_data);

	ret = drm_dp_dpcd_readb(&dp->aux, DP_LANE_COUNT_SET, &val);
	if (ret < 0) {
		dev_err(dp->dev, "read dpcd lane count failed");
		return ret;
	}

	val &= ~0x1F;
	val |= dp->lane_cnt;
	ret = drm_dp_dpcd_writeb(&dp->aux, DP_LANE_COUNT_SET, val);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd lane count failed\n");
		return ret;
	}

	return 0;
}

static int egt_set_config(struct egt_displayport *dp, u8 bw_code, u8 num_lanes)
{
	int ret = 0;

	ret = egt_dp_set_rate(dp, bw_code);
	if (ret < 0) {
		dev_err(dp->dev, "set link rate failed\n");
		return ret;
	}

	ret = egt_dp_set_num_lanes(dp, num_lanes);
	if (ret < 0) {
		dev_err(dp->dev, "set lane count failed\n");
		return ret;
	}

	return ret;
}

static int egt_dp_change_rate(struct egt_displayport *dp)
{
	int ret = 0;
	u8 bw_code = 0;

	switch (dp->bw_code) {
	case DP_LINK_BW_5_4:
		bw_code = DP_LINK_BW_2_7;
		break;
	case DP_LINK_BW_2_7:
		bw_code = DP_LINK_BW_1_62;
		break;
	default:
		pr_debug("can not adj lane cout\n");
		return EGT_TX_ADJUST_LANECOUNT;
	}

	ret = egt_set_config(dp, bw_code, dp->train_cfg.cr_done_oldstate);
	if (ret < 0) {
		dev_err(dp->dev, "set config failed\n");
		return EGT_TX_TRAIN_FAILURE;
	}

	return EGT_TX_TRAIN_CR;
}

static int egt_dp_set_tp_mode(struct egt_displayport *dp, u32 tp_mode)
{
	u8 val = 0;
	u32 cntrl = 0;
	int i = 0;
	int pat = 0;
	int ret = 0;

	val = tp_mode;
	cntrl = egt_dp_read(DP_SOURCE_TX_CONTROL, dp) & (~EGT_TX_TP_MASK);

	for (i = 0; i < ARRAY_SIZE(pat_mode); i++) {
		if (pat_mode[i].drm_pattern == tp_mode)
			pat = pat_mode[i].egt_pattern;
	}
	egt_dp_write((cntrl | pat), DP_SOURCE_TX_CONTROL, dp);

	if ((tp_mode != DP_TRAINING_PATTERN_4) && (tp_mode != DP_TRAINING_PATTERN_DISABLE))
		val |= DP_LINK_SCRAMBLING_DISABLE;

	ret = drm_dp_dpcd_writeb(&dp->aux, DP_TRAINING_PATTERN_SET, val);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd training pattern failed\n");
		return ret;
	}

	pr_debug("tx-tp-mode = 0x%x, dpcd-val = 0x%x\n", (cntrl | pat), val);

	return ret;
}

static int egt_dp_deal_lowest_rate(struct egt_displayport *dp)
{
	struct egt_displayport_link_config *config = &dp->train_cfg;
	u32 val = 0;
	int ret = 0;

	ret = egt_dp_set_tp_mode(dp, DP_TRAINING_PATTERN_DISABLE);
	if (ret < 0) {
		dev_err(dp->dev, "disable dpcd training pattern failed\n");
		return ret;
	}

	ret = egt_set_config(dp, DP_LINK_BW_5_4, config->cr_done_cnt);
	if (ret < 0) {
		dev_err(dp->dev, "adj config failed\n");
		return ret;
	}

	config->cr_done_oldstate = config->cr_done_cnt;

	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val &= ~BIT(29);
	val = SET_BIT_FIELD(val, EGT_TX_TP_0, 0, EGT_TX_TP_MASK);
	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);
	pr_err("CR training failed!\n");

	return ret;
}

static int egt_dp_cr_training(struct egt_displayport *dp)
{
	struct egt_displayport_link_config *config = &dp->train_cfg;
	u8 link_status[DP_LINK_STATUS_SIZE] = { 0 };
	u8 lane_cnt = dp->lane_cnt;
	u8 vs = 0;
	u8 tries = 0;
	u8 volt = 0;
	u8 pre = 0;
	u8 get_v = 0;
	u8 get_p = 0;
	u32 cr_loop_time = 0;
	bool cr_done = 0;
	int ret = 0;
	int i = 0;
	int cr_done_max_tries = 0;

	pr_debug("link training rate is %d K\n", dp->bw_code * 270);
	memset(dp->train_set, 0, 4);

	ret = egt_dp_set_volt_pre(dp, link_status);
	if (ret < 0)
		return EGT_TX_TRAIN_FAILURE;

	ret = egt_dp_set_tp_mode(dp, DP_TRAINING_PATTERN_1);
	if (ret < 0)
		return EGT_TX_TRAIN_FAILURE;

	egt_dp_ticks_wait_us(3000, dp);
	cr_loop_time = egt_caclu_cr_time(dp, EGT_TX_CR_TIME);

	/* check cr done status */
	for (cr_done_max_tries = 0;
		 cr_done_max_tries < EGT_TX_CR_DONE_TRIES_MAX;
		 cr_done_max_tries++) {
		egt_dp_ticks_wait_us(cr_loop_time, dp);
		drm_dp_link_train_clock_recovery_delay(&dp->aux, dp->dpcd);

		ret = drm_dp_dpcd_read_link_status(&dp->aux, link_status);
		if (ret < 0)
			return EGT_TX_TRAIN_FAILURE;

		cr_done = egt_dp_check_cr_ready(dp, lane_cnt, link_status);
		if (!cr_done)
			return EGT_TX_TRAIN_CE;

		for (i = 0; i < lane_cnt; i++) {
			if (!(dp->train_set[i] & DP_TRAIN_MAX_SWING_REACHED))
				break;
		}
		if (i == lane_cnt)
			break;

		if ((dp->train_set[0] & DP_TRAIN_VOLTAGE_SWING_MASK) == vs)
			tries++;
		else
			tries = 0;

		if (tries == EGT_TX_TRAINING_TRIES_MAX)
			break;

		vs = dp->train_set[0] & DP_TRAIN_VOLTAGE_SWING_MASK;

		/* read and change vs & pre */
		get_v = drm_dp_get_adjust_request_voltage(link_status, 0);
		if (get_v > volt)
			volt = get_v;

		get_p = drm_dp_get_adjust_request_pre_emphasis(link_status, 0);
		if (get_p > pre)
			pre = get_p;

		pr_debug("tx-reg: 0x%08x, sink-val = 0x%08x\n",
					DP_SOURCE_PRE_VOLT0, pre >> 1 | get_v);
		egt_dp_write(pre >> 1 | get_v, DP_SOURCE_PRE_VOLT0, dp);

		egt_dp_reconfig_analog(dp);

		ret = egt_dp_update_train_vp(dp, volt, pre);
		if (ret < 0)
			return EGT_TX_TRAIN_FAILURE;
	}

	if (dp->bw_code == DP_LINK_BW_1_62) {
		if (config->cr_done_cnt != 0x4 && config->cr_done_cnt != 0x0) {
			egt_dp_deal_lowest_rate(dp);
			return EGT_TX_TRAIN_FAILURE;
		}
	}

	return EGT_TX_ADJUST_LINKRATE;
}

static int egt_dp_select_ce_pattern(struct egt_displayport *dp)
{
	u32 pattern = 0;

	/* Check dp version and select ce training pattern */
	if (dp->dpcd[DP_DPCD_REV] >= EGT_TX_V1_4 &&
		(dp->dpcd[DP_MAX_LANE_COUNT] & DP_TPS4_SUPPORTED))
		pattern = DP_TRAINING_PATTERN_4;
	else if (dp->dpcd[DP_DPCD_REV] >= EGT_TX_V1_2 &&
		(dp->dpcd[DP_MAX_LANE_COUNT] & DP_TPS3_SUPPORTED))
		pattern = DP_TRAINING_PATTERN_3;
	else
		pattern = DP_TRAINING_PATTERN_2;

	return pattern;
}

static int egt_dp_ce_training(struct egt_displayport *dp)
{
	struct egt_displayport_link_config *config = &dp->train_cfg;
	u8 link_status[DP_LINK_STATUS_SIZE] = {0};
	u8 lane_cnt = dp->lane_cnt;
	u8 volt = 0;
	u8 pre = 0;
	u8 get_v = 0;
	u8 get_p = 0;
	u32 pat = 0;
	u32 tries = 0;
	u32 eq_loop_time = 400;
	bool ce_ok = 0;
	bool cr_ok = 0;
	int ret = 0;

	pat = egt_dp_select_ce_pattern(dp);

	pr_debug("link training pattern is 0x%x\n", pat);

	ret = egt_dp_set_tp_mode(dp, pat);
	if (ret < 0)
		return EGT_TX_TRAIN_FAILURE;

	egt_dp_ticks_wait_us(3000, dp);
	eq_loop_time = egt_caclu_cr_time(dp, EGT_TX_CE_TIME);

	for (tries = 0; tries < 5; tries++) {
		egt_dp_ticks_wait_us(eq_loop_time, dp);
		drm_dp_link_train_channel_eq_delay(&dp->aux, dp->dpcd);
		ret = drm_dp_dpcd_read_link_status(&dp->aux, link_status);
		if (ret < 0)
			return EGT_TX_TRAIN_FAILURE;

		cr_ok = drm_dp_clock_recovery_ok(link_status, lane_cnt);
		if (!cr_ok)
			break;

		ce_ok = drm_dp_channel_eq_ok(link_status, lane_cnt);
		if (ce_ok)
			return EGT_TX_TRAIN_SUCCESS;

		ret = drm_dp_dpcd_read_link_status(&dp->aux, link_status);
		if (ret < 0)
			return EGT_TX_TRAIN_FAILURE;

		/* Read and change vs & pre*/
		get_v = drm_dp_get_adjust_request_voltage(link_status, 0);
		if (get_v > volt)
			volt = get_v;

		get_p = drm_dp_get_adjust_request_pre_emphasis(link_status, 0);
		if (get_p > pre)
			pre = get_p;

		pr_debug("vs_pre_reg: 0x%08x, sink-val = 0x%08x\n",
					DP_SOURCE_PRE_VOLT0, pre >> 1 | get_v);
		egt_dp_write(pre >> 1 | get_v, DP_SOURCE_PRE_VOLT0, dp);

		egt_dp_reconfig_analog(dp);

		ret = egt_dp_update_train_vp(dp, volt, pre);
		if (ret < 0) {
			pr_err("ce adjust volt and pre failed.\n");
			return EGT_TX_TRAIN_FAILURE;
		}
	}

	if (!cr_ok) {
		pr_debug("cr status not ready\n");
		config->cr_done_oldstate = config->max_lanes;
		return EGT_TX_ADJUST_LINKRATE;
	} else if ((dp->lane_cnt == 1) && !ce_ok) {
		pr_debug("ce status not ready\n");
		dp->lane_cnt = config->max_lanes;
		config->cr_done_oldstate = config->max_lanes;
		return EGT_TX_ADJUST_LINKRATE;
	} else if ((dp->lane_cnt > 1) && !ce_ok) {
		return EGT_TX_ADJUST_LANECOUNT;
	}

	config->cr_done_oldstate = config->max_lanes;

	return EGT_TX_ADJUST_LINKRATE;
}

static int egt_dp_start_training(struct egt_displayport *dp)
{
	struct egt_displayport_link_config *config = &dp->train_cfg;
	int state = EGT_TX_TRAIN_CR;
	int ret = 0;
	unsigned int timeout_us = 10000000;
	s64 elapsed_us = 0;
	ktime_t start_time = 0;

	start_time = ktime_get();

	while (1) {
		switch (state) {
		case EGT_TX_TRAIN_CR:
			state = egt_dp_cr_training(dp);
			break;
		case EGT_TX_TRAIN_CE:
			state = egt_dp_ce_training(dp);
			break;
		case EGT_TX_ADJUST_LINKRATE:
			state = egt_dp_change_rate(dp);
			break;
		case EGT_TX_ADJUST_LANECOUNT:
			dev_err(dp->dev, "rate and num_lanes are lowest, training failed\n");
			state = EGT_TX_TRAIN_FAILURE;
			break;
		default:
			break;
		}

		switch (state) {
		case EGT_TX_TRAIN_SUCCESS:
			config->cr_done_oldstate = config->max_lanes;
			config->cr_done_cnt = config->max_lanes;
			dev_dbg(dp->dev, "dp training is success");
			return 0;
		case EGT_TX_TRAIN_FAILURE:
			config->cr_done_oldstate = config->max_lanes;
			config->cr_done_cnt = config->max_lanes;
			goto err_out;
		case EGT_TX_ADJUST_LINKRATE:
			fallthrough;
		case EGT_TX_ADJUST_LANECOUNT:
			ret = egt_dp_set_tp_mode(dp, DP_TRAINING_PATTERN_DISABLE);
			if (ret < 0) {
				dev_err(dp->dev, "disable dpcd-tp failed\n");
				goto err_out;
			}
		default:
			break;
		}

		elapsed_us = ktime_to_us(ktime_sub(ktime_get(), start_time));
		if (elapsed_us > timeout_us) {
			pr_warn("training timeout: elapsed=%lld us\n", (long long)elapsed_us);
			goto err_out;
		}
	}

err_out:
	dev_err(dp->dev, "dp training failed\n");
	return -EIO;
}

static int egt_dp_after_training(struct egt_displayport *dp)
{
	int ret = 0;
	u8 val = 0;

	if (dp->dpcd[DP_DPCD_REV] == EGT_TX_V1_4) {
		dev_dbg(dp->dev, "dprx-1.4");
		ret = drm_dp_dpcd_readb(&dp->aux, DP_LANE_COUNT_SET, &val);
		if (ret < 0) {
			dev_dbg(dp->dev, "get dpcd lane count failed");
			ret = drm_dp_dpcd_readb(&dp->aux, DP_LANE_COUNT_SET, &val);
			if (ret < 0) {
				dev_err(dp->dev, "retry get dpcd lane count failed");
				return ret;
			}
		}

		val |= 0x20;
		ret = drm_dp_dpcd_writeb(&dp->aux, DP_LANE_COUNT_SET, val);
		if (ret < 0) {
			dev_dbg(dp->dev, "set dpcd lane count failed");
			ret = drm_dp_dpcd_writeb(&dp->aux, DP_LANE_COUNT_SET, val);
			if (ret < 0) {
				dev_err(dp->dev, "retry set dpcd lane count failed");
				return ret;
			}
		}
	}

	return ret;
}

static void egt_dp_after_training_success(struct egt_displayport *dp)
{
	u32 val = 0;

	/* Set Idle mode */
	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val = SET_BIT_FIELD(val, EGT_TX_TP_IDLE, 0, EGT_TX_TP_MASK);
	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);

	egt_dp_ticks_wait_us(2000, dp);

	/* Set normal mode */
	val = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	val = SET_BIT_FIELD(val, EGT_TX_TP_0, 0, EGT_TX_TP_MASK);
	val &= ~(1 << 4);
	egt_dp_write(val, DP_SOURCE_TX_CONTROL, dp);
}

static int egt_dp_training_begin(struct egt_displayport *dp)
{
	u32 txctlreg = 0;
	int link_rate = dp->train_cfg.link_rate;
	int ret = 0;

	egt_dp_set_hpd_irq(dp, 0);

	if (egt_dp_set_fec(dp) < 0) {
		pr_err("FEC disable timeout\n");
		return -ETIMEDOUT;
	}

	egt_dp_set_sink_d0(dp);

	dp->bw_code = drm_dp_link_rate_to_bw_code(link_rate);

	/* Set default config */
	txctlreg = egt_dp_read(DP_SOURCE_TX_CONTROL, dp);
	txctlreg = SET_BIT_FIELD(txctlreg, EGT_TX_TP_IDLE, 0, EGT_TX_TP_MASK);
	txctlreg = SET_BIT_FIELD(txctlreg, (dp->lane_cnt & 0x07), 5, EGT_TX_LANE_CNT_MASK);
	txctlreg = SET_BIT_FIELD(txctlreg, dp->bw_code, 21, EGT_TX_LINK_RATE_MASK);
	egt_dp_write(txctlreg, DP_SOURCE_TX_CONTROL, dp);
	pr_debug("dp->bw_code = %d, dp->lane_cnt = %d\n", dp->bw_code, dp->lane_cnt);

	dp->lane_cnt = dp->train_cfg.lane_count;
	dp->train_cfg.cr_done_oldstate = dp->train_cfg.max_lanes;

	ret = egt_set_config(dp, dp->bw_code, dp->lane_cnt);
	if (ret < 0) {
		dev_err(dp->dev, "set config failed\n");
		return -EIO;
	}

	ret = egt_dp_dpcd_cap_config(dp);
	if (ret < 0) {
		dev_err(dp->dev, "set dpcd config failed\n");
		return -EIO;
	}

	memset(dp->train_set, 0, EGT_TX_MAX_LANES);
	ret = egt_dp_start_training(dp);
	if (ret < 0) {
		dev_err(dp->dev, "egt dp start train, training failed!\n");
		egt_dp_set_phy(dp, dp->bw_code);
		/* Enable dp hpd irq after training failed */
		egt_dp_set_hpd_irq(dp, 1);
		return -EIO;
	}

	{
		ret = egt_dp_after_training(dp);
		if (ret < 0) {
			dev_err(dp->dev, "set egt dp after train failed\n");
			return -EIO;
		}

		ret = egt_dp_check_link_ready(dp);
		if (ret < 0) {
			dev_err(dp->dev, "after train failed\n");
			return -EIO;
		}

		ret = egt_dp_set_tp_mode(dp, DP_TRAINING_PATTERN_DISABLE);
		if (ret < 0) {
			dev_err(dp->dev, "set dpcd-tp failed\n");
			return ret;
		}
	}

	ret = egt_dp_check_link_ready(dp);
	if (ret < 0) {
		dev_err(dp->dev, "after train success: check link sts failed\n");
		return -EIO;
	}

	egt_dp_after_training_success(dp);

	egt_dp_set_hpd_irq(dp, 1);

	return 0;
}

static void egt_update_config(struct egt_displayport *dp)
{
	struct egt_displayport_link_config *link_config = &dp->train_cfg;

	link_config->max_rate = min_t(int, drm_dp_max_link_rate(dp->dpcd), dp->max_link_rate);
	link_config->max_lanes = min_t(u8, drm_dp_max_lane_count(dp->dpcd), dp->max_lanes);

	link_config->link_rate = link_config->max_rate;
	link_config->lane_count = link_config->max_lanes;
	dp->lane_cnt = link_config->max_lanes;
	dp->bw_code = drm_dp_link_rate_to_bw_code(link_config->link_rate);

	pr_debug("tx&rx bpp = %d\n", dp->tx_cfg.bpp);
	pr_debug("tx&rx max link_config rate = %d\n", link_config->max_rate);
	pr_debug("tx&rx max link_config lanes = %d\n", link_config->max_lanes);
}

void egt_dptx_hpd_work(struct work_struct *work)
{
	struct egt_displayport *dp = container_of(work, struct egt_displayport,
						hot_plug_detect.work);
	struct drm_connector *connector = NULL;
	enum drm_connector_status old_status = connector_status_disconnected;
	u8 max_link_rate = 0;
	u32 sts = 0;
	int ret = 0;
	int try = 0;

	if (!dp) {
		pr_err("dp is NULL\n");
		goto adjust_sts;
	}

	connector = &dp->connector;

	mutex_lock(&dp->lock);

	dp->connected = false;

	for (try = 0; try <= 5; try++) {
		sts = egt_dp_read(DP_SOURCE_TX_STATUS, dp) & EGT_TX_HPD_LEVEL;
		if (sts != 0)
			break;

		usleep_range(1000, 1100);
	}

	if (try > 5) {
		dev_err(dp->dev, "dp is disconnected");
		goto exit;
	}

	if (egt_dpcd_read(dp) < 0) {
		dev_err(dp->dev, "read dpcd failed");
		goto exit;
	}

	if (dp->dpcd[DP_TRAINING_AUX_RD_INTERVAL] & DP_EXTENDED_RECEIVER_CAP_FIELD_PRESENT) {
		ret = drm_dp_dpcd_read(&dp->aux, DP_DP13_DPCD_REV + 1, &max_link_rate, 1);
		if (ret < 0) {
			dev_err(dp->dev, "read dpcd failed");
			goto exit;
		}

		if (max_link_rate == DP_LINK_BW_8_1)
			dp->dpcd[DP_MAX_LINK_RATE] = DP_LINK_BW_5_4;
	}

	egt_update_config(dp);

	dev_dbg(dp->dev, "connected dp rx. training\n");
	if (egt_dp_training_begin(dp) != 0)
		goto exit;

	dp->connected = true;

exit:
	mutex_unlock(&dp->lock);
adjust_sts:
	old_status = connector->status;
	connector->status = connector->funcs->detect(connector, false);
	if (old_status != connector->status)
		drm_kms_helper_hotplug_event(dp->drm);
}

MODULE_DESCRIPTION("Engiant DP Training Driver");
MODULE_LICENSE("GPL");
