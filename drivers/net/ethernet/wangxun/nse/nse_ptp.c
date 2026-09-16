// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/ptp_clock_kernel.h>
#include <linux/math64.h>

#include "nse.h"
#include "nse_lib.h"
#include "nse_ptp_hw.h"

/* We use our own definitions instead of NSEC_PER_SEC because we want to mark
 * the value as a ULL to force precision when bit shifting.
 */
#define NS_PER_SEC      1000000000ULL

/**
 * nse_set_tx_tstamp - Enable or disable Tx timestamping
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamps are enabled or disabled
 */
void nse_set_tx_tstamp(struct nse_pf *pf, bool on)
{
	struct nse_vsi *vsi;
	u16 i;

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return;

	/* Set the timestamp enable flag for all the Tx rings */
	nse_for_each_txq(vsi, i) {
		if (!vsi->tx_rings[i])
			continue;
		vsi->tx_rings[i]->ptp_tx = on;
	}

	pf->ptp.tstamp_config.tx_type = on ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
}

/**
 * nse_set_rx_tstamp - Enable or disable Rx timestamping
 * @pf: The PF pointer to search in
 * @on: bool value for whether timestamps are enabled or disabled
 */
void nse_set_rx_tstamp(struct nse_pf *pf, bool on)
{
	struct nse_vsi *vsi;
	u16 i;

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return;

	/* Set the timestamp flag for all the Rx rings */
	nse_for_each_rxq(vsi, i) {
		if (!vsi->rx_rings[i])
			continue;
		vsi->rx_rings[i]->ptp_rx = on;
	}

	pf->ptp.tstamp_config.rx_filter = on ? HWTSTAMP_FILTER_ALL :
					       HWTSTAMP_FILTER_NONE;
}

/**
 * nse_ptp_cfg_timestamp - Configure timestamp for init/deinit
 * @pf: Board private structure
 * @ena: bool value to enable or disable time stamp
 *
 * This function will configure timestamping during PTP initialization
 * and deinitialization
 */
void nse_ptp_cfg_timestamp(struct nse_pf *pf, bool ena)
{
	nse_set_tx_tstamp(pf, ena);
	nse_set_rx_tstamp(pf, ena);
}

/**
 * nse_get_ptp_clock_index - Get the PTP clock index
 * @pf: the PF pointer
 *
 * Determine the clock index of the PTP clock associated with this device.
 */
int nse_get_ptp_clock_index(struct nse_pf *pf)
{
	/* Use the ptp_clock structure if we're the main PF */
	if (pf->ptp.clock)
		return ptp_clock_index(pf->ptp.clock);

	return -1;
}

/**
 * nse_ptp_read_src_clk_reg - Read the source clock register
 * @pf: Board private structure
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 */
enum nse_status
nse_ptp_read_src_clk_reg(struct nse_pf *pf, struct ptp_system_timestamp *sts,
			 u32 *sec_part, u32 *nsec_part, u64 *raw_nsec)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status ret;

	/* Read the system timestamp pre PHC read */
	ptp_read_system_prets(sts);

	ret = nse_aq_ptp_get_sys_time(hw, sec_part, nsec_part, raw_nsec);

	/* Read the system timestamp post PHC read */
	ptp_read_system_postts(sts);

	return ret;
}

/**
 * nse_ptp_update_cached_phctime - Update the cached PHC time values
 * @pf: Board specific private structure
 *
 * This function updates the system time values which are cached in the PF
 * structure and the Rx rings.
 *
 * This function must be called periodically to ensure that the cached value
 * is never more than 2 seconds old. It must also be called whenever the PHC
 * time has been changed.
 *
 * Return:
 * * 0 - OK, successfully updated
 * * -EAGAIN - PF was busy, need to reschedule the update
 */
static int nse_ptp_update_cached_phctime(struct nse_pf *pf)
{
	struct nse_vsi *vsi = NULL;
	u64 systime;
	u32 sec_part, nsec_part;
	int j;
	enum nse_status status;
	int ret = 0;

	if (test_and_set_bit(NSE_CFG_BUSY, pf->state))
		return -EAGAIN;

	/* Read the current PHC time */
	status = nse_ptp_read_src_clk_reg(pf, NULL, &sec_part, &nsec_part, &systime);
	if (status) {
		ret = -EIO;
		goto out;
	}

	pf->ptp.cached_last_update = jiffies;

	/* Update the cached PHC time stored in the PF structure */
	WRITE_ONCE(pf->ptp.cached_phc_time, systime);
	WRITE_ONCE(pf->ptp.cached_phc_time_sec_part, sec_part);
	WRITE_ONCE(pf->ptp.cached_phc_time_nsec_part, nsec_part);

	vsi = nse_get_main_vsi(pf);
	if (vsi && vsi->rx_rings) {
		nse_for_each_rxq(vsi, j) {
			if (!vsi->rx_rings[j])
				continue;
			WRITE_ONCE(vsi->rx_rings[j]->cached_phctime, systime);
			WRITE_ONCE(vsi->rx_rings[j]->cached_phctime_sec_part, sec_part);
			WRITE_ONCE(vsi->rx_rings[j]->cached_phctime_nsec_part, nsec_part);
		}
	}

out:
	clear_bit(NSE_CFG_BUSY, pf->state);

	return ret;
}

/**
 * nse_ptp_read_time - Read the time from the device
 * @pf: Board private structure
 * @ts: timespec structure to hold the current time value
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 *
 * This function reads the source clock registers and stores them in a timespec.
 * However, since the registers are 64 bits of nanoseconds, we must convert the
 * result to a timespec before we can return.
 */
static int nse_ptp_read_time(struct nse_pf *pf, struct timespec64 *ts,
			      struct ptp_system_timestamp *sts)
{
	u64 time_ns;
	u32 sec_part, nsec_part;
	enum nse_status status;

	status = nse_ptp_read_src_clk_reg(pf, sts, &sec_part, &nsec_part, &time_ns);
	if (status) {
		dev_err(nse_pf_to_dev(pf),
			"read 1588 current sys time fails: status = %s!\n", nse_stat_str(status));
		return -EIO;
	}

	*ts = ns_to_timespec64(time_ns);

	return 0;
}

/**
 * nse_ptp_write_init - Set PHC time to provided value
 * @pf: Board private structure
 * @ts: timespec structure that holds the new time value
 *
 * Set the PHC time to the specified time provided in the timespec.
 */
static int nse_ptp_write_init(struct nse_pf *pf, struct timespec64 *ts)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;

	status = nse_ptp_init_time(hw, ts);
	if (status)
		return nse_status_to_errno(status);

	return 0;
}

/**
 * nse_ptp_write_adj - Adjust PHC clock time atomically
 * @pf: Board private structure
 * @adj: Adjustment in nanoseconds
 *
 * Perform an atomic adjustment of the PHC time by the specified number of
 * nanoseconds.
 */
static int
nse_ptp_write_adj(struct nse_pf *pf, s64 adj)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;

	status = nse_ptp_adj_clock(hw, adj);
	if (status)
		return nse_status_to_errno(status);

	return 0;
}

/**
 * nse_base_incval - Get base timer increment value
 * @pf: Board private structure
 *
 * Look up the base timer increment value for this device. The base increment
 * value is used to define the nominal clock tick rate. This increment value
 * is programmed during device initialization. It is also used as the basis
 * for calculating adjustments using scaled_ppm.
 */
static void nse_dflt_ptp_hw_setting_amber(struct nse_pf *pf, struct nse_ptp *ptp)
{
	struct nse_hw *hw = &pf->hw;

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA) {
		ptp->ref_freq = hw->hw_conf.ptp_ref_clock_freq;		/* 25000000 = 25 MHz*/
		ptp->ptp_freq = ptp->ref_freq;	/* also 25 MHz, no matter Fine or Coarse Update */
		if (pf->sw_conf.ptp_fine_mode) {
			/* (2000000000ULL / ptp_clock) */
			ptp->dflt_incval.amber.nsec_part = 80;
			ptp->dflt_incval.amber.subnsec_part = 0;
			ptp->dflt_fine_addend = 0x80000000;
		} else {
			ptp->dflt_incval.amber.nsec_part = 40;
			ptp->dflt_incval.amber.subnsec_part = 0;
			ptp->dflt_fine_addend = 0;
		}
	} else {	/* NSE_HW_PLATFORM_FPGA */
		ptp->ref_freq = hw->hw_conf.ptp_ref_clock_freq;		/* 500 MHz or 250 MHz */
		ptp->ptp_freq = ptp->ref_freq;

		if (pf->sw_conf.ptp_fine_mode) {
			if (hw->hw_conf.ptp_ref_clock_freq == NSE_AMBER_ASIC_MAIN_CLOCK_FREQ_500MHZ)
				/* 2 / clock_freq --- 2 is addend overflow each 2 times */
				ptp->dflt_incval.amber.nsec_part = 4;
			else	/* 250 MHz */
				ptp->dflt_incval.amber.nsec_part = 8;	/* 2 / clock_freq */

			ptp->dflt_incval.amber.subnsec_part = 0;
			ptp->dflt_fine_addend = 0x80000000;
		} else {
			if (hw->hw_conf.ptp_ref_clock_freq == NSE_AMBER_ASIC_MAIN_CLOCK_FREQ_500MHZ)
				ptp->dflt_incval.amber.nsec_part = 2;	/* 1 sec / clock_freq */
			else	/* 250 MHz */
				ptp->dflt_incval.amber.nsec_part = 4;

			ptp->dflt_incval.amber.subnsec_part = 0;
			ptp->dflt_fine_addend = 0;
		}
	}
}

static void nse_dflt_ptp_hw_setting_ms(struct nse_pf *pf, struct nse_ptp *ptp)
{
	struct nse_hw *hw = &pf->hw;

	ptp->ref_freq = hw->hw_conf.ptp_ref_clock_freq;	/* 200000000 = 200 MHz */
	ptp->ptp_freq = ptp->ref_freq;

	ptp->dflt_incval.ms.period_part = MS_PTP_DFLT_INC_PERIOD;
	ptp->dflt_incval.ms.value_part = MS_PTP_DFLT_INC_VALUE;

	ptp->dflt_fine_addend = 0;	/* moonstone does not support find mode */
}

static void nse_dflt_ptp_hw_setting(struct nse_pf *pf, struct nse_ptp *ptp)
{
	if (pf->hw.mac_type == NSE_MAC_TYPE_AMBER)
		nse_dflt_ptp_hw_setting_amber(pf, ptp);
	else if (pf->hw.mac_type == NSE_MAC_TYPE_MOONSTONE)
		nse_dflt_ptp_hw_setting_ms(pf, ptp);
}

/**
 * nse_ptp_reset_phy_timestamping - Reset PHY timestamping block
 * @pf: Board private structure
 */
static void nse_ptp_reset_phy_timestamping(struct nse_pf *pf)
{
}

static int nse_ptp_adj_frequency_fine_mode(struct ptp_clock_info *info, long scaled_ppm)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	u32 addend;

	addend = (u32)adjust_by_scaled_ppm(ptp->dflt_fine_addend, scaled_ppm);

	nse_debug(hw, NSE_DBG_PTP, "[%s]: scaled_ppm=%ld, addend=0x%X(dec: %d)\n",
							__func__, scaled_ppm, addend, addend);

	return nse_ptp_write_addend_locked(hw, addend);
}

static int nse_ptp_adj_frequency_coarse_mode_amber(struct ptp_clock_info *info, s32 ppb)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	s32 new_freq;
	u32 new_incval_nsec_part, new_incval_subnsec_part;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_PTP, "[%s]: ppb=%d\n", __func__, ppb);

	if (ppb == 0)
		return 0;

	new_freq = ptp->ptp_freq + ppb;	//in coarse mode: ptp_freq = ref_freq

	new_incval_nsec_part = (u32)div_u64_rem(NS_PER_SEC, (u32)new_freq,
						&new_incval_subnsec_part);

	/* MAC_Sub_Second_Increment -> SNSINC is not direct subnsec number, but 0.N * 256 */
	new_incval_subnsec_part = (new_incval_subnsec_part * 256) / new_freq;

	nse_debug(hw, NSE_DBG_PTP, "[%s]: new_freq=%d, new_inc_nsec=0x%X(%d), new_inc_subnsec=0x%X(%d)\n",
				__func__, new_freq, new_incval_nsec_part, new_incval_nsec_part,
							new_incval_subnsec_part,
								new_incval_subnsec_part);

	status = nse_ptp_write_incval_sec_subnsec_locked(hw, new_incval_nsec_part,
							 new_incval_subnsec_part);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: ptp_write_incval_sec_subnsec_locked(), status=%d(%s)\n",
			__func__, status, nse_stat_str(status));
		return -EIO;
	}

	return 0;
}

static int nse_ptp_adj_frequency_coarse_mode_ms(struct ptp_clock_info *info, s32 ppb)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	u64 freq, new_inc_value_part;
	u32 diff;
	u32 new_inc;
	int neg_adj = 0;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_PTP, "[%s]: ppb=%d\n", __func__, ppb);

	if (ppb == 0)
		return 0;

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}

	new_inc_value_part = ptp->dflt_incval.ms.value_part;

	freq = new_inc_value_part;
	freq *= ppb;
	diff = div_u64(freq, 1000000000ULL);

	new_inc_value_part = neg_adj ? (new_inc_value_part - diff) : (new_inc_value_part + diff);

	if (new_inc_value_part > MS_AQC_PTP_INC_VAL_M)
		dev_warn(nse_pf_to_dev(pf), "[%s] new_inc_value_part (0x%lX) overflow range (0x%X)\n",
			 __func__, (unsigned long)new_inc_value_part, MS_AQC_PTP_INC_VAL_M);

	new_inc = (((u32)ptp->dflt_incval.ms.period_part <<
		   MS_AQC_PTP_INC_PERIOD_S) & MS_AQC_PTP_INC_PERIOD_M) |
			((new_inc_value_part << MS_AQC_PTP_INC_VAL_S) & MS_AQC_PTP_INC_VAL_M);

	nse_debug(hw, NSE_DBG_PTP, "[%s]: new_inc=0x%X (value_part=0x%lX)\n",
							__func__, new_inc,
								(unsigned long)new_inc_value_part);

	status = nse_ptp_write_incval_raw_locked(hw, new_inc);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: ptp_write_incval_raw_locked(), status=%d(%s)\n",
			__func__, status, nse_stat_str(status));
		return -EIO;
	}

	return 0;
}

static int nse_ptp_adj_frequency_coarse_mode(struct ptp_clock_info *info, s32 ppb)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		ret = nse_ptp_adj_frequency_coarse_mode_amber(info, ppb);
	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		ret = nse_ptp_adj_frequency_coarse_mode_ms(info, ppb);
	} else {
		dev_err(dev, "[%s] unsupported mac_type(%d)\n", __func__, hw->mac_type);
		ret = -EOPNOTSUPP;
	}
	return ret;
}

/**
 * nse_ptp_adjfine - Adjust clock increment rate
 * @info: the driver's PTP info structure
 * @scaled_ppm: Parts per million with 16-bit fractional field
 *
 * Adjust the frequency of the clock by the indicated scaled ppm from the
 * base frequency.
 */
static int nse_ptp_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	int ret;

	nse_debug(hw, NSE_DBG_PTP, "[%s]: scaled_ppm=%ld\n", __func__, scaled_ppm);

	if (pf->sw_conf.ptp_fine_mode) {
		ret = nse_ptp_adj_frequency_fine_mode(info, scaled_ppm);
	} else {
		s32 ppb;

		/*  translate ppm to ppb, and call adjfreq(), like kernel ptp_clock_adjtime() ->
		 * ADJ_FREQUENCY do
		 */
		ppb = (s32)scaled_ppm_to_ppb(scaled_ppm);

		ret = nse_ptp_adj_frequency_coarse_mode(info, ppb);
	}
	return ret;
}

/**
 * nse_ptp_disable_all_clkout - Disable all currently configured outputs
 * @pf: pointer to the PF structure
 *
 * Disable all currently configured clock outputs. This is necessary before
 * certain changes to the PTP hardware clock. Use nse_ptp_enable_all_clkout to
 * re-enable the clocks again.
 */
static void nse_ptp_disable_all_clkout(struct nse_pf *pf)
{
}

/**
 * nse_ptp_enable_all_clkout - Enable all configured periodic clock outputs
 * @pf: pointer to the PF structure
 *
 * Enable all currently configured clock outputs. Use this after
 * nse_ptp_disable_all_clkout to reconfigure the output signals according to
 * their configuration.
 */
static void nse_ptp_enable_all_clkout(struct nse_pf *pf)
{
}

/**
 * nse_ptp_gettimex64 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure to hold the current time value
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int
nse_ptp_gettimex64(struct ptp_clock_info *info, struct timespec64 *ts,
		   struct ptp_system_timestamp *sts)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;

	if (!nse_ptp_lock(hw)) {
		ret = -EBUSY;
		dev_err(dev, "[%s]: fail to lock before gettime, ret=%d\n", __func__, ret);
		goto out;
	}

	ret = nse_ptp_read_time(pf, ts, sts);
	if (ret)
		dev_err(dev, "[%s]: fail to ptp_read_time(), ret=%d\n", __func__, ret);

	nse_ptp_unlock(hw);

out:
	return ret;
}

/**
 * nse_ptp_settime64 - Set the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int
nse_ptp_settime64(struct ptp_clock_info *info, const struct timespec64 *ts)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct timespec64 ts64 = *ts;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;

	nse_debug(hw, NSE_DBG_PTP, "[%s] ts->tv_sec=%ld, tv_nsec=%ld\n",
		  __func__, (long)ts->tv_sec, ts->tv_nsec);

	if (!nse_ptp_lock(hw)) {
		ret = -EBUSY;
		dev_err(dev, "[%s]: fail to lock before settime, ret=%d\n", __func__, ret);
		goto exit;
	}

	/* Disable periodic outputs */
	nse_ptp_disable_all_clkout(pf);

	ret = nse_ptp_write_init(pf, &ts64);
	if (ret)
		dev_err(dev, "[%s]: fail to ptp_write_init(), ret=%d", __func__, ret);

	nse_ptp_unlock(hw);

	if (!ret)
		(void)nse_ptp_update_cached_phctime(pf);

	/* Reenable periodic outputs */
	nse_ptp_enable_all_clkout(pf);

exit:
	if (ret)
		dev_err(dev, "[%s]: fail to settime, ret=%d\n", __func__, ret);

	return ret;
}

/**
 * nse_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int nse_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct nse_pf *pf = ptp_info_to_pf(info);
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;

	nse_debug(hw, NSE_DBG_PTP, "[%s]: delta=%ld\n", __func__, (long)delta);

	if (!nse_ptp_lock(hw)) {
		ret = -EBUSY;
		dev_err(dev, "[%s]: fail to lock before adjtime, ret=%d\n", __func__, ret);
		goto out;
	}

	/* Disable periodic outputs */
	nse_ptp_disable_all_clkout(pf);

	ret = nse_ptp_write_adj(pf, delta);
	if (ret)
		dev_err(dev, "[%s]: fail to ptp_write_adj(), ret=%d\n", __func__, ret);

	/* Reenable periodic outputs */
	nse_ptp_enable_all_clkout(pf);

	nse_ptp_unlock(hw);

	if (!ret)
		(void)nse_ptp_update_cached_phctime(pf);

out:
	if (ret)
		nse_dev_err_errno(dev, ret, "PTP failed to adjust time");

	return ret;
}

/**
 * nse_ptp_feature_enable - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int
nse_ptp_feature_enable(struct ptp_clock_info *info,
			 struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

/**
 * nse_ptp_set_timestamp_mode - Setup driver for requested timestamp mode
 * @pf: Board private structure
 * @config: hwtstamp settings requested or saved
 */
static int
nse_ptp_set_timestamp_mode(struct nse_pf *pf, struct hwtstamp_config *config)
{
	bool update_cached_now = false;

	/* Reserved for future extensions. */
	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		nse_set_tx_tstamp(pf, false);
		pf->ptp.user_tx_ts_sample_status = false;
		break;
	case HWTSTAMP_TX_ON:
		nse_set_tx_tstamp(pf, true);
		pf->ptp.user_tx_ts_sample_status = true;
		update_cached_now = true;
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		nse_set_rx_tstamp(pf, false);
		pf->ptp.user_rx_ts_sample_status = false;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_NTP_ALL:
	case HWTSTAMP_FILTER_ALL:
		nse_set_rx_tstamp(pf, true);
		pf->ptp.user_rx_ts_sample_status = false;
		update_cached_now = true;
		break;
	default:
		return -ERANGE;
	}

	if (update_cached_now)
		(void)nse_ptp_update_cached_phctime(pf);

	return 0;
}

/**
 * nse_ptp_get_ts_config - ioctl interface to read the timestamping config
 * @pf: Board private structure
 * @ifr: ioctl data
 *
 * Copy the timestamping config to user buffer
 */
int nse_ptp_get_ts_config(struct nse_pf *pf, struct ifreq *ifr)
{
	struct hwtstamp_config *config;

	if (!test_bit(NSE_FLAG_PTP, pf->flags))
		return -EIO;

	config = &pf->ptp.tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ?
		-EFAULT : 0;
}

/**
 * nse_ptp_set_ts_config - ioctl interface to control the timestamping
 * @pf: Board private structure
 * @ifr: ioctl data
 *
 * Get the user config and store it
 */
int nse_ptp_set_ts_config(struct nse_pf *pf, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (!test_bit(NSE_FLAG_PTP, pf->flags))
		return -EAGAIN;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = nse_ptp_set_timestamp_mode(pf, &config);
	if (err)
		return err;

	/* Return the actual configuration set */
	config = pf->ptp.tstamp_config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

static u64 nse_ptp_extend_rx_ts_amber(u32 cached_sec, u32 sample_7b_sec, u32 sample_nsec)
{
	struct timespec64 ts;

	if (sample_7b_sec < (cached_sec & 0x7F)) {
		/*  RX timestamp sample taken right after every cached_phc_time lower 7-bits
		 * overflow boundary: 128 sec.
		 */

		ts.tv_sec = ((cached_sec & ~0x7F) + 128) | sample_7b_sec;
	} else {
		ts.tv_sec = (cached_sec & ~0x7F) | sample_7b_sec;
	}

	ts.tv_nsec = sample_nsec;

	return (u64)timespec64_to_ns(&ts);
}

static void
nse_ptp_rx_hwtstamp_amber(struct nse_ring *rx_ring,
		    union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	u32 ts_high;
	u32 ts_7b_sec_part;
	u32 ts_nsec_part;
	u64 ts_ns;

	/* rx_ring->ptp_rx already be checked before calling this func */
	/* Populate timesync data into skb */
	if (rx_desc->wb.ts_low & NSE_PTP_TS_VALID) {
		struct skb_shared_hwtstamps *hwtstamps;
#if defined(NSE_DEBUG_EXT)
		struct nse_ptp *ptp = &rx_ring->vsi->back->ptp;
#endif

		ts_high = le32_to_cpu(rx_desc->wb.ts_high);

		ts_7b_sec_part = (ts_high >> 25);

		ts_nsec_part = ((ts_high & 0x1FFFFFF) << 7);
		ts_nsec_part |= ((u32)rx_desc->wb.ts_low >> 1);

		ts_ns = nse_ptp_extend_rx_ts_amber(rx_ring->cached_phctime_sec_part,
						   ts_7b_sec_part, ts_nsec_part);

#if defined(NSE_DEBUG_EXT)
		/* we are in BH, no need to disable preemption. */
		if (ptp->debug_rx_ts) {
			struct debug_rx_ts_s *debug_ts = this_cpu_ptr(ptp->debug_rx_ts);

			debug_ts->os_ns = ktime_get_real_ns();

			debug_ts->desc_ts_high = ts_high;
			debug_ts->desc_md4 = le16_to_cpu(rx_desc->wb.md4);
			debug_ts->desc_md5 = le16_to_cpu(rx_desc->wb.md5);

			debug_ts->desc_ts_low = rx_desc->wb.ts_low;

			debug_ts->amber.desc_7b_sec_part = ts_7b_sec_part;
			debug_ts->amber.desc_nsec_part = ts_nsec_part;

			debug_ts->desc_ns = ts_ns;

			memcpy(&debug_ts->saved_desc, rx_desc, sizeof(debug_ts->saved_desc));
		}
#endif

		hwtstamps = skb_hwtstamps(skb);
		memset(hwtstamps, 0, sizeof(*hwtstamps));
		hwtstamps->hwtstamp = ns_to_ktime(ts_ns);
	}
}

static void
nse_ptp_rx_hwtstamp_ms(struct nse_ring *rx_ring,
		    union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	u64 ts_h_32_bits;
	u64 ts_l_7_bits;
	u64 ts_ns;

	if (rx_desc->wb.ts_low & NSE_PTP_TS_VALID) {
		struct skb_shared_hwtstamps *hwtstamps;
#if defined(NSE_DEBUG_EXT)
		struct nse_ptp *ptp = &rx_ring->vsi->back->ptp;
#endif

		ts_h_32_bits = le32_to_cpu(rx_desc->wb.ts_high);

		ts_l_7_bits = rx_desc->wb.ts_low >> 1;

		/* mask low 39 bits of cached time */
		ts_ns = (rx_ring->cached_phctime & 0x7FFFFFFFFFULL);
		ts_ns |= (ts_h_32_bits << 7);
		ts_ns |= ts_l_7_bits;

		hwtstamps = skb_hwtstamps(skb);
		memset(hwtstamps, 0, sizeof(*hwtstamps));
		hwtstamps->hwtstamp = ns_to_ktime(ts_ns);

#if defined(NSE_DEBUG_EXT)
		/* we are in BH, no need to disable preemption. */
		if (ptp->debug_rx_ts) {
			struct debug_rx_ts_s *debug_ts = this_cpu_ptr(ptp->debug_rx_ts);

			debug_ts->os_ns = ktime_get_real_ns();

			debug_ts->desc_ts_high = ts_h_32_bits;
			debug_ts->desc_md4 = le16_to_cpu(rx_desc->wb.md4);
			debug_ts->desc_md5 = le16_to_cpu(rx_desc->wb.md5);

			debug_ts->desc_ts_low = rx_desc->wb.ts_low;

			debug_ts->ms.desc_h_32b_part = ts_h_32_bits;
			debug_ts->ms.desc_l_7b_part = ts_l_7_bits;

			debug_ts->desc_ns = ts_ns;

			memcpy(&debug_ts->saved_desc, rx_desc, sizeof(debug_ts->saved_desc));
		}
#endif
	}
}

void
nse_ptp_rx_hwtstamp(struct nse_ring *rx_ring,
		    union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	struct nse_hw *hw = &rx_ring->pf->hw;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		nse_ptp_rx_hwtstamp_amber(rx_ring, rx_desc, skb);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		nse_ptp_rx_hwtstamp_ms(rx_ring, rx_desc, skb);
}

/**
 * nse_ptp_set_funcs - Set specialized functions.
 * @pf: Board private structure
 * @info: PTP info to fill
 */
static void
nse_ptp_set_funcs(struct nse_pf *pf, struct ptp_clock_info *info)
{
	info->n_alarm = 0;
	info->n_ext_ts = 0;
	info->n_per_out = 0;
	info->n_pins = 0;
	info->pps = 0;

	info->enable = nse_ptp_feature_enable;
}

/**
 * nse_ptp_set_caps - Set PTP capabilities
 * @pf: Board private structure
 */
static void nse_ptp_set_caps(struct nse_pf *pf)
{
	struct ptp_clock_info *info = &pf->ptp.info;
	struct device *dev = nse_pf_to_dev(pf);

	snprintf(info->name, sizeof(info->name) - 1, "%s-%s-clk",
		 dev_driver_string(dev), dev_name(dev));
	info->owner = THIS_MODULE;

	info->max_adj = pf->ptp.ref_freq;

	info->adjtime = nse_ptp_adjtime;
	info->adjfine = nse_ptp_adjfine;

	info->gettimex64 = nse_ptp_gettimex64;
	info->settime64 = nse_ptp_settime64;

	nse_ptp_set_funcs(pf, info);
}

/**
 * nse_ptp_create_clock - Create PTP clock device for userspace
 * @pf: Board private structure
 *
 * This function creates a new PTP clock device. It only creates one if we
 * don't already have one. Will return error if it can't create one, but success
 * if we already have a device. Should be used by nse_ptp_init to create clock
 * initially, and prevent global resets from creating new clock devices.
 */
static long nse_ptp_create_clock(struct nse_pf *pf)
{
	struct ptp_clock_info *info;
	struct ptp_clock *clock;
	struct device *dev;

	/* No need to create a clock device if we already have one */
	if (pf->ptp.clock)
		return 0;

	nse_ptp_set_caps(pf);

	info = &pf->ptp.info;
	dev = nse_pf_to_dev(pf);

	/* Attempt to register the clock before enabling the hardware. */
	clock = ptp_clock_register(info, dev);
	if (IS_ERR(clock)) {
		nse_dev_err_errno(dev, PTR_ERR(clock),
				  "Failed to register PTP clock device");
		return PTR_ERR(clock);
	}

	pf->ptp.clock = clock;

	return 0;
}

static void nse_ptp_tx_tstamp(struct nse_ptp_tx *tx, struct nse_aqc_ptp_tx_ts_event *tx_ts_event)
{
	struct nse_ptp_port *ptp_port = container_of(tx, struct nse_ptp_port, tx);
	struct nse_pf *pf = ptp_port_to_pf(ptp_port);
	struct nse_hw *hw = &pf->hw;
	struct nse_aqc_ptp_tx_ts *sample_ts = NULL;
	unsigned int idx;
	u32 ts_vld;

	if (!tx->init)
		return;

	bitmap_clear(tx->report, 0, tx->len);

	ts_vld = le32_to_cpu(tx_ts_event->tx_ts_vld_l);
	for (idx = 0; idx < 32; idx++) {
		if (ts_vld & BIT(idx))
			set_bit(idx, tx->report);
	}

#if defined(NSE_DEBUG_EXT)
	nse_debug(hw, NSE_DBG_PTP, "[%s]: tx_ts_event -> tx_ts_vld_l = %X\n", __func__, ts_vld);
#endif

	ts_vld = le32_to_cpu(tx_ts_event->tx_ts_vld_h);
	for (idx = 0; idx < 32; idx++) {
		if (ts_vld & BIT(idx))
			set_bit((idx+32), tx->report);
	}

#if defined(NSE_DEBUG_EXT)
	nse_debug(hw, NSE_DBG_PTP, "[%s]: tx_ts_event -> tx_ts_vld_h = %X\n", __func__, ts_vld);
#endif

	sample_ts = tx_ts_event->tx_ts;

	for_each_set_bit(idx, tx->report, tx->len) {
		struct skb_shared_hwtstamps shhwtstamps = {};
		struct timespec64 ts;
		u64 tstamp_raw_ns;
		struct sk_buff *skb;

		if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
			ts.tv_sec = le32_to_cpu(sample_ts->tx_ts_high);
			ts.tv_nsec = le32_to_cpu(sample_ts->tx_ts_low);

			tstamp_raw_ns = (u64)timespec64_to_ns(&ts);

		} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
			tstamp_raw_ns = le32_to_cpu(sample_ts->tx_ts_low);

			tstamp_raw_ns |= ((u64)le32_to_cpu(sample_ts->tx_ts_high)) << 32;

			ts = ns_to_timespec64(tstamp_raw_ns);
		}

		shhwtstamps.hwtstamp = ns_to_ktime(tstamp_raw_ns);

#if defined(NSE_DEBUG_EXT)
		/* log for debug */
		nse_debug(hw, NSE_DBG_PTP, "[%s]: tx_ts_event[%d]: sample(high=%X, low=%X), tspec(sec=%ld, nsec=%ld)\n",
							__func__, idx,
							le32_to_cpu(sample_ts->tx_ts_high),
								le32_to_cpu(sample_ts->tx_ts_low),
							(unsigned long)ts.tv_sec,
								(unsigned long)ts.tv_nsec);
		ts = ktime_to_timespec64(ktime_get_real());
		nse_debug(hw, NSE_DBG_PTP, "\t current OS time: sec=%ld, nsec=%ld\n",
							(unsigned long)ts.tv_sec,
								(unsigned long)ts.tv_nsec);
		nse_debug(hw, NSE_DBG_PTP, "\t start_jiffies=%ld, current_jiffies=%ld, delta_jiffies=%ld, delta_jiffies_msecs=%d\n",
							tx->tstamps[idx].start,
								(unsigned long)jiffies,
							((unsigned long)jiffies -
							 tx->tstamps[idx].start),
							(jiffies_to_msecs(jiffies) -
							 jiffies_to_msecs(tx->tstamps[idx].start)));
#endif

		sample_ts++;	/* in advance, go to next ts for next iteration */

		/* The timestamp is valid, so we'll go ahead and clear this
		 * index and then send the timestamp up to the stack.
		 */
		spin_lock_bh(&tx->lock);
		clear_bit(idx, tx->in_use);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		spin_unlock_bh(&tx->lock);

		/* it's (unlikely but) possible we raced with the cleanup
		 * thread for discarding old timestamp requests.
		 */
		if (!skb)
			continue;

		nse_trace(tx_tstamp_complete, skb, idx);

		skb_tstamp_tx(skb, &shhwtstamps);
		dev_kfree_skb_any(skb);
	}
}

/**
 * nse_ptp_request_ts - Request an available Tx timestamp index
 * @tx: the PTP Tx timestamp tracker to request from
 * @skb: the SKB to associate with this timestamp request
 */
s8 nse_ptp_request_ts(struct nse_ptp_tx *tx, struct sk_buff *skb)
{
	u8 idx;

	/* Check if this tracker is initialized */
	if (!tx->init)
		return -1;

	spin_lock_bh(&tx->lock);
	/* Find and set the first available index */
	idx = find_first_zero_bit(tx->in_use, tx->len);
	if (idx < tx->len) {
		/* We got a valid index that no other thread could have set.
		 * Store a reference to the skb and the start time to allow
		 * discarding old requests.
		 */
		set_bit(idx, tx->in_use);
		tx->tstamps[idx].start = jiffies;
		tx->tstamps[idx].skb = skb_get(skb);
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		nse_trace(tx_tstamp_request, skb, idx);
	}

	spin_unlock_bh(&tx->lock);

	/* return the appropriate PHY timestamp register index, -1 if no
	 * indexes were available.
	 */
	if (idx >= tx->len)
		return -1;
	else
		return idx;
}

/**
 * nse_ptp_process_ts - Spawn kthread work to handle timestamps
 * @pf: Board private structure
 *
 * Queue work required to process the PTP Tx timestamps outside of interrupt
 * context.
 */
void nse_ptp_process_ts(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aqc_ptp_tx_ts_event *tx_ts_event =
		(struct nse_aqc_ptp_tx_ts_event *)event->msg_buf;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags) || !test_bit(NSE_FLAG_PTP, pf->flags))
		return;

	if (!pf->ptp.port.tx.init) {
		dev_info(dev, "[%s, %d] not init?\n", __func__, __LINE__);
		return;
	}

	/* this event is not for us? */
	if (tx_ts_event->lan_id != pf->hw.lan_id) {
		dev_info(dev, "how come tx_ts_event is not for me?\n");
		return;
	}

	nse_ptp_tx_tstamp(&pf->ptp.port.tx, tx_ts_event);
}

/**
 * nse_ptp_alloc_tx_tracker - Initialize tracking for Tx timestamps
 * @tx: Tx tracking structure to initialize
 *
 * Assumes that the length has already been initialized. Do not call directly,
 * use the nse_ptp_init_tx_* instead.
 */
static int
nse_ptp_alloc_tx_tracker(struct nse_ptp_tx *tx)
{
	tx->tstamps = kcalloc(tx->len, sizeof(*tx->tstamps), GFP_KERNEL);
	if (!tx->tstamps)
		return -ENOMEM;

	tx->in_use = bitmap_zalloc(tx->len, GFP_KERNEL);
	tx->report = bitmap_zalloc(tx->len, GFP_KERNEL);
	if (!tx->in_use || !tx->report) {
		if (tx->in_use)
			bitmap_free(tx->in_use);

		if (tx->report)
			bitmap_free(tx->report);

		tx->in_use = NULL;
		tx->report = NULL;

		kfree(tx->tstamps);
		tx->tstamps = NULL;
		return -ENOMEM;
	}

	spin_lock_init(&tx->lock);

	tx->init = 1;

	return 0;
}

/**
 * nse_ptp_flush_tx_tracker - Flush any remaining timestamps from the tracker
 * @pf: Board private structure
 * @tx: the tracker to flush
 */
static void
nse_ptp_flush_tx_tracker(struct nse_pf *pf, struct nse_ptp_tx *tx)
{
	u8 idx;

	for (idx = 0; idx < tx->len; idx++) {
		spin_lock_bh(&tx->lock);
		if (tx->tstamps[idx].skb) {
			dev_kfree_skb_any(tx->tstamps[idx].skb);
			tx->tstamps[idx].skb = NULL;
		}
		clear_bit(idx, tx->in_use);
		spin_unlock_bh(&tx->lock);
	}

	(void)nse_clear_all_phy_tstamp(&pf->hw);
}

/**
 * nse_ptp_release_tx_tracker - Release allocated memory for Tx tracker
 * @pf: Board private structure
 * @tx: Tx tracking structure to release
 *
 * Free memory associated with the Tx timestamp tracker.
 */
static void
nse_ptp_release_tx_tracker(struct nse_pf *pf, struct nse_ptp_tx *tx)
{
	tx->init = 0;

	nse_ptp_flush_tx_tracker(pf, tx);

	kfree(tx->tstamps);
	tx->tstamps = NULL;

	bitmap_free(tx->in_use);
	tx->in_use = NULL;

	bitmap_free(tx->report);
	tx->report = NULL;

	tx->len = 0;
}

/**
 * nse_ptp_init_tx - Initialize tracking for Tx timestamps
 * @pf: Board private structure
 * @tx: the Tx tracking structure to initialize
 *
 * Initialize the Tx timestamp tracker for this PF.
 */
static int
nse_ptp_init_tx(struct nse_pf *pf, struct nse_ptp_tx *tx)
{
	tx->len = TSYN_REG_NUM_PER_PORT;

	return nse_ptp_alloc_tx_tracker(tx);
}

/**
 * nse_ptp_tx_tstamp_cleanup - Cleanup old timestamp requests that got dropped
 * @hw: pointer to the hw struct
 * @tx: PTP Tx tracker to clean up
 *
 * Loop through the Tx timestamp requests and see if any of them have been
 * waiting for a long time. Discard any SKBs that have been waiting for more
 * than 2 seconds. This is long enough to be reasonably sure that the
 * timestamp will never be captured. This might happen if the packet gets
 * discarded before it reaches the PHY timestamping block.
 */
static void nse_ptp_tx_tstamp_cleanup(struct nse_hw *hw, struct nse_ptp_tx *tx)
{
	u8 idx;

	if (!tx->init)
		return;

	for_each_set_bit(idx, tx->in_use, tx->len) {
		struct sk_buff *skb;

		/* Check if this SKB has been waiting for too long */
		if (time_is_after_jiffies(tx->tstamps[idx].start + 2 * HZ))
			continue;

		nse_debug(hw, NSE_DBG_PTP, "[%s]: idx=%d, not get TX-TS in time, free this idx\n",
			  __func__, idx);

		/* Read tstamp to be able to use this register again */
		nse_clear_phy_tstamp(hw, idx);

		spin_lock_bh(&tx->lock);
		skb = tx->tstamps[idx].skb;
		tx->tstamps[idx].skb = NULL;
		clear_bit(idx, tx->in_use);
		spin_unlock_bh(&tx->lock);

		/* Free the SKB after we've cleared the bit */
		dev_kfree_skb_any(skb);
	}
}

static void nse_ptp_periodic_work(struct kthread_work *work)
{
	struct nse_ptp *ptp = container_of(work, struct nse_ptp, work.work);
	struct nse_pf *pf = container_of(ptp, struct nse_pf, ptp);
	int err = 0;

	if (!test_bit(NSE_FLAG_PTP, pf->flags))
		return;

	nse_ptp_tx_tstamp_cleanup(&pf->hw, &pf->ptp.port.tx);

	if ((ptp->tstamp_config.tx_type != HWTSTAMP_TX_OFF ||
			ptp->tstamp_config.rx_filter != HWTSTAMP_FILTER_NONE) &&
			time_is_before_jiffies(ptp->cached_last_update + 32 * HZ)) {
		err = nse_ptp_update_cached_phctime(pf);
	}

	/* Run twice a second or reschedule if PHC update failed */
	kthread_queue_delayed_work(ptp->kworker, &ptp->work,
				   msecs_to_jiffies(err ? 10 : 2000));
}

/**
 * nse_ptp_reset - Initialize PTP hardware clock support after reset
 * @pf: Board private structure
 */
void nse_ptp_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct nse_ptp *ptp = &pf->ptp;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	int err;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	/* Acquire the global hardware lock */
	if (!nse_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(dev, "[%s] FAIL: lock before reset, err=%d\n",
						__func__, err);
		goto err_out;
	}

	status = nse_ptp_init_phc(hw);
	if (status) {
		err = nse_status_to_errno(status);
		dev_err(dev, "[%s] FAIL: ptp_init_phc(), status=%s, err=%d\n",
						__func__, nse_stat_str(status), err);

		nse_ptp_unlock(hw);
		goto err_out;
	}

	/* Release the global hardware lock */
	nse_ptp_unlock(hw);

	/* Restart the PHY timestamping block */
	nse_ptp_reset_phy_timestamping(pf);

	/* Init Tx structures */
	err = nse_ptp_init_tx(pf, &ptp->port.tx);
	if (err) {
		dev_err(dev, "[%s] FAIL: ptp_init_tx(), err=%d\n",
						__func__, err);
		goto err_out;
	}

	set_bit(NSE_FLAG_PTP, pf->flags);

	/* Start periodic work going */
	kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	/* reverse nse_ptp_cfg_timestamp(pf, false) in nse_ptp_prepare_for_reset() */
	if (ptp->user_rx_ts_sample_status)
		nse_set_rx_tstamp(pf, true);
	if (ptp->user_tx_ts_sample_status)
		nse_set_tx_tstamp(pf, true);

	dev_info(dev, "[%s] SUCCESS\n", __func__);
	return;

err_out:
	dev_err(dev, "[%s] FAIL: err=%d\n", __func__, err);
}

/**
 * nse_ptp_prepare_for_reset - Prepare PTP for reset
 * @pf: Board private structure
 */
void nse_ptp_prepare_for_reset(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct nse_ptp *ptp = &pf->ptp;

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		return;

	clear_bit(NSE_FLAG_PTP, pf->flags);

	/* Disable timestamping for both Tx and Rx */
	nse_ptp_cfg_timestamp(pf, false);

	kthread_cancel_delayed_work_sync(&ptp->work);

	nse_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	/* Disable periodic outputs */
	nse_ptp_disable_all_clkout(pf);

	/* Acquire PHC and system timer to restore after reset */
	ptp->reset_time = ktime_get_real_ns();
}

/**
 * nse_ptp_init_owner - Initialize PTP_1588_CLOCK device
 * @pf: Board private structure
 *
 * Setup and initialize a PTP clock device that represents the device hardware
 * clock.
 */
static int nse_ptp_init_owner(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_ptp *ptp = &pf->ptp;
	enum nse_status status;
	int err;

	/* get base INCVAL */
	nse_dflt_ptp_hw_setting(pf, ptp);

	/* Acquire the global hardware lock */
	if (!nse_ptp_lock(hw)) {
		err = -EBUSY;
		dev_err(nse_pf_to_dev(pf), "[%s]: fail to lock, ret=%d\n", __func__, err);
		goto err_exit;
	}

	status = nse_ptp_init_phc(hw);
	if (status) {
		err = nse_status_to_errno(status);
		dev_err(dev, "[%s]: fail to ptp_init_phc(), ret=%d, status=%s\n",
						__func__,
						err, nse_stat_str(status));

		nse_ptp_unlock(hw);
		goto err_exit;
	}

	/* Release the global hardware lock */
	nse_ptp_unlock(hw);

	/* Ensure we have a clock device */
	err = nse_ptp_create_clock(pf);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "Failed to register PTP clock device");
		goto err_clk;
	}

	return 0;

err_clk:
	pf->ptp.clock = NULL;
err_exit:
	return err;
}

/**
 * nse_ptp_init_work - Initialize PTP work threads
 * @pf: Board private structure
 * @ptp: PF PTP structure
 */
static int nse_ptp_init_work(struct nse_pf *pf, struct nse_ptp *ptp)
{
	struct kthread_worker *kworker;

	/* Initialize work functions */
	kthread_init_delayed_work(&ptp->work, nse_ptp_periodic_work);

	/* Allocate a kworker for handling work required for the ports
	 * connected to the PTP hardware clock.
	 */
	kworker = kthread_create_worker(0, "nse-ptp-%s",
					dev_name(nse_pf_to_dev(pf)));
	if (IS_ERR(kworker))
		return PTR_ERR(kworker);

	ptp->kworker = kworker;

	/* Start periodic work going */
	kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	return 0;
}

/**
 * nse_ptp_init_port - Initialize PTP port structure
 * @pf: Board private structure
 * @ptp_port: PTP port structure
 */
static int nse_ptp_init_port(struct nse_pf *pf, struct nse_ptp_port *ptp_port)
{
	return nse_ptp_init_tx(pf, &ptp_port->tx);
}

/**
 * nse_ptp_init - Initialize PTP hardware clock support
 * @pf: Board private structure
 *
 * Set up the device for interacting with the PTP hardware clock for all
 * functions, both the function that owns the clock hardware, and the
 * functions connected to the clock hardware.
 *
 * The clock owner will allocate and register a ptp_clock with the
 * PTP_1588_CLOCK infrastructure. All functions allocate a kthread and work
 * items used for asynchronous work such as Tx timestamps and periodic work.
 */
void nse_ptp_init(struct nse_pf *pf)
{
	struct nse_ptp *ptp = &pf->ptp;
	struct nse_hw *hw = &pf->hw;
	int err;

#if defined(NSE_DEBUG_EXT)
	ptp->debug_rx_ts = NULL;
#endif

	if (!test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		return;

	err = nse_ptp_init_owner(pf);
	if (err)
		goto err_exit;

	ptp->port.port_num = hw->lan_id;
	err = nse_ptp_init_port(pf, &ptp->port);
	if (err)
		goto err_exit;

	/* Start the PHY timestamping block */
	nse_ptp_reset_phy_timestamping(pf);

	set_bit(NSE_FLAG_PTP, pf->flags);	//better set it before init_work()

	err = nse_ptp_init_work(pf, ptp);
	if (err)
		goto err_exit;

#if defined(NSE_DEBUG_EXT)
	ptp->debug_rx_ts = alloc_percpu(struct debug_rx_ts_s);
#endif

	dev_info(nse_pf_to_dev(pf), "PTP init successful\n");
	return;

err_exit:
	/* If we registered a PTP clock, release it */
	if (pf->ptp.clock) {
		ptp_clock_unregister(ptp->clock);
		pf->ptp.clock = NULL;
	}
	clear_bit(NSE_FLAG_PTP, pf->flags);
	nse_dev_err_errno(nse_pf_to_dev(pf), err, "PTP init failed");
}

/**
 * nse_ptp_release - Disable the driver/HW support and unregister the clock
 * @pf: Board private structure
 *
 * This function handles the cleanup work required from the initialization by
 * clearing out the important information and unregistering the clock
 */
void nse_ptp_release(struct nse_pf *pf)
{
	struct nse_vsi *vsi;
	char *dev_name;

	if (!pf)
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi || !test_bit(NSE_FLAG_PTP, pf->flags))
		return;

	dev_name = vsi->netdev->name;

	/* Disable timestamping for both Tx and Rx */
	nse_ptp_cfg_timestamp(pf, false);

	nse_ptp_release_tx_tracker(pf, &pf->ptp.port.tx);

	clear_bit(NSE_FLAG_PTP, pf->flags);

	kthread_cancel_delayed_work_sync(&pf->ptp.work);

	if (pf->ptp.kworker) {
		kthread_destroy_worker(pf->ptp.kworker);
		pf->ptp.kworker = NULL;
	}

#if defined(NSE_DEBUG_EXT)
	if (pf->ptp.debug_rx_ts) {
		free_percpu(pf->ptp.debug_rx_ts);
		pf->ptp.debug_rx_ts = NULL;
	}
#endif

	if (!pf->ptp.clock)
		return;

	/* Disable periodic outputs */
	nse_ptp_disable_all_clkout(pf);

	ptp_clock_unregister(pf->ptp.clock);
	pf->ptp.clock = NULL;

	/* Free pin config */
	if (pf->ptp.info.pin_config) {
		devm_kfree(nse_pf_to_dev(pf), pf->ptp.info.pin_config);
		pf->ptp.info.pin_config = NULL;
	}

	dev_info(nse_pf_to_dev(pf), "removed Clock from %s\n", dev_name);
}

