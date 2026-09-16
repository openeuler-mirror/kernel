// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_type.h"
#include "nse_common.h"
#include "nse_ptp_hw.h"

bool nse_ptp_lock(struct nse_hw *hw)
{
	return true;
}
void nse_ptp_unlock(struct nse_hw *hw)
{
	/* Do nothing for now. */
}

/**
 * nse_ptp_init_time - Initialize device time to provided value
 * @hw: pointer to HW struct
 * @time: 64bits of time
 */
enum nse_status nse_ptp_init_time(struct nse_hw *hw, struct timespec64 *ts)
{
	return nse_aq_ptp_set_sys_time_by_sec_nsec(hw, (u32)ts->tv_sec, (u32)ts->tv_nsec);
}

/**
 * nse_ptp_write_incval - Program PHC with new increment value
 * @hw: pointer to HW struct
 * @incval: Source timer increment value per clock cycle
 */
enum nse_status nse_ptp_write_incval_sec_subnsec(struct nse_hw *hw, u32 nsec_part, u32 subnsec_part)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 incval;

	if (hw->hw_conf.hw_lmac_type != NSE_HW_LMAC_TYPE_1) {
		dev_err(dev, "[%s] not support this way, use another way.\n", __func__);
		return NSE_ERR_NOT_SUPPORTED;
	}

	if (nsec_part > 0xFF) {
		dev_err(dev, "your frequency setting too high, not fit into INCVAL SSINC range\n");
		return NSE_ERR_PARAM;
	}

	if (subnsec_part)
		dev_warn(dev, "your frequency setting cause subns granularity, may not be that accurate\n");
	if (subnsec_part > 0xFF) {
		dev_err(dev, "your frequency setting too weird, not fit into INCVAL SNSINC range\n");
		return NSE_ERR_PARAM;
	}

	incval = (nsec_part << 16) | (subnsec_part << 8);

	return nse_aq_ptp_set_incval(hw, incval);
}

/**
 * nse_ptp_write_incval_locked - Program new incval while holding semaphore
 * @hw: pointer to HW struct
 * @incval: Source timer increment value per clock cycle
 *
 * Program a new PHC incval while holding the PTP semaphore.
 */
enum nse_status nse_ptp_write_incval_sec_subnsec_locked(struct nse_hw *hw,
							u32 nsec_part, u32 subnsec_part)
{
	enum nse_status status;

	if (!nse_ptp_lock(hw))
		return NSE_ERR_NOT_READY;

	status = nse_ptp_write_incval_sec_subnsec(hw, nsec_part, subnsec_part);

	nse_ptp_unlock(hw);

	return status;
}

enum nse_status nse_ptp_write_incval_raw_locked(struct nse_hw *hw, u32 raw_value)
{
	enum nse_status status;

	if (!nse_ptp_lock(hw))
		return NSE_ERR_NOT_READY;

	status = nse_aq_ptp_set_incval(hw, raw_value);

	nse_ptp_unlock(hw);

	return status;
}

enum nse_status nse_ptp_write_addend(struct nse_hw *hw, u32 addend)
{
	return nse_aq_ptp_set_addend(hw, addend);
}

enum nse_status nse_ptp_write_addend_locked(struct nse_hw *hw, u32 addend)
{
	enum nse_status status;

	if (!nse_ptp_lock(hw))
		return NSE_ERR_NOT_READY;

	status = nse_ptp_write_addend(hw, addend);

	nse_ptp_unlock(hw);

	return status;
}

static enum nse_status nse_ptp_adj_clock_amber(struct nse_hw *hw, s64 adj)
{
	struct timespec64 ts;
	u32 sec_part = 0, nsec_part = 0;
	bool neg_adj = false;

	if (adj < 0) {
		neg_adj = true;
		adj = -adj;
	}

	ts = ns_to_timespec64(adj);

	if (neg_adj) {
		sec_part = 0xFFFFFFFF - (u32)ts.tv_sec;
		sec_part += 1;

		nsec_part = NSEC_PER_SEC - (u32)ts.tv_nsec;
		nsec_part |= BIT(31);
	} else {
		sec_part = (u32)ts.tv_sec;

		nsec_part = (u32)ts.tv_nsec;
	}

	return nse_aq_ptp_adj_sys_time_amber(hw, sec_part, nsec_part);
}

static enum nse_status nse_ptp_adj_clock_ms(struct nse_hw *hw, s64 adj)
{
	bool neg_adj = false;
	u32 val_h, val_l;

	if (adj < 0) {
		neg_adj = true;
		adj = -adj;
	}

	val_l = (u64)adj;

	val_h = neg_adj ? BIT(31) : 0;
	val_h |= (((u64)adj >> 32) & 0x7FFFFFFF);	/* actually, & is not unnecessary ... */

	return nse_aq_ptp_adj_sys_time_ms(hw, val_h, val_l);
}

/**
 * nse_ptp_adj_clock - Adjust PHC clock time atomically
 * @hw: pointer to HW struct
 * @adj: Adjustment in nanoseconds
 */
enum nse_status nse_ptp_adj_clock(struct nse_hw *hw, s64 adj)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		return nse_ptp_adj_clock_amber(hw, adj);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		return nse_ptp_adj_clock_ms(hw, adj);
	else
		return NSE_ERR_NOT_SUPPORTED;
}

/**
 * nse_read_phy_tstamp - Read a PHY timestamp from the timestamp block
 * @hw: pointer to the HW struct
 * @idx: the timestamp index to read
 */
enum nse_status
nse_read_phy_tstamp(struct nse_hw *hw, u8 idx, u32 *sec_part, u32 *nsec_part)
{
	struct nse_aqc_ptp_rd_clr_tx_ts cmd_buf;
	enum nse_status status;

	cmd_buf.lan_id = hw->lan_id;
	cmd_buf.reg_idx = idx;

	status = nse_aq_ptp_read_tx_ts(hw, &cmd_buf);
	if (!status) {
		*sec_part = le32_to_cpu(cmd_buf.tx_ts.tx_ts_high);
		*nsec_part = le32_to_cpu(cmd_buf.tx_ts.tx_ts_low);
	}

	return status;
}

/**
 * nse_clear_phy_tstamp - Clear a timestamp from the timestamp block
 * @hw: pointer to the HW struct
 * @idx: the timestamp index to reset
 *
 * Clear a timestamp, resetting its valid bit, from the timestamp block.
 */
enum nse_status
nse_clear_phy_tstamp(struct nse_hw *hw, u8 idx)
{
	struct nse_aqc_ptp_rd_clr_tx_ts cmd_buf;

	cmd_buf.lan_id = hw->lan_id;
	cmd_buf.reg_idx = idx;

	return nse_aq_ptp_clear_tx_ts(hw, &cmd_buf);
}

enum nse_status
nse_clear_all_phy_tstamp(struct nse_hw *hw)
{
	struct nse_aqc_ptp_rd_clr_tx_ts cmd_buf;

	cmd_buf.lan_id = hw->lan_id;
	cmd_buf.reg_idx = NSE_AQC_PTP_TX_TS_ALL_REG;

	return nse_aq_ptp_clear_tx_ts(hw, &cmd_buf);
}

static enum nse_status nse_ptp_init_phc_amber(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ptp *ptp = &pf->ptp;
	struct nse_aqc_ptp_init init_cmd_buf;
	struct nse_aqc_ptp_init_amber *init_cmd_buf_amber;
	struct timespec64 curr_time;
	u32 var;
	enum nse_status status;

	/* issue aq-cmd: NSE_AQ_OPC_PTP_INIT */

	memset(&init_cmd_buf, 0, sizeof(init_cmd_buf));

	init_cmd_buf_amber = &init_cmd_buf.amber;

	init_cmd_buf_amber->lan_id = hw->lan_id;
	init_cmd_buf_amber->flags = 0;		/* don't set correction value for now. */

	curr_time = ns_to_timespec64(ktime_get_real_ns());
	init_cmd_buf_amber->sec = cpu_to_le32((u32)curr_time.tv_sec);
	init_cmd_buf_amber->nsec = cpu_to_le32((u32)curr_time.tv_nsec);

	var = (AMBER_AQC_PTP_CONTROL_TSCTRLSSR |
				AMBER_AQC_PTP_CONTROL_TSENALL |
				AMBER_AQC_PTP_CONTROL_TSENA);
	if (pf->sw_conf.ptp_fine_mode)
		var |= AMBER_AQC_PTP_CONTROL_TSCFUPDT;

	init_cmd_buf_amber->control = cpu_to_le32(var);

	var = (ptp->dflt_incval.amber.nsec_part << 16) |
			(ptp->dflt_incval.amber.subnsec_part << 8);
	init_cmd_buf_amber->incval = cpu_to_le32(var);

	if (pf->sw_conf.ptp_fine_mode)
		init_cmd_buf_amber->addend = ptp->dflt_fine_addend;

	init_cmd_buf_amber->rdm_rx_ts_en = cpu_to_le32(RDM_RX_TS_EN_BIT);
	init_cmd_buf_amber->rpp_rx_ts_en = cpu_to_le32(RPP_RX_TS_EN_BIT);

	status = nse_aq_ptp_init(hw, &init_cmd_buf);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ptp_init(), status=%d (%s)\n",
						__func__, status, nse_stat_str(status));
		return status;
	}

	curr_time = ns_to_timespec64(ktime_get_real_ns());
	status = nse_aq_ptp_set_sys_time_by_sec_nsec(hw, (u32)curr_time.tv_sec,
						     (u32)curr_time.tv_nsec);
	if (status)
		dev_err(dev, "[%s] FAIL: aq_ptp_set_sys_time_by_sec_nsec(), status=%d (%s)\n",
						__func__, status, nse_stat_str(status));

	return status;
}

static enum nse_status nse_ptp_init_phc_ms(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ptp *ptp = &pf->ptp;
	struct nse_aqc_ptp_init init_cmd_buf;
	struct nse_aqc_ptp_init_ms *init_cmd_buf_ms;
	u64 val64;
	u32 val32;
	enum nse_status status;

	/* issue aq-cmd: NSE_AQ_OPC_PTP_INIT */

	memset(&init_cmd_buf, 0, sizeof(init_cmd_buf));

	init_cmd_buf_ms = &init_cmd_buf.ms;

	init_cmd_buf_ms->lan_id = hw->lan_id;

	val64 = ktime_get_real_ns();
	init_cmd_buf_ms->systime_h = cpu_to_le32((u32)(val64 >> 32));
	init_cmd_buf_ms->systime_l = cpu_to_le32((u32)(val64));

	val32 = (((u32)ptp->dflt_incval.ms.period_part <<
		 MS_AQC_PTP_INC_PERIOD_S) & MS_AQC_PTP_INC_PERIOD_M) |
			(((u32)ptp->dflt_incval.ms.value_part <<
			 MS_AQC_PTP_INC_VAL_S) & MS_AQC_PTP_INC_VAL_M);
	init_cmd_buf_ms->inc = cpu_to_le32(val32);

	init_cmd_buf_ms->rdm_rx_ts_en = cpu_to_le32(RDM_RX_TS_EN_BIT);
	init_cmd_buf_ms->rpp_rx_ts_en = cpu_to_le32(RPP_RX_TS_EN_BIT);

	status = nse_aq_ptp_init(hw, &init_cmd_buf);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ptp_init(), status=%d (%s)\n",
						__func__, status, nse_stat_str(status));
		return status;
	}

	val64 = ktime_get_real_ns();

	status = nse_aq_ptp_set_sys_time_by_nsec(hw, val64);
	if (status)
		dev_err(dev, "[%s] FAIL: aq_ptp_set_sys_time_by_nsec(), status=%d (%s)\n",
						__func__, status, nse_stat_str(status));

	return status;
}

/**
 * nse_ptp_init_phc - Initialize PTP hardware clock
 * @hw: pointer to the HW struct
 *
 * Perform the steps required to initialize the PTP hardware clock.
 */
enum nse_status nse_ptp_init_phc(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_psr_set_ctrl psr_cmd_buf;
	enum nse_status status;

	/* issue aq-cmd, to configure PSR
	 *
	 * don't care if fails, because our MAC is gonna sample all.
	 */
	memset(&psr_cmd_buf, 0, sizeof(psr_cmd_buf));

	psr_cmd_buf.flags = cpu_to_le32(NSE_AQC_PSR_SET_CTRL_FLAG_RPSR |
					NSE_AQC_PSR_SET_CTRL_FLAG_TPSR);
	psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_TS_ET;
	psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */
	psr_cmd_buf.port_or_etype = cpu_to_le16(ETH_P_1588);

	(void)nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);

	psr_cmd_buf.flags = cpu_to_le32(NSE_AQC_PSR_SET_CTRL_FLAG_RPSR |
					NSE_AQC_PSR_SET_CTRL_FLAG_TPSR);
	psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_TS_UDP;
	psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */
	psr_cmd_buf.port_or_etype = cpu_to_le16(0x013F);

	(void)nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		status = nse_ptp_init_phc_amber(hw);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		status = nse_ptp_init_phc_ms(hw);
	else {
		dev_err(dev, "[%s] mac_type (%d) not supported\n", __func__, hw->mac_type);
		status = NSE_ERR_NOT_SUPPORTED;
	}

	return status;
}

