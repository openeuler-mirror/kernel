// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_dcb_lib.h"
#include "nse_dcb_nl.h"

/**
 * nse_dcb_get_mode - gets the DCB mode
 * @port_info: pointer to port info structure
 * @host: if set it's HOST if not it's MANAGED
 */
static u8 nse_dcb_get_mode(struct nse_port_info *port_info, bool host)
{
	u8 mode;

	if (host)
		mode = DCB_CAP_DCBX_HOST;
	else
		mode = DCB_CAP_DCBX_LLD_MANAGED;

	return mode | DCB_CAP_DCBX_VER_IEEE;
}

bool nse_dcb_sanity_check_tc(struct nse_pf *pf, struct nse_dcbx_cfg *dcbcfg)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *main_vsi = pf ? nse_get_main_vsi(pf) : NULL;
	bool tc_unused = false;
	u8 tc_bitmap = 0;
	u8 tc_number = 0;
	int i;

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++)
		tc_bitmap |= BIT(dcbcfg->etscfg.prio_table[i]);

	/* Scan bitmask for contiguous TCs starting with TC0 */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (tc_bitmap & BIT(i)) {
			if (!tc_unused) {
				tc_number++;
			} else {
				pr_err("Non-contiguous TCs - Not support\n");
				return false;
			}
		} else {
			tc_unused = true;
		}
	}

	if (!tc_number) {	/* impossible */
		pr_err("No TC enabled ? At least enable one TC-0\n");
		return false;
	}

	if (tc_number & (tc_number - 1)) {
		pr_err("TCs must be 2^N (1, 2, 4, 8) starting from 0\n");
		return false;
	}

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA &&
			!nse_qos_db_use_share &&
			tc_number > hw->hw_conf.max_tc_allowed) {
		pr_err("On FPGA, if db_use_share = 0, TC numbers must be not be too many, not larger than %d\n",
		       hw->hw_conf.max_tc_allowed);
		return false;
	}

	if (main_vsi) {
		if (main_vsi->alloc_rxq < tc_number ||
			main_vsi->alloc_txq < tc_number) {
			pr_err("main_vsi alloc_rxq=%d, alloc_txq=%d, can not satisfy tc_num=%d\n",
						main_vsi->alloc_rxq,
							main_vsi->alloc_txq, tc_number);
			return false;
		}
	}

	return true;
}

/**
 * nse_dcb_get_num_tc - Get the number of TCs from DCBX config
 * @dcbcfg: config to retrieve number of TCs from
 */
u8 nse_dcb_get_num_tc(struct nse_dcbx_cfg *dcbcfg)
{
	bool tc_unused = false;
	u8 tc_bitmap = 0;
	u8 ret = 0;
	int i;

	/* Scan the ETS Config Priority Table to find traffic classes
	 * enabled and create a bitmask of enabled TCs
	 */
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++)
		tc_bitmap |= BIT(dcbcfg->etscfg.prio_table[i]);

	/* Scan bitmask for contiguous TCs starting with TC0 */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (tc_bitmap & BIT(i)) {
			if (!tc_unused) {
				ret++;
			} else {
				pr_err("Non-contiguous TCs - Disabling DCB\n");
				return 1;
			}
		} else {
			tc_unused = true;
		}
	}

	/* There is always at least 1 TC */
	if (!ret)
		ret = 1;

	/* For convenience, our TC MUST be 2 ^ N, that is:
	 *
	 *		1, 2, 4, 8
	 *
	 * If not, then force it to be 1 TC
	 */
	if (ret & (ret - 1)) {
		pr_err("TCs must be 2^N (1, 2, 4, 8) starting from 0 - Disabling DCB\n");
		ret = 1;
	}

	return ret;
}

/**
 * nse_dcb_get_ena_tc - return bitmap of enabled TCs
 * @dcbcfg: DCB config to evaluate for enabled TCs
 */
u8 nse_dcb_get_ena_tc(struct nse_dcbx_cfg *dcbcfg)
{
	u8 i, num_tc, ena_tc = 1;

	num_tc = nse_dcb_get_num_tc(dcbcfg);

	for (i = 0; i < num_tc; i++)
		ena_tc |= BIT(i);

	return ena_tc;
}

/**
 * nse_vsi_set_dcb_tc_cfg - Set VSI's TC based on DCB configuration
 * @vsi: pointer to the VSI instance
 */
void nse_vsi_set_dcb_tc_cfg(struct nse_vsi *vsi)
{
	struct nse_dcbx_cfg *cfg = &vsi->port_info->qos_cfg.local_dcbx_cfg;

	switch (vsi->type) {
	case NSE_VSI_PF:
		vsi->tc_cfg.ena_tc = nse_dcb_get_ena_tc(cfg);
		vsi->tc_cfg.numtc = nse_dcb_get_num_tc(cfg);
		break;
	case NSE_VSI_OFFLOAD_MACVLAN:
	case NSE_VSI_LB:
	case NSE_VSI_VF:
	case NSE_VSI_SWITCHDEV_CTRL:
	default:
		vsi->tc_cfg.ena_tc = NSE_DFLT_TRAFFIC_CLASS;
		vsi->tc_cfg.numtc = 1;
	}
}

/**
 * nse_dcb_get_tc - Get the TC associated with the queue
 * @vsi: ptr to the VSI
 * @queue_index: queue number associated with VSI
 */
u8 nse_dcb_get_tc(struct nse_vsi *vsi, int queue_index)
{
	return vsi->tx_rings[queue_index]->dcb_tc;
}

/**
 * nse_vsi_cfg_dcb_rings - Update rings to reflect DCB TC
 * @vsi: VSI owner of rings being updated
 */
void nse_vsi_cfg_dcb_rings(struct nse_vsi *vsi)
{
	u16 qoffset, qcount;
	int i, n;

	if (!test_bit(NSE_FLAG_DCB_ENA, vsi->back->flags)) {
		/* Reset the TC information */
		for (i = 0; i < vsi->num_txq; i++)
			vsi->tx_rings[i]->dcb_tc = 0;

		for (i = 0; i < vsi->num_rxq; i++)
			vsi->rx_rings[i]->dcb_tc = 0;

		return;
	}

	nse_for_each_traffic_class(n) {
		if (!(vsi->tc_cfg.ena_tc & BIT(n)))
			break;

		qoffset = vsi->tc_cfg.tc_info[n].qoffset;

		qcount = vsi->tc_cfg.tc_info[n].qcount_tx;
		for (i = qoffset; i < (qoffset + qcount); i++)
			vsi->tx_rings[i]->dcb_tc = n;

		qcount = vsi->tc_cfg.tc_info[n].qcount_rx;
		for (i = qoffset; i < (qoffset + qcount); i++)
			vsi->rx_rings[i]->dcb_tc = n;
	}

	if (vsi->type == NSE_VSI_OFFLOAD_MACVLAN) {
		nse_for_each_alloc_txq(vsi, i)
			vsi->tx_rings[i]->dcb_tc = 0;
		nse_for_each_alloc_rxq(vsi, i)
			vsi->rx_rings[i]->dcb_tc = 0;
	}
}

/**
 * nse_dcb_ena_dis_vsi - disable certain VSIs for DCB config/reconfig
 * @pf: pointer to the PF instance
 * @ena: true to enable VSIs, false to disable
 * @locked: true if caller holds RTNL lock, false otherwise
 *
 * Before a new DCB configuration can be applied, VSIs of type PF, MACVLAN,
 * and CHNL need to be brought down. Following completion of DCB configuration
 * the VSIs that were downed need to be brought up again. This helper function
 * does both.
 */
static void nse_dcb_ena_dis_vsi(struct nse_pf *pf, bool ena, bool locked)
{
	struct nse_hw *hw = &pf->hw;
	int i;

	nse_for_each_vsi(pf, i) {
		struct nse_vsi *vsi = pf->vsi[i];

		if (!vsi)
			continue;

		switch (vsi->type) {
		case NSE_VSI_PF:
			if (ena)
				nse_ena_vsi_under_pf_drv(hw, vsi, locked);
			else
				nse_dis_vsi_under_pf_drv(hw, vsi, locked);
			break;
		default:
			continue;
		}
	}
}

/**
 * nse_dcb_bwchk - check if ETS bandwidth input parameters are correct
 * @pf: pointer to the PF struct
 * @dcbcfg: pointer to DCB config structure
 */
int nse_dcb_bwchk(struct nse_pf *pf, struct nse_dcbx_cfg *dcbcfg)
{
	struct nse_dcb_ets_cfg *etscfg = &dcbcfg->etscfg;
	u8 num_tc, total_bw = 0;
	int i;

	/* returns number of contigous TCs and 1 TC for non-contigous TCs,
	 * since at least 1 TC has to be configured
	 */
	num_tc = nse_dcb_get_num_tc(dcbcfg);

	/* no bandwidth checks required if there's only one TC, so assign
	 * all bandwidth to TC0 and return
	 */
	if (num_tc == 1) {
		etscfg->tcbwtable[0] = NSE_TC_MAX_BW;
		return 0;
	}

	for (i = 0; i < num_tc; i++)
		total_bw += etscfg->tcbwtable[i];

	if (!total_bw) {
		etscfg->tcbwtable[0] = NSE_TC_MAX_BW;
	} else if (total_bw != NSE_TC_MAX_BW) {
		dev_err(nse_pf_to_dev(pf), "Invalid config, total bandwidth must equal 100\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_pf_dcb_cfg - Apply new DCB configuration
 * @pf: pointer to the PF struct
 * @new_cfg: DCBX config to apply
 * @locked: is the RTNL held
 */
int nse_pf_dcb_cfg(struct nse_pf *pf, struct nse_dcbx_cfg *new_cfg, bool set_all, bool locked)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_qos_cfg *qos_cfg = &hw->port_info->qos_cfg;
	struct nse_dcbx_cfg *old_cfg, *curr_cfg;
	struct iidc_event *event;
	int ret = NSE_DCB_NO_HW_CHG;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_DCB, "[%s] set_all=%d, locked=%d\n", __func__, set_all, locked);

	if (nse_dcb_bwchk(pf, new_cfg)) {
		dev_err(dev, "[%s] BAD: dcb_bwchk()\n", __func__);
		return -EINVAL;
	}

	curr_cfg = &qos_cfg->local_dcbx_cfg;

	/* Store old config in case FW config fails */
	old_cfg = kmemdup(curr_cfg, sizeof(*old_cfg), GFP_KERNEL);
	if (!old_cfg)
		return -ENOMEM;

	/* Notify capable aux drivers about impending change to TCs */
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		kfree(old_cfg);
		return -ENOMEM;
	}

	set_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
	nse_send_event_to_auxs(pf, event);
	kfree(event);

	/* avoid race conditions by holding the lock while disabling and
	 * re-enabling the VSI
	 */
	if (!locked)
		rtnl_lock();

	/* disable VSIs affected by DCB changes */
	nse_dcb_ena_dis_vsi(pf, false, true);

	memcpy(curr_cfg, new_cfg, sizeof(*curr_cfg));

	if (qos_cfg->dcbx_mode == NSE_QOS_DCBX_MODE_FW)	/* tell remote I will */
		curr_cfg->etscfg.willing = 1;

	memcpy(&curr_cfg->etsrec, &curr_cfg->etscfg, sizeof(curr_cfg->etsrec));

	status = nse_set_dcb_cfg(pf->hw.port_info, set_all);
	if (status) {
		dev_err(dev, "[%s, %d] FAIL: set_dcb_cfg(): %d (%s)\n", __func__, __LINE__,
						status, nse_stat_str(status));

		/* Restore previous settings to local config */
		memcpy(curr_cfg, old_cfg, sizeof(*curr_cfg));

		ret = -EIO;

		goto out;
	}

	ret = NSE_DCB_HW_CHG_RST;

	/* Enable DCB tagging only when more than one TC */
	if (nse_dcb_get_num_tc(new_cfg) > 1) {
		nse_debug(hw, NSE_DBG_DCB, "[%s] DCB tagging enabled (num TC > 1)\n", __func__);
		set_bit(NSE_FLAG_DCB_ENA, pf->flags);
	} else {
		nse_debug(hw, NSE_DBG_DCB,
			  "[%s] DCB tagging disabled (num TC = 1)\n", __func__);
		clear_bit(NSE_FLAG_DCB_ENA, pf->flags);
	}

	(void)nse_set_dcb_up_enforcement(&pf->hw, curr_cfg);

	nse_sched_set_tc_cir_by_dcbxcfg(&pf->hw, curr_cfg);

	nse_pf_dcb_recfg(pf);

out:
	/* enable previously downed VSIs */
	nse_dcb_ena_dis_vsi(pf, true, true);
	if (!locked)
		rtnl_unlock();
	kfree(old_cfg);
	return ret;
}

int nse_pf_dcb_cfg_lw(struct nse_pf *pf, struct nse_dcbx_cfg *new_cfg,
		      u32 cfg_chg_type, bool locked)
{
	struct nse_dcbx_cfg *old_cfg, *curr_cfg;
	struct device *dev = nse_pf_to_dev(pf);
	struct iidc_event *event = NULL;
	struct iidc_core_dev_info *cdev_info = NULL;
	int ret = NSE_DCB_NO_HW_CHG;
	enum nse_status status;

	dev_info(dev, "[%s] (cfg_chg_type=%X)\n", __func__, cfg_chg_type);

	if (nse_dcb_bwchk(pf, new_cfg)) {
		dev_err(dev, "[%s] BAD: dcb_bwchk()\n", __func__);
		return -EINVAL;
	}

	curr_cfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	/* Store old config in case FW config fails */
	old_cfg = kmemdup(curr_cfg, sizeof(*old_cfg), GFP_KERNEL);
	if (!old_cfg)
		return -ENOMEM;

	/* if allocation fails, just skip notifying RDMA */
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (event) {
		set_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
		nse_send_event_to_auxs(pf, event);
	}

	/* avoid race conditions by holding the lock while disabling and
	 * re-enabling the VSI
	 */
	if (!locked)
		rtnl_lock();

	memcpy(curr_cfg, new_cfg, sizeof(*curr_cfg));
	memcpy(&curr_cfg->etsrec, &curr_cfg->etscfg, sizeof(curr_cfg->etsrec));
	memcpy(&new_cfg->etsrec, &curr_cfg->etscfg, sizeof(curr_cfg->etsrec));

		status = nse_set_dcb_cfg_lw(pf->hw.port_info, cfg_chg_type);
		if (status) {
			dev_err(dev, "[%s, %d] FAIL: set_dcb_cfg(): %d (%s)\n",
				__func__, __LINE__,
						ret, nse_stat_str(ret));

			/* Restore previous settings to local config */
			memcpy(curr_cfg, old_cfg, sizeof(*curr_cfg));

			ret = -EIO;

			goto out;
		}

		(void)nse_set_dcb_up_enforcement(&pf->hw, curr_cfg);

	if (cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_TC_TSA_BW)
		nse_sched_set_tc_cir_by_dcbxcfg(&pf->hw, curr_cfg);

	/* Enable DCB tagging only when more than one TC */
	if (nse_dcb_get_num_tc(new_cfg) > 1) {
		dev_info(dev, "DCB tagging enabled (num TC > 1)\n");
		set_bit(NSE_FLAG_DCB_ENA, pf->flags);
	} else {
		dev_info(dev, "DCB tagging disabled (num TC = 1)\n");
		clear_bit(NSE_FLAG_DCB_ENA, pf->flags);
	}

	cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (cdev_info && event) {
		memset(event, 0, sizeof(*event));

		/* curr_cfg = local_dcbx_cfg == new_cfg */
		nse_setup_dcb_qos_info(pf, &cdev_info->qos_info);

		set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
		event->info.port_qos = cdev_info->qos_info;
		nse_send_event_to_auxs(pf, event);
	}

	ret = NSE_DCB_HW_CHG;

out:
	if (!locked)
		rtnl_unlock();

	kfree(event);

	kfree(old_cfg);

	return ret;
}

/**
 * nse_dcb_need_recfg - Check if DCB needs reconfig
 * @pf: board private structure
 * @old_cfg: current DCB config
 * @new_cfg: new DCB config
 */
u32 nse_dcb_need_recfg(struct nse_pf *pf, struct nse_dcbx_cfg *old_cfg,
		   struct nse_dcbx_cfg *new_cfg)
{
	struct nse_hw *hw = &pf->hw;
	u32 chg_type = 0;
	u32 old_val, new_val;

	/* Check if ETS configuration has changed */
	if (memcmp(&new_cfg->etscfg, &old_cfg->etscfg,
		   sizeof(new_cfg->etscfg))) {
		old_val = nse_dcb_get_ena_tc(old_cfg);
		new_val = nse_dcb_get_ena_tc(new_cfg);
		if (new_val != old_val) {
			nse_debug(hw, NSE_DBG_DCB, "[%s]: ETS enabled TC bitmap change, old=%X, new=%X\n",
										__func__,
											old_val,
											new_val);

			chg_type |= NSE_DCB_CFG_CHG_TYPE_TC;
		}

		/* If Priority Table has changed reconfig is needed */
		if (memcmp(&new_cfg->etscfg.prio_table,
			   &old_cfg->etscfg.prio_table,
			   sizeof(new_cfg->etscfg.prio_table))) {
			nse_debug(hw, NSE_DBG_DCB, "[%s]: ETS UP2TC change\n", __func__);

			chg_type |= NSE_DCB_CFG_CHG_TYPE_UP2TC;
		}

		if (memcmp(&new_cfg->etscfg.tcbwtable,
			   &old_cfg->etscfg.tcbwtable,
			   sizeof(new_cfg->etscfg.tcbwtable))) {
			nse_debug(hw, NSE_DBG_DCB, "[%s]: ETS TC BW Table change\n", __func__);

			chg_type |= NSE_DCB_CFG_CHG_TYPE_TC_TSA_BW;
		}

		if (memcmp(&new_cfg->etscfg.tsatable,
			   &old_cfg->etscfg.tsatable,
			   sizeof(new_cfg->etscfg.tsatable))) {
			nse_debug(hw, NSE_DBG_DCB, "[%s]: ETS TSA Table change\n", __func__);

			chg_type |= NSE_DCB_CFG_CHG_TYPE_TC_TSA_BW;
		}
	}

	/* Check if PFC configuration has changed */
	if (new_cfg->pfc.pfcena != old_cfg->pfc.pfcena) {
		nse_debug(hw, NSE_DBG_DCB, "[%s]: PFC change\n", __func__);

		chg_type |= NSE_DCB_CFG_CHG_TYPE_PFC;
	}

	nse_debug(hw, NSE_DBG_DCB, "[%s]: chg_type=%X\n", __func__, chg_type);

	return chg_type;
}

/**
 * nse_dcb_rebuild - rebuild DCB post reset
 * @pf: physical function instance
 */
void nse_dcb_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_dcbx_cfg *err_cfg;
	bool set_all;
	enum nse_status ret;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	if (nse_is_high_reset_type(reset_type))
		set_all = true;
	else
		set_all = false;

	mutex_lock(&pf->tc_mutex);

	ret = nse_set_dcb_cfg(pf->hw.port_info, set_all);

	if (ret) {
		dev_err(dev, "[%s] FAIL: set_dcb_cfg( set_all=%d )\n",
						__func__, set_all);
		goto dcb_error;
	}

	(void)nse_set_dcb_up_enforcement(&pf->hw, &pf->hw.port_info->qos_cfg.local_dcbx_cfg);

	nse_sched_set_tc_cir_by_dcbxcfg(&pf->hw, &pf->hw.port_info->qos_cfg.local_dcbx_cfg);

	dev_info(dev, "[%s] INFO: DCB info restored\n", __func__);

	mutex_unlock(&pf->tc_mutex);

	return;

dcb_error:
	dev_err(dev, "[%s] Disabling DCB until new settings occur\n", __func__);
	err_cfg = kzalloc(sizeof(*err_cfg), GFP_KERNEL);
	if (!err_cfg) {
		mutex_unlock(&pf->tc_mutex);
		return;
	}

	err_cfg->etscfg.willing = true;
	err_cfg->etscfg.tcbwtable[0] = NSE_TC_MAX_BW;
	err_cfg->etscfg.tsatable[0] = IEEE_8021QAZ_TSA_ETS;
	memcpy(&err_cfg->etsrec, &err_cfg->etscfg, sizeof(err_cfg->etsrec));

	(void)nse_pf_dcb_cfg(pf, err_cfg, set_all, false);

	kfree(err_cfg);

	mutex_unlock(&pf->tc_mutex);
}

/**
 * nse_dcb_sw_dflt_cfg - Apply a default DCB config
 * @pf: PF to apply config to
 * @ets_willing: configure ETS willing
 * @locked: was this function called with RTNL held
 */
int nse_dcb_sw_dflt_cfg(struct nse_pf *pf, bool ets_willing, bool set_all, bool locked)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_dcbx_cfg *dcbcfg;
	int ret;

	nse_debug(hw, NSE_DBG_DCB, "[%s] ets_willing=%d, set_all=%d, locked=%d\n",
					__func__, ets_willing, set_all, locked);

	dcbcfg = kzalloc(sizeof(*dcbcfg), GFP_KERNEL);
	if (!dcbcfg)
		return -ENOMEM;

	memset(&pi->qos_cfg.local_dcbx_cfg, 0, sizeof(*dcbcfg));

	dcbcfg->etscfg.willing = ets_willing ? 1 : 0;
	dcbcfg->etscfg.maxtcs = IEEE_8021QAZ_MAX_TCS;
	dcbcfg->etscfg.tcbwtable[0] = 100;
	dcbcfg->etscfg.tsatable[0] = IEEE_8021QAZ_TSA_ETS;

	memcpy(&dcbcfg->etsrec, &dcbcfg->etscfg,
	       sizeof(dcbcfg->etsrec));
	dcbcfg->etsrec.willing = 0;

	dcbcfg->pfc.willing = 1;
	dcbcfg->pfc.pfccap = IEEE_8021QAZ_MAX_TCS;

	ret = nse_pf_dcb_cfg(pf, dcbcfg, set_all, locked);
	if (ret < 0) {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] FAIL: pf_dcb_cfg(): ret=%d\n",
									__func__,
										__LINE__, ret);
	} else {
		ret = 0;
	}

	/* local_dcbx_cfg is content synced to local var dcbcfg, inside nse_pf_dcb_cfg()
	 * here sync local_dcbx_cfg to desired_dcbx_cfg
	 */
	memcpy(&pi->qos_cfg.desired_dcbx_cfg, &pi->qos_cfg.local_dcbx_cfg,
	       sizeof(pi->qos_cfg.desired_dcbx_cfg));

	kfree(dcbcfg);

	return ret;
}

/**
 * nse_dcb_tc_contig - Check that TCs are contiguous
 * @prio_table: pointer to priority table
 *
 * Check if TCs begin with TC0 and are contiguous
 */
static bool nse_dcb_tc_contig(u8 *prio_table)
{
	bool found_empty = false;
	u8 used_tc = 0;
	int i;

	/* Create a bitmap of used TCs */
	for (i = 0; i < NSE_MAX_TRAFFIC_CLASS; i++)
		used_tc |= BIT(prio_table[i]);

	for (i = 0; i < NSE_MAX_TRAFFIC_CLASS; i++) {
		if (used_tc & BIT(i)) {
			if (found_empty)
				return false;
		} else {
			found_empty = true;
		}
	}

	return true;
}

/**
 * nse_pf_dcb_recfg - Reconfigure all VEBs and VSIs
 * @pf: pointer to the PF struct
 *
 * Assumed caller has already disabled all VSIs before
 * calling this function. Reconfiguring DCB based on
 * local_dcbx_cfg.
 */
void nse_pf_dcb_recfg(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_dcbx_cfg *dcbcfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;
	struct iidc_core_dev_info *cdev_info;
	struct iidc_event *event;
	u8 tc_map = 0;
	int v, ret;

	nse_for_each_vsi(pf, v) {
		struct nse_vsi *vsi = pf->vsi[v];

		if (!vsi || !vsi->type == NSE_VSI_PF)
			continue;

		if (nse_dcb_get_num_tc(dcbcfg) > vsi->alloc_txq)
			dev_warn(dev, "[%s]: More TCs defined than queues/rings allocated.\n",
				 __func__);

		tc_map = nse_dcb_get_ena_tc(dcbcfg);

		/* If DCBX request non-contiguous TC, then configure
		 * default TC
		 */
		if (!nse_dcb_tc_contig(dcbcfg->etscfg.prio_table)) {
			tc_map = NSE_DFLT_TRAFFIC_CLASS;
			dev_warn(dev, "[%s]: non-contig tc_map - force it to be TC-0 only.\n",
				 __func__);
		}

		ret = nse_vsi_cfg_tc(vsi, tc_map);
		if (ret) {
			dev_err(dev, "[%s] FAIL: vsi_cfg_tc(vsi idx=%d, tc_map=%d)\n",
				__func__, vsi->idx, tc_map);
			continue;
		}

		ret = nse_vsi_map_rings_to_vectors(vsi);
		if (ret) {
			dev_err(dev, "[%s] FAIL: vsi_cfg_tc(vsi idx=%d)\n", __func__, vsi->idx);
			continue;
		}

		nse_dcbnl_set_all(vsi);
	}

	/* Notify the aux drivers that TC change is finished
	 */
	cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (cdev_info) {
		nse_setup_dcb_qos_info(pf, &cdev_info->qos_info);

		event = kzalloc(sizeof(*event), GFP_KERNEL);
		if (!event)
			return;

		set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
		event->info.port_qos = cdev_info->qos_info;
		nse_send_event_to_auxs(pf, event);
		kfree(event);
	}
}

/**
 * nse_init_pf_dcb - initialize DCB for a PF
 * @pf: PF to initialize DCB for
 * @locked: Was function called with RTNL held
 */
int nse_init_pf_dcb(struct nse_pf *pf, bool set_all, bool locked)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_qos_cfg *qos_cfg = &pi->qos_cfg;
	struct nse_vsi *pf_vsi = NULL;
	int err;

	nse_debug(hw, NSE_DBG_DCB, "[%s] set_all=%d, locked=%d\n", __func__, set_all, locked);

	pi->lmac_phy_info.fc_info.current_mode = NSE_FC_LFC_FULL;
	pi->lmac_phy_info.fc_info.req_mode = NSE_FC_LFC_FULL;
	pi->lmac_phy_info.fc_info.autoneg_lfc = true;

	qos_cfg->dcbx_mode = NSE_QOS_DCBX_MODE_HOST;

		err = nse_dcb_sw_dflt_cfg(pf, false, set_all, locked);
		if (err) {
			nse_dev_err_errno(dev, err,
					  "Failed to set local DCB config");
			err = -EIO;
			goto dcb_init_err;
		}

		/* If the FW DCBX engine is not running then Rx LLDP packets
		 * need to be redirected up the stack.
		 */
		pf_vsi = nse_get_main_vsi(pf);
		if (!pf_vsi) {
			dev_err(dev, "Failed to set local DCB config\n");
			err = -EIO;
			goto dcb_init_err;
		}

		nse_cfg_sw_lldp(pf_vsi, false, true);

		pf->dcbx_cap = nse_dcb_get_mode(pi, true);

		return 0;

dcb_init_err:
	dev_err(dev, "[%s, %d] DCB init fail: %d\n",
					__func__, __LINE__,
					err);
	return err;
}

/**
 * nse_tx_prepare_vlan_flags_dcb - prepare VLAN tagging for DCB
 * @tx_ring: ring to send buffer on
 * @first: pointer to struct nse_tx_buf
 *
 * This should not be called if the outer VLAN is software offloaded as the VLAN
 * tag will already be configured with the correct ID and priority bits
 */
void
nse_tx_prepare_vlan_flags_dcb(struct nse_ring *tx_ring,
			      struct nse_tx_buf *first)
{
	struct sk_buff *skb = first->skb;

	if (nse_lan_vlan_force_up)	/* work even if !DCB_ENA */
		goto handle_up;

	if (!test_bit(NSE_FLAG_DCB_ENA, tx_ring->vsi->back->flags))
		return;

handle_up:
	/* Insert 802.1p priority into VLAN header */
	if ((first->tx_flags & NSE_TX_FLAGS_HW_VLAN ||
	     first->tx_flags & NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN)) {
		first->tx_flags &= ~NSE_TX_FLAGS_VLAN_PR_M;

		if (nse_lan_vlan_force_up)
			/* Use txq index to set the 802.1p priority */
			first->tx_flags |= (tx_ring->q_index & 0x7) <<
					   NSE_TX_FLAGS_VLAN_PR_S;
		else
			/* Mask the lower 3 bits to set the 802.1p priority */
			first->tx_flags |= (skb->priority & 0x7) <<
					   NSE_TX_FLAGS_VLAN_PR_S;

		/* if this is not already set it means a VLAN 0 + priority needs
		 * to be offloaded
		 */
		if (tx_ring->flags & NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2)
			first->tx_flags |= NSE_TX_FLAGS_HW_OUTER_SINGLE_VLAN;
		else
			first->tx_flags |= NSE_TX_FLAGS_HW_VLAN;
	}
}

/**
 * nse_setup_dcb_qos_info - Setup DCB QoS information
 * @pf: ptr to nse_pf
 * @qos_info: QoS param instance
 */
void nse_setup_dcb_qos_info(struct nse_pf *pf, struct iidc_qos_params *qos_info)
{
	struct iidc_core_dev_info *cdev_info;
	struct nse_dcbx_cfg *dcbx_cfg;
	unsigned int i;

	if (!pf || !qos_info)
		return;

	cdev_info = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);

	if (!cdev_info)
		return;

	dcbx_cfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	qos_info->num_tc = nse_dcb_get_num_tc(dcbx_cfg);

	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		qos_info->up2tc[i] = dcbx_cfg->etscfg.prio_table[i];

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->tc_info[i].rel_bw =
			dcbx_cfg->etscfg.tcbwtable[i];
#ifdef AMBER_PE_NEED_PFC_MODE
	qos_info->pfc_mode = dcbx_cfg->pfc_mode;
	for (i = 0; i < NSE_DSCP_NUM_VAL; i++)
		qos_info->dscp_map[i] = dcbx_cfg->dscp_map[i];
#endif
}

void nse_save_dcbx_cfg_from_aqc(struct nse_hw *hw, struct nse_dcbx_cfg *dst,
				struct nse_aqc_qos_db_cfg *db_cfg,
				bool local_or_remote)
{
	struct nse_dcbx_cfg *src = NULL;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		src = local_or_remote ? &db_cfg->amber.local_dcbx_cfg :
			&db_cfg->amber.remote_dcbx_cfg;
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		src = local_or_remote ? &db_cfg->ms.local_dcbx_cfg : &db_cfg->ms.remote_dcbx_cfg;
	else
		return;

	memcpy(dst, src, sizeof(*dst));
}

void
nse_dcb_process_dcbx_cfg_chg_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_port_info *pi = pf->hw.port_info;
	struct nse_aqc_qos_db_cfg *db_cfg = NULL;
	struct nse_aqc_qos_dcbx_conf_chg_event *chg_evt =
		(struct nse_aqc_qos_dcbx_conf_chg_event *)event->msg_buf;
	/* remote recommendation: etsrec suggest our local use this conf. */
	struct nse_dcbx_cfg *new_cfg = NULL;
	u32 cfg_chg_type = 0;
	u32 chg_flags;
	int err;

	nse_debug(hw, NSE_DBG_DCB, "[%s] evt: hdr.lan_id=%d, chg_flags=%X\n",
		  __func__, chg_evt->hdr.lan_id, le32_to_cpu(chg_evt->chg_flags));

	/* not my change, not my business */
	if (chg_evt->hdr.lan_id != hw->lan_id) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] evt lan_id(%d) != my lan_id(%d)\n",
								__func__, __LINE__,
									chg_evt->hdr.lan_id,
									hw->lan_id);
		goto out;
	}

	/* Not DCB capable or capability disabled */
	/*  MH-DPU secondary_PF (also no above FLAG_DCB_CAPABLE) should ignore this event --- even
	 * local_dcbx_conf change
	 */
	if (!(test_bit(NSE_FLAG_DCB_CAPABLE, pf->flags)) || hw->is_mh_dpu_secondary_pf) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] FLAG_DCB_CAPABLE = no\n",
			  __func__, __LINE__);
		goto out;
	}

	/* not in FW-LLDP-DCBx mode */
	if ((pf->dcbx_cap & DCB_CAP_DCBX_HOST) ||
		hw->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_HOST ||
		!test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] not in fw-lldp-dcbx mode\n",
			  __func__, __LINE__);
		goto out;
	}

	chg_flags = le32_to_cpu(chg_evt->chg_flags);

	if (!(chg_flags & QOS_DCBX_CONF_CHG_FLAG_REMOTE)) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] remote_dcbx_cfg no change\n",
			  __func__, __LINE__);
		goto out;
	}

	db_cfg = kzalloc(sizeof(*db_cfg), GFP_KERNEL);
	if (!db_cfg)
		goto out;

	/* get changed FW local_dcbx_cfg and remote_dcbx_cfg */
	if (nse_aq_qos_db_get_cfg(&pf->hw, db_cfg)) {
		dev_err(dev, "[%s, %d]: get db_cfg from FW failure\n", __func__, __LINE__);
		goto out;
	}

	nse_save_dcbx_cfg_from_aqc(hw, &pi->qos_cfg.remote_dcbx_cfg, db_cfg, false);

	new_cfg = &hw->port_info->qos_cfg.desired_dcbx_cfg;

	memset(new_cfg, 0, sizeof(*new_cfg));

	/* remote recommendation - ets[rec] to our local expected ets */

	memcpy(&new_cfg->etscfg, &pi->qos_cfg.remote_dcbx_cfg.etsrec, sizeof(new_cfg->etscfg));
	new_cfg->etscfg.maxtcs = IEEE_8021QAZ_MAX_TCS;
	new_cfg->etsrec.willing = 1;

	memcpy(&new_cfg->etsrec, &new_cfg->etscfg, sizeof(new_cfg->etsrec));
	new_cfg->etsrec.willing = 0;

	memcpy(&new_cfg->pfc, &pi->qos_cfg.remote_dcbx_cfg.pfc, sizeof(new_cfg->pfc));

	if (nse_dcb_bwchk(pf, new_cfg)) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] dcb_bwchk() BAD\n", __func__, __LINE__);
		goto out;
	}

	if (!nse_dcb_sanity_check_tc(pf, new_cfg)) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] dcb_sanity_check_tc() not support\n",
			  __func__, __LINE__);
		goto out;
	}

	/* That a DCB change has happened is now determined */
	mutex_lock(&pf->tc_mutex);

	cfg_chg_type = nse_dcb_need_recfg(pf, &pi->qos_cfg.local_dcbx_cfg, new_cfg);
	if (!cfg_chg_type) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] dcb_need_recfg=NO\n", __func__, __LINE__);
		goto unlock_mutex;
	}

	rtnl_lock();

	/* only UP-TC mapping change, but enabled TC bitmap does not change */
	if (cfg_chg_type == NSE_DCB_CFG_CHG_TYPE_UP2TC ||
		cfg_chg_type == NSE_DCB_CFG_CHG_TYPE_PFC) {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] do dcb_cfg_lw (cfg_chg_type=%X)\n",
			  __func__, __LINE__, cfg_chg_type);

		err = nse_pf_dcb_cfg_lw(pf, new_cfg, cfg_chg_type, true);

	} else {
		nse_debug(hw, NSE_DBG_DCB, "[%s, %d] do dcb_cfg - heavy weight (cfg_chg_type=%X)\n",
			  __func__, __LINE__, cfg_chg_type);

		err = nse_pf_dcb_cfg(pf, new_cfg, false, true);
	}

	rtnl_unlock();

unlock_mutex:
	mutex_unlock(&pf->tc_mutex);
out:
	kfree(db_cfg);
}
