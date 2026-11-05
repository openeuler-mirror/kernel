// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_dcb.h"
#include "nse_dcb_lib.h"
#include "nse_dcb_nl.h"
#include <net/dcbnl.h>

/**
 * nse_dcbnl_getets - retrieve local ETS configuration
 * @netdev: the relevant netdev
 * @ets: struct to hold ETS configuration
 */
static int nse_dcbnl_getets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nse_dcbx_cfg *dcbxcfg;
	struct nse_pf *pf;

	pf = nse_netdev_to_pf(netdev);
	dcbxcfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	ets->willing = dcbxcfg->etscfg.willing;
	ets->ets_cap = dcbxcfg->etscfg.maxtcs;
	ets->cbs = dcbxcfg->etscfg.cbs;
	memcpy(ets->tc_tx_bw, dcbxcfg->etscfg.tcbwtable, sizeof(ets->tc_tx_bw));
	memcpy(ets->tc_rx_bw, dcbxcfg->etscfg.tcbwtable, sizeof(ets->tc_rx_bw));
	memcpy(ets->tc_tsa, dcbxcfg->etscfg.tsatable, sizeof(ets->tc_tsa));
	memcpy(ets->prio_tc, dcbxcfg->etscfg.prio_table, sizeof(ets->prio_tc));
	memcpy(ets->tc_reco_bw, dcbxcfg->etsrec.tcbwtable,
	       sizeof(ets->tc_reco_bw));
	memcpy(ets->tc_reco_tsa, dcbxcfg->etsrec.tsatable,
	       sizeof(ets->tc_reco_tsa));
	memcpy(ets->reco_prio_tc, dcbxcfg->etscfg.prio_table,
	       sizeof(ets->reco_prio_tc));

	return 0;
}

/**
 * nse_dcbnl_setets - set IEEE ETS configuration
 * @netdev: pointer to relevant netdev
 * @ets: struct to hold ETS configuration
 */
static int nse_dcbnl_setets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_dcbx_cfg *new_cfg;
	int bwcfg = 0, bwrec = 0;
	u32 cfg_chg_type = 0;
	int err, i;

	if ((pf->dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
		hw->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_FW ||
		test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
		dev_err(dev, "fw-lldp-dcbx-agent is active, refuse host change conf\n");
		return -EINVAL;
	}

	new_cfg = &pf->hw.port_info->qos_cfg.desired_dcbx_cfg;

	mutex_lock(&pf->tc_mutex);

	new_cfg->etscfg.willing = ets->willing;
	new_cfg->etscfg.cbs = ets->cbs;
	nse_for_each_traffic_class(i) {
		new_cfg->etscfg.tcbwtable[i] = ets->tc_tx_bw[i];
		bwcfg += ets->tc_tx_bw[i];

		if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_STRICT &&
			ets->tc_tsa[i] != IEEE_8021QAZ_TSA_ETS) {
			netdev_err(netdev, "don't support DCB TSA other than SP and ETS, don't support CBS or VENDOR\n");
			err = -EINVAL;
			goto ets_out;
		}
		new_cfg->etscfg.tsatable[i] = ets->tc_tsa[i];

		new_cfg->etscfg.prio_table[i] = ets->prio_tc[i];
		new_cfg->etsrec.prio_table[i] = ets->reco_prio_tc[i];

		new_cfg->etsrec.tcbwtable[i] = ets->tc_reco_bw[i];
		bwrec += ets->tc_reco_bw[i];
		new_cfg->etsrec.tsatable[i] = ets->tc_reco_tsa[i];
	}

	if (nse_dcb_bwchk(pf, new_cfg)) {
		err = -EINVAL;
		goto ets_out;
	}

	if (!nse_dcb_sanity_check_tc(pf, new_cfg)) {
		err = -EINVAL;
		goto ets_out;
	}

	/* Not all TCs can have a BW of zero, FW requires at least one TC
	 * with BW assigned, and sum of all has to be 100%.  Set TC0 to 100%
	 */
	if (!bwcfg)
		new_cfg->etscfg.tcbwtable[0] = 100;

	if (!bwrec)
		new_cfg->etsrec.tcbwtable[0] = 100;

	new_cfg->etscfg.maxtcs = IEEE_8021QAZ_MAX_TCS;

	new_cfg->etsrec.willing = 0;

	cfg_chg_type = nse_dcb_need_recfg(pf, &pf->hw.port_info->qos_cfg.local_dcbx_cfg, new_cfg);
	if (!cfg_chg_type) {	/* actually no change */
		dev_info(dev, "[%s] ETS setting no change\n", __func__);
		err = 0;
		goto ets_out;
	}

	if (cfg_chg_type & ~(NSE_DCB_CFG_CHG_TYPE_LIGHTWEIGHT_SET)) {
		/* heavy weight change */

		nse_debug(hw, NSE_DBG_DCB, "[%s] do dcb_cfg - heavy weight (cfg_chg_type=0x%X)\n",
			  __func__, cfg_chg_type);

		err = nse_pf_dcb_cfg(pf, new_cfg, false, true);

	} else {
		/* only lightweight change */

		nse_debug(hw, NSE_DBG_DCB, "[%s] do dcb_cfg_lw (cfg_chg_type=0x%X)\n",
			  __func__, cfg_chg_type);

		err = nse_pf_dcb_cfg_lw(pf, new_cfg, cfg_chg_type, true);
	}

	/* other err are negative error code, return back to stack and uapp */
	if (err >= 0)
		err = 0;
	/* it seems we don't need to call nse_dcbnl_devreset() */

ets_out:
	mutex_unlock(&pf->tc_mutex);
	return err;
}

/**
 * nse_dcbnl_getdcbx - retrieve current DCBX capability
 * @netdev: pointer to the netdev struct
 */
static u8 nse_dcbnl_getdcbx(struct net_device *netdev)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);

	return pf->dcbx_cap;
}

/**
 * nse_dcbnl_setdcbx - set required DCBX capability
 * @netdev: the corresponding netdev
 * @mode: required mode
 */
static u8 nse_dcbnl_setdcbx(struct net_device *netdev, u8 mode)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_qos_cfg *qos_cfg;

	/* if FW LLDP agent is running, DCBNL not allowed to change mode */
	if (test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags))
		return NSE_DCB_NO_HW_CHG;

	/* No support for LLD_MANAGED modes or CEE */
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    (mode & DCB_CAP_DCBX_VER_CEE) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return NSE_DCB_NO_HW_CHG;

	/* Already set to the given mode no change */
	if (mode == pf->dcbx_cap)
		return NSE_DCB_NO_HW_CHG;

	qos_cfg = &pf->hw.port_info->qos_cfg;

	pf->dcbx_cap = mode;

	dev_info(nse_pf_to_dev(pf), "DCBx mode = 0x%x\n", mode);
	return NSE_DCB_HW_CHG_RST;
}

/**
 * nse_get_pfc_delay - Retrieve PFC Link Delay
 * @hw: pointer to HW struct
 * @delay: holds the PFC Link Delay value
 */
static void nse_get_pfc_delay(struct nse_hw *hw, u16 *delay)
{
	*delay = 0x79D;
}

/**
 * nse_dcbnl_getpfc - retrieve local IEEE PFC config
 * @netdev: pointer to netdev struct
 * @pfc: struct to hold PFC info
 */
static int nse_dcbnl_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_port_info *pi = pf->hw.port_info;
	struct nse_dcbx_cfg *dcbxcfg;
	int i;

	dcbxcfg = &pi->qos_cfg.local_dcbx_cfg;
	pfc->pfc_cap = dcbxcfg->pfc.pfccap;
	pfc->pfc_en = dcbxcfg->pfc.pfcena;
	pfc->mbc = dcbxcfg->pfc.mbc;
	nse_get_pfc_delay(&pf->hw, &pfc->delay);

	nse_for_each_traffic_class(i) {
		pfc->requests[i] = pf->stats.tx_pfc_xoff[i];
		pfc->indications[i] = pf->stats.rx_pfc_xoff[i];
	}

	return 0;
}

/**
 * nse_dcbnl_setpfc - set local IEEE PFC config
 * @netdev: pointer to relevant netdev
 * @pfc: pointer to struct holding PFC config
 */
static int nse_dcbnl_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_dcbx_cfg *new_cfg;
	u32 cfg_chg_type = 0;
	int err;

	if ((pf->dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
		hw->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_FW ||
		test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
		dev_err(dev, "fw-lldp-dcbx-agent is active, refuse host change conf\n");
		return -EINVAL;
	}

	mutex_lock(&pf->tc_mutex);

	new_cfg = &pf->hw.port_info->qos_cfg.desired_dcbx_cfg;

	new_cfg->pfc.pfccap = IEEE_8021QAZ_MAX_TCS;

	new_cfg->pfc.pfcena = pfc->pfc_en;

	cfg_chg_type = nse_dcb_need_recfg(pf, &pf->hw.port_info->qos_cfg.local_dcbx_cfg, new_cfg);
	if (!(cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_PFC)) {
		dev_info(dev, "[%s] PFC setting no change\n", __func__);
		err = 0;
		goto pfc_out;
	}

	err = nse_pf_dcb_cfg_lw(pf, new_cfg, NSE_DCB_CFG_CHG_TYPE_PFC, true);

	/* other err are negative error code, return back to stack and uapp */
	if (err >= 0)
		err = 0;

pfc_out:
	mutex_unlock(&pf->tc_mutex);
	return err;
}

#define NSE_BYTES_PER_DSCP_VAL		8

/**
 * nse_dcbnl_setapp - set local IEEE App config
 * @netdev: relevant netdev struct
 * @app: struct to hold app config info
 */
static int nse_dcbnl_setapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_dcb_app_priority_table new_app;
	struct nse_dcbx_cfg *old_cfg, *new_cfg;
	unsigned int max_tc;
	int ret, i, j;
	u32 cfg_chg_type = 0;

	/* ONLY DSCP APP TLVs have operational significance */
	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP)
		return -EINVAL;

	if ((pf->dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
		hw->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_FW ||
		test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
		dev_err(dev, "fw-lldp-dcbx-agent is active, refuse host change conf\n");
		return -EINVAL;
	}

	if (app->protocol >= NSE_DSCP_NUM_VAL) {
		dev_err(dev, "DSCP value 0x%04X out of range\n",
			app->protocol);
		return -EINVAL;
	}

	max_tc = hw->hw_conf.max_tc_allowed;
	if (app->priority >= max_tc) {
		dev_err(dev, "TC %d out of range, max TC %d\n",
			app->priority, max_tc);
		return -EINVAL;
	}

	/* grab TC mutex */
	mutex_lock(&pf->tc_mutex);

	new_cfg = &pf->hw.port_info->qos_cfg.desired_dcbx_cfg;
	old_cfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	ret = dcb_ieee_setapp(netdev, app);
	if (ret)
		goto setapp_out;

	if (test_and_set_bit(app->protocol, new_cfg->dscp_mapped)) {
		dev_err(dev, "DSCP value 0x%04X already user mapped\n",
			app->protocol);
		ret = dcb_ieee_delapp(netdev, app);
		if (ret)
			dev_err(dev, "Failed to delete re-mapping TLV\n");
		ret = -EINVAL;
		goto setapp_out;
	}

	new_app.selector = app->selector;
	new_app.prot_id = app->protocol;
	new_app.priority = app->priority;

	/* If port is not in DSCP mode, need to set */
	if (old_cfg->pfc_mode == NSE_QOS_MODE_VLAN) {
		new_cfg->pfc_mode = NSE_QOS_MODE_DSCP;
		/* set default DSCP QoS values */
		new_cfg->etscfg.willing = 0;
		new_cfg->pfc.pfccap = max_tc;
		new_cfg->pfc.willing = 0;

		for (i = 0; i < max_tc; i++)
			for (j = 0; j < NSE_BYTES_PER_DSCP_VAL; j++) {
				int dscp, offset;

				dscp = (i * max_tc) + j;
				offset = max_tc * NSE_BYTES_PER_DSCP_VAL;

				new_cfg->dscp_map[dscp] = i;
				/* if less that 8 TCs supported */
				if (max_tc < NSE_MAX_TRAFFIC_CLASS)
					new_cfg->dscp_map[dscp + offset] = i;
			}

		new_cfg->etscfg.tcbwtable[0] = 100;
		new_cfg->etscfg.tsatable[0] = NSE_IEEE_TSA_ETS;
		new_cfg->etscfg.prio_table[0] = 0;

		for (i = 1; i < max_tc; i++) {
			new_cfg->etscfg.tcbwtable[i] = 0;
			new_cfg->etscfg.tsatable[i] = NSE_IEEE_TSA_ETS;
			new_cfg->etscfg.prio_table[i] = i;
		}
	}
	/* apply new mapping for this DSCP value */
	new_cfg->dscp_map[app->protocol] = app->priority;
	new_cfg->app[new_cfg->numapps++] = new_app;

	cfg_chg_type = nse_dcb_need_recfg(pf,
					  &pf->hw.port_info->qos_cfg.local_dcbx_cfg,
					  new_cfg);
	if (!(cfg_chg_type & NSE_DCB_CFG_CHG_TYPE_DSCP)) {
		dev_info(dev, "[%s] APP setting no change\n", __func__);
		ret = NSE_DCB_NO_HW_CHG;
		goto setapp_out;
	}

	ret = nse_pf_dcb_dscp_cfg(pf, new_cfg, NSE_DCB_CFG_CHG_TYPE_DSCP, true);
	/* other err are negative error code, return back to stack and uapp */
	if (ret >= 0)
		ret = 0;

setapp_out:
	mutex_unlock(&pf->tc_mutex);
	return ret;
}

/**
 * nse_dcbnl_delapp - Delete local IEEE App config
 * @netdev: relevant netdev
 * @app: struct to hold app too delete
 *
 * Will not delete first application required by the FW
 */
static int nse_dcbnl_delapp(struct net_device *netdev, struct dcb_app *app)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_dcbx_cfg *old_cfg, *new_cfg;
	int ret, i, j;

	if ((pf->dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
		hw->port_info->qos_cfg.dcbx_mode == NSE_QOS_DCBX_MODE_FW ||
		test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags)) {
		dev_err(dev, "fw-lldp-dcbx-agent is active, refuse host change conf\n");
		return -EINVAL;
	}

	mutex_lock(&pf->tc_mutex);
	old_cfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		goto delapp_out;

	new_cfg = &pf->hw.port_info->qos_cfg.desired_dcbx_cfg;

	for (i = 0; i < new_cfg->numapps; i++) {
		if (app->selector == new_cfg->app[i].selector &&
		    app->protocol == new_cfg->app[i].prot_id &&
		    app->priority == new_cfg->app[i].priority) {
			new_cfg->app[i].selector = 0;
			new_cfg->app[i].prot_id = 0;
			new_cfg->app[i].priority = 0;
			break;
		}
	}

	/* Did not find DCB App */
	if (i == new_cfg->numapps) {
		ret = -EINVAL;
		goto delapp_out;
	}

	new_cfg->numapps--;

	for (j = i; j < new_cfg->numapps; j++) {
		new_cfg->app[j].selector = old_cfg->app[j + 1].selector;
		new_cfg->app[j].prot_id = old_cfg->app[j + 1].prot_id;
		new_cfg->app[j].priority = old_cfg->app[j + 1].priority;
	}

	/* if not a DSCP APP TLV or DSCP is not supported, we are done */
	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP) {
		ret = NSE_DCB_HW_CHG;
		goto delapp_out;
	}

	/* if DSCP TLV, then need to address change in mapping */
	clear_bit(app->protocol, new_cfg->dscp_mapped);
	/* remap this DSCP value to default value */
	new_cfg->dscp_map[app->protocol] = app->protocol %
					   NSE_BYTES_PER_DSCP_VAL;

	/* if the last DSCP mapping just got deleted, need to switch
	 * to L2 VLAN QoS mode
	 */
	if (bitmap_empty(new_cfg->dscp_mapped, NSE_DSCP_NUM_VAL) &&
	    new_cfg->pfc_mode == NSE_QOS_MODE_DSCP) {
		ret = nse_ena_dcb_dscp_mode(pf->hw.port_info, false);
		if (ret) {
			dev_err(dev, "[%s, %d] FAIL: ena_dscp_mode(): %d\n",
				__func__, __LINE__, ret);

			goto delapp_out;
		}

		new_cfg->pfc_mode = NSE_QOS_MODE_VLAN;

		ret = nse_dcb_sw_dflt_cfg(pf, false, false, true);
	} else {
		ret = nse_pf_dcb_dscp_cfg(pf, new_cfg,
					  NSE_DCB_CFG_CHG_TYPE_DSCP, true);
	}

	if (ret > 0)
		ret = 0;

delapp_out:
	mutex_unlock(&pf->tc_mutex);
	return ret;
}

static const struct dcbnl_rtnl_ops dcbnl_ops = {
	/* IEEE 802.1Qaz std */
	.ieee_getets = nse_dcbnl_getets,
	.ieee_setets = nse_dcbnl_setets,
	.ieee_getpfc = nse_dcbnl_getpfc,
	.ieee_setpfc = nse_dcbnl_setpfc,
	.ieee_setapp = nse_dcbnl_setapp,
	.ieee_delapp = nse_dcbnl_delapp,

	/* DCBX configuration */
	.getdcbx = nse_dcbnl_getdcbx,
	.setdcbx = nse_dcbnl_setdcbx,
};

void nse_dcbnl_set_all(struct nse_vsi *vsi)
{
	/* do nothing, no need */
}

/**
 * nse_dcbnl_setup - setup DCBNL
 * @vsi: VSI to get associated netdev from
 */
void nse_dcbnl_setup(struct nse_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct nse_pf *pf;

	pf = nse_netdev_to_pf(netdev);
	if (!test_bit(NSE_FLAG_DCB_CAPABLE, pf->flags))
		return;

	netdev->dcbnl_ops = &dcbnl_ops;
	nse_dcbnl_set_all(vsi);
}
