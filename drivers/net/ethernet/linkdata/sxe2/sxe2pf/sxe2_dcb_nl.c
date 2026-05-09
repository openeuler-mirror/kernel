// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dcb_nl.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_dcb_nl.h"
#include <net/dcbnl.h>

#define SXE2_1K (1000U)
#define SXE2_MINTC_RATE (62500ULL)

#define SXE2_B2KBIT(rate) ((rate) * BITS_PER_BYTE / SXE2_1K)

static int sxe2_dcbnl_getets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_dcbx_cfg *dcbxcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	ets->willing = dcbxcfg->ets.willing;
	ets->ets_cap = dcbxcfg->ets.maxtcs;
	ets->cbs = dcbxcfg->ets.cbs;
	(void)memcpy(ets->tc_tx_bw, dcbxcfg->ets.tcbw_tbl, sizeof(ets->tc_tx_bw));
	(void)memcpy(ets->tc_rx_bw, dcbxcfg->ets.tcbw_tbl, sizeof(ets->tc_rx_bw));
	(void)memcpy(ets->tc_tsa, dcbxcfg->ets.tsa_tbl, sizeof(ets->tc_tsa));
	(void)memcpy(ets->prio_tc, dcbxcfg->ets.prio_tbl, sizeof(ets->prio_tc));
	(void)memcpy(ets->tc_reco_bw, dcbxcfg->etsrec.tcbw_tbl,
		     sizeof(ets->tc_reco_bw));
	(void)memcpy(ets->tc_reco_tsa, dcbxcfg->etsrec.tsa_tbl,
		     sizeof(ets->tc_reco_tsa));
	(void)memcpy(ets->reco_prio_tc, dcbxcfg->etsrec.prio_tbl,
		     sizeof(ets->reco_prio_tc));

	return 0;
}

static int sxe2_dcbnl_setets(struct net_device *netdev, struct ieee_ets *ets)
{
	int ret, i;
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_IEEE)) {
		ret = -EINVAL;
		goto l_unlock;
	}

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	new_cfg->ets.willing = ets->willing;
	new_cfg->ets.cbs = ets->cbs;

	sxe2_for_each_tc(i)
	{
		new_cfg->ets.tcbw_tbl[i] = ets->tc_tx_bw[i];
		new_cfg->ets.tsa_tbl[i] = ets->tc_tsa[i];
		new_cfg->ets.prio_tbl[i] = ets->prio_tc[i];
	}

	if (sxe2_dcb_bw_chk(adapter, new_cfg)) {
		ret = -EINVAL;
		goto l_cfg_err;
	}

	new_cfg->ets.maxtcs = IEEE_8021QAZ_MAX_TCS;

	LOG_INFO_BDF("ets cfg, willing=%d, cbs=%d, maxtcs=%d\n"
		     "prio[0]=%d, tcbw[0]=%d, tsa_tbl[0]=%d\n"
		     "prio[1]=%d, tcbw[1]=%d, tsa_tbl[1]=%d\n"
		     "prio[2]=%d, tcbw[2]=%d, tsa_tbl[2]=%d\n"
		     "prio[3]=%d, tcbw[3]=%d, tsa_tbl[3]=%d\n"
		     "prio[4]=%d, tcbw[4]=%d, tsa_tbl[4]=%d\n"
		     "prio[5]=%d, tcbw[5]=%d, tsa_tbl[5]=%d\n"
		     "prio[6]=%d, tcbw[6]=%d, tsa_tbl[6]=%d\n"
		     "prio[7]=%d, tcbw[7]=%d, tsa_tbl[7]=%d\n",
		     new_cfg->ets.willing, new_cfg->ets.cbs, new_cfg->ets.maxtcs,
		     new_cfg->ets.prio_tbl[0], new_cfg->ets.tcbw_tbl[0],
		     new_cfg->ets.tsa_tbl[0], new_cfg->ets.prio_tbl[1],
		     new_cfg->ets.tcbw_tbl[1], new_cfg->ets.tsa_tbl[1],
		     new_cfg->ets.prio_tbl[2], new_cfg->ets.tcbw_tbl[2],
		     new_cfg->ets.tsa_tbl[2], new_cfg->ets.prio_tbl[3],
		     new_cfg->ets.tcbw_tbl[3], new_cfg->ets.tsa_tbl[3],
		     new_cfg->ets.prio_tbl[4], new_cfg->ets.tcbw_tbl[4],
		     new_cfg->ets.tsa_tbl[4], new_cfg->ets.prio_tbl[5],
		     new_cfg->ets.tcbw_tbl[5], new_cfg->ets.tsa_tbl[5],
		     new_cfg->ets.prio_tbl[6], new_cfg->ets.tcbw_tbl[6],
		     new_cfg->ets.tsa_tbl[6], new_cfg->ets.prio_tbl[7],
		     new_cfg->ets.tcbw_tbl[7], new_cfg->ets.tsa_tbl[7]);

	ret = sxe2_dcb_cfg(adapter, new_cfg, true);
l_cfg_err:
	if (ret)
		(void)memcpy(new_cfg, &adapter->dcb_ctxt.local_dcbx_cfg,
			     sizeof(*new_cfg));
l_unlock:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	return ret;
}

static int sxe2_dcbnl_getnumtcs(struct net_device *netdev, int __always_unused tcid,
				u8 *num)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (!test_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags))
		return -EINVAL;

	*num = IEEE_8021QAZ_MAX_TCS;
	return 0;
}

static u8 sxe2_dcbnl_getdcbx(struct net_device *netdev)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	return adapter->dcb_ctxt.dcbx_cap;
}

static u8 sxe2_dcbnl_setdcbx(struct net_device *netdev, u8 mode)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_dcb_context *dcb_ctxt;

	if (test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags))
		return SXE2_DCB_NO_HW_CHG;

	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    ((mode & DCB_CAP_DCBX_VER_IEEE) && (mode & DCB_CAP_DCBX_VER_CEE)) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return SXE2_DCB_NO_HW_CHG;

	if (mode == adapter->dcb_ctxt.dcbx_cap)
		return SXE2_DCB_NO_HW_CHG;

	dcb_ctxt = &adapter->dcb_ctxt;

	if (dcb_ctxt->local_dcbx_cfg.qos_mode == SXE2_QOS_MODE_DSCP) {
		LOG_INFO_BDF("dcbx cfg, \t"
			     "dscp configuration is not dcbx negotiated\n");
		return SXE2_DCB_NO_HW_CHG;
	}

	dcb_ctxt->dcbx_cap = mode;

	if (mode & DCB_CAP_DCBX_VER_CEE)
		dcb_ctxt->local_dcbx_cfg.dcbx_mode = SXE2_DCBX_MODE_CEE;
	else
		dcb_ctxt->local_dcbx_cfg.dcbx_mode = SXE2_DCBX_MODE_IEEE;

	LOG_INFO_BDF("DCBx mode = 0x%x\n", mode);
	return SXE2_DCB_HW_CHG_RST;
}

static void sxe2_dcbnl_get_perm_hw_addr(struct net_device *netdev, u8 *perm_addr)
{
	(void)memset(perm_addr, 0xff, MAX_ADDR_LEN);
}

static int sxe2_dcbnl_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	s32 i;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct sxe2_dcbx_cfg *dcbxcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	pfc->pfc_cap = dcbxcfg->pfc.cap;
	pfc->pfc_en = dcbxcfg->pfc.enable;
	pfc->mbc = dcbxcfg->pfc.mbc;

	sxe2_for_each_tc(i)
	{
		pfc->requests[i] = adapter->pf_stats.dcb_stats.curr_pause_stats
						   .prio_xoff_tx[i];
		pfc->indications[i] = adapter->pf_stats.dcb_stats.curr_pause_stats
						      .prio_xoff_rx[i];
	}

	return 0;
}

static void sxe2_pfc_cfg_recover(struct sxe2_adapter *adapter)
{
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct sxe2_vsi *dpdk_vsi = NULL;
	bool fc = false;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;
	(void)memcpy(new_cfg, &adapter->dcb_ctxt.local_dcbx_cfg,
		     sizeof(*new_cfg));

	mutex_lock(&adapter->vsi_ctxt.lock);
	dpdk_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);

	if (new_cfg->pfc.enable)
		fc = true;

	if (dpdk_vsi)
		sxe2_set_fc_flag(dpdk_vsi, fc);
	sxe2_set_fc_flag(vsi, fc);

	mutex_unlock(&adapter->vsi_ctxt.lock);
}

static int sxe2_dcbnl_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	int ret;
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_vsi *dpdk_vsi = NULL;
	bool fc = false;
	bool changed = false;
	u8 old_fc = SXE2_FC_MODE_DISABLE;
	u8 new_fc = SXE2_FC_MODE_DISABLE;

	(void)sxe2_fc_get(adapter, vsi->idx_in_dev, &old_fc);

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_IEEE)) {
		ret = -EINVAL;
		goto l_unlock;
	}

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	if (pfc->pfc_cap)
		new_cfg->pfc.cap = pfc->pfc_cap;
	else
		new_cfg->pfc.cap = IEEE_8021QAZ_MAX_TCS;

	new_cfg->pfc.enable = pfc->pfc_en;
	if (new_cfg->pfc.enable)
		fc = true;

	mutex_lock(&adapter->vsi_ctxt.lock);
	dpdk_vsi = sxe2_vsi_get_by_type_unlock(adapter, SXE2_VSI_T_DPDK_PF);
	if (dpdk_vsi)
		sxe2_set_fc_flag(dpdk_vsi, fc);
	sxe2_set_fc_flag(vsi, fc);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	LOG_INFO_BDF("pfc cfg, willing=%d, cap=%d, enable=%d\n",
		     new_cfg->pfc.willing, new_cfg->pfc.cap, new_cfg->pfc.enable);

	ret = sxe2_dcb_cfg(adapter, new_cfg, true);
	if (ret) {
		sxe2_pfc_cfg_recover(adapter);
		LOG_INFO_BDF("pfc cfg, failed ret=%d\n", ret);
	}

l_unlock:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);

	(void)sxe2_fc_get(adapter, vsi->idx_in_dev, &new_fc);
	if (new_fc != old_fc)
		changed = true;

	if (changed && ret == 0)
		(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
						       SXE2_COM_FC_ST_CHANGE);

	return ret;
}

static int sxe2_dcbnl_getapp(struct net_device *netdev, u8 idtype, u16 id)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;
	struct dcb_app app = {.selector = idtype, .protocol = id};

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return -EINVAL;

	return dcb_getapp(netdev, &app);
}

STATIC bool sxe2_dcbnl_find_app(struct sxe2_dcbx_cfg *cfg,
				struct sxe2_dcb_app_prio_tbl *app)
{
	u32 i;

	for (i = 0; i < cfg->numapps; i++) {
		if (app->selector == cfg->app[i].selector &&
		    app->prot_id == cfg->app[i].prot_id &&
		    app->prio == cfg->app[i].prio)
			return true;
	}

	return false;
}

static int sxe2_dcbnl_setapp_recover(struct net_device *netdev, struct dcb_app *app)
{
	int ret;
	unsigned int i, j;
	struct sxe2_dcbx_cfg *old_cfg, *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		goto delapp_out;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;
	old_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	for (i = 0; i < new_cfg->numapps; i++) {
		if (app->selector == new_cfg->app[i].selector &&
		    app->protocol == new_cfg->app[i].prot_id &&
		    app->priority == new_cfg->app[i].prio) {
			new_cfg->app[i].selector = 0;
			new_cfg->app[i].prot_id = 0;
			new_cfg->app[i].prio = 0;
			break;
		}
	}

	new_cfg->numapps--;
	for (j = i; j < new_cfg->numapps; j++) {
		new_cfg->app[j].selector = old_cfg->app[j + 1].selector;
		new_cfg->app[j].prot_id = old_cfg->app[j + 1].prot_id;
		new_cfg->app[j].prio = old_cfg->app[j + 1].prio;
	}
	memset(&new_cfg->app[j], 0, sizeof(struct sxe2_dcb_app_prio_tbl));

	clear_bit(app->protocol, new_cfg->dscp_mapped);

	if (bitmap_empty(new_cfg->dscp_mapped, SXE2_DSCP_NUM_VAL) &&
	    new_cfg->qos_mode == SXE2_QOS_MODE_DSCP) {
		ret = sxe2_qos_mode_set(adapter, SXE2_QOS_MODE_VLAN);
		if (ret) {
			LOG_NETDEV_ERR("failed to set VLAN PFC mode %d\n", ret);
			goto delapp_out;
		}

		LOG_DEV_INFO("switched QoS to L2 VLAN mode\n");

		new_cfg->qos_mode = SXE2_QOS_MODE_VLAN;
	}

delapp_out:
	return ret;
}

static int sxe2_dcbnl_setapp(struct net_device *netdev, struct dcb_app *app)
{
	s32 ret, rtn;
	u8 max_tc;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_dcbx_cfg *old_cfg, *new_cfg;

	LOG_INFO_BDF("addapp: app:%d up %d\n", app->protocol, app->priority);
	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP) {
		LOG_NETDEV_ERR("only support dscp mode set app\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	if (adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) {
		LOG_NETDEV_ERR("can't do DSCP QoS when FW DCB agent active\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	if (!(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_IEEE)) {
		LOG_NETDEV_ERR("only support set app in dscp mode\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	if (app->protocol >= SXE2_DSCP_NUM_VAL) {
		LOG_NETDEV_ERR("DSCP value 0x%04X out of range\n", app->protocol);
		ret = -EINVAL;
		goto l_unlock;
	}

	max_tc = IEEE_8021QAZ_MAX_TCS;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;
	old_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (app->priority >= IEEE_8021Q_MAX_PRIORITIES ||
	    old_cfg->ets.prio_tbl[app->priority] >= max_tc) {
		LOG_NETDEV_ERR("tc %d out of range, max tc %d\n", app->priority,
			       max_tc);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (test_and_set_bit(app->protocol, new_cfg->dscp_mapped)) {
		ret = -EINVAL;
		LOG_NETDEV_ERR("DSCP value 0x%04X already user mapped\n",
			       app->protocol);
		goto l_unlock;
	}

	if (old_cfg->qos_mode == SXE2_QOS_MODE_VLAN) {
		ret = sxe2_qos_mode_set(adapter, SXE2_QOS_MODE_DSCP);
		if (ret) {
			clear_bit(app->protocol, new_cfg->dscp_mapped);
			ret = dcb_ieee_delapp(netdev, app);
			if (ret)
				LOG_NETDEV_ERR("Failed to delete re-mapping TLV\n");

			ret = -EIO;
			LOG_NETDEV_ERR("Failed to set DSCP PFC mode %d\n", ret);
			goto l_unlock;
		}

		LOG_DEV_INFO("switched QoS to L3 DSCP mode\n");

		new_cfg->qos_mode = SXE2_QOS_MODE_DSCP;

		(void)memset(new_cfg->dscp_map, 0, sizeof(u8) * SXE2_DSCP_MAX_NUM);
	}

	new_cfg->dscp_map[app->protocol] = app->priority;
	new_cfg->app[new_cfg->numapps].selector = app->selector;
	new_cfg->app[new_cfg->numapps].prot_id = app->protocol;
	new_cfg->app[new_cfg->numapps].prio = app->priority;
	new_cfg->numapps++;

	ret = dcb_ieee_setapp(netdev, app);
	if (ret) {
		memcpy(new_cfg, old_cfg, sizeof(struct sxe2_dcbx_cfg));
		LOG_NETDEV_ERR("set app failed, ret=%d\n", ret);
		goto l_unlock;
	}

	ret = sxe2_dcb_cfg(adapter, new_cfg, true);
	if (ret) {
		rtn = sxe2_dcbnl_setapp_recover(netdev, app);
		if (rtn) {
			LOG_NETDEV_ERR("Failed to delete re-mapping TLV %d\n", rtn);
			goto l_unlock;
		}
	}

l_unlock:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	return ret;
}

static int sxe2_dcbnl_delapp(struct net_device *netdev, struct dcb_app *app)
{
	int ret;
	unsigned int i, j;
	struct sxe2_dcbx_cfg *old_cfg, *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	LOG_INFO_BDF("delapp: app:%d up %d\n", app->protocol, app->priority);
	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto l_unlock;
	}

	if (adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) {
		LOG_NETDEV_ERR("can't delete DSCP netlink app\t"
			       "when FW DCB agent is active\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	old_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		goto l_unlock;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	for (i = 0; i < new_cfg->numapps; i++) {
		if (app->selector == new_cfg->app[i].selector &&
		    app->protocol == new_cfg->app[i].prot_id &&
		    app->priority == new_cfg->app[i].prio) {
			new_cfg->app[i].selector = 0;
			new_cfg->app[i].prot_id = 0;
			new_cfg->app[i].prio = 0;
			break;
		}
	}

	if (i == new_cfg->numapps) {
		LOG_NETDEV_ERR("can't delete DSCP netlink app: does not exist.\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	new_cfg->numapps--;
	for (j = i; j < new_cfg->numapps; j++) {
		new_cfg->app[j].selector = old_cfg->app[j + 1].selector;
		new_cfg->app[j].prot_id = old_cfg->app[j + 1].prot_id;
		new_cfg->app[j].prio = old_cfg->app[j + 1].prio;
	}
	memset(&new_cfg->app[j], 0, sizeof(struct sxe2_dcb_app_prio_tbl));

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP) {
		ret = 0;
		goto l_unlock;
	}

	clear_bit(app->protocol, new_cfg->dscp_mapped);
	new_cfg->dscp_map[app->protocol] = 0;

	if (bitmap_empty(new_cfg->dscp_mapped, SXE2_DSCP_NUM_VAL) &&
	    new_cfg->qos_mode == SXE2_QOS_MODE_DSCP) {
		ret = sxe2_qos_mode_set(adapter, SXE2_QOS_MODE_VLAN);
		if (ret) {
			LOG_NETDEV_ERR("failed to set VLAN PFC mode %d\n", ret);
			goto l_unlock;
		}

		LOG_DEV_INFO("switched QoS to L2 VLAN mode\n");

		new_cfg->qos_mode = SXE2_QOS_MODE_VLAN;
	}

	ret = sxe2_dcb_cfg(adapter, new_cfg, true);
	if (ret)
		LOG_INFO_BDF("del app cfg failed:%d\n", ret);

l_unlock:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	return ret;
}

static int sxe2_dcbnl_ieee_getmaxrate(struct net_device *netdev,
				      struct ieee_maxrate *maxrate)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_dcbx_cfg *cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	int i;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		maxrate->tc_maxrate[i] = cfg->usr_bw_value[i];
		LOG_INFO_BDF("dcb get tc_%d max_bw %llu bps\n", i,
			     maxrate->tc_maxrate[i]);
	}

	return 0;
}

static int sxe2_maxrate_param_check(struct sxe2_adapter *adapter,
				    struct ieee_maxrate *maxrate)
{
	u64 max_tx_rate = 0;
	int ret = 0;
	int i;

	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto l_end;
	}

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_IEEE)) {
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (maxrate->tc_maxrate[i] == 0)
			continue;

		max_tx_rate = SXE2_B2KBIT(maxrate->tc_maxrate[i]);
		if (max_tx_rate > (SXE2_TXSCHED_MAX_BW)) {
			LOG_ERROR_BDF("invalid max rate %llu specified for the tc %d\n",
				      max_tx_rate, i);
			ret = -EINVAL;
			goto l_end;
		}
	}

l_end:
	return ret;
}

static void sxe2_dcb_maxrate_cfg(u64 *usr_rate, u32 *hw_rate, u64 maxrate)
{
	if (!maxrate) {
		*hw_rate = SXE2_TXSCHED_DFLT_BW;
		*usr_rate = 0;
	} else if (maxrate > SXE2_MINTC_RATE) {
		*hw_rate = (u32)SXE2_B2KBIT(maxrate);
		*usr_rate = maxrate;
	} else {
		*hw_rate = (u32)SXE2_B2KBIT(SXE2_MINTC_RATE);
		*usr_rate = SXE2_MINTC_RATE;
	}
}

static int sxe2_dcbnl_ieee_setmaxrate(struct net_device *netdev,
				      struct ieee_maxrate *maxrate)
{
	int ret, rc;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_dcbx_cfg *new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;
	struct sxe2_dcbx_cfg *local_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	int i;
	u8 tc_cnt;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	ret = sxe2_maxrate_param_check(adapter, maxrate);
	if (ret)
		goto l_unlock;

	memset(new_cfg->hw_bw_value, 0, sizeof(new_cfg->hw_bw_value));

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		sxe2_dcb_maxrate_cfg(&new_cfg->usr_bw_value[i],
				     &new_cfg->hw_bw_value[i], maxrate->tc_maxrate[i]);

	tc_cnt = sxe2_dcb_tc_cnt_get(new_cfg);
	for (i = 0; i < tc_cnt; i++) {
		if (new_cfg->hw_bw_value[i] != local_cfg->hw_bw_value[i]) {
			ret = sxe2_txsched_tc_max_bw_lmt_cfg(vsi, (u8)i,
							     (u32)new_cfg->hw_bw_value[i]);
			if (ret) {
				LOG_ERROR_BDF("dcb set tc %d maxrate %u kbps failed \t"
					      "%d.\n",
					      i, new_cfg->hw_bw_value[i], ret);
				goto l_recover;
			}
		}
		LOG_INFO_BDF("dcb set tc_%d max_bw %u kbps\n", i,
			     new_cfg->hw_bw_value[i]);
	}

	memcpy(local_cfg, new_cfg, sizeof(*local_cfg));
	goto l_unlock;

l_recover:
	for (; i >= 0; i--) {
		rc = sxe2_txsched_tc_max_bw_lmt_cfg(vsi, (u8)i,
						    local_cfg->hw_bw_value[i]);
		if (rc) {
			ret = rc;
			LOG_ERROR_BDF("dcb recover tc %d maxrate %u kbps failed %d.\n",
				      i, local_cfg->hw_bw_value[i], ret);
		}
	}
	memcpy(new_cfg, local_cfg, sizeof(*local_cfg));

l_unlock:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	return ret;
}

static void sxe2_dcbnl_get_pfc_cfg(struct net_device *netdev, int prio, u8 *setting)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES)
		return;

	*setting = (adapter->dcb_ctxt.local_dcbx_cfg.pfc.enable >> prio) & 0x1;
	LOG_INFO_BDF("get pfc config up=%d, setting=%d, pfc enable=0x%x\n", prio,
		     *setting, adapter->dcb_ctxt.local_dcbx_cfg.pfc.enable);
}

static void sxe2_dcbnl_set_pfc_cfg(struct net_device *netdev, int prio, u8 set)
{
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES)
		return;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	new_cfg->pfc.cap = IEEE_8021QAZ_MAX_TCS;
	if (set)
		new_cfg->pfc.enable |= BIT(prio);
	else
		new_cfg->pfc.enable &= ~BIT(prio);

	LOG_INFO_BDF("set pfc config up:%d set:%d pfcena:0x%x\n", prio, set,
		     new_cfg->pfc.enable);
}

static u8 sxe2_dcbnl_getpfcstate(struct net_device *netdev)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (adapter->dcb_ctxt.local_dcbx_cfg.pfc.enable)
		return 1;

	return 0;
}

static u8 sxe2_dcbnl_getstate(struct net_device *netdev)
{
	u8 state = 0;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	state = (u8)test_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags);

	LOG_INFO_BDF("dcb enabled state = %d\n", state);

	return state;
}

static u8 sxe2_dcbnl_setstate(struct net_device *netdev, u8 state)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return SXE2_DCB_NO_HW_CHG;

	if (!!state == test_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags))
		return SXE2_DCB_NO_HW_CHG;

	if (state) {
		set_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags);
		(void)memcpy(&adapter->dcb_ctxt.desired_dcbx_cfg,
			     &adapter->dcb_ctxt.local_dcbx_cfg,
			     sizeof(struct sxe2_dcbx_cfg));
	} else {
		clear_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags);
	}

	return SXE2_DCB_HW_CHG;
}

static void sxe2_dcbnl_get_pg_tc_cfg_tx(struct net_device *netdev, int prio,
					u8 __always_unused *prio_type, u8 *pgid,
					u8 __always_unused *bw_pct,
					u8 __always_unused *up_map)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES || prio < 0)
		return;

	*pgid = adapter->dcb_ctxt.local_dcbx_cfg.ets.prio_tbl[prio];
	LOG_INFO_BDF("get pg config prio=%d tc=%d\n", prio, *pgid);
}

static void sxe2_dcbnl_set_pg_tc_cfg_tx(struct net_device *netdev, int tc,
					u8 __always_unused prio_type,
					u8 __always_unused bwg_id,
					u8 __always_unused bw_pct, u8 up_map)
{
	u32 i;
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (tc >= IEEE_8021QAZ_MAX_TCS || tc < 0)
		return;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	sxe2_for_each_tc(i)
		if (up_map & BIT(i))
			new_cfg->ets.prio_tbl[i] = (u8)tc;

	new_cfg->ets.tsa_tbl[tc] = SXE2_IEEE_TSA_ETS;
}

static void sxe2_dcbnl_get_pg_bwg_cfg_tx(struct net_device *netdev, int pgid,
					 u8 *bw_pct)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (pgid >= IEEE_8021QAZ_MAX_TCS || pgid < 0)
		return;

	*bw_pct = adapter->dcb_ctxt.local_dcbx_cfg.ets.tcbw_tbl[pgid];
	LOG_INFO_BDF("get pg bw config tc=%d bw_pct=%d\n", pgid, *bw_pct);
}

static void sxe2_dcbnl_set_pg_bwg_cfg_tx(struct net_device *netdev, int pgid,
					 u8 bw_pct)
{
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (pgid >= IEEE_8021QAZ_MAX_TCS || pgid < 0)
		return;

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	new_cfg->ets.tcbw_tbl[pgid] = bw_pct;
	LOG_INFO_BDF("set pg bw config tc=%d bw_pct=%d\n", pgid, bw_pct);
}

static void sxe2_dcbnl_get_pg_tc_cfg_rx(struct net_device *netdev, int prio,
					u8 __always_unused *prio_type, u8 *pgid,
					u8 __always_unused *bw_pct,
					u8 __always_unused *up_map)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES || prio < 0)
		return;

	*pgid = adapter->dcb_ctxt.local_dcbx_cfg.ets.prio_tbl[prio];
	LOG_INFO_BDF("get up=%d config tc=%d\n", prio, *pgid);
}

static void
sxe2_dcbnl_set_pg_tc_cfg_rx(struct net_device *netdev, int __always_unused prio,
			    u8 __always_unused prio_type, u8 __always_unused pgid,
			    u8 __always_unused bw_pct, u8 __always_unused up_map)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	LOG_INFO_BDF("rx tc pg config not supported.\n");
}

static void sxe2_dcbnl_get_pg_bwg_cfg_rx(struct net_device *netdev,
					 int __always_unused pgid, u8 *bw_pct)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	*bw_pct = 0;
}

static void sxe2_dcbnl_set_pg_bwg_cfg_rx(struct net_device *netdev,
					 int __always_unused pgid,
					 u8 __always_unused bw_pct)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	LOG_INFO_BDF("rx bwg pg config not supported.\n");
}

static u8 sxe2_dcbnl_get_cap(struct net_device *netdev, int capid, u8 *cap)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_adapter *adapter = np->vsi->adapter;

	if (!(test_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags)))
		return SXE2_DCB_NO_HW_CHG;

	switch (capid) {
	case DCB_CAP_ATTR_PG:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PFC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_UP2TC:
		*cap = false;
		break;
	case DCB_CAP_ATTR_PG_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = 0x80;
		break;
	case DCB_CAP_ATTR_GSP:
		*cap = false;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	case DCB_CAP_ATTR_DCBX:
		*cap = adapter->dcb_ctxt.dcbx_cap;
		break;
	default:
		*cap = false;
		break;
	}

	LOG_INFO_BDF("dcbx get capability cap_mode=%d cap=0x%x\n", capid, *cap);
	return 0;
}

static u8 sxe2_dcbnl_cee_set_all(struct net_device *netdev)
{
	s32 ret = 0;
	struct sxe2_dcbx_cfg *new_cfg;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state != SXE2_DCB_STATE_READY) {
		ret = -EBUSY;
		goto no_change;
	}

	if ((adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_LLD_MANAGED) ||
	    !(adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_VER_CEE)) {
		goto no_change;
	}

	new_cfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	ret = sxe2_dcb_cfg(adapter, new_cfg, true);
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);

	return (ret != SXE2_DCB_HW_CHG_RST) ? SXE2_DCB_NO_HW_CHG : SXE2_DCB_HW_CHG_RST;

no_change:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	return SXE2_DCB_NO_HW_CHG;
}

static const struct dcbnl_rtnl_ops dcbnl_ops = {
		.ieee_getets = sxe2_dcbnl_getets,
		.ieee_setets = sxe2_dcbnl_setets,
		.ieee_getmaxrate = sxe2_dcbnl_ieee_getmaxrate,
		.ieee_setmaxrate = sxe2_dcbnl_ieee_setmaxrate,
		.ieee_getpfc = sxe2_dcbnl_getpfc,
		.ieee_setpfc = sxe2_dcbnl_setpfc,
		.ieee_setapp = sxe2_dcbnl_setapp,
		.ieee_delapp = sxe2_dcbnl_delapp,

		.getstate = sxe2_dcbnl_getstate,
		.setstate = sxe2_dcbnl_setstate,
		.getpermhwaddr = sxe2_dcbnl_get_perm_hw_addr,
		.setpgtccfgtx = sxe2_dcbnl_set_pg_tc_cfg_tx,
		.setpgbwgcfgtx = sxe2_dcbnl_set_pg_bwg_cfg_tx,
		.setpgtccfgrx = sxe2_dcbnl_set_pg_tc_cfg_rx,
		.setpgbwgcfgrx = sxe2_dcbnl_set_pg_bwg_cfg_rx,
		.getpgtccfgtx = sxe2_dcbnl_get_pg_tc_cfg_tx,
		.getpgbwgcfgtx = sxe2_dcbnl_get_pg_bwg_cfg_tx,
		.getpgtccfgrx = sxe2_dcbnl_get_pg_tc_cfg_rx,
		.getpgbwgcfgrx = sxe2_dcbnl_get_pg_bwg_cfg_rx,
		.setpfccfg = sxe2_dcbnl_set_pfc_cfg,
		.getpfccfg = sxe2_dcbnl_get_pfc_cfg,
		.getapp = sxe2_dcbnl_getapp,
		.getcap = sxe2_dcbnl_get_cap,
		.setall = sxe2_dcbnl_cee_set_all,
		.getnumtcs = sxe2_dcbnl_getnumtcs,
		.getpfcstate = sxe2_dcbnl_getpfcstate,

		.getdcbx = sxe2_dcbnl_getdcbx,
		.setdcbx = sxe2_dcbnl_setdcbx,
};

void sxe2_dcbnl_set_all(struct sxe2_vsi *vsi)
{
	u32 i;
	u8 prio, tc_map;
	struct dcb_app sapp;
	struct sxe2_dcbx_cfg *dcbxcfg;
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!netdev)
		return;

	if (adapter->dcb_ctxt.dcbx_cap & DCB_CAP_DCBX_HOST)
		return;

	if (!test_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags))
		return;

	dcbxcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	for (i = 0; i < dcbxcfg->numapps; i++) {
		prio = dcbxcfg->app[i].prio;
		tc_map = BIT(dcbxcfg->ets.prio_tbl[prio]);

		if (tc_map & vsi->tc.tc_map) {
			sapp.selector = dcbxcfg->app[i].selector;
			sapp.protocol = dcbxcfg->app[i].prot_id;
			sapp.priority = prio;
			(void)dcb_ieee_setapp(netdev, &sapp);
		}
	}

	(void)dcbnl_ieee_notify(netdev, RTM_SETDCB, DCB_CMD_IEEE_SET, 0, 0);
}

static void sxe2_dcbnl_vsi_del_app(struct sxe2_vsi *vsi,
				   struct sxe2_dcb_app_prio_tbl *app)
{
	s32 ret;
	struct dcb_app sapp;
	struct sxe2_adapter *adapter = vsi->adapter;

	sapp.priority = app->prio;
	sapp.protocol = app->prot_id;
	sapp.selector = app->selector;

	rtnl_lock();
	ret = sxe2_dcbnl_delapp(vsi->netdev, &sapp);
	rtnl_unlock();

	LOG_INFO_BDF("deleting app for vsi idx=%d ret=%d \t"
		     "sel=%d proto=0x%x, prio=%d\n",
		     vsi->idx_in_dev, ret, app->selector,
		     app->prot_id, app->prio);
}

void sxe2_dcbnl_flush_apps(struct sxe2_adapter *adapter,
			   struct sxe2_dcbx_cfg *old_cfg,
			   struct sxe2_dcbx_cfg *new_cfg)
{
	u32 i;
	struct sxe2_vsi *pf_vsi = adapter->vsi_ctxt.main_vsi;

	if (!pf_vsi)
		return;

	for (i = 0; i < old_cfg->numapps; i++) {
		struct sxe2_dcb_app_prio_tbl app = old_cfg->app[i];

		if (!sxe2_dcbnl_find_app(new_cfg, &app))
			sxe2_dcbnl_vsi_del_app(pf_vsi, &app);
	}
}

void sxe2_dcbnl_setup(struct sxe2_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (!test_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags))
		return;

	netdev->dcbnl_ops = &dcbnl_ops;

	sxe2_dcbnl_set_all(vsi);
}
