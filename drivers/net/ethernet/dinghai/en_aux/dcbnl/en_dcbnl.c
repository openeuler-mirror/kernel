// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

//#include <linux/device.h>
#include "../../en_aux.h"
#include "en_dcbnl.h"
#include "en_np/qos/include/dpp_drv_qos.h"
#include "en_aux/en_aux_cmd.h"
#include "en_dcbnl_api.h"

u32 g_maxrate_num;
static int zxdh_dcbnl_ieee_getets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 tc = 0;
	u32 j = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_ieee_getets: coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	ets->willing = 0;

	ets->ets_cap = ZXDH_DCBNL_MAX_TRAFFIC_CLASS;

	memcpy(ets->tc_tsa, en_dev->dcb_para.ets_cfg.tc_tsa, sizeof(ets->tc_tsa));
	memcpy(ets->tc_tx_bw, en_dev->dcb_para.ets_cfg.tc_tx_bw, sizeof(ets->tc_tx_bw));
	memcpy(ets->prio_tc, en_dev->dcb_para.ets_cfg.prio_tc, sizeof(ets->prio_tc));

	for (tc = 0; tc < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; tc++) {
		if (ets->tc_tsa[tc] != IEEE_8021QAZ_TSA_ETS)
			ets->tc_tx_bw[tc] = 0;
	}

	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++) {
		LOG_INFO(" idx:%d, ets->tc_tsa:%d, ets->tc_tx_bw:%d, ets->prio_tc:%d\n", j,
			 ets->tc_tsa[j], ets->tc_tx_bw[j], ets->prio_tc[j]);
	}

	return 0;
}

static int zxdh_dcbnl_check_ets_maxtc(struct ieee_ets *ets)
{
	u32 i;

	for (i = 0; i < ZXDH_DCBNL_MAX_PRIORITY; i++) {
		if (ets->prio_tc[i] >= ZXDH_DCBNL_MAX_TRAFFIC_CLASS) {
			LOG_ERR("dcbnl_check_ets: Failed! TC value greater than max(%d)\n",
				ZXDH_DCBNL_MAX_TRAFFIC_CLASS);
			return 1;
		}
	}
	return 0;
}

static int zxdh_dcbnl_check_ets_tcbw(struct ieee_ets *ets)
{
	bool have_ets_tc = false;
	u32 bw_sum = 0;
	u32 i;

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS) {
			have_ets_tc = true;
			bw_sum += ets->tc_tx_bw[i];
		}
	}

	if (have_ets_tc && ((bw_sum != 100) && (bw_sum != 0))) {
		LOG_ERR("dcbnl_check_ets_tcbw: Failed! ETS BW sum is illegal\n");
		return 1;
	}

	return 0;
}

static int zxdh_dcbnl_check_ets_para(struct ieee_ets *ets)
{
	u32 err = 0;

	err = zxdh_dcbnl_check_ets_maxtc(ets);
	if (err)
		return -EINVAL;

	err = zxdh_dcbnl_check_ets_tcbw(ets);
	if (err)
		return -EINVAL;
	LOG_INFO(" end\n");
	return 0;
}

static int zxdh_dcbnl_ieee_divide_tc_type(struct ieee_ets *ets, u8 *tc_type)
{
	u32 i;

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_ETS:
			tc_type[i] = ets->tc_tx_bw[i] ? ZXDH_DCBNL_ETS_TC :
							      ZXDH_DCBNL_ZEROBW_ETS_TC;
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			tc_type[i] = ZXDH_DCBNL_STRICT_TC;
			break;
		case IEEE_8021QAZ_TSA_VENDOR:
			tc_type[i] = ZXDH_DCBNL_VENDOR_TC;
			break;
		default:
			tc_type[i] = ZXDH_DCBNL_STRICT_TC;
			LOG_ERR("dcbnl: %d tsa error, change to strict\n", ets->tc_tsa[i]);
			break;
		}
	}

	return 0;
}

static int zxdh_dcbnl_ieee_convert_tc_bw(struct ieee_ets *ets, u8 *tc_type, u8 *tc_tx_bw)
{
	u32 i;
	u8 zero_ets_bw = 0;
	u8 zero_ets_num = 0;

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		if (tc_type[i] == ZXDH_DCBNL_ZEROBW_ETS_TC)
			zero_ets_num++;
	}

	if (zero_ets_num)
		zero_ets_bw = (u8)ZXDH_DCBNL_MAX_BW_ALLOC / zero_ets_num;

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		switch (tc_type[i]) {
		case ZXDH_DCBNL_ZEROBW_ETS_TC:
			tc_tx_bw[i] = zero_ets_bw;
			break;
		case ZXDH_DCBNL_ETS_TC:
			tc_tx_bw[i] = ets->tc_tx_bw[i];
			break;
		case ZXDH_DCBNL_STRICT_TC:
		case ZXDH_DCBNL_VENDOR_TC:
			tc_tx_bw[i] = ZXDH_DCBNL_MAX_BW_ALLOC;
			break;
		default:
			break;
		}
	}
	/* debug */
	LOG_INFO(" zero_ets_num:%d, zero_ets_bw:%d\n", zero_ets_num, zero_ets_bw);

	return 0;
}

static u32 zxdh_dcbnl_ieee_set_ets_para(struct zxdh_en_priv *en_priv, struct ieee_ets *ets)
{
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u8 tc_type[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u8 tc_tx_bw[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u32 err = 0;
	u32 j = 0;

	zxdh_dcbnl_ieee_divide_tc_type(ets, tc_type);

	zxdh_dcbnl_ieee_convert_tc_bw(ets, tc_type, tc_tx_bw);

	err = zxdh_dcbnl_set_tc_scheduling(en_priv, tc_type, tc_tx_bw);
	if (err) {
		LOG_ERR("set_tc_scheduling failed\n");
		return err;
	}

	err = zxdh_dcbnl_set_ets_up_tc_map(en_priv, ets->prio_tc);
	if (err) {
		LOG_ERR("set_prio_tc_map failed\n");
		return err;
	}

	memcpy(en_dev->dcb_para.ets_cfg.tc_tsa, ets->tc_tsa, sizeof(ets->tc_tsa));
	memcpy(en_dev->dcb_para.ets_cfg.tc_tx_bw, ets->tc_tx_bw, sizeof(ets->tc_tx_bw));
	memcpy(en_dev->dcb_para.ets_cfg.prio_tc, ets->prio_tc, sizeof(ets->prio_tc));
	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++) {
		LOG_DEBUG(" idx:%d, tc_tsa:%d, tc_tx_bw:%d, prio_tc:%d\n", j,
			  en_dev->dcb_para.ets_cfg.tc_tsa[j], en_dev->dcb_para.ets_cfg.tc_tx_bw[j],
			  en_dev->dcb_para.ets_cfg.prio_tc[j]);

		LOG_DEBUG(" idx:%d, tc_type:%d, tc_tx_bw:%d\n", j, tc_type[j], tc_tx_bw[j]);
	}

	return 0;
}

static int zxdh_dcbnl_ieee_setets(struct net_device *netdev, struct ieee_ets *ets)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 err;
	u32 j = 0;

	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++) {
		LOG_DEBUG(" idx:%d, ets->tc_tsa:%d, ets->tc_tx_bw:%d, ets->prio_tc:%d\n", j,
			  ets->tc_tsa[j], ets->tc_tx_bw[j], ets->prio_tc[j]);
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR(" coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	err = zxdh_dcbnl_check_ets_para(ets);
	if (err)
		return err;

	err = zxdh_dcbnl_ieee_set_ets_para(en_priv, ets);
	if (err)
		return err;

	return 0;
}

static int zxdh_dcbnl_ieee_getpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 pfc_cur_mac_en = 0;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	ret = zxdh_en_fc_mode_get(en_dev, &pfc_cur_mac_en);

	if (ret != 0) {
		LOG_ERR("zxdh_port_pfc_enable_get failed");
		return ret;
	}

	if (pfc_cur_mac_en == BIT(SPM_FC_PFC_FULL))
		pfc->pfc_en = 255;
	else
		pfc->pfc_en = 0;

	pfc->pfc_cap = 8;
	pfc->delay = 7;

	return ret;
}

static int zxdh_dcbnl_ieee_setpfc(struct net_device *netdev, struct ieee_pfc *pfc)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 port_mac_en = 0;
	u32 cur_port_mac_en = 0;
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;
	if (pfc->pfc_en != 0 && pfc->pfc_en != 0xff) {
		LOG_INFO("pfc->pfc_en input invalid: %d", pfc->pfc_en);
		return -EINVAL;
	}

	ret = zxdh_en_fc_mode_get(en_dev, &cur_port_mac_en);

	if (pfc->pfc_en != 0)
		port_mac_en = BIT(SPM_FC_PFC_FULL);
	else if (cur_port_mac_en == BIT(SPM_FC_PFC_FULL))
		port_mac_en = BIT(SPM_FC_NONE);
	else
		return 0;

	ret |= zxdh_en_fc_mode_set(en_dev, port_mac_en);

	if (ret != 0)
		LOG_ERR("zxdh dcbnl ieee setpfc pfc_en:%c failed, %d", pfc->pfc_en, ret);

	return ret;
}

static int zxdh_dcbnl_ieee_getmaxrate(struct net_device *netdev, struct ieee_maxrate *maxrate)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 i = 0;
	u32 j = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		if (en_dev->dcb_para.tc_maxrate[i] >= ZXDH_DCBNL_MAXRATE_KBITPS)
			maxrate->tc_maxrate[i] = 0; //0 indicates unlimited
		else
			maxrate->tc_maxrate[i] = en_dev->dcb_para.tc_maxrate[i];
	}

	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++)
		LOG_DEBUG(" tc:%d,tc_maxrate:%lld\n", j, maxrate->tc_maxrate[j]);

	return 0;
}

static int zxdh_dcbnl_ieee_setmaxrate(struct net_device *netdev, struct ieee_maxrate *maxrate)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev;
	u32 maxrate_kbps[ZXDH_DCBNL_MAX_TRAFFIC_CLASS] = { 0 };
	u32 err, i;
	u32 j = 0;
	u32 tc_td_th[ZXDH_DCBNL_MAX_TRAFFIC_CLASS] = { ZXDH_DCBNL_FLOW_TDTH_DEFAULT };
	struct dh_core_dev *dh_dev;
	struct zxdh_pf_device *pf_dev;
	u64 oldmaxrate = 0;

	if (netdev == NULL || maxrate == NULL || en_priv == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	en_dev = &en_priv->edev;
	if (en_dev == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	dh_dev = en_dev->parent;
	if (dh_dev == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	pf_dev = dh_core_priv(dh_dev->parent);
	if (pf_dev == NULL || en_dev->ops == NULL || en_dev->ops->get_coredev_type == NULL)
		return ZXDH_DCBNL_INVALID_PARA;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	/* Values are 64 bits and specified in Kbps */
	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		oldmaxrate = en_dev->dcb_para.tc_maxrate[i];

		if ((maxrate->tc_maxrate[i] == 0) ||
		    (maxrate->tc_maxrate[i] >= ZXDH_DCBNL_MAXRATE_KBITPS)) {
			if (pf_dev->board_type == DH_STDB || pf_dev->board_type == DH_STDA ||
			    pf_dev->board_type == DH_STDC) {
				tc_td_th[i] = ZXDH_DCBNL_FLOW_TDTH_DEFAULT;
				LOG_DEBUG(" old[%u]: maxrate %llu num %u\n", i, oldmaxrate,
					  g_maxrate_num);
				if ((g_maxrate_num > 0) && (oldmaxrate > 0) &&
				    (oldmaxrate < ZXDH_DCBNL_MAXRATE_KBITPS)) {
					g_maxrate_num--;
					err = zxdh_dcbnl_set_single_td_th(en_priv, i, tc_td_th[i]);
					if (err)
						return err;
				}
			}
			maxrate_kbps[i] = ZXDH_DCBNL_MAXRATE_KBITPS;

		} else if (maxrate->tc_maxrate[i] <= ZXDH_DCBNL_MINRATE_KBITPS) {
			maxrate_kbps[i] = ZXDH_DCBNL_MINRATE_KBITPS;
		} else {
			maxrate_kbps[i] = (u32)maxrate->tc_maxrate[i];

			if (pf_dev->board_type == DH_STDB || pf_dev->board_type == DH_STDA ||
			    pf_dev->board_type == DH_STDC) {
				LOG_DEBUG(" old[%u]: maxrate %llu new %u num %u\n", i, oldmaxrate,
					  maxrate_kbps[i], g_maxrate_num);
				tc_td_th[i] = ZXDH_DCBNL_FLOW_TDTH_DEFAULT;
				if ((oldmaxrate == 0) ||
				    (oldmaxrate >= ZXDH_DCBNL_MAXRATE_KBITPS)) {
					g_maxrate_num++;
				}

				if (g_maxrate_num <= MAX_RATE_LIMITED_NUM) {
					tc_td_th[i] = ZXDH_DCBNL_FLOW_TDTH_OPT;
					err = zxdh_dcbnl_set_single_td_th(en_priv, i, tc_td_th[i]);
					if (err)
						return err;
				}
			}
		}
	}
	LOG_DEBUG(" g_maxrate_num %u\n", g_maxrate_num);

	tc_td_th[0] = ZXDH_DCBNL_FLOW_TDTH_UPF;
	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++) {
		LOG_DEBUG(" tc:%d,maxrate->tc_maxrate:%lld,maxrate_kbps:%d\n", j,
			  maxrate->tc_maxrate[j], maxrate_kbps[j]);
	}

	err = zxdh_dcbnl_set_tc_maxrate(en_priv, maxrate_kbps);
	if (err)
		return err;

	return 0;
}

static int zxdh_dcbnl_ieee_setapp(struct net_device *netdev, struct dcb_app *app)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dcb_app app_old;
	bool is_new = false;
	int err = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR(" coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	if ((app->selector != IEEE_8021QAZ_APP_SEL_DSCP) ||
	    (app->protocol >= ZXDH_DCBNL_MAX_DSCP) || (app->priority >= ZXDH_DCBNL_MAX_PRIORITY)) {
		return -EINVAL;
	}
	/* Save the old entry info */
	app_old.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	app_old.protocol = app->protocol;
	app_old.priority = en_dev->dcb_para.dscp2prio[app->protocol];

	LOG_INFO(" protocol:%d, priority:%d\n", app->protocol, app->priority);

	if (!en_dev->dcb_para.dscp_app_num) {
		err = zxdh_dcbnl_set_ets_trust(en_priv, ZXDH_DCBNL_ETS_TRUST_DSCP);
		if (err)
			return err;
	}

	if (app->priority != en_dev->dcb_para.dscp2prio[app->protocol]) {
		err = zxdh_dcbnl_set_dscp2prio(en_priv, app->protocol, app->priority);
		if (err) {
			zxdh_dcbnl_set_ets_trust(en_priv, ZXDH_DCBNL_ETS_TRUST_PCP);
			return err;
		}
	}

	/* Delete the old entry if exists */
	err = dcb_ieee_delapp(netdev, &app_old);
	if (err)
		is_new = true;
	/* Add new entry and update counter */
	err = dcb_ieee_setapp(netdev, app);
	if (err)
		return err;
	if (is_new)
		en_dev->dcb_para.dscp_app_num++;
	LOG_INFO(" dscp_app_num:%d\n", en_dev->dcb_para.dscp_app_num);

	return err;
}

static int zxdh_dcbnl_ieee_delapp(struct net_device *netdev, struct dcb_app *app)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	int err = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl ieee delapp coredev type is not a PF");
		return -EOPNOTSUPP;
	}

	if ((app->selector != IEEE_8021QAZ_APP_SEL_DSCP) ||
	    (app->protocol >= ZXDH_DCBNL_MAX_DSCP)) {
		return -EINVAL;
	}

	if (!en_dev->dcb_para.dscp_app_num)
		return -ENOENT;

	if (app->priority != en_dev->dcb_para.dscp2prio[app->protocol])
		return -ENOENT;

	/* Delete the app entry */
	err = dcb_ieee_delapp(netdev, app);
	if (err)
		return err;

	/* Restore to default */
	err = zxdh_dcbnl_set_dscp2prio(en_priv, app->protocol, app->protocol >> 3);
	if (err) {
		zxdh_dcbnl_set_ets_trust(en_priv, ZXDH_DCBNL_ETS_TRUST_PCP);
		return err;
	}
	en_dev->dcb_para.dscp_app_num--;
	LOG_INFO(" protocol:%d, dscp_app_num:%d\n", app->protocol, en_dev->dcb_para.dscp_app_num);

	if (!en_dev->dcb_para.dscp_app_num)
		err = zxdh_dcbnl_set_ets_trust(en_priv, ZXDH_DCBNL_ETS_TRUST_PCP);

	return err;
}
#ifdef ZXDH_DCBNL_CEE_SUPPORT
static void zxdh_dcbnl_setpgtccfgtx(struct net_device *netdev, int tc, u8 prio_type, u8 pgid,
				    u8 bw_pct, u8 up_map)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_dcbnl_cee_ets *cee_ets_cfg;
	u32 i;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl setpgtccfgtx coredev type is not a PF");
		return;
	}

	if ((tc < 0) || (tc >= ZXDH_DCBNL_MAX_TRAFFIC_CLASS))
		return;

	cee_ets_cfg = &en_dev->dcb_para.cee_ets_cfg;
	for (i = 0; i < ZXDH_DCBNL_MAX_PRIORITY; i++) {
		if (up_map & BIT(i))
			cee_ets_cfg->prio_tc[i] = tc;
	}
	cee_ets_cfg->tc_tsa[tc] = IEEE_8021QAZ_TSA_ETS;
}
static void zxdh_dcbnl_setpgbwgcfgtx(struct net_device *netdev, int pgid, u8 bw_pct)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_setpgbwgcfgtx coredev type is not a PF");
		return;
	}

	if ((pgid >= 0) && (pgid < ZXDH_DCBNL_MAX_TRAFFIC_CLASS))
		en_dev->dcb_para.cee_ets_cfg.tc_tx_bw[pgid] = bw_pct;
	LOG_INFO(" tc_tx_bw[%d]:%d\n", pgid, bw_pct);
}

static void zxdh_dcbnl_getpgtccfgtx(struct net_device *netdev, int prio, u8 *prio_type, u8 *pgid,
				    u8 *bw_pct, u8 *up_map)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_getpgtccfgtx coredev type is not a PF");
		return;
	}

	if ((prio >= 0) && (prio < ZXDH_DCBNL_MAX_PRIORITY))
		*pgid = en_dev->dcb_para.ets_cfg.prio_tc[prio];
}

static void zxdh_dcbnl_getpgbwgcfgtx(struct net_device *netdev, int pgid, u8 *bw_pct)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_getpgbwgcfgtx coredev type is not a PF");
		return;
	}

	if ((pgid >= 0) && (pgid < ZXDH_DCBNL_MAX_TRAFFIC_CLASS))
		*bw_pct = en_dev->dcb_para.ets_cfg.tc_tx_bw[pgid];
}

static void zxdh_dcbnl_setpgtccfgrx(struct net_device *netdev, int prio, u8 prio_type, u8 pgid,
				    u8 bw_pct, u8 up_map)
{
	LOG_ERR("Rx PG TC Config Not Supported.\n");
}

static void zxdh_dcbnl_setpgbwgcfgrx(struct net_device *netdev, int pgid, u8 bw_pct)
{
	LOG_ERR("Rx PG BWG Config Not Supported.\n");
}

static void zxdh_dcbnl_getpgtccfgrx(struct net_device *netdev, int prio, u8 *prio_type, u8 *pgid,
				    u8 *bw_pct, u8 *up_map)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_getpgtccfgrx coredev type is not a PF");
		return;
	}

	if ((prio >= 0) && (prio < ZXDH_DCBNL_MAX_PRIORITY))
		*pgid = en_dev->dcb_para.ets_cfg.prio_tc[prio];
}

static void zxdh_dcbnl_getpgbwgcfgrx(struct net_device *netdev, int pgid, u8 *bw_pct)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_getpgbwgcfgrx coredev type is not a PF");
		return;
	}

	if ((pgid >= 0) && (pgid < ZXDH_DCBNL_MAX_TRAFFIC_CLASS))
		*bw_pct = 0;
}

static u8 zxdh_dcbnl_setall(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct ieee_ets ets = { 0 };
	u32 i = 0;
	u32 err = 0;
	u32 j = 0;

	if (en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) {
		LOG_ERR("zxdh dcbnl_setall coredev type is not a PF");
		return 1;
	}

	ets.ets_cap = ZXDH_DCBNL_MAX_TRAFFIC_CLASS;
	for (i = 0; i < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; i++) {
		ets.tc_tx_bw[i] = en_dev->dcb_para.cee_ets_cfg.tc_tx_bw[i];
		ets.tc_rx_bw[i] = en_dev->dcb_para.cee_ets_cfg.tc_tx_bw[i];
		ets.tc_tsa[i] = en_dev->dcb_para.cee_ets_cfg.tc_tsa[i];
	}

	for (i = 0; i < ZXDH_DCBNL_MAX_PRIORITY; i++)
		ets.prio_tc[i] = en_dev->dcb_para.cee_ets_cfg.prio_tc[i];
	/* debug */
	for (j = 0; j < ZXDH_DCBNL_MAX_TRAFFIC_CLASS; j++) {
		LOG_INFO(" idx:%d, tc_tsa:%d, tc_tx_bw:%d, prio_tc:%d\n", j, ets.tc_tx_bw[j],
			 ets.tc_tsa[j], ets.prio_tc[j]);
	}

	err = zxdh_dcbnl_check_ets_para(&ets);
	if (err)
		return err;

	err = zxdh_dcbnl_ieee_set_ets_para(en_priv, &ets);
	if (err)
		return err;

	return 0;
}

static u8 zxdh_dcbnl_getstate(struct net_device *netdev)
{
	return ZXDH_DCBNL_CEE_STATE_UP;
}

static u8 zxdh_dcbnl_setstate(struct net_device *netdev, u8 state)
{
	return 0;
}
#endif

static const struct dcbnl_rtnl_ops zxdh_dcbnl_ops = {
	.ieee_getets = zxdh_dcbnl_ieee_getets,
	.ieee_setets = zxdh_dcbnl_ieee_setets,
	.ieee_getpfc = zxdh_dcbnl_ieee_getpfc,
	.ieee_setpfc = zxdh_dcbnl_ieee_setpfc,

	.ieee_getmaxrate = zxdh_dcbnl_ieee_getmaxrate,
	.ieee_setmaxrate = zxdh_dcbnl_ieee_setmaxrate,

	.ieee_setapp = zxdh_dcbnl_ieee_setapp,
	.ieee_delapp = zxdh_dcbnl_ieee_delapp,

#ifdef ZXDH_DCBNL_CEE_SUPPORT
	/* CEE not support */
	.setall = zxdh_dcbnl_setall,

	.getstate = zxdh_dcbnl_getstate,
	.setstate = zxdh_dcbnl_setstate,

	.setpgtccfgtx = zxdh_dcbnl_setpgtccfgtx,
	.setpgbwgcfgtx = zxdh_dcbnl_setpgbwgcfgtx,
	.getpgtccfgtx = zxdh_dcbnl_getpgtccfgtx,
	.getpgbwgcfgtx = zxdh_dcbnl_getpgbwgcfgtx,

	.setpgtccfgrx = zxdh_dcbnl_setpgtccfgrx,
	.setpgbwgcfgrx = zxdh_dcbnl_setpgbwgcfgrx,
	.getpgtccfgrx = zxdh_dcbnl_getpgtccfgrx,
	.getpgbwgcfgrx = zxdh_dcbnl_getpgbwgcfgrx,
#endif
};

u32 zxdh_dcbnl_set_tm_pport_mcode_gate_open(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	u32 err = 0;

	err = zxdh_dcbnl_set_tm_gate(en_priv, 1);

	if (err)
		LOG_ERR(" set_tm_gate close failed\n");
	LOG_INFO(" tm mcode gate open ");
	return err;
}
EXPORT_SYMBOL(zxdh_dcbnl_set_tm_pport_mcode_gate_open);

u32 zxdh_dcbnl_set_tm_pport_mcode_gate_close(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	u32 err = 0;

	err = zxdh_dcbnl_set_tm_gate(en_priv, 0);
	if (err)
		LOG_ERR(" set_tm_gate close failed\n");
	LOG_INFO(" tm mcode gate close ");
	return err;
}
EXPORT_SYMBOL(zxdh_dcbnl_set_tm_pport_mcode_gate_close);

u32 zxdh_dcbnl_initialize(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u32 err = 0;

	LOG_INFO("%s dcbnl init begin\n", netdev->name);

	err = zxdh_dcbnl_init_port_speed(en_priv);
	if (err) {
		LOG_INFO("dcbnl_init_ets: init_port_speed failed\n");
		//return err;
	}

	err = zxdh_dcbnl_init_ets_scheduling_tree(en_priv);
	if (err) {
		LOG_ERR("dcbnl_init_ets: init_ets_scheduling_tree failed\n");
		return err;
	}

	zxdh_dcbnl_printk_ets_tree(en_priv);

	en_dev->dcb_para.init_flag = ZXDH_DCBNL_INIT_FLAG;
	netdev->dcbnl_ops = &zxdh_dcbnl_ops;

	//zxdh_dcbnl_set_tm_pport_mcode_gate_open(netdev);
	LOG_INFO("%s dcbnl init ok ", netdev->name);
	return 0;
}

u32 zxdh_dcbnl_ets_uninit(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if ((en_dev->ops->get_coredev_type(en_dev->parent) != DH_COREDEV_PF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return 0;
	}
	LOG_INFO("%s dcbnl uninit begin\n", netdev->name);

	en_dev->dcb_para.init_flag = 0;
	netdev->dcbnl_ops = NULL;
	zxdh_dcbnl_set_tm_pport_mcode_gate_close(netdev);

	zxdh_dcbnl_free_flow_resources(en_priv);

	zxdh_dcbnl_free_se_resources(en_priv);

	LOG_INFO("%s dcbnl uninit ok ", netdev->name);
	return 0;
}
