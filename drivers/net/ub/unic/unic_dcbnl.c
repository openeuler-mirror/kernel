// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/dcbnl.h>
#include <ub/ubase/ubase_comm_qos.h>

#include "unic_hw.h"
#include "unic_netdev.h"
#include "unic_dcbnl.h"

#define UNIC_PRIO_VL_MAP_CHANGED	BIT(0)
#define UNIC_TC_TSA_CHANGED		BIT(1)
#define UNIC_TC_BW_CHANGED		BIT(2)

static int unic_ets_prio_tc_validate(struct unic_dev *unic_dev,
				     struct ieee_ets *ets, u8 *changed,
				     u8 *vl_num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	u32 max_queue = unic_channels_max_num(adev);
	u8 i, rss_vl_num, max_vl = 0;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (ets->prio_tc[i] != unic_dev->channels.vl.prio_vl[i])
			*changed |= UNIC_PRIO_VL_MAP_CHANGED;

		max_vl = max(max_vl, ets->prio_tc[i] + 1);
	}

	if (max_vl > caps->vl_num) {
		unic_err(unic_dev, "tc num(%u) can't exceed max tc(%u).\n",
			 max_vl, caps->vl_num);
		return -EINVAL;
	}

	rss_vl_num = unic_get_rss_vl_num(unic_dev, max_vl);
	if (rss_vl_num > max_queue) {
		unic_err(unic_dev,
			 "rss vl num(%hhu) can't exceed queue num(%u).\n",
			 rss_vl_num, max_queue);
		return -EINVAL;
	}

	*vl_num = max_vl;

	return 0;
}

static int unic_ets_tc_bw_validate(struct unic_dev *unic_dev,
				   struct ieee_ets *ets, u8 *changed)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	/* continuous bitmap configured by the dcb tool */
	u16 tc_bitmap = (1 << caps->vl_num) - 1;
	int ret;
	u8 i;

	ret = ubase_check_qos_sch_param(adev, tc_bitmap, ets->tc_tx_bw,
					ets->tc_tsa, false);
	if (ret)
		return ret;

	for (i = 0; i < caps->vl_num; i++) {
		if (vl->vl_tsa[i] != ets->tc_tsa[i])
			*changed |= UNIC_TC_TSA_CHANGED;

		if (vl->vl_bw[i] != ets->tc_tx_bw[i])
			*changed |= UNIC_TC_BW_CHANGED;
	}

	return 0;
}

static int unic_setets_params_validate(struct unic_dev *unic_dev,
				       struct ieee_ets *ets, u8 *changed,
				       u8 *vl_num)
{
	int ret;

	ret = unic_ets_prio_tc_validate(unic_dev, ets, changed, vl_num);
	if (ret)
		return ret;

	return unic_ets_tc_bw_validate(unic_dev, ets, changed);
}

static int unic_dcbnl_ieee_getets(struct net_device *ndev, struct ieee_ets *ets)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct unic_vl *vl = &unic_dev->channels.vl;

	if (unic_resetting(ndev))
		return -EBUSY;

	if (!unic_dev_ets_supported(unic_dev))
		return -EOPNOTSUPP;

	memset(ets, 0, sizeof(*ets));
	ets->willing = 1;
	ets->ets_cap = caps->vl_num;

	memcpy(ets->prio_tc, vl->prio_vl, sizeof(ets->prio_tc));
	memcpy(ets->tc_tx_bw, vl->vl_bw, sizeof(ets->tc_tx_bw));
	memcpy(ets->tc_tsa, vl->vl_tsa, sizeof(ets->tc_tsa));

	return 0;
}

static int unic_setets_preconditions(struct net_device *net_dev)
{
	struct unic_dev *unic_dev = netdev_priv(net_dev);

	if (!unic_dev_ets_supported(unic_dev))
		return -EOPNOTSUPP;

	if (netif_running(net_dev)) {
		unic_err(unic_dev,
			 "failed to set ets, due to network interface is up, please down it first and try again.\n");
		return -EBUSY;
	}

	if (!(unic_dev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	if (unic_resetting(net_dev))
		return -EBUSY;

	return 0;
}

static int unic_handle_prio_vl_change(struct unic_dev *unic_dev,
				      struct ieee_ets *ets, u8 changed)
{
	struct unic_vl *vl = &unic_dev->channels.vl;
	u8 map_type;
	int ret;

	if (!(changed & UNIC_PRIO_VL_MAP_CHANGED))
		return 0;

	map_type = vl->dscp_app_cnt ? UNIC_DSCP_VL_MAP : UNIC_PRIO_VL_MAP;
	ret = unic_set_vl_map(unic_dev, vl->dscp_prio, ets->prio_tc,
			      map_type);
	if (ret)
		return ret;

	memcpy(vl->prio_vl, ets->prio_tc, sizeof(ets->prio_tc));

	return 0;
}

static inline void unic_convert_vl_sch_bw(struct ubase_caps *caps, u8 *vl_bw,
					  struct ieee_ets *ets)
{
	u8 i;

	for (i = 0; i < caps->vl_num; i++) {
		vl_bw[caps->req_vl[i]] = ets->tc_tx_bw[i];
		vl_bw[caps->resp_vl[i]] = ets->tc_tx_bw[i];
	}
}

static int unic_handle_tm_vl_sch_change(struct unic_dev *unic_dev,
					struct ubase_caps *caps,
					struct ieee_ets *ets)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_vl *vl = &unic_dev->channels.vl;
	u8 vl_tsa[UBASE_MAX_VL_NUM] = {0};
	u8 vl_bw[UBASE_MAX_VL_NUM] = {0};
	u32 i;

	unic_convert_vl_sch_bw(caps, vl_bw, ets);

	for (i = 0; i < caps->vl_num; i++) {
		if (ets->tc_tsa[i]) {
			vl_tsa[caps->req_vl[i]] = ets->tc_tsa[i];
			vl_tsa[caps->resp_vl[i]] = ets->tc_tsa[i];
		}
	}

	return ubase_config_tm_vl_sch(adev, vl->vl_bitmap, vl_bw, vl_tsa);
}

static int unic_handle_vl_tsa_bw_change(struct unic_dev *unic_dev,
					struct ieee_ets *ets, u8 changed)
{
	u8 *vl_tsa = unic_dev->channels.vl.vl_tsa;
	u8 *vl_bw = unic_dev->channels.vl.vl_bw;
	int ret;

	struct ubase_caps *caps = ubase_get_dev_caps(unic_dev->comdev.adev);

	if (!(changed & UNIC_TC_TSA_CHANGED || changed & UNIC_TC_BW_CHANGED))
		return 0;

	ret = unic_handle_tm_vl_sch_change(unic_dev, caps, ets);
	if (ret)
		return ret;

	memcpy(vl_tsa, ets->tc_tsa, sizeof(ets->tc_tsa));
	memcpy(vl_bw, ets->tc_tx_bw, sizeof(ets->tc_tx_bw));

	return 0;
}

static int unic_setets_config(struct net_device *ndev, struct ieee_ets *ets,
			      u8 changed, u8 vl_num)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	int ret;

	ret = unic_handle_prio_vl_change(unic_dev, ets, changed);
	if (ret)
		return ret;

	ret = unic_handle_vl_tsa_bw_change(unic_dev, ets, changed);
	if (ret)
		return ret;

	unic_dev->channels.vl.vl_num = vl_num;
	if (unic_rss_vl_num_changed(unic_dev, vl_num))
		return unic_update_channels(unic_dev, vl_num);

	return 0;
}

static int unic_dcbnl_ieee_setets(struct net_device *ndev, struct ieee_ets *ets)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	u8 changed = 0;
	u8 vl_num = 0;
	int ret;

	ret = unic_setets_preconditions(ndev);
	if (ret)
		return ret;

	ret = unic_setets_params_validate(unic_dev, ets, &changed, &vl_num);
	if (ret)
		return ret;

	if (!changed)
		return 0;

	return unic_setets_config(ndev, ets, changed, vl_num);
}

static int unic_check_pfc_preconditions(struct net_device *net_dev)
{
	struct unic_dev *unic_dev = netdev_priv(net_dev);

	if (!unic_dev_pfc_supported(unic_dev))
		return -EOPNOTSUPP;

	if (unic_resetting(net_dev))
		return -EBUSY;

	if (!(unic_dev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	return 0;
}

static int unic_pfc_down(struct unic_dev *unic_dev, struct ieee_pfc *pfc)
{
	struct unic_pfc_info *pfc_info = &unic_dev->channels.vl.pfc_info;
	u8 tx_pause, rx_pause;
	int ret;

	ret = unic_pfc_pause_cfg(unic_dev, pfc->pfc_en);
	if (ret)
		return ret;

	pfc_info->fc_mode &= ~(UNIC_FC_PFC_EN);
	pfc_info->pfc_en = pfc->pfc_en;

	tx_pause = pfc_info->fc_mode & UNIC_TX_PAUSE_EN ? 1 : 0;
	rx_pause = pfc_info->fc_mode & UNIC_RX_PAUSE_EN ? 1 : 0;

	return unic_mac_pause_en_cfg(unic_dev, tx_pause, rx_pause);
}

static int unic_dcbnl_ieee_getpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct ubase_eth_mac_stats eth_stats = {0};
	int i, ret;

	ret = unic_check_pfc_preconditions(ndev);
	if (ret)
		return ret;

	ret = ubase_get_eth_port_stats(unic_dev->comdev.adev, &eth_stats);
	if (ret)
		return ret;

	memset(pfc, 0, sizeof(*pfc));
	pfc->pfc_en = unic_dev->channels.vl.pfc_info.pfc_en;
	pfc->pfc_cap = UNIC_MAX_PRIO_NUM;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		pfc->requests[i] = unic_get_pfc_tx_pkts(&eth_stats, i);
		pfc->indications[i] = unic_get_pfc_rx_pkts(&eth_stats, i);
	}

	return 0;
}

static int unic_dcbnl_ieee_setpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_pfc_info *pfc_info;
	int ret;

	pfc_info = &unic_dev->channels.vl.pfc_info;

	ret = unic_check_pfc_preconditions(ndev);
	if (ret)
		return ret;

	if (pfc->pfc_en == pfc_info->pfc_en)
		return 0;

	if (!pfc->pfc_en)
		return unic_pfc_down(unic_dev, pfc);

	if (!(pfc_info->fc_mode & UNIC_FC_PFC_EN)) {
		ret = unic_mac_pause_en_cfg(unic_dev, false, false);
		if (ret) {
			unic_err(unic_dev, "failed to disable pause, ret = %d.\n",
				 ret);
			return ret;
		}
	}

	ret = unic_pfc_pause_cfg(unic_dev, pfc->pfc_en);
	if (ret) {
		unic_err(unic_dev,
			 "failed to set pfc tx rx enable or priority, ret = %d.\n",
			 ret);
		return ret;
	}

	pfc_info->fc_mode |= UNIC_FC_PFC_EN;
	pfc_info->pfc_en = pfc->pfc_en;

	return ret;
}

static int unic_dscp_prio_check(struct net_device *netdev, struct dcb_app *app)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	if (!unic_dev_ets_supported(unic_dev))
		return -EOPNOTSUPP;

	if (netif_running(netdev)) {
		unic_err(unic_dev,
			 "failed to set dscp-prio, due to network interface is up, please down it first and try again.\n");
		return -EBUSY;
	}

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= UBASE_MAX_DSCP ||
	    app->priority >= UNIC_MAX_PRIO_NUM)
		return -EINVAL;

	if (unic_resetting(netdev))
		return -EBUSY;

	return 0;
}

static int unic_set_app(struct net_device *netdev, struct dcb_app *app,
			struct unic_dev *unic_dev, struct unic_vl *vl)
{
	struct dcb_app old_app;
	int ret;

	unic_info(unic_dev, "setapp dscp = %u, priority = %u.\n",
		  app->protocol, app->priority);

	ret = dcb_ieee_setapp(netdev, app);
	if (ret) {
		unic_err(unic_dev, "failed to add app, ret = %d.\n", ret);
		return ret;
	}

	old_app.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	old_app.protocol = app->protocol;
	old_app.priority = vl->dscp_prio[app->protocol];

	vl->dscp_prio[app->protocol] = app->priority;
	ret = unic_set_vl_map(unic_dev, vl->dscp_prio, vl->prio_vl,
			      UNIC_DSCP_VL_MAP);
	if (ret) {
		vl->dscp_prio[app->protocol] = old_app.priority;
		dcb_ieee_delapp(netdev, app);
		return ret;
	}

	if (old_app.priority == UNIC_INVALID_PRIORITY) {
		vl->dscp_app_cnt++;
	} else {
		ret = dcb_ieee_delapp(netdev, &old_app);
		if (ret)
			unic_err(unic_dev,
				 "failed to delete old app, ret = %d.\n", ret);
	}

	return ret;
}

static int unic_dcbnl_ieee_setapp(struct net_device *netdev,
				  struct dcb_app *app)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	int ret;

	ret = unic_dscp_prio_check(netdev, app);
	if (ret) {
		unic_err(unic_dev, "failed to set dscp-prio, ret = %d\n", ret);
		return ret;
	}

	/* dscp-prio already set */
	if (vl->dscp_prio[app->protocol] == app->priority)
		return 0;

	return unic_set_app(netdev, app, unic_dev, vl);
}

static int unic_del_app(struct net_device *netdev, struct dcb_app *app,
			struct unic_dev *unic_dev, struct unic_vl *vl)
{
	u8 map_type = UNIC_DSCP_VL_MAP;
	int ret;

	unic_info(unic_dev, "delapp dscp = %u, priority = %u\n",
		  app->protocol, app->priority);

	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		return ret;

	if (vl->dscp_app_cnt <= 1)
		map_type = UNIC_PRIO_VL_MAP;

	vl->dscp_prio[app->protocol] = UNIC_INVALID_PRIORITY;
	ret = unic_set_vl_map(unic_dev, vl->dscp_prio, vl->prio_vl,
			      map_type);
	if (ret) {
		vl->dscp_prio[app->protocol] = app->priority;
		dcb_ieee_setapp(netdev, app);
		return ret;
	}

	if (vl->dscp_app_cnt)
		vl->dscp_app_cnt--;

	return 0;
}

static int unic_dcbnl_ieee_delapp(struct net_device *netdev,
				  struct dcb_app *app)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	int ret;

	ret = unic_dscp_prio_check(netdev, app);
	if (ret) {
		unic_err(unic_dev, "failed to del dscp-prio, ret = %d.\n", ret);
		return ret;
	}

	if (app->priority != vl->dscp_prio[app->protocol]) {
		unic_err(unic_dev, "failed to del no match dscp-prio.\n");
		return -EINVAL;
	}

	return unic_del_app(netdev, app, unic_dev, vl);
}

static u8 unic_dcbnl_getdcbx(struct net_device *ndev)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	return unic_dev->dcbx_cap;
}

static u8 unic_dcbnl_setdcbx(struct net_device *ndev, u8 mode)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    (mode & DCB_CAP_DCBX_VER_CEE) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return 1;

	unic_info(unic_dev, "set dcbx mode = %u\n.", mode);

	unic_dev->dcbx_cap = mode;

	return 0;
}

static int unic_ieee_getmaxrate(struct net_device *ndev,
				struct ieee_maxrate *maxrate)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (!unic_dev_ets_supported(unic_dev) ||
	    !unic_dev_tc_speed_limit_supported(unic_dev))
		return -EOPNOTSUPP;

	memcpy(maxrate->tc_maxrate, unic_dev->channels.vl.vl_maxrate,
	       sizeof(maxrate->tc_maxrate));
	return 0;
}

static int unic_check_maxrate(struct unic_dev *unic_dev,
			      struct ieee_maxrate *maxrate)
{
	u32 max_speed = max(unic_dev->channels.vl.maxrate,
			    unic_dev->hw.mac.max_speed);
	int i;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (!maxrate->tc_maxrate[i])
			continue;

		if (maxrate->tc_maxrate[i] / UNIC_MBYTE_PER_SEND > max_speed ||
		    maxrate->tc_maxrate[i] < UNIC_MBYTE_PER_SEND) {
			unic_err(unic_dev,
				 "invalid max_rate(%llubit), the range is [1Mbit, %uMbit].\n",
				 maxrate->tc_maxrate[i] * BITS_PER_BYTE,
				 max_speed);
			return -EINVAL;
		}
	}

	return 0;
}

static int unic_ieee_setmaxrate(struct net_device *ndev,
				struct ieee_maxrate *maxrate)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	u64 tc_maxrate[IEEE_8021QAZ_MAX_TCS];
	int ret;

	if (!unic_dev_ets_supported(unic_dev) ||
	    !unic_dev_tc_speed_limit_supported(unic_dev))
		return -EOPNOTSUPP;

	if (!(unic_dev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	ret = unic_check_maxrate(unic_dev, maxrate);
	if (ret)
		return ret;

	memcpy(tc_maxrate, maxrate->tc_maxrate, sizeof(maxrate->tc_maxrate));
	ret = unic_config_vl_rate_limit(unic_dev, tc_maxrate, vl->vl_bitmap);
	if (ret)
		return ret;

	memcpy(vl->vl_maxrate, tc_maxrate, sizeof(tc_maxrate));

	return 0;
}

static const struct dcbnl_rtnl_ops unic_dcbnl_ops = {
	.ieee_getets = unic_dcbnl_ieee_getets,
	.ieee_setets = unic_dcbnl_ieee_setets,
	.ieee_getmaxrate = unic_ieee_getmaxrate,
	.ieee_setmaxrate = unic_ieee_setmaxrate,
	.ieee_getpfc = unic_dcbnl_ieee_getpfc,
	.ieee_setpfc = unic_dcbnl_ieee_setpfc,
	.ieee_setapp = unic_dcbnl_ieee_setapp,
	.ieee_delapp = unic_dcbnl_ieee_delapp,
	.getdcbx     = unic_dcbnl_getdcbx,
	.setdcbx     = unic_dcbnl_setdcbx,
};

void unic_set_dcbnl_ops(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	if (!unic_dev_ets_supported(unic_dev) &&
	    !unic_dev_pfc_supported(unic_dev))
		return;

	netdev->dcbnl_ops = &unic_dcbnl_ops;

	unic_dev->dcbx_cap = DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_HOST;
}
