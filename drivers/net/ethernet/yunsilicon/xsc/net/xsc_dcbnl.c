// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/device.h>
#include <linux/netdevice.h>
#include <net/pkt_cls.h>
#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "xsc_eth.h"
#include "xsc_eth_debug.h"

#define XSC_100MB (100000)
#define XSC_1GB   (1000000)

#define XSC_CEE_STATE_UP    1
#define XSC_CEE_STATE_DOWN  0

/* Max supported cable length is 1000 meters */
#define XSC_MAX_CABLE_LENGTH 1000

enum {
	XSC_VENDOR_TC_GROUP_NUM = 7,
	XSC_LOWEST_PRIO_GROUP   = 0,
};

#define XSC_DCBX_STUB	1

#ifdef CONFIG_XSC_CORE_EN_DCB
static int xsc_set_trust_state(struct xsc_adapter *priv, u8 trust_state);
static int xsc_set_dscp2prio(struct xsc_adapter *priv, u8 dscp, u8 prio);

static int xsc_max_tc(struct xsc_core_device *dev)
{
	u8 num_tc = dev->caps.max_tc ? : 8;

	return num_tc - 1;
}

static int xsc_dcbnl_set_dcbx_mode(struct xsc_adapter *priv,
				   enum xsc_dcbx_oper_mode mode)
{
	return 1;
}

static int xsc_dcbnl_switch_to_host_mode(struct xsc_adapter *priv)
{
	struct xsc_dcbx *dcbx = &priv->dcbx;

	dcbx->mode = XSC_DCBX_PARAM_VER_OPER_HOST;
	return 0;
}

static int xsc_dcbnl_ieee_getets(struct net_device *netdev,
				 struct ieee_ets *ets)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	u8 tc_group[IEEE_8021QAZ_MAX_TCS];
	bool is_tc_group_6_exist = false;
	bool is_zero_bw_ets_tc = false;
	int err = 0;
	int i;

	if (!xdev->caps.ets)
		return -EOPNOTSUPP;

	ets->ets_cap = xsc_max_tc(priv->xdev) + 1;
	for (i = 0; i < ets->ets_cap; i++) {
#ifndef XSC_DCBX_STUB
		err = xsc_query_port_prio_tc(xdev, i, &ets->prio_tc[i]);
		if (err)
			return err;

		err = xsc_query_port_tc_group(xdev, i, &tc_group[i]);
		if (err)
			return err;

		err = xsc_query_port_tc_bw_alloc(xdev, i, &ets->tc_tx_bw[i]);
		if (err)
			return err;
#else
		ets->prio_tc[i] = i;
		tc_group[i] = XSC_VENDOR_TC_GROUP_NUM;
		ets->tc_tx_bw[i] = XSC_MAX_BW_ALLOC;
#endif
		if (ets->tc_tx_bw[i] < XSC_MAX_BW_ALLOC &&
		    tc_group[i] == (XSC_LOWEST_PRIO_GROUP + 1))
			is_zero_bw_ets_tc = true;

		if (tc_group[i] == (XSC_VENDOR_TC_GROUP_NUM - 1))
			is_tc_group_6_exist = true;
	}

	/* Report 0% ets tc if exits*/
	if (is_zero_bw_ets_tc) {
		for (i = 0; i < ets->ets_cap; i++)
			if (tc_group[i] == XSC_LOWEST_PRIO_GROUP)
				ets->tc_tx_bw[i] = 0;
	}

	/* Update tc_tsa based on fw setting*/
	for (i = 0; i < ets->ets_cap; i++) {
		if (ets->tc_tx_bw[i] < XSC_MAX_BW_ALLOC)
			priv->dcbx.tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
		else if (tc_group[i] == XSC_VENDOR_TC_GROUP_NUM &&
			 !is_tc_group_6_exist)
			priv->dcbx.tc_tsa[i] = IEEE_8021QAZ_TSA_VENDOR;
		xsc_eth_dbg(HW, priv, "%s: tc%d, group=%d, bw=%d\n",
			    __func__, i, tc_group[i], ets->tc_tx_bw[i]);
	}
	memcpy(ets->tc_tsa, priv->dcbx.tc_tsa, sizeof(ets->tc_tsa));

	return err;
}

static void xsc_build_tc_group(struct ieee_ets *ets, u8 *tc_group, int max_tc)
{
	bool any_tc_mapped_to_ets = false;
	bool ets_zero_bw = false;
	int strict_group;
	int i;

	for (i = 0; i <= max_tc; i++) {
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS) {
			any_tc_mapped_to_ets = true;
			if (!ets->tc_tx_bw[i])
				ets_zero_bw = true;
		}
	}

	/* strict group has higher priority than ets group */
	strict_group = XSC_LOWEST_PRIO_GROUP;
	if (any_tc_mapped_to_ets)
		strict_group++;
	if (ets_zero_bw)
		strict_group++;

	for (i = 0; i <= max_tc; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_VENDOR:
			tc_group[i] = XSC_VENDOR_TC_GROUP_NUM;
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			tc_group[i] = strict_group++;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			tc_group[i] = XSC_LOWEST_PRIO_GROUP;
			if (ets->tc_tx_bw[i] && ets_zero_bw)
				tc_group[i] = XSC_LOWEST_PRIO_GROUP + 1;
			break;
		}
	}
}

static void xsc_build_tc_tx_bw(struct ieee_ets *ets, u8 *tc_tx_bw,
			       u8 *tc_group, int max_tc)
{
	int bw_for_ets_zero_bw_tc = 0;
	int last_ets_zero_bw_tc = -1;
	int num_ets_zero_bw = 0;
	int i;

	for (i = 0; i <= max_tc; i++) {
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS &&
		    !ets->tc_tx_bw[i]) {
			num_ets_zero_bw++;
			last_ets_zero_bw_tc = i;
		}
	}

	if (num_ets_zero_bw)
		bw_for_ets_zero_bw_tc = XSC_MAX_BW_ALLOC / num_ets_zero_bw;

	for (i = 0; i <= max_tc; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_VENDOR:
			tc_tx_bw[i] = XSC_MAX_BW_ALLOC;
			break;
		case IEEE_8021QAZ_TSA_STRICT:
			tc_tx_bw[i] = XSC_MAX_BW_ALLOC;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			tc_tx_bw[i] = ets->tc_tx_bw[i] ?
				      ets->tc_tx_bw[i] :
				      bw_for_ets_zero_bw_tc;
			break;
		}
	}

	/* Make sure the total bw for ets zero bw group is 100% */
	if (last_ets_zero_bw_tc != -1)
		tc_tx_bw[last_ets_zero_bw_tc] +=
			XSC_MAX_BW_ALLOC % num_ets_zero_bw;
}

/* If there are ETS BW 0,
 *   Set ETS group # to 1 for all ETS non zero BW tcs. Their sum must be 100%.
 *   Set group #0 to all the ETS BW 0 tcs and
 *     equally splits the 100% BW between them
 *   Report both group #0 and #1 as ETS type.
 *     All the tcs in group #0 will be reported with 0% BW.
 */
int xsc_dcbnl_ieee_setets_core(struct xsc_adapter *priv, struct ieee_ets *ets)
{
	struct xsc_core_device *xdev = priv->xdev;
	u8 tc_tx_bw[IEEE_8021QAZ_MAX_TCS];
	u8 tc_group[IEEE_8021QAZ_MAX_TCS];
	int max_tc = xsc_max_tc(xdev);
	int err = 0;

	memset(tc_tx_bw, 0, IEEE_8021QAZ_MAX_TCS);
	memset(tc_group, 0, IEEE_8021QAZ_MAX_TCS);
	xsc_build_tc_group(ets, tc_group, max_tc);
	xsc_build_tc_tx_bw(ets, tc_tx_bw, tc_group, max_tc);
#ifndef XSC_DCBX_STUB
	err = xsc_set_port_prio_tc(xdev, ets->prio_tc);
	if (err)
		return err;

	err = xsc_set_port_tc_group(xdev, tc_group);
	if (err)
		return err;

	err = xsc_set_port_tc_bw_alloc(xdev, tc_tx_bw);

	if (err)
		return err;
#endif
	memcpy(priv->dcbx.tc_tsa, ets->tc_tsa, sizeof(ets->tc_tsa));

	return err;
}

static int xsc_dbcnl_validate_ets(struct net_device *netdev,
				  struct ieee_ets *ets,
				  bool zero_sum_allowed)
{
	bool have_ets_tc = false;
	int bw_sum = 0;
	int i;

	/* Validate Priority */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (ets->prio_tc[i] >= XSC_MAX_PRIORITY) {
			netdev_err(netdev,
				   "Failed to validate ETS: priority value greater than max(%d)\n",
				    XSC_MAX_PRIORITY);
			return -EINVAL;
		}
	}

	/* Validate Bandwidth Sum */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_ETS) {
			have_ets_tc = true;
			bw_sum += ets->tc_tx_bw[i];
		}
	}

	if (have_ets_tc && bw_sum != 100) {
		if (bw_sum || (!bw_sum && !zero_sum_allowed))
			netdev_err(netdev,
				   "Failed to validate ETS: BW sum is illegal\n");
		return -EINVAL;
	}
	return 0;
}

static int xsc_dcbnl_ieee_setets(struct net_device *dev,
				 struct ieee_ets *ets)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	int err;

	if (!priv->xdev->caps.ets)
		return -EOPNOTSUPP;

	err = xsc_dbcnl_validate_ets(dev, ets, false);
	if (err)
		return err;

	err = xsc_dcbnl_ieee_setets_core(priv, ets);
	if (err)
		return err;

	return 0;
}

static int xsc_dcbnl_ieee_getpfc(struct net_device *dev,
				 struct ieee_pfc *pfc)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;
	int i;

	pfc->pfc_cap = xsc_max_tc(xdev) + 1;
#ifndef XSC_DCBX_STUB
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		pfc->requests[i]    = PPORT_PER_PRIO_GET(pstats, i, tx_pause);
		pfc->indications[i] = PPORT_PER_PRIO_GET(pstats, i, rx_pause);
	}

	if (xdev->caps.port_buf)
		pfc->delay = priv->dcbx.cable_len;
	return xsc_query_port_pfc(xdev, &pfc->pfc_en, NULL);
#else
	pfc->pfc_en = 0;

	for (i = 0; i < pfc->pfc_cap; i++)
		pfc->pfc_en |= 1 << i;

	xsc_eth_dbg(HW, priv, "%s: pfc_en=0x%x\n", __func__, pfc->pfc_en);

	return 0;
#endif
}

static int xsc_dcbnl_ieee_setpfc(struct net_device *dev,
				 struct ieee_pfc *pfc)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	u32 changed = 0;
	u8 curr_pfc_en;
	int ret = 0;
#ifndef XSC_DCBX_STUB
	struct xsc_core_device *xdev = priv->xdev;
	u32 old_cable_len = priv->dcbx.cable_len;
	struct ieee_pfc pfc_new;
#else
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;
	int i;
#endif

	/* pfc_en */
#ifndef XSC_DCBX_STUB
	xsc_query_port_pfc(xdev, &curr_pfc_en, NULL);
	if (pfc->pfc_en != curr_pfc_en) {
		ret = xsc_set_port_pfc(xdev, pfc->pfc_en, pfc->pfc_en);
		if (ret)
			return ret;
		xsc_toggle_port_link(xdev);
		changed |= XSC_PORT_BUFFER_PFC;
	}
#else
	for (i = 0; i < CEE_DCBX_MAX_PRIO; i++)
		curr_pfc_en |= cee_cfg->pfc_setting[i] << i;

	if (pfc->pfc_en != curr_pfc_en) {
		changed |= XSC_PORT_BUFFER_PFC;
		for (i = 0; i < CEE_DCBX_MAX_PRIO; i++) {
			if (pfc->pfc_en & (1 << i))
				cee_cfg->pfc_setting[i] = 1;
			else
				cee_cfg->pfc_setting[i] = 0;
		}
	}
#endif
	xsc_eth_dbg(HW, priv, "%s: new_pfc_en=0x%x, cur_pfc_en=0x%x\n",
		    __func__, pfc->pfc_en, curr_pfc_en);

	if (pfc->delay &&
	    pfc->delay < XSC_MAX_CABLE_LENGTH &&
	    pfc->delay != priv->dcbx.cable_len) {
		priv->dcbx.cable_len = pfc->delay;
		changed |= XSC_PORT_BUFFER_CABLE_LEN;
	}

#ifndef XSC_DCBX_STUB
	if (xdev->caps.port_buf) {
		pfc_new.pfc_en = (changed & XSC_PORT_BUFFER_PFC) ?
				  pfc->pfc_en : curr_pfc_en;
		if (priv->dcbx.manual_buffer)
			ret = xsc_port_manual_buffer_config(priv, changed,
							    dev->mtu, &pfc_new,
							    NULL, NULL);
		if (ret && (changed & XSC_PORT_BUFFER_CABLE_LEN))
			priv->dcbx.cable_len = old_cable_len;
	}
#endif

	if (!ret)
		xsc_eth_dbg(HW, priv,
			    "%s: PFC per priority bit mask: 0x%x\n",
			    __func__, pfc->pfc_en);

	return ret;
}

static u8 xsc_dcbnl_getdcbx(struct net_device *dev)
{
	struct xsc_adapter *priv = netdev_priv(dev);

	xsc_eth_dbg(HW, priv, "%s: dcbx->cap=0x%x\n", __func__, priv->dcbx.cap);
	return priv->dcbx.cap;
}

static u8 xsc_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_dcbx *dcbx = &priv->dcbx;

	xsc_eth_dbg(HW, priv, "%s: mode=%d\n", __func__, mode);
	if (mode & DCB_CAP_DCBX_LLD_MANAGED)
		return 1;

	if (!mode && priv->xdev->caps.dcbx) {
		if (dcbx->mode == XSC_DCBX_PARAM_VER_OPER_AUTO)
			return 0;

		/* set dcbx to fw controlled */
		if (!xsc_dcbnl_set_dcbx_mode(priv, XSC_DCBX_PARAM_VER_OPER_AUTO)) {
			dcbx->mode = XSC_DCBX_PARAM_VER_OPER_AUTO;
			dcbx->cap &= ~DCB_CAP_DCBX_HOST;
			return 0;
		}

		return 1;
	}

	if (!(mode & DCB_CAP_DCBX_HOST))
		return 1;

	if (xsc_dcbnl_switch_to_host_mode(netdev_priv(dev)))
		return 1;

	dcbx->cap = mode;

	return 0;
}

static int xsc_dcbnl_ieee_setapp(struct net_device *dev, struct dcb_app *app)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct dcb_app temp;
	bool is_new;
	int err;

	if (!priv->xdev->caps.dscp)
		return -EOPNOTSUPP;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP || app->protocol >= XSC_MAX_DSCP)
		return -EINVAL;

	/* Save the old entry info */
	temp.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	temp.protocol = app->protocol;
	temp.priority = priv->dcbx_dp.dscp2prio[app->protocol];

	/* Check if need to switch to dscp trust state */
	if (!priv->dcbx.dscp_app_cnt) {
		err =  xsc_set_trust_state(priv, XSC_QPTS_TRUST_DSCP);
		if (err)
			return err;
	}

	/* Skip the fw command if new and old mapping are the same */
	if (app->priority != priv->dcbx_dp.dscp2prio[app->protocol]) {
		err = xsc_set_dscp2prio(priv, app->protocol, app->priority);
		if (err)
			goto fw_err;
	}

	/* Delete the old entry if exists */
	is_new = false;
	err = dcb_ieee_delapp(dev, &temp);
	if (err)
		is_new = true;

	/* Add new entry and update counter */
	err = dcb_ieee_setapp(dev, app);
	if (err)
		return err;

	if (is_new)
		priv->dcbx.dscp_app_cnt++;

	return err;

fw_err:
	xsc_set_trust_state(priv, XSC_QPTS_TRUST_PCP);
	return err;
}

static int xsc_dcbnl_ieee_delapp(struct net_device *dev, struct dcb_app *app)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	int err;

	if  (!priv->xdev->caps.dscp)
		return -EOPNOTSUPP;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP || app->protocol >= XSC_MAX_DSCP)
		return -EINVAL;

	/* Skip if no dscp app entry */
	if (!priv->dcbx.dscp_app_cnt)
		return -ENOENT;

	/* Check if the entry matches fw setting */
	if (app->priority != priv->dcbx_dp.dscp2prio[app->protocol])
		return -ENOENT;

	/* Delete the app entry */
	err = dcb_ieee_delapp(dev, app);
	if (err)
		return err;

	/* Reset the priority mapping back to zero */
	err = xsc_set_dscp2prio(priv, app->protocol, 0);
	if (err)
		goto fw_err;

	priv->dcbx.dscp_app_cnt--;

	/* Check if need to switch to pcp trust state */
	if (!priv->dcbx.dscp_app_cnt)
		err = xsc_set_trust_state(priv, XSC_QPTS_TRUST_PCP);

	return err;

fw_err:
	xsc_set_trust_state(priv, XSC_QPTS_TRUST_PCP);
	return err;
}

static int xsc_dcbnl_ieee_getmaxrate(struct net_device *netdev,
				     struct ieee_maxrate *maxrate)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	u8 max_bw_value[IEEE_8021QAZ_MAX_TCS];
	u8 max_bw_unit[IEEE_8021QAZ_MAX_TCS];
	int i;
#ifndef XSC_DCBX_STUB
	int err;

	err = xsc_query_port_ets_rate_limit(xdev, max_bw_value, max_bw_unit);
	if (err)
		return err;
#else
	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		max_bw_unit[i] = XSC_GBPS_UNIT;
		max_bw_value[i] = 25;
	}
#endif

	memset(maxrate->tc_maxrate, 0, sizeof(maxrate->tc_maxrate));

	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		switch (max_bw_unit[i]) {
		case XSC_100_MBPS_UNIT:
			maxrate->tc_maxrate[i] = max_bw_value[i] * XSC_100MB;
			break;
		case XSC_GBPS_UNIT:
			maxrate->tc_maxrate[i] = max_bw_value[i] * XSC_1GB;
			break;
		case XSC_BW_NO_LIMIT:
			break;
		default:
			WARN(true, "non-supported BW unit");
			break;
		}
	}
	return 0;
}

static int xsc_dcbnl_ieee_setmaxrate(struct net_device *netdev,
				     struct ieee_maxrate *maxrate)
{
	struct xsc_adapter *priv    = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	u8 max_bw_value[IEEE_8021QAZ_MAX_TCS];
	u8 max_bw_unit[IEEE_8021QAZ_MAX_TCS];
	__u64 upper_limit_mbps = roundup(255 * XSC_100MB, XSC_1GB);
	int i;

	memset(max_bw_value, 0, sizeof(max_bw_value));
	memset(max_bw_unit, 0, sizeof(max_bw_unit));

	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		if (!maxrate->tc_maxrate[i]) {
			max_bw_unit[i]  = XSC_BW_NO_LIMIT;
			continue;
		}
		if (maxrate->tc_maxrate[i] < upper_limit_mbps) {
			max_bw_value[i] = div_u64(maxrate->tc_maxrate[i],
						  XSC_100MB);
			max_bw_value[i] = max_bw_value[i] ? max_bw_value[i] : 1;
			max_bw_unit[i]  = XSC_100_MBPS_UNIT;
		} else {
			max_bw_value[i] = div_u64(maxrate->tc_maxrate[i],
						  XSC_1GB);
			max_bw_unit[i]  = XSC_GBPS_UNIT;
		}
	}

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		netdev_dbg(netdev, "%s: tc_%d <=> max_bw %d Gbps\n",
			   __func__, i, max_bw_value[i]);
#ifndef XSC_DCBX_STUB
	return xsc_modify_port_ets_rate_limit(xdev, max_bw_value, max_bw_unit);
#else
	return 0;
#endif
}

static u8 xsc_dcbnl_setall(struct net_device *netdev)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;
	struct xsc_core_device *xdev = priv->xdev;
	struct ieee_ets ets;
	struct ieee_pfc pfc;
	int err = -EOPNOTSUPP;
	int i;

	if (!xdev->caps.ets)
		goto out;

	memset(&ets, 0, sizeof(ets));
	memset(&pfc, 0, sizeof(pfc));

	ets.ets_cap = IEEE_8021QAZ_MAX_TCS;
	for (i = 0; i < CEE_DCBX_MAX_PGS; i++) {
		ets.tc_tx_bw[i] = cee_cfg->pg_bw_pct[i];
		ets.tc_rx_bw[i] = cee_cfg->pg_bw_pct[i];
		ets.tc_tsa[i]   = IEEE_8021QAZ_TSA_ETS;
		ets.prio_tc[i]  = cee_cfg->prio_to_pg_map[i];
	}

#ifndef XSC_DCBX_STUB
	err = xsc_dbcnl_validate_ets(netdev, &ets, true);
	if (err)
		goto out;
#endif

	err = xsc_dcbnl_ieee_setets_core(priv, &ets);
	if (err) {
		netdev_err(netdev,
			   "%s, Failed to set ETS: %d\n", __func__, err);
		goto out;
	}

	/* Set PFC */
	pfc.pfc_cap = xsc_max_tc(xdev) + 1;
	if (!cee_cfg->pfc_enable)
		pfc.pfc_en = 0;
	else
		for (i = 0; i < CEE_DCBX_MAX_PRIO; i++)
			pfc.pfc_en |= cee_cfg->pfc_setting[i] << i;

	err = xsc_dcbnl_ieee_setpfc(netdev, &pfc);
	if (err) {
		netdev_err(netdev,
			   "%s, Failed to set PFC: %d\n", __func__, err);
		goto out;
	}
out:
	return err ? XSC_DCB_NO_CHG : XSC_DCB_CHG_RESET;
}

static u8 xsc_dcbnl_getstate(struct net_device *netdev)
{
	return XSC_CEE_STATE_UP;
}

static void xsc_dcbnl_getpermhwaddr(struct net_device *netdev,
				    u8 *perm_addr)
{
#ifndef XSC_DCBX_STUB
	struct xsc_adapter *priv = netdev_priv(netdev);
#endif

	if (!perm_addr)
		return;

	memset(perm_addr, 0xff, MAX_ADDR_LEN);
#ifndef XSC_DCBX_STUB
	xsc_query_nic_vport_mac_address(priv->xdev, 0, perm_addr);
#endif
}

static void xsc_dcbnl_setpgtccfgtx(struct net_device *netdev,
				   int priority, u8 prio_type,
				   u8 pgid, u8 bw_pct, u8 up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	xsc_eth_dbg(HW, priv, "%s: prio=%d, type=%d, pgid=%d, bw_pct=%d, up_map=%d\n",
		    __func__, priority, prio_type, pgid,
		    bw_pct, up_map);
	if (priority >= CEE_DCBX_MAX_PRIO) {
		netdev_err(netdev,
			   "%s, priority is out of range\n", __func__);
		return;
	}

	if (pgid >= CEE_DCBX_MAX_PGS) {
		netdev_err(netdev,
			   "%s, priority group is out of range\n", __func__);
		return;
	}

	cee_cfg->prio_to_pg_map[priority] = pgid;
}

static void xsc_dcbnl_setpgbwgcfgtx(struct net_device *netdev,
				    int pgid, u8 bw_pct)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	xsc_eth_dbg(HW, priv, "%s: pgid=%d, bw_pct=%d\n",
		    __func__, pgid, bw_pct);
	if (pgid >= CEE_DCBX_MAX_PGS) {
		netdev_err(netdev,
			   "%s, priority group is out of range\n", __func__);
		return;
	}

	cee_cfg->pg_bw_pct[pgid] = bw_pct;
}

static void xsc_dcbnl_getpgtccfgtx(struct net_device *netdev,
				   int priority, u8 *prio_type,
				   u8 *pgid, u8 *bw_pct, u8 *up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!xdev->caps.ets) {
		netdev_err(netdev, "%s, ets is not supported\n", __func__);
		return;
	}

	if (priority >= CEE_DCBX_MAX_PRIO) {
		netdev_err(netdev,
			   "%s, priority is out of range\n", __func__);
		return;
	}

	*prio_type = 0;
	*bw_pct = 0;
	*up_map = 0;
#ifndef XSC_DCBX_STUB
	if (xsc_query_port_prio_tc(xdev, priority, pgid))
#endif
		*pgid = 0;

	xsc_eth_dbg(HW, priv, "%s: prio=%d, pgid=%d, bw_pct=%d\n",
		    __func__, priority, *pgid, *bw_pct);
}

static void xsc_dcbnl_getpgbwgcfgtx(struct net_device *netdev,
				    int pgid, u8 *bw_pct)
{
	struct ieee_ets ets;
	struct xsc_adapter *priv = netdev_priv(netdev);

	if (pgid >= CEE_DCBX_MAX_PGS) {
		netdev_err(netdev,
			   "%s, priority group is out of range\n", __func__);
		return;
	}

	xsc_dcbnl_ieee_getets(netdev, &ets);
	*bw_pct = ets.tc_tx_bw[pgid];
	xsc_eth_dbg(HW, priv, "%s: pgid=%d, bw_pct=%d\n",
		    __func__, pgid, *bw_pct);
}

static void xsc_dcbnl_setpfccfg(struct net_device *netdev,
				int priority, u8 setting)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	xsc_eth_dbg(HW, priv, "%s: prio=%d, setting=%d\n",
		    __func__, priority, setting);
	if (priority >= CEE_DCBX_MAX_PRIO) {
		netdev_err(netdev,
			   "%s, priority is out of range\n", __func__);
		return;
	}

	if (setting > 1)
		return;

	cee_cfg->pfc_setting[priority] = setting;
}

static int
xsc_dcbnl_get_priority_pfc(struct net_device *netdev,
			   int priority, u8 *setting)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct ieee_pfc pfc;
	int err;

	err = xsc_dcbnl_ieee_getpfc(netdev, &pfc);

	if (err)
		*setting = 0;
	else
		*setting = (pfc.pfc_en >> priority) & 0x01;

	xsc_eth_dbg(HW, priv, "%s: prio=%d, setting=%d\n",
		    __func__, priority, *setting);
	return err;
}

static void xsc_dcbnl_getpfccfg(struct net_device *netdev,
				int priority, u8 *setting)
{
	if (priority >= CEE_DCBX_MAX_PRIO) {
		netdev_err(netdev,
			   "%s, priority is out of range\n", __func__);
		return;
	}

	if (!setting)
		return;

	xsc_dcbnl_get_priority_pfc(netdev, priority, setting);
}

static u8 xsc_dcbnl_getcap(struct net_device *netdev,
			   int capid, u8 *cap)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	u8 rval = 0;

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
		*cap = 1 << xsc_max_tc(xdev);
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = 1 << xsc_max_tc(xdev);
		break;
	case DCB_CAP_ATTR_GSP:
		*cap = false;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	case DCB_CAP_ATTR_DCBX:
		*cap = priv->dcbx.cap |
		       DCB_CAP_DCBX_VER_CEE |
		       DCB_CAP_DCBX_VER_IEEE;
		break;
	default:
		*cap = 0;
		rval = 1;
		break;
	}

	xsc_eth_dbg(HW, priv, "%s: capid=%d, cap=%d, ret=%d\n",
		    __func__, capid, *cap, rval);
	return rval;
}

static int xsc_dcbnl_getnumtcs(struct net_device *netdev,
			       int tcs_id, u8 *num)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	switch (tcs_id) {
	case DCB_NUMTCS_ATTR_PG:
	case DCB_NUMTCS_ATTR_PFC:
		*num = xsc_max_tc(xdev) + 1;
		break;
	default:
		return -EINVAL;
	}

	xsc_eth_dbg(HW, priv, "%s: tcs_id=%d, tc_num=%d\n",
		    __func__, tcs_id, *num);
	return 0;
}

static u8 xsc_dcbnl_getpfcstate(struct net_device *netdev)
{
	struct ieee_pfc pfc;

	if (xsc_dcbnl_ieee_getpfc(netdev, &pfc))
		return XSC_CEE_STATE_DOWN;

	return pfc.pfc_en ? XSC_CEE_STATE_UP : XSC_CEE_STATE_DOWN;
}

static void xsc_dcbnl_setpfcstate(struct net_device *netdev, u8 state)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	if (state != XSC_CEE_STATE_UP && state != XSC_CEE_STATE_DOWN)
		return;

	cee_cfg->pfc_enable = state;
}

static int xsc_dcbnl_getbuffer(struct net_device *dev,
			       struct dcbnl_buffer *dcb_buffer)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_port_buffer port_buffer = {0};
	u8 buffer[XSC_MAX_PRIORITY];
	int i;
#ifndef XSC_DCBX_STUB
	int err = 0;
#endif

	if (!xdev->caps.port_buf)
		return -EOPNOTSUPP;

#ifndef XSC_DCBX_STUB
	err = xsc_port_query_priority2buffer(xdev, buffer);
	if (err)
		return err;
#endif

	for (i = 0; i < XSC_MAX_PRIORITY; i++)
		dcb_buffer->prio2buffer[i] = buffer[i];

#ifndef XSC_DCBX_STUB
	err = xsc_port_query_buffer(priv, &port_buffer);
	if (err)
		return err;
#endif

	for (i = 0; i < XSC_MAX_BUFFER; i++)
		dcb_buffer->buffer_size[i] = port_buffer.buffer[i].size;
	dcb_buffer->total_size = port_buffer.port_buffer_size;

	return 0;
}

static int xsc_dcbnl_setbuffer(struct net_device *dev,
			       struct dcbnl_buffer *dcb_buffer)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_port_buffer port_buffer = {0};
	u8 old_prio2buffer[XSC_MAX_PRIORITY] = {0};
	u32 *buffer_size = NULL;
	u8 *prio2buffer = NULL;
	u32 changed = 0;
	int i, err = 0;

	if (!xdev->caps.port_buf)
		return -EOPNOTSUPP;

	for (i = 0; i < DCBX_MAX_BUFFERS; i++)
		netdev_dbg(dev, "buffer[%d]=%d\n", i, dcb_buffer->buffer_size[i]);

	for (i = 0; i < XSC_MAX_PRIORITY; i++)
		netdev_dbg(dev, "priority %d buffer%d\n", i, dcb_buffer->prio2buffer[i]);

#ifndef XSC_DCBX_STUB
	err = xsc_port_query_priority2buffer(xdev, old_prio2buffer);
	if (err)
		return err;
#endif

	for (i = 0; i < XSC_MAX_PRIORITY; i++) {
		if (dcb_buffer->prio2buffer[i] != old_prio2buffer[i]) {
			changed |= XSC_PORT_BUFFER_PRIO2BUFFER;
			prio2buffer = dcb_buffer->prio2buffer;
			break;
		}
	}

#ifndef XSC_DCBX_STUB
	err = xsc_port_query_buffer(priv, &port_buffer);
	if (err)
		return err;
#endif

	for (i = 0; i < XSC_MAX_BUFFER; i++) {
		if (port_buffer.buffer[i].size != dcb_buffer->buffer_size[i]) {
			changed |= XSC_PORT_BUFFER_SIZE;
			buffer_size = dcb_buffer->buffer_size;
			break;
		}
	}

	if (!changed)
		return 0;

	priv->dcbx.manual_buffer = 1;
#ifndef XSC_DCBX_STUB
	err = xsc_port_manual_buffer_config(priv, changed, dev->mtu, NULL,
					    buffer_size, prio2buffer);
#endif
	return err;
}

const struct dcbnl_rtnl_ops xsc_dcbnl_ops = {
	.ieee_getets	= xsc_dcbnl_ieee_getets,
	.ieee_setets	= xsc_dcbnl_ieee_setets,
	.ieee_getmaxrate = xsc_dcbnl_ieee_getmaxrate,
	.ieee_setmaxrate = xsc_dcbnl_ieee_setmaxrate,
	.ieee_getpfc	= xsc_dcbnl_ieee_getpfc,
	.ieee_setpfc	= xsc_dcbnl_ieee_setpfc,
	.ieee_setapp    = xsc_dcbnl_ieee_setapp,
	.ieee_delapp    = xsc_dcbnl_ieee_delapp,
	.getdcbx	= xsc_dcbnl_getdcbx,
	.setdcbx	= xsc_dcbnl_setdcbx,
	.dcbnl_getbuffer = xsc_dcbnl_getbuffer,
	.dcbnl_setbuffer = xsc_dcbnl_setbuffer,
/* CEE interfaces */
	.setall         = xsc_dcbnl_setall,
	.getstate       = xsc_dcbnl_getstate,
	.getpermhwaddr  = xsc_dcbnl_getpermhwaddr,

	.setpgtccfgtx   = xsc_dcbnl_setpgtccfgtx,
	.setpgbwgcfgtx  = xsc_dcbnl_setpgbwgcfgtx,
	.getpgtccfgtx   = xsc_dcbnl_getpgtccfgtx,
	.getpgbwgcfgtx  = xsc_dcbnl_getpgbwgcfgtx,

	.setpfccfg      = xsc_dcbnl_setpfccfg,
	.getpfccfg      = xsc_dcbnl_getpfccfg,
	.getcap         = xsc_dcbnl_getcap,
	.getnumtcs      = xsc_dcbnl_getnumtcs,
	.getpfcstate    = xsc_dcbnl_getpfcstate,
	.setpfcstate    = xsc_dcbnl_setpfcstate,
};

static void xsc_dcbnl_query_dcbx_mode(struct xsc_adapter *priv,
				      enum xsc_dcbx_oper_mode *mode)
{
	*mode = XSC_DCBX_PARAM_VER_OPER_HOST;

	/* From driver's point of view, we only care if the mode
	 * is host (HOST) or non-host (AUTO)
	 */
	if (*mode != XSC_DCBX_PARAM_VER_OPER_HOST)
		*mode = XSC_DCBX_PARAM_VER_OPER_AUTO;
}

static void xsc_ets_init(struct xsc_adapter *priv)
{
#ifdef XSC_DCBX_STUB
	struct ieee_ets ets;
	int err;
	int i;

	if (!priv->xdev->caps.ets)
		return;
	memset(&ets, 0, sizeof(ets));
	ets.ets_cap = xsc_max_tc(priv->xdev) + 1;
	for (i = 0; i < ets.ets_cap; i++) {
		ets.tc_tx_bw[i] = XSC_MAX_BW_ALLOC;
		ets.tc_tsa[i] = IEEE_8021QAZ_TSA_VENDOR;
		ets.prio_tc[i] = i;
	}

	err = xsc_dcbnl_ieee_setets_core(priv, &ets);
	if (err)
		netdev_err(priv->netdev,
			   "%s, Failed to init ETS: %d\n", __func__, err);
#endif
}

enum {
	INIT,
	DELETE,
};

static void xsc_dcbnl_dscp_app(struct xsc_adapter *priv, int action)
{
	struct dcb_app temp;
	int i;

	xsc_eth_dbg(HW, priv, "%s: action=%d\n", __func__, action);
	if (!priv->xdev->caps.dscp)
		return;

	/* No SEL_DSCP entry in non DSCP state */
	if (priv->dcbx_dp.trust_state != XSC_QPTS_TRUST_DSCP)
		return;

	temp.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	for (i = 0; i < XSC_MAX_DSCP; i++) {
		temp.protocol = i;
		temp.priority = priv->dcbx_dp.dscp2prio[i];
		if (action == INIT)
			dcb_ieee_setapp(priv->netdev, &temp);
		else
			dcb_ieee_delapp(priv->netdev, &temp);
	}

	priv->dcbx.dscp_app_cnt = (action == INIT) ? XSC_MAX_DSCP : 0;
}

void xsc_dcbnl_init_app(struct xsc_adapter *priv)
{
	xsc_dcbnl_dscp_app(priv, INIT);
}

void xsc_dcbnl_delete_app(struct xsc_adapter *priv)
{
	xsc_dcbnl_dscp_app(priv, DELETE);
}

static void xsc_trust_update_tx_min_inline_mode(struct xsc_adapter *priv)
{
	struct xsc_eth_params *params = &priv->nic_param;

#ifndef XSC_DCBX_STUB
	xsc_query_min_inline(priv->xdev, &params->tx_min_inline_mode);
#endif
	if (priv->dcbx_dp.trust_state == XSC_QPTS_TRUST_DSCP &&
	    params->tx_min_inline_mode == XSC_INLINE_MODE_L2)
		params->tx_min_inline_mode = XSC_INLINE_MODE_IP;
}

static void xsc_trust_update_sq_inline_mode(struct xsc_adapter *priv)
{
	int old_mode = priv->nic_param.tx_min_inline_mode;

	mutex_lock(&priv->state_lock);

	xsc_trust_update_tx_min_inline_mode(priv);

	/* Skip if tx_min_inline is the same */
	if (old_mode == priv->nic_param.tx_min_inline_mode)
		goto out;
#ifndef XSC_DCBX_STUB
	xsc_safe_switch_channels(priv, NULL, NULL);
#endif

out:
	mutex_unlock(&priv->state_lock);
}

static int xsc_set_trust_state(struct xsc_adapter *priv, u8 trust_state)
{
	int err = 0;

#ifndef XSC_DCBX_STUB
	err = xsc_cmd_set_trust_state(priv->xdev, trust_state);
	if (err)
		return err;
#endif
	priv->dcbx_dp.trust_state = trust_state;
	xsc_trust_update_sq_inline_mode(priv);

	/* In DSCP trust state, we need 8 send queues per channel */
#ifndef XSC_DCBX_STUB
	struct tc_mqprio_qopt mqprio = {.num_tc = XSC_MAX_NUM_TC};

	if (priv->dcbx_dp.trust_state == XSC_QPTS_TRUST_DSCP)
		xsc_setup_tc_mqprio(priv->netdev, &mqprio);
#endif

	return err;
}

static int xsc_set_dscp2prio(struct xsc_adapter *priv, u8 dscp, u8 prio)
{
	int err = 0;

	xsc_eth_dbg(HW, priv, "%s: dscp=%d, prio=%d\n",
		    __func__, dscp, prio);
#ifndef XSC_DCBX_STUB
	err = xsc_cmd_set_dscp2prio(priv->xdev, dscp, prio);
	if (err)
		return err;
#endif
	priv->dcbx_dp.dscp2prio[dscp] = prio;
	return err;
}

static int xsc_trust_initialize(struct xsc_adapter *priv)
{
	struct xsc_core_device *xdev = priv->xdev;
#ifndef XSC_DCBX_STUB
	int err;
#endif

	priv->dcbx_dp.trust_state = XSC_QPTS_TRUST_PCP;

	if (!xdev->caps.dscp)
		return 0;

#ifndef XSC_DCBX_STUB
	err = xsc_query_trust_state(priv->xdev, &priv->dcbx_dp.trust_state);
	if (err)
		return err;
#endif

	xsc_trust_update_tx_min_inline_mode(priv);
	if (priv->dcbx_dp.trust_state == XSC_QPTS_TRUST_DSCP)
		priv->nic_param.num_tc = XSC_MAX_NUM_TC;
#ifndef XSC_DCBX_STUB
	err = xsc_query_dscp2prio(priv->xdev, priv->dcbx_dp.dscp2prio);
	if (err)
		return err;
#endif

	return 0;
}

#define XSC_BUFFER_CELL_SHIFT 7

static u16 xsc_query_port_buffers_cell_size(struct xsc_adapter *priv)
{
	return (1 << XSC_BUFFER_CELL_SHIFT);
}

static void xsc_cee_init(struct xsc_adapter *priv)
{
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;
	struct xsc_core_device *xdev = priv->xdev;
	int i, max_tc;

	memset(cee_cfg, 0, sizeof(*cee_cfg));

	cee_cfg->pfc_enable = 1;

	max_tc = xsc_max_tc(xdev) + 1;
	for (i = 0; i < max_tc; i++)
		cee_cfg->pfc_setting[i] = 1;

	for (i = 0; i < CEE_DCBX_MAX_PGS; i++)
		cee_cfg->prio_to_pg_map[i] = i % max_tc;
}

void xsc_dcbnl_initialize(struct xsc_adapter *priv)
{
	struct xsc_dcbx *dcbx = &priv->dcbx;

	xsc_trust_initialize(priv);

	if (!priv->xdev->caps.qos)
		return;

	if (priv->xdev->caps.dcbx)
		xsc_dcbnl_query_dcbx_mode(priv, &dcbx->mode);

	priv->dcbx.cap = DCB_CAP_DCBX_VER_CEE |
			 DCB_CAP_DCBX_VER_IEEE;
	if (priv->dcbx.mode == XSC_DCBX_PARAM_VER_OPER_HOST)
		priv->dcbx.cap |= DCB_CAP_DCBX_HOST;

	priv->dcbx.port_buff_cell_sz = xsc_query_port_buffers_cell_size(priv);
	priv->dcbx.manual_buffer = 0;
	priv->dcbx.cable_len = XSC_DEFAULT_CABLE_LEN;

	xsc_cee_init(priv);
	xsc_ets_init(priv);
}
#endif
