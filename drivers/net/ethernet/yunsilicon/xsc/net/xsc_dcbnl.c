// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/fcntl.h>
#include <net/pkt_cls.h>
#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "common/vport.h"
#include "xsc_eth.h"
#include "xsc_eth_debug.h"
#include "xsc_hw_comm.h"

#ifndef IEEE_8021QAZ_APP_SEL_DSCP
#define IEEE_8021QAZ_APP_SEL_DSCP       5
#endif

#define XSC_100MB (100000)
#define XSC_1GB   (1000000)
#define XSC_RATE_LIMIT_BASE	(16000)
#define XSC_WRR_DIV_BASE	10
#define XSC_WRR_DEFAULT_WEIGHT	10
#define XSC_DCBX_WFQ_TOTAL_WEIGHT 100
#define XSC_DCBX_MAX_TC 8

#define XSC_CEE_STATE_UP    1
#define XSC_CEE_STATE_DOWN  0

/* Max supported cable length is 1000 meters */
#define XSC_MAX_CABLE_LENGTH 1000

enum {
	XSC_VENDOR_TC_GROUP_NUM = 7,
	XSC_LOWEST_PRIO_GROUP   = 0,
};


#ifdef CONFIG_XSC_CORE_EN_DCB
static int xsc_set_trust_state(struct xsc_adapter *priv, u8 trust_state);
static int xsc_set_dscp2prio(struct xsc_adapter *priv, u8 dscp, u8 prio);
static u8 xsc_dcbnl_setall(struct net_device *netdev);

static int xsc_max_tc(struct xsc_core_device *dev)
{
	u8 num_tc = dev->caps.max_tc ? : 8;

	if (num_tc > XSC_DCBX_MAX_TC)
		num_tc = XSC_DCBX_MAX_TC;

	return num_tc - 1;
}

static void xsc_pfc_array2bitmap(u8 *pfcbitmap, u8 *array)
{
	u8 i;

	*pfcbitmap = 0;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (array[i])
			*pfcbitmap = *pfcbitmap | (1 << i);
	}
}

static void xsc_pfc_bitmap2array(u8 pfcbitmap, u8 *array)
{
	u8 i;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if ((pfcbitmap >> i) & 0x1)
			array[i] = 1;
	}
}

static int xsc_query_port_prio_tc(struct xsc_core_device *xdev, int prio, u8 *tc)
{
	/* user priotity to tc 0:0; 1:1; 2:2; 3:3 ... 7:7 */
	*tc = (u8)prio;
	return 0;
}

static int xsc_set_port_prio_tc(struct xsc_core_device *xdev, u8 *prio_tc)
{
	u8 i;

	for (i = 0; i <= xsc_max_tc(xdev); i++)
		prio_tc[i] = i;

	return 0;
}

static int xsc_wfq_to_wrr_adpat(struct xsc_core_device *xdev, u8 *dst_bw,
				u8 *src_bw, u8 ets_cnt, u8 min_weight)
{
	u8 i, index;
	u8 max_commom_div = 1;
	u8 flag[XSC_DCBX_WFQ_TOTAL_WEIGHT] = {0};

	if (min_weight >= XSC_DCBX_WFQ_TOTAL_WEIGHT || !ets_cnt)
		return 0;

	for (index = 1; index <= min_weight; index++) {
		for (i = 0; i < ets_cnt; i++) {
			/*any ets bw can not div by whole,flag = 1*/
			if (src_bw[i] % index) {
				flag[index] = 1;
				break;
			}
		}
	}

	for (index = 1; index <= min_weight; index++) {
		if (flag[index] == 0)
			max_commom_div = index;
	}

	xsc_core_dbg(xdev, "max_commom_div = %d, min_weight = %d\n", max_commom_div, min_weight);

	for (i = 0; i < ets_cnt; i++) {
		dst_bw[i] = src_bw[i] / max_commom_div;
		xsc_core_dbg(xdev, "dst_bw[%d] = %d\n", i, dst_bw[i]);
	}

	return 0;
}

static int xsc_wrr_to_wfq_adpat(struct xsc_core_device *xdev,
				struct xsc_weight_get *wrr, u8 *bandwidth)
{
	u8 i, wrr_cnt = 0, index;
	u16 wrr_total_weight = 0, wfq_tatal_weight = 0;
	u16 portion = 0;
	u16 rmndr = 0;
	u16 temp[IEEE_8021QAZ_MAX_TCS] = {0};

	/*1 calc cur wrr weight total*/
	for (i = 0; i <= wrr->max_prio; i++) {
		if (wrr->weight[i] > 0) {
			wrr_total_weight += wrr->weight[i];
			wrr_cnt++;
		}
	}

	xsc_core_dbg(xdev, "%s: wrr_total_weight = %d max_prio = %d\n",
		     __func__, wrr_total_weight, wrr->max_prio);

	if (!wrr_total_weight || wrr_total_weight > XSC_DCBX_WFQ_TOTAL_WEIGHT)
		return -EINVAL;

	portion = XSC_DCBX_WFQ_TOTAL_WEIGHT / wrr_total_weight;
	rmndr = XSC_DCBX_WFQ_TOTAL_WEIGHT % wrr_total_weight;

	/*2 calc major wfq weight*/
	for (i = 0; i <= wrr->max_prio; i++) {
		if (wrr->weight[i] > 0) {
			temp[i] = wrr->weight[i] * portion;
			wfq_tatal_weight += temp[i];
		}
	}

	xsc_core_dbg(xdev, "portion = %d, rmndr = %d, wfq_tatal = %d\n",
		     portion, rmndr, wfq_tatal_weight);

	/*3 average remainder to every prio*/
	if (rmndr > 0) {
		for (i = 0; i < rmndr; i++) {
			index = i % wrr_cnt;
			temp[index] = temp[index] + 1;
		}
	}
	for (i = 0; i <= wrr->max_prio; i++)
		bandwidth[i] = (u8)temp[i];

	return 0;
}

static int xsc_query_port_ets_rate_limit(struct xsc_core_device *xdev, u64 *ratelimit)
{
	u8 i;
	int err = 0;
	struct xsc_rate_limit_get req;
	struct xsc_rate_limit_get rsp;

	memset(&req, 0, sizeof(struct xsc_rate_limit_get));
	memset(&rsp, 0, sizeof(struct xsc_rate_limit_get));
	/*0--port rate limit; 1--priority rate limit*/
	req.limit_level = 1;

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_RATE_LIMIT, &req, &rsp);
	if (err)
		return err;

	for (i = 0; i <= xsc_max_tc(xdev); i++)
		ratelimit[i] = (u64)(rsp.rate_cir[i]);

	return 0;
}

static int xsc_modify_port_ets_rate_limit(struct xsc_core_device *xdev, u64 *ratelimit)
{
	u8 i;
	struct xsc_rate_limit_set req;

	memset(&req, 0, sizeof(struct xsc_rate_limit_set));
	req.limit_level = 1;

	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		req.rate_cir = (u32)ratelimit[i];
		req.limit_id = i;
		xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_RATE_LIMIT, &req, NULL);
	}

	return 0;
}

static int xsc_query_port_bw_config(struct xsc_core_device *xdev, u8 *bandwidth)
{
	u8 i;
	u8 sp_cnt = 0;
	int err = 0;
	struct xsc_sp_get sp_rsp;
	struct xsc_weight_get weight_rsp;

	memset(&sp_rsp, 0, sizeof(struct xsc_sp_get));
	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_SP, NULL, &sp_rsp);
	if (err)
		return err;
	/*SP enable,bandwidth is 0*/
	for (i = 0; i <= sp_rsp.max_prio; i++) {
		if (sp_rsp.sp[i]) {
			sp_cnt++;
			bandwidth[i] = 0;
		}
	}

	xsc_core_dbg(xdev, "sp_cnt = %d, max_prio = %d\n", sp_cnt, sp_rsp.max_prio);

	memset(&weight_rsp, 0, sizeof(struct xsc_weight_get));
	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_WEIGHT, NULL, &weight_rsp);
	if (err)
		return err;

	xsc_core_dbg(xdev, "weight_rsp.max_prio = %d\n", weight_rsp.max_prio);
	for (i = 0; i <= weight_rsp.max_prio; i++)
		xsc_core_dbg(xdev, "i = %d, weight = %d\n", i, weight_rsp.weight[i]);

	xsc_wrr_to_wfq_adpat(xdev, &weight_rsp, bandwidth);

	return 0;
}

static int xsc_query_port_pfc(struct xsc_core_device *xdev, u8 *pfc_bitmap)
{
	int err = 0;
	struct xsc_pfc_get rsp;

	memset(&rsp, 0, sizeof(struct xsc_pfc_get));

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_PFC, NULL, &rsp);
	if (err)
		return err;

	xsc_pfc_array2bitmap(pfc_bitmap, rsp.pfc_on);

	return 0;
}

static int xsc_query_port_stats(struct xsc_core_device *xdev, struct ieee_pfc *pfc)
{
	u8 i;
	int err = 0;
	struct xsc_pfc_prio_stats_mbox_in req;
	struct xsc_pfc_prio_stats_mbox_out rsp;

	memset(&req, 0, sizeof(struct xsc_pfc_prio_stats_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_pfc_prio_stats_mbox_out));

	req.pport = xdev->mac_port;
	req.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_QUERY_PFC_PRIO_STATS);

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_QUERY_PFC_PRIO_STATS, &req, &rsp);
	if (err == 0 && rsp.hdr.status == 0) {
		for (i = 0; i <= xsc_max_tc(xdev); i++) {
			pfc->requests[i]    = rsp.prio_stats[i].tx_pause;
			pfc->indications[i] = rsp.prio_stats[i].rx_pause;
		}
	}

	return 0;
}

static int xsc_query_port_pfc_stats(struct xsc_core_device *xdev, struct ieee_pfc *pfc)
{
	xsc_query_port_stats(xdev, pfc);

	xsc_query_port_pfc(xdev, &pfc->pfc_en);

	return 0;
}

static int xsc_set_port_pfc(struct xsc_core_device *xdev, u8 pfcbitmap)
{
	u8 i;
	u8 pfc_en[IEEE_8021QAZ_MAX_TCS] = {0};
	struct xsc_pfc_set_new req;
	struct xsc_pfc_set_new rsp;

	xsc_pfc_bitmap2array(pfcbitmap, pfc_en);

	memset(&req, 0, sizeof(struct xsc_pfc_set));
	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		req.pfc_on = pfc_en[i];
		req.req_prio = i;
		xsc_core_dbg(xdev, "%s: prio %d, pfc %d\n", __func__, i, req.pfc_on);
		xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_PFC_NEW, &req, &rsp);
	}
	return 0;
}

static int xsc_cmd_set_dscp2prio(struct xsc_core_device *xdev, u8 dscp, u8 prio)
{
	int err = 0;
	struct xsc_dscp_pmt_set req;

	memset(&req, 0, sizeof(struct xsc_dscp_pmt_set));
	req.dscp = dscp;
	req.priority = prio;

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_DSCP_PMT, &req, NULL);
	if (err)
		return err;

	xsc_core_dbg(xdev, "%s: dscp %d mapping to prio %d\n", __func__, dscp, prio);

	return 0;
}

static int xsc_cmd_set_trust_state(struct xsc_core_device *xdev, u8 trust_state)
{
	int err = 0;
	struct xsc_trust_mode_set req;

	memset(&req, 0, sizeof(struct xsc_trust_mode_set));

	/*set trust state,0,DSCP mdoe; 1,PCP mode*/
	if (trust_state == XSC_QPTS_TRUST_PCP)
		req.is_pcp = 1;

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_TRUST_MODE, &req, NULL);
	if (err)
		return err;

	return 0;
}

static int xsc_cmd_get_trust_state(struct xsc_core_device *xdev, u8 *trust_state)
{
	int err;
	struct xsc_trust_mode_get rsp;

	memset(&rsp, 0, sizeof(struct xsc_trust_mode_get));

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_TRUST_MODE, NULL, &rsp);
	if (err)
		return err;

	if (rsp.is_pcp)
		*trust_state = XSC_QPTS_TRUST_PCP;
	else
		*trust_state = XSC_QPTS_TRUST_DSCP;

	return 0;
}

static int xsc_dcbnl_ieee_getets(struct net_device *netdev,
				 struct ieee_ets *ets)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	int err = 0;
	int i;

	if (!priv->dcbx.enable || !xdev->caps.ets)
		return -EOPNOTSUPP;

	memset(ets, 0, sizeof(*ets));
	ets->willing = 1;
	ets->ets_cap = xsc_max_tc(priv->xdev) + 1;
	for (i = 0; i < ets->ets_cap; i++) {
		/*get prio->tc mapping*/
		xsc_query_port_prio_tc(xdev, i, &ets->prio_tc[i]);
	}

	err = xsc_query_port_bw_config(xdev, ets->tc_tx_bw);
	if (err)
		return err;

	for (i = 0; i < ets->ets_cap; i++) {
		if (!ets->tc_tx_bw[i])
			priv->dcbx.tc_tsa[i] = IEEE_8021QAZ_TSA_STRICT;
		else if (ets->tc_tx_bw[i] < XSC_MAX_BW_ALLOC)
			priv->dcbx.tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;

		xsc_core_dbg(xdev, "%s: tc%d, bw=%d\n",
			     __func__, i, ets->tc_tx_bw[i]);
	}

	memcpy(ets->tc_tsa, priv->dcbx.tc_tsa, sizeof(ets->tc_tsa));

	return err;
}

static void xsc_build_tc_tx_bw_sch(struct xsc_core_device *xdev,
				   struct ieee_ets *ets, u8 *tc_tx_bw,
				   u8 *tc_sp_enable, int max_tc)
{
	u8 i;
	u8 ets_cnt = 0;
	u8 min_weight = 0xff;

	for (i = 0; i <= max_tc; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			tc_tx_bw[i] = 1;
			tc_sp_enable[i] = i + 1;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			ets_cnt++;
			if (ets->tc_tx_bw[i] <= min_weight)
				min_weight = ets->tc_tx_bw[i];
			break;
		}
	}
	xsc_wfq_to_wrr_adpat(xdev, tc_tx_bw, ets->tc_tx_bw, ets_cnt, min_weight);
}

static int xsc_set_port_tx_bw_sch(struct xsc_core_device *xdev, u8 *tc_sp_enable, u8 *tc_tx_bw)
{
	u8 i;
	int err = 0;
	struct xsc_sp_set req_sch;
	struct xsc_weight_set req_weight;

	memset(&req_sch, 0, sizeof(struct xsc_sp_set));
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		req_sch.sp[i] = tc_sp_enable[i];

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_SP, &req_sch, NULL);
	if (err)
		return err;

	memset(&req_weight, 0, sizeof(struct xsc_weight_set));
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		req_weight.weight[i] = tc_tx_bw[i];

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_WEIGHT, &req_weight, NULL);
	if (err)
		return err;

	return 0;
}

int xsc_dcbnl_ieee_setets_core(struct xsc_adapter *priv, struct ieee_ets *ets)
{
	struct xsc_core_device *xdev = priv->xdev;
	u8 tc_tx_bw[IEEE_8021QAZ_MAX_TCS] = {1};
	u8 tc_sp_enable[IEEE_8021QAZ_MAX_TCS];
	int max_tc = xsc_max_tc(xdev);
	int err = 0;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	memset(tc_sp_enable, 0, IEEE_8021QAZ_MAX_TCS);
	xsc_build_tc_tx_bw_sch(xdev, ets, tc_tx_bw, tc_sp_enable, max_tc);
	xsc_set_port_prio_tc(xdev, ets->prio_tc);

	err = xsc_set_port_tx_bw_sch(xdev, tc_sp_enable, tc_tx_bw);
	if (err)
		return err;

	memcpy(priv->dcbx.tc_tsa, ets->tc_tsa, sizeof(ets->tc_tsa));

	return err;
}

static int xsc_dbcnl_validate_ets(struct net_device *netdev,
				  struct ieee_ets *ets)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	bool have_ets_tc = false;
	int bw_sum = 0;
	int i;

	if (!priv->dcbx.enable)
		return 0;

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
			/* do not allow ets with 0 weight */
			have_ets_tc = true;
			if (!ets->tc_tx_bw[i])
				return -EINVAL;
			bw_sum += ets->tc_tx_bw[i];
		}
	}

	xsc_core_dbg(xdev, "%s bw_sum = %d\n", __func__, bw_sum);

	if (have_ets_tc && bw_sum != 100) {
		netdev_err(netdev, "Failed to validate ETS: BW sum is illegal\n");
		return -EINVAL;
	}
	return 0;
}

static int xsc_dcbnl_ieee_setets(struct net_device *dev,
				 struct ieee_ets *ets)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	int err;

	if (!priv->dcbx.enable)
		return 0;

	if (!priv->xdev->caps.ets)
		return -EOPNOTSUPP;

	err = xsc_dbcnl_validate_ets(dev, ets);
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

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	pfc->pfc_cap = xsc_max_tc(xdev) + 1;
	pfc->pfc_en = 0;
	if (xdev->caps.port_buf)
		pfc->delay = priv->dcbx.cable_len;
	xsc_query_port_pfc_stats(xdev, pfc);

	xsc_core_dbg(xdev, "%s: pfc_en=0x%x\n", __func__, pfc->pfc_en);

	return 0;
}

static int xsc_dcbnl_ieee_setpfc(struct net_device *dev,
				 struct ieee_pfc *pfc)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;
	u8 curr_pfc_en;
	int ret = 0;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	/* pfc_en */
	xsc_query_port_pfc(xdev, &curr_pfc_en);
	if (pfc->pfc_en != curr_pfc_en) {
		ret = xsc_set_port_pfc(xdev, pfc->pfc_en);
		if (ret)
			return ret;
	}

	xsc_core_dbg(xdev, "%s: new_pfc_en=0x%x, cur_pfc_en=0x%x\n",
		     __func__, pfc->pfc_en, curr_pfc_en);
	return ret;
}

static u8 xsc_dcbnl_getdcbx(struct net_device *dev)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	xsc_core_dbg(xdev, "%s: dcbx->cap=0x%x\n", __func__, priv->dcbx.cap);
	return priv->dcbx.cap;
}

static u8 xsc_dcbnl_setdcbx(struct net_device *dev, u8 mode)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_dcbx *dcbx = &priv->dcbx;
	struct ieee_ets ets = {0};
	struct ieee_pfc pfc = {0};
	struct xsc_lldp_status_mbox_in  req;
	struct xsc_lldp_status_mbox_out rsp;
	int err = 0;

	memset(&req, 0, sizeof(struct xsc_lldp_status_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_lldp_status_mbox_out));

	req.sub_type = XSC_OS_HANDLE_LLDP_STATUS;
	req.os_handle_lldp  = cpu_to_be32(1);
	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_SET_LLDP_STATUS, &req, &rsp);
	if (err) {
		xsc_core_err(xdev, "set LLDP status fail,err %d\n", err);
		return err;
	}

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	xsc_core_dbg(xdev, "%s: mode=%d, dcbx->cap = %d\n", __func__, mode, dcbx->cap);

	/* no support for LLD_MANAGED modes or CEE+IEEE */
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    ((mode & DCB_CAP_DCBX_VER_IEEE) && (mode & DCB_CAP_DCBX_VER_CEE)) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return -EINVAL;

	if (mode == dcbx->cap)
		return 0;

	/* ETS and PFC defaults */
	ets.ets_cap = 8;
	pfc.pfc_cap = 8;

	/*mode switch, set base config*/
	if (mode & DCB_CAP_DCBX_VER_IEEE) {
		xsc_dcbnl_ieee_setets(dev, &ets);
		xsc_dcbnl_ieee_setpfc(dev, &pfc);
	} else if (mode & DCB_CAP_DCBX_VER_CEE) {
		xsc_dcbnl_setall(dev);
	}

	dcbx->cap = mode;

	return 0;
}

static int xsc_dcbnl_ieee_setapp(struct net_device *dev, struct dcb_app *app)
{
	struct xsc_adapter *priv = netdev_priv(dev);
	struct dcb_app temp;
	bool is_new;
	int err;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

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

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

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
	u64 max_bw_value[IEEE_8021QAZ_MAX_TCS] = {0};
	int i, err;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	memset(maxrate->tc_maxrate, 0, sizeof(maxrate->tc_maxrate));

	err = xsc_query_port_ets_rate_limit(xdev, max_bw_value);
	if (err)
		return err;

	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		maxrate->tc_maxrate[i] = max_bw_value[i] * XSC_RATE_LIMIT_BASE / XSC_1GB;
	}

	return 0;
}

static int xsc_dcbnl_ieee_setmaxrate(struct net_device *netdev,
				     struct ieee_maxrate *maxrate)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	u64 max_bw_value[IEEE_8021QAZ_MAX_TCS];
	int i;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	memset(max_bw_value, 0, sizeof(max_bw_value));

	for (i = 0; i <= xsc_max_tc(xdev); i++) {
		if (!maxrate->tc_maxrate[i])
			continue;
		max_bw_value[i] = maxrate->tc_maxrate[i] * XSC_1GB / XSC_RATE_LIMIT_BASE;
		xsc_core_dbg(xdev, "%s: tc_%d <=> max_bw %llu * 16kbps\n",
			     __func__, i, max_bw_value[i]);
	}

	return xsc_modify_port_ets_rate_limit(xdev, max_bw_value);
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

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

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

	err = xsc_dbcnl_validate_ets(netdev, &ets);
	if (err)
		goto out;

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
	struct xsc_adapter *priv = netdev_priv(netdev);

	if (!priv->dcbx.enable || !perm_addr)
		return;

	memset(perm_addr, 0xff, MAX_ADDR_LEN);
	xsc_query_nic_vport_mac_address(priv->xdev, 0, perm_addr);
}

static void xsc_dcbnl_setpgtccfgtx(struct net_device *netdev,
				   int priority, u8 prio_type,
				   u8 pgid, u8 bw_pct, u8 up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "%s: prio=%d, type=%d, pgid=%d, bw_pct=%d, up_map=%d\n",
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

static void xsc_dcbnl_setpgtccfgrx(struct net_device *netdev,
				   int priority, u8 prio_type,
				   u8 pgid, u8 bw_pct, u8 up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "Nothing to be done pgtccfg rx, not support\n");
}

static void xsc_dcbnl_setpgbwgcfgtx(struct net_device *netdev,
				    int pgid, u8 bw_pct)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "%s: pgid=%d, bw_pct=%d\n",
		     __func__, pgid, bw_pct);
	if (pgid >= CEE_DCBX_MAX_PGS) {
		netdev_err(netdev,
			   "%s, priority group is out of range\n", __func__);
		return;
	}

	cee_cfg->pg_bw_pct[pgid] = bw_pct;
}

static void xsc_dcbnl_setpgbwgcfgrx(struct net_device *netdev,
				    int pgid, u8 bw_pct)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "Nothing to be done pgbwgcfg rx, not support\n");
}

static void xsc_dcbnl_getpgtccfgtx(struct net_device *netdev,
				   int priority, u8 *prio_type,
				   u8 *pgid, u8 *bw_pct, u8 *up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	if (!xdev->caps.ets) {
		netdev_err(netdev, "%s, ets is not supported\n", __func__);
		return;
	}

	if (priority >= CEE_DCBX_MAX_PRIO) {
		netdev_err(netdev,
			   "%s, priority is out of range\n", __func__);
		return;
	}
	xsc_query_port_prio_tc(xdev, priority, pgid);

	*up_map = *pgid;
	*prio_type = 0;
	*bw_pct = 100;

	xsc_core_dbg(xdev, "%s: prio=%d, pgid=%d, bw_pct=%d\n",
		     __func__, priority, *pgid, *bw_pct);
}

static void xsc_dcbnl_getpgtccfgrx(struct net_device *netdev, int prio,
				   u8 *prio_type, u8 *pgid, u8 *bw_pct,
				   u8 *up_map)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "pgtccfgrx Nothing to get; No RX support\n");

	*prio_type = *pgid = *bw_pct = *up_map = 0;
}

static void xsc_dcbnl_getpgbwgcfgtx(struct net_device *netdev,
				    int pgid, u8 *bw_pct)
{
	struct ieee_ets ets;
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	if (pgid >= CEE_DCBX_MAX_PGS) {
		netdev_err(netdev,
			   "%s, priority group is out of range\n", __func__);
		return;
	}

	xsc_dcbnl_ieee_getets(netdev, &ets);
	*bw_pct = ets.tc_tx_bw[pgid];
	xsc_core_dbg(xdev, "%s: pgid=%d, bw_pct=%d\n",
		     __func__, pgid, *bw_pct);
}

static void xsc_dcbnl_setpfccfg(struct net_device *netdev,
				int priority, u8 setting)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "%s: prio=%d, setting=%d\n",
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

static void xsc_dcbnl_getpgbwgcfgrx(struct net_device *netdev,
				    int pgid, u8 *bw_pct)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return;

	xsc_core_dbg(xdev, "bwgcfgrx Nothing to get; No RX support\n");

	*bw_pct = 0;
}

static int xsc_dcbnl_get_priority_pfc(struct net_device *netdev,
				      int priority, u8 *setting)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;
	struct ieee_pfc pfc;
	int err;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	err = xsc_dcbnl_ieee_getpfc(netdev, &pfc);

	if (err)
		*setting = 0;
	else
		*setting = (pfc.pfc_en >> priority) & 0x01;

	xsc_core_dbg(xdev, "%s: prio=%d, setting=%d\n",
		     __func__, priority, *setting);
	return err;
}

static void xsc_dcbnl_getpfccfg(struct net_device *netdev,
				int priority, u8 *setting)
{
	struct xsc_adapter *priv = netdev_priv(netdev);

	if (!priv->dcbx.enable)
		return;

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

	if (!priv->dcbx.enable)
		return rval;

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

	xsc_core_dbg(xdev, "%s: capid=%d, cap=%d, ret=%d\n",
		     __func__, capid, *cap, rval);
	return rval;
}

static int xsc_dcbnl_getnumtcs(struct net_device *netdev,
			       int tcs_id, u8 *num)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_core_device *xdev = priv->xdev;

	if (!priv->dcbx.enable)
		return -EOPNOTSUPP;

	switch (tcs_id) {
	case DCB_NUMTCS_ATTR_PG:
	case DCB_NUMTCS_ATTR_PFC:
		*num = xsc_max_tc(xdev) + 1;
		break;
	default:
		return -EINVAL;
	}

	xsc_core_dbg(xdev, "%s: tcs_id=%d, tc_num=%d\n",
		     __func__, tcs_id, *num);
	return 0;
}

static u8 xsc_dcbnl_getpfcstate(struct net_device *netdev)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct ieee_pfc pfc;

	if (!priv->dcbx.enable)
		return XSC_CEE_STATE_DOWN;

	if (xsc_dcbnl_ieee_getpfc(netdev, &pfc))
		return XSC_CEE_STATE_DOWN;

	return pfc.pfc_en ? XSC_CEE_STATE_UP : XSC_CEE_STATE_DOWN;
}

static void xsc_dcbnl_setpfcstate(struct net_device *netdev, u8 state)
{
	struct xsc_adapter *priv = netdev_priv(netdev);
	struct xsc_cee_config *cee_cfg = &priv->dcbx.cee_cfg;

	if (!priv->dcbx.enable)
		return;

	if (state != XSC_CEE_STATE_UP && state != XSC_CEE_STATE_DOWN)
		return;

	cee_cfg->pfc_enable = state;
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

	/* CEE interfaces */
	.setall         = xsc_dcbnl_setall,
	.getstate       = xsc_dcbnl_getstate,
	.getpermhwaddr  = xsc_dcbnl_getpermhwaddr,

	.setpgtccfgtx   = xsc_dcbnl_setpgtccfgtx,
	.setpgtccfgrx   = xsc_dcbnl_setpgtccfgrx,
	.setpgbwgcfgtx  = xsc_dcbnl_setpgbwgcfgtx,
	.setpgbwgcfgrx  = xsc_dcbnl_setpgbwgcfgrx,

	.getpgtccfgtx   = xsc_dcbnl_getpgtccfgtx,
	.getpgtccfgrx   = xsc_dcbnl_getpgtccfgrx,
	.getpgbwgcfgtx  = xsc_dcbnl_getpgbwgcfgtx,
	.getpgbwgcfgtx  = xsc_dcbnl_getpgbwgcfgrx,

	.setpfccfg      = xsc_dcbnl_setpfccfg,
	.getpfccfg      = xsc_dcbnl_getpfccfg,
	.getcap         = xsc_dcbnl_getcap,
	.getnumtcs      = xsc_dcbnl_getnumtcs,
	.getpfcstate    = xsc_dcbnl_getpfcstate,
	.setpfcstate    = xsc_dcbnl_setpfcstate,
};

static void xsc_dcbnl_query_dcbx_mode(struct xsc_core_device *xdev,
				      enum xsc_dcbx_oper_mode *mode)
{
	int err = 0;
	struct xsc_lldp_status_mbox_in  req;
	struct xsc_lldp_status_mbox_out rsp;

	*mode = XSC_DCBX_PARAM_VER_OPER_HOST;

	memset(&req, 0, sizeof(struct xsc_lldp_status_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_lldp_status_mbox_out));

	req.sub_type = XSC_OS_HANDLE_LLDP_STATUS;
	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_GET_LLDP_STATUS, &req, &rsp);
	if (err) {
		xsc_core_err(xdev, "get LLDP status fail,err %d\n", err);
		return;
	}

	rsp.status.os_handle_lldp = be32_to_cpu(rsp.status.os_handle_lldp);
	xsc_core_dbg(xdev, "%s: lldp os handle  = %u\n", __func__, rsp.status.os_handle_lldp);
	if (rsp.status.os_handle_lldp != XSC_DCBX_PARAM_VER_OPER_HOST)
		*mode = XSC_DCBX_PARAM_VER_OPER_AUTO;
}

static void xsc_ets_init(struct xsc_adapter *priv)
{
	struct ieee_ets ets;
	int err;
	int i;

	if (!priv->xdev->caps.ets)
		return;
	memset(&ets, 0, sizeof(ets));
	ets.ets_cap = xsc_max_tc(priv->xdev) + 1;
	for (i = 0; i < ets.ets_cap; i++) {
		ets.tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
		ets.prio_tc[i] = i;
		ets.tc_tx_bw[i] = XSC_WRR_DEFAULT_WEIGHT;
	}

	err = xsc_dcbnl_ieee_setets_core(priv, &ets);
	if (err)
		netdev_err(priv->netdev,
			   "%s, Failed to init ETS: %d\n", __func__, err);
}

enum {
	INIT,
	DELETE,
};

static void xsc_dcbnl_dscp_app(struct xsc_adapter *priv, int action)
{
	struct dcb_app temp;
	struct xsc_core_device *xdev = priv->xdev;
	int i;

	xsc_core_dbg(xdev, "%s: action=%d\n", __func__, action);
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

static int xsc_query_trust_state(struct xsc_core_device *xdev, u8 *trust)
{
	int err = 0;

	err = xsc_cmd_get_trust_state(xdev, trust);
	if (err)
		return err;

	return 0;
}

static int xsc_set_trust_state(struct xsc_adapter *priv, u8 trust_state)
{
	int err = 0;

	err = xsc_cmd_set_trust_state(priv->xdev, trust_state);
	if (err)
		return err;

	priv->dcbx_dp.trust_state = trust_state;

	return err;
}

static int xsc_set_dscp2prio(struct xsc_adapter *priv, u8 dscp, u8 prio)
{
	int err = 0;
	struct xsc_core_device *xdev = priv->xdev;

	xsc_core_dbg(xdev, "%s: dscp=%d, prio=%d\n",
		     __func__, dscp, prio);

	err = xsc_cmd_set_dscp2prio(priv->xdev, dscp, prio);
	if (err)
		return err;

	priv->dcbx_dp.dscp2prio[dscp] = prio;
	return err;
}

static int xsc_query_dscp2prio(struct xsc_core_device *xdev, u8 *dscp2prio)
{
	int err = 0;
	struct xsc_dscp_pmt_get rsp;

	memset(&rsp, 0, sizeof(rsp));

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_DSCP_PMT, NULL, &rsp);
	if (err)
		return err;

	memcpy(dscp2prio, rsp.prio_map, sizeof(u8) * XSC_MAX_DSCP);

	return 0;
}

static int xsc_trust_initialize(struct xsc_adapter *priv)
{
	struct xsc_core_device *xdev = priv->xdev;
	int err;

	priv->dcbx_dp.trust_state = XSC_QPTS_TRUST_PCP;

	if (!xdev->caps.dscp)
		return 0;

	err = xsc_query_trust_state(xdev, &priv->dcbx_dp.trust_state);
	if (err)
		return err;

	err = xsc_query_dscp2prio(xdev, priv->dcbx_dp.dscp2prio);
	if (err)
		return err;

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
	u8 pfc_bitmap;

	memset(cee_cfg, 0, sizeof(*cee_cfg));

	cee_cfg->pfc_enable = 1;

	xsc_query_port_pfc(xdev, &pfc_bitmap);

	xsc_pfc_bitmap2array(pfc_bitmap, cee_cfg->pfc_setting);

	max_tc = xsc_max_tc(priv->xdev) + 1;
	for (i = 0; i < max_tc; i++)
		cee_cfg->prio_to_pg_map[i] = i % max_tc;
}

static u8 xsc_dcbnl_get_dcbx_status(struct xsc_core_device *xdev)
{
	u8 enable = 0;
	int err;
	struct xsc_lldp_status_mbox_in  req;
	struct xsc_lldp_status_mbox_out rsp;

	memset(&req, 0, sizeof(struct xsc_hwc_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_hwc_mbox_out));

	req.sub_type = XSC_DCBX_STATUS;
	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_GET_LLDP_STATUS, &req, &rsp);
	if (err)
		return 0;

	enable = (u8)be32_to_cpu(rsp.status.dcbx_status);

	return enable;
}

void xsc_dcbnl_initialize(struct xsc_adapter *priv)
{
	struct xsc_dcbx *dcbx = &priv->dcbx;
	struct xsc_core_device *xdev = priv->xdev;

	xsc_trust_initialize(priv);

	if (!priv->xdev->caps.qos)
		return;

	if (priv->xdev->caps.dcbx)
		xsc_dcbnl_query_dcbx_mode(xdev, &dcbx->mode);

	priv->dcbx.enable = xsc_dcbnl_get_dcbx_status(xdev);

	if (priv->dcbx.enable) {
		priv->dcbx.cap = DCB_CAP_DCBX_VER_CEE | DCB_CAP_DCBX_VER_IEEE;

		if (priv->dcbx.mode == XSC_DCBX_PARAM_VER_OPER_HOST)
			priv->dcbx.cap = priv->dcbx.cap | DCB_CAP_DCBX_HOST;

		priv->dcbx.port_buff_cell_sz = xsc_query_port_buffers_cell_size(priv);
		priv->dcbx.manual_buffer = 0;
		priv->dcbx.cable_len = XSC_DEFAULT_CABLE_LEN;

		xsc_cee_init(priv);
		xsc_ets_init(priv);
	}
}
#endif
