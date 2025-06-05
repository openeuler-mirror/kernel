// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/net.h>
#include <net/netlink.h>
#include <net/sock.h>
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_port_ctrl.h"
#include "common/tunnel_cmd.h"
#include "xsc_hw_comm.h"
#include "common/res_obj.h"
#include "xsc_eth.h"
#include "xsc_eth_ctrl.h"

#define XSC_ETH_CTRL_NAME	"eth_ctrl"

struct mutex pfc_mutex;	/* protect pfc operation */

static void encode_watchdog_set(void *data, u32 mac_port)
{
	struct xsc_watchdog_period_set *req =
		(struct xsc_watchdog_period_set *)data;

	req->period = __cpu_to_be32(req->period);
}

static void decode_watchdog_get(void *data)
{
	struct xsc_watchdog_period_get *resp =
		(struct xsc_watchdog_period_get *)data;

	resp->period = __be32_to_cpu(resp->period);
}

static void encode_rlimit_set(void *data, u32 mac_port)
{
	struct xsc_rate_limit_set *req = (struct xsc_rate_limit_set *)data;

	req->rate_cir = __cpu_to_be32(req->rate_cir);
	req->limit_id = __cpu_to_be32(req->limit_id);
}

static void decode_rlimit_get(void *data)
{
	struct xsc_rate_limit_get *resp = (struct xsc_rate_limit_get *)data;
	int i;

	for (i = 0; i <= QOS_PRIO_MAX; i++)
		resp->rate_cir[i] = __be32_to_cpu(resp->rate_cir[i]);

	resp->max_limit_id = __be32_to_cpu(resp->max_limit_id);
}

static void encode_roce_accl_set(void *data, u32 mac_port)
{
	struct xsc_roce_accl_set *req =
		(struct xsc_roce_accl_set *)data;

	req->flag = __cpu_to_be32(req->flag);
	req->sr_timeout = __cpu_to_be64(req->sr_timeout);
	req->sr_count = __cpu_to_be16(req->sr_count);
	req->sr_drop_limit = __cpu_to_be16(req->sr_drop_limit);
	req->ndp_dst_port = __cpu_to_be16(req->ndp_dst_port);

	req->cont_sport_start = __cpu_to_be16(req->cont_sport_start);
	req->max_num_exponent = __cpu_to_be16(req->max_num_exponent);
	req->disturb_period = __cpu_to_be16(req->disturb_period);
	req->disturb_th = __cpu_to_be16(req->disturb_th);
	req->mac_port = mac_port;
}

static void decode_roce_accl_get(void *data)
{
	struct xsc_roce_accl_get *resp =
		(struct xsc_roce_accl_get *)data;

	resp->sr_timeout = __be64_to_cpu(resp->sr_timeout);
	resp->sr_count = __be16_to_cpu(resp->sr_count);
	resp->sr_drop_limit = __be16_to_cpu(resp->sr_drop_limit);
	resp->ndp_dst_port = __be16_to_cpu(resp->ndp_dst_port);

	resp->cont_sport_start = __be16_to_cpu(resp->cont_sport_start);
	resp->max_num_exponent = __be16_to_cpu(resp->max_num_exponent);
	resp->disturb_period = __be16_to_cpu(resp->disturb_period);
	resp->disturb_th = __be16_to_cpu(resp->disturb_th);
}

static void encode_roce_accl_get(void *data, u32 mac_port)
{
	u8 *resp = (u8 *)data;

	*resp = mac_port;
}

static void encode_roce_accl_disc_sport_set(void *data, u32 mac_port)
{
	int i;
	struct xsc_roce_accl_disc_sport *req =
		(struct xsc_roce_accl_disc_sport *)data;

	for (i = 0; i < req->discrete_sports_num; i++)
		req->discrete_sports[i] = __cpu_to_be16(req->discrete_sports[i]);

	req->discrete_sports_num = __cpu_to_be32(req->discrete_sports_num);
	req->mac_port = mac_port;
}

static void decode_roce_accl_disc_sport_get(void *data)
{
	int i;
	struct xsc_roce_accl_disc_sport *resp =
		(struct xsc_roce_accl_disc_sport *)data;

	resp->discrete_sports_num = __be32_to_cpu(resp->discrete_sports_num);

	if (resp->discrete_sports_num > XSC_DISCRETE_SPORT_NUM_MAX) {
		pr_err("sports_num:%u, out of range\n", resp->discrete_sports_num);
		return;
	}

	for (i = 0; i < resp->discrete_sports_num; i++)
		resp->discrete_sports[i] = __be16_to_cpu(resp->discrete_sports[i]);
}

static void encode_perf_rate_measure(void *data, u32 mac_port)
{
	struct xsc_perf_rate_measure *rate_m = (struct xsc_perf_rate_measure *)data;
	int i;

	rate_m->qp_num = __cpu_to_be32(rate_m->qp_num);
	rate_m->hw_ts = __cpu_to_be32(rate_m->hw_ts);
	for (i = 0; i < XSC_QP_MEASURE_QP_NUM_MAX; i++) {
		rate_m->qp_id_list[i] = __cpu_to_be32(rate_m->qp_id_list[i]);
		rate_m->qp_byte_cnt[i] = __cpu_to_be32(rate_m->qp_byte_cnt[i]);
	}
}

static void decode_perf_rate_measure(void *data)
{
	struct xsc_perf_rate_measure *rate_m = (struct xsc_perf_rate_measure *)data;
	int i;

	rate_m->qp_num = __be32_to_cpu(rate_m->qp_num);
	rate_m->hw_ts = __be32_to_cpu(rate_m->hw_ts);
	for (i = 0; i < XSC_QP_MEASURE_QP_NUM_MAX; i++) {
		rate_m->qp_id_list[i] = __be32_to_cpu(rate_m->qp_id_list[i]);
		rate_m->qp_byte_cnt[i] = __be32_to_cpu(rate_m->qp_byte_cnt[i]);
	}
}

static void encode_roce_accl_next_set(void *data, u32 mac_port)
{
	struct xsc_roce_accl_next_set *req =
		(struct xsc_roce_accl_next_set *)data;
	int i;

	req->flag = __cpu_to_be64(req->flag);
	req->sack_threshold = __cpu_to_be32(req->sack_threshold);
	req->sack_timeout = __cpu_to_be32(req->sack_timeout);
	req->ack_aggregation_mode = __cpu_to_be32(req->ack_aggregation_mode);
	req->ack_aggregation_req_threshold = __cpu_to_be32(req->ack_aggregation_req_threshold);
	req->ack_aggregation_rsp_window = __cpu_to_be32(req->ack_aggregation_rsp_window);
	req->ack_aggregation_rsp_timeout = __cpu_to_be32(req->ack_aggregation_rsp_timeout);
	req->path_num = __cpu_to_be32(req->path_num);
	req->packet_spray_mode = __cpu_to_be32(req->packet_spray_mode);
	req->qp_id = __cpu_to_be32(req->qp_id);
	req->path_udp_sport_num = __cpu_to_be32(req->path_udp_sport_num);
	for (i = 0; i < ROCE_ACCL_NEXT_PATH_UDP_SPORT_NUM_MAX; i++)
		req->path_udp_sport[i] = __cpu_to_be32(req->path_udp_sport[i]);
}

static void decode_roce_accl_next_get_sport(void *data)
{
	struct xsc_roce_accl_next_set *resp =
		(struct xsc_roce_accl_next_set *)data;
	int i;

	resp->sack_threshold = __be32_to_cpu(resp->sack_threshold);
	resp->sack_timeout = __be32_to_cpu(resp->sack_timeout);
	resp->ack_aggregation_mode = __be32_to_cpu(resp->ack_aggregation_mode);
	resp->ack_aggregation_req_threshold = __be32_to_cpu(resp->ack_aggregation_req_threshold);
	resp->ack_aggregation_rsp_window = __be32_to_cpu(resp->ack_aggregation_rsp_window);
	resp->ack_aggregation_rsp_timeout = __be32_to_cpu(resp->ack_aggregation_rsp_timeout);
	resp->path_num = __be32_to_cpu(resp->path_num);
	resp->packet_spray_mode = __be32_to_cpu(resp->packet_spray_mode);
	resp->qp_id = __be32_to_cpu(resp->qp_id);
	resp->path_udp_sport_num = __be32_to_cpu(resp->path_udp_sport_num);
	for (i = 0; i < ROCE_ACCL_NEXT_PATH_UDP_SPORT_NUM_MAX; i++)
		resp->path_udp_sport[i] = __be32_to_cpu(resp->path_udp_sport[i]);
}

static void decode_roce_accl_next_get(void *data)
{
	struct xsc_roce_accl_next_get *resp =
		(struct xsc_roce_accl_next_get *)data;

	resp->sack_threshold = __be32_to_cpu(resp->sack_threshold);
	resp->sack_timeout = __be32_to_cpu(resp->sack_timeout);
	resp->ack_aggregation_mode = __be32_to_cpu(resp->ack_aggregation_mode);
	resp->ack_aggregation_req_threshold = __be32_to_cpu(resp->ack_aggregation_req_threshold);
	resp->ack_aggregation_rsp_window = __be32_to_cpu(resp->ack_aggregation_rsp_window);
	resp->ack_aggregation_rsp_timeout = __be32_to_cpu(resp->ack_aggregation_rsp_timeout);
	resp->path_num = __be32_to_cpu(resp->path_num);
	resp->packet_spray_mode = __be32_to_cpu(resp->packet_spray_mode);
}

static void encode_flexcc_next_set(void *data, u32 mac_port)
{
	struct yun_cc_next_cmd_hdr *req =
		(struct yun_cc_next_cmd_hdr *)data;
	u32 tmp;

	switch (req->cmd) {
	case YUN_CC_CMD_SET_SP_TH:
		((struct yun_cc_next_sp_th *)req->data)->threshold =
			cpu_to_be32(((struct yun_cc_next_sp_th *)req->data)->threshold);
		break;
	case YUN_CC_CMD_SET_RTT_INTERVAL_INBAND:
		tmp = ((struct yun_cc_next_rtt_interval_inband *)req->data)->interval;
		((struct yun_cc_next_rtt_interval_inband *)req->data)->interval =
			cpu_to_be32(tmp);
		break;
	case YUN_CC_CMD_SET_RTT_INTERVAL_OUTBAND:
		tmp = ((struct yun_cc_next_rtt_interval_outband *)req->data)->interval;
		((struct yun_cc_next_rtt_interval_outband *)req->data)->interval =
			cpu_to_be32(tmp);
		break;
	case YUN_CC_CMD_SET_BYTE_RST_INTERVAL:
		tmp = ((struct yun_cc_next_byte_rst_interval *)req->data)->interval;
		((struct yun_cc_next_byte_rst_interval *)req->data)->interval =
			cpu_to_be32(tmp);
		break;
	case YUN_CC_CMD_SET_BWU_INTERVAL:
		tmp =  ((struct yun_cc_next_bwu_interval *)req->data)->interval;
		((struct yun_cc_next_bwu_interval *)req->data)->interval =
			cpu_to_be32(tmp);
		break;
	case YUN_CC_CMD_SET_CSP_DSCP:
		((struct yun_cc_next_csp_dscp *)req->data)->dscp =
			cpu_to_be32(((struct yun_cc_next_csp_dscp *)req->data)->dscp);
		break;
	case YUN_CC_CMD_SET_RTT_DSCP_OUTBAND:
		tmp = ((struct yun_cc_next_rtt_dscp_outband *)req->data)->dscp;
		((struct yun_cc_next_rtt_dscp_outband *)req->data)->dscp =
			cpu_to_be32(tmp);
		break;
	case YUN_CC_CMD_SET_CSP_ECN_AGGREGATION:
		((struct yun_cc_csp_ecn_aggregation *)req->data)->agg =
			cpu_to_be32(((struct yun_cc_csp_ecn_aggregation *)req->data)->agg);
		break;
	case YUN_CC_CMD_SET_CC_ALG:
		((struct yun_cc_next_cc_alg *)req->data)->user_alg_en =
			cpu_to_be32(((struct yun_cc_next_cc_alg *)req->data)->user_alg_en);
		((struct yun_cc_next_cc_alg *)req->data)->slot_mask =
			cpu_to_be32(((struct yun_cc_next_cc_alg *)req->data)->slot_mask);
		((struct yun_cc_next_cc_alg *)req->data)->slot =
			cpu_to_be32(((struct yun_cc_next_cc_alg *)req->data)->slot);
		break;
	case YUN_CC_CMD_SET_ENABLE:
		((struct yun_cc_enable *)req->data)->en =
			cpu_to_be32(((struct yun_cc_enable *)req->data)->en);
		break;
	case YUN_CC_CMD_SET_CE_PROC_INTERVAL:
		((struct yun_cc_next_ce_proc_interval *)req->data)->interval =
			cpu_to_be32(((struct yun_cc_next_ce_proc_interval *)req->data)->interval);
		break;
	}
}

static void decode_flexcc_next_get(void *data)
{
	struct yun_cc_next_get_all *resp =
		(struct yun_cc_next_get_all *)data;

	resp->sp_threshold = __be32_to_cpu(resp->sp_threshold);
	resp->rtt_interval_inband = __be32_to_cpu(resp->rtt_interval_inband);
	resp->rtt_interval_outband = __be32_to_cpu(resp->rtt_interval_outband);
	resp->byte_rst_interval = __be32_to_cpu(resp->byte_rst_interval);
	resp->bwu_interval = __be32_to_cpu(resp->bwu_interval);
	resp->csp_dscp = __be32_to_cpu(resp->csp_dscp);
	resp->rtt_dscp_outband = __be32_to_cpu(resp->rtt_dscp_outband);
	resp->csp_ecn_aggregation = __be32_to_cpu(resp->csp_ecn_aggregation);
	resp->enable = __be32_to_cpu(resp->enable);
	resp->ce_proc_interval = __be32_to_cpu(resp->ce_proc_interval);
	resp->cc_alg = __be32_to_cpu(resp->cc_alg);
	resp->cc_alg_mask = __be32_to_cpu(resp->cc_alg_mask);
}

static void decode_flexcc_next_get_stat(void *data)
{
	struct yun_cc_next_get_all_stat *resp =
		(struct yun_cc_next_get_all_stat *)data;

	resp->evt_sp_deliverd = __be32_to_cpu(resp->evt_sp_deliverd);
	resp->evt_ce_deliverd = __be32_to_cpu(resp->evt_ce_deliverd);
	resp->evt_rtt_req_deliverd = __be32_to_cpu(resp->evt_rtt_req_deliverd);
	resp->evt_rtt_rsp_deliverd = __be32_to_cpu(resp->evt_rtt_rsp_deliverd);
	resp->evt_rto_deliverd = __be32_to_cpu(resp->evt_rto_deliverd);
	resp->evt_sack_deliverd = __be32_to_cpu(resp->evt_sack_deliverd);
	resp->evt_byte_deliverd = __be32_to_cpu(resp->evt_byte_deliverd);
	resp->evt_time_deliverd = __be32_to_cpu(resp->evt_time_deliverd);
	resp->evt_bwu_deliverd = __be32_to_cpu(resp->evt_bwu_deliverd);
	resp->evt_sp_aggregated = __be32_to_cpu(resp->evt_sp_aggregated);
	resp->evt_ce_aggregated = __be32_to_cpu(resp->evt_ce_aggregated);
	resp->evt_rtt_req_aggregated = __be32_to_cpu(resp->evt_rtt_req_aggregated);
	resp->evt_rtt_rsp_aggregated = __be32_to_cpu(resp->evt_rtt_rsp_aggregated);
	resp->evt_rto_aggregated = __be32_to_cpu(resp->evt_rto_aggregated);
	resp->evt_sack_aggregated = __be32_to_cpu(resp->evt_sack_aggregated);
	resp->evt_byte_aggregated = __be32_to_cpu(resp->evt_byte_aggregated);
	resp->evt_time_aggregated = __be32_to_cpu(resp->evt_time_aggregated);
	resp->evt_bwu_aggregated = __be32_to_cpu(resp->evt_bwu_aggregated);
	resp->evt_sp_dropped = __be32_to_cpu(resp->evt_sp_dropped);
	resp->evt_ce_dropped = __be32_to_cpu(resp->evt_ce_dropped);
	resp->evt_rtt_req_dropped = __be32_to_cpu(resp->evt_rtt_req_dropped);
	resp->evt_rtt_rsp_dropped = __be32_to_cpu(resp->evt_rtt_rsp_dropped);
	resp->evt_rto_dropped = __be32_to_cpu(resp->evt_rto_dropped);
	resp->evt_sack_dropped = __be32_to_cpu(resp->evt_sack_dropped);
	resp->evt_byte_dropped = __be32_to_cpu(resp->evt_byte_dropped);
	resp->evt_time_dropped = __be32_to_cpu(resp->evt_time_dropped);
	resp->evt_bwu_dropped = __be32_to_cpu(resp->evt_bwu_dropped);
}

static int xsc_get_port_pfc(struct xsc_core_device *xdev, u8 *pfc, u8 pfc_size)
{
	int err = 0;
	struct xsc_pfc_get rsp;

	memset(&rsp, 0, sizeof(struct xsc_pfc_get));

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_PFC, NULL, &rsp);
	if (err) {
		xsc_core_err(xdev, "failed to get pfc, err: %d\n", err);
		return err;
	}

	memcpy(pfc, rsp.pfc_on, pfc_size);

	return 0;
}

static int xsc_set_port_pfc_drop_th(struct xsc_core_device *xdev, u8 prio, u8 cfg_type)
{
	int err = 0;
	struct xsc_pfc_set_drop_th_mbox_in req;
	struct xsc_pfc_set_drop_th_mbox_out rsp;

	memset(&req, 0, sizeof(struct xsc_pfc_set_drop_th_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_pfc_set_drop_th_mbox_out));

	req.prio = prio;
	req.cfg_type = cfg_type;
	req.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_IOCTL_SET_PFC_DROP_TH);

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_PFC_DROP_TH, &req, &rsp);
	if (err) {
		xsc_core_err(xdev,
			     "failed to set pfc drop th, err: %d, prio: %d, cfg_type: %d\n",
			     err, prio, cfg_type);
		return err;
	}

	return 0;
}

static int xsc_set_drop_th(struct xsc_core_device *xdev,
			   const struct xsc_pfc_cfg *pfc_cfg,
			   u8 cfg_type)
{
	int err = 0;

	if (cfg_type == DROP_TH_CLEAR) {
		err = xsc_set_port_pfc_drop_th(xdev, pfc_cfg->req_prio, cfg_type);
		if (pfc_cfg->pfc_op == PFC_OP_MODIFY)
			err |= xsc_set_port_pfc_drop_th(xdev, pfc_cfg->curr_prio, cfg_type);
	} else if (cfg_type == DROP_TH_RECOVER) {
		if (pfc_cfg->pfc_op == PFC_OP_DISABLE) {
			err = xsc_set_port_pfc_drop_th(xdev,
						       pfc_cfg->req_prio,
						       DROP_TH_RECOVER_LOSSY);
		} else if (pfc_cfg->pfc_op == PFC_OP_ENABLE) {
			err = xsc_set_port_pfc_drop_th(xdev,
						       pfc_cfg->req_prio,
						       DROP_TH_RECOVER_LOSSLESS);
		} else if (pfc_cfg->pfc_op == PFC_OP_MODIFY) {
			err = xsc_set_port_pfc_drop_th(xdev,
						       pfc_cfg->req_prio,
						       DROP_TH_RECOVER_LOSSLESS);
			err |= xsc_set_port_pfc_drop_th(xdev,
							pfc_cfg->curr_prio,
							DROP_TH_RECOVER_LOSSY);
		}
	}

	return err;
}

static int xsc_get_port_pfc_cfg_status(struct xsc_core_device *xdev, u8 prio, int *status)
{
	int err = 0;
	struct xsc_pfc_get_cfg_status_mbox_in req;
	struct xsc_pfc_get_cfg_status_mbox_out rsp;

	memset(&req, 0, sizeof(struct xsc_pfc_get_cfg_status_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_pfc_get_cfg_status_mbox_out));

	req.prio = prio;
	req.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS);

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS, &req, &rsp);
	if (err) {
		xsc_core_err(xdev, "failed to get pfc cfg status, err: %d, prio: %d\n", err, prio);
		return err;
	}

	*status = rsp.hdr.status;

	return 0;
}

static int xsc_get_cfg_status(struct xsc_core_device *xdev,
			      struct xsc_pfc_cfg *pfc_cfg,
			      int *status)
{
	int err = 0;

	err = xsc_get_port_pfc_cfg_status(xdev, pfc_cfg->req_prio, status);
	if (pfc_cfg->pfc_op == PFC_OP_MODIFY)
		err |= xsc_get_port_pfc_cfg_status(xdev, pfc_cfg->curr_prio, status);

	return err;
}

static int xsc_wait_pfc_check_complete(struct xsc_core_device *xdev,
				       struct xsc_pfc_cfg *pfc_cfg)
{
	int err = 0;
	int status = 0;
	u32 valid_cnt = 0;
	u32 retry_cnt = 0;

	while (retry_cnt < PFC_CFG_CHECK_MAX_RETRY_TIMES) {
		err = xsc_get_cfg_status(xdev, pfc_cfg, &status);

		if (err || status) {
			valid_cnt = 0;
		} else {
			valid_cnt++;
			if (valid_cnt >= PFC_CFG_CHECK_VALID_CNT)
				break;
		}

		retry_cnt++;
		usleep_range(PFC_CFG_CHECK_SLEEP_TIME_US,
			     PFC_CFG_CHECK_SLEEP_TIME_US + 1);
	}

	if (retry_cnt >= PFC_CFG_CHECK_MAX_RETRY_TIMES) {
		xsc_core_err(xdev, "pfc check timeout, req_prio: %d, curr_prio:%d\n",
			     pfc_cfg->req_prio, pfc_cfg->curr_prio);
		err = -EFAULT;
	}

	return err | status;
}

static int xsc_set_port_pfc(struct xsc_core_device *xdev, u8 prio,
			    u8 pfc_on, u8 pfc_op, u8 *lossless_num)
{
	int err = 0;
	struct xsc_pfc_set req;
	struct xsc_pfc_set rsp;

	memset(&req, 0, sizeof(struct xsc_pfc_set));
	req.priority = prio;
	req.pfc_on = pfc_on;
	req.type = pfc_op;

	err = xsc_hw_kernel_call(xdev, XSC_CMD_OP_IOCTL_SET_PFC, &req, &rsp);
	if (err) {
		xsc_core_err(xdev, "failed to set pfc, err: %d, prio: %d, pfc_on: %d\n",
			     err, prio, pfc_on);
		return err;
	}

	*lossless_num = rsp.lossless_num;

	return 0;
}

static int xsc_set_pfc(struct xsc_core_device *xdev, struct xsc_pfc_cfg *pfc_cfg)
{
	int err = 0;
	u8 lossless_num = LOSSLESS_NUM_INVALID;

	switch (pfc_cfg->pfc_op) {
	case PFC_OP_DISABLE:
		err = xsc_set_port_pfc(xdev, pfc_cfg->req_prio, NIF_PFC_EN_OFF,
				       pfc_cfg->pfc_op, &lossless_num);
		break;
	case PFC_OP_ENABLE:
		err = xsc_set_port_pfc(xdev, pfc_cfg->req_prio, NIF_PFC_EN_ON,
				       pfc_cfg->pfc_op, &lossless_num);
		break;
	case PFC_OP_MODIFY:
		err = xsc_set_port_pfc(xdev, pfc_cfg->curr_prio, NIF_PFC_EN_OFF,
				       pfc_cfg->pfc_op, &lossless_num);
		err |= xsc_set_port_pfc(xdev, pfc_cfg->req_prio, NIF_PFC_EN_ON,
					pfc_cfg->pfc_op, &lossless_num);
		break;
	default:
		xsc_core_err(xdev, "unsupported pfc operation: %d\n", pfc_cfg->pfc_op);
		err = -EINVAL;
	}

	pfc_cfg->lossless_num = lossless_num;
	return err;
}

static int handle_pfc_cfg(struct xsc_core_device *xdev,
			  struct xsc_qos_mbox_in *in, int in_size,
			  struct xsc_qos_mbox_out *out, int out_size)
{
	const struct xsc_pfc_set *req = (struct xsc_pfc_set *)in->data;
	struct xsc_pfc_set *rsp = (struct xsc_pfc_set *)out->data;
	struct xsc_pfc_cfg pfc_cfg;
	u8 curr_pfc[PFC_PRIO_MAX + 1] = {0};
	int idx;
	int err = 0;
	bool invalid_op = false;

	if (!mutex_trylock(&pfc_mutex)) {
		xsc_core_err(xdev, "pfc is configuring by other user\n");
		return -EBUSY;
	}

	memcpy(rsp, req, sizeof(struct xsc_pfc_set));
	memset(&pfc_cfg, 0, sizeof(struct xsc_pfc_cfg));

	if (req->priority < 0 || req->priority > PFC_PRIO_MAX) {
		xsc_core_err(xdev, "invalid req priority: %d\n", req->priority);
		err = -EINVAL;
		goto err_process;
	}

	pfc_cfg.req_prio = req->priority;
	pfc_cfg.req_pfc_en = req->pfc_on;
	pfc_cfg.curr_pfc_en = 0;
	pfc_cfg.pfc_op = PFC_OP_TYPE_MAX;
	pfc_cfg.lossless_num = LOSSLESS_NUM_INVALID;

	err = xsc_get_port_pfc(xdev, curr_pfc, sizeof(curr_pfc));
	if (err)
		goto err_process;

	for (idx = 0; idx < PFC_PRIO_MAX + 1; idx++) {
		if (curr_pfc[idx] == NIF_PFC_EN_ON) {
			pfc_cfg.curr_prio = idx;
			pfc_cfg.curr_pfc_en = 1;
			break;
		}
	}

	if (pfc_cfg.curr_pfc_en && pfc_cfg.req_pfc_en) {
		if (pfc_cfg.curr_prio != pfc_cfg.req_prio)
			pfc_cfg.pfc_op = PFC_OP_MODIFY;
		else
			invalid_op = true;
	} else if (pfc_cfg.curr_pfc_en && !pfc_cfg.req_pfc_en) {
		if (pfc_cfg.curr_prio == pfc_cfg.req_prio)
			pfc_cfg.pfc_op = PFC_OP_DISABLE;
		else
			invalid_op = true;
	} else if (!pfc_cfg.curr_pfc_en && pfc_cfg.req_pfc_en) {
		pfc_cfg.pfc_op = PFC_OP_ENABLE;
	} else {
		invalid_op = true;
	}

	if (invalid_op) {
		xsc_core_err(xdev, "invalid operation, req_pfc_cfg:%d,%d curr_pfc_cfg:%d,%d\n",
			     pfc_cfg.req_prio, pfc_cfg.req_pfc_en,
			     pfc_cfg.curr_prio, pfc_cfg.curr_pfc_en);
		err = 0;
		goto err_process;
	}

	xsc_core_dbg(xdev, "req_pfc_cfg:%d, %d curr_pfc_cfg: %d,%d, pfc_op: %d\n",
		     pfc_cfg.req_prio, pfc_cfg.req_pfc_en,
		     pfc_cfg.curr_prio, pfc_cfg.curr_pfc_en, pfc_cfg.pfc_op);

	err = xsc_set_drop_th(xdev, &pfc_cfg, DROP_TH_CLEAR);
	if (err)
		goto err_process;

	err = xsc_wait_pfc_check_complete(xdev, &pfc_cfg);
	if (!err)
		err = xsc_set_pfc(xdev, &pfc_cfg);

	err |= xsc_set_drop_th(xdev, &pfc_cfg, DROP_TH_RECOVER);

err_process:
	mutex_unlock(&pfc_mutex);

	if (pfc_cfg.pfc_op == PFC_OP_MODIFY)
		rsp->src_prio = pfc_cfg.curr_prio;
	else
		rsp->src_prio = pfc_cfg.req_prio;

	rsp->lossless_num = pfc_cfg.lossless_num;
	rsp->type = pfc_cfg.pfc_op;
	out->hdr.status = err;
	xsc_core_dbg(xdev, "response lossless_num: %d, src_prio: %d, type: %d, hdr status: %d\n",
		     rsp->lossless_num, rsp->src_prio, rsp->type, out->hdr.status);
	return err;
}

static void xsc_get_pfc_cfg_status(struct xsc_core_device *xdev,
				   u8 mac_port, u8 *status, u8 *comp,
				   u8 tunnel_cmd, struct xsc_ioctl_tunnel_hdr *tunnel_hdr)
{
	struct xsc_get_pfc_cfg_status_mbox_in req;
	struct xsc_get_pfc_cfg_status_mbox_out rsp;

	memset(&req, 0, sizeof(struct xsc_get_pfc_cfg_status_mbox_in));
	memset(&rsp, 0, sizeof(struct xsc_get_pfc_cfg_status_mbox_out));

	req.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS_NEW);
	req.mac_port = mac_port;

	if (tunnel_cmd)
		xsc_tunnel_cmd_exec(xdev,
				    &req, sizeof(struct xsc_get_pfc_cfg_status_mbox_in),
				    &rsp, sizeof(struct xsc_get_pfc_cfg_status_mbox_out),
				    tunnel_hdr);
	else
		xsc_cmd_exec(xdev,
			     &req, sizeof(struct xsc_get_pfc_cfg_status_mbox_in),
			     &rsp, sizeof(struct xsc_get_pfc_cfg_status_mbox_out));
	*status = rsp.status;
	*comp = rsp.comp;
}

static int handle_pfc_cfg_new(struct xsc_core_device *xdev,
			      struct xsc_qos_mbox_in *in, int in_size,
			      struct xsc_qos_mbox_out *out, int out_size,
			      u8 tunnel_cmd, struct xsc_ioctl_tunnel_hdr *tunnel_hdr)
{
	const struct xsc_pfc_set_new *req = (struct xsc_pfc_set_new *)in->data;
	u8 mac_port = in->req_prfx.mac_port;
	int err = 0;
	u8 status = SET_PFC_STATUS_MAX, comp = SET_PFC_COMP_MAX;
	u32 timeout_cnt = 0;

	if (req->req_prio < 0 || req->req_prio > PFC_PRIO_MAX) {
		xsc_core_err(xdev,
			     "PFC cfg fail, req invalid req_prio: %d\n",
			     req->req_prio);
		out->hdr.status = EINVAL;

		return -EINVAL;
	}
	if (tunnel_cmd)
		err = xsc_tunnel_cmd_exec(xdev, in, in_size, out, out_size, tunnel_hdr);
	else
		err = xsc_cmd_exec(xdev, in, in_size, out, out_size);
	if (out->hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED) {
		xsc_core_dbg(xdev,
			     "PFC cfg not support, status: %d\n",
			     out->hdr.status);
		return err;
	} else if (out->hdr.status == 0) {
		xsc_core_dbg(xdev,
			     "PFC cfg not required\n");
		return 0;
	} else if (out->hdr.status == EAGAIN) {
		xsc_core_dbg(xdev,
			     "Try agine\n");
		return err;
	} else if (out->hdr.status == EINPROGRESS) {
		xsc_core_dbg(xdev, "PFC cfg in process\n");
	}

	timeout_cnt = 0;
	msleep(PFC_CFG_CHECK_SLEEP_TIME_MS);
	while (timeout_cnt < PFC_CFG_CHECK_TIMEOUT_CNT) {
		xsc_get_pfc_cfg_status(xdev, mac_port, &status, &comp, tunnel_cmd, tunnel_hdr);
		if (status == SET_PFC_STATUS_INIT &&
		    comp == SET_PFC_COMP_TIMEOUT) {
			err = -ETIMEDOUT;
			out->hdr.status = ETIMEDOUT;
			xsc_core_dbg(xdev,
				     "PFC cfg timeout, rsp hdr status: %d\n",
				     out->hdr.status);
			break;
		} else if (status == SET_PFC_STATUS_INIT &&
			   comp == SET_PFC_COMP_SUCCESS) {
			err = 0;
			out->hdr.status = 0;
			xsc_core_dbg(xdev, "PFC cfg success");
			break;
		} else if (status == SET_PFC_STATUS_IN_PROCESS) {
			timeout_cnt++;
			msleep(PFC_CFG_CHECK_SLEEP_TIME_MS);
		}
	}

	if (timeout_cnt == PFC_CFG_CHECK_TIMEOUT_CNT) {
		err = -ETIMEDOUT;
		out->hdr.status = ETIMEDOUT;
		xsc_core_dbg(xdev,
			     "PFC cfg timeout, rsp hdr status: %d\n",
			     out->hdr.status);
	}

	return err;
}

static int _eth_ctrl_ioctl_pfc(struct xsc_core_device *xdev,
			       struct xsc_ioctl_hdr __user *user_hdr,
			       struct xsc_ioctl_hdr *hdr,
			       u16 expect_req_size,
			       u16 expect_resp_size,
			       void (*encode)(void *, u32),
			       void (*decode)(void *))
{
	struct xsc_qos_mbox_in *in;
	struct xsc_qos_mbox_out *out;
	u16 user_size;
	int err;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr = {0};

	if (hdr->attr.tunnel_cmd)
		hdr->attr.length -= sizeof(tunnel_hdr);

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	if (hdr->attr.tunnel_cmd) {
		err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
		if (err)
			goto err;
		err = copy_from_user(&in->data, user_hdr->attr.data + sizeof(tunnel_hdr),
				     expect_req_size);
		if (err)
			goto err;
	} else {
		err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
		if (err)
			goto err;
	}

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->req_prfx.mac_port = xdev->mac_port;

	if (encode)
		encode((void *)in->data, xdev->mac_port);

	if (hdr->attr.opcode == XSC_CMD_OP_IOCTL_SET_PFC)
		err = handle_pfc_cfg(xdev, in, sizeof(*in) + expect_req_size, out,
				     sizeof(*out) + expect_resp_size);
	else
		err = handle_pfc_cfg_new(xdev, in, sizeof(*in) + expect_req_size, out,
					 sizeof(*out) + expect_resp_size,
					 hdr->attr.tunnel_cmd, &tunnel_hdr);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _eth_ctrl_ioctl_qos(struct xsc_core_device *xdev,
			       struct xsc_ioctl_hdr __user *user_hdr,
			       struct xsc_ioctl_hdr *hdr,
			       u16 expect_req_size,
			       u16 expect_resp_size,
			       void (*encode)(void *, u32),
			       void (*decode)(void *))
{
	struct xsc_qos_mbox_in *in;
	struct xsc_qos_mbox_out *out;
	u16 user_size;
	int err;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr = {0};

	if (hdr->attr.tunnel_cmd)
		hdr->attr.length -= sizeof(tunnel_hdr);
	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	if (hdr->attr.tunnel_cmd) {
		err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
		if (err)
			goto err;
		err = copy_from_user(&in->data, user_hdr->attr.data + sizeof(tunnel_hdr),
				     expect_req_size);
		if (err)
			goto err;
	} else {
		err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
		if (err)
			goto err;
	}

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	in->req_prfx.mac_port = xdev->mac_port;

	if (encode)
		encode((void *)in->data, xdev->mac_port);

	if (hdr->attr.tunnel_cmd)
		err = xsc_tunnel_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
					  sizeof(*out) + expect_resp_size, &tunnel_hdr);
	else
		err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
				   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _eth_ctrl_ioctl_hwconfig(struct xsc_core_device *xdev,
				    struct xsc_ioctl_hdr __user *user_hdr,
				    struct xsc_ioctl_hdr *hdr,
				    u16 expect_req_size,
				    u16 expect_resp_size,
				    void (*encode)(void *, u32),
				    void (*decode)(void *))
{
	struct xsc_hwc_mbox_in *in;
	struct xsc_hwc_mbox_out *out;
	u16 user_size;
	int err;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.tunnel_cmd)
		hdr->attr.length -= sizeof(tunnel_hdr);
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	if (hdr->attr.tunnel_cmd) {
		err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
		if (err)
			goto err;
		err = copy_from_user(&in->data, user_hdr->attr.data + sizeof(tunnel_hdr),
				     expect_req_size);
		if (err)
			goto err;
	} else {
		err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
		if (err)
			goto err;
	}

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	if (hdr->attr.tunnel_cmd)
		err = xsc_tunnel_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
					  sizeof(*out) + expect_resp_size, &tunnel_hdr);
	else
		err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
				   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;

	if (err)
		goto err;

	if (out->hdr.status)
		xsc_core_info(xdev, "hwconfig, rsp hdr status: %d\n",
			      out->hdr.status);

	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _eth_ctrl_ioctl_roce_accl(struct xsc_core_device *xdev,
				     struct xsc_ioctl_hdr __user *user_hdr,
				     struct xsc_ioctl_hdr *hdr,
				     u16 expect_req_size,
				     u16 expect_resp_size,
				     void (*encode)(void *, u32),
				     void (*decode)(void *))
{
	struct xsc_roce_accl_mbox_in *in;
	struct xsc_roce_accl_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _eth_ctrl_ioctl_rate_measure(struct xsc_core_device *xdev,
					struct xsc_ioctl_hdr __user *user_hdr,
					struct xsc_ioctl_hdr *hdr,
					u16 expect_req_size,
					u16 expect_resp_size,
					void (*encode)(void *, u32),
					void (*decode)(void *))
{
	struct xsc_perf_mbox_in *in;
	struct xsc_perf_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _eth_ctrl_ioctl_roce_accl_next(struct xsc_core_device *xdev,
					  struct xsc_ioctl_hdr __user *user_hdr,
					  struct xsc_ioctl_hdr *hdr,
					  u16 expect_req_size,
					  u16 expect_resp_size,
					  void (*encode)(void *, u32),
					  void (*decode)(void *))
{
	struct xsc_roce_accl_next_mbox_in *in;
	struct xsc_roce_accl_next_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int xsc_ioctl_netlink_cmd(struct xsc_core_device *xdev,
				 struct xsc_ioctl_hdr __user *user_hdr,
				 struct xsc_ioctl_hdr *hdr)
{
	u8 *nlmsg;
	int nlmsg_len;
	int err = 0;
	struct xsc_cmd_netlink_msg_mbox_in *in;
	struct xsc_cmd_netlink_msg_mbox_out out;
	int inlen;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;

	nlmsg_len = hdr->attr.length;
	nlmsg = kvzalloc(nlmsg_len, GFP_KERNEL);
	if (!nlmsg)
		return -ENOMEM;

	err = copy_from_user(nlmsg, user_hdr->attr.data, nlmsg_len);
	if (err)
		goto err;

	inlen = sizeof(*in) + nlmsg_len;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		goto err;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_IOCTL_NETLINK);
	in->nlmsg_len = cpu_to_be16(nlmsg_len);
	memcpy(in->data, nlmsg, nlmsg_len);
	memset(&tunnel_hdr, 0, sizeof(tunnel_hdr));
	err = xsc_tunnel_cmd_exec(xdev, in, inlen, &out, sizeof(out), &tunnel_hdr);

	kvfree(in);
	kvfree(nlmsg);

	if (err || out.hdr.status)
		err = -EFAULT;

	return err;
err:
	kvfree(nlmsg);
	return -EFAULT;
}

void xsc_handle_netlink_cmd(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_cmd_netlink_msg_mbox_in *_in = in;
	struct xsc_cmd_netlink_msg_mbox_out *_out = out;
	u8 *nlmsg = _in->data;
	int nlmsg_len = _in->nlmsg_len;
	int err;
	struct socket *sock = xdev->sock;
	struct kvec iov[1];
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	iov[0].iov_base = nlmsg;
	iov[0].iov_len = nlmsg_len;
	err = kernel_sendmsg(sock, &msg, iov, 1, nlmsg_len);
	_out->hdr.status = err;
}

static int _eth_ctrl_ioctl_flexcc_next(struct xsc_core_device *xdev,
				       struct xsc_ioctl_hdr __user *user_hdr,
				       struct xsc_ioctl_hdr *hdr,
				       u16 expect_req_size,
				       u16 expect_resp_size,
				       void (*encode)(void *, u32),
				       void (*decode)(void *))
{
	struct xsc_flexcc_next_mbox_in *in;
	struct xsc_flexcc_next_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (user_size > YUN_CC_CMD_DATA_LEN_MAX)
		return -EINVAL;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static long _eth_ctrl_ioctl_cmdq(struct xsc_core_device *xdev,
				 struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	int err;
	void *in;
	void *out;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_SET_DSCP_PMT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_dscp_pmt_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_DSCP_PMT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_dscp_pmt_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_TRUST_MODE:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_trust_mode_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_TRUST_MODE:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_trust_mode_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_PCP_PMT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_pcp_pmt_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_PCP_PMT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_pcp_pmt_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_DEFAULT_PRI:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_default_pri_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_DEFAULT_PRI:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_default_pri_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_PFC:
	case XSC_CMD_OP_IOCTL_SET_PFC_NEW:
		return _eth_ctrl_ioctl_pfc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_pfc_set),
					   sizeof(struct xsc_pfc_set),
					   NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_PFC:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_pfc_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_RATE_LIMIT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_rate_limit_set), 0,
					   encode_rlimit_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_RATE_LIMIT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr, sizeof(struct xsc_rate_limit_get),
					   sizeof(struct xsc_rate_limit_get),
					   NULL, decode_rlimit_get);
	case XSC_CMD_OP_IOCTL_SET_SP:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_sp_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_SP:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_sp_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_weight_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_weight_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_DPU_SET_PORT_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_dpu_port_weight_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_DPU_GET_PORT_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_dpu_port_weight_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_DPU_SET_PRIO_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_dpu_prio_weight_set), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_DPU_GET_PRIO_WEIGHT:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_dpu_prio_weight_get), NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_HWC:
		return _eth_ctrl_ioctl_hwconfig(xdev, user_hdr, &hdr,
						sizeof(struct hwc_set_t), sizeof(struct hwc_set_t),
						NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_HWC:
		return _eth_ctrl_ioctl_hwconfig(xdev, user_hdr, &hdr, sizeof(struct hwc_get_t),
						sizeof(struct hwc_get_t),
						NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_WATCHDOG_EN:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_watchdog_en_set), 0,
					   NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_WATCHDOG_EN:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_watchdog_en_get),
					   NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_WATCHDOG_PERIOD:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_watchdog_period_set), 0,
					   encode_watchdog_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_WATCHDOG_PERIOD:
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
					   0, sizeof(struct xsc_watchdog_period_get),
					   NULL, decode_watchdog_get);
	case XSC_CMD_OP_IOCTL_SET_ROCE_ACCL:
		return _eth_ctrl_ioctl_roce_accl(xdev, user_hdr, &hdr,
						 sizeof(struct xsc_roce_accl_set), 0,
						 encode_roce_accl_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_ROCE_ACCL:
		return _eth_ctrl_ioctl_roce_accl(xdev, user_hdr, &hdr,
						 sizeof(u8), sizeof(struct xsc_roce_accl_get),
						 encode_roce_accl_get, decode_roce_accl_get);
	case XSC_CMD_OP_IOCTL_SET_ROCE_ACCL_DISC_SPORT:
		return _eth_ctrl_ioctl_roce_accl(xdev, user_hdr, &hdr,
						 sizeof(struct xsc_roce_accl_disc_sport), 0,
						 encode_roce_accl_disc_sport_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_ROCE_ACCL_DISC_SPORT:
		return _eth_ctrl_ioctl_roce_accl(xdev, user_hdr, &hdr, sizeof(u8),
						 sizeof(struct xsc_roce_accl_disc_sport),
						 encode_roce_accl_get,
						 decode_roce_accl_disc_sport_get);
	case XSC_CMD_OP_IOCTL_GET_BYTE_CNT:
		return _eth_ctrl_ioctl_rate_measure(xdev, user_hdr, &hdr,
						 sizeof(struct xsc_perf_rate_measure),
						 sizeof(struct xsc_perf_rate_measure),
						 encode_perf_rate_measure,
						 decode_perf_rate_measure);
	case XSC_CMD_OP_IOCTL_SET_ROCE_ACCL_NEXT:
		return _eth_ctrl_ioctl_roce_accl_next(xdev, user_hdr, &hdr,
						 sizeof(struct xsc_roce_accl_next_set), 0,
						 encode_roce_accl_next_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_ROCE_ACCL_NEXT:
		return _eth_ctrl_ioctl_roce_accl_next(xdev, user_hdr, &hdr,
						 0, sizeof(struct xsc_roce_accl_next_get),
						 NULL, decode_roce_accl_next_get);
	case XSC_CMD_OP_IOCTL_NETLINK:
		return xsc_ioctl_netlink_cmd(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_IOCTL_GET_SPORT_ROCE_ACCL_NEXT:
		return _eth_ctrl_ioctl_roce_accl_next(xdev, user_hdr, &hdr,
						 sizeof(struct xsc_roce_accl_next_set),
						 sizeof(struct xsc_roce_accl_next_set),
						 encode_roce_accl_next_set,
						 decode_roce_accl_next_get_sport);
	case XSC_CMD_OP_IOCTL_SET_FLEXCC_NEXT:
		return _eth_ctrl_ioctl_flexcc_next(xdev, user_hdr, &hdr,
						YUN_CC_CMD_DATA_LEN_MAX, 0,
						encode_flexcc_next_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_FLEXCC_NEXT:
		return _eth_ctrl_ioctl_flexcc_next(xdev, user_hdr, &hdr,
						0, sizeof(struct yun_cc_next_get_all),
						NULL, decode_flexcc_next_get);
	case XSC_CMD_OP_IOCTL_GET_STAT_FLEXCC_NEXT:
		return _eth_ctrl_ioctl_flexcc_next(xdev, user_hdr, &hdr,
						0, sizeof(struct yun_cc_next_get_all_stat),
						NULL, decode_flexcc_next_get_stat);
	default:
		return TRY_NEXT_CB;
	}

	in = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	err = copy_from_user(in, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		err = -EFAULT;
		goto err_exit;
	}

	xsc_cmd_exec(xdev, in, hdr.attr.length, out, hdr.attr.length);

	if (copy_to_user((void *)user_hdr, &hdr, sizeof(hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, out, hdr.attr.length))
		err = -EFAULT;
err_exit:
	kfree(in);
	kfree(out);
	return err;
}

static void xsc_eth_restore_nic_hca(void *data)
{
	struct xsc_res_obj *obj = (struct xsc_res_obj *)data;
	struct xsc_bdf_file *file = obj->file;

	xsc_eth_enable_nic_hca((struct xsc_adapter *)file->xdev->eth_priv);
	xsc_free_user_mode_obj(file, XSC_IOCTL_OPCODE_VF_USER_MODE);
}

static void xsc_eth_restore_pkt_dst_info(void *data)
{
	struct xsc_res_obj *obj = (struct xsc_res_obj *)data;
	struct xsc_bdf_file *file = obj->file;
	struct xsc_user_mode_attr *attrs = (struct xsc_user_mode_attr *)obj->data;
	int i, j;

	for (i = 0; i < XSC_MAX_MAC_NUM; i++) {
		if (!attrs[i].pkt_bitmap)
			continue;

		for (j = 0; j < XSC_USER_MODE_FWD_PKT_NUM; j++) {
			if (!(attrs[i].pkt_bitmap & BIT(j)))
				continue;

			xsc_eth_modify_pkt_dst_info(file->xdev->eth_priv, BIT(i),
						    BIT(j), attrs[i].dst_info[j]);
		}
	}
	xsc_free_user_mode_obj(file, XSC_IOCTL_OPCODE_PF_USER_MODE);
}

static int xsc_change_user_mode(struct xsc_bdf_file *file, u16 opcode,
				struct xsc_ioctl_user_mode_attr *attr)
{
	struct xsc_user_mode_attr *user_attr = NULL;
	int i, err = 0;

	if (attr->enable) {
		if (opcode == XSC_IOCTL_OPCODE_VF_USER_MODE) {
			err = xsc_alloc_user_mode_obj(file, xsc_eth_restore_nic_hca,
						      opcode, (char *)attr, 0);
			goto out;
		}

		if (!attr->pkt_bitmap || !attr->mac_bitmap)
			return 0;

		user_attr = kcalloc(XSC_MAX_MAC_NUM, sizeof(struct xsc_user_mode_attr), GFP_KERNEL);
		if (unlikely(!user_attr)) {
			err = -ENOMEM;
			goto out;
		}

		for (i = 0; i < XSC_MAX_MAC_NUM; i++) {
			if (!(attr->mac_bitmap & BIT(i)))
				continue;

			user_attr[i].pkt_bitmap = attr->pkt_bitmap;
			err = xsc_eth_query_pkt_dst_info(file->xdev->eth_priv, BIT(i),
							 attr->pkt_bitmap, user_attr[i].dst_info);
			if (err)
				goto out;
		}
		err = xsc_eth_modify_pkt_dst_info(file->xdev->eth_priv, attr->mac_bitmap,
						  attr->pkt_bitmap, attr->dst_info);
		if (err)
			goto out;

		err = xsc_alloc_user_mode_obj(file, xsc_eth_restore_pkt_dst_info,
					      opcode, (char *)user_attr,
					      XSC_MAX_MAC_NUM * sizeof(struct xsc_user_mode_attr));
	} else {
		if (xsc_get_user_mode(file->xdev))
			xsc_release_user_mode(file, opcode);
	}

out:
	xsc_core_info(file->xdev,
		      "%s usr mode=0x%x, pkt=0x%x, mac=0x%x, dst_info=%d, err=%d\n",
		      attr->enable ? "enable" : "disable", opcode,
		      attr->pkt_bitmap, attr->mac_bitmap, attr->dst_info, err);
	kfree(user_attr);

	return err;
}

static int xsc_ioctl_user_mode(struct xsc_bdf_file *file, struct xsc_core_device *dev,
			       struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	struct xsc_ioctl_user_mode_attr *attr;
	u8 *buf;
	int err = 0;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err) {
		xsc_core_err(dev, "fail to copy from user hdr\n");
		return -EFAULT;
	}

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED) {
		xsc_core_err(dev, "invalid check filed %u\n", hdr.check_filed);
		return -EINVAL;
	}

	buf = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	err = copy_from_user(buf, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		xsc_core_err(dev, "failed to copy ioctl user data.\n");
		kvfree(buf);
		return -EFAULT;
	}

	attr = (struct xsc_ioctl_user_mode_attr *)buf;
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_OPCODE_VF_USER_MODE:
	case XSC_IOCTL_OPCODE_PF_USER_MODE:
		err = xsc_change_user_mode(file, hdr.attr.opcode, attr);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	kvfree(buf);
	return err;
}

static int _eth_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			    struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = _eth_ctrl_ioctl_cmdq(xdev, user_hdr);
		break;
	case XSC_IOCTL_USER_MODE:
		err = xsc_ioctl_user_mode(file, xdev, user_hdr);
		break;
	default:
		err = TRY_NEXT_CB;
		break;
	}

	return err;
}

static void _eth_ctrl_reg_fini(void)
{
	xsc_port_ctrl_cb_dereg(XSC_ETH_CTRL_NAME);
}

static int _eth_ctrl_reg_init(void)
{
	int ret;

	ret = xsc_port_ctrl_cb_reg(XSC_ETH_CTRL_NAME, _eth_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_ETH_CTRL_NAME);

	return ret;
}

static void _pfc_global_res_init(void)
{
	mutex_init(&pfc_mutex);
}

void xsc_eth_ctrl_fini(void)
{
	_eth_ctrl_reg_fini();
}

int xsc_eth_ctrl_init(void)
{
	_pfc_global_res_init();
	return _eth_ctrl_reg_init();
}

