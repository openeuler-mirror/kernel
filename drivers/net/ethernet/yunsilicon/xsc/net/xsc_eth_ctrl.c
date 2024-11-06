// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_port_ctrl.h"
#include "xsc_hw_comm.h"

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
	in->req_prfx.mac_port = xdev->mac_port;

	if (encode)
		encode((void *)in->data, xdev->mac_port);

	if (hdr->attr.opcode == XSC_CMD_OP_IOCTL_SET_PFC)
		err = handle_pfc_cfg(xdev, in, sizeof(*in) + expect_req_size, out,
				     sizeof(*out) + expect_resp_size);
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
		return _eth_ctrl_ioctl_qos(xdev, user_hdr, &hdr,
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

static int _eth_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			    struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = _eth_ctrl_ioctl_cmdq(xdev, user_hdr);
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

