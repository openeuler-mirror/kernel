// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
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
#include "global.h"
#include "xsc_ib.h"

#define XSC_RDMA_CTRL_NAME	"rdma_ctrl"

static void encode_cc_cmd_enable_rp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_rp *cc_cmd = (struct xsc_cc_cmd_enable_rp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_enable_np(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_np *cc_cmd = (struct xsc_cc_cmd_enable_np *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_init_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_init_alpha *cc_cmd = (struct xsc_cc_cmd_init_alpha *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->alpha = __cpu_to_be32(cc_cmd->alpha);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_g(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_g *cc_cmd = (struct xsc_cc_cmd_g *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->g = __cpu_to_be32(cc_cmd->g);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_ai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_ai *cc_cmd = (struct xsc_cc_cmd_ai *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ai = __cpu_to_be32(cc_cmd->ai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_hai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_hai *cc_cmd = (struct xsc_cc_cmd_hai *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->hai = __cpu_to_be32(cc_cmd->hai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_th(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_th *cc_cmd = (struct xsc_cc_cmd_th *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->threshold = __cpu_to_be32(cc_cmd->threshold);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_bc(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_bc *cc_cmd = (struct xsc_cc_cmd_bc *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bytecount = __cpu_to_be32(cc_cmd->bytecount);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_opcode(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_opcode *cc_cmd = (struct xsc_cc_cmd_cnp_opcode *)data;

	cc_cmd->opcode = __cpu_to_be32(cc_cmd->opcode);
}

static void encode_cc_cmd_cnp_bth_b(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_b *cc_cmd = (struct xsc_cc_cmd_cnp_bth_b *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_b = __cpu_to_be32(cc_cmd->bth_b);
}

static void encode_cc_cmd_cnp_bth_f(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_f *cc_cmd = (struct xsc_cc_cmd_cnp_bth_f *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_f = __cpu_to_be32(cc_cmd->bth_f);
}

static void encode_cc_cmd_cnp_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_ecn *cc_cmd = (struct xsc_cc_cmd_cnp_ecn *)data;

	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_data_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_data_ecn *cc_cmd = (struct xsc_cc_cmd_data_ecn *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_cnp_tx_interval(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_tx_interval *cc_cmd = (struct xsc_cc_cmd_cnp_tx_interval *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->interval = __cpu_to_be32(cc_cmd->interval);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_rsttime(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_rsttime *cc_cmd =
			(struct xsc_cc_cmd_evt_rsttime *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_cmd_cnp_dscp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_dscp *cc_cmd = (struct xsc_cc_cmd_cnp_dscp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->dscp = __cpu_to_be32(cc_cmd->dscp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_pcp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_pcp *cc_cmd = (struct xsc_cc_cmd_cnp_pcp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->pcp = __cpu_to_be32(cc_cmd->pcp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_period_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_period_alpha *cc_cmd = (struct xsc_cc_cmd_evt_period_alpha *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_cmd_clamp_tgt_rate(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_clamp_tgt_rate *cc_cmd = (struct xsc_cc_cmd_clamp_tgt_rate *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->clamp_tgt_rate = __cpu_to_be32(cc_cmd->clamp_tgt_rate);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_max_hai_factor(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_max_hai_factor *cc_cmd = (struct xsc_cc_cmd_max_hai_factor *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->max_hai_factor = __cpu_to_be32(cc_cmd->max_hai_factor);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_get_cfg(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_cfg(void *data)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *)data;

	cc_cmd->cmd = __be16_to_cpu(cc_cmd->cmd);
	cc_cmd->len = __be16_to_cpu(cc_cmd->len);
	cc_cmd->enable_rp = __be32_to_cpu(cc_cmd->enable_rp);
	cc_cmd->enable_np = __be32_to_cpu(cc_cmd->enable_np);
	cc_cmd->init_alpha = __be32_to_cpu(cc_cmd->init_alpha);
	cc_cmd->g = __be32_to_cpu(cc_cmd->g);
	cc_cmd->ai = __be32_to_cpu(cc_cmd->ai);
	cc_cmd->hai = __be32_to_cpu(cc_cmd->hai);
	cc_cmd->threshold = __be32_to_cpu(cc_cmd->threshold);
	cc_cmd->bytecount = __be32_to_cpu(cc_cmd->bytecount);
	cc_cmd->opcode = __be32_to_cpu(cc_cmd->opcode);
	cc_cmd->bth_b = __be32_to_cpu(cc_cmd->bth_b);
	cc_cmd->bth_f = __be32_to_cpu(cc_cmd->bth_f);
	cc_cmd->cnp_ecn = __be32_to_cpu(cc_cmd->cnp_ecn);
	cc_cmd->data_ecn = __be32_to_cpu(cc_cmd->data_ecn);
	cc_cmd->cnp_tx_interval = __be32_to_cpu(cc_cmd->cnp_tx_interval);
	cc_cmd->evt_period_rsttime = __be32_to_cpu(cc_cmd->evt_period_rsttime);
	cc_cmd->cnp_dscp = __be32_to_cpu(cc_cmd->cnp_dscp);
	cc_cmd->cnp_pcp = __be32_to_cpu(cc_cmd->cnp_pcp);
	cc_cmd->evt_period_alpha = __be32_to_cpu(cc_cmd->evt_period_alpha);
	cc_cmd->clamp_tgt_rate = __be32_to_cpu(cc_cmd->clamp_tgt_rate);
	cc_cmd->max_hai_factor = __be32_to_cpu(cc_cmd->max_hai_factor);
	cc_cmd->section = __be32_to_cpu(cc_cmd->section);
}

static void encode_cc_get_stat(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_stat *cc_cmd = (struct xsc_cc_cmd_get_stat *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_stat(void *data)
{
	struct xsc_cc_cmd_stat *cc_cmd = (struct xsc_cc_cmd_stat *)data;

	cc_cmd->cnp_handled = __be32_to_cpu(cc_cmd->cnp_handled);
	cc_cmd->alpha_recovery = __be32_to_cpu(cc_cmd->alpha_recovery);
	cc_cmd->reset_timeout = __be32_to_cpu(cc_cmd->reset_timeout);
	cc_cmd->reset_bytecount = __be32_to_cpu(cc_cmd->reset_bytecount);
}

static int xsc_priv_dev_ioctl_get_global_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ioctl_global_pcp *resp = (struct xsc_ioctl_global_pcp *)out;

	resp->pcp = get_global_force_pcp();
	return 0;
}

static int xsc_priv_dev_ioctl_get_global_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ioctl_global_dscp *resp = (struct xsc_ioctl_global_dscp *)out;

	resp->dscp = get_global_force_dscp();
	return 0;
}

static int xsc_priv_dev_ioctl_set_global_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_pcp *req = (struct xsc_ioctl_global_pcp *)out;

	ret = set_global_force_pcp(req->pcp);
	return ret;
}

static int xsc_priv_dev_ioctl_set_global_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_dscp *req = (struct xsc_ioctl_global_dscp *)out;

	ret = set_global_force_dscp(req->dscp);
	return ret;
}

static int xsc_priv_dev_ioctl_get_cma_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_pcp *resp = (struct xsc_ioctl_cma_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return -EOPNOTSUPP;

	resp->pcp = ib_dev->cm_pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_get_cma_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_dscp *resp = (struct xsc_ioctl_cma_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return -EOPNOTSUPP;

	resp->dscp = ib_dev->cm_dscp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_cma_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_pcp *req = (struct xsc_ioctl_cma_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return -EOPNOTSUPP;

	if (req->pcp < 0 || (req->pcp > QOS_PCP_MAX && req->pcp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->cm_pcp = req->pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_cma_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_dscp *req = (struct xsc_ioctl_cma_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return -EOPNOTSUPP;

	if (req->dscp < 0 || (req->dscp > QOS_DSCP_MAX && req->dscp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->cm_dscp = req->dscp;
	return 0;
}

static int _rdma_ctrl_ioctl_cc(struct xsc_core_device *xdev,
			       struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr,
			       u16 expect_req_size, u16 expect_resp_size,
			       void (*encode)(void *, u32), void (*decode)(void *))
{
	struct xsc_cc_mbox_in *in;
	struct xsc_cc_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_cc_mbox_in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_cc_mbox_out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	hdr->attr.error = __be32_to_cpu(out->hdr.status);
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

int _rdma_ctrl_exec_ioctl(struct xsc_core_device *xdev, void *in, int in_size, void *out,
			  int out_size)
{
	int opcode, ret = 0;
	struct xsc_ioctl_attr *hdr;

	hdr = (struct xsc_ioctl_attr *)in;
	opcode = hdr->opcode;
	switch (opcode) {
	case XSC_IOCTL_GET_GLOBAL_PCP:
		ret = xsc_priv_dev_ioctl_get_global_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_GLOBAL_DSCP:
		ret = xsc_priv_dev_ioctl_get_global_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_CMA_PCP:
		ret = xsc_priv_dev_ioctl_get_cma_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_CMA_DSCP:
		ret = xsc_priv_dev_ioctl_get_cma_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_GLOBAL_PCP:
		xsc_core_dbg(xdev, "setting global pcp\n");
		ret = xsc_priv_dev_ioctl_set_global_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_GLOBAL_DSCP:
		xsc_core_dbg(xdev, "setting global dscp\n");
		ret = xsc_priv_dev_ioctl_set_global_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_CMA_PCP:
		ret = xsc_priv_dev_ioctl_set_cma_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_CMA_DSCP:
		ret = xsc_priv_dev_ioctl_set_cma_dscp(xdev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static long _rdma_ctrl_ioctl_getinfo(struct xsc_core_device *xdev,
				     struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	struct xsc_ioctl_hdr *in;
	int in_size;
	int err;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_GET_GLOBAL_PCP:
	case XSC_IOCTL_GET_GLOBAL_DSCP:
	case XSC_IOCTL_SET_GLOBAL_PCP:
	case XSC_IOCTL_SET_GLOBAL_DSCP:
	case XSC_IOCTL_GET_CMA_PCP:
	case XSC_IOCTL_GET_CMA_DSCP:
	case XSC_IOCTL_SET_CMA_PCP:
	case XSC_IOCTL_SET_CMA_DSCP:
		break;
	default:
		return -EINVAL;
	}
	in_size = sizeof(struct xsc_ioctl_hdr) + hdr.attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -EFAULT;
	in->attr.opcode = hdr.attr.opcode;
	in->attr.length = hdr.attr.length;
	err = copy_from_user(in->attr.data, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	err = _rdma_ctrl_exec_ioctl(xdev, &in->attr, (in_size - sizeof(u32)), in->attr.data,
				    hdr.attr.length);
	in->attr.error = err;
	if (copy_to_user(user_hdr, in, in_size))
		err = -EFAULT;
	kvfree(in);
	return err;
}

static long _rdma_ctrl_ioctl_cmdq(struct xsc_core_device *xdev,
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
	case XSC_CMD_OP_IOCTL_SET_ENABLE_RP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_enable_rp),
					   0, encode_cc_cmd_enable_rp, NULL);
	case XSC_CMD_OP_IOCTL_SET_ENABLE_NP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_enable_np),
					   0, encode_cc_cmd_enable_np, NULL);
	case XSC_CMD_OP_IOCTL_SET_INIT_ALPHA:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_init_alpha),
					   0, encode_cc_cmd_init_alpha, NULL);
	case XSC_CMD_OP_IOCTL_SET_G:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_g),
					   0, encode_cc_cmd_g, NULL);
	case XSC_CMD_OP_IOCTL_SET_AI:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_ai),
					   0, encode_cc_cmd_ai, NULL);
	case XSC_CMD_OP_IOCTL_SET_HAI:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_hai),
					   0, encode_cc_cmd_hai, NULL);
	case XSC_CMD_OP_IOCTL_SET_TH:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_th),
					   0, encode_cc_cmd_th, NULL);
	case XSC_CMD_OP_IOCTL_SET_BC_TH:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_bc),
					   0, encode_cc_cmd_bc, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_OPCODE:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_opcode),
					   0, encode_cc_cmd_cnp_opcode, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_B:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_bth_b),
					   0, encode_cc_cmd_cnp_bth_b, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_F:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_bth_f),
					   0, encode_cc_cmd_cnp_bth_f, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_ECN:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_ecn),
			0, encode_cc_cmd_cnp_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_DATA_ECN:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_data_ecn),
					   0, encode_cc_cmd_data_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_TX_INTERVAL:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_tx_interval),
					   0, encode_cc_cmd_cnp_tx_interval, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_RSTTIME:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_evt_rsttime),
					   0, encode_cc_cmd_evt_rsttime, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_DSCP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_dscp),
					   0, encode_cc_cmd_cnp_dscp, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_PCP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_pcp),
					   0, encode_cc_cmd_cnp_pcp, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_ALPHA:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_evt_period_alpha),
					   0, encode_cc_cmd_evt_period_alpha, NULL);
	case XSC_CMD_OP_IOCTL_SET_CLAMP_TGT_RATE:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_clamp_tgt_rate),
					   0, encode_cc_cmd_clamp_tgt_rate, NULL);
	case XSC_CMD_OP_IOCTL_SET_MAX_HAI_FACTOR:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_max_hai_factor),
					   0, encode_cc_cmd_max_hai_factor, NULL);
	case XSC_CMD_OP_IOCTL_GET_CC_CFG:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_cfg),
					   sizeof(struct xsc_cc_cmd_get_cfg),
					   encode_cc_get_cfg, decode_cc_get_cfg);
	case XSC_CMD_OP_IOCTL_GET_CC_STAT:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_stat),
					   sizeof(struct xsc_cc_cmd_stat),
					   encode_cc_get_stat, decode_cc_get_stat);
	default:
		return -EINVAL;
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

static int _rdma_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			     struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = _rdma_ctrl_ioctl_cmdq(xdev, user_hdr);
		break;
	case XSC_IOCTL_DRV_GET:
	case XSC_IOCTL_DRV_SET:
		// TODO refactor to split driver get and set
		err = _rdma_ctrl_ioctl_getinfo(xdev, user_hdr);
		break;
	default:
		err = -EFAULT;
		break;
	}

	return err;
}

static void _rdma_ctrl_reg_fini(void)
{
	xsc_port_ctrl_cb_dereg(XSC_RDMA_CTRL_NAME);
}

static int _rdma_ctrl_reg_init(void)
{
	int ret;

	ret = xsc_port_ctrl_cb_reg(XSC_RDMA_CTRL_NAME, _rdma_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_RDMA_CTRL_NAME);

	return ret;
}

void xsc_rdma_ctrl_fini(void)
{
	_rdma_ctrl_reg_fini();
}

int xsc_rdma_ctrl_init(void)
{
	return _rdma_ctrl_reg_init();
}

