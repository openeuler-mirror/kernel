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
#include "common/xsc_cmd.h"
#include "xsc_eth.h"
#include "xsc_eth_debug.h"
#include "xsc_hw_comm.h"

static void precmd_rlimit_set(void *data, u32 mac_port)
{
	struct xsc_rate_limit_set *req = (struct xsc_rate_limit_set *)data;

	req->rate_cir = __cpu_to_be32(req->rate_cir);
	req->limit_id = __cpu_to_be32(req->limit_id);
}

static void postcmd_rlimit_get(void *data)
{
	struct xsc_rate_limit_get *resp = (struct xsc_rate_limit_get *)data;
	int i;

	for (i = 0; i <= QOS_PRIO_MAX; i++)
		resp->rate_cir[i] = __be32_to_cpu(resp->rate_cir[i]);

	resp->max_limit_id = __be32_to_cpu(resp->max_limit_id);
}

static int xsc_dcbx_hw_qos_cmdq(struct xsc_core_device *xdev, u16 opcode,
				void *inupt,
				void *output,
				u16 expect_req_size,
				u16 expect_resp_size,
				void (*precmdq)(void *, u32),
				void (*postcmdq)(void *))
{
	struct xsc_qos_mbox_in *in;
	struct xsc_qos_mbox_out *out;
	int err;

	in = kvzalloc(sizeof(*in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	if (inupt)
		memcpy(&in->data, inupt, expect_req_size);

	in->hdr.opcode = __cpu_to_be16(opcode);
	in->req_prfx.mac_port = xdev->mac_port;

	if (precmdq)
		precmdq((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
			   sizeof(*out) + expect_resp_size);

	if (postcmdq)
		postcmdq((void *)out->data);

	if (output)
		memcpy(output, out->data, expect_resp_size);

	kvfree(in);
	kvfree(out);
	return 0;

err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int xsc_dcbx_hw_common(struct xsc_core_device *xdev, u16 opcode,
			      void *input,
			      void *output,
			      u16 expect_req_size,
			      u16 expect_resp_size,
			      void (*precmdq)(void *, u32),
			      void (*postcmdq)(void *))
{
	int ret;
	struct xsc_inbox_hdr *hdr;

	hdr = (struct xsc_inbox_hdr *)input;
	hdr->opcode = __cpu_to_be16(opcode);

	ret = xsc_cmd_exec(xdev, (void *)input, expect_req_size,
			   (void *)output, expect_resp_size);

	return ret;
}

int xsc_hw_kernel_call(struct xsc_core_device *xdev, u16 opcode, void *req, void *rsp)
{
	int ret = 0;

	switch (opcode) {
	case XSC_CMD_OP_IOCTL_GET_RATE_LIMIT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_rate_limit_get),
					    sizeof(struct xsc_rate_limit_get),
					    NULL, postcmd_rlimit_get);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_RATE_LIMIT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_rate_limit_set),
					    0, precmd_rlimit_set, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_GET_PFC:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    0, sizeof(struct xsc_pfc_get),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_PFC:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_pfc_set),
					    sizeof(struct xsc_pfc_set),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_PFC_NEW:
		ret = xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					   sizeof(struct xsc_pfc_set_new),
					   sizeof(struct xsc_pfc_set_new),
					   NULL, NULL);
		break;
	case XSC_CMD_OP_IOCTL_GET_TRUST_MODE:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp, 0,
					    sizeof(struct xsc_trust_mode_get),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_TRUST_MODE:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_trust_mode_set), 0,
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_GET_DSCP_PMT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    0, sizeof(struct xsc_dscp_pmt_get),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_DSCP_PMT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_dscp_pmt_set),
					    0, NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_GET_SP:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    0, sizeof(struct xsc_sp_get),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_SP:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_sp_set),
					    0, NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_GET_WEIGHT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    0, sizeof(struct xsc_weight_get),
					    NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_WEIGHT:
		return xsc_dcbx_hw_qos_cmdq(xdev, opcode, req, rsp,
					    sizeof(struct xsc_weight_set),
					    0, NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_QUERY_PFC_PRIO_STATS:
		return xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					  sizeof(struct xsc_pfc_prio_stats_mbox_in),
					  sizeof(struct xsc_pfc_prio_stats_mbox_out),
					  NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_GET_LLDP_STATUS:
	case XSC_CMD_OP_SET_LLDP_STATUS:
		return xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					  sizeof(struct xsc_lldp_status_mbox_in),
					  sizeof(struct xsc_lldp_status_mbox_out),
					  NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_SET_PFC_DROP_TH:
		ret = xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					 sizeof(struct xsc_pfc_set_drop_th_mbox_in),
					 sizeof(struct xsc_pfc_set_drop_th_mbox_out),
					 NULL, NULL);
		break;
	case XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS:
		ret = xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					 sizeof(struct xsc_pfc_get_cfg_status_mbox_in),
					 sizeof(struct xsc_pfc_get_cfg_status_mbox_out),
					 NULL, NULL);
		break;
	default:
		xsc_core_dbg(xdev, "unknown type=%d\n", opcode);
	}

	return ret;
}

int xsc_cmd_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *xcq)
{
	struct xsc_destroy_cq_mbox_in in;
	struct xsc_destroy_cq_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_CQ);
	in.cqn = cpu_to_be32(xcq->cqn);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "failed to destroy cq, err=%d out.status=%u\n",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	xcq->cqn = 0;
	return 0;
}

int xsc_eth_create_cq(struct xsc_core_device *xdev, struct xsc_core_cq *xcq,
		      struct xsc_create_cq_ex_mbox_in *in, int insize)
{
	int err, ret = -1;
	struct xsc_cq_table *table = &xdev->dev_res->cq_table;
	struct xsc_create_cq_mbox_out out;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_CQ_EX);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || (out.hdr.status && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "failed to create cq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED) {
		ret = xsc_create_cq_compat_handler(xdev, in, &out);
		if (ret)
			return ret;
	}

	xcq->cqn = be32_to_cpu(out.cqn) & 0xffffff;
	xcq->cons_index = 0;
	xcq->arm_sn = 0;
	atomic_set(&xcq->refcount, 1);
	init_completion(&xcq->free);

	spin_lock_irq(&table->lock);
	ret = radix_tree_insert(&table->tree, xcq->cqn, xcq);
	spin_unlock_irq(&table->lock);
	if (ret)
		goto err_insert_cq;
	return 0;

err_insert_cq:
	err = xsc_cmd_destroy_cq(xdev, xcq);
	if (err)
		xsc_core_warn(xdev, "failed to destroy cqn=%d, err=%d\n", xcq->cqn, err);
	return ret;
}

int xsc_eth_modify_qp_status(struct xsc_core_device *xdev,
			     u32 qpn, u16 status)
{
	struct xsc_modify_qp_mbox_in in;
	struct xsc_modify_qp_mbox_out out;

	return xsc_modify_qp(xdev, &in, &out, qpn, status);
}

int xsc_eth_create_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq,
			 struct xsc_create_qp_mbox_in *in, int insize)
{
	struct xsc_create_qp_mbox_out out;
	int ret;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);
	ret = xsc_cmd_exec(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to create sq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	psq->sqn = be32_to_cpu(out.qpn) & 0xffffff;

	return 0;
}

int xsc_eth_modify_qp_sq(struct xsc_core_device *xdev, struct xsc_modify_raw_qp_mbox_in *in)
{
	struct xsc_modify_raw_qp_mbox_out out;
	int ret;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_RAW_QP);

	ret = xsc_cmd_exec(xdev, in, sizeof(struct xsc_modify_raw_qp_mbox_in),
			   &out, sizeof(struct xsc_modify_raw_qp_mbox_out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev, "failed to modify sq, err=%d out.status=%u\n",
			     ret, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_eth_destroy_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	err = xsc_eth_modify_qp_status(xdev, psq->sqn, XSC_CMD_OP_2RST_QP);
	if (err) {
		xsc_core_warn(xdev, "failed to set sq%d status=rst, err=%d\n", psq->sqn, err);
		return err;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(psq->sqn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed to destroy sq%d, err=%d out.status=%u\n",
			     psq->sqn, err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

int xsc_eth_create_rss_qp_rqs(struct xsc_core_device *xdev,
			      struct xsc_create_multiqp_mbox_in *in,
			      int insize,
			      int *prqn_base)
{
	int ret;
	struct xsc_create_multiqp_mbox_out out;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_MULTI_QP);
	ret = xsc_eth_create_multiqp(xdev, in, insize, &out, sizeof(out));
	if (ret || out.hdr.status) {
		xsc_core_err(xdev,
			     "failed to create rss rq, qp_num=%d, type=%d, err=%d out.status=%u\n",
			     in->qp_num, in->qp_type, ret, out.hdr.status);
		return -ENOEXEC;
	}

	*prqn_base = be32_to_cpu(out.qpn_base) & 0xffffff;
	return 0;
}

int xsc_eth_destroy_qp_rq(struct xsc_core_device *xdev, struct xsc_rq *prq)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	err = xsc_eth_modify_qp_status(xdev, prq->rqn, XSC_CMD_OP_2RST_QP);
	if (err) {
		xsc_core_warn(xdev, "failed to set rq%d status=rst, err=%d\n", prq->rqn, err);
		return err;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(prq->rqn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed to destroy rq%d, err=%d out.status=%u\n",
			     prq->rqn, err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}

