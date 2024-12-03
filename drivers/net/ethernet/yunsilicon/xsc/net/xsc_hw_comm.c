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
		return xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					  sizeof(struct xsc_pfc_set_drop_th_mbox_in),
					  sizeof(struct xsc_pfc_set_drop_th_mbox_out),
					  NULL, NULL);
		fallthrough;
	case XSC_CMD_OP_IOCTL_GET_PFC_CFG_STATUS:
		return xsc_dcbx_hw_common(xdev, opcode, req, rsp,
					  sizeof(struct xsc_pfc_get_cfg_status_mbox_in),
					  sizeof(struct xsc_pfc_get_cfg_status_mbox_out),
					  NULL, NULL);
		fallthrough;
	default:
		xsc_core_dbg(xdev, "unknown type=%d\n", opcode);
	}

	return 0;
}

