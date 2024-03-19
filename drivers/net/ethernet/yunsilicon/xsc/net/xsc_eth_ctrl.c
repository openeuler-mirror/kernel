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

#define XSC_ETH_CTRL_NAME	"eth_ctrl"

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
	in->req_prfx.mac_port = xdev->mac_port;

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
					   sizeof(struct xsc_pfc_set), 0, NULL, NULL);
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
						sizeof(struct hwc_set_t), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_HWC:
		return _eth_ctrl_ioctl_hwconfig(xdev, user_hdr, &hdr, sizeof(struct hwc_get_t),
						sizeof(struct hwc_get_t),
						NULL, NULL);
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

void xsc_eth_ctrl_fini(void)
{
	_eth_ctrl_reg_fini();
}

int xsc_eth_ctrl_init(void)
{
	return _eth_ctrl_reg_init();
}

