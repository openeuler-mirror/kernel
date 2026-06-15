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
#include "common/xsc_sample_port_ctrl.h"
#include "xsc_ib.h"
#include "xsc_sample_ctrl.h"

#define SAMPLE_IOCTL_MAGIC       (0x1d)
#define SAMPLE_IOCTL_BASE        (0x1)
#define SAMPLE_IOCTL_CMD         _IOWR(SAMPLE_IOCTL_MAGIC, SAMPLE_IOCTL_BASE,\
				       struct sample_ioctl_buf)

#define XSC_SAMPLE_CTRL_NAME	"sample_ctl"

static long _sample_ioctl_cmdq(struct xsc_core_device *xdev,
			       struct sample_ioctl_buf __user *user_buf)
{
	struct xsc_sample_mbox_in *in;
	struct xsc_sample_mbox_out *out;
	int in_len = sizeof(struct xsc_sample_mbox_in) + sizeof(struct sample_ioctl_buf);
	int out_len = sizeof(struct xsc_sample_mbox_out) + sizeof(struct sample_ioctl_buf);
	int err;
	struct sample_ctrl_req *req;

	in = kvzalloc(in_len, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kvzalloc(out_len, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	err = copy_from_user(&in->data, user_buf, sizeof(struct sample_ioctl_buf));
	if (err) {
		err = -EFAULT;
		goto err_exit;
	}

	req = (struct sample_ctrl_req *)&in->data;
	in->hdr.opcode = req->hdr.cmd;
	in->hdr.ver = cpu_to_be16(0);

	err = xsc_cmd_exec(xdev, (void *)in, in_len, (void *)out, out_len);
	if (err) {
		err = -EFAULT;
		pr_err("failed to exec sample ioctrl cmd 0x%x\n",  be16_to_cpu(in->hdr.opcode));
		goto err_exit;
	}

	if (out->hdr.status)
		err = -EAGAIN;

	if (copy_to_user(user_buf, out->data, sizeof(struct sample_ioctl_buf)))
		err = -EFAULT;

err_exit:
	kvfree(in);
	kvfree(out);
	return err;
}

static int _sample_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			       unsigned long args, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	struct sample_ioctl_buf __user *user_buf = (struct sample_ioctl_buf __user *)args;
	int err;

	switch (cmd) {
	case SAMPLE_IOCTL_CMD:
		err = _sample_ioctl_cmdq(xdev, user_buf);
		break;
	default:
		err = -EFAULT;
		break;
	}

	return err;
}

static void _sample_ctrl_reg_fini(void)
{
	xsc_sample_port_ctrl_cb_dereg(XSC_SAMPLE_CTRL_NAME);
}

static int _sample_ctrl_reg_init(void)
{
	int ret;

	ret = xsc_sample_port_ctrl_cb_reg(XSC_SAMPLE_CTRL_NAME, _sample_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_SAMPLE_CTRL_NAME);

	return ret;
}

void xsc_sample_ctrl_fini(void)
{
	_sample_ctrl_reg_fini();
}

int xsc_sample_ctrl_init(void)
{
	return _sample_ctrl_reg_init();
}

