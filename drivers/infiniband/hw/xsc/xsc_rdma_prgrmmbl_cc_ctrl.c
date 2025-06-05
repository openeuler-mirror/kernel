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
#include "common/xsc_prgrmmbl_cc_ctrl.h"
#include "xsc_ib.h"
#include "xsc_rdma_prgrmmbl_cc_ctrl.h"

#define FLEXCC_IOCTL_MAGIC       (0x1c)
#define FLEXCC_IOCTL_BASE        (0x1)
#define FLEXCC_IOCTL_CMD         _IOWR(FLEXCC_IOCTL_MAGIC, FLEXCC_IOCTL_BASE,\
				       struct flexcc_ioctl_buf)

#define XSC_RDMA_CTRL_NAME	"r_prgrm_cc_ctl"

static long _rdma_ctrl_ioctl_cmdq(struct xsc_core_device *xdev,
				  struct flexcc_ioctl_buf __user *user_buf)
{
	struct flexcc_mbox_in *in;
	struct flexcc_mbox_out *out;
	int in_len = sizeof(struct flexcc_mbox_in) + sizeof(struct flexcc_ioctl_buf);
	int out_len = sizeof(struct flexcc_mbox_out) + sizeof(struct flexcc_ioctl_buf);
	int err;

	in = kvzalloc(in_len, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kvzalloc(out_len, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_IOCTL_PRGRMMBL_CC);
	in->hdr.ver = cpu_to_be16(0);

	err = copy_from_user(&in->data, user_buf, sizeof(struct flexcc_ioctl_buf));
	if (err) {
		err = -EFAULT;
		goto err_exit;
	}

	xsc_cmd_exec(xdev, (void *)in, in_len, (void *)out, out_len);

	if (copy_to_user(user_buf, out->data, sizeof(struct flexcc_ioctl_buf)))
		err = -EFAULT;

	if (out->hdr.status)
		err = -EFAULT;

err_exit:
	kvfree(in);
	kvfree(out);
	return err;
}

static int _rdma_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			     unsigned long args, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	struct flexcc_ioctl_buf __user *user_buf = (struct flexcc_ioctl_buf __user *)args;
	int err;

	switch (cmd) {
	case FLEXCC_IOCTL_CMD:
		err = _rdma_ctrl_ioctl_cmdq(xdev, user_buf);
		break;
	default:
		err = -EFAULT;
		break;
	}

	return err;
}

static void _rdma_prgrmmbl_cc_ctrl_reg_fini(void)
{
	xsc_prgrmmbl_cc_ctrl_cb_dereg(XSC_RDMA_CTRL_NAME);
}

static int _rdma_prgrmmbl_cc_ctrl_reg_init(void)
{
	int ret;

	ret = xsc_prgrmmbl_cc_ctrl_cb_reg(XSC_RDMA_CTRL_NAME, _rdma_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_RDMA_CTRL_NAME);

	return ret;
}

void xsc_rdma_prgrmmbl_cc_ctrl_fini(void)
{
	_rdma_prgrmmbl_cc_ctrl_reg_fini();
}

int xsc_rdma_prgrmmbl_cc_ctrl_init(void)
{
	return _rdma_prgrmmbl_cc_ctrl_reg_init();
}

