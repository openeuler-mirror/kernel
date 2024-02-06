// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "common/driver.h"

int xsc_core_mad_ifc(struct xsc_core_device *xdev, void *inb, void *outb,
		     u16 opmod, int port)
{
	struct xsc_mad_ifc_mbox_in *in = NULL;
	struct xsc_mad_ifc_mbox_out *out = NULL;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto out;
	}

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MAD_IFC);
	in->hdr.opmod = cpu_to_be16(opmod);
	in->port = port;

	memcpy(in->data, inb, sizeof(in->data));

	err = xsc_cmd_exec(xdev, in, sizeof(*in), out, sizeof(*out));
	if (err)
		goto out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out;
	}

	memcpy(outb, out->data, sizeof(out->data));

out:
	kfree(out);
	kfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_mad_ifc);
