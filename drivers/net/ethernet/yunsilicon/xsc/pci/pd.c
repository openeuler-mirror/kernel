// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "common/driver.h"

int xsc_core_alloc_pd(struct xsc_core_device *xdev, u32 *pdn)
{
	struct xsc_alloc_pd_mbox_in	in;
	struct xsc_alloc_pd_mbox_out	out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ALLOC_PD);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	*pdn = be32_to_cpu(out.pdn) & 0xffffff;
	return err;
}
EXPORT_SYMBOL(xsc_core_alloc_pd);

int xsc_core_dealloc_pd(struct xsc_core_device *xdev, u32 pdn)
{
	struct xsc_dealloc_pd_mbox_in	in;
	struct xsc_dealloc_pd_mbox_out	out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEALLOC_PD);
	in.pdn = cpu_to_be32(pdn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	return err;
}
EXPORT_SYMBOL(xsc_core_dealloc_pd);
