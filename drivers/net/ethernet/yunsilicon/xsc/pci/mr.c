// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <common/driver.h>
#include <common/xsc_cmd.h>

int xsc_core_create_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_create_mkey_mbox_in in;
	struct xsc_create_mkey_mbox_out out;
	int err;
	u8 key;

	memset(&out, 0, sizeof(out));
	spin_lock(&dev->dev_res->mkey_lock);
	key = 0x80 + dev->dev_res->mkey_key++;
	spin_unlock(&dev->dev_res->mkey_lock);
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_MKEY);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_create_mkey(dev, &in, &out);
#endif
	if (err) {
		xsc_core_dbg(dev, "cmd exec faile %d\n", err);
		return err;
	}

	if (out.hdr.status) {
		xsc_core_dbg(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	mr->key = xsc_idx_to_mkey(be32_to_cpu(out.mkey) & 0xffffff) | key;
	xsc_core_dbg(dev, "out 0x%x, key 0x%x, mkey 0x%x\n", be32_to_cpu(out.mkey), key, mr->key);

	return err;
}
EXPORT_SYMBOL(xsc_core_create_mkey);

int xsc_core_destroy_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_destroy_mkey_mbox_in in;
	struct xsc_destroy_mkey_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_MKEY);
	in.mkey = cpu_to_be32(mr->key);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_destroy_mkey(dev, &in, &out);
#endif
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	return err;
}
EXPORT_SYMBOL(xsc_core_destroy_mkey);

int xsc_core_register_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr,
		struct xsc_register_mr_mbox_in *in, int inlen)
{
	struct xsc_register_mr_mbox_out out;
	int err;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_REG_MR);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, in, inlen, &out, sizeof(out));
#else
	err = xsc_reg_mr(dev, in, &out);
#endif
	if (err) {
		xsc_core_dbg(dev, "cmd exec failed %d\n", err);
		return err;
	}
	if (out.hdr.status) {
		xsc_core_dbg(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	return 0;
}
EXPORT_SYMBOL(xsc_core_register_mr);

int xsc_core_dereg_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_unregister_mr_mbox_in in;
	struct xsc_unregister_mr_mbox_out out;
	int err;

	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEREG_MR);
	in.mkey = cpu_to_be32(xsc_mkey_to_idx(mr->key));
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_dereg_mr(dev, &in, &out);
#endif
	if (err) {
		xsc_core_dbg(dev, "cmd exec failed %d\n", err);
		return err;
	}
	if (out.hdr.status) {
		xsc_core_dbg(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	return 0;
}
EXPORT_SYMBOL(xsc_core_dereg_mr);

