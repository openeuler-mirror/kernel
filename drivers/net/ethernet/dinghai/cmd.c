// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/types.h>
#include <linux/dinghai/device.h>
#include <linux/dinghai/dh_ifc.h>

static s32 cmd_status_err(struct dh_core_dev *dev, s32 err, u16 opcode, void *out)
{
	u8 status = DH_GET(mbox_out, out, status);

	return err;
}

static s32 cmd_exec(struct dh_core_dev *dev, void *in, s32 in_size, void *out, s32 out_size,
		    zxdh_cmd_cbk_t callback, void *context, bool force_polling)
{
	return 0;
}

s32 zxdh_cmd_do(struct dh_core_dev *dev, void *in, s32 in_size, void *out, s32 out_size)
{
	s32 err = cmd_exec(dev, in, in_size, out, out_size, NULL, NULL, false);
	u16 opcode = DH_GET(mbox_in, in, opcode);

	err = cmd_status_err(dev, err, opcode, out);

	return err;
}
EXPORT_SYMBOL(zxdh_cmd_do);

s32 zxdh_cmd_exec(struct dh_core_dev *dev, void *in, s32 in_size, void *out, s32 out_size)
{
	s32 err = zxdh_cmd_do(dev, in, in_size, out, out_size);

	return zxdh_cmd_check(dev, err, in, out);
}
