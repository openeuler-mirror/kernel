// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_dev.h"
#include "ubaseproxy_reset.h"

int ubaseproxy_handle_ue_reset_notify(void *dev, void *data, u32 len)
{
	struct ubaseproxy_ue_reset_notify_cmd *cmd = data;
	struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa;
	struct ubaseproxy_ue_ctx_buf *ctx_buf;
	struct auxiliary_device *adev = dev;
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	u16 mbx_ue_id;

	if (len != sizeof(*cmd)) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(cmd->mbx_ue_id),
				   reset_len,
				   "ubaseproxy handle ue reset notify msg len error, len = %u.\n",
				   len);
		return -EINVAL;
	}

	mbx_ue_id = le16_to_cpu(cmd->mbx_ue_id);

	ue_ctx_xa = ubaseproxy_get_ue_ctx_xa(udev, mbx_ue_id);
	ubaseproxy_erase_ue_ctx_resources(udev, ue_ctx_xa);

	ctx_buf = ubaseproxy_get_ue_ctx_buf(udev, mbx_ue_id);
	ubaseproxy_ue_ctx_buf_free(udev, ctx_buf);

	return 0;
}

static void ubaseproxy_reset_uninit(struct auxiliary_device *adev)
{
	struct ubaseproxy_dev *udev = (struct ubaseproxy_dev *)dev_get_drvdata(&adev->dev);
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	if (!managed_ue_num)
		return;

	for (i = 0; i < managed_ue_num; i++) {
		ubaseproxy_erase_ue_ctx_resources(udev, &udev->ue_res_info[i].ue_ctx_xa);
		ubaseproxy_ue_ctx_buf_free(udev, &udev->ue_res_info[i].ue_ctx_buf);
	}
}

int ubaseproxy_reset_handler(struct auxiliary_device *adev,
			     enum ubase_reset_stage stage)
{
	switch (stage) {
	case UBASE_RESET_STAGE_DOWN:
		break;
	case UBASE_RESET_STAGE_UNINIT:
		ubaseproxy_reset_uninit(adev);
		break;
	case UBASE_RESET_STAGE_INIT:
		break;
	default:
		break;
	}

	return 0;
}
