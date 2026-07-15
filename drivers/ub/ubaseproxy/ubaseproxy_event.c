// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/module.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_ctrlq.h>

#include "ubaseproxy_mbx.h"
#include "ubaseproxy_event.h"

static int ubaseproxy_handle_crq_msg(void *dev, void *data, u32 len)
{
	struct ubase_proxy_req_msg *req = data;
	struct auxiliary_device *adev = dev;
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	u32 data_len;
	int ret;

	if (len < sizeof(*req)) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   crq_msg_len,
				   "req msg len error, len = %u.\n", len);
		return -EINVAL;
	}

	data_len = len - sizeof(*req);
	if (data_len < req->data_len) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   crq_data_len,
				   "req data len error, req->data_len = %u, data_len = %u.\n",
				   req->data_len, data_len);
		return -EINVAL;
	}

	switch (req->module) {
	case UBASE_MODULE_UDMA_TO_PROXY:
	case UBASE_MODULE_UBASE_TO_PROXY:
		ret = ubaseproxy_handle_mbox_req(udev, req);
		break;
	default:
		ubaseproxy_risk_rl(udev, le16_to_cpu(req->mbx_ue_id),
				   crq_req_module,
				   "unsupported module is %u.\n",
				   req->module);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct ubase_crq_event_nb ubaseproxy_crq_events[] = {
	{
		.opcode = UBASE_OPC_UE_TO_PROXY,
		.crq_handler = ubaseproxy_handle_crq_msg,
	}
};

static int ubaseproxy_register_crq_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(ubaseproxy_crq_events); i++) {
		ubaseproxy_crq_events[i].back = adev;

		ret = ubase_register_crq_event(adev, &ubaseproxy_crq_events[i]);
		if (ret) {
			ubaseproxy_err(udev,
				       "failed to register crq event[%d], ret = %d.\n",
				       i, ret);
			goto err_register_event;
		}
	}

	return ret;

err_register_event:
	for (i = i - 1; i >= 0; i--)
		ubase_unregister_crq_event(adev,
					   ubaseproxy_crq_events[i].opcode);
	return ret;
}

static void ubaseproxy_unregister_crq_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	int i;

	for (i = 0; i < ARRAY_SIZE(ubaseproxy_crq_events); i++)
		ubase_unregister_crq_event(adev,
					   ubaseproxy_crq_events[i].opcode);
}

int ubaseproxy_register_event(struct ubaseproxy_dev *udev)
{
	int ret;

	ret = ubaseproxy_register_crq_event(udev);
	if (ret)
		return ret;

	return 0;
}

void ubaseproxy_unregister_event(struct ubaseproxy_dev *udev)
{
	ubaseproxy_unregister_crq_event(udev);
}
