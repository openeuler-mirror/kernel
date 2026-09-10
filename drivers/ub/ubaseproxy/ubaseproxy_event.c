// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/module.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_ctrlq.h>

#include "ubaseproxy_ctrlq.h"
#include "ubaseproxy_ctx_mgt.h"
#include "ubaseproxy_mbx.h"
#include "ubaseproxy_reset.h"
#include "ubaseproxy_event.h"

static int ubaseproxy_handle_crq_msg(void *dev, void *data, u32 len)
{
	struct ubaseproxy_ue_res_info *ue_res_info;
	struct ubase_proxy_req_msg *req = data;
	struct auxiliary_device *adev = dev;
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	u16 bus_ue_id = le16_to_cpu(req->bus_ue_id);
	u16 mbx_ue_id = le16_to_cpu(req->mbx_ue_id);
	u32 data_len;
	int ret;

	if (!test_bit(bus_ue_id, udev->bus_ue_id_bitmap))
		return 0;

	ue_res_info = ubaseproxy_get_ue_ctx(udev, mbx_ue_id);
	ue_res_info->bus_ue_id = bus_ue_id;

	if (len < sizeof(*req)) {
		ubaseproxy_risk_rl(udev, mbx_ue_id, crq_msg_len,
				   "req msg len error, len = %u.\n", len);
		return -EINVAL;
	}

	data_len = len - sizeof(*req);
	if (data_len < req->data_len) {
		ubaseproxy_risk_rl(udev, mbx_ue_id,
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
		ubaseproxy_risk_rl(udev, mbx_ue_id,
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
	},
	{
		.opcode = UBASE_OPC_SET_CTX_VA_REQ,
		.crq_handler = ubaseproxy_handle_ue_ctx_va_req,
	},
	{
		.opcode = UBASE_OPC_UE_RESET_NOTIFY,
		.crq_handler = ubaseproxy_handle_ue_reset_notify,
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

static void ubaseproxy_clear_ue_res(struct ubaseproxy_dev *udev, u16 bus_ue_id)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	struct ubaseproxy_ue_seid_table *ue_seid_table;
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;
	struct ubaseproxy_ue_res_info *ue_res_info;
	struct ubaseproxy_ue_ctx_qos *ue_ctx_qos;

	for (i = 0; i < managed_ue_num; i++) {
		ue_res_info = &udev->ue_res_info[i];
		if (ue_res_info->bus_ue_id != bus_ue_id)
			continue;

		ue_ctx_qos = &ue_res_info->ue_ctx_qos;
		memset(ue_ctx_qos, 0, sizeof(*ue_ctx_qos));

		ue_seid_table = &ue_res_info->ue_seid_table;
		spin_lock_bh(&ue_seid_table->seid_lock);
		bitmap_zero(ue_seid_table->seid_bmap,
			    UBASEPROXY_MAX_SEID_TABLE_SIZE);
		spin_unlock_bh(&ue_seid_table->seid_lock);

		memset(&ue_res_info->risk_stats, 0,
		       sizeof(ue_res_info->risk_stats));

		break;
	}
}

static void ubaseproxy_virt_handler(struct auxiliary_device *adev, u16 bus_ue_id,
				    bool is_en)
{
	struct ubaseproxy_dev *udev = (struct ubaseproxy_dev *)dev_get_drvdata(&adev->dev);

	if (is_en) {
		if (!try_module_get(THIS_MODULE))
			ubaseproxy_err(udev, "failed to handle virt event.\n");
		else
			atomic_inc(&udev->virt_refcnt);

		ubaseproxy_clear_ue_res(udev, bus_ue_id);
		set_bit(bus_ue_id, udev->bus_ue_id_bitmap);
	} else {
		if (atomic_dec_if_positive(&udev->virt_refcnt) >= 0)
			module_put(THIS_MODULE);
		clear_bit(bus_ue_id, udev->bus_ue_id_bitmap);
	}
}

static struct ubase_ctrlq_ue_msg_nb ubaseproxy_ue_resp_events[] = {
	/* The return value 0 of the callback function indicates synchronous
	 * operation, and the message will be continued to be sent by ubase;
	 * a non-zero return value indicates an asynchronous operation, and the
	 * message will be sent by the current module. If the message needs
	 * further processing by ubase, the return value must be 0, even if an
	 * error is reported by msg_handler.
	 */
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_QOS,
		.opcode = UBASE_CTRLQ_OPC_QUERY_SL,
		.msg_handler = ubaseproxy_ctrlq_handle_query_sl_resp,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASEPROXY_CTRLQ_GET_SEID_INFO,
		.msg_handler = ubaseproxy_ctrlq_handle_query_eid_resp,
	},
	{
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = UBASEPROXY_CTRLQ_UPDATE_SEID_INFO,
		.msg_handler = ubaseproxy_ctrlq_handle_updata_eid_resp,
	},
};

static int ubaseproxy_ctrlq_register_ue_resp_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ubaseproxy_ue_resp_events); i++) {
		ubaseproxy_ue_resp_events[i].back = adev;
		ret = ubase_ctrlq_register_ue_resp_event(adev, &ubaseproxy_ue_resp_events[i]);
		if (ret) {
			ubaseproxy_err(udev,
				       "failed to register ue resp event[%d], ret = %d.\n",
				       i, ret);
			goto err_register_event;
		}
	}

	return 0;

err_register_event:
	for (i = i - 1; i >= 0; i--)
		ubase_ctrlq_unregister_ue_resp_event(adev,
						     ubaseproxy_ue_resp_events[i].service_type,
						     ubaseproxy_ue_resp_events[i].opcode);
	return ret;
}

static void ubaseproxy_ctrlq_unregister_ue_resp_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ubaseproxy_ue_resp_events); i++)
		ubase_ctrlq_unregister_ue_resp_event(adev,
						     ubaseproxy_ue_resp_events[i].service_type,
						     ubaseproxy_ue_resp_events[i].opcode);
}

int ubaseproxy_register_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	int ret;

	ret = ubaseproxy_register_crq_event(udev);
	if (ret)
		return ret;

	ret = ubaseproxy_ctrlq_register_ue_resp_event(udev);
	if (ret)
		goto register_ue_resp_err;

	ubase_reset_register(adev, ubaseproxy_reset_handler);
	atomic_set(&udev->virt_refcnt, 0);
	ubase_virt_register(adev, ubaseproxy_virt_handler);

	return 0;

register_ue_resp_err:
	ubaseproxy_unregister_crq_event(udev);
	return ret;
}

void ubaseproxy_unregister_event(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;

	ubase_virt_unregister(adev);
	ubase_reset_unregister(adev);
	ubaseproxy_ctrlq_unregister_ue_resp_event(udev);
	ubaseproxy_unregister_crq_event(udev);
}
