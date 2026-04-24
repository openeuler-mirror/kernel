// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_dev.h>

#include "ubase_cmd.h"
#include "ubase_proxy.h"

int ubase_handle_ue_isolated_notify_event(void *dev, void *data, u32 len)
{
	struct ubase_isolated_notify_cmd *cmd = data;
	struct ubase_ue_node *ue_pos;
	struct ubase_dev *udev = dev;
	u16 bus_ue_id;

	if (len != sizeof(*cmd)) {
		ubase_err(udev,
			  "mbx ue isolated notify event len error, len = %u, expect = %lu.\n",
			  len, sizeof(*cmd));
		return -EINVAL;
	}

	mutex_lock(&udev->ue_list_lock);
	bus_ue_id = le16_to_cpu(cmd->bus_ue_id);
	list_for_each_entry(ue_pos, &udev->ue_list, list) {
		if (ue_pos->bus_ue_id != bus_ue_id)
			continue;

		ue_pos->isolated = cmd->status;
		mutex_unlock(&udev->ue_list_lock);
		ubase_info(udev, "update ue(%u) isolated status to %u.\n",
			   bus_ue_id, cmd->status);

		return 0;
	}

	mutex_unlock(&udev->ue_list_lock);
	ubase_warn(udev, "recv unknown bus ue(%u) isolated status event.\n",
		   bus_ue_id);

	return -ENXIO;
}

int ubase_init_ue_isolated_state(struct ubase_dev *udev)
{
	ubase_update_ue_isolated_state(udev);
	return 0;
}

int ubase_update_ue_isolated_state(struct ubase_dev *udev)
{
#define BITMAP_MAX_LEN 160U
#define BITMAP_LEN 32U

	struct ubase_query_ue_isolated_state_cmd resp = {0};
	u32 new_bitmap[ARRAY_SIZE(resp.bitmap)];
	struct ubase_ue_node *ue_node;
	struct ubase_cmd_buf in, out;
	u32 offset, idx, shift;
	int ret;
	u16 i;

	if (!ubase_dev_mbx_proxy_supported(udev))
		return -EOPNOTSUPP;

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_UE_ISOLATED_STATE, true,
			       0, NULL);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_UE_ISOLATED_STATE, true,
			       sizeof(resp), &resp);
	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev,
			  "failed to query mbx ue isolate state, ret = %d.\n",
			  ret);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(resp.bitmap); i++)
		new_bitmap[i] = le32_to_cpu(resp.bitmap[i]);

	mutex_lock(&udev->ue_list_lock);
	list_for_each_entry(ue_node, &udev->ue_list, list) {
		if (ue_node->bus_ue_id < resp.first_bus_ue_id)
			continue;

		offset = ue_node->bus_ue_id - resp.first_bus_ue_id;
		if (offset >= BITMAP_MAX_LEN)
			continue;

		idx = offset / BITMAP_LEN;
		shift = offset % BITMAP_LEN;
		if (test_bit(shift, (unsigned long *)&new_bitmap[idx]))
			ue_node->isolated = 1;
		else
			ue_node->isolated = 0;
	}
	mutex_unlock(&udev->ue_list_lock);

	return 0;
}

int ubase_ue_req_ctx_buf(struct ubase_dev *udev)
{
	struct ubase_proxy_set_ctx_va_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;
	u16 i;

	__ubase_fill_inout_buf(&in, UBASE_OPC_SET_CTX_VA_REQ, false, sizeof(req),
			       &req);

	for (i = 0; i < UBASE_CTX_VA_TYPE_NUM; i++) {
		req.ctx_type = cpu_to_le16(i);
		ret = __ubase_cmd_send_in(udev, &in);
		if (ret) {
			ubase_err(udev,
				  "failed to set ctx va buf, ctx_type = %u, ret = %d.\n",
				  i, ret);
			return ret;
		}

		if (!wait_for_completion_timeout(&udev->ctx_status.ctx_va_done,
						 msecs_to_jiffies(UBASE_UE2UE_MSG_WAIT_TIME))) {
			ubase_err(udev,
				  "wait ctx va resp timeout, ctx_type = %u.\n",
				  i);
			return -ETIMEDOUT;
		}

		if (udev->ctx_status.ctx_ret) {
			ubase_err(udev,
				  "failed to set ctx buf to hw, ctx_type = %u, ctx_ret = %d.\n",
				  i, udev->ctx_status.ctx_ret);
			return -EIO;
		}
	}

	return 0;
}

int ubase_handle_ue_ctx_va_resp(void *dev, void *data, u32 len)
{
	struct ubase_proxy_set_ctx_va_cmd *cmd = data;
	struct ubase_dev *udev = dev;
	u16 ctx_type;

	if (len != sizeof(*cmd)) {
		ubase_err(udev,
			  "ubase handle ctx va event msg len(%u) error, except len = %zu.\n",
			  len, sizeof(*cmd));
		return -EINVAL;
	}

	ctx_type = le16_to_cpu(cmd->ctx_type);
	if (ctx_type >= UBASE_CTX_VA_TYPE_NUM) {
		ubase_err(udev,
			  "ubase handle ctx va event ctx type(%u) error.\n",
			  ctx_type);
		return -EINVAL;
	}

	udev->ctx_status.ctx_ret = cmd->result;
	complete(&udev->ctx_status.ctx_va_done);

	return 0;
}
