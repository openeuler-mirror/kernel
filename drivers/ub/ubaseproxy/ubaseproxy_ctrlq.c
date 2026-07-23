// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_ctrlq.h>

#include "ubaseproxy_ctrlq.h"

static int ubaseproxy_ctrlq_check_ue_msg(struct auxiliary_device *adev,
					 void *data, u16 len, u32 expect_len,
					 struct ubase_ctrlq_ue_msg_info *msg_info)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(adev);
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1;

	if (len < expect_len) {
		ubaseproxy_err(udev,
			       "failed to check data len, len = %u, expect len = %u.\n",
			       len, expect_len);
		return -EINVAL;
	}

	ubase_ctrlq_parse_ue_msg(adev, data, len, msg_info);
	if (msg_info->ret || msg_info->service_ver != UBASE_CTRLQ_SER_VER_01) {
		ubaseproxy_err(udev,
			       "failed to check ue msg, service_ver = %u, ret = %d.\n",
			       msg_info->service_ver, msg_info->ret);
		return -EINVAL;
	}

	if (!msg_info->mbx_ue_id || msg_info->mbx_ue_id > managed_ue_num) {
		ubaseproxy_err(udev,
			       "failed to check ue id, ue_id = %u, managed_ue_num = %u.\n",
			       msg_info->mbx_ue_id, managed_ue_num);
		return -EINVAL;
	}

	return 0;
}

int ubaseproxy_ctrlq_handle_query_eid_resp(struct auxiliary_device *adev,
					   void *data, u16 len)
{
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	struct ubaseproxy_ue_seid_table *ue_seid_table;
	struct ubase_ctrlq_ue_msg_info msg_info = {0};
	struct ubaseproxy_ctrlq_query_seid_info *resp;
	u16 hdr_len = ubase_ctrlq_ue_msg_header_len();
	u32 i, seid_idx;
	int ret;

	ret = ubaseproxy_ctrlq_check_ue_msg(adev, data, len, hdr_len, &msg_info);
	if (ret)
		return 0;

	resp = (struct ubaseproxy_ctrlq_query_seid_info *)((u8 *)data + hdr_len);
	if (resp->seid_num > UBASEPROXY_CTRLQ_SEID_NUM) {
		ubaseproxy_err(udev, "invalid seid num[%u]].\n", resp->seid_num);
		return 0;
	}

	ue_seid_table = ubaseproxy_get_ue_seid_table(udev, msg_info.mbx_ue_id);

	spin_lock_bh(&ue_seid_table->seid_lock);
	bitmap_zero(ue_seid_table->seid_bmap, UBASEPROXY_MAX_SEID_TABLE_SIZE);
	for (i = 0; i < resp->seid_num; i++) {
		seid_idx = le32_to_cpu(resp->seids[i].seid_idx);
		if (seid_idx > UBASEPROXY_MAX_SEID_TABLE_SIZE) {
			ubaseproxy_err(udev,
				       "invalid seid idx when query eid[%u].\n",
				       seid_idx);
			break;
		}
		set_bit(seid_idx, ue_seid_table->seid_bmap);
	}
	spin_unlock_bh(&ue_seid_table->seid_lock);

	return 0;
}

int ubaseproxy_ctrlq_handle_updata_eid_resp(struct auxiliary_device *adev,
					    void *data, u16 len)
{
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	struct ubaseproxy_ue_seid_table *ue_seid_table;
	struct ubaseproxy_ctrlq_update_seid_info *resp;
	struct ubase_ctrlq_ue_msg_info msg_info = {0};
	u16 hdr_len = ubase_ctrlq_ue_msg_header_len();
	u32 seid_idx, expect_len;
	u8 seid_cmd;
	int ret;

	expect_len = hdr_len + sizeof(*resp);
	ret = ubaseproxy_ctrlq_check_ue_msg(adev, data, len, expect_len,
					    &msg_info);
	if (ret)
		return 0;

	resp = (struct ubaseproxy_ctrlq_update_seid_info *)((u8 *)data + hdr_len);

	seid_cmd = le32_to_cpu(resp->seid_operation) & UBASEPROXY_CTRLQ_SEID_CMD;
	if (seid_cmd != UBASEPROXY_CTRLQ_ADD_SEID && seid_cmd != UBASEPROXY_CTRLQ_DEL_SEID) {
		ubaseproxy_err(udev, "invalid seid cmd[%u].\n", seid_cmd);
		return 0;
	}

	ue_seid_table = ubaseproxy_get_ue_seid_table(udev, msg_info.mbx_ue_id);

	spin_lock_bh(&ue_seid_table->seid_lock);
	seid_idx = le32_to_cpu(resp->seid_info.seid_idx);
	if (seid_idx > UBASEPROXY_MAX_SEID_TABLE_SIZE)
		ubaseproxy_err(udev,
			       "invalid seid idx when update eid[%u].\n",
			       seid_idx);
	else if (seid_cmd == UBASEPROXY_CTRLQ_ADD_SEID)
		set_bit(seid_idx, ue_seid_table->seid_bmap);
	else if (seid_cmd == UBASEPROXY_CTRLQ_DEL_SEID)
		clear_bit(seid_idx, ue_seid_table->seid_bmap);
	spin_unlock_bh(&ue_seid_table->seid_lock);

	return 0;
}

int ubaseproxy_ctrlq_handle_query_sl_resp(struct auxiliary_device *adev,
					  void *data, u16 len)
{
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	struct ubase_ctrlq_ue_msg_info msg_info = {0};
	u16 hdr_len = ubase_ctrlq_ue_msg_header_len();
	struct ubaseproxy_ctrlq_query_sl_resp *resp;
	struct ubaseproxy_ue_ctx_qos *ue_ctx_qos;
	struct ubaseproxy_ue_ctx_buf *ctx_buf;
	u32 expect_len;
	int ret;

	expect_len = hdr_len + sizeof(*resp);
	ret = ubaseproxy_ctrlq_check_ue_msg(adev, data, len, expect_len,
					    &msg_info);
	if (ret)
		return 0;

	resp = (struct ubaseproxy_ctrlq_query_sl_resp *)((u8 *)data + hdr_len);
	ue_ctx_qos = ubaseproxy_get_ue_ctx_qos(udev, msg_info.mbx_ue_id);

	ue_ctx_qos->um_sl_bitmap = le16_to_cpu(resp->um_sl_bitmap);
	ue_ctx_qos->tp_sl_bitmap = le16_to_cpu(resp->tp_sl_bitmap);
	ue_ctx_qos->ctp_sl_bitmap = le16_to_cpu(resp->ctp_sl_bitmap);
	ue_ctx_qos->total_sl_bitmap = ue_ctx_qos->um_sl_bitmap |
				      ue_ctx_qos->tp_sl_bitmap |
				      ue_ctx_qos->ctp_sl_bitmap;

	ctx_buf = ubaseproxy_get_ue_ctx_buf(udev, msg_info.mbx_ue_id);
	ctx_buf->rc.entry_cnt = le16_to_cpu(resp->rc_max_cnt);
	if (!resp->rc_max_cnt)
		ubaseproxy_err(udev, "rc max cnt is zero.\n");

	ubaseproxy_dbg(udev,
		       "ue_id = %u, um_sl_bitmap = 0x%lx, tp_sl_bitmap = 0x%lx.",
		       msg_info.mbx_ue_id, ue_ctx_qos->um_sl_bitmap,
		       ue_ctx_qos->tp_sl_bitmap);
	ubaseproxy_dbg(udev,
		       "ctp_sl_bitmap = 0x%lx, total_sl_bitmap = 0x%lx, rc_max_cnt = %u.\n",
		       ue_ctx_qos->ctp_sl_bitmap, ue_ctx_qos->total_sl_bitmap,
		       ctx_buf->rc.entry_cnt);

	return 0;
}
