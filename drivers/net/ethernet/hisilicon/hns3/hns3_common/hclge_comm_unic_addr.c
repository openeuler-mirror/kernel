// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "hclge_comm_unic_addr.h"

static void
hclge_comm_unic_func_guid_cmd_prepare(u8 *guid,
				      struct hclge_comm_func_guid_cmd *req)
{
	req->entry_vld = HCLGE_COMM_FUNC_GUID_ENTRY_VALID_EN;
	memcpy(req->guid, guid, UBL_ALEN);
}

int hclge_comm_unic_set_func_guid(struct hclge_comm_hw *hw, u8 *guid)
{
	struct hclge_comm_func_guid_cmd *req;
	struct hclge_desc desc;
	int ret;

	req = (struct hclge_comm_func_guid_cmd *)desc.data;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_CFG_FUNC_GUID,
					false);
	hclge_comm_unic_func_guid_cmd_prepare(guid, req);

	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret)
		dev_err(&hw->cmq.csq.pdev->dev,
			"failed to set guid for cmd_send, ret = %d\n", ret);

	return ret;
}

void hclge_comm_unic_rm_func_guid(struct hclge_comm_hw *hw)
{
	struct hclge_comm_func_guid_cmd *req;
	struct hclge_desc desc;
	int ret;

	req = (struct hclge_comm_func_guid_cmd *)desc.data;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_CFG_FUNC_GUID,
					false);
	req->entry_vld = 0;
	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret)
		dev_warn(&hw->cmq.csq.pdev->dev,
			 "failed to delete func guid for cmd_send, ret = %d.\n",
			 ret);
}

static bool hclge_comm_unic_is_valid_func_guid(u8 *guid)
{
	u8 invalid_guid_zero[UBL_ALEN] = {0};
	u8 invalid_guid_all_one[UBL_ALEN];

	memset(invalid_guid_all_one, 0xff, UBL_ALEN);
	if (!(memcmp(guid, invalid_guid_all_one, HCLGE_COMM_MGUID_PREFIX_LEN) &&
	      memcmp(guid, invalid_guid_zero, UBL_ALEN)))
		return false;

	return true;
}

static void hclge_comm_unic_guid_le_to_net_trans(u8 *src_guid, u8 *dest_guid)
{
	int i;

	for (i = 0; i < UBL_ALEN; i++)
		dest_guid[i] = src_guid[UBL_ALEN - i - 1];
}

int hclge_comm_unic_get_func_guid(struct hclge_comm_hw *hw, u8 *guid)
{
	struct hclge_desc desc;
	bool is_random = false;
	int ret;

	hclge_comm_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMM_GET_FUNC_GUID,
					true);
	ret = hclge_comm_cmd_send(hw, &desc, 1);
	if (ret) {
		dev_err(&hw->cmq.csq.pdev->dev,
			"failed to get function GUID, ret = %d\n", ret);
		return ret;
	}

	hclge_comm_unic_guid_le_to_net_trans((u8 *)desc.data, guid);
	while (unlikely(!hclge_comm_unic_is_valid_func_guid(guid))) {
		get_random_bytes(guid, UBL_ALEN);
		is_random = true;
	}

	if (unlikely(is_random))
		dev_warn(&hw->cmq.csq.pdev->dev,
			 "using random GUID %02x:%02x:...:%02x:%02x\n",
			 guid[0], guid[1],
			 guid[UBL_ALEN - 2], guid[UBL_ALEN - 1]);

	return 0;
}
