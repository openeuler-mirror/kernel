// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2023 Hisilicon Limited.

#include <linux/etherdevice.h>

#include "ubl.h"
#include "hclgevf_main.h"
#include "hclge_comm_unic_addr.h"
#include "hclge_mbx.h"
#include "hclgevf_unic_guid.h"

int hclgevf_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(handle);

	return hclge_comm_unic_set_func_guid(&hdev->hw.hw, guid);
}

int hclgevf_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclgevf_dev *hdev = hclgevf_ae_get_hdev(handle);

	return hclge_comm_unic_get_func_guid(&hdev->hw.hw, guid);
}
