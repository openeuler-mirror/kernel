// SPDX-License-Identifier: GPL-2.0+
/* Hisilicon UNIC Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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

#include <linux/etherdevice.h>
#include <linux/random.h>

#include "ubl.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hclge_mbx.h"
#include "hclge_unic_guid.h"
#include "hnae3.h"

int hclge_unic_set_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;

	return hclge_comm_unic_set_func_guid(&hdev->hw.hw, guid);
}

int hclge_unic_get_func_guid(struct hnae3_handle *handle, u8 *guid)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;

	return hclge_comm_unic_get_func_guid(&hdev->hw.hw, guid);
}

void hclge_unic_rm_func_guid(struct hclge_dev *hdev)
{
	hclge_comm_unic_rm_func_guid(&hdev->hw.hw);
}
