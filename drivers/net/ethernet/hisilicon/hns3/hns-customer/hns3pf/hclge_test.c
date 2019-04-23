// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include "hclge_test.h"

int hclge_send_cmdq(struct hnae3_handle *handle, void *data, int num)
{
	struct hclge_vport *vport;
	struct hclge_dev *hdev;

	vport = hclge_get_vport(handle);
	hdev = vport->back;

	return (int)hclge_cmd_send(&hdev->hw, data, num);
}
