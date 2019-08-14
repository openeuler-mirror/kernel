// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/kernel.h>
#include "hns3_priv_m7_cmd.h"

int hns3_m7_cmd_handle(struct hns3_nic_priv *nic_dev, void *buf_in, u16 in_size,
		       void *buf_out, u16 *out_size)
{
	struct m7_cmd_para *cmd_para = (struct m7_cmd_para *)buf_in;
	struct hnae3_handle *handle = nic_dev->ae_handle;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	enum hclge_cmd_status status;
	struct hclge_desc *desc;
	int bd_size;

	bd_size = sizeof(struct hclge_desc) * cmd_para->bd_count;
	desc = kzalloc(bd_size, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(desc)) {
		pr_err("desc kzalloc failed in m7_cmd_handle function\n");
		return -ENOMEM;
	}
	if (copy_from_user((void *)desc, cmd_para->bd_data, bd_size)) {
		pr_err("copy from user failed in m7_cmd_handle function\n");
		kfree(desc);
		return -EFAULT;
	}

	status = hclge_cmd_send(&hdev->hw, desc, cmd_para->bd_count);
	if (status) {
		dev_err(&hdev->pdev->dev,
			"generic cmd send fail, status is %d.\n", status);
		kfree(desc);
		return status;
	}

	if (desc->flag & HCLGE_CMD_FLAG_WR) {
		memcpy(buf_out, desc, bd_size);
		*out_size = (u16)bd_size;
	}

	kfree(desc);

	return 0;
}
