// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2019 Hisilicon Limited.

#include <linux/kernel.h>

#include "hnae3.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_led.h"

int hns3_led_cfg_ncl_info(struct hns3_nic_priv *net_priv, void *buf_in,
			  u32 in_size, void *buf_out, u32 out_size)
{
	struct hnae3_handle *handle = hns3_get_handle(net_priv->netdev);
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct led_statistic_param *parm_out = buf_out;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc = {0};
	bool check;
	int index;
	int ret;

	check = !buf_out || out_size < sizeof(struct led_statistic_param);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_LED_CFG_NCL_INFO, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "send led command failed %d\n", ret);
		return ret;
	}

	for (index = 0; index < HCLGE_DESC_DATA_LEN; index++)
		parm_out->data[index] = desc.data[index];

	return 0;
}
