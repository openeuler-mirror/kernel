// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.


#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hnae3.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_lib.h"

int hns3_cae_common_cmd_send(const struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size, void *buf_out,
			     u32 out_size)
{
#define MAX_DESC_DATA_LEN       6
	struct cmd_desc_param *param_in = (struct cmd_desc_param *)buf_in;
	struct hclge_vport *vport = NULL;
	struct hclge_dev *hdev = NULL;
	struct hclge_desc desc;
	bool check = !buf_in || in_size < sizeof(struct cmd_desc_param);
	int ret;
	int i;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hns3_cae_get_vport(net_priv->ae_handle);
	hdev = vport->back;

	hns3_cae_cmd_setup_basic_desc(&desc, param_in->fw_dw_opcode,
				      param_in->is_read);
	for (i = 0; i < MAX_DESC_DATA_LEN; i++)
		desc.data[i] = param_in->reg_desc.data[i];
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "%s, ret is %d.\n", __func__,
			ret);
		return ret;
	}
	if (param_in->is_read) {
		struct cmd_desc_param *param_out =
					(struct cmd_desc_param *)buf_out;

		check = !buf_out || out_size < sizeof(struct cmd_desc_param);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		for (i = 0; i < MAX_DESC_DATA_LEN; i++)
			param_out->reg_desc.data[i] = desc.data[i];
	}

	return 0;
}

