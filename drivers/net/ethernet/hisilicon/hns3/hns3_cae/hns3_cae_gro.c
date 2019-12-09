// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>

#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_gro.h"

int hns3_gro_age_handle(struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size)
{
	struct hnae3_handle *h = net_priv->ae_handle;
	struct hns3_cae_gro_age_config_cmd *req;
	struct hclge_vport *vport;
	struct gro_param *param;
	struct hclge_desc desc;
	struct hclge_dev *hdev;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct gro_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = container_of(h, struct hclge_vport, nic);
	param = (struct gro_param *)buf_in;
	hdev = vport->back;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_GRO_AGE_CFG,
				      param->is_read ? true : false);
	req = (struct hns3_cae_gro_age_config_cmd *)desc.data;

	if (!param->is_read)
		req->ppu_gro_age_cnt = param->age_cnt;

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "gro age config fail, ret = %d\n",
			ret);
		return ret;
	}

	if (param->is_read) {
		if (!buf_out || out_size < sizeof(u32)) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		memcpy(buf_out, &req->ppu_gro_age_cnt,
		       sizeof(req->ppu_gro_age_cnt));
	}

	return 0;
}
