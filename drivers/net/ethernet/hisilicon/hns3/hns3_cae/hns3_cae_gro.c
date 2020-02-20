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

int hns3_gro_age_handle(const struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size)
{
	struct hnae3_handle *h = net_priv->ae_handle;
	struct hns3_cae_gro_age_config_cmd *req = NULL;
	struct hclge_vport *vport = NULL;
	struct gro_param *param = NULL;
	struct hclge_dev *hdev = NULL;
	struct hclge_desc desc;
	bool check = !buf_in || in_size < sizeof(struct gro_param);
	int ret;

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

int hns3_gro_dump_bd_buff_size(const struct hns3_nic_priv *net_priv,
			       void *buf_in, u32 in_size, void *buf_out,
			       u32 out_size)
{
	struct hclge_vport *vport = NULL;
	struct hnae3_handle *h = NULL;
	struct hclge_dev *hdev = NULL;

	if (!buf_out || out_size < sizeof(u16)) {
		pr_err("input param buf_out error in %s function\n",
		       __func__);
			return -EFAULT;
	}

	h = net_priv->ae_handle;
	vport = container_of(h, struct hclge_vport, nic);
	hdev = vport->back;

	memcpy(buf_out, &hdev->rx_buf_len, sizeof(hdev->rx_buf_len));

	return 0;
}
