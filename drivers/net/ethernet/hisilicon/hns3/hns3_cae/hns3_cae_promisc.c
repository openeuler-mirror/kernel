// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hns3_cae_promisc.h"

int hns3_read_promisc_mode_cfg(struct hns3_nic_priv *nic_dev,
			       void *buf_in, u32 in_size,
			       void *buf_out, u32 out_size)
{
	struct hclge_promisc_cfg_cmd *req;
	enum hclge_cmd_status status;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	u8 *out_buf;
	bool check;
	u8 enable;

	check = !buf_out || out_size < sizeof(u8);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	out_buf = (u8 *)buf_out;
	vport = hclge_get_vport(nic_dev->ae_handle);
	hdev = vport->back;
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	req->vf_id = vport->vport_id;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PROMISC_MODE, true);
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Get promisc mode fail, status is %d.\n", status);
		return status;
	}
	enable = req->flag >> HCLGE_PROMISC_EN_B;
	*out_buf = enable;

	return 0;
}

int hns3_set_promisc_mode_cfg(struct hns3_nic_priv *nic_dev,
			      void *buf_in, u32 in_size,
			      void *buf_out, u32 out_size)
{
	struct promisc_mode_param *mode_param;
	struct hclge_promisc_cfg_cmd *req;
	enum hclge_cmd_status status;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	bool en_uc;
	bool en_mc;
	bool en_bc;
	bool check;
	u8 enable;

	check = !buf_in || in_size < sizeof(struct promisc_mode_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hclge_get_vport(nic_dev->ae_handle);
	hdev = vport->back;
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	req->vf_id = vport->vport_id;
	mode_param = (struct promisc_mode_param *)buf_in;
	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PROMISC_MODE, true);
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	if (status) {
		dev_err(&hdev->pdev->dev,
			"Get promisc mode fail, status is %d.\n", status);
		return status;
	}

	enable = req->flag >> HCLGE_PROMISC_EN_B;
	if (enable & HCLGE_PROMISC_EN_UC)
		en_uc = 1;
	else
		en_uc = 0;

	if (enable & HCLGE_PROMISC_EN_MC)
		en_mc = 1;
	else
		en_mc = 0;

	if (enable & HCLGE_PROMISC_EN_BC)
		en_bc = 1;
	else
		en_bc = 0;

	switch (mode_param->type) {
	case HNS3_UNICAST:
		en_uc = mode_param->uc;
		break;
	case HNS3_MULTICAST:
		en_mc = mode_param->mc;
		break;
	case HNS3_BROADCAST:
		en_bc = mode_param->bc;
		break;
	default:
		return -1;
	}

	return hclge_set_vport_promisc_mode(vport, en_uc, en_mc, en_bc);
}

int hns3_promisc_mode_cfg(struct hns3_nic_priv *nic_dev,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size)
{
	struct promisc_mode_param *mode_param;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct promisc_mode_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	mode_param = (struct promisc_mode_param *)buf_in;
	if (mode_param->is_read == 1)
		ret = hns3_read_promisc_mode_cfg(nic_dev, buf_in, in_size,
						 buf_out, out_size);
	else
		ret = hns3_set_promisc_mode_cfg(nic_dev, buf_in, in_size,
						buf_out, out_size);

	return ret;
}
