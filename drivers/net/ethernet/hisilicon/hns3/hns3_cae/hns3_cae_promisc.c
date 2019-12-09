// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.
#include "hns3_cae_cmd.h"
#include "hns3_cae_promisc.h"

int hns3_read_promisc_mode_cfg(struct hns3_nic_priv *nic_dev,
			       void *buf_in, u32 in_size,
			       void *buf_out, u32 out_size)
{
	struct hclge_promisc_cfg_cmd *req;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	u8 *out_buf;
	bool check;
	u8 enable;
	int ret;

	check = !buf_out || out_size < sizeof(u8);
	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	out_buf = (u8 *)buf_out;
	vport = hns3_cae_get_vport(nic_dev->ae_handle);
	hdev = vport->back;
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	req->vf_id = vport->vport_id;
	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PROMISC_MODE, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"Get promisc mode fail, ret is %d.\n", ret);
		return ret;
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
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	bool check;
	int ret;

	check = !buf_in || in_size < sizeof(struct promisc_mode_param);
	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	vport = hns3_cae_get_vport(nic_dev->ae_handle);
	hdev = vport->back;
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	req->vf_id = vport->vport_id;
	mode_param = (struct promisc_mode_param *)buf_in;
	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_PROMISC_MODE, true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	req = (struct hclge_promisc_cfg_cmd *)desc.data;
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"Get promisc mode fail, ret is %d.\n", ret);
		return ret;
	}

	hns3_cae_cmd_reuse_desc(&desc, false);
	switch (mode_param->type) {
	case HNS3_UNICAST:
		req->flag &= ~BIT(HNS3_CAE_UC_PROMISC_EN_B);
		req->flag |= (mode_param->uc << HNS3_CAE_UC_PROMISC_EN_B) |
			     HCLGE_PROMISC_TX_EN_B | HCLGE_PROMISC_RX_EN_B;
		break;
	case HNS3_MULTICAST:
		req->flag &= ~BIT(HNS3_CAE_MC_PROMISC_EN_B);
		req->flag |= (mode_param->mc << HNS3_CAE_MC_PROMISC_EN_B) |
			     HCLGE_PROMISC_TX_EN_B | HCLGE_PROMISC_RX_EN_B;
		break;
	case HNS3_BROADCAST:
		req->flag &= ~BIT(HNS3_CAE_BC_PROMISC_EN_B);
		req->flag |= (mode_param->bc << HNS3_CAE_BC_PROMISC_EN_B) |
			     HCLGE_PROMISC_TX_EN_B | HCLGE_PROMISC_RX_EN_B;
		break;
	default:
		return -1;
	}

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"Set promisc mode fail, ret is %d.\n", ret);

	return ret;
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
