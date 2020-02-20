// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/phy_fixed.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_fd.h"

static int hns3_cae_send_generic_cmd(struct hclge_dev *hdev, u8 *buf_in,
				     u32 in_size, u8 *buf_out, u32 out_size)
{
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_get_fd_mode_cmd *mode_cfg = NULL;
	struct hclge_get_fd_mode_cmd *req = NULL;
	struct hclge_desc desc;
	bool check = false;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_MODE_CTRL,
				      param->is_read ? true : false);

	req = (struct hclge_get_fd_mode_cmd *)desc.data;
	if (!param->is_read) {
		mode_cfg = (struct hclge_get_fd_mode_cmd *)param->data;
		req->mode = mode_cfg->mode;
		req->enable = mode_cfg->enable;
	}
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "set fd mode fail, ret = %d\n", ret);
		return ret;
	}

	if (param->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hclge_get_fd_mode_cmd);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}

		mode_cfg = (struct hclge_get_fd_mode_cmd *)buf_out;
		mode_cfg->mode = req->mode;
		mode_cfg->enable = req->enable;
	}

	return 0;
}

static int hns3_cae_send_allocate_cmd(struct hclge_dev *hdev, u8 *buf_in,
				      u32 in_size, u8 *buf_out, u32 out_size)
{
	struct hclge_get_fd_allocation_cmd *allocation_cfg = NULL;
	struct hclge_get_fd_allocation_cmd *req = NULL;
	struct hclge_desc desc;
	bool check = !buf_out ||
		     out_size < sizeof(struct hclge_get_fd_allocation_cmd);
	int ret;

	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	allocation_cfg = (struct hclge_get_fd_allocation_cmd *)buf_out;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_GET_ALLOCATION, true);

	req = (struct hclge_get_fd_allocation_cmd *)desc.data;

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"query fd allocation fail, ret = %d\n",
			ret);
		return ret;
	}

	allocation_cfg->stage1_entry_num = req->stage1_entry_num;
	allocation_cfg->stage2_entry_num = req->stage2_entry_num;
	allocation_cfg->stage1_counter_num = req->stage1_counter_num;
	allocation_cfg->stage2_counter_num = req->stage2_counter_num;

	return 0;
}

static int hns3_cae_send_key_cfg_cmd(struct hclge_dev *hdev, u8 *buf_in,
				     u32 in_size, u8 *buf_out, u32 out_size)
{
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_set_fd_key_config_cmd *key_cfg_data = NULL;
	struct hclge_set_fd_key_config_cmd *req = NULL;
	struct hclge_desc desc;
	bool check = false;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_KEY_CONFIG,
				      param->is_read ? true : false);

	req = (struct hclge_set_fd_key_config_cmd *)desc.data;
	req->stage = param->stage;
	if (!param->is_read) {
		key_cfg_data =
		    (struct hclge_set_fd_key_config_cmd *)param->data;
		req->key_select = key_cfg_data->key_select;
		req->inner_sipv6_word_en = key_cfg_data->inner_sipv6_word_en;
		req->inner_dipv6_word_en = key_cfg_data->inner_dipv6_word_en;
		req->outer_sipv6_word_en = key_cfg_data->outer_sipv6_word_en;
		req->outer_dipv6_word_en = key_cfg_data->outer_dipv6_word_en;
		req->tuple_mask = key_cfg_data->tuple_mask;
		req->meta_data_mask = key_cfg_data->meta_data_mask;
	}
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "set fd key fail, ret = %d\n", ret);
		return ret;
	}

	if (param->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hclge_set_fd_key_config_cmd);
		if (check) {
			pr_err("input parameter error in %s function\n",
			       __func__);
			return -EFAULT;
		}
		key_cfg_data = (struct hclge_set_fd_key_config_cmd *)buf_out;
		key_cfg_data->key_select = req->key_select;
		key_cfg_data->inner_sipv6_word_en = req->inner_sipv6_word_en;
		key_cfg_data->inner_dipv6_word_en = req->inner_dipv6_word_en;
		key_cfg_data->outer_sipv6_word_en = req->outer_sipv6_word_en;
		key_cfg_data->outer_dipv6_word_en = req->outer_dipv6_word_en;
		key_cfg_data->tuple_mask = req->tuple_mask;
		key_cfg_data->meta_data_mask = req->meta_data_mask;
	}

	return 0;
}

static int hns3_cae_send_tcam_op_cmd(struct hclge_dev *hdev, u8 *buf_in,
				     u32 in_size, u8 *buf_out, u32 out_size)
{
#define HNS3_CAE_FD_TCAM_BD_NUM		3
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_desc desc[HNS3_CAE_FD_TCAM_BD_NUM];
	struct hclge_fd_tcam_config_1_cmd *req1 = NULL;
	struct hclge_fd_tcam_config_2_cmd *req2 = NULL;
	struct hclge_fd_tcam_config_3_cmd *req3 = NULL;
	struct hclge_fd_tcam_data *tcam_data = NULL;
	struct hclge_desc *pdesc = NULL;
	bool check = false;
	u8 *buf = NULL;
	int ret;
	int i;

	for (i = 0; i < HNS3_CAE_FD_TCAM_BD_NUM; i++) {
		pdesc = &desc[i];
		hns3_cae_cmd_setup_basic_desc(pdesc, HCLGE_OPC_FD_TCAM_OP,
					      param->is_read ? true : false);
		if (i < HNS3_CAE_FD_TCAM_BD_NUM - 1)
			pdesc->flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
	}

	req1 = (struct hclge_fd_tcam_config_1_cmd *)desc[0].data;
	req2 = (struct hclge_fd_tcam_config_2_cmd *)desc[1].data;
	req3 = (struct hclge_fd_tcam_config_3_cmd *)desc[2].data;

	req1->stage = param->stage;
	req1->xy_sel = param->xy_sel;
	req1->index = param->idx;

	if (!param->is_read) {
		req1->entry_vld = param->entry_vld;
		tcam_data = (struct hclge_fd_tcam_data *)param->data;
		buf = tcam_data->tcam_data;
		memcpy(req1->tcam_data, buf, sizeof(req1->tcam_data));
		buf += sizeof(req1->tcam_data);
		memcpy(req2->tcam_data, buf, sizeof(req2->tcam_data));
		buf += sizeof(req2->tcam_data);
		memcpy(req3->tcam_data, buf, sizeof(req3->tcam_data));
	}

	ret = hns3_cae_cmd_send(hdev, desc, HNS3_CAE_FD_TCAM_BD_NUM);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"config tcam key fail, ret = %d\n", ret);

		return ret;
	}

	if (param->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hclge_fd_tcam_data);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}

		tcam_data = (struct hclge_fd_tcam_data *)buf_out;
		tcam_data->vld = req1->entry_vld;
		buf = tcam_data->tcam_data;
		memcpy(buf, req1->tcam_data, sizeof(req1->tcam_data));
		buf += sizeof(req1->tcam_data);
		memcpy(buf, req2->tcam_data, sizeof(req2->tcam_data));
		buf += sizeof(req2->tcam_data);
		memcpy(buf, req3->tcam_data, sizeof(req3->tcam_data));
	}

	return 0;
}

static int hns3_cae_send_ad_op_cmd(struct hclge_dev *hdev, u8 *buf_in,
				   u32 in_size, u8 *buf_out, u32 out_size)
{
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_fd_ad_config_cmd *ad_data = NULL;
	struct hclge_fd_ad_config_cmd *req = NULL;
	struct hclge_desc desc;
	bool check = false;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_AD_OP,
				      param->is_read ? true : false);
	req = (struct hclge_fd_ad_config_cmd *)desc.data;
	req->stage = param->stage;
	req->index = param->idx;

	if (!param->is_read) {
		ad_data = (struct hclge_fd_ad_config_cmd *)param->data;
		memcpy(&req->ad_data, &ad_data->ad_data, sizeof(req->ad_data));
	}

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "fd ad config fail, ret = %d\n", ret);
		return ret;
	}

	if (param->is_read) {
		check = !buf_out ||
			out_size < sizeof(struct hclge_fd_ad_config_cmd);
		if (check) {
			pr_err("input param buf_out error in %s function\n",
			       __func__);
			return -EFAULT;
		}

		ad_data = (struct hclge_fd_ad_config_cmd *)buf_out;
		memcpy(&ad_data->ad_data, &req->ad_data, sizeof(req->ad_data));
	}

	return 0;
}

static int hns3_cae_send_cnt_op_cmd(struct hclge_dev *hdev, u8 *buf_in,
				    u32 in_size, u8 *buf_out, u32 out_size)
{
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_fd_cnt_op_cmd *cnt_data = NULL;
	struct hclge_fd_cnt_op_cmd *req = NULL;
	struct hclge_desc desc;
	bool check = !buf_out || out_size < sizeof(struct hclge_fd_cnt_op_cmd);
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_CNT_OP, true);
	req = (struct hclge_fd_cnt_op_cmd *)desc.data;
	req->stage = param->stage;
	req->cnt_idx = param->idx;

	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "read fd cnt fail, ret = %d\n", ret);
		return ret;
	}

	cnt_data = (struct hclge_fd_cnt_op_cmd *)buf_out;
	memcpy(&cnt_data->cnt_value, &req->cnt_value, sizeof(req->cnt_value));

	return 0;
}

int hns3_cae_fd_cfg(const struct hns3_nic_priv *net_priv,
		    void *buf_in, u32 in_size, void *buf_out,
		    u32 out_size)
{
	bool check = !buf_in || in_size < sizeof(struct fd_param);
	struct hnae3_handle *handle = net_priv->ae_handle;
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct fd_param *param = (struct fd_param *)buf_in;
	struct hclge_dev *hdev = vport->back;
	int ret = -1;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (!hnae3_dev_fd_supported(hdev))
		return -EOPNOTSUPP;

	if (param->op == HCLGE_OPC_FD_MODE_CTRL) {
		ret = hns3_cae_send_generic_cmd(hdev, buf_in, in_size,
						buf_out, out_size);
	}

	if (param->op == HCLGE_OPC_FD_GET_ALLOCATION) {
		ret = hns3_cae_send_allocate_cmd(hdev, buf_in, in_size,
						 buf_out, out_size);
	}

	if (param->op == HCLGE_OPC_FD_KEY_CONFIG) {
		ret = hns3_cae_send_key_cfg_cmd(hdev, buf_in, in_size,
						buf_out, out_size);
	}

	if (param->op == HCLGE_OPC_FD_TCAM_OP) {
		ret = hns3_cae_send_tcam_op_cmd(hdev, buf_in, in_size,
						buf_out, out_size);
	}

	if (param->op == HCLGE_OPC_FD_AD_OP) {
		ret = hns3_cae_send_ad_op_cmd(hdev, buf_in, in_size,
					      buf_out, out_size);
	}

	if (param->op == HCLGE_OPC_FD_CNT_OP) {
		ret = hns3_cae_send_cnt_op_cmd(hdev, buf_in, in_size,
					       buf_out, out_size);
	}

	return ret;
}
