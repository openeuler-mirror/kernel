// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_hilink_param.h"

#define HILINK_PARAM_CMD_BD_LEN				10UL
#define HILINK_PARAM_SINGLE_PORT_LANE_NUM		4

static void copy_data_from_cmd(u8 *dest, u32 dest_len, u8 *src, u32 src_len)
{
	u32 cpy_len;

	cpy_len = dest_len >= src_len ? src_len : dest_len;
	memcpy(dest, src, cpy_len);
}

static int hns3_get_hilink_ctle(struct hclge_dev *hdev,
				u32 lane_start, u32 lane_len,
				struct hns3_hilink_param *hns3_param_out)
{
	struct hclge_desc ctle_desc[HILINK_LANE_MAX_NUM] = {0};
	u8 *ctle_data = NULL;
	u32 bd_num;
	int ret;
	u32 i;

	for (i = 0; i < HILINK_PARAM_CMD_BD_LEN; i++) {
		hns3_cae_cmd_setup_basic_desc(&ctle_desc[i],
					      HCLGE_OPC_DUMP_CTLE_PARAM, true);
		if (i == 0)
			ctle_desc[0].data[0] = lane_start | (lane_len << 4);

		if (i < HILINK_PARAM_CMD_BD_LEN - 1)
			ctle_desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			ctle_desc[i].flag &=
			    ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hns3_cae_cmd_send(hdev, ctle_desc, HILINK_PARAM_CMD_BD_LEN);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink param cmd failed %d\n",
			ret);
		return ret;
	}

	hns3_param_out->lane_start = ctle_desc[0].data[0] & 0xF;
	hns3_param_out->lane_len = (ctle_desc[0].data[0] >> 4) & 0xF;
	if (hns3_param_out->lane_len > HILINK_LANE_MAX_NUM)
		hns3_param_out->lane_len = HILINK_LANE_MAX_NUM;

	bd_num = min_t(u32, hns3_param_out->lane_len, HILINK_PARAM_CMD_BD_LEN);
	for (i = 0; i < bd_num; i++) {
		ctle_data = (u8 *)&ctle_desc[i].data[0];
		if (i == 0) {
			ctle_data = ctle_data + 1;
			copy_data_from_cmd((u8 *)&hns3_param_out->ctle_param[i],
					   sizeof(struct hns3_ctle_data),
					   ctle_data, 23);
		} else {
			copy_data_from_cmd((u8 *)&hns3_param_out->ctle_param[i],
					   sizeof(struct hns3_ctle_data),
					   ctle_data, 24);
		}
	}
	return ret;
}

static int hns3_get_hilink_dfe(struct hclge_dev *hdev,
			       u32 lane_start, u32 lane_len,
			       struct hns3_hilink_param *hns3_param_out)
{
	struct hclge_desc dfe_desc[HILINK_LANE_MAX_NUM] = {0};
	u8 *dfe_data = NULL;
	u32 bd_num;
	int ret;
	u32 i;

	for (i = 0; i < HILINK_PARAM_CMD_BD_LEN; i++) {
		hns3_cae_cmd_setup_basic_desc(&dfe_desc[i],
					      HCLGE_OPC_DUMP_DFE_PARAM, true);
		if (i == 0)
			dfe_desc[0].data[0] = lane_start | (lane_len << 4);

		if (i < HILINK_PARAM_CMD_BD_LEN - 1)
			dfe_desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			dfe_desc[i].flag &= ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hns3_cae_cmd_send(hdev, dfe_desc, HILINK_PARAM_CMD_BD_LEN);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink param cmd failed %d\n",
			ret);
		return ret;
	}

	bd_num = min_t(u32, hns3_param_out->lane_len, HILINK_PARAM_CMD_BD_LEN);
	for (i = 0; i < bd_num; i++) {
		dfe_data = (u8 *)&dfe_desc[i].data[0];
		if (i == 0) {
			dfe_data = dfe_data + 1;
			copy_data_from_cmd((u8 *)&hns3_param_out->dfe_param[i],
					   sizeof(struct hns3_dfe_data),
					   dfe_data, 23);
		} else {
			copy_data_from_cmd((u8 *)&hns3_param_out->dfe_param[i],
					   sizeof(struct hns3_dfe_data),
					   dfe_data, 24);
		}
	}

	return ret;
}

static int hns3_get_hilink_ffe(struct hclge_dev *hdev,
			       u32 lane_start, u32 lane_len,
			       struct hns3_hilink_param *hns3_param_out)
{
	struct hclge_desc ffe_desc[HILINK_LANE_MAX_NUM] = {0};
	u8 *ffe_data = NULL;
	u32 bd_num;
	int ret;
	u32 i;

	for (i = 0; i < HILINK_PARAM_CMD_BD_LEN; i++) {
		hns3_cae_cmd_setup_basic_desc(&ffe_desc[i],
					      HCLGE_OPC_DUMP_FFE_PARAM, true);
		if (i == 0)
			ffe_desc[0].data[0] = lane_start | (lane_len << 4);

		if (i < HILINK_PARAM_CMD_BD_LEN - 1)
			ffe_desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			ffe_desc[i].flag &= ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hns3_cae_cmd_send(hdev, ffe_desc, HILINK_PARAM_CMD_BD_LEN);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink param cmd failed %d\n",
			ret);
		return ret;
	}

	bd_num = min_t(u32, hns3_param_out->lane_len, HILINK_PARAM_CMD_BD_LEN);
	for (i = 0; i < bd_num; i++) {
		ffe_data = (u8 *)&ffe_desc[i].data[0];
		if (i == 0) {
			ffe_data = ffe_data + 1;
			copy_data_from_cmd((u8 *)&hns3_param_out->ffe_param[i],
					   sizeof(struct hns3_ffe_data),
					   ffe_data, 23);
		} else {
			copy_data_from_cmd((u8 *)&hns3_param_out->ffe_param[i],
					   sizeof(struct hns3_ffe_data),
					   ffe_data, 24);
		}
	}

	return ret;
}

int hns3_get_hilink_param(const struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size)
{
	struct hnae3_handle *handle = hns3_get_handle(net_priv->netdev);
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hns3_hilink_param *hns3_param_out =
					    (struct hns3_hilink_param *)buf_out;
	struct hns3_hilink_param *hns3_param_in =
					     (struct hns3_hilink_param *)buf_in;
	struct hclge_dev *hdev = vport->back;
	bool check = !buf_in || in_size < sizeof(struct hns3_hilink_param) ||
		     !buf_out || out_size < sizeof(struct hns3_hilink_param);
	int ret;

	if (check) {
		pr_err("input parameter error in %s function\n", __func__);
		return -EFAULT;
	}

	memset(hns3_param_out->ctle_param, 0x0,
	       sizeof(hns3_param_out->ctle_param));
	memset(hns3_param_out->dfe_param, 0x0,
	       sizeof(hns3_param_out->dfe_param));
	memset(hns3_param_out->ffe_param, 0x0,
	       sizeof(hns3_param_out->ffe_param));

	ret = hns3_get_hilink_ctle(hdev, hns3_param_in->lane_start,
				   hns3_param_in->lane_len, hns3_param_out);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink ctle cmd failed %d\n",
			ret);
		return ret;
	}

	ret = hns3_get_hilink_dfe(hdev, hns3_param_in->lane_start,
				  hns3_param_in->lane_len, hns3_param_out);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink dfe cmd failed %d\n",
			ret);
		return ret;
	}

	ret = hns3_get_hilink_ffe(hdev, hns3_param_in->lane_start,
				  hns3_param_in->lane_len, hns3_param_out);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get hilink ffe cmd failed %d\n",
			ret);
		return ret;
	}

	return ret;
}
