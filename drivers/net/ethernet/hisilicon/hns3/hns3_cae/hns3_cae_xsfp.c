// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_xsfp.h"

#define BD0_DATA_LEN	20
#define BD1_DATA_LEN	24

static int hns3_get_sfp_present(struct hnae3_handle *handle, u32 *present)
{
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	struct hclge_sfp_present_cmd *resp = NULL;
	struct hclge_desc desc;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, XSFP_OPC_SFP_GET_PRESENT, true);
	resp = (struct hclge_sfp_present_cmd *)desc.data;
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get spf present failed %d\n", ret);
		return ret;
	}

	*present = resp->sfp_present;
	return 0;
}

static int _hns3_get_sfpinfo(struct hnae3_handle *handle, u8 *buff,
			     u16 offset, u16 size, u16 *outlen)
{
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hclge_desc desc[HCLGE_SFP_INFO_LEN];
	struct hclge_dev *hdev = vport->back;
	struct hclge_sfp_info *resp = NULL;
	u32 data_length;
	u8 *temp_data = NULL;
	u32 temp_len;
	int ret;
	u32 i;
	u32 j;

	memset(desc, 0x0, sizeof(desc));

	for (i = 0; i < HCLGE_SFP_INFO_LEN; i++) {
		hns3_cae_cmd_setup_basic_desc(&desc[i], XSFP_OPC_SFP_GET_INFO,
					      true);
		if (i == 0)
			desc[0].data[0] = offset | (size << 16);

		if (i < HCLGE_SFP_INFO_LEN - 1)
			desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hns3_cae_cmd_send(hdev, desc, HCLGE_SFP_INFO_LEN);
	if (ret) {
		dev_err(&hdev->pdev->dev, "get spf information cmd failed %d\n",
			ret);
		return ret;
	}

	for (i = 0; i < HCLGE_SFP_INFO_LEN; i++) {
		resp = (struct hclge_sfp_info *)desc[i].data;
		if (i == 0) {
			*outlen = (resp[i].sfpinfo[0] >> 16) & 0xFFFF;
			temp_len = *outlen;
			data_length =
			    (temp_len > BD0_DATA_LEN) ? BD0_DATA_LEN : temp_len;
			temp_data = (u8 *)&resp->sfpinfo[1];
		} else {
			data_length =
			    (temp_len > BD1_DATA_LEN) ? BD1_DATA_LEN : temp_len;
			temp_data = (u8 *)&resp->sfpinfo[0];
		}

		for (j = 0; j < data_length; j++)
			*buff++ = *temp_data++;

		temp_len -= data_length;
		if (temp_len == 0)
			break;
	}

	return 0;
}

static int hns3_get_sfpinfo(struct hnae3_handle *handle, u8 *buff, u16 offset,
			    u16 size, u16 *outlen)
{
	u16 tmp_size;
	u8 *tmp_buff = NULL;
	u16 tmp_outlen;
	int ret;

	tmp_buff = buff;
	while (size) {
		WARN_ON_ONCE(!tmp_buff);
		if (size > HCLGE_SFP_INFO_SIZE)
			tmp_size = HCLGE_SFP_INFO_SIZE;
		else
			tmp_size = size;
		ret =
		    _hns3_get_sfpinfo(handle, tmp_buff, offset, tmp_size,
				      &tmp_outlen);
		if (ret)
			return ret;
		offset += tmp_size;
		size -= tmp_size;
		tmp_buff += tmp_size;
		*outlen += tmp_outlen;
		if (tmp_size != tmp_outlen)
			break;
	}
	return 0;
}

static int hns3_set_sfp_state(struct hnae3_handle *handle, bool en)
{
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hclge_sfp_enable_cmd *req = NULL;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	int ret;

	hns3_cae_cmd_setup_basic_desc(&desc, XSFP_OPC_SFP_SET_STATUS, false);
	req = (struct hclge_sfp_enable_cmd *)desc.data;
	req->set_sfp_enable_flag = en;

	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev, "set spf on/off cmd failed %d\n",
			ret);

	return ret;
}

int hns3_xsfp_cfg(const struct hns3_nic_priv *net_priv, void *buf_in,
		  u32 in_size, void *buf_out, u32 out_size)
{
	struct hns3_xsfp_info *xsfp_info_out = (struct hns3_xsfp_info *)buf_out;
	bool check = !buf_in || in_size < sizeof(struct hns3_cfg_xsfp) ||
		     !buf_out || out_size < sizeof(struct hns3_xsfp_info);
	struct hnae3_handle *handle = hns3_get_handle(net_priv->netdev);
	struct hns3_cfg_xsfp *param = (struct hns3_cfg_xsfp *)buf_in;
	u32 sfp_present = 0;
	int ret;

	if (check)
		return -ENODEV;

	ret = hns3_get_sfp_present(handle, &sfp_present);
	if (ret) {
		pr_err("nic_get_sfp_present error.\n");
		xsfp_info_out->light_module_status = 0xff;
		return 0;
	}

	xsfp_info_out->light_module_status = (u8)sfp_present;

	if (sfp_present) {
		if (param->cfg_optype == OPC_QUERY_XSFP_INFO) {
			ret = hns3_get_sfpinfo(handle, xsfp_info_out->sfp_info,
					       0,
					       STD_XSFP_INFO_A0_SIZE +
					       STD_XSFP_INFO_A2_SIZE,
					       &xsfp_info_out->eeprom_len);
			if (ret) {
				pr_err("hns3_get_sfpinfo error.\n");
				return ret;
			}
		} else if (param->cfg_optype == OPC_QUERY_ALL_XSFP_INFO) {
			ret = hns3_get_sfpinfo(handle, xsfp_info_out->sfp_info,
					       0, STD_XSFP_INFO_MAX_SIZE,
					       &xsfp_info_out->eeprom_len);
			if (ret) {
				pr_err("hns3_get_sfpinfo error.\n");
				return ret;
			}
		} else if (param->cfg_optype == OPC_CONFIG_XSFP_TX_STATUS) {
			ret = hns3_set_sfp_state(handle, param->status);
			if (ret) {
				pr_err("nic_set_sfp_state error.\n");
				return ret;
			}
		} else {
			pr_err("%s error: unsupport optype:%u.\n",
			       __func__, param->cfg_optype);
			ret = -EINVAL;
		}
	} else {
		ret = 0;
	}

	return ret;
}
