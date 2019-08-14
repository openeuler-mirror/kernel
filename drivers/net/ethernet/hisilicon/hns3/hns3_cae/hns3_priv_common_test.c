// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/phy_fixed.h>
#include <linux/platform_device.h>

#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hnae3.h"
#include "hns3_enet.h"
#include "hns3_priv_common_test.h"

static int hns3_test_write_reg_cfg(struct hns3_nic_priv *net_priv,
				   void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size)
{
	struct reg_param *in_buf = (struct reg_param *)buf_in;
	enum hclge_cmd_status status;
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	hdev = vport->back;

	if (in_buf->bits_width == 64) {
		hclge_cmd_setup_basic_desc(&desc, CMDQ_64_COM_CMD_OPCODE,
					   false);
		desc.data[0] = in_buf->addr;
		desc.data[1] = in_buf->data[0];
	} else {
		hclge_cmd_setup_basic_desc(&desc, CMDQ_32_COM_CMD_OPCODE,
					   false);
		desc.data[0] = in_buf->addr;
		desc.data[2] = in_buf->data[0];
	}
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev, "%s fail, status is %d.\n", __func__,
			status);
		return status;
	}

	return 0;
}

static int hns3_test_read_reg_cfg(struct hns3_nic_priv *net_priv,
				  void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	struct reg_ret_param *out_buf = (struct reg_ret_param *)buf_out;
	struct reg_param *in_buf = (struct reg_param *)buf_in;
	struct hnae3_handle *handle = net_priv->ae_handle;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	enum hclge_cmd_status status;
	struct hclge_desc desc;

	if (in_buf->bits_width == 64)
		hclge_cmd_setup_basic_desc(&desc, CMDQ_64_COM_CMD_OPCODE, true);
	else
		hclge_cmd_setup_basic_desc(&desc, CMDQ_32_COM_CMD_OPCODE, true);

	desc.data[0] = in_buf->addr;
	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev, "%s fail, status is %d.\n", __func__,
			status);
		return status;
	}

	out_buf->value[0] = desc.data[0];
	if (in_buf->bits_width == 64)
		out_buf->value[1] = desc.data[1];

	return 0;
}

int hns3_test_reg_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct reg_param *mode_param = (struct reg_param *)buf_in;
	int ret;

	if (!mode_param) {
		pr_err("%s error: mode_param NULL.\n", __func__);
		return -EINVAL;
	}
	if (mode_param->is_read == 1)
		ret = hns3_test_read_reg_cfg(net_priv, buf_in, in_size,
					     buf_out, out_size);
	else
		ret = hns3_test_write_reg_cfg(net_priv, buf_in, in_size,
					      buf_out, out_size);

	return ret;
}

static int hns3_reg_read_cfg(struct hns3_nic_priv *net_priv,
			     void *buf_in, u16 in_size,
			     void *buf_out, u16 *out_size)
{
	struct com_reg_param *out_buf = (struct com_reg_param *)buf_out;
	struct com_reg_param *in_buf = (struct com_reg_param *)buf_in;
	struct hnae3_handle *handle = net_priv->ae_handle;
	struct hclge_vport *vport = hclge_get_vport(handle);
	struct hclge_dev *hdev = vport->back;
	enum hclge_cmd_status status;
	struct hclge_desc desc;
	int i;

	hclge_cmd_setup_basic_desc(&desc, in_buf->fw_dw_opcode,
				   in_buf->is_read);

	for (i = 0; i < 6; i++)
		desc.data[i] = in_buf->reg_desc.data[i];

	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev, "%s, status is %d.\n", __func__,
			status);
		return status;
	}

	for (i = 0; i < 6; i++)
		out_buf->reg_desc.data[i] = desc.data[i];

	return 0;
}

static int hns3_reg_write_cfg(struct hns3_nic_priv *net_priv,
			      void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size)
{
	struct hnae3_handle *handle;
	struct hclge_vport *vport;
	struct hclge_dev *hdev;
	struct hclge_desc desc;
	enum hclge_cmd_status status;
	struct com_reg_param *in_buf = (struct com_reg_param *)buf_in;
	int i;

	handle = net_priv->ae_handle;
	vport = hclge_get_vport(handle);
	hdev = vport->back;

	hclge_cmd_setup_basic_desc(&desc, in_buf->fw_dw_opcode,
				   in_buf->is_read);
	for (i = 0; i < 6; i++)
		desc.data[i] = in_buf->reg_desc.data[i];

	status = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (status) {
		dev_err(&hdev->pdev->dev, "%s, status is %d.\n", __func__,
			status);
		return status;
	}

	return 0;
}

int hns3_reg_cfg(struct hns3_nic_priv *net_priv,
		 void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	int ret = 0;
	struct com_reg_param *param;

	param = (struct com_reg_param *)buf_in;
	if (!param) {
		pr_err("%s error: param NULL.\n", __func__);
		return -EINVAL;
	}

	if (param->is_read == 1)
		ret = hns3_reg_read_cfg(net_priv, buf_in, in_size, buf_out,
					out_size);
	else
		ret = hns3_reg_write_cfg(net_priv, buf_in, in_size, buf_out,
					 out_size);

	return ret;
}
