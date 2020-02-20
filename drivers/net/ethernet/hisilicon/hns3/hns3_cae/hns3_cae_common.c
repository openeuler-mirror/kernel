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
#include "hns3_cae_cmd.h"
#include "hns3_cae_common.h"

static int hns3_cae_write_reg_cfg(const struct hns3_nic_priv *net_priv,
				  void *buf_in, u32 in_size,
				  void *buf_out, u32 out_size)
{
	struct reg_param *in_buf = (struct reg_param *)buf_in;
	struct hclge_vport *vport = NULL;
	struct hclge_dev *hdev = NULL;
	struct hclge_desc desc;
	int ret;

	vport = hns3_cae_get_vport(net_priv->ae_handle);
	hdev = vport->back;

	if (in_buf->bits_width == 64) {
		hns3_cae_cmd_setup_basic_desc(&desc, CMDQ_64_COM_CMD_OPCODE,
					      false);
		desc.data[0] = in_buf->addr;
		desc.data[1] = in_buf->data[0];
	} else {
		hns3_cae_cmd_setup_basic_desc(&desc, CMDQ_32_COM_CMD_OPCODE,
					      false);
		desc.data[0] = in_buf->addr;
		desc.data[2] = in_buf->data[0];
	}
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "%s fail, ret is %d.\n", __func__,
			ret);
		return ret;
	}

	return 0;
}

static int hns3_cae_read_reg_cfg(const struct hns3_nic_priv *net_priv,
				 void *buf_in, u32 in_size,
				 void *buf_out, u32 out_size)
{
	struct hclge_vport *vport = hns3_cae_get_vport(net_priv->ae_handle);
	struct reg_ret_param *out_buf = (struct reg_ret_param *)buf_out;
	struct reg_param *in_buf = (struct reg_param *)buf_in;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc desc;
	bool check = !buf_out || out_size < sizeof(struct reg_param);
	int ret;

	if (check) {
		pr_err("input param buf_out error in %s function\n", __func__);
		return -EFAULT;
	}

	if (in_buf->bits_width == 64)
		hns3_cae_cmd_setup_basic_desc(&desc,
					      CMDQ_64_COM_CMD_OPCODE, true);
	else
		hns3_cae_cmd_setup_basic_desc(&desc,
					      CMDQ_32_COM_CMD_OPCODE, true);

	desc.data[0] = in_buf->addr;
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "%s fail, ret is %d.\n", __func__,
			ret);
		return ret;
	}

	out_buf->value[0] = desc.data[0];
	if (in_buf->bits_width == 64)
		out_buf->value[1] = desc.data[1];

	return 0;
}

int hns3_cae_reg_cfg(const struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out,
		     u32 out_size)
{
	bool check = !buf_in || in_size < sizeof(struct reg_param);
	struct reg_param *mode_param = (struct reg_param *)buf_in;
	int ret;

	if (check) {
		pr_err("input param buf_in error in %s function\n", __func__);
		return -EFAULT;
	}

	if (mode_param->is_read == 1)
		ret = hns3_cae_read_reg_cfg(net_priv, buf_in, in_size,
					    buf_out, out_size);
	else
		ret = hns3_cae_write_reg_cfg(net_priv, buf_in, in_size,
					     buf_out, out_size);

	return ret;
}
