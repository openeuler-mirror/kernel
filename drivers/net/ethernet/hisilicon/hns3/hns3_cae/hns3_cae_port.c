// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_port.h"

#define HCLGE_CMD_DATA_BYTE_LEN			24
#define BD_NUM_5				5
#define BD_NUM_6				6
#define BD_NUM_7				7

static void fill_port_info(struct hclge_port_info *get_port_info_out,
			   struct hclge_desc *port_desc, u32 bd_num)
{
	u8 *dest_data = NULL;
	u8 *tmp_buff = NULL;
	u32 i;

	dest_data = (u8 *)get_port_info_out;

	/* first BD (24 Bytes) */
	for (i = 0; i < bd_num; i++) {
		tmp_buff = (u8 *)&port_desc[i].data[0];
		if (i == BD_NUM_5) {
			get_port_info_out->his_link_machine_state =
			    port_desc[i].data[0];
			get_port_info_out->his_machine_state_length =
			    port_desc[i].data[1] & 0xFF;
			memcpy(get_port_info_out->his_machine_state_data,
			       tmp_buff + 5, 19);
		} else if (i == BD_NUM_6) {
			get_port_info_out->cur_link_machine_state =
			    port_desc[i].data[0];
			get_port_info_out->cur_machine_state_length =
			    port_desc[i].data[1] & 0xFF;
			memcpy(get_port_info_out->cur_machine_state_data,
			       tmp_buff + 5, 19);
		} else {
			if (i == BD_NUM_7)
				dest_data =
				    (u8 *)&get_port_info_out->param_info;

			memcpy(dest_data, tmp_buff, HCLGE_CMD_DATA_BYTE_LEN);
			if (i != (bd_num - 1))
				dest_data = dest_data + HCLGE_CMD_DATA_BYTE_LEN;
		}
	}
}

int hns3_get_port_info(const struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size, void *buf_out,
		       u32 out_size)
{
	struct hnae3_handle *handle = hns3_get_handle(net_priv->netdev);
	struct hclge_vport *vport = hns3_cae_get_vport(handle);
	struct hclge_port_info *get_port_info_out =
					      (struct hclge_port_info *)buf_out;
	struct hclge_dev *hdev = vport->back;
	struct hclge_desc *port_desc = NULL;
	struct hclge_desc desc = {0};
	__le32 *desc_data = NULL;
	u32 bd_num;
	int ret;
	u32 i;

	if (!buf_out || out_size < sizeof(struct hclge_port_info))
		return -ENODEV;

	get_port_info_out->gpio_insert = 0;

	hns3_cae_cmd_setup_basic_desc(&desc, HCLGE_OPC_QUERY_PORTINFO_BD_NUM,
				      true);
	ret = hns3_cae_cmd_send(hdev, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"hclge get port info BD num failed %d\n", ret);
		return ret;
	}

	desc_data = (__le32 *)(&desc.data[0]);
	bd_num = le32_to_cpu(*desc_data);

	port_desc = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(port_desc))
		return -ENOMEM;

	for (i = 0; i < bd_num; i++) {
		hns3_cae_cmd_setup_basic_desc(&port_desc[i],
					      HCLGE_OPC_DUMP_PORT_INFO, true);
		if (i < bd_num - 1)
			port_desc[i].flag |= cpu_to_le16(HCLGE_CMD_FLAG_NEXT);
		else
			port_desc[i].flag &=
			    ~(cpu_to_le16(HCLGE_CMD_FLAG_NEXT));
	}

	ret = hns3_cae_cmd_send(hdev, port_desc, bd_num);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"get port information cmd failed %d\n", ret);
		kfree(port_desc);
		return ret;
	}

	fill_port_info(get_port_info_out, port_desc, bd_num);

	kfree(port_desc);

	return ret;
}
