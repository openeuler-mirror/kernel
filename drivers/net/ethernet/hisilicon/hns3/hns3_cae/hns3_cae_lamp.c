// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifdef CONFIG_EXT_TEST
#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"
#include "hns3_cae_lamp.h"

int hns3_lamp_cfg(struct hns3_nic_priv *net_priv,
		  void *buf_in, u32 in_size, void *buf_out, u32 out_size)
{
	struct net_device *netdev = net_priv->netdev;
	struct hns3_lamp_signal *signal;
	struct hns3_lamp_param *param;
	int ret = -1;

	if (!buf_in || in_size < sizeof(struct hns3_lamp_param))
		return -ENODEV;

	param = (struct hns3_lamp_param *)buf_in;
	signal = (struct hns3_lamp_signal *)buf_out;

	if (param->op_type == LAMP_OP_GET_SGPIO) {
		if (!buf_out || out_size < sizeof(struct hns3_lamp_signal))
			return -ENODEV;
		ret = nic_get_led_signal(netdev, signal);
	} else if (param->op_type == LAMP_OP_SET_TYPE) {
		ret = nic_set_led(netdev, param->type, param->status);
	}

	return ret;
}
#endif
