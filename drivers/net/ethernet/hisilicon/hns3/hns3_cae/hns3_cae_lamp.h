/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_LAMP_H__
#define __HNS3_CAE_LAMP_H__
#include "hclge_cmd.h"
#include "hnae3.h"
#include "hclge_main.h"
#include "hns3_enet.h"

enum hns3_lamp_spgio_e {
	LAMP_OP_GET_SGPIO = 0,
	LAMP_OP_SET_TYPE,
	LAMP_OP_UNKNOWN
};

struct hns3_lamp_param {
	u32 op_type;
	u32 type;
	u32 status;
};

struct hns3_lamp_signal {
	u8 error;
	u8 locate;
	u8 activity;
};

int hns3_lamp_cfg(struct hns3_nic_priv *net_priv,
		  void *buf_in, u32 in_size,
		  void *buf_out, u32 out_size);
int nic_get_led_signal(struct net_device *ndev,
		       struct hns3_lamp_signal *signal);
int nic_set_led(struct net_device *ndev, int type, int status);

#endif
