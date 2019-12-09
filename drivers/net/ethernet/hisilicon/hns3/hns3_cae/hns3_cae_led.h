/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_LED_H__
#define __HNS3_CAE_LED_H__

#define HCLGE_OPC_LED_CFG_NCL_INFO	0x7021

struct led_statistic_param {
	u32 data[6];
};

int hns3_led_cfg_ncl_info(struct hns3_nic_priv *net_priv, void *buf_in,
			  u32 in_size, void *buf_out, u32 out_size);
#endif
