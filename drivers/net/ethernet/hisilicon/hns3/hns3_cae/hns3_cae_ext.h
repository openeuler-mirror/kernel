/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_EXT_H
#define __HNS3_CAE_EXT_H

#include "hnae3.h"
#include "hns3_enet.h"

#define HNS3_AFFI_SET_BIT	BIT(0)
#define HNS3_AFFI_GET_BIT	BIT(1)

#define HNS3_AFFI_MAX_LEN	34

enum ext_op_code {
	EXT_AFFI_MASK = 0,
	EXT_DISABLE_NET_CLK,
	EXT_GET_CHIP_ID,
	EXT_NET_MATCH_CHECK,
	EXT_SET_LED,
	EXT_GET_SFP_INFO,
	EXT_GET_SFP_PRESENT,
	EXT_SET_SFP_STATE,
	EXT_CLEAN_STATS64,
	EXT_GET_CHIP_NUM,
	EXT_GET_PORT_NUM,
	EXT_DISABLE_NET_LANE,
	EXT_GET_LANE_STATUS,
	EXT_SET_MAC_STATE,
	EXT_SET_PFC_STORM_PARA,
	EXT_GET_PFC_STORM_PARA,
	EXT_GET_PHY_REG,
	EXT_SET_PHY_REG,
	EXT_GET_MAC_ID,
	EXT_GET_HILINK_REF_LOS,
	EXT_GET_8211_PHY_REG,
	EXT_SET_8211_PHY_REG,
};

enum phy_type {
	PHY_TYPE_8211 = 0,
	PHY_TYPE_1512,
};

struct hns3_cpumask_param {
	u32 affi_exec_flag;
	char mask[HNS3_AFFI_MAX_LEN];
};

struct hns3_priv_sfp_info_para {
	u8 buff[768];
	u16 offset;
	u16 size;
	u16 outlen;
};

struct cmd_ext_driver_param {
	u32 op_code;
	u32 judge_class;
	u8 buf[1024];
};

int hns3_ext_interface_test(struct hns3_nic_priv *net_priv,
			    void *buf_in, u32 in_size,
			    void *buf_out, u32 out_size);

#endif
