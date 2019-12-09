/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_PROMISC_H__
#define __HNS3_CAE_PROMISC_H__

#include "hclge_main.h"
#include "hclge_cmd.h"
#include "hns3_enet.h"

#define HNS3_CAE_UC_PROMISC_EN_B	0x1
#define HNS3_CAE_MC_PROMISC_EN_B	0x2
#define HNS3_CAE_BC_PROMISC_EN_B	0x3

enum promisc_mode {
	HNS3_UNICAST = 0,
	HNS3_MULTICAST,
	HNS3_BROADCAST,
};

struct promisc_mode_param {
	u8 uc;
	u8 mc;
	u8 bc;
	u8 is_read;
	u8 type;
};

int hns3_promisc_mode_cfg(struct hns3_nic_priv *nic_dev,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size);
#endif
