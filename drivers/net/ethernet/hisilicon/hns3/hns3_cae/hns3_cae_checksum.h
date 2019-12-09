/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_CHECKSUM_H__
#define __HNS3_CAE_CHECKSUM_H__

#include "hns3_enet.h"

#define HCLGE_CHS_OUT_L3_B 0
#define HCLGE_CHS_OUT_UDP_B 1
#define HCLGE_CHS_INNER_L3_B 0
#define HCLGE_CHS_INNER_TCP_B 1
#define HCLGE_CHS_INNER_UDP_B 2
#define HCLGE_CHS_INNER_SCTP_B 3
#define HCLGE_OPC_CHECKSUM_CHECK_EN 0x0601

#define OUTER_L3_CHECK_EN		0x1
#define OUTER_UDP_CHECK_EN		0x1
#define INNER_L3_CHECK_EN		0x1
#define INNER_TCP_CHECK_EN		0x1
#define INNER_UDP_CHECK_EN		0x1
#define INNER_SCTP_CHECK_EN		0x1

enum {
	CKS_OUTER_L3_EN = 0,
	CKS_OUTER_UDP_EN,
	CKS_INNER_L3_EN,
	CKS_INNER_TCP_EN,
	CKS_INNER_UDP_EN,
	CKS_INNER_SCTP_EN,
	CKS_MAX,
};

struct hns3_cae_chs_cmd_param {
	u8 outer_en;
	u8 inner_en;
	u8 rsv[22];
};

struct hns3_cae_chs_param {
	u8 is_set;
	u8 type;
	u8 is_enable;
};

int hns3_cae_chs_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size);
#endif
