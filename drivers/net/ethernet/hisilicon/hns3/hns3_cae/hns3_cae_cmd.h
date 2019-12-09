/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_CMD_H
#define __HNS3_CAE_CMD_H
#include <linux/types.h>
#include "hnae3.h"
#include "hclge_main.h"
#include "hclge_cmd.h"

#define HNS3_CAE_DESC_DATA_LEN		6

struct hns3_cae_desc {
	__le16 opcode;

#define HNS3_CAE_CMDQ_RX_INVLD_B		0
#define HNS3_CAE_CMDQ_RX_OUTVLD_B		1

	__le16 flag;
	__le16 retval;
	__le16 rsv;
	__le32 data[HNS3_CAE_DESC_DATA_LEN];
};

int hns3_cae_cmd_send(struct hclge_dev *hdev, struct hclge_desc *desc, int num);
void hns3_cae_cmd_setup_basic_desc(struct hclge_desc *desc,
				   enum hclge_opcode_type opcode, bool is_read);
void hns3_cae_cmd_reuse_desc(struct hclge_desc *desc, bool is_read);
struct hclge_vport *hns3_cae_get_vport(struct hnae3_handle *handle);

#endif
