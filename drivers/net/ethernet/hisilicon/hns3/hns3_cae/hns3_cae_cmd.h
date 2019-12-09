/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_CMD_H__
#define __HNS3_CAE_CMD_H__
#include <linux/types.h>
#include "hnae3.h"
#include "hclge_main.h"
#include "hclge_cmd.h"

#define HCLGE_OPC_GRO_AGE_CFG		0x0c11

/* misc command */
#define HCLGE_OPC_CHIP_ID_GET		0x7003
#define HCLGE_OPC_IMP_COMMIT_ID_GET	0x7004
#define HCLGE_OPC_GET_CHIP_NUM		0x7005
#define HCLGE_OPC_GET_PORT_NUM		0x7006
/* SFP command */
#define HCLGE_OPC_SFP_GET_INFO		0x7100
#define HCLGE_OPC_SFP_GET_PRESENT	0x7101
#define HCLGE_OPC_SFP_SET_STATUS	0x7102
/* DCQCN command */
#define HCLGE_OPC_DCQCN_TEMPLATE_CFG	0x7014
#define HCLGE_OPC_DCQCN_GET_MSG_CNT	0x7017

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
