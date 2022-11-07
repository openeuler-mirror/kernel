/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2020-2022 Hisilicon Limited.

#ifndef __HNS3_ROH_CMDQ_H__
#define __HNS3_ROH_CMDQ_H__

#include "hns3_common.h"

#define HNS3_ROH_MAILBOX_SIZE 4096
#define HNS3_ROH_CMDQ_DESC_NUM 3
#define HNS3_ROH_CMDQ_TX_TIMEOUT 30000

#define HNS3_ROH_MAX_CMD_NUM 32

#define HNS3_ROH_CMDQ_CSQ_DESC_NUM 1024
#define HNS3_ROH_CMDQ_CRQ_DESC_NUM 1024

#define HNS3_ROH_CMD_FLAG_IN BIT(0)
#define HNS3_ROH_CMD_FLAG_OUT BIT(1)
#define HNS3_ROH_CMD_FLAG_NEXT BIT(2)
#define HNS3_ROH_CMD_FLAG_WR BIT(3)
#define HNS3_ROH_CMD_FLAG_NO_INTR BIT(4)
#define HNS3_ROH_CMD_FLAG_ERR_INTR BIT(5)

enum { HNS3_ROH_CMDQ_CRQ = 0, HNS3_ROH_CMDQ_CSQ };

enum hns3_roh_opcode_type {
	HNS3_ROH_OPC_GET_INTR_INFO = 0x0023,
	HNS3_ROH_OPC_SET_EID = 0x9001,
	HNS3_ROH_OPC_GET_GUID = 0x9002,
	HNS3_ROH_OPC_QUERY_MIB_PUBLIC = 0x9005,
	HNS3_ROH_OPC_QUERY_MIB_PRIVATE = 0x9006,
};

enum hns3_roh_cmd_return_status {
	HNS3_ROH_CMD_EXEC_SUCCESS = 0,
	HNS3_ROH_CMD_NO_AUTH,
	HNS3_ROH_CMD_NOT_EXIST,
	HNS3_ROH_CMD_QUEUE_FULL,
	HNS3_ROH_CMD_NEXT_ERR,
	HNS3_ROH_CMD_NOT_EXEC,
	HNS3_ROH_CMD_PARA_ERR,
	HNS3_ROH_CMD_RESULT_ERR,
	HNS3_ROH_CMD_EXEC_TIMEOUT
};

struct hns3_roh_set_eid_info {
	__le32 base_eid;
	__le32 num_eid;
	u8 rsv[16];
};

struct hns3_roh_get_guid_info {
	u8 guid[16];
	u8 rsv[8];
};

static inline void hns3_roh_mbx_ring_ptr_move_crq(struct hns3_roh_cmdq_ring *crq)
{
	crq->next_to_use = (crq->next_to_use + 1) % crq->desc_num;
}

int hns3_roh_cmdq_init(struct hns3_roh_device *hroh_dev);
void hns3_roh_cmdq_exit(struct hns3_roh_device *hroh_dev);
int hns3_roh_cmdq_send(struct hns3_roh_device *hroh_dev,
		       struct hns3_roh_desc *desc, int num);
void hns3_roh_cmdq_setup_basic_desc(struct hns3_roh_desc *desc,
				    enum hns3_roh_opcode_type opcode, bool is_read);

#endif /* __HNS3_ROH_CMDQ_H__ */
