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
	HNS3_ROH_OPC_QUERY_PORT_LINK_STATUS = 0x038a,
	HNS3_ROH_OPC_SET_EID = 0x9001,
	HNS3_ROH_OPC_QUERY_MIB_PUBLIC = 0x9005,
	HNS3_ROH_OPC_QUERY_MIB_PRIVATE = 0x9006,
};

struct hns3_roh_errcode {
	u32 imp_errcode;
	int common_errno;
};

enum hns3_roh_cmd_return_status {
	HNS3_ROH_CMD_EXEC_SUCCESS	= 0,
	HNS3_ROH_CMD_NO_AUTH		= 1,
	HNS3_ROH_CMD_NOT_SUPPORTED	= 2,
	HNS3_ROH_CMD_QUEUE_FULL		= 3,
	HNS3_ROH_CMD_NEXT_ERR		= 4,
	HNS3_ROH_CMD_UNEXE_ERR		= 5,
	HNS3_ROH_CMD_PARA_ERR		= 6,
	HNS3_ROH_CMD_RESULT_ERR		= 7,
	HNS3_ROH_CMD_TIMEOUT		= 8,
	HNS3_ROH_CMD_HILINK_ERR		= 9,
	HNS3_ROH_CMD_QUEUE_ILLEGAL	= 10,
	HNS3_ROH_CMD_INVALID		= 11,
};

enum hns3_roh_mbx_opcode {
	HNS3_ROH_MBX_PUSH_LINK_STATUS = 201 /* (M7 -> PF) get port link status */
};

struct hns3_roh_get_intr_info {
	__le16 tqp_num;
	__le16 packet_buffer_cell_cnt;
	__le16 msixcap_localid_ba_nic;
	__le16 msixcap_localid_number_nic;
	__le16 pf_intr_vector_number_roce;
	__le16 pf_own_fun_number;
	__le16 tx_pkt_buffer_cell_cnt;
	__le16 delay_value_cell_num;
	__le16 tqp_number_1k;
	__le16 pf_intr_vector_number_roh;
	u8 rsv[4];
};

struct hns3_roh_set_eid_info {
	__le32 base_eid;
	__le32 num_eid;
	u8 rsv[16];
};

struct hns3_roh_query_link_status_info {
	__le32 query_link_status;
	u8 rsv[20];
};

#define HNS3_ROH_MBX_MAX_MSG_SIZE 14

struct hns3_roh_vf_to_pf_msg {
	u8 code;
	struct {
		u8 subcode;
		u8 data[HNS3_ROH_MBX_MAX_MSG_SIZE];
	};
};

struct hns3_roh_mbx_vf_to_pf_cmd {
	u8 rsv;
	u8 mbx_src_vfid; /* Auto filled by IMP */
	u8 mbx_need_resp;
	u8 rsv1;
	u8 msg_len;
	u8 rsv2[3];
	struct hns3_roh_vf_to_pf_msg msg;
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
int hns3_roh_get_link_status(struct hns3_roh_device *hroh_dev, u32 *link_status);
void hns3_roh_update_link_status(struct hns3_roh_device *hroh_dev);

#endif /* __HNS3_ROH_CMDQ_H__ */
