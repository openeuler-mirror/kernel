/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_CMD_H__
#define __UDMA_CMD_H__

#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_mbx.h>
#include <ub/ubase/ubase_comm_ctrlq.h>
#include "udma_dev.h"

extern bool debug_switch;

#define UDMA_MAILBOX_SIZE 4096

#define SPEED_200G  200000
#define SPEED_400G  400000
#define SPEED_100G  100000
#define SPEED_50G   50000
#define SPEED_25G   25000

#define UDMA_CTRLQ_SEID_NUM	64

struct udma_ctrlq_eid_info {
	uint32_t eid_idx;
	union ubcore_eid eid;
	uint32_t upi;
} __packed;

struct udma_ctrlq_eid_in_query {
	uint32_t cmd : 8;
	uint32_t rsv : 24;
};

struct udma_ctrlq_eid_out_query {
	uint32_t seid_num : 8;
	uint32_t rsv : 24;
	struct udma_ctrlq_eid_info eids[UDMA_CTRLQ_SEID_NUM];
} __packed;

struct udma_ctrlq_eid_out_update {
	struct udma_ctrlq_eid_info eid_info;
	uint32_t op_type : 4;
	uint32_t rsv : 28;
} __packed;

enum udma_ctrlq_eid_update_op {
	UDMA_CTRLQ_EID_ADD = 0,
	UDMA_CTRLQ_EID_DEL,
};

enum udma_ctrlq_eid_guid_update_op {
	UDMA_CTRLQ_EID_GUID_ADD = 0,
	UDMA_CTRLQ_EID_GUID_DEL,
};

struct udma_ctrlq_ue_eid_guid_out {
	struct udma_ctrlq_eid_info eid_info;
	uint32_t op_type : 4;
	uint32_t rsv : 28;
	uint32_t ue_id;
	guid_t ue_guid;
} __packed;

enum udma_ctrlq_dev_mgmt_opcode {
	UDMA_CTRLQ_GET_SEID_INFO = 0x1,
	UDMA_CTRLQ_UPDATE_SEID_INFO = 0x2,
	UDMA_CTRLQ_OPC_UPDATE_UE_SEID_GUID = 0x3,
	UDMA_CTRLQ_GET_DEV_RESOURCE_COUNT = 0x11,
	UDMA_CTRLQ_GET_DEV_RESOURCE_RATIO = 0x12,
	UDMA_CTRLQ_NOTIFY_DEV_RESOURCE_RATIO = 0x13,
};

enum udma_cmd_opcode_type {
	UDMA_CMD_QUERY_UE_RES = 0x0002,
	UDMA_CMD_QUERY_UE_INDEX = 0x241d,
	UDMA_CMD_CFG_CONG_PARAM = 0x3003,
	UDMA_CMD_CHANGE_ACTIVE_PORT = 0x3102,
	UDMA_CMD_GET_CQE_AUX_INFO = 0x4213,
	UDMA_CMD_GET_AE_AUX_INFO = 0x4214,
	UDMA_CMD_QUERY_PORT_INFO = 0x6200,
	UDMA_CMD_WQEBB_VA_INFO = 0xa01f,
};

struct udma_cmd {
	uint32_t opcode;
	void *in_buf;
	uint32_t in_len;
	void *out_buf;
	uint32_t out_len;
};

enum {
	/* JFS CMDS */
	UDMA_CMD_CREATE_JFS_CONTEXT = 0x04,
	UDMA_CMD_MODIFY_JFS_CONTEXT = 0x05,
	UDMA_CMD_QUERY_JFS_CONTEXT = 0x06,
	UDMA_CMD_DESTROY_JFS_CONTEXT = 0x07,

	/* RC CMDS */
	UDMA_CMD_CREATE_RC_CONTEXT = 0x14,
	UDMA_CMD_MODIFY_RC_CONTEXT = 0x15,
	UDMA_CMD_QUERY_RC_CONTEXT = 0x16,
	UDMA_CMD_DESTROY_RC_CONTEXT = 0x17,

	/* JFC CMDS */
	UDMA_CMD_CREATE_JFC_CONTEXT = 0x24,
	UDMA_CMD_MODIFY_JFC_CONTEXT = 0x25,
	UDMA_CMD_QUERY_JFC_CONTEXT = 0x26,
	UDMA_CMD_DESTROY_JFC_CONTEXT = 0x27,

	/* JFR CMDS */
	UDMA_CMD_CREATE_JFR_CONTEXT = 0x54,
	UDMA_CMD_MODIFY_JFR_CONTEXT = 0x55,
	UDMA_CMD_QUERY_JFR_CONTEXT = 0x56,
	UDMA_CMD_DESTROY_JFR_CONTEXT = 0x57,

	/* JETTY GROUP CMDS */
	UDMA_CMD_CREATE_JETTY_GROUP_CONTEXT = 0x64,
	UDMA_CMD_MODIFY_JETTY_GROUP_CONTEXT = 0x65,
	UDMA_CMD_QUERY_JETTY_GROUP_CONTEXT = 0x66,
	UDMA_CMD_DESTROY_JETTY_GROUP_CONTEXT = 0x67,

	/* TP CMDS */
	UDMA_CMD_QUERY_TP_CONTEXT = 0x86,
};

struct udma_mbx_op_match {
	uint32_t	op;
	bool		ignore_ret;
	uint32_t	entry_size;
};

struct cap_info {
	uint16_t ar_en : 1;
	uint16_t jfc_per_wr : 1;
	uint16_t stride_up : 1;
	uint16_t load_store_op : 1;
	uint16_t jfc_inline : 1;
	uint16_t non_pin : 1;
	uint16_t selective_retrans : 1;
	uint16_t rsvd : 9;
	uint16_t rsvd1;
};

struct udma_cmd_ue_resource {
	/* BD0 */
	uint16_t jfs_num_shift : 4;
	uint16_t jfr_num_shift : 4;
	uint16_t jfc_num_shift : 4;
	uint16_t jetty_num_shift : 4;

	uint16_t jetty_grp_num;

	uint16_t jfs_depth_shift : 4;
	uint16_t jfr_depth_shift : 4;
	uint16_t jfc_depth_shift : 4;
	uint16_t cqe_size_shift : 4;

	uint16_t jfs_sge : 5;
	uint16_t jfr_sge : 5;
	uint16_t jfs_rsge : 6;

	uint16_t max_jfs_inline_sz;
	uint16_t max_jfc_inline_sz;
	uint32_t cap_info;

	uint16_t trans_mode : 5;
	uint16_t ue_num : 8;
	uint16_t virtualization : 1;
	uint16_t dcqcn_sw_en : 1;
	uint16_t rsvd0 : 1;

	uint16_t ue_cnt;
	uint8_t ue_id;
	uint8_t default_cong_alg;
	uint8_t cons_ctrl_alg;
	uint8_t cc_priority_cnt;

	/* BD1 */
	uint16_t src_addr_tbl_sz;
	uint16_t src_addr_tbl_num;
	uint16_t dest_addr_tbl_sz;
	uint16_t dest_addr_tbl_num;
	uint16_t seid_upi_tbl_sz;
	uint16_t seid_upi_tbl_num;
	uint16_t tpm_tbl_sz;
	uint16_t tpm_tbl_num;
	uint32_t tp_range;
	uint8_t port_num;
	uint8_t port_id;
	uint8_t rsvd1[2];
	uint16_t rc_queue_num;
	uint16_t rc_depth;
	uint8_t rc_entry;
	uint8_t rsvd2[3];

	/* BD2 */
	uint16_t well_known_jetty_start;
	uint16_t well_known_jetty_num;
	uint16_t ccu_jetty_start;
	uint16_t ccu_jetty_num;
	uint16_t drv_jetty_start;
	uint16_t drv_jetty_num;
	uint16_t cache_lock_jetty_start;
	uint16_t cache_lock_jetty_num;
	uint16_t normal_jetty_start;
	uint16_t normal_jetty_num;
	uint16_t standard_jetty_start;
	uint16_t standard_jetty_num;
	uint32_t rsvd3[2];

	/* BD3 */
	uint32_t max_write_size;
	uint32_t max_read_size;
	uint32_t max_cas_size;
	uint32_t max_fetch_and_add_size;
	uint32_t atomic_feat;
	uint32_t rsvd4[3];
};

struct udma_cmd_port_info {
	uint32_t speed;
	uint8_t rsv[10];
	uint8_t lanes;
	uint8_t rsv2[9];
};

struct udma_cmd_wqebb_va {
	uint64_t va_start;
	uint64_t va_size;
	uint32_t die_num;
	uint32_t ue_num;
};

#define UDMA_CMD_QUERY_ALL_AUX_INFO 0xF

struct udma_cmd_query_cqe_aux_info {
	uint32_t status : 8;
	uint32_t is_client : 1;
	uint32_t rsvd : 23;

	uint32_t cqe_aux_info[MAX_CQE_AUX_INFO_TYPE_NUM];
};

struct udma_cmd_query_ae_aux_info {
	uint32_t event_type : 8;
	uint32_t sub_type : 8;
	uint32_t rsvd : 16;

	uint32_t ae_aux_info[MAX_AE_AUX_INFO_TYPE_NUM];
};

static inline void udma_fill_buf(struct ubase_cmd_buf *buf, u16 opcode,
				 bool is_read, u32 data_size, void *data)
{
	buf->opcode = opcode;
	buf->is_read = is_read;
	buf->data_size = data_size;
	buf->data = data;
}

static inline struct ubase_cmd_mailbox *udma_alloc_cmd_mailbox(struct udma_dev *dev)
{
	return ubase_alloc_cmd_mailbox(dev->comdev.adev);
}

static inline void udma_free_cmd_mailbox(struct udma_dev *dev, struct ubase_cmd_mailbox *mailbox)
{
	return ubase_free_cmd_mailbox(dev->comdev.adev, mailbox);
}

int udma_cmd_init(struct udma_dev *udma_dev);
void udma_cmd_cleanup(struct udma_dev *udma_dev);
int udma_post_mbox(struct udma_dev *dev, struct ubase_cmd_mailbox *mailbox,
		   struct ubase_mbx_attr *attr);
int udma_cmd_query_hw_resource(struct udma_dev *udma_dev, void *out_addr);
int udma_config_ctx_buf_to_hw(struct udma_dev *udma_dev,
			      struct udma_buf *ctx_buf,
			      struct ubase_mbx_attr *attr);
int post_mailbox_update_ctx(struct udma_dev *udma_dev, void *ctx, uint32_t size,
			    struct ubase_mbx_attr *attr);
struct ubase_cmd_mailbox *udma_mailbox_query_ctx(struct udma_dev *udma_dev,
						 struct ubase_mbx_attr *attr);
int udma_close_ue_rx(struct udma_dev *dev, bool check_feature_enable, bool check_ta_flush,
		     bool is_reset, uint32_t tp_num);
int udma_open_ue_rx(struct udma_dev *dev, bool check_feature_enable, bool check_ta_flush,
		    bool is_reset, uint32_t tp_num);

#endif /* __UDMA_CMD_H__ */
