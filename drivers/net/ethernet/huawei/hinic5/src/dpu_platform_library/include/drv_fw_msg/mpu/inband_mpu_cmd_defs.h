/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : inband_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : mpu cmd
 */

#ifndef INBAND_MPU_CMD_DEFS_H
#define INBAND_MPU_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"

typedef struct {
	struct mgmt_msg_head head;

	u8 low_power_enable;
	u8 opt_type;
	u8 rsv[6];
	u32 ncsi_enter_low_power_mode_cnt;
	u32 ncsi_exit_low_power_mode_cnt;
} comm_cmd_low_power_set_s;

#define MAX_LOG_BUF_SIZE 1024
struct nic_cmd_get_uart_log_info {
	struct mgmt_msg_head head;
	struct {
		u32 ret : 8;
		u32 version : 8;
		u32 log_elem_real_num : 16;
	} log_head;
	char uart_log[MAX_LOG_BUF_SIZE];
};

#define MAX_LOG_CMD_BUF_SIZE 128
struct nic_cmd_set_uart_log_cmd {
	struct mgmt_msg_head head;
	struct {
		u32 ret : 8;
		u32 version : 8;
		u32 cmd_elem_real_num : 16;
	} log_head;
	char uart_cmd[MAX_LOG_CMD_BUF_SIZE];
};

enum log_or_index_type {
	MPU_COMM_GET_LOG = 0,    /**< Get mpu log */
	MPU_COMM_GET_INDEX,      /**< Get index log */
	NPU_COMM_GET_SIM_DATA,   /**< Get microcode dictionary from flash */
};

enum log_module_type {
	LOG_MODULE_TYPE_MPU_LOG = 0,
	LOG_MODULE_TYPE_NPU_LOG,
	LOG_MODULE_TYPE_SMU_LOG,
	LOG_MODULE_TYPE_MPU_LASTWORD,
	LOG_MODULE_TYPE_NPU_LASTWORD,
	LOG_MODULE_TYPE_MPU_RELOAD_LOG = 5,
	LOG_MODULE_TYPE_MPU_CNT_DICT,
	LOG_MODULE_TYPE_NPU_CNT_DICT,
	LOG_MODULE_TYPE_UBC_IMP_LOG,
	LOG_MODULE_TYPE_UBC_IMP_LASTWORD,
	LOG_MODULE_TYPE_ROCE_IMP_LOG = 10,
	LOG_MODULE_TYPE_ROCE_SCC_LOG,
	LOG_MODULE_TYPE_BUTT
};

enum log_area_type {
	LOG_AREA_RAM = 0,
	LOG_AREA_FLASH,
};

struct nic_log_info {
	struct mgmt_msg_head msg_head;

	u32 offset;
	u8 log_or_index;	// 0:log;    1:index;
	u8 type;		// 0:up; 1:ucode;
				// 2:smu;(log_or_index: 0, this bit: log type,
				//	  1, this bit: dictionary type)
				// 3:mpu lastword 4:npu lastword
				// 5:mpu cnt dictionary file, 6: npu cnt dictionary file
	u8 area;		// 0:ram;
				// 1:flash; (this bit is only valid when log_or_index is 0)
	u8 rsvd1;		// reserved
	u8 data[MAX_LOG_BUF_SIZE]; // 1KB data per fetch
};

/* Log control info (pi and log sequence info reserved for log anti-overwrite function) */
typedef struct {
	u32 log_valid;	/* Log valid bit */
	u32 rsv_log_pi;
	u32 pi;		/* Log offset */
	/* Log sequence number, incremented by 1 per write, identifies which log session,
	 * and the next partition to write to (even: master partition, odd: backup partition)
	 */
	u32 log_seq;
	u32 info_rsv[2]; /* Log reserved info rsv field */
} log_ctrl_info_s;

typedef struct {
	u32 log_type : 2;  /* Log data source, 0:up, 1:ucode, 2:sec */
	u32 rsvd1 : 6;
	u32 core_id : 2;
	u32 time_sync : 1;  /* Whether time is synced, MPU_LOG_TIME_SYNC_TYPE type */
	u32 patch_log : 1; /* Patch log flag, 0: non-patch log, 1: patch log */
	u32 patch_log_level : 3; /* Patch log level */
	u32 rsvd3 : 17;
} log_head_mpu;

typedef struct {
	u32 index : 8;
	u32 valid : 1;
	u32 rsv : 23;
} log_head_imp;

typedef struct {
	u32 log_type : 2;  /* Log data source, 0:up, 1:ucode, 2:sec */
	u32 core_id : 6;   /* Microcode core id, valid when type is 1 */
	u32 thread_id : 2; /* Microcode thread id, valid when type is 1 */
	u32 srv_data : 22; /* Feature private data */
} log_head_def;

/* User log entry */
#define LOG_USER_ITEM 4

/* Log storage format, total size is 32B */
typedef struct {
	/* DW0 */
	union {
		log_head_mpu mpu;
		log_head_imp imp;
		log_head_def def;
	} head;

	/* DW1 */
	u16 file_id;       /* Stored file ID */
	u16 code_line_num; /* Line where the print code is located */

	/* DW2~DW3 */
	u32 time_l32; /* Time counter (low) */
	u32 time_h32; /* Time counter (high) */

	/* Dw4~DW7 */
	u32 user_val[LOG_USER_ITEM]; /* Determined by each log entry type */
} log_item_s;

typedef struct tag_mpu_mctp_counter_info {
	u32 mctp_send_get_routing_tbl_port_err;
	u32 mctp_get_routing_tbl_trans_pkt_err;
	u32 mctp_dis_eid_proc_msg_len_err;
	u32 mctp_send_one_cmd_trans_pkt_err;
	u32 mctp_send_first_cmd_trans_pkt_err;
	u32 mctp_send_middle_cmd_trans_pkt_err;
	u32 mctp_send_last_cmd_trans_pkt_err;
	u32 mctp_get_routing_tbl_err;
	u32 mctp_lldp_capture_send_cmd_msg_err;
	u32 mctp_reset_unsupported_err;
	u32 mctp_set_eid_msg_len_err;
	u32 mctp_set_eid_req_eid_err;
	u32 mctp_get_eid_msg_len_err;
	u32 mctp_predis_eid_msg_len_err;
	u32 mctp_notify_dis_iid_err;
	u32 mctp_get_routing_tbl_fail_err;
	u32 mctp_ctrl_cmd_not_support_err;
	u32 mctp_handle_cmd_ic_err;
	u32 mctp_handle_cmd_proc_err;
	u32 mctp_handle_cmd_func_remap_err;
	u32 mctp_handle_cmd_send_msg_err;
	u32 mctp_assemble_not_first_pkt_err;
	u32 mctp_assemble_msg_check_tag_err;
	u32 mctp_assemble_msg_check_seq_err;
	u32 mctp_assemble_msg_rcv_offset_err;
	u32 mctp_check_pkg_len_shorter_err;
	u32 mctp_check_pkg_len_err;
	u32 mctp_check_pkg_trans_head_err;
	u32 mctp_ncsi_msg_proc_err;
	u32 mctp_pldm_msg_proc_err;
	u32 mctp_handle_msg_type_not_support_err;
	u32 mctp_handle_msg_fail_err;
	u32 mctp_handle_msg_send_cmd_msg_err;
	u32 mctp_alloc_rcv_buff_err;
	u32 mctp_alloc_send_buff_err;
	u32 mctp_assemble_msg_err;
	u32 mctp_pkt_proc_err;
	u32 mctp_recv_pkt_pldm_type;
	u32 mctp_pldm_msg_handle_err;
	u32 mctp_recv_pkt_ncsi_type;
	u32 mctp_ncsi_msg_handle_err;
	u32 mctp_recv_full_pkt_cnt;
	u32 mctp_recv_ctr_pkt_cnt;
	u32 mctp_recv_data_pkt_cnt;
	u32 mctp_handle_cmd_proc_cnt;
	u32 mctp_set_eid_msg_cnt;
	u32 mctp_get_eid_msg_cnt;
	u32 mctp_get_uuid_msg_cnt;
	u32 mctp_get_version_msg_cnt;
	u32 mctp_get_msgtype_msg_cnt;
	u32 mctp_resovle_eid_msg_cnt;
	u32 mctp_update_routing_tbl_msg_cnt;
	u32 mctp_get_routing_tbl_msg_cnt;
	u32 mctp_predis_eid_msg_cnt;
	u32 mctp_dis_eid_proc_msg_cnt;
	u32 mctp_notify_dis_msg_cnt;
	u32 mctp_get_network_id_msg_cnt;
	u32 mctp_query_hop_msg_cnt;
	u32 mctp_resolve_uuid_msg_cnt;
	u32 mctp_handle_cmd_send_cnt;
	u32 mctp_handle_msg_proc_cnt;
	u32 mctp_handle_msg_send_cnt;
	u32 mctp_assemble_msg_correct;
	u32 mctp_lldp_capture_send_cmd_msg_cnt;
} mpu_mctp_counter_info_s;

#define OOB_INFO_BUFFER_MAX 1024
typedef struct comm_cmd_oob_info_resp_new {
	struct mgmt_msg_head head; /* 8B */
	u8 oob_info_buf[OOB_INFO_BUFFER_MAX];
} comm_cmd_oob_info_resp_new;

enum sfp_type_enum {
    SFP_TYPE_SFP = 0,
    SFP_TYPE_QSFP = 1,
    SFP_TYPE_OSFP = 2,
    SFP_TYPE_DSFP = 3,
    SFP_TYPE_COUNT
};

enum power_channel_enum {
    POWER_CHANNEL_INDEX_0 = 0,
    POWER_CHANNEL_INDEX_1 = 1,
    POWER_CHANNEL_INDEX_2 = 2,
    POWER_CHANNEL_INDEX_3 = 3,
    POWER_CHANNEL_INDEX_COUNT
};

#endif
