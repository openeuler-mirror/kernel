/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : inband_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : mpu cmd
 */

#ifndef INBAND_MPU_CMD_DEFS_H
#define INBAND_MPU_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"
#include "outband_mpu_ncsi_cmd_defs.h"

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
	MPU_COMM_GET_LOG = 0,    /**< get mpu log */
	MPU_COMM_GET_INDEX,      /**< get index log */
	NPU_COMM_GET_SIM_DATA,   /**< get ucode dictionary from flash */
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
	u8 log_or_index;           // 0:log;    1:index;
	u8 type;                   // 0:up; 1:ucode; 2:smu;(log_or_index: 0, this bit: log type, 1, this bit: dictionary type)
				// 3:mpu lastword 4.npu lastword
				// 5:mpu cnt dictionary file, 6. npu cnt dictionary file
	u8 area;                   // 0:ram;    1:flash;(only valid when log_or_index is 0)
	u8 rsvd1;                  // reserved
	u8 data[MAX_LOG_BUF_SIZE]; // get 1KB data at a time
};

/* log control info (pi and log sequence info reserved for log anti-overwrite function) */
typedef struct {
	u32 log_valid;   /* log valid bit */
	u32 rsv_log_pi;
	u32 pi;          /* log offset */
	u32 log_seq;     /* log sequence number, incremented by 1 each write, identifies which log, and the partition to write next (even writes to primary, odd writes to backup) */
	u32 info_rsv[2]; /* log reserved info rsv field */
} log_ctrl_info_s;

typedef struct {
	u32 log_type : 2;  /* log data source, 0: up, 1: ucode, 2: sec */
	u32 rsvd1 : 6;
	u32 core_id : 2;
	u32 time_sync : 1;  /* whether time is synchronized, MPU_LOG_TIME_SYNC_TYPE type */
	u32 patch_log : 1; /* patch log flag, 0: non-patch log, 1: patch log */
	u32 patch_log_level : 3; /* patch log level */
	u32 rsvd3 : 17;
} log_head_mpu;

typedef struct {
	u32 index : 8;
	u32 valid : 1;
	u32 rsv : 23;
} log_head_imp;

typedef struct {
	u32 log_type : 2;  /* log data source, 0: up, 1: ucode, 2: sec */
	u32 core_id : 6;   /* ucode core id, valid when type is 1 */
	u32 thread_id : 2; /* ucode thread id, valid when type is 1 */
	u32 srv_data : 22; /* feature private data */
} log_head_def;

/* user log entry */
#define LOG_USER_ITEM 4

/* log storage format, total size is 32B */
typedef struct {
	/* DW0 */
	union {
		log_head_mpu mpu;
		log_head_imp imp;
		log_head_def def;
	} head;

	/* DW1 */
	u16 file_id;       /* stores file ID */
	u16 code_line_num; /* line number of the print code */

	/* DW2~DW3 */
	u32 time_l32; /* time counter  */
	u32 time_h32; /* time counter  */

	/* Dw4~DW7 */
	u32 user_val[LOG_USER_ITEM]; /* determined by each type of log entry  */
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

#define OOB_INFO_BUFFER_MAX 1536
typedef struct {
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

/* flash check result 0: ok   1: error  2: data mismatch */
#define FLASH_CHECK_OK 0
#define FLASH_CHECK_ERR 1
#define FLASH_CHECK_DISMATCH 2

struct comm_info_check_flash {
	struct mgmt_msg_head head;
	u8 status;
	u8 rsv[3];
};

#define HINIC5_CAR_ENABLE_INVALID_NUM 0xFF

typedef struct tag_mpu_ncsi_counter_info_s {
	u32 ncsi_rx_octets_total_ok;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_octets_bad;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_uc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_mc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_bc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_64octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_65to127octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_128to255octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_255to511octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_512to1023octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_1024to1518octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_1519tomaxoctets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_fcs_errs;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_tagged;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_data_errs;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_align_errs;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_long_errs;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_jabber_errs;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pause_maccontrol_framcounter;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_unknow_maccontrol_framcounter;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_very_long_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_runt_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_short_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_filt_pkt_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_octets_total_filt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_octets_transmitte_ok;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_octets_transmitte_bad;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_uc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_mc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_bc_pkts;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_64octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_65to127octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_128to255octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_255to511octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_512to1023octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_1024to1518octets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_1519tomaxoctets;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_underrun;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_tagged;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_crc_err;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pause_frams;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_overrun_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_lengthfield_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_fail_comma_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_frm_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_frm_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_xon_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_xoff_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_xon_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_empty_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_app_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_add_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_empty_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_code_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_min_frame_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_max_frame_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rls_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_cnt_low;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_cnt_high;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_disc_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt0;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt1;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt2;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt3;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_pkt_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_ok_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_disc_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_chksum_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_pkt_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_len_mismatch_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_len_short;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt0;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt1;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt2;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt3;   /**< ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_pavload_len_err_cnt;   /**< ncsi register, see nmanager for details */
	u32 ncsi_ipsurx_hit_count;   /**< ncsi register, see nmanager for details */
	u32 pie_to_mpu_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 pie_to_ipsu_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 pie_to_ncsi_bd_cnt;   /**< ncsi register, see nmanager for details */
	u32 rsv[10];
} mpu_ncsi_counter_info_s;   /**< ncsi register, see nmanager for details */

#define NCSI_STANDARD_OPCODE_MAX_NUM 50   /**< NCSI standard command opcode counter count (reserved considered) */
#define NCSI_OEM_OPCODE_MAX_NUM 60   /**< NCSI OEM command opcode counter count (reserved considered) */

/**
 * @brief ncsi_cmd_counter_s - counter unit shared by NCSI standard command opcode and OEM command opcode
 * @details opcode represents a specific command opcode, rsvd is used for alignment, rx counter and tx counter represent the receive/transmit counter for that command opcode
 */
typedef struct {
	u16 opcode;   /**< a specific ncsi command opcode */
	u16 rsvd;    /**< rsvd */
	u32 rx_counter;   /**< rx counter count */
	u32 tx_counter;   /**< tx counter count */
} ncsi_cmd_counter_s;

/**
 * @brief ncsi_standard_cmd_counter_info_s - NCSI standard command opcode counter struct
 * @details cmd_counter is the counter array, counter_len is the current count of NCSI standard command opcodes
 */
typedef struct {
	ncsi_cmd_counter_s cmd_counter[NCSI_STANDARD_OPCODE_MAX_NUM];   /**< counter array */
	u32 counter_len;   /**< current count of NCSI standard command opcodes */
} ncsi_standard_cmd_counter_info_s;

/**
 * @brief ncsi_oem_cmd_counter_info_s - NCSI OEM command opcode counter struct
 * @details cmd_counter is the counter array, counter_len is the current count of NCSI OEM command opcodes
 */
typedef struct {
	ncsi_cmd_counter_s cmd_counter[NCSI_OEM_OPCODE_MAX_NUM];
	u32 counter_len;
} ncsi_oem_cmd_counter_info_s;

/**
 * @brief mpu_ncsi_cmd_counter_info_s - NCSI all command opcode counter struct
 * @details includes NCSI standard command opcode counter struct and NCSI OEM command opcode counter struct
 */
typedef struct {
	ncsi_standard_cmd_counter_info_s standard_cmd_counter_info;   /**< NCSI standard command opcode counter struct */
	ncsi_oem_cmd_counter_info_s oem_cmd_counter_info;   /**< NCSI OEM command opcode counter struct */
} mpu_ncsi_cmd_counter_info_s;

#define NCSI_COUNT_OPT_TYPE_READ 0   /**< ncsi counter read */
#define NCSI_COUNT_OPT_TYPE_CLEAR 1   /**< ncsi counter clear */
#define NCSI_ALL_CNT_MAXLEN 120
#define NCSI_COM_CNT_MAXLEN 40
#define NCSI_OEM_CNT_MAXLEN (NCSI_ALL_CNT_MAXLEN - NCSI_COM_CNT_MAXLEN)
#define TIMEOUT_COUNTER_VALID 0x1
typedef struct {
	u16 opcode;
	u16 valid;
	u32 timeout_counter;
} oob_timeout_counter_s;

typedef struct {
	u32 len;
	oob_timeout_counter_s ncsi_cnt[NCSI_OEM_CNT_MAXLEN];
} ncsi_oem_timeout_counter_s;

typedef struct {
	u32 len;
	oob_timeout_counter_s ncsi_cnt[NCSI_COM_CNT_MAXLEN];
} ncsi_com_timeout_counter_s;

struct comm_cmd_ncsi_counter_req {   /**< get ncsi counter */
	struct mgmt_msg_head head;    /**< mbox message header */
	u8 opt_type;                  /**< 0:read counter 1:counter clear */
	u8 rsvd[3];
};

struct comm_cmd_ncsi_counter_resp {   /**< get ncsi counter */
	struct mgmt_msg_head head;       /**< mbox message header */

	mpu_ncsi_counter_info_s ncsi_cnt_info;   /**< counter info */
};

#pragma pack(1)
typedef struct tag_ncsi_chan_info {
	u8 aen_en;       /* AEN enable */
	u8 index;        /* index of channel */
	u8 port;         /* net port number */
	u8 state;        /* NCSI state(enum) */
	u8 ncsi_port_en; /* indicates the port switch status (1:on; 0:off) */
	u8 rsv[3];
	ncsi_chan_capa_s capabilities;
	ncsi_parameters_s parameters;
} ncsi_chan_info_s;

typedef struct tag_ncsi_public_info {
	u8 ncsi_ver;
	u8 ncsi_pkg_id; // need to read register to query
	u8 arb_en;      /* arbitration en */
	u8 duplex_set;  /* duplex mode */
	u8 chan_num; /* virtual channel count, hardware supports up to 4, how many to use is determined by software configuration register */
	u8 iid;      /* identify new instances of a command */
	u8 lldp_over_ncsi_enable;
	u8 lldp_over_mctp_enable;
	u32 magicwd;
	u8 lldp_tx_enable;
	u8 rsd[2];
	u8 crc_flag;
	u32 crc;
} ncsi_pubcli_info_s;

/* ncsi configuration struct for one port */
typedef struct {
	ncsi_pubcli_info_s ncsi_public_info;
	ncsi_chan_info_s ncsi_chan_info;
} comm_cmd_ncsi_settings;

#define IPSURX_MAC_NUM 0x4
#define IPSURX_MAC_BYTES 0x6
#define IPSURX_VLAN_NUM 0x8

typedef struct tag_ncsi_filter_cfg {
	/* 1.ipsurx filter configuration */
	u32 ipsurx_ncsi_ctrl;
	u32 ipsurx_ncsi_filter_mng;

	u8 ipsurx_mac_cfg[IPSURX_MAC_NUM][IPSURX_MAC_BYTES];
	u8 ipsurx_mac_vld[IPSURX_MAC_NUM];

	u32 ipsurx_ncsi_vlan_en;
	u16 ipsurx_vlan_tag[IPSURX_VLAN_NUM];
	u16 ipsurx_vlan_vld[IPSURX_VLAN_NUM];

	u32 ipsurx_ncsi_bc_ctrl;
	u32 ipsurx_ncsi_mc_ctrl;

	/* 2.ncsi filter configuration */
	u8 ncsi_smac_cfg[IPSURX_MAC_BYTES];
	u32 ncsi_chnl_ctrl;

	/* 3.ucode filter configuration */
	u8 lldp_fwd_en;        /* lldp forward enable(4 port) */
	u8 lacp_fwd_en;        /* lacp forward enable(4 port) */
	u8 ncsi_arp_en;
	u8 lldp_over_ncsi_enable;
	u8 lldp_over_mctp_enable;
	u8 lldp_tx_enable;
	u8 rsv[22];
} comm_cmd_ncsi_filter_cfg;

typedef enum {
	OPERATOR_OBJECT_NCSI = 0,
	OPERATOR_OBJECT_PIE,
	OPERATOR_OBJECT_SMBUS,
	OPERATOR_OBJECT_MCTP,
	OPERATOR_OBJECT_I3C,
} oob_info_object_e;

typedef enum {
	OPERATOR_TYPE_READ_RAM_CFG = 0,
	OPERATOR_TYPE_READ_FLASH_CFG,
	OPERATOR_TYPE_READ_REG_CFG,
	OPERATOR_TYPE_CLEAR_FLASH_CFG,
	OPERATOR_TYPE_CLEAR_COUNTER,
	OPERATOR_TYPE_READ_COUNTER,
	OPERATOR_TYPE_READ_TIMEOUT_CMD,
	OPERATOR_TYPE_READ_NCSI_PT_RX_COUNTER,
	OPERATOR_TYPE_READ_NCSI_PT_TX_COUNTER,
	OPERATOR_TYPE_READ_CMD_COUNTER,
} oob_info_type_e;

/* oob cfg req */
typedef struct {
	struct mgmt_msg_head head; /* 8B */

	u8 port;                    /* net port number */
	u8 oob_type;                  /**< 0:ncsi 1:mctp */
	u8 opt_type;                 /**< 0:read ram cfg  1:read flash cfg 2:clear flash cfg 3.clear counter 4.read counter*/
	u8 rsvd[5];
} comm_cmd_oob_info_req_s;

typedef struct {
	u8 ncsi_cable_state;        /* 0--cable not present, 1--cable present */
	u8 rsvd[3];
	comm_cmd_ncsi_settings setting_info;
	comm_cmd_ncsi_filter_cfg filter_cfg;
} mpu_ncsi_cfg_info_s;

/* PIE statistics */
typedef struct tag_pie_statistics {
	u32 recv_correct_pkt;
	u32 recv_err_pkt;
	u32 recv_correct_ncsi_pkt;
	u32 recv_err_ncsi_pkt;
	u32 send_ncsi_pkt;
	u32 recv_correct_vnet_pkt;
	u32 recv_err_vnet_pkt;
	u32 send_vnet_pkt;
	u32 recv_lacp_pkt_number;
	u32 task_sch;
	u32 bd_oq2up_cvg_int;
	u32 sgl_cvg_int;
	u32 bm_fifo_ful_int;
	u32 oq_eccm_int;
	u32 oq_eccs_int;
	u32 tx_parity_int;
	u32 rx_parity_int;
	u32 bd_oq2ipsu_ful_int;
	u32 bd_oq2ncsi_ful_int;
	u32 bd_oq2up_ful_int;
	u32 tx_ucerr;
	u32 rx_ucerr;
	u32 irq_nums;
} pie_statistics;

typedef struct {
	u16 opcode;
	u16 reserved;
	u32 rx_counter;
	u32 tx_counter;
} smbus_counter;

#define SMBUS_OPCODE_MAX_NUM ((OOB_INFO_BUFFER_MAX - sizeof(u32)) / sizeof(smbus_counter))

typedef struct {
	u16 len;
	u16 reserved;
	smbus_counter smb_counter[SMBUS_OPCODE_MAX_NUM];
} smbus_counter_info_s;

typedef struct {
	mpu_ncsi_counter_info_s ncsi_cnt_info;
	pie_statistics pie_cnt_info;
} oob_counter_info_s;

typedef union {
	mpu_ncsi_cfg_info_s ncsi_cfg_info;
	oob_counter_info_s cnt_info;
} comm_cmd_oob_info_buf;

typedef struct {
	struct mgmt_msg_head head; /* 8B */
	comm_cmd_oob_info_buf oob_info_buf;
} comm_cmd_oob_info_resp;

/* ncsi cfg */
typedef struct {
	struct mgmt_msg_head head; /* 8B */

	u8 ncsi_cable_state;        /* 0--cable not present, 1--cable present */
	u8 setting_type;            /* 0 means get current ram configuration, 1 means get flash configuration */
	u8 port;                    /* net port number */
	u8 erase_flag;
	comm_cmd_ncsi_settings setting_info;
} comm_cmd_ncsi_cfg_s;
#pragma pack()

/* ncsi passthrough counter related definitions */
#define NO_COUNTER 0xffffffff
#define OOB_INFO_PT_CH_S_MAX 12
#define OOB_INFO_PT_CH_M_MAX 42
#define OOB_INFO_PT_CH_L_MAX 62

typedef struct {
	u32 ch_num;
	u32 ch[OOB_INFO_PT_CH_S_MAX];
} oob_info_pt_counter_s;

typedef struct {
	u32 ch_num;
	u32 ch[OOB_INFO_PT_CH_M_MAX];
} oob_info_pt_counter_m;

/**
 * @brief oob_info_pt_counter_s - counter for large specification channels
 * @details ch_num is the valid channel count, ch array stores counter info
 */
typedef struct {
	u32 ch_num;
	u32 ch[OOB_INFO_PT_CH_L_MAX];
} oob_info_pt_counter_l;

/**
 * @brief oob_info_ncsi_pt_rx - ncsi rx direction DP counters
 * @details statistics of counter counts for each module on the DP path
 */
typedef struct {
	oob_info_pt_counter_s mag_rx_input_pt;
	oob_info_pt_counter_s mag_rx_output_pt;
	oob_info_pt_counter_s ipsurx_rx_input_pt;
	oob_info_pt_counter_s ipsurx_rx_output_pt;
	oob_info_pt_counter_s cpb_from_ipsurx_pt;
	u32 cpb_to_iq;
	u32 iq_input;
	u32 iq_output;
	u32 isch_dispatch_num;
	u32 oq_input;
	u32 oq_output;
	u32 esch_dispatch_num;
	u32 cpb_from_oq;
	oob_info_pt_counter_m cpb_to_perx_pt;
	oob_info_pt_counter_l perx_input_pt;
	oob_info_pt_counter_l perx_output_pt;
	u32 pie_out2ncsi;
	u32 ncsi_rx_pt_cnt;
} oob_info_ncsi_pt_rx;

typedef struct {
	u64 ncsi_tx_pt_cnt;
	u32 pie_out2ipsu;
	oob_info_pt_counter_m ipsutx_tx_input_pt;
	oob_info_pt_counter_m ipsutx_tx_output_pt;
	u32 cpb_from_ipsutx;
	u32 cpb_to_iq;
	u32 iq_input;
	u32 iq_output;
	u32 isch_dispatch_num;
	u32 oq_input;
	u32 oq_output;
	u32 esch_dispatch_num;
	u32 cpb_from_oq;
	oob_info_pt_counter_s cpb_to_petx_pt;
	oob_info_pt_counter_s petx_input_pt;
	oob_info_pt_counter_s petx_output_pt;
	oob_info_pt_counter_s mag_tx_input_pt;
	oob_info_pt_counter_s mag_tx_output_pt;
} oob_info_ncsi_pt_tx;

#endif