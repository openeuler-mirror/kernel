/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_COMM_MSG_INTF_H
#define SPHW_COMM_MSG_INTF_H

#include "sphw_mgmt_msg_base.h"

#define FUNC_RESET_FLAG_MAX_VALUE ((1U << (RES_TYPE_IPSEC + 1)) - 1)
struct comm_cmd_func_reset {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1[3];
	u64 reset_flag;
};

enum {
	COMM_F_API_CHAIN = 1U << 0,
};

#define COMM_MAX_FEATURE_QWORD	4
struct comm_cmd_feature_nego {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode;	/* 1: set, 0: get */
	u8 rsvd;
	u64 s_feature[COMM_MAX_FEATURE_QWORD];
};

struct comm_cmd_clear_doorbell {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1[3];
};

struct comm_cmd_clear_resource {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1[3];
};

struct comm_global_attr {
	u8 max_host_num;
	u8 max_pf_num;
	u16 vf_id_start;

	u8 mgmt_host_node_id;	/* for api cmd to mgmt cpu */
	u8 rsvd1[3];

	u32 rsvd2[8];
};

struct comm_cmd_get_glb_attr {
	struct mgmt_msg_head head;

	struct comm_global_attr attr;
};

enum sphw_fw_ver_type {
	SPHW_FW_VER_TYPE_BOOT,
	SPHW_FW_VER_TYPE_MPU,
	SPHW_FW_VER_TYPE_NPU,
	SPHW_FW_VER_TYPE_SMU,
	SPHW_FW_VER_TYPE_CFG,
};

#define SPHW_FW_VERSION_LEN		16
#define SPHW_FW_COMPILE_TIME_LEN	20
struct comm_cmd_get_fw_version {
	struct mgmt_msg_head head;

	u16 fw_type;
	u16 rsvd1;
	u8 ver[SPHW_FW_VERSION_LEN];
	u8 time[SPHW_FW_COMPILE_TIME_LEN];
};

/* hardware define: cmdq context */
struct cmdq_ctxt_info {
	u64	curr_wqe_page_pfn;
	u64	wq_block_pfn;
};

struct comm_cmd_cmdq_ctxt {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 cmdq_id;
	u8 rsvd1[5];

	struct cmdq_ctxt_info ctxt;
};

struct comm_cmd_root_ctxt {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 set_cmdq_depth;
	u8 cmdq_depth;
	u16 rx_buf_sz;
	u8 lro_en;
	u8 rsvd1;
	u16 sq_depth;
	u16 rq_depth;
	u64 rsvd2;
};

struct comm_cmd_wq_page_size {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode;
	/* real_size=4KB*2^page_size, range(0~20) must be checked by driver */
	u8 page_size;

	u32 rsvd1;
};

struct comm_cmd_msix_config {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u16 msix_index;
	u8 pending_cnt;
	u8 coalesce_timer_cnt;
	u8 resend_timer_cnt;
	u8 lli_timer_cnt;
	u8 lli_credit_cnt;
	u8 rsvd2[5];
};

struct comm_cmd_dma_attr_config {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 entry_idx;
	u8 st;
	u8 at;
	u8 ph;
	u8 no_snooping;
	u8 tph_en;
	u32 resv1;
};

struct comm_cmd_ceq_ctrl_reg {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 q_id;
	u32 ctrl0;
	u32 ctrl1;
	u32 rsvd1;
};

struct comm_cmd_func_tmr_bitmap_op {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode; /* 1: start, 0: stop */
	u8 rsvd1[5];
};

struct comm_cmd_ppf_tmr_op {
	struct mgmt_msg_head head;

	u8 ppf_id;
	u8 opcode; /* 1: start, 0: stop */
	u8 rsvd1[6];
};

struct comm_cmd_ht_gpa {
	struct mgmt_msg_head head;

	u8 host_id;
	u32 rsvd1[7];
	u64 page_pa0;
	u64 page_pa1;
};

struct comm_cmd_get_eqm_num {
	struct mgmt_msg_head head;

	u8 host_id;
	u8 rsvd1[3];
	u32 chunk_num;
	u32 search_gpa_num;
};

struct comm_cmd_eqm_cfg {
	struct mgmt_msg_head head;

	u8 host_id;
	u8 valid;
	u16 rsvd1;
	u32 page_size;
	u32 rsvd2;
};

struct comm_cmd_eqm_search_gpa {
	struct mgmt_msg_head head;

	u8 host_id;
	u8 rsvd1[3];
	u32 start_idx;
	u32 num;
	u32 rsvd2;
	u64 gpa_hi52[0];
};

struct comm_cmd_ffm_info {
	struct mgmt_msg_head head;

	u8 node_id;
	/* error level of the interrupt source */
	u8 err_level;
	/* Classification by interrupt source properties */
	u16 err_type;
	u32 err_csr_addr;
	u32 err_csr_value;
	u32 rsvd1;
};

struct sphw_board_info {
	u8	board_type;
	u8	port_num;
	u8	port_speed;
	u8	pcie_width;
	u8	host_num;
	u8	pf_num;
	u16	vf_total_num;
	u8	tile_num;
	u8	qcm_num;
	u8	core_num;
	u8	work_mode;
	u8	service_mode;
	u8	pcie_mode;
	u8	boot_sel;
	u8	board_id;
	u32	cfg_addr;
};

struct comm_cmd_board_info {
	struct mgmt_msg_head head;

	struct sphw_board_info info;
	u32 rsvd[25];
};

struct comm_cmd_sync_time {
	struct mgmt_msg_head head;

	u64 mstime;
	u64 rsvd1;
};

struct comm_cmd_bdf_info {
	struct mgmt_msg_head head;

	u16 function_idx;
	u8 rsvd1[2];
	u8 bus;
	u8 device;
	u8 function;
	u8 rsvd2[5];
};

#endif
