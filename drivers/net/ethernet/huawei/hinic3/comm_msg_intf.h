/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * File Name     : comm_msg_intf.h
 * Version       : Initial Draft
 * Created       : 2021/6/28
 * Last Modified :
 * Description   : COMM Command interfaces between Driver and MPU
 * Function List :
 */

#ifndef COMM_MSG_INTF_H
#define COMM_MSG_INTF_H

#include "comm_defs.h"
#include "mgmt_msg_base.h"

/* func_reset_flag的边界值 */
#define FUNC_RESET_FLAG_MAX_VALUE ((1U << (RES_TYPE_MAX + 1)) - 1)
struct comm_cmd_func_reset {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1[3];
	u64 reset_flag;
};

struct comm_cmd_ppf_flr_type_set {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 rsvd1[2];
	u32 ppf_flr_type;
};

enum {
	COMM_F_API_CHAIN = 1U << 0,
	COMM_F_CLP = 1U << 1,
	COMM_F_CHANNEL_DETECT = 1U << 2,
	COMM_F_MBOX_SEGMENT = 1U << 3,
	COMM_F_CMDQ_NUM = 1U << 4,
	COMM_F_VIRTIO_VQ_SIZE = 1U << 5,
};

#define COMM_MAX_FEATURE_QWORD 4
struct comm_cmd_feature_nego {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode; /* 1: set, 0: get */
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

	u8 mgmt_host_node_id; /* for api cmd to mgmt cpu */
	u8 cmdq_num;
	u8 rsvd1[2];

	u32 rsvd2[8];
};

struct spu_cmd_freq_operation {
	struct comm_info_head head;

	u8 op_code; /* 0: get  1: set 2: check */
	u8 rsvd[3];
	u32 freq;
};

struct spu_cmd_power_operation {
	struct comm_info_head head;

	u8 op_code; /* 0: get  1: set 2: init */
	u8 slave_addr;
	u8 cmd_id;
	u8 size;
	u32 value;
};

struct spu_cmd_tsensor_operation {
	struct comm_info_head head;

	u8 op_code;
	u8 rsvd[3];
	s16 fabric_tsensor_temp_avg;
	s16 fabric_tsensor_temp;
	s16 sys_tsensor_temp_avg;
	s16 sys_tsensor_temp;
};

struct comm_cmd_heart_event {
	struct mgmt_msg_head head;

	u8 init_sta; /* 0: mpu init ok, 1: mpu init error. */
	u8 rsvd1[3];
	u32 heart;           /* add one by one */
	u32 heart_handshake; /* should be alwasys: 0x5A5A5A5A */
};

struct comm_cmd_channel_detect {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1[3];
	u32 rsvd2[2];
};

enum hinic3_svc_type {
	SVC_T_COMM = 0,
	SVC_T_NIC,
	SVC_T_OVS,
	SVC_T_ROCE,
	SVC_T_TOE,
	SVC_T_IOE,
	SVC_T_FC,
	SVC_T_VBS,
	SVC_T_IPSEC,
	SVC_T_VIRTIO,
	SVC_T_MIGRATE,
	SVC_T_PPA,
	SVC_T_MAX,
};

struct comm_cmd_func_svc_used_state {
	struct mgmt_msg_head head;
	u16 func_id;
	u16 svc_type;
	u8 used_state;
	u8 rsvd[35];
};

#define TABLE_INDEX_MAX 129

struct sml_table_id_info {
	u8 node_id;
	u8 instance_id;
};

struct comm_cmd_get_sml_tbl_data {
	struct comm_info_head head; /* 8B */
	u8 tbl_data[512];
};

struct comm_cmd_get_glb_attr {
	struct mgmt_msg_head head;

	struct comm_global_attr attr;
};

enum hinic3_fw_ver_type {
	HINIC3_FW_VER_TYPE_BOOT,
	HINIC3_FW_VER_TYPE_MPU,
	HINIC3_FW_VER_TYPE_NPU,
	HINIC3_FW_VER_TYPE_SMU_L0,
	HINIC3_FW_VER_TYPE_SMU_L1,
	HINIC3_FW_VER_TYPE_CFG,
};

#define HINIC3_FW_VERSION_LEN 16
#define HINIC3_FW_COMPILE_TIME_LEN 20
struct comm_cmd_get_fw_version {
	struct mgmt_msg_head head;

	u16 fw_type;
	u16 rsvd1;
	u8 ver[HINIC3_FW_VERSION_LEN];
	u8 time[HINIC3_FW_COMPILE_TIME_LEN];
};

/* hardware define: cmdq context */
struct cmdq_ctxt_info {
	u64 curr_wqe_page_pfn;
	u64 wq_block_pfn;
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

enum cfg_msix_operation {
	CFG_MSIX_OPERATION_FREE = 0,
	CFG_MSIX_OPERATION_ALLOC = 1,
};

struct comm_cmd_cfg_msix_num {
	struct comm_info_head head; /* 8B */

	u16 func_id;
	u8 op_code; /* 1: alloc 0: free */
	u8 rsvd0;

	u16 msix_num;
	u16 rsvd1;
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
	u8 rsvd0[3];
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
	u64 gpa_hi52[0]; /*lint !e1501*/
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

#define HARDWARE_ID_1XX3V100_TAG 31 /* 1xx3v100 tag */

struct hinic3_board_info {
	u8 board_type;
	u8 port_num;
	u8 port_speed;
	u8 pcie_width;
	u8 host_num;
	u8 pf_num;
	u16 vf_total_num;
	u8 tile_num;
	u8 qcm_num;
	u8 core_num;
	u8 work_mode;
	u8 service_mode;
	u8 pcie_mode;
	u8 boot_sel;
	u8 board_id;
	u32 cfg_addr;
	u32 service_en_bitmap;
	u8 scenes_id;
	u8 cfg_template_id;
	u8 hardware_id;
	u8 spu_en;
	u16 pf_vendor_id;
	u8 tile_bitmap;
	u8 sm_bitmap;
};

struct comm_cmd_board_info {
	struct mgmt_msg_head head;

	struct hinic3_board_info info;
	u32 rsvd[22];
};

struct comm_cmd_sync_time {
	struct mgmt_msg_head head;

	u64 mstime;
	u64 rsvd1;
};

struct comm_cmd_sdi_info {
	struct mgmt_msg_head head;
	u32 cfg_sdi_mode;
};

/* func flr set */
struct comm_cmd_func_flr_set {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 type;  /* 1: close 置flush */
	u8 isall; /* 是否操作对应pf下的所有vf 1: all vf */
	u32 rsvd;
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

struct hw_pf_info {
	u16 glb_func_idx;
	u16 glb_pf_vf_offset;
	u8 p2p_idx;
	u8 itf_idx;
	u16 max_vfs;
	u16 max_queue_num;
	u16 vf_max_queue_num;
	u16 port_id;
	u16 rsvd0;
	u32 pf_service_en_bitmap;
	u32 vf_service_en_bitmap;
	u16 rsvd1[2];

	u8 device_type;
	u8 bus_num;    /* tl_cfg_bus_num */
	u16 vf_stride; /* VF_RID_SETTING.vf_stride */
	u16 vf_offset; /* VF_RID_SETTING.vf_offset */
	u8 rsvd[2];
};

#define CMD_MAX_MAX_PF_NUM 32
struct hinic3_hw_pf_infos {
	u8 num_pfs;
	u8 rsvd1[3];

	struct hw_pf_info infos[CMD_MAX_MAX_PF_NUM];
};

struct comm_cmd_hw_pf_infos {
	struct mgmt_msg_head head;

	struct hinic3_hw_pf_infos infos;
};

#define DD_CFG_TEMPLATE_MAX_IDX 12
#define DD_CFG_TEMPLATE_MAX_TXT_LEN 64
#define CFG_TEMPLATE_OP_QUERY 0
#define CFG_TEMPLATE_OP_SET 1
#define CFG_TEMPLATE_SET_MODE_BY_IDX 0
#define CFG_TEMPLATE_SET_MODE_BY_NAME 1

struct comm_cmd_cfg_template {
	struct mgmt_msg_head head;
	u8 opt_type; /* 0: query  1: set */
	u8 set_mode; /* 0-index mode. 1-name mode. */
	u8 tp_err;
	u8 rsvd0;

	u8 cur_index;     /* Current cfg tempalte index. */
	u8 cur_max_index; /* Max support cfg tempalte index. */
	u8 rsvd1[2];
	u8 cur_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];
	u8 cur_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];

	u8 next_index;     /* Next reset cfg tempalte index. */
	u8 next_max_index; /* Max support cfg tempalte index. */
	u8 rsvd2[2];
	u8 next_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];
	u8 next_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];
};

#define MQM_SUPPORT_COS_NUM 8
#define MQM_INVALID_WEIGHT 256
#define MQM_LIMIT_SET_FLAG_READ 0
#define MQM_LIMIT_SET_FLAG_WRITE 1
struct comm_cmd_set_mqm_limit {
	struct mgmt_msg_head head;

	u16 set_flag; /* 置位该标记位表示设置 */
	u16 func_id;
	/* 对应cos_id所占的权重，0-255, 0为SP调度. */
	u16 cos_weight[MQM_SUPPORT_COS_NUM];
	u32 host_min_rate; /* 本host支持的最低限速 */
	u32 func_min_rate; /* 本function支持的最低限速，单位Mbps */
	u32 func_max_rate; /* 本function支持的最高限速，单位Mbps  */
	u8 rsvd[64]; /* Reserved */
};

#define DUMP_16B_PER_LINE	16
#define DUMP_8_VAR_PER_LINE	8
#define DUMP_4_VAR_PER_LINE	4

#define DATA_LEN_1K 1024
/* 软狗超时信息上报接口 */
struct comm_info_sw_watchdog {
	struct comm_info_head head;

	/* 全局信息 */
	u32 curr_time_h; /* 发生死循环的时间,cycle */
	u32 curr_time_l; /* 发生死循环的时间,cycle */
	u32 task_id;     /* 发生死循环的任务       */
	u32 rsv;         /* 保留字段，用于扩展     */

	/* 寄存器信息，TSK_CONTEXT_S */
	u64 pc;

	u64 elr;
	u64 spsr;
	u64 far;
	u64 esr;
	u64 xzr;
	u64 x30;
	u64 x29;
	u64 x28;
	u64 x27;
	u64 x26;
	u64 x25;
	u64 x24;
	u64 x23;
	u64 x22;
	u64 x21;
	u64 x20;
	u64 x19;
	u64 x18;
	u64 x17;
	u64 x16;
	u64 x15;
	u64 x14;
	u64 x13;
	u64 x12;
	u64 x11;
	u64 x10;
	u64 x09;
	u64 x08;
	u64 x07;
	u64 x06;
	u64 x05;
	u64 x04;
	u64 x03;
	u64 x02;
	u64 x01;
	u64 x00;

	/* 堆栈控制信息，STACK_INFO_S */
	u64 stack_top;    /* 栈顶                   */
	u64 stack_bottom; /* 栈底                   */
	u64 sp;           /* 栈当前SP指针值         */
	u32 curr_used;          /* 栈当前使用的大小       */
	u32 peak_used;          /* 栈使用的历史峰值       */
	u32 is_overflow;        /* 栈是否溢出             */

	/* 堆栈具体内容 */
	u32 stack_actlen;      /* 实际的堆栈长度(<=1024) */
	u8 stack_data[DATA_LEN_1K]; /* 超过1024部分，会被截断 */
};

/* 临终遗言信息 */
#define XREGS_NUM 31
struct tag_cpu_tick {
	u32 cnt_hi; /* *<  cycle计数高32位 */
	u32 cnt_lo; /* *<  cycle计数低32位 */
};

struct tag_ax_exc_reg_info {
	u64 ttbr0;
	u64 ttbr1;
	u64 tcr;
	u64 mair;
	u64 sctlr;
	u64 vbar;
	u64 current_el;
	u64 sp;
	/* 以下字段的内存布局与TskContext保持一致 */
	u64 elr;               /* 返回地址 */
	u64 spsr;
	u64 far_r;
	u64 esr;
	u64 xzr;
	u64 xregs[XREGS_NUM];         /* 0~30: x30~x0 */
};

struct tag_exc_info {
	char os_ver[48];   /* *< OS版本号 */
	char app_ver[64];  /* *< 产品版本号 */
	u32 exc_cause;     /* *< 异常原因 */
	u32 thread_type;   /* *< 异常前的线程类型 */
	u32 thread_id;     /* *< 异常前线程PID */
	u16 byte_order;    /* *< 字节序 */
	u16 cpu_type;      /* *< CPU类型 */
	u32 cpu_id;        /* *< CPU ID */
	struct tag_cpu_tick cpu_tick; /* *< CPU Tick */
	u32 nest_cnt;      /* *< 异常嵌套计数 */
	u32 fatal_errno;     /* *< 致命错误码，发生致命错误时有效 */
	u64 uw_sp;           /* *< 异常前栈指针 */
	u64 stack_bottom;  /* *< 异常前栈底 */
	/* 异常发生时的核内寄存器上下文信息，82\57必须位于152字节处，
	 * 若有改动，需更新sre_platform.eh中的OS_EXC_REGINFO_OFFSET宏
	 */
	struct tag_ax_exc_reg_info reg_info;
};

/* 上报给驱动的up lastword模块接口 */
#define MPU_LASTWORD_SIZE 1024
struct tag_comm_info_up_lastword {
	struct comm_info_head head;

	struct tag_exc_info stack_info;

	/* 堆栈具体内容 */
	u32 stack_actlen; /* 实际的堆栈长度(<=1024) */
	u8 stack_data[MPU_LASTWORD_SIZE]; /* 超过1024部分，会被截断 */
};

#define FW_UPDATE_MGMT_TIMEOUT	3000000U

struct hinic3_cmd_update_firmware {
	struct mgmt_msg_head msg_head;

	struct {
		u32 sl : 1;
		u32 sf : 1;
		u32 flag : 1;
		u32 bit_signed : 1;
		u32 reserved : 12;
		u32 fragment_len : 16;
	} ctl_info;

	struct {
		u32 section_crc;
		u32 section_type;
	} section_info;

	u32 total_len;
	u32 section_len;
	u32 section_version;
	u32 section_offset;
	u32 data[384];
};

struct hinic3_cmd_activate_firmware {
	struct mgmt_msg_head msg_head;
	u8 index; /* 0 ~ 7 */
	u8 data[7];
};

struct hinic3_cmd_switch_config {
	struct mgmt_msg_head msg_head;
	u8 index; /* 0 ~ 7 */
	u8 data[7];
};

#endif
