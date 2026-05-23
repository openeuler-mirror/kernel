/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_comm_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : COMM Commands between Driver and MPU
 */

#ifndef HINIC5_COMMON_CMD_H
#define HINIC5_COMMON_CMD_H

#include "base_type.h"

#define DFX_LOG_PRINT_MAX_PARA 8

/**
 * @brief comm_cmdq_cmd - CmdQ Common subtype
 *
 * @details COMM Commands between Driver and MPU
 */
enum comm_cmdq_cmd {
	COMM_CMD_UCODE_ARM_BIT_SET = 2,    /**< Command to set UCODE_ARM bit */
	COMM_CMD_SEND_NPU_DFT_CMD,         /**< Send NPU debug command */
	COMM_CMD_MICROLOG_PRINT_CNT_CLEAR, /**< Command to clear microlog print count */
	COMM_CMD_UCODE_FAST_MSG_CMD,       /**< Command to send fast message */
	COMM_CMD_UCODE_FAST_MSG_CLEAR,     /**< Command to clear fast message */
	COMM_CMD_MICROLOG_GPA_SET,         /**< Save host address of cache log to sml table */
	COMM_CMD_MICROLOG_CTRL_INFO_SET,   /**< Update log control information to sml table */
};

typedef struct tag_cmdq_microlog_gpa_set {
	u32 wr_init_pc_h32;
	u32 wr_init_pc_l32;
	u32 lt_index;
} cmdq_microlog_gpa_set_s;

typedef struct tag_cmdq_microlog_ctrl_info_set {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u32 state : 8;
		u32 microlog_en : 1;
		u32 microlog_init_flag : 1;
		u32 rsvd : 11;
		u32 max_num : 11; /* Maximum data block size */
#else
		u32 max_num : 11; /* Maximum data block size */
		u32 rsvd : 11;
		u32 microlog_init_flag : 1;
		u32 microlog_en : 1;
		u32 state : 8;
#endif
	};
	u32 ci_index;
} cmdq_microlog_ctrl_info_set_s;

typedef struct tag_micro_log_item {
	union {
		struct {
#if (BYTE_ORDER == BIG_ENDIAN)
			u32 action : 1;	   /* 1:record log 0:print */
			u32 type : 2;		 /* 0:err 1:trace 2:info */
			u32 feature : 5;	  /* 0:l2nic 1:roce 2:toe 3:ioe 4:feoe */
			u32 core_id : 6;
			u32 thread_id : 2;
			u32 valid_param_num : 8; /* Number of valid parameters */
			u32 tile_id : 3;
			u32 ctrl_flag : 1;
			u32 rsv : 4;
#else
			u32 rsv : 4;
			u32 ctrl_flag : 1;
			u32 tile_id : 3;
			u32 valid_param_num : 8; /* Number of valid parameters */
			u32 thread_id : 2;
			u32 core_id : 6;
			u32 feature : 5;	  /* 0:l2nic 1:roce 2:toe 3:ioe 4:feoe */
			u32 type : 2;		 /* 0:err 1:trace 2:info */
			u32 action : 1;	   /* 1:record log 0:print */
#endif
		} bs;
		u32 value;
	} ctrl_info;

	u32 string_addr;
	u32 data[DFX_LOG_PRINT_MAX_PARA];
	u32 func_name_addr; /* File name must not exceed 26 characters */

	union {
		struct {
#if (BYTE_ORDER == BIG_ENDIAN)
			u32 line : 16;		  /* Aligned with log_items in mpu, line only needs 16bit */
			u32 log_seq : 16;	  /* Equivalent to log_pi, range: 0~65535. As log seq, to detect if microcode log is lost */
#else
			u32 log_seq : 16;
			u32 line : 16;
#endif
		} bs;
		u32 value;
	} line_and_pi;
} micro_log_item_s;

#endif /* HINIC5_COMMON_CMD_H */
