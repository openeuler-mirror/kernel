/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_comm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Micro log common header
 */

#ifndef MICRO_LOG_COMM_H_
#define MICRO_LOG_COMM_H_

#include "ossl_knl.h"

#define microlog_info(fmt, ...) \
	pr_info("[MICRO_LOG][INFO][%s:%d]:" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define microlog_warning(fmt, ...) \
	pr_warn("[MICRO_LOG][WARN][%s:%d]:" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define microlog_err(fmt, ...) \
	pr_err("[MICRO_LOG][ERROR][%s:%d]:" fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MICRO_LOG_VIR_ADDR 0
#define MICRO_LOG_PHY_ADDR 1
#define MICRO_LOG_VIR_PHY_ADDR 2

#define MICRO_LOG_MAX_QUEUE_NUM 256
#define MICRO_LOG_MAX_QUEUE_DEPTH 256

#define MICRO_LOG_MAX_STRING_LEN (128)

#define LOG_LEVEL_INFO_MAX_SIZE 32

struct nic_micro_log_statistics_info {
	u32 recv_log_num;
};

struct micro_log_info {
	struct sdk_thread_info hinic_micro_log_task;
	u64 que_addr[MICRO_LOG_VIR_PHY_ADDR][MICRO_LOG_MAX_QUEUE_NUM];
	struct nic_micro_log_statistics_info log_stati_info;
	char micro_log_tmpbuf[MICRO_LOG_MAX_STRING_LEN * 8 + 1];
	u8 nic_micro_log_dbg;
	u8 nic_micro_log_enable;
	struct file *fp_log_file;
	struct file *fp_asm_file;
	char *micro_log_data_addr;
	void *hwdev;
	u32 all_ci;
};

/* 1) state = 0, do not print logs
 * 2) state = 1, print err logs
 * 3) state = 2, warn logs: include err and warn logs
 * 4) state = 3, info logs: include err, warn, and info logs
 */
enum log_level_type {
	ALL_LOG_DROP = 0,
	ERR_LOG_PRINT = 1,
	WARN_LOG_PRINT = 2,
	INFO_LOG_PRINT = 3
};

struct log_level_message {
	enum log_level_type level_type;
	char level_info[LOG_LEVEL_INFO_MAX_SIZE];
};

int hinic5_set_microlog_cmdq(void *hwdev, void *microlog_msg, size_t msg_len, u8 cmd);
int hinic5_microlog_gpa_set(void *hwdev, u64 p_addr, u8 lt_index);
int hinic5_microlog_ctrl_info_set(void *hwdev, u8 microlog_en, u32 ci_index,
				  enum log_level_type state);

#endif /* MICRO_LOG_COMM_H_ */
