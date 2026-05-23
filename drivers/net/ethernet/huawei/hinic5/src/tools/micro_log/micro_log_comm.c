/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_comm.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Microcode host log common functions
 */
#include "micro_log_comm.h"
#include "comm_defs.h"
#include "hinic5_comm_cmd.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_hwdev.h"

int hinic5_set_microlog_cmdq(void *hwdev, void *microlog_msg, size_t msg_len, u8 cmd)
{
	int err;
	u64 out_param = 0;
	struct hinic5_cmd_buf *cmd_buf = NULL;

	if (hinic5_is_chip_present((struct hinic5_hwdev *)hwdev) == false)
		return 0;

	cmd_buf = hinic5_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		microlog_err("failed to allocate cmd buf!");
		return -ENOMEM;
	}

	cmd_buf->size = msg_len;
	memcpy(cmd_buf->buf, microlog_msg, msg_len);
	hinic5_cpu_to_be32(cmd_buf->buf, cmd_buf->size);

	err = hinic5_cmdq_direct_resp(hwdev, HINIC5_MOD_COMM, cmd, cmd_buf,
				      &out_param, 0, HINIC5_CHANNEL_NIC);
	if ((err) || (out_param)) {
		microlog_err("cmdq_cmd:%d, err:%d, out_param: 0x%llx!", cmd, err, out_param);
		err = -EFAULT;
	}

	hinic5_free_cmd_buf(hwdev, cmd_buf);
	return err;
}

int hinic5_microlog_gpa_set(void *hwdev, u64 p_addr, u8 lt_index)
{
	cmdq_microlog_gpa_set_s microlog_gpa = { 0 };

	microlog_gpa.wr_init_pc_h32 = (u32)((p_addr >> 32) & 0xffffffff);
	microlog_gpa.wr_init_pc_l32 = (u32)(p_addr & 0xffffffff);
	microlog_gpa.lt_index = lt_index;
	return hinic5_set_microlog_cmdq(hwdev, (void *)&microlog_gpa,
					sizeof(cmdq_microlog_gpa_set_s),
					COMM_CMD_MICROLOG_GPA_SET);
}

int hinic5_microlog_ctrl_info_set(void *hwdev, u8 microlog_en, u32 ci_index,
				  enum log_level_type state)
{
	cmdq_microlog_ctrl_info_set_s microlog_ctrl_info = { { 0 } };
	size_t msg_len = sizeof(cmdq_microlog_ctrl_info_set_s);

	microlog_ctrl_info.max_num = MICRO_LOG_MAX_QUEUE_DEPTH;
	microlog_ctrl_info.microlog_en = microlog_en;
	microlog_ctrl_info.state = state;
	microlog_ctrl_info.ci_index = ci_index;
	return hinic5_set_microlog_cmdq(hwdev, (void *)&microlog_ctrl_info,
					msg_len, COMM_CMD_MICROLOG_CTRL_INFO_SET);
}
