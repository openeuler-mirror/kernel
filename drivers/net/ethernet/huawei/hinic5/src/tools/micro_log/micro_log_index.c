/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : micro_log_index.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Micro log index implementation
 */

#include "ossl_knl.h"

#include "micro_log_index.h"
#include "comm_defs.h"
#include "hinic5_hw.h"
#include "fw_typedef.h"
#include "mpu_inband_cmd.h"
#include "inband_mpu_cmd_defs.h"

static int micro_log_read_fw_cfg_info(void *hwdev, fw_info_s *cfg_info)
{
	struct cmd_query_fw query_fw_input;
	struct cmd_fw_info query_fw_output;
	u16 out_size = sizeof(struct cmd_fw_info);
	int ret;
	int err = 0;

	memset(&query_fw_input, 0, sizeof(struct cmd_query_fw));
	memset(&query_fw_output, 0, sizeof(struct cmd_fw_info));

	if (!hwdev || !cfg_info) {
		microlog_err("point is null\r\n");
		return -EINVAL;
	}

	query_fw_input.offset = 0;
	query_fw_input.len = MAX_LOG_BUF_SIZE;
	ret = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM,
				      COMM_MGMT_CMD_QUERY_FW_INFO,
				      &query_fw_input,
				      sizeof(struct cmd_query_fw),
				      &query_fw_output, &out_size, 0,
				      HINIC5_CHANNEL_COMM);
	if (ret != 0 || out_size == 0 || query_fw_output.head.status != 0) {
		microlog_err("Failed to get length. ret:%d, status:0x%x, out_size:0x%x\n",
			     ret, query_fw_output.head.status, out_size);
		return ret;
	}

	if (query_fw_output.len != query_fw_input.len) {
		microlog_err("The length is inconsistent!\n");
		return -EFAULT;
	}

	memcpy((u8 *)cfg_info, query_fw_output.data, query_fw_output.len);
	return err;
}

static int micro_log_read_sim_data(void *hwdev, struct nic_log_info *simdata_info,
				   u32 read_offset, u32 sim_data_len)
{
	u32 ret;
	u16 out_size = sizeof(struct nic_log_info);
	struct nic_log_info simdata_buf_in;

	if (!hwdev || !simdata_info) {
		microlog_err("point is null\r\n");
		return -EINVAL;
	}

	memset(simdata_info, 0, sizeof(struct nic_log_info));
	memset(&simdata_buf_in, 0, sizeof(struct nic_log_info));
	simdata_buf_in.offset = read_offset;
	simdata_buf_in.log_or_index = NPU_COMM_GET_SIM_DATA;
	/* For compatibility with old and new hinic tools, use data[3:0] field instead of file_size, occupying 32bit */
	*(u32 *)(void *)simdata_buf_in.data = sim_data_len;

	ret = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM,
				      COMM_MGMT_CMD_GET_LOG, &simdata_buf_in,
				      sizeof(struct nic_log_info), simdata_info,
				      &out_size, 0, HINIC5_CHANNEL_COMM);
	if (ret != 0 || out_size == 0 || simdata_info->msg_head.status != 0) {
		microlog_err("Failed to read sim_data, ret:%d, status:0x%x, out_size:0x%x\n",
			     ret, simdata_info->msg_head.status, out_size);
	}
	return ret;
}

static int micro_log_get_sim_data_length(void *hwdev, u32 *sim_data_len)
{
	fw_info_s cfg_info;

	if (micro_log_read_fw_cfg_info(hwdev, &cfg_info) != 0) {
		microlog_err("Fail to read_fw_cfg_info\n");
		return -EFAULT;
	}

	if (cfg_info.fw_attr[FW_TILE_DATA_INDEX].invalid != 0) {
		microlog_err("fw_tile_data_index invalid\n");
		return -EFAULT;
	}

	*sim_data_len = cfg_info.fw_attr[FW_TILE_DATA_INDEX].fw_len;
	return 0;
}

int mirco_log_get_sim_data_from_flash(void *hwdev, struct micro_log_info *log_info)
{
	u32 sim_data_len = 0;
	u32 i;
	u32 j;
	u32 k;
	struct nic_log_info simdata_info;

	if (micro_log_get_sim_data_length(hwdev, &sim_data_len) != 0)
		return -EFAULT;
	microlog_info("get sim_data_len(0x%x) ok.", sim_data_len);

	log_info->micro_log_data_addr = kzalloc((sim_data_len + 1), GFP_KERNEL);
	if (!log_info->micro_log_data_addr)
		return -EFAULT;

	/* mbox can read up to 1K data each time */
	for (i = 0, j = 0; i < sim_data_len; i += MAX_LOG_BUF_SIZE) {
		if (micro_log_read_sim_data(hwdev, &simdata_info, i, sim_data_len) != 0)
			goto err_free_mem;

		for (k = 0; k < MAX_LOG_BUF_SIZE && j < sim_data_len; k++, j++)
			log_info->micro_log_data_addr[j] = simdata_info.data[k];
	}

	microlog_info("get_sim_data_from_flash ok\n");
	return 0;

err_free_mem:
	if (log_info->micro_log_data_addr) {
		kfree((void *)(log_info->micro_log_data_addr));
		log_info->micro_log_data_addr = NULL;
	}
	return -EFAULT;
}
