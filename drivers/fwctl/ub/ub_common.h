/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved.
 */

#ifndef __UB_COMMAND_H__
#define __UB_COMMAND_H__

#include <linux/auxiliary_bus.h>
#include <linux/fwctl.h>
#include <linux/kfifo.h>
#include <ub/ubase/ubase_comm_stats.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_dev.h>

#include <uapi/fwctl/ub_fwctl.h>

#define UBCTL_READ true
#define UBCTL_WRITE false

#define ubctl_err(ucdev, format, ...) \
	dev_err(&ucdev->fwctl.dev, format, ##__VA_ARGS__)

#define ubctl_dbg(ucdev, format, ...) \
	dev_dbg(&ucdev->fwctl.dev, "PID %u: " format, current->pid, \
		##__VA_ARGS__)

#define ubctl_info(ucdev, format, ...) \
	dev_info(&ucdev->fwctl.dev, "PID %u: " format, current->pid, \
		##__VA_ARGS__)

#define ubctl_warn(ucdev, format, ...) \
	dev_warn(&ucdev->fwctl.dev, "PID %u: " format, current->pid, \
		##__VA_ARGS__)

#define UBCTL_GET_PHY_ADDR(high, low) ((((u64)(high)) << 32) | (low))
#define UBCTL_EXTRACT_BITS(value, start, end) \
	(((value) >> (start)) & ((1UL << ((end) - (start) + 1)) - 1))

/**
 * struct ubctl_dev - Device struct of framework
 * @fwctl: The device of fwctl
 * @data_size: Length of @data
 * @adev: data transmitted to users
 */
struct ubctl_dev {
	struct fwctl_device fwctl;
	DECLARE_KFIFO_PTR(ioctl_fifo, unsigned long);
	struct auxiliary_device *adev;
};

/**
 * struct ubctl_query_cmd_param - Parameters of userspace RPC
 * @in_len: Length of @in
 * @in: Data of input
 * @out_len: Length of @out
 * @out: Data of output
 *
 * Used to receive parameters passed from userspace RPC
 */
struct ubctl_query_cmd_param {
	size_t in_len;
	struct fwctl_rpc_ub_in *in;
	size_t out_len;
	struct fwctl_rpc_ub_out *out;
};

/**
 * struct ubctl_cmd - Parameters of query command
 * @op_code: The operation code
 * @is_read: Read-only or read-write
 * @in_len: Length of @in_data
 * @out_len: Length of @out_data
 * @in: Data of input
 * @out: Data of output
 *
 * Used for sending and receiving software communication
 */
struct ubctl_cmd {
	u32 op_code;
	u32 is_read;
	u32 in_len;
	u32 out_len;
	void *in_data;
	void *out_data;
};

struct ubctl_func_dispatch {
	u32 rpc_cmd;
	int (*execute)(struct ubctl_dev *ucdev,
		       struct ubctl_query_cmd_param *query_cmd_param,
		       struct ubctl_func_dispatch *query_func);
	int (*data_deal)(struct ubctl_dev *ucdev,
			 struct ubctl_query_cmd_param *query_cmd_param,
			 struct ubctl_cmd *cmd, u32 out_len, u32 offset_index);
};

struct ubctl_query_dp {
	u32 op_code;
	u32 out_len;
	bool is_read;
	void *data;
	u32 data_len;
};

struct ubctl_query_cmd_dp {
	struct ubctl_func_dispatch *query_func;
	void *cmd_in;
	void *cmd_out;
};

/**
 * ubctl_ubase_cmd_send - The ubase interface for issuing cmdq
 * @adev: The auxiliary framework device
 * @cmd: Command information of ubctl
 */
int ubctl_ubase_cmd_send(struct auxiliary_device *adev,
			 struct ubctl_cmd *cmd);
int ubctl_fill_cmd(struct ubctl_cmd *cmd, void *cmd_in, void *cmd_out,
		   u32 out_len, u32 is_read);

/**
 * ubctl_query_data - Packaging and delivering parameters of cmdq
 * @ucdev: Ubctl device
 * @query_cmd_param: Parameters passed from userspace RPC
 * @query_func: Callback functions for issuing and processing data
 * @query_dp: Parameters related to cmdq
 * @query_dp_num: Number of elements in @query_dp
 *
 */
int ubctl_query_data(struct ubctl_dev *ucdev,
		     struct ubctl_query_cmd_param *query_cmd_param,
		     struct ubctl_func_dispatch *query_func,
		     struct ubctl_query_dp *query_dp, u32 query_dp_num);

/**
 * ubctl_query_data_deal - Default callback function for processing returned data
 * @ucdev: Ubctl device
 * @query_cmd_param: Parameters passed from userspace RPC and IMP
 * @cmd: Command information of ubctl
 * @out_len: Data length of the 'out' in @query_cmd_param
 * @offset: Data offset of the 'out' in @query_cmd_param
 *
 * On return the device is visible through sysfs and /dev, driver ops may be
 * called.
 */
int ubctl_query_data_deal(struct ubctl_dev *ucdev,
			  struct ubctl_query_cmd_param *query_cmd_param,
			  struct ubctl_cmd *cmd, u32 out_len, u32 offset);

int ubctl_query_perf(struct ubctl_dev *ucdev, u32 port_bitmap,
		     struct ubase_perf_stats_result *result_data,
		     u32 result_data_size, u32 period);
int ubctl_query_perf_stats(struct ubctl_dev *ucdev, u32 port_bitmap,
			   struct ubase_perf_stats_result *result_data,
			   u32 result_data_size);

#endif
