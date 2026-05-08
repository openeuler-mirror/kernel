/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cli_drv_priv.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_cmd.h"

struct sxe2_adapter;
struct sxe2_hw;

#define SXE2_DRV_MSG_INFO_SIZE (sizeof(struct drv_msg_info))
#define SXE2_CLI_DRV_RSP_MSG_HDR(param) \
	((struct drv_msg_info *)((param)->resp_buff))

#define SXE2_CLI_DRV_REQ_MSG_HDR(param) \
	((struct drv_msg_info *)((param)->req_buff))

typedef s32 (*sxe2_cb_func)(struct sxe2_adapter *adapter,
							struct sxe2_cmd_trans_info *param);

struct sxe2_cmd_handler_info {
	u32 opcode;
	sxe2_cb_func handler;
};

s32 sxe2_cmd_cli_drv_exec(struct sxe2_adapter *adapter,
			  struct sxe2_cmd_params *cmd_params);
