// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_mbx_channel.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_log.h"
#include "sxe2_mbx_channel.h"

s32 sxe2_mbx_msg_send(struct sxe2_adapter *adapter,
		      struct sxe2_cmd_params *cmd_params)
{
	s32 ret = 0;

	ret = sxe2_cmd_mbx_exec(adapter, cmd_params);
	if (ret)
		LOG_ERROR_BDF("pf send msg to vf:%u opcode:0x%x req_len:%u \t"
			      "fail.(err:%d)\n",
			      cmd_params->vf_idx, cmd_params->opcode,
			      cmd_params->req_len, ret);

	return ret;
}

s32 sxe2_mbx_msg_reply(struct sxe2_adapter *adapter,
		       struct sxe2_cmd_params *cmd_params)
{
	s32 ret;

	ret = sxe2_cmd_mbx_reply(adapter, cmd_params);
	if (unlikely(ret))
		LOG_ERROR_BDF("pf send msg to vf:%u opcode:0x%x session_id:0x%llx \t"
			      "req_len:%u fail.(err:%d)\n",
			      cmd_params->vf_idx, cmd_params->opcode,
			      cmd_params->session_id, cmd_params->req_len, ret);

	return ret;
}
