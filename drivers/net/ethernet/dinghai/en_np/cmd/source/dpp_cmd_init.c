// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_netlink.h"
#include "dpp_cmd_init.h"

extern char *dpp_cmd_trim(char *line);

u32 dpp_cmd_msg_proc(void *msg_body, u32 msg_len, void **resp, u32 *reps_len)
{
	char *line = NULL;
	struct T_MSG_CMD_SHELL *msg = (struct T_MSG_CMD_SHELL *)(msg_body);

	ZXIC_COMM_CHECK_POINT(msg);

	line = dpp_cmd_trim(msg->command);
	ZXIC_COMM_CHECK_POINT(line);

	if (*line) {
		ZXIC_COMM_PRINT("---------------------------------------------------\n");
		dpp_cmd_exec(line);
		ZXIC_COMM_PRINT("---------------------------------------------------\n");
	}

	return DPP_OK;
}

u32 dpp_cmd_init(void)
{
	dpp_netlink_regist_msg_proc_fun(MSG_ID_MSG_DPP_CMD_SHELL, dpp_cmd_msg_proc);

	return DPP_OK;
}
