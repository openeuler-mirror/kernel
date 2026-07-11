/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

//generate function cmdlist from symbol file

#ifndef DPP_CMD_INIT_H
#define DPP_CMD_INIT_H

#include "zxic_common.h"

#define MSG_ID_MSG_DPP_CMD_SHELL ((u32)(100))
struct T_MSG_CMD_SHELL {
	u32 msgId;
	u8 command[256];
};

u32 dpp_cmd_init(void);
u32 dpp_cmd_exec(char *line);

#endif
