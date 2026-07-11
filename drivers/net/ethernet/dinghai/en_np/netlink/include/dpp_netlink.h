/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_NETLINK_H
#define DPP_NETLINK_H

#include "zxic_common.h"
#include "dpp_type_api.h"

s32 dpp_netlink_init(void);
void dpp_netlink_exit(void);
DPP_STATUS dpp_netlink_regist_msg_proc_fun(u32 id, void *ptr);

#endif
