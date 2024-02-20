/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma netlink header
 * Author: Yan Fangfang
 * Create: 2023-12-06
 * Note:
 * History: 2023-12-06: create file
 */

#ifndef UBURMA_NETLINK_H
#define UBURMA_NETLINK_H

#include <linux/netlink.h>
#include <urma/ubcore_types.h>

enum uburma_nlmsg_type {
	UBURMA_NL_SET_NS_MODE = NLMSG_MIN_TYPE, /* 0x10 */
	UBURMA_NL_SET_DEV_NS
};

struct uburma_nl_set_ns_mode {
	uint8_t ns_mode;
};

struct uburma_nl_set_dev_ns {
	char dev_name[UBCORE_MAX_DEV_NAME];
	int ns_fd;
};

struct uburma_nl_resp {
	int ret;
};

int uburma_netlink_init(void);
void uburma_netlink_exit(void);

#endif
