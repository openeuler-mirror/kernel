/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: ubcore GENERIC NETLINK
 * Author: Zhao yanchao
 * Create: 2024-01-25
 * Note:
 * History: 2024-01-25  Zhao yanchao  Add base code
 */

#ifndef UBCORE_GENERIC_NETLINK_DEFINE_H
#define UBCORE_GENERIC_NETLINK_DEFINE_H

/* NETLINK_GENERIC related info */
#define UBCORE_GENL_FAMILY_NAME		"UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION	1

enum {
	UBCORE_ATTR_UNSPEC,
	UBCORE_HDR_COMMAND,
	UBCORE_HDR_ARGS_LEN,
	UBCORE_HDR_ARGS_ADDR,
	UBCORE_ATTR_NS_MODE,
	UBCORE_ATTR_DEV_NAME,
	UBCORE_ATTR_NS_FD,
	UBCORE_MSG_SEQ,
	UBCORE_MSG_TYPE,
	UBCORE_TRANSPORT_TYPE,
	UBORE_SRC_ID,
	UBORE_DST_ID,
	UBCORE_PAYLOAD_LEN,
	UBCORE_PAYLOAD_DATA,
	UBCORE_UPDATE_EID_RET,
	UBCORE_ATTR_AFTER_LAST,
	NUM_UBCORE_ATTR = UBCORE_ATTR_AFTER_LAST,
	UBCORE_ATTR_MAX = UBCORE_ATTR_AFTER_LAST - 1
};

#endif // UBCORE_GENERIC_NETLINK_DEFINE_H
