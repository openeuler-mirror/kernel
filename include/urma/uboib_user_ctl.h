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
 * Description: UBOIB user control header file
 * Author: Wu Yuyan
 * Create: 2024-01-13
 * Note:
 * History: 2024-01-13   Create File
 */

#ifndef UBOIB_USER_CTL_H
#define UBOIB_USER_CTL_H

#include <urma/ubcore_types.h>

/* add user_ctrl for ums */
enum uboib_user_control_opcode {
	UBOIB_USER_CTL_SYNC_SG = 0x30,
	UBOIB_USER_CTL_GET_MAC,
	UBOIB_USER_CTL_GET_GID,
	UBOIB_USER_CTL_PUT_GID,
	UBOIB_USER_CTL_QUERY_DEV_ATTR,
	UBOIB_USER_CTL_READ_PNET
};

/* Refer to UBOIB_USER_CTL_SYNC_SG */
struct uboib_user_ctl_sync_sg_in {
	struct ubcore_target_seg *ub_tseg;
	int data_direction;
};

/* Refer to UBOIB_USER_CTL_GET_MAC */
struct uboib_user_ctl_get_mac_in {
	uint8_t port;
};

struct uboib_user_ctl_get_mac_out {
	uint8_t mac[UBCORE_MAC_BYTES];
	int ret;
};

/* Refer to UBOIB_USER_CTL_GET_GID */
struct uboib_user_ctl_get_gid_in {
	uint8_t port;
	int gid_idx;
};

struct uboib_user_ctl_gid_attr {
	int gid_type;
	int roce_v1_type;
	int roce_v2_type;
	uint16_t index;
	uint8_t gid[UBCORE_EID_SIZE];
};

struct uboib_user_ctl_get_gid_out {
	uint32_t core_cap_flags;
	const struct net_device *ndev;
	struct uboib_user_ctl_gid_attr gid_attr;
	int ret;
};

/* Refer to UBOIB_USER_CTL_PUT_GID */
struct uboib_user_ctl_put_gid_in {
	uint8_t port;
	int gid_idx;
};

/* Refer to UBOIB_USER_CTL_QUERY_DEV_ATTR */
enum uboib_user_ctl_query_dev_mask {
	UBOIB_QUERY_GID_TBL_LEN = 0x1,
	UBOIB_QUERY_NET_DEV = 0x1 << 1,
	UBOIB_QUERY_NET_NS = 0x1 << 2
};

struct uboib_user_ctl_query_dev_attr_in {
	uint32_t mask;
	uint8_t port;
	struct net *net;
};

struct uboib_user_ctl_port_attr {
	bool is_valid;
	int gid_tbl_len;
	struct net_device *ndev;
};

#define UBOIB_USER_CTL_MAX_PORTS 2
struct uboib_user_ctl_dev_attr {
	bool is_accessed_from_ns;
	struct uboib_user_ctl_port_attr port_attr[UBOIB_USER_CTL_MAX_PORTS];
};

struct uboib_user_ctl_query_dev_attr_out {
	struct uboib_user_ctl_dev_attr dev_attr;
	int ret;
};

/* Refer to UBOIB_USER_CTL_READ_PNET */
struct uboib_user_ctl_read_pnet_out {
	struct net *net;
};

int uboib_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *user_ctl);

#endif
