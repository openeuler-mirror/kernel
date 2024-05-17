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
 * Description: ubcore cmd header file
 * Author: Qian Guoxin
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBCORE_CMD_H
#define UBCORE_CMD_H

#include <linux/types.h>
#include <linux/uaccess.h>
#include "ubcore_log.h"
#include <urma/ubcore_types.h>

struct ubcore_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBCORE_CMD_MAGIC 'C'
#define UBCORE_CMD _IOWR(UBCORE_CMD_MAGIC, 1, struct ubcore_cmd_hdr)
#define UBCORE_MAX_CMD_SIZE 8192

/* only for ubcore device ioctl */
enum ubcore_cmd {
	UBCORE_CMD_QUERY_STATS = 1,
	UBCORE_CMD_QUERY_RES,
	UBCORE_CMD_ADD_EID,
	UBCORE_CMD_DEL_EID,
	UBCORE_CMD_SET_EID_MODE,
	UBCORE_CMD_SET_NS_MODE,
	UBCORE_CMD_SET_DEV_NS,
	UBCORE_CMD_SET_GENL_PID,
	UBCORE_CMD_UVS_INIT_RES,
	/* alpha netlink ops begin: */
	UBCORE_CMD_QUERY_TP_REQ,
	UBCORE_CMD_QUERY_TP_RESP,
	UBCORE_CMD_RESTORE_TP_REQ,
	UBCORE_CMD_RESTORE_TP_RESP,
	/* alpha netlink ops end: */
	UBCORE_CMD_FE2TPF_REQ,
	UBCORE_CMD_TPF2FE_RESP,
	UBCORE_CMD_ADD_SIP_REQ,
	UBCORE_CMD_ADD_SIP_RESP,
	UBCORE_CMD_DEL_SIP_REQ,
	UBCORE_CMD_DEL_SIP_RESP,
	UBCORE_CMD_TP_ERROR_REQ,
	UBCORE_CMD_TP_SUSPEND_REQ,
	UBCORE_CMD_MIGRATE_VTP_SWITCH,
	UBCORE_CMD_MIGRATE_VTP_ROLLBACK,
	UBCORE_CMD_UPDATE_TPF_DEV_INFO_REQ,
	UBCORE_CMD_UPDATE_TPF_DEV_INFO_RESP,
	UBCORE_CMD_MAX
};

struct ubcore_cmd_query_stats {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
	} in;
	struct {
		uint64_t tx_pkt;
		uint64_t rx_pkt;
		uint64_t tx_bytes;
		uint64_t rx_bytes;
		uint64_t tx_pkt_err;
		uint64_t rx_pkt_err;
	} out;
};

struct ubcore_cmd_query_res {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t type;
		uint32_t key;
		uint32_t key_ext;
		uint32_t key_cnt;
		bool query_cnt;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
		uint64_t save_ptr; /* save ubcore address for second ioctl */
	} out;
};

struct ubcore_cmd_show_utp {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t utpn;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
	} out;
};

struct ubcore_cmd_update_ueid {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint32_t eid_index;
		int ns_fd;
	} in;
};

struct ubcore_cmd_set_eid_mode {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		bool eid_mode;
	} in;
};

/* copy from user_space addr to kernel args */
static inline int ubcore_copy_from_user(void *args, const void *args_addr, unsigned long args_size)
{
	int ret;

	ret = (int)copy_from_user(args, args_addr, args_size);
	if (ret != 0)
		ubcore_log_err("copy from user failed, ret:%d.\n", ret);
	return ret;
}

/* copy kernel args to user_space addr */
static inline int ubcore_copy_to_user(void *args_addr, const void *args, unsigned long args_size)
{
	int ret;

	ret = (int)copy_to_user(args_addr, args, args_size);
	if (ret != 0)
		ubcore_log_err("copy to user failed ret:%d.\n", ret);
	return ret;
}
#endif
