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
#define UBCORE_MAX_CMD_SIZE 4096
#define UBCORE_CMD_EID_SIZE 16

/* only for ubcore device ioctl */
enum ubcore_cmd {
	UBCORE_CMD_SET_UASID = 1,
	UBCORE_CMD_PUT_UASID,
	UBCORE_CMD_SET_UTP,
	UBCORE_CMD_SHOW_UTP,
	UBCORE_CMD_QUERY_STATS,
	UBCORE_CMD_QUERY_RES
};

struct ubcore_cmd_set_uasid {
	struct {
		uint64_t token;
		uint32_t uasid;
	} in;
	struct {
		uint32_t uasid;
	} out;
};

struct ubcore_cmd_put_uasid {
	struct {
		uint32_t uasid;
	} in;
};

struct ubcore_cmd_query_stats {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint8_t eid[UBCORE_CMD_EID_SIZE];
		uint32_t tp_type;
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
		uint8_t eid[UBCORE_CMD_EID_SIZE];
		uint32_t tp_type;
		uint32_t type;
		uint32_t key;
	} in;
	struct {
		uint64_t addr;
		uint32_t len;
	} out;
};

struct ubcore_cmd_set_utp {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint8_t eid[UBCORE_CMD_EID_SIZE];
		uint32_t transport_type;
		bool spray_en;
		uint16_t data_udp_start;
		uint8_t udp_range;
	} in;
};

struct ubcore_cmd_show_utp {
	struct {
		char dev_name[UBCORE_MAX_DEV_NAME];
		uint8_t eid[UBCORE_CMD_EID_SIZE];
		uint32_t transport_type;
	} in;
};

/* copy from user_space addr to kernel args */
static inline int ubcore_copy_from_user(void *args, const void *args_addr, unsigned long args_size)
{
	int ret = (int)copy_from_user(args, args_addr, args_size);

	if (ret != 0)
		ubcore_log_err("copy from user failed, ret:%d.\n", ret);
	return ret;
}

/* copy kernel args to user_space addr */
static inline int ubcore_copy_to_user(void *args_addr, const void *args, unsigned long args_size)
{
	int ret = (int)copy_to_user(args_addr, args, args_size);

	if (ret != 0)
		ubcore_log_err("copy to user failed ret:%d.\n", ret);
	return ret;
}
#endif
