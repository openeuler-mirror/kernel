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
 * Description: uburma cmd header file
 * Author: Qian Guoxin
 * Create: 2023-2-28
 * Note:
 * History: 2023-2-28: Create file
 */

#ifndef UBURMA_CMD_H
#define UBURMA_CMD_H
#include <linux/types.h>
#include <linux/uaccess.h>

#include "uburma_types.h"

struct uburma_cmd_hdr {
	uint32_t command;
	uint32_t args_len;
	uint64_t args_addr;
};

#define UBURMA_CMD_MAX_ARGS_SIZE 4096

/* only for uburma device ioctl */
#define UBURMA_CMD_MAGIC 'U'
#define UBURMA_CMD _IOWR(UBURMA_CMD_MAGIC, 1, struct uburma_cmd_hdr)

enum uburma_cmd {
	UBURMA_CMD_CREATE_CTX = 1,
	UBURMA_CMD_DESTROY_CTX,
	UBURMA_CMD_USER_CTL
};

struct uburma_cmd_udrv_priv {
	uint64_t in_addr;
	uint32_t in_len;
	uint64_t out_addr;
	uint32_t out_len;
};

struct uburma_cmd_create_ctx {
	struct {
		uint32_t uasid;
	} in;
	struct {
		int async_fd;
	} out;
	struct uburma_cmd_udrv_priv udata;
};

/* copy from user_space addr to kernel args */
static inline int uburma_copy_from_user(void *args, const void *args_addr, unsigned long args_size)
{
	int ret = (int)copy_from_user(args, args_addr, args_size);

	if (ret != 0) {
		uburma_log_err("copy from user failed, ret:%d.\n", ret);
		return -EFAULT;
	}
	return 0;
}

/* copy kernel args to user_space addr */
static inline int uburma_copy_to_user(void *args_addr, const void *args, unsigned long args_size)
{
	int ret = (int)copy_to_user(args_addr, args, args_size);

	if (ret != 0) {
		uburma_log_err("copy to user failed ret:%d.\n", ret);
		return -EFAULT;
	}
	return 0;
}

void uburma_cmd_inc(struct uburma_device *ubu_dev);
void uburma_cmd_dec(struct uburma_device *ubu_dev);
void uburma_cmd_flush(struct uburma_device *ubu_dev);

#endif /* UBURMA_CMD_H */
