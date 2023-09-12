// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: uburma cmd implementation
 * Author: Qian Guoxin
 * Create: 2021-08-04
 * Note:
 * History: 2021-08-04: Create file
 * History: 2022-07-25: Yan Fangfang Change the prefix uburma_ioctl_ to uburma_cmd_
 */

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <urma/ubcore_uapi.h>
#include <urma/ubcore_types.h>
#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cmd.h"

#define UBURMA_INVALID_TPN UINT_MAX

void uburma_cmd_inc(struct uburma_device *ubu_dev)
{
	atomic_inc(&ubu_dev->cmdcnt);
}

void uburma_cmd_dec(struct uburma_device *ubu_dev)
{
	if (atomic_dec_and_test(&ubu_dev->cmdcnt))
		complete(&ubu_dev->cmddone);
}

void uburma_cmd_flush(struct uburma_device *ubu_dev)
{
	uburma_cmd_dec(ubu_dev);
	wait_for_completion(&ubu_dev->cmddone);
}

typedef int (*uburma_cmd_handler)(struct ubcore_device *ubc_dev, struct uburma_file *file,
				  struct uburma_cmd_hdr *hdr);

static uburma_cmd_handler g_uburma_cmd_handlers[] = {
	[0] = NULL,
};

static int uburma_cmd_parse(struct ubcore_device *ubc_dev, struct uburma_file *file,
			    struct uburma_cmd_hdr *hdr)
{
	if (hdr->command < UBURMA_CMD_CREATE_CTX || hdr->command > UBURMA_CMD_USER_CTL ||
	    g_uburma_cmd_handlers[hdr->command] == NULL) {
		uburma_log_err("bad uburma command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}
	return g_uburma_cmd_handlers[hdr->command](ubc_dev, file, hdr);
}

long uburma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct uburma_cmd_hdr *user_hdr = (struct uburma_cmd_hdr *)arg;
	struct uburma_file *file = filp->private_data;
	struct uburma_device *ubu_dev = file->ubu_dev;
	struct ubcore_device *ubc_dev;
	struct uburma_cmd_hdr hdr;
	int srcu_idx;
	long ret;

	uburma_cmd_inc(ubu_dev);
	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		uburma_log_err("can not find ubcore device.\n");
		ret = -EIO;
		goto srcu_unlock;
	}

	if (cmd == UBURMA_CMD) {
		ret = (long)copy_from_user(&hdr, user_hdr, sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.command > UBURMA_CMD_CREATE_CTX && file->ucontext == NULL)) {
			uburma_log_err(
				"invalid input, hdr.command: %d, ret:%ld, hdr.args_len: %d\n",
				hdr.command, ret, hdr.args_len);
			ret = -EINVAL;
		} else {
			ret = (long)uburma_cmd_parse(ubc_dev, file, &hdr);
		}
	} else {
		uburma_log_err("bad ioctl command.\n");
		ret = -ENOIOCTLCMD;
	}

srcu_unlock:
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	uburma_cmd_dec(ubu_dev);
	return ret;
}
