// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include "euler.h"

static const char *eufs_get_link(struct dentry *dentry, struct inode *inode,
				  struct delayed_call *call)
{
	struct eufs_inode *pi = EUFS_FRESH_PI(EUFS_PI(inode));

	return ((char *)o2p(inode->i_sb, eufs_iread_root(pi))) + sizeof(u64);
}

const struct inode_operations eufs_symlink_inode_operations = {
	.get_link = eufs_get_link,
	.setattr = eufs_notify_change,
};
