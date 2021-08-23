/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef EUFS_H
#define EUFS_H

#include <linux/crc16.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>
#include <linux/version.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/uio.h>
#include <linux/mutex.h>
#include <linux/slab.h>

/* annotation for pointer to persistent memory */
#define __pmem

#define NV_CHECK (0)

#if NV_CHECK
#pragma message "NV CHECK IS TURNED ON! NO PERF. EVAL.!"
#endif

#if NV_CHECK
#define NV_ASSERT(x)                                                           \
	do {                                                                   \
		if (!(x)) {                                                    \
			eufs_warn("assertion failed %s:%d: %s\n", __FILE__,    \
				  __LINE__, #x);                               \
		}                                                              \
		WARN(!(x), "detail:");                                         \
	} while (0)
#else
#define NV_ASSERT(x)
#endif

#include "const.h"
#include "euler_dbg.h"
#include "nvm_struct.h"
#include "euler_def.h"
#include "kmem_cache.h"
#include "flush.h"
#include "euler_common.h"
#include "inode.h"
#include "nvalloc.h"

extern int num_sockets;

/* Function Prototypes */
extern __printf(2, 3) void eufs_error_mng(struct super_block *sb,
					  const char *fmt, ...);

/* dir.c */
extern const struct file_operations eufs_dir_operations;

/* file.c */
extern const struct inode_operations eufs_file_inode_operations;
extern const struct file_operations eufs_file_operations;
int eufs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* inode.c */
extern const struct address_space_operations eufs_aops;

/* namei.c */
extern const struct inode_operations eufs_dir_inode_operations;
extern const struct inode_operations eufs_special_inode_operations;

/* symlink.c */
extern const struct inode_operations eufs_symlink_inode_operations;

#endif /* EUFS_H */
