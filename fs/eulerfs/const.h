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

#ifndef EUFS_CONST_H
#define EUFS_CONST_H

/* EULER */
#define EUFS_SUPER_MAGIC 0x50C9
/* Mount flags */
#define EUFS_MOUNT_ERRORS_RO	0x000001 /* Remount fs ro on errors */
#define EUFS_MOUNT_ERRORS_PANIC	0x000002 /* Panic on errors */
#define EUFS_MOUNT_FORMAT	0x000004 /* was FS formatted on mount? */

#define NULL_ADDR ((u64)-1ll)
#define NULL_VAL (0)
#define NULL_ADDR_PTR ((void *)(NULL_ADDR))

/* FS Limits */
#define EUFS_MAX_NAME_LEN (255)
#define EUFS_LINK_MAX (32000) /* max links to a file */

/* layout: hash_len (u64) + sym_link + trailing zero */
#define EUFS_MAX_SYMLINK_LEN (PAGE_SIZE - sizeof(u64) - 1)
#define EUFS_SYMLINK_HASHLEN_LEN(hashlen) (((hashlen) >> 48) & 0xfff)
#define EUFS_SYMLINK_SIZE(len) ((len) + sizeof(u64) + 1)

#define EUFS_BLOCK_SIZE (4096)
#define EUFS_BLOCK_SIZE_BITS (12)

/* The initial height is 0 when the file tree contains no or one block */
#define EUFS_MAX_FILE_TREE_HEIGHT 3
#define EUFS_FILE_TREE_DEGREE_SHIFT 9
#define EUFS_FILE_TREE_DEGREE (1U << EUFS_FILE_TREE_DEGREE_SHIFT)
#define EUFS_MAX_FILE_BLK_CNT                                                 \
	(1ll << (EUFS_MAX_FILE_TREE_HEIGHT * EUFS_FILE_TREE_DEGREE_SHIFT))
#define EUFS_MAX_FILE_SIZE (4096ll * EUFS_MAX_FILE_BLK_CNT)

#define EUFS_POISON_POINTER ((void *)0x1010101010101010UL)
#define EUFS_POISON_VALUE ((u64)0x1010101010101010UL)

#define CACHELINE_SIZE (64)

#define EUFS_ALLOC_BLOCKS_ZERO_NONE (0x0) /* Zero none NULL_ADDR pages */
#define EUFS_ALLOC_BLOCKS_ZERO_ALL (0x1) /* Zero all NULL_ADDR pages */
#define EUFS_ALLOC_BLOCKS_ZERO_EDGE (0x2) /* Zero edge NULL_ADDR pages */

#define EUFS_INODE_SIZE (CACHELINE_SIZE * 2)

#define NV_DICT_CAPACITY (512ULL)
/*
 * EOC stands for "End Of Chain".
 *
 * When volatile bucket (namely table[idx]) is EUFS_DIR_EOC_PTR,
 * it means that both volatile bucket and persist bucket are empty.
 * When volatile bucket is NULL, it just means that volatile
 * bucket is empty.
 *
 * When volatile_next is EUFS_DIR_EOC, it means current entry is
 * the last one in the chain although its next may still points
 * to an entry (because the setting and persistence of next are
 * deferred). When volatile_next is NULL, it means next should be
 * checked to ensure whether or not the current entry is the last
 * one in the chain.
 */
#define EUFS_DIR_EOC ((u64)-1)
#define EUFS_DIR_EOC_PTR ((void *)EUFS_DIR_EOC)
/* DIR DELeted NEW dentry */
#define EUFS_DIR_DELNEW ((u64)0x3030303030303030UL)

#endif /* EUFS_CONST_H */
