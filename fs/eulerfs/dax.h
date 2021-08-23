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

#ifndef EUFS_DAX_H
#define EUFS_DAX_H

#include "euler.h"

#define EUFS_FILE_BCNT_WITH_HEIGHT(h)                                         \
	(1ULL << ((h)*EUFS_FILE_TREE_DEGREE_SHIFT))
#define EUFS_PTR_CNT_SHIFT_PER_CACHELINE 3

#define EUFS_H2_INDEX_IN_L0(bidx) ((bidx) >> EUFS_FILE_TREE_DEGREE_SHIFT)
#define EUFS_H2_INDEX_IN_L1(bidx) ((bidx) & (EUFS_FILE_TREE_DEGREE - 1))
#define EUFS_H2_IS_FREE_L1_SUBTREE(idx0, bcnt)                                \
	(((idx0) << EUFS_FILE_TREE_DEGREE_SHIFT) >= (bcnt))

#define EUFS_H3_INDEX_IN_L0(bidx)                                             \
	((bidx) >> (EUFS_FILE_TREE_DEGREE_SHIFT * 2))
/* (bidx - (idx0 << (SHIFT * 2))) >> SHIFT */
#define EUFS_H3_INDEX_IN_L1(idx0, bidx)                                       \
	(((bidx) >> EUFS_FILE_TREE_DEGREE_SHIFT) -                            \
	 ((idx0) << EUFS_FILE_TREE_DEGREE_SHIFT))
#define EUFS_H3_INDEX_IN_L2(bidx) ((bidx) & (EUFS_FILE_TREE_DEGREE - 1))

#define EUFS_H3_IS_FREE_L2_SUBTREE(idx0, idx1, bcnt)                          \
	((((idx0) << (EUFS_FILE_TREE_DEGREE_SHIFT * 2)) +                     \
	  ((idx1) << EUFS_FILE_TREE_DEGREE_SHIFT)) >= (bcnt))
#define EUFS_H3_IS_FREE_L1_SUBTREE(idx0, bcnt)                                \
	(((idx0) << (EUFS_FILE_TREE_DEGREE_SHIFT * 2)) >= (bcnt))

int eufs_alloc_blocks_btree(struct inode *inode, unsigned long start_block,
			     unsigned long num_blocks, int zero);
ssize_t eufs_file_read(struct file *filp, char __user *buf, size_t len,
			    loff_t *ppos);
ssize_t eufs_file_write(struct file *filp, const char __user *buf,
			     size_t len, loff_t *ppos);
int eufs_dax_file_mmap(struct file *file, struct vm_area_struct *vma);

int eufs_extend_btree(struct inode *inode, unsigned long num_blocks);

int eufs_shrink_btree(struct inode *inode);

static __always_inline u64 encode_root(u64 off, u64 height)
{
	return (off & ((1UL << 56) - 1)) | (height << 56);
}

static __always_inline u64 root_ptr(u64 encoded_root)
{
	return (u64)(encoded_root & ((0x1UL << 56) - 1));
}
static __always_inline int root_height(u64 ptr)
{
	return ((u64)ptr >> 56) & 0xff;
}

int eufs_free_btree(struct super_block *sb, void *root, int height,
		     u64 blocks);
int eufs_persist_btree(struct super_block *sb, void *root, int height,
			u64 old_size, u64 new_size);

ssize_t __eufs_file_write(struct address_space *mapping,
			       const char __user *buf, size_t count, loff_t pos,
			       loff_t *ppos, bool zero, bool keep);
ssize_t __eufs_file_write_inode(struct inode *inode,
				     const char __user *buf, size_t count,
				     loff_t pos, loff_t *ppos, bool zero,
				     bool keep);

loff_t eufs_file_llseek(struct file *file, loff_t offset, int whence);

/* zeroing range [pos, end) */
static inline void eufs_inode_zero_range(struct inode *inode, loff_t pos,
					  loff_t end)
{
	if (pos == end)
		return;
	__eufs_file_write_inode(inode, NULL, end - pos, pos, NULL, true,
				     true);
}
/* zeroing range [pos, end) */
static inline void eufs_inode_zero_range_len(struct inode *inode, loff_t pos,
					      size_t len)
{
	if (!len)
		return;
	__eufs_file_write_inode(inode, NULL, len, pos, NULL, true, true);
}

#endif /* EUFS_DAX_H */
