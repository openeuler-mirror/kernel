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

#ifndef EUFS_ALLOC_INTERFACE_H
#define EUFS_ALLOC_INTERFACE_H

#include "nvalloc.h"
#include "pbatch.h"

static __always_inline void *nvzalloc(struct super_block *sb, size_t size,
				      u8 tag, bool nonblocking)
{
	void *r = nvmalloc(sb, size, tag, nonblocking);

	if (r)
		memset(r, 0, size);

	return r;
}

static __always_inline void *
nv_zalloc_file_data_nonblocking(struct super_block *sb)
{
	return nvzalloc(sb, PAGE_SIZE, EUFS_PAGE_FILE_DATA, true);
}

struct eufs_inode;
struct nv_name_ext;
struct nv_dict_entry;

static __always_inline struct eufs_inode *
eufs_malloc_pinode(struct super_block *sb)
{
	/* mirrored inodes: the head inode and the tail inode */
	return nvmalloc(sb, EUFS_INODE_SIZE * 2, EUFS_LINE4_INODE, false);
}
static __always_inline struct nv_dict_entry *
eufs_malloc_dentry(struct super_block *sb)
{
	return nvmalloc(sb, CACHELINE_SIZE, EUFS_LINE_DENTRY, false);
}
static __always_inline struct nv_name_ext *
eufs_malloc_name_ext(struct super_block *sb)
{
	return nvmalloc(sb, CACHELINE_SIZE, EUFS_LINE_NAME_EXT, false);
}

static __always_inline void *eufs_malloc_file_data(struct super_block *sb)
{
	return nvmalloc(sb, PAGE_SIZE, EUFS_PAGE_FILE_DATA, false);
}
static __always_inline void *eufs_zalloc_file_data(struct super_block *sb)
{
	return nvzalloc(sb, PAGE_SIZE, EUFS_PAGE_FILE_DATA, false);
}
static __always_inline void *eufs_zmlloc_file_index(struct super_block *sb)
{
	return nvmalloc(sb, PAGE_SIZE, EUFS_PAGE_FILE_INDEX, false);
}
static __always_inline void *eufs_zalloc_symlink(struct super_block *sb)
{
	return nvzalloc(sb, PAGE_SIZE, EUFS_PAGE_SYMLINK, false);
}
static __always_inline void *eufs_zalloc_htable(struct super_block *sb)
{
	return nvzalloc(sb, PAGE_SIZE, EUFS_PAGE_HTABLE, false);
}
static __always_inline void *eufs_malloc_inode_ext(struct super_block *sb)
{
	return nvmalloc(sb, PAGE_SIZE, EUFS_PAGE_INODE_EXT, false);
}

static __always_inline void nv_zfree(struct super_block *sb, void *p)
{
	if (p == NULL_ADDR_PTR)
		return;

	nvfree(sb, p, false);
}

static __always_inline void nv_free(struct super_block *sb, void *p)
{
	if (p != NULL_ADDR_PTR)
		nv_zfree(sb, p);
}

static __always_inline void nv_free_rest(struct super_block *sb, void *p)
{
	if (p != NULL_ADDR_PTR)
		nvfree(sb, p, true);
}

static __always_inline void *zalloc(ssize_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

static __always_inline void zfree(void *p)
{
	kfree(p);
}

#endif /* EUFS_ALLOC_INTERFACE_H */
