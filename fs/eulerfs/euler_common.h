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

#ifndef EUFS_COMMON_H
#define EUFS_COMMON_H

#include <linux/crc16.h>
#include <linux/crc32.h>
#include <linux/crc32c.h>
#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/uio.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/fs.h>

#ifndef EUFS_H
#error "Please include euler_common.h by including euler.h"
#endif

#define EUFS_INODE_CNT_IN_RENAME 4

#define PAGE_DIV_ROUND_UP(x) (((x) + PAGE_SIZE - 1) >> PAGE_SHIFT)
#define PAGE_DIV_ROUND_DOWN(x) (((x)) >> PAGE_SHIFT)

#define clear_opt(o, opt) (o &= ~EUFS_MOUNT_##opt)
#define set_opt(o, opt) (o |= EUFS_MOUNT_##opt)
#define test_opt(sb, opt) (EUFS_SB(sb)->s_mount_opt & EUFS_MOUNT_##opt)

static __always_inline void *o2p(struct super_block *sb, u64 offset);
static __always_inline u64 p2o(struct super_block *sb, void *ptr);

static __always_inline struct eufs_sb_info *EUFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static __always_inline struct eufs_inode_info *EUFS_I(struct inode *inode)
{
	return container_of(inode, struct eufs_inode_info, vfs_inode);
}

static __always_inline struct eufs_inode *EUFS_PI(struct inode *inode)
{
	return (struct eufs_inode *)o2p(inode->i_sb, inode->i_ino);
}

static __always_inline unsigned long eufs_pi2ino(struct super_block *sb,
						  struct eufs_inode *pi)
{
	return p2o(sb, EUFS_HEAD_PI(pi));
}

static __always_inline struct eufs_super_block *
eufs_get_super(struct super_block *sb)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	return (struct eufs_super_block *)sbi->virt_addr;
}

static __always_inline void *eufs_get_renamej(struct super_block *sb, int cpu)
{
	struct eufs_sb_info *sbi = EUFS_SB(sb);

	return (void *)((u64)sbi->renamej + EUFS_RENAMEJ_ENTRY_SIZE * cpu);
}

/*
 * o: offset: u64
 * p: pointer: void *
 * s: storage: __le64
 */
static __always_inline void *o2p(struct super_block *sb, u64 offset)
{
	if (offset == 0)
		return NULL;
	if (offset == -1)
		return (void *)-1;
	return (void *)(EUFS_SB(sb)->virt_addr + offset);
}

static __always_inline u64 p2o(struct super_block *sb, void *ptr)
{
	if (ptr == NULL)
		return 0;
	if (ptr == (void *)-1)
		return -1;
	return (u64)(ptr - EUFS_SB(sb)->virt_addr);
}

/* pointer to storage */
static __always_inline __le64 p2s(struct super_block *sb, void *ptr)
{
	return cpu_to_le64(p2o(sb, ptr));
}
/* storage to pointer */
static __always_inline void *s2p(struct super_block *sb, __le64 s)
{
	return o2p(sb, le64_to_cpu(s));
}

static __always_inline bool
eufs_access_ok(struct super_block *sb, const void *pointer, unsigned long sz)
{
	return true;
}

#define eufs_ptr_fast_check_b(ptr) 0

#define eufs_ptr_fast_check(ptr) BUG_ON(eufs_ptr_fast_check_b(ptr))

#define HASHLEN_LEN(hashlen) (((hashlen) >> 48) & 0xff)

static __always_inline hashlen_t hash(const char *name, size_t len)
{
	static const int seed = 131;
	u64 r = 0;
	int i;

	for (i = 0; i < len; ++i)
		r = r * seed + (int)name[i];

	return (u64)len << 48 | (r & 0xffffffffffff);
}

static __always_inline bool key_equals(struct super_block *sb, const char *key,
				       hashlen_t hashlen,
				       const struct nv_dict_entry *de)
{
	int len;
	struct nv_name_ext *p;

	NV_ASSERT(key);
	NV_ASSERT(hashlen);

	if (hashlen != de->hv)
		return false;
	len = HASHLEN_LEN(hashlen);
	if (likely(len <= FIRST_LEN))
		return memcmp(de->name, key, len) == 0;
	if (memcmp(de->name, key, FIRST_LEN))
		return false;
	eufs_dbg("first len ok\n");
	len -= FIRST_LEN;
	p = s2p(sb, de->nextname);
	key += FIRST_LEN;
	while (len > FOLLOW_LEN) {
		eufs_dbg("check again p:%*s key:%*s\n", (int)FOLLOW_LEN,
			  p->name, (int)FOLLOW_LEN, key);
		if (memcmp(p->name, key, FOLLOW_LEN))
			return false;
		p = s2p(sb, p->nextname);
		key += FOLLOW_LEN;
		len -= FOLLOW_LEN;
	}
	eufs_dbg("final check name p:%*s key:%*s\n", len, p->name, len, key);
	return !memcmp(p->name, key, len);
}

static __always_inline void eufs_flush_pi(struct eufs_inode *pi)
{
	eufs_flush_cacheline(pi);
	eufs_flush_cacheline(&pi->i_fresh);
}

static __always_inline void inode_dep_lock(struct inode *inode)
{
	mutex_lock(&EUFS_I(inode)->i_dep_lock);
}
static __always_inline void inode_dep_unlock(struct inode *inode)
{
	mutex_unlock(&EUFS_I(inode)->i_dep_lock);
}
static __always_inline int inode_is_dep_locked(struct inode *inode)
{
	return mutex_is_locked(&EUFS_I(inode)->i_dep_lock);
}
static __always_inline void inode_header_lock(struct inode *inode)
{
	mutex_lock(&EUFS_I(inode)->i_header_lock);
}
static __always_inline void inode_header_unlock(struct inode *inode)
{
	mutex_unlock(&EUFS_I(inode)->i_header_lock);
}
static __always_inline int inode_is_header_locked(struct inode *inode)
{
	return mutex_is_locked(&EUFS_I(inode)->i_header_lock);
}
static __always_inline void inode_urgent_lock(struct inode *inode)
{
	mutex_lock(&EUFS_I(inode)->i_urgent_mutex);
}
static __always_inline void inode_urgent_unlock(struct inode *inode)
{
	mutex_unlock(&EUFS_I(inode)->i_urgent_mutex);
}
static __always_inline int inode_is_urgent_locked(struct inode *inode)
{
	return mutex_is_locked(&EUFS_I(inode)->i_urgent_mutex);
}

static __always_inline void inode_leaf_lock(struct inode *inode)
{
	mutex_lock(&EUFS_I(inode)->i_leaf_lock);
}

static __always_inline void inode_leaf_unlock(struct inode *inode)
{
	mutex_unlock(&EUFS_I(inode)->i_leaf_lock);
}

#endif /* EUFS_COMMON_H */
