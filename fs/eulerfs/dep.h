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

#ifndef EUFS_DEP_H
#define EUFS_DEP_H

#include <linux/llist.h>
#include <linux/list.h>
#include <linux/fs.h>
#include "euler.h"
#include "alloc_interface.h"

/**
 * Dep type:
 * - diradd (for create/symlink/link/mknod)
 * - dirrem
 */

enum fsync_type {
	FSYNC_DEP,
	FSYNC_RENAME,
	FSYNC_SYSCALL,
};

extern int disable_persisters;
extern int persist_period;
extern int persisters_per_socket;

#define eufs_dep_seq_after(a, b) ((s32)((b) - (a)) < 0)
#define eufs_dep_seq_after_eq(a, b) ((s32)((a) - (b)) >= 0)

void eufs_dir_fsync_oneshot(struct inode *dir);
void fsync_on_draining(struct inode *dir, struct inode *inode);

void fsync_rename_inodes(struct inode *old_inode, struct inode *new_inode,
			 struct inode **locked_inodes);

void fsync_oneshot(struct inode *inode);

enum dep_type {
	DEP_DIRADD, /* Hard link is detected by checking inode->i_nlink */
	DEP_DIRREM,
	DEP_TYPE_COUNT,

};

struct dep_node {
	struct list_head node;
	struct list_head owner_node;
	u32 seq;
	/* Type of the dependency */
	enum dep_type type;
	/* Previous dentry */
	struct nv_dict_entry *prevde;
	/* header of the list */
	u64 *nv_header;
	/* Related Dentry, which also points to an inode */
	struct nv_dict_entry __pmem *de;
	/* inode for de->pi */
	struct inode *inode;
	struct inode *dir;
} __aligned(CACHELINE_SIZE);

int dep_init(struct super_block *sb);
void dep_fini(struct super_block *sb);

static __always_inline void request_persistence(struct inode *inode)
{
	struct eufs_sb_info *sbi = EUFS_SB(inode->i_sb);
	struct eufs_inode_info *vi = EUFS_I(inode);
	int cpu;

	BUG_ON(!inode_is_locked(inode));

	if (!vi->i_is_dirty)
		vi->i_is_dirty = true;

	if (vi->i_is_persisting)
		return;

	cpu = get_cpu();
	llist_add(&vi->i_persistee_node, per_cpu_ptr(sbi->persistee_list, cpu));
	put_cpu();

	eufs_dbg_vlimit("sbi->s_nr_dirty_inodes=%d ++ vi=%px @cpu=%d\n",
			 atomic_read(&sbi->s_nr_dirty_inodes), vi, cpu);

	if (atomic_inc_return(&sbi->s_nr_dirty_inodes) > max_dirty_inodes &&
	    !sbi->s_draining)
		sbi->s_draining = true;

	vi->i_is_persisting = true;
	ihold(inode);
}

/* precondition: dir inode is mutex-locked */
static __always_inline void dep_insert(struct inode *dir, struct dep_node *dep)
{
	struct eufs_inode_info *dir_vi = EUFS_I(dir);
	struct eufs_inode_info *child_vi = EUFS_I(dep->inode);
	struct eufs_sb_info *sbi = EUFS_SB(dir->i_sb);

	inode_dep_lock(dir);
	inode_header_unlock(dir);
	list_add_tail(&dep->node, &dir_vi->i_dep_list);
	spin_lock(&child_vi->i_owner_lock);
	list_add_tail(&dep->owner_node, &child_vi->i_owner_list);
	spin_unlock(&child_vi->i_owner_lock);
	inode_dep_unlock(dir);

	eufs_dbg_vlimit("sbi->s_nr_dep_nodes=%d ++\n",
			 atomic_read(&sbi->s_nr_dep_nodes));
	if (atomic_inc_return(&sbi->s_nr_dep_nodes) > max_dep_nodes &&
	    !sbi->s_draining) {
		sbi->s_draining = true;
	}

	/* Request a persistence */
	request_persistence(dir);
}

static __always_inline bool eufs_valid_inode_in_de(struct nv_dict_entry *de,
						    struct inode *inode)
{
	return (le64_to_cpu(de->inode) == inode->i_ino);
}

static __always_inline void
dep_new_insert(struct dep_node *dep, struct inode *dir, enum dep_type type,
	       struct nv_dict_entry *prevde, u64 *nv_header,
	       struct nv_dict_entry *de, struct inode *inode, u32 seq)
{
	dep->type = type;
	dep->prevde = prevde;
	dep->nv_header = nv_header;
	dep->de = de;
	dep->inode = inode;
	dep->dir = dir;
	dep->seq = seq;
	NV_ASSERT(eufs_valid_inode_in_de(dep->de, dep->inode));
	ihold(dep->inode);
	dep_insert(dir, dep);
}

static __always_inline void persist_dentry(struct nv_dict_entry *de)
{
	NV_ASSERT(de);
	NV_ASSERT((u64)de % CACHELINE_SIZE == 0);
	NV_ASSERT(sizeof(de) <= CACHELINE_SIZE);
	eufs_flush_cacheline(de);
}

static __always_inline void persist_pinode(struct eufs_inode *pi)
{
	WARN_ON(!EUFS_IS_HEAD_PI(pi));
	NV_ASSERT(pi);
	NV_ASSERT((u64)pi % CACHELINE_SIZE == 0);
	NV_ASSERT(sizeof(pi) <= EUFS_INODE_SIZE);
	eufs_flush_cacheline(EUFS_FRESH_PI(pi));
	eufs_flush_cacheline(&EUFS_FRESH_PI(pi)->i_fresh);
}

static __always_inline void persist_name(struct super_block *sb,
					 const struct nv_dict_entry *de,
					 struct alloc_batch *ab)
{
	size_t len = HASHLEN_LEN(de->hv);
	struct nv_name_ext *next;
	const char *name;

	if (likely(len <= FIRST_LEN)) {
		/* embedded in de */
		return;
	}
	next = s2p(sb, de->nextname);
	len -= FIRST_LEN;
	name = next->name;
	eufs_alloc_batch_add(sb, ab, (void *)name);
	while (len > FOLLOW_LEN) {
		next = s2p(sb, next->nextname);
		eufs_flush_cacheline(name);
		len -= FOLLOW_LEN;
		name = next->name;
		eufs_alloc_batch_add(sb, ab, (void *)name);
	}
	eufs_flush_cacheline(name);
}

static __always_inline void persist_symlink(void *root)
{
	u64 len;

	NV_ASSERT(root);
	NV_ASSERT(((u64)root) % PAGE_SIZE == 0);
	len = EUFS_SYMLINK_HASHLEN_LEN(*((u64 *)root));
	NV_ASSERT(len <= EUFS_MAX_SYMLINK_LEN);
	BUG_ON(len > EUFS_MAX_SYMLINK_LEN);
	eufs_flush_range(root, EUFS_SYMLINK_SIZE(len));
}

static __always_inline void persist_page(const char *page)
{
	NV_ASSERT(page);
	NV_ASSERT(((u64)page) % PAGE_SIZE == 0);
	eufs_flush_page(page);
}

#endif /* EUFS_DEP_H */
