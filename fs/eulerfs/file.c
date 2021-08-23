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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "euler.h"
#include "dax.h"
#include "dep.h"

static long eufs_fallocate(struct file *file, int mode, loff_t offset,
			    loff_t len)
{
	struct inode *inode = file_inode(file);
	struct eufs_inode_info *vi = EUFS_I(inode);
	loff_t end = offset + len;
	unsigned long start_page = offset >> PAGE_SHIFT,
		      end_page = DIV_ROUND_UP(end, PAGE_SIZE);
	bool zero = mode & FALLOC_FL_ZERO_RANGE;
	bool keep = mode & FALLOC_FL_KEEP_SIZE;
	long r = 0;

	if (mode & (FALLOC_FL_INSERT_RANGE | FALLOC_FL_PUNCH_HOLE |
		    FALLOC_FL_COLLAPSE_RANGE))
		return -EOPNOTSUPP;

	/* Fix xfstests 228 */
	r = inode_newsize_ok(inode, len + offset);
	if (r)
		return r;

	inode_lock(inode);

	down_write(&vi->mmap_rwsem);

	r = eufs_alloc_blocks_btree(
		inode, start_page, end_page - start_page,
		(offset < inode->i_size) ?
			/* Zero if overwriting */
			EUFS_ALLOC_BLOCKS_ZERO_ALL :
			(((offset >> PAGE_SHIFT) <=
				  (inode->i_size >> PAGE_SHIFT) &&
			  (offset > inode->i_size)) ?
				 EUFS_ALLOC_BLOCKS_ZERO_EDGE :
				 EUFS_ALLOC_BLOCKS_ZERO_NONE));
	if (IS_ERR_VALUE(r))
		goto out;

	eufs_dbg(
		"fallocate (f=%px, fsize=%llx, offset=%llx, len=%llx, zero=%d, keep=%d)\n",
		file, inode->i_size, offset, len, zero, keep);
	if (offset + len >= inode->i_size) {
		if (!zero) {
			/* zero inode->i_size ~> offset + len */
			__eufs_file_write(file->f_mapping, NULL,
					       offset + len - inode->i_size,
					       inode->i_size, NULL, true, keep);

			/* zero part of the last block goes beyond the new EOF */
			eufs_inode_zero_range(inode, offset + len,
					       PAGE_ALIGN(offset + len));
		} else if (offset >= inode->i_size) {
			eufs_dbg("zero(f=%px): %llx to %llx\n", file,
				  inode->i_size, offset);
			/* zero inode->i_size ~> offset */
			__eufs_file_write(file->f_mapping, NULL,
					       offset - inode->i_size,
					       inode->i_size, NULL, true, keep);
		}

		if (!keep)
			inode->i_size = offset + len;
	}

	if (zero) {
		/* zero offset ~> offset + len */
		__eufs_file_write(file->f_mapping, NULL, len, offset, NULL,
				       true, keep);

		/* zero part of the last block goes beyond the new EOF */
		if (offset + len >= inode->i_size)
			eufs_inode_zero_range(inode, offset + len,
					       PAGE_ALIGN(offset + len));
	}

	request_persistence(inode);

out:
	up_write(&vi->mmap_rwsem);
	inode_unlock(inode);

	return r;
}

static void eufs_dir_fsync_until_seq(struct inode *dir, u32 dep_seq)
{
	struct eufs_inode_info *vinode = EUFS_I(dir);

	if (eufs_dep_seq_after_eq(vinode->i_persisted_dep_seq, dep_seq))
		return;

	inode_lock(dir);
	eufs_dir_fsync_oneshot(dir);
	inode_unlock(dir);
}

static void eufs_persist_dentries(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct list_head *head = &vi->i_owner_list;

	if (list_empty(head))
		return;

	spin_lock(&vi->i_owner_lock);
	while (!list_empty(head)) {
		struct dep_node *dep;
		struct inode *dir;
		u32 seq;

		dep = list_first_entry(head, struct dep_node, owner_node);
		dir = dep->dir;
		seq = dep->seq;

		/* let it be deleted by dir persistence ? */
		list_del_init(&dep->owner_node);
		spin_unlock(&vi->i_owner_lock);

		eufs_dir_fsync_until_seq(dir, seq);

		spin_lock(&vi->i_owner_lock);
	}
	spin_unlock(&vi->i_owner_lock);
}

static void eufs_persist_parent_dentry_till_root(struct dentry *child)
{
	struct dentry *cur = child;

	while (!IS_ROOT(cur)) {
		struct dentry *parent;

		parent = cur->d_parent;
		eufs_persist_dentries(parent->d_inode);
		cur = parent;
	}
}

static int eufs_persist_parent_dentries_till_root(struct file *filp)
{
	struct inode *inode = filp->f_inode;
	unsigned int nlink = inode->i_nlink;
	struct dentry *alias;
	struct dentry **aliases;
	unsigned int cnt;
	unsigned int idx;

	if (nlink == 0)
		return 0;

	if (nlink == 1) {
		eufs_persist_parent_dentry_till_root(filp->f_path.dentry);
		return 0;
	}

	aliases = kmalloc(nlink * sizeof(*aliases), GFP_KERNEL);
	if (aliases == NULL)
		return -ENOMEM;

	cnt = 0;
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(alias, &inode->i_dentry, d_u.d_alias) {
		dget(alias);
		aliases[cnt++] = alias;

		if (cnt >= nlink)
			break;
	}
	spin_unlock(&inode->i_lock);

	for (idx = 0; idx < cnt; idx++) {
		eufs_persist_parent_dentry_till_root(aliases[idx]);
		dput(aliases[idx]);
	}

	kfree(aliases);

	return 0;
}

/*
 * inconsistency:
 *
 * non-dir:
 * data -> inode & name -> dentries... -> parent dentries...
 * dentry [parent data -> parent inode]
 *  (1) link can be high: new A/1, link B/2 (A/1), fsync A/1
 *  (2) link can be low: new A/1, link B/2 (A/1), fsync A/1, rm A/1,
 *      fsync A/1
 *
 * dir:
 *  children inodes -> data -> inode & name
 *  (1) link & size can be low: new A/1..3, fsync A
 *  (2) link & size can be high: new A/1..3, fsync A, rm A/1, fsync A
 */
/* This function is called by both msync() and fsync(). */
int eufs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct eufs_inode_info *vi = EUFS_I(inode);
	umode_t mode;
	int err;
	bool inode_is_dirty;

	mode = inode->i_mode;
	/* persist file data written through mmap */
	if (S_ISREG(mode)) {
		err = filemap_write_and_wait_range(inode->i_mapping, start,
						   end);
		if (err)
			return err;
	}

	/* persist its data and inode first */
	inode_is_dirty = false;
	inode_lock(inode);
	if (vi->i_is_dirty) {
		inode_is_dirty = true;
	} else {
		/*
		 * modifications of mtime/ctime/atime has not been tracked
		 * by persister yet, so check it here
		 */
		spin_lock(&inode->i_lock);
		if (inode->i_state & I_DIRTY_SYNC) {
			inode->i_state &= ~I_DIRTY_SYNC;
			inode_is_dirty = true;
		}
		spin_unlock(&inode->i_lock);
	}
	if (inode_is_dirty)
		fsync_oneshot(inode);
	inode_unlock(inode);

	/*
	 * persist dentries related with the inode. If it is non-dir,
	 * there may be multiple dentries related with it (namely hard-link).
	 */
	eufs_persist_dentries(inode);

	/*
	 * persist parent dentries and recurse upward until the root dentry is reached.
	 * For non-dir, there may be multiple parent dentries due to hard-link.
	 */
	if (!S_ISDIR(mode))
		err = eufs_persist_parent_dentries_till_root(file);
	else
		eufs_persist_parent_dentry_till_root(file->f_path.dentry);

	return err;
}

const struct file_operations eufs_file_operations = {
	.llseek = eufs_file_llseek,
	.read = eufs_file_read,
	.write = eufs_file_write,
	.mmap = eufs_dax_file_mmap,
	.open = generic_file_open,
	.fsync = eufs_fsync,
	.flush = NULL,
	.fallocate = eufs_fallocate,
};

const struct inode_operations eufs_file_inode_operations = {
	.setattr = eufs_notify_change,
	.getattr = eufs_file_getattr,
};
