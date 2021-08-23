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
#include <linux/aio.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/dax.h>
#include "euler.h"
#include "dax.h"
#include "dht.h"
#include "dep.h"

static int eufs_read_pinode(struct inode *inode, struct eufs_inode *pi)
{
	int ret = -EIO;
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct super_block *sb = inode->i_sb;
	umode_t mode;
	u64 blocks;
	u64 encoded_root;

	eufs_dbg("%s: inode=%px pi=%px, pi->i_mode=%x\n", __func__, inode,
		  pi, eufs_iread_mode(pi));

	pi = EUFS_FRESH_PI(pi);

	eufs_set_inode_flags(inode, eufs_iread_flags(pi));
	mode = eufs_iread_mode(pi);
	inode->i_mode = mode;
	vi->i_version = eufs_iread_version(pi);
	inode->i_ctime.tv_sec = eufs_iread_ctime(pi);
	inode->i_ctime.tv_nsec = eufs_iread_ctime_nsec(pi);
	i_uid_write(inode, eufs_iread_uid(pi));
	i_gid_write(inode, eufs_iread_gid(pi));
	vi->i_dotdot = eufs_iread_dotdot(pi);
	vi->i_ext = eufs_iread_ext(pi);

	inode->i_generation = eufs_iread_generation(pi);
	set_nlink(inode, eufs_iread_nlink(pi));
	inode->i_mtime.tv_sec = eufs_iread_mtime(pi);
	inode->i_atime.tv_sec = eufs_iread_atime(pi);
	inode->i_mtime.tv_nsec = eufs_iread_mtime_nsec(pi);
	inode->i_atime.tv_nsec = eufs_iread_atime_nsec(pi);

	inode->i_size = eufs_iread_size(pi);

	blocks = 0;
	switch (mode & S_IFMT) {
	case S_IFDIR:
		vi->i_dotdot = eufs_iread_dotdot(pi);
		vi->i_volatile_root = NULL;
		vi->i_volatile_height = 0;
		blocks = 1;
		break;
	case S_IFREG:
		vi->i_volatile_tree_blocks = eufs_iread_tree_blocks(pi);
		eufs_alloc_batch_init(&vi->page_batch, 2);
		fallthrough;
	case S_IFLNK:
		encoded_root = eufs_iread_root(pi);
		vi->i_volatile_root = o2p(sb, root_ptr(encoded_root));
		vi->i_volatile_height = root_height(encoded_root);

		if (S_ISREG(mode))
			/* These blocks contain hole as well */
			blocks = vi->i_volatile_tree_blocks;
		else
			blocks = 1;
		break;
	case S_IFCHR:
	case S_IFBLK:
		inode->i_rdev = eufs_iread_rdev(pi);
		break;
	}

	/* check if the inode is active. */
	if (inode->i_nlink == 0) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = blocks << (inode->i_blkbits - 9);

	inode->i_mapping->a_ops = &eufs_aops;

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &eufs_file_inode_operations;
		inode->i_fop = &eufs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &eufs_dir_inode_operations;
		inode->i_fop = &eufs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &eufs_symlink_inode_operations;
		break;
	default:
		inode->i_size = 0;
		inode->i_op = &eufs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, eufs_iread_rdev(pi));
		break;
	}

	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

void eufs_sync_pinode(struct inode *inode, struct eufs_inode *pi, bool evict)
{
	struct eufs_inode_info *vi = EUFS_I(inode);
	struct super_block *sb = inode->i_sb;
	u64 pi_root_o;
	u64 pi_tree_blocks;
	struct eufs_inode __pmem *twin_pi = EUFS_TWIN_PI(pi);
	bool new = false;

	BUG_ON(!pi);
	BUG_ON(!inode);
	BUG_ON(!evict && !inode_is_locked(inode));

	if (!inode->i_nlink)
		return;

	/* let pi be the latest pinode */
	if (!pi->i_fresh || !twin_pi->i_fresh)
		new = true;

	if (pi->i_fresh < twin_pi->i_fresh || (new && (pi > twin_pi))) {
		struct eufs_inode *t = pi;

		pi = twin_pi;
		twin_pi = t;
	}

	pi_root_o = eufs_iread_root(pi);

	pi_tree_blocks = eufs_iread_tree_blocks(pi);
	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		break;
	case S_IFREG:
		BUG_ON(!evict && !inode_is_locked(inode));

		if (vi->i_volatile_tree_blocks > pi_tree_blocks) {
			/* For a newly created pi, this is always true */
			void __pmem *root = vi->i_volatile_root;
			int height = vi->i_volatile_height;

			BUG_ON(root_height(pi_root_o) > vi->i_volatile_height);

			eufs_alloc_batch_persist_reset(sb, &vi->page_batch);

			eufs_persist_btree(
				sb, root, height, pi_tree_blocks * PAGE_SIZE,
				vi->i_volatile_tree_blocks * PAGE_SIZE);

		} else {
			eufs_alloc_batch_persist_reset(sb, &vi->page_batch);
		}
		pi_root_o = encode_root(p2o(sb, vi->i_volatile_root),
					vi->i_volatile_height);
		pi_tree_blocks = vi->i_volatile_tree_blocks;
		break;
	case S_IFLNK:
		/* Never change */
		break;
	case S_IFCHR:
	case S_IFBLK:
		pi_root_o = ((u64)inode->i_rdev << 32) | inode->i_rdev;
		break;
	}
	if (!evict && !inode_is_locked(inode)) {
		eufs_info("! inode=%px\n", inode);
		BUG();
	}
	BUG_ON(!evict && !inode_is_locked(inode));

	/* update to new data */
	eufs_iwrite_flags(twin_pi, eufs_get_inode_flags(inode, pi));
	eufs_iwrite_mode(twin_pi, inode->i_mode);
	eufs_iwrite_version(twin_pi, 1);
	eufs_iwrite_ctime(twin_pi, inode->i_ctime.tv_sec);
	eufs_iwrite_ctime_nsec(twin_pi, inode->i_ctime.tv_nsec);
	eufs_iwrite_uid(twin_pi, i_uid_read(inode));
	eufs_iwrite_gid(twin_pi, i_gid_read(inode));
	eufs_iwrite_dotdot(twin_pi, vi->i_dotdot);
	eufs_iwrite_ext(twin_pi, vi->i_ext); /* no ext here */

	eufs_iwrite_generation(twin_pi, inode->i_generation);
	eufs_iwrite_nlink(twin_pi, inode->i_nlink);
	eufs_iwrite_mtime(twin_pi, inode->i_mtime.tv_sec);
	eufs_iwrite_atime(twin_pi, inode->i_atime.tv_sec);
	eufs_iwrite_mtime_nsec(twin_pi, inode->i_mtime.tv_nsec);
	eufs_iwrite_atime_nsec(twin_pi, inode->i_atime.tv_nsec);
	eufs_iwrite_root(twin_pi, pi_root_o);
	eufs_iwrite_size(twin_pi, inode->i_size);
	eufs_iwrite_tree_blocks(twin_pi, pi_tree_blocks);

	eufs_flush_cacheline(twin_pi);
	if (new) {
		/* Handle new */
		pi->i_fresh = 1;
		eufs_flush_cacheline(&pi->i_fresh);
		twin_pi->i_fresh = 2;
	} else if (unlikely(pi->i_fresh == U16_MAX)) {
		/* Handle overflow */
		/* Invarient: pi should always be the freshest */
		/* freshness 0 is reserved for new inodes */
		twin_pi->i_fresh = 1;
		eufs_flush_cacheline(&twin_pi->i_fresh);
		pi->i_fresh = 2;
		eufs_flush_cacheline(&pi->i_fresh);
		twin_pi->i_fresh = 3;
	} else {
		/* Normal case */
		twin_pi->i_fresh = pi->i_fresh + 1;
	}
	/* This flush also flushes the bottom half of the twin_pi */
	eufs_flush_cacheline(&twin_pi->i_fresh);
}

struct inode *eufs_iget(struct super_block *sb, struct eufs_inode *pi)
{
	struct inode *inode;
	int err;

	WARN_ON(!EUFS_IS_HEAD_PI(pi));
	inode = iget_locked(sb, eufs_pi2ino(sb, pi));
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = eufs_read_pinode(inode, pi);
	if (unlikely(err))
		goto fail;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

void eufs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct eufs_inode *pi = EUFS_PI(inode);
	struct eufs_inode *fresh_pi;
	struct eufs_inode_info *vi = EUFS_I(inode);

	eufs_dbg(
		"Evicting: inode=%px, pi=%px i_nlink=%u inode->i_size=%lld blocks=%lld\n",
		inode, pi, inode->i_nlink, inode->i_size,
		vi->i_volatile_tree_blocks);

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		/* Free the inode */
		fresh_pi = EUFS_FRESH_PI(pi);

		switch (inode->i_mode & S_IFMT) {
		case S_IFDIR:
			/* Directory can be removed only if the dict is empty */
			NV_ASSERT(!vi->i_volatile_root);
			nv_free(sb, o2p(sb, eufs_iread_dict(fresh_pi)));
			break;
		case S_IFLNK:
			NV_ASSERT(!vi->i_volatile_root);
			nv_free(sb, o2p(sb, eufs_iread_root(fresh_pi)));
			break;
		case S_IFREG:
			/* Traverse the B-tree! */
			eufs_free_btree(sb, vi->i_volatile_root,
					 vi->i_volatile_height,
					 vi->i_volatile_tree_blocks);
			break;
		default:
			break;
		}
		eufs_iwrite_nlink(fresh_pi, 0);
		eufs_iwrite_mode(fresh_pi, 0);
		eufs_flush_cacheline(fresh_pi);
		WARN_ON(!EUFS_IS_HEAD_PI(pi));
		nv_free(sb, pi);
	} else if (!is_bad_inode(inode)) {
		eufs_sync_pinode(inode, pi, true);
	}
	if (!is_bad_inode(inode) && vi->i_volatile_dict) {
		eufs_free_page(vi->i_volatile_dict);
		vi->i_volatile_dict = NULL;
	}
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	return;
}

int eufs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	inode_lock(inode);
	eufs_sync_pinode(inode, EUFS_PI(inode), false);
	inode_unlock(inode);
	return 0;
}

int eufs_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct eufs_inode *pi = EUFS_PI(inode);
	int ret;
	unsigned int ia_valid = attr->ia_valid;

	if (!pi)
		return -EACCES;

	ret = setattr_prepare(dentry, attr);
	if (ret)
		return ret;

	if ((ia_valid & ATTR_SIZE) && attr->ia_size != inode->i_size) {
		struct eufs_inode_info *vi = EUFS_I(inode);
		bool shrink;

		eufs_dbg(
			"notify change (size): vi=%px inode=%px, pi=%px (%lld), %lld to %lld\n",
			vi, inode, pi, eufs_iread_size(pi), inode->i_size,
			attr->ia_size);

		down_write(&vi->mmap_rwsem);
		shrink = attr->ia_size < inode->i_size;

		if (attr->ia_size > inode->i_size) {
			unsigned long num_blocks =
				DIV_ROUND_UP(attr->ia_size, PAGE_SIZE);
			/* make sure the file has enough pages allocated */
			ret = eufs_extend_btree(inode, num_blocks);
			if (ret < 0) {
				up_write(&vi->mmap_rwsem);
				return ret;
			}

			/* zeroing the extended range [i_size, ia_size) */
			eufs_inode_zero_range(inode, inode->i_size,
					       attr->ia_size);
		}

		truncate_setsize(inode, attr->ia_size);

		attr->ia_valid = ia_valid | (ATTR_CTIME | ATTR_MTIME);

		if (shrink)
			eufs_shrink_btree(inode);

		/* zeroing the part beyond the new EOF [ia_size, PAGE_ALIGN(ia_size)) */
		eufs_inode_zero_range(inode, attr->ia_size,
				       PAGE_ALIGN(attr->ia_size));

		up_write(&vi->mmap_rwsem);
	}
	eufs_dbg("notify change: inode=%px, pi=%px, imode=%x to imode=%x\n",
		  inode, pi, inode->i_mode, attr->ia_mode);
	setattr_copy(inode, attr);

	request_persistence(inode);

	return 0;
}

int eufs_file_getattr(const struct path *path, struct kstat *stat,
		       u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct eufs_inode *pi = EUFS_FRESH_PI(EUFS_PI(inode));
	unsigned int flags = eufs_get_inode_flags(inode, pi);

	flags &= FS_FL_USER_VISIBLE;
	if (flags & FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;

	stat->attributes_mask |= (STATX_ATTR_APPEND | STATX_ATTR_IMMUTABLE);

	generic_fillattr(inode, stat);
	return 0;
}

/* Transfer FS_*_FL to S_* and write to inode */
void eufs_set_inode_flags(struct inode *inode, unsigned int flags)
{
	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	inode->i_flags |= S_DAX;
}

/* Get S_* from inode and transfer to FS_*_FL */
unsigned int eufs_get_inode_flags(struct inode *inode, struct eufs_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int eufs_flags = eufs_iread_flags(EUFS_FRESH_PI(pi));

	eufs_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		eufs_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		eufs_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		eufs_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		eufs_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		eufs_flags |= FS_DIRSYNC_FL;

	return eufs_flags;
}

static int eufs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct dax_device *dax_dev = NULL;
	int ret = 0;

	/* Only for regular file */
	if (!S_ISREG(inode->i_mode))
		return -EIO;

	dax_dev = EUFS_SB(inode->i_sb)->s_dax_dev;
	ret = dax_writeback_mapping_range(mapping, dax_dev, wbc);

	return ret;
}

const struct address_space_operations eufs_aops = {
	.writepages = eufs_writepages,
};

struct inode *pre_inodes_get(struct dentry *dentry, struct inode *dir,
			     umode_t mode, bool special, dev_t rdev)
{
	struct inode *inode = NULL;
	struct eufs_inode __pmem *pi;
	struct super_block *sb = dir->i_sb;
	struct eufs_sb_info *sbi = EUFS_SB(sb);
	struct eufs_inode __pmem *dir_pi = EUFS_FRESH_PI(EUFS_PI(dir));
	struct eufs_inode_info *vi;
	void *pre_page = NULL;
	int err;
	u64 blocks;

	NV_ASSERT(dir_pi);

	inode = new_inode(sb);
	if (IS_ERR(inode))
		return inode;

	vi = EUFS_I(inode);
	vi->i_volatile_dict = NULL;

	BUG_ON(inode->i_nlink != 1);
	inode->i_size = 0;
	vi->i_ext = 0;
	vi->i_dotdot = 0;
	vi->i_version = 1;

	pi = eufs_malloc_pinode(sb);
	if (!pi)
		goto no_space_err;

	pi->i_fresh = 0;
	EUFS_TWIN_PI(pi)->i_fresh = 0;

	blocks = 0;
	if (S_ISREG(mode)) {
		pre_page = eufs_malloc_file_data(sb);
		if (!pre_page)
			goto no_space_err;
		blocks = 1;
	} else if (S_ISLNK(mode)) {
		pre_page = eufs_zalloc_symlink(sb);
		if (!pre_page)
			goto no_space_err;
		blocks = 1;
	} else if (S_ISDIR(mode)) {
		pre_page = eufs_zalloc_htable(sb);
		if (!pre_page)
			goto no_space_err;
		blocks = 1;
	}
	inode->i_blocks = blocks << (inode->i_blkbits - 9);

	eufs_dbg("bind inode(%px) ->pi(%px)->i_ino=0x%lx, vi->trans=%d\n",
		  inode, pi, eufs_pi2ino(sb, pi), vi->i_lock_transferred);
	inode->i_ino = eufs_pi2ino(sb, pi);

	inode_init_owner(inode, dir, mode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_generation = atomic_add_return(1, &sbi->next_generation);

	if (special)
		init_special_inode(inode, mode, rdev);

	eufs_iwrite_root(pi, EUFS_POISON_VALUE);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		eufs_iwrite_rdev(pi, inode->i_rdev);
	} else {
		vi->i_volatile_height = 0;
		if (S_ISREG(inode->i_mode)) {
			vi->i_volatile_tree_blocks = 1;
			eufs_iwrite_tree_blocks(pi, 0);
			vi->i_volatile_root = pre_page;
			/* 0th block is treated as a hole until allocated. */
			vi->hole_at_sta = true;
			eufs_iwrite_root(
				pi, encode_root(p2o(sb, vi->i_volatile_root),
						vi->i_volatile_height));
			eufs_alloc_batch_init(&vi->page_batch, 2);
			eufs_alloc_batch_add(sb, &vi->page_batch,
					      vi->i_volatile_root);

		} else if (S_ISDIR(inode->i_mode)) {
			vi->i_volatile_dict = NULL;
			eufs_iwrite_dict(pi, p2o(sb, pre_page));
			/* allocation persisted in do_dep_diradd */
		} else if (S_ISLNK(inode->i_mode)) {
			eufs_iwrite_root(pi, p2o(sb, pre_page));
			/* allocation persisted in do_dep_diradd */
		}
	}

	eufs_iwrite_mode(pi, inode->i_mode);
	eufs_iwrite_size(pi, 0);

	eufs_dbg(
		"alloc inode=%px pi=%px pi->root=0x%llx pi->i_mode=0%o on cpu %d\n",
		inode, pi, eufs_iread_root(pi), eufs_iread_mode(pi),
		smp_processor_id());

	eufs_iwrite_flags(pi, dir_pi->i_flags);
	eufs_set_inode_flags(inode, eufs_iread_flags(pi));

	err = insert_inode_locked(inode);
	if (err) {
		eufs_err(sb, "eufs_new_inode failed ino 0x%lx err %d\n",
			  inode->i_ino, err);
		goto out;
	}

	return inode;

no_space_err:
	err = -ENOSPC;
out:
	if (pre_page)
		nv_free(sb, pre_page);
	if (pi)
		nv_free(sb, pi);
	if (inode) {
		make_bad_inode(inode);
		inode->i_ino = 0;
		iput(inode);
	}
	return ERR_PTR(err);
}

void eufs_inode_size_write(struct inode *inode, loff_t new_size)
{
	i_size_write(inode, new_size);
	request_persistence(inode);
}
