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
#include <linux/pagemap.h>
#include <linux/crc32c.h>
#include "euler.h"
#include "dht.h"
#include "dep.h"
#include "lock.h"

/*
 * If sbi->s_draining is set, do fsync after each namei syscall! This is much
 * better than lock transfer for volatility quota.
 */
static void sync_on_draining(struct inode *dir, struct inode *inode)
{
	struct eufs_sb_info *sbi = EUFS_SB(dir->i_sb);

	if (likely(!sbi->s_draining))
		return;

	/* fsync the inodes to reduce the number of dirty inodes */
	fsync_on_draining(dir, inode);
}

static __always_inline void
eufs_trace_newfile(const char *prompt, struct inode *dir, struct inode *inode,
		   struct eufs_inode *pi, struct nv_dict_entry *de)
{
	eufs_dbg("%s (%s): inode=%px pi=%px pi->root=%llx pi->mode=0%o de=%px de->len=%lld de->name=%6s de->nextname=%llx inode->nlink=%d pi->nlink=%d de->volatile_next=%llx de->next=%llx\n",
		 __func__, prompt, inode, pi, eufs_iread_root(pi),
		 eufs_iread_mode(pi), de, HASHLEN_LEN(de->hv), de->name,
		 de->nextname, inode->i_nlink, pi->i_nlink, de->volatile_next,
		 de->next);

	BUG_ON(inode->i_mode != pi->i_mode);
}

static __always_inline void eufs_trace_delfile(const char *prompt,
					       struct inode *dir,
					       struct inode *inode,
					       struct eufs_inode *pi)
{
	eufs_dbg("%s (%s): inode=%px pi=%px pi->root=%llx pi->mode=0%o inode->i_nlink=%d pi->i_nlink=%d\n",
		 __func__, prompt, inode, pi, eufs_iread_root(pi),
		 eufs_iread_mode(pi), inode->i_nlink, eufs_iread_nlink(pi));
	/*
	 * because inode is locked by unlink/link, so the increment/decrement
	 * of nlink should be in order and its max value is (EUFS_LINK_MAX - 1)
	 * after unlink.
	 */
	if ((inode->i_mode & S_IFMT) != S_IFDIR)
		WARN(inode->i_nlink >= EUFS_LINK_MAX,
		     "unexpected nlink %d for inode 0x%lx\n", inode->i_nlink,
		     inode->i_ino);
}

static __always_inline struct nv_dict_entry *
nv_dict_add_wrapper(struct inode *dir, u64 **nv_header, struct eufs_inode *pi,
		    hashlen_t hv, const char *name)
{
	struct eufs_inode_info *vi = EUFS_I(dir);

	NV_ASSERT(pi);
	if (!vi->i_volatile_dict)
		vi->i_volatile_dict = eufs_zalloc_page();

	/* insert into parent dir hash table */
	return nv_dict_add(dir, nv_header, hv, name, pi);
}

static __always_inline struct nv_dict_entry *
nv_dict_del_wrapper(struct inode *dir, struct nv_dict_entry **prevde,
		    u64 **nv_header, hashlen_t hv, const char *name)
{
	struct eufs_inode_info *vi = EUFS_I(dir);
	/* Alloc for dict if necessary */
	if (!vi->i_volatile_dict)
		vi->i_volatile_dict = eufs_zalloc_page();

	/* insert into parent dir hash table */
	return nv_dict_delete(dir, prevde, nv_header, hv, name);
}

/*
 * Methods themselves.
 */
static struct dentry *eufs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct inode *inode = NULL;
	struct nv_dict_entry *de;
	const char *name;
	u64 hv;

	if (dentry->d_name.len > EUFS_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	hv = hash(dentry->d_name.name, dentry->d_name.len);
	name = dentry->d_name.name;
	de = nv_dict_find(dir, hv, name);
	if (!de)
		goto not_found;

	inode = eufs_iget(dir->i_sb, s2p(dir->i_sb, de->inode));
	if (inode == ERR_PTR(-ESTALE)) {
		eufs_err(dir->i_sb, "deleted inode referenced: 0x%lx",
			 inode->i_ino);
		return ERR_PTR(-EIO);
	}
not_found:

	if (inode)
		BUG_ON(atomic_read(&inode->i_count) < 1);
	return d_splice_alias(inode, dentry);
}

static int add_pinode(struct inode *dir, struct dentry *dentry,
		      struct inode *inode, bool need_unlock_inode)
{
	/* Name must be checked before this is invoked. */
	struct eufs_inode_info *dir_vi = EUFS_I(dir);
	struct eufs_inode *pi;
	const char *name;
	struct nv_dict_entry *de;
	u64 *nv_header;
	u64 hv;
	struct dep_node *dep;
	int err;

	dep = eufs_alloc_dep_node();
	if (!dep)
		return -ENOMEM;

	if (need_unlock_inode)
		eufs_inode_mark_lock_transferable(inode);

	/* Add to dict */
	pi = EUFS_PI(inode);
	name = dentry->d_name.name;
	hv = hash(name, dentry->d_name.len);
	de = nv_dict_add_wrapper(dir, &nv_header, pi, hv, name);
	if (IS_ERR(de)) {
		err = PTR_ERR(de);
		goto err_out;
	}

	/* One more dentry */
	dir->i_size++;
	eufs_dbg("diradd +> %lld of %px 0x%lx\n", dir->i_size, dir, dir->i_ino);

	/* Update dir time */
	dir->i_ctime = dir->i_mtime = current_time(dir);

	dep_new_insert(dep, dir, DEP_DIRADD, NULL, nv_header, de, inode,
		       dir_vi->i_next_dep_seq);

	if (need_unlock_inode)
		eufs_inode_wait_lock_transfer_done(inode);

	dir_vi->i_next_dep_seq++;

	return 0;

err_out:
	if (need_unlock_inode)
		eufs_inode_wait_lock_transfer_done(inode);
	eufs_free_dep_node(dep);
	return err;
}

static __always_inline int del_pinode(struct inode *dir, struct dentry *dentry,
				      bool is_dir)
{
	struct eufs_inode_info *dir_vi = EUFS_I(dir);
	struct inode *inode = dentry->d_inode;
	struct nv_dict_entry *de, *prevde;
	u64 *nv_header;
	const char *name;
	u64 hv;
	struct dep_node *dep;
	struct eufs_inode *pi;
	int err;

	dep = eufs_alloc_dep_node();
	if (!dep)
		return -ENOMEM;

	eufs_inode_mark_lock_transferable(inode);

	/* Remove from parent dir hash table */
	name = dentry->d_name.name;
	hv = hash(name, dentry->d_name.len);
	de = nv_dict_del_wrapper(dir, &prevde, &nv_header, hv, name);
	if (unlikely(!de)) {
		err = -ENOENT;
		goto err_out;
	}

	/* Drop one dentry */
	dir->i_size--;
	eufs_dbg("dirdel -> %lld of %px 0x%lx\n", dir->i_size, dir, dir->i_ino);

	/* Update parent dir time */
	dir->i_ctime = dir->i_mtime = current_time(dir);

	/* Update inode ctime and link */
	inode->i_ctime = dir->i_ctime;
	if (is_dir) {
		/* Update nlink and ctime for the removed inode */
		WARN_ON(inode->i_nlink != 2);
		clear_nlink(inode);
	} else if (inode->i_nlink) {
		drop_nlink(inode);
	} else {
		pi = EUFS_PI(inode);
		eufs_info("!%s!: inode=%p, inode->i_nlink=%d inode->i_mode=0%o pi=%p pi->i_nlink=%d pi->i_mode=0%o\n",
			  __func__, inode, inode->i_nlink, inode->i_mode, pi,
			  eufs_iread_nlink(pi), eufs_iread_mode(pi));
		BUG();
	}

	dep_new_insert(dep, dir, DEP_DIRREM, prevde, nv_header, de, inode,
		       dir_vi->i_next_dep_seq);

	eufs_inode_wait_lock_transfer_done(inode);

	dir_vi->i_next_dep_seq++;

	return 0;

err_out:
	eufs_inode_wait_lock_transfer_done(inode);
	eufs_free_dep_node(dep);
	return err;
}

static void eufs_free_new_inode(struct inode *inode)
{
	clear_nlink(inode);
	remove_inode_hash(inode);
	unlock_new_inode(inode);
	iput(inode);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int eufs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	struct inode *inode;
	int err;

	/* name checks */
	if (unlikely(!dentry->d_name.len))
		return -EINVAL;
	if (unlikely(dentry->d_name.len > EUFS_MAX_NAME_LEN))
		return -ENAMETOOLONG;

	inode = pre_inodes_get(dentry, dir, mode, false, 0);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = add_pinode(dir, dentry, inode, false);
	if (err) {
		eufs_free_new_inode(inode);
		return err;
	}

	inode->i_op = &eufs_file_inode_operations;
	inode->i_mapping->a_ops = &eufs_aops;
	inode->i_fop = &eufs_file_operations;

	eufs_trace_newfile("!create!", dir, inode, EUFS_PI(inode), NULL);

	EUFS_I(inode)->i_is_dirty = true;
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	sync_on_draining(dir, NULL);

	return 0;
}

static int eufs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		      dev_t rdev)
{
	struct inode *inode;
	int err;

	if (unlikely(!dentry->d_name.len))
		return -EINVAL;
	if (unlikely(dentry->d_name.len > EUFS_MAX_NAME_LEN))
		return -ENAMETOOLONG;

	inode = pre_inodes_get(dentry, dir, mode, true, rdev);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = add_pinode(dir, dentry, inode, false);
	if (err) {
		eufs_free_new_inode(inode);
		return err;
	}

	inode->i_op = &eufs_special_inode_operations;

	eufs_trace_newfile("!mknode!", dir, inode, EUFS_PI(inode), NULL);

	EUFS_I(inode)->i_is_dirty = true;
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	sync_on_draining(dir, NULL);

	return 0;
}

static int eufs_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct inode *inode = NULL;
	struct eufs_inode *pi;
	u32 len = strlen(symname);
	void *pi_root;
	int err;

	/* name checks */
	if (unlikely(!dentry->d_name.len))
		return -EINVAL;
	if (unlikely(dentry->d_name.len > EUFS_MAX_NAME_LEN))
		return -ENAMETOOLONG;
	if (unlikely(len > EUFS_MAX_SYMLINK_LEN))
		return -ENAMETOOLONG;

	/* alloc vfs inode and xxfs inode */
	inode = pre_inodes_get(dentry, dir, S_IFLNK | S_IRWXUGO, false, 0);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	pi = EUFS_FRESH_PI(EUFS_PI(inode));

	pi_root = o2p(dir->i_sb, eufs_iread_root(pi));

	/* copy the symname */
	*((u64 *)pi_root) = hash(symname, len);
	memcpy(((char *)pi_root) + sizeof(u64), symname, len);
	BUG_ON(!eufs_access_ok(inode->i_sb, pi_root, PAGE_SIZE));

	/* update the size */
	inode->i_size = len;

	err = add_pinode(dir, dentry, inode, false);
	if (err) {
		eufs_free_new_inode(inode);
		return err;
	}

	inode->i_op = &eufs_symlink_inode_operations;
	inode->i_mapping->a_ops = &eufs_aops;

	eufs_trace_newfile("!symlink!", dir, inode, pi, NULL);

	EUFS_I(inode)->i_is_dirty = true;
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	sync_on_draining(dir, NULL);

	return 0;
}

static int eufs_link(struct dentry *dest_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct inode *inode = dest_dentry->d_inode;
	struct eufs_inode *pi = EUFS_PI(inode);
	struct nv_dict_entry *de;
	int err;

	/* name checks */
	if (unlikely(!dentry->d_name.len))
		return -EINVAL;
	if (unlikely(dentry->d_name.len > EUFS_MAX_NAME_LEN))
		return -ENAMETOOLONG;
	/* nlink check */
	if (unlikely(inode->i_nlink >= EUFS_LINK_MAX))
		return -EMLINK;

	ihold(inode);

	err = add_pinode(dir, dentry, inode, true);
	if (unlikely(err)) {
		iput(inode);
		return err;
	}

	/* update inode ctime */
	inode->i_ctime = current_time(inode);
	inc_nlink(inode);

	EUFS_I(inode)->i_is_dirty = true;
	d_instantiate(dentry, inode);

	eufs_trace_newfile("!link!", dir, inode, pi, de);

	/* inode_lock() has been acquired */
	sync_on_draining(dir, inode);

	return 0;
}

static int eufs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int ret;

	ret = del_pinode(dir, dentry, false);
	if (ret < 0)
		return ret;

	eufs_trace_delfile("!unlink!", dir, inode, EUFS_PI(inode));

	EUFS_I(inode)->i_is_dirty = true;

	sync_on_draining(dir, inode);

	return 0;
}

/* NOTE: do not count the link for directories */
static int eufs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct eufs_inode *dir_pi = EUFS_PI(dir);
	struct eufs_inode_info *vi;
	struct eufs_inode *pi;
	int err;

	/* name checks */
	if (unlikely(!dentry->d_name.len))
		return -EINVAL;

	if (unlikely(dentry->d_name.len > EUFS_MAX_NAME_LEN))
		return -ENAMETOOLONG;

	/* alloc vfs inode and xxfs inode */
	inode = pre_inodes_get(dentry, dir, S_IFDIR | mode, false, 0);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &eufs_dir_inode_operations;
	inode->i_fop = &eufs_dir_operations;
	inode->i_mapping->a_ops = &eufs_aops;
	/* We have to mimic the nlink number */
	inc_nlink(inode);

	/* alloc & init dir hash table for new inode */
	pi = EUFS_FRESH_PI(EUFS_PI(inode));
	vi = EUFS_I(inode);
	vi->i_dotdot = p2o(dir->i_sb, dir_pi);
	pi->i_dotdot = cpu_to_le64(vi->i_dotdot);

	err = add_pinode(dir, dentry, inode, false);
	if (err) {
		eufs_free_new_inode(inode);
		return err;
	}

	/* We have to mimic the nlink number */
	inc_nlink(dir);

	eufs_trace_newfile("!mkdir!", dir, inode, pi, NULL);

	vi->i_is_dirty = true;
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	sync_on_draining(dir, NULL);

	PRINT_PINODE(pi, "FINAL-CHECK: ");

	BUG_ON(atomic_read(&dir->i_count) < 1);
	if (inode)
		BUG_ON(atomic_read(&inode->i_count) < 1);

	return 0;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static __always_inline int eufs_empty_dir(struct inode *inode)
{
	return !inode->i_size;
}

static int eufs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int ret;

	/* checks before rmdir */
	if (!inode)
		return -ENOENT;
	if (!eufs_empty_dir(inode))
		return -ENOTEMPTY;

	ret = del_pinode(dir, dentry, true);
	if (ret < 0)
		return ret;

	/* We have to mimic the nlink number */
	drop_nlink(dir);

	EUFS_I(inode)->i_is_dirty = true;

	eufs_trace_delfile("!rmdir!", dir, inode, EUFS_PI(inode));

	sync_on_draining(dir, inode);

	return 0;
}

/*
 * Precondition: old_dentry exists in the old directory
 */
static int eufs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	/*
	 * TODO: need to lock old_inode
	 * If old_inode is a directory, its inode lock will
	 * not be acquired, so the offset of newest physical node
	 * may be changed during the rename procedure.
	 */
	struct eufs_inode *pi = EUFS_FRESH_PI(EUFS_PI(old_inode));
	struct eufs_inode *old_dir_pi;
	struct eufs_inode *new_dir_pi;
	struct inode *locked_inodes[EUFS_INODE_CNT_IN_RENAME] = {
		old_dir, new_dir, old_inode, new_inode
	};
	struct super_block *sb = old_inode->i_sb;

	struct nv_dict_entry *new_de;
	u64 *new_dir_nv_header;
	struct nv_dict_entry *old_de, *old_prevde;
	u64 *old_dir_nv_header;
	bool in_same_dir = (old_dir == new_dir);

	const char *name;
	struct eufs_renamej *renamej;
	u64 old_hv, new_hv;
	struct nv_dict_entry **vde;
	int cpu;
	void *buffer[16];

	NV_ASSERT(pi->i_mode == old_inode->i_mode);

	if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EOPNOTSUPP;

	/* checks */
	if (new_inode) {
		eufs_dbg(
			"!new_inode=%px new_inode->i_count=%d new_dentry->d_lockref.count=%d\n",
			new_inode, atomic_read(&new_inode->i_count),
			new_dentry->d_lockref.count);
		if (S_ISDIR(new_inode->i_mode) && !eufs_empty_dir(new_inode))
			return -ENOTEMPTY;
		eufs_dbg("rename overwrites! newinode=%px newpi=%px newinode->i_mode=0%o, newinode->root=%px oldinode=%px oldpi=%px oldinode->i_mode=0%o, oldinode->root=%px\n",
			 new_inode, EUFS_PI(new_inode), new_inode->i_mode,
			 EUFS_I(new_inode)->i_volatile_root, old_inode,
			 EUFS_PI(old_inode), old_inode->i_mode,
			 EUFS_I(old_inode)->i_volatile_root);
		BUG_ON(new_inode->i_mode != EUFS_PI(new_inode)->i_mode);
	}
	eufs_dbg("%s: rename %s to %s before fsync, old_pi=%px new_pi=%px\n",
		 __func__, old_dentry->d_name.name, new_dentry->d_name.name,
		 EUFS_PI(old_inode),
		 new_inode ? EUFS_PI(new_inode) : (void *)-1);

	eufs_dbg("old: dir=%px inode=%px; new: dir=%px inode=%px\n", old_dir,
		 old_inode, new_dir, new_inode);

	if (S_ISDIR(old_inode->i_mode))
		locked_inodes[2] = NULL;
	if (locked_inodes[0] == locked_inodes[1])
		locked_inodes[1] = NULL;

	if (locked_inodes[0])
		BUG_ON(!inode_is_locked(locked_inodes[0]));
	if (locked_inodes[1])
		BUG_ON(!inode_is_locked(locked_inodes[1]));
	if (locked_inodes[2])
		BUG_ON(!inode_is_locked(locked_inodes[2]));
	if (locked_inodes[3])
		BUG_ON(!inode_is_locked(locked_inodes[3]));

	fsync_rename_inodes(old_dir, new_dir, locked_inodes);

	/*
	 * get the newer inodes after fsync_rename_inodes() completes
	 * which may update the offset of the newer inodes
	 */
	old_dir_pi = EUFS_FRESH_PI(EUFS_PI(old_dir));
	new_dir_pi = EUFS_FRESH_PI(EUFS_PI(new_dir));

	/* -------------- get new dentry info -------------- */
	/* get new filename */
	new_hv = hash(new_dentry->d_name.name, new_dentry->d_name.len);
	name = new_dentry->d_name.name;
	eufs_dbg("%s: rename %s to %s\n", __func__, old_dentry->d_name.name,
		 new_dentry->d_name.name);

	/* -------------- insertion ---------------- */
	/* insert into parent dir hash table */
	if (new_inode) {
		new_de = nv_dict_find(new_dir, new_hv, name);
		if (!new_de)
			return -ENOENT;
		/* Delay the actual write */
		BUG_ON(!new_inode->i_nlink);
		ihold(new_inode);
		/* We have new_inode in hand */
		if (S_ISDIR(new_inode->i_mode)) {
			WARN_ON(new_inode->i_nlink != 2);
			clear_nlink(new_inode);
		} else {
			drop_nlink(new_inode);
		}
		new_dir_nv_header = NULL;
	} else {
		new_de = nv_dict_add_wrapper(new_dir, &new_dir_nv_header,
					     EUFS_HEAD_PI(pi), new_hv, name);
		if (IS_ERR(new_de))
			return PTR_ERR(new_de);
		if (unlikely(!new_de))
			return -EEXIST;
		/* We have no dep in rename. Just release the header lock */
		inode_header_unlock(new_dir);

		if (!in_same_dir) {
			new_dir->i_size++;
			if (S_ISDIR(old_inode->i_mode))
				inc_nlink(new_dir);
		}
		eufs_dbg("rename diradd +> %lld of %px 0x%lx\n",
			 new_dir->i_size, new_dir, new_dir->i_ino);
	}
	/* update dir time */
	new_dir->i_ctime = new_dir->i_mtime = current_time(new_dir);

	/* -------------- get old dentry info -------------- */
	/* get old filename */
	old_hv = hash(old_dentry->d_name.name, old_dentry->d_name.len);
	name = old_dentry->d_name.name;
	if (!name) {
		BUG();
		return -ENOENT;
	}

	/* -------------- removal ---------------- */
	old_de = nv_dict_del_wrapper(old_dir, &old_prevde, &old_dir_nv_header,
				     old_hv, name);
	if (unlikely(!old_de)) {
		BUG();
		return -ENOENT;
	}
	/* We have no dep in rename. Just release the header lock */
	inode_header_unlock(old_dir);

	if (!in_same_dir || new_inode) {
		old_dir->i_size--;
		if (S_ISDIR(old_inode->i_mode))
			drop_nlink(old_dir);
	}
	if (old_dir != new_dir)
		old_dir->i_ctime = old_dir->i_mtime = new_dir->i_ctime;

	eufs_dbg("rename dirdel -> %lld of %px 0x%lx\n", old_dir->i_size,
		 old_dir, old_dir->i_ino);

	/* old_inode may NOT be locked ? */
	/* update ctime of source inode */
	old_inode->i_ctime = new_dir->i_ctime;
	if (!in_same_dir && S_ISDIR(old_inode->i_mode)) {
		/* update parent pointer of source inode */
		struct eufs_inode_info *vi = EUFS_I(old_inode);

		vi->i_dotdot = p2o(sb, EUFS_HEAD_PI(new_dir_pi));
	}

	NV_ASSERT(new_de->inode == old_de->inode);
	NV_ASSERT(eufs_valid_inode_in_de(old_de, old_inode));
	NV_ASSERT(old_inode->i_mode ==
		  eufs_iread_mode(EUFS_FRESH_PI(
			  (struct eufs_inode *)(s2p(sb, old_de->inode)))));

	if (!new_inode) {
		struct alloc_batch ab;

		ab.n_used = 0;
		ab.size = 16;
		ab.batch = buffer;

		eufs_alloc_batch_add(old_dir->i_sb, &ab, new_de);
		persist_name(old_dir->i_sb, new_de, &ab);
		eufs_dentry_clr_not_persist_flag(new_de);
		persist_dentry(new_de);

		eufs_alloc_batch_persist_reset(old_dir->i_sb, &ab);
	}

	cpu = get_cpu();
	/* RenameJ is redo log */
	renamej = eufs_get_renamej(old_dir->i_sb, cpu);
	renamej->crc = 0;
	renamej->flags = 0;
	/* address to put old_de->next */
	renamej->addr_of_oldnext =
		p2s(sb, (old_prevde ? &old_prevde->next :
				      (void *)old_dir_nv_header));
	/* the value: old_de->next */
	renamej->oldnext =
		(old_prevde ?
			 old_de->next :
			 old_de->next == EUFS_DIR_EOC ?
			 NULL_VAL :
			 COMPOSE_DICT_HEAD_le64(sb, s2p(sb, old_de->next)));

	/* address to put new_de if necessary */
	renamej->addr_of_newde = p2s(sb, new_dir_nv_header);
	/* the value: new_de */
	renamej->composed_newde = COMPOSE_DICT_HEAD_le64(sb, new_de);
	/* the value: new_de->inode */
	renamej->newde_inode = p2s(sb, EUFS_HEAD_PI(pi));

	/* dir pi */
	renamej->old_dir_pi = p2s(sb, EUFS_HEAD_PI(old_dir_pi));
	renamej->new_dir_pi = p2s(sb, EUFS_HEAD_PI(new_dir_pi));
	/* inode attributes */
	renamej->time = cpu_to_le64(new_dir->i_ctime.tv_sec);
	renamej->time_nsec = cpu_to_le32(new_dir->i_ctime.tv_nsec);
	renamej->old_link = cpu_to_le16(old_dir->i_nlink);
	renamej->new_link = cpu_to_le16(new_dir->i_nlink);
	renamej->old_size = cpu_to_le32(old_dir->i_size);
	renamej->new_size = cpu_to_le32(new_dir->i_size);
	memset(renamej->pad, 0, sizeof(renamej->pad));

	renamej->flags = EUFS_RENAME_IN_ACTION;
	renamej->crc = cpu_to_le32(
		crc32c(EUFS_CRC_SEED, (char *)renamej + sizeof(renamej->crc),
		       sizeof(*renamej) - sizeof(renamej->crc)));

	eufs_flush_cacheline((char *)renamej + CACHELINE_SIZE);
	eufs_flush_cacheline(renamej);

	if (old_prevde) {
		old_prevde->next = old_de->next;
	} else {
		if (old_de->next == EUFS_DIR_EOC)
			*old_dir_nv_header = NULL_VAL;
		else
			*old_dir_nv_header = COMPOSE_DICT_HEAD_le64(
				sb, s2p(sb, old_de->next));
	}
	eufs_flush_cacheline(old_prevde ? (void *)&old_prevde->next :
					  (void *)old_dir_nv_header);

	vde = &(EUFS_I(old_dir)->i_volatile_dict->table[INDEX(old_hv)]);
	if (*vde) {
		bool vbool = (*vde == NULL || *vde == (void *)EUFS_DIR_EOC);
		bool pbool = (*old_dir_nv_header == NULL_VAL ||
			      *old_dir_nv_header == EUFS_DIR_EOC);
		BUG_ON(vbool != pbool);
		*vde = NULL;
	}

	if (new_inode) {
		new_de->inode = p2s(sb, EUFS_HEAD_PI(pi));
		eufs_flush_cacheline(new_de);
	} else {
		*new_dir_nv_header = COMPOSE_DICT_HEAD_le64(sb, new_de);
		eufs_flush_cacheline(new_dir_nv_header);
		vde = &EUFS_I(new_dir)->i_volatile_dict->table[INDEX(new_hv)];
		if (*vde) {
			bool vbool =
				(*vde == NULL || *vde == (void *)EUFS_DIR_EOC);
			bool pbool = (*new_dir_nv_header == NULL_VAL ||
				      *new_dir_nv_header == EUFS_DIR_EOC);
			BUG_ON(vbool != pbool);
			*vde = NULL;
		}
	}

	eufs_iwrite_size(old_dir_pi, old_dir->i_size);
	eufs_iwrite_nlink(old_dir_pi, old_dir->i_nlink);
	eufs_iwrite_ctime_mtime(old_dir_pi, old_dir);
	eufs_flush_pi(old_dir_pi);

	if (old_dir != new_dir) {
		eufs_iwrite_size(new_dir_pi, new_dir->i_size);
		eufs_iwrite_nlink(new_dir_pi, new_dir->i_nlink);
		eufs_iwrite_ctime_mtime(new_dir_pi, new_dir);
		eufs_flush_pi(new_dir_pi);
	}

	eufs_iwrite_ctime(pi, old_inode->i_ctime.tv_sec);
	eufs_iwrite_ctime_nsec(pi, old_inode->i_ctime.tv_nsec);
	if (!in_same_dir && S_ISDIR(old_inode->i_mode)) {
		struct eufs_inode_info *vi = EUFS_I(old_inode);

		eufs_iwrite_dotdot(pi, vi->i_dotdot);
	}
	eufs_flush_pi(pi);

	renamej->flags = 0;
	eufs_flush_cacheline(renamej);
	put_cpu();

	/* remove overwritten inode */
	if (new_inode)
		iput(new_inode);

	/* remove the source dentry */
	eufs_free_name(old_dir->i_sb, old_de);
	nv_free(old_dir->i_sb, old_de);

	eufs_dbg("%s: renamed %s to %s , old_pi=%llx new_pi=%llx\n", __func__,
		 old_dentry->d_name.name, new_dentry->d_name.name,
		 old_de->inode, new_de->inode);

	return 0;
}

const struct inode_operations eufs_dir_inode_operations = {
	.create = eufs_create,
	.lookup = eufs_lookup,
	.link = eufs_link,
	.unlink = eufs_unlink,
	.symlink = eufs_symlink,
	.mkdir = eufs_mkdir,
	.rmdir = eufs_rmdir,
	.mknod = eufs_mknod,
	.rename = eufs_rename,
	.setattr = eufs_notify_change,
};

const struct inode_operations eufs_special_inode_operations = {
	.setattr = eufs_notify_change,
};
