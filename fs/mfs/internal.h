/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#ifndef _MFS_INTERNAL_H
#define _MFS_INTERNAL_H

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/container_of.h>
#include <linux/spinlock_types.h>
#include <linux/xarray.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/types.h>
#include <linux/mfs.h>

#define MFS_NAME "mfs"

#define MFS_OPEN_FLAGS (O_NOATIME)
#define MFS_EVENT_NEW	XA_MARK_1

/* mfs_sb_info flags */
#define MFS_MOUNTED 0

/* mfs_caches flags */
#define MFS_CACHE_READY 0
#define MFS_CACHE_OPENED 1

struct mfs_cache_object {
	struct file *cache_file;
	struct inode *mfs_inode;

	struct rw_semaphore rwsem;
	int fd;  /* anon file handle */
};

struct mfs_syncer {
	atomic_t notback;
	struct list_head head;
	spinlock_t list_lock;
	struct completion done;
	atomic_t res;
};

struct mfs_event {
	refcount_t ref;
	struct mfs_cache_object *object;
	struct mfs_syncer *syncer;
	struct list_head link;
	struct mfs_msg msg;
};

struct mfs_caches {
	struct xarray events;
	wait_queue_head_t pollwq;
	unsigned long next_msg;
	unsigned long next_ev;
	unsigned long flags;
};

struct mfs_sb_info {
	int mode;
	char *mtree;
	char *cachedir;
	struct path lower;
	struct path cache;

	int minor;

	unsigned long flags;
	struct super_block *sb;

	struct mfs_caches caches;
};

struct mfs_inode {
	struct inode *lower;
	struct inode *cache;
	struct mutex lock;
	struct inode vfs_inode;
};

struct mfs_file_info {
	struct file *lower;
	struct file *cache;
	const struct vm_operations_struct *cache_vm_ops;
};

struct mfs_dentry_info {
	spinlock_t lock;
	struct path lower;
	struct path cache;
};

#define MFS_SB(sb) ((struct mfs_sb_info *)(sb)->s_fs_info)
#define MFS_I(ptr) container_of(ptr, struct mfs_inode, vfs_inode)
#define MFS_D(dent) ((struct mfs_dentry_info *)(dent)->d_fsdata)

extern const struct file_operations mfs_dir_fops;
extern const struct file_operations mfs_file_fops;
extern const struct address_space_operations mfs_aops;
extern const struct vm_operations_struct mfs_file_vm_ops;

static inline struct inode *mfs_lower_inode(const struct inode *i)
{
	return MFS_I(i)->lower;
}

static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}

/*
 * dent: mfs vfs dentry
 */
static inline void mfs_get_path(const struct dentry *dent,
				    struct path *lpath,
				    struct path *cpath)
{
	spin_lock(&MFS_D(dent)->lock);
	pathcpy(lpath, &MFS_D(dent)->lower);
	path_get(lpath);
	pathcpy(cpath, &MFS_D(dent)->cache);
	path_get(cpath);
	spin_unlock(&MFS_D(dent)->lock);
}

static inline void mfs_put_path(struct path *lpath, struct path *cpath)
{
	path_put(lpath);
	path_put(cpath);
}

static inline void mfs_install_path(const struct dentry *dent,
					 struct path *lpath,
					 struct path *cpath)
{
	spin_lock(&MFS_D(dent)->lock);
	pathcpy(&MFS_D(dent)->lower, lpath);
	pathcpy(&MFS_D(dent)->cache, cpath);
	spin_unlock(&MFS_D(dent)->lock);
}

static inline void mfs_release_path(const struct dentry *dent)
{
	struct path lpath, cpath;

	if (!dent || !dent->d_fsdata)
		return;
	spin_lock(&MFS_D(dent)->lock);
	pathcpy(&lpath, &MFS_D(dent)->lower);
	pathcpy(&cpath, &MFS_D(dent)->cache);
	MFS_D(dent)->lower.dentry = NULL;
	MFS_D(dent)->lower.mnt = NULL;
	MFS_D(dent)->cache.dentry = NULL;
	MFS_D(dent)->cache.mnt = NULL;
	path_put(&lpath);
	path_put(&cpath);
	spin_unlock(&MFS_D(dent)->lock);
}

static inline void mfs_inode_lock(struct inode *inode)
{
	mutex_lock(&MFS_I(inode)->lock);
}

static inline void mfs_inode_unlock(struct inode *inode)
{
	mutex_unlock(&MFS_I(inode)->lock);
}

static inline bool support_event(struct mfs_sb_info *sbi)
{
	return sbi->mode != MFS_MODE_NONE;
}

static inline bool need_sync_event(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);

	return sbi->mode == MFS_MODE_REMOTE;
}

static inline bool cache_is_ready(struct mfs_sb_info *sbi)
{
	return test_bit(MFS_CACHE_READY, &sbi->caches.flags);
}

static inline void get_mfs_event(struct mfs_event *event)
{
	refcount_inc(&event->ref);
}

static inline void put_mfs_event(struct mfs_event *event)
{
	if (refcount_dec_and_test(&event->ref)) {
		iput(event->object->mfs_inode);
		kfree(event);
	}
}

struct inode *mfs_iget(struct super_block *sb, struct inode *lower_inode,
			  struct path *cache_path);
int mfs_alloc_dentry_info(struct dentry *dentry);
void mfs_free_dentry_info(struct dentry *dentry);

int mfs_fs_dev_init(struct super_block *sb);
void mfs_fs_dev_exit(struct super_block *sb);
int mfs_dev_init(void);
void mfs_dev_exit(void);

struct mfs_event *mfs_pick_event(struct xa_state *xas,
				 unsigned long xa_max);
void mfs_post_event_read(struct mfs_cache_object *object,
			       loff_t off, uint64_t len,
			       struct mfs_syncer *syncer, int op);
void mfs_destroy_events(struct super_block *sb);
void mfs_cancel_syncer_events(struct mfs_cache_object *object,
			      struct mfs_syncer *syncer);
void mfs_cancel_all_events(struct mfs_sb_info *sbi);
int try_hook_fd(struct mfs_event *event);
struct mfs_cache_object *mfs_alloc_object(struct inode *inode,
					       struct path *cache_path);
void mfs_free_object(void *data);
int mfs_cache_init(void);
void mfs_cache_exit(void);

#endif
