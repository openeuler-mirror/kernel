// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include "internal.h"

#include <linux/anon_inodes.h>
#include <linux/mfs.h>
#include <linux/fadvise.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>

#include <trace/events/mfs.h>

/*
 * Used for cache object
 */
static struct kmem_cache *mfs_cobject_cachep;

static int fd_release(struct inode *inode, struct file *file)
{
	struct mfs_cache_object *object = file->private_data;

	down_write(&object->rwsem);
	if (object->fd > 0) {
		object->fd = -1;
		object->anon_file = NULL;
		up_write(&object->rwsem);
		iput(object->mfs_inode);
	} else {
		up_write(&object->rwsem);
	}
	return 0;
}

static ssize_t fd_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *ori_file = iocb->ki_filp;
	struct mfs_cache_object *object = ori_file->private_data;
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);
	ssize_t ret;

	if (!test_bit(MFS_CACHE_READY, &sbi->caches.flags))
		return -EINVAL;
	if (sbi->mode != MFS_MODE_REMOTE)
		return -EOPNOTSUPP;

	iocb->ki_filp = object->cache_file;
	ret = vfs_iocb_iter_write(object->cache_file, iocb, iter);
	iocb->ki_filp = ori_file;
	return ret;
}

static loff_t fd_llseek(struct file *filp, loff_t pos, int whence)
{
	struct mfs_cache_object *object = filp->private_data;
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);

	if (!test_bit(MFS_CACHE_READY, &sbi->caches.flags))
		return -EINVAL;
	if (sbi->mode != MFS_MODE_REMOTE)
		return -EOPNOTSUPP;

	return vfs_llseek(object->cache_file, pos, whence);
}

/* Used for sync events */
static long _ioc_done(struct mfs_cache_object *object,
			 struct mfs_ioc_done *done)
{
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);
	struct mfs_caches *caches = &sbi->caches;
	XA_STATE(xas, &caches->events, done->id);
	struct mfs_syncer *syncer;
	struct mfs_event *event;

	xas_lock(&xas);
	event = xas_load(&xas);
	if (!event || event->object != object) {
		xa_unlock(&caches->events);
		return -EINVAL;
	}
	xas_store(&xas, NULL);
	syncer = event->syncer;
	if (done->ret)
		atomic_cmpxchg(&syncer->res, 0, -EIO);
	spin_lock(&syncer->list_lock);
	list_del(&event->link);
	spin_unlock(&syncer->list_lock);
	if (atomic_dec_return(&syncer->notback) == 0)
		complete(&syncer->done);
	xas_unlock(&xas);

	put_mfs_event(event);
	return 0;
}

static void force_ra(struct address_space *mapping, struct file *file,
			pgoff_t start, pgoff_t end)
{
	unsigned long default_pages = (4 * 1024 * 1024) / PAGE_SIZE;
	DEFINE_READAHEAD(ractl, file, NULL, mapping, start);
	pgoff_t index = start;
	unsigned long nr_to_read;

	nr_to_read = end - start + 1;
	while (nr_to_read) {
		if (default_pages > nr_to_read)
			default_pages = nr_to_read;
		if (index > end)
			return;
		ractl._index = index;
		page_cache_ra_unbounded(&ractl, default_pages, 0);
		index += default_pages;
		nr_to_read -= default_pages;
	}
}

/* Used for async events */
static long _ioc_ra(struct mfs_cache_object *object,
		      struct mfs_ioc_ra *ra)
{
	struct file *file = object->cache_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file_inode(file);
	loff_t endbyte, isize;
	pgoff_t start, end;

	isize = i_size_read(inode);
	if (!isize)
		return 0;
	if (ra->off >= isize)
		return -EINVAL;
	endbyte = (u64)ra->off + (u64)ra->len;
	if (!ra->len || endbyte < ra->len)
		endbyte = LLONG_MAX;
	else
		endbyte--;
	endbyte = min_t(loff_t, endbyte, isize);

	start = ra->off >> PAGE_SHIFT;
	end = endbyte >> PAGE_SHIFT;

	force_ra(mapping, file, start, end);
	return 0;
}

static long fd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct mfs_cache_object *object = filp->private_data;
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);
	int ret = 0;

	if (!test_bit(MFS_CACHE_READY, &sbi->caches.flags))
		return -EINVAL;

	switch (cmd) {
	case MFS_IOC_DONE:
	{
		struct mfs_ioc_done done;

		if (sbi->mode != MFS_MODE_REMOTE)
			return -EOPNOTSUPP;
		if (copy_from_user(&done, (void __user *)arg, sizeof(done)))
			return -EFAULT;
		ret = _ioc_done(object, &done);
		break;
	}
	case MFS_IOC_RA:
	{
		struct mfs_ioc_ra ra;

		if (sbi->mode != MFS_MODE_LOCAL)
			return -EOPNOTSUPP;
		if (copy_from_user(&ra, (void __user *)arg, sizeof(ra)))
			return -EFAULT;
		ret = _ioc_ra(object, &ra);
		break;
	}
	case MFS_IOC_RPATH:
	{
		struct mfs_ioc_rpath __user *ua = (struct mfs_ioc_rpath __user *)arg;
		struct mfs_ioc_rpath *rpath;
		int plen, clen;
		u32 bytes;
		char *p;

		if (get_user(bytes, &ua->max))
			return -EFAULT;
		rpath = kzalloc(bytes + sizeof(struct mfs_ioc_rpath), GFP_KERNEL);
		if (!rpath)
			return -ENOMEM;

		rpath->max = bytes;
		p = file_path(object->cache_file, rpath->d, rpath->max);
		if (IS_ERR(p)) {
			kfree(rpath);
			return PTR_ERR(p);
		}
		plen = strlen(p), clen = strlen(sbi->cachedir);
		if (plen <= clen) {
			kfree(rpath);
			return -EFAULT;
		}
		rpath->len = plen - clen;
		/* include the tailing nil */
		memmove(rpath->d, p + clen, rpath->len + 1);
		if (copy_to_user((void __user *)arg, rpath,
				  rpath->len + 1 + sizeof(struct mfs_ioc_rpath)))
			ret = -EFAULT;
		kfree(rpath);
		break;
	}
	default:
		return -EINVAL;
	}
	return ret;
}

static const struct file_operations mfs_fd_fops = {
	.owner		= THIS_MODULE,
	.release	= fd_release,
	.write_iter	= fd_write_iter,
	.llseek		= fd_llseek,
	.unlocked_ioctl = fd_ioctl,
};

static int mfs_setup_object(struct mfs_cache_object *object,
				 struct inode *inode,
				 struct path *cache_path)
{
	struct inode *cache_inode = d_inode(cache_path->dentry);
	struct file *cache_file;
	int flags = O_RDONLY;

	if (need_sync_event(inode->i_sb))
		flags = O_RDWR;
	cache_file = kernel_file_open(cache_path, flags | O_LARGEFILE,
				      cache_inode, current_cred());
	if (IS_ERR(cache_file))
		return PTR_ERR(cache_file);
	/*
	 * object belongs to a mfs inode,
	 * this is a reverse pointer, no refcount needed.
	 */
	object->mfs_inode = inode;
	object->cache_file = cache_file;
	init_rwsem(&object->rwsem);
	object->fd = -1;
	object->anon_file = NULL;
	return 0;
}

struct mfs_event *mfs_pick_event(struct xa_state *xas,
				 unsigned long xa_max)
{
	struct mfs_event *event;

	xas_for_each_marked(xas, event, xa_max, MFS_EVENT_NEW) {
		return event;
	}

	return NULL;
}

void mfs_post_event_read(struct mfs_cache_object *object,
			       loff_t off, uint64_t len,
			       struct mfs_syncer *syncer, int op)
{
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);
	struct mfs_caches *caches = &sbi->caches;
	XA_STATE(xas, &caches->events, 0);
	struct mfs_event *event;
	struct mfs_read *msg;
	int ret;

	/* 1. init event struct */
	event = kzalloc(sizeof(*event) + sizeof(*msg), GFP_KERNEL);
	if (!event) {
		pr_warn("post read event failed, off:%lld, len:%llu\n", off, len);
		return;
	}

	/* 2. hold object's owner mfs_inode */
	ihold(object->mfs_inode);
	trace_mfs_post_event_read(object->mfs_inode, off, len, op);
	refcount_set(&event->ref, 1);
	event->object = object;
	event->msg.version = 0;
	event->msg.opcode = op;
	event->msg.len = sizeof(struct mfs_msg) + sizeof(struct mfs_read);
	event->msg.fd = object->fd;
	msg = (void *)event->msg.data;
	msg->off = off;
	msg->len = len;
	msg->pid = current->pid;
	INIT_LIST_HEAD(&event->link);
	event->syncer = syncer;
	if (event->syncer) {
		atomic_inc(&syncer->notback);
		spin_lock(&syncer->list_lock);
		list_add_tail(&event->link, &syncer->head);
		spin_unlock(&syncer->list_lock);
	}

	/* 3. put event into reqs' xarray */
	do {
		xas_lock(&xas);

		/* Ensure flags changed after lock */
		smp_mb__before_atomic();
		if (!test_bit(MFS_CACHE_READY, &caches->flags)) {
			xas_unlock(&xas);
			goto out;
		}

		/* Ensure cache enabled judgement before posting events */
		smp_mb__after_atomic();

		xas.xa_index = caches->next_msg;
		xas_find_marked(&xas, UINT_MAX, XA_FREE_MARK);
		if (xas.xa_node == XAS_RESTART) {
			xas.xa_index = 0;
			xas_find_marked(&xas, caches->next_msg - 1, XA_FREE_MARK);
		}
		if (xas.xa_node == XAS_RESTART)
			xas_set_err(&xas, -EBUSY);
		xas_store(&xas, event);
		if (xas_valid(&xas)) {
			caches->next_msg = xas.xa_index + 1;
			event->msg.id = xas.xa_index;
			xas_clear_mark(&xas, XA_FREE_MARK);
			xas_set_mark(&xas, MFS_EVENT_NEW);
		}
		xas_unlock(&xas);
	} while (xas_nomem(&xas, GFP_KERNEL));

	ret = xas_error(&xas);
	if (ret) {
		pr_warn("post read event failed to insert events, off:%lld, len:%llu, ret:%d\n",
			off, len, ret);
		goto out;
	}

	/* 3. wakeup the polling wait list */
	wake_up_all(&caches->pollwq);
	return;
out:
	if (event->syncer) {
		spin_lock(&syncer->list_lock);
		list_del_init(&event->link);
		spin_unlock(&syncer->list_lock);
		atomic_dec(&syncer->notback);
	}
	kfree(event);
	iput(object->mfs_inode);
}

void mfs_destroy_events(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);
	struct mfs_caches *caches = &sbi->caches;
	unsigned long index;
	struct mfs_event *event;

	xa_lock(&caches->events);
	xa_for_each(&caches->events, index, event) {
		/*
		 * Inodes will be evicted before destroy events.
		 * Hence there should be none of events.
		 */
		pr_warn("Event remains:%lu\n", index);
		__xa_erase(&caches->events, index);
		put_mfs_event(event);
	}
	xa_unlock(&caches->events);
	xa_destroy(&caches->events);
}

void mfs_cancel_syncer_events(struct mfs_cache_object *object,
			      struct mfs_syncer *syncer)
{
	struct mfs_sb_info *sbi = MFS_SB(object->mfs_inode->i_sb);
	struct mfs_caches *caches = &sbi->caches;
	struct xarray *xa = &caches->events;
	struct mfs_event *event, *nevent;

	xa_lock(xa);
	spin_lock(&syncer->list_lock);
	list_for_each_entry_safe(event, nevent, &syncer->head, link) {
		__xa_erase(&caches->events, event->msg.id);
		list_del(&event->link);
		put_mfs_event(event);
	}
	spin_unlock(&syncer->list_lock);
	xa_unlock(xa);
}

void mfs_cancel_all_events(struct mfs_sb_info *sbi)
{
	struct mfs_caches *caches = &sbi->caches;
	struct xarray *xa = &caches->events;
	struct mfs_syncer *syncer;
	struct mfs_event *event;
	unsigned long index;

	while (!xa_empty(xa)) {
		xa_lock(xa);
		xa_for_each(xa, index, event) {
			__xa_erase(xa, index);
			syncer = event->syncer;
			/*
			 * Here should keep syncer (a stack variable), so we should
			 * wakeup the syncer list in the protect of xa lock.
			 */
			if (syncer) {
				spin_lock(&syncer->list_lock);
				list_del(&event->link);
				spin_unlock(&syncer->list_lock);
				if (atomic_dec_return(&syncer->notback) == 0) {
					atomic_cmpxchg(&syncer->res, 0, -EIO);
					complete(&syncer->done);
				}
			}
			put_mfs_event(event);
			if (need_resched())
				break;
		}
		xa_unlock(xa);
		cond_resched();
	}
	caches->next_ev = 0;
	caches->next_msg = 0;
}

int try_hook_fd(struct mfs_event *event)
{
	struct mfs_cache_object *object = event->object;
	struct file *anon_file;
	int fd;

	down_read(&object->rwsem);
	if (object->fd > 0) {
		up_read(&object->rwsem);
		return object->fd;
	}
	up_read(&object->rwsem);
	down_write(&object->rwsem);
	if (object->fd > 0) {
		up_write(&object->rwsem);
		return object->fd;
	}
	fd = get_unused_fd_flags(O_WRONLY);
	if (fd < 0) {
		up_write(&object->rwsem);
		return fd;
	}

	anon_file = anon_inode_getfile("[mfs]", &mfs_fd_fops, object, O_WRONLY);
	if (IS_ERR(anon_file)) {
		put_unused_fd(fd);
		up_write(&object->rwsem);
		return PTR_ERR(anon_file);
	}
	anon_file->f_mode |= FMODE_PWRITE | FMODE_LSEEK;
	object->fd = fd;
	object->anon_file = anon_file;
	/* lifecyle of fd/anon_file should later than mfs_inode */
	ihold(object->mfs_inode);
	fd_install(fd, anon_file);
	up_write(&object->rwsem);
	return fd;
}

struct mfs_cache_object *mfs_alloc_object(struct inode *inode,
					       struct path *cache_path)
{
	struct mfs_cache_object *object;
	int err;

	object = kmem_cache_alloc(mfs_cobject_cachep, GFP_KERNEL);
	if (!object)
		return ERR_PTR(-ENOMEM);

	err = mfs_setup_object(object, inode, cache_path);
	if (err) {
		kmem_cache_free(mfs_cobject_cachep, object);
		return ERR_PTR(err);
	}

	return object;
}

void mfs_free_object(void *data)
{
	struct mfs_cache_object *object = (struct mfs_cache_object *)data;

	fput(object->cache_file);
	kmem_cache_free(mfs_cobject_cachep, object);
}

int mfs_cache_init(void)
{
	mfs_cobject_cachep =
		kmem_cache_create("mfs_object",
				  sizeof(struct mfs_cache_object), 0,
				  SLAB_RECLAIM_ACCOUNT, NULL);
	if (!mfs_cobject_cachep)
		return -ENOMEM;
	return 0;
}

void mfs_cache_exit(void)
{
	kmem_cache_destroy(mfs_cobject_cachep);
}
