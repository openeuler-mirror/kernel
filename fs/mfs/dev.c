// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include "internal.h"

#include <linux/device.h>
#include <linux/idr.h>
#include <linux/poll.h>
#include <linux/list.h>

#include <trace/events/mfs.h>

static DEFINE_MUTEX(mfs_dev_lock);
static DEFINE_IDR(mfs_dev_minor);

static int mfs_dev_major;
static const struct class mfs_dev_class = {
	.name	= "mfs",
};
static struct device *mfs_dev;

static int mfs_dev_open(struct inode *inode, struct file *file)
{
	struct mfs_caches *caches;
	struct mfs_sb_info *sbi;
	unsigned minor = iminor(inode);

	sbi = minor < U8_MAX ? idr_find(&mfs_dev_minor, minor) : NULL;
	if (!sbi)
		return -EOPNOTSUPP;
	caches = &sbi->caches;
	if (test_and_set_bit(MFS_CACHE_OPENED, &caches->flags))
		return -EBUSY;
	smp_mb__after_atomic();

	/* not mounted or cleaned by umounting */
	if (!test_bit(MFS_MOUNTED, &sbi->flags)) {
		clear_bit(MFS_CACHE_OPENED, &caches->flags);
		return -EBUSY;
	}

	file->private_data = sbi;
	set_bit(MFS_CACHE_READY, &caches->flags);
	return 0;
}

static int mfs_dev_release(struct inode *inode, struct file *file)
{
	struct mfs_sb_info *sbi = file->private_data;
	struct mfs_caches *caches = &sbi->caches;

	clear_bit(MFS_CACHE_READY, &caches->flags);
	smp_mb__after_atomic();
	mfs_cancel_all_events(sbi);
	smp_mb__before_atomic();
	clear_bit(MFS_CACHE_OPENED, &caches->flags);
	return 0;
}

static ssize_t mfs_dev_read(struct file *file, char __user *buf,
				size_t blen, loff_t *off)
{
	struct mfs_sb_info *sbi = file->private_data;
	struct mfs_caches *caches = &sbi->caches;
	XA_STATE(xas, &caches->events, caches->next_ev);
	struct mfs_event *event;
	struct mfs_msg *msg;
	bool sync;
	size_t n;
	int ret;

	xas_lock(&xas);
	event = mfs_pick_event(&xas, ULONG_MAX);
	if (!event && caches->next_ev > 0) {
		xas_set(&xas, 0);
		event = mfs_pick_event(&xas, caches->next_ev - 1);
	}
	if (!event) {
		xas_unlock(&xas);
		return 0;
	}
	sync = event->syncer ? true : false;
	if (sync)
		get_mfs_event(event);
	xas_unlock(&xas);

	msg = &event->msg;
	n = msg->len;
	if (n > blen) {
		ret = -EMSGSIZE;
		goto out;
	}

	ret = try_hook_fd(event);
	if (ret < 0)
		goto out;

	msg->fd = ret;
	ret = 0;
	if (copy_to_user(buf, msg, n)) {
		ret = -EFAULT;
		goto out;
	}
	xas_lock(&xas);
	xas_clear_mark(&xas, MFS_EVENT_NEW);
	caches->next_ev = xas.xa_index + 1;
	if (!sync)
		xas_store(&xas, NULL);
	xas_unlock(&xas);
out:
	trace_mfs_dev_read(file, msg->opcode, msg->id, msg->fd);
	/* unread async event don't need to released immediately */
	if (ret == 0 || sync)
		put_mfs_event(event);
	return ret ? ret : n;
}

static __poll_t mfs_dev_poll(struct file *file,
				 struct poll_table_struct *poll)
{
	struct mfs_sb_info *sbi = file->private_data;
	struct mfs_caches *caches = &sbi->caches;
	struct mfs_event *event;
	XA_STATE(xas, &caches->events, 0);
	__poll_t mask;

	poll_wait(file, &caches->pollwq, poll);
	mask = 0;

	if (!test_bit(MFS_MOUNTED, &sbi->flags)) {
		mask |= EPOLLERR;
		return mask;
	}

	if (!xa_empty(&caches->events)) {
		xas_lock(&xas);
		xas_for_each_marked(&xas, event, ULONG_MAX, MFS_EVENT_NEW) {
			mask |= EPOLLIN;
			break;
		}
		xas_unlock(&xas);
	}

	return mask;
}

static long mfs_dev_ioctl(struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	struct mfs_ioc_fsinfo fsinfo;
	unsigned minor = iminor(file_inode(filp));
	struct mfs_sb_info *sbi = minor < U8_MAX ?
				  idr_find(&mfs_dev_minor, minor) : NULL;
	if (!sbi)
		return -EOPNOTSUPP;

	if (cmd != MFS_IOC_FSINFO)
		return -EINVAL;
	if (!test_bit(MFS_MOUNTED, &sbi->flags))
		return -EBUSY;

	fsinfo.mode = sbi->mode;
	if (copy_to_user((void __user *)arg, &fsinfo,
			  sizeof(struct mfs_ioc_fsinfo)))
		return -EFAULT;
	return 0;
}

static const struct file_operations mfs_dev_fops = {
	.owner		= THIS_MODULE,
	.open		= mfs_dev_open,
	.release	= mfs_dev_release,
	.read		= mfs_dev_read,
	.poll		= mfs_dev_poll,
	.unlocked_ioctl = mfs_dev_ioctl,
};

int mfs_fs_dev_init(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);
	struct device *dev;

	mutex_lock(&mfs_dev_lock);
	sbi->minor = idr_alloc(&mfs_dev_minor, sbi, 0, U8_MAX, GFP_KERNEL);
	if (sbi->minor < 0) {
		mutex_unlock(&mfs_dev_lock);
		return sbi->minor;
	}

	dev = device_create(&mfs_dev_class, NULL,
			    MKDEV(mfs_dev_major, sbi->minor), sbi,
			    "mfs%u", sbi->minor);
	if (IS_ERR(dev)) {
		idr_remove(&mfs_dev_minor, sbi->minor);
		sbi->minor = -1;
		mutex_unlock(&mfs_dev_lock);
		return PTR_ERR(dev);
	}
	mutex_unlock(&mfs_dev_lock);
	return 0;
}

void mfs_fs_dev_exit(struct super_block *sb)
{
	struct mfs_sb_info *sbi = MFS_SB(sb);

	if (sbi->minor < 0)
		return;
	mutex_lock(&mfs_dev_lock);
	device_destroy(&mfs_dev_class, MKDEV(mfs_dev_major, sbi->minor));
	idr_remove(&mfs_dev_minor, sbi->minor);
	mutex_unlock(&mfs_dev_lock);
	sbi->minor = -1;
}

int mfs_dev_init(void)
{
	int ret;

	mfs_dev_major = register_chrdev(0, "mfs-ctl", &mfs_dev_fops);
	if (mfs_dev_major < 0)
		return mfs_dev_major;

	ret = class_register(&mfs_dev_class);
	if (ret)
		goto major_out;

	mfs_dev = device_create(&mfs_dev_class, NULL,
				MKDEV(mfs_dev_major, U8_MAX),
				NULL, "mfs-ctl");
	if (IS_ERR(mfs_dev)) {
		ret = PTR_ERR(mfs_dev);
		goto class_out;
	}
	return 0;

class_out:
	class_unregister(&mfs_dev_class);
major_out:
	unregister_chrdev(mfs_dev_major, "mfs-ctl");
	return ret;
}

void mfs_dev_exit(void)
{
	if (!IS_ERR_OR_NULL(mfs_dev))
		device_destroy(&mfs_dev_class, MKDEV(mfs_dev_major, U8_MAX));
	class_unregister(&mfs_dev_class);
	if (mfs_dev_major > 0)
		unregister_chrdev(mfs_dev_major, "mfs-ctl");
}
