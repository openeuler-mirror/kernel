// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>		/* everything... */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <asm/ioctls.h>
#include <linux/slab.h>
#include "kbox_include.h"
#include "kbox_ram_drive.h"
#include "kbox_main.h"
#include "kbox_ram_image.h"
#include "kbox_ram_op.h"

#define KBOX_DEVICE_NAME "kbox"
#define KBOX_DEVICE_MINOR 255

static struct kbox_dev_s *g_kbox_dev;
static ssize_t kbox_read(struct file *filp, char __user *data, size_t count,
			 loff_t *ppos);
static ssize_t kbox_write(struct file *filp, const char __user *data,
			  size_t count, loff_t *ppos);

static long kbox_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static int kbox_mmap(struct file *filp, struct vm_area_struct *vma);
static int kbox_open(struct inode *inode, struct file *filp);
static int kbox_release(struct inode *inode, struct file *filp);

const struct file_operations kbox_fops = {
	.owner = THIS_MODULE,
	.read = kbox_read,
	.write = kbox_write,
	.unlocked_ioctl = kbox_ioctl,
	.mmap = kbox_mmap,
	.open = kbox_open,
	.release = kbox_release,
};

static struct miscdevice kbox_device = {
	KBOX_DEVICE_MINOR,
	KBOX_DEVICE_NAME,
	&kbox_fops,
};

static ssize_t kbox_read(struct file *filp, char __user *data, size_t count,
			 loff_t *ppos)
{
	int read_len = 0;

	if (!filp || !data || !ppos) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	read_len = kbox_read_op((long long)(*ppos),
				count,
				data,
				KBOX_SECTION_USER);
	if (read_len < 0)
		return -EFAULT;

	*ppos += read_len;

	return read_len;
}

static ssize_t kbox_write(struct file *filp, const char __user *data,
			  size_t count, loff_t *ppos)
{
	int write_len = 0;

	if (!filp || !data || !ppos) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	write_len = kbox_write_op((long long)(*ppos),
				  count, data, KBOX_SECTION_USER);
	if (write_len < 0)
		return -EFAULT;

	*ppos += write_len;

	return write_len;
}

static long kbox_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	UNUSED(filp);

	if (kbox_ioctl_detail(cmd, arg) < 0)
		return -ENOTTY;

	return 0;
}

static int kbox_mmap(struct file *filp, struct vm_area_struct *vma)
{
	if (!filp || !vma) {
		KBOX_MSG("input NULL point!\n");
		return -EFAULT;
	}

	if (kbox_mmap_ram(filp, vma, KBOX_SECTION_USER) < 0)
		return -EFAULT;

	return 0;
}

static int kbox_open(struct inode *pinode, struct file *filp)
{
	UNUSED(pinode);

	if ((g_kbox_dev) && (!atomic_dec_and_test(&g_kbox_dev->au_count))) {
		atomic_inc(&g_kbox_dev->au_count);
		KBOX_MSG("EBUSY\n");
		return -EBUSY;
	}

	filp->private_data = (void *)g_kbox_dev;

	return 0;
}

int kbox_release(struct inode *pinode, struct file *filp)
{
	struct kbox_dev_s *kbox_dev = (struct kbox_dev_s *)filp->private_data;

	UNUSED(pinode);

	KBOX_MSG("\n");

	if (kbox_dev)
		atomic_inc(&kbox_dev->au_count);

	return 0;
}

int kbox_drive_init(void)
{
	int ret = 0;

	KBOX_MSG("\n");

	g_kbox_dev =
	    kmalloc(sizeof(struct kbox_dev_s), GFP_KERNEL);
	if (!g_kbox_dev)
		return -ENOMEM;

	ret = misc_register(&kbox_device);
	if (ret)
		goto fail;

	atomic_set(&g_kbox_dev->au_count, 1);

	KBOX_MSG("ok!\n");

	return ret;

fail:
	kfree(g_kbox_dev);
	g_kbox_dev = NULL;

	return ret;
}

void kbox_drive_cleanup(void)
{
	if (!g_kbox_dev)
		return;

	misc_deregister(&kbox_device);

	kfree(g_kbox_dev);
	g_kbox_dev = NULL;
}
