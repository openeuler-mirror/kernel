// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for support ioctl for schedluler
 *
 * Copyright (C) 2023-2024 Huawei Technologies Co., Ltd
 *
 * Author: Hui Tang <tanghui20@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/string.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/compat.h>

#include "sched.h"

static int sched_ctl_open(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;

	return 0;
}

static int sched_ctl_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int sched_ctrl_get_relationship(void __user *arg)
{
	struct sctl_get_relationship_args data;
	struct task_struct *tsk;
	pid_t pid;

	if (!task_relationship_used()) {
		pr_err("task relationship disabled!\n");
		return -EPERM;
	}

	if (copy_from_user(&data, arg, sizeof(data))) {
		pr_err("fail to copy_from_user!\n");
		return -EFAULT;
	}

	pid = data.tid;

	rcu_read_lock();

	tsk = find_task_by_vpid(pid);
	if (!tsk) {
		rcu_read_unlock();
		return -ESRCH;
	}

	if (!task_relationship_supported(tsk)) {
		rcu_read_unlock();
		return -EPERM;
	}

	sctl_sched_get_net_relationship(tsk, &data.nrsi);
	sctl_sched_get_mem_relationship(tsk, &data.mrsi);

	rcu_read_unlock();

	if (copy_to_user(arg, &data, sizeof(data))) {
		pr_err("fail to copy_to_user!\n");
		return -EFAULT;
	}

	return 0;
}

static long sched_ctl_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	int ret = 0;
	struct sched_ctl_data *data;

	if (_IOC_TYPE(cmd) != SCTL_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > SCTL_IOC_MAXNR)
		return -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	data = filp->private_data;

	switch (cmd) {
	case SCTL_GET_RSHIP:
		ret = sched_ctrl_get_relationship((void __user *)(uintptr_t)arg);
		break;
	default:
		ret = -EINVAL;

	}

	return ret;
}

#ifdef CONFIG_COMPAT
static long
sched_ctl_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)(uintptr_t)compat_ptr(arg);
	return sched_ctl_ioctl(file, cmd, arg);
}
#endif /* CONFIG_COMPAT */

static const struct file_operations sched_ctl_fops = {
	.open = sched_ctl_open,
	.release = sched_ctl_release,
	.llseek = no_llseek,
	.unlocked_ioctl = sched_ctl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sched_ctl_compat_ioctl,
#endif
};

static struct miscdevice sched_ctl_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "relationship_ctrl",
	.fops = &sched_ctl_fops,
};

static int __init sched_ctl_device_init(void)
{
	return misc_register(&sched_ctl_device);
};

device_initcall(sched_ctl_device_init);
