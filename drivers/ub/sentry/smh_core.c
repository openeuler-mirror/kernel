// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: Sentry Msg Helper
 * Author: Luckky
 * Create: 2025-02-17
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>

#include "smh_message.h"

#define SMH_DEV_NAME "sentry_msg_helper"

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][message_helper]: " fmt

/**
 * smh_dev_ioctl - IOCTL handler for sentry message helper device
 * @file: File structure pointer
 * @cmd: IOCTL command
 * @arg: User space argument
 *
 * Return: 0 on success, negative error code on failure
 */
static long smh_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case SMH_MSG_ACK: {
		struct sentry_msg_helper_msg cmd_msg = {0};

		if (copy_from_user(&cmd_msg, (void __user *)arg, sizeof(cmd_msg)))
			return -EFAULT;

		ret = smh_message_ack(&cmd_msg);
		break;
	}
	case SMH_VERSION_CHECK: {
		struct smh_version_info sentry_version = {
			.major      = SMH_VERSION_MAJOR,
			.minor      = SMH_VERSION_MINOR,
		};

		pr_info("sentry version is %d.%d\n", SMH_VERSION_MAJOR, SMH_VERSION_MINOR);

		if (copy_to_user((void __user *)arg, &sentry_version, sizeof(sentry_version)))
			return -EFAULT;
		break;
	}
	default:
		ret = -EINVAL;
	}

	return ret;
}

/**
 * smh_dev_open - Open handler for sentry message helper device
 * @inode: Inode structure pointer
 * @file: File structure pointer
 *
 * Return: 0 on success
 */
static int smh_dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

/**
 * smh_dev_flush - Flush handler for sentry message helper device
 * @file: File structure pointer
 * @owner: File owner ID
 *
 * Return: 0 on success
 */
static int smh_dev_flush(struct file *file, fl_owner_t owner)
{
	return 0;
}

/**
 * smh_dev_read - Read handler for sentry message helper device
 * @filp: File structure pointer
 * @buf: User space buffer
 * @count: Number of bytes to read
 * @f_pos: File position pointer
 *
 * Return: Number of bytes read on success, zero or negative error code on failure
 */
static ssize_t smh_dev_read(struct file *filp, char __user *buf, size_t count,
			    loff_t *f_pos)
{
	if (count != sizeof(struct sentry_msg_helper_msg)) {
		pr_err("smh_dev_read: read size mismatch\n");
		return 0;
	}

	return smh_message_get(buf);
}

static const struct file_operations smh_dev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= smh_dev_ioctl,
	.open		= smh_dev_open,
	.read		= smh_dev_read,
	.flush		= smh_dev_flush,
};

static struct miscdevice smh_dev_handle = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= SMH_DEV_NAME,
	.fops	= &smh_dev_fops,
};

/**
 * smh_init - Module initialization function
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init smh_init(void)
{
	int ret;

	ret = smh_message_init();
	if (ret) {
		pr_err("Failed to init smh message. retval=%d\n", ret);
		return ret;
	}
	pr_info("smh init successfully.\n");

	ret = misc_register(&smh_dev_handle);
	if (ret) {
		pr_err("Failed to register smh device. retval=%d\n", ret);
		smh_message_exit();
		return ret;
	}
	pr_info("smh device registered successfully.\n");

	return 0;
}

/**
 * smh_exit - Module cleanup function
 */
static void __exit smh_exit(void)
{
	misc_deregister(&smh_dev_handle);
	smh_message_exit();
}

module_init(smh_init);
module_exit(smh_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luckky");
MODULE_DESCRIPTION("SMH: Sentry Msg Helper");
MODULE_VERSION("1.0");
