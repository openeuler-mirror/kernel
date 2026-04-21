// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg kernel module
 * Author: Dongxu Li
 * Create: 2025-1-14
 * Note:
 * History: 2025-1-14: Create file
 */

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/module.h>

#include "ubagg_log.h"
#include "ubagg_ioctl.h"
#include "ubagg_netlink.h"
#include "ubagg_seg.h"
#include "ubagg_bitmap.h"
#include "ubagg_hash_table.h"

#define UBAGG_MODULE_NAME "ubagg"
#define UBAGG_DEVNODE_MODE (0666)
#define UBAGG_DEVICE_NAME UBAGG_MODULE_NAME
#define UBAGG_LOG_FILE_PERMISSION (0644)

module_param(g_ubagg_log_level, uint, UBAGG_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(g_ubagg_log_level,
		 " 3: ERR, 4: WARNING, 5:NOTICE, 6: INFO, 7: DEBUG");

struct ubagg_ctx {
	dev_t ubagg_devno;
	struct cdev ubagg_cdev;
	struct device *ubagg_dev;
};

static struct ubagg_ctx g_ubagg_ctx = { 0 };

static int ubagg_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static int ubagg_close(struct inode *i_node, struct file *filp)
{
	return 0;
}

static const struct file_operations g_ubagg_ops = {
	.owner = THIS_MODULE,
	.open = ubagg_open,
	.release = ubagg_close,
	.unlocked_ioctl = ubagg_ioctl,
	.compat_ioctl = ubagg_ioctl,
};

static char *ubagg_devnode(const struct device *dev, umode_t *mode)

{
	if (mode)
		*mode = UBAGG_DEVNODE_MODE;

	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

static struct class g_ubagg_class = {
	.name = UBAGG_MODULE_NAME,
	.devnode = ubagg_devnode,
};

static int ubagg_cdev_create(void)
{
	int ret;

	ret = alloc_chrdev_region(&g_ubagg_ctx.ubagg_devno, 0, 1,
				  UBAGG_MODULE_NAME);
	if (ret != 0) {
		ubagg_log_err("alloc chrdev no for ubagg fail.\n");
		return ret;
	}

	/* create /sys/class/ubagg */
	ret = class_register(&g_ubagg_class);
	if (ret) {
		ubagg_log_err("couldn't create class %s.\n", UBAGG_MODULE_NAME);
		goto unregister_devno;
	}

	cdev_init(&g_ubagg_ctx.ubagg_cdev, &g_ubagg_ops);
	g_ubagg_ctx.ubagg_cdev.owner = THIS_MODULE;

	ret = cdev_add(&g_ubagg_ctx.ubagg_cdev, g_ubagg_ctx.ubagg_devno, 1);
	if (ret != 0) {
		ubagg_log_err("ubagg chrdev add failed, ret:%d.\n", ret);
		goto class_unregister;
	}

	/* /dev/ubagg */
	g_ubagg_ctx.ubagg_dev = device_create(&g_ubagg_class, NULL,
					      g_ubagg_ctx.ubagg_devno, NULL,
					      UBAGG_DEVICE_NAME);
	if (IS_ERR(g_ubagg_ctx.ubagg_dev)) {
		ret = (int)PTR_ERR(g_ubagg_ctx.ubagg_dev);
		ubagg_log_err("couldn't create device %s, ret:%d.\n",
			      UBAGG_DEVICE_NAME, ret);
		g_ubagg_ctx.ubagg_dev = NULL;
		goto cdev_del;
	}
	ubagg_log_info("ubagg cdev,device and class created success.\n");

	return 0;

cdev_del:
	cdev_del(&g_ubagg_ctx.ubagg_cdev);
class_unregister:
	class_unregister(&g_ubagg_class);
unregister_devno:
	unregister_chrdev_region(g_ubagg_ctx.ubagg_devno, 1);

	return ret;
}

static void ubagg_cdev_destroy(void)
{
	device_destroy(&g_ubagg_class, g_ubagg_ctx.ubagg_cdev.dev);
	g_ubagg_ctx.ubagg_dev = NULL;
	cdev_del(&g_ubagg_ctx.ubagg_cdev);
	class_unregister(&g_ubagg_class);
	unregister_chrdev_region(g_ubagg_ctx.ubagg_devno, 1);
}

static int __init ubagg_init(void)
{
	int ret = 0;

	ret = ubagg_cdev_create();
	if (ret != 0) {
		ubagg_log_err("create cdev fail.");
		return ret;
	}

	ret = ubagg_netlink_init();
	if (ret != 0) {
		ubagg_log_err("create ubagg netlink fail.\n");
		ubagg_cdev_destroy();
		return ret;
	}

	return 0;
}

static void __exit ubagg_exit(void)
{
	ubagg_delete_topo_map();
	ubagg_clear_dev_list();
	ubagg_netlink_uninit();
	ubagg_cdev_destroy();
}

module_init(ubagg_init);
module_exit(ubagg_exit);

MODULE_DESCRIPTION("Kernel module for ubus");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL");
