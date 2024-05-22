// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma kernel module
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: Create file
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_file_ops.h"
#include "uburma_uobj.h"
#include "uburma_cmd.h"

#define UBURMA_LOG_FILE_PERMISSION (0644)

module_param(g_uburma_log_level, uint, UBURMA_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(g_uburma_log_level, " 3: ERR, 4: WARNING, 6: INFO, 7: DEBUG");

#define UBURMA_MAX_DEVICE 1024
#define UBURMA_DYNAMIC_MINOR_NUM UBURMA_MAX_DEVICE
#define UBURMA_MODULE_NAME "uburma"
#define UBURMA_DEVNODE_MODE (0666)

static DECLARE_BITMAP(g_dev_bitmap, UBURMA_MAX_DEVICE);

static dev_t g_dynamic_uburma_dev;

static char *uburma_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = UBURMA_DEVNODE_MODE;

	return kasprintf(GFP_KERNEL, "uburma/%s", dev_name(dev));
}

static struct class g_uburma_class = {
	.name    = UBURMA_MODULE_NAME,
	.devnode = uburma_devnode,
};

static const struct file_operations g_uburma_fops = {
	.owner = THIS_MODULE,
	// .write	 = uburma_write,
	.mmap = uburma_mmap,
	.open = uburma_open,
	.release = uburma_close,
	.llseek = no_llseek,
	.unlocked_ioctl = uburma_ioctl,
	.compat_ioctl = uburma_ioctl,
};


static int uburma_add_device(struct ubcore_device *ubc_dev);
static void uburma_remove_device(struct ubcore_device *ubc_dev, void *client_ctx);
static struct ubcore_client g_urma_client = {
	.list_node = LIST_HEAD_INIT(g_urma_client.list_node),
	.client_name = "urma",
	.add = uburma_add_device,
	.remove = uburma_remove_device,
};

static void uburma_release_dev(struct kobject *kobj)
{
	struct uburma_device *ubu_dev = container_of(kobj, struct uburma_device, kobj);

	cleanup_srcu_struct(&ubu_dev->ubc_dev_srcu);
	kfree(ubu_dev);
}

static struct kobj_type uburma_dev_ktype = {
	.release = uburma_release_dev,
};

static int uburma_get_devt(dev_t *devt)
{
	unsigned int devnum;

	devnum = (unsigned int)find_first_zero_bit(g_dev_bitmap, UBURMA_MAX_DEVICE);
	if (devnum >= UBURMA_MAX_DEVICE) {
		uburma_log_err("Invalid argument.\n");
		return -ENOMEM;
	}
	set_bit(devnum, g_dev_bitmap);
	*devt = g_dynamic_uburma_dev + devnum;
	return 0;
}

static int uburma_device_create(struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev)
{
	/* create /sys/class/uburma/<ubc_dev->dev_name> */
	ubu_dev->dev = device_create(&g_uburma_class, ubc_dev->dev.parent,
			ubu_dev->cdev.dev, ubu_dev, "%s", ubc_dev->dev_name);
	if (IS_ERR(ubu_dev->dev)) {
		uburma_log_err("device create failed, device:%s.\n", ubc_dev->dev_name);
		return -ENOMEM;
	}

	return 0;
}

static void uburma_device_destroy(struct uburma_device *ubu_dev)
{
	device_destroy(&g_uburma_class, ubu_dev->cdev.dev);
	ubu_dev->dev = NULL;
}

static int uburma_cdev_create(struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev)
{
	dev_t base;

	if (uburma_get_devt(&base) != 0) {
		uburma_log_err("Invalid argument.\n");
		return -ENOMEM;
	}
	ubu_dev->devnum = base - g_dynamic_uburma_dev;

	cdev_init(&ubu_dev->cdev, NULL);
	ubu_dev->cdev.owner = THIS_MODULE;
	ubu_dev->cdev.ops = &g_uburma_fops;
	ubu_dev->cdev.kobj.parent = &ubu_dev->kobj;
	(void)kobject_set_name(&ubu_dev->cdev.kobj, "%s", ubc_dev->dev_name);

	/* create /dev/uburma/<ubc_dev->dev_name> */
	if (cdev_add(&ubu_dev->cdev, base, 1))
		goto free_bit;

	if (uburma_device_create(ubu_dev, ubc_dev) != 0) {
		uburma_log_err("device create failed, device:%s.\n", ubc_dev->dev_name);
		goto del_cdev;
	}

	return 0;

del_cdev:
	cdev_del(&ubu_dev->cdev);
free_bit:
	clear_bit(ubu_dev->devnum, g_dev_bitmap);
	return -EPERM;
}


static int uburma_add_device(struct ubcore_device *ubc_dev)
{
	struct uburma_device *ubu_dev;
	int ret;

	ubu_dev = kzalloc(sizeof(struct uburma_device), GFP_KERNEL);
	if (ubu_dev == NULL)
		return -ENOMEM;

	ret = init_srcu_struct(&ubu_dev->ubc_dev_srcu);
	if (ret != 0) {
		kfree(ubu_dev);
		return -EPERM;
	}

	atomic_set(&ubu_dev->refcnt, 1);
	init_completion(&ubu_dev->comp);

	/* cmd cnt and completion for ioctl and mmap cmds */
	atomic_set(&ubu_dev->cmdcnt, 1);
	init_completion(&ubu_dev->cmddone);

	kobject_init(&ubu_dev->kobj, &uburma_dev_ktype);
	mutex_init(&ubu_dev->lists_mutex);
	INIT_LIST_HEAD(&ubu_dev->uburma_file_list);

	rcu_assign_pointer(ubu_dev->ubc_dev, ubc_dev);

	if (uburma_cdev_create(ubu_dev, ubc_dev) != 0) {
		uburma_log_err("can not create cdev.\n");
		goto err;
	}

	ubcore_set_client_ctx_data(ubc_dev, &g_urma_client, ubu_dev);
	return 0;

err:
	if (atomic_dec_and_test(&ubu_dev->refcnt))
		complete(&ubu_dev->comp);

	wait_for_completion(&ubu_dev->comp);
	mutex_destroy(&ubu_dev->lists_mutex);
	kfree(ubu_dev);
	return -EPERM;
}

static void uburma_free_ucontext(struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev)
{
	struct uburma_file *file;

	rcu_assign_pointer(ubu_dev->ubc_dev, NULL);
	synchronize_srcu(&ubu_dev->ubc_dev_srcu);

	mutex_lock(&ubu_dev->lists_mutex);
	while (list_empty(&ubu_dev->uburma_file_list) == false) {
		struct ubcore_ucontext *ucontext;

		file = list_first_entry(&ubu_dev->uburma_file_list, struct uburma_file, list);
		file->is_closed = true;
		list_del(&file->list);
		kref_get(&file->ref);
		mutex_unlock(&ubu_dev->lists_mutex);

		mutex_lock(&file->mutex);
		uburma_cleanup_uobjs(file, UBURMA_REMOVE_DRIVER_REMOVE);
		ucontext = file->ucontext;
		file->ucontext = NULL;
		if (ucontext != NULL)
			ubcore_free_ucontext(ubc_dev, ucontext);

		mutex_unlock(&file->mutex);

		mutex_lock(&ubu_dev->lists_mutex);
		(void)kref_put(&file->ref, uburma_release_file);
	}
	mutex_unlock(&ubu_dev->lists_mutex);
}

static void uburma_remove_device(struct ubcore_device *ubc_dev, void *client_ctx)
{
	struct uburma_device *ubu_dev = client_ctx;

	if (ubu_dev == NULL)
		return;

	uburma_device_destroy(ubu_dev);
	cdev_del(&ubu_dev->cdev);
	clear_bit(ubu_dev->devnum, g_dev_bitmap);

	uburma_free_ucontext(ubu_dev, ubc_dev);

	if (atomic_dec_and_test(&ubu_dev->refcnt))
		complete(&ubu_dev->comp);

	/* do not wait_for_completion(&ubu_dev->comp) */
	uburma_cmd_flush(ubu_dev);
	kobject_put(&ubu_dev->kobj);
}

static void uburma_register_client(void)
{
	int ret;

	ret = ubcore_register_client(&g_urma_client);
	if (ret != 0)
		uburma_log_err("register client failed, ret: %d.\n", ret);
	else
		uburma_log_info("register client succeed.\n");
}

static void uburma_unregister_client(void)
{
	ubcore_unregister_client(&g_urma_client);
	uburma_log_info("unregister client succeed.\n");
}

static int uburma_class_create(void)
{
	int ret;

	ret = alloc_chrdev_region(&g_dynamic_uburma_dev, 0, UBURMA_DYNAMIC_MINOR_NUM,
				  UBURMA_MODULE_NAME);
	if (ret != 0) {
		uburma_log_err("couldn't register dynamic device number.\n");
		goto out;
	}

	/* create /sys/class/uburma */
	ret = class_register(&g_uburma_class);
	if (ret) {
		uburma_log_err("couldn't create class %s.\n", UBURMA_MODULE_NAME);
		goto out_chrdev;
	}

	return 0;
out_chrdev:
	unregister_chrdev_region(g_dynamic_uburma_dev, UBURMA_DYNAMIC_MINOR_NUM);
out:
	return ret;
}

static void uburma_class_destroy(void)
{
	class_unregister(&g_uburma_class);
	unregister_chrdev_region(g_dynamic_uburma_dev, UBURMA_DYNAMIC_MINOR_NUM);
}

static int __init uburma_init(void)
{
	int ret;

	ret = uburma_class_create();
	if (ret != 0) {
		uburma_log_err("uburma dev create failed.\n");
		return ret;
	}

	uburma_register_client();

	uburma_log_info("uburma module init success.\n");
	return 0;
}

static void __exit uburma_exit(void)
{
	uburma_unregister_client();
	uburma_class_destroy();
	uburma_log_info("uburma module exits.\n");
}

module_init(uburma_init);
module_exit(uburma_exit);

MODULE_DESCRIPTION("Kernel module for urma client");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
