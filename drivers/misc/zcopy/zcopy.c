// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

struct zcopy_cdev {
	struct cdev chrdev;
	dev_t dev;
	int major;
	struct class *dev_class;
	struct device *dev_device;
};

static struct zcopy_cdev z_cdev;

long zcopy_ioctl(struct file *file, unsigned int type, unsigned long ptr)
{
	return 0;
}

static const struct file_operations zcopy_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = zcopy_ioctl,
};

static int register_device_zcopy(void)
{
	int ret;

	ret = alloc_chrdev_region(&z_cdev.dev, 0, 1, "zcopy");
	if (ret < 0)
		goto err_out;

	z_cdev.major = MAJOR(z_cdev.dev);

	cdev_init(&z_cdev.chrdev, &zcopy_fops);
	ret = cdev_add(&z_cdev.chrdev, z_cdev.dev, 1);
	if (ret < 0)
		goto err_unregister_chrdev;

	z_cdev.dev_class = class_create(THIS_MODULE, "zcopy");
	if (IS_ERR(z_cdev.dev_class)) {
		ret = PTR_ERR(z_cdev.dev_class);
		goto err_cdev_del;
	}

	z_cdev.dev_device = device_create(z_cdev.dev_class, NULL,
						MKDEV(z_cdev.major, 0), NULL, "zdax");
	if (IS_ERR(z_cdev.dev_device)) {
		ret = PTR_ERR(z_cdev.dev_device);
		goto err_class_destroy;
	}

	return 0;

err_class_destroy:
	class_destroy(z_cdev.dev_class);
err_cdev_del:
	cdev_del(&z_cdev.chrdev);
err_unregister_chrdev:
	unregister_chrdev_region(z_cdev.dev, 1);
err_out:
	return ret;
}

static void unregister_device_zcopy(void)
{
	device_destroy(z_cdev.dev_class, MKDEV(z_cdev.major, 0));
	class_destroy(z_cdev.dev_class);
	cdev_del(&z_cdev.chrdev);
	unregister_chrdev_region(z_cdev.dev, 1);
}

static int __init zcopy_init(void)
{
	int ret;

	ret = register_device_zcopy();
	if (ret)
		return ret;

	return 0;
}

static void __exit zcopy_exit(void)
{
	unregister_device_zcopy();
}

module_init(zcopy_init);
module_exit(zcopy_exit);

MODULE_AUTHOR("liumingrui <liumingrui@huawei.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PAGEATTACH: A zero-copy data transfer mechanism");
