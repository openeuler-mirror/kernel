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
#include "uburma_cdev_file.h"
#include "uburma_uobj.h"
#include "uburma_cmd.h"

#define UBURMA_MAX_DEVICE 1024
#define UBURMA_DYNAMIC_MINOR_NUM UBURMA_MAX_DEVICE
#define UBURMA_MODULE_NAME "uburma"
#define UBURMA_DEVNODE_MODE (0666)

static DECLARE_BITMAP(g_dev_bitmap, UBURMA_MAX_DEVICE);

static dev_t g_dynamic_uburma_dev;

static const void *uburma_net_namespace(struct device *dev)
{
	struct uburma_logic_device *ldev = dev_get_drvdata(dev);
	struct uburma_device *ubu_dev;
	struct ubcore_device *ubc_dev;

	if (ldev == NULL || ldev->ubu_dev == NULL || ldev->ubu_dev->ubc_dev == NULL) {
		uburma_log_info("init net %p", ldev);
		return &init_net;
	}

	ubu_dev = ldev->ubu_dev;
	ubc_dev = ubu_dev->ubc_dev;

	if (ubc_dev->transport_type == UBCORE_TRANSPORT_UB) {
		return read_pnet(&ldev->net);
	} else if (ubc_dev->transport_type == UBCORE_TRANSPORT_IP) {
		if (ubc_dev->netdev)
			return dev_net(ubc_dev->netdev);
		else
			return &init_net;
	} else { /* URMA IB device not support namespace yet */
		return &init_net;
	}
}
static char *uburma_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = UBURMA_DEVNODE_MODE;

	return kasprintf(GFP_KERNEL, "uburma/%s", dev_name(dev));
}

static struct class g_uburma_class = {
	.name    = UBURMA_MODULE_NAME,
	.devnode = uburma_devnode,
	.ns_type = &net_ns_type_operations,
	.namespace = uburma_net_namespace
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

static LIST_HEAD(g_uburma_device_list);
static DECLARE_RWSEM(g_uburma_device_rwsem);

static unsigned int g_uburma_net_id;
static LIST_HEAD(g_uburma_net_list);
static DEFINE_SPINLOCK(g_uburma_net_lock);
static DECLARE_RWSEM(g_uburma_net_rwsem);

struct uburma_net {
	possible_net_t net;
	struct list_head node;
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

static int uburma_create_eid_table(struct uburma_logic_device *ldev, struct ubcore_device *ubc_dev)
{
	struct uburma_eid *eid_list;

	eid_list = kcalloc(1, ubc_dev->attr.max_eid_cnt * sizeof(struct uburma_eid), GFP_ATOMIC);
	if (eid_list == NULL)
		return -ENOMEM;

	ldev->eid = eid_list;
	return 0;
}

static void uburma_destroy_eid_table(struct uburma_logic_device *ldev)
{
	if (ldev->eid != NULL) {
		kfree(ldev->eid);
		ldev->eid = NULL;
	}
}

static int uburma_fill_logic_device_attr(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev)
{
	uint32_t e1, e2; /* eid */
	uint16_t f1, f2; /* fe */
	uint8_t p1, p2; /* port */

	if (uburma_create_dev_attr_files(ldev) != 0) {
		uburma_log_err("failed to fill attributes, device:%s.\n", ubc_dev->dev_name);
		return -EPERM;
	}

	/* create /sys/class/uburma/<ubc_dev->dev_name>/port* */
	for (p1 = 0; p1 < ubc_dev->attr.port_cnt; p1++) {
		if (uburma_create_port_attr_files(ldev, ubu_dev, p1) != 0)
			goto err_port_attr;
	}

	/* create /sys/class/uburma/<ubc_dev->dev_name>/fe* */
	for (f1 = 0; f1 < ubc_dev->attr.fe_cnt; f1++) {
		if (uburma_create_fe_attr_files(ldev, ubu_dev, f1) != 0)
			goto err_fe_attr;
	}

	/* create /sys/class/uburma/<ubc_dev->dev_name>/eid* */
	if (uburma_create_eid_table(ldev, ubc_dev) != 0)
		goto err_fe_attr;

	for (e1 = 0; e1 < ubc_dev->attr.max_eid_cnt; e1++) {
		if (uburma_create_eid_attr_files(ldev, e1) != 0)
			goto err_eid_attr;
	}
	return 0;

err_eid_attr:
	for (e2 = 0; e2 < e1; e2++)
		uburma_remove_eid_attr_files(ldev, e2);

	uburma_destroy_eid_table(ldev);
err_fe_attr:
	for (f2 = 0; f2 < f1; f2++)
		uburma_remove_fe_attr_files(ldev, f2);
err_port_attr:
	for (p2 = 0; p2 < p1; p2++)
		uburma_remove_port_attr_files(ldev, p2);

	uburma_remove_dev_attr_files(ldev);
	return -EPERM;
}


static void uburma_unfill_logic_device_attr(struct uburma_logic_device *ldev,
	struct ubcore_device *ubc_dev)
{
	uint32_t e;
	uint16_t f;
	uint8_t p;

	for (e = 0; e < ubc_dev->attr.max_eid_cnt; e++)
		uburma_remove_eid_attr_files(ldev, e);

	uburma_destroy_eid_table(ldev);

	for (f = 0; f < ubc_dev->attr.fe_cnt; f++)
		uburma_remove_fe_attr_files(ldev, f);

	for (p = 0; p < ubc_dev->attr.port_cnt; p++)
		uburma_remove_port_attr_files(ldev, p);

	uburma_remove_dev_attr_files(ldev);
}

static int uburma_device_create(struct uburma_logic_device *ldev,
	struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev, struct net *net)
{
	/* create /sys/class/uburma/<ubc_dev->dev_name> */
	write_pnet(&ldev->net, net);
	ldev->ubu_dev = ubu_dev;

	/* Two devices have same char device devt will cause duplicate file name
	 * error in sysfs_create_link, although they are in different namespaces
	 */
	if (net_eq(net, &init_net))
		ldev->dev = device_create(&g_uburma_class, ubc_dev->dev.parent,
			ubu_dev->cdev.dev, ldev, "%s", ubc_dev->dev_name);
	else
		ldev->dev = device_create(&g_uburma_class, ubc_dev->dev.parent,
			MKDEV(0, 0), ldev, "%s", ubc_dev->dev_name);
	if (IS_ERR(ldev->dev)) {
		uburma_log_err("device create failed, device:%s.\n", ubc_dev->dev_name);
		return -ENOMEM;
	}

	if (uburma_fill_logic_device_attr(ldev, ubu_dev, ubc_dev) != 0) {
		device_unregister(ldev->dev);
		ldev->dev = NULL;
		uburma_log_err("failed to fill attributes, device:%s.\n", ubc_dev->dev_name);
		return -EPERM;
	}

	return 0;
}

static void uburma_device_destroy(struct uburma_logic_device *ldev, struct ubcore_device *ubc_dev)
{
	uburma_unfill_logic_device_attr(ldev, ubc_dev);
	device_unregister(ldev->dev);
	ldev->dev = NULL;
}

static void uburma_remove_one_logic_device(struct uburma_device *ubu_dev, struct net *net)
{
	struct uburma_logic_device *ldev, *tmp;
	struct ubcore_device *ubc_dev;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return;
	}

	if (ubc_dev->transport_type != UBCORE_TRANSPORT_UB) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return;
	}

	mutex_lock(&ubu_dev->ldev_mutex);
	list_for_each_entry_safe(ldev, tmp, &ubu_dev->ldev_list, node) {
		if (net_eq(read_pnet(&ldev->net), net)) {
			uburma_device_destroy(ldev, ubc_dev);
			list_del(&ldev->node);
			kfree(ldev);
			break;
		}
	}
	mutex_unlock(&ubu_dev->ldev_mutex);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
}

static void uburma_remove_logic_devices(struct uburma_device *ubu_dev,
	struct ubcore_device *ubc_dev)
{
	struct uburma_logic_device *ldev, *tmp;

	if (ubc_dev->transport_type != UBCORE_TRANSPORT_UB)
		return;

	mutex_lock(&ubu_dev->ldev_mutex);
	list_for_each_entry_safe(ldev, tmp, &ubu_dev->ldev_list, node) {
		uburma_device_destroy(ldev, ubc_dev);
		list_del(&ldev->node);
		kfree(ldev);
	}
	mutex_unlock(&ubu_dev->ldev_mutex);
}

static int uburma_create_one_logic_device(struct uburma_device *ubu_dev,
	struct ubcore_device *ubc_dev, struct net *net)
{
	struct uburma_logic_device *ldev;
	int ret;

	mutex_lock(&ubu_dev->ldev_mutex);
	list_for_each_entry(ldev, &ubu_dev->ldev_list, node) {
		if (net_eq(read_pnet(&ubu_dev->ldev.net), net)) {
			mutex_unlock(&ubu_dev->ldev_mutex);
			return 0;
		}
	}

	ldev = kzalloc(sizeof(struct uburma_logic_device), GFP_KERNEL);
	if (ldev == NULL) {
		mutex_unlock(&ubu_dev->ldev_mutex);
		return -ENOMEM;
	}

	ret = uburma_device_create(ldev, ubu_dev, ubc_dev, net);
	if (ret) {
		kfree(ldev);
		mutex_unlock(&ubu_dev->ldev_mutex);
		uburma_log_err("add device failed %s in net %u", ubc_dev->dev_name, net->ns.inum);
		return ret;
	}

	list_add_tail(&ldev->node, &ubu_dev->ldev_list);
	mutex_unlock(&ubu_dev->ldev_mutex);
	uburma_log_info("add device %s in net %u", ubc_dev->dev_name, net->ns.inum);
	return 0;
}

static int uburma_add_one_logic_device(struct uburma_device *ubu_dev, struct net *net)
{
	struct ubcore_device *ubc_dev;
	int srcu_idx;
	int ret;

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return 0;
	}

	if (ubc_dev->transport_type != UBCORE_TRANSPORT_UB) {
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		return 0;
	}

	ret = uburma_create_one_logic_device(ubu_dev, ubc_dev, net);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	return ret;
}

static int uburma_copy_logic_devices(struct uburma_device *ubu_dev, struct ubcore_device *ubc_dev)
{
	struct uburma_net *unet;
	int ret = 0;

	if (ubc_dev->transport_type != UBCORE_TRANSPORT_UB)
		return 0;

	down_read(&g_uburma_net_rwsem);
	list_for_each_entry(unet, &g_uburma_net_list, node) {
		if (net_eq(read_pnet(&unet->net), read_pnet(&ubu_dev->ldev.net)))
			continue;
		ret = uburma_create_one_logic_device(ubu_dev, ubc_dev, read_pnet(&unet->net));
		if (ret != 0)
			break;
	}
	up_read(&g_uburma_net_rwsem);

	if (ret)
		uburma_remove_logic_devices(ubu_dev, ubc_dev);

	return ret;
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

	if (uburma_device_create(&ubu_dev->ldev, ubu_dev, ubc_dev, &init_net) != 0) {
		uburma_log_err("device create failed, device:%s.\n", ubc_dev->dev_name);
		goto del_cdev;
	}

	if (uburma_copy_logic_devices(ubu_dev, ubc_dev) != 0) {
		uburma_log_err("copy logic device failed, device:%s.\n", ubc_dev->dev_name);
		goto destroy_device;
	}
	return 0;

destroy_device:
	uburma_device_destroy(&ubu_dev->ldev, ubc_dev);
del_cdev:
	cdev_del(&ubu_dev->cdev);
free_bit:
	clear_bit(ubu_dev->devnum, g_dev_bitmap);
	return -EPERM;
}

static void uburma_list_add_device(struct uburma_device *ubu_dev)
{
	down_write(&g_uburma_device_rwsem);
	list_add_tail(&ubu_dev->node, &g_uburma_device_list);
	up_write(&g_uburma_device_rwsem);
}

static void uburma_list_remove_device(struct uburma_device *ubu_dev)
{
	down_write(&g_uburma_device_rwsem);
	list_del_init(&ubu_dev->node);
	up_write(&g_uburma_device_rwsem);
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

	mutex_init(&ubu_dev->ldev_mutex);
	INIT_LIST_HEAD(&ubu_dev->ldev_list);

	rcu_assign_pointer(ubu_dev->ubc_dev, ubc_dev);

	if (uburma_cdev_create(ubu_dev, ubc_dev) != 0) {
		uburma_log_err("can not create cdev.\n");
		goto err;
	}

	ubcore_set_client_ctx_data(ubc_dev, &g_urma_client, ubu_dev);
	uburma_list_add_device(ubu_dev);
	return 0;

err:
	if (atomic_dec_and_test(&ubu_dev->refcnt))
		complete(&ubu_dev->comp);

	wait_for_completion(&ubu_dev->comp);
	mutex_destroy(&ubu_dev->ldev_mutex);
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

	uburma_list_remove_device(ubu_dev);
	uburma_remove_logic_devices(ubu_dev, ubc_dev);
	uburma_device_destroy(&ubu_dev->ldev, ubc_dev);
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

	/*
	 * to do class_create_file
	 */

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

static void uburma_net_exit(struct net *net)
{
	struct uburma_net *unet = net_generic(net, g_uburma_net_id);
	struct uburma_device *ubu_dev;
	unsigned long flags;

	if (unet == NULL)
		return;

	uburma_log_info("net exit %u", net->ns.inum);
	down_write(&g_uburma_net_rwsem);
	spin_lock_irqsave(&g_uburma_net_lock, flags);
	if (list_empty(&unet->node)) {
		spin_unlock_irqrestore(&g_uburma_net_lock, flags);
		up_write(&g_uburma_net_rwsem);
		return;
	}
	list_del_init(&unet->node);
	spin_unlock_irqrestore(&g_uburma_net_lock, flags);
	up_write(&g_uburma_net_rwsem);

	down_read(&g_uburma_device_rwsem);
	list_for_each_entry(ubu_dev, &g_uburma_device_list, node) {
		uburma_remove_one_logic_device(ubu_dev, net);
	}
	up_read(&g_uburma_device_rwsem);
}

static int uburma_net_init(struct net *net)
{
	struct uburma_net *unet = net_generic(net, g_uburma_net_id);
	struct uburma_device *ubu_dev;
	unsigned long flags;
	int ret = 0;

	if (unet == NULL)
		return 0;

	uburma_log_info("net init %u", net->ns.inum);
	write_pnet(&unet->net, net);
	if (net_eq(net, &init_net)) {
		INIT_LIST_HEAD(&unet->node);
		return 0;
	}

	spin_lock_irqsave(&g_uburma_net_lock, flags);
	list_add_tail(&unet->node, &g_uburma_net_list);
	spin_unlock_irqrestore(&g_uburma_net_lock, flags);

	down_read(&g_uburma_device_rwsem);
	list_for_each_entry(ubu_dev, &g_uburma_device_list, node) {
		down_read(&g_uburma_net_rwsem);
		ret = uburma_add_one_logic_device(ubu_dev, net);
		up_read(&g_uburma_net_rwsem);
		if (ret)
			break;
	}
	up_read(&g_uburma_device_rwsem);
	if (ret)
		uburma_net_exit(net);

	/* return ret will cause error starting a container */
	return 0;
}

static struct pernet_operations g_uburma_net_ops = {
	.init = uburma_net_init,
	.exit = uburma_net_exit,
	.id = &g_uburma_net_id,
	.size = sizeof(struct uburma_net)
};

static int __init uburma_init(void)
{
	int ret;

	ret = uburma_class_create();
	if (ret != 0) {
		uburma_log_err("uburma dev create failed.\n");
		return ret;
	}

	uburma_register_client();

	ret = register_pernet_device(&g_uburma_net_ops);
	if (ret != 0) {
		uburma_unregister_client();
		uburma_class_destroy();
		uburma_log_err("register_pernet_device failed");
		return ret;
	}
	uburma_log_info("uburma module init success.\n");
	return 0;
}

static void __exit uburma_exit(void)
{
	unregister_pernet_device(&g_uburma_net_ops);
	uburma_unregister_client();
	uburma_class_destroy();
	uburma_log_info("uburma module exits.\n");
}

module_init(uburma_init);
module_exit(uburma_exit);

MODULE_DESCRIPTION("Kernel module for urma client");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
