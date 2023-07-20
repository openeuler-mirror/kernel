// SPDX-License-Identifier: GPL-2.0
/* Huawei IP notify Protocol Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#include <linux/rwsem.h>
#include <linux/module.h>

#include "ubl.h"
#include "network_mgmt.h"

#define UB_NETWORK_MGMT_MOD_VERSION "1.0"

static struct workqueue_struct *ub_nm_wq;
static DECLARE_RWSEM(ub_nm_dev_rwsem);
static LIST_HEAD(ub_nm_dev_list);

void ub_nm_down_read(void)
{
	down_read(&ub_nm_dev_rwsem);
}

void ub_nm_up_read(void)
{
	up_read(&ub_nm_dev_rwsem);
}

void ub_nm_down_write(void)
{
	down_write(&ub_nm_dev_rwsem);
}

void ub_nm_up_write(void)
{
	up_write(&ub_nm_dev_rwsem);
}

struct list_head *ub_nm_get_dev_list(void)
{
	return &ub_nm_dev_list;
}

static int ub_nm_sysfs_create(struct ub_nm_device *nm_dev)
{
	struct ub_nm_sysfs_context *root_sys_ctx = &nm_dev->sys_ctx;

	root_sys_ctx->nm_root = kobject_create_and_add("ub_network_mgmt",
						       &nm_dev->ndev->dev.kobj);
	if (!root_sys_ctx->nm_root) {
		pr_err("failed to create ub_nm dir.\n");
		return -ENOMEM;
	}

	return 0;
}

static void ub_nm_sysfs_destroy(struct ub_nm_device *nm_dev)
{
	struct ub_nm_sysfs_context *root_sys_ctx = &nm_dev->sys_ctx;

	kobject_put(root_sys_ctx->nm_root);
}

static int ub_nm_add_device(struct net_device *ndev)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev;
	int ret = 0;

	/* check ndev whether is in ub_nm_dev_list */
	ub_nm_down_write();
	list_for_each_entry(nm_dev, dev_list, nm_dev_list)
		if (nm_dev->ndev->ifindex == ndev->ifindex)
			goto out;

	nm_dev = kzalloc(sizeof(*nm_dev), GFP_KERNEL);
	if (!nm_dev) {
		ret = -ENOMEM;
		goto out;
	}

	nm_dev->ndev = ndev;

	ret = ub_nm_sysfs_create(nm_dev);
	if (ret) {
		netdev_err(ndev, "failed to create nm sysfs.\n");
		goto err_nm_sysfs_create;
	}

	list_add_tail(&nm_dev->nm_dev_list, dev_list);
	goto out;

err_nm_sysfs_create:
	kfree(nm_dev);
out:
	ub_nm_up_write();
	return ret;
}

static void ub_nm_del_device(struct net_device *ndev)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev;

	ub_nm_down_write();
	list_for_each_entry(nm_dev, dev_list, nm_dev_list) {
		if (nm_dev->ndev != ndev)
			continue;

		list_del(&nm_dev->nm_dev_list);
		ub_nm_sysfs_destroy(nm_dev);
		kfree(nm_dev);
		break;
	}
	ub_nm_up_write();
}

static void ub_nm_dev_op_handler(struct work_struct *_work)
{
	struct ub_um_device_op_work *dev_op_work =
		container_of(_work, struct ub_um_device_op_work, work);
	enum ub_nm_device_op dev_op = dev_op_work->op;
	struct net_device *ndev = dev_op_work->ndev;
	int ret;

	switch (dev_op) {
	case UB_NM_DEVICE_ADD:
		ret = ub_nm_add_device(ndev);
		if (ret)
			netdev_err(ndev, "failed to add device, ret = %d\n",
				   ret);
		break;
	case UB_NM_DEVICE_DEL:
		ub_nm_del_device(ndev);
		break;
	default:
		break;
	}

	dev_put(ndev);
	kfree(dev_op_work);
}

static int ub_nm_netdev_chain_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct ub_um_device_op_work *dev_op_work;
	enum ub_nm_device_op dev_op;
	struct net_device *ndev;

	ndev = netdev_notifier_info_to_dev((const struct netdev_notifier_info *)ptr);
	if (ndev->type != ARPHRD_UB)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		dev_op = UB_NM_DEVICE_ADD;
		break;
	case NETDEV_UNREGISTER:
		dev_op = UB_NM_DEVICE_DEL;
		break;
	default:
		return NOTIFY_DONE;
	}

	dev_op_work = kzalloc(sizeof(*dev_op_work), GFP_ATOMIC);
	if (!dev_op_work)
		return NOTIFY_DONE;

	INIT_WORK(&dev_op_work->work, ub_nm_dev_op_handler);

	dev_op_work->op = dev_op;
	dev_hold(ndev);
	dev_op_work->ndev = ndev;
	queue_work(ub_nm_wq, &dev_op_work->work);

	return NOTIFY_DONE;
}

static struct notifier_block ub_nm_netdev_chain_nb = {
	.notifier_call = ub_nm_netdev_chain_event
};

/* The network management module tries its best to add all UB devices
 * to ub_nm_dev_list. If ub_nm_dev_list fails to be initialized due
 * to insufficient system memory, some UB devices are not in
 * ub_nm_dev_list. Error logs are generated.
 */
static void ub_nm_dev_init(void)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev;
	struct net_device *ndev;
	struct net *net;
	int ret;

	ub_nm_down_write();
	rtnl_lock();
	down_read(&net_rwsem);
	for_each_net(net) {
		for_each_netdev(net, ndev) {
			if (ndev->type != ARPHRD_UB)
				continue;

			dev_hold(ndev);

			nm_dev = kzalloc(sizeof(*nm_dev), GFP_KERNEL);
			if (!nm_dev)
				goto err_nm_dev_create;

			nm_dev->ndev = ndev;
			ret = ub_nm_sysfs_create(nm_dev);
			if (ret) {
				netdev_err(ndev,
					   "failed to create nm sysfs.\n");
				goto err_nm_sysfs_create;
			}
			list_add_tail(&nm_dev->nm_dev_list,
				      dev_list);
			dev_put(ndev);
		}
	}
	goto out;

err_nm_sysfs_create:
	kfree(nm_dev);
err_nm_dev_create:
	dev_put(ndev);
out:
	up_read(&net_rwsem);
	rtnl_unlock();
	ub_nm_up_write();
}

static void ub_nm_dev_cleanup(void)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev, *tmp;

	ub_nm_down_write();
	list_for_each_entry_safe(nm_dev, tmp, dev_list,
				 nm_dev_list) {
		list_del(&nm_dev->nm_dev_list);
		ub_nm_sysfs_destroy(nm_dev);
		kfree(nm_dev);
	}
	ub_nm_up_write();
}

static int __init ub_nm_init_module(void)
{
	int ret;

	/* alloc ub nm wq */
	ub_nm_wq = create_singlethread_workqueue("ub_nm_wq");
	if (!ub_nm_wq) {
		pr_err("failed to create ub_nm_wq.\n");
		return -ENOMEM;
	}

	ub_nm_dev_init();

	/* register netdev_chain */
	ret = register_netdevice_notifier(&ub_nm_netdev_chain_nb);
	if (ret) {
		pr_err("failed to register netdev notifier chain, ret = %d\n",
		       ret);
		ub_nm_dev_cleanup();
		destroy_workqueue(ub_nm_wq);
		return ret;
	}

	pr_info("ub network mgmt init success.\n");

	return 0;
}
module_init(ub_nm_init_module);

static void __exit ub_nm_exit_module(void)
{
	int ret;

	ret = unregister_netdevice_notifier(&ub_nm_netdev_chain_nb);
	if (ret)
		pr_warn("failed to unregister netdev notifier chain, ret = %d\n",
			ret);

	ub_nm_dev_cleanup();

	destroy_workqueue(ub_nm_wq);

	pr_info("ub network mgmt uninit success.\n");
}
module_exit(ub_nm_exit_module);

MODULE_DESCRIPTION("UB: Network MGMT Driver");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_VERSION(UB_NETWORK_MGMT_MOD_VERSION);
