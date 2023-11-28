// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <common/xsc_core.h>
#include <common/driver.h>
#include <common/xsc_port_ctrl.h>

#include "fw/xsc_tbm.h"

#define XSC_PORT_CTRL_MAX		256
#define XSC_PORT_CTRL_NAME_PRE		"yunsilicon"
#define XSC_PORT_CTRL_NAME		"port_ctrl"
#define XSC_PORT_CTRL_CB_NAME_LEN	15

struct xsc_port_ctrl_reg {
	struct list_head node;
	char name[XSC_PORT_CTRL_CB_NAME_LEN + 1];
	port_ctrl_cb cb;
	void *data;
};

static dev_t g_port_ctrl_root_dev;
static struct class *g_port_ctrl_class;
static int g_port_ctrl_dev_cnt;
static struct list_head g_port_ctrl_cbs = LIST_HEAD_INIT(g_port_ctrl_cbs);
struct mutex g_port_ctrl_cbs_lock;

static int _port_ctrl_open(struct inode *inode, struct file *filp)
{
	struct xsc_port_ctrl *ctrl
		= container_of(inode->i_cdev, struct xsc_port_ctrl, cdev);

	filp->private_data = ctrl;

	return 0;
}

static bool is_db_ofst(struct xsc_core_device *xdev, unsigned long offset)
{
	if (offset == (xdev->regs.tx_db & PAGE_MASK))
		return true;
	else if (offset == (xdev->regs.rx_db & PAGE_MASK))
		return true;
	else if (offset == (xdev->regs.complete_db & PAGE_MASK))
		return true;
	else if (offset == (xdev->regs.complete_reg & PAGE_MASK))
		return true;
	return false;
}

static int _port_ctrl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	resource_size_t reg_base;
	unsigned long start = (unsigned long)vma->vm_start;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	struct xsc_port_ctrl *ctrl;
	struct xsc_core_device *xdev;

	ctrl = filp->private_data;
	xdev = container_of(ctrl, struct xsc_core_device, port_ctrl);

	if (is_db_ofst(xdev, offset))
		reg_base = (pci_resource_start(xdev->pdev, xdev->bar_num) + (offset & PAGE_MASK));
	else
		return -EINVAL;

#if (CHIP_VERSION_H == 0x100) && (CHIP_HOTFIX_NUM >= 0x17)
	reg_base = xsc_core_is_pf(xdev) ? reg_base - 0xA0000000 : reg_base;
#else
	reg_base = reg_base - 0xA0000000;
#endif

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	if (remap_pfn_range(vma, start, (reg_base >> PAGE_SHIFT), size, vma->vm_page_prot)) {
		pr_err("[%s:%d] remap_pfn_range err\n", __func__, __LINE__);
		return -1;
	}

	return 0;
}

static long _port_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct xsc_port_ctrl_reg *p;
	struct xsc_port_ctrl *ctrl;
	struct xsc_core_device *xdev;
	struct xsc_ioctl_hdr __user *user_hdr;

	ctrl = filp->private_data;
	xdev = container_of(ctrl, struct xsc_core_device, port_ctrl);
	user_hdr = (struct xsc_ioctl_hdr __user *)arg;

	list_for_each_entry(p, &g_port_ctrl_cbs, node) {
		if (p->cb)
			p->cb(xdev, cmd, user_hdr, p->data);
	}

	return 0;
}

static const struct file_operations g_port_ctrl_fops = {
	.owner		= THIS_MODULE,
	.open		= _port_ctrl_open,
	.mmap		= _port_ctrl_mmap,
	.unlocked_ioctl = _port_ctrl_ioctl,
	.compat_ioctl   = _port_ctrl_ioctl,
};

static struct xsc_port_ctrl_reg *_port_ctrl_cbs_get(const char *name)
{
	struct xsc_port_ctrl_reg *p, *found;

	found = NULL;
	list_for_each_entry(p, &g_port_ctrl_cbs, node) {
		if (strcmp(p->name, name) == 0) {
			found = p;
			break;
		}
	}

	return found;
}

static void _port_ctrl_data_fini(void)
{
	class_destroy(g_port_ctrl_class);
	unregister_chrdev_region(g_port_ctrl_root_dev, XSC_PORT_CTRL_MAX);
}

static int _port_ctrl_data_init(void)
{
	int ret;
	int major_devid;

	ret = alloc_chrdev_region(&g_port_ctrl_root_dev, 0, XSC_PORT_CTRL_MAX,
			XSC_PORT_CTRL_NAME_PRE);
	if (ret < 0) {
		pr_err("%s cant't get major id\n", XSC_PORT_CTRL_NAME_PRE);
		return -1;
	}

	major_devid = MAJOR(g_port_ctrl_root_dev);
	pr_info("requested major_devid %d\n", major_devid);

	g_port_ctrl_class = class_create(THIS_MODULE, XSC_PORT_CTRL_NAME_PRE);
	if (IS_ERR(g_port_ctrl_class)) {
		pr_err("failed to call create class witch name %s\n",
			XSC_PORT_CTRL_NAME_PRE);
		unregister_chrdev_region(g_port_ctrl_root_dev, XSC_PORT_CTRL_MAX);
		return -1;
	}

	g_port_ctrl_dev_cnt = 0;

	return 0;
}

static void _port_ctrl_dev_del(struct xsc_core_device *dev)
{
	struct xsc_port_ctrl *ctrl;

	ctrl = &dev->port_ctrl;
	if (!ctrl)
		return;

	device_destroy(g_port_ctrl_class, ctrl->devid);
	cdev_del(&ctrl->cdev);
}

static int _port_ctrl_dev_add(struct xsc_core_device *dev)
{
	struct xsc_port_ctrl *ctrl;
	int ret;

	if (g_port_ctrl_dev_cnt >= XSC_PORT_CTRL_MAX) {
		xsc_core_err(dev, "too many port control devices\n");
		return -ENOMEM;
	}

	ctrl = &dev->port_ctrl;
	ctrl->devid = g_port_ctrl_root_dev + g_port_ctrl_dev_cnt;
	ctrl->cdev.owner = THIS_MODULE;
	cdev_init(&ctrl->cdev, &g_port_ctrl_fops);
	ret = cdev_add(&ctrl->cdev, ctrl->devid, 1);
	if (ret != 0) {
		xsc_core_err(dev, "failed to add cdev\n");
		kfree(ctrl);
		return -ENOMEM;
	}

	ctrl->device = device_create(g_port_ctrl_class, NULL, ctrl->devid, NULL,
		"%s!%s_%02x:%02x.%x", XSC_PORT_CTRL_NAME_PRE, XSC_PORT_CTRL_NAME,
		dev->bus_id, dev->dev_id, dev->func_id);
	if (IS_ERR(ctrl->device)) {
		xsc_core_err(dev, "failed to create port control device\n");
		cdev_del(&ctrl->cdev);
		kfree(ctrl);
		return -ENOMEM;
	}

	g_port_ctrl_dev_cnt++;

	return 0;
}

static void _port_ctrl_cb_fini(void)
{
	struct xsc_port_ctrl_reg *p, *n;

	list_for_each_entry_safe(p, n, &g_port_ctrl_cbs, node) {
		mutex_lock(&g_port_ctrl_cbs_lock);
		list_del(&p->node);
		mutex_unlock(&g_port_ctrl_cbs_lock);
		kfree(p);
	}
}

static int _port_ctrl_cb_init(void)
{
	mutex_init(&g_port_ctrl_cbs_lock);

	return 0;
}

static void _port_ctrl_dev_flush(void)
{
}

void xsc_port_ctrl_fini(void)
{
	_port_ctrl_dev_flush();
	_port_ctrl_data_fini();
	_port_ctrl_cb_fini();
}

int xsc_port_ctrl_init(void)
{
	int ret;

	ret = _port_ctrl_data_init();
	if (ret != 0) {
		pr_err("failed to initialize port ctrl data\n");
		return -1;
	}

	ret = _port_ctrl_cb_init();
	if (ret != 0) {
		pr_err("failed to initialize port ctrl cb\n");
		_port_ctrl_data_fini();
		return -1;
	}

	return 0;
}

void xsc_port_ctrl_remove(struct xsc_core_device *dev)
{
#ifndef RUN_WITH_PSV
	if (xsc_core_is_pf(dev))
#else
	if (1)
#endif
		_port_ctrl_dev_del(dev);
}

int xsc_port_ctrl_probe(struct xsc_core_device *dev)
{
	int ret = 0;
#ifndef RUN_WITH_PSV
	if (xsc_core_is_pf(dev)) {
#else
	if (1) {
#endif
		ret = _port_ctrl_dev_add(dev);
		if (ret != 0)
			xsc_core_err(dev, "failed to add new port control device\n");
	}

	return ret;
}

int xsc_port_ctrl_cb_reg(const char *name, port_ctrl_cb cb, void *data)
{
	struct xsc_port_ctrl_reg *reg_node;

	if (strlen(name) > XSC_PORT_CTRL_CB_NAME_LEN) {
		pr_err("the name is too long to register to port control\n");
		return -1;
	}

	reg_node = _port_ctrl_cbs_get(name);
	if (reg_node) {
		pr_err("failed to register a duplicated node\n");
		return -1;
	}

	reg_node = kmalloc(sizeof(struct xsc_port_ctrl_reg), GFP_KERNEL);
	if (!reg_node)
		return -1;

	strlcpy(reg_node->name, name, sizeof(reg_node->name));
	reg_node->cb = cb;
	reg_node->data = data;
	INIT_LIST_HEAD(&reg_node->node);

	mutex_lock(&g_port_ctrl_cbs_lock);
	list_add_tail(&reg_node->node, &g_port_ctrl_cbs);
	mutex_unlock(&g_port_ctrl_cbs_lock);

	return 0;
}
EXPORT_SYMBOL(xsc_port_ctrl_cb_reg);

void xsc_port_ctrl_cb_dereg(const char *name)
{
	struct xsc_port_ctrl_reg *p, *n;

	list_for_each_entry_safe(p, n, &g_port_ctrl_cbs, node) {
		if (strcmp(p->name, name) == 0) {
			mutex_lock(&g_port_ctrl_cbs_lock);
			list_del(&p->node);
			mutex_unlock(&g_port_ctrl_cbs_lock);
			kfree(p);
			break;
		}
	}
}
EXPORT_SYMBOL(xsc_port_ctrl_cb_dereg);

