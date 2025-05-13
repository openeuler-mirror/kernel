// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/bitmap.h>
#include "common/xsc_core.h"
#include "common/driver.h"
#include "common/xsc_port_ctrl.h"
#include "common/xsc_prgrmmbl_cc_ctrl.h"
#include "common/res_obj.h"

#define XSC_PORT_CTRL_NAME_PRE		"yunsilicon"
#define XSC_PRGRMMBL_CC_CTRL_NAME	"flexcc"
#define XSC_PORT_CTRL_CB_NAME_LEN	15

struct xsc_prgrmmbl_cc_ctrl_reg {
	struct list_head node;
	char name[XSC_PORT_CTRL_CB_NAME_LEN + 1];
	port_prgrmmbl_cc_ctrl_cb cb;
	void *data;
};

static struct list_head g_prgrmmbl_cc_ctrl_cbs = LIST_HEAD_INIT(g_prgrmmbl_cc_ctrl_cbs);
struct mutex g_prgrmmbl_cc_ctrl_cbs_lock;	/* protect programmable cc ctrl node list */

static void xsc_release_port_ctrl_file(struct xsc_port_ctrl_file *file)
{
	struct xsc_bdf_file *bdf_file;
	struct radix_tree_iter iter;
	void **slot;

	xsc_close_bdf_file(file->root_bdf);
	kfree(file->root_bdf);
	spin_lock(&file->bdf_lock);
	radix_tree_for_each_slot(slot, &file->bdf_tree, &iter, 0) {
		bdf_file = (struct xsc_bdf_file *)(*slot);
		xsc_close_bdf_file(bdf_file);
		radix_tree_iter_delete(&file->bdf_tree, &iter, slot);
		kfree(bdf_file);
	}
	spin_unlock(&file->bdf_lock);
}

static int _prgrmmble_cc_ctrl_release(struct inode *inode, struct file *filp)
{
	struct xsc_port_ctrl_file *file = filp->private_data;

	xsc_release_port_ctrl_file(file);
	spin_lock(&file->ctrl->file_lock);
	list_del(&file->file_node);
	spin_unlock(&file->ctrl->file_lock);
	kfree(file);

	return 0;
}

bool xsc_prgrmmble_cc_ctrl_is_supported(struct xsc_core_device *dev)
{
	return xsc_core_is_pf(dev) && xsc_support_hw_feature(dev, XSC_HW_PRGRMMBL_CC_SUPPORT);
}

static int _prgrmmble_cc_ctrl_open(struct inode *inode, struct file *filp)
{
	struct xsc_port_ctrl *ctrl = container_of(inode->i_cdev, struct xsc_port_ctrl, cdev);
	struct xsc_port_ctrl_file *file;

	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return -ENOMEM;

	INIT_RADIX_TREE(&file->bdf_tree, GFP_ATOMIC);
	spin_lock_init(&file->bdf_lock);
	file->ctrl = ctrl;

	file->root_bdf = kzalloc(sizeof(*file->root_bdf), GFP_KERNEL);
	if (!file->root_bdf) {
		kfree(file);
		return -ENOMEM;
	}
	INIT_RADIX_TREE(&file->root_bdf->obj_tree, GFP_ATOMIC);
	spin_lock_init(&file->root_bdf->obj_lock);
	file->root_bdf->xdev = container_of(ctrl, struct xsc_core_device, prgrmmbl_cc_ctrl);

	spin_lock(&ctrl->file_lock);
	list_add_tail(&file->file_node, &ctrl->file_list);
	spin_unlock(&ctrl->file_lock);
	filp->private_data = file;

	xsc_core_info(file->root_bdf->xdev,
		      "process %d open programmable cc ctrl file\n", current->pid);

	return 0;
}

static long _prgrmmbl_cc_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct xsc_prgrmmbl_cc_ctrl_reg *p;
	struct xsc_port_ctrl_file *file;
	struct xsc_bdf_file *bdf_file;
	int err;

	err = TRY_NEXT_CB;
	file = filp->private_data;

	bdf_file = file->root_bdf;
	if (!bdf_file) {
		pr_err("%s: fail to find bdf file\n", __func__);
		return -EFAULT;
	}

	if (!xsc_prgrmmble_cc_ctrl_is_supported(bdf_file->xdev)) {
		xsc_core_err(bdf_file->xdev, "%s: programmable cc is not supported!\n", __func__);
		return err;
	}

	list_for_each_entry(p, &g_prgrmmbl_cc_ctrl_cbs, node) {
		if (p->cb) {
			err = p->cb(bdf_file, cmd, arg, p->data);
			if (err != TRY_NEXT_CB)
				break;
		}
	}

	return err;
}

static const struct file_operations g_prgrmmbl_cc_ctrl_fops = {
	.owner		= THIS_MODULE,
	.open		= _prgrmmble_cc_ctrl_open,
	.unlocked_ioctl = _prgrmmbl_cc_ctrl_ioctl,
	.compat_ioctl   = _prgrmmbl_cc_ctrl_ioctl,
	.release	= _prgrmmble_cc_ctrl_release,
};

int xsc_prgrmmbl_cc_ctrl_dev_add(struct xsc_core_device *dev,
				 struct class *port_ctrl_class, dev_t dev_id)
{
	struct xsc_port_ctrl *ctrl;
	int ret = 0;

	ctrl = &dev->prgrmmbl_cc_ctrl;
	ctrl->devid = dev_id;
	ctrl->cdev.owner = THIS_MODULE;
	INIT_LIST_HEAD(&ctrl->file_list);
	spin_lock_init(&ctrl->file_lock);
	cdev_init(&ctrl->cdev, &g_prgrmmbl_cc_ctrl_fops);
	ret = cdev_add(&ctrl->cdev, ctrl->devid, 1);
	if (ret != 0) {
		xsc_core_err(dev, "failed to add cdev\n");
		kfree(ctrl);
		return -ENOMEM;
	}

	ctrl->device = device_create(port_ctrl_class, NULL, ctrl->devid, NULL,
				     "%s!%s_%04x:%02x:%02x.%x", XSC_PORT_CTRL_NAME_PRE,
				     XSC_PRGRMMBL_CC_CTRL_NAME, pci_domain_nr(dev->pdev->bus),
				     dev->pdev->bus->number,
				     PCI_SLOT(dev->pdev->devfn),
				     PCI_FUNC(dev->pdev->devfn));
	if (IS_ERR(ctrl->device)) {
		xsc_core_err(dev, "failed to create programmable cc control device\n");
		cdev_del(&ctrl->cdev);
		kfree(ctrl);
		return -ENOMEM;
	}

	return 0;
}

int xsc_prgrmmbl_cc_ctrl_dev_del(struct xsc_core_device *dev,
				 struct class *port_ctrl_class, int *dev_id)
{
	struct xsc_port_ctrl *ctrl;
	struct xsc_port_ctrl_file *file, *n;

	ctrl = &dev->prgrmmbl_cc_ctrl;
	if (!ctrl)
		return -EFAULT;

	*dev_id = MINOR(ctrl->devid);
	spin_lock(&ctrl->file_lock);
	list_for_each_entry_safe(file, n, &ctrl->file_list, file_node) {
		xsc_release_port_ctrl_file(file);
		list_del(&file->file_node);
		kfree(file);
	}
	spin_unlock(&ctrl->file_lock);

	device_destroy(port_ctrl_class, ctrl->devid);
	cdev_del(&ctrl->cdev);

	return 0;
}

int xsc_prgrmmbl_cc_ctrl_cb_init(void)
{
	mutex_init(&g_prgrmmbl_cc_ctrl_cbs_lock);
	return 0;
}

void xsc_prgrmmbl_cc_ctrl_cb_fini(void)
{
	struct xsc_prgrmmbl_cc_ctrl_reg *p, *n;

	list_for_each_entry_safe(p, n, &g_prgrmmbl_cc_ctrl_cbs, node) {
		mutex_lock(&g_prgrmmbl_cc_ctrl_cbs_lock);
		list_del(&p->node);
		mutex_unlock(&g_prgrmmbl_cc_ctrl_cbs_lock);
		kfree(p);
	}
}

static struct xsc_prgrmmbl_cc_ctrl_reg *_prgrmmbl_cc_ctrl_cbs_get(const char *name)
{
	struct xsc_prgrmmbl_cc_ctrl_reg *p, *found;

	found = NULL;
	list_for_each_entry(p, &g_prgrmmbl_cc_ctrl_cbs, node) {
		if (strcmp(p->name, name) == 0) {
			found = p;
			break;
		}
	}

	return found;
}

int xsc_prgrmmbl_cc_ctrl_cb_reg(const char *name, port_prgrmmbl_cc_ctrl_cb cb, void *data)
{
	struct xsc_prgrmmbl_cc_ctrl_reg *reg_node;

	if (strlen(name) > XSC_PORT_CTRL_CB_NAME_LEN) {
		pr_err("the name is too long to register to programmable cc control\n");
		return -1;
	}

	reg_node = _prgrmmbl_cc_ctrl_cbs_get(name);
	if (reg_node) {
		pr_err("failed to register a duplicated node\n");
		return -1;
	}

	reg_node = kmalloc(sizeof(*reg_node), GFP_KERNEL);
	if (!reg_node)
		return -1;

	strscpy(reg_node->name, name, sizeof(reg_node->name));
	reg_node->cb = cb;
	reg_node->data = data;
	INIT_LIST_HEAD(&reg_node->node);

	mutex_lock(&g_prgrmmbl_cc_ctrl_cbs_lock);
	list_add_tail(&reg_node->node, &g_prgrmmbl_cc_ctrl_cbs);
	mutex_unlock(&g_prgrmmbl_cc_ctrl_cbs_lock);

	return 0;
}
EXPORT_SYMBOL(xsc_prgrmmbl_cc_ctrl_cb_reg);

void xsc_prgrmmbl_cc_ctrl_cb_dereg(const char *name)
{
	struct xsc_prgrmmbl_cc_ctrl_reg *p, *n;

	list_for_each_entry_safe(p, n, &g_prgrmmbl_cc_ctrl_cbs, node) {
		if (strcmp(p->name, name) == 0) {
			mutex_lock(&g_prgrmmbl_cc_ctrl_cbs_lock);
			list_del(&p->node);
			mutex_unlock(&g_prgrmmbl_cc_ctrl_cbs_lock);
			kfree(p);
			break;
		}
	}
}
EXPORT_SYMBOL(xsc_prgrmmbl_cc_ctrl_cb_dereg);
