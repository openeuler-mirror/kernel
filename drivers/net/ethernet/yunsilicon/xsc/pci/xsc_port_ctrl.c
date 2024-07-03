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
#include "common/xsc_core.h"
#include "common/driver.h"
#include "common/xsc_port_ctrl.h"
#include "common/res_obj.h"


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
struct mutex g_port_ctrl_cbs_lock;	/* protect port ctrl node list */

static int _port_ctrl_open(struct inode *inode, struct file *filp)
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
	file->root_bdf->xdev = container_of(ctrl, struct xsc_core_device, port_ctrl);

	spin_lock(&ctrl->file_lock);
	list_add_tail(&file->file_node, &ctrl->file_list);
	spin_unlock(&ctrl->file_lock);
	filp->private_data = file;

	xsc_core_info(file->root_bdf->xdev, "process %d open port ctrl file\n", current->pid);

	return 0;
}

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

static int _port_ctrl_release(struct inode *inode, struct file *filp)
{
	struct xsc_port_ctrl_file *file = filp->private_data;

	xsc_release_port_ctrl_file(file);
	spin_lock(&file->ctrl->file_lock);
	list_del(&file->file_node);
	spin_unlock(&file->ctrl->file_lock);
	kfree(file);

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
	u64 addr;
	u32 db_type;
	u32 domain = 0;
	u32 bus;
	u32 devfn;
	struct xsc_port_ctrl_file *file;
	struct xsc_core_device *xdev;
	struct xsc_core_device *rl_xdev;
	u32 bdf;

	file = filp->private_data;
	xdev = container_of(file->ctrl, struct xsc_core_device, port_ctrl);

	xsc_core_dbg(xdev, "_port_ctrl_map:offset=%lx\n", offset);

	bdf = offset >> 32;
	db_type = bdf & 0x0000000f;
	devfn = (bdf >> 4) & 0x000000ff;
	bus = (bdf >> 12) & 0x000000ff;

	xsc_core_dbg(xdev, "bus=%u,devfn=%u,db_type=%u\n", bus, devfn, db_type);

	if (bdf != 0) {
		rl_xdev = xsc_pci_get_xdev_by_bus_and_slot(domain, bus, devfn);
		if (!rl_xdev)
			return -1;

		if (db_type == XSC_MMAP_MSG_SQDB) {
			addr = rl_xdev->regs.tx_db;
		} else if (db_type == XSC_MMAP_MSG_RQDB) {
			addr = rl_xdev->regs.rx_db;
		} else if (db_type == XSC_MMAP_MSG_CQDB) {
			addr = rl_xdev->regs.complete_db;
		} else if (db_type == XSC_MMAP_MSG_ARM_CQDB) {
			addr = rl_xdev->regs.complete_reg;
		} else {
			pr_err("[%s:%d] mmap err\n", __func__, __LINE__);
			return -1;
		}
	} else {
		rl_xdev = xdev;
		if (is_db_ofst(xdev, offset))
			addr = offset;
		else
			return -EINVAL;
	}

	xsc_core_dbg(xdev, "tx_db=%llx,rx_db=%llx,cq_db=%llx,cq_reg=%llx\n",
		     rl_xdev->regs.tx_db, rl_xdev->regs.rx_db,
		     rl_xdev->regs.complete_db, rl_xdev->regs.complete_reg);

	reg_base = (pci_resource_start(rl_xdev->pdev, rl_xdev->bar_num) + (addr & PAGE_MASK));

	if (xdev->chip_ver_h == 0x100)
		reg_base = xsc_core_is_pf(rl_xdev) ? reg_base - 0xA0000000 : reg_base;
	else
		reg_base = reg_base - 0xA0000000;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	if (remap_pfn_range(vma, start, (reg_base >> PAGE_SHIFT), size, vma->vm_page_prot)) {
		pr_err("[%s:%d] remap_pfn_range err\n", __func__, __LINE__);
		return -1;
	}

	return 0;
}

static inline struct xsc_bdf_file *get_bdf_file(struct xsc_port_ctrl_file *file,
						struct xsc_ioctl_hdr *hdr)
{
	struct xsc_core_device *xdev;
	struct xsc_bdf_file *bdf_file;
	struct xsc_core_device *rl_xdev;
	unsigned long key;

	xdev = container_of(file->ctrl, struct xsc_core_device, port_ctrl);
	xsc_core_dbg(xdev, "domain=%x, bus=%x, devfn=%x\n", hdr->domain, hdr->bus, hdr->devfn);
	if ((hdr->domain == 0 && hdr->bus == 0 && hdr->devfn == 0) ||
	    (hdr->domain == pci_domain_nr(xdev->pdev->bus) &&
	    hdr->bus == xdev->pdev->bus->number &&
	    hdr->devfn == xdev->pdev->devfn))
		return file->root_bdf;

	key = bdf_to_key(hdr->domain, hdr->bus, hdr->devfn);
	spin_lock(&file->bdf_lock);
	bdf_file = radix_tree_lookup(&file->bdf_tree, key);
	spin_unlock(&file->bdf_lock);
	if (bdf_file) {
		xsc_core_dbg(bdf_file->xdev, "find the bdf file: %lx\n", bdf_file->key);
		return bdf_file;
	}

	rl_xdev = xsc_pci_get_xdev_by_bus_and_slot(hdr->domain, hdr->bus, hdr->devfn);
	if (!rl_xdev) {
		xsc_core_err(bdf_file->xdev, "fail to get xdev:domain=%x, bus=%x, devfn=%x\n",
			     hdr->domain, hdr->bus, hdr->devfn);
		return NULL;
	}

	bdf_file = kzalloc(sizeof(*bdf_file), GFP_KERNEL);
	if (!bdf_file)
		return NULL;

	bdf_file->key = key;
	INIT_RADIX_TREE(&bdf_file->obj_tree, GFP_ATOMIC);
	spin_lock_init(&bdf_file->obj_lock);
	bdf_file->xdev = rl_xdev;
	radix_tree_preload(GFP_KERNEL);
	spin_lock(&file->bdf_lock);
	radix_tree_insert(&file->bdf_tree, key, bdf_file);
	spin_unlock(&file->bdf_lock);
	radix_tree_preload_end();
	xsc_core_dbg(rl_xdev, "bdf file not exist, create it and add to port ctrl file\n");

	return bdf_file;
}

static long _port_ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct xsc_port_ctrl_reg *p;
	struct xsc_port_ctrl_file *file;
	struct xsc_ioctl_hdr __user *user_hdr;
	struct xsc_bdf_file *bdf_file;
	struct xsc_ioctl_hdr hdr;
	int err;

	file = filp->private_data;
	user_hdr = (struct xsc_ioctl_hdr __user *)arg;
	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err) {
		pr_err("%s: fail to copy from user hdr\n", __func__);
		return err;
	}

	bdf_file = get_bdf_file(file, &hdr);
	if (!bdf_file) {
		pr_err("%s: fail to find bdf file\n", __func__);
		return -EFAULT;
	}

	list_for_each_entry(p, &g_port_ctrl_cbs, node) {
		if (p->cb) {
			err = p->cb(bdf_file, cmd, user_hdr, p->data);
			if (err != TRY_NEXT_CB)
				break;
		}
	}

	return err;
}

static const struct file_operations g_port_ctrl_fops = {
	.owner		= THIS_MODULE,
	.open		= _port_ctrl_open,
	.mmap		= _port_ctrl_mmap,
	.unlocked_ioctl = _port_ctrl_ioctl,
	.compat_ioctl   = _port_ctrl_ioctl,
	.release	= _port_ctrl_release,
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

	g_port_ctrl_class = class_create(XSC_PORT_CTRL_NAME_PRE);
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
	struct xsc_port_ctrl_file *file, *n;

	ctrl = &dev->port_ctrl;
	if (!ctrl)
		return;

	spin_lock(&ctrl->file_lock);
	list_for_each_entry_safe(file, n, &ctrl->file_list, file_node) {
		xsc_release_port_ctrl_file(file);
		list_del(&file->file_node);
		kfree(file);
	}
	spin_unlock(&ctrl->file_lock);

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
	INIT_LIST_HEAD(&ctrl->file_list);
	spin_lock_init(&ctrl->file_lock);
	cdev_init(&ctrl->cdev, &g_port_ctrl_fops);
	ret = cdev_add(&ctrl->cdev, ctrl->devid, 1);
	if (ret != 0) {
		xsc_core_err(dev, "failed to add cdev\n");
		kfree(ctrl);
		return -ENOMEM;
	}

	ctrl->device = device_create(g_port_ctrl_class, NULL, ctrl->devid, NULL,
				     "%s!%s_%02x:%02x.%x", XSC_PORT_CTRL_NAME_PRE,
				     XSC_PORT_CTRL_NAME, dev->pdev->bus->number,
				     PCI_SLOT(dev->pdev->devfn),
				     PCI_FUNC(dev->pdev->devfn));
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

static void xsc_release_bdf_file(struct xsc_core_device *dev)
{
	struct xsc_core_device *pf_dev;
	int domain;
	unsigned int bus;
	unsigned int devfn;
	struct xsc_port_ctrl_file *file, *n;
	struct xsc_bdf_file *bdf_file;
	unsigned long key;

	if (!dev->pdev->physfn)    /*for vf passthrough vm*/
		return;

	pf_dev = pci_get_drvdata(dev->pdev->physfn);
	domain = pci_domain_nr(dev->pdev->bus);
	bus = dev->pdev->bus->number;
	devfn = dev->pdev->devfn;
	key = bdf_to_key(domain, bus, devfn);
	xsc_core_dbg(dev, "%x %x %x removed\n", domain, bus, devfn);

	spin_lock(&pf_dev->port_ctrl.file_lock);
	list_for_each_entry_safe(file, n, &pf_dev->port_ctrl.file_list, file_node) {
		spin_lock(&file->bdf_lock);
		bdf_file = radix_tree_delete(&file->bdf_tree, key);
		spin_unlock(&file->bdf_lock);
		if (!bdf_file)
			continue;
		xsc_close_bdf_file(bdf_file);
		kfree(bdf_file);
	}
	spin_unlock(&pf_dev->port_ctrl.file_lock);
}

void xsc_port_ctrl_remove(struct xsc_core_device *dev)
{
	if (xsc_core_is_pf(dev))
		_port_ctrl_dev_del(dev);
	else
		xsc_release_bdf_file(dev);
}

int xsc_port_ctrl_probe(struct xsc_core_device *dev)
{
	int ret = 0;

	if (xsc_core_is_pf(dev)) {
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

	reg_node = kmalloc(sizeof(*reg_node), GFP_KERNEL);
	if (!reg_node)
		return -1;

	strscpy(reg_node->name, name, sizeof(reg_node->name));
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

