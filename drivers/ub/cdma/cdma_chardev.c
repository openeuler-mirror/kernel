// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt
#define dev_fmt pr_fmt

#include <linux/fs.h>
#include <ub/ubus/ubus.h>
#include "cdma_cmd.h"
#include "cdma_ioctl.h"
#include "cdma_context.h"
#include "cdma_chardev.h"
#include "cdma_jfs.h"
#include "cdma_types.h"
#include "cdma_uobj.h"
#include "cdma.h"
#include "cdma_mmap.h"

#define CDMA_DEVICE_NAME "cdma/dev"

struct cdma_num_manager {
	struct idr idr;
	spinlock_t lock;
};

static struct cdma_num_manager cdma_num_mg = {
	.idr = IDR_INIT(cdma_num_mg.idr),
	.lock = __SPIN_LOCK_UNLOCKED(cdma_num_mg.lock),
};

static void cdma_num_free(struct cdma_dev *cdev)
{
	spin_lock(&cdma_num_mg.lock);
	idr_remove(&cdma_num_mg.idr, cdev->chardev.dev_num);
	spin_unlock(&cdma_num_mg.lock);
}

static inline u64 cdma_get_mmap_idx(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff >> MAP_INDEX_SHIFT) & MAP_INDEX_MASK;
}

static inline int cdma_get_mmap_cmd(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff & MAP_COMMAND_MASK);
}

static int cdma_num_alloc(struct cdma_dev *cdev)
{
#define CDMA_START 0
#define CDMA_END 0xffff
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&cdma_num_mg.lock);
	id = idr_alloc(&cdma_num_mg.idr, cdev, CDMA_START, CDMA_END, GFP_NOWAIT);
	spin_unlock(&cdma_num_mg.lock);
	idr_preload_end();

	return id;
}

static long cdma_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
#define CDMA_MAX_CMD_SIZE 8192
	struct cdma_file *cfile = (struct cdma_file *)file->private_data;
	struct cdma_ioctl_hdr hdr = { 0 };
	int ret;

	if (!cfile->cdev || cfile->cdev->status >= CDMA_SUSPEND) {
		pr_info("ioctl cdev is invalid.\n");
		return -ENODEV;
	}
	cdma_cmd_inc(cfile->cdev);

	if (cmd == CDMA_SYNC) {
		ret = copy_from_user(&hdr, (void *)arg, sizeof(hdr));
		if (ret || hdr.args_len > CDMA_MAX_CMD_SIZE) {
			pr_err("copy user ret = %d, input parameter len = %u.\n",
				ret, hdr.args_len);
			cdma_cmd_dec(cfile->cdev);
			return -EINVAL;
		}
		ret = cdma_cmd_parse(cfile, &hdr);
		cdma_cmd_dec(cfile->cdev);
		return ret;
	}

	pr_err("invalid ioctl command, command = %u.\n", cmd);
	cdma_cmd_dec(cfile->cdev);
	return -ENOIOCTLCMD;
}

static int cdma_remap_check_jfs_id(struct cdma_file *cfile, u32 jfs_id)
{
	struct cdma_dev *cdev = cfile->cdev;
	struct cdma_jfs *jfs;
	int ret = -EINVAL;

	spin_lock(&cdev->jfs_table.lock);
	jfs = idr_find(&cdev->jfs_table.idr_tbl.idr, jfs_id);
	if (!jfs) {
		spin_unlock(&cdev->jfs_table.lock);
		dev_err(cdev->dev, "check failed, jfs_id = %u not exist.\n",
			jfs_id);
		return ret;
	}

	if (cfile->uctx != jfs->base_jfs.ctx) {
		dev_err(cdev->dev, "check failed, jfs_id = %u, uctx invalid\n",
			jfs_id);
		spin_unlock(&cdev->jfs_table.lock);
		return -EINVAL;
	}
	spin_unlock(&cdev->jfs_table.lock);

	return 0;
}

static int cdma_remap_pfn_range(struct cdma_file *cfile, struct vm_area_struct *vma)
{
#define JFC_DB_UNMAP_BOUND 1
	struct cdma_dev *cdev = cfile->cdev;
	resource_size_t db_addr;
	u64 address;
	u32 jfs_id;
	u32 cmd;

	if (cdev->status >= CDMA_SUSPEND) {
		dev_warn(cdev->dev, "cdev is resetting.\n");
		return -EBUSY;
	}

	db_addr = cdev->db_base;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	cmd = cdma_get_mmap_cmd(vma);
	switch (cmd) {
	case CDMA_MMAP_JFC_PAGE:
		if (io_remap_pfn_range(vma, vma->vm_start,
				       jfc_arm_mode > JFC_DB_UNMAP_BOUND ?
				       (uint64_t)db_addr >> PAGE_SHIFT :
				       page_to_pfn(cdev->arm_db_page),
				       PAGE_SIZE, vma->vm_page_prot)) {
			dev_err(cdev->dev, "remap jfc page fail.\n");
			return -EAGAIN;
		}
		break;
	case CDMA_MMAP_JETTY_DSQE:
		jfs_id = cdma_get_mmap_idx(vma);
		if (cdma_remap_check_jfs_id(cfile, jfs_id)) {
			dev_err(cdev->dev, "mmap failed, invalid jfs_id = %u\n",
				jfs_id);
			return -EINVAL;
		}

		address = (uint64_t)db_addr + CDMA_JETTY_DSQE_OFFSET + jfs_id * CDMA_HW_PAGE_SIZE;

		if (io_remap_pfn_range(vma, vma->vm_start, address >> PAGE_SHIFT,
				       PAGE_SIZE, vma->vm_page_prot)) {
			dev_err(cdev->dev, "remap jetty page failed.\n");
			return -EAGAIN;
		}
		break;
	default:
		dev_err(cdev->dev,
			"mmap failed, cmd(%u) is not supported.\n", cmd);
		return -EINVAL;
	}

	return 0;
}

static int cdma_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct cdma_file *cfile = (struct cdma_file *)file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct cdma_umap_priv *priv;
	int ret;

	if (!cfile->cdev || cfile->cdev->status >= CDMA_SUSPEND) {
		pr_info("mmap cdev is invalid.\n");
		return -ENODEV;
	}

	if (size != PAGE_SIZE) {
		pr_err("expect size 0x%lx, but got 0x%lx\n", PAGE_SIZE, size);
		return -EINVAL;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	vma->vm_ops = cdma_get_umap_ops();
	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_WIPEONFORK | VM_IO);

	mutex_lock(&cfile->ctx_mutex);
	ret = cdma_remap_pfn_range(cfile, vma);
	if (ret) {
		mutex_unlock(&cfile->ctx_mutex);
		kfree(priv);
		return ret;
	}
	mutex_unlock(&cfile->ctx_mutex);

	cdma_umap_priv_init(priv, vma);

	return 0;
}

static void cdma_mmu_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct cdma_mn *mn_notifier = container_of(mn, struct cdma_mn, mn);
	struct cdma_file *cfile = container_of(mn_notifier, struct cdma_file, mn_notifier);

	if (mn_notifier->mm != mm || mn_notifier->mm == NULL) {
		pr_info("mm already released.\n");
		return;
	}
	mn_notifier->mm = NULL;

	mutex_lock(&cfile->ctx_mutex);
	cdma_cleanup_context_uobj(cfile, CDMA_REMOVE_CLOSE);
	if (cfile->uctx)
		cdma_cleanup_context_res(cfile->uctx);
	cfile->uctx = NULL;
	mutex_unlock(&cfile->ctx_mutex);
}

static const struct mmu_notifier_ops cdma_mm_notifier_ops = {
	.release = cdma_mmu_release
};

static int cdma_register_mmu(struct cdma_file *file)
{
	struct cdma_mn *mn_notifier = &file->mn_notifier;
	int ret;

	mn_notifier->mm = current->mm;
	mn_notifier->mn.ops = &cdma_mm_notifier_ops;
	ret = mmu_notifier_register(&mn_notifier->mn, current->mm);
	if (ret)
		mn_notifier->mm = NULL;

	return ret;
}

static void cdma_unregister_mmu(struct cdma_file *cfile)
{
	struct cdma_mn *mn_notifier = &cfile->mn_notifier;
	struct mm_struct *mm = mn_notifier->mm;

	if (!mm)
		return;

	cfile->mn_notifier.mm = NULL;
	mmu_notifier_unregister(&cfile->mn_notifier.mn, mm);
}

static int cdma_open(struct inode *inode, struct file *file)
{
	struct cdma_chardev *chardev;
	struct cdma_file *cfile;
	struct cdma_dev *cdev;
	int ret;

	chardev = container_of(inode->i_cdev, struct cdma_chardev, cdev);
	cdev = container_of(chardev, struct cdma_dev, chardev);

	if (cdev->status >= CDMA_SUSPEND) {
		dev_warn(cdev->dev, "cdev is resetting.\n");
		return -EBUSY;
	}

	cfile = kzalloc(sizeof(struct cdma_file), GFP_KERNEL);
	if (!cfile)
		return -ENOMEM;

	ret = cdma_register_mmu(cfile);
	if (ret) {
		dev_err(cdev->dev, "register mmu failed, ret = %d.\n", ret);
		kfree(cfile);
		return ret;
	}

	cdma_init_uobj_idr(cfile);
	mutex_lock(&cdev->file_mutex);
	cfile->cdev = cdev;
	cfile->uctx = NULL;
	kref_init(&cfile->ref);
	file->private_data = cfile;
	mutex_init(&cfile->ctx_mutex);
	list_add_tail(&cfile->list, &cdev->file_list);
	mutex_init(&cfile->umap_mutex);
	INIT_LIST_HEAD(&cfile->umaps_list);
	nonseekable_open(inode, file);
	mutex_unlock(&cdev->file_mutex);

	return 0;
}

static int cdma_close(struct inode *inode, struct file *file)
{
	struct cdma_file *cfile = (struct cdma_file *)file->private_data;
	struct cdma_dev *cdev;

	mutex_lock(&g_cdma_reset_mutex);

	cdev = cfile->cdev;
	if (!cdev) {
		mutex_unlock(&g_cdma_reset_mutex);
		kref_put(&cfile->ref, cdma_release_file);
		inode->i_cdev = NULL;
		return 0;
	}

	mutex_lock(&cdev->file_mutex);
	list_del(&cfile->list);
	mutex_unlock(&cdev->file_mutex);

	mutex_lock(&cfile->ctx_mutex);
	cdma_cleanup_context_uobj(cfile, CDMA_REMOVE_CLOSE);
	if (cfile->uctx)
		cdma_cleanup_context_res(cfile->uctx);
	cfile->uctx = NULL;

	mutex_unlock(&cfile->ctx_mutex);
	mutex_unlock(&g_cdma_reset_mutex);
	kref_put(&cfile->ref, cdma_release_file);
	pr_info("cdma close success.\n");

	return 0;
}

static const struct file_operations cdma_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = cdma_ioctl,
	.mmap = cdma_mmap,
	.open = cdma_open,
	.release = cdma_close,
};

void cdma_destroy_chardev(struct cdma_dev *cdev)
{
	struct cdma_chardev *chardev = &cdev->chardev;

	if (!chardev->dev)
		return;

	device_destroy(cdma_cdev_class, chardev->devno);
	cdev_del(&chardev->cdev);
	unregister_chrdev_region(chardev->devno, CDMA_MAX_DEVICES);
	cdma_num_free(cdev);
}

int cdma_create_chardev(struct cdma_dev *cdev)
{
	struct cdma_chardev *chardev = &cdev->chardev;
	int ret;

	chardev->dev_num = cdma_num_alloc(cdev);
	if (chardev->dev_num < 0) {
		dev_err(cdev->dev, "alloc dev_num failed, ret = %d\n", chardev->dev_num);
		return -ENOMEM;
	}

	ret = snprintf(chardev->name, sizeof(chardev->name), "%s.%d",
		       CDMA_DEVICE_NAME, chardev->dev_num);
	if (ret < 0) {
		dev_err(cdev->dev, "sprintf failed in create cdma chardev\n");
		goto num_free;
	}

	ret = alloc_chrdev_region(&chardev->devno, 0, CDMA_MAX_DEVICES,
				  chardev->name);
	if (ret) {
		dev_err(cdev->dev, "alloc chrdev region failed, ret = %d\n", ret);
		goto num_free;
	}

	cdev_init(&chardev->cdev, &cdma_ops);
	ret = cdev_add(&chardev->cdev, chardev->devno, CDMA_MAX_DEVICES);
	if (ret) {
		dev_err(cdev->dev, "cdev add failed, ret = %d\n", ret);
		goto chrdev_unregister;
	}

	chardev->dev = device_create(cdma_cdev_class, NULL, chardev->devno,
				     NULL, "%s", chardev->name);
	if (IS_ERR(chardev->dev)) {
		ret = PTR_ERR(chardev->dev);
		dev_err(cdev->dev, "create device failed, ret = %d\n", ret);
		goto cdev_delete;
	}

	dev_info(cdev->dev, "cdma create chardev: %s success\n", chardev->name);
	return 0;

cdev_delete:
	cdev_del(&chardev->cdev);
chrdev_unregister:
	unregister_chrdev_region(chardev->devno, CDMA_MAX_DEVICES);
num_free:
	cdma_num_free(cdev);
	return ret;
}

void cdma_release_file(struct kref *ref)
{
	struct cdma_file *cfile = container_of(ref, struct cdma_file, ref);

	if (cfile->fault_page)
		__free_pages(cfile->fault_page, 0);
	cdma_unregister_mmu(cfile);
	mutex_destroy(&cfile->umap_mutex);
	mutex_destroy(&cfile->ctx_mutex);
	idr_destroy(&cfile->idr);
	kfree(cfile);
}
