// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: uburma device ops file
 * Author: Qian Guoxin
 * Create: 2021-08-04
 * Note:
 * History: 2021-08-04: Create file
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "ub/urma/ubcore_types.h"
#include "ub/urma/ubcore_uapi.h"

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_uobj.h"
#include "uburma_cmd.h"
#include "uburma_mmap.h"

static void uburma_mmu_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct uburma_mn *ub_mn = container_of(mn, struct uburma_mn, mn);
	struct uburma_file *file =
		container_of(ub_mn, struct uburma_file, ub_mn);
	struct uburma_device *ubu_dev = file->ubu_dev;
	struct ubcore_ucontext *ucontext = NULL;
	struct ubcore_device *ubc_dev;
	int srcu_idx;

	uburma_log_debug("Start mmu release uobjs and ucontext\n");
	if (ub_mn->mm != mm || !ub_mn->mm) {
		uburma_log_debug("mm already released.\n");
		return;
	}
	ub_mn->mm = NULL;

	if (!ubu_dev) {
		uburma_log_err("ubu dev is null.\n");
		return;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);

	down_write(&file->ucontext_rwsem);
	ucontext = file->ucontext;
	uburma_cleanup_uobjs(file, UBURMA_REMOVE_CLOSE);
	if (ucontext) {
		uburma_log_info("Start ubcore free ucontext.\n");
		if (ubc_dev) {
			file->ucontext = NULL;
			ubcore_free_ucontext(ubc_dev, ucontext);
		}
	}
	up_write(&file->ucontext_rwsem);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	uburma_log_debug("Release uobjs and ucontext\n");
}

static const struct mmu_notifier_ops uburma_mm_notifier_ops = {
	.release = uburma_mmu_release,
};

void uburma_unregister_mmu(struct uburma_file *file)
{
	struct uburma_mn *ub_mn = &file->ub_mn;
	struct mm_struct *mm = ub_mn->mm;

	if (!mm)
		return;

	file->ub_mn.mm = NULL;
	mmu_notifier_unregister(&file->ub_mn.mn, mm);
}

int uburma_register_mmu(struct uburma_file *file)
{
	struct uburma_mn *ub_mn = &file->ub_mn;
	int ret = 0;

	ub_mn->mm = current->mm;
	ub_mn->mn.ops = &uburma_mm_notifier_ops;
	ret = mmu_notifier_register(&ub_mn->mn, current->mm);
	if (ret) {
		ub_mn->mm = NULL;
		return ret;
	}

	return 0;
}

int uburma_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct uburma_file *file = filp->private_data;
	struct uburma_device *ubu_dev;
	struct ubcore_device *ubc_dev;
	struct uburma_umap_priv *priv;
	int srcu_idx;
	int ret;

	if (!file || !file->ucontext || !file->ubu_dev) {
		uburma_log_debug("can not find ucontext.\n");
		return -EINVAL;
	}

	ubu_dev = file->ubu_dev;
	uburma_cmd_inc(ubu_dev);

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev || !ubc_dev->ops || !ubc_dev->ops->mmap) {
		uburma_log_debug("can not find ubcore device.\n");
		ret = -ENODEV;
		goto out;
	}

	vma->vm_ops = uburma_get_umap_ops();
	ret = ubc_dev->ops->mmap(file->ucontext, vma);
	if (ret != 0)
		goto out;

	if (!down_read_trylock(&file->cleanup_rwsem))
		goto out;
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto unlock_read;
	}
	uburma_umap_priv_init(priv, vma);

unlock_read:
	up_read(&file->cleanup_rwsem);
out:
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	uburma_cmd_dec(ubu_dev);
	return ret;
}

void uburma_release_file(struct kref *ref)
{
	struct uburma_file *file = container_of(ref, struct uburma_file, ref);
	struct ubcore_device *ubc_dev;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&file->ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(file->ubu_dev->ubc_dev,
				   &file->ubu_dev->ubc_dev_srcu);
	if (ubc_dev && !ubc_dev->ops->disassociate_ucontext &&
	    ubc_dev->ops->owner)
		module_put(ubc_dev->ops->owner);

	srcu_read_unlock(&file->ubu_dev->ubc_dev_srcu, srcu_idx);

	uburma_unregister_mmu(file);
	if (atomic_dec_and_test(&file->ubu_dev->refcnt))
		complete(&file->ubu_dev->comp);

	kobject_put(&file->ubu_dev->kobj);
	if (file->fault_page)
		__free_pages(file->fault_page, 0);
	mutex_destroy(&file->umap_mutex);
	kfree(file);
}

int uburma_open(struct inode *inode, struct file *filp)
{
	struct uburma_device *ubu_dev;
	struct ubcore_device *ubc_dev;
	struct uburma_file *file;
	int srcu_idx;
	int ret;

	ubu_dev = container_of(inode->i_cdev, struct uburma_device, cdev);
	if (!atomic_inc_not_zero(&ubu_dev->refcnt)) {
		uburma_log_err("device was not ready.\n");
		return -ENXIO;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		ret = EIO;
		uburma_log_err("can not find ubcore device.\n");
		goto err;
	}

	if (!ubc_dev->ops->disassociate_ucontext &&
	    ubc_dev->ops->owner) {
		if (!try_module_get(ubc_dev->ops->owner)) {
			ret = -ENODEV;
			goto err;
		}
	}

	file = kzalloc(sizeof(struct uburma_file), GFP_KERNEL);
	if (!file) {
		ret = -ENOMEM;
		uburma_log_err("can not alloc memory.\n");
		goto err;
	}

	file->ubu_dev = ubu_dev;
	file->ucontext = NULL;
	kref_init(&file->ref);
	init_rwsem(&file->ucontext_rwsem);
	uburma_init_uobj_context(file);
	mutex_init(&file->umap_mutex);
	INIT_LIST_HEAD(&file->umaps_list);
	filp->private_data = file;
	ret = uburma_register_mmu(file);
	if (ret != 0) {
		uburma_log_err("fail to register mmu ret:%u\n", ret);
		kfree(file);
		goto err;
	}

	kobject_get(&ubu_dev->kobj); // Increase reference count for file.
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);

	mutex_lock(&ubu_dev->uburma_file_list_mutex);
	list_add_tail(&file->list, &ubu_dev->uburma_file_list);
	mutex_unlock(&ubu_dev->uburma_file_list_mutex);

	return nonseekable_open(inode, filp);

err:
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	if (atomic_dec_and_test(&ubu_dev->refcnt))
		complete(&ubu_dev->comp);
	return ret;
}

int uburma_close(struct inode *inode, struct file *filp)
{
	struct uburma_file *file = filp->private_data;
	struct uburma_device *ubu_dev = file->ubu_dev;
	struct ubcore_ucontext *ucontext = NULL;
	struct ubcore_device *ubc_dev;
	int srcu_idx;

	if (!ubu_dev) {
		uburma_log_err("ubu dev is null.\n");
		return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		uburma_log_info("ubcore device release in another proccess.\n");
		srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
		kref_put(&file->ref, uburma_release_file);
		return 0;
	}

	mutex_lock(&ubu_dev->uburma_file_list_mutex);
	if (!list_empty_careful(&file->list))
		list_del_init(&file->list);
	mutex_unlock(&ubu_dev->uburma_file_list_mutex);

	down_write(&file->ucontext_rwsem);
	ucontext = file->ucontext;
	uburma_cleanup_uobjs(file, UBURMA_REMOVE_CLOSE);
	if (ucontext) {
		uburma_log_info("Start ubcore free ucontext.\n");
		file->ucontext = NULL;
		ubcore_free_ucontext(ubc_dev, ucontext);
	}
	up_write(&file->ucontext_rwsem);

	uburma_log_debug("device: %s close.\n", ubc_dev->dev_name);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);

	kref_put(&file->ref, uburma_release_file);

	return 0;
}
