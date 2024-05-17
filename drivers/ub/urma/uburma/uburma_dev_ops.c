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
 * Description: uburma device ops file
 * Author: Qian Guoxin
 * Create: 2021-08-04
 * Note:
 * History: 2021-08-04: Create file
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_uobj.h"
#include "uburma_cmd.h"

int uburma_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct uburma_file *file = filp->private_data;
	struct uburma_device *ubu_dev;
	struct ubcore_device *ubc_dev;
	int srcu_idx;
	int ret;

	if (file == NULL || file->ucontext == NULL || file->ubu_dev == NULL) {
		uburma_log_err("can not find ucontext.\n");
		return -EINVAL;
	}

	ubu_dev = file->ubu_dev;
	uburma_cmd_inc(ubu_dev);

	srcu_idx = srcu_read_lock(&ubu_dev->ubc_dev_srcu);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL || ubc_dev->ops == NULL || ubc_dev->ops->mmap == NULL) {
		uburma_log_err("can not find ubcore device.\n");
		ret = -ENODEV;
		goto out;
	}

	ret = ubc_dev->ops->mmap(file->ucontext, vma);

out:
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	uburma_cmd_dec(ubu_dev);
	return ret;
}

void uburma_release_file(struct kref *ref)
{
	struct uburma_file *file = container_of(ref, struct uburma_file, ref);
	int srcu_idx;

	srcu_idx = srcu_read_lock(&file->ubu_dev->ubc_dev_srcu);
	srcu_dereference(file->ubu_dev->ubc_dev, &file->ubu_dev->ubc_dev_srcu);

	srcu_read_unlock(&file->ubu_dev->ubc_dev_srcu, srcu_idx);

	if (atomic_dec_and_test(&file->ubu_dev->refcnt))
		complete(&file->ubu_dev->comp);

	kobject_put(&file->ubu_dev->kobj);
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
	mutex_lock(&ubu_dev->lists_mutex);
	ubc_dev = srcu_dereference(ubu_dev->ubc_dev, &ubu_dev->ubc_dev_srcu);
	if (ubc_dev == NULL || ubc_dev->dev_name == NULL) {
		ret = EIO;
		uburma_log_err("can not find ubcore device.\n");
		goto err;
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
	mutex_init(&file->mutex);
	uburma_init_uobj_context(file);
	filp->private_data = file;

	list_add_tail(&file->list, &ubu_dev->uburma_file_list);
	kobject_get(&ubu_dev->kobj); // Increase reference count for file.

	mutex_unlock(&ubu_dev->lists_mutex);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);

	uburma_log_info("device: %s open succeed.\n", ubc_dev->dev_name);
	return nonseekable_open(inode, filp);

err:
	mutex_unlock(&ubu_dev->lists_mutex);
	srcu_read_unlock(&ubu_dev->ubc_dev_srcu, srcu_idx);
	if (atomic_dec_and_test(&ubu_dev->refcnt))
		complete(&ubu_dev->comp);
	return ret;
}

int uburma_close(struct inode *inode, struct file *filp)
{
	struct uburma_file *file = filp->private_data;

	mutex_lock(&file->mutex);
	uburma_cleanup_uobjs(file, UBURMA_REMOVE_CLOSE);
	if (file->ucontext) {
		ubcore_free_ucontext(file->ubu_dev->ubc_dev, file->ucontext);
		file->ucontext = NULL;
	}
	mutex_unlock(&file->mutex);
	mutex_destroy(&file->mutex);

	mutex_lock(&file->ubu_dev->lists_mutex);
	if (file->is_closed == 0) {
		list_del(&file->list);
		file->is_closed = 1;
	}
	mutex_unlock(&file->ubu_dev->lists_mutex);

	kref_put(&file->ref, uburma_release_file);

	return 0;
}
