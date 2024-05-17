// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: uburma mmap module
 * Author: Wen Chen
 * Create: 2024-03-18
 * Note:
 * History: 2024-03-18: Create file
 */

#include <linux/version.h>
#include <linux/mmap_lock.h>

#include <linux/sched/mm.h>

#include "uburma_log.h"
#include "uburma_types.h"

void uburma_umap_priv_init(struct uburma_umap_priv *priv,
	struct vm_area_struct *vma)
{
	struct uburma_file *ufile = vma->vm_file->private_data;

	priv->vma = vma;
	vma->vm_private_data = priv;

	mutex_lock(&ufile->umap_mutex);
	list_add(&priv->node, &ufile->umaps_list);
	mutex_unlock(&ufile->umap_mutex);
}

void uburma_unmap_vma_pages(struct uburma_file *ufile)
{
	struct uburma_umap_priv *priv, *next_priv;
	struct mm_struct *mm = NULL;
	struct vm_area_struct *vma;
	int ret;

	lockdep_assert_held(&ufile->cleanup_rwsem);

	while (1) {
		mutex_lock(&ufile->umap_mutex);
		list_for_each_entry_safe(priv, next_priv, &ufile->umaps_list, node) {
			mm = priv->vma->vm_mm;
			ret = mmget_not_zero(mm);
			if (ret != 0) {
				list_del_init(&priv->node);
				mm = NULL;
				continue;
			}
			break;
		}
		mutex_unlock(&ufile->umap_mutex);
		if (!mm)
			return;

		mmap_read_lock(mm);
		mutex_lock(&ufile->umap_mutex);
		list_for_each_entry_safe(priv, next_priv, &ufile->umaps_list, node) {
			vma = priv->vma;
			if (vma->vm_mm != mm)
				continue;
			list_del_init(&priv->node);
			zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
		}
		mutex_unlock(&ufile->umap_mutex);
		mmap_read_unlock(mm);
		mmput(mm);
	}
}

static void uburma_umap_open(struct vm_area_struct *vma)
{
	struct uburma_file *ufile = vma->vm_file->private_data;
	struct uburma_umap_priv *priv;

	if (!down_read_trylock(&ufile->cleanup_rwsem))
		goto out_zap;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		goto out_unlock;

	uburma_umap_priv_init(priv, vma);

	up_read(&ufile->cleanup_rwsem);
	return;

out_unlock:
	up_read(&ufile->cleanup_rwsem);
out_zap:
	vma->vm_private_data = NULL;
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static void uburma_umap_close(struct vm_area_struct *vma)
{
	struct uburma_file *ufile = vma->vm_file->private_data;
	struct uburma_umap_priv *priv = vma->vm_private_data;

	if (!priv)
		return;

	mutex_lock(&ufile->umap_mutex);
	list_del(&priv->node);
	mutex_unlock(&ufile->umap_mutex);
	kfree(priv);
	vma->vm_private_data = NULL;
}

static vm_fault_t uburma_umap_fault(struct vm_fault *vmf)
{
	struct uburma_file *ufile = vmf->vma->vm_file->private_data;
	struct uburma_umap_priv *priv = vmf->vma->vm_private_data;
	vm_fault_t ret = 0;

	if (!priv)
		return VM_FAULT_SIGBUS;

	if (!(vmf->vma->vm_flags & (VM_WRITE | VM_MAYWRITE))) {
		vmf->page = ZERO_PAGE(0);
		get_page(vmf->page);
		return 0;
	}

	mutex_lock(&ufile->umap_mutex);
	if (!ufile->fault_page)
		ufile->fault_page = alloc_pages(vmf->gfp_mask | __GFP_ZERO, 0);

	if (ufile->fault_page) {
		vmf->page = ufile->fault_page;
		get_page(vmf->page);
	} else {
		ret = VM_FAULT_SIGBUS;
	}
	mutex_unlock(&ufile->umap_mutex);

	return ret;
}

static const struct vm_operations_struct g_urma_umap_ops = {
	.open = uburma_umap_open,
	.close = uburma_umap_close,
	.fault = uburma_umap_fault,
};

const struct vm_operations_struct *uburma_get_umap_ops(void)
{
	return (const struct vm_operations_struct *)&g_urma_umap_ops;
}
