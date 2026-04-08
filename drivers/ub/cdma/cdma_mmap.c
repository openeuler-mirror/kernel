// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt

#include <linux/version.h>
#include <linux/sched/mm.h>
#include "cdma_mmap.h"

void cdma_umap_priv_init(struct cdma_umap_priv *priv,
			struct vm_area_struct *vma)
{
	struct cdma_file *cfile = vma->vm_file->private_data;

	priv->vma = vma;
	vma->vm_private_data = priv;

	mutex_lock(&cfile->umap_mutex);
	list_add(&priv->node, &cfile->umaps_list);
	mutex_unlock(&cfile->umap_mutex);
}

/* thanks to drivers/infiniband/core/ib_core_uverbs.c */
void cdma_unmap_vma_pages(struct cdma_file *cfile)
{
	struct cdma_umap_priv *priv, *next_priv;
	struct mm_struct *mm = NULL;
	struct vm_area_struct *vma;
	int ret;

	while (1) {
		mm = NULL;
		mutex_lock(&cfile->umap_mutex);
		list_for_each_entry_safe(priv, next_priv, &cfile->umaps_list, node) {
			mm = priv->vma->vm_mm;
			ret = mmget_not_zero(mm);
			if (!ret) {
				list_del_init(&priv->node);
				mm = NULL;
				continue;
			}
			break;
		}
		mutex_unlock(&cfile->umap_mutex);
		if (!mm)
			return;

		mmap_read_lock(mm);
		mutex_lock(&cfile->umap_mutex);
		list_for_each_entry_safe(priv, next_priv, &cfile->umaps_list, node) {
			vma = priv->vma;
			if (vma->vm_mm != mm)
				continue;
			list_del_init(&priv->node);
			zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
		}
		mutex_unlock(&cfile->umap_mutex);
		mmap_read_unlock(mm);

		mmput(mm);
	}
}

static void cdma_umap_open(struct vm_area_struct *vma)
{
	struct cdma_umap_priv *priv;

	priv = kzalloc(sizeof(struct cdma_umap_priv), GFP_KERNEL);
	if (!priv)
		goto out_zap;

	cdma_umap_priv_init(priv, vma);

	return;

out_zap:
	vma->vm_private_data = NULL;
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static void cdma_umap_close(struct vm_area_struct *vma)
{
	struct cdma_umap_priv *priv = (struct cdma_umap_priv *)vma->vm_private_data;
	struct cdma_file *cfile = (struct cdma_file *)vma->vm_file->private_data;

	if (!priv)
		return;

	mutex_lock(&cfile->umap_mutex);
	list_del(&priv->node);
	mutex_unlock(&cfile->umap_mutex);
	kfree(priv);
	vma->vm_private_data = NULL;

	pr_info("cdma umap close success.\n");
}

static vm_fault_t cdma_umap_fault(struct vm_fault *vmf)
{
	struct cdma_umap_priv *priv = (struct cdma_umap_priv *)vmf->vma->vm_private_data;
	struct cdma_file *cfile = (struct cdma_file *)vmf->vma->vm_file->private_data;
	vm_fault_t ret = 0;

	if (!priv)
		return VM_FAULT_SIGBUS;

	if (!(vmf->vma->vm_flags & (VM_WRITE | VM_MAYWRITE))) {
		vmf->page = ZERO_PAGE(0);
		get_page(vmf->page);
		return 0;
	}

	mutex_lock(&cfile->umap_mutex);
	if (!cfile->fault_page)
		cfile->fault_page = alloc_pages(vmf->gfp_mask | __GFP_ZERO, 0);

	if (cfile->fault_page) {
		vmf->page = cfile->fault_page;
		get_page(vmf->page);
	} else {
		ret = VM_FAULT_SIGBUS;
	}
	mutex_unlock(&cfile->umap_mutex);

	return ret;
}

static int cdma_umap_remap(struct vm_area_struct *vma)
{
	pr_err("cdma umap remap is not permitted.\n");
	return -EINVAL;
}

static int cdma_umap_can_split(struct vm_area_struct *vma, unsigned long addr)
{
	pr_err("cdma umap split is not permitted.\n");
	return -EINVAL;
}

static const struct vm_operations_struct g_cdma_umap_ops = {
	.open = cdma_umap_open,
	.close = cdma_umap_close,
	.fault = cdma_umap_fault,
	.mremap = cdma_umap_remap,
	.may_split = cdma_umap_can_split,
};

const struct vm_operations_struct *cdma_get_umap_ops(void)
{
	return (const struct vm_operations_struct *)&g_cdma_umap_ops;
}
