// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#define pr_fmt(fmt) "hisi_l0: " fmt

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/mempolicy.h>
#include <linux/pfn_t.h>

#include "hisi_l3t.h"

struct l0_vma_data {
	struct page *page;
	unsigned long size;
	int nid;
};

static int get_node_node(struct vm_area_struct *vma)
{
	struct mempolicy *pol;
	nodemask_t *nmask;
	int nid;

	nid = get_vma_policy_node(vma, vma->vm_start, GFP_KERNEL, &pol, &nmask);
	if (pol->mode == MPOL_BIND || pol->mode == MPOL_PREFERRED_MANY)
		nid = first_node(*nmask);

	return nid;
}

static vm_fault_t __l0_pmd_fault(struct vm_fault *vmf)
{
	unsigned long pmd_addr = vmf->address & PMD_MASK;
	struct l0_vma_data *data;
	unsigned long pfn;

	data = vmf->vma->vm_private_data;
	if (!data) {
		pr_err("%s: pid: %d, invalid private data\n", current->comm,
		       current->pid);
		return VM_FAULT_SIGBUS;
	}

	if (PAGE_ALIGN(vmf->vma->vm_end - vmf->vma->vm_start) != data->size) {
		pr_err("%s: pid: %d, invalid vma size, start: %#lx, end: %#lx, size: %#lx\n",
		       current->comm, current->pid, vmf->vma->vm_start,
		       vmf->vma->vm_end, data->size);
		return VM_FAULT_SIGBUS;
	}

	/* if we are outside of the VMA */
	if (pmd_addr < vmf->vma->vm_start ||
			(pmd_addr + PMD_SIZE) > vmf->vma->vm_end)
		return VM_FAULT_SIGBUS;

	pfn = page_to_pfn(data->page) +
		   ((pmd_addr - vmf->vma->vm_start) >> PAGE_SHIFT);

	return vmf_insert_pfn_pmd(vmf, pfn_to_pfn_t(pfn), vmf->flags & FAULT_FLAG_WRITE);
}

static vm_fault_t l0_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	pr_debug("%s: pid: %d, %s (%#lx - %#lx) size = %d\n", current->comm,
		 current->pid,
		 (vmf->flags & FAULT_FLAG_WRITE) ? "write" : "read",
		 vmf->vma->vm_start, vmf->vma->vm_end, pe_size);

	if (pe_size == PE_SIZE_PMD)
		return __l0_pmd_fault(vmf);

	return VM_FAULT_SIGBUS;
}

static void l0_vma_close(struct vm_area_struct *vma)
{
	struct l0_vma_data *data;

	data = (struct l0_vma_data *)vma->vm_private_data;
	if (!data) {
		pr_err("%s: pid: %d, invalid private data\n", current->comm,
		       current->pid);
		return;
	}

	l3t_shared_unlock(data->nid, page_to_pfn(data->page), data->size);
	free_contig_range(page_to_pfn(data->page), data->size >> PAGE_SHIFT);

	kfree(data);
}

static const struct vm_operations_struct l0_vm_ops = {
	.huge_fault = l0_huge_fault,
	.close = l0_vma_close,
};

static int l0_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long cont_size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
	struct l0_vma_data *data;
	int page_cnt, nid, ret;
	struct page *page;

	pr_debug("%s: pid: %d, vma_start: %#lx, vma_end: %#lx vma_flags: %pGv\n",
		current->comm, current->pid, vma->vm_start, vma->vm_end,
		&vma->vm_flags);

	if ((vma->vm_start % PMD_SIZE) || (vma->vm_end % PMD_SIZE))
		return -EINVAL;

	data = kzalloc(sizeof(struct l0_vma_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	page_cnt = cont_size >> PAGE_SHIFT;
	nid = get_node_node(vma);
	page = alloc_contig_pages(page_cnt, GFP_KERNEL, nid, NULL);
	if (!page) {
		ret = -ENOMEM;
		goto free_data;
	}

	ret = l3t_shared_lock(nid, page_to_pfn(page), cont_size);
	if (ret) {
		pr_err("%s: pid: %d, l3t lock failed, ret: %d\n", current->comm,
		       current->pid, ret);
		ret = -ENOMEM;
		goto free_page;
	}

	data->page = page;
	data->size = cont_size;
	data->nid = nid;

	vma->vm_ops = &l0_vm_ops;
	vma->vm_flags |= (VM_MIXEDMAP | VM_DONTCOPY | VM_DONTEXPAND);
	vma->vm_private_data = data;

	return 0;
free_page:
	free_contig_range(page_to_pfn(page), page_cnt);
free_data:
	kfree(data);
	return ret;
}

static const struct file_operations l0_fops = {
	.owner = THIS_MODULE,
	.mmap = l0_mmap,
};

static struct miscdevice l0_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hisi_l0",
	.fops = &l0_fops,
};
module_misc_device(l0_dev);

MODULE_DESCRIPTION("HiSilicon SoC L0 driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ma Wupeng <mawupeng1@huawei.com>");
