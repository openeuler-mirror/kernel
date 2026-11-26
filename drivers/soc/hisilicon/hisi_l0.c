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
#include <linux/page_ref.h>

#include "hisi_l3t.h"

/* max size for l0 mmap */
#define HISI_L0_MAX_SIZE (256UL << 20)

struct l0_vma_data {
	struct page *page;
	unsigned long size;
	int nid;
	refcount_t refcnt;
};

static int get_node_node(struct vm_area_struct *vma, nodemask_t *nmask)
{
	struct mempolicy *pol;
	nodemask_t *pol_nmask;
	int nid;

	nid = get_vma_policy_node(vma, vma->vm_start, GFP_KERNEL, &pol,
				  &pol_nmask);
	/*
	 * An out-of-range nid is fed to node_zonelist() unchecked, so
	 * fall back to the local node.
	 */
	if (pol->mode == MPOL_BIND) {
		nid = first_node(*pol_nmask);
		if (nid >= MAX_NUMNODES) {
			nodes_clear(*nmask);
			nid = numa_node_id();
		} else {
			*nmask = *pol_nmask;
		}
	} else {
		/* Soft policies keep their fallback. */
		if (pol->mode == MPOL_PREFERRED_MANY)
			nid = first_node(*pol_nmask);
		if (nid < 0 || nid >= MAX_NUMNODES)
			nid = numa_node_id();
	}

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

/*
 * A poisoned tail must not return to the buddy allocator inside its
 * compound block: the bulk free path only checks the head, so the
 * page would be handed out again.  Each PMD is a compound page of its
 * own, so keeping the one PMD that holds the poison costs 2MB, and
 * the range is logged so it can be quarantined by hand.
 */
static bool l0_pmd_has_poison(struct page *head, unsigned long *poisoned)
{
	unsigned long nr_pages = PMD_SIZE >> PAGE_SHIFT;
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		if (PageHWPoison(head + i)) {
			*poisoned = page_to_pfn(head + i);
			return true;
		}
	}

	return false;
}

static void l0_free_block(struct l0_vma_data *data)
{
	unsigned long poisoned;
	int i, pmd_nr;

	/*
	 * The block stays a valid compound page until the last
	 * put_page(), so a GUP unpin may free it instead.
	 */
	pmd_nr = data->size >> PMD_SHIFT;
	for (i = 0; i < pmd_nr; i++) {
		struct page *p = data->page + i * (PMD_SIZE >> PAGE_SHIFT);

		if (l0_pmd_has_poison(p, &poisoned)) {
			pr_info("keep pmd at pfn %#lx, holds poisoned pfn %#lx\n",
				page_to_pfn(p), poisoned);
			continue;
		}

		put_page(p);
	}
}

/*
 * Duplicated vmas (fork, mremap rollback) share data; only the
 * last close may release the block.
 */
static void l0_vma_open(struct vm_area_struct *vma)
{
	struct l0_vma_data *data = vma->vm_private_data;

	if (!data) {
		pr_err("%s: pid: %d, invalid private data\n", current->comm,
		       current->pid);
		return;
	}

	refcount_inc(&data->refcnt);
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

	if (!refcount_dec_and_test(&data->refcnt))
		return;

	l3t_shared_unlock(data->nid, page_to_pfn(data->page), data->size);
	l0_free_block(data);

	kfree(data);
}

static int l0_mremap(struct vm_area_struct *vma)
{
	pr_err("mremap for l0 is not supported\n");

	return -EINVAL;
}

static int l0_may_split(struct vm_area_struct *vma, unsigned long addr)
{
	pr_err("l0 may not be split\n");

	return -EINVAL;
}

static const struct vm_operations_struct l0_vm_ops = {
	.huge_fault = l0_huge_fault,
	.open = l0_vma_open,
	.close = l0_vma_close,
	.split = l0_may_split,
	.mremap = l0_mremap,
};

static int l0_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long cont_size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
	struct l0_vma_data *data;
	int page_cnt, nid, ret, i, pmd_nr;
	struct page *page;
	nodemask_t nmask;

	pr_debug("%s: pid: %d, vma_start: %#lx, vma_end: %#lx vma_flags: %pGv\n",
		current->comm, current->pid, vma->vm_start, vma->vm_end,
		&vma->vm_flags);

	if ((vma->vm_start % PMD_SIZE) || (vma->vm_end % PMD_SIZE))
		return -EINVAL;

	if (cont_size >= HISI_L0_MAX_SIZE)
		return -EINVAL;

	data = kzalloc(sizeof(struct l0_vma_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	page_cnt = cont_size >> PAGE_SHIFT;
	/*
	 * BIND fills the mask.  Soft policies pass NULL
	 * and keep the fallback.
	 */
	nodes_clear(nmask);
	nid = get_node_node(vma, &nmask);
	page = alloc_contig_pages(page_cnt, GFP_KERNEL, nid,
				  nodes_empty(nmask) ? NULL : &nmask);
	if (!page) {
		ret = -ENOMEM;
		goto free_data;
	}

	/*
	 * The allocation path never zeroes these pages, so clear the
	 * previous owner's data.  Yields under mmap_write_lock.
	 */
	for (i = 0; i < page_cnt; i++) {
		clear_highpage(page + i);
		cond_resched();
	}

	nid = page_to_nid(page);
	ret = l3t_shared_lock(nid, page_to_pfn(page), cont_size);
	if (ret) {
		pr_err("%s: pid: %d, l3t lock failed, ret: %d\n", current->comm,
		       current->pid, ret);
		goto free_page;
	}

	/*
	 * One compound page per PMD so pin and put_page() both land on
	 * the head.  Drop the tails' refcount 1 from split_map_pages()
	 * or check_free_page() rejects the page at free time.
	 */
	pmd_nr = cont_size >> PMD_SHIFT;
	for (i = 0; i < pmd_nr; i++) {
		struct page *p = page + i * (PMD_SIZE >> PAGE_SHIFT);
		int j;

		prep_compound_page(p, PMD_SHIFT - PAGE_SHIFT);
		for (j = 1; j < (PMD_SIZE >> PAGE_SHIFT); j++)
			set_page_count(p + j, 0);
	}

	data->page = page;
	data->size = cont_size;
	data->nid = nid;
	refcount_set(&data->refcnt, 1);

	vma->vm_ops = &l0_vm_ops;
	/*
	 * A first fault on a pmd_none entry reaches .huge_fault
	 * only while the VMA is THP-eligible.  The vma has no
	 * .fault handler, so a PTE-level fault would SIGBUS.
	 */
	vma->vm_flags |= (VM_MIXEDMAP | VM_DONTCOPY | VM_DONTEXPAND |
			  VM_HUGEPAGE);
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
	.name = "hisi_soc_cache_mgmt",
	.fops = &l0_fops,
	.mode = 0600,
};
module_misc_device(l0_dev);

MODULE_VERSION("1.0");
MODULE_DESCRIPTION("HiSilicon SoC L0 driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ma Wupeng <mawupeng1@huawei.com>");
