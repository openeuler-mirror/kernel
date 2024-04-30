// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "hinic3_rdma.h"
#include "hmm_umem.h"

#ifndef ROCE_SERVICE
static void hmm_umemsg_release(struct device *device, struct hmm_umem *hmm_umem, int dirty)
{
	struct scatterlist *sg = NULL;
	struct page *page = NULL;
	int i;

	if (hmm_umem->nmap > 0)
		dma_unmap_sg(device, hmm_umem->sg_head.sgl, hmm_umem->npages, DMA_BIDIRECTIONAL);

	for_each_sg(hmm_umem->sg_head.sgl, sg, hmm_umem->npages, i) {
		page = sg_page(sg);
		if (!PageDirty(page) && hmm_umem->writable && dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}

	sg_free_table(&hmm_umem->sg_head);
}

/**
 * hmm_umem_get - Pin and DMA map userspace memory.
 *
 * If access flags indicate ODP memory, avoid pinning. Instead, stores
 * the mm for future page fault handling in conjunction with MMU notifiers.
 *
 * @context: userspace context to pin memory for
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: RDMA_IB_ACCESS_xxx flags for memory being pinned
 * @dmasync: flush in-flight DMA when the memory region is written
 */
struct hmm_umem *hmm_umem_get(struct device *device, unsigned long addr,
	size_t size, int access, int dmasync)
{
	int ret;
	int i;
	struct hmm_umem *hmem = NULL;
	struct page **page_list = NULL;
	struct vm_area_struct **vma_list = NULL;
	unsigned long locked_pages;
	unsigned long lock_limit;
	unsigned long current_base;
	unsigned long npages;

#ifdef HAVE_STRUCT_DMA_ATTRS
	DEFINE_DMA_ATTRS(dma_attrs);
#else
	unsigned long dma_attrs = 0;
#endif
	struct scatterlist *sg = NULL, *sg_list_start = NULL;
	int need_release = 0;
#ifdef HAVE_GET_USER_PAGES_GUP_FLAGS
	unsigned int gup_flags = FOLL_WRITE;
#endif

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((addr + size) < addr) || PAGE_ALIGN(addr + size) < (addr + size))
		return ERR_PTR(-EINVAL);

	if (can_do_mlock() == 0)
		return ERR_PTR(-EPERM);

	hmem = kzalloc(sizeof(*hmem), GFP_KERNEL);
	if (hmem == NULL)
		return ERR_PTR(-ENOMEM);

	hmem->context = kzalloc(sizeof(*(hmem->context)), GFP_KERNEL);
	if ((hmem->context) == NULL) {
		kfree(hmem);
		return ERR_PTR(-ENOMEM);
	}
	hmem->context->device = device;
	hmem->length = size;
	hmem->address = addr;
	hmem->page_shift = PAGE_SHIFT;
	/*
	 * We ask for writable memory if any of the following
	 * access flags are set.  "Local write" and "remote write"
	 * obviously require write access.  "Remote atomic" can do
	 * things like fetch and add, which will modify memory, and
	 * "MW bind" can change permissions by binding a window.
	 */
	hmem->writable = !!(access & (RDMA_IB_ACCESS_LOCAL_WRITE | RDMA_IB_ACCESS_REMOTE_WRITE |
		RDMA_IB_ACCESS_REMOTE_ATOMIC | RDMA_IB_ACCESS_MW_BIND));

	if ((access & RDMA_IB_ACCESS_ON_DEMAND) != 0) {
		kfree(hmem->context);
		kfree(hmem);
		dev_err(device, "[HMM, ERR] %s(%d): don't support odp\n", __func__, __LINE__);
		return ERR_PTR(-ENOMEM);
	}
	hmem->odp_data = NULL;

	/* We assume the memory is from hugetlb until proved otherwise */
	hmem->hugetlb = 1;
	page_list = (struct page **)__get_free_page(GFP_KERNEL);
	if (page_list == NULL) {
		kfree(hmem->context);
		kfree(hmem);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * if we can't alloc the vma_list, it's not so bad;
	 * just assume the memory is not hugetlb memory
	 */
	vma_list = (struct vm_area_struct **)__get_free_page(GFP_KERNEL);
	if (vma_list == NULL)
		hmem->hugetlb = 0;

	npages = hmm_umem_num_pages(hmem);
	mmap_write_lock(current->mm);
	locked_pages = npages + atomic64_read(&current->mm->pinned_vm);
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if ((locked_pages > lock_limit) && !capable(CAP_IPC_LOCK)) {
		ret = -ENOMEM;
		goto out;
	}
	current_base = addr & PAGE_MASK;
	if (npages == 0 || npages > UINT_MAX) {
		ret = -EINVAL;
		goto out;
	}
	ret = sg_alloc_table(&hmem->sg_head, (unsigned int)npages, GFP_KERNEL);
	if (ret != 0)
		goto out;

#ifdef HAVE_GET_USER_PAGES_GUP_FLAGS
	if (hmem->writable == 0)
		gup_flags |= FOLL_FORCE;
#endif

	need_release = 1;
	sg_list_start = hmem->sg_head.sgl;

	while (npages != 0) {
#ifdef HAVE_GET_USER_PAGES_8_PARAMS
		ret = get_user_pages(current, current->mm, current_base,
			min_t(unsigned long, npages, PAGE_SIZE / sizeof(struct page *)),
			1, !hmem->writable, page_list, vma_list);
#else
#ifdef HAVE_GET_USER_PAGES_LONGTERM
		ret = get_user_pages(current_base,
#else
		ret = get_user_pages(current_base,
#endif
			min_t(unsigned long, npages, PAGE_SIZE / sizeof(struct page *)),
#ifdef HAVE_GET_USER_PAGES_GUP_FLAGS
			gup_flags, page_list, vma_list);
#else
			1, !hmem->writable, page_list, vma_list);
#endif
#endif

		if (ret < 0)
			goto out;

		hmem->npages += ret;
		current_base += ret * PAGE_SIZE;
		npages = (unsigned long)(npages - ret);

		for_each_sg(sg_list_start, sg, ret, i) {
			if (vma_list != NULL && !is_vm_hugetlb_page(vma_list[i]))
				hmem->hugetlb = 0;

			sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
		}

		/* preparing for next loop */
		sg_list_start = sg;
	}

	hmem->nmap = dma_map_sg_attrs(device, hmem->sg_head.sgl, hmem->npages, DMA_BIDIRECTIONAL,
#ifdef HAVE_STRUCT_DMA_ATTRS
		&dma_attrs);
#else
		dma_attrs);
#endif
	if (hmem->nmap <= 0) {
		ret = -ENOMEM;
		goto out;
	}
	ret = 0;

out:
	if (ret < 0) {
		if (need_release != 0)
			hmm_umemsg_release(device, hmem, 0);

		kfree(hmem->context);
		kfree(hmem);
	} else {
		atomic64_set(&current->mm->pinned_vm, locked_pages);
	}

	mmap_write_unlock(current->mm);
	if (vma_list != NULL)
		free_page((unsigned long)(uintptr_t)vma_list);

	free_page((unsigned long)(uintptr_t)page_list);
	return (ret < 0) ? ERR_PTR(ret) : hmem;
}

/**
 * hmm_umem_release - release memory pinned with ib_umem_get
 * @hmem: umem struct to release
 */
void hmm_umem_release(struct hmm_umem *hmem)
{
	struct ib_ucontext *context = hmem->context;
	struct mm_struct *mm = NULL;
	struct task_struct *task = NULL;
	unsigned long diff;

	if (hmem->odp_data) {
		pr_err("[HMM, ERR] %s(%d): Don't support odp\n", __func__, __LINE__);
		return;
	}

	hmm_umemsg_release(context->device, hmem, 1);
	task = get_pid_task(context->tgid, PIDTYPE_PID);
	if (task == NULL)
		goto out;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (mm == NULL)
		goto out;

	diff = hmm_umem_num_pages(hmem);
	mmap_write_lock(mm);
	atomic64_sub(diff, &mm->pinned_vm);
	mmap_write_unlock(mm);
	mmput(mm);
out:
	kfree(context);
	kfree(hmem);
}
#endif

u32 hmm_umem_page_count(struct hmm_umem *hmem)
{
	u32 i;
	u32 n;
	struct scatterlist *sg = NULL;

	if (hmem->odp_data)
		return (u32)(hmm_umem_num_pages(hmem));

	n = 0;
	for_each_sg(hmem->sg_head.sgl, sg, hmem->nmap, i) n += sg_dma_len(sg) >>
		((u32)hmem->page_shift);

	return n;
}
