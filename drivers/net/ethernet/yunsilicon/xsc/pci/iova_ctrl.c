// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/pagemap.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include "common/xsc_core.h"

#include <linux/mmap_lock.h>

#include <linux/sched/signal.h>

#include <linux/sched/mm.h>

#include "common/res_obj.h"
#include "common/driver.h"
#include "common/xsc_port_ctrl.h"
#include "iova_ctrl.h"

#ifndef DMA_MAPPING_ERROR
#define DMA_MAPPING_ERROR  (~(dma_addr_t)0)
#endif

#define XSC_UMEM_ID_NUM  65536

struct xsc_umem {
	u64 va;
	u64 size;
	struct sg_table sgt;
	struct page **pages;
	int num_pages;
	struct mm_struct *mm;
};

struct xsc_umem_res {
	u8 umem_tbl[XSC_UMEM_ID_NUM >> 3];
	spinlock_t umem_lock;	/* protect umem_tbl */
};

static struct xsc_umem_res g_umem_res;

static int unpin_memory(struct xsc_core_device *xdev, struct xsc_umem *umem);

static void xsc_umem_res_init(void)
{
	memset(g_umem_res.umem_tbl, 0xFF, XSC_UMEM_ID_NUM >> 3);
	spin_lock_init(&g_umem_res.umem_lock);
}

static int find_umem_id(struct xsc_bdf_file *bdf_file, u64 va)
{
	int i;
	struct xsc_umem_obj *umem_obj;
	struct xsc_umem *umem;

	spin_lock(&g_umem_res.umem_lock);
	for (i = 0; i < XSC_UMEM_ID_NUM; i++) {
		if (!test_bit(i, (unsigned long *)g_umem_res.umem_tbl)) {
			umem_obj = xsc_find_umem_obj(bdf_file, i);
			if (umem_obj && umem_obj->obj.data) {
				umem = (struct xsc_umem *)umem_obj->obj.data;
				if (umem->va == va) {
					spin_unlock(&g_umem_res.umem_lock);
					return umem_obj->umem_id;
				}
			}
		}
	}
	spin_unlock(&g_umem_res.umem_lock);

	return -1;
}

static int alloc_umem_id(u32 *umem_id)
{
	u32 i;

	spin_lock(&g_umem_res.umem_lock);
	for (i = 0; i < XSC_UMEM_ID_NUM; i++) {
		if (test_bit(i, (unsigned long *)g_umem_res.umem_tbl)) {
			__clear_bit(i, (unsigned long *)g_umem_res.umem_tbl);
			*umem_id = i;
			spin_unlock(&g_umem_res.umem_lock);
			return 0;
		}
	}
	spin_unlock(&g_umem_res.umem_lock);

	return -1;
}

static void release_umem_id(u32 umem_id)
{
	spin_lock(&g_umem_res.umem_lock);
	test_and_set_bit(umem_id, (unsigned long *)g_umem_res.umem_tbl);
	spin_unlock(&g_umem_res.umem_lock);
}

static void xsc_umem_release(void *data)
{
	struct xsc_umem_obj *umem_obj;
	struct xsc_res_obj *obj = data;
	struct xsc_umem *umem;
	u32 umem_id;

	if (!data)
		return;

	umem_obj = container_of(obj, struct xsc_umem_obj, obj);

	umem = (struct xsc_umem *)umem_obj->obj.data;
	umem_id = umem_obj->umem_id;
	unpin_memory(obj->file->xdev, umem);
	xsc_free_umem_obj(obj->file, obj, umem_obj->umem_id);
	release_umem_id(umem_id);
}

static bool is_valid_sg_entry(struct scatterlist *sg)
{
	return (sg_dma_address(sg) != DMA_MAPPING_ERROR &&
		sg_dma_address(sg) != 0xffffffffffffffffULL &&
		sg_dma_len(sg) > 0);
}

static void fill_iova_segment(struct iova_segment *segment, struct scatterlist *sg)
{
	segment->iova = sg_dma_address(sg);
	segment->size = sg_dma_len(sg);
	segment->pa = page_to_phys(sg_page(sg));
}

static void mm_mmap_read_lock(struct mm_struct *mm)
{
	mmap_read_lock(mm);
}

static void mm_mmap_read_unlock(struct mm_struct *mm)
{
	mmap_read_unlock(mm);
}

static int pinned_vm_add(struct xsc_core_device *xdev, struct mm_struct *mm, int npages)
{
	unsigned long lock_limit;
	unsigned long new_pinned;

	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	new_pinned = atomic64_add_return(npages, &mm->pinned_vm);
	if (new_pinned > lock_limit && !capable(CAP_IPC_LOCK)) {
		atomic64_sub(npages, &mm->pinned_vm);
		xsc_core_err(xdev, "invalid npages because of limit, got npages %d\n", npages);
		return -1;
	}

	return 0;
}

static void pinned_vm_sub(struct xsc_core_device *xdev, struct mm_struct *mm, int npages)
{
	atomic64_sub(npages, &mm->pinned_vm);
}

static int pin_user_pages_compat(struct xsc_core_device *xdev, u64 va, u64 size,
				 struct page ***pages_ptr, int *num_pages)
{
	struct page **pages;
	int ret;
	u64 start = va & PAGE_MASK;
	u64 end = (va + size + PAGE_SIZE - 1) & PAGE_MASK;
	int npages = (end - start) >> PAGE_SHIFT;
	int gup_flags = 0;
	struct mm_struct *mm = current->mm;

	if (size == 0 || !IS_ALIGNED(va, PAGE_SIZE)) {
		xsc_core_err(xdev, "invalid size or unaligned address\n");
		return -EINVAL;
	}

	if (!mm) {
		xsc_core_err(xdev, "invalid mm struct\n");
		return -EFAULT;
	}

	mmgrab(mm);
	pages = kcalloc(npages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		ret = -ENOMEM;
		goto err_pages;
	}

	ret = pinned_vm_add(xdev, mm, npages);
	if (ret) {
		ret = -ENOMEM;
		goto err_pinned_vm;
	}

	gup_flags = FOLL_WRITE;

	mm_mmap_read_lock(mm);

	ret = pin_user_pages(start, npages, gup_flags, pages);

	mm_mmap_read_unlock(mm);

	if (ret < 0) {
		xsc_core_err(xdev, "pin user pages failed: %d\n", ret);
		goto err;
	}

	if (ret != npages) {
		xsc_core_err(xdev, "requested %d pages, got %d\n", npages, ret);
		unpin_user_pages_dirty_lock(pages, ret, 0);
		ret = -EFAULT;
		goto err;
	}

	*pages_ptr = pages;
	*num_pages = npages;

	xsc_core_info(xdev, "pinned %d pages for va 0x%llx, size 0x%llx\n", npages, va, size);
	return 0;

err:
	pinned_vm_sub(xdev, mm, npages);
err_pinned_vm:
	kfree(pages);
err_pages:
	mmdrop(mm);
	return ret;
}

static void unpin_user_pages_compat(struct xsc_core_device *xdev, struct page **pages,
				    int num_pages, struct mm_struct *mm)
{
	unpin_user_pages_dirty_lock(pages, num_pages, 1);

	pinned_vm_sub(xdev, mm, num_pages);

	kfree(pages);

	mmdrop(mm);
	xsc_core_info(xdev, "unpinned %d pages\n", num_pages);
}

static int va_to_iova_sg(struct xsc_bdf_file *bdf_file, u64 va, u64 size,
			 struct iova_segment *iova_segments,
			 u32 array_size, u32 *num_entries)
{
	u32 umem_id;
	struct page **pages = NULL;
	int npages = 0;
	int ret, i, num_dma_sg;
	int num_valid_sg_entries = 0;
	struct sg_table *sgt;
	struct scatterlist *sg;
	struct xsc_umem umem;
	struct xsc_core_device *xdev = bdf_file->xdev;

	if (!va || !size || !IS_ALIGNED(size, PAGE_SIZE)) {
		xsc_core_err(xdev, "invalid parameters: va=%llx, size=%llu\n", va, size);
		return -EINVAL;
	}

	ret = find_umem_id(bdf_file, va);
	if (ret >= 0) {
		xsc_core_err(xdev, "mapping already exists for va 0x%llx, umem_id %d\n", va, ret);
		return -EALREADY;
	}

	ret = alloc_umem_id(&umem_id);
	if (ret) {
		xsc_core_err(xdev, "failed to alloc umem id\n");
		return -ENOMEM;
	}

	ret = pin_user_pages_compat(xdev, va, size, &pages, &npages);
	if (ret) {
		xsc_core_err(xdev, "pin_user_pages_compat failed: %d\n", ret);
		return ret;
	}

	sgt = &umem.sgt;

	ret = sg_alloc_table_from_pages(sgt, pages, npages, 0, size, GFP_KERNEL);
	if (ret || array_size < sgt->nents) {
		xsc_core_err(xdev, "failed to alloc sg ret %d, nents %d, got array size %u\n",
			     ret, sgt->nents, array_size);
		ret = -ENOMEM;
		goto err_sg_alloc;
	}

	num_dma_sg = dma_map_sg(&xdev->pdev->dev, sgt->sgl, sgt->nents, DMA_BIDIRECTIONAL);
	if (num_dma_sg == 0 || array_size < num_dma_sg) {
		xsc_core_err(xdev, "failed to dma map sg ret %d, got array size %u\n",
			     num_dma_sg, array_size);
		ret = -ENOMEM;
		goto err_dma_map;
	}
	xsc_core_dbg(xdev, "dma map sg nents %d\n", num_dma_sg);

	*num_entries = num_dma_sg;

	i = 0;
	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		if (is_valid_sg_entry(sg)) {
			if (num_valid_sg_entries < array_size) {
				fill_iova_segment(&iova_segments[num_valid_sg_entries],
						  sg);

				xsc_core_dbg(xdev, "sg %d %d: iova=0x%llx, size=%llu, pa=0x%llx\n",
					     i, num_valid_sg_entries,
					     iova_segments[i].iova,
					     iova_segments[i].size,
					     iova_segments[i].pa);
			}
			num_valid_sg_entries++;
		}
	}

	if (num_dma_sg != num_valid_sg_entries) {
		xsc_core_err(xdev, "invalid num of sg entries, need %d, got %d\n", num_dma_sg,
			     num_valid_sg_entries);
		ret = -EIO;
		goto err;
	}

	umem.va = va;
	umem.size = size;
	umem.pages = pages;
	umem.num_pages = npages;
	umem.mm = current->mm;

	ret = xsc_alloc_umem_obj(bdf_file, xsc_umem_release, umem_id, (void *)&umem, sizeof(umem));
	if (ret) {
		xsc_core_err(xdev, "failed to alloc umem obj\n");
		ret = -ENOMEM;
		goto err;
	}

	xsc_core_info(xdev,
		      "va to iova sg: va=0x%llx, size=%llu, sg_entries=%d, pages=%d, id %u\n",
		      va, size, sgt->nents, npages, umem_id);

	return 0;

err:
	dma_unmap_sg(&xdev->pdev->dev, sgt->sgl, sgt->nents, DMA_BIDIRECTIONAL);
err_dma_map:
	sg_free_table(sgt);
err_sg_alloc:
	unpin_user_pages_compat(xdev, pages, npages, current->mm);
	return ret;
}

static int unpin_memory(struct xsc_core_device *xdev, struct xsc_umem *umem)
{
	int num_sg_entries;
	u64 va, size;

	if (!umem)
		return -1;

	dma_unmap_sg(&xdev->pdev->dev, umem->sgt.sgl, umem->sgt.nents, DMA_BIDIRECTIONAL);

	num_sg_entries = umem->sgt.nents;
	va = umem->va;
	size = umem->size;
	sg_free_table(&umem->sgt);
	unpin_user_pages_compat(xdev, umem->pages, umem->num_pages, umem->mm);

	xsc_core_info(xdev, "unpinned memory for va 0x%llx, size 0x%llx, %d sg entries\n", va,
		      size, num_sg_entries);
	return 0;
}

static int put_memory(struct xsc_bdf_file *bdf_file, u64 va)
{
	int umem_id = find_umem_id(bdf_file, va);
	struct xsc_core_device *xdev = bdf_file->xdev;

	if (umem_id < 0) {
		xsc_core_err(xdev, "failed to find memory: va=%llx\n", va);
		return -1;
	}

	xsc_destroy_umem_obj(bdf_file, umem_id);

	return 0;
}

static int iova_ctrl_handler(struct xsc_bdf_file *bdf_file, unsigned int cmd,
			     struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	struct xsc_ioctl_hdr hdr;
	struct xsc_iova_sg_req req;
	struct iova_segment *iova_segments = NULL;
	int ret = 0;

	ret = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (ret)
		return -EFAULT;

	ret = copy_from_user(&req, user_hdr->attr.data, sizeof(req));
	if (ret)
		return -EFAULT;

	if (cmd != XSC_IOVA_CTRL)
		return TRY_NEXT_CB;

	switch (hdr.attr.opcode) {
	case XSC_IOVA_CTRL_GET_IOVA:
		if (!req.iova_array || req.array_size == 0) {
			ret = -EINVAL;
			goto out;
		}

		iova_segments = kmalloc_array(req.array_size, sizeof(struct iova_segment),
					      GFP_KERNEL);
		if (!iova_segments) {
			ret = -ENOMEM;
			goto out;
		}

		req.result = va_to_iova_sg(bdf_file, req.va, req.size, iova_segments,
					   req.array_size, &req.num_entries);

		if (req.result == 0) {
			if (copy_to_user((void __user *)req.iova_array, iova_segments,
					 req.num_entries * sizeof(struct iova_segment))) {
				req.result = -EFAULT;
				put_memory(bdf_file, req.va);
			}
		}
		break;

	case XSC_IOVA_CTRL_PUT:
		req.result = put_memory(bdf_file, req.va);
		break;

	default:
		return TRY_NEXT_CB;
	}

	if (copy_to_user((void *)user_hdr, &hdr, sizeof(hdr))) {
		ret = -EFAULT;
		if (hdr.attr.opcode == XSC_IOVA_CTRL_GET_IOVA)
			put_memory(bdf_file, req.va);
	}

	if (copy_to_user((void *)user_hdr->attr.data, &req, sizeof(req))) {
		ret = -EFAULT;
		if (hdr.attr.opcode == XSC_IOVA_CTRL_GET_IOVA)
			put_memory(bdf_file, req.va);
	}

out:
	kfree(iova_segments);
	return ret;
}

int iova_ctrl_cb_init(void)
{
	int ret;

	xsc_umem_res_init();

	ret = xsc_port_ctrl_cb_reg(IOVA_CTRL_CB_NAME, iova_ctrl_handler, NULL);
	if (ret) {
		pr_err("Failed to register IOVA control callback\n");
		return ret;
	}

	return 0;
}

void iova_ctrl_cb_fini(void)
{
	xsc_port_ctrl_cb_dereg(IOVA_CTRL_CB_NAME);
}
