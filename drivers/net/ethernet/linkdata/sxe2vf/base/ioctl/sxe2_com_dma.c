// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_dma.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/mmzone.h>
#include <linux/gfp.h>

#include "sxe2_com_cdev.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_com_dma.h"
#include "sxe2_compat.h"

struct sxe2_com_batch {
	struct page **pages;
	struct page *fallback_page;
	int capacity;
	int size;
	int offset;
};

static bool is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn))
		return PageReserved(pfn_to_page(pfn));

	return true;
}

static int put_pfn(unsigned long pfn, int prot)
{
	if (!is_invalid_reserved_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
#ifdef NOT_SUPP_UNPIN_USER_PAGE
		if (prot & IOMMU_WRITE)
			SetPageDirty(page);
		put_page(page);
#else
		unpin_user_pages_dirty_lock(&page, 1, prot & IOMMU_WRITE);
#endif
		return 1;
	}
	return 0;
}

#define SXE2_COM_BATCH_MAX_CAPACITY (PAGE_SIZE / sizeof(struct page *))

static void sxe2_com_batch_init(struct sxe2_com_batch *batch)
{
	batch->size = 0;
	batch->offset = 0;

	batch->pages = (struct page **)__get_free_page(GFP_KERNEL);
	if (!batch->pages)
		goto fallback;

	batch->capacity = SXE2_COM_BATCH_MAX_CAPACITY;
	return;

fallback:
	batch->pages = &batch->fallback_page;
	batch->capacity = 1;
}

static void sxe2_com_batch_unpin(struct sxe2_com_batch *batch, struct sxe2_com_dma *dma)
{
	while (batch->size) {
		unsigned long pfn = page_to_pfn(batch->pages[batch->offset]);

		put_pfn(pfn, dma->prot);
		batch->offset++;
		batch->size--;
	}
}

static void sxe2_com_batch_fini(struct sxe2_com_batch *batch)
{
	if (batch->capacity == SXE2_COM_BATCH_MAX_CAPACITY)
		free_page((unsigned long)batch->pages);
}

static int follow_fault_pfn(struct vm_area_struct *vma,
			    struct mm_struct *mm, unsigned long vaddr, unsigned long *pfn,
			    bool write_fault)
{
#ifdef NOT_SUPP_FOLLOW_PTE
	(void)mm;
	(void)write_fault;
	*pfn = ((vaddr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	return 0;
#else
	pte_t *ptep;
	/* in order to protect the data */
	spinlock_t *ptl;
	bool unlocked;
	int ret;

	ret = follow_pte(vma->vm_mm, vaddr, &ptep, &ptl);
	if (ret) {
		unlocked = false;
		ret = fixup_user_fault(mm, vaddr,
				       FAULT_FLAG_REMOTE | (write_fault ? FAULT_FLAG_WRITE : 0),
				       &unlocked);
		if (unlocked)
			return -EAGAIN;

		if (ret)
			return ret;

		ret = follow_pte(vma->vm_mm, vaddr, &ptep, &ptl);
		if (ret)
			return ret;
	}

	if (write_fault && !pte_write(*ptep))
		ret = -EFAULT;
	else
		*pfn = pte_pfn(*ptep);

	pte_unmap_unlock(ptep, ptl);
	return ret;
#endif
}

static int vaddr_get_pfns(struct mm_struct *mm, unsigned long vaddr,
			  long npages, int prot, unsigned long *pfn,
			  struct page **pages)
{
	struct vm_area_struct *vma;
	unsigned int flags = 0;
	int ret;

	if (prot & IOMMU_WRITE)
		flags |= FOLL_WRITE;

	mmap_read_lock(mm);

#ifndef NOT_SUPP_PIN_USER_PAGE
	ret = pin_user_pages_remote(mm, vaddr, npages, flags | FOLL_LONGTERM, pages, NULL, NULL);
#elif !defined(NOT_SUPP_FOLL_LONGTERM)
	ret = get_user_pages(vaddr, npages, flags | FOLL_LONGTERM, pages, NULL);
#elif !defined(NOT_SUPP_GET_USER_PAGES_LONGTERM)
	ret = get_user_pages_longterm(vaddr, npages, flags, pages, NULL);
#else
	ret = get_user_pages_fast(vaddr, npages, !!(prot & IOMMU_WRITE), pages);
#endif

	if (ret > 0) {
		*pfn = page_to_pfn(pages[0]);
		goto done;
	}

	vaddr = untagged_addr(vaddr);

retry:
	vma = vma_lookup(mm, vaddr);

	if (vma && vma->vm_flags & VM_PFNMAP) {
		ret = follow_fault_pfn(vma, mm, vaddr, pfn, prot & IOMMU_WRITE);
		if (ret == -EAGAIN)
			goto retry;

		if (!ret) {
			if (is_invalid_reserved_pfn(*pfn))
				ret = 1;
			else
				ret = -EFAULT;
		}
	}
done:
	mmap_read_unlock(mm);
	return ret;
}

static long sxe2_com_pin_pages_remote(struct sxe2_com_dma *dma, unsigned long vaddr, long npage,
				      unsigned long *pfn_base, struct sxe2_com_batch *batch)
{
	unsigned long pfn = 0;
	struct mm_struct *mm = current->mm;
	long ret = 0;
	long pinned = 0;
	bool rsvd = 0;
	dma_addr_t iova = vaddr - dma->vaddr + dma->iova;

	if (!mm)
		return -ENODEV;

	if (batch->size) {
		*pfn_base = page_to_pfn(batch->pages[batch->offset]);
		pfn = *pfn_base;
		rsvd = is_invalid_reserved_pfn(*pfn_base);
	} else {
		*pfn_base = 0;
	}

	while (npage) {
		if (!batch->size) {
			long req_pages = min_t(long, npage, batch->capacity);

			ret = vaddr_get_pfns(mm, vaddr, req_pages, dma->prot, &pfn, batch->pages);
			if (ret < 0)
				goto unpin_out;

			batch->size = ret;
			batch->offset = 0;

			if (!*pfn_base) {
				*pfn_base = pfn;
				rsvd = is_invalid_reserved_pfn(*pfn_base);
			}
		}

		while (true) {
			if (pfn != *pfn_base + pinned || rsvd != is_invalid_reserved_pfn(pfn))
				goto unpin_out;

			pinned++;
			npage--;
			vaddr += PAGE_SIZE;
			iova += PAGE_SIZE;
			batch->offset++;
			batch->size--;

			if (!batch->size)
				break;

			pfn = page_to_pfn(batch->pages[batch->offset]);
		}
	}

unpin_out:
	if (batch->size == 1 && !batch->offset) {
		put_pfn(pfn, dma->prot);
		batch->size = 0;
	}

	if (ret < 0) {
		if (pinned && !rsvd) {
			for (pfn = *pfn_base; pinned; pfn++, pinned--)
				put_pfn(pfn, dma->prot);
		}
		sxe2_com_batch_unpin(batch, dma);

		return ret;
	}

	return pinned;
}

static int sxe2_com_iommu_map(struct sxe2_com_context *com_ctxt,
			      dma_addr_t iova, unsigned long pfn, long npage,
			      int prot)
{
#ifdef NOT_SUPP_IOMMU_CAPABLE
	prot |= IOMMU_CACHE;
#else
	if (iommu_capable(SXE2_COM_TO_BUS(&com_ctxt->dma_dev), IOMMU_CAP_CACHE_COHERENCY))
		prot |= IOMMU_CACHE;
#endif

	return iommu_map(SXE2_COM_TO_DOMAIN(&com_ctxt->dma_dev),
			 iova, (phys_addr_t)pfn << PAGE_SHIFT, npage << PAGE_SHIFT, prot);
}

static long sxe2_com_unpin_pages_remote(struct sxe2_com_dma *dma,
					dma_addr_t iova, unsigned long pfn, long npage)
{
	long unlocked = 0;
	long i;

	for (i = 0; i < npage; i++, iova += PAGE_SIZE) {
		if (put_pfn(pfn++, dma->prot))
			unlocked++;
	}

	return unlocked;
}

static size_t unmap_unpin(struct sxe2_com_context *com_ctxt,
			  struct sxe2_com_dma *dma, dma_addr_t *iova, size_t len,
			  phys_addr_t phys, long *unlocked)
{
	size_t unmapped = iommu_unmap(SXE2_COM_TO_DOMAIN(&com_ctxt->dma_dev), *iova, len);

	if (unmapped) {
		*unlocked += sxe2_com_unpin_pages_remote(dma, *iova, phys >> PAGE_SHIFT,
							 unmapped >> PAGE_SHIFT);
		*iova += unmapped;
		cond_resched();
	}
	return unmapped;
}

static long sxe2_com_unmap_unpin(struct sxe2_com_context *com_ctxt, struct sxe2_com_dma *dma)
{
	dma_addr_t iova = dma->iova, end = dma->iova + dma->size;
	long unlocked = 0;

	if (!dma->size)
		return 0;

	while (iova < end) {
		size_t unmapped;
		size_t len = PAGE_SIZE;
		phys_addr_t phys;

		phys = iommu_iova_to_phys(SXE2_COM_TO_DOMAIN(&com_ctxt->dma_dev), iova);
		if (WARN_ON(!phys)) {
			iova += PAGE_SIZE;
			continue;
		}

		unmapped = unmap_unpin(com_ctxt, dma, &iova, len, phys, &unlocked);
		if (WARN_ON(!unmapped))
			break;
	}

	return unlocked;
}

static int sxe2_com_pin_map_dma(struct sxe2_com_context *com_ctxt,
				struct sxe2_com_dma *dma, size_t map_size)
{
	dma_addr_t iova = dma->iova;
	unsigned long vaddr = dma->vaddr;
	struct sxe2_com_batch batch;
	size_t size = map_size;
	long npage;
	unsigned long pfn;
	int ret = 0;

	sxe2_com_batch_init(&batch);

	while (size) {
		npage = sxe2_com_pin_pages_remote(dma, vaddr + dma->size,
						  size >> PAGE_SHIFT, &pfn, &batch);
		if (npage <= 0) {
			WARN_ON(!npage);
			ret = (int)npage;
			break;
		}

		ret = sxe2_com_iommu_map(com_ctxt, iova + dma->size, pfn, npage, dma->prot);
		if (ret) {
			sxe2_com_unpin_pages_remote(dma, iova + dma->size, pfn, npage);
			sxe2_com_batch_unpin(&batch, dma);
			break;
		}

		size -= npage << PAGE_SHIFT;
		dma->size += npage << PAGE_SHIFT;
	}

	sxe2_com_batch_fini(&batch);

	return ret;
}

STATIC struct sxe2_com_dma *sxe2_com_dma_find_unlock(struct sxe2_com_context *com_ctxt,
						     dma_addr_t start, u32 size)
{
	struct sxe2_com_dma *dma;
	struct sxe2_com_dma_dev *dma_dev = &com_ctxt->dma_dev;

	list_for_each_entry(dma, &dma_dev->buffer_list, list) {
		if ((start + size > dma->iova) && (start < dma->iova + dma->size))
			return dma;
	}

	return NULL;
}

static s32 sxe2_com_dma_alloc(struct sxe2_com_context *com_ctxt,
			      struct sxe2_ioctl_iommu_dma_map *map)
{
	int ret = 0;
	struct sxe2_com_dma *dma = NULL;
	dma_addr_t iova = map->iova;
	unsigned long vaddr = map->vaddr;
	size_t size = map->size;
	size_t pgsize;
	struct sxe2_com_dma_dev *dma_dev = &com_ctxt->dma_dev;

	if (!sxe2_com_iommu_supp(dma_dev))
		return -EOPNOTSUPP;

	if (map->size != size || map->vaddr != vaddr || map->iova != iova) {
		ret = -EINVAL;
		goto l_out;
	}

	pgsize = (size_t)1 << __ffs(PAGE_MASK);
	if (!size || (size | iova | vaddr) & (pgsize - 1)) {
		ret = -EINVAL;
		goto l_out;
	}

	if (iova + size - 1 < iova || vaddr + size - 1 < vaddr) {
		ret = -EINVAL;
		goto l_out;
	}

	dma = kzalloc(sizeof(*dma), GFP_KERNEL);
	if (!dma) {
		ret = -ENOMEM;
		goto l_out;
	}

	dma->vaddr = map->vaddr;
	dma->iova = iova;
	dma->prot = IOMMU_WRITE | IOMMU_READ;

	mutex_lock(&dma_dev->lock);
	if (sxe2_com_dma_find_unlock(com_ctxt, iova, size)) {
		ret = -EEXIST;
		goto l_free;
	}

	ret = sxe2_com_pin_map_dma(com_ctxt, dma, size);
	if (ret)
		goto l_free;

	list_add(&dma->list, &dma_dev->buffer_list);

	ret = 0;
	goto l_unlock;

l_free:
	kfree(dma);
l_unlock:
	mutex_unlock(&dma_dev->lock);
l_out:
	LOG_INFO_BDF_COM("vaddr: 0x%lx, iova: 0x%llx, size: %zu, ret:%d\n", vaddr, iova, size,
			 ret);
	return ret;
}

static int sxe2_com_dma_free(struct sxe2_com_context *com_ctxt, dma_addr_t iova, u8 free_all)
{
	int ret = free_all ? 0 : -ENOENT;
	struct sxe2_com_dma *dma;
	struct sxe2_com_dma *tmp;
	struct sxe2_com_dma_dev *dma_dev = &com_ctxt->dma_dev;

	mutex_lock(&dma_dev->lock);
	list_for_each_entry_safe(dma, tmp, &dma_dev->buffer_list, list) {
		if (free_all) {
			list_del(&dma->list);
			sxe2_com_unmap_unpin(com_ctxt, dma);
			kfree(dma);
			continue;
		}

		if (dma->iova == iova) {
			list_del(&dma->list);
			sxe2_com_unmap_unpin(com_ctxt, dma);
			kfree(dma);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&dma_dev->lock);
	LOG_INFO_BDF_COM("iova: 0x%llx, free_all %d, ret:%d\n", iova, free_all, ret);
	return ret;
}

s32 sxe2_com_dma_map(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_iommu_dma_map map = {};
	u32 arg_sz;

	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_DMA_MAP);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver, SXE2_DEVICE_DMA_MAP);
		return ret;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&map, (void __user *)arg, arg_sz))
		return -EFAULT;

	ret = sxe2_com_dma_alloc(com_ctxt, &map);

	return ret;
}

s32 sxe2_com_dma_unmap(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_iommu_dma_unmap map = {};
	u32 arg_sz;

	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_DMA_UNMAP);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver, SXE2_DEVICE_DMA_UNMAP);
		return ret;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&map, (void __user *)arg, arg_sz))
		return -EFAULT;

	return sxe2_com_dma_free(com_ctxt, map.iova, false);
}

s32 sxe2_com_dma_clear(struct sxe2_com_context *com_ctxt)
{
	return sxe2_com_dma_free(com_ctxt, 0xFF, true);
}

void sxe2_com_dma_print(struct sxe2_com_context *com_ctxt)
{
	struct sxe2_com_dma *dma;
	struct sxe2_com_dma_dev *dma_dev = &com_ctxt->dma_dev;

	mutex_lock(&dma_dev->lock);
	LOG_DEV_INFO_COM("dma map list:\n");
	list_for_each_entry(dma, &dma_dev->buffer_list, list) {
		LOG_DEV_INFO_COM("dma vaddr: 0x%lx, iova:0x%llx, size:%zu\n",
				 dma->vaddr, dma->iova, dma->size);
	}
	mutex_unlock(&dma_dev->lock);
}
