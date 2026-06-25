// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/highmem.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/iommu.h>
#include <linux/ummu_core.h>
#include "cdma_common.h"
#include "cdma.h"

static inline void cdma_fill_umem(struct cdma_umem *umem,
				  struct cdma_umem_param *param)
{
	umem->dev = param->dev;
	umem->va = param->va;
	umem->length = param->len;
	umem->flag = param->flag;
}

static int cdma_pin_part_of_pages(u64 cur_base, u64 npages, u32 gup_flags,
				  struct page **page_list)
{
	/*
	 * page_list size is 4kB, the nr_pages should not larger than
	 * PAGE_SIZE / sizeof(struct page *)
	 */
	return pin_user_pages_fast(cur_base,
				   min_t(unsigned long, (unsigned long)npages,
					 PAGE_SIZE / sizeof(struct page *)),
				   gup_flags | FOLL_LONGTERM, page_list);
}

static void cdma_append_release(struct sg_append_table *append)
{
	struct scatterlist *sg;
	unsigned int i;

	for_each_sgtable_sg(&append->sgt, sg, i)
		unpin_user_page_range_dirty_lock(
			sg_page(sg), DIV_ROUND_UP(sg->length, PAGE_SIZE), 0);

	sg_free_append_table(append);
}

static u64 cdma_pin_pages(struct cdma_dev *cdev, struct cdma_umem *umem,
			  u64 npages, u32 gup_flags, struct page **pages)
{
	u64 cur_base = umem->va & PAGE_MASK;
	u64 page_left = npages;
	int pinned;
	int ret;

	while (page_left > 0) {
		cond_resched();

		pinned = cdma_pin_part_of_pages(cur_base, page_left, gup_flags,
						pages);
		if (pinned <= 0) {
			dev_err(cdev->dev,
				"pin pages failed, page_left = 0x%llx, pinned = %d\n",
				page_left, pinned);
			return npages - page_left;
		}
		cur_base += (u64)pinned * PAGE_SIZE;
		page_left -= (u64)pinned;
		ret = sg_alloc_append_table_from_pages(
			&umem->sgt_append, pages, pinned, 0,
			pinned << PAGE_SHIFT, UINT_MAX, page_left, GFP_KERNEL);
		if (ret) {
			unpin_user_pages_dirty_lock(pages, pinned, 0);
			cdma_append_release(&umem->sgt_append);
			return 0;
		}
	}

	return npages;
}

static u64 cdma_k_pin_pages(struct cdma_dev *cdev, struct cdma_umem *umem,
			    u64 npages)
{
	u64 cur_base = umem->va & PAGE_MASK;
	struct scatterlist *sg_cur;
	struct page *pg;
	int ret;
	u64 n;

	ret = sg_alloc_table(&umem->sg_head, (unsigned int)npages, GFP_KERNEL);
	if (ret) {
		dev_err(cdev->dev, "sg alloc table failed\n");
		return 0;
	}
	sg_cur = umem->sg_head.sgl;

	for (n = 0; n < npages; n++) {
		if (is_vmalloc_addr((void *)(uintptr_t)cur_base))
			pg = vmalloc_to_page((void *)(uintptr_t)cur_base);
		else
			pg = kmap_to_page((void *)(uintptr_t)cur_base);

		if (!pg) {
			dev_err(cdev->dev, "vmalloc or kmap to page failed\n");
			break;
		}

		get_page(pg);

		cur_base += PAGE_SIZE;

		sg_set_page(sg_cur, pg, PAGE_SIZE, 0);
		sg_cur = sg_next(sg_cur);
	}

	if (n == 0)
		sg_free_table(&umem->sg_head);

	return n;
}

static void cdma_unpin_pages(struct cdma_umem *umem, u64 nents, bool is_kernel,
			     bool dirty)
{
	struct scatterlist *sg;
	struct page *page;
	u32 i;

	if (is_kernel) {
		for_each_sg(umem->sg_head.sgl, sg, nents, i) {
			page = sg_page(sg);
			put_page(page);
		}
		sg_free_table(&umem->sg_head);
	} else {
		for_each_sgtable_sg(&umem->sgt_append.sgt, sg, i) {
			page = sg_page(sg);
			unpin_user_page_range_dirty_lock(
				page, DIV_ROUND_UP(sg->length, PAGE_SIZE),
				dirty);
		}
		sg_free_append_table(&umem->sgt_append);
	}
}

static void cdma_sva_matt_unmap(struct cdma_umem *umem)
{
	struct ummu_matt_domain matt_domain = { 0 };
	u64 len;

	len = ALIGN(umem->va + umem->length, PAGE_SIZE) -
	      ALIGN_DOWN(umem->va, PAGE_SIZE);

	matt_domain.l_tid = umem->tid;
	matt_domain.r_tid = UMMU_INVALID_TID;
	matt_domain.mm = current->mm;
	ummu_sva_matt_unmap(&matt_domain, umem->va, len);
}

static int cdma_sva_matt_map(struct cdma_umem *umem)
{
	struct ummu_matt_domain matt_domain = { 0 };
	int prot = IOMMU_WRITE | IOMMU_READ;
	int ret;

	matt_domain.l_tid = umem->tid;
	matt_domain.r_tid = UMMU_INVALID_TID;
	matt_domain.mm = current->mm;
	ret = ummu_sva_matt_map(&matt_domain, umem->va, &umem->sgt_append.sgt,
				prot);
	if (ret)
		dev_err(umem->dev->dev, "ummu sva matt map failed, ret = %d\n",
			ret);

	return ret;
}

static void cdma_put_target_umem(struct cdma_umem *umem, bool is_kernel)
{
	cdma_unpin_pages(umem, umem->sg_head.nents, is_kernel, 1);
	kfree(umem);
}

void cdma_put_umem(struct cdma_umem *umem, bool is_kernel)
{
	if (IS_ERR_OR_NULL(umem))
		return;

	if (is_kernel && umem->dev->ksva)
		cdma_ksva_tlb_inv(umem->dev->ksva->handle.domain, umem->va,
				  umem->length);

	if (!is_kernel && umem->sva_mode == UMMU_SVA_SEPARATE_MODE)
		cdma_sva_matt_unmap(umem);
	cdma_put_target_umem(umem, is_kernel);
}

static int cdma_verify_mem(struct cdma_dev *cdev, u64 va, u64 len)
{
	if (((va + len) <= va) || PAGE_ALIGN(va + len) < (va + len)) {
		dev_err(cdev->dev, "invalid address parameter, len = %llu\n",
			len);
		return -EINVAL;
	}

	if (cdev->iopf_feature == 0 && cdev->sva_mode == UMMU_SVA_SHARE_MODE) {
		dev_err(cdev->dev,
			"invalid sva mode, not support iopf, mode = %d\n",
			cdev->sva_mode);
		return -EINVAL;
	}

	return 0;
}

static struct cdma_umem *cdma_get_target_umem(struct cdma_umem_param *param,
					      struct page **page_list)
{
	struct cdma_dev *cdev = param->dev;
	struct cdma_umem *umem;
	u64 npages, pinned;
	u32 gup_flags;
	int ret = 0;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem) {
		ret = -ENOMEM;
		goto out;
	}

	cdma_fill_umem(umem, param);

	npages = cdma_cal_npages(umem->va, umem->length);
	if (!npages || npages > UINT_MAX) {
		dev_err(cdev->dev,
			"invalid npages %llu in getting target umem process\n",
			npages);
		ret = -EINVAL;
		goto umem_kfree;
	}

	if (param->is_kernel) {
		pinned = cdma_k_pin_pages(cdev, umem, npages);
	} else {
		gup_flags = param->flag.bs.writable ? FOLL_WRITE : 0;
		pinned = cdma_pin_pages(cdev, umem, npages, gup_flags,
					page_list);
	}

	if (pinned != npages) {
		ret = -ENOMEM;
		goto umem_release;
	}

	goto out;

umem_release:
	if (pinned)
		cdma_unpin_pages(umem, pinned, param->is_kernel, 0);
umem_kfree:
	kfree(umem);
out:
	return ret != 0 ? ERR_PTR(ret) : umem;
}

struct cdma_umem *cdma_umem_get(struct cdma_dev *cdev, u64 va, u64 len,
				bool is_kernel, struct cdma_context *ctx)
{
	struct cdma_umem_param param;
	struct page **page_list;
	struct cdma_umem *umem;
	int ret;

	ret = cdma_verify_mem(cdev, va, len);
	if (ret)
		return ERR_PTR(ret);

	page_list = (struct page **)__get_free_page(GFP_KERNEL);
	if (!page_list)
		return ERR_PTR(-ENOMEM);

	param.dev = cdev;
	param.va = va;
	param.len = len;
	param.flag.bs.writable = true;
	param.flag.bs.non_pin = 0;
	param.is_kernel = is_kernel;
	umem = cdma_get_target_umem(&param, page_list);
	if (IS_ERR(umem)) {
		dev_err(cdev->dev, "get target umem failed\n");
		goto free_page;
	}
	umem->sva_mode = cdev->sva_mode;

	if (!is_kernel && umem->sva_mode == UMMU_SVA_SEPARATE_MODE && ctx) {
		umem->tid = ctx->tid;
		ret = cdma_sva_matt_map(umem);
		if (ret) {
			dev_err(cdev->dev, "sva matt map failed\n");
			goto release_umem;
		}
	}

	goto free_page;

release_umem:
	cdma_put_target_umem(umem, is_kernel);
	umem = ERR_PTR(ret);
free_page:
	free_page((unsigned long)(uintptr_t)page_list);
	return umem;
}

int cdma_k_alloc_buf(struct cdma_dev *cdev, size_t memory_size,
		     struct cdma_buf *buf)
{
	size_t aligned_memory_size;
	int ret;

	aligned_memory_size = memory_size + CDMA_HW_PAGE_SIZE - 1;
	buf->va_aligned = vmalloc(aligned_memory_size);
	if (!buf->va_aligned) {
		dev_err(cdev->dev, "vmalloc kernel buf failed, size = %lu\n",
			aligned_memory_size);
		return -ENOMEM;
	}

	memset(buf->va_aligned, 0, aligned_memory_size);
	buf->umem = cdma_umem_get(cdev, (u64)buf->va_aligned,
				  aligned_memory_size, true, NULL);
	if (IS_ERR(buf->umem)) {
		ret = PTR_ERR(buf->umem);
		vfree(buf->va_aligned);
		dev_err(cdev->dev, "pin kernel buf failed, ret = %d\n", ret);
		return ret;
	}

	buf->addr = ((u64)buf->va_aligned + CDMA_HW_PAGE_SIZE - 1) &
		    ~(CDMA_HW_PAGE_SIZE - 1);
	buf->kva = (void *)buf->addr;

	return 0;
}

void cdma_k_free_buf(struct cdma_dev *cdev, struct cdma_buf *buf)
{
	cdma_put_umem(buf->umem, true);
	vfree(buf->va_aligned);
	buf->va_aligned = NULL;
	buf->kva = NULL;
	buf->addr = 0;
}
