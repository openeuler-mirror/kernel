// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
 * Description: ubcore device add and remove ops file
 * Author: Fan Yizhen
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: create file
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include "ubcore_log.h"
#include <urma/ubcore_types.h>

static void umem_unpin_pages(struct ubcore_umem *umem, uint64_t nents)
{
	struct scatterlist *sg;
	uint32_t i;

	for_each_sg(umem->sg_head.sgl, sg, nents, i) {
		struct page *page = sg_page(sg);
		unpin_user_page(page);
	}
	sg_free_table(&umem->sg_head);
}

static void umem_free_sgt(struct ubcore_umem *umem)
{
	umem_unpin_pages(umem, umem->sg_head.nents);
}

static inline uint64_t umem_cal_npages(uint64_t va, uint64_t len)
{
	return (ALIGN(va + len, PAGE_SIZE) - ALIGN_DOWN(va, PAGE_SIZE)) / PAGE_SIZE;
}

static int umem_pin_pages(uint64_t cur_base, uint64_t npages, uint32_t gup_flags,
			  struct page **page_list)
{
	int pinned;

	pinned = pin_user_pages_fast(cur_base,
				     min_t(unsigned long, (unsigned long)npages,
					   PAGE_SIZE / sizeof(struct page *)),
				     gup_flags | FOLL_LONGTERM, page_list);

	return pinned;
}

static uint64_t umem_atomic_add(uint64_t npages, struct mm_struct *mm)
{
	uint64_t ret;

	ret = atomic64_add_return(npages, &mm->pinned_vm);

	return ret;
}

static void umem_atomic_sub(uint64_t npages, struct mm_struct *mm)
{
	atomic64_sub(npages, &mm->pinned_vm);
}

static struct scatterlist *umem_sg_set_page(struct scatterlist *sg_start, int pinned,
					    struct page **page_list)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sg_start, sg, pinned, i) {
		sg_set_page(sg, page_list[i], PAGE_SIZE, 0);
	}
	return sg;
}

static int umem_add_new_pinned(struct ubcore_umem *umem, uint64_t npages)
{
	uint64_t lock_limit;
	uint64_t new_pinned;

	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	new_pinned = umem_atomic_add(npages, umem->owning_mm);
	if (new_pinned > lock_limit && !capable(CAP_IPC_LOCK)) {
		ubcore_log_err("Npages to be pinned is greater than RLIMIT_MEMLOCK[%llu].\n",
			       lock_limit);
		return -ENOMEM;
	}
	return 0;
}

static uint64_t umem_pin_all_pages(struct ubcore_umem *umem, uint64_t npages,
	uint32_t gup_flags, struct page **page_list)
{
	struct scatterlist *sg_list_start = umem->sg_head.sgl;
	uint64_t cur_base = umem->va & PAGE_MASK;
	uint64_t page_count = npages;
	int pinned;

	while (page_count != 0) {
		cond_resched();
		pinned = umem_pin_pages(cur_base, page_count, gup_flags, page_list);
		if (pinned < 0) {
			ubcore_log_err(
				"Pin pages failed, cur_base: %llx, page_count: %llx, pinned: %d.\n",
				cur_base, page_count, pinned);
			return npages - page_count;
		}
		cur_base += (uint64_t)pinned * PAGE_SIZE;
		page_count -= (uint64_t)pinned;
		sg_list_start = umem_sg_set_page(sg_list_start, pinned, page_list);
	}
	return npages;
}

static int umem_verify_input(struct ubcore_device *ub_dev, uint64_t va, uint64_t len,
			     union ubcore_umem_flag flag)
{
	if (ub_dev == NULL || ((va + len) < va) ||
		PAGE_ALIGN(va + len) < (va + len)) {
		ubcore_log_err("Invalid parameter, va or len is invalid.\n");
		return -EINVAL;
	}
	if (flag.bs.non_pin == 1) {
		ubcore_log_err("Non-pin mode is not supported.\n");
		return -EINVAL;
	}
	if (can_do_mlock() == 0)
		return -EPERM;
	return 0;
}

static int umem_dma_map(struct ubcore_umem *umem, uint64_t npages, unsigned long dma_attrs)
{
	int ret;

	ret = dma_map_sg_attrs(umem->ub_dev->dma_dev, umem->sg_head.sgl, (int)npages,
		DMA_BIDIRECTIONAL, dma_attrs);
	if (ret == 0) {
		ubcore_log_err("Dma map failed, ret: %d\n", ret);
		return -ENOMEM;
	}
	umem->nmap += (uint32_t)ret;
	return 0;
}

static int ubcore_fill_umem(struct ubcore_umem *umem, struct ubcore_device *dev, uint64_t va,
			     uint64_t len, union ubcore_umem_flag flag)
{
	umem->ub_dev = dev;
	umem->va = va;
	umem->length = len;
	umem->flag = flag;
	umem->owning_mm = current->mm;
	if (!umem->owning_mm) {
		ubcore_log_err("mm is null.\n");
		return -EINVAL;
	}
	mmgrab(umem->owning_mm);
	return 0;
}

static struct ubcore_umem *ubcore_get_target_umem(struct ubcore_device *dev, uint64_t va,
						  uint64_t len, union ubcore_umem_flag flag,
						  struct page **page_list)
{
	uint32_t gup_flags = (flag.bs.writable == 1) ? FOLL_WRITE : (FOLL_WRITE | FOLL_FORCE);
	unsigned long dma_attrs = 0;
	struct ubcore_umem *umem;
	uint64_t npages;
	uint64_t pinned;
	int ret = 0;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (umem == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = ubcore_fill_umem(umem, dev, va, len, flag);
	if (ret != 0) {
		kfree(umem);
		goto out;
	}

	npages = umem_cal_npages(umem->va, umem->length);
	if (npages == 0 || npages > UINT_MAX) {
		ret = -EINVAL;
		goto umem_kfree;
	}

	ret = umem_add_new_pinned(umem, npages);
	if (ret != 0)
		goto sub_pinned_vm;

	ret = sg_alloc_table(&umem->sg_head, (unsigned int)npages, GFP_KERNEL);
	if (ret != 0)
		goto sub_pinned_vm;

	pinned = umem_pin_all_pages(umem, npages, gup_flags, page_list);
	if (pinned != npages) {
		ret = -ENOMEM;
		goto umem_release;
	}

	ret = umem_dma_map(umem, npages, dma_attrs);
	if (ret != 0)
		goto umem_release;

	goto out;

umem_release:
	umem_unpin_pages(umem, pinned);
sub_pinned_vm:
	umem_atomic_sub(npages, umem->owning_mm);
umem_kfree:
	mmdrop(umem->owning_mm);
	kfree(umem);
out:
	free_page((unsigned long)page_list);
	return ret != 0 ? ERR_PTR(ret) : umem;
}

struct ubcore_umem *ubcore_umem_get(struct ubcore_device *dev, uint64_t va,
	uint64_t len, union ubcore_umem_flag flag)
{
	struct page **page_list;
	int ret;

	ret = umem_verify_input(dev, va, len, flag);
	if (ret < 0)
		return ERR_PTR(ret);

	page_list = (struct page **)__get_free_page(GFP_KERNEL);
	if (page_list == NULL)
		return ERR_PTR(-ENOMEM);

	return ubcore_get_target_umem(dev, va, len, flag, page_list);
}
EXPORT_SYMBOL(ubcore_umem_get);

void ubcore_umem_release(struct ubcore_umem *umem)
{
	uint64_t npages;

	if (IS_ERR_OR_NULL(umem) || umem->ub_dev == NULL || umem->owning_mm == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return;
	}

	if (((umem->va + umem->length) < umem->va) ||
		PAGE_ALIGN(umem->va + umem->length) < (umem->va + umem->length)) {
		ubcore_log_err("Invalid parameter, va or len is invalid.\n");
		return;
	}

	npages = umem_cal_npages(umem->va, umem->length);
	dma_unmap_sg(umem->ub_dev->dma_dev, umem->sg_head.sgl, (int)umem->nmap, DMA_BIDIRECTIONAL);
	umem_free_sgt(umem);
	umem_atomic_sub(npages, umem->owning_mm);
	mmdrop(umem->owning_mm);
	kfree(umem);
}
EXPORT_SYMBOL(ubcore_umem_release);
