// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/wait.h>
#include <linux/mmzone.h>

#include <uapi/linux/sched/types.h>

#include <uapi/ub/obmm.h>
#include <linux/ummu_core.h>
#include "conti_mem_allocator.h"
#include "ubmempool_allocator.h"
#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_export_region_ops.h"

/**
 * walk_fn for one obmm_export_region.
 * @start: start physical address.
 * @end: end physical address.
 * @offset: offset of `start` address in this obmm_export_region.
 * @arg: private argument.
 */
typedef int (*walk_fn)(phys_addr_t start, phys_addr_t end, unsigned long offset, void *arg);

/*
 * this function stops if walk_fn returns an error.
 */
static void walk_export_memory(const struct obmm_export_region *e_reg, unsigned long offset,
			       unsigned long length, walk_fn fn, void *arg)
{
	struct scatterlist *sg;
	/* the offset of current sg from the region's beginning */
	unsigned long offset_from_head = 0;
	unsigned int i;
	int ret = 0;

	if (length == 0)
		return;

	for_each_sgtable_sg(&e_reg->sgt, sg, i) {
		phys_addr_t start, size;

		if (offset >= sg->length) {
			offset -= sg->length;
			offset_from_head += sg->length;
			continue;
		}

		/* now the offset is an intra-sg offset */
		start = page_to_phys(sg_page(sg)) + offset;
		size = min(sg->length, offset + length) - offset;

		ret = fn(start, start + size - 1, offset_from_head + offset, arg);
		if (ret)
			return;

		offset = 0;
		length -= size;
		if (length == 0)
			break;

		offset_from_head += sg->length;
	}

	if (ret == 0 && length != 0)
		pr_warn("%s: excessive length: %#lx bytes not walked.\n", __func__, length);
}

struct flush_cache_info {
	int ret;
	int succ_flush_count;
	int total_flush_count;
	unsigned long cache_ops;
};

static int flush_cache_call(phys_addr_t start, phys_addr_t end,
			    unsigned long offset __always_unused, void *arg)
{
	struct flush_cache_info *info = (struct flush_cache_info *)arg;

	int ret = flush_cache_by_pa(start, end - start + 1, info->cache_ops);

	if (ret == 0)
		info->succ_flush_count++;
	else if (info->ret == 0)
		info->ret = ret;
	else if (info->ret != ret)
		pr_warn("multiple flush error types detected: new flush_ret=%pe.\n", ERR_PTR(ret));
	info->total_flush_count++;

	return 0;
}

int flush_export_region(struct obmm_export_region *e_reg, unsigned long offset,
			unsigned long length, unsigned long cache_ops)
{
	struct flush_cache_info info = { 0 };

	info.cache_ops = cache_ops;
	walk_export_memory(e_reg, offset, length, flush_cache_call, &info);

	pr_debug("export region flushed: flush_offset:0x%lx, flush_len:0x%lx, cache_ops:%lu, flush_round:%d, flush_succ_round:%d, flush_retval:%pe.\n",
		 offset, length, cache_ops, info.total_flush_count, info.succ_flush_count,
		 ERR_PTR(info.ret));
	return info.ret;
}

struct kernel_pgtable_info {
	int ret;
	bool set_inval;
};

static int kernel_pgtable_invalid_call(phys_addr_t start, phys_addr_t end,
				       unsigned long offset __always_unused, void *arg)
{
	struct kernel_pgtable_info *info = (struct kernel_pgtable_info *)arg;
	int ret;
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long end_pfn = (end + 1) >> PAGE_SHIFT;

	pr_debug("call external: set_linear_mapping_invalid(set_inval=%d)\n", info->set_inval);
	ret = set_linear_mapping_invalid(start_pfn, end_pfn, info->set_inval);
	if (ret < 0) {
		pr_err("error calling set_linear_mapping_invalid(set_inval=%d): ret=%pe\n",
		       info->set_inval, ERR_PTR(ret));
	} else {
		pr_debug("external called: set_linear_mapping_invalid(set_inval=%d, ret=%pe)\n",
			 info->set_inval, ERR_PTR(ret));
	}

	info->ret = ret;
	return 0;
}

int kernel_pgtable_set_export_invalid(struct obmm_export_region *e_reg, unsigned long offset,
				      unsigned long length, bool set_inval)
{
	struct kernel_pgtable_info info = { 0 };

	if (offset % OBMM_MEMSEG_SIZE != 0 || length % OBMM_MEMSEG_SIZE != 0) {
		pr_err("%s: invalid param: offset=%#lx length=%#lx", __func__, offset, length);
		return -EINVAL;
	}

	info.set_inval = set_inval;
	walk_export_memory(e_reg, offset, length, kernel_pgtable_invalid_call, &info);
	pr_debug("%s: [flush_offset=0x%lx, flush_len=0x%lx, set_inval=%d, ret=%pe]\n",
		 __func__, offset, length, set_inval, ERR_PTR(info.ret));
	return info.ret;
}

struct map_range_info {
	struct obmm_export_region *e_reg;
	struct vm_area_struct *vma;
	enum obmm_mmap_granu mmap_granu;
	int ret;
};

static int map_range_call(phys_addr_t start, phys_addr_t end, unsigned long offset, void *arg)
{
	struct map_range_info *info = (struct map_range_info *)arg;
	unsigned long length = end - start + 1;
	unsigned long vm_offset;

	vm_offset = offset - (info->vma->vm_pgoff << PAGE_SHIFT);
	if (info->mmap_granu == OBMM_MMAP_GRANU_PAGE) {
		info->ret = remap_pfn_range(info->vma, info->vma->vm_start + vm_offset,
					    start >> PAGE_SHIFT, length, info->vma->vm_page_prot);
	} else if (info->mmap_granu == OBMM_MMAP_GRANU_PMD) {
		info->ret = remap_pfn_range_try_pmd(info->vma, info->vma->vm_start + vm_offset,
						    start >> PAGE_SHIFT, length,
						    info->vma->vm_page_prot);
	} else {
		pr_err("invalid mmap granu: %d\n", info->mmap_granu);
		info->ret = -EINVAL;
	}
	if (info->ret) {
		pr_err("map_export_region: failed to call remap_pfn_range on region %d: offset=%#lx, length=%#lx, ret=%pe]\n",
		       info->e_reg->region.regionid, offset, length, ERR_PTR(info->ret));
		return -1;
	}

	return 0;
}

int map_export_region(struct vm_area_struct *vma, struct obmm_export_region *e_reg,
		      enum obmm_mmap_granu mmap_granu)
{
	struct map_range_info info;
	unsigned long size, offset;

	info.e_reg = e_reg;
	info.vma = vma;
	info.ret = 0;
	info.mmap_granu = mmap_granu;

	size = vma->vm_end - vma->vm_start;
	offset = vma->vm_pgoff << PAGE_SHIFT;

	walk_export_memory(e_reg, offset, size, map_range_call, (void *)(&info));

	return info.ret;
}

struct pa_info {
	unsigned long pa;
	unsigned long offset;
	bool found;
};

static int search_offset_from_pa(phys_addr_t start, phys_addr_t end, unsigned long offset,
				 void *arg)
{
	struct pa_info *info = (struct pa_info *)arg;

	if (info->pa >= start && info->pa <= end) {
		info->offset = info->pa - start + offset;
		info->found = true;
		/* end iterator */
		return -1;
	}

	return 0;
}

/* terminate iteration in all cases */
static int search_pa_from_offset(phys_addr_t start, phys_addr_t end __always_unused,
				 unsigned long offset, void *arg)
{
	struct pa_info *info = (struct pa_info *)arg;

	if (offset != info->offset) {
		pr_warn("iterator bug encountered in %s, iter.offset=%#lx, expect %#lx.\n",
			__func__, offset, info->offset);
		info->found = false;
		return -1;
	}

	info->pa = start;
	info->found = true;
	return -1;
}

int get_pa_detail_export_region(const struct obmm_export_region *e_reg, unsigned long pa,
				struct obmm_ext_addr *ext_addr)
{
	struct pa_info info = { 0 };

	info.pa = pa;
	walk_export_memory(e_reg, 0, e_reg->region.mem_size, search_offset_from_pa, &info);

	/* not found */
	if (!info.found)
		return -EFAULT;

	/* found */
	ext_addr->region_type = OBMM_EXPORT_REGION;
	ext_addr->regionid = e_reg->region.regionid;
	ext_addr->offset = info.offset;
	ext_addr->tid = e_reg->tokenid;
	ext_addr->uba = e_reg->uba + info.offset;
	ext_addr->numa_id = NUMA_NO_NODE;
	ext_addr->pa = pa;

	return 0;
}

int get_offset_detail_export_region(const struct obmm_export_region *e_reg, unsigned long offset,
				    struct obmm_ext_addr *ext_addr)
{
	struct pa_info info = { 0 };

	if (offset >= e_reg->region.mem_size) {
		pr_err("%s: invalid offset 0x%lx\n", __func__, offset);
		return -EINVAL;
	}

	info.offset = offset;
	walk_export_memory(e_reg, offset, 1, search_pa_from_offset, &info);
	if (!info.found) {
		/* Offset has been checked at the beginning of this function. If the code reaches
		 * here, it must be an implementation error.
		 */
		pr_err("%s: internal bug encountered\n", __func__);
		return -ENODATA;
	}

	ext_addr->region_type = e_reg->region.type;
	ext_addr->regionid = e_reg->region.regionid;
	ext_addr->offset = offset;
	ext_addr->tid = e_reg->tokenid;
	ext_addr->uba = e_reg->uba + offset;
	ext_addr->pa = info.pa;
	/* to be decided */
	ext_addr->numa_id = NUMA_NO_NODE;

	return 0;
}
