// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 * Description: export sg_table walk, flush, map and query cores.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/io.h>

#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_backend.h"	/* struct obmm_export_common */
#include "obmm_export_region_ops.h"

/**
 * walk_fn for one sg chunk of an export backend.
 * @start: start physical address.
 * @end: end physical address.
 * @offset: offset of `start` address from the backend's beginning.
 * @arg: private argument.
 */
typedef int (*walk_fn)(phys_addr_t start, phys_addr_t end, unsigned long offset, void *arg);

/*
 * this function stops if walk_fn returns an error.
 */
static void walk_export_memory(const struct sg_table *sgt, unsigned long offset,
			       unsigned long length, walk_fn fn, void *arg)
{
	struct scatterlist *sg;
	/* the offset of current sg from the backend's beginning */
	unsigned long offset_from_head = 0;
	unsigned int i;
	int ret = 0;

	if (length == 0)
		return;

	for_each_sgtable_sg(sgt, sg, i) {
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

/* Walk the sg_table: the sg chunk count is unbounded, so no segment array. */
int obmm_export_phys_at(const struct sg_table *sgt, u64 off, u64 *phys,
			u64 *seg_end)
{
	struct scatterlist *sg;
	u64 seg_off = 0;
	unsigned int i;

	for_each_sgtable_sg(sgt, sg, i) {
		u64 delta = off - seg_off;

		if (delta < sg->length) {
			*phys = page_to_phys(sg_page(sg)) + delta;
			if (seg_end)
				*seg_end = seg_off + sg->length;
			return 0;
		}
		seg_off += sg->length;
	}

	return -ERANGE;
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

/* Per-chunk cache flush of an export sg_table; no export write-queue drain. */
int export_flush_sgt(const struct sg_table *sgt, unsigned long offset, unsigned long length,
		     unsigned long cache_ops)
{
	struct flush_cache_info info = { 0 };

	info.cache_ops = cache_ops;
	walk_export_memory(sgt, offset, length, flush_cache_call, &info);

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

int kernel_pgtable_set_export_invalid(const struct sg_table *sgt, unsigned long offset,
				      unsigned long length, bool set_inval)
{
	struct kernel_pgtable_info info = { 0 };

	if (offset % OBMM_MEMSEG_SIZE != 0 || length % OBMM_MEMSEG_SIZE != 0) {
		pr_err("%s: invalid param: offset=%#lx length=%#lx", __func__, offset, length);
		return -EINVAL;
	}

	info.set_inval = set_inval;
	walk_export_memory(sgt, offset, length, kernel_pgtable_invalid_call, &info);
	pr_debug("%s: [flush_offset=0x%lx, flush_len=0x%lx, set_inval=%d, ret=%pe]\n",
		 __func__, offset, length, set_inval, ERR_PTR(info.ret));
	return info.ret;
}

struct map_range_info {
	struct vm_area_struct *vma;
	enum obmm_mmap_granu mmap_granu;
	int regionid;
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
		pr_err("%s: failed to call remap_pfn_range on region %d: offset=%#lx, length=%#lx, ret=%pe\n",
		       __func__, info->regionid, offset, length, ERR_PTR(info->ret));
		return -1;
	}

	return 0;
}

/* Eager core of the pool map_range op: map [vma pgoff, +size) per chunk. */
int export_map_range(struct vm_area_struct *vma, const struct sg_table *sgt, int regionid,
		     enum obmm_mmap_granu mmap_granu)
{
	struct map_range_info info;
	unsigned long size, offset;

	info.vma = vma;
	info.ret = 0;
	info.regionid = regionid;
	info.mmap_granu = mmap_granu;

	size = vma->vm_end - vma->vm_start;
	offset = vma->vm_pgoff << PAGE_SHIFT;

	walk_export_memory(sgt, offset, size, map_range_call, (void *)(&info));

	return info.ret;
}

static void export_fill_ext_addr(const struct obmm_export_common *exp, u32 regionid,
				 u64 offset, u64 pa, struct obmm_ext_addr *ext_addr)
{
	ext_addr->region_type = OBMM_EXPORT_REGION;
	ext_addr->regionid = regionid;
	ext_addr->offset = offset;
	ext_addr->tid = exp->tokenid;
	ext_addr->uba = exp->uba + offset;
	ext_addr->numa_id = NUMA_NO_NODE;
	ext_addr->pa = pa;
}

/* By-offset query shared by both export backends. */
int export_query(struct obmm_backend *be, struct obmm_ext_addr *out)
{
	struct obmm_export_common *exp = obmm_backend_to_export_common(be);
	u64 pa;

	if (!be->shell)
		return -EINVAL;
	if (out->offset >= be->mem_size) {
		pr_err("%s: invalid offset 0x%llx\n", __func__, out->offset);
		return -EINVAL;
	}

	if (obmm_export_phys_at(&exp->sgt, out->offset, &pa, NULL)) {
		pr_err("%s: internal bug encountered\n", __func__);
		return -ENODATA;
	}

	export_fill_ext_addr(exp, be->shell->regionid, out->offset, pa, out);
	return 0;
}

/* [pa, pa+len) must fit one sg chunk; the table is not PA-sorted, so test
 * containment per chunk.
 */
bool export_covers_pa(struct obmm_backend *be, u64 pa, u64 len,
		      struct obmm_ext_addr *out)
{
	const struct obmm_export_common *exp = obmm_backend_to_export_common(be);
	const struct sg_table *sgt = &exp->sgt;
	struct scatterlist *sg;
	u64 offset = 0;
	unsigned int i;

	for_each_sgtable_sg(sgt, sg, i) {
		u64 start = page_to_phys(sg_page(sg));

		if (pa >= start && pa - start < sg->length &&
		    len <= sg->length - (pa - start)) {
			if (out)
				export_fill_ext_addr(exp, be->regionid,
						     offset + (pa - start), pa, out);
			return true;
		}
		offset += sg->length;
	}

	return false;
}
