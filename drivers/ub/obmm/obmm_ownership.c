// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: OBMM ownership tracking - region level R/W counters
 */

#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "obmm_cache.h"
#include "obmm_core.h"
#include "obmm_ownership.h"

/* Merge cache ops: WB_ONLY + INVAL = WB_INVAL, others return stronger op */
uint8_t merge_cache_ops(uint8_t ops1, uint8_t ops2)
{
	if (ops1 == OBMM_SHM_CACHE_NONE)
		return ops2;
	if (ops2 == OBMM_SHM_CACHE_NONE)
		return ops1;
	if (ops1 == OBMM_SHM_CACHE_WB_INVAL || ops2 == OBMM_SHM_CACHE_WB_INVAL)
		return OBMM_SHM_CACHE_WB_INVAL;
	if ((ops1 == OBMM_SHM_CACHE_WB_ONLY && ops2 == OBMM_SHM_CACHE_INVAL) ||
	    (ops1 == OBMM_SHM_CACHE_INVAL && ops2 == OBMM_SHM_CACHE_WB_ONLY))
		return OBMM_SHM_CACHE_WB_INVAL;
	return ops1;
}

/* Update R/W counters for a page, return cache op needed */
static uint8_t update_page_ownership(struct obmm_ownership_info *ownership,
				     unsigned long pgoff,
				     uint8_t old_access,
				     uint8_t new_access)
{
	struct obmm_page_state *page = &ownership->page_states[pgoff];
	uint16_t old_w = page->w_count;
	uint16_t old_r = page->r_count;
	uint16_t new_w, new_r;

	if (obmm_access_is_writer(old_access))
		page->w_count--;
	if (obmm_access_is_reader(old_access))
		page->r_count--;
	if (obmm_access_is_writer(new_access))
		page->w_count++;
	if (obmm_access_is_reader(new_access))
		page->r_count++;

	new_w = page->w_count;
	new_r = page->r_count;

	if (old_w > 0 && new_w == 0)
		return new_r > 0 ? OBMM_SHM_CACHE_WB_ONLY : OBMM_SHM_CACHE_WB_INVAL;
	if (old_r > 0 && new_r == 0 && new_w == 0)
		return OBMM_SHM_CACHE_INVAL;
	return OBMM_SHM_CACHE_NONE;
}

/* Update counters for VMA range, return combined cache op */
uint8_t update_vma_perm_count(struct obmm_region *reg,
			      unsigned long region_pgoff,
			      unsigned long npages,
			      uint8_t old_access,
			      uint8_t new_access)
{
	struct obmm_ownership_info *ownership = reg->ownership_info;
	uint8_t combined_ops = OBMM_SHM_CACHE_NONE, op;
	unsigned long start_idx, nentries, i;

	if (!ownership)
		return OBMM_SHM_CACHE_NONE;

	start_idx = ownership_pgoff_to_index(reg, region_pgoff);
	nentries = ownership_size_to_nentries(reg, npages << PAGE_SHIFT);

	for (i = 0; i < nentries; i++) {
		op = update_page_ownership(ownership, start_idx + i, old_access, new_access);
		combined_ops = merge_cache_ops(combined_ops, op);
	}

	return combined_ops;
}

/* Convert access bits to vm_flags (R/W only, preserves existing EXEC) */
vm_flags_t access_to_vm_flags(uint8_t access)
{
	switch (access & OBMM_SHM_MEM_ACCESS_MASK) {
	case OBMM_SHM_MEM_READWRITE:
		return VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE;
	case OBMM_SHM_MEM_READEXEC:
		return VM_READ | VM_MAYREAD;
	case OBMM_SHM_MEM_READONLY:
		return VM_READ | VM_MAYREAD;
	default:
		return 0;
	}
}

int init_ownership_info(struct obmm_region *reg)
{
	struct obmm_ownership_info *info;
	unsigned long nentries;

	if (reg->ownership_info)
		return 0;

	if (reg->mmap_granu == OBMM_MMAP_GRANU_NONE) {
		pr_err("init ownership: mmap_granu not set\n");
		return -EINVAL;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	nentries = ownership_size_to_nentries(reg, reg->mem_size);
	info->page_states = vzalloc(sizeof(struct obmm_page_state) * nentries);
	if (!info->page_states)
		goto err_pages;

	/* mem_size >> PMD_SHIFT always fits in int */
	info->nentries = (int)nentries;
	reg->ownership_info = info;

	pr_debug("init ownership: granu=%d nentries=%lu\n", reg->mmap_granu, nentries);
	return 0;

err_pages:
	kfree(info);
	return -ENOMEM;
}

void release_ownership_info(struct obmm_region *reg)
{
	struct obmm_ownership_info *info = reg->ownership_info;

	if (!info)
		return;

	reg->ownership_info = NULL;
	vfree(info->page_states);
	kfree(info);
}
