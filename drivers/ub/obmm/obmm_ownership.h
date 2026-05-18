/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 */

#ifndef OBMM_OWNERSHIP_H
#define OBMM_OWNERSHIP_H

#include "obmm_core.h"

/* Per-page ownership counters - r/w kept together for cache locality */
struct obmm_page_state {
	uint16_t r_count;
	uint16_t w_count;
};

struct obmm_ownership_info {
	struct obmm_page_state *page_states;
	int nentries;
};

/* Extract access bits from vm_flags using uapi OBMM_SHM_MEM_* definitions */
static inline uint8_t vm_flags_to_access(vm_flags_t flags)
{
	if (flags & VM_WRITE)
		return OBMM_SHM_MEM_READWRITE;
	if (flags & VM_READ)
		return (flags & VM_EXEC) ? OBMM_SHM_MEM_READEXEC : OBMM_SHM_MEM_READONLY;
	return OBMM_SHM_MEM_NO_ACCESS;
}

static inline bool obmm_access_is_reader(uint8_t access)
{
	return (access & OBMM_SHM_MEM_ACCESS_MASK) != OBMM_SHM_MEM_NO_ACCESS;
}

static inline bool obmm_access_is_writer(uint8_t access)
{
	return (access & OBMM_SHM_MEM_ACCESS_MASK) == OBMM_SHM_MEM_READWRITE;
}

/* Convert pgoff to ownership array index based on mmap granularity */
static inline unsigned long ownership_pgoff_to_index(const struct obmm_region *reg,
						      unsigned long pgoff)
{
	if (reg->mmap_granu == OBMM_MMAP_GRANU_PMD)
		return pgoff >> (PMD_SHIFT - PAGE_SHIFT);
	return pgoff;
}

/* Convert size in bytes to ownership array entry count */
static inline unsigned long ownership_size_to_nentries(const struct obmm_region *reg,
							unsigned long size)
{
	if (reg->mmap_granu == OBMM_MMAP_GRANU_PMD)
		return size >> PMD_SHIFT;
	return size >> PAGE_SHIFT;
}

/* Convert VM flags to mem_state */
static inline unsigned long vm_flags_to_mem_state(vm_flags_t vm_flags, bool cacheable)
{
	unsigned long access = vm_flags_to_access(vm_flags);

	if (access != OBMM_SHM_MEM_NO_ACCESS)
		access |= cacheable ? OBMM_SHM_MEM_NORMAL : OBMM_SHM_MEM_NORMAL_NC;

	return access;
}

/* Convert access bits to vm_flags (R/W only, preserves existing EXEC) */
vm_flags_t access_to_vm_flags(uint8_t access);
uint8_t merge_cache_ops(uint8_t ops1, uint8_t ops2);
uint8_t update_vma_perm_count(struct obmm_region *reg,
			      unsigned long region_pgoff,
			      unsigned long npages,
			      uint8_t old_access,
			      uint8_t new_access);
int init_ownership_info(struct obmm_region *reg);
void release_ownership_info(struct obmm_region *reg);

#endif
