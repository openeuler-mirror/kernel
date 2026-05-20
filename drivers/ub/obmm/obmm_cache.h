/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 */
#ifndef OBMM_CACHE_H
#define OBMM_CACHE_H

#include <uapi/misc/hisi_soc_cache/hisi_soc_cache.h>
#include "obmm_core.h"

int ub_write_queue_flush(uint32_t scna);

/* This function serializes all cache flush request issued by OBMM to avoid
 * hardware resource contention
 */
int flush_cache_by_pa(phys_addr_t addr, size_t size, unsigned long cache_ops);
int obmm_region_flush_range(struct obmm_region *reg, unsigned long offset, unsigned long length,
			    uint8_t cache_ops);
void obmm_flush_tlb(struct mm_struct *mm);

static inline bool obmm_is_valid_cache_ops(unsigned long cache_ops)
{
	if (cache_ops == OBMM_SHM_CACHE_NONE || cache_ops == OBMM_SHM_CACHE_INVAL ||
	    cache_ops == OBMM_SHM_CACHE_WB_ONLY || cache_ops == OBMM_SHM_CACHE_WB_INVAL)
		return true;
	pr_err("Invalid cache operations: %#lx\n", cache_ops);
	return false;
}
/* Caller must guarantee that there is no concurrent modify requests made to the same va range. */
int modify_pgtable_prot(struct mm_struct *mm, void *va, size_t size, bool cacheable);
int obmm_cache_clear(void);

/* Defined in drivsers/soc/hisilicon, exported but not defined in their header file. */
extern int hisi_soc_cache_maintain(phys_addr_t addr, size_t size,
				   enum hisi_soc_cache_maint_type maint_type);

#endif
