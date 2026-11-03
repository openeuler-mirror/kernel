/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 */
#ifndef OBMM_EXPORT_REGION_H
#define OBMM_EXPORT_REGION_H

#include "obmm_core.h"

struct sg_table;
struct obmm_export_common;

/* Backend-ops machinery: the sg-table walk and its flush/map/query cores,
 * the type-independent ops both export tables assign, and the per-type
 * memory sources in obmm_export_from_pool.c / obmm_export_from_user.c.
 */
int export_flush_sgt(const struct sg_table *sgt, unsigned long offset, unsigned long length,
		     unsigned long cache_ops);
int export_map_range(struct vm_area_struct *vma, const struct sg_table *sgt, int regionid,
		     enum obmm_mmap_granu mmap_granu);
/* offset within an export backend's sg_table -> physical address; -ERANGE
 * past the end. When non-NULL, @seg_end receives the containing segment's
 * end offset so a caller can test further range containment without a walk.
 */
int obmm_export_phys_at(const struct sg_table *sgt, u64 off, u64 *phys,
			u64 *seg_end);
int export_query(struct obmm_backend *be, struct obmm_ext_addr *out);
bool export_covers_pa(struct obmm_backend *be, u64 pa, u64 len,
		      struct obmm_ext_addr *out);

int kernel_pgtable_set_export_invalid(const struct sg_table *sgt, unsigned long offset,
				      unsigned long length, bool set_nc);

#endif
