/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 */
#ifndef OBMM_EXPORT_REGION_H
#define OBMM_EXPORT_REGION_H

#include "obmm_core.h"

struct sg_table;
struct obmm_export_common;

/* Backend-ops machinery: the sg-table walk and its flush/query cores, the
 * type-independent ops both export tables assign, and the per-type memory
 * sources in obmm_export_from_pool.c / obmm_export_from_user.c.
 */
int export_flush_sgt(const struct sg_table *sgt, unsigned long offset, unsigned long length,
		     unsigned long cache_ops);
/* offset within an export backend's sg_table -> physical address; -ERANGE
 * past the end.
 */
int obmm_export_phys_at(const struct sg_table *sgt, u64 off, u64 *phys);
/* Prove [off, off + len) maps to one physically linear PA range; @phys gets
 * the base PA. Every sg seam inside the window must continue the PA line:
 * the table is built in allocation order, not PA order.
 */
int obmm_export_phys_linear_at(const struct sg_table *sgt, u64 off, u64 len,
			       u64 *phys);
int export_query(struct obmm_backend *be, struct obmm_ext_addr *out);
bool export_covers_pa(struct obmm_backend *be, u64 pa, u64 len,
		      struct obmm_ext_addr *out);

int kernel_pgtable_set_export_invalid(const struct sg_table *sgt, unsigned long offset,
				      unsigned long length, bool set_nc);

#endif
