/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Jun Chen
 * Co-Author: Jiangtian Feng
 */
#ifndef __GMEM_KSYMBOL_H__
#define __GMEM_KSYMBOL_H__

#include <linux/map.h>

typedef int (*rmap_walk_anon_symbol_t)(struct page *page,
		struct rmap_walk_control *rwc, bool locked);
extern rmap_walk_anon_symbol_t rmap_walk_anon_symbol;

typedef int (*__anon_vma_prepare_symbol_t)(struct vm_area_struct *vma);
extern __anon_vma_prepare_symbol_t __anon_vma_prepare_symbol;

typedef int (*__page_set_anon_rmap_symbol_t)(struct page *page,
		struct vm_area_struct *vma,	unsigned long address, int exclusive);
extern __page_set_anon_rmap_symbol_t __page_set_anon_rmap_symbol;

typedef int (*pgtable_trans_huge_deposit_symbol_t)(struct mm_struct *mm,
		pmd_t *pmdp, pgtable_t pgtable);
extern pgtable_trans_huge_deposit_symbol_t pgtable_trans_huge_deposit_symbol;

typedef int (*pgtable_trans_huge_withdraw_symbol_t)(struct mm_struct *mm,
		pmd_t *pmdp);
extern pgtable_trans_huge_withdraw_symbol_t pgtable_trans_huge_withdraw_symbol;

int kernel_symbol_init(void);

#endif
