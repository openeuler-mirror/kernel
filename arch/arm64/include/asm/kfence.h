/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64 KFENCE support.
 *
 * Copyright (C) 2020, Google LLC.
 */

#ifndef __ASM_KFENCE_H
#define __ASM_KFENCE_H

#include <linux/kfence.h>
#include <asm/cacheflush.h>
#include <asm/pgalloc.h>

static inline int split_pud_page(pud_t *pud, unsigned long addr)
{
	int i;
	pmd_t *pmd = pmd_alloc_one(&init_mm, addr);
	unsigned long pfn = PFN_DOWN(__pa(addr));

	if (!pmd)
		return -ENOMEM;

	for (i = 0; i < PTRS_PER_PMD; i++)
		set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PTE, PAGE_KERNEL)));

	smp_wmb(); /* See comment in __pte_alloc */
	pud_populate(&init_mm, pud, pmd);

	flush_tlb_kernel_range(addr, addr + PUD_SIZE);
	return 0;
}

static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
{
	int i;
	pte_t *pte = pte_alloc_one_kernel(&init_mm);
	unsigned long pfn = PFN_DOWN(__pa(addr));

	if (!pte)
		return -ENOMEM;

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));

	smp_wmb(); /* See comment in __pte_alloc */
	pmd_populate_kernel(&init_mm, pmd, pte);

	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
	return 0;
}

static inline bool arch_kfence_init_pool(void)
{
	unsigned long addr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
	     addr += PAGE_SIZE) {
		pgd = pgd_offset(&init_mm, addr);
		if (pgd_leaf(*pgd))
			return false;
		p4d = p4d_offset(pgd, addr);
		if (p4d_leaf(*p4d))
			return false;
		pud = pud_offset(p4d, addr);
		if (pud_leaf(*pud)) {
			if (split_pud_page(pud, addr & PUD_MASK))
				return false;
		}
		pmd = pmd_offset(pud, addr);
		if (pmd_leaf(*pmd)) {
			if (split_pmd_page(pmd, addr & PMD_MASK))
				return false;
		}
	}
	return true;
}

static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	set_memory_valid(addr, 1, !protect);

	return true;
}

#endif /* __ASM_KFENCE_H */
