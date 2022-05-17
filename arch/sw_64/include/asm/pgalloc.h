/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PGALLOC_H
#define _ASM_SW64_PGALLOC_H

#include <linux/mm.h>
#include <linux/mmzone.h>
#include <asm-generic/pgalloc.h>        /* for pte_{alloc,free}_one */

/*
 * Allocate and free page tables. The xxx_kernel() versions are
 * used to allocate a kernel page table - this turns on ASN bits
 * if any.
 */

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmd, pgtable_t pte)
{
	pmd_set(pmd, (pte_t *)__va(page_to_pa(pte)));
}
#define pmd_pgtable(pmd) pmd_page(pmd)

static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	pmd_set(pmd, pte);
}

static inline void
p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	p4d_set(p4d, pud);
}

static inline void
pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, pmd);
}

extern pgd_t *pgd_alloc(struct mm_struct *mm);

#define check_pgt_cache()	do { } while (0)

#endif /* _ASM_SW64_PGALLOC_H */
