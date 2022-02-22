/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_HUGETLB_H
#define _ASM_SW64_HUGETLB_H

#include <asm/page.h>
#include <asm-generic/hugetlb.h>

static inline void hugetlb_prefault_arch_hook(struct mm_struct *mm)
{
}

void hugetlb_free_pgd_range(struct mmu_gather *tlb, unsigned long addr,
			    unsigned long end, unsigned long floor,
			    unsigned long ceiling);

static inline int arch_prepare_hugepage(struct page *page)
{
	return 0;
}

static inline void arch_release_hugepage(struct page *page)
{
}

#endif /* _ASM_SW64_HUGETLB_H */
