/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PAGE_H
#define _ASM_SW64_PAGE_H

#include <linux/const.h>
#include <asm/hmcall.h>

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT		13
#define PAGE_SIZE		(_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE - 1))

#define HPAGE_SHIFT		PMD_SHIFT
#define HPAGE_SIZE		(_AC(1, UL) << HPAGE_SHIFT)
#define HPAGE_MASK		(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)

#define HUGE_MAX_HSTATE		2

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

extern void clear_page(void *page);
#define clear_user_page(page, vaddr, pg)	clear_page(page)

#define __alloc_zeroed_user_highpage(movableflags, vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO | movableflags, vma, vaddr)
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

extern void copy_page(void *_to, void *_from);
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

typedef struct page *pgtable_t;

extern unsigned long __phys_addr(unsigned long);
#endif /* !__ASSEMBLY__ */

#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)

#include <asm/pgtable-4level.h>

#if defined(CONFIG_SW64_LEGACY_KTEXT_ADDRESS)
#define __START_KERNEL_map	PAGE_OFFSET
#else
#define __START_KERNEL_map	0xffffffff80000000
#endif

#define __pa(x)			__phys_addr((unsigned long)(x))
#define __va(x)			((void *)((unsigned long) (x) | PAGE_OFFSET))
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#define virt_to_pfn(vaddr)	(PHYS_PFN(__pa(vaddr)))
#define pfn_to_virt(pfn)	(__va(PFN_PHYS(pfn)))

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif /* CONFIG_FLATMEM */

#define VM_DATA_DEFAULT_FLAGS		(VM_READ | VM_WRITE | VM_EXEC | \
					 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>
#endif

#endif /* _ASM_SW64_PAGE_H */
