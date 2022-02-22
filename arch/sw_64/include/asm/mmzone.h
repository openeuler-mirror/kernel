/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_MMZONE_H
#define _ASM_SW64_MMZONE_H

#include <asm/smp.h>

/*
 * Following are macros that are specific to this numa platform.
 */

extern pg_data_t *node_data[];

#ifdef CONFIG_NEED_MULTIPLE_NODES
#define NODE_DATA(nid)		(node_data[(nid)])
#endif

#ifdef CONFIG_DISCONTIGMEM
extern int pa_to_nid(unsigned long pa);
extern int pfn_valid(unsigned long pfn);

#define mk_pte(page, pgprot)							\
({										\
	pte_t pte;								\
	unsigned long pfn;							\
										\
	pfn = page_to_pfn(page) << _PTE_FLAGS_BITS;				\
	pte_val(pte) = pfn | pgprot_val(pgprot);				\
										\
	pte;									\
})

#define pte_page(x)								\
({										\
	unsigned long kvirt;							\
	struct page *__xx;							\
										\
	kvirt = (unsigned long)__va(pte_val(x) >> (_PTE_FLAGS_BITS-PAGE_SHIFT));\
	__xx = virt_to_page(kvirt);						\
										\
	__xx;									\
})

#define page_to_pa(page)	(page_to_pfn(page) << PAGE_SHIFT)
#define pfn_to_nid(pfn)		pa_to_nid(((u64)(pfn) << PAGE_SHIFT))
#endif /* CONFIG_DISCONTIGMEM */

#endif /* _ASM_SW64_MMZONE_H */
