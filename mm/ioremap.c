// SPDX-License-Identifier: GPL-2.0
/*
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
static bool __ro_after_init iomap_max_page_shift = PAGE_SHIFT;

static int __init set_nohugeiomap(char *str)
{
	iomap_max_page_shift = P4D_SHIFT;
	return 0;
}
early_param("nohugeiomap", set_nohugeiomap);
#else /* CONFIG_HAVE_ARCH_HUGE_VMAP */
static const bool iomap_max_page_shift = PAGE_SHIFT;
#endif	/* CONFIG_HAVE_ARCH_HUGE_VMAP */

int ioremap_page_range(unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	return vmap_range(addr, end, phys_addr, prot, iomap_max_page_shift);
}
