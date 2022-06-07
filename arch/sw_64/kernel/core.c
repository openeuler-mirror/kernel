// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/memblock.h>
#include <linux/pfn.h>
#include <linux/export.h>
#include <asm/core.h>
#include <asm/tlbflush.h>
#include <asm/smp.h>
#include <asm/compiler.h>
#include <asm/mmu_context.h>
#include <asm/bitops.h>
#include <asm/sw64_init.h>
#include <asm/hw_init.h>
#ifdef CONFIG_NUMA
#include <asm/memory.h>
#endif
#include "pci_impl.h"

#ifdef CONFIG_DISCONTIGMEM
#ifdef CONFIG_NUMA
int pa_to_nid(unsigned long pa)
{
	int i = 0;
	phys_addr_t pfn_base, pfn_size, pfn;

	pfn = pa >> PAGE_SHIFT;
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (!NODE_DATA(i))
			continue;

		pfn_base = NODE_DATA(i)->node_start_pfn;
		pfn_size = NODE_DATA(i)->node_spanned_pages;

		if (pfn >= pfn_base && pfn < pfn_base + pfn_size)
			return i;
	}

	pr_err("%s: pa %#lx does not belong to any node, return node 0\n", __func__, pa);
	return 0;
}
EXPORT_SYMBOL(pa_to_nid);
#else /* !CONFIG_NUMA */
int pa_to_nid(unsigned long pa)
{
	return 0;
}
EXPORT_SYMBOL(pa_to_nid);
#endif /* CONFIG_NUMA */
#endif /* CONFIG_DISCONTIGMEM */
