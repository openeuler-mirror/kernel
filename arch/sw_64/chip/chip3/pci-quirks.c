// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/delay.h>

#include <asm/sw64io.h>

void __init reserve_mem_for_pci(void)
{
	int ret;
	unsigned long base = PCI_32BIT_MEMIO;

	ret = add_memmap_region(base, PCI_32BIT_MEMIO_SIZE, memmap_pci);
	if (ret) {
		pr_err("reserved pages for pcie memory space failed\n");
		return;
	}

	pr_info("reserved pages for pcie memory space %lx:%lx\n", base >> PAGE_SHIFT,
			(base + PCI_32BIT_MEMIO_SIZE) >> PAGE_SHIFT);
}
