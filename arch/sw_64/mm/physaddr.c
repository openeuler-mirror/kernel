// SPDX-License-Identifier: GPL-2.0
#include <linux/mmdebug.h>
#include <linux/module.h>
#include <asm/page.h>

unsigned long __phys_addr(unsigned long x)
{
	unsigned long y = x;

	if (y >= __START_KERNEL_map) {
		y -= __START_KERNEL_map;
		VIRTUAL_BUG_ON(y >= KERNEL_IMAGE_SIZE);
	} else {
		VIRTUAL_BUG_ON(y < PAGE_OFFSET);
		y -= PAGE_OFFSET;
		VIRTUAL_BUG_ON(!phys_addr_valid(y));
	}
	return y;
}
EXPORT_SYMBOL(__phys_addr);

bool __virt_addr_valid(unsigned long x)
{
	unsigned long y = x;

	if (y >= __START_KERNEL_map) {
		y -= __START_KERNEL_map;
		if (y >= KERNEL_IMAGE_SIZE)
			return false;
	} else {
		if (y < PAGE_OFFSET)
			return false;
		y -= PAGE_OFFSET;
	}

	return pfn_valid(y >> PAGE_SHIFT);
}
EXPORT_SYMBOL(__virt_addr_valid);
