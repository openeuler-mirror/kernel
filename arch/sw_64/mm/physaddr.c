// SPDX-License-Identifier: GPL-2.0
#include <linux/mmdebug.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <asm/page.h>

unsigned long __phys_addr(unsigned long x)
{
	VIRTUAL_BUG_ON(x < PAGE_OFFSET);
	x &= ~PAGE_OFFSET;
	VIRTUAL_BUG_ON(!phys_addr_valid(x));
	return x;
}
EXPORT_SYMBOL(__phys_addr);

bool __virt_addr_valid(unsigned long x)
{
	if (x < PAGE_OFFSET)
		return false;
	x &= ~PAGE_OFFSET;
	return pfn_valid(x >> PAGE_SHIFT);
}
EXPORT_SYMBOL(__virt_addr_valid);

#ifdef CONFIG_SUBARCH_C3B
#define LEGACY_BOOT_VA		0xffffffff80000000
unsigned long __boot_phys_addr(unsigned long x)
{
	if (x >= LEGACY_BOOT_VA) {
		x &= ~LEGACY_BOOT_VA;
		VIRTUAL_BUG_ON(x >= KERNEL_IMAGE_SIZE);
	} else {
		VIRTUAL_BUG_ON(x < PAGE_OFFSET);
		x &= ~PAGE_OFFSET;
		VIRTUAL_BUG_ON(!phys_addr_valid(x));
	}
	return x;
}
#endif
