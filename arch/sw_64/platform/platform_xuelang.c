// SPDX-License-Identifier: GPL-2.0
#include <asm/platform.h>
#include <asm/sw64_init.h>

static inline void __iomem *xuelang_ioportmap(unsigned long addr)
{
	unsigned long io_offset;

	if (addr < 0x100000) {
		io_offset = is_in_host() ? LPC_LEGACY_IO : PCI_VT_LEGACY_IO;
		addr = addr | io_offset;
	}

	return __va(addr);
}

struct sw64_platform_ops xuelang_ops = {
	.ioportmap	= xuelang_ioportmap,
	.ops_fixup	= sw64_init_noop,
};
