// SPDX-License-Identifier: GPL-2.0
#include <linux/start_kernel.h>

#include <asm/sw64_init.h>

void sw64_init_noop(void) { }
struct sw64_platform_ops *sw64_platform;
EXPORT_SYMBOL(sw64_platform);

static void __init sw64_setup_platform_ops(void)
{
	/*
	 * FIXME: set platform operation depending on CONFIG now.
	 * SMBIOS will help use to determin actual board.
	 */
#ifdef CONFIG_PLATFORM_XUELANG
	sw64_platform = &xuelang_ops;
#endif
}


asmlinkage __visible void __init sw64_start_kernel(void)
{
	fixup_hmcall();
	save_ktp();
	sw64_setup_platform_ops();
	sw64_platform->ops_fixup();
	start_kernel();
}
