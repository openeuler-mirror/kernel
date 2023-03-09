// SPDX-License-Identifier: GPL-2.0
#include <asm/tlbflush.h>

extern int restore_image(void);
extern void enable_pcie_wakeup(void);
extern void swsusp_arch_save(void);

int swsusp_arch_suspend(void)
{
	enable_pcie_wakeup();
	swsusp_arch_save();

	return 0;
}

int swsusp_arch_resume(void)
{
	/* Avoid TLB mismatch during and after kernel resume */
	local_flush_tlb_all();
	return restore_image();
}
