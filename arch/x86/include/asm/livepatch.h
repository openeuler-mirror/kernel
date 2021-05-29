/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - x86-specific Kernel Live Patching Core
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 SUSE
 */

#ifndef _ASM_X86_LIVEPATCH_H
#define _ASM_X86_LIVEPATCH_H

#include <asm/setup.h>
#include <linux/ftrace.h>

struct klp_patch;
struct klp_func;

#ifdef CONFIG_LIVEPATCH_FTRACE
static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long ip)
{
	regs->ip = ip;
}
#else /* CONFIG_LIVEPATCH_WO_FTRACE */
#define klp_smp_isb()
int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);
#endif

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
int klp_check_calltrace(struct klp_patch *patch, int enable);
#endif

#endif /* _ASM_X86_LIVEPATCH_H */
