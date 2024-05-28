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

#if defined(CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY) || \
    defined(CONFIG_LIVEPATCH_WO_FTRACE)

#define JMP_E9_INSN_SIZE 5
struct arch_klp_data {
	unsigned char old_insns[JMP_E9_INSN_SIZE];
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
	/*
	 * Saved opcode at the entry of the old func (which maybe replaced
	 * with breakpoint).
	 */
	unsigned char saved_opcode;
#endif
};

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
int arch_klp_check_breakpoint(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func);
void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func);
int klp_int3_handler(struct pt_regs *regs);
int arch_klp_module_check_calltrace(void *data);
#endif

#endif

#endif /* _ASM_X86_LIVEPATCH_H */
