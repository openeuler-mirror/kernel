/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - x86-specific Kernel Live Patching Core
 *
 * Copyright (C) 2023 Huawei.
 */

#ifndef _ASM_X86_LIVEPATCH_H
#define _ASM_X86_LIVEPATCH_H

#ifdef CONFIG_LIVEPATCH_WO_FTRACE

#define JMP_E9_INSN_SIZE 5
struct arch_klp_data {
	unsigned char old_insns[JMP_E9_INSN_SIZE];
};

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

struct klp_func;

#define klp_smp_isb()
int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);
long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
bool arch_check_jump_insn(unsigned long func_addr);
int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data);
void arch_klp_code_modify_prepare(void);
void arch_klp_code_modify_post_process(void);

#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

#endif /* _ASM_X86_LIVEPATCH_H */
