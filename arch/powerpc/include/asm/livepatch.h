/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2015-2016, SUSE, IBM Corp.
 * Copyright (C) 2023  Huawei Technologies Co., Ltd.
 */
#ifndef _ASM_POWERPC_LIVEPATCH_H
#define _ASM_POWERPC_LIVEPATCH_H

#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#ifdef CONFIG_LIVEPATCH_64
static inline void klp_init_thread_info(struct task_struct *p)
{
	/* + 1 to account for STACK_END_MAGIC */
	task_thread_info(p)->livepatch_sp = end_of_stack(p) + 1;
}
#else
static inline void klp_init_thread_info(struct task_struct *p) { }
#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE

#define PPC32_INSN_SIZE	4
#define LJMP_INSN_SIZE	4
struct arch_klp_data {
	u32 old_insns[LJMP_INSN_SIZE];
};

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

struct klp_func;

/* kernel livepatch instruction barrier */
#define klp_smp_isb()  __smp_lwsync()
int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);
long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data);
bool arch_check_jump_insn(unsigned long func_addr);
int klp_patch_text(u32 *dst, const u32 *src, int len);

#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

#endif /* _ASM_POWERPC_LIVEPATCH_H */
