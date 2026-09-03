/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/uaccess.h>
#include <asm/fpu.h>
#include <asm/lbt.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/ftrace.h>
#include <asm-generic/asm-prototypes.h>

asmlinkage void noinstr __no_stack_protector ret_from_fork(struct task_struct *prev,
							   struct pt_regs *regs);

asmlinkage void noinstr __no_stack_protector ret_from_kernel_thread(struct task_struct *prev,
								    struct pt_regs *regs,
								    int (*fn)(void *),
								    void *fn_arg);
