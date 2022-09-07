/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SYSCALL_H
#define _ASM_SW64_SYSCALL_H

#include <uapi/linux/audit.h>

extern void *sys_call_table[];
static inline int syscall_get_nr(struct task_struct *task,
				 struct pt_regs *regs)
{
	return regs->r0;
}

static inline long
syscall_get_error(struct task_struct *task, struct pt_regs *regs)
{
	return regs->r19 ? -regs->r0 : 0;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->r0;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	if (error) {
		regs->r0  = -error;
		regs->r19 = -1;
	} else {
		regs->r0 = val;
		regs->r19 = 0;
	}
}


static inline void syscall_rollback(struct task_struct *task,
				    struct pt_regs *regs)
{
	/* Do nothing */
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned long *args)
{
	*args++ = regs->r16;
	*args++ = regs->r17;
	*args++ = regs->r18;
	*args++ = regs->r19;
	*args++ = regs->r20;
	*args	= regs->r21;
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 const unsigned long *args)
{
	regs->r16 = *args++;
	regs->r17 = *args++;
	regs->r18 = *args++;
	regs->r19 = *args++;
	regs->r20 = *args++;
	regs->r21 = *args;
}

static inline int syscall_get_arch(struct task_struct *task)
{
	return AUDIT_ARCH_SW64;
}

#endif /* _ASM_SW64_SYSCALL_H */
