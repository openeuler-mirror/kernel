/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PTRACE_H
#define _ASM_SW64_PTRACE_H

#include <uapi/asm/ptrace.h>
#include <linux/sched/task_stack.h>
#include <asm/hmcall.h>
#include <asm/thread_info.h>
#include <asm/processor.h>
#include <asm/page.h>

#define arch_has_single_step()		(1)
#define user_mode(regs) (((regs)->ps & 8) != 0)
#define instruction_pointer(regs) ((regs)->pc)
#define profile_pc(regs) instruction_pointer(regs)
#define current_user_stack_pointer() rdusp()
#define user_stack_pointer(regs) rdusp()
#define kernel_stack_pointer(regs) (((regs->ps) >> 4) & (TASK_SIZE - 1))
#define instruction_pointer_set(regs, val) ((regs)->pc = val)

#define task_pt_regs(task) \
	((struct pt_regs *) (task_stack_page(task) + 2 * PAGE_SIZE) - 1)

#define current_pt_regs() \
	((struct pt_regs *) ((char *)current_thread_info() + 2 * PAGE_SIZE) - 1)
#define signal_pt_regs current_pt_regs

#define force_successful_syscall_return() (current_pt_regs()->r0 = 0)

#define MAX_REG_OFFSET (offsetof(struct pt_regs, r18))
/**
 * regs_get_register() - get register value from its offset
 * @regs:       pt_regs from which register value is gotten
 * @offset:     offset of the register.
 *
 * regs_get_register returns the value of a register whose offset from @regs.
 * The @offset is the offset of the register in struct pt_regs.
 * If @offset is bigger than MAX_REG_OFFSET, this returns 0.
 */
static inline u64 regs_get_register(struct pt_regs *regs, unsigned int offset)
{
	if (unlikely(offset > MAX_REG_OFFSET))
		return 0;

	return *(unsigned long *)((unsigned long)regs + offset);
}
extern int regs_query_register_offset(const char *name);
extern unsigned long regs_get_kernel_stack_nth(struct pt_regs *regs,
					       unsigned int n);

static inline unsigned long regs_return_value(struct pt_regs *regs)
{
	return regs->r0;
}
#endif
