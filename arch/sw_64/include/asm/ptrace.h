/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PTRACE_H
#define _ASM_SW64_PTRACE_H

#include <uapi/asm/ptrace.h>
#include <asm/hmcall.h>
#include <asm/thread_info.h>
#include <asm/page.h>

/*
 * This struct defines the way the registers are stored on the
 * kernel stack during a system call or other kernel entry
 */

struct pt_regs {
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
	unsigned long r4;
	unsigned long r5;
	unsigned long r6;
	unsigned long r7;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	/* r16 ~ r18 saved by hmcode */
	unsigned long r19;
	unsigned long r20;
	unsigned long r21;
	unsigned long r22;
	unsigned long r23;
	unsigned long r24;
	unsigned long r25;
	unsigned long r26;
	unsigned long r27;
	unsigned long r28;
	unsigned long hae;
/* JRP - These are the values provided to a0-a2 by HMcode */
	unsigned long trap_a0;
	unsigned long trap_a1;
	unsigned long trap_a2;
/* These are saved by HMcode: */
	unsigned long ps;
	unsigned long pc;
	unsigned long gp;
	unsigned long r16;
	unsigned long r17;
	unsigned long r18;
};

#define arch_has_single_step()		(1)
#define user_mode(regs) (((regs)->ps & 8) != 0)
#define instruction_pointer(regs) ((regs)->pc)
#define profile_pc(regs) instruction_pointer(regs)
#define current_user_stack_pointer() rdusp()
#define user_stack_pointer(regs) rdusp()
#define kernel_stack_pointer(regs) (((regs->ps) >> 4) & (TASK_SIZE - 1))
#define instruction_pointer_set(regs, val) ((regs)->pc = val)


#define current_pt_regs() \
	((struct pt_regs *) ((char *)current_thread_info() + 2 * PAGE_SIZE) - 1)
#define signal_pt_regs current_pt_regs

#define force_successful_syscall_return() (current_pt_regs()->r0 = 0)

#define MAX_REG_OFFSET (offsetof(struct pt_regs, r18))

extern short regoffsets[];

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
