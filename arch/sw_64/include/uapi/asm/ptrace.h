/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_SW64_PTRACE_H
#define _UAPI_ASM_SW64_PTRACE_H


/*
 * This struct defines the way the registers are stored on the
 * kernel stack during a system call or other kernel entry
 *
 * NOTE! I want to minimize the overhead of system calls, so this
 * struct has as little information as possible.  I does not have
 *
 *  - floating point regs: the kernel doesn't change those
 *  - r9-15: saved by the C compiler
 *
 * This makes "fork()" and "exec()" a bit more complex, but should
 * give us low system call latency.
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

/*
 * This is the extended stack used by signal handlers and the context
 * switcher: it's pushed after the normal "struct pt_regs".
 */
struct switch_stack {
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long r26;
};

#define PTRACE_GETREGS		12	/* get general purpose registers */
#define PTRACE_SETREGS		13	/* set general purpose registers */
#define PTRACE_GETFPREGS	14	/* get floating-point registers */
#define PTRACE_SETFPREGS	15	/* set floating-point registers */
/* PTRACE_ATTACH is 16 */
/* PTRACE_DETACH is 17 */

#define REG_BASE		0
#define REG_END			29
#define USP			30
#define FPREG_BASE		32
#define FPREG_END		62
#define FPCR			63
#define PC			64
#define UNIQUE			65
#define VECREG_BASE		67
#define VECREG_END		161
#define F31_V1			98
#define F31_V2			130
#define DA_MATCH		163
#define DA_MASK			164
#define DV_MATCH		165
#define DV_MASK			166
#define DC_CTL			167

#endif /* _UAPI_ASM_SW64_PTRACE_H */
