/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_SW64_PTRACE_H
#define _UAPI_ASM_SW64_PTRACE_H

/*
 * User structures for general purpose, floating point and debug registers.
 */
struct user_pt_regs {
	__u64 regs[31];
	__u64 pc;
	__u64 pstate;
};

struct user_fpsimd_state {
	__u64 vregs[124];
	__u64 fpcr;
};

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
