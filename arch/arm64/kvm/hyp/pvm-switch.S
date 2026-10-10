/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PVM guest context switching at physical EL1.
 * Based on entry.S, Copyright (C) 2015 - ARM Ltd.
 */

#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/kvm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>

	.text

/* x0: vcpu, x1-x17: scratch, x29: guest context. */
SYM_FUNC_START(__pvm_guest_enter)
	adr_this_cpu x1, kvm_hyp_ctxt, x2
	save_callee_saved_regs x1
	save_sp_el0	x1, x2

	/* Defer entry if an asynchronous exception is already pending. */
alternative_if ARM64_HAS_RAS_EXTN
	dsb	nshst
	isb
alternative_else_nop_endif
	mrs	x1, isr_el1
	cbz	x1, 1f
	mov	x0, #ARM_EXCEPTION_IRQ
	ret
1:
	set_loaded_vcpu x0, x1, x2
	add	x29, x0, #VCPU_CONTEXT

	restore_sp_el0 x29, x0

	ldp	x0, x1,   [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x29, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9,   [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]
	restore_callee_saved_regs x29

	/* Do not touch any register after restoring the guest state. */
	eret
	sb

SYM_INNER_LABEL(__pvm_guest_exit_panic, SYM_L_GLOBAL)
	/* x0-x1 were saved by the vector; restore the host before panic. */
	get_loaded_vcpu x0, x1
	cbnz	x0, 1f
	b	hyp_panic
1:
	adr_this_cpu x0, kvm_hyp_ctxt, x1
	adr_l	x1, hyp_panic
	str	x1, [x0, #CPU_XREG_OFFSET(30)]
	get_vcpu_ptr	x1, x0

SYM_INNER_LABEL(__pvm_guest_exit, SYM_L_GLOBAL)
	/* x0: exit code, x1: vcpu; guest x0-x1 are on the host stack. */
	add	x1, x1, #VCPU_CONTEXT
	ALTERNATIVE(nop, SET_PSTATE_PAN(1), ARM64_HAS_PAN, CONFIG_ARM64_PAN)
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]
	ldp	x2, x3, [sp], #16
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x1, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x1, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x1, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x1, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x1, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x1, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x1, #CPU_XREG_OFFSET(16)]
	save_callee_saved_regs x1

	save_sp_el0	x1, x2

	adr_this_cpu x2, kvm_hyp_ctxt, x3
	restore_sp_el0 x2, x3
	restore_callee_saved_regs x2
	set_loaded_vcpu xzr, x2, x3

alternative_if ARM64_HAS_RAS_EXTN
	/* The vector ESB consumed any pending guest SError. */
	mrs_s	x2, SYS_DISR_EL1
	str	x2, [x1, #(VCPU_FAULT_DISR - VCPU_CONTEXT)]
	cbz	x2, 1f
	msr_s	SYS_DISR_EL1, xzr
	orr	x0, x0, #(1 << ARM_EXIT_WITH_SERROR_BIT)
1:	ret
alternative_else
	dsb	sy
	isb
	mrs	x2, isr_el1
	tbnz	x2, #ISR_EL1_A_SHIFT, 2f
	ret
	nop
2:
alternative_endif
	/* Preserve EL1 exception state across the pending-SError window. */
	mrs	x2, elr_el1
	mrs	x3, esr_el1
	mrs	x4, spsr_el1
	mov	x5, x0
	msr	daifclr, #4
.Lpvm_abort_guest_exit_start:
	isb
.Lpvm_abort_guest_exit_end:
	msr	daifset, #4
	ret

	_kvm_extable	.Lpvm_abort_guest_exit_start, 9997f
	_kvm_extable	.Lpvm_abort_guest_exit_end, 9997f
9997:
	msr	daifset, #4
	mov	x0, #(1 << ARM_EXIT_WITH_SERROR_BIT)
	msr	elr_el1, x2
	msr	esr_el1, x3
	msr	spsr_el1, x4
	orr	x0, x0, x5
	ret
SYM_FUNC_END(__pvm_guest_enter)
