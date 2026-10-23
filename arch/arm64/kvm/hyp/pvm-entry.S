/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * PVM exception entry at physical EL1.
 * Based on hyp-entry.S, Copyright (C) 2015-2018 - ARM Ltd.
 */

#include <linux/arm-smccc.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/mmu.h>
#include <asm/spectre.h>

	.text

pvm_guest_sync:
	mrs	x0, esr_el1
	ubfx	x0, x0, #ESR_ELx_EC_SHIFT, #ESR_ELx_EC_WIDTH
	cmp	x0, #ESR_ELx_EC_HVC64
	ccmp	x0, #ESR_ELx_EC_HVC32, #4, ne
	b.ne	pvm_guest_trap

	/* Preserve the existing SMCCC workaround fast return. */
	ldr	x1, [sp]
	eor	w1, w1, #ARM_SMCCC_ARCH_WORKAROUND_1
	cbz	w1, pvm_wa_epilogue

	eor	w1, w1, #(ARM_SMCCC_ARCH_WORKAROUND_1 ^ \
			  ARM_SMCCC_ARCH_WORKAROUND_2)
	cbz	w1, pvm_wa_epilogue

	eor	w1, w1, #(ARM_SMCCC_ARCH_WORKAROUND_2 ^ \
			  ARM_SMCCC_ARCH_WORKAROUND_3)
	cbnz	w1, pvm_guest_trap

pvm_wa_epilogue:
	mov	x0, xzr
	add	sp, sp, #16
	eret
	sb

pvm_guest_trap:
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_TRAP
	b	__pvm_guest_exit

pvm_guest_irq:
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_IRQ
	b	__pvm_guest_exit

pvm_guest_error:
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_EL1_SERROR
	b	__pvm_guest_exit

.macro pvm_save_caller_saved_regs
	/* x0 and x1 were saved in the vector entry. */
	stp	x2, x3,   [sp, #-16]!
	stp	x4, x5,   [sp, #-16]!
	stp	x6, x7,   [sp, #-16]!
	stp	x8, x9,   [sp, #-16]!
	stp	x10, x11, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x14, x15, [sp, #-16]!
	stp	x16, x17, [sp, #-16]!
.endm

.macro pvm_restore_caller_saved_regs
	ldp	x16, x17, [sp], #16
	ldp	x14, x15, [sp], #16
	ldp	x12, x13, [sp], #16
	ldp	x10, x11, [sp], #16
	ldp	x8, x9,   [sp], #16
	ldp	x6, x7,   [sp], #16
	ldp	x4, x5,   [sp], #16
	ldp	x2, x3,   [sp], #16
	ldp	x0, x1,   [sp], #16
.endm

pvm_host_sync:
	/* Check for illegal exception return. */
	mrs	x0, spsr_el1
	tbnz	x0, #20, 1f

	pvm_save_caller_saved_regs
	stp	x29, x30, [sp, #-16]!
	bl	kvm_unexpected_el2_exception
	ldp	x29, x30, [sp], #16
	pvm_restore_caller_saved_regs
	eret

1:
	get_vcpu_ptr	x1, x0
	mov	x0, #ARM_EXCEPTION_IL
	b	__pvm_guest_exit

pvm_host_error:
	pvm_save_caller_saved_regs
	stp	x29, x30, [sp, #-16]!
	bl	kvm_unexpected_el2_exception
	ldp	x29, x30, [sp], #16
	pvm_restore_caller_saved_regs
	eret
	sb

pvm_invalid:
	b	__pvm_guest_exit_panic

	.ltorg

.macro pvm_vect target, valid = 1
	.align 7
661:
	.if \valid
	esb
	.else
	nop
	.endif
	stp	x0, x1, [sp, #-16]!
662:
	/* Hardened vectors branch past the preamble to this BTI. */
	bti j
	b	\target
	.if ((662b - 661b) != KVM_VECTOR_PREAMBLE)
	.error "PVM vector preamble length mismatch"
	.endif
.endm

	.align 11
SYM_CODE_START(__pvm_hyp_vector)
	pvm_vect	pvm_invalid, 0		// Current EL, SP0
	pvm_vect	pvm_invalid, 0
	pvm_vect	pvm_invalid, 0
	pvm_vect	pvm_invalid, 0

	pvm_vect	pvm_host_sync		// Current EL, SPx
	pvm_vect	pvm_invalid, 0
	pvm_vect	pvm_invalid, 0
	pvm_vect	pvm_host_error

	pvm_vect	pvm_guest_sync		// Lower EL, AArch64
	pvm_vect	pvm_guest_irq
	pvm_vect	pvm_guest_irq
	pvm_vect	pvm_guest_error

	pvm_vect	pvm_guest_sync		// Lower EL, AArch32
	pvm_vect	pvm_guest_irq
	pvm_vect	pvm_guest_irq
	pvm_vect	pvm_guest_error
	.org __pvm_hyp_vector + SZ_2K
SYM_CODE_END(__pvm_hyp_vector)

.macro pvm_spectrev2_smccc_wa1_smc
	sub	sp, sp, #(8 * 4)
	stp	x2, x3, [sp, #(8 * 0)]
	stp	x0, x1, [sp, #(8 * 2)]
	alternative_cb ARM64_ALWAYS_SYSTEM, spectre_bhb_patch_wa3
	/* Patched to mov WA3 when supported. */
	mov	w0, #ARM_SMCCC_ARCH_WORKAROUND_1
	alternative_cb_end
	smc	#0
	ldp	x2, x3, [sp, #(8 * 0)]
	add	sp, sp, #(8 * 2)
.endm

.macro pvm_ventry spectrev2
	.align 7
1:	esb
	.if \spectrev2
	pvm_spectrev2_smccc_wa1_smc
	.else
	stp	x0, x1, [sp, #-16]!
	mitigate_spectre_bhb_loop	x0
	mitigate_spectre_bhb_clear_insn
	.endif
	b	__pvm_hyp_vector + (1b - 0b + KVM_VECTOR_PREAMBLE)
.endm

.macro pvm_generate_vectors spectrev2
0:
	.rept 16
	pvm_ventry \spectrev2
	.endr
	.org 0b + SZ_2K
.endm

	.align 11
SYM_CODE_START(__bp_harden_pvm_vecs)
	pvm_generate_vectors 1	// HYP_VECTOR_SPECTRE_DIRECT
	pvm_generate_vectors 0	// HYP_VECTOR_INDIRECT
	pvm_generate_vectors 1	// HYP_VECTOR_SPECTRE_INDIRECT
1:	.org __bp_harden_pvm_vecs + __BP_HARDEN_HYP_VECS_SZ
	.org 1b
SYM_CODE_END(__bp_harden_pvm_vecs)
