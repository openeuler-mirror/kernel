/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <linux/linkage.h>
#include <linux/arm-smccc.h>

#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/thread_info.h>

/*
 * If we have SMCCC v1.3 and (as is likely) no SVE state in
 * the registers then set the SMCCC hint bit to say there's no
 * need to preserve it.  Do this by directly adjusting the SMCCC
 * function value which is already stored in x0 ready to be called.
 */
SYM_FUNC_START(__arm_smccc_sve_check)

	ldr_l	x16, smccc_has_sve_hint
	cbz	x16, 2f

	get_current_task x16
	ldr	x16, [x16, #TSK_TI_FLAGS]
	tbnz	x16, #TIF_FOREIGN_FPSTATE, 1f	// Any live FP state?
	tbnz	x16, #TIF_SVE, 2f		// Does that state include SVE?

1:	orr	x0, x0, ARM_SMCCC_1_3_SVE_HINT

2:	ret
SYM_FUNC_END(__arm_smccc_sve_check)
EXPORT_SYMBOL(__arm_smccc_sve_check)

	.macro SMCCC instr
	stp     x29, x30, [sp, #-16]!
	mov	x29, sp
alternative_if ARM64_SVE
	bl	__arm_smccc_sve_check
alternative_else_nop_endif
	\instr	#0
	ldr	x4, [sp, #16]
	stp	x0, x1, [x4, #ARM_SMCCC_RES_X0_OFFS]
	stp	x2, x3, [x4, #ARM_SMCCC_RES_X2_OFFS]
	ldr	x4, [sp, #24]
	cbz	x4, 1f /* no quirk structure */
	ldr	x9, [x4, #ARM_SMCCC_QUIRK_ID_OFFS]
	cmp	x9, #ARM_SMCCC_QUIRK_QCOM_A6
	b.ne	1f
	str	x6, [x4, ARM_SMCCC_QUIRK_STATE_OFFS]
1:	ldp     x29, x30, [sp], #16
	ret
	.endm

/*
 * void arm_smccc_smc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct arm_smccc_res *res,
 *		  struct arm_smccc_quirk *quirk)
 */
SYM_FUNC_START(__arm_smccc_smc)
	SMCCC	smc
SYM_FUNC_END(__arm_smccc_smc)
EXPORT_SYMBOL(__arm_smccc_smc)

/*
 * void arm_smccc_hvc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct arm_smccc_res *res,
 *		  struct arm_smccc_quirk *quirk)
 */
SYM_FUNC_START(__arm_smccc_hvc)
	SMCCC	hvc
SYM_FUNC_END(__arm_smccc_hvc)
EXPORT_SYMBOL(__arm_smccc_hvc)
