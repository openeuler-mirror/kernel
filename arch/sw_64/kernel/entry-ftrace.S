/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/sw_64/kernel/entry-ftrace.S
 *
 * Author: linyue
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/ftrace.h>

	.text
	.set noat
	.align 4

#define FTRACE_SP_OFF	0x50
	.macro mcount_enter
	subl	$sp, FTRACE_SP_OFF, $sp
	stl	$16, 0($sp)
	stl	$17, 0x8($sp)
	stl	$18, 0x10($sp)
	stl	$26, 0x18($sp)
	stl	$27, 0x20($sp)
	stl	$28, 0x28($sp)
	stl	$29, 0x30($sp)
	stl	$19, 0x38($sp)
	stl	$20, 0x40($sp)
	stl	$21, 0x48($sp)
	.endm

	.macro mcount_end
	ldl	$16, 0($sp)
	ldl	$17, 0x8($sp)
	ldl	$18, 0x10($sp)
	ldl	$26, 0x18($sp)
	ldl	$27, 0x20($sp)
	ldl	$28, 0x28($sp)
	ldl	$29, 0x30($sp)
	ldl	$19, 0x38($sp)
	ldl	$20, 0x40($sp)
	ldl	$21, 0x48($sp)
	addl	$sp, FTRACE_SP_OFF, $sp
	.endm

	.macro SAVE_PT_REGS
	ldi	$sp, -PT_REGS_SIZE($sp)
	stl	$0, PT_REGS_R0($sp)
	stl	$1, PT_REGS_R1($sp)
	stl	$2, PT_REGS_R2($sp)
	stl	$3, PT_REGS_R3($sp)
	stl	$4, PT_REGS_R4($sp)
	stl	$5, PT_REGS_R5($sp)
	stl	$6, PT_REGS_R6($sp)
	stl	$7, PT_REGS_R7($sp)
	stl	$8, PT_REGS_R8($sp)
	stl	$9, PT_REGS_R9($sp)
	stl	$10, PT_REGS_R10($sp)
	stl	$11, PT_REGS_R11($sp)
	stl	$12, PT_REGS_R12($sp)
	stl	$13, PT_REGS_R13($sp)
	stl	$14, PT_REGS_R14($sp)
	stl	$15, PT_REGS_R15($sp)
	stl	$16, PT_REGS_R16($sp)
	stl	$17, PT_REGS_R17($sp)
	stl	$18, PT_REGS_R18($sp)
	stl	$19, PT_REGS_R19($sp)
	stl	$20, PT_REGS_R20($sp)
	stl	$21, PT_REGS_R21($sp)
	stl	$22, PT_REGS_R22($sp)
	stl	$23, PT_REGS_R23($sp)
	stl	$24, PT_REGS_R24($sp)
	stl	$25, PT_REGS_R25($sp)
	stl	$26, PT_REGS_R26($sp)
	stl	$27, PT_REGS_R27($sp)
	stl	$28, PT_REGS_R28($sp)
	.endm

	.macro RESTORE_PT_REGS
	ldl	$0, PT_REGS_R0($sp)
	ldl	$1, PT_REGS_R1($sp)
	ldl	$2, PT_REGS_R2($sp)
	ldl	$3, PT_REGS_R3($sp)
	ldl	$4, PT_REGS_R4($sp)
	ldl	$5, PT_REGS_R5($sp)
	ldl	$6, PT_REGS_R6($sp)
	ldl	$7, PT_REGS_R7($sp)
	ldl	$8, PT_REGS_R8($sp)
	ldl	$9, PT_REGS_R9($sp)
	ldl	$10, PT_REGS_R10($sp)
	ldl	$11, PT_REGS_R11($sp)
	ldl	$12, PT_REGS_R12($sp)
	ldl	$13, PT_REGS_R13($sp)
	ldl	$14, PT_REGS_R14($sp)
	ldl	$15, PT_REGS_R15($sp)
	ldl	$16, PT_REGS_R16($sp)
	ldl	$17, PT_REGS_R17($sp)
	ldl	$18, PT_REGS_R18($sp)
	ldl	$19, PT_REGS_R19($sp)
	ldl	$20, PT_REGS_R20($sp)
	ldl	$21, PT_REGS_R21($sp)
	ldl	$22, PT_REGS_R22($sp)
	ldl	$23, PT_REGS_R23($sp)
	ldl	$24, PT_REGS_R24($sp)
	ldl	$25, PT_REGS_R25($sp)
	ldl	$26, PT_REGS_R26($sp)
	ldl	$27, PT_REGS_R27($sp)
	ldl	$28, PT_REGS_R28($sp)
	ldi	$sp, PT_REGS_SIZE($sp)
	.endm

#ifdef CONFIG_DYNAMIC_FTRACE
	.global _mcount
	.ent _mcount
_mcount:
	ret	$31, ($28), 1
	.end _mcount


	.global ftrace_caller
	.ent ftrace_caller
ftrace_caller:
	mcount_enter

	br	$27, 2f
2:	ldgp	$29, 0($27)

	subl	$28, MCOUNT_INSN_SIZE, $16
	bis	$26, $31, $17
	ldl	$18, function_trace_op

	ldi	$4, current_tracer
	ldl	$27, 0($4)

	.global ftrace_call
ftrace_call:					/* tracer(pc, lr); call 26, 27 , 1 */
	nop

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	ldi	 $27, prepare_ftrace_return	/* prepare_ftrace_return(&lr, pc, fp) */
	.global ftrace_graph_call
ftrace_graph_call:				/* ftrace_graph_caller(); */
	nop					/* If enabled, this will be replaced */
						/* "br ftrace_graph_caller" */
#endif
	mcount_end
	ret	$31, ($28), 1
	.end ftrace_caller
#else /* !CONFIG_DYNAMIC_FTRACE */

	.global _mcount
	.ent _mcount
_mcount:
	mcount_enter

	br	$27, 1f
1:	ldgp	$29, 0($27)

	ldi	$4, ftrace_trace_function
	ldl	$27, 0($4)
	ldi	$5, ftrace_stub
	cmpeq	$4, $5, $6
	bne	$6, skip_ftrace

	subl	$28, MCOUNT_INSN_SIZE, $16
	bis	$26, $31, $17
	call	$26, ($27), 1

skip_ftrace:
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	ldi	$4, ftrace_graph_return
	ldl	$4, 0($4)
	ldi	$5, ftrace_stub
	cmpeq	$4, $5, $6
	beq	$6, ftrace_graph_caller


	ldi	$4, ftrace_graph_entry
	ldl	$4, 0($4)
	ldi	$5, ftrace_graph_entry_stub
	cmpeq	$4, $5, $6
	beq	$6, ftrace_graph_caller
#endif
	mcount_end
	ret	$31, ($28), 1
	.end _mcount

#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
	.global ftrace_regs_caller
	.ent ftrace_regs_caller
ftrace_regs_caller:
	SAVE_PT_REGS

	br	$27, 2f
2:	ldgp	$29, 0($27)

	subl	$28, MCOUNT_INSN_SIZE, $16
	bis	$26, $31, $17
	ldi	$4, function_trace_op
	ldl	$18, 0($4)
	mov	$sp, $19

	ldi	$4, current_tracer
	ldl	$27, 0($4)

	.global ftrace_regs_call
ftrace_regs_call:
	nop

	RESTORE_PT_REGS
	ret $31, ($28), 1
	.end ftrace_regs_caller
#endif /* CONFIG_DYNAMIC_FTRACE_WITH_REGS */

	.global ftrace_stub
	.ent ftrace_stub
ftrace_stub:
	ret	$31, ($26), 1
	.end ftrace_stub


#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	.macro RESTORE_GRAPH_ARGS
	ldl	$26, 0x18($sp)
	ldl	$28, 0x28($sp)
	.endm

	/* save return value regs*/
	.macro save_return_regs
	subl	$sp, 0x8, $sp
	stl	$0, 0x0($sp)
	.endm

	/* restore return value regs*/
	.macro restore_return_regs
	ldl	$0, 0x0($sp)
	addl	$sp, 0x8, $sp
	.endm


/*
 * void ftrace_graph_caller(void)
 *
 * Called from _mcount() or ftrace_caller() when function_graph tracer is
 * selected.
 * This function w/ prepare_ftrace_return() fakes link register's value on
 * the call stack in order to intercept instrumented function's return path
 * and run return_to_handler() later on its exit.
 */
	.global ftrace_graph_caller
	.ent ftrace_graph_caller
ftrace_graph_caller:
	memb			/* need memb, otherwise it'll  go wrong */
	RESTORE_GRAPH_ARGS
	addl	$sp, 0x18, $16
	subl	$28, MCOUNT_INSN_SIZE, $17
	bis	$15, $31, $18	/* parent's fp */

	call	$26, ($27)	/* prepare_ftrace_return() */

	mcount_end
	ret	$31, ($28), 1
	.end ftrace_graph_caller

/*
 * void return_to_handler(void)
 *
 * Run ftrace_return_to_handler() before going back to parent.
 * @fp is checked against the value passed by ftrace_graph_caller()
 * only when HAVE_FUNCTION_GRAPH_FP_TEST is enabled.
 */
ENTRY(return_to_handler)
	save_return_regs
	br	$27, 3f
3:	ldgp	$29, 0($27)
	ldi	$27, ftrace_return_to_handler
	call	$26, ($27)
	bis	$0, $31, $26
	restore_return_regs
	ret	$31, ($26), 1
END(return_to_handler)

#endif
