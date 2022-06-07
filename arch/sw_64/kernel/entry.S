/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel entry-points.
 */

#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/hmcall.h>
#include <asm/errno.h>
#include <asm/unistd.h>

	.text
	.set noat
/*
 * This defines the normal kernel pt-regs layout.
 *
 * regs 9-15 preserved by C code
 * regs 16-18 saved by HMcode
 * regs 29-30 saved and set up by HMcode
 * JRP - Save regs 16-18 in a special area of the stack, so that
 * the hmcode-provided values are available to the signal handler.
 */

#define SAVE_ALL				\
	ldi	$sp, -PT_REGS_PS($sp);		\
	stl	$0, PT_REGS_R0($sp);		\
	stl	$1, PT_REGS_R1($sp);		\
	stl	$2, PT_REGS_R2($sp);		\
	stl	$3, PT_REGS_R3($sp);		\
	stl	$4, PT_REGS_R4($sp);		\
	stl	$28, PT_REGS_R28($sp);		\
	stl	$5, PT_REGS_R5($sp);		\
	stl	$6, PT_REGS_R6($sp);		\
	stl	$7, PT_REGS_R7($sp);		\
	stl	$8, PT_REGS_R8($sp);		\
	stl	$19, PT_REGS_R19($sp);		\
	stl	$20, PT_REGS_R20($sp);		\
	stl	$21, PT_REGS_R21($sp);		\
	stl	$22, PT_REGS_R22($sp);		\
	stl	$23, PT_REGS_R23($sp);		\
	stl	$24, PT_REGS_R24($sp);		\
	stl	$25, PT_REGS_R25($sp);		\
	stl	$26, PT_REGS_R26($sp);		\
	stl	$27, PT_REGS_R27($sp);		\
	stl	$16, PT_REGS_TRAP_A0($sp);	\
	stl	$17, PT_REGS_TRAP_A1($sp);	\
	stl	$18, PT_REGS_TRAP_A2($sp)

#define RESTORE_ALL				\
	ldl	$0, PT_REGS_R0($sp);		\
	ldl	$1, PT_REGS_R1($sp);		\
	ldl	$2, PT_REGS_R2($sp);		\
	ldl	$3, PT_REGS_R3($sp);		\
	ldl	$4, PT_REGS_R4($sp);		\
	ldl	$5, PT_REGS_R5($sp);		\
	ldl	$6, PT_REGS_R6($sp);		\
	ldl	$7, PT_REGS_R7($sp);		\
	ldl	$8, PT_REGS_R8($sp);		\
	ldl	$19, PT_REGS_R19($sp);		\
	ldl	$20, PT_REGS_R20($sp);		\
	ldl	$21, PT_REGS_R21($sp);		\
	ldl	$22, PT_REGS_R22($sp);		\
	ldl	$23, PT_REGS_R23($sp);		\
	ldl	$24, PT_REGS_R24($sp);		\
	ldl	$25, PT_REGS_R25($sp);		\
	ldl	$26, PT_REGS_R26($sp);		\
	ldl	$27, PT_REGS_R27($sp);		\
	ldl	$28, PT_REGS_R28($sp);		\
	ldi	$sp, PT_REGS_PS($sp)

/*
 * Non-syscall kernel entry points.
 */

	.align 4
	.globl entInt
	.ent entInt
entInt:
	SAVE_ALL
	ldi	$8, 0x3fff
	ldi	$26, ret_from_sys_call
	bic	$sp, $8, $8
	mov	$sp, $19
	call	$31, do_entInt
	.end entInt

	.align 4
	.globl entArith
	.ent entArith
entArith:
	SAVE_ALL
	ldi	$8, 0x3fff
	ldi	$26, ret_from_sys_call
	bic	$sp, $8, $8
	mov	$sp, $18
	call	$31, do_entArith
	.end entArith

	.align 4
	.globl entMM
	.ent entMM
entMM:
	SAVE_ALL
/* save $9 - $15 so the inline exception code can manipulate them.  */
	subl	$sp, SWITCH_STACK_RA, $sp
	stl	$9, SWITCH_STACK_R9($sp)
	stl	$10, SWITCH_STACK_R10($sp)
	stl	$11, SWITCH_STACK_R11($sp)
	stl	$12, SWITCH_STACK_R12($sp)
	stl	$13, SWITCH_STACK_R13($sp)
	stl	$14, SWITCH_STACK_R14($sp)
	stl	$15, SWITCH_STACK_R15($sp)
	addl	$sp, SWITCH_STACK_RA, $19
/* handle the fault */
	ldi	$8, 0x3fff
	bic	$sp, $8, $8
	call	$26, do_page_fault
/* reload the registers after the exception code played.  */
	ldl	$9, SWITCH_STACK_R9($sp)
	ldl	$10, SWITCH_STACK_R10($sp)
	ldl	$11, SWITCH_STACK_R11($sp)
	ldl	$12, SWITCH_STACK_R12($sp)
	ldl	$13, SWITCH_STACK_R13($sp)
	ldl	$14, SWITCH_STACK_R14($sp)
	ldl	$15, SWITCH_STACK_R15($sp)
	addl	$sp, SWITCH_STACK_RA, $sp
/* finish up the syscall as normal.  */
	br	ret_from_sys_call
	.end entMM

	.align 4
	.globl entIF
	.ent entIF
entIF:
	SAVE_ALL
	ldi	$8, 0x3fff
	ldi	$26, ret_from_sys_call
	bic	$sp, $8, $8
	mov	$sp, $17
	call	$31, do_entIF
	.end entIF

	.align 4
	.globl entUna
	.ent entUna
entUna:
	ldi	$sp, -ALLREGS_PS($sp)
	stl	$0, ALLREGS_R0($sp)
	ldl	$0, ALLREGS_PS($sp)	/* get PS */
	stl	$1, ALLREGS_R1($sp)
	stl	$2, ALLREGS_R2($sp)
	stl	$3, ALLREGS_R3($sp)
	and	$0, 8, $0	/* user mode? */
	stl	$4, ALLREGS_R4($sp)
	bne	$0, entUnaUser	/* yup -> do user-level unaligned fault */
	stl	$5, ALLREGS_R5($sp)
	stl	$6, ALLREGS_R6($sp)
	stl	$7, ALLREGS_R7($sp)
	stl	$8, ALLREGS_R8($sp)
	stl	$9, ALLREGS_R9($sp)
	stl	$10, ALLREGS_R10($sp)
	stl	$11, ALLREGS_R11($sp)
	stl	$12, ALLREGS_R12($sp)
	stl	$13, ALLREGS_R13($sp)
	stl	$14, ALLREGS_R14($sp)
	stl	$15, ALLREGS_R15($sp)
	/* 16-18 HMCODE-saved */
	stl	$19, ALLREGS_R19($sp)
	stl	$20, ALLREGS_R20($sp)
	stl	$21, ALLREGS_R21($sp)
	stl	$22, ALLREGS_R22($sp)
	stl	$23, ALLREGS_R23($sp)
	stl	$24, ALLREGS_R24($sp)
	stl	$25, ALLREGS_R25($sp)
	stl	$26, ALLREGS_R26($sp)
	stl	$27, ALLREGS_R27($sp)
	stl	$28, ALLREGS_R28($sp)
	mov	$sp, $19
	stl	$gp, ALLREGS_R29($sp)
	ldi	$8, 0x3fff
	stl	$31, ALLREGS_R31($sp)
	bic	$sp, $8, $8
	call	$26, do_entUna
	ldl	$0, ALLREGS_R0($sp)
	ldl	$1, ALLREGS_R1($sp)
	ldl	$2, ALLREGS_R2($sp)
	ldl	$3, ALLREGS_R3($sp)
	ldl	$4, ALLREGS_R4($sp)
	ldl	$5, ALLREGS_R5($sp)
	ldl	$6, ALLREGS_R6($sp)
	ldl	$7, ALLREGS_R7($sp)
	ldl	$8, ALLREGS_R8($sp)
	ldl	$9, ALLREGS_R9($sp)
	ldl	$10, ALLREGS_R10($sp)
	ldl	$11, ALLREGS_R11($sp)
	ldl	$12, ALLREGS_R12($sp)
	ldl	$13, ALLREGS_R13($sp)
	ldl	$14, ALLREGS_R14($sp)
	ldl	$15, ALLREGS_R15($sp)
	/* 16-18 HMCODE-saved */
	ldl	$19, ALLREGS_R19($sp)
	ldl	$20, ALLREGS_R20($sp)
	ldl	$21, ALLREGS_R21($sp)
	ldl	$22, ALLREGS_R22($sp)
	ldl	$23, ALLREGS_R23($sp)
	ldl	$24, ALLREGS_R24($sp)
	ldl	$25, ALLREGS_R25($sp)
	ldl	$26, ALLREGS_R26($sp)
	ldl	$27, ALLREGS_R27($sp)
	ldl	$28, ALLREGS_R28($sp)
	ldl	$gp, ALLREGS_R29($sp)
	ldi	$sp, ALLREGS_PS($sp)
	sys_call HMC_rti
	.end entUna

	.align 4
	.ent entUnaUser
entUnaUser:
	ldl	$0, ALLREGS_R0($sp)	/* restore original $0 */
	ldi	$sp, ALLREGS_PS($sp)	/* pop entUna's stack frame */
	SAVE_ALL		/* setup normal kernel stack */
	ldi	$sp, -SWITCH_STACK_RA($sp)
	stl	$9, SWITCH_STACK_R9($sp)
	stl	$10, SWITCH_STACK_R10($sp)
	stl	$11, SWITCH_STACK_R11($sp)
	stl	$12, SWITCH_STACK_R12($sp)
	stl	$13, SWITCH_STACK_R13($sp)
	stl	$14, SWITCH_STACK_R14($sp)
	stl	$15, SWITCH_STACK_R15($sp)
	ldi	$8, 0x3fff
	addl	$sp, SWITCH_STACK_RA, $19
	bic	$sp, $8, $8
	call	$26, do_entUnaUser
	ldl	$9, SWITCH_STACK_R9($sp)
	ldl	$10, SWITCH_STACK_R10($sp)
	ldl	$11, SWITCH_STACK_R11($sp)
	ldl	$12, SWITCH_STACK_R12($sp)
	ldl	$13, SWITCH_STACK_R13($sp)
	ldl	$14, SWITCH_STACK_R14($sp)
	ldl	$15, SWITCH_STACK_R15($sp)
	ldi	$sp, SWITCH_STACK_RA($sp)
	br	ret_from_sys_call
	.end entUnaUser


/*
 * The system call entry point is special.  Most importantly, it looks
 * like a function call to userspace as far as clobbered registers.  We
 * do preserve the argument registers (for syscall restarts) and $26
 * (for leaf syscall functions).
 *
 * So much for theory.  We don't take advantage of this yet.
 *
 * Note that a0-a2 are not saved by HMcode as with the other entry points.
 */

	.align 4
	.globl entSys
	.globl ret_from_sys_call
	.ent entSys
entSys:

	SAVE_ALL
	ldi	$8, 0x3fff
	bic	$sp, $8, $8
	ldi	$4, NR_SYSCALLS($31)
	stl	$16, PT_REGS_R16($sp)
	ldi	$5, sys_call_table
	ldi	$27, sys_ni_syscall
	cmpult	$0, $4, $4
	ldw	$3, TI_FLAGS($8)
	stl	$17, PT_REGS_R17($sp)
	s8addl	$0, $5, $5
	stl	$18, PT_REGS_R18($sp)
	ldi	$6, _TIF_SYSCALL_WORK
	and	$3, $6, $3
	bne	$3, strace

	beq	$4, 1f
	ldl	$27, 0($5)
1:	call	$26, ($27), ni_syscall
	ldgp	$gp, 0($26)
	blt	$0, $syscall_error	/* the call failed */
	stl	$0, PT_REGS_R0($sp)
	stl	$31, PT_REGS_R19($sp)	/* a3=0 => no error */

	.align 4
ret_from_sys_call:
#ifdef CONFIG_SUBARCH_C3B
	fillcs	0($sp)			/* prefetch */
	fillcs	128($sp)		/* prefetch */
#endif
	selne	$26, 0, $18, $18		/* $18 = 0 => non-restartable */
	ldl	$0, PT_REGS_PS($sp)
	and	$0, 8, $0
	beq	$0, ret_to_kernel
ret_to_user:
	/* Make sure need_resched and sigpending don't change between
		sampling and the rti.  */
	ldi	$16, 7
	sys_call HMC_swpipl
	ldw	$17, TI_FLAGS($8)
	and	$17, _TIF_WORK_MASK, $2
	bne	$2, work_pending
restore_all:
	RESTORE_ALL
	sys_call HMC_rti

ret_to_kernel:
	ldi	$16, 7
	sys_call HMC_swpipl
	br restore_all


	.align 3
$syscall_error:
	/*
	 * Some system calls (e.g., ptrace) can return arbitrary
	 * values which might normally be mistaken as error numbers.
	 * Those functions must zero $0 (v0) directly in the stack
	 * frame to indicate that a negative return value wasn't an
	 * error number..
	 */
	ldl	$18, PT_REGS_R0($sp)	/* old syscall nr (zero if success) */
	beq	$18, $ret_success

	ldl	$19, PT_REGS_R19($sp)	/* .. and this a3 */
	subl	$31, $0, $0	/* with error in v0 */
	addl	$31, 1, $1	/* set a3 for errno return */
	stl	$0, PT_REGS_R0($sp)
	mov	$31, $26	/* tell "ret_from_sys_call" we can restart */
	stl	$1, PT_REGS_R19($sp)	/* a3 for return */
	br	ret_from_sys_call


$ret_success:
	stl	$0, PT_REGS_R0($sp)
	stl	$31, PT_REGS_R19($sp)	/* a3=0 => no error */
	br	ret_from_sys_call
	.end entSys

/*
 * Do all cleanup when returning from all interrupts and system calls.
 *
 * Arguments:
 *	$8: current.
 *	$17: TI_FLAGS.
 *	$18: The old syscall number, or zero if this is not a return
 *		from a syscall that errored and is possibly restartable.
 *	$19: The old a3 value
 */

	.align 4
	.ent work_pending
work_pending:
	and	$17, _TIF_NOTIFY_RESUME | _TIF_SIGPENDING | _TIF_UPROBE, $2
	bne	$2, $work_notifysig

$work_resched:
	/*
	 * We can get here only if we returned from syscall without SIGPENDING
	 * or got through work_notifysig already.  Either case means no syscall
	 * restarts for us, so let $18 and $19 burn.
	 */
	call	$26, schedule
	mov	0, $18
	br	ret_to_user

$work_notifysig:
	mov	$sp, $16
	bsr	$1, do_switch_stack
	call	$26, do_work_pending
	bsr	$1, undo_switch_stack
	br	restore_all
	.end work_pending



/*
 * PTRACE syscall handler
 */

	.align 4
	.ent strace
strace:
	/* set up signal stack, call syscall_trace */
	bsr	$1, do_switch_stack
	mov	$0, $9
	mov	$19, $10
	call	$26, syscall_trace_enter
	mov	$9, $18
	mov	$10, $19
	bsr	$1, undo_switch_stack

	blt	$0, $syscall_trace_failed

	/* get the system call number and the arguments back.. */
	ldl	$16, PT_REGS_R16($sp)
	ldl	$17, PT_REGS_R17($sp)
	ldl	$18, PT_REGS_R18($sp)
	ldl	$19, PT_REGS_R19($sp)
	ldl	$20, PT_REGS_R20($sp)
	ldl	$21, PT_REGS_R21($sp)

	/* get the system call pointer.. */
	ldi	$1, NR_SYSCALLS($31)
	ldi	$2, sys_call_table
	ldi	$27, ni_syscall

	cmpult	$0, $1, $1
	s8addl	$0, $2, $2
	beq	$1, 1f
	ldl	$27, 0($2)
1:	call	$26, ($27), sys_gettimeofday
ret_from_straced:
	ldgp	$gp, 0($26)

	/* check return.. */
	blt	$0, $strace_error	/* the call failed */
	stl	$31, PT_REGS_R19($sp)	/* a3=0 => no error */
$strace_success:
	stl	$0, PT_REGS_R0($sp)	/* save return value */

	bsr	$1, do_switch_stack
	call	$26, syscall_trace_leave
	bsr	$1, undo_switch_stack
	br	$31, ret_from_sys_call

	.align 3
$strace_error:
	ldl	$18, PT_REGS_R0($sp)	/* old syscall nr (zero if success) */

	beq	$18, $strace_success
	ldl	$19, PT_REGS_R19($sp)	/* .. and this a3 */

	subl	$31, $0, $0	/* with error in v0 */
	addl	$31, 1, $1	/* set a3 for errno return */
	stl	$0, PT_REGS_R0($sp)
	stl	$1, PT_REGS_R19($sp)	/* a3 for return */

	bsr	$1, do_switch_stack
	mov	$18, $9		/* save old syscall number */
	mov	$19, $10	/* save old a3 */
	call	$26, syscall_trace_leave
	mov	$9, $18
	mov	$10, $19
	bsr	$1, undo_switch_stack

	mov	$31, $26	/* tell "ret_from_sys_call" we can restart */
	br	ret_from_sys_call

$syscall_trace_failed:
	bsr	$1, do_switch_stack
	mov	$18, $9
	mov	$19, $10
	call	$26, syscall_trace_leave
	mov	$9, $18
	mov	$10, $19
	bsr	$1, undo_switch_stack
	mov	$31, $26	/* tell "ret_from_sys_call" we can restart */
	br	ret_from_sys_call
	.end strace

	.align 4
	.ent do_switch_stack
do_switch_stack:
	ldi	$sp, -SWITCH_STACK_SIZE($sp)
	flds	$f31, 0($sp) /* fillde hint */
	stl	$9, SWITCH_STACK_R9($sp)
	stl	$10, SWITCH_STACK_R10($sp)
	stl	$11, SWITCH_STACK_R11($sp)
	stl	$12, SWITCH_STACK_R12($sp)
	stl	$13, SWITCH_STACK_R13($sp)
	stl	$14, SWITCH_STACK_R14($sp)
	stl	$15, SWITCH_STACK_R15($sp)
	stl	$26, SWITCH_STACK_RA($sp)
	// SIMD-FP
	ldl	$9, TI_TASK($8)
	ldi	$9, TASK_THREAD($9)
	ldi	$10, THREAD_CTX_FP($9)
	vstd	$f0, CTX_FP_F0($10)
	vstd	$f1, CTX_FP_F1($10)
	vstd	$f2, CTX_FP_F2($10)
	vstd	$f3, CTX_FP_F3($10)
	vstd	$f4, CTX_FP_F4($10)
	vstd	$f5, CTX_FP_F5($10)
	vstd	$f6, CTX_FP_F6($10)
	vstd	$f7, CTX_FP_F7($10)
	vstd	$f8, CTX_FP_F8($10)
	vstd	$f9, CTX_FP_F9($10)
	vstd	$f10, CTX_FP_F10($10)
	vstd	$f11, CTX_FP_F11($10)
	vstd	$f12, CTX_FP_F12($10)
	vstd	$f13, CTX_FP_F13($10)
	vstd	$f14, CTX_FP_F14($10)
	vstd	$f15, CTX_FP_F15($10)
	vstd	$f16, CTX_FP_F16($10)
	vstd	$f17, CTX_FP_F17($10)
	vstd	$f18, CTX_FP_F18($10)
	vstd	$f19, CTX_FP_F19($10)
	vstd	$f20, CTX_FP_F20($10)
	vstd	$f21, CTX_FP_F21($10)
	vstd	$f22, CTX_FP_F22($10)
	vstd	$f23, CTX_FP_F23($10)
	vstd	$f24, CTX_FP_F24($10)
	vstd	$f25, CTX_FP_F25($10)
	vstd	$f26, CTX_FP_F26($10)
	vstd	$f27, CTX_FP_F27($10)
	rfpcr	$f0
	vstd	$f28, CTX_FP_F28($10)
	vstd	$f29, CTX_FP_F29($10)
	vstd	$f30, CTX_FP_F30($10)
	fstd	$f0, THREAD_FPCR($9)
	vldd	$f0, CTX_FP_F0($10)
	ldl	$9, SWITCH_STACK_R9($sp)
	ldl	$10, SWITCH_STACK_R10($sp)
	ret	$31, ($1), 1
	.end do_switch_stack

	.align 4
	.ent undo_switch_stack
undo_switch_stack:
#ifdef CONFIG_SUBARCH_C3B
	fillcs	0($sp)		/* prefetch */
#endif
	ldl	$11, SWITCH_STACK_R11($sp)
	ldl	$12, SWITCH_STACK_R12($sp)
	ldl	$13, SWITCH_STACK_R13($sp)
	ldl	$14, SWITCH_STACK_R14($sp)
	ldl	$15, SWITCH_STACK_R15($sp)
	ldl	$26, SWITCH_STACK_RA($sp)
	// SIMD-FP
	ldl	$9, TI_TASK($8)
	ldi	$9, TASK_THREAD($9)
	fldd	$f0, THREAD_FPCR($9)
	wfpcr	$f0
	fimovd	$f0, $10
	and	$10, 0x3, $10
	beq	$10, $setfpec_0
	subl	$10, 0x1, $10
	beq	$10, $setfpec_1
	subl	$10, 0x1, $10
	beq	$10, $setfpec_2
	setfpec3
	br	$setfpec_over
$setfpec_0:
	setfpec0
	br	$setfpec_over
$setfpec_1:
	setfpec1
	br	$setfpec_over
$setfpec_2:
	setfpec2
$setfpec_over:
	ldi	$10, THREAD_CTX_FP($9)
	vldd	$f0, CTX_FP_F0($10)
	vldd	$f1, CTX_FP_F1($10)
	vldd	$f2, CTX_FP_F2($10)
	vldd	$f3, CTX_FP_F3($10)
	vldd	$f4, CTX_FP_F4($10)
	vldd	$f5, CTX_FP_F5($10)
	vldd	$f6, CTX_FP_F6($10)
	vldd	$f7, CTX_FP_F7($10)
	vldd	$f8, CTX_FP_F8($10)
	vldd	$f9, CTX_FP_F9($10)
	vldd	$f10, CTX_FP_F10($10)
	vldd	$f11, CTX_FP_F11($10)
	vldd	$f12, CTX_FP_F12($10)
	vldd	$f13, CTX_FP_F13($10)
	vldd	$f14, CTX_FP_F14($10)
	vldd	$f15, CTX_FP_F15($10)
	vldd	$f16, CTX_FP_F16($10)
	vldd	$f17, CTX_FP_F17($10)
	vldd	$f18, CTX_FP_F18($10)
	vldd	$f19, CTX_FP_F19($10)
	vldd	$f20, CTX_FP_F20($10)
	vldd	$f21, CTX_FP_F21($10)
	vldd	$f22, CTX_FP_F22($10)
	vldd	$f23, CTX_FP_F23($10)
	vldd	$f24, CTX_FP_F24($10)
	vldd	$f25, CTX_FP_F25($10)
	vldd	$f26, CTX_FP_F26($10)
	vldd	$f27, CTX_FP_F27($10)
	vldd	$f28, CTX_FP_F28($10)
	vldd	$f29, CTX_FP_F29($10)
	vldd	$f30, CTX_FP_F30($10)
	ldl	$9, SWITCH_STACK_R9($sp)
	ldl	$10, SWITCH_STACK_R10($sp)
	ldi	$sp, SWITCH_STACK_SIZE($sp)
	ret	$31, ($1), 1
	.end undo_switch_stack

/*
 * The meat of the context switch code.
 */

	.align 4
	.globl __switch_to
	.ent __switch_to
__switch_to:
	.prologue 0
	bsr	$1, do_switch_stack
	sys_call HMC_swpctx
	ldi	$8, 0x3fff
	bic	$sp, $8, $8
	bsr	$1, undo_switch_stack
	mov	$17, $0
	ret
	.end __switch_to

/*
 * New processes begin life here.
 */

	.globl ret_from_fork
	.align 4
	.ent ret_from_fork
ret_from_fork:
	ldi	$26, ret_from_sys_call
	mov	$17, $16
	jmp	$31, schedule_tail
	.end ret_from_fork

/*
 * ... and new kernel threads - here
 */
	.align 4
	.globl ret_from_kernel_thread
	.ent ret_from_kernel_thread
ret_from_kernel_thread:
	mov	$17, $16
	call	$26, schedule_tail
	mov	$9, $27
	mov	$10, $16
	call	$26, ($9)
	mov	$31, $19		/* to disable syscall restarts */
	br	$31, ret_to_user
	.end ret_from_kernel_thread

/*
 * Special system calls.  Most of these are special in that they either
 * have to play switch_stack games or in some way use the pt_regs struct.
 */

.macro	fork_like name
	.align 4
	.globl sw64_\name
	.ent sw64_\name
sw64_\name:
	.prologue 0
	bsr	$1, do_switch_stack
	call	$26, sys_\name
	ldl	$26, SWITCH_STACK_RA($sp)
	ldi	$sp, SWITCH_STACK_SIZE($sp)
	ret
	.end	sw64_\name
	.endm

fork_like fork
fork_like vfork
fork_like clone
fork_like clone3

	.align 4
	.globl sys_sigreturn
	.ent sys_sigreturn
sys_sigreturn:
	.prologue 0
	ldi	$9, ret_from_straced
	cmpult	$26, $9, $9
	ldi	$sp, -SWITCH_STACK_SIZE($sp)
	call	$26, do_sigreturn
	bne	$9, 1f
	call	$26, syscall_trace_leave
1:	br	$1, undo_switch_stack
	br	ret_from_sys_call
	.end sys_sigreturn

	.align 4
	.globl sys_rt_sigreturn
	.ent sys_rt_sigreturn
sys_rt_sigreturn:
	.prologue 0
	ldi	$9, ret_from_straced
	cmpult	$26, $9, $9
	ldi	$sp, -SWITCH_STACK_SIZE($sp)
	call	$26, do_rt_sigreturn
	bne	$9, 1f
	call	$26, syscall_trace_leave
1:	br	$1, undo_switch_stack
	br	ret_from_sys_call
	.end sys_rt_sigreturn

	.align 4
	.globl ni_syscall
	.ent ni_syscall
ni_syscall:
	.prologue 0
	/* Special because it also implements overflow handling via
	 * syscall number 0.  And if you recall, zero is a special
	 * trigger for "not an error".  Store large non-zero there.
	 */
	ldi	$0, -ENOSYS
	unop
	stl	$0, PT_REGS_R0($sp)
	ret
	.end ni_syscall
