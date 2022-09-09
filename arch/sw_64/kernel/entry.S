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
 * regs 9-15 preserved by C code, saving to pt_regs will make
 * them easier to be accessed in an unified way.
 * regs 16-18 saved by HMcode
 * regs 29-30 saved and set up by HMcode
 */

	.macro SAVE_COMMON_REGS
	ldi	$sp, -PT_REGS_PS($sp)
	stl	$0, PT_REGS_R0($sp)
	stl	$1, PT_REGS_R1($sp)
	stl	$2, PT_REGS_R2($sp)
	stl	$3, PT_REGS_R3($sp)
	stl	$4, PT_REGS_R4($sp)
	stl	$28, PT_REGS_R28($sp)
	stl	$5, PT_REGS_R5($sp)
	stl	$6, PT_REGS_R6($sp)
	stl	$7, PT_REGS_R7($sp)
	stl	$8, PT_REGS_R8($sp)
	stl	$19, PT_REGS_R19($sp)
	stl	$20, PT_REGS_R20($sp)
	stl	$21, PT_REGS_R21($sp)
	stl	$22, PT_REGS_R22($sp)
	stl	$23, PT_REGS_R23($sp)
	stl	$24, PT_REGS_R24($sp)
	stl	$25, PT_REGS_R25($sp)
	stl	$26, PT_REGS_R26($sp)
	stl	$27, PT_REGS_R27($sp)
	.endm

	.macro RESTORE_COMMON_REGS
	ldl	$0, PT_REGS_R0($sp)
	ldl	$1, PT_REGS_R1($sp)
	ldl	$2, PT_REGS_R2($sp)
	ldl	$3, PT_REGS_R3($sp)
	ldl	$4, PT_REGS_R4($sp)
	ldl	$5, PT_REGS_R5($sp)
	ldl	$6, PT_REGS_R6($sp)
	ldl	$7, PT_REGS_R7($sp)
	ldl	$8, PT_REGS_R8($sp)
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
	ldi	$sp, PT_REGS_PS($sp)
	.endm

	.macro SAVE_CALLEE_REGS
	stl	$9, PT_REGS_R9($sp)
	stl	$10, PT_REGS_R10($sp)
	stl	$11, PT_REGS_R11($sp)
	stl	$12, PT_REGS_R12($sp)
	stl	$13, PT_REGS_R13($sp)
	stl	$14, PT_REGS_R14($sp)
	stl	$15, PT_REGS_R15($sp)
	.endm

	.macro RESTORE_CALLEE_REGS
	ldl	$9, PT_REGS_R9($sp)
	ldl	$10, PT_REGS_R10($sp)
	ldl	$11, PT_REGS_R11($sp)
	ldl	$12, PT_REGS_R12($sp)
	ldl	$13, PT_REGS_R13($sp)
	ldl	$14, PT_REGS_R14($sp)
	ldl	$15, PT_REGS_R15($sp)
	.endm

	.macro SAVE_ALL
	SAVE_COMMON_REGS
	SAVE_CALLEE_REGS
	.endm

	.macro RESTORE_ALL
	RESTORE_CALLEE_REGS
	RESTORE_COMMON_REGS
	.endm

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
	ldi	$8, 0x3fff
	ldi	$26, ret_from_sys_call
	bic	$sp, $8, $8
	mov	$sp, $19
	call	$31, do_page_fault
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

/*
 * Handle unalignment exception.
 * We don't handle the "gp" register correctly, but if we fault on a
 * gp-register unaligned load/store, something is _very_ wrong in the
 * kernel anyway.
 */
	.align 4
	.globl entUna
	.ent entUna
entUna:
	SAVE_ALL
	ldi	$8, 0x3fff
	bic	$sp, $8, $8
	mov	$sp, $19
	ldl	$0, PT_REGS_PS($sp)
	and	$0, 8, $0		/* user mode ? */
	beq	$0, 1f
	ldi	$26, ret_from_sys_call
	call	$31, do_entUnaUser	/* return to ret_from_syscall */
1:	ldl	$9, PT_REGS_GP($sp)
	call	$26, do_entUna
	stl	$9, PT_REGS_GP($sp)
	RESTORE_ALL
	sys_call HMC_rti
	.end entUna

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
	call	$26, do_work_pending
	br	restore_all
	.end work_pending



/*
 * PTRACE syscall handler
 */

	.align 4
	.ent strace
strace:
	/* set up signal stack, call syscall_trace */
	mov	$0, $9
	mov	$19, $10
	call	$26, syscall_trace_enter
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
	call	$26, syscall_trace_leave
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

	mov	$18, $9		/* save old syscall number */
	mov	$19, $10	/* save old a3 */
	call	$26, syscall_trace_leave
	mov	$9, $18
	mov	$10, $19

	mov	$31, $26	/* tell "ret_from_sys_call" we can restart */
	br	ret_from_sys_call

$syscall_trace_failed:
	call	$26, syscall_trace_leave
	mov	$9, $18
	mov	$10, $19
	mov	$31, $26	/* tell "ret_from_sys_call" we can restart */
	br	ret_from_sys_call
	.end strace

/*
 * Integer register context switch
 * The callee-saved registers must be saved and restored.
 *
 *   a0: previous task_struct (must be preserved across the switch)
 *   a1: next task_struct
 *
 * The value of a0  must be preserved by this function, as that's how
 * arguments are passed to schedule_tail.
 */
	.align 4
	.globl __switch_to
	.ent __switch_to
__switch_to:
	.prologue 0
	/* Save context into prev->thread */
	stl	$26, TASK_THREAD_RA($16)
	stl	$30, TASK_THREAD_SP($16)
	stl	$9, TASK_THREAD_S0($16)
	stl	$10, TASK_THREAD_S1($16)
	stl	$11, TASK_THREAD_S2($16)
	stl	$12, TASK_THREAD_S3($16)
	stl	$13, TASK_THREAD_S4($16)
	stl	$14, TASK_THREAD_S5($16)
	stl	$15, TASK_THREAD_S6($16)
	/* Restore context from next->thread */
	ldl	$26, TASK_THREAD_RA($17)
	ldl     $30, TASK_THREAD_SP($17)
	ldl	$9, TASK_THREAD_S0($17)
	ldl	$10, TASK_THREAD_S1($17)
	ldl	$11, TASK_THREAD_S2($17)
	ldl	$12, TASK_THREAD_S3($17)
	ldl	$13, TASK_THREAD_S4($17)
	ldl	$14, TASK_THREAD_S5($17)
	ldl	$15, TASK_THREAD_S6($17)
	ldi	$8, 0x3fff
	bic	$sp, $8, $8
	mov	$16, $0
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
	call	$31, schedule_tail
	.end ret_from_fork

/*
 * ... and new kernel threads - here
 */
	.align 4
	.globl ret_from_kernel_thread
	.ent ret_from_kernel_thread
ret_from_kernel_thread:
	call	$26, schedule_tail
	mov	$9, $27
	mov	$10, $16
	call	$26, ($9)
	mov	$31, $19		/* to disable syscall restarts */
	br	$31, ret_to_user
	.end ret_from_kernel_thread

	.align 4
	.globl sys_sigreturn
	.ent sys_sigreturn
sys_sigreturn:
	.prologue 0
	ldi	$9, ret_from_straced
	cmpult	$26, $9, $9
	call	$26, do_sigreturn
	bne	$9, 1f
	call	$26, syscall_trace_leave
1:	br	ret_from_sys_call
	.end sys_sigreturn

	.align 4
	.globl sys_rt_sigreturn
	.ent sys_rt_sigreturn
sys_rt_sigreturn:
	.prologue 0
	ldi	$9, ret_from_straced
	cmpult	$26, $9, $9
	call	$26, do_rt_sigreturn
	bne	$9, 1f
	call	$26, syscall_trace_leave
1:	br	ret_from_sys_call
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
