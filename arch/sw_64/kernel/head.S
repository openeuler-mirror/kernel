/* SPDX-License-Identifier: GPL-2.0 */
/*
 * initial boot stuff.. At this point, the bootloader has already
 * switched into HMcode, and loaded us at the correct address
 * (START_ADDR).  So there isn't much left for us to do: just set up
 * the kernel global pointer and jump to the kernel entry-point.
 */

#include <linux/init.h>
#include <asm/asm-offsets.h>
#include <asm/hmcall.h>
#include <asm/setup.h>

__HEAD
	.globl _stext
	.set noreorder
	.globl __start
	.ent __start
_stext:
__start:
	.prologue 0
	br	$27, 1f
1:	ldgp	$29, 0($27)
	/* We need to get current_task_info loaded up...  */
	ldi	$8, init_thread_union
	/* ... and find our stack ... */
	ldi	$30, ASM_THREAD_SIZE($8)
	/* ... and then we can clear bss data.  */
	ldi	$2, __bss_start
	ldi	$3, __bss_stop
	/* 8 bytes alignment */
1:	and	$2, 0x7, $1	# align check
	bne	$1, 3f
2:	subl	$3, $2, $1	# align clear
	ble	$1, 4f
	subl	$1, 0x8, $1
	ble	$1, 3f
	stl	$31, 0($2)
	addl	$2, 8, $2
	br	$31, 2b
3:	stb	$31, 0($2)	# non align clear
	addl	$2, 1, $2
	subl	$3, $2, $1
	bgt	$1, 1b
4:# finish clear
#ifdef CONFIG_RELOCATABLE
	ldi	$30, -8($30)
	stl	$29, 0($30)
	/* Copy kernel and apply the relocations */
	call	$26, relocate_kernel
	ldl	$29, 0($30)
	addl	$29, $0, $29
	/* Repoint the sp into the new kernel image */
	ldi	$30, ASM_THREAD_SIZE($8)
#endif
	/* ... and then we can start the kernel.  */
	call	$26, sw64_start_kernel
	sys_call HMC_halt
	.end __start

#ifdef CONFIG_SMP
	.align 3
	.globl __smp_callin
	.ent __smp_callin
	/* On entry here the PCB of the idle task for this processor
	 * has been loaded.  We've arranged for the tilde_pcb[x] for
	 * this process to contain the PCBB of the target idle task.
	 */
__smp_callin:
	.prologue 1
	br	$27, 2f		# we copy this from above "br $27 1f"
2:	ldgp	$29, 0($27)	# First order of business, load the GP.

	bis	$31, $31, $16	# invalidate all TLB with current VPN
	sys_call HMC_tbi

	sys_call HMC_whami	# Get hard cid

	ldi	$1, __rcid_to_cpu
	s4addl	$0, $1, $1
	ldw	$0, 0($1)	# Get logical cpu number

	ldi	$2, tidle_ksp
	s8addl	$0, $2, $2
	ldl	$30, 0($2)	# Get ksp of idle thread

	ldi	$8, -ASM_THREAD_SIZE($30) # Find "current"

	call	$26, smp_callin
	sys_call HMC_halt
	.end __smp_callin
#endif /* CONFIG_SMP */
	#
	# It is handy, on occasion, to make halt actually just loop.
	# Putting it here means we dont have to recompile the whole
	# kernel.
	#

	.align 3
	.globl halt
	.ent halt
halt:
	.prologue 0
	sys_call HMC_halt
	.end halt
