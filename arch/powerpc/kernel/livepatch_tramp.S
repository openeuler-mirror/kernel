/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.c - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2023  Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/asm-offsets.h>
#include <asm/ppc_asm.h>
#include <asm/ptrace.h>

.section ".text","ax",@progbits

	/*
	 * Livepatch function branch stub.
	 * see struct ppc64_klp_bstub_entry
	 * use it jump to livepatch trampoline
	 */
_GLOBAL(livepatch_branch_stub)
	addis   r11,r2, 0		/* <high> */
	addi    r11,r11, 0		/* <low>  */
	ld      r12,24(r11)
	mtctr   r12
	bctr
_GLOBAL(livepatch_branch_stub_end)
	nop				/* for magic */

	/*
	 * This function runs in the livepatch context, between two functions.
	 * As such it can only clobber registers which are volatile and used in
	 * function linkage.
	 *
	 * We get here when a function A, calls another function B, but B has
	 * been live patched with a new function C.
	 *
	 * On entry:
	 *  - we have no stack frame and can not allocate one
	 *  - LR points back to the original caller (in A)
	 *  - CTR used to hold the new NIP for call
	 *  - r0, r11 & r12 are free
	 *	-- r11 point back to the bstub data which store (func descr)
	 *	----  0(saved_entry) : new function address
	 *	---- 8(r0) : new R2(toc) for new function
	 *	-- tag livepatch stack with r11
	 *	-- save temporary variables with r12
	 */
_GLOBAL(livepatch_branch_trampoline)
	mflr	r0
	std	r0, 16(r1)
	std	r2, 24(r1)
	stdu    r1, -STACK_FRAME_MIN_SIZE(r1)

	/* Load func descr address to R11 */
	lis	r11, 0		/* saved_entry@highest */
	ori	r11,r11,0	/* saved_entry@higher */
	rldicr r11,r11,32,31
	oris	r11,r11,0	/* saved_entry@high */
	ori	r11,r11,0	/* saved_entry@low */

	/* Call NEW_FUNC */
	ld	r12, 0(r11)	/* load new func address to R12 */
	ld	r2,  8(r11)	/* set up new R2 */
	mtctr   r12		/* load R12(new func address) to CTR */
	bctrl			/* call new func */

	/*
	 * Now we are returning from the patched function to the original
	 * caller A. We are free to use r11, r12 and we can use r2 until we
	 * restore it.
	 */
	addi	r1, r1, STACK_FRAME_MIN_SIZE
	ld	r2, 24(r1)
	ld	r0, 16(r1)
	mtlr	r0

	/* Return to original caller of live patched function */
	blr
_GLOBAL(livepatch_branch_trampoline_end)
	nop

/*
 * This function is the trampoline of livepatch brk handler.
 *
 * brk -> traps
 *  - klp_brk_handler
 *   - set R11 to new_func address
 *   - set NIP to livepatch_brk_trampoline address
 * see arch/powerpc/kernel/livepatch.c
 */
_GLOBAL(livepatch_brk_trampoline)
	mflr	r0
	std	r0, 16(r1)
	std	r2, 24(r1)
	stdu    r1, -STACK_FRAME_MIN_SIZE(r1)

	/* Call NEW_FUNC */
	ld	r12, 0(r11)	/* load new func address to R12 */
	ld	r2,  8(r11)	/* set up new R2 */
	mtctr   r12		/* load R12(new func address) to CTR */
	bctrl			/* call new func */

	/*
	 * Now we are returning from the patched function to the original
	 * caller A. We are free to use r11, r12 and we can use r2 until we
	 * restore it.
	 */
	addi	r1, r1, STACK_FRAME_MIN_SIZE
	ld	r2, 24(r1)
	ld	r0, 16(r1)
	mtlr	r0

	/* Return to original caller of live patched function */
	blr
