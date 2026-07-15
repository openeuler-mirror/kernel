/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/linkage.h>

#include <asm/asm-uaccess.h>
#include <asm/assembler.h>
#include <asm/cache.h>

/*
 * Copy from user space to a kernel buffer (alignment handled by the hardware)
 *
 * Parameters:
 *	x0 - to
 *	x1 - from
 *	x2 - n
 * Returns:
 *	x0 - bytes not copied
 */

	.macro ldrb1 reg, ptr, val
	user_ldst 9998f, ldtrb, \reg, \ptr, \val
	.endm

	.macro strb1 reg, ptr, val
	strb \reg, [\ptr], \val
	.endm

	.macro ldrh1 reg, ptr, val
	user_ldst 9997f, ldtrh, \reg, \ptr, \val
	.endm

	.macro strh1 reg, ptr, val
	strh \reg, [\ptr], \val
	.endm

	.macro ldr1 reg, ptr, val
	user_ldst 9997f, ldtr, \reg, \ptr, \val
	.endm

	.macro str1 reg, ptr, val
	str \reg, [\ptr], \val
	.endm

	.macro ldp1 reg1, reg2, ptr, val
	user_ldp 9997f, \reg1, \reg2, \ptr, \val
	.endm

	.macro stp1 reg1, reg2, ptr, val
	stp \reg1, \reg2, [\ptr], \val
	.endm

end	.req	x5
srcin	.req	x15
SYM_FUNC_START(__arch_copy_from_user)
	add	end, x0, x2
	mov	srcin, x1
#include "copy_template.S"
	mov	x0, #0				// Nothing to copy
	ret

	// Exception fixups
9997:	cmp	dst, dstin
	b.ne	9998f
	// Before being absolutely sure we couldn't copy anything, try harder
USER(9998f, ldtrb tmp1w, [srcin])
	strb	tmp1w, [dst], #1
9998:	sub	x0, end, dst			// bytes not copied
	ret
SYM_FUNC_END(__arch_copy_from_user)
EXPORT_SYMBOL(__arch_copy_from_user)

#ifdef CONFIG_ARM64_COPY_FROM_USER_OPT

	.macro ldp2 reg1, reg2, ptr, val
	user_ldst_pair_index 9997f, ldp, \reg1, \reg2, \ptr, \val
	.endm

	.macro stp2 reg1, reg2, ptr, val
	stp \reg1, \reg2, [\ptr, \val]
	.endm

SYM_FUNC_START(__arch_copy_from_user_opt)
	add	end, x0, x2
	mov	srcin, x1

	ALTERNATIVE("nop", __stringify(SET_PSTATE_PAN(0)), ARM64_HAS_PAN)

#include "copy_template_opt.S"
	mov	x0, #0				// Nothing to copy

.L__arch_copy_from_user_opt_exit:
	ALTERNATIVE("nop", __stringify(SET_PSTATE_PAN(1)), ARM64_HAS_PAN)
	ret

	// Exception fixups
9997:	cmp	dst, dstin
	b.ne	9998f
	// Before being absolutely sure we couldn't copy anything, try harder
USER(9998f, ldtrb tmp1w, [srcin])
	strb	tmp1w, [dst], #1
9998:	sub	x0, end, dst			// bytes not copied
	b	.L__arch_copy_from_user_opt_exit
SYM_FUNC_END(__arch_copy_from_user_opt)
EXPORT_SYMBOL(__arch_copy_from_user_opt)

#endif /* CONFIG_ARM64_COPY_FROM_USER_OPT */
