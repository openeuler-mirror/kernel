/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 ARM Ltd.
 * Copyright (C) 2013 Linaro.
 *
 * This code is based on glibc cortex strings work originally authored by Linaro
 * be found @
 *
 * http://bazaar.launchpad.net/~linaro-toolchain-dev/cortex-strings/trunk/
 * files/head:/src/aarch64/
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/cache.h>

/*
 * Copy a buffer from src to dest (alignment handled by the hardware)
 * with machine check safe.
 *
 * Parameters:
 *	x0 - dest
 *	x1 - src
 *	x2 - n
 * Returns:
 *	x0 - bytes not copied
 */
	.macro ldrb1 reg, ptr, val
	CPY_MC(9998f, ldrb  \reg, [\ptr], \val)
	.endm

	.macro strb1 reg, ptr, val
	CPY_MC(9998f, strb \reg, [\ptr], \val)
	.endm

	.macro ldrh1 reg, ptr, val
	CPY_MC(9998f, ldrh  \reg, [\ptr], \val)
	.endm

	.macro strh1 reg, ptr, val
	CPY_MC(9998f, strh \reg, [\ptr], \val)
	.endm

	.macro ldr1 reg, ptr, val
	CPY_MC(9998f, ldr \reg, [\ptr], \val)
	.endm

	.macro str1 reg, ptr, val
	CPY_MC(9998f, str \reg, [\ptr], \val)
	.endm

	.macro ldp1 reg1, reg2, ptr, val
	CPY_MC(9998f, ldp \reg1, \reg2, [\ptr], \val)
	.endm

	.macro stp1 reg1, reg2, ptr, val
	CPY_MC(9998f, stp \reg1, \reg2, [\ptr], \val)
	.endm

end	.req	x5
SYM_FUNC_START_ALIAS(__memcpy_mcs)
SYM_FUNC_START_WEAK_PI(memcpy_mcs)
	add end, x0, x2
#include "copy_template.S"
	mov x0, #0
	ret

9998:	sub x0, end, dst
	ret
SYM_FUNC_END_PI(memcpy_mcs)
EXPORT_SYMBOL(memcpy_mcs)
SYM_FUNC_END_ALIAS(__memcpy_mcs)
EXPORT_SYMBOL(__memcpy_mcs)
