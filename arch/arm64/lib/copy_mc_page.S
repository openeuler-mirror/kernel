/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/linkage.h>
#include <linux/const.h>
#include <asm/assembler.h>
#include <asm/page.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>
#include <asm/asm-extable.h>
#include <asm/asm-uaccess.h>

/*
 * Copy a page from src to dest (both are page aligned) with memory error safe
 *
 * Parameters:
 *	x0 - dest
 *	x1 - src
 * Returns:
 * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
 *	     while copying.
 */
	.macro ldp1 reg1, reg2, ptr, val
	KERNEL_ME_SAFE(9998f, ldp \reg1, \reg2, [\ptr, \val])
	.endm

SYM_FUNC_START(__pi_copy_mc_page)
#include "copy_page_template.S"

	mov x0, #0
	ret

9998:	mov x0, #-EFAULT
	ret

SYM_FUNC_END(__pi_copy_mc_page)
SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
EXPORT_SYMBOL(copy_mc_page)
