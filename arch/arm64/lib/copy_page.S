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

/*
 * Copy a page from src to dest (both are page aligned)
 *
 * Parameters:
 *	x0 - dest
 *	x1 - src
 */
	.macro ldp1 reg1, reg2, ptr, val
	ldp \reg1, \reg2, [\ptr, \val]
	.endm

SYM_FUNC_START(__pi_copy_page)
#include "copy_page_template.S"
	ret
SYM_FUNC_END(__pi_copy_page)
SYM_FUNC_ALIAS(copy_page, __pi_copy_page)
EXPORT_SYMBOL(copy_page)
