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

/*
 * Copy a page from src to dest (both are page aligned) with machine check
 *
 * Parameters:
 *	x0 - dest
 *	x1 - src
 * Returns:
 * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
 *	     while copying.
 */
SYM_FUNC_START(__pi_copy_mc_page)
alternative_if ARM64_HAS_NO_HW_PREFETCH
	// Prefetch three cache lines ahead.
	prfm	pldl1strm, [x1, #128]
	prfm	pldl1strm, [x1, #256]
	prfm	pldl1strm, [x1, #384]
alternative_else_nop_endif

CPY_MC(9998f, ldp	x2, x3, [x1])
CPY_MC(9998f, ldp	x4, x5, [x1, #16])
CPY_MC(9998f, ldp	x6, x7, [x1, #32])
CPY_MC(9998f, ldp	x8, x9, [x1, #48])
CPY_MC(9998f, ldp	x10, x11, [x1, #64])
CPY_MC(9998f, ldp	x12, x13, [x1, #80])
CPY_MC(9998f, ldp	x14, x15, [x1, #96])
CPY_MC(9998f, ldp	x16, x17, [x1, #112])

	add	x0, x0, #256
	add	x1, x1, #128
1:
	tst	x0, #(PAGE_SIZE - 1)

alternative_if ARM64_HAS_NO_HW_PREFETCH
	prfm	pldl1strm, [x1, #384]
alternative_else_nop_endif

CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
CPY_MC(9998f, ldp	x2, x3, [x1])
CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
CPY_MC(9998f, ldp	x4, x5, [x1, #16])
CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
CPY_MC(9998f, ldp	x6, x7, [x1, #32])
CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
CPY_MC(9998f, ldp	x8, x9, [x1, #48])
CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
CPY_MC(9998f, ldp	x10, x11, [x1, #64])
CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
CPY_MC(9998f, ldp	x12, x13, [x1, #80])
CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
CPY_MC(9998f, ldp	x14, x15, [x1, #96])
CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
CPY_MC(9998f, ldp	x16, x17, [x1, #112])

	add	x0, x0, #128
	add	x1, x1, #128

	b.ne	1b

CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])

	mov x0, #0
	ret

9998:	mov x0, #-EFAULT
	ret

SYM_FUNC_END(__pi_copy_mc_page)
SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
EXPORT_SYMBOL(copy_mc_page)
