/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CPU park routines
 *
 * Copyright (C) 2020 Huawei Technologies., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/cpu_park.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

.text
.pushsection    .idmap.text, "awx"

/* cpu park helper in idmap section */
SYM_CODE_START(enter_cpu_park)
	/* Clear sctlr_el1 flags. */
	mrs	x12, sctlr_el1
	mov_q	x13, SCTLR_ELx_FLAGS
	bic	x12, x12, x13
	pre_disable_mmu_workaround
	msr	sctlr_el1, x12		/* disable mmu */
	isb

	mov	x18, x0
	mov	x0, x1			/* secondary_entry addr */
	br	x18			/* call do_cpu_park of each cpu */
SYM_CODE_END(enter_cpu_park)

.popsection

SYM_CODE_START(do_cpu_park)
	ldr	x18, =PARK_MAGIC	/* magic number "park" */
	add	x1, x0, #8
	str	x18, [x1]		/* set on-park flag */
	dc	civac, x1		/* flush cache of "park" */
	dsb     nsh
	isb

.Lloop:
	wfe
	isb
	ldr	x19, [x0]
	cmp	x19, #0			/* test secondary_entry */
	b.eq	.Lloop

	ic	iallu			/* invalidate the local I-cache */
	dsb	nsh
	isb

	br	x19			/* jump to secondary_entry */
SYM_CODE_END(do_cpu_park)
