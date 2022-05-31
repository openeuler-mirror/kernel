/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Loongson Technology Corporation Limited
 */
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/export.h>
#include <asm/regdef.h>

/*
 * long __strnlen_user(const char *s, long n)
 *
 * a0: s
 * a1: n
 */
SYM_FUNC_START(__strnlen_user)
	move	a2, zero

1:	ld.b	t0, a0, 0
	addi.d	a0, a0, 1
	addi.d	a2, a2, 1
	beqz	t0, 2f

	bge	a1, a2, 1b

	/*
	 * return the size of a string including the ending NUL character
	 * up to a maximum of n
	 */
2:	move	a0, a2
	jr	ra

	.section .fixup, "ax"
	/* return 0 in case of error */
3:	move	a0, zero
	jr	ra
	.previous

	.section __ex_table, "a"
	PTR	1b, 3b
	.previous
SYM_FUNC_END(__strnlen_user)

EXPORT_SYMBOL(__strnlen_user)
