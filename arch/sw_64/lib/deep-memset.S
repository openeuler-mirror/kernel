/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Optimized memset() for SW64 with SIMD instructions
 *
 * Copyright (C) Mao Minkai
 * Author: Mao Minkai
 *
 * Fill SIZE bytes pointed to by SRC with CHAR.
 *
 * Input:
 *	$16:	SRC, clobbered
 *	$17:	CHAR, clobbered
 *	$18:	SIZE, clobbered
 *
 * Output:
 *	$0:	SRC
 *
 * Temporaries:
 *	$1:	unaligned parts of addr (0 means aligned addr), tmp data
 *	$2:	tmp data
 *	$3:	tmp data
 *	$4:	tmp data
 *	$5:	compare result
 *	$f10:	32 bytes data (manually saved)
 *
 */

#include <asm/export.h>

#define NC_STORE_THRESHOLD	2048

	.set noat
	.set noreorder
	.text
	.align 4
	.globl memset
	.globl __memset
	.globl ___memset
	.globl __memsetw
	.globl __constant_c_memset
	.ent ___memset
___memset:
	.frame $30, 0, $26, 0
	.prologue 0

/* expand 1 byte data to 8 bytes */
	and	$17, 0xff, $17
	sll	$17, 8, $4
	bis	$17, $4, $17
	sll	$17, 16, $4
	bis	$17, $4, $17
	sll	$17, 32, $4
	bis	$17, $4, $17

__constant_c_memset:
	bis	$31, $16, $0	# set return value
	beq	$18, $out	# return if size is 0
	cmplt	$18, 8, $5	# size less than 8, do 1-byte loop
	bne	$5, $tail_loop

/* loop until SRC is 8 bytes aligned */
	.align 5
$head_loop:
	and	$16, 0x7, $1
	beq	$1, $mod8_aligned
	stb	$17, 0($16)
	subl	$18, 1, $18
	beq	$18, $out
	addl	$16, 1, $16
	br	$31, $head_loop

$mod8_aligned:

/* set 8 bytes each time */
	.align 5
$mod8_loop:
	and	$16, 0x1f, $1
	beq	$1, $mod32_aligned
	subl	$18, 8, $18
	blt	$18, $tail
	stl	$17, 0($16)
	addl	$16, 8, $16
	br	$31, $mod8_loop

/* expand data to 32 bytes */
$mod32_aligned:
	subl	$sp, 64, $sp
	addl	$sp, 31, $4
	bic	$4, 0x1f, $4
	vstd	$f10, 0($4)
	ifmovd	$17, $f10
	vcpyf	$f10, $f10

	ldi	$1, NC_STORE_THRESHOLD($31)
	cmple	$18, $1, $1
	bne	$1, $mod32_loop

/* set 64 bytes each time */
	.align 5
$mod32_loop_nc:
	subl	$18, 64, $18
	blt	$18, $mod32_tail_memb
	vstd_nc	$f10, 0($16)
	vstd_nc	$f10, 32($16)
	addl	$16, 64, $16
	br	$31, $mod32_loop_nc

	.align 5
$mod32_loop:
	subl	$18, 64, $18
	blt	$18, $mod32_tail
	vstd	$f10, 0($16)
	vstd	$f10, 32($16)
	addl	$16, 64, $16
	br	$31, $mod32_loop

$mod32_tail_memb:
	memb			# required for _nc store instructions
$mod32_tail:
	vldd	$f10, 0($4)
	addl	$sp, 64, $sp
	addl	$18, 64, $18
	.align 5
$mod32_tail_loop:
	subl	$18, 8, $18
	blt	$18, $tail
	stl	$17, 0($16)
	addl	$16, 8, $16
	br	$31, $mod32_tail_loop

$tail:
	addl	$18, 8, $18

/* set one byte each time */
	.align 5
$tail_loop:
	beq	$18, $out
	stb	$17, 0($16)
	subl	$18, 1, $18
	addl	$16, 1, $16
	br	$31, $tail_loop

/* done, return */
$out:
	ret

	.end ___memset
	EXPORT_SYMBOL(___memset)

	.align 5
	.ent __memsetw
__memsetw:
	.prologue 0

	inslh	$17, 0, $1
	inslh	$17, 2, $2
	inslh	$17, 4, $3
	bis	$1, $2, $1
	inslh	$17, 6, $4
	bis	$1, $3, $1
	bis	$1, $4, $17
	br	$31, __constant_c_memset

	.end __memsetw
	EXPORT_SYMBOL(__memsetw)

memset = ___memset
EXPORT_SYMBOL(memset)
__memset = ___memset
EXPORT_SYMBOL(__memset)
