/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/export.h>
	.set noreorder
	.set noat

	.align  4
	.globl memcpy
	.ent memcpy

memcpy:
	.frame $30, 0, $26, 0
	.prologue 0

	subl	$sp, 0xa0, $sp
	ldi	$4, 0x40($sp)
	stl	$4, 0($sp)
	bic	$4, 0x1f, $4
	vstd	$f4, 0($4)
	vstd	$f5, 0x20($4)

	mov	$16, $0
	ble	$18, $nomoredata
	xor	$16, $17, $1
	and	$1, 7, $1

	bne	$1, $misaligned

	and	$16, 7, $1
	beq	$1, $both_0mod8

$head_align:
	ldbu	$1, 0($17)
	subl	$18, 1, $18
	addl	$17, 1, $17
	stb	$1, 0($16)
	addl	$16, 1, $16
	and	$16, 7, $1
	ble	$18, $nomoredata
	bne	$1, $head_align

$both_0mod8:
	cmple	$18, 127, $1
	bne	$1, $no_unroll
	and	$16, 63, $1
	beq	$1, $do_unroll

$single_head_quad:
	ldl	$1, 0($17)
	subl	$18, 8, $18
	addl	$17, 8, $17

	stl	$1, 0($16)
	addl	$16, 8, $16
	and	$16, 63, $1
	bne	$1, $single_head_quad

$do_unroll:
	addl	$16, 64, $7
	cmple	$18, 127, $1
	bne	$1, $tail_quads

#JJ
	and	$17, 31, $1
	bne	$1, $unroll_body

$unroll_body_simd:
	ldwe	$f31,128*5($17)
	vldd	$f4, 0($17)
	vldd	$f5, 32($17)
	vstd_nc	$f4, 0($16)
	vstd_nc	$f5, 32($16)
	addl	$16, 64, $16
	subl	$18, 64, $18
	addl	$17, 64, $17
	cmple	$18, 63, $1
	beq	$1, $unroll_body_simd
	memb
	br	$no_unroll
#endJJ

$unroll_body:
	#wh64 ($7)
	#e_fillcs 0($7)

	ldl	$6, 0($17)
	#e_fillcs 256($17)

	ldl	$4, 8($17)
	ldl	$5, 16($17)
	addl	$7, 64, $7

	ldl	$3, 24($17)
	addl	$16, 64, $1

	addl	$17, 32, $17
	stl_nc	$6, 0($16)

	stl_nc	$4, 8($16)
	stl_nc	$5, 16($16)
	subl	$18, 192, $2

	stl_nc	$3, 24($16)
	addl	$16, 32, $16

	ldl	$6, 0($17)
	ldwe	$f31, 4*128($17)
	#e_fillcs 288($17)
	ldl	$4, 8($17)
	#cmovlt	$2, $1, $7
	sellt	$2, $1, $7, $7

	ldl	$5, 16($17)
	ldl	$3, 24($17)
	addl	$16, 32, $16
	subl	$18, 64, $18

	addl	$17, 32, $17
	stl_nc	$6, -32($16)
	stl_nc	$4, -24($16)
	cmple	$18, 63, $1

	stl_nc	$5, -16($16)
	stl_nc	$3, -8($16)
	beq	$1, $unroll_body

	memb

$tail_quads:
$no_unroll:
	.align 4
	subl	$18, 8, $18
	blt	$18, $less_than_8

$move_a_quad:
	ldl	$1, 0($17)
	subl	$18, 8, $18
	addl	$17, 8, $17

	stl	$1, 0($16)
	addl	$16, 8, $16
	bge	$18, $move_a_quad

$less_than_8:
	.align 4
	addl	$18, 8, $18
	ble	$18, $nomoredata


$tail_bytes:
	subl	$18, 1, $18
	ldbu	$1, 0($17)
	addl	$17, 1, $17

	stb	$1, 0($16)
	addl	$16, 1, $16
	bgt	$18, $tail_bytes

	ldi	$4, 0x40($sp)
	bic	$4, 0x1f, $4
	vldd	$f4, 0($4)
	vldd	$f5, 0x20($4)
	ldl	$4, 0($sp)
	addl	$sp, 0xa0, $sp

	ret	$31, ($26), 1

$misaligned:
	mov	$0, $4
	and	$0, 7, $1
	beq	$1, $dest_0mod8

$aligndest:
	ble	$18, $nomoredata
	ldbu	$1, 0($17)
	subl	$18, 1, $18
	addl	$17, 1, $17

	stb	$1, 0($4)
	addl	$4, 1, $4
	and	$4, 7, $1
	bne	$1, $aligndest


$dest_0mod8:
	subl	$18, 8, $18
	blt	$18, $misalign_tail
	ldl_u	$3, 0($17)

$mis_quad:
	ldl_u	$16, 8($17)
	#extql	$3, $17, $3
	fillde	256($17)
	and	$17, 7, $1
	sll	$1, 3, $1
	srl	$3, $1, $3

	#extqh $16, $17, $1
	subl	$1, 64, $1
	negl	$1, $1
	sll	$16, $1, $1

	bis	$3, $1, $1

	subl	$18, 8, $18
	addl	$17, 8, $17
	fillde	128($4)
	stl	$1, 0($4)
	mov	$16, $3

	addl	$4, 8, $4
	bge	$18, $mis_quad

$misalign_tail:
	addl	$18, 8, $18
	ble	$18, $nomoredata

$misalign_byte:
	ldbu	$1, 0($17)
	subl	$18, 1, $18
	addl	$17, 1, $17

	stb	$1, 0($4)
	addl	$4, 1, $4
	bgt	$18, $misalign_byte


$nomoredata:
	ldi	$4, 0x40($sp)
	bic	$4, 0x1f, $4
	vldd	$f4, 0($4)
	vldd	$f5, 0x20($4)
	ldl	$4, 0($sp)
	addl	$sp, 0xa0, $sp

	ret	$31, ($26), 1

	.end memcpy
	 EXPORT_SYMBOL(memcpy)
__memcpy = memcpy
.globl __memcpy
