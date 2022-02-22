/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copy to/from user space, handling exceptions as we go..  This
 * isn't exactly pretty.
 *
 * This is essentially the same as "memcpy()", but with a few twists.
 * Notably, we have to make sure that $18 is always up-to-date and
 * contains the right "bytes left to copy" value (and that it is updated
 * only _after_ a successful copy). There is also some rather minor
 * exception setup stuff..
 *
 * Inputs:
 *	length in $18
 *	destination address in $16
 *	source address in $17
 *	return address in $26
 *
 * Outputs:
 *	bytes left to copy in $0
 *
 * Clobbers:
 *	$1,$2,$3,$4,$5,$16,$17
 *
 */

/* Author: Copy_user simd version 1.1 (20190904) by Gao Xiuwu.
*/
#include <asm/export.h>

/* Allow an exception for an insn; exit if we get one.  */
#define EXI(x, y...)			\
	99: x, ##y;			\
	.section __ex_table, "a";	\
	.long 99b - .;			\
	ldi $31, $exitin-99b($31);	\
	.previous

#define EXO(x,y...)			\
	99: x, ##y;			\
	.section __ex_table, "a";	\
	.long 99b - .;			\
	ldi $31, $exitout-99b($31);	\
	.previous

	.set noat
	.align 4
	.globl __copy_user
	.ent __copy_user

__copy_user:
	.prologue 0
	subl	$18, 32, $1
	beq	$18, $zerolength

	and	$16, 7, $3
	ble	$1, $onebyteloop
	beq	$3, $destaligned
	subl	$3, 8, $3
/*
 * The fetcher stall also hides the 1 cycle cross-cluster stall for $3 (L --> U)
 * This loop aligns the destination a byte at a time
 * We know we have at least one trip through this loop
 */
$aligndest:
	EXI(ldbu $1, 0($17))
	addl	$16, 1, $16
	addl	$3, 1, $3

/*
 * the -1 is to compensate for the inc($16) done in a previous quadpack
 * which allows us zero dependencies within either quadpack in the loop
 */
	EXO(stb $1, -1($16))
	addl	$17, 1, $17
	subl	$18, 1, $18
	bne	$3, $aligndest

/*
 * If we fell through into here, we have a minimum of 33 - 7 bytes
 * If we arrived via branch, we have a minimum of 32 bytes
 */
$destaligned:
	and	$17, 7, $1
	bic	$18, 7, $4
	#EXI(ldl_u $3, 0($17))
	beq	$1, $quadaligned

#ifndef MISQUAD_SCALAR
$misquad:
	and	$16, 31, $1
	beq	$1, $dest32Baligned

$align_32B:
	EXI(ldbu $1, 0($17))
	addl	$17, 1, $17
	EXO(stb $1, 0($16))
	subl	$18, 1, $18
	addl	$16, 1, $16
	and	$16, 31, $1
	beq	$18, $exitout
	bne	$1, $align_32B

$dest32Baligned:
	ldi	$2, 256($31)
	andnot	$17, 31, $3
	EXI(vldd  $f10, 0($3))
	and	$17, 31, $5
	sll	$5, 3, $5
	subw	$2, $5, $4
	ifmovs	$5, $f15
	ifmovs	$4, $f14

	cmple $18, 63, $1
	bne $1, $misalign_tail_simd

$misalign_body_simd:
	EXI(vldd $f11, 32($3))
	fillcs	128*5($3)

	srlow	$f10, $f15, $f12
	sllow	$f11, $f14, $f13
	#fillde	128*5($16)
	vlogfc	$f12, $f13, $f31, $f12

	EXI(vldd $f10, 64($3))
	srlow	$f11, $f15, $f22
	sllow	$f10, $f14, $f23
	vlogfc	$f22, $f23, $f31, $f22

	EXO(vstd  $f12, 0($16))
	EXO(vstd  $f22, 32($16))

	addl	$16, 64, $16
	addl	$3, 64, $3
	subl	$18, 64, $18

	cmple	$18, 63, $1
	beq	$1, $misalign_body_simd
	br	$misalign_tail_simd

$misalign_tail_simd:
	cmple	$18, 31, $1
	bne	$1, $before_misalign_tail_quads

	EXI(vldd $f11, 32($3))
	srlow	$f10, $f15, $f12
	sllow	$f11, $f14, $f13
	vlogfc	$f12, $f13, $f31, $f12

	EXO(vstd $f12, 0($16))

	subl	$18, 32, $18
	addl	$16, 32, $16
	addl	$3, 32, $3
	vfmov	$f11, $f10

$before_misalign_tail_quads:
	srlow	$f10, $f15, $f12
	s8subl	$18, $4, $1
	ble	$1, $tail_quads

	EXI(vldd $f11, 32($3))
	sllow	$f11, $f14, $f13
	vlogfc	$f12, $f13, $f31, $f12

$tail_quads:
	subl	$18, 8, $1
	blt	$1, $less_than_8

$move_a_quad:
	fimovd	$f12, $1
	srlow	$f12, 64, $f12

	EXO(stl $1, 0($16))
	subl	$18, 8, $18
	addl	$16, 8, $16
	subl	$18, 8, $1
	bge	$1, $move_a_quad

$less_than_8:
	.align 4
	beq	$18, $exitout
	fimovd	$f12, $1

$tail_bytes:
	EXO(stb $1, 0($16))
	subl	$18, 1, $18
	srl	$1, 8, $1
	addl	$16, 1, $16
	bgt	$18, $tail_bytes
	br	$exitout
#else

/*
 * In the worst case, we've just executed an ldl_u here from 0($17)
 * and we'll repeat it once if we take the branch
 */

/* Misaligned quadword loop - not unrolled.  Leave it that way. */
$misquad:
	EXI(ldl_u $2, 8($17))
	subl	$4, 8, $4
	extll	$3, $17, $3
	exthl	$2, $17, $1

	bis	$3, $1, $1
	EXO(stl $1, 0($16))
	addl	$17, 8, $17
	subl	$18, 8, $18

	addl	$16, 8, $16
	bis	$2, $2, $3
	bne	$4, $misquad

	beq	$18, $zerolength

/* We know we have at least one trip through the byte loop */
	EXI(ldbu $2, 0($17))
	addl	$16, 1, $16
	br	$31, $dirtyentry
#endif
/* Do the trailing byte loop load, then hop into the store part of the loop */

/*
 * A minimum of (33 - 7) bytes to do a quad at a time.
 * Based upon the usage context, it's worth the effort to unroll this loop
 * $18 - number of bytes to be moved
 * $4 - number of bytes to move as quadwords
 * $16 is current destination address
 * $17 is current source address
 */

$quadaligned:
	and	$16, 31, $1
	beq	$1, $quadaligned_dest32Baligned

$quadaligned_align_32B:
	EXI(ldl $1, 0($17))
	addl	$17, 8, $17
	EXO(stl $1, 0($16))
	subl	$18, 8, $18
	subl	$4, 8, $4
	addl	$16, 8, $16
	and	$16, 31, $1
	beq	$4, $onebyteloop
	bne	$1, $quadaligned_align_32B

$quadaligned_dest32Baligned:
	and	$17, 31, $2
	bne	$2, $dest32Baligned

$quad32Bailgned:
	subl	$4, 64, $2
	blt	$2, $onequad

/*
 * There is a significant assumption here that the source and destination
 * addresses differ by more than 32 bytes.  In this particular case, a
 * sparsity of registers further bounds this to be a minimum of 8 bytes.
 * But if this isn't met, then the output result will be incorrect.
 * Furthermore, due to a lack of available registers, we really can't
 * unroll this to be an 8x loop (which would enable us to use the wh64
 * instruction memory hint instruction).
 */

$simd_quadalign_unroll2:
	fillcs 128 * 5($17)
	EXI(vldd $f22, 0($17))
	EXI(vldd $f23, 32($17))
	EXO(vstd $f22, 0($16))
	EXO(vstd $f23, 32($16))
	#fillde 128 * 5($16)
	subl	$4, 64, $4
	subl	$18, 64, $18
	addl	$17, 64, $17
	addl	$16, 64, $16
	subl	$4, 64, $3
	bge	$3, $simd_quadalign_unroll2
	bne	$4, $onequad
	br	$31, $noquads

$onequad:
	EXI(ldl $1, 0($17))
	subl	$4, 8, $4
	addl	$17, 8, $17

	EXO(stl $1, 0($16))
	subl	$18, 8, $18
	addl	$16, 8, $16
	bne	$4, $onequad

$noquads:
	beq	$18, $zerolength

/*
 * For small copies (or the tail of a larger copy), do a very simple byte loop.
 * There's no point in doing a lot of complex alignment calculations to try to
 * to quadword stuff for a small amount of data.
 *	$18 - remaining number of bytes left to copy
 *	$16 - current dest addr
 *	$17 - current source addr
 */

$onebyteloop:
	EXI(ldbu $2, 0($17))
	addl	$16, 1, $16

$dirtyentry:
/*
 * the -1 is to compensate for the inc($16) done in a previous quadpack
 * which allows us zero dependencies within either quadpack in the loop
 */
	EXO(stb $2, -1($16))
	addl	$17, 1, $17
	subl	$18, 1, $18
	bgt	$18, $onebyteloop

$zerolength:
$exitout:
	bis	$31, $18, $0
	ret	$31, ($26), 1

$exitin:

	/* A stupid byte-by-byte zeroing of the rest of the output
	 * buffer.  This cures security holes by never leaving
	 * random kernel data around to be copied elsewhere.
	 */

	mov	$18, $1

$101:
	EXO(stb $31, 0($16))
	subl	$1, 1, $1
	addl	$16, 1, $16
	bgt	$1, $101

	bis	$31, $18, $0
	ret	$31, ($26), 1

	.end __copy_user
	EXPORT_SYMBOL(__copy_user)
