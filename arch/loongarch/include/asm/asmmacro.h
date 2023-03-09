/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_ASMMACRO_H
#define _ASM_ASMMACRO_H

#include <asm/asm-offsets.h>
#include <asm/regdef.h>
#include <asm/fpregdef.h>
#include <asm/loongarch.h>

	.macro	parse_v var val
	\var	= \val
	.endm

	.macro	parse_r var r
	\var	= -1
	.ifc	\r, $r0
	\var	= 0
	.endif
	.ifc	\r, $r1
	\var	= 1
	.endif
	.ifc	\r, $r2
	\var	= 2
	.endif
	.ifc	\r, $r3
	\var	= 3
	.endif
	.ifc	\r, $r4
	\var	= 4
	.endif
	.ifc	\r, $r5
	\var	= 5
	.endif
	.ifc	\r, $r6
	\var	= 6
	.endif
	.ifc	\r, $r7
	\var	= 7
	.endif
	.ifc	\r, $r8
	\var	= 8
	.endif
	.ifc	\r, $r9
	\var	= 9
	.endif
	.ifc	\r, $r10
	\var	= 10
	.endif
	.ifc	\r, $r11
	\var	= 11
	.endif
	.ifc	\r, $r12
	\var	= 12
	.endif
	.ifc	\r, $r13
	\var	= 13
	.endif
	.ifc	\r, $r14
	\var	= 14
	.endif
	.ifc	\r, $r15
	\var	= 15
	.endif
	.ifc	\r, $r16
	\var	= 16
	.endif
	.ifc	\r, $r17
	\var	= 17
	.endif
	.ifc	\r, $r18
	\var	= 18
	.endif
	.ifc	\r, $r19
	\var	= 19
	.endif
	.ifc	\r, $r20
	\var	= 20
	.endif
	.ifc	\r, $r21
	\var	= 21
	.endif
	.ifc	\r, $r22
	\var	= 22
	.endif
	.ifc	\r, $r23
	\var	= 23
	.endif
	.ifc	\r, $r24
	\var	= 24
	.endif
	.ifc	\r, $r25
	\var	= 25
	.endif
	.ifc	\r, $r26
	\var	= 26
	.endif
	.ifc	\r, $r27
	\var	= 27
	.endif
	.ifc	\r, $r28
	\var	= 28
	.endif
	.ifc	\r, $r29
	\var	= 29
	.endif
	.ifc	\r, $r30
	\var	= 30
	.endif
	.ifc	\r, $r31
	\var	= 31
	.endif
	.iflt	\var
	.error	"Unable to parse register name \r"
	.endif
	.endm

	.macro	parse_vr var vr
	\var	= -1
	.ifc	\vr, $vr0
	\var	= 0
	.endif
	.ifc	\vr, $vr1
	\var	= 1
	.endif
	.ifc	\vr, $vr2
	\var	= 2
	.endif
	.ifc	\vr, $vr3
	\var	= 3
	.endif
	.ifc	\vr, $vr4
	\var	= 4
	.endif
	.ifc	\vr, $vr5
	\var	= 5
	.endif
	.ifc	\vr, $vr6
	\var	= 6
	.endif
	.ifc	\vr, $vr7
	\var	= 7
	.endif
	.ifc	\vr, $vr8
	\var	= 8
	.endif
	.ifc	\vr, $vr9
	\var	= 9
	.endif
	.ifc	\vr, $vr10
	\var	= 10
	.endif
	.ifc	\vr, $vr11
	\var	= 11
	.endif
	.ifc	\vr, $vr12
	\var	= 12
	.endif
	.ifc	\vr, $vr13
	\var	= 13
	.endif
	.ifc	\vr, $vr14
	\var	= 14
	.endif
	.ifc	\vr, $vr15
	\var	= 15
	.endif
	.ifc	\vr, $vr16
	\var	= 16
	.endif
	.ifc	\vr, $vr17
	\var	= 17
	.endif
	.ifc	\vr, $vr18
	\var	= 18
	.endif
	.ifc	\vr, $vr19
	\var	= 19
	.endif
	.ifc	\vr, $vr20
	\var	= 20
	.endif
	.ifc	\vr, $vr21
	\var	= 21
	.endif
	.ifc	\vr, $vr22
	\var	= 22
	.endif
	.ifc	\vr, $vr23
	\var	= 23
	.endif
	.ifc	\vr, $vr24
	\var	= 24
	.endif
	.ifc	\vr, $vr25
	\var	= 25
	.endif
	.ifc	\vr, $vr26
	\var	= 26
	.endif
	.ifc	\vr, $vr27
	\var	= 27
	.endif
	.ifc	\vr, $vr28
	\var	= 28
	.endif
	.ifc	\vr, $vr29
	\var	= 29
	.endif
	.ifc	\vr, $vr30
	\var	= 30
	.endif
	.ifc	\vr, $vr31
	\var	= 31
	.endif
	.iflt	\var
	.error	"Unable to parse register name \r"
	.endif
	.endm

	.macro	parse_xr var xr
	\var	= -1
	.ifc	\xr, $xr0
	\var	= 0
	.endif
	.ifc	\xr, $xr1
	\var	= 1
	.endif
	.ifc	\xr, $xr2
	\var	= 2
	.endif
	.ifc	\xr, $xr3
	\var	= 3
	.endif
	.ifc	\xr, $xr4
	\var	= 4
	.endif
	.ifc	\xr, $xr5
	\var	= 5
	.endif
	.ifc	\xr, $xr6
	\var	= 6
	.endif
	.ifc	\xr, $xr7
	\var	= 7
	.endif
	.ifc	\xr, $xr8
	\var	= 8
	.endif
	.ifc	\xr, $xr9
	\var	= 9
	.endif
	.ifc	\xr, $xr10
	\var	= 10
	.endif
	.ifc	\xr, $xr11
	\var	= 11
	.endif
	.ifc	\xr, $xr12
	\var	= 12
	.endif
	.ifc	\xr, $xr13
	\var	= 13
	.endif
	.ifc	\xr, $xr14
	\var	= 14
	.endif
	.ifc	\xr, $xr15
	\var	= 15
	.endif
	.ifc	\xr, $xr16
	\var	= 16
	.endif
	.ifc	\xr, $xr17
	\var	= 17
	.endif
	.ifc	\xr, $xr18
	\var	= 18
	.endif
	.ifc	\xr, $xr19
	\var	= 19
	.endif
	.ifc	\xr, $xr20
	\var	= 20
	.endif
	.ifc	\xr, $xr21
	\var	= 21
	.endif
	.ifc	\xr, $xr22
	\var	= 22
	.endif
	.ifc	\xr, $xr23
	\var	= 23
	.endif
	.ifc	\xr, $xr24
	\var	= 24
	.endif
	.ifc	\xr, $xr25
	\var	= 25
	.endif
	.ifc	\xr, $xr26
	\var	= 26
	.endif
	.ifc	\xr, $xr27
	\var	= 27
	.endif
	.ifc	\xr, $xr28
	\var	= 28
	.endif
	.ifc	\xr, $xr29
	\var	= 29
	.endif
	.ifc	\xr, $xr30
	\var	= 30
	.endif
	.ifc	\xr, $xr31
	\var	= 31
	.endif
	.iflt	\var
	.error	"Unable to parse register name \r"
	.endif
	.endm

	.macro	cpu_save_nonscratch thread
	stptr.d	s0, \thread, THREAD_REG23
	stptr.d	s1, \thread, THREAD_REG24
	stptr.d	s2, \thread, THREAD_REG25
	stptr.d	s3, \thread, THREAD_REG26
	stptr.d	s4, \thread, THREAD_REG27
	stptr.d	s5, \thread, THREAD_REG28
	stptr.d	s6, \thread, THREAD_REG29
	stptr.d	s7, \thread, THREAD_REG30
	stptr.d	s8, \thread, THREAD_REG31
	stptr.d	sp, \thread, THREAD_REG03
	stptr.d	fp, \thread, THREAD_REG22
	.endm

	.macro	cpu_restore_nonscratch thread
	ldptr.d	s0, \thread, THREAD_REG23
	ldptr.d	s1, \thread, THREAD_REG24
	ldptr.d	s2, \thread, THREAD_REG25
	ldptr.d	s3, \thread, THREAD_REG26
	ldptr.d	s4, \thread, THREAD_REG27
	ldptr.d	s5, \thread, THREAD_REG28
	ldptr.d	s6, \thread, THREAD_REG29
	ldptr.d	s7, \thread, THREAD_REG30
	ldptr.d	s8, \thread, THREAD_REG31
	ldptr.d	ra, \thread, THREAD_REG01
	ldptr.d	sp, \thread, THREAD_REG03
	ldptr.d	fp, \thread, THREAD_REG22
	.endm

	.macro fpu_save_csr thread tmp
	movfcsr2gr	\tmp, fcsr0
	stptr.w	\tmp, \thread, THREAD_FCSR
	.endm

	.macro fpu_restore_csr thread tmp
	ldptr.w	\tmp, \thread, THREAD_FCSR
	movgr2fcsr	fcsr0, \tmp
	.endm

	.macro fpu_save_cc thread tmp0 tmp1
	movcf2gr	\tmp0, $fcc0
	move	\tmp1, \tmp0
	movcf2gr	\tmp0, $fcc1
	bstrins.d	\tmp1, \tmp0, 15, 8
	movcf2gr	\tmp0, $fcc2
	bstrins.d	\tmp1, \tmp0, 23, 16
	movcf2gr	\tmp0, $fcc3
	bstrins.d	\tmp1, \tmp0, 31, 24
	movcf2gr	\tmp0, $fcc4
	bstrins.d	\tmp1, \tmp0, 39, 32
	movcf2gr	\tmp0, $fcc5
	bstrins.d	\tmp1, \tmp0, 47, 40
	movcf2gr	\tmp0, $fcc6
	bstrins.d	\tmp1, \tmp0, 55, 48
	movcf2gr	\tmp0, $fcc7
	bstrins.d	\tmp1, \tmp0, 63, 56
	stptr.d		\tmp1, \thread, THREAD_FCC
	.endm

	.macro fpu_restore_cc thread tmp0 tmp1
	ldptr.d	\tmp0, \thread, THREAD_FCC
	bstrpick.d	\tmp1, \tmp0, 7, 0
	movgr2cf	$fcc0, \tmp1
	bstrpick.d	\tmp1, \tmp0, 15, 8
	movgr2cf	$fcc1, \tmp1
	bstrpick.d	\tmp1, \tmp0, 23, 16
	movgr2cf	$fcc2, \tmp1
	bstrpick.d	\tmp1, \tmp0, 31, 24
	movgr2cf	$fcc3, \tmp1
	bstrpick.d	\tmp1, \tmp0, 39, 32
	movgr2cf	$fcc4, \tmp1
	bstrpick.d	\tmp1, \tmp0, 47, 40
	movgr2cf	$fcc5, \tmp1
	bstrpick.d	\tmp1, \tmp0, 55, 48
	movgr2cf	$fcc6, \tmp1
	bstrpick.d	\tmp1, \tmp0, 63, 56
	movgr2cf	$fcc7, \tmp1
	.endm

	.macro	fpu_save_double thread tmp
	li.w	\tmp, THREAD_FPR0
	PTR_ADD \tmp, \tmp, \thread
	fst.d	$f0, \tmp, THREAD_FPR0  - THREAD_FPR0
	fst.d	$f1, \tmp, THREAD_FPR1  - THREAD_FPR0
	fst.d	$f2, \tmp, THREAD_FPR2  - THREAD_FPR0
	fst.d	$f3, \tmp, THREAD_FPR3  - THREAD_FPR0
	fst.d	$f4, \tmp, THREAD_FPR4  - THREAD_FPR0
	fst.d	$f5, \tmp, THREAD_FPR5  - THREAD_FPR0
	fst.d	$f6, \tmp, THREAD_FPR6  - THREAD_FPR0
	fst.d	$f7, \tmp, THREAD_FPR7  - THREAD_FPR0
	fst.d	$f8, \tmp, THREAD_FPR8  - THREAD_FPR0
	fst.d	$f9, \tmp, THREAD_FPR9  - THREAD_FPR0
	fst.d	$f10, \tmp, THREAD_FPR10 - THREAD_FPR0
	fst.d	$f11, \tmp, THREAD_FPR11 - THREAD_FPR0
	fst.d	$f12, \tmp, THREAD_FPR12 - THREAD_FPR0
	fst.d	$f13, \tmp, THREAD_FPR13 - THREAD_FPR0
	fst.d	$f14, \tmp, THREAD_FPR14 - THREAD_FPR0
	fst.d	$f15, \tmp, THREAD_FPR15 - THREAD_FPR0
	fst.d	$f16, \tmp, THREAD_FPR16 - THREAD_FPR0
	fst.d	$f17, \tmp, THREAD_FPR17 - THREAD_FPR0
	fst.d	$f18, \tmp, THREAD_FPR18 - THREAD_FPR0
	fst.d	$f19, \tmp, THREAD_FPR19 - THREAD_FPR0
	fst.d	$f20, \tmp, THREAD_FPR20 - THREAD_FPR0
	fst.d	$f21, \tmp, THREAD_FPR21 - THREAD_FPR0
	fst.d	$f22, \tmp, THREAD_FPR22 - THREAD_FPR0
	fst.d	$f23, \tmp, THREAD_FPR23 - THREAD_FPR0
	fst.d	$f24, \tmp, THREAD_FPR24 - THREAD_FPR0
	fst.d	$f25, \tmp, THREAD_FPR25 - THREAD_FPR0
	fst.d	$f26, \tmp, THREAD_FPR26 - THREAD_FPR0
	fst.d	$f27, \tmp, THREAD_FPR27 - THREAD_FPR0
	fst.d	$f28, \tmp, THREAD_FPR28 - THREAD_FPR0
	fst.d	$f29, \tmp, THREAD_FPR29 - THREAD_FPR0
	fst.d	$f30, \tmp, THREAD_FPR30 - THREAD_FPR0
	fst.d	$f31, \tmp, THREAD_FPR31 - THREAD_FPR0
	.endm

	.macro	fpu_restore_double thread tmp
	li.w	\tmp, THREAD_FPR0
	PTR_ADD \tmp, \tmp, \thread
	fld.d	$f0, \tmp, THREAD_FPR0  - THREAD_FPR0
	fld.d	$f1, \tmp, THREAD_FPR1  - THREAD_FPR0
	fld.d	$f2, \tmp, THREAD_FPR2  - THREAD_FPR0
	fld.d	$f3, \tmp, THREAD_FPR3  - THREAD_FPR0
	fld.d	$f4, \tmp, THREAD_FPR4  - THREAD_FPR0
	fld.d	$f5, \tmp, THREAD_FPR5  - THREAD_FPR0
	fld.d	$f6, \tmp, THREAD_FPR6  - THREAD_FPR0
	fld.d	$f7, \tmp, THREAD_FPR7  - THREAD_FPR0
	fld.d	$f8, \tmp, THREAD_FPR8  - THREAD_FPR0
	fld.d	$f9, \tmp, THREAD_FPR9  - THREAD_FPR0
	fld.d	$f10, \tmp, THREAD_FPR10 - THREAD_FPR0
	fld.d	$f11, \tmp, THREAD_FPR11 - THREAD_FPR0
	fld.d	$f12, \tmp, THREAD_FPR12 - THREAD_FPR0
	fld.d	$f13, \tmp, THREAD_FPR13 - THREAD_FPR0
	fld.d	$f14, \tmp, THREAD_FPR14 - THREAD_FPR0
	fld.d	$f15, \tmp, THREAD_FPR15 - THREAD_FPR0
	fld.d	$f16, \tmp, THREAD_FPR16 - THREAD_FPR0
	fld.d	$f17, \tmp, THREAD_FPR17 - THREAD_FPR0
	fld.d	$f18, \tmp, THREAD_FPR18 - THREAD_FPR0
	fld.d	$f19, \tmp, THREAD_FPR19 - THREAD_FPR0
	fld.d	$f20, \tmp, THREAD_FPR20 - THREAD_FPR0
	fld.d	$f21, \tmp, THREAD_FPR21 - THREAD_FPR0
	fld.d	$f22, \tmp, THREAD_FPR22 - THREAD_FPR0
	fld.d	$f23, \tmp, THREAD_FPR23 - THREAD_FPR0
	fld.d	$f24, \tmp, THREAD_FPR24 - THREAD_FPR0
	fld.d	$f25, \tmp, THREAD_FPR25 - THREAD_FPR0
	fld.d	$f26, \tmp, THREAD_FPR26 - THREAD_FPR0
	fld.d	$f27, \tmp, THREAD_FPR27 - THREAD_FPR0
	fld.d	$f28, \tmp, THREAD_FPR28 - THREAD_FPR0
	fld.d	$f29, \tmp, THREAD_FPR29 - THREAD_FPR0
	fld.d	$f30, \tmp, THREAD_FPR30 - THREAD_FPR0
	fld.d	$f31, \tmp, THREAD_FPR31 - THREAD_FPR0
	.endm

	.macro lsx_save_data thread tmp
	parse_r __tmp, \tmp
	li.w		\tmp, THREAD_FPR0
	PTR_ADD 	\tmp, \thread, \tmp
	/* vst opcode is 0xb1 */
	.word (0xb1 << 22 | ((THREAD_FPR0-THREAD_FPR0) << 10) | __tmp << 5 | 0)
	.word (0xb1 << 22 | ((THREAD_FPR1-THREAD_FPR0) << 10) | __tmp << 5 | 1)
	.word (0xb1 << 22 | ((THREAD_FPR2-THREAD_FPR0) << 10) | __tmp << 5 | 2)
	.word (0xb1 << 22 | ((THREAD_FPR3-THREAD_FPR0) << 10) | __tmp << 5 | 3)
	.word (0xb1 << 22 | ((THREAD_FPR4-THREAD_FPR0) << 10) | __tmp << 5 | 4)
	.word (0xb1 << 22 | ((THREAD_FPR5-THREAD_FPR0) << 10) | __tmp << 5 | 5)
	.word (0xb1 << 22 | ((THREAD_FPR6-THREAD_FPR0) << 10) | __tmp << 5 | 6)
	.word (0xb1 << 22 | ((THREAD_FPR7-THREAD_FPR0) << 10) | __tmp << 5 | 7)
	.word (0xb1 << 22 | ((THREAD_FPR8-THREAD_FPR0) << 10) | __tmp << 5 | 8)
	.word (0xb1 << 22 | ((THREAD_FPR9-THREAD_FPR0) << 10) | __tmp << 5 | 9)
	.word (0xb1 << 22 | ((THREAD_FPR10-THREAD_FPR0) << 10) | __tmp << 5 | 10)
	.word (0xb1 << 22 | ((THREAD_FPR11-THREAD_FPR0) << 10) | __tmp << 5 | 11)
	.word (0xb1 << 22 | ((THREAD_FPR12-THREAD_FPR0) << 10) | __tmp << 5 | 12)
	.word (0xb1 << 22 | ((THREAD_FPR13-THREAD_FPR0) << 10) | __tmp << 5 | 13)
	.word (0xb1 << 22 | ((THREAD_FPR14-THREAD_FPR0) << 10) | __tmp << 5 | 14)
	.word (0xb1 << 22 | ((THREAD_FPR15-THREAD_FPR0) << 10) | __tmp << 5 | 15)
	.word (0xb1 << 22 | ((THREAD_FPR16-THREAD_FPR0) << 10) | __tmp << 5 | 16)
	.word (0xb1 << 22 | ((THREAD_FPR17-THREAD_FPR0) << 10) | __tmp << 5 | 17)
	.word (0xb1 << 22 | ((THREAD_FPR18-THREAD_FPR0) << 10) | __tmp << 5 | 18)
	.word (0xb1 << 22 | ((THREAD_FPR19-THREAD_FPR0) << 10) | __tmp << 5 | 19)
	.word (0xb1 << 22 | ((THREAD_FPR20-THREAD_FPR0) << 10) | __tmp << 5 | 20)
	.word (0xb1 << 22 | ((THREAD_FPR21-THREAD_FPR0) << 10) | __tmp << 5 | 21)
	.word (0xb1 << 22 | ((THREAD_FPR22-THREAD_FPR0) << 10) | __tmp << 5 | 22)
	.word (0xb1 << 22 | ((THREAD_FPR23-THREAD_FPR0) << 10) | __tmp << 5 | 23)
	.word (0xb1 << 22 | ((THREAD_FPR24-THREAD_FPR0) << 10) | __tmp << 5 | 24)
	.word (0xb1 << 22 | ((THREAD_FPR25-THREAD_FPR0) << 10) | __tmp << 5 | 25)
	.word (0xb1 << 22 | ((THREAD_FPR26-THREAD_FPR0) << 10) | __tmp << 5 | 26)
	.word (0xb1 << 22 | ((THREAD_FPR27-THREAD_FPR0) << 10) | __tmp << 5 | 27)
	.word (0xb1 << 22 | ((THREAD_FPR28-THREAD_FPR0) << 10) | __tmp << 5 | 28)
	.word (0xb1 << 22 | ((THREAD_FPR29-THREAD_FPR0) << 10) | __tmp << 5 | 29)
	.word (0xb1 << 22 | ((THREAD_FPR30-THREAD_FPR0) << 10) | __tmp << 5 | 30)
	.word (0xb1 << 22 | ((THREAD_FPR31-THREAD_FPR0) << 10) | __tmp << 5 | 31)
	.endm

	.macro lsx_restore_data thread tmp
	parse_r __tmp, \tmp
	li.w		\tmp, THREAD_FPR0
	PTR_ADD		\tmp, \thread, \tmp
	/* vld opcode is 0xb0 */
	.word (0xb0 << 22 | ((THREAD_FPR0-THREAD_FPR0) << 10) | __tmp << 5 | 0)
	.word (0xb0 << 22 | ((THREAD_FPR1-THREAD_FPR0) << 10) | __tmp << 5 | 1)
	.word (0xb0 << 22 | ((THREAD_FPR2-THREAD_FPR0) << 10) | __tmp << 5 | 2)
	.word (0xb0 << 22 | ((THREAD_FPR3-THREAD_FPR0) << 10) | __tmp << 5 | 3)
	.word (0xb0 << 22 | ((THREAD_FPR4-THREAD_FPR0) << 10) | __tmp << 5 | 4)
	.word (0xb0 << 22 | ((THREAD_FPR5-THREAD_FPR0) << 10) | __tmp << 5 | 5)
	.word (0xb0 << 22 | ((THREAD_FPR6-THREAD_FPR0) << 10) | __tmp << 5 | 6)
	.word (0xb0 << 22 | ((THREAD_FPR7-THREAD_FPR0) << 10) | __tmp << 5 | 7)
	.word (0xb0 << 22 | ((THREAD_FPR8-THREAD_FPR0) << 10) | __tmp << 5 | 8)
	.word (0xb0 << 22 | ((THREAD_FPR9-THREAD_FPR0) << 10) | __tmp << 5 | 9)
	.word (0xb0 << 22 | ((THREAD_FPR10-THREAD_FPR0) << 10) | __tmp << 5 | 10)
	.word (0xb0 << 22 | ((THREAD_FPR11-THREAD_FPR0) << 10) | __tmp << 5 | 11)
	.word (0xb0 << 22 | ((THREAD_FPR12-THREAD_FPR0) << 10) | __tmp << 5 | 12)
	.word (0xb0 << 22 | ((THREAD_FPR13-THREAD_FPR0) << 10) | __tmp << 5 | 13)
	.word (0xb0 << 22 | ((THREAD_FPR14-THREAD_FPR0) << 10) | __tmp << 5 | 14)
	.word (0xb0 << 22 | ((THREAD_FPR15-THREAD_FPR0) << 10) | __tmp << 5 | 15)
	.word (0xb0 << 22 | ((THREAD_FPR16-THREAD_FPR0) << 10) | __tmp << 5 | 16)
	.word (0xb0 << 22 | ((THREAD_FPR17-THREAD_FPR0) << 10) | __tmp << 5 | 17)
	.word (0xb0 << 22 | ((THREAD_FPR18-THREAD_FPR0) << 10) | __tmp << 5 | 18)
	.word (0xb0 << 22 | ((THREAD_FPR19-THREAD_FPR0) << 10) | __tmp << 5 | 19)
	.word (0xb0 << 22 | ((THREAD_FPR20-THREAD_FPR0) << 10) | __tmp << 5 | 20)
	.word (0xb0 << 22 | ((THREAD_FPR21-THREAD_FPR0) << 10) | __tmp << 5 | 21)
	.word (0xb0 << 22 | ((THREAD_FPR22-THREAD_FPR0) << 10) | __tmp << 5 | 22)
	.word (0xb0 << 22 | ((THREAD_FPR23-THREAD_FPR0) << 10) | __tmp << 5 | 23)
	.word (0xb0 << 22 | ((THREAD_FPR24-THREAD_FPR0) << 10) | __tmp << 5 | 24)
	.word (0xb0 << 22 | ((THREAD_FPR25-THREAD_FPR0) << 10) | __tmp << 5 | 25)
	.word (0xb0 << 22 | ((THREAD_FPR26-THREAD_FPR0) << 10) | __tmp << 5 | 26)
	.word (0xb0 << 22 | ((THREAD_FPR27-THREAD_FPR0) << 10) | __tmp << 5 | 27)
	.word (0xb0 << 22 | ((THREAD_FPR28-THREAD_FPR0) << 10) | __tmp << 5 | 28)
	.word (0xb0 << 22 | ((THREAD_FPR29-THREAD_FPR0) << 10) | __tmp << 5 | 29)
	.word (0xb0 << 22 | ((THREAD_FPR30-THREAD_FPR0) << 10) | __tmp << 5 | 30)
	.word (0xb0 << 22 | ((THREAD_FPR31-THREAD_FPR0) << 10) | __tmp << 5 | 31)
	.endm

	.macro	lsx_save_all	thread tmp0 tmp1
	fpu_save_cc	\thread, \tmp0, \tmp1
	fpu_save_csr	\thread, \tmp0
	lsx_save_data	\thread, \tmp0
	.endm

	.macro	lsx_restore_all	thread tmp0 tmp1
	lsx_restore_data	\thread, \tmp0
	fpu_restore_cc	\thread, \tmp0, \tmp1
	fpu_restore_csr	\thread, \tmp0
	.endm

	.macro lsx_save_upper vd base tmp off
	parse_vr __vd, \vd
	parse_r __tmp, \tmp
	/* vpickve2gr opcode is 0xe5dfe */
	.word (0xe5dfe << 11 | 1 << 10 | __vd << 5 | __tmp)
	st.d	\tmp, \base, (\off+8)
	.endm

	.macro lsx_save_all_upper thread base tmp
	li.w	\tmp, THREAD_FPR0
	PTR_ADD	\base, \thread, \tmp
	lsx_save_upper $vr0,  \base, \tmp, (THREAD_FPR0-THREAD_FPR0)
	lsx_save_upper $vr1,  \base, \tmp, (THREAD_FPR1-THREAD_FPR0)
	lsx_save_upper $vr2,  \base, \tmp, (THREAD_FPR2-THREAD_FPR0)
	lsx_save_upper $vr3,  \base, \tmp, (THREAD_FPR3-THREAD_FPR0)
	lsx_save_upper $vr4,  \base, \tmp, (THREAD_FPR4-THREAD_FPR0)
	lsx_save_upper $vr5,  \base, \tmp, (THREAD_FPR5-THREAD_FPR0)
	lsx_save_upper $vr6,  \base, \tmp, (THREAD_FPR6-THREAD_FPR0)
	lsx_save_upper $vr7,  \base, \tmp, (THREAD_FPR7-THREAD_FPR0)
	lsx_save_upper $vr8,  \base, \tmp, (THREAD_FPR8-THREAD_FPR0)
	lsx_save_upper $vr9,  \base, \tmp, (THREAD_FPR9-THREAD_FPR0)
	lsx_save_upper $vr10, \base, \tmp, (THREAD_FPR10-THREAD_FPR0)
	lsx_save_upper $vr11, \base, \tmp, (THREAD_FPR11-THREAD_FPR0)
	lsx_save_upper $vr12, \base, \tmp, (THREAD_FPR12-THREAD_FPR0)
	lsx_save_upper $vr13, \base, \tmp, (THREAD_FPR13-THREAD_FPR0)
	lsx_save_upper $vr14, \base, \tmp, (THREAD_FPR14-THREAD_FPR0)
	lsx_save_upper $vr15, \base, \tmp, (THREAD_FPR15-THREAD_FPR0)
	lsx_save_upper $vr16, \base, \tmp, (THREAD_FPR16-THREAD_FPR0)
	lsx_save_upper $vr17, \base, \tmp, (THREAD_FPR17-THREAD_FPR0)
	lsx_save_upper $vr18, \base, \tmp, (THREAD_FPR18-THREAD_FPR0)
	lsx_save_upper $vr19, \base, \tmp, (THREAD_FPR19-THREAD_FPR0)
	lsx_save_upper $vr20, \base, \tmp, (THREAD_FPR20-THREAD_FPR0)
	lsx_save_upper $vr21, \base, \tmp, (THREAD_FPR21-THREAD_FPR0)
	lsx_save_upper $vr22, \base, \tmp, (THREAD_FPR22-THREAD_FPR0)
	lsx_save_upper $vr23, \base, \tmp, (THREAD_FPR23-THREAD_FPR0)
	lsx_save_upper $vr24, \base, \tmp, (THREAD_FPR24-THREAD_FPR0)
	lsx_save_upper $vr25, \base, \tmp, (THREAD_FPR25-THREAD_FPR0)
	lsx_save_upper $vr26, \base, \tmp, (THREAD_FPR26-THREAD_FPR0)
	lsx_save_upper $vr27, \base, \tmp, (THREAD_FPR27-THREAD_FPR0)
	lsx_save_upper $vr28, \base, \tmp, (THREAD_FPR28-THREAD_FPR0)
	lsx_save_upper $vr29, \base, \tmp, (THREAD_FPR29-THREAD_FPR0)
	lsx_save_upper $vr30, \base, \tmp, (THREAD_FPR30-THREAD_FPR0)
	lsx_save_upper $vr31, \base, \tmp, (THREAD_FPR31-THREAD_FPR0)
	.endm

	.macro lsx_restore_upper vd base tmp off
	parse_vr __vd, \vd
	parse_r __tmp, \tmp
	ld.d	\tmp, \base, (\off+8)
	/* vinsgr2vr opcode is 0xe5d7e */
	.word	(0xe5d7e << 11 | 1 << 10 | __tmp << 5 | __vd)
	.endm

	.macro lsx_restore_all_upper thread base tmp
	li.w	\tmp, THREAD_FPR0
	PTR_ADD	\base, \thread, \tmp
	lsx_restore_upper $vr0,  \base, \tmp, (THREAD_FPR0-THREAD_FPR0)
	lsx_restore_upper $vr1,  \base, \tmp, (THREAD_FPR1-THREAD_FPR0)
	lsx_restore_upper $vr2,  \base, \tmp, (THREAD_FPR2-THREAD_FPR0)
	lsx_restore_upper $vr3,  \base, \tmp, (THREAD_FPR3-THREAD_FPR0)
	lsx_restore_upper $vr4,  \base, \tmp, (THREAD_FPR4-THREAD_FPR0)
	lsx_restore_upper $vr5,  \base, \tmp, (THREAD_FPR5-THREAD_FPR0)
	lsx_restore_upper $vr6,  \base, \tmp, (THREAD_FPR6-THREAD_FPR0)
	lsx_restore_upper $vr7,  \base, \tmp, (THREAD_FPR7-THREAD_FPR0)
	lsx_restore_upper $vr8,  \base, \tmp, (THREAD_FPR8-THREAD_FPR0)
	lsx_restore_upper $vr9,  \base, \tmp, (THREAD_FPR9-THREAD_FPR0)
	lsx_restore_upper $vr10, \base, \tmp, (THREAD_FPR10-THREAD_FPR0)
	lsx_restore_upper $vr11, \base, \tmp, (THREAD_FPR11-THREAD_FPR0)
	lsx_restore_upper $vr12, \base, \tmp, (THREAD_FPR12-THREAD_FPR0)
	lsx_restore_upper $vr13, \base, \tmp, (THREAD_FPR13-THREAD_FPR0)
	lsx_restore_upper $vr14, \base, \tmp, (THREAD_FPR14-THREAD_FPR0)
	lsx_restore_upper $vr15, \base, \tmp, (THREAD_FPR15-THREAD_FPR0)
	lsx_restore_upper $vr16, \base, \tmp, (THREAD_FPR16-THREAD_FPR0)
	lsx_restore_upper $vr17, \base, \tmp, (THREAD_FPR17-THREAD_FPR0)
	lsx_restore_upper $vr18, \base, \tmp, (THREAD_FPR18-THREAD_FPR0)
	lsx_restore_upper $vr19, \base, \tmp, (THREAD_FPR19-THREAD_FPR0)
	lsx_restore_upper $vr20, \base, \tmp, (THREAD_FPR20-THREAD_FPR0)
	lsx_restore_upper $vr21, \base, \tmp, (THREAD_FPR21-THREAD_FPR0)
	lsx_restore_upper $vr22, \base, \tmp, (THREAD_FPR22-THREAD_FPR0)
	lsx_restore_upper $vr23, \base, \tmp, (THREAD_FPR23-THREAD_FPR0)
	lsx_restore_upper $vr24, \base, \tmp, (THREAD_FPR24-THREAD_FPR0)
	lsx_restore_upper $vr25, \base, \tmp, (THREAD_FPR25-THREAD_FPR0)
	lsx_restore_upper $vr26, \base, \tmp, (THREAD_FPR26-THREAD_FPR0)
	lsx_restore_upper $vr27, \base, \tmp, (THREAD_FPR27-THREAD_FPR0)
	lsx_restore_upper $vr28, \base, \tmp, (THREAD_FPR28-THREAD_FPR0)
	lsx_restore_upper $vr29, \base, \tmp, (THREAD_FPR29-THREAD_FPR0)
	lsx_restore_upper $vr30, \base, \tmp, (THREAD_FPR30-THREAD_FPR0)
	lsx_restore_upper $vr31, \base, \tmp, (THREAD_FPR31-THREAD_FPR0)
	.endm

	.macro	lsx_init_upper vd tmp
	parse_vr __vd, \vd
	parse_r __tmp, \tmp
	/* vinsgr2vr opcode is 0xe5d7e */
	.word	(0xe5d7e << 11 | 1 << 10 | __tmp << 5 | __vd)
	.endm

	.macro	lsx_init_all_upper tmp
	not	\tmp, zero
	lsx_init_upper	$vr0 \tmp
	lsx_init_upper	$vr1 \tmp
	lsx_init_upper	$vr2 \tmp
	lsx_init_upper	$vr3 \tmp
	lsx_init_upper	$vr4 \tmp
	lsx_init_upper	$vr5 \tmp
	lsx_init_upper	$vr6 \tmp
	lsx_init_upper	$vr7 \tmp
	lsx_init_upper	$vr8 \tmp
	lsx_init_upper	$vr9 \tmp
	lsx_init_upper	$vr10 \tmp
	lsx_init_upper	$vr11 \tmp
	lsx_init_upper	$vr12 \tmp
	lsx_init_upper	$vr13 \tmp
	lsx_init_upper	$vr14 \tmp
	lsx_init_upper	$vr15 \tmp
	lsx_init_upper	$vr16 \tmp
	lsx_init_upper	$vr17 \tmp
	lsx_init_upper	$vr18 \tmp
	lsx_init_upper	$vr19 \tmp
	lsx_init_upper	$vr20 \tmp
	lsx_init_upper	$vr21 \tmp
	lsx_init_upper	$vr22 \tmp
	lsx_init_upper	$vr23 \tmp
	lsx_init_upper	$vr24 \tmp
	lsx_init_upper	$vr25 \tmp
	lsx_init_upper	$vr26 \tmp
	lsx_init_upper	$vr27 \tmp
	lsx_init_upper	$vr28 \tmp
	lsx_init_upper	$vr29 \tmp
	lsx_init_upper	$vr30 \tmp
	lsx_init_upper	$vr31 \tmp
	.endm

	.macro lasx_save_data thread tmp
	parse_r __tmp, \tmp
	li.w            \tmp, THREAD_FPR0
	PTR_ADD         \tmp, \thread, \tmp
	/* xvst opcode is 0xb3 */
	.word (0xb3 << 22 | ((THREAD_FPR0-THREAD_FPR0) << 10) | __tmp << 5 | 0)
	.word (0xb3 << 22 | ((THREAD_FPR1-THREAD_FPR0) << 10) | __tmp << 5 | 1)
	.word (0xb3 << 22 | ((THREAD_FPR2-THREAD_FPR0) << 10) | __tmp << 5 | 2)
	.word (0xb3 << 22 | ((THREAD_FPR3-THREAD_FPR0) << 10) | __tmp << 5 | 3)
	.word (0xb3 << 22 | ((THREAD_FPR4-THREAD_FPR0) << 10) | __tmp << 5 | 4)
	.word (0xb3 << 22 | ((THREAD_FPR5-THREAD_FPR0) << 10) | __tmp << 5 | 5)
	.word (0xb3 << 22 | ((THREAD_FPR6-THREAD_FPR0) << 10) | __tmp << 5 | 6)
	.word (0xb3 << 22 | ((THREAD_FPR7-THREAD_FPR0) << 10) | __tmp << 5 | 7)
	.word (0xb3 << 22 | ((THREAD_FPR8-THREAD_FPR0) << 10) | __tmp << 5 | 8)
	.word (0xb3 << 22 | ((THREAD_FPR9-THREAD_FPR0) << 10) | __tmp << 5 | 9)
	.word (0xb3 << 22 | ((THREAD_FPR10-THREAD_FPR0) << 10) | __tmp << 5 | 10)
	.word (0xb3 << 22 | ((THREAD_FPR11-THREAD_FPR0) << 10) | __tmp << 5 | 11)
	.word (0xb3 << 22 | ((THREAD_FPR12-THREAD_FPR0) << 10) | __tmp << 5 | 12)
	.word (0xb3 << 22 | ((THREAD_FPR13-THREAD_FPR0) << 10) | __tmp << 5 | 13)
	.word (0xb3 << 22 | ((THREAD_FPR14-THREAD_FPR0) << 10) | __tmp << 5 | 14)
	.word (0xb3 << 22 | ((THREAD_FPR15-THREAD_FPR0) << 10) | __tmp << 5 | 15)
	.word (0xb3 << 22 | ((THREAD_FPR16-THREAD_FPR0) << 10) | __tmp << 5 | 16)
	.word (0xb3 << 22 | ((THREAD_FPR17-THREAD_FPR0) << 10) | __tmp << 5 | 17)
	.word (0xb3 << 22 | ((THREAD_FPR18-THREAD_FPR0) << 10) | __tmp << 5 | 18)
	.word (0xb3 << 22 | ((THREAD_FPR19-THREAD_FPR0) << 10) | __tmp << 5 | 19)
	.word (0xb3 << 22 | ((THREAD_FPR20-THREAD_FPR0) << 10) | __tmp << 5 | 20)
	.word (0xb3 << 22 | ((THREAD_FPR21-THREAD_FPR0) << 10) | __tmp << 5 | 21)
	.word (0xb3 << 22 | ((THREAD_FPR22-THREAD_FPR0) << 10) | __tmp << 5 | 22)
	.word (0xb3 << 22 | ((THREAD_FPR23-THREAD_FPR0) << 10) | __tmp << 5 | 23)
	.word (0xb3 << 22 | ((THREAD_FPR24-THREAD_FPR0) << 10) | __tmp << 5 | 24)
	.word (0xb3 << 22 | ((THREAD_FPR25-THREAD_FPR0) << 10) | __tmp << 5 | 25)
	.word (0xb3 << 22 | ((THREAD_FPR26-THREAD_FPR0) << 10) | __tmp << 5 | 26)
	.word (0xb3 << 22 | ((THREAD_FPR27-THREAD_FPR0) << 10) | __tmp << 5 | 27)
	.word (0xb3 << 22 | ((THREAD_FPR28-THREAD_FPR0) << 10) | __tmp << 5 | 28)
	.word (0xb3 << 22 | ((THREAD_FPR29-THREAD_FPR0) << 10) | __tmp << 5 | 29)
	.word (0xb3 << 22 | ((THREAD_FPR30-THREAD_FPR0) << 10) | __tmp << 5 | 30)
	.word (0xb3 << 22 | ((THREAD_FPR31-THREAD_FPR0) << 10) | __tmp << 5 | 31)
	.endm

	.macro lasx_restore_data thread tmp
	parse_r __tmp, \tmp
	li.w            \tmp, THREAD_FPR0
	PTR_ADD         \tmp, \thread, \tmp
	/* xvld opcode is 0xb2 */
	.word (0xb2 << 22 | ((THREAD_FPR0-THREAD_FPR0) << 10) | __tmp << 5 | 0)
	.word (0xb2 << 22 | ((THREAD_FPR1-THREAD_FPR0) << 10) | __tmp << 5 | 1)
	.word (0xb2 << 22 | ((THREAD_FPR2-THREAD_FPR0) << 10) | __tmp << 5 | 2)
	.word (0xb2 << 22 | ((THREAD_FPR3-THREAD_FPR0) << 10) | __tmp << 5 | 3)
	.word (0xb2 << 22 | ((THREAD_FPR4-THREAD_FPR0) << 10) | __tmp << 5 | 4)
	.word (0xb2 << 22 | ((THREAD_FPR5-THREAD_FPR0) << 10) | __tmp << 5 | 5)
	.word (0xb2 << 22 | ((THREAD_FPR6-THREAD_FPR0) << 10) | __tmp << 5 | 6)
	.word (0xb2 << 22 | ((THREAD_FPR7-THREAD_FPR0) << 10) | __tmp << 5 | 7)
	.word (0xb2 << 22 | ((THREAD_FPR8-THREAD_FPR0) << 10) | __tmp << 5 | 8)
	.word (0xb2 << 22 | ((THREAD_FPR9-THREAD_FPR0) << 10) | __tmp << 5 | 9)
	.word (0xb2 << 22 | ((THREAD_FPR10-THREAD_FPR0) << 10) | __tmp << 5 | 10)
	.word (0xb2 << 22 | ((THREAD_FPR11-THREAD_FPR0) << 10) | __tmp << 5 | 11)
	.word (0xb2 << 22 | ((THREAD_FPR12-THREAD_FPR0) << 10) | __tmp << 5 | 12)
	.word (0xb2 << 22 | ((THREAD_FPR13-THREAD_FPR0) << 10) | __tmp << 5 | 13)
	.word (0xb2 << 22 | ((THREAD_FPR14-THREAD_FPR0) << 10) | __tmp << 5 | 14)
	.word (0xb2 << 22 | ((THREAD_FPR15-THREAD_FPR0) << 10) | __tmp << 5 | 15)
	.word (0xb2 << 22 | ((THREAD_FPR16-THREAD_FPR0) << 10) | __tmp << 5 | 16)
	.word (0xb2 << 22 | ((THREAD_FPR17-THREAD_FPR0) << 10) | __tmp << 5 | 17)
	.word (0xb2 << 22 | ((THREAD_FPR18-THREAD_FPR0) << 10) | __tmp << 5 | 18)
	.word (0xb2 << 22 | ((THREAD_FPR19-THREAD_FPR0) << 10) | __tmp << 5 | 19)
	.word (0xb2 << 22 | ((THREAD_FPR20-THREAD_FPR0) << 10) | __tmp << 5 | 20)
	.word (0xb2 << 22 | ((THREAD_FPR21-THREAD_FPR0) << 10) | __tmp << 5 | 21)
	.word (0xb2 << 22 | ((THREAD_FPR22-THREAD_FPR0) << 10) | __tmp << 5 | 22)
	.word (0xb2 << 22 | ((THREAD_FPR23-THREAD_FPR0) << 10) | __tmp << 5 | 23)
	.word (0xb2 << 22 | ((THREAD_FPR24-THREAD_FPR0) << 10) | __tmp << 5 | 24)
	.word (0xb2 << 22 | ((THREAD_FPR25-THREAD_FPR0) << 10) | __tmp << 5 | 25)
	.word (0xb2 << 22 | ((THREAD_FPR26-THREAD_FPR0) << 10) | __tmp << 5 | 26)
	.word (0xb2 << 22 | ((THREAD_FPR27-THREAD_FPR0) << 10) | __tmp << 5 | 27)
	.word (0xb2 << 22 | ((THREAD_FPR28-THREAD_FPR0) << 10) | __tmp << 5 | 28)
	.word (0xb2 << 22 | ((THREAD_FPR29-THREAD_FPR0) << 10) | __tmp << 5 | 29)
	.word (0xb2 << 22 | ((THREAD_FPR30-THREAD_FPR0) << 10) | __tmp << 5 | 30)
	.word (0xb2 << 22 | ((THREAD_FPR31-THREAD_FPR0) << 10) | __tmp << 5 | 31)
	.endm

	.macro	lasx_save_all	thread tmp0 tmp1
	fpu_save_cc	\thread, \tmp0, \tmp1
	fpu_save_csr	\thread, \tmp0
	lasx_save_data	\thread, \tmp0
	.endm

	.macro	lasx_restore_all thread tmp0 tmp1
	lasx_restore_data	\thread, \tmp0
	fpu_restore_cc	\thread, \tmp0, \tmp1
	fpu_restore_csr	\thread, \tmp0
	.endm

	.macro lasx_save_upper xd base tmp off
	/* Nothing */
	.endm

	.macro lasx_save_all_upper thread base tmp
	/* Nothing */
	.endm

	.macro lasx_restore_upper xd base tmp off
	parse_xr __xd, \xd
	parse_xr __xt, \tmp
	parse_r __base, \base
	/* vld opcode is 0xb0 */
	.word (0xb0 << 22 | (\off+16) << 10 | __base << 5 | __xt)
	/* xvpermi.q opcode is 0x1dfb */
	.word (0x1dfb << 18 | 0x2 << 10 | __xt << 5 | __xd)
	.endm

	.macro lasx_restore_all_upper thread base tmp
	li.w	\tmp, THREAD_FPR0
	PTR_ADD	\base, \thread, \tmp
	/* Save $vr31, xvpickve2gr opcode is 0x76efe */
	.word (0x76efe << 12 | 0 << 10 | 31 << 5 | 0x11)
	.word (0x76efe << 12 | 1 << 10 | 31 << 5 | 0x12)
	lasx_restore_upper $xr0, \base, $xr31, (THREAD_FPR0-THREAD_FPR0)
	lasx_restore_upper $xr1, \base, $xr31, (THREAD_FPR1-THREAD_FPR0)
	lasx_restore_upper $xr2, \base, $xr31, (THREAD_FPR2-THREAD_FPR0)
	lasx_restore_upper $xr3, \base, $xr31, (THREAD_FPR3-THREAD_FPR0)
	lasx_restore_upper $xr4, \base, $xr31, (THREAD_FPR4-THREAD_FPR0)
	lasx_restore_upper $xr5, \base, $xr31, (THREAD_FPR5-THREAD_FPR0)
	lasx_restore_upper $xr6, \base, $xr31, (THREAD_FPR6-THREAD_FPR0)
	lasx_restore_upper $xr7, \base, $xr31, (THREAD_FPR7-THREAD_FPR0)
	lasx_restore_upper $xr8, \base, $xr31, (THREAD_FPR8-THREAD_FPR0)
	lasx_restore_upper $xr9, \base, $xr31, (THREAD_FPR9-THREAD_FPR0)
	lasx_restore_upper $xr10, \base, $xr31, (THREAD_FPR10-THREAD_FPR0)
	lasx_restore_upper $xr11, \base, $xr31, (THREAD_FPR11-THREAD_FPR0)
	lasx_restore_upper $xr12, \base, $xr31, (THREAD_FPR12-THREAD_FPR0)
	lasx_restore_upper $xr13, \base, $xr31, (THREAD_FPR13-THREAD_FPR0)
	lasx_restore_upper $xr14, \base, $xr31, (THREAD_FPR14-THREAD_FPR0)
	lasx_restore_upper $xr15, \base, $xr31, (THREAD_FPR15-THREAD_FPR0)
	lasx_restore_upper $xr16, \base, $xr31, (THREAD_FPR16-THREAD_FPR0)
	lasx_restore_upper $xr17, \base, $xr31, (THREAD_FPR17-THREAD_FPR0)
	lasx_restore_upper $xr18, \base, $xr31, (THREAD_FPR18-THREAD_FPR0)
	lasx_restore_upper $xr19, \base, $xr31, (THREAD_FPR19-THREAD_FPR0)
	lasx_restore_upper $xr20, \base, $xr31, (THREAD_FPR20-THREAD_FPR0)
	lasx_restore_upper $xr21, \base, $xr31, (THREAD_FPR21-THREAD_FPR0)
	lasx_restore_upper $xr22, \base, $xr31, (THREAD_FPR22-THREAD_FPR0)
	lasx_restore_upper $xr23, \base, $xr31, (THREAD_FPR23-THREAD_FPR0)
	lasx_restore_upper $xr24, \base, $xr31, (THREAD_FPR24-THREAD_FPR0)
	lasx_restore_upper $xr25, \base, $xr31, (THREAD_FPR25-THREAD_FPR0)
	lasx_restore_upper $xr26, \base, $xr31, (THREAD_FPR26-THREAD_FPR0)
	lasx_restore_upper $xr27, \base, $xr31, (THREAD_FPR27-THREAD_FPR0)
	lasx_restore_upper $xr28, \base, $xr31, (THREAD_FPR28-THREAD_FPR0)
	lasx_restore_upper $xr29, \base, $xr31, (THREAD_FPR29-THREAD_FPR0)
	lasx_restore_upper $xr30, \base, $xr31, (THREAD_FPR30-THREAD_FPR0)
	lasx_restore_upper $xr31, \base, $xr31, (THREAD_FPR31-THREAD_FPR0)
	/* Restore $vr31, xvinsgr2vr opcode is 0x76ebe */
	.word (0x76ebe << 12 | 0 << 10 | 0x11 << 5 | 31)
	.word (0x76ebe << 12 | 1 << 10 | 0x12 << 5 | 31)
	.endm

	.macro	lasx_init_upper xd tmp
	parse_xr __xd, \xd
	parse_r __tmp, \tmp
	/* xvinsgr2vr opcode is 0x76ebe */
	.word	(0x76ebe << 12 | 2 << 10 | __tmp << 5 | __xd)
	.word	(0x76ebe << 12 | 3 << 10 | __tmp << 5 | __xd)
	.endm

	.macro	lasx_init_all_upper tmp
	not	\tmp, zero
	lasx_init_upper	$xr0 \tmp
	lasx_init_upper	$xr1 \tmp
	lasx_init_upper	$xr2 \tmp
	lasx_init_upper	$xr3 \tmp
	lasx_init_upper	$xr4 \tmp
	lasx_init_upper	$xr5 \tmp
	lasx_init_upper	$xr6 \tmp
	lasx_init_upper	$xr7 \tmp
	lasx_init_upper	$xr8 \tmp
	lasx_init_upper	$xr9 \tmp
	lasx_init_upper	$xr10 \tmp
	lasx_init_upper	$xr11 \tmp
	lasx_init_upper	$xr12 \tmp
	lasx_init_upper	$xr13 \tmp
	lasx_init_upper	$xr14 \tmp
	lasx_init_upper	$xr15 \tmp
	lasx_init_upper	$xr16 \tmp
	lasx_init_upper	$xr17 \tmp
	lasx_init_upper	$xr18 \tmp
	lasx_init_upper	$xr19 \tmp
	lasx_init_upper	$xr20 \tmp
	lasx_init_upper	$xr21 \tmp
	lasx_init_upper	$xr22 \tmp
	lasx_init_upper	$xr23 \tmp
	lasx_init_upper	$xr24 \tmp
	lasx_init_upper	$xr25 \tmp
	lasx_init_upper	$xr26 \tmp
	lasx_init_upper	$xr27 \tmp
	lasx_init_upper	$xr28 \tmp
	lasx_init_upper	$xr29 \tmp
	lasx_init_upper	$xr30 \tmp
	lasx_init_upper	$xr31 \tmp
	.endm

.macro not dst src
	nor	\dst, \src, zero
.endm

#endif /* _ASM_ASMMACRO_H */
