/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

.global crc_t10dif_neon
.text

/* X0 is initial CRC value
 * X1 is data buffer
 * X2 is the length of buffer
 * X3 is the backup buffer(for extend)
 * X4 for other extend parameter(for extend)
 * Q0, Q1, Q2, Q3 maybe as parameter for other functions,
 * the value of Q0, Q1, Q2, Q3 maybe modified.
 *
 * suggestion:
 * 1. dont use general purpose register for calculation
 * 2. set data endianness outside of the kernel
 * 3. use ext as shifting around
 * 4. dont use LD3/LD4, ST3/ST4
 */

crc_t10dif_neon:
	/* push the register to stack that CRC16 will use */
	STP		X5, X6, [sp, #-0x10]!
	STP		X7, X8, [sp, #-0x10]!
	STP		X9, X10, [sp, #-0x10]!
	STP		X11, X12, [sp, #-0x10]!
	STP		X13, X14, [sp, #-0x10]!
	STP		Q10, Q11, [sp, #-0x20]!
	STP		Q12, Q13, [sp, #-0x20]!
	STP		Q4, Q5, [sp, #-0x20]!
	STP		Q6, Q7, [sp, #-0x20]!
	STP		Q8, Q9, [sp, #-0x20]!
	STP		Q14, Q15, [sp, #-0x20]!
	STP		Q16, Q17, [sp, #-0x20]!
	STP		Q18, Q19, [sp, #-0x20]!

	SUB		sp,sp,#0x20

	MOV		X11, #0		// PUSH STACK FLAG

	CMP		X2, #0x80
	B.LT		2f		// _less_than_128, <128

	/* V10/V11/V12/V13	is 128bit.
	 * we get data 512bit( by cacheline ) each time
	 */
	LDP		Q10, Q11, [X1], #0x20
	LDP		Q12, Q13, [X1], #0x20

	/* move the initial value to V6 register */
	LSL		X0, X0, #48
	EOR		V6.16B, V6.16B, V6.16B
	MOV		V6.D[1], X0

	/* big-little end change. because the data in memory is little-end,
	 * we deal the data for bigend
	 */

	REV64		V10.16B, V10.16B
	REV64		V11.16B, V11.16B
	REV64		V12.16B, V12.16B
	REV64		V13.16B, V13.16B
	EXT     	V10.16B, V10.16B, V10.16B, #8
	EXT     	V11.16B, V11.16B, V11.16B, #8
	EXT     	V12.16B, V12.16B, V12.16B, #8
	EXT     	V13.16B, V13.16B, V13.16B, #8

	EOR		V10.16B, V10.16B, V6.16B

	SUB		X2, X2, #0x80
	ADD     	X5, X1, #0x20

	/* deal data when the size of buffer bigger than 128 bytes */
	/* _fold_64_B_loop */
	LDR		Q6, .Ldata1
1:

	LDP		Q16, Q17, [X1] ,#0x40
	LDP		Q18, Q19, [X5], #0x40

	/* carry-less multiply.
	 * V10 high-64bits carry-less multiply
	 * V6 high-64bits(PMULL2)
	 * V11 low-64bits carry-less multiply V6 low-64bits(PMULL)
	 */

	PMULL2		V4.1Q, V10.2D, V6.2D
	PMULL		V10.1Q, V10.1D, V6.1D
	PMULL2		V5.1Q, V11.2D, V6.2D
	PMULL		V11.1Q, V11.1D, V6.1D

	REV64		V16.16B, V16.16B
	REV64		V17.16B, V17.16B
	REV64		V18.16B, V18.16B
	REV64		V19.16B, V19.16B

	PMULL2		V14.1Q, V12.2D, V6.2D
	PMULL		V12.1Q, V12.1D, V6.1D
	PMULL2		V15.1Q, V13.2D, V6.2D
	PMULL		V13.1Q, V13.1D, V6.1D

	EXT     	V16.16B, V16.16B, V16.16B, #8
	EOR		V10.16B, V10.16B, V4.16B

	EXT     	V17.16B, V17.16B, V17.16B, #8
	EOR		V11.16B, V11.16B, V5.16B

	EXT     	V18.16B, V18.16B, V18.16B, #8
	EOR		V12.16B, V12.16B, V14.16B

	EXT     	V19.16B, V19.16B, V19.16B, #8
	EOR		V13.16B, V13.16B, V15.16B

	SUB		X2, X2, #0x40


	EOR		V10.16B, V10.16B, V16.16B
	EOR		V11.16B, V11.16B, V17.16B

	EOR		V12.16B, V12.16B, V18.16B
	EOR		V13.16B, V13.16B, V19.16B

	CMP		X2, #0x0
	B.GE		1b			// >=0

	LDR		Q6, .Ldata2
	MOV		V4.16B, V10.16B
	/* V10 carry-less 0x06df000000000000([127:64]*[127:64]) */
	PMULL		V4.1Q, V4.1D, V6.1D	//switch PMULL & PMULL2 order
	PMULL2		V10.1Q, V10.2D, V6.2D
	EOR		V11.16B, V11.16B, V4.16B
	EOR		V11.16B, V11.16B, V10.16B

	MOV		V4.16B, V11.16B
	PMULL		V4.1Q, V4.1D, V6.1D	//switch PMULL & PMULL2 order
	PMULL2		V11.1Q, V11.2D, V6.2D
	EOR		V12.16B, V12.16B, V4.16B
	EOR		V12.16B, V12.16B, V11.16B

	MOV		V4.16B, V12.16B
	PMULL		V4.1Q, V4.1D, V6.1D	//switch PMULL & PMULL2 order
	PMULL2		V12.1Q, V12.2D, V6.2D
	EOR		V13.16B, V13.16B, V4.16B
	EOR		V13.16B, V13.16B, V12.16B

	ADD		X2, X2, #48
	CMP		X2, #0x0
	B.LT		3f			// _final_reduction_for_128, <0

	/* _16B_reduction_loop */
4:
	/* unrelated load as early as possible*/
	LDR		Q10, [X1], #0x10

	MOV		V4.16B, V13.16B
	PMULL2		V13.1Q, V13.2D, V6.2D
	PMULL		V4.1Q, V4.1D, V6.1D
	EOR		V13.16B, V13.16B, V4.16B

	REV64		V10.16B, V10.16B
	EXT     	V10.16B, V10.16B, V10.16B, #8

	EOR		V13.16B, V13.16B, V10.16B

	SUB		X2, X2, #0x10
	CMP		X2, #0x0
	B.GE		4b			// _16B_reduction_loop, >=0

	/*  _final_reduction_for_128 */
3:	ADD		X2, X2, #0x10
	CMP		X2, #0x0
	B.EQ		5f			// _128_done, ==0

	/* _get_last_two_xmms */
6:	MOV		V12.16B, V13.16B
	SUB		X1, X1, #0x10
	ADD		X1, X1, X2
	LDR		Q11, [X1], #0x10
	REV64		V11.16B, V11.16B
	EXT		V11.16B, V11.16B, V11.16B, #8

	CMP		X2, #8
	B.EQ		50f
	B.LT		51f
	B.GT		52f

50:
	/* dont use X register as temp one */
	FMOV		D14, D12
	MOVI		D12, #0
	MOV		V12.D[1],V14.D[0]
	B		53f
51:
	MOV		X9, #64
	LSL     	X13, X2, #3		// <<3 equal x8
	SUB		X9, X9, X13
	MOV		X5, V12.D[0]		// low 64-bit
	MOV		X6, V12.D[1]		// high 64-bit
	LSR		X10, X5, X9		// high bit of low 64-bit
	LSL		X7, X5, X13
	LSL		X8, X6, X13
	ORR		X8, X8, X10		// combination of high 64-bit
	MOV		V12.D[1], X8
	MOV		V12.D[0], X7

	B		53f
52:
	LSL		X13, X2, #3		// <<3 equal x8
	SUB		X13, X13, #64

	DUP		V18.2D, X13
	FMOV		D16, D12
	USHL		D16, D16, D18
	EXT		V12.16B, V16.16B, V16.16B, #8

53:
	MOVI		D14, #0			//add one zero constant

	CMP		X2, #0
	B.EQ	30f
	CMP		X2, #1
	B.EQ	31f
	CMP		X2, #2
	B.EQ	32f
	CMP		X2, #3
	B.EQ	33f
	CMP		X2, #4
	B.EQ	34f
	CMP		X2, #5
	B.EQ	35f
	CMP		X2, #6
	B.EQ	36f
	CMP		X2, #7
	B.EQ	37f
	CMP		X2, #8
	B.EQ	38f
	CMP		X2, #9
	B.EQ	39f
	CMP		X2, #10
	B.EQ	40f
	CMP		X2, #11
	B.EQ	41f
	CMP		X2, #12
	B.EQ	42f
	CMP		X2, #13
	B.EQ	43f
	CMP		X2, #14
	B.EQ	44f
	CMP		X2, #15
	B.EQ	45f

	// >> 128bit
30:
	EOR		V13.16B, V13.16B, V13.16B
	EOR		V8.16B, V8.16B, V8.16B
	LDR		Q9, .L128B
	B		46f

	// >> 120bit
31:
	USHR		V13.2D, V13.2D, #56
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_8B
	LDR		Q9, .L120B
	B		46f

	// >> 112bit
32:
	USHR		 V13.2D, V13.2D, #48
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_16B
	LDR		Q9, .L112B
	B		46f

	// >> 104bit
33:
	USHR		V13.2D, V13.2D, #40
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_24B
	LDR		Q9, .L104B
	B		46f

	// >> 96bit
34:
	USHR		V13.2D, V13.2D, #32
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_32B
	LDR		Q9, .L96B
	B		46f

	// >> 88bit
35:
	USHR		V13.2D, V13.2D, #24
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_40B
	LDR		Q9, .L88B
	B		46f

	// >> 80bit
36:
	USHR		V13.2D, V13.2D, #16
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_48B
	LDR		Q9, .L80B
	B		46f

	// >> 72bit
37:
	USHR		V13.2D, V13.2D, #8
	EXT		V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_56B
	LDR		Q9, .L72B
	B		46f

	// >> 64bit
38:
	EXT		 V13.16B, V13.16B, V14.16B, #8
	LDR		Q8, .LQ8_64B
	LDR		Q9, .L64B
	B		46f

	// >> 56bit
39:
	EXT		V13.16B, V13.16B, V13.16B, #7
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]
	MOV		V13.B[9], V14.B[0]

	LDR		Q8, .LQ8_72B
	LDR		Q9, .L56B
	B		46f

	// >> 48bit
40:
	EXT		V13.16B, V13.16B, V13.16B, #6
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]

	LDR		Q8, .LQ8_80B
	LDR		Q9, .L48B
	B		46f

	// >> 40bit
41:
	EXT		V13.16B, V13.16B, V13.16B, #5
	MOV		V13.S[3], V14.S[0]
	MOV		V13.B[11], V14.B[0]

	LDR		Q8,  .LQ8_88B
	LDR		Q9,  .L40B
	B		46f

	// >> 32bit
42:
	EXT		V13.16B, V13.16B, V13.16B, #4
	MOV		V13.S[3], V14.S[0]

	LDR		Q8, .LQ8_96B
	LDR		Q9, .L32B
	B		46f

	// >> 24bit
43:
	EXT		V13.16B, V13.16B, V13.16B, #3
	MOV		V13.H[7], V14.H[0]
	MOV		V13.B[13], V14.B[0]

	LDR		Q8, .LQ8_104B
	LDR		Q9, .L24B
	B		46f

	// >> 16bit
44:
	EXT		V13.16B, V13.16B, V13.16B, #2
	MOV		V13.H[7], V14.H[0]

	LDR		Q8, .LQ8_112B
	LDR		Q9, .L16B
	B		46f

	// >> 8bit
45:
	EXT		 V13.16B, V13.16B, V13.16B, #1
	MOV		V13.B[15], V14.B[0]

	LDR		Q8, .LQ8_120B
	LDR		Q9, .L8B

	// backup V12 first
	// pblendvb	xmm1, xmm2
46:
	AND		V12.16B, V12.16B, V9.16B
	AND		V11.16B, V11.16B, V8.16B
	ORR		V11.16B, V11.16B, V12.16B

	MOV		V12.16B, V11.16B
	MOV		V4.16B, V13.16B
	PMULL2		V13.1Q, V13.2D, V6.2D
	PMULL		V4.1Q, V4.1D, V6.1D
	EOR		V13.16B, V13.16B, V4.16B
	EOR		V13.16B, V13.16B, V12.16B

	/* _128_done. we change the Q6 D[0] and D[1] */
5:	LDR		Q6, .Ldata3
	MOVI		D14, #0
	MOV		V10.16B, V13.16B
	PMULL2		V13.1Q, V13.2D, V6.2D

	MOV		V10.D[1], V10.D[0]
	MOV		V10.D[0], V14.D[0]    //set zero

	EOR		V13.16B, V13.16B, V10.16B

	MOV		V10.16B, V13.16B
	LDR		Q7, .Ldata4
	AND		V10.16B, V10.16B, V7.16B

	MOV		S13, V13.S[3]

	PMULL		V13.1Q, V13.1D, V6.1D
	EOR		V13.16B, V13.16B, V10.16B

	/* _barrett */
7:	LDR		Q6, .Ldata5
	MOVI    	D14, #0
	MOV		V10.16B, V13.16B
	PMULL2		V13.1Q, V13.2D, V6.2D

	EXT		V13.16B, V13.16B, V13.16B, #12
	MOV		V13.S[0], V14.S[0]

	EXT		V6.16B, V6.16B, V6.16B, #8
	PMULL2		V13.1Q, V13.2D, V6.2D

	EXT		V13.16B, V13.16B, V13.16B, #12
	MOV		V13.S[0], V14.S[0]

	EOR		V13.16B, V13.16B, V10.16B
	MOV		X0, V13.D[0]

	/* _cleanup */
8:	MOV		X14, #48
	LSR		X0, X0, X14
99:
	ADD		sp, sp, #0x20

	LDP		Q18, Q19, [sp], #0x20
	LDP		Q16, Q17, [sp], #0x20
	LDP		Q14, Q15, [sp], #0x20

	LDP		Q8, Q9, [sp], #0x20
	LDP		Q6, Q7, [sp], #0x20
	LDP		Q4, Q5, [sp], #0x20
	LDP		Q12, Q13, [sp], #0x20
	LDP		Q10, Q11, [sp], #0x20
	LDP		X13, X14, [sp], #0x10
	LDP		X11, X12, [sp], #0x10
	LDP		X9, X10, [sp], #0x10
	LDP		X7, X8, [sp], #0x10
	LDP		X5, X6, [sp], #0x10

	RET

	/* _less_than_128 */
2:	CMP		X2, #32
	B.LT		9f				// _less_than_32
	LDR		Q6, .Ldata2

	LSL		X0, X0, #48
	LDR		Q10, .Lzero
	MOV		V10.D[1], X0
	LDR		Q13, [X1], #0x10
	REV64		V13.16B, V13.16B
	EXT     	V13.16B, V13.16B, V13.16B, #8

	EOR		V13.16B, V13.16B, V10.16B

	SUB		X2, X2, #32
	B		4b

	/* _less_than_32 */
9:	CMP		X2, #0
	B.EQ		99b			// _cleanup
	LSL		X0, X0, #48
	LDR		Q10, .Lzero
	MOV		V10.D[1], X0

	CMP		X2, #16
	B.EQ		10f			// _exact_16_left
	B.LE		11f			// _less_than_16_left
	LDR		Q13, [X1], #0x10

	REV64		V13.16B, V13.16B
	EXT		V13.16B, V13.16B, V13.16B, #8

	EOR		V13.16B, V13.16B, V10.16B
	SUB		X2, X2, #16
	LDR		Q6, .Ldata2
	B		6b			// _get_last_two_xmms

	/*  _less_than_16_left */
11:	CMP		X2, #4
	B.LT		13f			// _only_less_than_4

	/* backup the length of data, we used in _less_than_2_left */
	MOV		X8, X2
	CMP		X2, #8
	B.LT		14f			// _less_than_8_left

	LDR		X14, [X1], #8
	/* push the data to stack, we backup the data to V10 */
	STR		X14, [sp, #0]
	SUB		X2, X2, #8
	ADD		X11, X11, #8

	/* _less_than_8_left */
14:	CMP		X2, #4
	B.LT		15f			// _less_than_4_left

	/* get 32bit data */
	LDR		W5, [X1], #4

	/* push the data to stack */
	STR		W5, [sp, X11]
	SUB		X2, X2, #4
	ADD		X11, X11, #4

	/* _less_than_4_left */
15:	CMP		X2, #2
	B.LT		16f			// _less_than_2_left

	/* get 16bits data */
	LDRH		W6, [X1], #2

	/* push the data to stack */
	STRH		W6, [sp, X11]
	SUB		X2, X2, #2
	ADD		X11, X11, #2

	/* _less_than_2_left */
16:
	/* get 8bits data */
	LDRB		W7, [X1], #1
	STRB		W7, [sp, X11]
	ADD		X11, X11, #1

	/* POP data from stack, store to V13 */
	LDR		Q13, [sp]
	MOVI    	D14, #0
	REV64		V13.16B, V13.16B
	MOV		V8.16B, V13.16B
	MOV		V13.D[1], V8.D[0]
	MOV		V13.D[0], V8.D[1]

	EOR		V13.16B, V13.16B, V10.16B
	CMP		X8, #15
	B.EQ	80f
	CMP		X8, #14
	B.EQ	81f
	CMP		X8, #13
	B.EQ	82f
	CMP		X8, #12
	B.EQ	83f
	CMP		X8, #11
	B.EQ	84f
	CMP		X8, #10
	B.EQ	85f
	CMP		X8, #9
	B.EQ	86f
	CMP		X8, #8
	B.EQ	87f
	CMP		X8, #7
	B.EQ	88f
	CMP		X8, #6
	B.EQ	89f
	CMP		X8, #5
	B.EQ	90f
	CMP		X8, #4
	B.EQ	91f
	CMP		X8, #3
	B.EQ	92f
	CMP		X8, #2
	B.EQ	93f
	CMP		X8, #1
	B.EQ	94f
	CMP		X8, #0
	B.EQ	95f

80:
	EXT		V13.16B, V13.16B, V13.16B, #1
	MOV		V13.B[15], V14.B[0]
	B		5b

81:
	EXT		V13.16B, V13.16B, V13.16B, #2
	MOV		 V13.H[7], V14.H[0]
	B		5b

82:
	EXT		V13.16B, V13.16B, V13.16B, #3
	MOV		V13.H[7], V14.H[0]
	MOV		V13.B[13], V14.B[0]
	B		5b
83:

	EXT		V13.16B, V13.16B, V13.16B, #4
	MOV		V13.S[3], V14.S[0]
	B		5b

84:
	EXT		V13.16B, V13.16B, V13.16B, #5
	MOV		V13.S[3], V14.S[0]
	MOV		V13.B[11], V14.B[0]
	B		5b

85:
	EXT		V13.16B, V13.16B, V13.16B, #6
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]
	B		5b

86:
	EXT		V13.16B, V13.16B, V13.16B, #7
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]
	MOV		V13.B[9], V14.B[0]
	B		5b

87:
	MOV		V13.D[0], V13.D[1]
	MOV		V13.D[1], V14.D[0]
	B		5b

88:
	EXT		V13.16B, V13.16B, V13.16B, #9
	MOV		V13.D[1], V14.D[0]
	MOV		V13.B[7], V14.B[0]
	B		5b

89:
	EXT		V13.16B, V13.16B, V13.16B, #10
	MOV		V13.D[1], V14.D[0]
	MOV		 V13.H[3], V14.H[0]
	B		5b

90:
	EXT		V13.16B, V13.16B, V13.16B, #11
	MOV		V13.D[1], V14.D[0]
	MOV		V13.H[3], V14.H[0]
	MOV		V13.B[5], V14.B[0]
	B		5b

91:
	MOV		V13.S[0], V13.S[3]
	MOV		V13.D[1], V14.D[0]
	MOV		V13.S[1], V14.S[0]
	B		5b

92:
	EXT		V13.16B, V13.16B, V13.16B, #13
	MOV		V13.D[1], V14.D[0]
	MOV		V13.S[1], V14.S[0]
	MOV		V13.B[3], V14.B[0]
	B		5b

93:
	MOV		V15.H[0], V13.H[7]
	MOV		V13.16B, V14.16B
	MOV		V13.H[0], V15.H[0]
	B		5b

94:
	MOV		V15.B[0], V13.B[15]
	MOV		V13.16B, V14.16B
	MOV		V13.B[0], V15.B[0]
	B		5b

95:
	LDR		Q13, .Lzero
	B		5b				// _128_done

	/* _exact_16_left */
10:
	LD1		{ V13.2D }, [X1], #0x10

	REV64		V13.16B, V13.16B
	EXT		V13.16B, V13.16B, V13.16B, #8
	EOR		V13.16B, V13.16B, V10.16B
	B		5b				// _128_done

	/* _only_less_than_4 */
13:	CMP		X2, #3
	MOVI		D14, #0
	B.LT		17f				//_only_less_than_3

	LDR		S13, [X1], #4
	MOV		 V13.B[15], V13.B[0]
	MOV		V13.B[14], V13.B[1]
	MOV		V13.B[13], V13.B[2]
	MOV		V13.S[0], V13.S[1]

	EOR		V13.16B, V13.16B, V10.16B

	EXT		V13.16B, V13.16B, V13.16B, #5

	MOV		V13.S[3], V14.S[0]
	MOV		V13.B[11], V14.B[0]

	B		7b				// _barrett
	/* _only_less_than_3 */
17:
	CMP		X2, #2
	B.LT		18f				// _only_less_than_2

	LDR		H13, [X1], #2
	MOV		V13.B[15], V13.B[0]
	MOV		V13.B[14], V13.B[1]
	MOV		V13.H[0], V13.H[1]

	EOR		V13.16B, V13.16B, V10.16B

	EXT		V13.16B, V13.16B, V13.16B, #6
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]

	B		7b				// _barrett

	/* _only_less_than_2 */
18:
	LDRB		W7, [X1], #1
	LDR		Q13, .Lzero
	MOV		V13.B[15], W7

	EOR		V13.16B, V13.16B, V10.16B

	EXT		V13.16B, V13.16B, V13.16B, #7
	MOV		V13.S[3], V14.S[0]
	MOV		V13.H[5], V14.H[0]
	MOV		V13.B[9], V14.B[0]

	B		7b				// _barrett

.Ldata1:
	.word	0x00000000
	.word	0x044c0000
	.word	0x00000000
	.word	0xe6580000

.Ldata2:
	.word	0x00000000
	.word	0x2d560000
	.word	0x00000000
	.word	0x06df0000

.Ldata3:
	.word	0x00000000
	.word	0x13680000
	.word	0x00000000
	.word	0x2d560000

.Ldata4:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x00000000

.Ldata5:
	.word	0x8bb70000
	.word	0x00000001
	.word	0xf65a57f8
	.word	0x00000001

.L128B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF

.L120B:
	.word	0xFFFFFF00
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF

.L112B:
	.word	0xFFFF0000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF

.L104B:
	.word	0xFF000000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF

.L96B:
	.word	0x00000000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
.L88B:
	.word	0x00000000
	.word	0xFFFFFF00
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
.L80B:
	.word	0x00000000
	.word	0xFFFF0000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
.L72B:
	.word	0x00000000
	.word	0xFF000000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
.L64B:
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
.L56B:
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFFFF00
	.word	0xFFFFFFFF
.L48B:
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFF0000
	.word	0xFFFFFFFF
.L40B:
	.word	0x00000000
	.word	0x00000000
	.word	0xFF000000
	.word	0xFFFFFFFF
.L32B:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFFFFFF
.L24B:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFFFF00
.L16B:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0xFFFF0000
.L8B:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0xFF000000

.LQ8_8B:
	.word	0x000000FF
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000

.LQ8_16B:
	.word	0x0000FFFF
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000

.LQ8_24B:
	.word	0x00FFFFFF
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000

.LQ8_32B:
	.word	0xFFFFFFFF
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000

.LQ8_40B:
	.word	0xFFFFFFFF
	.word	0x000000FF
	.word	0x00000000
	.word	0x00000000

.LQ8_48B:
	.word	0xFFFFFFFF
	.word	0x0000FFFF
	.word	0x00000000
	.word	0x00000000

.LQ8_56B:
	.word	0xFFFFFFFF
	.word	0x00FFFFFF
	.word	0x00000000
	.word	0x00000000

.LQ8_64B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x00000000
	.word	0x00000000

.LQ8_72B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x000000FF
	.word	0x00000000

.LQ8_80B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x0000FFFF
	.word	0x00000000


.LQ8_88B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x00FFFFFF
	.word	0x00000000


.LQ8_96B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x00000000

.LQ8_104B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x000000FF

.LQ8_112B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x0000FFFF

.LQ8_120B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0x00FFFFFF

.LQ8_128B:
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF
	.word	0xFFFFFFFF

.Lzero:
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
	.word	0x00000000
