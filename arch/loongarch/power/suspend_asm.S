/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Sleep helper for Loongson-3 sleep mode.
 *
 *  Copyright (C) 2020 Loongson Technology Co., Ltd.
 *  Author: Huacai Chen <chenhuacai@loongson.cn>
 */

#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/loongarch.h>
#include <asm/stackframe.h>
#include <asm/addrspace.h>

	.extern loongarch_nr_nodes
	.extern loongarch_suspend_addr
	.extern loongarch_pcache_ways
	.extern loongarch_pcache_sets
	.extern loongarch_pcache_linesz
	.extern loongarch_scache_ways
	.extern loongarch_scache_sets
	.extern loongarch_scache_linesz

	.text
	.align	5

/* preparatory stuff */
.macro	SETUP_SLEEP
	addi.d	sp, sp, -PT_SIZE
	st.d	$r1, sp, PT_R1
	st.d	$r2, sp, PT_R2
	st.d	$r3, sp, PT_R3
	st.d	$r4, sp, PT_R4
	st.d	$r5, sp, PT_R5
	st.d	$r6, sp, PT_R6
	st.d	$r7, sp, PT_R7
	st.d	$r8, sp, PT_R8
	st.d	$r9, sp, PT_R9
	st.d	$r10, sp, PT_R10
	st.d	$r11, sp, PT_R11
	st.d	$r20, sp, PT_R20
	st.d	$r21, sp, PT_R21
	st.d	$r22, sp, PT_R22
	st.d	$r23, sp, PT_R23
	st.d	$r24, sp, PT_R24
	st.d	$r25, sp, PT_R25
	st.d	$r26, sp, PT_R26
	st.d	$r27, sp, PT_R27
	st.d	$r28, sp, PT_R28
	st.d	$r29, sp, PT_R29
	st.d	$r30, sp, PT_R30
	st.d	$r31, sp, PT_R31

#ifdef CONFIG_ACPI
	la.pcrel	t0, acpi_saved_sp
	st.d	sp, t0, 0
#endif
.endm
/* Sleep code for Loongson-3 */
SYM_CODE_START(loongarch_suspend_enter)
	SETUP_SLEEP
	bl cpu_flush_caches

	/* Pass RA and SP to BIOS, for machines without CMOS RAM */
	addi.d	a1, sp, 0
	la.pcrel	a0, loongarch_wakeup_start

	la.pcrel	t0, loongarch_suspend_addr
	ld.d	t0, t0, 0 /* Call BIOS's STR sleep routine */
	jr	t0
	nop
SYM_CODE_END(loongarch_suspend_enter)

.macro  SETUP_WAKEUP

	nop
	ld.d	$r1, sp, PT_R1
	ld.d	$r2, sp, PT_R2
	ld.d	$r3, sp, PT_R3
	ld.d	$r4, sp, PT_R4
	ld.d	$r5, sp, PT_R5
	ld.d	$r6, sp, PT_R6
	ld.d	$r7, sp, PT_R7
	ld.d	$r8, sp, PT_R8
	ld.d	$r9, sp, PT_R9
	ld.d	$r10, sp, PT_R10
	ld.d	$r11, sp, PT_R11
	ld.d	$r20, sp, PT_R20
	ld.d	$r21, sp, PT_R21
	ld.d	$r22, sp, PT_R22
	ld.d	$r23, sp, PT_R23
	ld.d	$r24, sp, PT_R24
	ld.d	$r25, sp, PT_R25
	ld.d	$r26, sp, PT_R26
	ld.d	$r27, sp, PT_R27
	ld.d	$r28, sp, PT_R28
	ld.d	$r29, sp, PT_R29
	ld.d	$r30, sp, PT_R30
	ld.d	$r31, sp, PT_R31
.endm

	/* This is where we return upon wakeup.
	 * Reload all of the registers and return.
	 */
	.align	12
SYM_CODE_START(loongarch_wakeup_start)
	li.d	t0, CSR_DMW0_INIT	# UC, PLV0
	csrwr	t0, LOONGARCH_CSR_DMWIN0
	li.d	t0, CSR_DMW1_INIT	# CA, PLV0
	csrwr	t0, LOONGARCH_CSR_DMWIN1

	JUMP_VIRT_ADDR	t0, t1

	la.pcrel	t0, acpi_saved_sp
	ld.d	sp, t0, 0
	SETUP_WAKEUP
	addi.d	sp, sp, PT_SIZE
	jr	ra
SYM_CODE_END(loongarch_wakeup_start)
