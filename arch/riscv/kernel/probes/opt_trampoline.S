/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2022 Guokai Chen
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>

#ifdef CONFIG_OPTPROBES

ENTRY(optprobe_template_entry)
ENTRY(optprobe_template_sub_sp)

	REG_S sp, (-(PT_SIZE_ON_STACK) + PT_SP)(sp)
	addi sp, sp, -(PT_SIZE_ON_STACK)
ENTRY(optprobe_template_store_epc)
	REG_S ra, PT_EPC(sp)
	REG_S ra, PT_RA(sp)
	REG_S gp, PT_GP(sp)
	REG_S tp, PT_TP(sp)
	REG_S t0, PT_T0(sp)
	REG_S t1, PT_T1(sp)
	REG_S t2, PT_T2(sp)
	REG_S s0, PT_S0(sp)
	REG_S s1, PT_S1(sp)
	REG_S a0, PT_A0(sp)
	REG_S a1, PT_A1(sp)
	REG_S a2, PT_A2(sp)
	REG_S a3, PT_A3(sp)
	REG_S a4, PT_A4(sp)
	REG_S a5, PT_A5(sp)
	REG_S a6, PT_A6(sp)
	REG_S a7, PT_A7(sp)
	REG_S s2, PT_S2(sp)
	REG_S s3, PT_S3(sp)
	REG_S s4, PT_S4(sp)
	REG_S s5, PT_S5(sp)
	REG_S s6, PT_S6(sp)
	REG_S s7, PT_S7(sp)
	REG_S s8, PT_S8(sp)
	REG_S s9, PT_S9(sp)
	REG_S s10, PT_S10(sp)
	REG_S s11, PT_S11(sp)
	REG_S t3, PT_T3(sp)
	REG_S t4, PT_T4(sp)
	REG_S t5, PT_T5(sp)
	REG_S t6, PT_T6(sp)
	csrr t0, sstatus
	csrr t1, stval
	csrr t2, scause
	REG_S t0, PT_STATUS(sp)
	REG_S t1, PT_BADADDR(sp)
	REG_S t2, PT_CAUSE(sp)
ENTRY(optprobe_template_add_sp)
	move a1, sp
	lla a0, 1f
	REG_L a0, 0(a0)
	REG_L a2, 2f
	jalr 0(a2)
ENTRY(optprobe_template_restore_begin)
	REG_L t0, PT_STATUS(sp)
	REG_L t1, PT_BADADDR(sp)
	REG_L t2, PT_CAUSE(sp)
	csrw sstatus, t0
	csrw stval, t1
	csrw scause, t2
	REG_L ra, PT_RA(sp)
	REG_L gp, PT_GP(sp)
	REG_L tp, PT_TP(sp)
	REG_L t0, PT_T0(sp)
	REG_L t1, PT_T1(sp)
	REG_L t2, PT_T2(sp)
	REG_L s0, PT_S0(sp)
	REG_L s1, PT_S1(sp)
	REG_L a0, PT_A0(sp)
	REG_L a1, PT_A1(sp)
	REG_L a2, PT_A2(sp)
	REG_L a3, PT_A3(sp)
	REG_L a4, PT_A4(sp)
	REG_L a5, PT_A5(sp)
	REG_L a6, PT_A6(sp)
	REG_L a7, PT_A7(sp)
	REG_L s2, PT_S2(sp)
	REG_L s3, PT_S3(sp)
	REG_L s4, PT_S4(sp)
	REG_L s5, PT_S5(sp)
	REG_L s6, PT_S6(sp)
	REG_L s7, PT_S7(sp)
	REG_L s8, PT_S8(sp)
	REG_L s9, PT_S9(sp)
	REG_L s10, PT_S10(sp)
	REG_L s11, PT_S11(sp)
	REG_L t3, PT_T3(sp)
	REG_L t4, PT_T4(sp)
	REG_L t5, PT_T5(sp)
	REG_L t6, PT_T6(sp)
	addi sp, sp, PT_SIZE_ON_STACK
ENTRY(optprobe_template_restore_orig_insn)
	nop
	nop
ENTRY(optprobe_template_restore_end)
ret_to_normal:
	auipc ra, 0
	jalr x0, 0(ra)
ENTRY(optprobe_template_val)
1:
	.dword 0
ENTRY(optprobe_template_call)
2:
	.dword 0
	.dword 0
ENTRY(optprobe_template_end)
END(optprobe_template_end)
END(optprobe_template_call)
END(optprobe_template_val)
END(optprobe_template_restore_end)
END(optprobe_template_restore_orig_insn)
END(optprobe_template_restore_begin)
END(optprobe_template_add_sp)
END(optprobe_template_store_epc)
END(optprobe_template_sub_sp)
END(optprobe_template_entry)

#endif /* CONFIG_OPTPROBES */
