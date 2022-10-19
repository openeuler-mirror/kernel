/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copied from arch/arm64/include/asm/kprobes.h
 *
 * Copyright (C) 2013 Linaro Limited
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_KPROBES_H
#define _ASM_RISCV_KPROBES_H

#include <asm-generic/kprobes.h>

#ifdef CONFIG_KPROBES
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/percpu.h>

#define __ARCH_WANT_KPROBES_INSN_SLOT
#define MAX_INSN_SIZE			2

#define flush_insn_slot(p)		do { } while (0)
#define kretprobe_blacklist_size	0

#include <asm/probes.h>

struct prev_kprobe {
	struct kprobe *kp;
	unsigned int status;
};

/* per-cpu kprobe control block */
struct kprobe_ctlblk {
	unsigned int kprobe_status;
	unsigned long saved_status;
	struct prev_kprobe prev_kprobe;
};

void arch_remove_kprobe(struct kprobe *p);
int kprobe_fault_handler(struct pt_regs *regs, unsigned int trapnr);
bool kprobe_breakpoint_handler(struct pt_regs *regs);
bool kprobe_single_step_handler(struct pt_regs *regs);
void kretprobe_trampoline(void);
void __kprobes *trampoline_probe_handler(struct pt_regs *regs);

#ifdef CONFIG_OPTPROBES

/* optinsn template addresses */
extern __visible kprobe_opcode_t optprobe_template_entry[];
extern __visible kprobe_opcode_t optprobe_template_val[];
extern __visible kprobe_opcode_t optprobe_template_call[];
extern __visible kprobe_opcode_t optprobe_template_store_epc[];
extern __visible kprobe_opcode_t optprobe_template_end[];
extern __visible kprobe_opcode_t optprobe_template_sub_sp[];
extern __visible kprobe_opcode_t optprobe_template_add_sp[];
extern __visible kprobe_opcode_t optprobe_template_restore_begin[];
extern __visible kprobe_opcode_t optprobe_template_restore_orig_insn[];
extern __visible kprobe_opcode_t optprobe_template_restore_end[];

#define MAX_OPTINSN_SIZE				\
		((unsigned long)optprobe_template_end -	\
		 (unsigned long)optprobe_template_entry)

#define MAX_COPIED_INSN 2
#define MAX_OPTIMIZED_LENGTH  (MAX_COPIED_INSN * 4)
#define JUMP_SIZE             MAX_OPTIMIZED_LENGTH

struct arch_optimized_insn {
	kprobe_opcode_t copied_insn[MAX_COPIED_INSN];
	/* detour code buffer */
	kprobe_opcode_t *insn;
};

#define RVI_INST_SIZE 4

#endif /* CONFIG_OPTPROBES */
#endif /* CONFIG_KPROBES */
#endif /* _ASM_RISCV_KPROBES_H */
