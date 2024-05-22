/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2015-2016, SUSE, IBM Corp.
 */
#ifndef _ASM_POWERPC_LIVEPATCH_H
#define _ASM_POWERPC_LIVEPATCH_H

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/sched/task_stack.h>

#ifdef CONFIG_LIVEPATCH
#ifdef CONFIG_LIVEPATCH_FTRACE
static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long ip)
{
	regs->nip = ip;
}

#define klp_get_ftrace_location klp_get_ftrace_location
static inline unsigned long klp_get_ftrace_location(unsigned long faddr)
{
	/*
	 * Live patch works only with -mprofile-kernel on PPC. In this case,
	 * the ftrace location is always within the first 16 bytes.
	 */
	return ftrace_location_range(faddr, faddr + 16);
}

#elif defined(CONFIG_LIVEPATCH_WO_FTRACE)
struct klp_func;

/* kernel livepatch instruction barrier */
#define klp_smp_isb()  __smp_lwsync()

int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);

#if defined(CONFIG_PPC64)
/*
 * use the livepatch stub to jump to the trampoline.
 * It is similar to stub, but does not need to save
 * and load R2.
 * struct ppc64_klp_bstub_entry
 */
struct ppc64_klp_bstub_entry {
	u32 jump[5];
	u32 magic;
	/* address for livepatch trampoline  */
	u64 trampoline;
};

#ifdef PPC64_ELF_ABI_v1
struct ppc64_klp_btramp_entry {
	u32 jump[18];
	u32 magic;
	union {
		struct ppc64_opd_entry funcdata;
		unsigned long saved_entry[2];
	};
};
#endif /* PPC64_ELF_ABI_v1 */

#define PPC64_INSN_SIZE	4
#define LJMP_INSN_SIZE	(sizeof(struct ppc64_klp_bstub_entry) / PPC64_INSN_SIZE)

/* STUB_MAGIC 0x73747562 "stub" */
#define BRANCH_STUB_MAGIC	0x73747563 /* stub + 1	*/
#define BRANCH_TRAMPOLINE_MAGIC 0x73747564 /* stub + 2	*/

extern void livepatch_branch_stub(void);
extern void livepatch_branch_stub_end(void);

#ifdef PPC64_ELF_ABI_v1
extern void livepatch_branch_trampoline(void);
extern void livepatch_branch_trampoline_end(void);
extern void livepatch_brk_trampoline(void);
void livepatch_create_btramp(struct ppc64_klp_btramp_entry *entry, unsigned long addr);
#else
static inline void livepatch_create_btramp(struct ppc64_klp_btramp_entry *entry,
					   unsigned long addr) {}
#endif /* PPC64_ELF_ABI_v1 */

int livepatch_create_branch(unsigned long pc,
			    unsigned long trampoline,
			    unsigned long addr,
			    struct module *me);

struct arch_klp_data {
	u32 old_insns[LJMP_INSN_SIZE];
#ifdef PPC64_ELF_ABI_v1
	struct ppc64_klp_btramp_entry trampoline;
#else
	unsigned long trampoline;
#endif /* PPC64_ELF_ABI_v1 */

	/*
	 * Saved opcode at the entry of the old func (which maybe replaced
	 * with breakpoint).
	 */
	u32 saved_opcode;
};

#elif defined(CONFIG_PPC32)

#define PPC32_INSN_SIZE	4
#define LJMP_INSN_SIZE	4
struct arch_klp_data {
	u32 old_insns[LJMP_INSN_SIZE];

	/*
	 * Saved opcode at the entry of the old func (which maybe replaced
	 * with breakpoint).
	 */
	u32 saved_opcode;
};

#endif	/* CONFIG_PPC64 */

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

struct stackframe {
	/* stack frame to be unwinded */
	unsigned long sp;
	/* link register saved in last stack frame */
	unsigned long pc;
	/* instruction register saved in pt_regs */
	unsigned long nip;
	/* link register saved in pt_regs */
	unsigned long link;
	/* stack frame pointer (r1 register) saved in pt_regs */
	unsigned long sfp;
	/* check if nip and link are in same function */
	unsigned int nip_link_in_same_func;
	/* check if it is top frame before interrupt */
	unsigned int is_top_frame;
};

#ifdef PPC64_ELF_ABI_v1
struct klp_func_node;
void arch_klp_set_brk_func(struct klp_func_node *func_node, void *new_func);
#endif
int klp_brk_handler(struct pt_regs *regs);
int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func);
void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func);
long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_module_check_calltrace(void *data);
int klp_unwind_frame(struct task_struct *tsk, struct stackframe *frame);
int klp_patch_text(u32 *dst, const u32 *src, int len);

#endif /* CONFIG_LIVEPATCH_FTRACE */

static inline void klp_init_thread_info(struct task_struct *p)
{
	/* + 1 to account for STACK_END_MAGIC */
	task_thread_info(p)->livepatch_sp = end_of_stack(p) + 1;
}
#else
static inline void klp_init_thread_info(struct task_struct *p) { }
#endif /* CONFIG_LIVEPATCH */

#endif /* _ASM_POWERPC_LIVEPATCH_H */
