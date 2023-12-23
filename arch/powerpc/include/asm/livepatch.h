/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * livepatch.h - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2015-2016, SUSE, IBM Corp.
 * Copyright (C) 2023  Huawei Technologies Co., Ltd.
 */
#ifndef _ASM_POWERPC_LIVEPATCH_H
#define _ASM_POWERPC_LIVEPATCH_H

#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#ifdef CONFIG_LIVEPATCH_64
static inline void klp_init_thread_info(struct task_struct *p)
{
	/* + 1 to account for STACK_END_MAGIC */
	task_thread_info(p)->livepatch_sp = end_of_stack(p) + 1;
}
#else
static inline void klp_init_thread_info(struct task_struct *p) { }
#endif

#ifdef CONFIG_LIVEPATCH_WO_FTRACE

struct klp_func;

#ifdef CONFIG_PPC64
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

struct ppc64_klp_btramp_entry {
	u32 jump[18];
	u32 magic;
	union {
		func_desc_t funcdata;
		unsigned long saved_entry[3];
	};
};

#define PPC64_INSN_SIZE	4
#define LJMP_INSN_SIZE	(sizeof(struct ppc64_klp_bstub_entry) / PPC64_INSN_SIZE)

/* STUB_MAGIC 0x73747562 "stub" */
#define BRANCH_STUB_MAGIC	0x73747563 /* stub + 1	*/
#define BRANCH_TRAMPOLINE_MAGIC 0x73747564 /* stub + 2	*/
void livepatch_branch_stub(void);
void livepatch_branch_stub_end(void);
void livepatch_branch_trampoline(void);
void livepatch_branch_trampoline_end(void);
void livepatch_brk_trampoline(void);

int livepatch_create_branch(unsigned long pc, unsigned long trampoline,
			    unsigned long addr, struct module *me);
struct klp_object;
int arch_klp_init_func(struct klp_object *obj, struct klp_func *func);
void *arch_klp_mem_alloc(size_t size);
void arch_klp_mem_free(void *mem);
#else /* !CONFIG_PPC64 */
#define PPC32_INSN_SIZE	4
#define LJMP_INSN_SIZE	4
#endif /* CONFIG_PPC64 */

struct arch_klp_data {
	u32 old_insns[LJMP_INSN_SIZE];
#ifdef CONFIG_PPC64
	struct ppc64_klp_btramp_entry trampoline;
#endif
	/*
	 * Saved opcode at the entry of the old func (which maybe replaced
	 * with breakpoint).
	 */
	u32 saved_opcode;
};

#define KLP_MAX_REPLACE_SIZE sizeof_field(struct arch_klp_data, old_insns)

/* kernel livepatch instruction barrier */
#define klp_smp_isb()  __smp_lwsync()
int arch_klp_patch_func(struct klp_func *func);
void arch_klp_unpatch_func(struct klp_func *func);
long arch_klp_save_old_code(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_check_calltrace(bool (*check_func)(void *, int *, unsigned long), void *data);
bool arch_check_jump_insn(unsigned long func_addr);
int klp_patch_text(u32 *dst, const u32 *src, int len);
int klp_brk_handler(struct pt_regs *regs);
int arch_klp_add_breakpoint(struct arch_klp_data *arch_data, void *old_func);
void arch_klp_remove_breakpoint(struct arch_klp_data *arch_data, void *old_func);
int arch_klp_module_check_calltrace(void *data);

#endif /* CONFIG_LIVEPATCH_WO_FTRACE */

#endif /* _ASM_POWERPC_LIVEPATCH_H */
