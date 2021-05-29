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

#ifdef PPC64_ELF_ABI_v1
struct ppc64_klp_btramp_entry {
	u32 jump[16];
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
#endif /* PPC64_ELF_ABI_v1 */

int livepatch_create_branch(unsigned long pc,
			    unsigned long trampoline,
			    unsigned long addr,
			    struct module *me);
#endif	/* CONFIG_PPC64 */

#endif /* CONFIG_LIVEPATCH_FTRACE */

#ifdef CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
struct klp_patch;
int klp_check_calltrace(struct klp_patch *patch, int enable);
#endif

static inline void klp_init_thread_info(struct task_struct *p)
{
	/* + 1 to account for STACK_END_MAGIC */
	task_thread_info(p)->livepatch_sp = end_of_stack(p) + 1;
}
#else
static inline void klp_init_thread_info(struct task_struct *p) { }
#endif /* CONFIG_LIVEPATCH */

#endif /* _ASM_POWERPC_LIVEPATCH_H */
