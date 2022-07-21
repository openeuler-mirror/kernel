/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_MMU_CONTEXT_H
#define _ASM_SW64_MMU_CONTEXT_H

/*
 * get a new mmu context..
 *
 * Copyright (C) 1996, Linus Torvalds
 */
#include <linux/mm_types.h>

#include <asm/compiler.h>
#include <asm/io.h>

/*
 * Force a context reload. This is needed when we change the page
 * table pointer or when we update the ASN of the current process.
 */

static inline unsigned long
__reload_thread(struct pcb_struct *pcb)
{
	register unsigned long a0 __asm__("$16");
	register unsigned long v0 __asm__("$0");

	a0 = virt_to_phys(pcb);
	__asm__ __volatile__(
		"sys_call %2 #__reload_thread"
		: "=r"(v0), "=r"(a0)
		: "i"(HMC_swpctx), "r"(a0)
		: "$1", "$22", "$23", "$24", "$25");

	return v0;
}

#define load_asn_ptbr   load_mm

/*
 * The maximum ASN's the processor supports.
 *
 * If a processor implements address space numbers (ASNs), and the old
 * PTE has the Address Space Match (ASM) bit clear (ASNs in use) and
 * the Valid bit set, then entries can also effectively be made coherent
 * by assigning a new, unused ASN to the currently running process and
 * not reusing the previous ASN before calling the appropriate HMcode
 * routine to invalidate the translation buffer (TB).
 *
 */

#ifdef CONFIG_SUBARCH_C3B
#define WIDTH_HARDWARE_ASN	10
#endif

/*
 * cpu_last_asn(processor):
 * 63                                            0
 * +-------------+----------------+--------------+
 * | asn version | this processor | hardware asn |
 * +-------------+----------------+--------------+
 */

#include <asm/hw_init.h>
#ifdef CONFIG_SMP
#define cpu_last_asn(cpuid)	(cpu_data[cpuid].last_asn)
#else
extern unsigned long last_asn;
#define cpu_last_asn(cpuid)	last_asn
#endif /* CONFIG_SMP */

#define ASN_FIRST_VERSION	(1UL << WIDTH_HARDWARE_ASN)
#define HARDWARE_ASN_MASK	((1UL << WIDTH_HARDWARE_ASN) - 1)

/*
 * NOTE! The way this is set up, the high bits of the "asn_cache" (and
 * the "mm->context") are the ASN _version_ code. A version of 0 is
 * always considered invalid, so to invalidate another process you only
 * need to do "p->mm->context = 0".
 *
 * If we need more ASN's than the processor has, we invalidate the old
 * user TLB's (tbiap()) and start a new ASN version. That will automatically
 * force a new asn for any other processes the next time they want to
 * run.
 */

static inline unsigned long
__get_new_mm_context(struct mm_struct *mm, long cpu)
{
	unsigned long asn = cpu_last_asn(cpu);
	unsigned long next = asn + 1;

	if ((asn & HARDWARE_ASN_MASK) >= HARDWARE_ASN_MASK) {
		tbiap();
		next = (asn & ~HARDWARE_ASN_MASK) + ASN_FIRST_VERSION;
	}
	cpu_last_asn(cpu) = next;
	return next;
}

static inline void
switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
	  struct task_struct *next)
{
	/* Check if our ASN is of an older version, and thus invalid. */
	unsigned long asn;
	unsigned long mmc;
	long cpu = smp_processor_id();

#ifdef CONFIG_SMP
	cpu_data[cpu].asn_lock = 1;
	barrier();
#endif
	asn = cpu_last_asn(cpu);
	mmc = next_mm->context.asid[cpu];
	if ((mmc ^ asn) & ~HARDWARE_ASN_MASK) {
		/* Check if mmc and cpu asn is in the same version */
		mmc = __get_new_mm_context(next_mm, cpu);
		next_mm->context.asid[cpu] = mmc;
	}
#ifdef CONFIG_SMP
	else
		cpu_data[cpu].need_new_asn = 1;
#endif

	/*
	 * Always update the PCB ASN.  Another thread may have allocated
	 * a new mm->context (via flush_tlb_mm) without the ASN serial
	 * number wrapping.  We have no way to detect when this is needed.
	 */
	task_thread_info(next)->pcb.asn = mmc & HARDWARE_ASN_MASK;
	/*
	 * Always update the PCB PTBR. If next is kernel thread, it must
	 * update PTBR. If next is user process, it's ok to update PTBR.
	 */
	task_thread_info(next)->pcb.ptbr = virt_to_pfn(next_mm->pgd);
	load_asn_ptbr(task_thread_info(next)->pcb.asn, task_thread_info(next)->pcb.ptbr);
}

extern void __load_new_mm_context(struct mm_struct *);

#ifdef CONFIG_SMP
#define check_mmu_context()					\
do {								\
	int cpu = smp_processor_id();				\
	cpu_data[cpu].asn_lock = 0;				\
	barrier();						\
	if (cpu_data[cpu].need_new_asn) {			\
		struct mm_struct *mm = current->active_mm;	\
		cpu_data[cpu].need_new_asn = 0;			\
		if (!mm->context.asid[cpu])			\
			__load_new_mm_context(mm);		\
	}							\
} while (0)
#else
#define check_mmu_context()  do { } while (0)
#endif

static inline void activate_mm(struct mm_struct *prev_mm,
			       struct mm_struct *next_mm)
{
	__load_new_mm_context(next_mm);
}

#define deactivate_mm(tsk, mm)	do { } while (0)

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	int i;

	for_each_possible_cpu(i)
		mm->context.asid[i] = 0;
	if (tsk != current)
		task_thread_info(tsk)->pcb.ptbr = virt_to_pfn(mm->pgd);
	return 0;
}

static inline void destroy_context(struct mm_struct *mm)
{
	/* Nothing to do.  */
}

static inline void enter_lazy_tlb(struct mm_struct *mm,
				  struct task_struct *tsk)
{
	task_thread_info(tsk)->pcb.ptbr = virt_to_pfn(mm->pgd);
}

static inline int arch_dup_mmap(struct mm_struct *oldmm,
				struct mm_struct *mm)
{
	return 0;
}

static inline void arch_exit_mmap(struct mm_struct *mm)
{
}

static inline void arch_unmap(struct mm_struct *mm, unsigned long start,
				unsigned long end)
{
}

static inline void arch_bprm_mm_init(struct mm_struct *mm,
				     struct vm_area_struct *vma)
{
}

static inline bool arch_vma_access_permitted(struct vm_area_struct *vma,
					     bool write, bool execute,
					     bool foreign)
{
	/* by default, allow everything */
	return true;
}
#endif /* _ASM_SW64_MMU_CONTEXT_H */
