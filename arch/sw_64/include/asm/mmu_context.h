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
 * Load a mm context. This is needed when we change the page
 * table pointer(CSR:PTBR) or when we update the ASID.
 *
 */
#define load_asn_ptbr   load_mm

/*
 * The maximum ASN's the processor supports. ASN is called ASID too.
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
#define cpu_last_asn(cpuid)	(cpu_data[cpuid].last_asn)

#define ASN_FIRST_VERSION	(1UL << WIDTH_HARDWARE_ASN)
#define HARDWARE_ASN_MASK	((1UL << WIDTH_HARDWARE_ASN) - 1)

/*
 * NOTE! The way this is set up, the high bits of the "asn_cache" (and
 * the "mm->context") are the ASN _version_ code. A version of 0 is
 * always considered invalid, so to invalidate another process you only
 * need to do "p->mm->context = 0".
 *
 * If we need more ASN's than the processor has, we invalidate the old
 * user TLB's (tbivp()) and start a new ASN version. That will automatically
 * force a new asn for any other processes the next time they want to
 * run.
 */

static inline unsigned long
__get_new_mm_context(struct mm_struct *mm, long cpu)
{
	unsigned long asn = cpu_last_asn(cpu);
	unsigned long next = asn + 1;

	if ((asn & HARDWARE_ASN_MASK) >= HARDWARE_ASN_MASK) {
		tbivp();
		next = (asn & ~HARDWARE_ASN_MASK) + ASN_FIRST_VERSION;
	}
	cpu_last_asn(cpu) = next;
	return next;
}

static inline void
switch_mm_irqs_off(struct mm_struct *prev_mm, struct mm_struct *next_mm,
		   struct task_struct *next)
{
	/* Check if our ASN is of an older version, and thus invalid. */
	unsigned long asn, mmc, ptbr;
	long cpu = smp_processor_id();

	asn = cpu_last_asn(cpu);
	mmc = next_mm->context.asid[cpu];
	if ((mmc ^ asn) & ~HARDWARE_ASN_MASK) {
		/* Check if mmc and cpu asn is in the same version */
		mmc = __get_new_mm_context(next_mm, cpu);
		next_mm->context.asid[cpu] = mmc;
	}

	/*
	 * Update CSR:UPN and CSR:PTBR. Another thread may have allocated
	 * a new mm->context[asid] (via flush_tlb_mm) without the ASN serial
	 * number wrapping.  We have no way to detect when this is needed.
	 */
	asn = mmc & HARDWARE_ASN_MASK;
	ptbr = virt_to_pfn(next_mm->pgd);
	load_asn_ptbr(asn, ptbr);
}

#define switch_mm_irqs_off switch_mm_irqs_off

static inline void
switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
	  struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	switch_mm_irqs_off(prev_mm, next_mm, tsk);
	local_irq_restore(flags);
}

#define activate_mm(prev, next) switch_mm(prev, next, current)
#define deactivate_mm(tsk, mm)	do { } while (0)

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	int i;

	for_each_possible_cpu(i)
		mm->context.asid[i] = 0;
	return 0;
}

static inline void destroy_context(struct mm_struct *mm)
{
	/* Nothing to do.  */
}

static inline void enter_lazy_tlb(struct mm_struct *mm,
				  struct task_struct *tsk)
{
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
