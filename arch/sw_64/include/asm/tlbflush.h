/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_TLBFLUSH_H
#define _ASM_SW64_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/compiler.h>
#include <asm/pgalloc.h>
#include <asm/hw_init.h>
#include <asm/hmcall.h>

extern void __load_new_mm_context(struct mm_struct *);


static inline void flush_tlb_current(struct mm_struct *mm)
{
	__load_new_mm_context(mm);
}

/*
 * Flush just one page in the current TLB set.  We need to be very
 * careful about the icache here, there is no way to invalidate a
 * specific icache page.
 */

static inline void flush_tlb_current_page(struct mm_struct *mm,
					  struct vm_area_struct *vma,
					  unsigned long addr)
{
	if (vma->vm_flags & VM_EXEC)
		tbis(addr);
	else
		tbisd(addr);
}


/* Flush current user mapping.  */
static inline void flush_tlb(void)
{
	flush_tlb_current(current->active_mm);
}

/* Flush someone else's user mapping.  */
static inline void flush_tlb_other(struct mm_struct *mm)
{
	unsigned long *mmc;

	if (mm) {
		mmc = &mm->context.asid[smp_processor_id()];
	/*
	 * Check it's not zero first to avoid cacheline ping pong
	 * when possible.
	 */
		if (*mmc)
			*mmc = 0;
	}
}

#ifndef CONFIG_SMP
/*
 * Flush everything (kernel mapping may also have changed
 * due to vmalloc/vfree).
 */
static inline void flush_tlb_all(void)
{
	tbiv();
}

/* Flush a specified user mapping.  */
static inline void
flush_tlb_mm(struct mm_struct *mm)
{
	if (mm == current->mm)
		flush_tlb_current(mm);
	else
		flush_tlb_other(mm);
}

/* Page-granular tlb flush.  */
static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long addr)
{
	struct mm_struct *mm = vma->vm_mm;

	if (mm == current->mm)
		flush_tlb_current_page(mm, vma, addr);
	else
		flush_tlb_other(mm);
}

/*
 * Flush a specified range of user mapping.  On the sw64 we flush
 * the whole user tlb.
 */
static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	flush_tlb_mm(vma->vm_mm);
}

#else /* CONFIG_SMP */

extern void flush_tlb_all(void);
extern void flush_tlb_mm(struct mm_struct *);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);
extern void flush_tlb_range(struct vm_area_struct *, unsigned long,
			    unsigned long);

#endif /* CONFIG_SMP */

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	flush_tlb_all();
}

#endif /* _ASM_SW64_TLBFLUSH_H */
