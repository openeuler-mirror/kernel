// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/extable.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>

#include <asm/mmu_context.h>

__read_mostly bool segv_debug_enabled;

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs, unsigned long mmcsr)
{
	int ret = 0;
	/* kprobe_running() needs smp_processor_id() */
	if (!user_mode(regs)) {
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, mmcsr))
			ret = 1;
		preempt_enable();
	}
	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs, unsigned long mmcsr)
{
	return 0;
}
#endif

extern void die_if_kernel(char *, struct pt_regs *, long);
extern void dik_show_regs(struct pt_regs *regs);

void show_all_vma(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *tmp;

	unsigned long start = 0;
	unsigned long end = 0;
	int i = 0;

	if (mm) {
		tmp = mm->mmap;
		while (tmp) {
			start = tmp->vm_start;
			end = tmp->vm_end;
			if (tmp->vm_file)
				pr_info("vma[%d]: [%#lx, %#lx], len = %#lx, flags = %#lx, file = %s, name = %s\n",
						i, start, end, (end - start), tmp->vm_flags,
						tmp->vm_file->f_path.dentry->d_name.name, current->comm);
			else
				pr_info("vma[%d]: [%#lx, %#lx], len = %#lx, flags = %#lx, name = %s\n",
						i, start, end, (end - start), tmp->vm_flags, current->comm);
			tmp = tmp->vm_next;
			i++;
		}
	}
}

/*
 * Force a new ASN for a task.
 */

#ifndef CONFIG_SMP
unsigned long last_asn = ASN_FIRST_VERSION;
#endif

void
__load_new_mm_context(struct mm_struct *next_mm)
{
	unsigned long mmc;
	struct pcb_struct *pcb;

	mmc = __get_new_mm_context(next_mm, smp_processor_id());
	next_mm->context.asid[smp_processor_id()] = mmc;

	pcb = &current_thread_info()->pcb;
	pcb->asn = mmc & HARDWARE_ASN_MASK;
	pcb->ptbr = virt_to_pfn(next_mm->pgd);

	__reload_thread(pcb);
}


/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to handle_mm_fault().
 *
 * mmcsr:
 *	0 = translation not valid
 *	1 = access violation
 *	2 = fault-on-read
 *	3 = fault-on-execute
 *	4 = fault-on-write
 *
 * cause:
 *	-1 = instruction fetch
 *	0 = load
 *	1 = store
 *
 * Registers $9 through $15 are saved in a block just prior to `regs' and
 * are saved and restored around the call to allow exception code to
 * modify them.
 */

unsigned long show_va_to_pa(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud  = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long ret = 0UL;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd)) {
		ret = 0;
		pr_debug("addr = %#lx, pgd = %#lx\n", addr, pgd_val(*pgd));
		goto out;
	}
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d)) {
		ret = 0;
		pr_debug("addr = %#lx, pgd = %#lx, p4d = %#lx\n",
				addr, pgd_val(*pgd), p4d_val(*p4d));
		goto out;
	}
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud)) {
		ret = 0;
		pr_debug("addr = %#lx, pgd = %#lx, pud = %#lx\n",
				addr, pgd_val(*pgd), pud_val(*pud));
		goto out;
	}
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		ret = 0;
		pr_debug("addr = %#lx, pgd = %#lx, pud = %#lx, pmd = %#lx\n",
				addr, pgd_val(*pgd), pud_val(*pud), pmd_val(*pmd));
		goto out;

	}
	pte = pte_offset_map(pmd, addr);
	if (pte_present(*pte)) {
		ret = (unsigned long)pfn_to_virt(pte_val(*pte) >> _PFN_SHIFT);
		pr_debug("addr = %#lx, pgd = %#lx, pud = %#lx, pmd = %#lx, pte = %#lx, ret = %#lx\n",
				addr, *(unsigned long *)pgd, *(unsigned long *)pud,
				*(unsigned long *)pmd, *(unsigned long *)pte, ret);
	}
out:
	return ret;
}

extern int do_match(unsigned long address, unsigned long mmcsr, long cause, struct pt_regs *regs);

asmlinkage void notrace
do_page_fault(unsigned long address, unsigned long mmcsr,
		long cause, struct pt_regs *regs)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	const struct exception_table_entry *fixup;
	int si_code = SEGV_MAPERR;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	if (notify_page_fault(regs, mmcsr))
		return;

	if (unlikely(mmcsr >= MMCSR__DA_MATCH)) {
		if (do_match(address, mmcsr, cause, regs) == 1)
			return;
	}

	if (unlikely(mmcsr == MMCSR__ACV1)) {
		if (!user_mode(regs))
			goto no_context;
		else {
			down_read(&mm->mmap_lock);
			goto bad_area;
		}
	}

	/*
	 * If we're in an interrupt context, or have no user context,
	 * we must not take the fault.
	 */
	if (!mm || faulthandler_disabled())
		goto no_context;

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;

retry:
	down_read(&mm->mmap_lock);
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;

	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it.
	 */
good_area:
	si_code = SEGV_ACCERR;
	if (cause < 0) {
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
	} else if (!cause) {
		/* Allow reads even for write-only mappings */
		if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
			goto bad_area;
	} else {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, address, flags, NULL);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return;
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1,
					regs, address);
			current->maj_flt++;
		} else {
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1,
					regs, address);
			current->min_flt++;
		}
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;

			 /*
			  * No need to up_read(&mm->mmap_lock) as we would
			  * have already released it in __lock_page_or_retry
			  * in mm/filemap.c.
			  */

			goto retry;
		}
	}

	up_read(&mm->mmap_lock);

	return;

	/*
	 * Something tried to access memory that isn't in our memory map.
	 * Fix it, but check if it's kernel or user first.
	 */
 bad_area:
	up_read(&mm->mmap_lock);

	if (user_mode(regs))
		goto do_sigsegv;

 no_context:
	/* Are we prepared to handle this fault as an exception?  */
	fixup = search_exception_tables(regs->pc);
	if (fixup != 0) {
		unsigned long newpc;

		newpc = fixup_exception(map_regs, fixup, regs->pc);
		regs->pc = newpc;
		return;
	}

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	pr_alert("Unable to handle kernel paging request at virtual address %016lx\n",
	       address);
	die_if_kernel("Oops", regs, cause);
	do_exit(SIGKILL);

	/*
	 * We ran out of memory, or some other thing happened to us that
	 * made us unable to handle the page fault gracefully.
	 */
 out_of_memory:
	up_read(&mm->mmap_lock);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

 do_sigbus:
	up_read(&mm->mmap_lock);
	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address, 0);
	if (!user_mode(regs))
		goto no_context;
	return;

 do_sigsegv:
	force_sig_fault(SIGSEGV, si_code, (void __user *) address, 0);

	if (unlikely(segv_debug_enabled)) {
		pr_info("fault: want to send_segv: pid %d, cause = %#lx, mmcsr = %#lx, address = %#lx, pc %#lx\n",
				current->pid, cause, mmcsr, address, regs->pc);
		dik_show_regs(regs);
		show_all_vma();
	}

	return;
}
