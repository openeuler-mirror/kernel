// SPDX-License-Identifier: GPL-2.0
/*
 * This file handles the architecture-dependent parts of process handling.
 */

#include <linux/sched/debug.h>
#include <linux/ptrace.h>
#include <linux/elfcore.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/random.h>

#include <asm/fpu.h>
#include <asm/switch_to.h>

#include "proto.h"

/*
 * Power off function, if any
 */
void (*pm_power_off)(void) = machine_power_off;
EXPORT_SYMBOL(pm_power_off);

struct halt_info {
	int mode;
	char *restart_cmd;
};

#ifdef CONFIG_HOTPLUG_CPU
void arch_cpu_idle_dead(void)
{
	play_dead();
}
#endif

void arch_cpu_idle(void)
{
	int i;

	local_irq_enable();
	cpu_relax();

	if (is_in_guest())
		hcall(HCALL_HALT, 0, 0, 0);
	else {
		for (i = 0; i < 16; i++)
			asm("nop");
		asm("halt");
	}
}

static void common_shutdown_1(void *generic_ptr)
{
	struct halt_info *how = (struct halt_info *)generic_ptr;
	int cpuid __maybe_unused = smp_processor_id();

	/* No point in taking interrupts anymore. */
	local_irq_disable();

#ifdef CONFIG_SMP
	/* Secondaries halt here. */
	if (cpuid != 0) {
		set_cpu_present(cpuid, false);
		set_cpu_possible(cpuid, false);

		if (is_in_guest()) {
			hcall(HCALL_SET_CLOCKEVENT, 0, 0, 0);
			while (1)
				asm("nop");
		} else
			asm("halt");
	}
#endif
	if (sw64_platform->kill_arch)
		sw64_platform->kill_arch(how->mode);
}

static void common_shutdown(int mode, char *restart_cmd)
{
	struct halt_info args;

	args.mode = mode;
	args.restart_cmd = restart_cmd;
	on_each_cpu(common_shutdown_1, &args, 0);
}

void machine_restart(char *restart_cmd)
{
	common_shutdown(LINUX_REBOOT_CMD_RESTART, restart_cmd);
}


void machine_halt(void)
{
	common_shutdown(LINUX_REBOOT_CMD_HALT, NULL);
}


void machine_power_off(void)
{
	common_shutdown(LINUX_REBOOT_CMD_POWER_OFF, NULL);
}


/*
 * Re-start a thread when doing execve()
 */
void
start_thread(struct pt_regs *regs, unsigned long pc, unsigned long sp)
{
	regs->pc = pc;
	regs->ps = 8;
	wrusp(sp);
}
EXPORT_SYMBOL(start_thread);


void
flush_thread(void)
{
	/* Arrange for each exec'ed process to start off with a clean slate
	 * with respect to the FPU.  This is all exceptions disabled.
	 */
	current_thread_info()->ieee_state = 0;
	wrfpcr(FPCR_DYN_NORMAL | ieee_swcr_to_fpcr(0));

	/* Clean slate for TLS.  */
	current_thread_info()->pcb.tp = 0;
}

void
release_thread(struct task_struct *dead_task)
{
}

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	/*
	 * aux_save() has to read the current TLS pointer from CSR:TID as it
	 * may be out-of-sync with the saved value.
	 */
	aux_save(src);
	*dst = *src;
	return 0;
}

/*
 * Copy architecture-specific thread state
 */

int
copy_thread(unsigned long clone_flags, unsigned long usp,
	   unsigned long kthread_arg, struct task_struct *p,
	   unsigned long tls)
{
	extern void ret_from_fork(void);
	extern void ret_from_kernel_thread(void);

	struct thread_info *childti = task_thread_info(p);
	struct pt_regs *childregs = task_pt_regs(p);
	struct pt_regs *regs = current_pt_regs();

	p->thread.sp = (unsigned long) childregs;

	if (unlikely(p->flags & PF_KTHREAD)) {
		/* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		p->thread.ra = (unsigned long) ret_from_kernel_thread;
		p->thread.s[0] = usp;	/* function */
		p->thread.s[1] = kthread_arg;
		childti->pcb.usp = 0;
		return 0;
	}

	/*
	 * Note: if CLONE_SETTLS is not set, then we must inherit the
	 * value from the parent, which will have been set by the block
	 * copy in dup_task_struct.  This is non-intuitive, but is
	 * required for proper operation in the case of a threaded
	 * application calling fork.
	 */
	if (clone_flags & CLONE_SETTLS)
		childti->pcb.tp = regs->r20;
	else
		regs->r20 = 0;
	if (usp)
		childti->pcb.usp = usp;
	*childregs = *regs;
	childregs->r0 = 0;
	childregs->r19 = 0;
	p->thread.ra = (unsigned long) ret_from_fork;
	return 0;
}

/*
 * Fill in the user structure for a ELF core dump.
 * @regs: should be signal_pt_regs() or task_pt_reg(task)
 */
void sw64_elf_core_copy_regs(elf_greg_t *dest, struct pt_regs *regs)
{
	int i;
	struct thread_info *ti;

	ti = (void *)((__u64)regs & ~(THREAD_SIZE - 1));

	for (i = 0; i < 30; i++)
		dest[i] = *(__u64 *)((void *)regs + regoffsets[i]);
	dest[30] = ti == current_thread_info() ? rdusp() : ti->pcb.usp;
	dest[31] = regs->pc;
	dest[32] = ti->pcb.tp;
}
EXPORT_SYMBOL(sw64_elf_core_copy_regs);

/* Fill in the fpu structure for a core dump.  */
int dump_fpu(struct pt_regs *regs, elf_fpregset_t *fpu)
{
	memcpy(fpu, &current->thread.fpstate, sizeof(*fpu));
	return 1;
}
EXPORT_SYMBOL(dump_fpu);

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}
