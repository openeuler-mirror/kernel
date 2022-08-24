// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/arch/sw_64/kernel/smp.c
 */

#include <linux/errno.h>
#include <linux/sched/mm.h>
#include <linux/sched/hotplug.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/cpu.h>

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/sw64_init.h>
#include <asm/topology.h>

#include "proto.h"

struct smp_rcb_struct *smp_rcb;

extern struct cpuinfo_sw64 cpu_data[NR_CPUS];

int smp_booted;

#define smp_debug 0
#define DBGS(fmt, arg...) \
	do { if (smp_debug) printk("SMP: " fmt, ## arg); } while (0)

int __cpu_to_rcid[NR_CPUS];		/* Map logical to physical */
EXPORT_SYMBOL(__cpu_to_rcid);

int __rcid_to_cpu[NR_CPUS];		/* Map physical to logical */
EXPORT_SYMBOL(__rcid_to_cpu);

void *tidle_ksp[NR_CPUS];

/* State of each CPU */
DEFINE_PER_CPU(int, cpu_state) = { 0 };

/* A collection of single bit ipi messages.  */
static struct {
	unsigned long bits ____cacheline_aligned;
} ipi_data[NR_CPUS] __cacheline_aligned;

enum ipi_message_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
	IPI_CPU_STOP,
};

/* Set to a secondary's cpuid when it comes online.  */
static int smp_secondary_alive;

int smp_num_cpus = 1;		/* Number that came online.  */
EXPORT_SYMBOL(smp_num_cpus);

#define send_sleep_interrupt(cpu)	send_ipi((cpu), II_SLEEP)
#define send_wakeup_interrupt(cpu)	send_ipi((cpu), II_WAKE)


static void __init wait_boot_cpu_to_stop(int cpuid)
{
	unsigned long stop = jiffies + 10*HZ;

	while (time_before(jiffies, stop)) {
		if (!smp_secondary_alive)
			return;
		barrier();
	}

	printk("%s: FAILED on CPU %d, hanging now\n", __func__, cpuid);
	for (;;)
		barrier();
}

void __weak enable_chip_int(void) { }

/*
 * Where secondaries begin a life of C.
 */
void smp_callin(void)
{
	int cpuid = smp_processor_id();

	local_irq_disable();

	enable_chip_int();

	if (cpu_online(cpuid)) {
		printk("??, cpu 0x%x already present??\n", cpuid);
		BUG();
	}
	set_cpu_online(cpuid, true);

	/* clear ksp, usp  */
	wrksp(0);
	wrusp(0);

	/* Set trap vectors.  */
	trap_init();

	/* Set interrupt vector.  */
	wrent(entInt, 0);

	/* Get our local ticker going. */
	setup_timer();

	/* All kernel threads share the same mm context.  */
	mmgrab(&init_mm);
	current->active_mm = &init_mm;
	/* update csr:ptbr */
	wrptbr(virt_to_phys(init_mm.pgd));

	/* inform the notifiers about the new cpu */
	notify_cpu_starting(cpuid);

	per_cpu(cpu_state, cpuid) = CPU_ONLINE;
	per_cpu(hard_node_id, cpuid) = cpu_to_rcid(cpuid) >> CORES_PER_NODE_SHIFT;

	/* Must have completely accurate bogos.  */
	local_irq_enable();

	/* Wait boot CPU to stop with irq enabled before running
	 * calibrate_delay.
	 */
	wait_boot_cpu_to_stop(cpuid);
	mb();

	/* Allow master to continue only after we written loops_per_jiffy.  */
	wmb();
	smp_secondary_alive = 1;

	DBGS("%s: commencing CPU %d (RCID: %d)current %p active_mm %p\n",
		__func__, cpuid, cpu_to_rcid(cpuid), current, current->active_mm);

	/* Cpu0 init preempt_count at start_kernel, other smp cpus do here. */
	preempt_disable();

	cpu_startup_entry(CPUHP_AP_ONLINE_IDLE);
}


/*
 * Set ready for secondary cpu.
 */
static inline void set_secondary_ready(int cpuid)
{
	smp_rcb->ready = cpuid;
}

/*
 * Convince the hmcode to have a secondary cpu begin execution.
 */
static int secondary_cpu_start(int cpuid, struct task_struct *idle)
{
	unsigned long timeout;
	/*
	 * Precalculate the target ksp.
	 */
	tidle_ksp[cpuid] = idle->stack + THREAD_SIZE;

	DBGS("Starting secondary cpu %d: state 0x%lx\n", cpuid, idle->state);

	set_cpu_online(cpuid, false);
	wmb();

	set_secondary_ready(cpuid);

	/* Wait 10 seconds for secondary cpu.  */
	timeout = jiffies + 10*HZ;
	while (time_before(jiffies, timeout)) {
		if (cpu_online(cpuid))
			goto started;
		udelay(10);
		barrier();
	}
	pr_err("SMP: Processor %d failed to start.\n", cpuid);
	return -1;

started:
	DBGS("%s: SUCCESS for CPU %d!!!\n", __func__, cpuid);
	store_cpu_topology(cpuid);
	numa_add_cpu(cpuid);
	return 0;
}

/*
 * Bring one cpu online.
 */
static int smp_boot_one_cpu(int cpuid, struct task_struct *idle)
{
	unsigned long timeout;

	/* Signal the secondary to wait a moment.  */
	smp_secondary_alive = -1;

	per_cpu(cpu_state, cpuid) = CPU_UP_PREPARE;

	/* Whirrr, whirrr, whirrrrrrrrr... */
	if (secondary_cpu_start(cpuid, idle))
		return -1;

	/* Notify the secondary CPU it can run calibrate_delay.  */
	mb();
	smp_secondary_alive = 0;

	/* We've been acked by the console; wait one second for
	 * the task to start up for real.
	 */
	timeout = jiffies + 1*HZ;
	while (time_before(jiffies, timeout)) {
		if (smp_secondary_alive == 1)
			goto alive;
		udelay(10);
		barrier();
	}

	/* We failed to boot the CPU.  */

	pr_err("SMP: Processor %d is stuck.\n", cpuid);
	return -1;

alive:
	/* Another "Red Snapper". */
	return 0;
}

static void __init process_nr_cpu_ids(void)
{
	int i;

	for (i = nr_cpu_ids; i < NR_CPUS; i++) {
		set_cpu_possible(i, false);
		set_cpu_present(i, false);
	}

	nr_cpu_ids = num_possible_cpus();
}

void __init smp_rcb_init(void)
{
	smp_rcb = INIT_SMP_RCB;
	memset(smp_rcb, 0, sizeof(struct smp_rcb_struct));
	/* Setup SMP_RCB fields that uses to activate secondary CPU */
	smp_rcb->restart_entry = __smp_callin;
	smp_rcb->init_done = 0xDEADBEEFUL;
	mb();
}

/*
 * Called from setup_arch.  Detect an SMP system and which processors
 * are present.
 */
void __init setup_smp(void)
{
	int i = 0, num = 0; /* i: physical id, num: logical id */

	init_cpu_possible(cpu_none_mask);

	/* For unified kernel, NR_CPUS is the maximum possible value */
	for (; i < NR_CPUS; i++) {
		if (cpumask_test_cpu(i, &core_start)) {
			__cpu_to_rcid[num] = i;
			__rcid_to_cpu[i] = num;
			set_cpu_possible(num, true);
			store_cpu_data(num);
			if (!cpumask_test_cpu(i, &cpu_offline))
				set_cpu_present(num, true);
			num++;
		} else
			__rcid_to_cpu[i] = -1;
	}
	/* for sw64, the BSP must be logical core 0 */
	BUG_ON(cpu_to_rcid(0) != hard_smp_processor_id());

	while (num < NR_CPUS) {
		__cpu_to_rcid[num] = -1;
		num++;
	}

	process_nr_cpu_ids();

	pr_info("Detected %u possible CPU(s), %u CPU(s) are present\n",
			nr_cpu_ids, num_present_cpus());

	smp_rcb_init();
}
/*
 * Called by smp_init prepare the secondaries
 */
void __init native_smp_prepare_cpus(unsigned int max_cpus)
{
	unsigned int cpu;
	/* Take care of some initial bookkeeping.  */
	memset(ipi_data, 0, sizeof(ipi_data));

	init_cpu_topology();
	current_thread_info()->cpu = 0;
	store_cpu_topology(smp_processor_id());
	numa_add_cpu(smp_processor_id());

	for_each_possible_cpu(cpu) {
		numa_store_cpu_info(cpu);
	}

	/* Nothing to do on a UP box, or when told not to.  */
	if (nr_cpu_ids == 1 || max_cpus == 0) {
		init_cpu_possible(cpumask_of(0));
		init_cpu_present(cpumask_of(0));
		pr_info("SMP mode deactivated.\n");
		return;
	}

	pr_info("SMP starting up secondaries.\n");
}

void  native_smp_prepare_boot_cpu(void)
{
	int me = smp_processor_id();

	per_cpu(cpu_state, me) = CPU_ONLINE;
}

int native_vt_cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	printk("%s: cpu = %d\n", __func__, cpu);

	wmb();
	smp_rcb->ready = 0;
	smp_boot_one_cpu(cpu, tidle);

	return cpu_online(cpu) ? 0 : -ENOSYS;
}

DECLARE_STATIC_KEY_FALSE(use_tc_as_sched_clock);
int native_cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	if (is_in_guest())
		return native_vt_cpu_up(cpu, tidle);

	wmb();
	smp_rcb->ready = 0;

#ifdef CONFIG_SW64_SUSPEND_DEEPSLEEP_NONBOOT_CORE
	/* send wake up signal */
	send_wakeup_interrupt(cpu);
#endif
	/* send reset signal */
	if (smp_booted) {
		if (is_in_host()) {
			reset_cpu(cpu);
		} else {
			while (1) {
				cpu_relax();
			}
		}
	}
	smp_boot_one_cpu(cpu, tidle);

#ifdef CONFIG_SW64_SUSPEND_DEEPSLEEP_NONBOOT_CORE
	if (static_branch_likely(&use_tc_as_sched_clock)) {
		if (smp_booted) {
			tc_sync_clear();
			smp_call_function_single(cpu, tc_sync_ready, NULL, 0);
			tc_sync_set();
		}
	}
#endif

	return cpu_online(cpu) ? 0 : -ENOSYS;
}

void __init native_smp_cpus_done(unsigned int max_cpus)
{
	smp_booted = 1;
	pr_info("SMP: Total of %d processors activated.\n", num_online_cpus());
}

int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
}


static void send_ipi_message(const struct cpumask *to_whom, enum ipi_message_type operation)
{
	int i;

	mb();
	for_each_cpu(i, to_whom)
		set_bit(operation, &ipi_data[i].bits);

	mb();
	for_each_cpu(i, to_whom)
		send_ipi(i, II_II0);
}

void handle_ipi(struct pt_regs *regs)
{
	int this_cpu = smp_processor_id();
	unsigned long *pending_ipis = &ipi_data[this_cpu].bits;
	unsigned long ops;

	mb();	/* Order interrupt and bit testing. */
	while ((ops = xchg(pending_ipis, 0)) != 0) {
		mb();	/* Order bit clearing and data access. */
		do {
			unsigned long which;

			which = ops & -ops;
			ops &= ~which;
			which = __ffs(which);

			switch (which) {
			case IPI_RESCHEDULE:
				scheduler_ipi();
				break;

			case IPI_CALL_FUNC:
				irq_enter();
				generic_smp_call_function_interrupt();
				irq_exit();
				break;

			case IPI_CPU_STOP:
				local_irq_disable();
				pr_crit("other core panic, now halt...\n");
				while (1)
					asm("nop");
				halt();

			default:
				pr_crit("Unknown IPI on CPU %d: %lu\n", this_cpu, which);
				break;
			}
		} while (ops);

		mb();	/* Order data access and bit testing. */
	}

	cpu_data[this_cpu].ipi_count++;
}

void native_smp_send_reschedule(int cpu)
{
#ifdef DEBUG_IPI_MSG
	if (cpu == hard_smp_processor_id())
		pr_warn("smp_send_reschedule: Sending IPI to self.\n");
#endif
	send_ipi_message(cpumask_of(cpu), IPI_RESCHEDULE);
}

static void native_stop_other_cpus(int wait)
{
	cpumask_t to_whom;

	cpumask_copy(&to_whom, cpu_possible_mask);
	cpumask_clear_cpu(smp_processor_id(), &to_whom);
#ifdef DEBUG_IPI_MSG
	if (hard_smp_processor_id() != boot_cpu_id)
		pr_warn("smp_send_stop: Not on boot cpu.\n");
#endif
	send_ipi_message(&to_whom, IPI_CPU_STOP);

}

void native_send_call_func_ipi(const struct cpumask *mask)
{
	send_ipi_message(mask, IPI_CALL_FUNC);
}

void native_send_call_func_single_ipi(int cpu)
{
	send_ipi_message(cpumask_of(cpu), IPI_CALL_FUNC);
}

static void ipi_flush_tlb_all(void *ignored)
{
	tbiv();
}

void flush_tlb_all(void)
{
	/* Although we don't have any data to pass, we do want to
	 * synchronize with the other processors.
	 */
	on_each_cpu(ipi_flush_tlb_all, NULL, 1);
}

static void ipi_flush_tlb_mm(void *x)
{
	struct mm_struct *mm = (struct mm_struct *) x;

	if (mm == current->mm)
		flush_tlb_current(mm);
	else
		flush_tlb_other(mm);
}

void flush_tlb_mm(struct mm_struct *mm)
{
	preempt_disable();

	/* happens as a result of exit_mmap()
	 * Shall we clear mm->context.asid[] here?
	 */
	if (atomic_read(&mm->mm_users) == 0) {
		preempt_enable();
		return;
	}

	if (mm == current->mm) {
		flush_tlb_current(mm);
		if (atomic_read(&mm->mm_users) == 1) {
			int cpu, this_cpu = smp_processor_id();

			for (cpu = 0; cpu < NR_CPUS; cpu++) {
				if (!cpu_online(cpu) || cpu == this_cpu)
					continue;
				if (mm->context.asid[cpu])
					mm->context.asid[cpu] = 0;
			}
			preempt_enable();
			return;
		}
	} else
		flush_tlb_other(mm);

	smp_call_function(ipi_flush_tlb_mm, mm, 1);

	preempt_enable();
}
EXPORT_SYMBOL(flush_tlb_mm);

struct flush_tlb_page_struct {
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long addr;
};

static void ipi_flush_tlb_page(void *x)
{
	struct flush_tlb_page_struct *data = (struct flush_tlb_page_struct *)x;
	struct mm_struct *mm = data->mm;

	if (mm == current->mm)
		flush_tlb_current_page(mm, data->vma, data->addr);
	else
		flush_tlb_other(mm);

}

void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr)
{
	struct flush_tlb_page_struct data;
	struct mm_struct *mm = vma->vm_mm;

	preempt_disable();

	if (mm == current->mm) {
		flush_tlb_current_page(mm, vma, addr);
		if (atomic_read(&mm->mm_users) == 1) {
			int cpu, this_cpu = smp_processor_id();

			for (cpu = 0; cpu < NR_CPUS; cpu++) {
				if (!cpu_online(cpu) || cpu == this_cpu)
					continue;
				if (mm->context.asid[cpu])
					mm->context.asid[cpu] = 0;
			}
			preempt_enable();
			return;
		}
	} else
		flush_tlb_other(mm);

	data.vma = vma;
	data.mm = mm;
	data.addr = addr;

	smp_call_function(ipi_flush_tlb_page, &data, 1);

	preempt_enable();
}
EXPORT_SYMBOL(flush_tlb_page);

void flush_tlb_range(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	/* On the SW we always flush the whole user tlb.  */
	flush_tlb_mm(vma->vm_mm);
}
EXPORT_SYMBOL(flush_tlb_range);

int native_cpu_disable(void)
{
	int cpu = smp_processor_id();

	set_cpu_online(cpu, false);
	remove_cpu_topology(cpu);
	numa_remove_cpu(cpu);
#ifdef CONFIG_HOTPLUG_CPU
	clear_tasks_mm_cpumask(cpu);
#endif
	return 0;
}

void native_cpu_die(unsigned int cpu)
{
	/* We don't do anything here: idle task is faking death itself. */
	unsigned int i;

	for (i = 0; i < 10; i++) {
		/* They ack this in play_dead by setting CPU_DEAD */
		if (per_cpu(cpu_state, cpu) == CPU_DEAD) {
			if (system_state == SYSTEM_RUNNING)
				pr_info("CPU %u is now offline\n", cpu);
			return;
		}
		msleep(100);
	}
	pr_err("CPU %u didn't die...\n", cpu);
}

static void disable_timer(void)
{
	if (is_in_guest())
		hcall(HCALL_SET_CLOCKEVENT, 0, 0, 0);
	else
		wrtimer(0);
}

void native_play_dead(void)
{
	idle_task_exit();
	mb();
	__this_cpu_write(cpu_state, CPU_DEAD);
#ifdef CONFIG_HOTPLUG_CPU
	fixup_irqs();
#endif
	local_irq_disable();

	disable_timer();

	if (is_in_guest())
		hcall(HCALL_STOP, 0, 0, 0);

#ifdef CONFIG_SUSPEND

#ifdef CONFIG_SW64_SUSPEND_DEEPSLEEP_NONBOOT_CORE
	sleepen();
	send_sleep_interrupt(smp_processor_id());
	while (1)
		asm("nop");
#else
	asm volatile("halt");
	while (1)
		asm("nop");
#endif /* SW64_SUSPEND_DEEPSLEEP */


#else
	asm volatile("memb");
	asm volatile("halt");
#endif
}

struct smp_ops smp_ops = {
	.smp_prepare_boot_cpu	= native_smp_prepare_boot_cpu,
	.smp_prepare_cpus	= native_smp_prepare_cpus,
	.smp_cpus_done		= native_smp_cpus_done,

	.stop_other_cpus	= native_stop_other_cpus,
	.smp_send_reschedule	= native_smp_send_reschedule,

	.cpu_up			= native_cpu_up,
	.cpu_die		= native_cpu_die,
	.cpu_disable		= native_cpu_disable,
	.play_dead		= native_play_dead,

	.send_call_func_ipi	= native_send_call_func_ipi,
	.send_call_func_single_ipi = native_send_call_func_single_ipi,
};
EXPORT_SYMBOL_GPL(smp_ops);
