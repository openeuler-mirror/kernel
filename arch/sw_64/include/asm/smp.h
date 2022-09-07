/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_SMP_H
#define _ASM_SW64_SMP_H

#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/bitops.h>
#include <asm/hmcall.h>
#include <asm/hcall.h>
#include <asm/core.h>
#include <asm/hw_init.h>

/* HACK: Cabrio WHAMI return value is bogus if more than 8 bits used.. :-( */

extern cpumask_t core_start;

static inline unsigned char
__hard_smp_processor_id(void)
{
	register unsigned char __r0 __asm__("$0");
	__asm__ __volatile__(
		"sys_call %1 #whami"
		: "=r"(__r0)
		: "i" (HMC_whami)
		: "$1", "$22", "$23", "$24", "$25");
	return __r0;
}

static inline unsigned long
read_vpcr(void)
{
	register unsigned long __r0 __asm__("$0");
	__asm__ __volatile__(
		"sys_call %1 #rvpcr"
		: "=r"(__r0)
		: "i" (0x39)
		: "$1", "$22", "$23", "$24", "$25");
	return __r0;
}

#ifdef CONFIG_SMP
/* SMP initialization hook for setup_arch */
void __init setup_smp(void);

#include <asm/irq.h>

/* smp reset control block */
struct smp_rcb_struct {
	void (*restart_entry)(unsigned long args);
	unsigned long restart_args;
	unsigned long ready;
	unsigned long init_done;
};

#define INIT_SMP_RCB ((struct smp_rcb_struct *) __va(0x820000UL))

#define hard_smp_processor_id()	__hard_smp_processor_id()
#define raw_smp_processor_id()	(current_thread_info()->cpu)

/* The map from sequential logical cpu number to hard cid.  */
extern int __cpu_to_rcid[NR_CPUS];
#define cpu_to_rcid(cpu)  __cpu_to_rcid[cpu]

/*
 * Map from hard cid to sequential logical cpu number.  This will only
 * not be idempotent when cpus failed to come on-line.
 */
extern int __rcid_to_cpu[NR_CPUS];
#define rcid_to_cpu(cpu)  __rcid_to_cpu[cpu]
#define cpu_physical_id(cpu)    __cpu_to_rcid[cpu]

extern unsigned long tidle_pcb[NR_CPUS];

struct smp_ops {
	void (*smp_prepare_boot_cpu)(void);
	void (*smp_prepare_cpus)(unsigned int max_cpus);
	void (*smp_cpus_done)(unsigned int max_cpus);

	void (*stop_other_cpus)(int wait);
	void (*smp_send_reschedule)(int cpu);

	int (*cpu_up)(unsigned int cpu, struct task_struct *tidle);
	int (*cpu_disable)(void);
	void (*cpu_die)(unsigned int cpu);
	void (*play_dead)(void);

	void (*send_call_func_ipi)(const struct cpumask *mask);
	void (*send_call_func_single_ipi)(int cpu);
};

extern struct smp_ops smp_ops;

static inline void smp_send_stop(void)
{
	smp_ops.stop_other_cpus(0);
}

static inline void stop_other_cpus(void)
{
	smp_ops.stop_other_cpus(1);
}

static inline void smp_prepare_boot_cpu(void)
{
	smp_ops.smp_prepare_boot_cpu();
}

static inline void smp_prepare_cpus(unsigned int max_cpus)
{
	smp_ops.smp_prepare_cpus(max_cpus);
}

static inline void smp_cpus_done(unsigned int max_cpus)
{
	smp_ops.smp_cpus_done(max_cpus);
}

static inline int __cpu_up(unsigned int cpu, struct task_struct *tidle)
{
	return smp_ops.cpu_up(cpu, tidle);
}

static inline int __cpu_disable(void)
{
	return smp_ops.cpu_disable();
}

static inline void __cpu_die(unsigned int cpu)
{
	smp_ops.cpu_die(cpu);
}

static inline void play_dead(void)
{
	smp_ops.play_dead();
}

static inline void smp_send_reschedule(int cpu)
{
	smp_ops.smp_send_reschedule(cpu);
}

static inline void arch_send_call_function_single_ipi(int cpu)
{
	smp_ops.send_call_func_single_ipi(cpu);
}

static inline void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	smp_ops.send_call_func_ipi(mask);
}


#else /* CONFIG_SMP */
static inline void play_dead(void)
{
	BUG(); /*Fixed me*/
}
#define hard_smp_processor_id()		0
#define smp_call_function_on_cpu(func, info, wait, cpu)    ({ 0; })
#define cpu_to_rcid(cpu)	((int)whami())
#define rcid_to_cpu(rcid)	0
#endif /* CONFIG_SMP */

#define NO_PROC_ID	(-1)

static inline void send_ipi(int cpu, unsigned long type)
{
	int rcid;

	rcid = cpu_to_rcid(cpu);

	if (is_in_guest())
		hcall(HCALL_IVI, rcid, type, 0);
	else
		sendii(rcid, type, 0);
}

#define reset_cpu(cpu)  send_ipi((cpu), II_RESET)

#endif /* _ASM_SW64_SMP_H */
