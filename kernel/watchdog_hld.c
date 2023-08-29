// SPDX-License-Identifier: GPL-2.0
/*
 * Detect hard lockups on a system
 *
 * started by Don Zickus, Copyright (C) 2010 Red Hat, Inc.
 *
 * Note: Most of this code is borrowed heavily from the original softlockup
 * detector, so thanks to Ingo for the initial implementation.
 * Some chunks also taken from the old x86-specific nmi watchdog code, thanks
 * to those contributors as well.
 */

#define pr_fmt(fmt) "NMI watchdog: " fmt

#include <linux/nmi.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched/debug.h>

#include <asm/irq_regs.h>
#include <linux/perf_event.h>

static DEFINE_PER_CPU(bool, hard_watchdog_warn);
static DEFINE_PER_CPU(bool, watchdog_nmi_touch);

static unsigned long hardlockup_allcpu_dumped;

#ifndef CONFIG_PPC
notrace void __weak arch_touch_nmi_watchdog(void)
{
	/*
	 * Using __raw here because some code paths have
	 * preemption enabled.  If preemption is enabled
	 * then interrupts should be enabled too, in which
	 * case we shouldn't have to worry about the watchdog
	 * going off.
	 */
	raw_cpu_write(watchdog_nmi_touch, true);
}
EXPORT_SYMBOL(arch_touch_nmi_watchdog);
#endif

#ifdef CONFIG_CORELOCKUP_DETECTOR
/*
 * The softlockup and hardlockup detector only check the status
 * of the cpu which it resides. If certain cpu core suspends,
 * they are both not works. There is no any valid log but the
 * cpu already abnormal and brings a lot of problems of system.
 * To detect this case, we add the corelockup detector.
 *
 * First we use whether cpu core can responds to nmi  as a sectence
 * to determine if it is suspended. Then things is simple. Per cpu
 * core maintains it's nmi interrupt counts and detector the
 * nmi_counts of next cpu core. If the nmi interrupt counts not
 * changed any more which means it can't respond nmi normally, we
 * regard it as suspend.
 *
 * To ensure robustness, only consecutive lost nmi more than two
 * times then trigger the warn.
 *
 * The detection chain is as following:
 * cpu0->cpu1->...->cpuN->cpu0
 *
 * When using pmu events as nmi source, the pmu clock is disabled
 * under wfi/wfe mode. And the nmi can't respond periodically.
 * To minimize the misjudgment by wfi/wfe, we adopt a simple method
 * which to disable wfi/wfe at the right time and the watchdog hrtimer
 * is a good baseline.
 *
 * The watchdog hrtimer is based on generate timer and has high freq
 * than nmi. If watchdog hrtimer not works we disable wfi/wfe mode
 * then the pmu nmi should always responds as long as the cpu core
 * not suspend.
 *
 * detector_cpu: the target cpu to detector of current cpu
 * nmi_interrupts: the nmi counts of current cpu
 * nmi_cnt_saved: saved nmi counts of detector_cpu
 * nmi_cnt_missed: the nmi consecutive miss counts of detector_cpu
 * hrint_saved: saved hrtimer interrupts of detector_cpu
 * hrint_missed: the hrtimer consecutive miss counts of detector_cpu
 * corelockup_cpumask/close_wfi_wfe:
 * the cpu mask is set if certain cpu maybe fall in suspend and close
 * wfi/wfe mode if any bit is set
 */
static DEFINE_PER_CPU(unsigned int, detector_cpu);
static DEFINE_PER_CPU(unsigned long, nmi_interrupts);
static DEFINE_PER_CPU(unsigned long, nmi_cnt_saved);
static DEFINE_PER_CPU(unsigned long, nmi_cnt_missed);
static DEFINE_PER_CPU(bool, core_watchdog_warn);
static DEFINE_PER_CPU(unsigned long, hrint_saved);
static DEFINE_PER_CPU(unsigned long, hrint_missed);
struct cpumask corelockup_cpumask __read_mostly;
unsigned int close_wfi_wfe;
static bool pmu_based_nmi;
bool enable_corelockup_detector;

static int __init enable_corelockup_detector_setup(char *str)
{
	enable_corelockup_detector = true;
	return 1;
}
__setup("enable_corelockup_detector", enable_corelockup_detector_setup);

static void watchdog_nmi_interrupts(void)
{
	__this_cpu_inc(nmi_interrupts);
}

static void corelockup_status_copy(unsigned int from, unsigned int to)
{
	per_cpu(nmi_cnt_saved, to) = per_cpu(nmi_cnt_saved, from);
	per_cpu(nmi_cnt_missed, to) = per_cpu(nmi_cnt_missed, from);
	per_cpu(hrint_saved, to) = per_cpu(hrint_saved, from);
	per_cpu(hrint_missed, to) = per_cpu(hrint_missed, from);

	/* always update detector cpu at the end */
	per_cpu(detector_cpu, to) = per_cpu(detector_cpu, from);
}

static void corelockup_status_init(unsigned int cpu, unsigned int target)
{
	/*
	 * initialize saved count to max to avoid unnecessary misjudge
	 * caused by delay running of nmi on target cpu
	 */
	per_cpu(nmi_cnt_saved, cpu) = ULONG_MAX;
	per_cpu(nmi_cnt_missed, cpu) = 0;
	per_cpu(hrint_saved, cpu) = ULONG_MAX;
	per_cpu(hrint_missed, cpu) = 0;

	/* always update detector cpu at the end */
	per_cpu(detector_cpu, cpu) = target;
}

void __init corelockup_detector_init(void)
{
	unsigned int cpu, next;

	/* detector cpu is set to the next valid logically one */
	for_each_cpu_and(cpu, &watchdog_cpumask, cpu_online_mask) {
		next = cpumask_next_and(cpu, &watchdog_cpumask,
					cpu_online_mask);
		if (next >= nr_cpu_ids)
			next = cpumask_first_and(&watchdog_cpumask,
						 cpu_online_mask);
		corelockup_status_init(cpu, next);
	}
}

void watchdog_check_hrtimer(void)
{
	unsigned int cpu = __this_cpu_read(detector_cpu);
	unsigned long hrint = watchdog_hrtimer_interrupts(cpu);

	/*
	 * The freq of hrtimer is fast than nmi interrupts and
	 * the core mustn't hangs if hrtimer still working.
	 * So update the nmi interrupts in hrtimer either to
	 * improved robustness of nmi counts check.
	 */
	watchdog_nmi_interrupts();

	if (!pmu_based_nmi)
		return;

	if (__this_cpu_read(hrint_saved) != hrint) {
		__this_cpu_write(hrint_saved, hrint);
		__this_cpu_write(hrint_missed, 0);
		cpumask_clear_cpu(cpu, &corelockup_cpumask);
	} else {
		__this_cpu_inc(hrint_missed);
		if (__this_cpu_read(hrint_missed) > 2)
			cpumask_set_cpu(cpu, &corelockup_cpumask);
	}

	if (likely(cpumask_empty(&corelockup_cpumask)))
		close_wfi_wfe = 0;
	else
		close_wfi_wfe = 1;
}

/*
 * Before: first->next
 * After: first->[new]->next
 */
void corelockup_detector_online_cpu(unsigned int cpu)
{
	unsigned int first = cpumask_first_and(&watchdog_cpumask,
					       cpu_online_mask);

	if (WARN_ON(first >= nr_cpu_ids))
		return;

	/* cpu->next */
	corelockup_status_copy(first, cpu);

	/* first->cpu */
	corelockup_status_init(first, cpu);
}

/*
 * Before: prev->cpu->next
 * After: prev->next
 */
void corelockup_detector_offline_cpu(unsigned int cpu)
{
	unsigned int prev = nr_cpu_ids;
	unsigned int i;

	/* clear bitmap */
	cpumask_clear_cpu(cpu, &corelockup_cpumask);

	/* found prev cpu */
	for_each_cpu_and(i, &watchdog_cpumask, cpu_online_mask) {
		if (per_cpu(detector_cpu, i) == cpu) {
			prev = i;
			break;
		}
	}

	if (WARN_ON(prev == nr_cpu_ids))
		return;

	/* prev->next */
	corelockup_status_copy(cpu, prev);
}

static bool is_corelockup(unsigned int cpu)
{
	unsigned long nmi_int = per_cpu(nmi_interrupts, cpu);

	/* skip check if only one cpu online */
	if (cpu == smp_processor_id())
		return false;

	if (__this_cpu_read(nmi_cnt_saved) != nmi_int) {
		__this_cpu_write(nmi_cnt_saved, nmi_int);
		__this_cpu_write(nmi_cnt_missed, 0);
		per_cpu(core_watchdog_warn, cpu) = false;
		return false;
	}

	__this_cpu_inc(nmi_cnt_missed);
	if (__this_cpu_read(nmi_cnt_missed) > 2)
		return true;

	return false;
}
NOKPROBE_SYMBOL(is_corelockup);

static void watchdog_corelockup_check(struct pt_regs *regs)
{
	unsigned int cpu = __this_cpu_read(detector_cpu);

	if (is_corelockup(cpu)) {
		if (per_cpu(core_watchdog_warn, cpu) == true)
			return;
		pr_emerg("Watchdog detected core LOCKUP on cpu %d\n", cpu);

		if (hardlockup_panic)
			nmi_panic(regs, "Core LOCKUP");

		per_cpu(core_watchdog_warn, cpu) = true;
	}
}
#endif

#ifdef CONFIG_HARDLOCKUP_CHECK_TIMESTAMP
static DEFINE_PER_CPU(ktime_t, last_timestamp);
static DEFINE_PER_CPU(unsigned int, nmi_rearmed);
static ktime_t watchdog_hrtimer_sample_threshold __read_mostly;

void watchdog_update_hrtimer_threshold(u64 period)
{
	/*
	 * The hrtimer runs with a period of (watchdog_threshold * 2) / 5
	 *
	 * So it runs effectively with 2.5 times the rate of the NMI
	 * watchdog. That means the hrtimer should fire 2-3 times before
	 * the NMI watchdog expires. The NMI watchdog on x86 is based on
	 * unhalted CPU cycles, so if Turbo-Mode is enabled the CPU cycles
	 * might run way faster than expected and the NMI fires in a
	 * smaller period than the one deduced from the nominal CPU
	 * frequency. Depending on the Turbo-Mode factor this might be fast
	 * enough to get the NMI period smaller than the hrtimer watchdog
	 * period and trigger false positives.
	 *
	 * The sample threshold is used to check in the NMI handler whether
	 * the minimum time between two NMI samples has elapsed. That
	 * prevents false positives.
	 *
	 * Set this to 4/5 of the actual watchdog threshold period so the
	 * hrtimer is guaranteed to fire at least once within the real
	 * watchdog threshold.
	 */
	watchdog_hrtimer_sample_threshold = period * 2;
}

static bool watchdog_check_timestamp(void)
{
	ktime_t delta, now = ktime_get_mono_fast_ns();

	delta = now - __this_cpu_read(last_timestamp);
	if (delta < watchdog_hrtimer_sample_threshold) {
		/*
		 * If ktime is jiffies based, a stalled timer would prevent
		 * jiffies from being incremented and the filter would look
		 * at a stale timestamp and never trigger.
		 */
		if (__this_cpu_inc_return(nmi_rearmed) < 10)
			return false;
	}
	__this_cpu_write(nmi_rearmed, 0);
	__this_cpu_write(last_timestamp, now);
	return true;
}

void refresh_hld_last_timestamp(void)
{
	ktime_t now;

	now = ktime_get_mono_fast_ns();
	__this_cpu_write(last_timestamp, now);

}
#else
static inline bool watchdog_check_timestamp(void)
{
	return true;
}
#endif

void watchdog_hardlockup_check(struct pt_regs *regs)
{
#ifdef CONFIG_CORELOCKUP_DETECTOR
	if (enable_corelockup_detector) {
		/* Kick nmi interrupts */
		watchdog_nmi_interrupts();

		/* corelockup check */
		watchdog_corelockup_check(regs);
	}
#endif

	if (__this_cpu_read(watchdog_nmi_touch) == true) {
		__this_cpu_write(watchdog_nmi_touch, false);
		return;
	}

	if (!watchdog_check_timestamp())
		return;

	/* check for a hardlockup
	 * This is done by making sure our timer interrupt
	 * is incrementing.  The timer interrupt should have
	 * fired multiple times before we overflow'd.  If it hasn't
	 * then this is a good indication the cpu is stuck
	 */
	if (is_hardlockup()) {
		int this_cpu = smp_processor_id();

		/* only print hardlockups once */
		if (__this_cpu_read(hard_watchdog_warn) == true)
			return;

		pr_emerg("Watchdog detected hard LOCKUP on cpu %d\n",
			 this_cpu);
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		/*
		 * Perform all-CPU dump only once to avoid multiple hardlockups
		 * generating interleaving traces
		 */
		if (sysctl_hardlockup_all_cpu_backtrace &&
				!test_and_set_bit(0, &hardlockup_allcpu_dumped))
			trigger_allbutself_cpu_backtrace();

		if (hardlockup_panic)
			nmi_panic(regs, "Hard LOCKUP");

		__this_cpu_write(hard_watchdog_warn, true);
		return;
	}

	__this_cpu_write(hard_watchdog_warn, false);
	return;
}
NOKPROBE_SYMBOL(watchdog_hardlockup_check);

#ifdef CONFIG_HARDLOCKUP_DETECTOR_PERF
static DEFINE_PER_CPU(struct perf_event *, watchdog_ev);
static DEFINE_PER_CPU(struct perf_event *, dead_event);
static struct cpumask dead_events_mask;
static atomic_t watchdog_cpus = ATOMIC_INIT(0);

static struct perf_event_attr wd_hw_attr = {
	.type		= PERF_TYPE_HARDWARE,
	.config		= PERF_COUNT_HW_CPU_CYCLES,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 1,
};

/* Callback function for perf event subsystem */
static void watchdog_overflow_callback(struct perf_event *event,
				       struct perf_sample_data *data,
				       struct pt_regs *regs)
{
	/* Ensure the watchdog never gets throttled */
	event->hw.interrupts = 0;

	watchdog_hardlockup_check(regs);
}

static int hardlockup_detector_event_create(void)
{
	unsigned int cpu = smp_processor_id();
	struct perf_event_attr *wd_attr;
	struct perf_event *evt;

	wd_attr = &wd_hw_attr;
	wd_attr->sample_period = hw_nmi_get_sample_period(watchdog_thresh);

	/* Try to register using hardware perf events */
	evt = perf_event_create_kernel_counter(wd_attr, cpu, NULL,
					       watchdog_overflow_callback, NULL);
	if (IS_ERR(evt)) {
		pr_debug("Perf event create on CPU %d failed with %ld\n", cpu,
			 PTR_ERR(evt));
		return PTR_ERR(evt);
	}
	this_cpu_write(watchdog_ev, evt);
	return 0;
}

/**
 * hardlockup_detector_perf_enable - Enable the local event
 */
void hardlockup_detector_perf_enable(void)
{
	if (hardlockup_detector_event_create())
		return;

	/* use original value for check */
	if (!atomic_fetch_inc(&watchdog_cpus))
		pr_info("Enabled. Permanently consumes one hw-PMU counter.\n");

	perf_event_enable(this_cpu_read(watchdog_ev));
}

/**
 * hardlockup_detector_perf_disable - Disable the local event
 */
void hardlockup_detector_perf_disable(void)
{
	struct perf_event *event = this_cpu_read(watchdog_ev);

	if (event) {
		perf_event_disable(event);
		this_cpu_write(watchdog_ev, NULL);
		this_cpu_write(dead_event, event);
		cpumask_set_cpu(smp_processor_id(), &dead_events_mask);
		atomic_dec(&watchdog_cpus);
	}
}

/**
 * hardlockup_detector_perf_cleanup - Cleanup disabled events and destroy them
 *
 * Called from lockup_detector_cleanup(). Serialized by the caller.
 */
void hardlockup_detector_perf_cleanup(void)
{
	int cpu;

	for_each_cpu(cpu, &dead_events_mask) {
		struct perf_event *event = per_cpu(dead_event, cpu);

		/*
		 * Required because for_each_cpu() reports  unconditionally
		 * CPU0 as set on UP kernels. Sigh.
		 */
		if (event)
			perf_event_release_kernel(event);
		per_cpu(dead_event, cpu) = NULL;
	}
	cpumask_clear(&dead_events_mask);
}

/**
 * hardlockup_detector_perf_stop - Globally stop watchdog events
 *
 * Special interface for x86 to handle the perf HT bug.
 */
void __init hardlockup_detector_perf_stop(void)
{
	int cpu;

	lockdep_assert_cpus_held();

	for_each_online_cpu(cpu) {
		struct perf_event *event = per_cpu(watchdog_ev, cpu);

		if (event)
			perf_event_disable(event);
	}
}

/**
 * hardlockup_detector_perf_restart - Globally restart watchdog events
 *
 * Special interface for x86 to handle the perf HT bug.
 */
void __init hardlockup_detector_perf_restart(void)
{
	int cpu;

	lockdep_assert_cpus_held();

	if (!(watchdog_enabled & NMI_WATCHDOG_ENABLED))
		return;

	for_each_online_cpu(cpu) {
		struct perf_event *event = per_cpu(watchdog_ev, cpu);

		if (event)
			perf_event_enable(event);
	}
}

/**
 * hardlockup_detector_perf_init - Probe whether NMI event is available at all
 */
int __init hardlockup_detector_perf_init(void)
{
	int ret = hardlockup_detector_event_create();

	if (ret) {
		pr_info("Perf NMI watchdog permanently disabled\n");
	} else {
		perf_event_release_kernel(this_cpu_read(watchdog_ev));
		this_cpu_write(watchdog_ev, NULL);
	}
#ifdef CONFIG_CORELOCKUP_DETECTOR
	pmu_based_nmi = true;
#endif
	return ret;
}
#endif /* CONFIG_HARDLOCKUP_DETECTOR_PERF */
