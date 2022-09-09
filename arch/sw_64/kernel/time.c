// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/clk-provider.h>
#ifndef CONFIG_SMP
#include <linux/clocksource.h>
#endif

#include <asm/debug.h>

#include "proto.h"

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);

DECLARE_PER_CPU(u64, tc_offset);

#define TICK_SIZE (tick_nsec / 1000)

/*
 * Shift amount by which scaled_ticks_per_cycle is scaled.  Shifting
 * by 48 gives us 16 bits for HZ while keeping the accuracy good even
 * for large CPU clock rates.
 */
#define FIX_SHIFT	48

unsigned long est_cycle_freq;

static u64 sc_start;
static u64 sc_shift;
static u64 sc_multi;

DEFINE_STATIC_KEY_FALSE(use_tc_as_sched_clock);
static int __init sched_clock_setup(char *opt)
{
	if (!opt)
		return -EINVAL;

	if (!strncmp(opt, "on", 2)) {
		static_branch_enable(&use_tc_as_sched_clock);
		pr_info("Using TC instead of jiffies as source of sched_clock()\n");
	}

	return 0;
}
early_param("tc_sched_clock", sched_clock_setup);

#ifdef CONFIG_IRQ_WORK

DEFINE_PER_CPU(u8, irq_work_pending);

#define set_irq_work_pending_flag()  __this_cpu_write(irq_work_pending, 1)
#define test_irq_work_pending()      __this_cpu_read(irq_work_pending)
#define clear_irq_work_pending()     __this_cpu_write(irq_work_pending, 0)

void arch_irq_work_raise(void)
{
	set_irq_work_pending_flag();
}

#else  /* CONFIG_IRQ_WORK */

#define test_irq_work_pending()      0
#define clear_irq_work_pending()

#endif /* CONFIG_IRQ_WORK */

#ifndef CONFIG_SMP
static u64 read_tc(struct clocksource *cs)
{
	return rdtc();
}

static struct clocksource clocksource_tc = {
	.name		= "tc",
	.rating		= 300,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
	.mask		= CLOCKSOURCE_MASK(64),
	.shift		= 22,
	.mult		= 0,  /* To be filled in */
	.read		= read_tc,
};

void setup_clocksource(void)
{
	clocksource_register_hz(&clocksource_tc, get_cpu_freq());
	pr_info("Setup clocksource TC, mult = %d\n", clocksource_tc.mult);
}

#else /* !CONFIG_SMP */
void setup_clocksource(void)
{
	setup_chip_clocksource();
}
#endif /* !CONFIG_SMP */


void __init
time_init(void)
{
	unsigned long cycle_freq;

	cycle_freq = get_cpu_freq();

	pr_info("CPU Cycle frequency = %ld Hz\n", cycle_freq);

	/* Register clocksource */
	setup_clocksource();
	of_clk_init(NULL);
	/* Startup the timer source. */
	setup_timer();
	/* Calibrate the delay loop directly */
	lpj_fine = cycle_freq / HZ;
}

static void __init calibrate_sched_clock(void)
{
	sc_start = rdtc();
}

void __init setup_sched_clock(void)
{
	unsigned long step;

	sc_shift = 7;
	step = 1UL << sc_shift;
	sc_multi = step * NSEC_PER_SEC / get_cpu_freq();
	calibrate_sched_clock();

	pr_info("sched_clock: sc_multi=%llu, sc_shift=%llu\n", sc_multi, sc_shift);
}

#ifdef CONFIG_GENERIC_SCHED_CLOCK
static u64 notrace sched_clock_read(void)
{
	return (rdtc() - sc_start) >> sc_shift;
}

void __init sw64_sched_clock_init(void)
{
	sched_clock_register(sched_clock_read, BITS_PER_LONG, get_cpu_freq() >> sc_shift);
}
#else
unsigned long long sched_clock(void)
{
	if (static_branch_likely(&use_tc_as_sched_clock))
		return ((rdtc() - sc_start + __this_cpu_read(tc_offset)) >> sc_shift) * sc_multi;
	else
		return (jiffies - INITIAL_JIFFIES) * (NSEC_PER_SEC / HZ);
}

#ifdef CONFIG_DEBUG_FS
static ssize_t sched_clock_status_read(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	char buf[2];

	if (static_key_enabled(&use_tc_as_sched_clock))
		buf[0] = 'Y';
	else
		buf[0] = 'N';
	buf[1] = '\n';
	return simple_read_from_buffer(user_buf, count, ppos, buf, 2);
}

static ssize_t sched_clock_status_write(struct file *file, const char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	int r;
	bool bv;
	bool val = static_key_enabled(&use_tc_as_sched_clock);

	r = kstrtobool_from_user(user_buf, count, &bv);
	if (!r) {
		if (val != bv) {
			if (bv) {
				static_branch_enable(&use_tc_as_sched_clock);
				pr_info("source of sched_clock() switched from jiffies to TC\n");
			} else {
				static_branch_disable(&use_tc_as_sched_clock);
				pr_info("source of sched_clock() switched from TC to jiffies\n");
			}
		} else {
			if (val)
				pr_info("source of sched_clock() unchanged (using TC)\n");
			else
				pr_info("source of sched_clock() unchanged (using jiffies)\n");
		}
	}

	return count;
}

static const struct file_operations sched_clock_status_fops = {
	.read		= sched_clock_status_read,
	.write		= sched_clock_status_write,
	.open		= nonseekable_open,
	.llseek		= no_llseek,
};

static int __init sched_clock_debug_init(void)
{
	struct dentry *sched_clock_status;

	if (!sw64_debugfs_dir)
		return -ENODEV;

	sched_clock_status = debugfs_create_file("tc_sched_clock",
			0644, sw64_debugfs_dir, NULL,
			&sched_clock_status_fops);

	if (!sched_clock_status)
		return -ENOMEM;

	return 0;
}
late_initcall(sched_clock_debug_init);
#endif /* CONFIG_DEBUG_FS */
#endif /* CONFIG_GENERIC_SCHED_CLOCK */
