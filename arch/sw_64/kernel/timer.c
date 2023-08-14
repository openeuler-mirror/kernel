// SPDX-License-Identifier: GPL-2.0
/*
 *  Filename:  timer.c
 *  Description:  percpu local timer, based on arch/x86/kernel/apic/apic.c
 */

#include <linux/interrupt.h>
#include <linux/clockchips.h>

#include <asm/hw_init.h>
#include <asm/hardirq.h>

static int timer_next_event(unsigned long delta,
		struct clock_event_device *evt);
static int sw64_timer_shutdown(struct clock_event_device *evt);
static int timer_set_oneshot(struct clock_event_device *evt);

/*
 * The local apic timer can be used for any function which is CPU local.
 */
static struct clock_event_device timer_clockevent = {
	.name			= "timer",
	.features		= CLOCK_EVT_FEAT_ONESHOT,
	.shift			= 20,
	.mult			= 0,
	.set_state_shutdown	= sw64_timer_shutdown,
	.set_state_oneshot	= timer_set_oneshot,
	.set_next_event		= timer_next_event,
	.rating			= 300,
	.irq			= -1,
};

static int vtimer_next_event(unsigned long delta,
		struct clock_event_device *evt)
{
	hcall(HCALL_SET_CLOCKEVENT, delta, 0, 0);
	return 0;
}

static int vtimer_shutdown(struct clock_event_device *evt)
{
	hcall(HCALL_SET_CLOCKEVENT, 0, 0, 0);
	return 0;
}

static int vtimer_set_oneshot(struct clock_event_device *evt)
{
	return 0;
}
static struct clock_event_device vtimer_clockevent = {
	.name			= "vtimer",
	.features		= CLOCK_EVT_FEAT_ONESHOT,
	.shift			= 20,
	.mult			= 0,
	.set_state_shutdown	= vtimer_shutdown,
	.set_state_oneshot	= vtimer_set_oneshot,
	.set_next_event		= vtimer_next_event,
	.rating			= 300,
	.irq			= -1,
};

static DEFINE_PER_CPU(struct clock_event_device, timer_events);

/*
 * Program the next event, relative to now
 */
static int timer_next_event(unsigned long delta,
		struct clock_event_device *evt)
{
	wrtimer(delta);
	return 0;
}

static int sw64_timer_shutdown(struct clock_event_device *evt)
{
	wrtimer(0);
	return 0;
}

static int timer_set_oneshot(struct clock_event_device *evt)
{
	/*
	 * SW-TIMER support CLOCK_EVT_MODE_ONESHOT only, and automatically.
	 * unlike PIT and HPET, which support ONESHOT or PERIODIC by setting PIT_MOD or HPET_Tn_CFG
	 * so, nothing to do here ...
	 */
	return 0;
}

void sw64_update_clockevents(unsigned long cpu, u32 freq)
{
	struct clock_event_device *swevt = &per_cpu(timer_events, cpu);

	if (cpu == smp_processor_id())
		clockevents_update_freq(swevt, freq);
}

/*
 * Setup the local timer for this CPU. Copy the initilized values
 * of the boot CPU and register the clock event in the framework.
 */
void setup_timer(void)
{
	int cpu = smp_processor_id();
	struct clock_event_device *swevt = &per_cpu(timer_events, cpu);

	if (is_in_guest()) {
		memcpy(swevt, &vtimer_clockevent, sizeof(*swevt));
		/*
		 * CUIWEI: This value is very important.
		 * If it's too small, the timer will timeout when the IER
		 * haven't been opened.
		 */
		swevt->min_delta_ns = 400;
	} else {
		memcpy(swevt, &timer_clockevent, sizeof(*swevt));
		swevt->min_delta_ns = 100;
	}

	swevt->cpumask = cpumask_of(cpu);
	swevt->mult = div_sc(get_cpu_freq(), NSEC_PER_SEC, swevt->shift);
	swevt->max_delta_ns = clockevent_delta2ns(0xFFFFFFFFFFFFFFFF, swevt);

	swevt->set_state_shutdown(swevt);

	clockevents_register_device(swevt);
}

void sw64_timer_interrupt(void)
{
	struct clock_event_device *evt = this_cpu_ptr(&timer_events);

	irq_enter();
	if (!evt->event_handler) {
		pr_warn("Spurious local timer interrupt on cpu %d\n",
				smp_processor_id());
		sw64_timer_shutdown(evt);
		return;
	}

	inc_irq_stat(timer_irqs_event);

	evt->event_handler(evt);

	irq_exit();
}
