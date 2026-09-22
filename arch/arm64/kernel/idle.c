// SPDX-License-Identifier: GPL-2.0-only
/*
 * Low-level idle sequences
 */

#include <linux/cpu.h>
#include <linux/irqflags.h>

#include <asm/barrier.h>
#include <asm/cpuidle.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

/*
 *	cpu_do_idle()
 *
 *	Idle the processor (wait for interrupt).
 *
 *	If the CPU supports priority masking we must do additional work to
 *	ensure that interrupts are not masked at the PMR (because the core will
 *	not wake up if we block the wake up signal in the interrupt controller).
 */
void noinstr cpu_do_idle(void)
{
	struct arm_cpuidle_irq_context context;

	arm_cpuidle_save_irq_context(&context);

	dsb(sy);
	wfi();

	arm_cpuidle_restore_irq_context(&context);
}

/*
 * This is our default idle handler.
 */
void noinstr arch_cpu_idle(void)
{
	/*
	 * This should do all the clock switching and wait for interrupt
	 * tricks
	 */
	cpu_do_idle();
}
EXPORT_SYMBOL_GPL(arch_cpu_idle);

#ifdef CONFIG_SCHED_SOFT_QUOTA
static DEFINE_PER_CPU(int, sibling_idle) = 1;

int is_sibling_idle(void)
{
	return this_cpu_read(sibling_idle);
}

static void smt_measurement_begin(void)
{
}

static void smt_measurement_done(void)
{
}
#else
static inline void smt_measurement_begin(void) { }
static inline void smt_measurement_done(void) { }
#endif

#ifdef CONFIG_ACTLR_XCALL_XINT
struct arm_cpuidle_xcall_xint_context {
	unsigned long actlr_el1;
	unsigned long actlr_el2;
};

DEFINE_PER_CPU_ALIGNED(struct arm_cpuidle_xcall_xint_context, contexts);
#endif

void arch_cpu_idle_enter(void)
{
#ifdef CONFIG_ACTLR_XCALL_XINT
	struct arm_cpuidle_xcall_xint_context *context;

	if (system_uses_xcall_xint()) {
		context = &get_cpu_var(contexts);
		context->actlr_el1 = read_sysreg(actlr_el1);
		if (read_sysreg(CurrentEL) == CurrentEL_EL2)
			context->actlr_el2 = read_sysreg(actlr_el2);
		put_cpu_var(contexts);
	}
#endif
	smt_measurement_begin();
}

void arch_cpu_idle_exit(void)
{
#ifdef CONFIG_ACTLR_XCALL_XINT
	struct arm_cpuidle_xcall_xint_context *context;

	if (system_uses_xcall_xint()) {
		context = &get_cpu_var(contexts);
		write_sysreg(context->actlr_el1, actlr_el1);
		if (read_sysreg(CurrentEL) == CurrentEL_EL2)
			write_sysreg(context->actlr_el2, actlr_el2);
		put_cpu_var(contexts);
	}
#endif
	smt_measurement_done();
}
