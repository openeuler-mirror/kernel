// SPDX-License-Identifier: GPL-2.0
/*
 * sw64 idle loop support.
 *
 */
#include <linux/cpu.h>
#include <linux/irqflags.h>
#include <asm/cpu.h>
#include <asm/idle.h>

#ifdef CONFIG_HOTPLUG_CPU
void arch_cpu_idle_dead(void)
{
	play_dead();
}
#endif

void cpu_idle(void)
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

void arch_cpu_idle(void)
{
	cpu_idle();
}
