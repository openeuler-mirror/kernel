/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_IRQ_H
#define __ASM_IRQ_H

#ifndef __ASSEMBLER__

#include <asm-generic/irq.h>

#if defined(CONFIG_SMP) && defined(CONFIG_IPI_AS_NMI)
extern bool arch_trigger_cpumask_backtrace(const cpumask_t *mask,
					   int exclude_cpu);
#define arch_trigger_cpumask_backtrace arch_trigger_cpumask_backtrace
#endif

struct pt_regs;

int set_handle_nmi_irq(void (*handle_irq)(struct pt_regs *));
int set_handle_irq(void (*handle_irq)(struct pt_regs *));
#define set_handle_irq	set_handle_irq
int set_handle_fiq(void (*handle_fiq)(struct pt_regs *));

static inline int nr_legacy_irqs(void)
{
	return 0;
}

#endif /* !__ASSEMBLER__ */
#endif
