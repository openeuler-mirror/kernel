/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_XINT_H
#define __ASM_XINT_H

#define NR_IPI_USER	7  // SGI

#ifndef __ASSEMBLY__
extern void gic_handle_irq_noack(struct pt_regs *regs);
extern void gic_handle_nmi_noack(struct pt_regs *regs);
extern void arch_smp_send_ipi_user(int cpu);
extern bool should_restrict(void);
#endif /* __ASSEMBLY__ */
#endif /* __ASM_XINT_H */
