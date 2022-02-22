/* SPDX-License-Identifier: GPL-2.0 */
/*
 * irq.h: in kernel interrupt controller related definitions
 */

#ifndef __IRQ_H
#define __IRQ_H
static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 1;
}
#endif
