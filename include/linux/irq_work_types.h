/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_WORK_TYPES_H
#define _LINUX_IRQ_WORK_TYPES_H

#include <linux/smp_types.h>
#include <linux/types.h>
#include <linux/kabi.h>

struct irq_work {
	struct __call_single_node	node;
	void				(*func)(struct irq_work *work);
	struct rcuwait			irqwait;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

#endif
