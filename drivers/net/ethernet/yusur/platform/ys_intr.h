/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_INTR_H_
#define __YS_INTR_H_

#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/mutex.h>

#include "ys_irq.h"

struct ys_irq {
	int state;
	int index;
	int irqn;
	struct pci_dev *pdev;
	struct ys_irq_sub sub;
};

struct ys_irq_table {
	struct ys_irq *irqs;
	int max;
	int used;
	/* mutex lock */
	struct mutex lock;
	struct blocking_notifier_head nh;
};

int ys_irq_init(struct pci_dev *pdev);
void ys_irq_uninit(struct pci_dev *pdev);

#endif /* __YS_INTR_H_ */
