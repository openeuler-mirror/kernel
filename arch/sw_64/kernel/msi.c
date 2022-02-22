// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/cpumask.h>
#include <asm/sw64io.h>
#include <asm/msi.h>
#include <asm/pci.h>


int msi_compose_msg(unsigned int irq, struct msi_msg *msg)
{
	msg->address_hi = (unsigned int)(MSIX_MSG_ADDR >> 32);
	msg->address_lo = (unsigned int)(MSIX_MSG_ADDR & 0xffffffff);
	msg->data = irq;
	return irq;
}

void sw64_irq_noop(struct irq_data *d)
{
}

void destroy_irq(unsigned int irq)
{
#if 0
	int pos;

	irq_init_desc(irq);

	if (irq < RC1_FIRST_MSI_VECTOR) {
		pos = irq - RC0_FIRST_MSI_VECTOR;
		clear_bit(pos, msi0_irq_in_use);
	} else {
		pos = irq - RC1_FIRST_MSI_VECTOR;
		clear_bit(pos, msi1_irq_in_use);
	}
#endif
}

void arch_teardown_msi_irq(unsigned int irq)
{
	destroy_irq(irq);
}

static int __init msi_init(void)
{
	return 0;
}

static void __exit msi_exit(void)
{
}

module_init(msi_init);
module_exit(msi_exit);
MODULE_LICENSE("GPL v2");
