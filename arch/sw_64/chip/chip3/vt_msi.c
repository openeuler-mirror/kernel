// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/msi.h>

#define QEMU_MSIX_MSG_ADDR     (0x8000fee00000UL)

static DEFINE_RAW_SPINLOCK(vector_lock);

static struct irq_chip msi_chip = {
	.name = "PCI-MSI",
	.irq_unmask = pci_msi_unmask_irq,
	.irq_mask = pci_msi_mask_irq,
	.irq_ack = sw64_irq_noop,
};

static int qemu_msi_compose_msg(unsigned int irq, struct msi_msg *msg)
{
	msg->address_hi = (unsigned int)(QEMU_MSIX_MSG_ADDR >> 32);
	msg->address_lo = (unsigned int)(QEMU_MSIX_MSG_ADDR & 0xffffffff);
	msg->data = irq;
	return irq;
}

int chip_setup_vt_msix_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	int virq, val_node = 0;
	struct irq_data *irq_data;
	struct sw6_msi_chip_data *cdata;
	struct pci_controller *hose = (struct pci_controller *)dev->sysdata;
	unsigned long flags, node, rc_index;
	const struct cpumask *mask;

	node = hose->node;
	rc_index = hose->index;
	mask = cpumask_of_node(node);

	raw_spin_lock_irqsave(&vector_lock, flags);
	/* Find unused msi config reg in PIU-IOR0 */
	if (!node_online(node))
		val_node = next_node_in(node, node_online_map);
	else
		val_node = node;

	virq = irq_alloc_descs_from(NR_IRQS_LEGACY, desc->nvec_used, val_node);
	if (virq < 0) {
		pr_debug("cannot allocate IRQ(base 16, count %d)\n", desc->nvec_used);
		raw_spin_unlock_irqrestore(&vector_lock, flags);
		return virq;
	}

	qemu_msi_compose_msg(virq, &msg);
	irq_set_msi_desc(virq, desc);
	pci_write_msi_msg((virq), &msg);
	irq_set_chip_and_handler_name(virq, &msi_chip, handle_edge_irq, "edge");
	irq_data = irq_get_irq_data(virq);
	cdata = kzalloc(sizeof(*cdata), GFP_KERNEL);
	if (!cdata)
		return -ENOMEM;
	irq_data->chip_data = cdata;
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return 0;
}
EXPORT_SYMBOL(chip_setup_vt_msix_irq);

int chip_setup_vt_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *desc;
	struct msi_msg msg;
	struct pci_controller *hose = (struct pci_controller *)dev->sysdata;
	struct irq_data *irq_data;
	struct sw6_msi_chip_data *cdata;
	int i = 0;
	unsigned long node, rc_index;
	int virq = -1, val_node = 0;
	unsigned long flags;

	if (type == PCI_CAP_ID_MSI && nvec > 32)
		return 1;

	node = hose->node;
	rc_index = hose->index;
	raw_spin_lock_irqsave(&vector_lock, flags);
	for_each_msi_entry(desc, &(dev->dev)) {
		/* Find unused msi config reg in PIU-IOR0 */
		if (!node_online(node))
			val_node = next_node_in(node, node_online_map);
		else
			val_node = node;
		virq = irq_alloc_descs_from(NR_IRQS_LEGACY, desc->nvec_used, val_node);
		if (virq < 0) {
			pr_debug("cannot allocate IRQ(base 16, count %d)\n", desc->nvec_used);
			raw_spin_unlock_irqrestore(&vector_lock, flags);
			return virq;
		}
		qemu_msi_compose_msg(virq, &msg);
		for (i = 0; i < desc->nvec_used; i++) {
			irq_set_msi_desc_off(virq, i, desc);
			pci_write_msi_msg((virq + i), &msg);
			desc->msi_attrib.multiple = ilog2(__roundup_pow_of_two(nvec));
			irq_set_chip_and_handler_name(virq + i, &msi_chip, handle_edge_irq, "edge");
			irq_data = irq_get_irq_data(virq + i);
			cdata = kzalloc(sizeof(*cdata), GFP_KERNEL);
			if (!cdata)
				return -ENOMEM;
			irq_data->chip_data = cdata;
		}
	}

	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return 0;
}
EXPORT_SYMBOL(chip_setup_vt_msi_irqs);

int __arch_setup_vt_msix_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *entry;
	int ret;

	list_for_each_entry(entry, &dev->dev.msi_list, list) {
		ret = chip_setup_vt_msix_irq(dev, entry);
		if (ret)
			return ret;
	}

	return 0;
}

int sw64_setup_vt_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	int ret = 0;

	if (type == PCI_CAP_ID_MSI)
		ret = chip_setup_vt_msi_irqs(dev, nvec, type);
	else if (type == PCI_CAP_ID_MSIX)
		ret = __arch_setup_vt_msix_irqs(dev, nvec, type);
	else
		pr_info("SW arch do not identify ID:%d\n", type);

	return ret;
}
MODULE_LICENSE("GPL v2");
