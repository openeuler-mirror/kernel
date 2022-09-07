/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_MSI_H
#define _ASM_SW64_MSI_H

#define NR_VECTORS NR_IRQS
#define NR_IRQ_VECTORS NR_IRQS

#define AUTO_ASSIGN		0

#define LAST_DEVICE_VECTOR	31

#define MSI_OFFSET		0x44

#define NUM_MSI_IRQS		256

#define PERCPU_MSI_IRQS		256

#define MSIX_MSG_ADDR		(0x91abc0UL)

#ifdef CONFIG_PCI_MSI
extern int sw64_setup_vt_msi_irqs(struct pci_dev *dev, int nvec, int type);
extern int msi_compose_msg(unsigned int irq, struct msi_msg *msg);
extern void sw64_irq_noop(struct irq_data *d);
extern struct irq_chip sw64_irq_chip;

#ifdef CONFIG_PCI_MSI_IRQ_DOMAIN
#define MSI_ADDR_BASE_HI	0
#define MSI_ADDR_BASE_LO	0x91abc0
struct sw6_msi_chip_data {
	unsigned int msi_config_index;
};
extern void arch_init_msi_domain(struct irq_domain *domain);
enum irq_alloc_type {
	IRQ_ALLOC_TYPE_MSI,
	IRQ_ALLOC_TYPE_MSIX,
	IRQ_ALLOC_TYPE_INTX,
};
struct irq_alloc_info {
	struct msi_desc         *desc;
	enum irq_alloc_type	type;
	struct pci_dev		*msi_dev;
	irq_hw_number_t         hwirq;
};
typedef struct irq_alloc_info msi_alloc_info_t;
#endif /* CONFIG_PCI_MSI_IRQ_DOMAIN */
#endif /* CONFIG_PCI_MSI */
#endif /* _ASM_SW64_MSI_H */
