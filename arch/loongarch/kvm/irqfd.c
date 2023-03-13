// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/kvm_host.h>
#include <trace/events/kvm.h>
#include "intc/ls7a_irq.h"

static int kvm_ls7a_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
					struct kvm *kvm, int irq_source_id,
					int level, bool line_status)
{
	/* ioapic pin (0 ~ 64) <---> gsi(0 ~ 64) */
	u32 irq = e->irqchip.pin;
	unsigned long flags;
	int ret;

	if (!ls7a_ioapic_in_kernel(kvm))
		return -ENXIO;

	ls7a_ioapic_lock(ls7a_ioapic_irqchip(kvm), &flags);
	ret = kvm_ls7a_ioapic_set_irq(kvm, irq, level);
	ls7a_ioapic_unlock(ls7a_ioapic_irqchip(kvm), &flags);

	return ret;
}

/**
 * kvm_set_routing_entry: populate a kvm routing entry
 * from a user routing entry
 *
 * @kvm: the VM this entry is applied to
 * @e: kvm kernel routing entry handle
 * @ue: user api routing entry handle
 * return 0 on success, -EINVAL on errors.
 */
int kvm_set_routing_entry(struct kvm *kvm,
			  struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		e->set = kvm_ls7a_set_ioapic_irq;

		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin;

		if (e->irqchip.pin >= LS7A_APIC_NUM_PINS)
			goto out;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		/*
		 * linux4.19 kernel have flags and devid
		 * e->msi.flags = ue->flags;
		 * e->msi.devid = ue->u.msi.devid;
		 */
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	if (e->type == KVM_IRQ_ROUTING_MSI)
		return kvm_ls7a_set_msi(e, kvm, irq_source_id, 1, false);

	return -EWOULDBLOCK;
}

/**
 * kvm_set_msi: inject the MSI corresponding to the
 * MSI routing entry
 *
 * This is the entry point for irqfd MSI injection
 * and userspace MSI injection.
 */
int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	unsigned int ret;

	if (!level)
		return -1;

	ret = kvm_ls7a_set_msi(e, kvm, irq_source_id, 1, false);
	return ret;
}
