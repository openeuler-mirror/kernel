/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LOONGHARCH_KVM_IRQ_H__
#define __LOONGHARCH_KVM_IRQ_H__

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return kvm->arch.v_ioapic ? 1 : 0;
}

#endif
