// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include "kvmcpu.h"
#include <linux/kvm_host.h>
#include "kvm_compat.h"

static u32 int_to_coreint[LOONGARCH_EXC_MAX] = {
	[LARCH_INT_TIMER]	= CPU_TIMER,
	[LARCH_INT_IPI]		= CPU_IPI,
	[LARCH_INT_SIP0]	= CPU_SIP0,
	[LARCH_INT_SIP1]	= CPU_SIP1,
	[LARCH_INT_IP0]		= CPU_IP0,
	[LARCH_INT_IP1]		= CPU_IP1,
	[LARCH_INT_IP2]		= CPU_IP2,
	[LARCH_INT_IP3]		= CPU_IP3,
	[LARCH_INT_IP4]		= CPU_IP4,
	[LARCH_INT_IP5]		= CPU_IP5,
	[LARCH_INT_IP6]		= CPU_IP6,
	[LARCH_INT_IP7]		= CPU_IP7,
};

static int _kvm_irq_deliver(struct kvm_vcpu *vcpu, unsigned int priority)
{
	unsigned int irq = 0;

	clear_bit(priority, &vcpu->arch.irq_pending);
	if (priority < LOONGARCH_EXC_MAX)
		irq = int_to_coreint[priority];

	switch (priority) {
	case LARCH_INT_TIMER:
	case LARCH_INT_IPI:
	case LARCH_INT_SIP0:
	case LARCH_INT_SIP1:
		kvm_set_gcsr_estat(irq);
		break;

	case LARCH_INT_IP0:
	case LARCH_INT_IP1:
	case LARCH_INT_IP2:
	case LARCH_INT_IP3:
	case LARCH_INT_IP4:
	case LARCH_INT_IP5:
	case LARCH_INT_IP6:
	case LARCH_INT_IP7:
		kvm_set_csr_gintc(irq);
		break;

	default:
		break;
	}

	return 1;
}

static int _kvm_irq_clear(struct kvm_vcpu *vcpu, unsigned int priority)
{
	unsigned int irq = 0;

	clear_bit(priority, &vcpu->arch.irq_clear);
	if (priority < LOONGARCH_EXC_MAX)
		irq = int_to_coreint[priority];

	switch (priority) {
	case LARCH_INT_TIMER:
	case LARCH_INT_IPI:
	case LARCH_INT_SIP0:
	case LARCH_INT_SIP1:
		kvm_clear_gcsr_estat(irq);
		break;

	case LARCH_INT_IP0:
	case LARCH_INT_IP1:
	case LARCH_INT_IP2:
	case LARCH_INT_IP3:
	case LARCH_INT_IP4:
	case LARCH_INT_IP5:
	case LARCH_INT_IP6:
	case LARCH_INT_IP7:
		kvm_clear_csr_gintc(irq);
		break;

	default:
		break;
	}

	return 1;
}

void _kvm_deliver_intr(struct kvm_vcpu *vcpu)
{
	unsigned long *pending = &vcpu->arch.irq_pending;
	unsigned long *pending_clr = &vcpu->arch.irq_clear;
	unsigned int priority;

	if (!(*pending) && !(*pending_clr))
		return;

	if (*pending_clr) {
		priority = __ffs(*pending_clr);
		while (priority <= LOONGARCH_EXC_IPNUM) {
			_kvm_irq_clear(vcpu, priority);
			priority = find_next_bit(pending_clr,
					BITS_PER_BYTE * sizeof(*pending_clr),
					priority + 1);
		}
	}

	if (*pending) {
		priority = __ffs(*pending);
		while (priority <= LOONGARCH_EXC_IPNUM) {
			_kvm_irq_deliver(vcpu, priority);
			priority = find_next_bit(pending,
					BITS_PER_BYTE * sizeof(*pending),
					priority + 1);
		}
	}

}

int _kvm_pending_timer(struct kvm_vcpu *vcpu)
{
	return test_bit(LARCH_INT_TIMER, &vcpu->arch.irq_pending);
}
