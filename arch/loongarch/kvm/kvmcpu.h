/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __ASM_LOONGARCH_KVMCPU_H__
#define __ASM_LOONGARCH_KVMCPU_H__

#include <linux/kvm_host.h>
#include <asm/kvm_host.h>

#define LARCH_INT_SIP0			0
#define LARCH_INT_SIP1			1
#define LARCH_INT_IP0			2
#define LARCH_INT_IP1			3
#define LARCH_INT_IP2			4
#define LARCH_INT_IP3			5
#define LARCH_INT_IP4			6
#define LARCH_INT_IP5			7
#define LARCH_INT_IP6			8
#define LARCH_INT_IP7			9
#define LARCH_INT_PMU			10
#define LARCH_INT_TIMER			11
#define LARCH_INT_IPI			12
#define LOONGARCH_EXC_MAX		(LARCH_INT_IPI + 1)
#define LOONGARCH_EXC_IPNUM		(LOONGARCH_EXC_MAX)

/* Controlled by 0x5 guest exst */
#define CPU_SIP0			(_ULCAST_(1))
#define CPU_SIP1			(_ULCAST_(1) << 1)
#define CPU_PMU				(_ULCAST_(1) << 10)
#define CPU_TIMER			(_ULCAST_(1) << 11)
#define CPU_IPI				(_ULCAST_(1) << 12)

/* Controlled by 0x52 guest exception VIP
 * aligned to exst bit 5~12
 */
#define CPU_IP0				(_ULCAST_(1))
#define CPU_IP1				(_ULCAST_(1) << 1)
#define CPU_IP2				(_ULCAST_(1) << 2)
#define CPU_IP3				(_ULCAST_(1) << 3)
#define CPU_IP4				(_ULCAST_(1) << 4)
#define CPU_IP5				(_ULCAST_(1) << 5)
#define CPU_IP6				(_ULCAST_(1) << 6)
#define CPU_IP7				(_ULCAST_(1) << 7)

#define MNSEC_PER_SEC			(NSEC_PER_SEC >> 20)

/* KVM_IRQ_LINE irq field index values */
#define KVM_LOONGSON_IRQ_TYPE_SHIFT		24
#define KVM_LOONGSON_IRQ_TYPE_MASK		0xff
#define KVM_LOONGSON_IRQ_VCPU_SHIFT		16
#define KVM_LOONGSON_IRQ_VCPU_MASK		0xff
#define KVM_LOONGSON_IRQ_NUM_SHIFT		0
#define KVM_LOONGSON_IRQ_NUM_MASK		0xffff

/* irq_type field */
#define KVM_LOONGSON_IRQ_TYPE_CPU_IP		0
#define KVM_LOONGSON_IRQ_TYPE_CPU_IO		1
#define KVM_LOONGSON_IRQ_TYPE_HT		2
#define KVM_LOONGSON_IRQ_TYPE_MSI		3
#define KVM_LOONGSON_IRQ_TYPE_IOAPIC		4
#define KVM_LOONGSON_IRQ_TYPE_ROUTE		5

/* out-of-kernel GIC cpu interrupt injection irq_number field */
#define KVM_LOONGSON_IRQ_CPU_IRQ		0
#define KVM_LOONGSON_IRQ_CPU_FIQ		1
#define KVM_LOONGSON_CPU_IP_NUM			8

typedef int (*exit_handle_fn)(struct kvm_vcpu *);

int  _kvm_emu_mmio_write(struct kvm_vcpu *vcpu, union loongarch_instruction inst);
int  _kvm_emu_mmio_read(struct kvm_vcpu *vcpu, union loongarch_instruction inst);
int  _kvm_complete_mmio_read(struct kvm_vcpu *vcpu, struct kvm_run *run);
int  _kvm_complete_iocsr_read(struct kvm_vcpu *vcpu, struct kvm_run *run);
int  _kvm_emu_idle(struct kvm_vcpu *vcpu);
int  _kvm_handle_pv_hcall(struct kvm_vcpu *vcpu);
int  _kvm_pending_timer(struct kvm_vcpu *vcpu);
int  _kvm_handle_fault(struct kvm_vcpu *vcpu, int fault);
void _kvm_deliver_intr(struct kvm_vcpu *vcpu);
void irqchip_debug_init(struct kvm *kvm);
void irqchip_debug_destroy(struct kvm *kvm);

void kvm_own_fpu(struct kvm_vcpu *vcpu);
void kvm_own_lsx(struct kvm_vcpu *vcpu);
void kvm_lose_fpu(struct kvm_vcpu *vcpu);
void kvm_own_lasx(struct kvm_vcpu *vcpu);
void kvm_save_fpu(struct kvm_vcpu *cpu);
void kvm_restore_fpu(struct kvm_vcpu *cpu);
void kvm_restore_fcsr(struct kvm_vcpu *cpu);
void kvm_save_lsx(struct kvm_vcpu *cpu);
void kvm_restore_lsx(struct kvm_vcpu *cpu);
void kvm_restore_lsx_upper(struct kvm_vcpu *cpu);
void kvm_save_lasx(struct kvm_vcpu *cpu);
void kvm_restore_lasx(struct kvm_vcpu *cpu);
void kvm_restore_lasx_upper(struct kvm_vcpu *cpu);

void kvm_lose_hw_perf(struct kvm_vcpu *vcpu);
void kvm_restore_hw_perf(struct kvm_vcpu *vcpu);

void kvm_reset_timer(struct kvm_vcpu *vcpu);
void kvm_init_timer(struct kvm_vcpu *vcpu, unsigned long hz);
void kvm_restore_timer(struct kvm_vcpu *vcpu);
void kvm_save_timer(struct kvm_vcpu *vcpu);
enum hrtimer_restart kvm_swtimer_wakeup(struct hrtimer *timer);

/*
 * Loongarch KVM guest interrupt handling.
 */
static inline void _kvm_queue_irq(struct kvm_vcpu *vcpu, unsigned int irq)
{
	set_bit(irq, &vcpu->arch.irq_pending);
	clear_bit(irq, &vcpu->arch.irq_clear);
}

static inline void _kvm_dequeue_irq(struct kvm_vcpu *vcpu, unsigned int irq)
{
	clear_bit(irq, &vcpu->arch.irq_pending);
	set_bit(irq, &vcpu->arch.irq_clear);
}

#endif /* __ASM_LOONGARCH_KVMCPU_H__ */
