/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LS7A_KVM_IRQ_H
#define __LS7A_KVM_IRQ_H

#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include "kvmcpu.h"

#include <kvm/iodev.h>

#define LS7A_APIC_NUM_PINS	64

#define LS7A_ROUTE_ENTRY_OFFSET	0x100
#define LS7A_INT_ID_OFFSET	0x0
#define LS7A_INT_ID_VAL		0x7000000UL
#define LS7A_INT_ID_VER		0x1f0001UL
#define LS7A_INT_MASK_OFFSET	0x20
#define LS7A_INT_EDGE_OFFSET	0x60
#define LS7A_INT_CLEAR_OFFSET	0x80
#define LS7A_INT_STATUS_OFFSET	0x3a0
#define LS7A_INT_POL_OFFSET	0x3e0
#define LS7A_HTMSI_EN_OFFSET	0x40
#define LS7A_HTMSI_VEC_OFFSET	0x200
#define LS7A_AUTO_CTRL0_OFFSET	0xc0
#define LS7A_AUTO_CTRL1_OFFSET	0xe0

#define LS7A_IOAPIC_GUEST_REG_BASE		0x10000000UL
#define LS7A_IOAPIC_GUEST_REG_BASE_ALIAS	0xe0010000000UL

#define LS7A_IOAPIC_NUM_PINS			32

typedef struct kvm_ls7a_ioapic_state {
	u64 int_id;
	/* 0x020 interrupt mask register */
	u64 int_mask;
	/* 0x040 1=msi */
	u64 htmsi_en;
	/* 0x060 edge=1 level  =0 */
	u64 intedge;
	/* 0x080 for clean edge int,set 1 clean,set 0 is noused */
	u64 intclr;
	/* 0x0c0 */
	u64 auto_crtl0;
	/* 0x0e0 */
	u64 auto_crtl1;
	/* 0x100 - 0x140 */
	u8 route_entry[64];
	/* 0x200 - 0x240 */
	u8 htmsi_vector[64];
	/* 0x300 */
	u64 intisr_chip0;
	/* 0x320 */
	u64 intisr_chip1;
	/* edge detection */
	u64 last_intirr;
	/* 0x380 interrupt request register */
	u64 intirr;
	/* 0x3a0 interrupt service register */
	u64 intisr;
	/* 0x3e0 interrupt level polarity selection register,
	 * 0 for high level tirgger
	 */
	u64 int_polarity;
} LS7AApicState;

struct ls7a_kvm_ioapic {
	spinlock_t lock;
	bool wakeup_needed;
	unsigned pending_acks;
	struct kvm *kvm;
	struct kvm_ls7a_ioapic_state ls7a_ioapic;
	struct kvm_io_device dev_ls7a_ioapic;
	struct kvm_io_device ls7a_ioapic_alias;
	void (*ack_notifier)(void *opaque, int irq);
	unsigned long irq_states[LS7A_APIC_NUM_PINS];
};

static inline struct ls7a_kvm_ioapic *ls7a_ioapic_irqchip(struct kvm *kvm)
{
	return kvm->arch.v_ioapic;
}

static inline int ls7a_ioapic_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ls7a_ioapic_irqchip(kvm) != NULL);
	return ret;
}

int kvm_set_ls7a_ioapic(struct kvm *kvm, struct ls7a_ioapic_state *state);
int kvm_get_ls7a_ioapic(struct kvm *kvm, struct ls7a_ioapic_state *state);
int kvm_create_ls7a_ioapic(struct kvm *kvm);
void kvm_destroy_ls7a_ioapic(struct kvm *kvm);
int kvm_ls7a_ioapic_set_irq(struct kvm *kvm, int irq, int level);

void ls7a_ioapic_lock(struct ls7a_kvm_ioapic *s, unsigned long *flags);
void ls7a_ioapic_unlock(struct ls7a_kvm_ioapic *s, unsigned long *flags);
int kvm_ls7a_send_userspace_msi(struct kvm *kvm, struct kvm_msi *msi);
int kvm_ls7a_set_msi(struct kvm_kernel_irq_routing_entry *e, struct kvm *kvm,
					int irq_source_id, int level, bool line_status);

void kvm_dump_ls7a_ioapic_state(struct seq_file *m, struct ls7a_kvm_ioapic *ioapic);
#endif
