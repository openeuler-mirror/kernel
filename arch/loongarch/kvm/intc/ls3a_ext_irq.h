/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LS3A_KVM_EXT_IRQ_H
#define __LS3A_KVM_EXT_IRQ_H

#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>

#include <kvm/iodev.h>

#define IOCSR_EXTIOI_ADDR		KVM_IOCSR_EXTIOI_NODEMAP_BASE

#define EXTIOI_ADDR_OFF			0x10000
#define EXTIOI_REG_BASE			(LOONGSON_VIRT_REG_BASE + EXTIOI_ADDR_OFF)
#define EXTIOI_REG_END			(EXTIOI_REG_BASE + 0x20000)
#define EXTIOI_ADDR_SIZE		(EXTIOI_REG_END - EXTIOI_REG_BASE)
#define EXTIOI_PERCORE_REG_OFF		0x10000
#define EXTIOI_PERCORE_REG_END		(EXTIOI_PERCORE_REG_OFF + 0x10000)

#define EXTIOI_ADDR(off)		(EXTIOI_REG_BASE + (off) - IOCSR_EXTIOI_ADDR)
#define EXTIOI_PERCORE_ADDR(id, off) \
	(EXTIOI_REG_BASE + EXTIOI_PERCORE_REG_OFF + ((id) << 8) + (off))

#define EXTIOI_NODETYPE_START		(KVM_IOCSR_EXTIOI_NODEMAP_BASE - IOCSR_EXTIOI_ADDR)
#define EXTIOI_NODETYPE_END		(EXTIOI_NODETYPE_START + 0x20)
#define EXTIOI_IPMAP_START		(KVM_IOCSR_EXTIOI_IPMAP_BASE - IOCSR_EXTIOI_ADDR)
#define EXTIOI_IPMAP_END		(EXTIOI_IPMAP_START + 0x8)
#define EXTIOI_ENABLE_START		(KVM_IOCSR_EXTIOI_EN_BASE - IOCSR_EXTIOI_ADDR)
#define EXTIOI_ENABLE_END		(EXTIOI_ENABLE_START + 0x20)
#define EXTIOI_BOUNCE_START		(KVM_IOCSR_EXTIOI_BOUNCE_BASE - IOCSR_EXTIOI_ADDR)
#define EXTIOI_BOUNCE_END		(EXTIOI_BOUNCE_START + 0x20)
#define EXTIOI_ISR_START		(0x1700 - IOCSR_EXTIOI_ADDR)
#define EXTIOI_ISR_END			(EXTIOI_ISR_START + 0x20)
#define EXTIOI_COREMAP_START		(KVM_IOCSR_EXTIOI_ROUTE_BASE - IOCSR_EXTIOI_ADDR)
#define EXTIOI_COREMAP_END		(EXTIOI_COREMAP_START + 0x100)
#define EXTIOI_COREISR_START		(EXTIOI_PERCORE_REG_OFF)
#define EXTIOI_COREISR_END		(EXTIOI_PERCORE_REG_END)

#define LS3A_INTC_IP			8
#define EXTIOI_IRQS			KVM_EXTIOI_IRQS
#define EXTIOI_IRQS_BITMAP_SIZE		(EXTIOI_IRQS / 8)
/* map to ipnum per 32 irqs */
#define EXTIOI_IRQS_IPMAP_SIZE		(EXTIOI_IRQS / 32)
#define EXTIOI_IRQS_PER_GROUP		KVM_EXTIOI_IRQS_PER_GROUP
#define EXTIOI_IRQS_COREMAP_SIZE	(EXTIOI_IRQS)
#define EXTIOI_IRQS_NODETYPE_SIZE	KVM_EXTIOI_IRQS_NODETYPE_SIZE

typedef struct kvm_ls3a_extirq_state {
	union ext_en {
		uint64_t reg_u64[EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[EXTIOI_IRQS_BITMAP_SIZE];
	} ext_en;
	union bounce {
		uint64_t reg_u64[EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[EXTIOI_IRQS_BITMAP_SIZE];
	} bounce;
	union ext_isr {
		uint64_t reg_u64[EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[EXTIOI_IRQS_BITMAP_SIZE];
	} ext_isr;
	union ext_core_isr {
		uint64_t reg_u64[KVM_MAX_VCPUS][EXTIOI_IRQS_BITMAP_SIZE / 8];
		uint32_t reg_u32[KVM_MAX_VCPUS][EXTIOI_IRQS_BITMAP_SIZE / 4];
		uint8_t reg_u8[KVM_MAX_VCPUS][EXTIOI_IRQS_BITMAP_SIZE];
	} ext_core_isr;
	union ip_map {
		uint64_t reg_u64;
		uint32_t reg_u32[EXTIOI_IRQS_IPMAP_SIZE / 4];
		uint8_t reg_u8[EXTIOI_IRQS_IPMAP_SIZE];
	} ip_map;
	union core_map {
		uint64_t reg_u64[EXTIOI_IRQS_COREMAP_SIZE / 8];
		uint32_t reg_u32[EXTIOI_IRQS_COREMAP_SIZE / 4];
		uint8_t reg_u8[EXTIOI_IRQS_COREMAP_SIZE];
	} core_map;
	union {
		uint64_t reg_u64[EXTIOI_IRQS_NODETYPE_SIZE / 4];
		uint32_t reg_u32[EXTIOI_IRQS_NODETYPE_SIZE / 2];
		uint16_t reg_u16[EXTIOI_IRQS_NODETYPE_SIZE];
		uint8_t reg_u8[EXTIOI_IRQS_NODETYPE_SIZE * 2];
	} node_type;

	/*software state */
	uint8_t ext_sw_ipmap[EXTIOI_IRQS];
	uint8_t ext_sw_coremap[EXTIOI_IRQS];
	uint8_t ext_sw_ipisr[KVM_MAX_VCPUS][LS3A_INTC_IP][EXTIOI_IRQS_BITMAP_SIZE];
} LS3AExtirqState;

struct ls3a_kvm_extirq {
	spinlock_t lock;
	struct kvm *kvm;
	struct kvm_io_device device;
	struct kvm_ls3a_extirq_state ls3a_ext_irq;
};

static inline struct ls3a_kvm_extirq *ls3a_ext_irqchip(struct kvm *kvm)
{
	return kvm->arch.v_extirq;
}

static inline int ls3a_extirq_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ls3a_ext_irqchip(kvm) != NULL);
	return ret;
}


void ext_irq_handler(struct kvm *kvm, int irq, int level);
int kvm_create_ls3a_ext_irq(struct kvm *kvm);
int kvm_get_ls3a_extirq(struct kvm *kvm,
			struct kvm_loongarch_ls3a_extirq_state *state);
int kvm_set_ls3a_extirq(struct kvm *kvm,
			struct kvm_loongarch_ls3a_extirq_state *state);
void kvm_destroy_ls3a_ext_irq(struct kvm *kvm);
void msi_irq_handler(struct kvm *kvm, int irq, int level);
int kvm_setup_ls3a_extirq(struct kvm *kvm);
void kvm_dump_ls3a_extirq_state(struct seq_file *m, struct ls3a_kvm_extirq *irqchip);
#endif
