/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#ifndef __LS3A_KVM_IPI_H
#define __LS3A_KVM_IPI_H

#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <kvm/iodev.h>

typedef struct gipi_single {
	uint32_t status;
	uint32_t en;
	uint32_t set;
	uint32_t clear;
	uint64_t buf[4];
} gipi_single;

typedef struct gipiState {
	gipi_single core[KVM_MAX_VCPUS];
} gipiState;

struct ls3a_kvm_ipi;

typedef struct ipi_io_device {
	struct ls3a_kvm_ipi *ipi;
	struct kvm_io_device device;
	int nodeNum;
} ipi_io_device;

struct ls3a_kvm_ipi {
	spinlock_t lock;
	struct kvm *kvm;
	gipiState ls3a_gipistate;
	int nodeNum;
	ipi_io_device dev_ls3a_ipi;
};

#define SMP_MAILBOX			(LOONGSON_VIRT_REG_BASE + 0x0000)
#define KVM_IPI_REG_ADDRESS(id, off)	(SMP_MAILBOX | (id << 8) | off)
#define KVM_IOCSR_IPI_ADDR_SIZE		0x10000

#define CORE0_STATUS_OFF	0x000
#define CORE0_EN_OFF		0x004
#define CORE0_SET_OFF		0x008
#define CORE0_CLEAR_OFF		0x00c
#define CORE0_BUF_20		0x020
#define CORE0_BUF_28		0x028
#define CORE0_BUF_30		0x030
#define CORE0_BUF_38		0x038
#define CORE0_IPI_SEND		0x040
#define CORE0_MAIL_SEND		0x048

static inline struct ls3a_kvm_ipi *ls3a_ipi_irqchip(struct kvm *kvm)
{
	return kvm->arch.v_gipi;
}

static inline int ls3a_ipi_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ls3a_ipi_irqchip(kvm) != NULL);
	return ret;
}

int kvm_create_ls3a_ipi(struct kvm *kvm);
void kvm_destroy_ls3a_ipi(struct kvm *kvm);
int kvm_set_ls3a_ipi(struct kvm *kvm, struct loongarch_gipiState *state);
int kvm_get_ls3a_ipi(struct kvm *kvm, struct loongarch_gipiState *state);
int kvm_helper_send_ipi(struct kvm_vcpu *vcpu, unsigned int cpu, unsigned int action);
#endif
