/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: wanghaibin <wanghaibin.wang@huawei.com>
 */

#ifndef __ASM_ARM_KVM_RV_TIMER_H
#define __ASM_ARM_KVM_RV_TIMER_H

#include <linux/clocksource.h>
#include <linux/hrtimer.h>
#include <linux/init.h>

#include <kvm/arm_arch_timer.h>

enum kvm_rv_timers {
	RVTIMER_VTIMER,
	NR_KVM_RVTIMERS,
};

struct rv_timer_offset {
	/*
	 * If set, pointer to one of the offsets in the kvm's offset
	 * structure. If NULL, assume a zero offset.
	 */
	u64	*vm_offset;
};

struct rv_timer_vm_data {
	u64	offset;

	/* The PPI for each timer, global to the VM */
	u8	ppi[NR_KVM_RVTIMERS];
};

struct rv_timer_context {
	struct kvm_vcpu			*vcpu;

	/* Host hrtimer backing the virtual timer. */
	struct hrtimer			hrtimer;
	u64				ns_frac;

	/* Offset for this counter/timer */
	struct rv_timer_offset		offset;

	/* Output level of the timer IRQ */
	struct {
		bool			level;
	} irq;
};

struct rv_timer_cpu {
	struct rv_timer_context timers[NR_KVM_RVTIMERS];

	/* Background timer used when the guest is not running */
	struct hrtimer			bg_timer;

	/* Is the timer enabled */
	bool			enabled;
};

int __init kvm_rv_timer_hyp_init(void);

void kvm_rv_timer_init_vm(struct kvm *kvm);
void kvm_rv_timer_vcpu_init(struct kvm_vcpu *vcpu);
int kvm_rv_timer_enable(struct kvm_vcpu *vcpu);
void kvm_rv_timer_vcpu_terminate(struct kvm_vcpu *vcpu);
int kvm_rv_timer_vcpu_reset(struct kvm_vcpu *vcpu);

u64 kvm_rv_timer_read_sysreg(struct kvm_vcpu *vcpu,
			     enum kvm_arch_timers tmr,
			     enum kvm_arch_timer_regs treg);
void kvm_rv_timer_write_sysreg(struct kvm_vcpu *vcpu,
			       enum kvm_arch_timers tmr,
			       enum kvm_arch_timer_regs treg,
			       u64 val);

u64 kvm_rv_timer_get_reg(struct kvm_vcpu *vcpu, u64 regid);
int kvm_rv_timer_set_reg(struct kvm_vcpu *vcpu, u64 regid, u64 value);

void kvm_rv_timer_vcpu_load(struct kvm_vcpu *vcpu);
void kvm_rv_timer_vcpu_put(struct kvm_vcpu *vcpu);

int kvm_cpu_has_pending_rv_timer(struct kvm_vcpu *vcpu);

/* Needed for tracing */
u32 rv_timer_get_ctl(struct rv_timer_context *ctxt);
u64 rv_timer_get_cval(struct rv_timer_context *ctxt);

#endif
