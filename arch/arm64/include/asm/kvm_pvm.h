/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_H__
#define __ARM64_KVM_PVM_H__

#include <linux/types.h>

struct kvm_vcpu;
bool kvm_pvm_vgic_cpuif_access(struct kvm_vcpu *vcpu, u32 sysreg,
			       bool is_write, u64 *val);

void __init kvm_arm_init_pvm(void);
#define KVM_PVM_IPA_BITS 48
#define PVM_SHADOW_S1_VA_BITS 48

void kvm_arm_destroy_pvm(void);

bool kvm_pvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu);
void kvm_pvm_vgic_flush_hwstate(struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_PVM_H__ */
