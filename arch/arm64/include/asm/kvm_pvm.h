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

void kvm_arm_init_pvm(void);
void kvm_arm_destroy_pvm(void);

#endif /* __ARM64_KVM_PVM_H__ */
