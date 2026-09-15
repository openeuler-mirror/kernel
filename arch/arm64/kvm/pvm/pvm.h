/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */
#ifndef __ARM64_KVM_PVM_H
#define __ARM64_KVM_PVM_H

#include <linux/types.h>

struct kvm_vcpu;

int kvm_pvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr_el1);

#endif /* __ARM64_KVM_PVM_H */
