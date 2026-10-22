/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_MMU_H__
#define __ARM64_KVM_PVM_MMU_H__

#include <linux/kvm_host.h>

#include "pvm.h"

/* Private wrappers keep PVM metadata out of the public KVM structures. */
struct kvm_pvm_mmu {
	struct kvm_s2_mmu mmu;
};

int kvm_pvm_init_vcpu_mmu(struct kvm_vcpu *vcpu);
void kvm_pvm_destroy_mmu(struct kvm *kvm);
void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block);

#endif /* __ARM64_KVM_PVM_MMU_H__ */
