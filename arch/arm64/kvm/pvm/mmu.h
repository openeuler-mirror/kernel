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
	bool used;
	unsigned int active;
	u64 ttbr0;
	u64 tcr;
	u64 sctlr;
	u64 mair;
	u16 asid;
};

int kvm_pvm_init_vcpu_mmu(struct kvm_vcpu *vcpu);
void kvm_pvm_destroy_mmu(struct kvm *kvm);
void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block);
int kvm_pvm_vcpu_select_mmu(struct kvm_vcpu *vcpu, bool may_block);
void kvm_pvm_vcpu_put_mmu(struct kvm_vcpu *vcpu);
bool kvm_pvm_vcpu_mmu_enabled(struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_PVM_MMU_H__ */
