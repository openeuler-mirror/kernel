// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <asm/kvm_mmu.h>

#include "mmu.h"

#define PVM_SUSER_MMUS_PER_VCPU 8

/*
 * KVM_ARM_VCPU_INIT runs after KVM_CREATE_VCPU has accounted the vCPU in
 * online_vcpus. Size the shared pool for all vCPUs created so far, whether
 * userspace initializes them one at a time or after creating the full set.
 */
int kvm_pvm_init_vcpu_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	struct kvm_pvm_mmu **old = pvm->suser_mmus;
	struct kvm_pvm_mmu **new;
	size_t old_size = pvm->suser_mmus_size;
	size_t new_size, i;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	new_size = atomic_read(&kvm->online_vcpus) *
		   PVM_SUSER_MMUS_PER_VCPU;
	if (new_size <= old_size)
		return 0;

	new = kvcalloc(new_size, sizeof(*new), GFP_KERNEL_ACCOUNT);
	if (!new)
		return -ENOMEM;

	if (old_size)
		memcpy(new, old, size_mul(old_size, sizeof(*old)));
	for (i = old_size; i < new_size; i++) {
		new[i] = kzalloc(sizeof(*new[i]), GFP_KERNEL_ACCOUNT);
		if (!new[i]) {
			ret = -ENOMEM;
			goto err_free_new_mmus;
		}

		ret = kvm_init_shadow_mmu(kvm, &new[i]->mmu);
		if (ret) {
			kfree(new[i]);
			goto err_free_new_mmus;
		}
	}

	write_lock(&kvm->mmu_lock);
	pvm->suser_mmus = new;
	pvm->suser_mmus_size = new_size;
	write_unlock(&kvm->mmu_lock);
	kvfree(old);
	return 0;

err_free_new_mmus:
	while (i-- > old_size) {
		kvm_free_stage2_pgd(&new[i]->mmu);
		kfree(new[i]);
	}
	kvfree(new);
	return ret;
}

void kvm_pvm_destroy_mmu(struct kvm *kvm)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t i;

	for (i = 0; i < pvm->suser_mmus_size; i++) {
		kvm_free_stage2_pgd(&pvm->suser_mmus[i]->mmu);
		kfree(pvm->suser_mmus[i]);
	}

	kvfree(pvm->suser_mmus);
	pvm->suser_mmus = NULL;
	pvm->suser_mmus_size = 0;
}

void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t i;

	lockdep_assert_held_write(&kvm->mmu_lock);
	if (!kvm->arch.mmu.pgt)
		return;
	for (i = 0; i < pvm->suser_mmus_size; i++)
		unmap_stage2_range(&pvm->suser_mmus[i]->mmu, 0,
				   BIT_ULL(pvm->suser_mmus[i]->mmu.pgt->ia_bits),
				   may_block);
	unmap_stage2_range(&kvm->arch.mmu, 0, kvm_phys_size(kvm), may_block);
}
