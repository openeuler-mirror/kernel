// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_pvm.h>

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
		WARN_ON_ONCE(pvm->suser_mmus[i]->active);
		kvm_free_stage2_pgd(&pvm->suser_mmus[i]->mmu);
		kfree(pvm->suser_mmus[i]);
	}

	kvfree(pvm->suser_mmus);
	pvm->suser_mmus = NULL;
	pvm->suser_mmus_size = 0;
	pvm->suser_mmus_next = 0;
}

bool kvm_pvm_vcpu_mmu_enabled(struct kvm_vcpu *vcpu)
{
	return ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1) & SCTLR_ELx_M;
}

static u16 pvm_guest_asid(struct kvm_vcpu *vcpu, u64 tcr)
{
	u64 ttbr = ctxt_sys_reg(&vcpu->arch.ctxt,
			       (tcr & TCR_A1) ? TTBR1_EL1 : TTBR0_EL1);
	u16 asid = FIELD_GET(TTBR_ASID_MASK, ttbr);

	return (tcr & TCR_ASID16) ? asid : asid & 0xff;
}

static void pvm_put_mmu(struct kvm_pvm_mmu *mmu)
{
	if (WARN_ON_ONCE(!mmu->active))
		return;
	mmu->active--;
}

static bool pvm_user_va_bits_valid(u64 tcr)
{
	unsigned int va_bits = 64 - FIELD_GET(TCR_T0SZ_MASK, tcr);

	return va_bits >= PVM_SHADOW_S1_MIN_VA_BITS && va_bits <= 47;
}

static bool pvm_user_key_matches(struct kvm_pvm_mmu *mmu, u64 ttbr0,
				 u64 tcr, u64 sctlr, u64 mair, u16 asid)
{
	return (mmu->ttbr0 & TTBRx_EL1_BADDR) ==
	       (ttbr0 & TTBRx_EL1_BADDR) && mmu->tcr == tcr &&
	       mmu->sctlr == sctlr && mmu->mair == mair && mmu->asid == asid;
}

static bool pvm_cached_contexts_match(struct kvm_vcpu *vcpu)
{
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);
	u64 tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);
	bool matches;

	read_lock(&vcpu->kvm->mmu_lock);
	if (kvm_to_pvm(vcpu->kvm)->invalidating)
		matches = false;
	else if (!kvm_pvm_vcpu_mmu_enabled(vcpu) || !pvm_user_va_bits_valid(tcr))
		matches = !pv->suser_mmu;
	else
		matches = pv->suser_mmu && pv->suser_mmu->used &&
			  pvm_user_key_matches(pv->suser_mmu,
					       ctxt_sys_reg(&vcpu->arch.ctxt, TTBR0_EL1), tcr,
					       ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1),
					       ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1),
					       pvm_guest_asid(vcpu, tcr));
	read_unlock(&vcpu->kvm->mmu_lock);
	return matches;
}

int kvm_pvm_vcpu_select_mmu(struct kvm_vcpu *vcpu, bool may_block)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);
	struct kvm_pvm_mmu *mmu = NULL, *old;
	u64 ttbr0, tcr, sctlr, mair;
	u16 asid;
	unsigned int va_bits;
	unsigned long seq;
	size_t i;
	int ret = 0;

	/* Pins survive scheduling; only a matching, published regime is reusable. */
	if (pvm_cached_contexts_match(vcpu))
		return 0;

	ttbr0 = ctxt_sys_reg(&vcpu->arch.ctxt, TTBR0_EL1);
	tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);
	sctlr = ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1);
	mair = ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1);
	asid = pvm_guest_asid(vcpu, tcr);
	va_bits = 64 - FIELD_GET(TCR_T0SZ_MASK, tcr);

	write_lock(&kvm->mmu_lock);
	seq = pvm->invalidate_seq;
	if (pvm->invalidating) {
		ret = -EAGAIN;
		goto out;
	}
	old = pv->suser_mmu;
	if (!kvm_pvm_vcpu_mmu_enabled(vcpu) || !pvm_user_va_bits_valid(tcr)) {
		pv->suser_mmu = NULL;
		if (old)
			pvm_put_mmu(old);
		goto out;
	}

	for (i = 0; i < pvm->suser_mmus_size; i++) {
		struct kvm_pvm_mmu *candidate = pvm->suser_mmus[i];

		if (candidate->used &&
		    pvm_user_key_matches(candidate, ttbr0, tcr, sctlr, mair, asid)) {
			mmu = candidate;
			break;
		}
	}

	if (mmu == old && mmu)
		goto out;
	if (mmu) {
		mmu->active++;
	} else {
		for (i = 0; i < pvm->suser_mmus_size; i++) {
			size_t index = (pvm->suser_mmus_next + i) %
				       pvm->suser_mmus_size;

			if (!pvm->suser_mmus[index]->active) {
				mmu = pvm->suser_mmus[index];
				pvm->suser_mmus_next =
					(index + 1) % pvm->suser_mmus_size;
				break;
			}
		}
		if (!mmu) {
			ret = -EBUSY;
			goto out;
		}

		/* Reserve the context before unmapping can drop mmu_lock. */
		mmu->used = false;
		mmu->active++;
		unmap_stage2_range(&mmu->mmu, 0,
				   BIT_ULL(mmu->mmu.pgt->ia_bits), may_block);
		if (pvm->invalidating || pvm->invalidate_seq != seq) {
			pvm_put_mmu(mmu);
			ret = -EAGAIN;
			goto out;
		}
		mmu->ttbr0 = ttbr0;
		mmu->tcr = tcr;
		mmu->sctlr = sctlr;
		mmu->mair = mair;
		mmu->asid = asid;
		mmu->mmu.pgt->ia_bits = va_bits;
		mmu->mmu.pgt->start_level = KVM_PGTABLE_MAX_LEVELS -
					   PVM_PGTABLE_LEVELS(va_bits);
		mmu->used = true;
	}

	pv->suser_mmu = mmu;
	if (old)
		pvm_put_mmu(old);
out:
	write_unlock(&kvm->mmu_lock);
	return ret;
}

void kvm_pvm_vcpu_put_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);

	write_lock(&vcpu->kvm->mmu_lock);
	if (pv->suser_mmu) {
		pvm_put_mmu(pv->suser_mmu);
		pv->suser_mmu = NULL;
	}
	write_unlock(&vcpu->kvm->mmu_lock);
}

void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t i;

	lockdep_assert_held_write(&kvm->mmu_lock);
	if (!kvm->arch.mmu.pgt)
		return;
	pvm->invalidating++;
	pvm->invalidate_seq++;
	/*
	 * Unpublished, unpinned contexts have no guest mappings. A context
	 * being unmapped keeps an active pin even while mmu_lock is dropped,
	 * so another invalidation must not skip it until withdrawal completes.
	 */
	for (i = 0; i < pvm->suser_mmus_size; i++) {
		struct kvm_pvm_mmu *mmu = pvm->suser_mmus[i];

		if (!mmu->used && !mmu->active)
			continue;
		mmu->used = false;
		mmu->active++;
		unmap_stage2_range(&mmu->mmu, 0,
				   BIT_ULL(mmu->mmu.pgt->ia_bits), may_block);
		pvm_put_mmu(mmu);
	}
	unmap_stage2_range(&kvm->arch.mmu, 0, kvm_phys_size(kvm), may_block);
	pvm->invalidate_seq++;
	pvm->invalidating--;
}
