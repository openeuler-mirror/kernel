/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_TLBI_H__
#define __ARM64_KVM_PVM_TLBI_H__

#include <linux/types.h>

struct kvm_vcpu;

struct kvm_s2_mmu;
struct kvm_pvm_unmap_page;

void kvm_pvm_note_shadow_leaf(struct kvm_s2_mmu *mmu, u64 pte);
void kvm_pvm_flush_tlb_asid(u16 asid);
void kvm_pvm_flush_shadow_tlb_batch(struct kvm_pvm_unmap_page *pages,
				    unsigned int nr);
void kvm_pvm_flush_shadow_tlb(struct kvm_s2_mmu *mmu);
void kvm_pvm_flush_shadow_tlb_ipa(struct kvm_s2_mmu *mmu, u64 addr, int level);
void kvm_pvm_flush_shadow_tlb_ipa_nsh(struct kvm_s2_mmu *mmu, u64 addr, int level);

/*
 * Decode base EL1 operations and perform shadow invalidation.
 * Range and Outer Shareable extensions are not accepted.
 * Return one after shadow invalidation and PC advancement, or zero if rejected.
 * Call from a sleepable host context without mmu_lock held. This function
 * acquires mmu_lock, and the full unmap may drop the lock and reschedule.
 */
int kvm_pvm_emulate_tlbi(struct kvm_vcpu *vcpu, u32 insn);

#endif /* __ARM64_KVM_PVM_TLBI_H__ */
