/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_TLBI_H__
#define __ARM64_KVM_PVM_TLBI_H__

#include <linux/types.h>

struct kvm_vcpu;

/*
 * Validate base EL1 operations and perform conservative full invalidation.
 * Range and Outer Shareable extensions are not accepted.
 * Return one after full invalidation and PC advancement, or zero if rejected.
 * Call from a sleepable host context without mmu_lock held. This function
 * acquires mmu_lock, and the full unmap may drop the lock and reschedule.
 */
int kvm_pvm_emulate_tlbi(struct kvm_vcpu *vcpu, u32 insn);

#endif /* __ARM64_KVM_PVM_TLBI_H__ */
