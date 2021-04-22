// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/pvsched-abi.h>

#include <kvm/arm_hypercalls.h>

void kvm_update_pvsched_preempted(struct kvm_vcpu *vcpu, u32 preempted)
{
	__le32 preempted_le;
	u64 offset;
	int idx;
	u64 base = vcpu->arch.pvsched.base;
	struct kvm *kvm = vcpu->kvm;

	if (base == GPA_INVALID)
		return;

	preempted_le = cpu_to_le32(preempted);

	/*
	 * This function is called from atomic context, so we need to
	 * disable page faults.
	 */
	pagefault_disable();

	idx = srcu_read_lock(&kvm->srcu);
	offset = offsetof(struct pvsched_vcpu_state, preempted);
	kvm_put_guest(kvm, base + offset, preempted_le, u32);
	srcu_read_unlock(&kvm->srcu, idx);

	pagefault_enable();
}

int kvm_hypercall_pvsched_features(struct kvm_vcpu *vcpu)
{
	u32 feature = smccc_get_arg1(vcpu);
	int val = SMCCC_RET_NOT_SUPPORTED;

	switch (feature) {
	case ARM_SMCCC_HV_PV_SCHED_FEATURES:
	case ARM_SMCCC_HV_PV_SCHED_IPA_INIT:
	case ARM_SMCCC_HV_PV_SCHED_IPA_RELEASE:
		val = SMCCC_RET_SUCCESS;
		break;
	}

	return val;
}
