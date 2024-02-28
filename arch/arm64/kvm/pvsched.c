// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#ifdef CONFIG_PARAVIRT_SCHED
#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/pvsched-abi.h>

#include <kvm/arm_hypercalls.h>

void kvm_update_pvsched_preempted(struct kvm_vcpu *vcpu, u32 preempted)
{
	struct kvm *kvm = vcpu->kvm;
	u64 base = vcpu->arch.pvsched.base;
	u64 offset = offsetof(struct pvsched_vcpu_state, preempted);
	int idx;

	if (base == INVALID_GPA)
		return;

	/*
	 * This function is called from atomic context, so we need to
	 * disable page faults.
	 */
	pagefault_disable();

	idx = srcu_read_lock(&kvm->srcu);
	kvm_put_guest(kvm, base + offset, cpu_to_le32(preempted));
	srcu_read_unlock(&kvm->srcu, idx);

	pagefault_enable();
}

long kvm_hypercall_pvsched_features(struct kvm_vcpu *vcpu)
{
	u32 feature = smccc_get_arg1(vcpu);
	long val = SMCCC_RET_NOT_SUPPORTED;

	switch (feature) {
	case ARM_SMCCC_HV_PV_SCHED_FEATURES:
	case ARM_SMCCC_HV_PV_SCHED_IPA_INIT:
	case ARM_SMCCC_HV_PV_SCHED_IPA_RELEASE:
		val = SMCCC_RET_SUCCESS;
		break;
	}

	return val;
}
#endif /* CONFIG_PARAVIRT_SCHED */

