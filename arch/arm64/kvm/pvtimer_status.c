// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 * Author: Jia Qingtong <jiaqingtong@huawei.com>
 */

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>
#include <asm/pvtimer-status-abi.h>

#include <kvm/arm_hypercalls.h>

#ifdef CONFIG_VIRT_VTIMER_PV_STATUS
gpa_t kvm_init_pvtimer_status(struct kvm_vcpu *vcpu)
{
	/* no more things need to do. */
	return vcpu->arch.pvtimer_status.base;
}

int kvm_arm_pvtimer_status_set_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	struct kvm *kvm = vcpu->kvm;
	u64 ipa;
	int ret = 0;
	int idx;

	if (attr->attr != KVM_ARM_VCPU_PVTIMER_STATUS_IPA)
		return -ENXIO;

	if (get_user(ipa, user))
		return -EFAULT;
	if (!IS_ALIGNED(ipa, 64))
		return -EINVAL;
	if (vcpu->arch.pvtimer_status.base != INVALID_GPA)
		return -EEXIST;

	/* Check the address is in a valid memslot */
	idx = srcu_read_lock(&kvm->srcu);
	if (kvm_is_error_hva(gfn_to_hva(kvm, ipa >> PAGE_SHIFT)))
		ret = -EINVAL;
	srcu_read_unlock(&kvm->srcu, idx);

	if (!ret)
		vcpu->arch.pvtimer_status.base = ipa;

	return ret;
}

int kvm_arm_pvtimer_status_get_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	u64 ipa;

	if (attr->attr != KVM_ARM_VCPU_PVTIMER_STATUS_IPA)
		return -ENXIO;

	ipa = vcpu->arch.pvtimer_status.base;

	if (put_user(ipa, user))
		return -EFAULT;
	return 0;
}

int kvm_arm_pvtimer_status_has_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_ARM_VCPU_PVTIMER_STATUS_IPA:
		return vtimer_is_irqbypass() ? 0 : -ENXIO;
	}
	return -ENXIO;
}

#endif

