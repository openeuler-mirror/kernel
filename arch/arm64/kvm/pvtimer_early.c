// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 * Author: Jia Qingtong <jiaqingtong@huawei.com>
 */

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <asm/cputype.h>
#include <asm/kvm_mmu.h>
#include <asm/pvtimer-early-abi.h>

#include <kvm/arm_hypercalls.h>

#ifdef CONFIG_VIRT_TIMER_EARLY_INJECT

static int set_vm_timer_early_inject(const char *val, const struct kernel_param *kp);

ulong timer_early_inject_ns;
static const struct kernel_param_ops timer_early_inject_ns_ops = {
	.set = set_vm_timer_early_inject,
};

module_param_cb(timer_early_inject_ns, &timer_early_inject_ns_ops, &timer_early_inject_ns, 0600);
MODULE_PARM_DESC(timer_early_inject_ns, "Timer early injection latency in nanoseconds.");

void kvm_timer_early_inject_config(struct kvm *kvm)
{
	gpa_t base = kvm->arch.timer_early.base;
	u64 offset_early_ns = offsetof(struct pvtimer_early_vcpu_state, early_ns);
	int idx;

	if (base == INVALID_GPA)
		return;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_put_guest(kvm, base + offset_early_ns, cpu_to_le64(timer_early_inject_ns));
	srcu_read_unlock(&kvm->srcu, idx);
}

static int set_vm_timer_early_inject(const char *val, const struct kernel_param *kp)
{
	struct kvm *kvm;
	ulong oldvalue;
	int err;

	oldvalue = timer_early_inject_ns;
	err = param_set_ulong(val, kp);
	if (err)
		return err;

	if (oldvalue == timer_early_inject_ns)
		return err;

	/*
	 * We need to kick vcpus out of guest mode here to reload
	 * timer early inject config when re-enter guest mode.
	 */
	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		kvm_make_all_cpus_request(kvm, KVM_REQ_RELOAD_TIMER_EARLY_INJECT);
	mutex_unlock(&kvm_lock);
	return err;
}

gpa_t kvm_init_timer_early_inject(struct kvm *kvm)
{
	kvm_timer_early_inject_config(kvm);

	return kvm->arch.timer_early.base;
}

void kvm_arm_timer_early_inject_vm_init(struct kvm *kvm)
{
	kvm->arch.timer_early.base = INVALID_GPA;
}

#define TIMER_EARLY_NS_HIP12 180
int kvm_arm_timer_early_inject_set_attr(struct kvm *kvm,
					struct kvm_device_attr *attr)
{
	u64 __user *user = (u64 __user *)attr->addr;
	u64 ipa;
	int ret = 0;
	int idx;

	if (attr->attr != KVM_VM_TIMER_EARLY_INJECT_IPA)
		return -ENXIO;

	if (get_user(ipa, user))
		return -EFAULT;
	if (!IS_ALIGNED(ipa, 64))
		return -EINVAL;
	if (kvm->arch.timer_early.base != INVALID_GPA)
		return -EEXIST;

	/* Check the address is in a valid memslot */
	idx = srcu_read_lock(&kvm->srcu);
	if (kvm_is_error_hva(gfn_to_hva(kvm, ipa >> PAGE_SHIFT)))
		ret = -EINVAL;
	srcu_read_unlock(&kvm->srcu, idx);

	if (!ret) {
		kvm->arch.timer_early.base = ipa;
		/* let's set default value if user did'nt set */
		if ((timer_early_inject_ns == 0) &&
		    ((read_cpuid_id() & MIDR_CPU_MODEL_MASK) == MIDR_HISI_HIP12)) {
			timer_early_inject_ns = TIMER_EARLY_NS_HIP12;
		}
	}

	return ret;
}

int kvm_arm_timer_early_inject_has_attr(struct kvm *kvm,
					struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_VM_TIMER_EARLY_INJECT_IPA:
		return 0;
	}
	return -ENXIO;
}

bool kvm_arm_timer_early_inject_supported(void)
{
	return IS_ENABLED(CONFIG_VIRT_TIMER_EARLY_INJECT);
}

#endif
