// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/sched/stat.h>
#include <asm/kvm_para.h>
#include "intc/ls3a_ipi.h"
#include "kvm_compat.h"


int kvm_virt_ipi(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	u64 ipi_bitmap;
	unsigned int min, action, cpu;

	ipi_bitmap = vcpu->arch.gprs[KVM_REG_A1];
	min = vcpu->arch.gprs[KVM_REG_A2];
	action = vcpu->arch.gprs[KVM_REG_A3];

	if (ipi_bitmap) {
		cpu = find_first_bit((void *)&ipi_bitmap, BITS_PER_LONG);
		while (cpu < BITS_PER_LONG) {
			kvm_helper_send_ipi(vcpu, cpu + min, action);
			cpu = find_next_bit((void *)&ipi_bitmap, BITS_PER_LONG, cpu + 1);
		}
	}

	return ret;
}

int kvm_save_notify(struct kvm_vcpu *vcpu)
{
	unsigned long num, id, data;

	int ret = 0;

	num = vcpu->arch.gprs[KVM_REG_A0];
	id = vcpu->arch.gprs[KVM_REG_A1];
	data = vcpu->arch.gprs[KVM_REG_A2];

	switch (id) {
	case KVM_FEATURE_STEAL_TIME:
		if (!sched_info_on())
			break;
		vcpu->arch.st.guest_addr = data;
		kvm_debug("cpu :%d addr:%lx\n", vcpu->vcpu_id, data);
		vcpu->arch.st.last_steal = current->sched_info.run_delay;
		kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);
		break;
	default:
		break;
	};

	return ret;
};

static int _kvm_pv_feature(struct kvm_vcpu *vcpu)
{
	int feature = vcpu->arch.gprs[KVM_REG_A1];
	int ret = KVM_RET_NOT_SUPPORTED;
	switch (feature) {
	case KVM_FEATURE_STEAL_TIME:
		if (sched_info_on())
			ret = KVM_RET_SUC;
		break;
	case KVM_FEATURE_MULTI_IPI:
		ret = KVM_RET_SUC;
		break;
	default:
		break;
	}
	return ret;
}

/*
 * hypcall emulation always return to guest, Caller should check retval.
 */
int _kvm_handle_pv_hcall(struct kvm_vcpu *vcpu)
{
	unsigned long func = vcpu->arch.gprs[KVM_REG_A0];
	int hyp_ret = KVM_RET_NOT_SUPPORTED;

	switch (func) {
	case KVM_HC_FUNC_FEATURE:
		hyp_ret = _kvm_pv_feature(vcpu);
		break;
	case KVM_HC_FUNC_NOTIFY:
		hyp_ret = kvm_save_notify(vcpu);
		break;
	case KVM_HC_FUNC_IPI:
		hyp_ret = kvm_virt_ipi(vcpu);
		break;
	default:
		kvm_info("[%#lx] hvc func:%#lx unsupported\n", vcpu->arch.pc, func);
		break;
	};

	vcpu->arch.gprs[KVM_REG_A0] = hyp_ret;

	return RESUME_GUEST;
}
