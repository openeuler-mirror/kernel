// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#include <linux/arm-smccc.h>

#include <kvm/arm_hypercalls.h>

int kvm_hypercall_pvsched_features(struct kvm_vcpu *vcpu)
{
	u32 feature = smccc_get_arg1(vcpu);
	int val = SMCCC_RET_NOT_SUPPORTED;

	switch (feature) {
	case ARM_SMCCC_HV_PV_SCHED_FEATURES:
		val = SMCCC_RET_SUCCESS;
		break;
	}

	return val;
}
