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

#endif

