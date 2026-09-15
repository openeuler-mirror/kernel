// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>

#include <pvm/pvm.h>

int kvm_pvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr_el1)
{
	__kvm_adjust_pc(vcpu);
	kvm_pend_exception(vcpu, EXCEPT_AA64_EL1_SYNC);
	ctxt_sys_reg(&vcpu->arch.ctxt, ESR_EL1) = esr_el1;

	return 1;
}
