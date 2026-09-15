// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>

#include <pvm/pvm.h>

void kvm_pvm_emulate_eret(struct kvm_vcpu *vcpu)
{
	u64 elr = ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1);
	u64 spsr = ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1);

	switch (pvm_eret_target(spsr)) {
	case PVM_ERET_LEGAL:
		*vcpu_pc(vcpu) = elr;
		*vcpu_cpsr(vcpu) = spsr;
		break;
	case PVM_ERET_ILLEGAL:
		/*
		 * As kvm_check_illegal_exception_return() does, keep the EL
		 * and set PSTATE.IL, then deliver the Illegal Execution state
		 * exception that the next instruction would take.
		 */
		*vcpu_pc(vcpu) = elr;
		*vcpu_cpsr(vcpu) |= PSR_IL_BIT;
		kvm_pvm_inject_sync(vcpu, ESR_ELx_IL |
				   (ESR_ELx_EC_ILL << ESR_ELx_EC_SHIFT));
		break;
	case PVM_ERET_EL1T:
		kvm_inject_undefined(vcpu);
		break;
	}
}

int kvm_pvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr_el1)
{
	__kvm_adjust_pc(vcpu);
	kvm_pend_exception(vcpu, EXCEPT_AA64_EL1_SYNC);
	ctxt_sys_reg(&vcpu->arch.ctxt, ESR_EL1) = esr_el1;

	return 1;
}
