// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/insn.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

#include <pvm/pvm.h>

#include "mmu.h"

/* Copy an opcode without retaining a translation or page reference. */
int kvm_pvm_read_guest_insn(struct kvm_vcpu *vcpu, u32 *insn)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_s1_trans trans = {};
	u64 pc = *vcpu_pc(vcpu);
	__le32 opcode;
	int idx, ret;

	*insn = 0;
	if (!IS_ALIGNED(pc, sizeof(opcode)))
		return -EFAULT;

	idx = srcu_read_lock(&kvm->srcu);
	if (kvm_pvm_vcpu_mmu_enabled(vcpu)) {
		ret = kvm_pvm_walk_shadow_s1(vcpu, pc, &trans);
		if (ret || !(trans.px || trans.ux)) {
			ret = -EFAULT;
			goto out;
		}
	} else {
		if (pc >= kvm_phys_size(kvm)) {
			ret = -EFAULT;
			goto out;
		}
		trans.output = pc;
	}

	ret = kvm_read_guest(kvm, trans.output, &opcode, sizeof(opcode));
	if (!ret)
		*insn = le32_to_cpu(opcode);
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

/* The caller classifies MRS/MSR/SYS; supply the missing SYS64 syndrome. */
int kvm_pvm_emulate_sysreg(struct kvm_vcpu *vcpu, u32 insn)
{
	u32 sysreg, rt;
	u64 esr;

	sysreg = (u32)aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16,
						    insn) << 5;
	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	esr = ESR_ELx_IL | (ESR_ELx_EC_SYS64 << ESR_ELx_EC_SHIFT) |
	      sysreg_to_esr_sys64_iss(sysreg) |
	      (rt << ESR_ELx_SYS64_ISS_RT_SHIFT) |
	      (aarch64_insn_is_mrs(insn) ? ESR_ELx_SYS64_ISS_DIR_READ :
					ESR_ELx_SYS64_ISS_DIR_WRITE);
	vcpu->arch.fault.esr_el2 = esr;

	return kvm_handle_sys_reg(vcpu);
}

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
