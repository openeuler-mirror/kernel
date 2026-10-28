// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pvm.h>
#include <asm/sysreg.h>

#include "mmu.h"
#include "pvm.h"

static u64 kvm_pvm_par_fault(u32 fsc)
{
	return SYS_PAR_EL1_F | SYS_PAR_EL1_RES1 |
	       ((u64)(fsc & ESR_ELx_FSC) << 1);
}

static u64 kvm_pvm_par_success(struct kvm_vcpu *vcpu,
			       const struct kvm_s1_trans *trans)
{
	u64 attr_index = FIELD_GET(PTE_ATTRINDX_MASK, trans->desc);
	u64 mair = ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1);
	u64 attr = (mair >> (attr_index * 8)) & GENMASK_ULL(7, 0);
	u64 sh = FIELD_GET(GENMASK_ULL(9, 8), trans->desc);

	/* Device and fully non-cacheable Normal memory are Outer Shareable. */
	if (!(attr & 0xf0) || attr == 0x44)
		sh = 2;

	return (trans->output & SYS_PAR_EL1_PA) |
	       FIELD_PREP(SYS_PAR_EL1_ATTR, attr) |
	       FIELD_PREP(SYS_PAR_EL1_SH, sh) |
	       SYS_PAR_EL1_RES1;
}

/*
 * Support the S1E1R operation used by the Linux fault path. Other AT
 * variants remain unsupported; this is not a complete AT implementation.
 */
int kvm_pvm_emulate_at(struct kvm_vcpu *vcpu, u32 insn)
{
	struct kvm_s1_trans trans = {};
	u64 par, va;
	u32 fsc, rt;
	int idx;
	int ret;

	if (!is_pvm_mode() || !vcpu_mode_priv(vcpu) ||
	    !aarch64_insn_is_at_s1e1r(insn))
		return 0;

	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	va = vcpu_get_reg(vcpu, rt);

	/*
	 * With the guest MMU off the read resolves by identity: the
	 * address is the output with Device-nGnRnE, Outer Shareable
	 * attributes.  Anything above the IPA limit reports an
	 * address-size fault.
	 */
	if (!kvm_pvm_vcpu_mmu_enabled(vcpu)) {
		if (va >= kvm_phys_size(vcpu->kvm))
			par = kvm_pvm_par_fault(0);
		else
			par = (va & SYS_PAR_EL1_PA) | SYS_PAR_EL1_RES1 |
			      FIELD_PREP(SYS_PAR_EL1_SH, 2);
		goto out;
	}

	/* The walk reads guest page-table pages through the L1 slots. */
	idx = srcu_read_lock(&vcpu->kvm->srcu);

	ret = kvm_pvm_walk_shadow_s1(vcpu, va, &trans);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	if (ret) {
		fsc = trans.esr & ESR_ELx_FSC;
		par = kvm_pvm_par_fault(fsc);
	} else if (!trans.pr) {
		par = kvm_pvm_par_fault(ESR_ELx_FSC_PERM |
					     (trans.level & ESR_ELx_FSC_LEVEL));
	} else {
		par = kvm_pvm_par_success(vcpu, &trans);
	}

out:
	vcpu_write_sys_reg(vcpu, par, PAR_EL1);
	kvm_incr_pc(vcpu);

	return 1;
}
