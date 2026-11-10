// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Huawei Technologies Co., Ltd. */

#include <linux/cacheflush.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

#include "mmu.h"
#include "pvm.h"

static int pvm_inject_dc_abort(struct kvm_vcpu *vcpu, u64 va, u32 fsc)
{
	u64 esr = ((u64)ESR_ELx_EC_DABT_CUR << ESR_ELx_EC_SHIFT) |
		  ESR_ELx_IL | ESR_ELx_CM | ESR_ELx_WNR | (fsc & ESR_ELx_FSC);

	/* Supply the data-abort syndrome and operand VA for an UNKNOWN trap. */
	kvm_inject_dabt(vcpu, va);
	vcpu_write_sys_reg(vcpu, esr, ESR_EL1);
	return 1;
}

int kvm_pvm_emulate_dc_by_va(struct kvm_vcpu *vcpu, u32 insn)
{
	struct kvm_s1_trans trans = {};
	unsigned long kaddr, line;
	kvm_pfn_t pfn;
	u64 va;
	u32 fsc;
	bool mmu_enabled;
	int idx, ret;

	if (!is_pvm_mode() || !vcpu_mode_priv(vcpu) ||
	    !aarch64_insn_is_dc_ivac(insn))
		return 0;

	va = vcpu_get_reg(vcpu, insn & 0x1f);
	mmu_enabled = kvm_pvm_vcpu_mmu_enabled(vcpu);
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (mmu_enabled) {
		ret = kvm_pvm_walk_shadow_s1(vcpu, va, &trans);
		if (ret) {
			fsc = trans.esr & ESR_ELx_FSC;
			goto out_fault;
		}
		/* IVAC requires write permission to the target address. */
		if (!trans.pw) {
			fsc = ESR_ELx_FSC_PERM | (trans.level & ESR_ELx_FSC_LEVEL);
			goto out_fault;
		}
	} else {
		if (va >= kvm_phys_size(vcpu->kvm))
			goto out_retire;
		trans.output = va;
	}

	/* Maintenance changes cache state, not guest bytes; a read pin suffices. */
	pfn = gfn_to_pfn_prot(vcpu->kvm, gpa_to_gfn(trans.output), false, NULL);
	if (is_error_noslot_pfn(pfn)) {
		if (!mmu_enabled)
			goto out_retire;
		ret = -EFAULT;
		goto out_error;
	}
	if (pfn_is_map_memory(pfn)) {
		kaddr = (unsigned long)page_address(pfn_to_page(pfn));
		line = 4UL << FIELD_GET(CTR_EL0_DminLine_MASK,
				       read_sysreg(ctr_el0));
		kaddr += offset_in_page(trans.output);
		kaddr = ALIGN_DOWN(kaddr, line);
		/* IVAC must not discard dirty cache lines belonging to the host. */
		dcache_clean_inval_poc(kaddr, kaddr + line);
	}
	kvm_release_pfn_clean(pfn);
out_retire:
	/* Retain the MMU-off boot policy for addresses without backing RAM. */
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	kvm_incr_pc(vcpu);
	return 1;
out_fault:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return pvm_inject_dc_abort(vcpu, va, fsc);
out_error:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
