// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/insn.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>

#include "mmu.h"
#include "tlbi.h"

int kvm_pvm_emulate_tlbi(struct kvm_vcpu *vcpu, u32 insn)
{
	u32 crm = sys_reg_CRm(insn);
	u32 op2 = sys_reg_Op2(insn);

	/* Base EL1 operations; range and OS extensions are not advertised. */
	if (!is_pvm_mode() || !vcpu_mode_priv(vcpu) ||
	    !aarch64_insn_is_tlbi(insn) || sys_reg_Op1(insn) != 0 ||
	    sys_reg_CRn(insn) != 8 || (crm != 3 && crm != 7) ||
	    !(op2 <= 3 || op2 == 5 || op2 == 7))
		return 0;

	/* Discard software translations too, or hardware can refill stale data. */
	write_lock(&vcpu->kvm->mmu_lock);
	kvm_pvm_unmap_all(vcpu->kvm, true);
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_incr_pc(vcpu);
	return 1;
}
