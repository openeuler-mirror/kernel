// SPDX-License-Identifier: GPL-2.0-only
/*
 * Guest PC manipulation helpers
 *
 * Copyright (C) 2012,2013 - ARM Ltd
 * Copyright (C) 2020 - Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#ifndef __ARM64_KVM_HYP_ADJUST_PC_H__
#define __ARM64_KVM_HYP_ADJUST_PC_H__

#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_mmu.h>

static inline void kvm_skip_instr(struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu)) {
		kvm_skip_instr32(vcpu);
	} else {
		*vcpu_pc(vcpu) += 4;
		*vcpu_cpsr(vcpu) &= ~PSR_BTYPE_MASK;
	}

	/* advance the singlestep state machine */
	*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
}

/*
 * Skip an instruction which has been emulated at hyp while most guest sysregs
 * are live.
 */
static inline void __kvm_skip_instr(struct kvm_vcpu *vcpu)
{
	*vcpu_pc(vcpu) = read_sysreg_el2(SYS_ELR);
	if (is_pvm_mode())
		vcpu_gp_regs(vcpu)->pstate =
			pvm_restore_virtual_pstate(read_sysreg_el2(SYS_SPSR),
						   vcpu_gp_regs(vcpu)->pstate);
	else
		vcpu_gp_regs(vcpu)->pstate = read_sysreg_el2(SYS_SPSR);

	kvm_skip_instr(vcpu);

	write_sysreg_el2(is_pvm_mode() ?
			 pvm_to_phys_pstate(vcpu_gp_regs(vcpu)->pstate) :
			 vcpu_gp_regs(vcpu)->pstate, SYS_SPSR);
	write_sysreg_el2(*vcpu_pc(vcpu), SYS_ELR);
}

/*
 * Vector offset for an exception taken from @mode to @target_mode, which
 * must be a privileged mode with PSTATE.SP == 1.
 */
static inline u64 kvm_exception64_offset(unsigned long mode,
					 unsigned long target_mode)
{
	if (mode == target_mode)
		return CURRENT_EL_SP_ELx_VECTOR;
	if ((mode | PSR_MODE_THREAD_BIT) == target_mode)
		return CURRENT_EL_SP_EL0_VECTOR;
	if (!(mode & PSR_MODE32_BIT))
		return LOWER_EL_AArch64_VECTOR;
	return LOWER_EL_AArch32_VECTOR;
}

/*
 * PSTATE on exception entry to AArch64 @target_mode, computed from the old
 * PSTATE and the target SCTLR_ELx.
 *
 * When an exception is taken, most PSTATE fields are left unchanged in the
 * handler. However, some are explicitly overridden (e.g. M[4:0]). Luckily all
 * of the inherited bits have the same position in the AArch64/AArch32 SPSR_ELx
 * layouts, so we don't need to shuffle these for exceptions from AArch32 EL0.
 *
 * For the SPSR_ELx layout for AArch64, see ARM DDI 0487E.a page C5-429.
 * For the SPSR_ELx layout for AArch32, see ARM DDI 0487E.a page C5-426.
 *
 * Here we manipulate the fields in order of the AArch64 SPSR_ELx layout, from
 * MSB to LSB.
 */
static inline u64 kvm_exception64_pstate(struct kvm_vcpu *vcpu, u64 old,
					 u64 sctlr, unsigned long target_mode)
{
	u64 new = 0;

	new |= (old & PSR_N_BIT);
	new |= (old & PSR_Z_BIT);
	new |= (old & PSR_C_BIT);
	new |= (old & PSR_V_BIT);

	if (kvm_has_mte(kern_hyp_va(vcpu->kvm)))
		new |= PSR_TCO_BIT;

	new |= (old & PSR_DIT_BIT);

	// PSTATE.UAO is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D5-2579.

	// PSTATE.PAN is unchanged unless SCTLR_ELx.SPAN == 0b0
	// SCTLR_ELx.SPAN is RES1 when ARMv8.1-PAN is not implemented
	// See ARM DDI 0487E.a, page D5-2578.
	new |= (old & PSR_PAN_BIT);
	if (!(sctlr & SCTLR_EL1_SPAN))
		new |= PSR_PAN_BIT;

	// PSTATE.SS is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D2-2452.

	// PSTATE.IL is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, page D1-2306.

	// PSTATE.SSBS is set to SCTLR_ELx.DSSBS upon any exception to AArch64
	// See ARM DDI 0487E.a, page D13-3258
	if (sctlr & SCTLR_ELx_DSSBS)
		new |= PSR_SSBS_BIT;

	// PSTATE.BTYPE is set to zero upon any exception to AArch64
	// See ARM DDI 0487E.a, pages D1-2293 to D1-2294.

	new |= PSR_D_BIT;
	new |= PSR_A_BIT;
	new |= PSR_I_BIT;
	new |= PSR_F_BIT;

	new |= target_mode;

	return new;
}

/*
 * Skip an instruction while host sysregs are live.
 * Assumes host is always 64-bit.
 */
static inline void kvm_skip_host_instr(void)
{
	write_sysreg_el2(read_sysreg_el2(SYS_ELR) + 4, SYS_ELR);
}

#endif
