// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/switch.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pvm.h>
#include <asm/mmu_context.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/vectors.h>

#include "../../pvm/mmu.h"

/* VHE specific context */
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);

/* PVM mode: the SCTLR_EL1 value the guest runs with on this CPU */
DEFINE_PER_CPU(u64, kvm_pvm_run_sctlr);

/*
 * SCTLR_EL1 bits taken from the guest: those that only control EL0, where the
 * guest runs.  All other bits also control the host, which handles guest exits
 * at EL1 under the guest-run value until __pvm_guest_exit() restores its own, so
 * they keep the host value.  EE, for instance, sets the endianness of the
 * host's data accesses and translation table walks.
 */
#define PVM_SCTLR_GUEST		(SCTLR_EL1_SA0 | SCTLR_EL1_CP15BEN | \
				 SCTLR_EL1_ITD | SCTLR_EL1_SED | \
				 SCTLR_EL1_EnRCTX | SCTLR_EL1_E0E | \
				 SCTLR_EL1_nTLSMD | SCTLR_EL1_LSMAOE | \
				 SCTLR_EL1_BT0 | SCTLR_EL1_TCF0_MASK | \
				 SCTLR_EL1_ATA0 | SCTLR_EL1_TWEDEn | \
				 SCTLR_EL1_TWEDEL_MASK | SCTLR_EL1_MSCEn | \
				 SCTLR_EL1_EnASR | SCTLR_EL1_EnAS0 | \
				 SCTLR_EL1_EnALS)

/*
 * SCTLR_EL1 bits forced on for the guest run, whatever the guest configured:
 *  M:           PVM has no stage 2, so stage 1 is the only translation
 *               between the guest and host memory.
 *  C, I:        the host maps guest memory cacheable; keep the guest's
 *               accesses cacheable as well, so the attributes never mismatch.
 *  UCI:         the guest kernel runs at EL0 but maintains the caches by VA
 *               as an EL1 kernel would; allow it instead of trapping each one.
 *  DZE:         likewise for DC ZVA.
 */
#define PVM_SCTLR_FLAGS1	(SCTLR_EL1_M | SCTLR_EL1_C | \
				 SCTLR_EL1_I | SCTLR_EL1_UCI | \
				 SCTLR_EL1_DZE)

/*
 * SCTLR_EL1 bits forced off for the guest run:
 *  UCT:         trap EL0 reads of CTR_EL0, so the guest sees the VM's value.
 *  nTWI, nTWE:  trap WFI and WFE, so an idle vCPU blocks in KVM instead of
 *               stalling the physical CPU.
 *  SPAN:        set PSTATE.PAN on exception entry to EL1, where the host
 *               handles guest exits, so the host does not reach
 *               EL0-accessible guest memory by accident.
 *  ITFSB, EPAN: these only affect EL1 behaviour, that is, the host while it
 *               handles guest exits.
 *  UMA:         trap EL0 DAIF accesses, so that they are emulated against
 *               the virtual PSTATE.
 *  EnIA, EnIB, EnDA, EnDB:
 *               PVM does not switch the pointer authentication keys, so the
 *               guest would sign and authenticate with the host's keys.
 */
#define PVM_SCTLR_FLAGS2	(SCTLR_EL1_UCT | SCTLR_EL1_nTWI | \
				 SCTLR_EL1_nTWE | SCTLR_EL1_SPAN | \
				 SCTLR_EL1_ITFSB | SCTLR_EL1_EPAN | \
				 SCTLR_EL1_UMA | SCTLR_EL1_EnIA | \
				 SCTLR_EL1_EnIB | SCTLR_EL1_EnDA | \
				 SCTLR_EL1_EnDB)

/*
 * The guest-run TCR_EL1 describes the page tables installed for the run,
 * which the host side builds, not the guest's own: it is the host's value,
 * with the shadow input size and virtual EL0 access controls projected.
 * TCR2_EL1, PIR_EL1 and PIRE0_EL1 also describe the installed page tables, so
 * they are not switched at all and keep the host's value. Hosts with S1PIE
 * are rejected because shadow leaves use the classic AP permission encoding.
 *
 * TCR_TBI1 is deliberately not part of this mask.  The run TCR also governs
 * host EL1 accesses taken before the translation registers are restored: the
 * entry/exit assembly, the current-EL vectors and the C code they call.
 * KASAN_SW_TAGS and MTE hosts carry tags in ordinary kernel pointers, which
 * rely on the host's TBI1.  Clearing it for a guest with TBI1=0 would make
 * those pointers non-canonical.  Keeping the host bit preserves valid guest
 * kernel addresses, but it also ignores the top byte of non-canonical ones:
 * such an address could hit an existing shadow mapping instead of taking the
 * address-size fault the guest expects.  A guest that requires TBI1=0 is
 * therefore rejected when its MMU is enabled, and a guest that sets TBI1 is
 * only added to, never subtracted from, the host value below.
 *
 * PVM hides PAuth from the guest, so TBI applies to both instruction and
 * data addresses. Clear host TBID bits for the run; the host entry/exit
 * code uses canonical instruction addresses. Restore the saved host TCR
 * when leaving the run loop.
 */
#define PVM_TCR_GUEST_MASK	(TCR_TBI0 | TCR_E0PD0 | TCR_E0PD1)

/*
 * The guest-run CPACR_EL1 keeps the host's EL1 controls, as the host handles
 * guest exits at EL1.  Physical EL0 FP/SIMD access follows the guest's
 * virtual EL and FPEN.  These EL0 enables are forced off:
 *  ZEN, SMEN:   SVE and SME state is not preserved for the guest.
 */
#define PVM_CPACR_FLAGS		(CPACR_EL1_ZEN_EL0EN | \
				 CPACR_EL1_SMEN_EL0EN)

/*
 * PVM runs the guest kernel at physical EL0. Trap both timer classes so
 * accesses are emulated against the single RV timer state.
 */
#define PVM_CNTKCTL_FLAGS	(ARCH_TIMER_USR_PCT_ACCESS_EN | \
				 ARCH_TIMER_USR_VCT_ACCESS_EN | \
				 ARCH_TIMER_USR_PT_ACCESS_EN | \
				 ARCH_TIMER_USR_VT_ACCESS_EN)

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 val;

	if (is_pvm_mode()) {
		struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
		u64 sctlr, cpacr, cntkctl;

		sctlr = ctxt_sys_reg(ctxt, SCTLR_EL1) & PVM_SCTLR_GUEST;
		sctlr |= read_sysreg_el2(SYS_SCTLR) & ~PVM_SCTLR_GUEST;
		sctlr |= PVM_SCTLR_FLAGS1;
		sctlr &= ~PVM_SCTLR_FLAGS2;
		/*
		 * __pvm_guest_enter() installs it right before the ERET: compiled
		 * code, with its pointer authentication, never runs under it.
		 */
		__this_cpu_write(kvm_pvm_run_sctlr, sctlr);

		cpacr = read_sysreg_el2(SYS_CPACR) & ~CPACR_EL1_FPEN_EL0EN;
		if (pvm_vcpu_fp_enabled(vcpu))
			cpacr |= CPACR_EL1_FPEN_EL0EN;
		/* PVM does not virtualize trace; trap trace register accesses. */
		cpacr |= CPACR_ELx_TTA;
		cpacr &= ~PVM_CPACR_FLAGS;
		write_sysreg(cpacr, cpacr_el1);

		cntkctl = read_sysreg_el2(SYS_CNTKCTL);
		cntkctl &= ~PVM_CNTKCTL_FLAGS;
		write_sysreg_el2(cntkctl, SYS_CNTKCTL);

		write_sysreg(__this_cpu_read(kvm_hyp_vector), vbar_el1);
		return;
	}

	___activate_traps(vcpu);

	if (has_cntpoff()) {
		struct timer_map map;

		get_timer_map(vcpu, &map);

		/*
		 * We're entrering the guest. Reload the correct
		 * values from memory now that TGE is clear.
		 */
		if (map.direct_ptimer == vcpu_ptimer(vcpu))
			val = __vcpu_sys_reg(vcpu, CNTP_CVAL_EL0);
		if (map.direct_ptimer == vcpu_hptimer(vcpu))
			val = __vcpu_sys_reg(vcpu, CNTHP_CVAL_EL2);

		if (map.direct_ptimer) {
			write_sysreg_el0(val, SYS_CNTP_CVAL);
			isb();
		}
	}

	val = read_sysreg(cpacr_el1);
	val |= CPACR_ELx_TTA;
	val &= ~(CPACR_EL1_ZEN_EL0EN | CPACR_EL1_ZEN_EL1EN |
		 CPACR_EL1_SMEN_EL0EN | CPACR_EL1_SMEN_EL1EN);

	/*
	 * With VHE (HCR.E2H == 1), accesses to CPACR_EL1 are routed to
	 * CPTR_EL2. In general, CPACR_EL1 has the same layout as CPTR_EL2,
	 * except for some missing controls, such as TAM.
	 * In this case, CPTR_EL2.TAM has the same position with or without
	 * VHE (HCR.E2H == 1) which allows us to use here the CPTR_EL2.TAM
	 * shift value for trapping the AMU accesses.
	 */

	val |= CPTR_EL2_TAM;

	if (guest_owns_fp_regs(vcpu)) {
		if (vcpu_has_sve(vcpu))
			val |= CPACR_EL1_ZEN_EL0EN | CPACR_EL1_ZEN_EL1EN;
	} else {
		val &= ~(CPACR_EL1_FPEN_EL0EN | CPACR_EL1_FPEN_EL1EN);
		__activate_traps_fpsimd32(vcpu);
	}

	write_sysreg(val, cpacr_el1);

	write_sysreg(__this_cpu_read(kvm_hyp_vector), vbar_el1);
}
NOKPROBE_SYMBOL(__activate_traps);

static void __deactivate_traps(struct kvm_vcpu *vcpu)
{
	const char *host_vectors = vectors;

	if (is_pvm_mode()) {
		if (!arm64_kernel_unmapped_at_el0())
			host_vectors = __this_cpu_read(this_cpu_vector);
		write_sysreg(host_vectors, vbar_el1);
		return;
	}

	___deactivate_traps(vcpu);

	write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);

	if (has_cntpoff()) {
		struct timer_map map;
		u64 val, offset;

		get_timer_map(vcpu, &map);

		/*
		 * We're exiting the guest. Save the latest CVAL value
		 * to memory and apply the offset now that TGE is set.
		 */
		val = read_sysreg_el0(SYS_CNTP_CVAL);
		if (map.direct_ptimer == vcpu_ptimer(vcpu))
			__vcpu_sys_reg(vcpu, CNTP_CVAL_EL0) = val;
		if (map.direct_ptimer == vcpu_hptimer(vcpu))
			__vcpu_sys_reg(vcpu, CNTHP_CVAL_EL2) = val;

		offset = read_sysreg_s(SYS_CNTPOFF_EL2);

		if (map.direct_ptimer && offset) {
			write_sysreg_el0(val + offset, SYS_CNTP_CVAL);
			isb();
		}
	}

	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL2/EL0 translation regime used by
	 * the host.
	 */
	asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));

	kvm_reset_cptr_el2(vcpu);

	if (!arm64_kernel_unmapped_at_el0())
		host_vectors = __this_cpu_read(this_cpu_vector);
	write_sysreg(host_vectors, vbar_el1);
}
NOKPROBE_SYMBOL(__deactivate_traps);

/*
 * Disable IRQs in {activate,deactivate}_traps_vhe_{load,put}() to
 * prevent a race condition between context switching of PMUSERENR_EL0
 * in __{activate,deactivate}_traps_common() and IPIs that attempts to
 * update PMUSERENR_EL0. See also kvm_set_pmuserenr().
 */
void activate_traps_vhe_load(struct kvm_vcpu *vcpu)
{
	unsigned long flags;

	local_irq_save(flags);
	__activate_traps_common(vcpu);
	local_irq_restore(flags);
}

void deactivate_traps_vhe_put(struct kvm_vcpu *vcpu)
{
	unsigned long flags;

	local_irq_save(flags);
	__deactivate_traps_common(vcpu);
	local_irq_restore(flags);
}

static const exit_handler_fn hyp_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= NULL,
	[ESR_ELx_EC_UNKNOWN]		= kvm_hyp_handle_unknown,
	[ESR_ELx_EC_CP15_32]		= kvm_hyp_handle_cp15_32,
	[ESR_ELx_EC_SYS64]		= kvm_hyp_handle_sysreg,
	[ESR_ELx_EC_SVE]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_FP_ASIMD]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_IABT_LOW]		= kvm_hyp_handle_iabt_low,
	[ESR_ELx_EC_PC_ALIGN]		= kvm_hyp_handle_pc_align,
	[ESR_ELx_EC_DABT_LOW]		= kvm_hyp_handle_dabt_low,
	[ESR_ELx_EC_WATCHPT_LOW]	= kvm_hyp_handle_watchpt_low,
	[ESR_ELx_EC_PAC]		= kvm_hyp_handle_ptrauth,
	[ESR_ELx_EC_SVC64]		= kvm_hyp_handle_svc,
};

static inline bool fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	synchronize_vcpu_pstate(vcpu, exit_code);

	/*
	 * If we were in HYP context on entry, adjust the PSTATE view
	 * so that the usual helpers work correctly.
	 */
	if (vcpu_has_nv(vcpu) && (read_sysreg(hcr_el2) & HCR_NV)) {
		u64 mode = *vcpu_cpsr(vcpu) & (PSR_MODE_MASK | PSR_MODE32_BIT);

		switch (mode) {
		case PSR_MODE_EL1t:
			mode = PSR_MODE_EL2t;
			break;
		case PSR_MODE_EL1h:
			mode = PSR_MODE_EL2h;
			break;
		}

		*vcpu_cpsr(vcpu) &= ~(PSR_MODE_MASK | PSR_MODE32_BIT);
		*vcpu_cpsr(vcpu) |= mode;
	}

	return __fixup_guest_exit(vcpu, exit_code, hyp_exit_handlers);
}

static void __pvm_load_stage1(struct kvm_vcpu *vcpu,
			      struct kvm_cpu_context *host_ctxt)
{
	struct kvm_pvm_mmu *shadow = vcpu_to_pvm(vcpu)->suser_mmu;
	struct kvm_pvm_mmu *kernel = vcpu_to_pvm(vcpu)->skern_mmu;
	struct kvm_pvm *pvm = kvm_to_pvm(vcpu->kvm);
	struct kvm_s2_mmu *mmu = shadow ? &shadow->mmu : vcpu->arch.hw_mmu;
	bool mmu_enabled = kvm_pvm_vcpu_mmu_enabled(vcpu);
	u64 guest_tcr = mmu_enabled ? ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1) : 0;
	u64 empty_ttbr0 = phys_to_ttbr(__pa_symbol(reserved_pg_dir));
	u64 ttbr0 = phys_to_ttbr(mmu->pgd_phys);
	u64 ttbr1 = phys_to_ttbr(kernel ? kernel->kern_pgd_phys : pvm->kern_pgd_phys);
	u64 tcr = ctxt_sys_reg(host_ctxt, TCR_EL1);

	/* Host mappings require table permissions while the guest runs. */
	tcr &= ~(TCR_T0SZ_MASK | PVM_TCR_GUEST_MASK | TCR_HPD1 |
		 TCR_TBID0 | TCR_TBID1);
	tcr |= FIELD_PREP(TCR_T0SZ_MASK, 64 - mmu->pgt->ia_bits);
	tcr |= guest_tcr & (TCR_TBI0 | TCR_TBI1);
	if (!vcpu_mode_priv(vcpu)) {
		tcr |= guest_tcr & TCR_E0PD0;
		tcr |= TCR_E0PD1;
	}

	/* Unsupported T0SZ must fault on access, not reuse MMU-off mappings. */
	if (mmu_enabled && !shadow)
		ttbr0 = empty_ttbr0;

	/* Keep TTBR0 empty until the table layout is synchronized. */
	cpu_set_reserved_ttbr0();
	local_flush_tlb_all();
	write_sysreg_el2(ttbr1, SYS_TTBR1);
	isb();
	write_sysreg_el2(tcr, SYS_TCR);
	isb();
	/* Remove host global entries before the restricted root is used. */
	local_flush_tlb_all();
	write_sysreg_el2(ttbr0, SYS_TTBR0);
	isb();
}

/*
 * Hyp fixups can change the virtual EL without leaving the run loop.
 * E0PD only affects EL0 accesses and needs no TLB maintenance. The
 * guest-entry ERET synchronizes the update.
 */
static void __pvm_load_e0pd(struct kvm_vcpu *vcpu)
{
	u64 guest_tcr = kvm_pvm_vcpu_mmu_enabled(vcpu) ?
		ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1) : 0;
	u64 tcr = read_sysreg_el2(SYS_TCR);
	u64 val = tcr & ~(TCR_E0PD0 | TCR_E0PD1);

	if (!vcpu_mode_priv(vcpu)) {
		val |= guest_tcr & TCR_E0PD0;
		val |= TCR_E0PD1;
	}

	if (val != tcr)
		write_sysreg_el2(val, SYS_TCR);
}

static void __pvm_restore_stage1(struct kvm_cpu_context *ctxt)
{
	cpu_set_reserved_ttbr0();
	local_flush_tlb_all();
	write_sysreg_el2(ctxt_sys_reg(ctxt, TTBR1_EL1), SYS_TTBR1);
	isb();
	write_sysreg_el2(ctxt_sys_reg(ctxt, TCR_EL1), SYS_TCR);
	isb();
	/* Remove guest restrictions before restoring the host TTBR0. */
	local_flush_tlb_all();
	write_sysreg_el2(ctxt_sys_reg(ctxt, TTBR0_EL1), SYS_TTBR0);
	isb();
}

static void __sysreg_save_host_state_pvm(struct kvm_cpu_context *ctxt)
{
	if (!is_pvm_mode())
		return;

	ctxt_sys_reg(ctxt, TCR_EL1) = read_sysreg_el2(SYS_TCR);
	ctxt_sys_reg(ctxt, TTBR0_EL1) = read_sysreg_el2(SYS_TTBR0);
	ctxt_sys_reg(ctxt, TTBR1_EL1) = read_sysreg_el2(SYS_TTBR1);
	ctxt_sys_reg(ctxt, CPACR_EL1) = read_sysreg_el2(SYS_CPACR);
	ctxt_sys_reg(ctxt, CNTKCTL_EL1) = read_sysreg_el2(SYS_CNTKCTL);
}

static void __sysreg_restore_host_state_pvm(struct kvm_cpu_context *ctxt)
{
	if (!is_pvm_mode())
		return;

	write_sysreg_el2(ctxt_sys_reg(ctxt, CPACR_EL1), SYS_CPACR);
	write_sysreg_el2(ctxt_sys_reg(ctxt, CNTKCTL_EL1), SYS_CNTKCTL);
}

/* Run a guest using the VHE or PVM context switch. */
static int __kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;

	host_ctxt = host_data_ptr(host_ctxt);
	host_ctxt->__hyp_running_vcpu = vcpu;
	guest_ctxt = &vcpu->arch.ctxt;

	sysreg_save_host_state_vhe(host_ctxt);

	__sysreg_save_host_state_pvm(host_ctxt);

	/*
	 * ARM erratum 1165522 requires us to configure both stage 1 and
	 * stage 2 translation for the guest context before we clear
	 * HCR_EL2.TGE.
	 *
	 * We have already configured the guest's stage 1 translation in
	 * kvm_vcpu_load_sysregs_vhe above.  We must now call
	 * __load_stage2 before __activate_traps, because
	 * __load_stage2 configures stage 2 translation, and
	 * __activate_traps clear HCR_EL2.TGE (among other things).
	 */
	__load_stage2(vcpu->arch.hw_mmu, vcpu->arch.hw_mmu->arch);
#ifdef CONFIG_ARM64_HDBSS
	__load_hdbss(vcpu);
#endif
	__activate_traps(vcpu);

	__kvm_adjust_pc(vcpu);

	sysreg_restore_guest_state_vhe(guest_ctxt);
	__debug_switch_to_guest(vcpu);

	if (is_pvm_mode()) {
		/* A pending exception may have changed the virtual mode. */
		kvm_pvm_sync_fpen(vcpu);
		__pvm_load_stage1(vcpu, host_ctxt);
	}

	do {
		if (is_pvm_mode())
			__pvm_load_e0pd(vcpu);

		/* Jump in the fire! */
		if (is_pvm_mode())
			exit_code = __pvm_guest_enter(vcpu);
		else
			exit_code = __guest_enter(vcpu);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	if (is_pvm_mode())
		__pvm_restore_stage1(host_ctxt);

	sysreg_save_guest_state_vhe(guest_ctxt);

	__deactivate_traps(vcpu);

	__sysreg_restore_host_state_pvm(host_ctxt);

	sysreg_restore_host_state_vhe(host_ctxt);

	if (*host_data_ptr(fp_owner) == FP_STATE_GUEST_OWNED)
		__fpsimd_save_fpexc32(vcpu);

	__debug_switch_to_host(vcpu);

	return exit_code;
}
NOKPROBE_SYMBOL(__kvm_vcpu_run_vhe);

int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	int ret;

	local_daif_mask();

	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 *
	 * local_daif_mask() already sets GIC_PRIO_PSR_I_SET, we just need a
	 * dsb to ensure the redistributor is forwards EL2 IRQs to the CPU.
	 */
	pmr_sync();

	ret = __kvm_vcpu_run_vhe(vcpu);

	/*
	 * local_daif_restore() takes care to properly restore PSTATE.DAIF
	 * and the GIC PMR if the host is using IRQ priorities.
	 */
	local_daif_restore(DAIF_PROCCTX_NOIRQ);

	/*
	 * When we exit from the guest we change a number of CPU configuration
	 * parameters, such as traps.  We rely on the isb() in kvm_call_hyp*()
	 * to make sure these changes take effect before running the host or
	 * additional guests.
	 */
	return ret;
}

static void __hyp_call_panic(u64 spsr, u64 elr, u64 par)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_vcpu *vcpu;

	host_ctxt = host_data_ptr(host_ctxt);
	vcpu = host_ctxt->__hyp_running_vcpu;

	if (is_pvm_mode())
		__pvm_restore_stage1(host_ctxt);

	__deactivate_traps(vcpu);
	__sysreg_restore_host_state_pvm(host_ctxt);
	sysreg_restore_host_state_vhe(host_ctxt);

	if (is_pvm_mode())
		panic("PVM panic at EL1:\n"
		      "PS:%08llx PC:%016llx ESR_EL1:%08llx\nFAR_EL1:%016llx PAR_EL1:%016llx\nVCPU:%p\n",
		      spsr, elr, read_sysreg_el2(SYS_ESR), read_sysreg_el2(SYS_FAR), par, vcpu);

	panic("HYP panic:\nPS:%08llx PC:%016llx ESR:%08llx\nFAR:%016llx HPFAR:%016llx PAR:%016llx\nVCPU:%p\n",
	      spsr, elr,
	      read_sysreg_el2(SYS_ESR), read_sysreg_el2(SYS_FAR),
	      read_sysreg(hpfar_el2), par, vcpu);
}
NOKPROBE_SYMBOL(__hyp_call_panic);

void __noreturn hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 elr = read_sysreg_el2(SYS_ELR);
	u64 par = read_sysreg_par();

	__hyp_call_panic(spsr, elr, par);
	unreachable();
}

asmlinkage void kvm_unexpected_el2_exception(void)
{
	__kvm_unexpected_el2_exception();
}
