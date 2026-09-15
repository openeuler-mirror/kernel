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
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/vectors.h>

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
 *  EnIA, EnIB, EnDA, EnDB:
 *               PVM does not switch the pointer authentication keys, so the
 *               guest would sign and authenticate with the host's keys.
 */
#define PVM_SCTLR_FLAGS2	(SCTLR_EL1_UCT | SCTLR_EL1_nTWI | \
				 SCTLR_EL1_nTWE | SCTLR_EL1_SPAN | \
				 SCTLR_EL1_ITFSB | SCTLR_EL1_EPAN | \
				 SCTLR_EL1_EnIA | SCTLR_EL1_EnIB | \
				 SCTLR_EL1_EnDA | SCTLR_EL1_EnDB)

/*
 * The guest-run TCR_EL1 describes the page tables installed for the run,
 * which the host side builds, not the guest's own: it is the host's value,
 * with these bits forced off:
 *  E0PD1:       the guest kernel runs at EL0 in the TTBR1 range, where E0PD1
 *               would fault every one of its accesses.
 * TCR2_EL1, PIR_EL1 and PIRE0_EL1 also describe the installed page tables, so
 * they are not switched at all and keep the host's value.
 */
#define PVM_TCR_FLAGS		TCR_E0PD1

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 val;

	if (is_pvm_mode()) {
		struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
		u64 sctlr, tcr;

		sctlr = ctxt_sys_reg(ctxt, SCTLR_EL1) & PVM_SCTLR_GUEST;
		sctlr |= read_sysreg_el2(SYS_SCTLR) & ~PVM_SCTLR_GUEST;
		sctlr |= PVM_SCTLR_FLAGS1;
		sctlr &= ~PVM_SCTLR_FLAGS2;
		/*
		 * __pvm_guest_enter() installs it right before the ERET: compiled
		 * code, with its pointer authentication, never runs under it.
		 */
		__this_cpu_write(kvm_pvm_run_sctlr, sctlr);

		tcr = read_sysreg_el2(SYS_TCR) & ~PVM_TCR_FLAGS;
		write_sysreg_el2(tcr, SYS_TCR);

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
	[ESR_ELx_EC_CP15_32]		= kvm_hyp_handle_cp15_32,
	[ESR_ELx_EC_SYS64]		= kvm_hyp_handle_sysreg,
	[ESR_ELx_EC_SVE]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_FP_ASIMD]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_IABT_LOW]		= kvm_hyp_handle_iabt_low,
	[ESR_ELx_EC_DABT_LOW]		= kvm_hyp_handle_dabt_low,
	[ESR_ELx_EC_WATCHPT_LOW]	= kvm_hyp_handle_watchpt_low,
	[ESR_ELx_EC_PAC]		= kvm_hyp_handle_ptrauth,
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

static void __sysreg_save_host_state_pvm(struct kvm_cpu_context *ctxt)
{
	if (!is_pvm_mode())
		return;

	ctxt_sys_reg(ctxt, TCR_EL1) = read_sysreg_el2(SYS_TCR);
}

static void __sysreg_restore_host_state_pvm(struct kvm_cpu_context *ctxt)
{
	if (!is_pvm_mode())
		return;

	write_sysreg_el2(ctxt_sys_reg(ctxt, TCR_EL1), SYS_TCR);
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

	do {
		/* Jump in the fire! */
		if (is_pvm_mode())
			exit_code = __pvm_guest_enter(vcpu);
		else
			exit_code = __guest_enter(vcpu);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

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

	__deactivate_traps(vcpu);
	__sysreg_restore_host_state_pvm(host_ctxt);
	sysreg_restore_host_state_vhe(host_ctxt);

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
