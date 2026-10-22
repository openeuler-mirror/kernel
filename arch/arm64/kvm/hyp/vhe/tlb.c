// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/irqflags.h>

#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>

struct tlb_inv_context {
	unsigned long	flags;
	u64		tcr;
	u64		sctlr;
};

static void __tlb_switch_to_guest(struct kvm_s2_mmu *mmu,
				  struct tlb_inv_context *cxt)
{
	u64 val;

	local_irq_save(cxt->flags);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/*
		 * For CPUs that are affected by ARM errata 1165522 or 1530923,
		 * we cannot trust stage-1 to be in a correct state at that
		 * point. Since we do not want to force a full load of the
		 * vcpu state, we prevent the EL1 page-table walker to
		 * allocate new TLBs. This is done by setting the EPD bits
		 * in the TCR_EL1 register. We also need to prevent it to
		 * allocate IPA->PA walks, so we enable the S1 MMU...
		 */
		val = cxt->tcr = read_sysreg_el1(SYS_TCR);
		val |= TCR_EPD1_MASK | TCR_EPD0_MASK;
		write_sysreg_el1(val, SYS_TCR);
		val = cxt->sctlr = read_sysreg_el1(SYS_SCTLR);
		val |= SCTLR_ELx_M;
		write_sysreg_el1(val, SYS_SCTLR);
	}

	/*
	 * With VHE enabled, we have HCR_EL2.{E2H,TGE} = {1,1}, and
	 * most TLB operations target EL2/EL0. In order to affect the
	 * guest TLBs (EL1/EL0), we need to change one of these two
	 * bits. Changing E2H is impossible (goodbye TTBR1_EL2), so
	 * let's flip TGE before executing the TLB operation.
	 *
	 * ARM erratum 1165522 requires some special handling (again),
	 * as we need to make sure both stages of translation are in
	 * place before clearing TGE. __load_stage2() already
	 * has an ISB in order to deal with this.
	 */
	__load_stage2(mmu, mmu->arch);
	val = read_sysreg(hcr_el2);
	val &= ~HCR_TGE;
	write_sysreg(val, hcr_el2);
	isb();
}

static void __tlb_switch_to_host(struct tlb_inv_context *cxt)
{
	/*
	 * We're done with the TLB operation, let's restore the host's
	 * view of HCR_EL2.
	 */
	write_sysreg(0, vttbr_el2);
	write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);
	isb();

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/* Restore the registers to what they were */
		write_sysreg_el1(cxt->tcr, SYS_TCR);
		write_sysreg_el1(cxt->sctlr, SYS_SCTLR);
	}

	local_irq_restore(cxt->flags);
}

static void pvm_tlb_flush_all(void)
{
	dsb(ishst);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();
}

/*
 * Permission relaxation only widens access and needs no break-before-make,
 * so the invalidation has to reach this CPU only: a PE that still holds
 * the old entry merely takes a permission fault and retries after the
 * grant.  Stay local and target the VA being relaxed instead of the whole
 * EL1 TLB.  The shadow ASID is not tracked yet, so use the all-ASID form;
 * the VA alone already bounds the invalidation.
 */
static void pvm_tlb_flush_ipa_nsh(phys_addr_t ipa)
{
	dsb(nshst);
	__tlbi(vaae1, __TLBI_VADDR(ipa, 0));
	dsb(nsh);
	isb();
}

void __kvm_tlb_flush_vmid_ipa(struct kvm_s2_mmu *mmu,
			      phys_addr_t ipa, int level)
{
	struct tlb_inv_context cxt;

	if (is_pvm_mode()) {
		pvm_tlb_flush_all();
		return;
	}

	dsb(ishst);

	/* Switch to requested VMID */
	__tlb_switch_to_guest(mmu, &cxt);

	/*
	 * We could do so much better if we had the VA as well.
	 * Instead, we invalidate Stage-2 for this IPA, and the
	 * whole of Stage-1. Weep...
	 */
	ipa >>= 12;
	__tlbi_level(ipas2e1is, ipa, level);

	/*
	 * We have to ensure completion of the invalidation at Stage-2,
	 * since a table walk on another CPU could refill a TLB with a
	 * complete (S1 + S2) walk based on the old Stage-2 mapping if
	 * the Stage-1 invalidation happened first.
	 */
	dsb(ish);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();

	__tlb_switch_to_host(&cxt);
}

void __kvm_tlb_flush_vmid_ipa_nsh(struct kvm_s2_mmu *mmu,
				  phys_addr_t ipa, int level)
{
	struct tlb_inv_context cxt;

	if (is_pvm_mode()) {
		pvm_tlb_flush_ipa_nsh(ipa);
		return;
	}

	dsb(nshst);

	/* Switch to requested VMID */
	__tlb_switch_to_guest(mmu, &cxt);

	/*
	 * We could do so much better if we had the VA as well.
	 * Instead, we invalidate Stage-2 for this IPA, and the
	 * whole of Stage-1. Weep...
	 */
	ipa >>= 12;
	__tlbi_level(ipas2e1, ipa, level);

	/*
	 * We have to ensure completion of the invalidation at Stage-2,
	 * since a table walk on another CPU could refill a TLB with a
	 * complete (S1 + S2) walk based on the old Stage-2 mapping if
	 * the Stage-1 invalidation happened first.
	 */
	dsb(nsh);
	__tlbi(vmalle1);
	dsb(nsh);
	isb();

	__tlb_switch_to_host(&cxt);
}

void __kvm_tlb_flush_vmid_range(struct kvm_s2_mmu *mmu,
				phys_addr_t start, unsigned long pages)
{
	struct tlb_inv_context cxt;
	unsigned long stride;

	if (is_pvm_mode()) {
		pvm_tlb_flush_all();
		return;
	}

	/*
	 * Since the range of addresses may not be mapped at
	 * the same level, assume the worst case as PAGE_SIZE
	 */
	stride = PAGE_SIZE;
	start = round_down(start, stride);

	dsb(ishst);

	/* Switch to requested VMID */
	__tlb_switch_to_guest(mmu, &cxt);

	__flush_s2_tlb_range_op(ipas2e1is, start, pages, stride, 0);

	dsb(ish);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();

	__tlb_switch_to_host(&cxt);
}

void __kvm_tlb_flush_vmid(struct kvm_s2_mmu *mmu)
{
	struct tlb_inv_context cxt;

	if (is_pvm_mode()) {
		pvm_tlb_flush_all();
		return;
	}

	dsb(ishst);

	/* Switch to requested VMID */
	__tlb_switch_to_guest(mmu, &cxt);

	__tlbi(vmalls12e1is);
	dsb(ish);
	isb();

	__tlb_switch_to_host(&cxt);
}

void __kvm_flush_cpu_context(struct kvm_s2_mmu *mmu)
{
	struct tlb_inv_context cxt;

	if (is_pvm_mode()) {
		pvm_tlb_flush_all();
		asm volatile("ic iallu");
		dsb(ish);
		isb();
		return;
	}

	/* Switch to requested VMID */
	__tlb_switch_to_guest(mmu, &cxt);

	__tlbi(vmalle1);
	asm volatile("ic iallu");
	dsb(nsh);
	isb();

	__tlb_switch_to_host(&cxt);
}

void __kvm_flush_vm_context(void)
{
	if (is_pvm_mode()) {
		pvm_tlb_flush_all();
		return;
	}

	dsb(ishst);
	__tlbi(alle1is);
	dsb(ish);
}
