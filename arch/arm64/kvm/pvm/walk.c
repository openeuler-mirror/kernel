// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/cpufeature.h>
#include <asm/esr.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pvm.h>
#include <asm/pgtable-hwdef.h>

#include "mmu.h"

#define PVM_S1_DESC_TYPE	BIT(1)
#define PVM_S1_DESC_BLOCK	0
#define PVM_S1_FSC_ADDRSZ	0
#define PVM_S1_TABLE_AP		GENMASK_ULL(62, 61)

struct pvm_s1_walk_info {
	u64 baddr;
	u64 va;
	unsigned int max_oa_bits;
	unsigned int pgshift;
	unsigned int txsz;
	int start_level;
	bool ttbr1;
	bool walk_disabled;
	bool hpd;
};

static u32 pvm_s1_fsc(int level, u32 type)
{
	return type | (level & ESR_ELx_FSC_LEVEL);
}

static u64 pvm_s1_fault_esr(struct kvm_vcpu *vcpu, u32 fsc)
{
	u64 esr = kvm_vcpu_get_esr(vcpu);
	u64 ec = ESR_ELx_EC(esr);

	if (vcpu_mode_priv(vcpu)) {
		if (ec == ESR_ELx_EC_DABT_LOW)
			ec = ESR_ELx_EC_DABT_CUR;
		else if (ec == ESR_ELx_EC_IABT_LOW)
			ec = ESR_ELx_EC_IABT_CUR;
	}

	esr &= ~(ESR_ELx_EC_MASK | ESR_ELx_FSC);
	esr |= ec << ESR_ELx_EC_SHIFT;
	esr |= fsc & ESR_ELx_FSC;

	return esr;
}

static int pvm_s1_check_input_size(const struct pvm_s1_walk_info *wi, u64 va)
{
	u64 ia_bits = 64 - wi->txsz;

	if (!wi->ttbr1 && va > GENMASK_ULL(ia_bits - 1, 0))
		return -EFAULT;
	if (wi->ttbr1 && va < ~GENMASK_ULL(ia_bits - 1, 0))
		return -EFAULT;

	return 0;
}

static int pvm_s1_check_output_size(const struct pvm_s1_walk_info *wi,
				    phys_addr_t output)
{
	if (wi->max_oa_bits != 48 &&
	    (output & GENMASK_ULL(47, wi->max_oa_bits)))
		return -EFAULT;

	return 0;
}

static unsigned int pvm_s1_pgshift(u64 tcr, bool ttbr1)
{
	u64 tg = tcr & (ttbr1 ? TCR_TG1_MASK : TCR_TG0_MASK);

	if (ttbr1) {
		switch (tg) {
		case TCR_TG1_4K:
			return 12;
		case TCR_TG1_16K:
			return 14;
		case TCR_TG1_64K:
			return 16;
		default:
			return 0;
		}
	}

	switch (tg) {
	case TCR_TG0_4K:
		return 12;
	case TCR_TG0_16K:
		return 14;
	case TCR_TG0_64K:
		return 16;
	default:
		return 0;
	}
}

static int pvm_s1_setup_geometry(u64 tcr, struct pvm_s1_walk_info *wi)
{
	unsigned int stride;
	u64 ia_bits;

	wi->pgshift = pvm_s1_pgshift(tcr, wi->ttbr1);
	if (!wi->pgshift)
		return -EINVAL;

	if (wi->ttbr1)
		wi->txsz = FIELD_GET(TCR_T1SZ_MASK, tcr);
	else
		wi->txsz = FIELD_GET(TCR_T0SZ_MASK, tcr);
	ia_bits = 64 - wi->txsz;

	/*
	 * The kernel space must fold into the top pgd entry, which
	 * only lines up for kernel spaces that fill whole pgd slots;
	 * the user shadow can carry any size its tables can walk.
	 */
	if (wi->ttbr1) {
		if (wi->txsz != PVM_SHADOW_S1_T0SZ)
			return -EINVAL;
	} else if (ia_bits < PVM_SHADOW_S1_MIN_VA_BITS || ia_bits > 47 ||
		   PVM_PGTABLE_LEVELS(ia_bits) < 2) {
		return -EINVAL;
	}

	stride = wi->pgshift - 3;
	if (ia_bits <= wi->pgshift || ia_bits > wi->pgshift + 4 * stride)
		return -EINVAL;

	wi->start_level = 3 - ((ia_bits - 1 - wi->pgshift) / stride);

	/*
	 * Base-address bits below the starting-level span are RES0 and
	 * the hardware ignores them; mask the base to the level's lower
	 * bound so stray bits cannot spill into descriptor addresses.
	 */
	wi->baddr &= GENMASK_ULL(47, 3 + ia_bits -
				((3 - wi->start_level) * stride + wi->pgshift));

	return 0;
}

static int pvm_s1_setup_walk(struct kvm_vcpu *vcpu, u64 va,
			     struct pvm_s1_walk_info *wi)
{
	static const u8 oa_bits[] = { 32, 36, 40, 42, 44, 48, 52 };
	enum vcpu_sysreg ttbr;
	int ret;
	u64 ips;
	u64 tcr;

	wi->ttbr1 = va & BIT(55);
	ttbr = wi->ttbr1 ? TTBR1_EL1 : TTBR0_EL1;
	wi->baddr = ctxt_sys_reg(&vcpu->arch.ctxt, ttbr) & TTBRx_EL1_BADDR;

	tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);
	wi->hpd = tcr & (wi->ttbr1 ? TCR_HPD1 : TCR_HPD0);
	if (tcr & (wi->ttbr1 ? TCR_TBI1 : TCR_TBI0)) {
		if (wi->ttbr1)
			va |= GENMASK_ULL(63, 56);
		else
			va &= GENMASK_ULL(55, 0);
	}
	wi->va = va;
	wi->walk_disabled = tcr & (wi->ttbr1 ? TCR_EPD1_MASK :
						   TCR_EPD0_MASK);

	/*
	 * E0PD0 and E0PD1 deny their respective address ranges to virtual
	 * EL0. Report the translation fault before reading guest tables.
	 * The L2 kernel also runs at physical EL0 but remains exempt,
	 * as hardware exempts EL1.
	 */
	if (!vcpu_mode_priv(vcpu) &&
	    (tcr & (wi->ttbr1 ? TCR_E0PD1 : TCR_E0PD0)))
		wi->walk_disabled = true;

	ret = pvm_s1_setup_geometry(tcr, wi);
	if (ret)
		return ret;

	ips = FIELD_GET(TCR_IPS_MASK, tcr);
	if (ips >= ARRAY_SIZE(oa_bits))
		return -ERANGE;
	/* PVM supports at most 48-bit output addresses. */
	wi->max_oa_bits = min_t(u32, oa_bits[ips], 48);
	wi->max_oa_bits = min_t(u32, wi->max_oa_bits, get_kvm_ipa_limit());

	return 0;
}

static int pvm_s1_read_desc(struct kvm_vcpu *vcpu, u64 ipa, u64 *desc)
{
	__le64 val;
	int ret;

	/* Aligned descriptors cannot straddle a host page. */
	ret = kvm_read_guest_page(vcpu->kvm, ipa >> PAGE_SHIFT, &val,
				  offset_in_page(ipa), sizeof(val));
	if (ret)
		return ret;

	*desc = le64_to_cpu(val);
	return 0;
}

static void pvm_s1_compute_permissions(struct kvm_vcpu *vcpu,
				       struct kvm_s1_trans *result)
{
	u64 sctlr;
	enum pvm_s1_attr type;

	switch (FIELD_GET(PTE_USER | PTE_RDONLY, result->desc)) {
	case 0:
		result->pr = true;
		result->pw = true;
		break;
	case 1:
		result->pr = true;
		result->pw = true;
		result->ur = true;
		result->uw = true;
		break;
	case 2:
		result->pr = true;
		break;
	case 3:
		result->pr = true;
		result->ur = true;
		break;
	}

	result->px = !(result->desc & PTE_PXN);
	result->ux = !(result->desc & PTE_UXN);

	if (result->ap_table & BIT(0)) {
		result->ur = false;
		result->uw = false;
	}
	if (result->ap_table & BIT(1)) {
		result->pw = false;
		result->uw = false;
	}
	if (result->pxn_table)
		result->px = false;
	if (result->uxn_table)
		result->ux = false;

	/* EL0-writable memory is implicitly execute-never at EL1. */
	if (result->uw)
		result->px = false;

	/*
	 * Deny a leaf whose attribute the host's fixed MAIR cannot
	 * represent.  The consumer then reports a permission fault
	 * instead of mapping the page with attributes the guest did not
	 * ask for.
	 */
	type = pvm_s1_attr_type(ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1),
				result->desc);
	if (type == PVM_S1_ATTR_UNSUPPORTED) {
		result->pr = false;
		result->pw = false;
		result->ur = false;
		result->uw = false;
		result->px = false;
		result->ux = false;
		return;
	}

	/* Device memory is never executable. */
	if (type == PVM_S1_ATTR_DEVICE) {
		result->px = false;
		result->ux = false;
	}

	/*
	 * WXN revokes execute permission per level, and only where that
	 * level is also writable: PrivWXN is WXN && PW && PX, UnprivWXN
	 * is WXN && UW && UX.
	 */
	sctlr = ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1);
	if (sctlr & SCTLR_ELx_WXN) {
		if (result->pw && result->px)
			result->px = false;
		if (result->uw && result->ux)
			result->ux = false;
	}
}

static int pvm_s1_walk(struct kvm_vcpu *vcpu, u64 va,
		       struct pvm_s1_walk_info *wi,
		       struct kvm_s1_trans *result)
{
	u64 va_top, va_bottom, baddr, desc, output;
	int level, stride, ret;

	/* TBI, when enabled, has already made the top byte canonical. */
	if (va != (u64)sign_extend64(va, 55)) {
		result->esr = pvm_s1_fsc(0, PVM_S1_FSC_ADDRSZ);
		return 1;
	}

	if (wi->walk_disabled) {
		result->esr = pvm_s1_fsc(wi->start_level, ESR_ELx_FSC_FAULT);
		return 1;
	}

	ret = pvm_s1_check_input_size(wi, va);
	if (ret) {
		/* Input-range faults are reported at the starting level. */
		result->esr = pvm_s1_fsc(wi->start_level, ESR_ELx_FSC_FAULT);
		return 1;
	}

	level = wi->start_level;
	ret = pvm_s1_check_output_size(wi, wi->baddr);
	if (ret) {
		result->esr = pvm_s1_fsc(0, PVM_S1_FSC_ADDRSZ);
		return 1;
	}

	stride = wi->pgshift - 3;
	baddr = wi->baddr;
	va_top = 63 - wi->txsz;

	for (;;) {
		u64 index;
		u64 ipa;

		va_bottom = (3 - level) * stride + wi->pgshift;
		index = (va & GENMASK_ULL(va_top, va_bottom)) >>
			(va_bottom - 3);
		ipa = baddr | index;

		ret = pvm_s1_read_desc(vcpu, ipa, &desc);
		if (ret) {
			/*
			 * The guest page tables cannot be read through
			 * the KVM memory slots: report a synchronous
			 * external abort on the walk instead of failing
			 * the whole run.
			 */
			result->esr = ESR_ELx_FSC_SEA_TTW0 + level;
			return 1;
		}

		if (!(desc & PTE_VALID)) {
			result->esr = pvm_s1_fsc(level, ESR_ELx_FSC_FAULT);
			result->desc = desc;
			return 1;
		}

		if (FIELD_GET(PVM_S1_DESC_TYPE, desc) == PVM_S1_DESC_BLOCK) {
			if (level == 2 || (level == 1 && wi->pgshift == 12))
				break;

			result->esr = pvm_s1_fsc(level, ESR_ELx_FSC_FAULT);
			result->desc = desc;
			return 1;
		}

		if (pvm_s1_check_output_size(wi, desc)) {
			result->esr = pvm_s1_fsc(level, PVM_S1_FSC_ADDRSZ);
			result->desc = desc;
			return 1;
		}

		if (level == 3)
			break;

		if (!wi->hpd) {
			result->ap_table |= FIELD_GET(PVM_S1_TABLE_AP, desc);
			result->uxn_table |= desc & PMD_TABLE_UXN;
			result->pxn_table |= desc & PMD_TABLE_PXN;
		}
		baddr = desc & GENMASK_ULL(47, wi->pgshift);
		va_top = va_bottom - 1;
		level++;
	}

	if (!(desc & PTE_AF)) {
		result->esr = pvm_s1_fsc(level, ESR_ELx_FSC_ACCESS);
		result->desc = desc;
		return 1;
	}

	output = (desc & GENMASK_ULL(47, va_bottom)) |
		 (va & GENMASK_ULL(va_bottom - 1, 0));
	if (pvm_s1_check_output_size(wi, output)) {
		result->esr = pvm_s1_fsc(level, PVM_S1_FSC_ADDRSZ);
		result->desc = desc;
		return 1;
	}
	result->output = output;
	result->level = level;
	result->desc = desc;
	result->af = true;
	pvm_s1_compute_permissions(vcpu, result);

	return 0;
}

int kvm_pvm_walk_shadow_s1(struct kvm_vcpu *vcpu, u64 va,
			   struct kvm_s1_trans *result)
{
	struct pvm_s1_walk_info wi = {};
	int ret;

	memset(result, 0, sizeof(*result));
	ret = pvm_s1_setup_walk(vcpu, va, &wi);
	if (ret) {
		u32 fsc;

		/*
		 * Report an unsupported IPS encoding as a level-0 address-size
		 * fault, and unsupported table geometry as a level-0 translation
		 * fault. Actual output addresses are checked during the walk.
		 */
		if (ret == -ERANGE)
			fsc = pvm_s1_fsc(0, PVM_S1_FSC_ADDRSZ);
		else
			fsc = pvm_s1_fsc(0, ESR_ELx_FSC_FAULT);
		result->esr = pvm_s1_fault_esr(vcpu, fsc);
		return 1;
	}

	ret = pvm_s1_walk(vcpu, wi.va, &wi, result);
	if (ret > 0)
		result->esr = pvm_s1_fault_esr(vcpu, result->esr);

	return ret;
}

bool kvm_pvm_s1_access_denied(struct kvm_vcpu *vcpu,
			      struct kvm_s1_trans *result)
{
	bool privileged = vcpu_mode_priv(vcpu);
	bool denied;

	/*
	 * Virtual EL0 must never reach the reserved kernel window, even
	 * when the guest leaves E0PD1 clear. Report this PVM restriction
	 * as a level-0 translation fault.
	 */
	if (!privileged && kvm_pvm_is_kernel_va(kvm_vcpu_get_hfar(vcpu))) {
		result->esr = pvm_s1_fault_esr(vcpu,
					       pvm_s1_fsc(0, ESR_ELx_FSC_FAULT));
		return true;
	}

	if (kvm_vcpu_trap_is_iabt(vcpu))
		denied = !(result->px || result->ux);
	else if (kvm_is_write_fault(vcpu))
		denied = !(result->pw || result->uw);
	else
		denied = !(result->pr || result->ur);

	if (denied)
		result->esr = pvm_s1_fault_esr(vcpu,
					       pvm_s1_fsc(result->level, ESR_ELx_FSC_PERM));
	return denied;
}

int kvm_pvm_inject_s1_fault(struct kvm_vcpu *vcpu, u32 fsc)
{
	unsigned long far = kvm_vcpu_get_hfar(vcpu);
	u64 esr = pvm_s1_fault_esr(vcpu, fsc);

	if (kvm_vcpu_trap_is_iabt(vcpu))
		kvm_inject_pabt(vcpu, far);
	else
		kvm_inject_dabt(vcpu, far);
	ctxt_sys_reg(&vcpu->arch.ctxt, ESR_EL1) = esr;
	return 1;
}
