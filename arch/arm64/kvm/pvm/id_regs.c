// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 - Huawei LLC
 * Author: Kunkun Jiang <Jiangkunkun@huawei.com>
 */

#include <linux/bitfield.h>
#include <linux/bits.h>

#include <asm/sysreg.h>

#include <pvm/id_regs.h>

/*
 * A PVM guest runs its kernel and userspace at physical EL0, where it executes
 * the unprivileged instructions natively whatever its ID registers say.  Hiding
 * those would only cost performance, so they are exposed.  What is hidden needs
 * EL1 or EL2 control, or state, that PVM does not virtualize; the guest could
 * otherwise rely on a feature that does not take effect.
 */
u64 kvm_pvm_filter_id_reg(u32 id, u64 val)
{
	u64 field;

	switch (id) {
	case SYS_ID_AA64PFR0_EL1:
		val &= ~(ID_AA64PFR0_EL1_AMU | ID_AA64PFR0_EL1_MPAM |
			 ID_AA64PFR0_EL1_SVE | ID_AA64PFR0_EL1_RAS |
			 ID_AA64PFR0_EL1_GIC | ID_AA64PFR0_EL1_SEL2 |
			 ID_AA64PFR0_EL1_EL3 | ID_AA64PFR0_EL1_EL2 |
			 ID_AA64PFR0_EL1_EL1 | ID_AA64PFR0_EL1_EL0);
		val |= FIELD_PREP(ID_AA64PFR0_EL1_EL1, 0b0001) |
		       FIELD_PREP(ID_AA64PFR0_EL1_EL0, 0b0001);
		break;
	case SYS_ID_AA64PFR1_EL1:
		val &= ~(ID_AA64PFR1_EL1_NMI | ID_AA64PFR1_EL1_RAS_frac |
			 ID_AA64PFR1_EL1_BT);
		break;
	case SYS_ID_AA64PFR2_EL1:
		if (!IS_ENABLED(CONFIG_ENABLE_KVM_FPMR))
			val &= ~ID_AA64PFR2_EL1_FPMR;
		break;
	case SYS_ID_AA64DFR0_EL1:
		val &= ID_AA64DFR0_EL1_WRPs | ID_AA64DFR0_EL1_BRPs |
		       ID_AA64DFR0_EL1_DebugVer;
		field = FIELD_GET(ID_AA64DFR0_EL1_DebugVer, val);
		if (field > 0b0111) {
			val &= ~ID_AA64DFR0_EL1_DebugVer;
			val |= FIELD_PREP(ID_AA64DFR0_EL1_DebugVer, 0b0111);
		}
		break;
	case SYS_ID_AA64DFR1_EL1:
		val = 0;
		break;
	case SYS_ID_AA64ISAR0_EL1:
		val &= ~(ID_AA64ISAR0_EL1_TLB | ID_AA64ISAR0_EL1_TME);
		break;
	case SYS_ID_AA64ISAR1_EL1:
		val &= ~(GENMASK_ULL(63, 56) | ID_AA64ISAR1_EL1_SPECRES |
			 ID_AA64ISAR1_EL1_API | ID_AA64ISAR1_EL1_APA |
			 ID_AA64ISAR1_EL1_GPA | ID_AA64ISAR1_EL1_GPI);
		break;
	case SYS_ID_AA64ISAR2_EL1:
		val &= ~(ID_AA64ISAR2_EL1_SYSINSTR_128 | ID_AA64ISAR2_EL1_MOPS |
			 ID_AA64ISAR2_EL1_APA3 | ID_AA64ISAR2_EL1_GPA3);
		break;
	case SYS_ID_AA64MMFR0_EL1:
		val &= ~(ID_AA64MMFR0_EL1_ECV | ID_AA64MMFR0_EL1_FGT |
			 ID_AA64MMFR0_EL1_EXS | ID_AA64MMFR0_EL1_BIGEND |
			 ID_AA64MMFR0_EL1_TGRAN4_2 |
			 ID_AA64MMFR0_EL1_TGRAN16_2 |
			 ID_AA64MMFR0_EL1_TGRAN64_2 |
			 ID_AA64MMFR0_EL1_SNSMEM);

		field = FIELD_GET(ID_AA64MMFR0_EL1_PARANGE, val);
		if (field > ID_AA64MMFR0_EL1_PARANGE_48) {
			val &= ~ID_AA64MMFR0_EL1_PARANGE;
			val |= FIELD_PREP(ID_AA64MMFR0_EL1_PARANGE,
					  ID_AA64MMFR0_EL1_PARANGE_48);
		}
		break;
	case SYS_ID_AA64MMFR1_EL1:
		val &= ~(ID_AA64MMFR1_EL1_HAFDBS | ID_AA64MMFR1_EL1_PAN |
			 ID_AA64MMFR1_EL1_LO | ID_AA64MMFR1_EL1_HPDS |
			 ID_AA64MMFR1_EL1_VMIDBits | ID_AA64MMFR1_EL1_VH |
			 ID_AA64MMFR1_EL1_HCX | ID_AA64MMFR1_EL1_XNX |
			 ID_AA64MMFR1_EL1_TIDCP1);
		break;
	case SYS_ID_AA64MMFR2_EL1:
		/* E0PD stays, to isolate the guest kernel from its EL0 */
		val &= ~(ID_AA64MMFR2_EL1_EVT | ID_AA64MMFR2_EL1_BBM |
			 ID_AA64MMFR2_EL1_ST | ID_AA64MMFR2_EL1_NV |
			 ID_AA64MMFR2_EL1_FWB | ID_AA64MMFR2_EL1_CCIDX |
			 ID_AA64MMFR2_EL1_VARange | ID_AA64MMFR2_EL1_IESB |
			 ID_AA64MMFR2_EL1_UAO | ID_AA64MMFR2_EL1_TTL);
		val |= FIELD_PREP(ID_AA64MMFR2_EL1_TTL, 0b0001);
		break;
	case SYS_ID_AA64MMFR3_EL1:
		val &= ID_AA64MMFR3_EL1_TCRX;
		break;
	case SYS_ID_AA64MMFR4_EL1:
	case SYS_ID_AA64ZFR0_EL1:
		val = 0;
		break;
	default:
		break;
	}

	return val;
}
