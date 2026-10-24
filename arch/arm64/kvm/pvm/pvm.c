// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>

#include <asm/cpufeature.h>
#include <asm/kvm_pvm.h>
#include <kvm/arm_rv_timer.h>
#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

#include "mmu.h"

DEFINE_STATIC_KEY_FALSE(kvm_pvm_is_available);

void __init kvm_arm_init_pvm(void)
{
	u64 mmfr2, mmfr3;
	int ret;

	/*
	 * PVM requires the L1 kernel to run at EL1, so it only supports
	 * hosts without a usable EL2: with EL2 available the host kernel
	 * either runs at EL2 itself (VHE) or leaves EL2 to a hypervisor
	 * (nVHE), and neither matches the EL1-based shadow entry path.
	 */
	if (is_hyp_mode_available()) {
		kvm_err("PVM: not supported when EL2 is available\n");
		return;
	}

	if (PAGE_SHIFT != 12) {
		kvm_info("PVM: only the 4K host page granule is supported\n");
		return;
	}

	/*
	 * Kernel shadow roots retain the host's fixed 48-bit TTBR1
	 * layout. Do not enable PVM with an incompatible host layout.
	 */
	if (VA_BITS != 48) {
		kvm_info("PVM: only a 48-bit host VA layout is supported\n");
		return;
	}

	/*
	 * PVM borrows the host kernel's TTBR1 mappings for its kernel shadow
	 * root. Keep hierarchical permissions enabled to prevent L2 from
	 * accessing those L1 mappings.
	 */
	if (read_sysreg(tcr_el1) & TCR_HPD1) {
		kvm_err("PVM: TTBR1 hierarchical permissions are required\n");
		return;
	}

	/*
	 * Shadow tables project guest EL1 permissions onto physical EL0, so
	 * TCR_EL1.E0PD1 keeps the reserved kernel-address window inaccessible
	 * to guest EL0. Without FEAT_E0PD the bit is RES0, so refuse to
	 * enable PVM without that boundary. This does not restore complete
	 * privilege isolation within an L2.
	 */
	mmfr2 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
	if (!cpuid_feature_extract_unsigned_field(mmfr2, ID_AA64MMFR2_EL1_E0PD_SHIFT)) {
		kvm_err("PVM: FEAT_E0PD is required for the guest kernel window\n");
		return;
	}

	/* PVM assumes uniform S1PIE capability across CPUs. */
	mmfr3 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR3_EL1);
	if (cpuid_feature_extract_unsigned_field(mmfr3, ID_AA64MMFR3_EL1_S1PIE_SHIFT)) {
		kvm_err("PVM: FEAT_S1PIE hosts are not supported\n");
		return;
	}

	ret = kvm_rv_timer_hyp_init();
	if (ret) {
		pr_err("pvm: failed to init kvm rv timer, err = %d\n", ret);
		return;
	}
	static_branch_enable(&kvm_pvm_is_available);
}

void kvm_arm_destroy_pvm(void)
{
	kvm_pvm_sysfs_exit();
	static_branch_disable(&kvm_pvm_is_available);
}
