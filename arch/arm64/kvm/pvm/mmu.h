/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_MMU_H__
#define __ARM64_KVM_PVM_MMU_H__

#include <linux/bitfield.h>
#include <linux/kvm_host.h>

#include "pvm.h"

#include <asm/pgtable-hwdef.h>

/*
 * The host runs PVM guests through a fixed MAIR, so a guest leaf can only
 * be projected when its ATTRINDX selects an encoding that fixed MAIR
 * represents: the Device encodings 0x00, 0x04, 0x08 and 0x0c, and the
 * Normal encodings 0x44 (non-cacheable) and 0xff (write-back).  Normal
 * descriptors must also be inner shareable.
 */
enum pvm_s1_attr {
	PVM_S1_ATTR_UNSUPPORTED,
	PVM_S1_ATTR_DEVICE,
	PVM_S1_ATTR_NORMAL_NC,
	PVM_S1_ATTR_NORMAL_WB,
};

static inline enum pvm_s1_attr pvm_s1_attr_type(u64 mair, u64 desc)
{
	u8 attr = mair >> (FIELD_GET(PTE_ATTRINDX_MASK, desc) * 8);

	switch (attr) {
	case 0x00:
	case 0x04:
	case 0x08:
	case 0x0c:
		return PVM_S1_ATTR_DEVICE;
	case 0x44:
	case 0xff:
		if ((desc & PTE_SHARED) != PTE_SHARED)
			return PVM_S1_ATTR_UNSUPPORTED;
		if (attr == 0x44)
			return PVM_S1_ATTR_NORMAL_NC;
		return PVM_S1_ATTR_NORMAL_WB;
	}

	return PVM_S1_ATTR_UNSUPPORTED;
}

struct kvm_s1_trans {
	phys_addr_t output;
	u64 desc;
	u64 esr;
	u8 ap_table;
	u8 level;
	bool uxn_table;
	bool pxn_table;
	bool ur;
	bool uw;
	bool ux;
	bool pr;
	bool pw;
	bool px;
	bool af;
};

/* Private wrappers keep PVM metadata out of the public KVM structures. */
struct kvm_pvm_mmu {
	struct kvm_s2_mmu mmu;
	bool used;
	unsigned int active;
	u64 ttbr0;
	u64 tcr;
	u64 sctlr;
	u64 mair;
	u16 asid;
};

int kvm_pvm_init_vcpu_mmu(struct kvm_vcpu *vcpu);
void kvm_pvm_destroy_mmu(struct kvm *kvm);
void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block);
int kvm_pvm_vcpu_select_mmu(struct kvm_vcpu *vcpu, bool may_block);
void kvm_pvm_vcpu_put_mmu(struct kvm_vcpu *vcpu);
bool kvm_pvm_vcpu_mmu_enabled(struct kvm_vcpu *vcpu);
int kvm_pvm_walk_shadow_s1(struct kvm_vcpu *vcpu, u64 va,
			   struct kvm_s1_trans *result);
bool kvm_pvm_s1_access_denied(struct kvm_vcpu *vcpu,
			      struct kvm_s1_trans *result);
int kvm_pvm_inject_s1_fault(struct kvm_vcpu *vcpu, u32 fsc);

#endif /* __ARM64_KVM_PVM_MMU_H__ */
