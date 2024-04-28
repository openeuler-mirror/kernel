/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef __ASM_KVM_TMM_H
#define __ASM_KVM_TMM_H

#include <uapi/linux/kvm.h>

enum cvm_state {
	CVM_STATE_NONE,
	CVM_STATE_NEW,
	CVM_STATE_ACTIVE,
	CVM_STATE_DYING
};

struct cvm {
	enum cvm_state state;
	u32 cvm_vmid;
	u64 rd;
	u64 loader_start;
	u64 initrd_start;
	u64 initrd_size;
	u64 ram_size;
	struct kvm_numa_info numa_info;
	struct tmi_cvm_params *params;
};

/*
 * struct cvm_tec - Additional per VCPU data for a CVM
 */
struct cvm_tec {
	u64 tec;
	bool tec_created;
	void *tec_run;
};

int kvm_init_tmm(void);
int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap);
int kvm_init_cvm_vm(struct kvm *kvm);
void kvm_destroy_cvm(struct kvm *kvm);
int kvm_create_tec(struct kvm_vcpu *vcpu);
void kvm_destroy_tec(struct kvm_vcpu *vcpu);
int kvm_tec_enter(struct kvm_vcpu *vcpu);
int handle_cvm_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_arm_create_cvm(struct kvm *kvm);
void kvm_free_rd(struct kvm *kvm);
int cvm_create_rd(struct kvm *kvm);
int kvm_arm_cvm_first_run(struct kvm_vcpu *vcpu);
int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target);
int kvm_arch_tec_init(struct kvm_vcpu *vcpu);

void kvm_cvm_unmap_destroy_range(struct kvm *kvm);

#define CVM_TTT_BLOCK_LEVEL	2
#define CVM_TTT_MAX_LEVEL	3

#define CVM_PAGE_SHIFT		12
#define CVM_PAGE_SIZE		BIT(CVM_PAGE_SHIFT)
#define CVM_TTT_LEVEL_SHIFT(l)	\
	((CVM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define CVM_L2_BLOCK_SIZE	BIT(CVM_TTT_LEVEL_SHIFT(2))

static inline unsigned long cvm_ttt_level_mapsize(int level)
{
	if (WARN_ON(level > CVM_TTT_BLOCK_LEVEL))
		return CVM_PAGE_SIZE;

	return (1UL << CVM_TTT_LEVEL_SHIFT(level));
}

#endif
