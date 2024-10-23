/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef __ASM_KVM_TMM_H
#define __ASM_KVM_TMM_H

#include <uapi/linux/kvm.h>

/*
 * There is a conflict with the internal iova of CVM,
 * so it is necessary to offset the msi iova.
 * According to qemu file(hw/arm/virt.c), 0x0a001000 - 0x0b000000
 * iova is not being used, so it is used as the iova range for msi
 * mapping.
 */
#define CVM_MSI_ORIG_IOVA	0x8000000
#define CVM_MSI_MIN_IOVA	0x0a001000
#define CVM_MSI_MAX_IOVA	0x0b000000
#define CVM_MSI_IOVA_OFFSET	0x1000

#define CVM_RW_8_BIT	0x8
#define CVM_RW_16_BIT	0x10
#define CVM_RW_32_BIT	0x20
#define CVM_RW_64_BIT	0x40

enum virtcca_cvm_state {
	CVM_STATE_NONE = 1,
	CVM_STATE_NEW,
	CVM_STATE_ACTIVE,
	CVM_STATE_DYING
};

/*
 * Many of these fields are smaller than u64 but all fields have u64
 * alignment, so use u64 to ensure correct alignment.
 */
struct tmi_cvm_params {
	u64	flags;
	u64	s2sz;
	u64	sve_vl;
	u64	num_bps;
	u64	num_wps;
	u64	pmu_num_cnts;
	u64	measurement_algo;
	u64	vmid;
	u64	ns_vtcr;
	u64	vttbr_el2;
	u64	ttt_base;
	s64	ttt_level_start;
	u64	ttt_num_start;
	u8	rpv[64]; /* Bits 512 */
};

struct cvm {
	enum virtcca_cvm_state state;
	u32 cvm_vmid;
	u64 rd;
	u64 loader_start;
	u64 initrd_start;
	u64 initrd_size;
	u64 ram_size;
	struct kvm_numa_info numa_info;
	struct tmi_cvm_params *params;
	bool is_cvm;
};

struct virtcca_cvm {
	enum virtcca_cvm_state state;
	u32 cvm_vmid;
	u64 rd;
	u64 loader_start;
	u64 image_end;
	u64 initrd_start;
	u64 dtb_end;
	u64 ram_size;
	struct kvm_numa_info numa_info;
	struct tmi_cvm_params *params;
	bool is_mapped; /* Whether the cvm RAM memory is mapped */
};

/*
 * struct cvm_tec - Additional per VCPU data for a CVM
 */
struct virtcca_cvm_tec {
	u64 tec;
	bool tec_created;
	void *tec_run;
};

struct cvm_ttt_addr {
	struct list_head list;
	u64 addr;
};

int kvm_init_tmm(void);
int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap);
void kvm_destroy_cvm(struct kvm *kvm);
int kvm_finalize_vcpu_tec(struct kvm_vcpu *vcpu);
void kvm_destroy_tec(struct kvm_vcpu *vcpu);
int kvm_tec_enter(struct kvm_vcpu *vcpu);
int handle_cvm_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_arm_create_cvm(struct kvm *kvm);
void kvm_free_rd(struct kvm *kvm);
int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target);

void kvm_cvm_unmap_destroy_range(struct kvm *kvm);
int kvm_cvm_map_range(struct kvm *kvm);
int virtcca_cvm_arm_smmu_domain_set_kvm(void *group);
int cvm_map_unmap_ipa_range(struct kvm *kvm, phys_addr_t ipa_base, phys_addr_t pa,
	unsigned long map_size, uint32_t is_map);
int kvm_cvm_map_ipa_mmio(struct kvm *kvm, phys_addr_t ipa_base,
	phys_addr_t pa, unsigned long map_size);

bool is_in_virtcca_ram_range(struct kvm *kvm, uint64_t iova);
bool is_virtcca_iova_need_vfio_dma(struct kvm *kvm, uint64_t iova);

#define CVM_TTT_BLOCK_LEVEL	2
#define CVM_TTT_MAX_LEVEL	3

#define CVM_MAP_IPA_RAM	1
#define CVM_MAP_IPA_SMMU	2
#define CVM_MAP_IPA_UNPROTECTED	4

#define CVM_PAGE_SHIFT		12
#define CVM_PAGE_SIZE		BIT(CVM_PAGE_SHIFT)
#define CVM_TTT_LEVEL_SHIFT(l)	\
	((CVM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define CVM_L2_BLOCK_SIZE	BIT(CVM_TTT_LEVEL_SHIFT(2))

#define TMM_GRANULE_SIZE2		12
#define TMM_TTT_WIDTH			19
#define TMM_GRANULE_SIZE		(1UL << TMM_GRANULE_SIZE2)
#define tmm_granule_size(level)	(TMM_GRANULE_SIZE << ((3 - level)) * TMM_TTT_WIDTH)

static inline unsigned long cvm_ttt_level_mapsize(int level)
{
	if (WARN_ON(level > CVM_TTT_BLOCK_LEVEL))
		return CVM_PAGE_SIZE;

	return (1UL << CVM_TTT_LEVEL_SHIFT(level));
}

#endif
