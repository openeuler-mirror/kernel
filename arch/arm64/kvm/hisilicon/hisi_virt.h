// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2022 Huawei Technologies Co., Ltd
 */

#ifndef __HISI_VIRT_H__
#define __HISI_VIRT_H__

enum hisi_cpu_type {
	HI_1612,
	HI_1616,
	HI_1620,
	HI_IP09,
	UNKNOWN_HI_TYPE
};

/* HIP09 */
#define AIDR_EL1_DVMBM_MASK	GENMASK_ULL(13, 12)
#define SYS_LSUDVM_CTRL_EL2	sys_reg(3, 4, 15, 7, 4)
#define LSUDVM_CTLR_EL2_MASK	BIT_ULL(0)

void probe_hisi_cpu_type(void);
bool hisi_ncsnp_supported(void);
bool hisi_dvmbm_supported(void);

int kvm_hisi_dvmbm_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_hisi_dvmbm_vcpu_destroy(struct kvm_vcpu *vcpu);
void kvm_hisi_dvmbm_load(struct kvm_vcpu *vcpu);
void kvm_hisi_dvmbm_put(struct kvm_vcpu *vcpu);
int kvm_hisi_init_dvmbm(struct kvm *kvm);
void kvm_hisi_destroy_dvmbm(struct kvm *kvm);

#endif /* __HISI_VIRT_H__ */
