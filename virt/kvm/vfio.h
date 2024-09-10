/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_VFIO_H
#define __KVM_VFIO_H

#ifdef CONFIG_HISI_VIRTCCA_HOST
#include "../drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h"
#endif

#ifdef CONFIG_KVM_VFIO
int kvm_vfio_ops_init(void);
void kvm_vfio_ops_exit(void);
#else
static inline int kvm_vfio_ops_init(void)
{
	return 0;
}
static inline void kvm_vfio_ops_exit(void)
{
}
#endif

#ifdef CONFIG_HISI_VIRTCCA_HOST
struct kvm *virtcca_arm_smmu_get_kvm(struct arm_smmu_domain *domain);
#endif
#endif
