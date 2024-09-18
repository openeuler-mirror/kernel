/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#ifndef __VIRTCCA_CODA_H
#define __VIRTCCA_CODA_H

#include <linux/iommu.h>
#include <linux/vfio_pci_core.h>

#include "../../../drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.h"
#include "../../../drivers/iommu/arm/arm-smmu-v3/arm-s-smmu-v3.h"

#ifdef CONFIG_HISI_VIRTCCA_HOST
int virtcca_attach_secure_dev(struct iommu_domain *domain, struct iommu_group *group);
int virtcca_smmu_secure_dev_operator(struct iommu_domain *domain, struct device *dev);

struct iommu_domain *virtcca_iommu_group_get_domain(struct iommu_group *iommu_group);
int virtcca_iommu_map(struct iommu_domain *domain, unsigned long iova,
	phys_addr_t paddr, size_t size, int prot);
size_t virtcca_iommu_unmap(struct iommu_domain *domain,
	unsigned long iova, size_t size);
int virtcca_map_pages(void *ops, unsigned long iova,
	phys_addr_t paddr, size_t pgsize, size_t pgcount,
	int iommu_prot, size_t *mapped);
size_t virtcca_unmap_pages(void *ops, unsigned long iova,
	size_t pgsize, size_t pgcount);

void virtcca_pci_read_msi_msg(struct pci_dev *dev, struct msi_msg *msg,
	void __iomem *base);
int virtcca_pci_write_msg_msi(struct msi_desc *desc, struct msi_msg *msg);
void virtcca_msix_prepare_msi_desc(struct pci_dev *dev,
	struct msi_desc *desc, void __iomem *addr);
int virtcca_pci_msix_write_vector_ctrl(struct msi_desc *desc, u32 ctrl);
int virtcca_pci_msix_mask(struct msi_desc *desc);
int msix_mask_all_cc(struct pci_dev *dev, void __iomem *base, int tsize, u64 dev_num);

int virtcca_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 *val);
int virtcca_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 val);

bool is_virtcca_pci_io_rw(struct vfio_pci_core_device *vdev);
void virtcca_pci_io_write(struct vfio_pci_core_device *vdev, u64 val,
	u64 size, void __iomem *io);
u64 virtcca_pci_io_read(struct vfio_pci_core_device *vdev,
	u64 size, void __iomem *io);

bool virtcca_iommu_domain_get_kvm(struct iommu_domain *domain, struct kvm **kvm);
bool virtcca_check_kvm_is_cvm(void *iommu, struct kvm **kvm);
int virtcca_vfio_iommu_map(void *iommu, dma_addr_t iova,
	unsigned long pfn, long npage, int prot);
int cvm_vfio_add_kvm_to_smmu_domain(struct file *filp, void *kv);
struct kvm *virtcca_arm_smmu_get_kvm(struct arm_smmu_domain *domain);
void kvm_get_arm_smmu_domain(struct kvm *kvm, struct list_head *smmu_domain_group_list);
struct arm_lpae_io_pgtable *virtcca_io_pgtable_get_data(void *ops);
struct io_pgtable_cfg *virtcca_io_pgtable_get_cfg(struct arm_lpae_io_pgtable *data);
struct iommu_group *cvm_vfio_file_iommu_group(struct file *file);
struct kvm *virtcca_smmu_domain_get_kvm(struct arm_lpae_io_pgtable *data);
#endif
#endif
