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

#ifdef CONFIG_HISI_VIRTCCA_CODA

#define MAX_CC_DEV_NUM_ORDER    8
#define MASK_DEV_FUNCTION       0xfff8
#define MASK_DEV_BUS            0xff

#define DEV_BUS_NUM             0x8
#define DEV_FUNCTION_NUM        0x3

#define STE_ENTRY_SIZE          0x40

#define SMMU_DOMAIN_IS_SAME     0x2

int virtcca_attach_secure_dev(struct iommu_domain *domain, struct iommu_group *group);

u64 virtcca_get_iommu_device_msi_addr(struct iommu_group *iommu_group);
int virtcca_iommu_group_set_dev_msi_addr(struct iommu_group *iommu_group, unsigned long *iova);
int virtcca_map_msi_address(struct kvm *kvm, struct arm_smmu_domain *smmu_domain, phys_addr_t pa,
	unsigned long map_size);

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
bool virtcca_pci_write_msg_msi(struct msi_desc *desc, struct msi_msg *msg);
void virtcca_msix_prepare_msi_desc(struct pci_dev *dev,
	struct msi_desc *desc, void __iomem *addr);
bool virtcca_pci_msix_write_vector_ctrl(struct msi_desc *desc, u32 ctrl);
bool virtcca_pci_msix_mask(struct msi_desc *desc);
int virtcca_msix_mask_all_cc(struct pci_dev *dev, void __iomem *base, int tsize, u64 dev_num);

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
bool virtcca_check_is_cvm_or_not(void *iommu, struct kvm **kvm);
int virtcca_vfio_iommu_map(void *iommu, dma_addr_t iova,
	unsigned long pfn, long npage, int prot);
int cvm_vfio_add_kvm_to_smmu_domain(struct file *filp, void *kv);
struct kvm *virtcca_arm_smmu_get_kvm(struct arm_smmu_domain *domain);
void kvm_get_arm_smmu_domain(struct kvm *kvm, struct list_head *smmu_domain_group_list);
struct iommu_group *cvm_vfio_file_iommu_group(struct file *file);

struct iommu_group *virtcca_vfio_file_iommu_group(struct file *file);

bool is_cc_vmid(u32 vmid);
/* Has the root bus device number switched to secure */
bool is_cc_dev(u32 sid);

u64 get_g_cc_dev_msi_addr(u32 sid);

void set_g_cc_dev_msi_addr(u32 sid, u64 msi_addr);

void g_cc_dev_table_init(void);

u32 virtcca_tmi_dev_attach(struct arm_smmu_domain *arm_smmu_domain, struct kvm *kvm);

void virtcca_iommu_dma_get_msi_page(void *cookie, dma_addr_t *iova, phys_addr_t *phys);

int virtcca_msi_map(struct vfio_pci_core_device *vdev);
#endif
#endif
