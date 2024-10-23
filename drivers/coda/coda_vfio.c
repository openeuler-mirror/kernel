// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/io-pgtable.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <asm/virtcca_coda.h>

/**
 * virtcca_map_pages - Virtcca need map the secure
 * memory with paddr
 * @ops: The handle of io_pgtable_ops
 * @iova: Ipa address
 * @paddr: Physical address
 * @pgsize: Page size
 * @pgcount: Page count
 * @iommu_prot: Iommu attribute
 * @mapped: Mapped size
 *
 * Returns:
 * %0 if map pages success
 */
int virtcca_map_pages(void *ops, unsigned long iova,
	phys_addr_t paddr, size_t pgsize, size_t pgcount,
	int iommu_prot, size_t *mapped)
{
	struct kvm *kvm;
	u64 loader_start;
	u64 ram_size;
	struct io_pgtable *data = io_pgtable_ops_to_pgtable(ops);
	struct io_pgtable_cfg *cfg = &data->cfg;
	long iaext = (s64)iova >> cfg->ias;
	int ret = 0;
	struct arm_smmu_domain *smmu_domain = NULL;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize))
		return -EINVAL;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext || paddr >> cfg->oas))
		return -ERANGE;

	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	smmu_domain = (struct arm_smmu_domain *)(data->cookie);
	if (!smmu_domain)
		return -EINVAL;

	kvm = smmu_domain->kvm;
	if (kvm) {
		struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;

		loader_start = virtcca_cvm->loader_start;
		ram_size = virtcca_cvm->ram_size;
		/* Cvm ram space mapping*/
		if (iova >= loader_start &&
		iova < loader_start + ram_size &&
		!virtcca_cvm->is_mapped) {
			ret = kvm_cvm_map_range(kvm);
		} else if (iova < loader_start || iova >= loader_start + ram_size) {
			if (iova == CVM_MSI_ORIG_IOVA)
				/* Cvm msi address mapping */
				ret = virtcca_map_msi_address(kvm, smmu_domain,
					paddr, pgsize * pgcount);
			else
				/* Cvm mmio space mapping */
				ret = cvm_map_unmap_ipa_range(kvm, iova,
					paddr, pgsize * pgcount, true);
		}
		if (mapped)
			*mapped += pgsize * pgcount;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_map_pages);

/**
 * virtcca_unmap_pages - Virtcca unmap the iova
 * @ops: The handle of io_pgtable_ops
 * @iova: Ipa address
 * @pgsize: Page size
 * @pgcount: Page count
 *
 * Returns:
 * %0 if map pages success or parameter is invalid
 */
size_t virtcca_unmap_pages(void *ops, unsigned long iova,
	size_t pgsize, size_t pgcount)
{
	struct kvm *kvm;
	struct io_pgtable *data = io_pgtable_ops_to_pgtable(ops);
	struct io_pgtable_cfg *cfg = &data->cfg;
	long iaext = (s64)iova >> cfg->ias;
	struct arm_smmu_domain *smmu_domain = NULL;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize || !pgcount))
		return 0;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext))
		return 0;

	smmu_domain = (struct arm_smmu_domain *)(data->cookie);
	if (!smmu_domain)
		return 0;

	kvm = smmu_domain->kvm;
	if (!kvm)
		return 0;

	return cvm_map_unmap_ipa_range(kvm, iova, 0, pgsize * pgcount, false);
}
EXPORT_SYMBOL_GPL(virtcca_unmap_pages);

/**
 * virtcca_iommu_map - Iommu driver map pages, and then
 * calls the map function in the
 * smmu to perform mapping
 * @domain: Iommu domain
 * @iova: Ipa address
 * @paddr: Physical address
 * @size: Map size
 * @prot: Iommu attribute
 *
 * Returns:
 * %0 if map success
 * %-EINVAL if domain type is not paging
 * %-ENODEV if the domain pgsize_bitmap is zero or parameter is invalid
 */
int virtcca_iommu_map(struct iommu_domain *domain, unsigned long iova,
	phys_addr_t paddr, size_t size, int prot)
{
	unsigned int min_pagesz;
	int ret = 0;
	unsigned long orig_iova = iova;
	size_t orig_size = size;
	const struct iommu_domain_ops *ops = domain->ops;
	struct io_pgtable_ops *io_ops = to_smmu_domain(domain)->pgtbl_ops;

	if (unlikely(!(domain->type & __IOMMU_DOMAIN_PAGING)))
		return -EINVAL;

	if (WARN_ON(domain->pgsize_bitmap == 0UL))
		return -ENODEV;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->pgsize_bitmap);

	/*
	 * both the virtual address and the physical one, as well as
	 * the size of the mapping, must be aligned (at least) to the
	 * size of the smallest page supported by the hardware
	 */
	if (!IS_ALIGNED(iova | paddr | size, min_pagesz)) {
		pr_err("unaligned: iova 0x%lx pa %pa size 0x%zx min_pagesz 0x%x\n",
			iova, &paddr, size, min_pagesz);
		return -EINVAL;
	}

	if (!io_ops)
		return -ENODEV;

	while (size) {
		size_t pgsize, count, mapped = 0;

		pgsize = iommu_pgsize(domain, iova, paddr, size, &count);

		ret = virtcca_map_pages(io_ops, iova, paddr, pgsize,
			count, prot, &mapped);
		/*
		 * Some pages may have been mapped, even if an error occurred,
		 * so we should account for those so they can be unmapped.
		 */
		size -= mapped;

		if (ret)
			break;

		iova += mapped;
		paddr += mapped;
	}

	/* unroll mapping in case something went wrong */
	if (ret)
		virtcca_iommu_unmap(domain, orig_iova, orig_size - size);

	if (ret == 0 && ops->iotlb_sync_map) {
		ret = ops->iotlb_sync_map(domain, iova, size);
		if (ret)
			goto out_err;
	}

	return ret;

out_err:
	/* undo mappings already done */
	virtcca_iommu_unmap(domain, iova, size);

	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_iommu_map);

/**
 * virtcca_iommu_unmap - Iommu driver unmap pages, and then
 * calls the map function in the
 * smmu to perform unmapping
 * @domain: Iommu domain
 * @iova: Ipa address
 * @size: Map size
 *
 * Returns:
 * %0 if map success or domain type and parameter is invalid
 */

size_t virtcca_iommu_unmap(struct iommu_domain *domain,
	unsigned long iova, size_t size)
{
	size_t unmapped_page, unmapped = 0;
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;
	unsigned int min_pagesz;

	if (unlikely(!(domain->type & __IOMMU_DOMAIN_PAGING)))
		return 0;

	if (WARN_ON(domain->pgsize_bitmap == 0UL))
		return 0;

	/* find out the minimum page size supported */
	min_pagesz = 1 << __ffs(domain->pgsize_bitmap);

	/*
	 * The virtual address, as well as the size of the mapping, must be
	 * aligned (at least) to the size of the smallest page supported
	 * by the hardware
	 */
	if (!IS_ALIGNED(iova | size, min_pagesz)) {
		pr_err("unaligned: iova 0x%lx size 0x%zx min_pagesz 0x%x\n",
			iova, size, min_pagesz);
		return 0;
	}

	if (!ops)
		return 0;

	/*
	 * Keep iterating until we either unmap 'size' bytes (or more)
	 * or we hit an area that isn't mapped.
	 */
	while (unmapped < size) {
		size_t pgsize, count;

		pgsize = iommu_pgsize(domain, iova, iova, size - unmapped, &count);
		unmapped_page = virtcca_unmap_pages(ops, iova, pgsize, count);
		if (!unmapped_page)
			break;

		iova += unmapped_page;
		unmapped += unmapped_page;
	}
	return unmapped;
}
EXPORT_SYMBOL_GPL(virtcca_iommu_unmap);

/* Whether the kvm is cvm */
bool virtcca_iommu_domain_get_kvm(struct iommu_domain *domain, struct kvm **kvm)
{
	struct arm_smmu_domain *arm_smmu_domain;

	arm_smmu_domain = to_smmu_domain(domain);
	*kvm = virtcca_arm_smmu_get_kvm(arm_smmu_domain);
	if (*kvm)
		return (*kvm)->arch.is_virtcca_cvm;

	return false;
}
EXPORT_SYMBOL_GPL(virtcca_iommu_domain_get_kvm);

/**
 * cvm_vfio_file_iommu_group - Get iommu group from vfio file
 * @file: Vfio file
 *
 * Returns:
 * %NULL if the virtcca_vfio_file_iommu_group func is not defined
 * or CONFIG_HISI_VIRTCCA_CODA is not enable, group is null
 * %iommu_group if get the iommu group from file success
 */
struct iommu_group *cvm_vfio_file_iommu_group(struct file *file)
{
	struct iommu_group *(*fn)(struct file *file);
	struct iommu_group *ret;

	fn = symbol_get(virtcca_vfio_file_iommu_group);
	if (!fn)
		return NULL;

	ret = fn(file);

	symbol_put(virtcca_vfio_file_iommu_group);

	return ret;
}

/* Obtain msi address through iommu group id */
u64 virtcca_get_iommu_device_msi_addr(struct iommu_group *iommu_group)
{
	u64 msi_addr = iommu_group_id(iommu_group) * CVM_MSI_IOVA_OFFSET + CVM_MSI_MIN_IOVA;

	if (msi_addr >= CVM_MSI_MAX_IOVA || msi_addr < CVM_MSI_MIN_IOVA) {
		pr_err("MSI address 0x%llx overflow.\n", msi_addr);
		return 0;
	}

	return msi_addr;
}
EXPORT_SYMBOL_GPL(virtcca_get_iommu_device_msi_addr);

/* Set the corresponding MSI address */
int virtcca_set_dev_msi_addr(struct device *dev, void *iova)
{
	unsigned long *msi_iova = (unsigned long *)iova;

	if (dev_is_pci(dev)) {
		struct pci_dev *pci_dev = to_pci_dev(dev);
		u16 pci_id = pci_dev_id(pci_dev);

		set_g_cc_dev_msi_addr(pci_id, *msi_iova);
	}
	return 0;
}

/* Traverse the devices in the iommu group and set the corresponding MSI address */
int virtcca_iommu_group_set_dev_msi_addr(struct iommu_group *iommu_group, unsigned long *iova)
{
	int ret;

	ret = iommu_group_for_each_dev(iommu_group, (void *)iova, virtcca_set_dev_msi_addr);
	return ret;
}

/**
 * virtcca_msi_map - Vfio driver mapping device side msi address
 * @vdev: Vfio pci core device
 *
 * Returns:
 * %0 if map success
 */
int virtcca_msi_map(struct vfio_pci_core_device *vdev)
{
	if (!is_virtcca_cvm_enable())
		return 0;

	int ret;
	dma_addr_t iova;
	phys_addr_t msi_addr;
	struct iommu_domain *domain = NULL;
	struct pci_dev *pdev = vdev->pdev;
	bool cc_dev = pdev == NULL ? false : is_cc_dev(pci_dev_id(pdev));
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	/*
	 * If the device is secure and has not done MSI address mapping,
	 * Mapping is required.
	 */
	if (cc_dev && !get_g_cc_dev_msi_addr(pci_dev_id(pdev))) {
		domain = iommu_get_domain_for_dev(&(pdev->dev));
		/* Get the MSI address of the device */
		virtcca_iommu_dma_get_msi_page((void *)domain->iova_cookie, &iova, &msi_addr);
		/* Release non-secure side device MSI address mapping */
		iommu_unmap(domain, iova, PAGE_SIZE);
		/* Mapping secure side MSI address */
		ret = virtcca_iommu_map(domain, iova, msi_addr, PAGE_SIZE, prot);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(virtcca_msi_map);
