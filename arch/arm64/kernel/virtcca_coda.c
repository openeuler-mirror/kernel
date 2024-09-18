// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/vfio.h>
#include <linux/io-pgtable.h>
#include <asm/virtcca_coda.h>
#include <asm/virtcca_cvm_host.h>
#include <asm/kvm_host.h>
#include <asm/kvm_tmm.h>
#include <asm/kvm_tmi.h>

#include "../../drivers/pci/msi/msi.h"
#include "../../drivers/vfio/vfio.h"

/**
 * virtcca_map_pages - Virtcca need map the secure
 * memory with paddr
 * @ops: the handle of io_pgtable_ops
 * @iova: Ipa address
 * @paddr: Physical address
 * @pgsize: Page size
 * @pgcount: Page count
 * @iommu_prot: iommu attribute
 * @mapped: mapped size
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
	struct arm_lpae_io_pgtable *data = virtcca_io_pgtable_get_data(ops);
	struct io_pgtable_cfg *cfg = virtcca_io_pgtable_get_cfg(data);
	long iaext = (s64)iova >> cfg->ias;
	int ret = 0;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize))
		return -EINVAL;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext || paddr >> cfg->oas))
		return -ERANGE;

	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	kvm = virtcca_smmu_domain_get_kvm(data);
	if (kvm) {
		struct virtcca_cvm *virtcca_cvm = kvm->arch.virtcca_cvm;

		loader_start = virtcca_cvm->loader_start;
		ram_size = virtcca_cvm->ram_size;
		if (iova >= loader_start &&
			iova < loader_start + ram_size &&
			!virtcca_cvm->is_mapped) {
			ret = kvm_cvm_map_range(kvm);
		} else if (iova < loader_start) {
			if (iova == CVM_MSI_ORIG_IOVA)
				iova += CVM_MSI_IOVA_OFFSET;
			ret = cvm_map_unmap_ipa_range(kvm, iova, paddr, pgsize * pgcount, true);
		}
		if (mapped)
			*mapped += pgsize * pgcount;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(virtcca_map_pages);

/**
 * virtcca_unmap_pages - Virtcca unmap the iova
 * @ops: the handle of io_pgtable_ops
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
	struct arm_lpae_io_pgtable *data = virtcca_io_pgtable_get_data(ops);
	struct io_pgtable_cfg *cfg = virtcca_io_pgtable_get_cfg(data);
	long iaext = (s64)iova >> cfg->ias;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize || !pgcount))
		return 0;

	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
		iaext = ~iaext;
	if (WARN_ON(iaext))
		return 0;

	kvm = virtcca_smmu_domain_get_kvm(data);
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

/**
 * virtcca_pci_read_msi_msg - secure dev read msi msg
 * @dev: Pointer to the pci_dev data structure of MSI-X device function
 * @msg: Msg information
 * @base: Msi base address
 *
 **/
void virtcca_pci_read_msi_msg(struct pci_dev *dev, struct msi_msg *msg,
	void __iomem *base)
{
	u64 pbase = mmio_va_to_pa(base);

	msg->address_lo = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_LOWER_ADDR,
		CVM_RW_32_BIT, pci_dev_id(dev));
	msg->address_hi = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_UPPER_ADDR,
		CVM_RW_32_BIT, pci_dev_id(dev));
	msg->data = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_DATA, CVM_RW_32_BIT, pci_dev_id(dev));
}

/**
 * virtcca_pci_write_msi_msg - secure dev write msi msg
 * @desc: MSI-X description
 * @msg: Msg information
 *
 **/
int virtcca_pci_write_msg_msi(struct msi_desc *desc, struct msi_msg *msg)
{
	if (!is_virtcca_cvm_enable())
		return 0;

	void __iomem *base = pci_msix_desc_addr(desc);
	u32 ctrl = desc->pci.msix_ctrl;
	bool unmasked = !(ctrl & PCI_MSIX_ENTRY_CTRL_MASKBIT);
	u64 pbase = mmio_va_to_pa(base);
	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (!is_cc_dev(pci_dev_id(pdev)))
		return 0;

	u64 addr = (u64)msg->address_lo | ((u64)msg->address_hi << 32);

	addr += CVM_MSI_IOVA_OFFSET;
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_LOWER_ADDR,
		lower_32_bits(addr), CVM_RW_32_BIT, pci_dev_id(pdev));
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_UPPER_ADDR,
		upper_32_bits(addr), CVM_RW_32_BIT, pci_dev_id(pdev));
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_DATA,
		msg->data, CVM_RW_32_BIT, pci_dev_id(pdev));

	if (unmasked)
		pci_msix_write_vector_ctrl(desc, ctrl);
	tmi_mmio_read(mmio_va_to_pa((void *)pbase + PCI_MSIX_ENTRY_DATA),
		CVM_RW_32_BIT, pci_dev_id(pdev));

	return 1;
}

void virtcca_msix_prepare_msi_desc(struct pci_dev *dev,
	struct msi_desc *desc, void __iomem *addr)
{
	desc->pci.msix_ctrl = tmi_mmio_read(mmio_va_to_pa(addr + PCI_MSIX_ENTRY_VECTOR_CTRL),
		CVM_RW_32_BIT, pci_dev_id(dev));
}

/*
 * If it is a safety device, write vector ctrl need
 * use tmi interface
 */
int virtcca_pci_msix_write_vector_ctrl(struct msi_desc *desc, u32 ctrl)
{
	if (!is_virtcca_cvm_enable())
		return 0;

	void __iomem *desc_addr = pci_msix_desc_addr(desc);
	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (pdev == NULL || !is_cc_dev(pci_dev_id(pdev)))
		return 0;

	if (desc->pci.msi_attrib.can_mask)
		tmi_mmio_write(mmio_va_to_pa(desc_addr + PCI_MSIX_ENTRY_VECTOR_CTRL),
			ctrl, CVM_RW_32_BIT, pci_dev_id(pdev));
	return 1;
}

/*
 * If it is a safety device, read msix need
 * use tmi interface
 */
int virtcca_pci_msix_mask(struct msi_desc *desc)
{
	if (!is_virtcca_cvm_enable())
		return 0;

	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (pdev == NULL || !is_cc_dev(pci_dev_id(pdev)))
		return 0;

	/* Flush write to device */
	tmi_mmio_read(mmio_va_to_pa(desc->pci.mask_base), CVM_RW_32_BIT, pci_dev_id(pdev));
	return 1;
}

/**
 * msix_mask_all_cc - mask all secure dev msix c
 * @dev: Pointer to the pci_dev data structure of MSI-X device function
 * @base: Io address
 * @tsize: Number of entry
 * @dev_num: Dev number
 *
 * Returns:
 * %0 if msix mask all cc device success
 **/
int msix_mask_all_cc(struct pci_dev *dev, void __iomem *base, int tsize, u64 dev_num)
{
	int i;
	u16 rw_ctrl;
	u32 ctrl = PCI_MSIX_ENTRY_CTRL_MASKBIT;
	u64 pbase = mmio_va_to_pa(base);

	if (pci_msi_ignore_mask)
		goto out;

	for (i = 0; i < tsize; i++, base += PCI_MSIX_ENTRY_SIZE) {
		tmi_mmio_write(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL,
			ctrl, CVM_RW_32_BIT, dev_num);
	}

out:
	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &rw_ctrl);
	rw_ctrl &= ~PCI_MSIX_FLAGS_MASKALL;
	rw_ctrl |= 0;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, rw_ctrl);

	pcibios_free_irq(dev);
	return 0;
}

/* If device is secure dev, read config need transfer to tmm module */
int virtcca_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 *val)
{
	if (size == 1)
		*val = tmi_mmio_read(mmio_va_to_pa(addr), CVM_RW_8_BIT,
			((bus_num << BUS_NUM_SHIFT) | devfn));
	else if (size == 2)
		*val = tmi_mmio_read(mmio_va_to_pa(addr), CVM_RW_16_BIT,
			((bus_num << BUS_NUM_SHIFT) | devfn));
	else
		*val = tmi_mmio_read(mmio_va_to_pa(addr), CVM_RW_32_BIT,
			((bus_num << BUS_NUM_SHIFT) | devfn));

	return 0;
}

/* If device is secure dev, write config need transfer to tmm module */
int virtcca_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 val)
{
	if (size == 1)
		WARN_ON(tmi_mmio_write(mmio_va_to_pa(addr), val,
			CVM_RW_8_BIT, ((bus_num << BUS_NUM_SHIFT) | devfn)));
	else if (size == 2)
		WARN_ON(tmi_mmio_write(mmio_va_to_pa(addr), val,
			CVM_RW_16_BIT, ((bus_num << BUS_NUM_SHIFT) | devfn)));
	else
		WARN_ON(tmi_mmio_write(mmio_va_to_pa(addr), val,
			CVM_RW_32_BIT, ((bus_num << BUS_NUM_SHIFT) | devfn)));

	return 0;
}

/* Judge startup virtcca_cvm_host is enable and device is secure or not */
bool is_virtcca_pci_io_rw(struct vfio_pci_core_device *vdev)
{
	if (!is_virtcca_cvm_enable())
		return false;

	struct pci_dev *pdev = vdev->pdev;
	bool cc_dev = pdev == NULL ? false : is_cc_dev(pci_dev_id(pdev));

	if (cc_dev)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_virtcca_pci_io_rw);

/* Transfer to tmm write io value */
void virtcca_pci_io_write(struct vfio_pci_core_device *vdev, u64 val,
	u64 size, void __iomem *io)
{
	struct pci_dev *pdev = vdev->pdev;

	WARN_ON(tmi_mmio_write(mmio_va_to_pa(io), val, size, pci_dev_id(pdev)));
}
EXPORT_SYMBOL_GPL(virtcca_pci_io_write);

/* Transfer to tmm read io value */
u64 virtcca_pci_io_read(struct vfio_pci_core_device *vdev,
	u64 size, void __iomem *io)
{
	struct pci_dev *pdev = vdev->pdev;

	return tmi_mmio_read(mmio_va_to_pa(io), size, pci_dev_id(pdev));
}
EXPORT_SYMBOL_GPL(virtcca_pci_io_read);

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
 * or CONFIG_HISI_VIRTCCA_HOST is not enable, group is null
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
