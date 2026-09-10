// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/io.h>
#include <linux/swiotlb.h>
#include <asm/rsi.h>
#ifdef CONFIG_HISI_CCADA_GUEST
#include <linux/pci.h>
#endif
#include <asm/realm_guest.h>

static struct device realm_alloc_device;

/*
 * struct io_tlb_no_swiotlb_mem - whether use the
 * bounce buffer mechanism or not
 * @for_alloc: %true if the pool is used for memory allocation.
 *	Here it is set to %false, to force devices to use direct dma operations.
 *
 * @force_bounce: %true if swiotlb bouncing is forced.
 *	Here it is set to %false, to force devices to use direct dma operations.
 */
static struct io_tlb_mem io_tlb_no_swiotlb_mem = {
	.for_alloc = false,
	.force_bounce = false,
};

void enable_swiotlb_for_realm_dev(struct device *dev, bool enable)
{
	if (!is_realm_world())
		return;

	if (enable)
		swiotlb_dev_init(dev);
	else
		dev->dma_io_tlb_mem = &io_tlb_no_swiotlb_mem;
}
EXPORT_SYMBOL_GPL(enable_swiotlb_for_realm_dev);

void __init realm_guest_init(void)
{
	device_initialize(&realm_alloc_device);
	enable_swiotlb_for_realm_dev(&realm_alloc_device, true);
}

struct page *realm_alloc_swiotlb_shared_pages(gfp_t gfp, unsigned int order)
{
	return swiotlb_alloc(&realm_alloc_device, (1UL << order) * PAGE_SIZE);
}

bool realm_free_swiotlb_shared_pages(void *addr, unsigned int order)
{
	return swiotlb_free(&realm_alloc_device, virt_to_page(addr),
			    (1UL << order) * PAGE_SIZE);
}

#ifdef CONFIG_HISI_CCADA_GUEST
static int set_msix_region_shared(struct pci_dev *pdev, int bar)
{
	resource_size_t start;
	resource_size_t end;
	u32 table_offset;
	u16 control;
	u8 msix_bir;
	size_t tsize;

	pci_read_config_dword(pdev, pdev->msix_cap + PCI_MSIX_TABLE, &table_offset);
	msix_bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	if (msix_bir != bar)
		return 0;

	table_offset &= PCI_MSIX_TABLE_OFFSET;
	start = pci_resource_start(pdev, msix_bir) + table_offset;
	if (start <= table_offset) {
		pci_err(pdev, "pci dev msi start overflow.\n");
		return -EINVAL;
	}

	pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &control);
	tsize = (control & PCI_MSIX_FLAGS_QSIZE) + 1;
	end = ALIGN(start + tsize * PCI_MSIX_ENTRY_SIZE, PAGE_SIZE);
	if (end <= start) {
		pci_err(pdev, "pci dev msi end overflow.\n");
		return -EINVAL;
	}
	return rsi_set_memory_range_shared(start, end);
}

int ccada_init_mem_region(struct pci_dev *pdev, int bar)
{
	int ret;

	if (!is_realm_world())
		return 0;

	if (!pdev || bar < 0 || bar >= PCI_STD_NUM_BARS)
		return -EINVAL;

	if (pci_resource_len(pdev, bar) == 0)
		return 0;

	if (!rsi_is_realm_dev(pci_dev_id(pdev)))
		return 0;

	ret = rsi_set_mmio_range_protected(pci_resource_start(pdev, bar),
					   pci_resource_len(pdev, bar));
	if (ret) {
		pci_err(pdev, "Failed to set bar[%d] to protected\n", bar);
		return ret;
	}

	if (pdev->msix_cap) {
		ret = set_msix_region_shared(pdev, bar);
		if (ret)
			pci_err(pdev, "Failed to set msi-x to shared\n");
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ccada_init_mem_region);
#endif
