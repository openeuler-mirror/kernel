// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/arch/sw_64/kernel/pci_iommu.c
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/export.h>
#include <linux/scatterlist.h>
#include <linux/log2.h>
#include <linux/dma-mapping.h>
#include <linux/iommu-helper.h>
#include <linux/slab.h>
#include <linux/dma-direct.h>
#include <linux/swiotlb.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <asm/dma.h>
#include <asm/io.h>

#include "pci_impl.h"

#define DEBUG_ALLOC 0
#if DEBUG_ALLOC > 0
# define DBGA(args...)		printk(KERN_DEBUG args)
#else
# define DBGA(args...)
#endif
#if DEBUG_ALLOC > 1
# define DBGA2(args...)		printk(KERN_DEBUG args)
#else
# define DBGA2(args...)
#endif

#define DEBUG_NODIRECT 0

#define ISA_DMA_MASK		0x00ffffff

/*
 * Map a single buffer of the indicated size for PCI DMA in streaming
 * mode.  The 32-bit PCI bus mastering address to use is returned.
 * Once the device is given the dma address, the device owns this memory
 * until either pci_unmap_single or pci_dma_sync_single is performed.
 */

static dma_addr_t
pci_direct_map_single_1(struct pci_dev *pdev, void *cpu_addr)
{
	struct pci_controller *hose = pdev->sysdata;
	unsigned long paddr;
	unsigned long dma_offset;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	dma_offset = read_piu_ior0(hose->node, hose->index, EPDMABAR);
	paddr = __pa(cpu_addr) + dma_offset;
	return paddr;
}

/* Helper for generic DMA-mapping functions. */
static struct pci_dev *sw64_direct_gendev_to_pci(struct device *dev)
{
	if (dev && dev->bus == &pci_bus_type)
		return to_pci_dev(dev);

	/* This assumes ISA bus master with dma_mask 0xffffff. */
	return NULL;
}

static dma_addr_t sw64_direct_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size,
		enum dma_data_direction dir,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw64_direct_gendev_to_pci(dev);

	if (dir == PCI_DMA_NONE)
		BUG();

	return pci_direct_map_single_1(pdev, (char *)page_address(page) + offset);
}

/*
 * Unmap a single streaming mode DMA translation.  The DMA_ADDR and
 * SIZE must match what was provided for in a previous pci_map_single
 * call.  All other usages are undefined.  After this call, reads by
 * the cpu to the buffer are guaranteed to see whatever the device
 * wrote there.
 */

static inline void sw64_direct_unmap_page(struct device *dev, dma_addr_t dma_addr,
		size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
}

/* Allocate and map kernel buffer using consistent mode DMA for PCI
 * device.  Returns non-NULL cpu-view pointer to the buffer if
 * successful and sets *DMA_ADDRP to the pci side dma address as well,
 * else DMA_ADDRP is undefined.
 */

static void *sw64_direct_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_addrp, gfp_t gfp,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw64_direct_gendev_to_pci(dev);
	void *cpu_addr;
	long order = get_order(size);

	gfp &= ~GFP_DMA;

#ifdef CONFIG_ZONE_DMA
	if (dev->coherent_dma_mask < DMA_BIT_MASK(32))
		gfp |= GFP_DMA;
#endif

try_again:
	cpu_addr = (void *)__get_free_pages(gfp, order);
	if (!cpu_addr) {
		pr_info("pci_alloc_consistent: get_free_pages failed from %ps\n",
				__builtin_return_address(0));
		/* ??? Really atomic allocation?  Otherwise we could play
		 * with vmalloc and sg if we can't find contiguous memory.
		 */
		return NULL;
	}
	memset(cpu_addr, 0, size);

	*dma_addrp = pci_direct_map_single_1(pdev, cpu_addr);
	if (*dma_addrp == 0) {
		free_pages((unsigned long)cpu_addr, order);
		if (gfp & GFP_DMA)
			return NULL;
		/* The address doesn't fit required mask and we
		 * do not have iommu. Try again with GFP_DMA.
		 */
		gfp |= GFP_DMA;
		goto try_again;
	}

	DBGA2("pci_alloc_consistent: %zx -> [%p,%llx] from %ps\n",
			size, cpu_addr, *dma_addrp, __builtin_return_address(0));

	return cpu_addr;
}

/* Free and unmap a consistent DMA buffer.  CPU_ADDR and DMA_ADDR must
 * be values that were returned from pci_alloc_consistent.  SIZE must
 * be the same as what as passed into pci_alloc_consistent.
 * References to the memory and mappings associated with CPU_ADDR or
 * DMA_ADDR past this call are illegal.
 */

static void sw64_direct_free_coherent(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_addr,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw64_direct_gendev_to_pci(dev);

	pci_unmap_single(pdev, dma_addr, size, PCI_DMA_BIDIRECTIONAL);
	free_pages((unsigned long)cpu_addr, get_order(size));
	DBGA2("pci_free_consistent: [%llx,%zx] from %ps\n",
			dma_addr, size, __builtin_return_address(0));
}
#define SG_ENT_VIRT_ADDRESS(SG) (sg_virt((SG)))
#define SG_ENT_PHYS_ADDRESS(SG) __pa(SG_ENT_VIRT_ADDRESS(SG))

static dma_addr_t sw64_phys_to_dma(struct device *dev, phys_addr_t pa)
{
	unsigned long dma_offset;
	struct pci_dev *pdev = sw64_gendev_to_pci(dev);
	struct pci_controller *hose = pdev->sysdata;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	dma_offset = read_piu_ior0(hose->node, hose->index, EPDMABAR);
	return pa + dma_offset;
}

static bool
check_addr(struct device *dev, dma_addr_t dma_addr, size_t size,
		const char *caller)
{
	if (unlikely(dev && !dma_capable(dev, dma_addr, size, true))) {
		if (!dev->dma_mask) {
			dev_err(dev,
					"%s: call on device without dma_mask\n",
					caller);
			return false;
		}

		if (*dev->dma_mask >= DMA_BIT_MASK(32)) {
			dev_err(dev,
					"%s: overflow %pad+%zu of device mask %llx\n",
					caller, &dma_addr, size, *dev->dma_mask);
		}
		return false;
	}
	return true;
}

static int sw64_direct_map_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir, unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		BUG_ON(!sg_page(sg));

		sg_dma_address(sg) = sw64_phys_to_dma(dev, sg_phys(sg));
		if (!check_addr(dev, sg_dma_address(sg), sg->length, __func__))
			return 0;
		sg_dma_len(sg) = sg->length;
	}

	return nents;
}

/* Unmap a set of streaming mode DMA translations.  Again, cpu read
 * rules concerning calls here are the same as for pci_unmap_single()
 * above.
 */

static inline void sw64_direct_unmap_sg(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir,
		unsigned long attrs)
{
}

/* Return whether the given PCI device DMA address mask can be
 * supported properly.
 */

static int sw64_direct_supported(struct device *dev, u64 mask)
{
	struct pci_dev *pdev = sw64_direct_gendev_to_pci(dev);
	struct pci_controller *hose;

	if ((max_low_pfn << PAGE_SHIFT) - 1 <= mask)
		return 1;

	/* Check that we have a scatter-gather arena that fits.  */
	hose = pdev->sysdata;
	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	/* As last resort try ZONE_DMA.  */
	if (MAX_DMA_ADDRESS - PAGE_OFFSET - 1 <= mask)
		return 1;

	/*
	 * Upstream PCI/PCIe bridges or SoC interconnects may not carry
	 * as many DMA address bits as the device itself supports.
	 */
	if (dev->bus_dma_limit && mask > dev->bus_dma_limit)
		return 0;

	return 0;
}

const struct dma_map_ops sw64_dma_direct_ops = {
	.alloc = sw64_direct_alloc_coherent,
	.free = sw64_direct_free_coherent,
	.map_page = sw64_direct_map_page,
	.unmap_page = sw64_direct_unmap_page,
	.map_sg = sw64_direct_map_sg,
	.unmap_sg = sw64_direct_unmap_sg,
	.dma_supported = sw64_direct_supported,
};

const struct dma_map_ops *dma_ops = &sw64_dma_direct_ops;
EXPORT_SYMBOL(dma_ops);
