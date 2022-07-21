// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/arch/sw_64/kernel/pci_iommu.c
 */

#include <linux/pci.h>
#include <linux/export.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>
#include <linux/swiotlb.h>

static dma_addr_t sw64_direct_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size,
		enum dma_data_direction dir,
		unsigned long attrs)
{
	dma_addr_t dma_addr = page_to_phys(page) + offset;

	if (unlikely(swiotlb_force == SWIOTLB_FORCE))
		return swiotlb_map(dev, dma_addr, size, dir, attrs);

	if (unlikely(!dma_capable(dev, dma_addr, size, true))) {
		if (swiotlb_force != SWIOTLB_NO_FORCE)
			return swiotlb_map(dev, dma_addr, size, dir, attrs);

		dev_WARN_ONCE(dev, 1,
			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
		return DMA_MAPPING_ERROR;
	}

	return dma_addr;
}

static inline void sw64_direct_unmap_page(struct device *dev, dma_addr_t addr,
		size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
	if (unlikely(is_swiotlb_buffer(addr)))
		swiotlb_tbl_unmap_single(dev, addr, size, size, dir, attrs);
}

static bool dma_coherent_ok(struct device *dev, phys_addr_t phys, size_t size)
{
	return phys + size - 1 <=
		min_not_zero(dev->coherent_dma_mask, dev->bus_dma_limit);
}

static void *sw64_direct_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_addrp, gfp_t gfp,
		unsigned long attrs)
{
	struct page *page;
	void *ret;
	u64 dma_limit;

	size = PAGE_ALIGN(size);
	if (attrs & DMA_ATTR_NO_WARN)
		gfp |= __GFP_NOWARN;

	dma_limit = min_not_zero(dev->coherent_dma_mask, dev->bus_dma_limit);
	if (dma_limit <= DMA_BIT_MASK(32))
		gfp |= GFP_DMA32;

	/* we always manually zero the memory once we are done */
	gfp &= ~__GFP_ZERO;
again:
	page = alloc_pages_node(dev_to_node(dev), gfp, get_order(size));
	if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
		dma_free_contiguous(dev, page, size);
		page = NULL;

		if (IS_ENABLED(CONFIG_ZONE_DMA32) &&
				dma_limit < DMA_BIT_MASK(64) &&
				!(gfp & (GFP_DMA32 | GFP_DMA))) {
			gfp |= GFP_DMA32;
			goto again;
		}
	}

	if (!page)
		return NULL;

	ret = page_address(page);
	memset(ret, 0, size);
	*dma_addrp = page_to_phys(page);

	return ret;
}

static void sw64_direct_free_coherent(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_addr,
		unsigned long attrs)
{
	if (attrs & DMA_ATTR_NO_KERNEL_MAPPING) {
		/* cpu_addr is a struct page cookie, not a kernel address */
		dma_free_contiguous(dev, cpu_addr, size);
		return;
	}

	free_pages((unsigned long)cpu_addr, get_order(size));
}

static void sw64_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir, unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i)
		sw64_direct_unmap_page(dev, sg->dma_address, sg_dma_len(sg), dir,
				attrs);
}

static int sw64_direct_map_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir, unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		sg_dma_address(sg) = sw64_direct_map_page(dev, sg_page(sg),
				   sg->offset, sg->length, dir, attrs);
		if (sg->dma_address == DMA_MAPPING_ERROR)
			goto out_unmap;
		sg_dma_len(sg) = sg->length;
	}
	return nents;

out_unmap:
	sw64_direct_unmap_sg(dev, sgl, i, dir, attrs | DMA_ATTR_SKIP_CPU_SYNC);
	return 0;
}

const struct dma_map_ops sw64_dma_direct_ops = {
	.alloc = sw64_direct_alloc_coherent,
	.free = sw64_direct_free_coherent,
	.map_page = sw64_direct_map_page,
	.unmap_page = sw64_direct_unmap_page,
	.map_sg = sw64_direct_map_sg,
	.unmap_sg = sw64_direct_unmap_sg,
	.dma_supported = dma_direct_supported,
};

const struct dma_map_ops *dma_ops = &sw64_dma_direct_ops;
EXPORT_SYMBOL(dma_ops);
