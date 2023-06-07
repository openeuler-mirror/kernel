// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/init.h>
#include <linux/dma-direct.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/swiotlb.h>
#include <linux/highmem.h>
#include <linux/iommu-helper.h>

#include <asm/bootinfo.h>
#include <asm/dma.h>
#include <asm/loongson.h>

/*
 * We extract 4bit node id (bit 44~47) from Loongson-3's
 * 48bit physical address space and embed it into 40bit.
 */

#define IO_TLB_SHIFT_BACKUPS 12
#define DMA_ATTR_FORCE_SWIOTLB    (1UL << 10)
#define SWIOTLB_MAP_ERROR (~(phys_addr_t)0x0)
#define BOOTMEM_ALLOC_ANYWHERE (~(phys_addr_t)0)
#define IO_TLB_DEFAULT_SIZE_BACKUPS (4ULL << 30)
#define INVALID_PHYS_ADDR (~(phys_addr_t)0)
#define OFFSET(val, align) ((unsigned long)	\
		((val) & ((align) - 1)))
#define arch_dma_cache_sync NULL

unsigned int max_segment_backups;
bool swiotlb_need_fix;
static DEFINE_SPINLOCK(io_tlb_lock_high);
static phys_addr_t io_tlb_backups_start, io_tlb_backups_end;
static phys_addr_t *io_tlb_orig_backups_addr;
static bool no_iotlb_backups_memory;
static int node_id_offset;
static unsigned int *io_tlb_backups_list;
static unsigned long io_tlb_nslabs_backups;

static phys_addr_t map_single_loongson(struct device *hwdev, phys_addr_t phys, size_t size,
	   enum dma_data_direction dir, unsigned long attrs);
static phys_addr_t map_single_copy(struct device *hwdev, phys_addr_t phys, size_t size,
	   enum dma_data_direction dir, unsigned long attrs);

static inline bool sme_active(void) { return false; }

void arch_setup_dma_ops(struct device *dev, u64 dma_base,
		u64 size, const struct iommu_ops *iommu, bool coherent)
{

}

dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	long nid = (paddr >> 44) & 0xf;

	return ((nid << 44) ^ paddr) | (nid << node_id_offset);
}

phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	long nid = (daddr >> node_id_offset) & 0xf;

	return ((nid << node_id_offset) ^ daddr) | (nid << 44);
}

static inline void *dma_to_virt(struct device *dev, dma_addr_t dma_addr)
{
	return phys_to_virt(dma_to_phys(dev, dma_addr));
}

void swiotlb_free(struct device *dev, size_t size, void *vaddr,
		dma_addr_t dma_addr, unsigned long attrs)
{
	dma_direct_free(dev, size, vaddr, dma_addr, attrs);
}

static void *loongson_dma_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	void *ret = dma_direct_alloc(dev, size, dma_handle, gfp, attrs);
	return ret;
}

static void loongson_dma_free_coherent(struct device *dev, size_t size,
		void *vaddr, dma_addr_t dma_handle, unsigned long attrs)
{
	swiotlb_free(dev, size, vaddr, dma_handle, attrs);
}

static int loongson_dma_mmap(struct device *dev, struct vm_area_struct *vma,
	void *cpu_addr, dma_addr_t dma_addr, size_t size, unsigned long attrs)
{
	int ret = -ENXIO;
	unsigned long user_count = vma_pages(vma);
	unsigned long count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long pfn = page_to_pfn(virt_to_page(cpu_addr));
	unsigned long off = vma->vm_pgoff;

	unsigned long prot = pgprot_val(vma->vm_page_prot);

	prot = (prot & ~_CACHE_MASK) | _CACHE_CC;
	vma->vm_page_prot = __pgprot(prot);

	if (dma_mmap_from_dev_coherent(dev, vma, cpu_addr, size, &ret))
		return ret;

	if (off < count && user_count <= (count - off)) {
		ret = remap_pfn_range(vma, vma->vm_start, pfn + off,
				      user_count << PAGE_SHIFT, vma->vm_page_prot);
	}

	return ret;
}

static void swiotlb_bounce_loongson(phys_addr_t orig_addr, phys_addr_t tlb_addr,
			   size_t size, enum dma_data_direction dir)
{
	unsigned long pfn = PFN_DOWN(orig_addr);
	unsigned char *vaddr = phys_to_virt(tlb_addr);

	if (PageHighMem(pfn_to_page(pfn))) {
		/* The buffer does not have a mapping.  Map it in and copy */
		unsigned int offset = orig_addr & ~PAGE_MASK;
		char *buffer;
		unsigned int sz = 0;
		unsigned long flags;

		while (size) {
			sz = min_t(size_t, PAGE_SIZE - offset, size);

			local_irq_save(flags);
			buffer = kmap_atomic(pfn_to_page(pfn));
			if (dir == DMA_TO_DEVICE)
				memcpy(vaddr, buffer + offset, sz);
			else
				memcpy(buffer + offset, vaddr, sz);
			kunmap_atomic(buffer);
			local_irq_restore(flags);

			size -= sz;
			pfn++;
			vaddr += sz;
			offset = 0;
		}
	} else if (dir == DMA_TO_DEVICE) {
		memcpy(vaddr, phys_to_virt(orig_addr), size);
	} else {
		memcpy(phys_to_virt(orig_addr), vaddr, size);
	}
}

void swiotlb_tbl_unmap_single_loongson(struct device *hwdev, phys_addr_t tlb_addr,
			      size_t size, enum dma_data_direction dir,
			      unsigned long attrs)
{
	unsigned long flags;
	int i, count, nslots = ALIGN(size, 1 << IO_TLB_SHIFT_BACKUPS) >> IO_TLB_SHIFT_BACKUPS;
	int index = (tlb_addr - io_tlb_backups_start) >> IO_TLB_SHIFT_BACKUPS;
	phys_addr_t orig_addr = io_tlb_orig_backups_addr[index];

	/*
	 * First, sync the memory before unmapping the entry
	 */
	if (orig_addr != INVALID_PHYS_ADDR &&
	    !(attrs & DMA_ATTR_SKIP_CPU_SYNC) &&
	    ((dir == DMA_FROM_DEVICE) || (dir == DMA_BIDIRECTIONAL)))
		swiotlb_bounce_loongson(orig_addr, tlb_addr, size, DMA_FROM_DEVICE);

	/*
	 * Return the buffer to the free list by setting the corresponding
	 * entries to indicate the number of contiguous entries available.
	 * While returning the entries to the free list, we merge the entries
	 * with slots below and above the pool being returned.
	 */
	spin_lock_irqsave(&io_tlb_lock_high, flags);
	{
		count = ((index + nslots) < ALIGN(index + 1, IO_TLB_SEGSIZE) ?
			 io_tlb_backups_list[index + nslots] : 0);
		/*
		 * Step 1: return the slots to the free list, merging the
		 * slots with superceeding slots
		 */
		for (i = index + nslots - 1; i >= index; i--) {
			io_tlb_backups_list[i] = ++count;
			io_tlb_orig_backups_addr[i] = INVALID_PHYS_ADDR;
		}
		/*
		 * Step 2: merge the returned slots with the preceding slots,
		 * if available (non zero)
		 */
		for (i = index - 1; (OFFSET(i, IO_TLB_SEGSIZE) != IO_TLB_SEGSIZE - 1)
					&& io_tlb_backups_list[i]; i--)
			io_tlb_backups_list[i] = ++count;
	}
	spin_unlock_irqrestore(&io_tlb_lock_high, flags);
}

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * physical address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory until
 * either swiotlb_unmap_page or swiotlb_dma_sync_single is performed.
 */
dma_addr_t swiotlb_map_page_loongson(struct device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction dir,
			    unsigned long attrs)
{
	phys_addr_t map, phys = page_to_phys(page) + offset;
	dma_addr_t dev_addr = phys_to_dma(dev, phys);

	WARN_ON(dir == DMA_NONE);

	/* Oh well, have to allocate and map a bounce buffer. */
	map = map_single_loongson(dev, phys, size, dir, attrs);
	if (map == SWIOTLB_MAP_ERROR)
		return DMA_MAPPING_ERROR;

	dev_addr = phys_to_dma(dev, map);

	/* Ensure that the address returned is DMA'ble */
	if (dma_capable(dev, dev_addr, size, true))
		return dev_addr;

	attrs |= DMA_ATTR_SKIP_CPU_SYNC;
	swiotlb_tbl_unmap_single_loongson(dev, map, size, dir, attrs);

	return DMA_MAPPING_ERROR;
}

/*
 * Allocates bounce buffer and returns its physical address.
 */
static phys_addr_t
map_single(struct device *hwdev, phys_addr_t phys, size_t size,
	   enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t start_dma_addr;

	if (swiotlb_force == SWIOTLB_NO_FORCE) {
		dev_warn_ratelimited(hwdev, "Cannot do DMA to address %pa\n",
				     &phys);
		return SWIOTLB_MAP_ERROR;
	}

	start_dma_addr = phys_to_dma(hwdev, io_tlb_start);
	return swiotlb_tbl_map_single(hwdev, start_dma_addr, phys, size,
				      dir, attrs);
}

/*
 * Map a single buffer of the indicated size for DMA in streaming mode.  The
 * physical address to use is returned.
 *
 * Once the device is given the dma address, the device owns this memory until
 * either swiotlb_unmap_page or swiotlb_dma_sync_single is performed.
 */
dma_addr_t swiotlb_map_page(struct device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction dir,
			    unsigned long attrs)
{
	phys_addr_t map, phys = page_to_phys(page) + offset;
	dma_addr_t dev_addr = phys_to_dma(dev, phys);
	int dev_swiotlb_force = attrs & DMA_ATTR_FORCE_SWIOTLB;

	WARN_ON(dir == DMA_NONE);
	/*
	 * If the address happens to be in the device's DMA window,
	 * we can safely return the device addr and not worry about bounce
	 * buffering it.
	 */
	if (dma_capable(dev, dev_addr, size, true) &&
			swiotlb_force != SWIOTLB_FORCE && !dev_swiotlb_force)
		return dev_addr;

	/* Oh well, have to allocate and map a bounce buffer. */
	map = map_single(dev, phys, size, dir, attrs);
	if (map == SWIOTLB_MAP_ERROR)
		return DMA_MAPPING_ERROR;

	dev_addr = phys_to_dma(dev, map);

	/* Ensure that the address returned is DMA'ble */
	if (dma_capable(dev, dev_addr, size, true))
		return dev_addr;

	attrs |= DMA_ATTR_SKIP_CPU_SYNC;
	swiotlb_tbl_unmap_single(dev, map, size, size, dir, attrs);

	return DMA_MAPPING_ERROR;
}

static dma_addr_t loongson_dma_map_page(struct device *dev, struct page *page,
				unsigned long offset, size_t size,
				enum dma_data_direction dir,
				unsigned long attrs)
{
	dma_addr_t daddr;

	phys_addr_t phys = page_to_phys(page) + offset;

	/* check if phys addr is on Node 4,5,6,7 and need swiotlb fix */
	if ((phys & (0x4ULL << 44)) && swiotlb_need_fix)
		daddr = swiotlb_map_page_loongson(dev, page, offset, size, dir, attrs);
	else
		daddr = swiotlb_map_page(dev, page, offset, size, dir, attrs);
	return daddr;
}

int is_swiotlb_backups_buffer(phys_addr_t paddr)
{
	return paddr >= io_tlb_backups_start && paddr < io_tlb_backups_end;
}

static void unmap_single_loongson(struct device *hwdev, dma_addr_t dev_addr,
			 size_t size, enum dma_data_direction dir,
			 unsigned long attrs)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	WARN_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		swiotlb_tbl_unmap_single(hwdev, paddr, size, size, dir, attrs);
		return;
	}

	if (is_swiotlb_backups_buffer(paddr)) {
		swiotlb_tbl_unmap_single_loongson(hwdev, paddr, size, dir, attrs);
		return;
	}
	if (dir != DMA_FROM_DEVICE)
		return;
}

static void unmap_single(struct device *hwdev, dma_addr_t dev_addr,
			 size_t size, enum dma_data_direction dir,
			 unsigned long attrs)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	WARN_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		swiotlb_tbl_unmap_single(hwdev, paddr, size, size, dir, attrs);
		return;
	}

	if (dir != DMA_FROM_DEVICE)
		return;
}

void swiotlb_unmap_page_loongson(struct device *hwdev, dma_addr_t dev_addr,
			size_t size, enum dma_data_direction dir,
			unsigned long attrs)
{
	unmap_single_loongson(hwdev, dev_addr, size, dir, attrs);
}

static void loongson_dma_unmap_page(struct device *dev, dma_addr_t dev_addr,
			size_t size, enum dma_data_direction dir,
			unsigned long attrs)
{
	swiotlb_unmap_page_loongson(dev, dev_addr, size, dir, attrs);
}

static unsigned int io_tlb_backups_index;
phys_addr_t swiotlb_tbl_map_single_loongson(struct device *hwdev,
				   dma_addr_t tbl_dma_addr,
				   phys_addr_t orig_addr, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	unsigned long flags;
	phys_addr_t tlb_addr;
	unsigned int nslots, stride, index, wrap;
	int i;
	unsigned long mask;
	unsigned long offset_slots;
	unsigned long max_slots;

	if (no_iotlb_backups_memory)
		panic("Can not allocate SWIOTLB buffer earlier and can't now provide you with the DMA bounce buffer");

	if (mem_encrypt_active())
		pr_warn_once("%s is active and system is using DMA bounce buffers\n",
			     sme_active() ? "SME" : "SEV");

	mask = dma_get_seg_boundary(hwdev);

	tbl_dma_addr &= mask;

	offset_slots = ALIGN(tbl_dma_addr, 1 << IO_TLB_SHIFT_BACKUPS) >> IO_TLB_SHIFT_BACKUPS;

	/*
	 * Carefully handle integer overflow which can occur when mask == ~0UL.
	 */
	max_slots = mask + 1
		    ? ALIGN(mask + 1, 1 << IO_TLB_SHIFT_BACKUPS) >> IO_TLB_SHIFT_BACKUPS
		    : 1UL << (BITS_PER_LONG - IO_TLB_SHIFT_BACKUPS);

	/*
	 * For mappings greater than or equal to a page, we limit the stride
	 * (and hence alignment) to a page size.
	 */
	nslots = ALIGN(size, 1 << IO_TLB_SHIFT_BACKUPS) >> IO_TLB_SHIFT_BACKUPS;
	if (size >= PAGE_SIZE)
		stride = (1 << (PAGE_SHIFT - IO_TLB_SHIFT_BACKUPS));
	else
		stride = 1;

	WARN_ON(!nslots);

	/*
	 * Find suitable number of IO TLB entries size that will fit this
	 * request and allocate a buffer from that IO TLB pool.
	 */
	spin_lock_irqsave(&io_tlb_lock_high, flags);
	index = ALIGN(io_tlb_backups_index, stride);
	if (index >= io_tlb_nslabs_backups)
		index = 0;
	wrap = index;

	do {
		while (iommu_is_span_boundary(index, nslots, offset_slots,
					      max_slots)) {
			index += stride;
			if (index >= io_tlb_nslabs_backups)
				index = 0;
			if (index == wrap)
				goto not_found;
		}

		/*
		 * If we find a slot that indicates we have 'nslots' number of
		 * contiguous buffers, we allocate the buffers from that slot
		 * and mark the entries as '0' indicating unavailable.
		 */
		if (io_tlb_backups_list[index] >= nslots) {
			int count = 0;

			for (i = index; i < (int) (index + nslots); i++)
				io_tlb_backups_list[i] = 0;
			for (i = index - 1; (OFFSET(i, IO_TLB_SEGSIZE) != IO_TLB_SEGSIZE - 1)
					&& io_tlb_backups_list[i]; i--)
				io_tlb_backups_list[i] = ++count;
			tlb_addr = io_tlb_backups_start + (index << IO_TLB_SHIFT_BACKUPS);

			/*
			 * Update the indices to avoid searching in the next
			 * round.
			 */
			io_tlb_backups_index = ((index + nslots) < io_tlb_nslabs_backups
					? (index + nslots) : 0);

			goto found;
		}
		index += stride;
		if (index >= io_tlb_nslabs_backups)
			index = 0;
	} while (index != wrap);

not_found:
	spin_unlock_irqrestore(&io_tlb_lock_high, flags);
	if (!(attrs & DMA_ATTR_NO_WARN))
		dev_warn(hwdev, "swiotlb buffer is full (sz: %zd bytes)\n", size);
	return SWIOTLB_MAP_ERROR;
found:
	spin_unlock_irqrestore(&io_tlb_lock_high, flags);

	/*
	 * Save away the mapping from the original address to the DMA address.
	 * This is needed when we sync the memory.  Then we sync the buffer if
	 * needed.
	 */
	for (i = 0; i < nslots; i++)
		io_tlb_orig_backups_addr[index+i] = orig_addr + (i << IO_TLB_SHIFT_BACKUPS);
	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC) &&
	    (dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
		swiotlb_bounce_loongson(orig_addr, tlb_addr, size, DMA_TO_DEVICE);

	return tlb_addr;
}

static phys_addr_t map_single_copy(struct device *hwdev, phys_addr_t phys, size_t size,
	   enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t start_dma_addr;

	if (swiotlb_force == SWIOTLB_NO_FORCE) {
		dev_warn_ratelimited(hwdev, "Cannot do DMA to address %pa\n",
				     &phys);
		return SWIOTLB_MAP_ERROR;
	}

	start_dma_addr = phys_to_dma(hwdev, io_tlb_start);
	return swiotlb_tbl_map_single(hwdev, start_dma_addr, phys, size,
				      dir, attrs);
}

/*
 * Allocates bounce buffer and returns its physical address.
 */
static phys_addr_t map_single_loongson(struct device *hwdev, phys_addr_t phys, size_t size,
	   enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t start_dma_addr;

	if (swiotlb_force == SWIOTLB_NO_FORCE) {
		dev_warn_ratelimited(hwdev, "Cannot do DMA to address %pa\n",
				     &phys);
		return SWIOTLB_MAP_ERROR;
	}

	start_dma_addr = phys_to_dma(hwdev, io_tlb_backups_start);
	return swiotlb_tbl_map_single_loongson(hwdev, start_dma_addr, phys, size,
				      dir, attrs);
}

void swiotlb_unmap_sg_attrs(struct device *hwdev, struct scatterlist *sgl,
		       int nelems, enum dma_data_direction dir,
		       unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	WARN_ON(dir == DMA_NONE);

	for_each_sg(sgl, sg, nelems, i)
		unmap_single(hwdev, sg->dma_address, sg_dma_len(sg), dir,
			     attrs);
}

int swiotlb_map_sg_attrs_loongson(struct device *hwdev, struct scatterlist *sgl, int nelems,
		     enum dma_data_direction dir, unsigned long attrs)
{
	struct scatterlist *sg;
	int i, dev_swiotlb_force = attrs & DMA_ATTR_FORCE_SWIOTLB;

	WARN_ON(dir == DMA_NONE);

	for_each_sg(sgl, sg, nelems, i) {
		phys_addr_t paddr = sg_phys(sg);
		dma_addr_t dev_addr = phys_to_dma(hwdev, paddr);

		if (swiotlb_force == SWIOTLB_FORCE || dev_swiotlb_force ||
		    !dma_capable(hwdev, dev_addr, sg->length, true)) {
			phys_addr_t map = map_single_copy(hwdev, sg_phys(sg),
						     sg->length, dir, attrs);
			if (map == SWIOTLB_MAP_ERROR) {
				/*
				 * Don't panic here, we expect map_sg users
				 * to do proper error handling.
				 */
				attrs |= DMA_ATTR_SKIP_CPU_SYNC;
				swiotlb_unmap_sg_attrs(hwdev, sgl, i, dir,
						       attrs);
				sg_dma_len(sgl) = 0;
				return 0;
			}
			sg->dma_address = phys_to_dma(hwdev, map);
		} else if (paddr & (0x4ULL << 44) && swiotlb_need_fix) {
			phys_addr_t map = map_single_loongson(hwdev, sg_phys(sg),
					sg->length, dir, attrs);
			if (map == SWIOTLB_MAP_ERROR) {
				/*
				 * Don't panic here, we expect map_sg users
				 * to do proper error handling.
				 */
				attrs |= DMA_ATTR_SKIP_CPU_SYNC;
				swiotlb_unmap_sg_attrs(hwdev, sgl, i, dir,
						       attrs);
				sg_dma_len(sgl) = 0;
				return 0;
			}
			sg->dma_address = phys_to_dma(hwdev, map);
		} else {
			sg->dma_address = dev_addr;
		}
		sg_dma_len(sg) = sg->length;
	}
	return nelems;
}

static int loongson_dma_map_sg(struct device *dev, struct scatterlist *sgl,
				int nents, enum dma_data_direction dir,
				unsigned long attrs)
{
	int  r;

	r = swiotlb_map_sg_attrs_loongson(dev, sgl, nents, dir, attrs);
	return r;
}

void swiotlb_unmap_sg_attrs_loongson(struct device *hwdev, struct scatterlist *sgl,
		       int nelems, enum dma_data_direction dir,
		       unsigned long attrs)
{
	struct scatterlist *sg;
	int i;

	WARN_ON(dir == DMA_NONE);

	for_each_sg(sgl, sg, nelems, i)
		unmap_single_loongson(hwdev, sg->dma_address, sg_dma_len(sg), dir,
			     attrs);
}

static void loongson_dma_unmap_sg(struct device *dev, struct scatterlist *sgl,
			int nelems, enum dma_data_direction dir,
			unsigned long attrs)
{
	swiotlb_unmap_sg_attrs_loongson(dev, sgl, nelems, dir, attrs);
}

void swiotlb_tbl_sync_single_loongson(struct device *hwdev, phys_addr_t tlb_addr,
			     size_t size, enum dma_data_direction dir,
			     enum dma_sync_target target)
{
	int index = (tlb_addr - io_tlb_backups_start) >> IO_TLB_SHIFT_BACKUPS;
	phys_addr_t orig_addr = io_tlb_orig_backups_addr[index];

	if (orig_addr == INVALID_PHYS_ADDR)
		return;
	orig_addr += (unsigned long)tlb_addr & ((1 << IO_TLB_SHIFT_BACKUPS) - 1);

	switch (target) {
	case SYNC_FOR_CPU:
		if (likely(dir == DMA_FROM_DEVICE || dir == DMA_BIDIRECTIONAL))
			swiotlb_bounce_loongson(orig_addr, tlb_addr,
				       size, DMA_FROM_DEVICE);
		else
			WARN_ON(dir != DMA_TO_DEVICE);
		break;
	case SYNC_FOR_DEVICE:
		if (likely(dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL))
			swiotlb_bounce_loongson(orig_addr, tlb_addr,
				       size, DMA_TO_DEVICE);
		else
			WARN_ON(dir != DMA_FROM_DEVICE);
		break;
	default:
		WARN(1, "bug");
	}
}

static void swiotlb_sync_single_loongson(struct device *hwdev, dma_addr_t dev_addr,
		    size_t size, enum dma_data_direction dir,
		    enum dma_sync_target target)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	WARN_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		swiotlb_tbl_sync_single(hwdev, paddr, size, dir, target);
		return;
	}

	if (is_swiotlb_backups_buffer(paddr)) {
		swiotlb_tbl_sync_single_loongson(hwdev, paddr, size, dir, target);
		return;
	}
	if (dir != DMA_FROM_DEVICE)
		return;
}

static void swiotlb_sync_single(struct device *hwdev, dma_addr_t dev_addr,
		    size_t size, enum dma_data_direction dir,
		    enum dma_sync_target target)
{
	phys_addr_t paddr = dma_to_phys(hwdev, dev_addr);

	WARN_ON(dir == DMA_NONE);

	if (is_swiotlb_buffer(paddr)) {
		swiotlb_tbl_sync_single(hwdev, paddr, size, dir, target);
		return;
	}

	if (dir != DMA_FROM_DEVICE)
		return;
}

void swiotlb_sync_single_for_cpu_loongson(struct device *hwdev, dma_addr_t dev_addr,
			    size_t size, enum dma_data_direction dir)
{
	swiotlb_sync_single_loongson(hwdev, dev_addr, size, dir, SYNC_FOR_CPU);
}

void swiotlb_sync_single_for_cpu(struct device *hwdev, dma_addr_t dev_addr,
			    size_t size, enum dma_data_direction dir)
{
	swiotlb_sync_single(hwdev, dev_addr, size, dir, SYNC_FOR_CPU);
}

static void loongson_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dev_addr,
			size_t size, enum dma_data_direction dir)
{
	/* use dma address directly since dma addr == phy addr for swiotlb */
	if (is_swiotlb_buffer(dev_addr))
		swiotlb_sync_single_for_cpu(dev, dev_addr, size, dir);
	if (is_swiotlb_backups_buffer(dev_addr))
		swiotlb_sync_single_for_cpu_loongson(dev, dev_addr, size, dir);
}

void swiotlb_sync_single_for_device_loongson(struct device *hwdev, dma_addr_t dev_addr,
			       size_t size, enum dma_data_direction dir)
{
	swiotlb_sync_single_loongson(hwdev, dev_addr, size, dir, SYNC_FOR_DEVICE);
}

static void loongson_dma_sync_single_for_device(struct device *dev,
				dma_addr_t dma_handle, size_t size,
				enum dma_data_direction dir)
{
	swiotlb_sync_single_for_device_loongson(dev, dma_handle, size, dir);
	/*
	 * There maybe exist write-buffer, device can not get cpu's write buffer
	 * need flush data from write-buffer to cache
	 */
	mb();
}
static void swiotlb_sync_sg_loongson(struct device *hwdev, struct scatterlist *sgl,
		int nelems, enum dma_data_direction dir,
		enum dma_sync_target target)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nelems, i)
		swiotlb_sync_single_loongson(hwdev, sg->dma_address,
				    sg_dma_len(sg), dir, target);
}

void swiotlb_sync_sg_for_cpu_loongson(struct device *hwdev, struct scatterlist *sg,
			int nelems, enum dma_data_direction dir)
{
	swiotlb_sync_sg_loongson(hwdev, sg, nelems, dir, SYNC_FOR_CPU);
}

static void loongson_dma_sync_sg_for_cpu(struct device *dev,
				struct scatterlist *sgl, int nents,
				enum dma_data_direction dir)
{
	swiotlb_sync_sg_for_cpu_loongson(dev, sgl, nents, dir);
}

void swiotlb_sync_sg_for_device_loongson(struct device *hwdev, struct scatterlist *sg,
			   int nelems, enum dma_data_direction dir)
{
	swiotlb_sync_sg_loongson(hwdev, sg, nelems, dir, SYNC_FOR_DEVICE);
}

static void loongson_dma_sync_sg_for_device(struct device *dev,
				struct scatterlist *sgl, int nents,
				enum dma_data_direction dir)
{
	swiotlb_sync_sg_for_device_loongson(dev, sgl, nents, dir);
	/*
	 * There maybe exist write-buffer, device can not get cpu's write buffer
	 * need flush data from write-buffer to cache
	 */
	mb();
}

static int loongson_dma_supported(struct device *dev, u64 mask)
{
	return dma_direct_supported(dev, mask);
}

const struct dma_map_ops loongson_dma_ops = {
	.alloc = loongson_dma_alloc_coherent,
	.free = loongson_dma_free_coherent,
	.mmap = loongson_dma_mmap,
	.map_page = loongson_dma_map_page,
	.unmap_page = loongson_dma_unmap_page,
	.map_sg = loongson_dma_map_sg,
	.unmap_sg = loongson_dma_unmap_sg,
	.sync_single_for_cpu = loongson_dma_sync_single_for_cpu,
	.sync_single_for_device = loongson_dma_sync_single_for_device,
	.sync_sg_for_cpu = loongson_dma_sync_sg_for_cpu,
	.sync_sg_for_device = loongson_dma_sync_sg_for_device,
	.dma_supported = loongson_dma_supported,
	.cache_sync = arch_dma_cache_sync,
};
EXPORT_SYMBOL(loongson_dma_ops);

static inline void * __init memblock_alloc_high(
					phys_addr_t size, phys_addr_t align)
{
	return memblock_alloc_try_nid(size, align, ARCH_LOW_ADDRESS_LIMIT,
						   BOOTMEM_ALLOC_ANYWHERE,
						   NUMA_NO_NODE);
}

void swiotlb_print_info_loongson(void)
{
	unsigned long bytes = io_tlb_nslabs_backups << IO_TLB_SHIFT_BACKUPS;

	if (no_iotlb_backups_memory) {
		pr_warn("No low mem\n");
		return;
	}

	pr_info("mapped [mem %#010llx-%#010llx] (%luMB)\n",
	       (unsigned long long)io_tlb_backups_start,
	       (unsigned long long)io_tlb_backups_end,
	       bytes >> 20);
}

void swiotlb_set_max_segment_loongson(unsigned int val)
{
	if (swiotlb_force == SWIOTLB_FORCE)
		max_segment_backups = 1;
	else
		max_segment_backups = rounddown(val, PAGE_SIZE);
}

int __init swiotlb_init_with_tbl_backups(char *tlb, unsigned long nslabs, int verbose)
{
	size_t alloc_size;
	unsigned long i, bytes;

	bytes = nslabs << IO_TLB_SHIFT_BACKUPS;

	io_tlb_nslabs_backups = nslabs;
	io_tlb_backups_start = __pa(tlb);
	io_tlb_backups_end = io_tlb_backups_start + bytes;

	/*
	 * Allocate and initialize the free list array.  This array is used
	 * to find contiguous free memory regions of size up to IO_TLB_SEGSIZE
	 * between io_tlb_backups_start and io_tlb_backups_end.
	 */
	alloc_size = PAGE_ALIGN(io_tlb_nslabs_backups * sizeof(int));
	io_tlb_backups_list = memblock_alloc(alloc_size, PAGE_SIZE);
	if (!io_tlb_backups_list)
		panic("%s: Failed to allocate %zu bytes align=0x%lx\n",
		      __func__, alloc_size, PAGE_SIZE);

	alloc_size = PAGE_ALIGN(io_tlb_nslabs_backups * sizeof(phys_addr_t));
	io_tlb_orig_backups_addr = memblock_alloc(alloc_size, PAGE_SIZE);
	if (!io_tlb_orig_backups_addr)
		panic("%s: Failed to allocate %zu bytes align=0x%lx\n",
		      __func__, alloc_size, PAGE_SIZE);

	for (i = 0; i < io_tlb_nslabs_backups; i++) {
		io_tlb_backups_list[i] = IO_TLB_SEGSIZE - OFFSET(i, IO_TLB_SEGSIZE);
		io_tlb_orig_backups_addr[i] = INVALID_PHYS_ADDR;
	}
	io_tlb_backups_index = 0;

	no_iotlb_backups_memory = false;

	if (verbose)
		swiotlb_print_info_loongson();

	swiotlb_set_max_segment_loongson(io_tlb_nslabs_backups << IO_TLB_SHIFT_BACKUPS);
	return 0;
}

void  __init swiotlb_init_backups(int verbose)
{
	size_t default_size = IO_TLB_DEFAULT_SIZE_BACKUPS;
	unsigned char *vstart;
	unsigned long bytes;

	if ((!strcmp(__cpu_full_name[0], "Loongson-3D5000")) && loongson_sysconf.nr_nodes > 4)
		swiotlb_need_fix = 1;

	if (!io_tlb_nslabs_backups) {
		io_tlb_nslabs_backups = (default_size >> IO_TLB_SHIFT_BACKUPS);
		io_tlb_nslabs_backups = ALIGN(io_tlb_nslabs_backups, IO_TLB_SEGSIZE);
	}

	bytes = io_tlb_nslabs_backups << IO_TLB_SHIFT_BACKUPS;

	/* Get IO TLB memory from the high pages */
	vstart = memblock_alloc_high(PAGE_ALIGN(bytes), PAGE_SIZE);
	if (vstart && !swiotlb_init_with_tbl_backups(vstart, io_tlb_nslabs_backups, verbose))
		return;

	if (io_tlb_backups_start) {
		memblock_free_early(io_tlb_backups_start,
				    PAGE_ALIGN(io_tlb_nslabs_backups << IO_TLB_SHIFT_BACKUPS));
		io_tlb_backups_start = 0;
	}
	pr_warn("Cannot allocate buffer");
	no_iotlb_backups_memory = true;
}

void __init plat_swiotlb_setup(void)
{
	swiotlb_init(true);
	swiotlb_init_backups(1);

	node_id_offset = ((readl(LS7A_DMA_CFG) & LS7A_DMA_NODE_MASK) >> LS7A_DMA_NODE_SHF) + 36;
}
