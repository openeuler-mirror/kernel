// SPDX-License-Identifier: GPL-2.0
/* iommu.c: Generic sw_64 IOMMU support for 3231
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
#include <linux/delay.h>
#include <linux/syscore_ops.h>
#include <linux/swiotlb.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <asm/dma.h>
#include <asm/io.h>
#include <asm/swio.h>
#include <asm/pci.h>

#include "proto.h"
#include "pci_impl.h"
#include "sw_pci_impl.h"

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

unsigned long iommu_cmd;

static void sw_iommu_create_new(struct pci_controller *hose, unsigned int error_bus_number,
				unsigned int error_devfn, unsigned int error_da)
{
	unsigned long dtbr;
	u64 *paddr;
	u32 ofs;
	unsigned long dtbbaseaddr, dtbbasecond;

	sw_read_piu_ior0(hose->node, hose->index, DTBASEADDR, &dtbr);
	dtbr += PAGE_OFFSET;
	ofs = error_da >> PAGE_SHIFT;

	dtbbaseaddr = dtbr + (error_bus_number << 3);
	dtbbasecond = (*(u64 *)(dtbbaseaddr)) & (~(SW_IOMMU_ENTRY_VALID)) & PAGE_MASK;
	dtbbasecond += (error_devfn << 3) + PAGE_OFFSET;

	paddr = (u64 *)get_zeroed_page(GFP_DMA);
	sw_iommu_map(__pa(paddr), ofs, dtbbasecond, hose, NULL);
}

irqreturn_t iommu_interrupt(int irq, void *dev)
{
	struct pci_controller *hose = (struct pci_controller *)dev;
	unsigned long iommu_status;
	unsigned int type, bus_number;
	unsigned int devfn, error_da;

	sw_read_piu_ior0(hose->node, hose->index, IOMMUEXCPT_STATUS, &iommu_status);
	if (!(iommu_status >> 63))
		return IRQ_NONE;

	type = (iommu_status >> 59) & 0x7;
	bus_number = (iommu_status >> 45) & 0xff;
	devfn = (iommu_status >> 37) & 0xff;
	error_da = iommu_status & 0xffffffff;

	if (type == 0x3) {
		iommu_status &= ~(1UL << 62);
		iommu_status = iommu_status | (1UL << 63);
		sw_write_piu_ior0(hose->node, hose->index, IOMMUEXCPT_STATUS, iommu_status);
		return IRQ_HANDLED;
	}

	if (type == 0x2)
		sw_iommu_create_new(hose, bus_number, devfn, error_da);

	udelay(100);
	sw_write_piu_ior0(hose->node, hose->index, PTLB_FLUSHALL, 0);
	sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHALL, 0);

	iommu_status = iommu_status | (3UL << 62);
	sw_write_piu_ior0(hose->node, hose->index, IOMMUEXCPT_STATUS, iommu_status);

	return IRQ_HANDLED;
}

struct irqaction iommu_irqaction = {
	.handler        = iommu_interrupt,
	.flags          = IRQF_SHARED | IRQF_NO_THREAD,
	.name           = "sw_iommu",
};

void sw_enable_iommu_func(struct pci_controller *hose)
{
	struct irqaction *action;
	unsigned int  iommu_irq;
	unsigned long iommu_conf, iommu_ctrl;

	iommu_irq = hose->int_irq;
	action = &iommu_irqaction;
	action->dev_id = hose;
	request_irq(iommu_irq, action.iommu_interrupt, action.flags, "sw_iommu", action->dev_id);
	iommu_ctrl = (1UL << 63) | (0x100UL << 10);
	sw_write_piu_ior0(hose->node, hose->index, IOMMUEXCPT_CTRL, iommu_ctrl);
	sw_read_piu_ior0(hose->node, hose->index, PIUCONFIG0, &iommu_conf);
	iommu_conf = iommu_conf | (0x3 << 7);
	sw_write_piu_ior0(hose->node, hose->index, PIUCONFIG0, iommu_conf);
	sw_write_piu_ior0(hose->node, hose->index, TIMEOUT_CONFIG, 0xf);
	sw_read_piu_ior0(hose->node, hose->index, PIUCONFIG0, &iommu_conf);
	pr_info("SW arch configure node %ld hose-%ld iommu_conf = %#lx\n",
			hose->node, hose->index, iommu_conf);
}

struct sw_iommu_dev *pci_to_iommu(struct pci_dev *pdev)
{
	struct sw_iommu *iommu;
	struct pci_controller *hose = (struct pci_controller *)pdev->sysdata;
	struct sw_iommu_dev *sw_dev;
	int busnumber, devid;

	iommu = hose->pci_iommu;

	list_for_each_entry(sw_dev, &iommu->dev_list, list) {
		busnumber = sw_dev->dev_id >> 8;
		devid = sw_dev->dev_id & 0xff;
		if ((busnumber == pdev->bus->number) && (devid == pdev->devfn))
			return sw_dev;
	}

	return NULL;
}

struct sw_iommu_dev *create_sw_iommu_dev(struct pci_dev *dev, unsigned long *pte, struct sw_iommu *iommu)
{
	struct sw_iommu_dev *sw_dev = kzalloc(sizeof(struct sw_iommu_dev), GFP_KERNEL);

	sw_dev->dev_id = (dev->bus->number << 8) + dev->devfn;
	sw_dev->io_page_base = pte;
	sw_dev->iommu = iommu;

	list_add_tail(&sw_dev->list, &iommu->dev_list);
	return sw_dev;
}

void __sw_pci_iommu_dte_alloc(struct pci_bus *bus, struct sw_iommu *iommu)
{
	struct pci_dev *dev;
	struct sw_iommu_dev *iommu_dev;
	unsigned long *pte;
	u64 *dte;
	u64 dtebaseaddr;
	u64 dtentry;
	u64 dtebaseaddr2, ptentry;

	dtebaseaddr = (unsigned long)iommu->iommu_dtbr + (bus->number << 3);
	dte = (u64 *)get_zeroed_page(GFP_KERNEL);
	dtentry = (__pa(dte) & PAGE_MASK) | (1UL << 63);
	*(u64 *)dtebaseaddr = dtentry;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		if (dev->hdr_type == PCI_HEADER_TYPE_NORMAL) {
			pte = (unsigned long *)get_zeroed_page(GFP_KERNEL);
			dtebaseaddr2 = ((unsigned long)dte & PAGE_MASK) + ((dev->devfn) << 3);
			iommu_dev = create_sw_iommu_dev(dev, pte, iommu);
			ptentry = (__pa(pte) & PAGE_MASK) | (1UL << 63);
			iommu_dev->iommu_bypass = 0;
			*(u64 *)dtebaseaddr2 = ptentry;
			/* legacy VGA frame buffer has occupied 0xA0000-0xBFFFF memory segment */
			iommu_dev->iommu_area = sw_iommu_area_new(iommu_dev, 0x100000UL);
		} else if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE) {
			struct pci_bus *b = dev->subordinate;

			if (b)
				__sw_pci_iommu_dte_alloc(b, iommu);
		}
	}
}

static int iommu_cpu_suspend(void)
{
	return 0;
}

static void iommu_cpu_resume(void)
{
}

struct syscore_ops iommu_cpu_syscore_ops = {
	.suspend	= iommu_cpu_suspend,
	.resume         = iommu_cpu_resume,
};

int sw_iommu_init(struct pci_controller *hose)
{
	struct sw_iommu *iommu;
	unsigned long base;
	unsigned long rc_mask = 0x1;

	rc_mask <<= (8 * hose->node + hose->index);
	if (!(iommu_cmd & rc_mask))
		return 0;
	sw_write_piu_ior0(hose->node, hose->index, DTLB_FLUSHALL, 0);
	sw_write_piu_ior0(hose->node, hose->index, PTLB_FLUSHALL, 0);
	sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHALL, 0);
	hose->pci_iommu = kzalloc(sizeof(struct sw_iommu), GFP_KERNEL);
	if (!hose->pci_iommu) {
		printk("Can't alloc memory for pci_iommu!\n");
		return 0;
	}
	iommu = hose->pci_iommu;
	spin_lock_init(&iommu->dt_lock);
	iommu->index = hose->index;
	iommu->enabled = true;
	iommu->iommu_dtbr = (unsigned long *)get_zeroed_page(GFP_KERNEL);
	base = __pa(iommu->iommu_dtbr) & PAGE_MASK;
	sw_write_piu_ior0(hose->node, hose->index, DTBASEADDR, base);
	INIT_LIST_HEAD(&iommu->dev_list);
	__sw_pci_iommu_dte_alloc(hose->bus, iommu);
	sw_write_piu_ior0(hose->node, hose->index, DTLB_FLUSHALL, 0);
	sw_write_piu_ior0(hose->node, hose->index, PTLB_FLUSHALL, 0);
	sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHALL, 0);
	sw_enable_iommu_func(hose);
	hose->iommu_enable = true;

	return 0;
}

struct sw_pci_dev_iommu_area *sw_iommu_area_new(struct sw_iommu_dev *iommu_dev, dma_addr_t base)
{
	struct sw_pci_dev_iommu_area *iommu_area = kzalloc(sizeof(struct sw_pci_dev_iommu_area), GFP_KERNEL);

	if (!iommu_area) {
		pr_err("SW arch could not allocate pci iommu dma_area.\n");
		return NULL;
	}

	spin_lock_init(&iommu_area->lock);
	iommu_area->iommu = iommu_dev->iommu;
	iommu_area->dma_base = base;
	iommu_area->bitmap = (void *)__get_free_pages(GFP_KERNEL, 3);
	if (!iommu_area->bitmap) {
		free_pages((unsigned long)iommu_area->bitmap, 3);
		pr_err("SW arch could not allocate dma_area->bitmap.\n");
		return NULL;
	}
	memset(iommu_area->bitmap, 0, 8*PAGE_SIZE);
	iommu_area->next_address = 0;
	return iommu_area;
}

/**
 * sw_iommu_map -
 * @paddr: buffer of the indicated size for PCI DMA
 * @dma_ofs: virtual DMA buffer page frame number allocated from pdev private DMA zone
 * @dtbaddr: Device Table Base Addr for Level 2
 * @index: PCIe host index
 */
int sw_iommu_map(unsigned long paddr, long dma_ofs, unsigned long dtbaddr,
		 struct pci_controller *hose, struct pci_dev *pdev)
{
	unsigned long pde, pte;             /*pde means Page Table Base Addr for Level 2 pte means Page Table Entry*/
	unsigned long pdebaseaddr;
	u64 *ptebasesecond, ptebaseaddr;    /*ptebasesecond means Page Table Pointer for Level 2*/
	unsigned long pcache_flush_addr;

	pdebaseaddr = ((dma_ofs >> 10) & SW_IOMMU_LEVEL1_OFFSET) << 3; /* Offset of Page Table Entry for Level 1 */
	pdebaseaddr += ((*(volatile u64 *)dtbaddr) & (~(SW_IOMMU_ENTRY_VALID)) & (PAGE_MASK)) + PAGE_OFFSET;
	pte = (paddr & PAGE_MASK) | SW_IOMMU_ENTRY_VALID | SW_IOMMU_GRN | SW_IOMMU_ENABLE;

	/* If pde exists, no need to allocate a new page */
	if ((*(volatile u64 *)pdebaseaddr) & SW_IOMMU_ENTRY_VALID) {
		ptebaseaddr = ((*(volatile u64 *)pdebaseaddr) & (~(SW_IOMMU_ENTRY_VALID)) & (PAGE_MASK)) + PAGE_OFFSET;
		ptebaseaddr += (dma_ofs & SW_IOMMU_LEVEL2_OFFSET) << 3;

		pcache_flush_addr = __pa(ptebaseaddr) & 0xffffffff80;

		*(volatile u64 *)ptebaseaddr = pte;
		mb();
		sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHPADDR, pcache_flush_addr);
	} else {
		ptebasesecond = (u64 *)get_zeroed_page(GFP_ATOMIC);

		if (!ptebasesecond) {
			printk("allocating pages fails.\n");
			free_page((unsigned long)ptebasesecond);
			return -1;
		}
		pde = (__pa(ptebasesecond) & PAGE_MASK) | SW_IOMMU_ENTRY_VALID;

		pcache_flush_addr = __pa(pdebaseaddr) & 0xffffffff80;

		*(volatile u64 *)pdebaseaddr = pde;
		mb();
		sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHPADDR, pcache_flush_addr);

		ptebaseaddr = (unsigned long)ptebasesecond + ((dma_ofs & SW_IOMMU_LEVEL2_OFFSET) << 3);

		pcache_flush_addr = __pa(ptebaseaddr) & 0xffffffff80;

		*(volatile u64 *)ptebaseaddr = pte;
		mb();
		sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHPADDR, pcache_flush_addr);
	}

	return 0;
}

static unsigned long
sw_iommu_area_alloc(struct sw_pci_dev_iommu_area *area, unsigned int pages,
		unsigned long start)
{
	unsigned long next_bit = start >> PAGE_SHIFT;
	unsigned long address = -1;
	unsigned long boundary_size = ((4UL << 30)) >> PAGE_SHIFT;
	unsigned long limit = boundary_size - (1UL << 17) - (area->dma_base >> PAGE_SHIFT);

	address = iommu_area_alloc(area->bitmap, limit, next_bit, pages, 0, boundary_size, 0);
	if (address != -1) {
		address = address << PAGE_SHIFT;
		area->next_address = address + (pages << PAGE_SHIFT);
	}

	return address;
}

static long
sw_iommu_alloc_da(struct sw_pci_dev_iommu_area *area, long n)
{
	unsigned long address;

	address = sw_iommu_area_alloc(area, n, area->next_address);
	if (address == -1) {
		area->next_address = 0;
		address = sw_iommu_area_alloc(area, n, area->next_address);
		if (address == -1)
			pr_err("SW arch failed to allocate device address.\n");
	}

	return address;
}

static void sw_iommu_free_da(unsigned long *map, long dma_ofs, long n)
{
	bitmap_clear(map, dma_ofs, n);
}

static void sw_iommu_unmap(struct pci_dev *pdev, long ofs)
{
	unsigned long dtbbaseaddr, dtbbasecond;  /* dtbbaseaddr means Device Table Base Addr for Level 1 */
						 /* dtbbasecond means Device Table Base Addr for Level 2 */
	unsigned long pde, pte;                  /* pde means Page Table Base Addr for Level 2 */
						 /* pte means Page Table Entry */
	unsigned long tlb_flush_addr, pcache_flush_addr;
	unsigned long addr;
	unsigned long pdebaseaddr;      /* ptebasefirst means Page Table Pointer for Level 1  */
	unsigned long ptebaseaddr;      /* ptebasesecond means Page Table Pointer for Level 2 */
	unsigned long ptebaseaddr_full; /* ptebasesecond means Page Table Pointer for Level 2 */
	unsigned long ptebaseaddr_offset;
	struct pci_controller *hose = (struct pci_controller *)pdev->sysdata;
	int i;
	u64 per_pte;
	struct sw_iommu *sw_pci_iommu = hose->pci_iommu;

	addr = (unsigned long)sw_pci_iommu->iommu_dtbr;
	dtbbaseaddr = addr + (pdev->bus->number << 3);

	dtbbasecond = (*(volatile u64 *)dtbbaseaddr) & (~(SW_IOMMU_ENTRY_VALID)) & PAGE_MASK;
	dtbbasecond += (pdev->devfn << 3) + PAGE_OFFSET;

	pdebaseaddr = ((*(volatile u64 *)dtbbasecond) & (~(SW_IOMMU_ENTRY_VALID)) & (PAGE_MASK)) + PAGE_OFFSET;
	pdebaseaddr += ((ofs >> 10) & SW_IOMMU_LEVEL1_OFFSET) << 3;

	pde = *(volatile u64 *)(pdebaseaddr);
	ptebaseaddr = (pde & (~(SW_IOMMU_ENTRY_VALID)) & PAGE_MASK) + PAGE_OFFSET;
	ptebaseaddr_offset = ptebaseaddr + ((ofs & SW_IOMMU_LEVEL2_OFFSET) << 3);

	tlb_flush_addr = (pdev->bus->number << 8) | pdev->devfn | (ofs << 16);
	sw_write_piu_ior0(hose->node, hose->index, PTLB_FLUSHVADDR, tlb_flush_addr);    /* TLB FLUSH*/

	pte = *(volatile u64 *)(ptebaseaddr_offset);
	pte &= ~(SW_IOMMU_ENTRY_VALID);      /*disable Page Table Entry*/
	pcache_flush_addr = __pa(ptebaseaddr_offset) & 0xffffffff80;

	*(volatile u64 *)(ptebaseaddr_offset) = pte;
	mb();
	sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHPADDR, pcache_flush_addr);

	ptebaseaddr_full = ptebaseaddr + 0x1ff8;
	if (ptebaseaddr_offset == ptebaseaddr_full) {
		for (i = 0; i < 1024; i++) {
			per_pte = *(volatile u64 *)(ptebaseaddr + i * 8);
			if (per_pte & SW_IOMMU_ENTRY_VALID)
				break;
		}
		if (i == 1024) {
			free_page(ptebaseaddr);
			pde &= ~(SW_IOMMU_ENTRY_VALID);

			pcache_flush_addr = __pa(pdebaseaddr) & 0xffffffff80;

			*(volatile u64 *)(pdebaseaddr) = pde;
			mb();
			sw_write_piu_ior0(hose->node, hose->index, PCACHE_FLUSHPADDR, pcache_flush_addr);
		}
	}
}

static dma_addr_t __sw_map_single(struct pci_dev *pdev, unsigned long paddr,
		struct sw_pci_dev_iommu_area *iommu_area, size_t size)
{
	long npages, dma_ofs, i, ofs;
	unsigned long dtbbaseaddr;     /* dtbbaseaddr means Device Table Base Addr for Level 1 */
	unsigned long dtbbasecond;     /* dtbbasecond means Device Table Base Addr for Level 2 */
	unsigned long addr;
	dma_addr_t ret = -1;
	struct pci_controller *hose = pdev->sysdata;
	struct sw_iommu *sw_pci_iommu = hose->pci_iommu;
	unsigned long flags;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	addr = (unsigned long)sw_pci_iommu->iommu_dtbr;
	dtbbaseaddr = addr + (pdev->bus->number << 3);

	dtbbasecond = (*(volatile u64 *)dtbbaseaddr) & ~(SW_IOMMU_ENTRY_VALID) & PAGE_MASK;
	dtbbasecond += (pdev->devfn << 3) + PAGE_OFFSET;
	npages = iommu_num_pages(paddr, size, PAGE_SIZE);

	if (hose->iommu_enable) {
		spin_lock_irqsave(&iommu_area->lock, flags);

		dma_ofs = sw_iommu_alloc_da(iommu_area, npages);
		if (dma_ofs == -1) {
			pr_warn("%s %s failed: could not allocate dma page tables\n",
					pci_name(pdev), __func__);
			spin_unlock_irqrestore(&iommu_area->lock, flags);
			return 0;
		}

		ret = iommu_area->dma_base + dma_ofs;

		for (i = 0; i < npages; ++i, paddr += PAGE_SIZE) {
			ofs = (ret >> PAGE_SHIFT) + i;
			sw_iommu_map(paddr, ofs, dtbbasecond, hose, pdev);
		}

		spin_unlock_irqrestore(&iommu_area->lock, flags);

		ret += paddr & ~PAGE_MASK;
	}

	return ret;
}

/*
 * Map a single buffer of the indicated size for PCI DMA in streaming
 * mode.  The 32-bit PCI bus mastering address to use is returned.
 * Once the device is given the dma address, the device owns this memory
 * until either pci_unmap_single or pci_dma_sync_single is performed.
 */

static dma_addr_t
pci_iommu_map_single(struct pci_dev *pdev, void *cpu_addr, size_t size)
{
	struct pci_controller *hose = pdev->sysdata;
	unsigned long paddr;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	if (!hose->iommu_enable) {
		unsigned long dma_offset;

		sw_read_piu_ior0(hose->node, hose->index, EPDMABAR, &dma_offset);
		paddr = __pa(cpu_addr) + dma_offset;
	} else {
		struct sw_pci_dev_iommu_area *iommu_area;
		struct sw_iommu_dev *sw_dev = pci_to_iommu(pdev);

		paddr = __pa(cpu_addr);
		iommu_area = sw_dev->iommu_area;
		if (!iommu_area) {
			pr_err("SW arch get iommu_area error!\n");
			return 0;
		}

		paddr = __sw_map_single(pdev, paddr, iommu_area, size);
	}

	return paddr;
}

static dma_addr_t sw_iommu_map_page(struct device *dev, struct page *page,
				    unsigned long offset, size_t size,
				    enum dma_data_direction dir,
				    unsigned long attrs)
{
	struct pci_dev *pdev = sw_gendev_to_pci(dev);

	if (dir == PCI_DMA_NONE)
		BUG();

	return pci_iommu_map_single(pdev, (char *)page_address(page) + offset, size);
}

/*
 * Unmap a single streaming mode DMA translation.  The DMA_ADDR and
 * SIZE must match what was provided for in a previous pci_map_single
 * call.  All other usages are undefined.  After this call, reads by
 * the cpu to the buffer are guaranteed to see whatever the device
 * wrote there.
 */

static void sw_iommu_unmap_page(struct device *dev, dma_addr_t dma_addr,
		size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw_gendev_to_pci(dev);
	struct pci_controller *hose = pdev->sysdata;
	struct sw_iommu_dev *sw_dev = pci_to_iommu(pdev);
	struct sw_pci_dev_iommu_area *iommu_area;
	long dma_ofs, npages, ofs;
	unsigned long flags;
	int i;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	if (!hose->iommu_enable)
		return;

	iommu_area = sw_dev->iommu_area;
	dma_ofs = (dma_addr - iommu_area->dma_base) >> PAGE_SHIFT;
	npages = iommu_num_pages(dma_addr, size, PAGE_SIZE);

	spin_lock_irqsave(&iommu_area->lock, flags);

	for (i = 0; i < npages; ++i) {
		ofs = (dma_addr >> PAGE_SHIFT) + i;
		sw_iommu_unmap(pdev, ofs);
	}

	sw_iommu_free_da(iommu_area->bitmap, dma_ofs, npages);
	spin_unlock_irqrestore(&iommu_area->lock, flags);
}

/*
 * Allocate and map kernel buffer using consistent mode DMA for PCI
 * device.  Returns non-NULL cpu-view pointer to the buffer if
 * successful and sets *DMA_ADDRP to the pci side dma address as well,
 * else DMA_ADDRP is undefined.
 */
static void *sw_iommu_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_addrp, gfp_t gfp,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw_gendev_to_pci(dev);
	void *cpu_addr;
	long order = get_order(size);

	gfp &= ~GFP_DMA;

try_again:
	cpu_addr = (void *)__get_free_pages(gfp | __GFP_ZERO, order);
	if (!cpu_addr) {
		pr_info("pci_alloc_consistent: get_free_pages failed from %ps\n",
				__builtin_return_address(0));
		/* ??? Really atomic allocation?  Otherwise we could play
		 * with vmalloc and sg if we can't find contiguous memory.
		 */
		return NULL;
	}
	memset(cpu_addr, 0, size);

	*dma_addrp = pci_iommu_map_single(pdev, cpu_addr, size);
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

static void sw_iommu_free_coherent(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_addr,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw_gendev_to_pci(dev);

	pci_unmap_single(pdev, dma_addr, size, PCI_DMA_BIDIRECTIONAL);
	free_pages((unsigned long)cpu_addr, get_order(size));

	DBGA2("pci_free_consistent: [%llx,%zx] from %ps\n",
			dma_addr, size, __builtin_return_address(0));
}

#define SG_ENT_VIRT_ADDRESS(SG) (sg_virt((SG)))
#define SG_ENT_PHYS_ADDRESS(SG) __pa(SG_ENT_VIRT_ADDRESS(SG))

static int sw_iommu_map_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir,
		unsigned long attrs)
{
	int i;
	struct scatterlist *sg;
	struct pci_dev *pdev = sw_gendev_to_pci(dev);
	int out_nents = 0;

	if (dir == PCI_DMA_NONE)
		BUG();

	for_each_sg(sgl, sg, nents, i) {
		BUG_ON(!sg_page(sg));

		sg_dma_address(sg) = pci_iommu_map_single(pdev, SG_ENT_VIRT_ADDRESS(sg), sg->length);
		if (sg_dma_address(sg) == 0)
			goto error;
		sg_dma_len(sg) = sg->length;
		out_nents++;
	}

	return nents;

error:
	pr_warn("pci_map_sg failed: could not allocate dma page tables\n");

	/* Some allocation failed while mapping the scatterlist
	 * entries.  Unmap them now.
	 */
	if (out_nents)
		pci_unmap_sg(pdev, sgl, out_nents, dir);
	return 0;
}

/*
 * Unmap a set of streaming mode DMA translations.  Again, cpu read
 * rules concerning calls here are the same as for pci_unmap_single()
 * above.
 */
static void sw_iommu_unmap_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir,
		unsigned long attrs)
{
	struct pci_dev *pdev = sw_gendev_to_pci(dev);
	struct pci_controller *hose = pdev->sysdata;
	struct scatterlist *sg;
	int i, j;
	dma_addr_t dma_addr;
	struct sw_pci_dev_iommu_area *iommu_area;
	struct sw_iommu_dev *sw_dev = pci_to_iommu(pdev);
	long dma_ofs, npages, ofs, size;
	unsigned long flags;

	if (hose == NULL) {
		pr_err("%s: hose does not exist!\n", __func__);
		return 0;
	}

	if (!hose->iommu_enable)
		return;

	iommu_area = sw_dev->iommu_area;
	for_each_sg(sgl, sg, nents, j) {
		BUG_ON(!sg_page(sg));
		dma_addr = sg->dma_address;
		size = sg->dma_length;
		if (!size)
			break;
		npages = iommu_num_pages(dma_addr, size, PAGE_SIZE);
		dma_ofs = (dma_addr - iommu_area->dma_base) >> PAGE_SHIFT;

		spin_lock_irqsave(&iommu_area->lock, flags);
		for (i = 0; i < npages; ++i) {
			ofs = (dma_addr >> PAGE_SHIFT) + i;
			sw_iommu_unmap(pdev, ofs);
		}

		sw_iommu_free_da(iommu_area->bitmap, dma_ofs, npages);

		spin_unlock_irqrestore(&iommu_area->lock, flags);
	}
}

/* Return whether the given PCI device DMA address mask can be
 * supported properly.
 */

static int sw_iommu_supported(struct device *dev, u64 mask)
{
	/* As last resort try ZONE_DMA.  */
	if (MAX_DMA_ADDRESS - PAGE_OFFSET - 1 <= mask)
		return 1;

	return 0;
}

static int sw_iommu_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	return dma_addr == 0;
}

static int iommu_get_option(char **str, unsigned long *pint)
{
	char *cur = *str;

	if (!cur || !(*cur))
		return 0;
	*pint = kstrtol(cur, str, 16);

	return 1;
}

static int __init iommu_enable_setup(char *s)
{
	unsigned long rc_bitmap = 0;

	iommu_get_option(&s, &rc_bitmap);
	iommu_cmd = rc_bitmap;

	return 1;
}
__setup("iommu_enable=", iommu_enable_setup);

const struct dma_map_ops sw_iommu_dma_ops = {
	.alloc			= sw_iommu_alloc_coherent,
	.free			= sw_iommu_free_coherent,
	.map_page		= sw_iommu_map_page,
	.unmap_page		= sw_iommu_unmap_page,
	.map_sg			= sw_iommu_map_sg,
	.unmap_sg		= sw_iommu_unmap_sg,
	.mapping_error		= sw_iommu_mapping_error,
	.dma_supported		= sw_iommu_supported,
};

const struct dma_map_ops *dma_ops = &sw_iommu_dma_ops;
EXPORT_SYMBOL(dma_ops);
