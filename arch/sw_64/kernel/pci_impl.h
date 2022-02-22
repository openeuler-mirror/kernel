/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file contains declarations and inline functions for interfacing
 * with the PCI initialization routines.
 */
#ifndef _SW64_KERNEL_PCI_IMPL_H
#define	_SW64_KERNEL_PCI_IMPL_H

struct pci_dev;
struct pci_controller;
struct pci_iommu_arena;

/*
 * We can't just blindly use 64K for machines with EISA busses; they
 * may also have PCI-PCI bridges present, and then we'd configure the
 * bridge incorrectly.
 *
 * Also, we start at 0x8000 or 0x9000, in hopes to get all devices'
 * IO space areas allocated *before* 0xC000; this is because certain
 * BIOSes (Millennium for one) use PCI Config space "mechanism #2"
 * accesses to probe the bus. If a device's registers appear at 0xC000,
 * it may see an INx/OUTx at that address during BIOS emulation of the
 * VGA BIOS, and some cards, notably Adaptec 2940UW, take mortal offense.
 */

#define EISA_DEFAULT_IO_BASE	0x9000	/* start above 8th slot */
#define DEFAULT_IO_BASE		0x0     /* start at 8th slot */

/*
 * We try to make the DEFAULT_MEM_BASE addresses *always* have more than
 * a single bit set. This is so that devices like the broken Myrinet card
 * will always have a PCI memory address that will never match a IDSEL
 * address in PCI Config space, which can cause problems with early rev cards.
 */

#define DEFAULT_MEM_BASE 0

/*
 * A PCI IOMMU allocation arena.  There are typically two of these
 * regions per bus.
 * ??? The 8400 has a 32-byte pte entry, and the entire table apparently
 * lives directly on the host bridge (no tlb?).  We don't support this
 * machine, but if we ever did, we'd need to parameterize all this quite
 * a bit further.  Probably with per-bus operation tables.
 */

struct pci_iommu_arena {
	spinlock_t lock;
	struct pci_controller *hose;
#define IOMMU_INVALID_PTE 0x2 /* 32:63 bits MBZ */
#define IOMMU_RESERVED_PTE 0xface
	unsigned long *ptes;
	dma_addr_t dma_base;
	unsigned int size;
	unsigned int next_entry;
	unsigned int align_entry;
};


/* The hose list.  */
extern struct pci_controller *hose_head, **hose_tail;

extern void common_init_pci(void);
#define common_swizzle pci_common_swizzle
extern struct pci_controller *alloc_pci_controller(void);
extern struct resource *alloc_resource(void);

extern unsigned long size_for_memory(unsigned long max);

extern struct pci_dev *sw64_gendev_to_pci(struct device *dev);
extern const struct dma_map_ops sw64_dma_direct_ops;

extern struct cma *sw64_kvm_cma;
extern struct gen_pool *sw64_kvm_pool;
#endif
