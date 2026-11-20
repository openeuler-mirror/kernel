// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/vgaarb.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <asm/cacheflush.h>
#include <asm/loongson.h>

#define PCI_DEVICE_ID_LOONGSON_HOST     0x7a00
#define PCI_DEVICE_ID_LOONGSON_DC1      0x7a06
#define PCI_DEVICE_ID_LOONGSON_DC2      0x7a36
#define PCI_DEVICE_ID_LOONGSON_DC3      0x7a46
#define PCI_DEVICE_ID_LOONGSON_GPU1     0x7a15
#define PCI_DEVICE_ID_LOONGSON_GPU2     0x7a25
#define PCI_DEVICE_ID_LOONGSON_GPU3     0x7a35

int raw_pci_read(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 *val)
{
	struct pci_bus *bus_tmp = pci_find_bus(domain, bus);

	if (bus_tmp)
		return bus_tmp->ops->read(bus_tmp, devfn, reg, len, val);
	return -EINVAL;
}

int raw_pci_write(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 val)
{
	struct pci_bus *bus_tmp = pci_find_bus(domain, bus);

	if (bus_tmp)
		return bus_tmp->ops->write(bus_tmp, devfn, reg, len, val);
	return -EINVAL;
}

phys_addr_t mcfg_addr_init(int node)
{
	return (((u64)node << 44) | MCFG_EXT_PCICFG_BASE);
}

static int __init pcibios_init(void)
{
	unsigned int lsize;

	/*
	 * Set PCI cacheline size to that of the last level in the
	 * cache hierarchy.
	 */
	lsize = cpu_last_level_cache_line_size();

	if (lsize) {
		pci_dfl_cache_line_size = lsize >> 2;

		pr_debug("PCI: pci_cache_line_size set to %d bytes\n", lsize);
	}

	return 0;
}

subsys_initcall(pcibios_init);

int pcibios_device_add(struct pci_dev *dev)
{
	int id;
	struct irq_domain *dom;

	id = pci_domain_nr(dev->bus);
	dom = irq_find_matching_fwnode(get_pch_msi_handle(id), DOMAIN_BUS_PCI_MSI);
	dev_set_msi_domain(&dev->dev, dom);

	return 0;
}

int pcibios_alloc_irq(struct pci_dev *dev)
{
	if (acpi_disabled)
		return 0;
	if (pci_dev_msi_enabled(dev))
		return 0;
	return acpi_pci_irq_enable(dev);
}

static void pci_fixup_vgadev(struct pci_dev *pdev)
{
	struct pci_dev *devp = NULL;

	while ((devp = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, devp))) {
		if (devp->vendor != PCI_VENDOR_ID_LOONGSON) {
			vga_set_default_device(devp);
			dev_info(&pdev->dev,
				"Overriding boot device as %X:%X\n",
				devp->vendor, devp->device);
		}
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_LOONGSON, PCI_DEVICE_ID_LOONGSON_DC1, pci_fixup_vgadev);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_LOONGSON, PCI_DEVICE_ID_LOONGSON_DC2, pci_fixup_vgadev);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_LOONGSON, PCI_DEVICE_ID_LOONGSON_DC3, pci_fixup_vgadev);


#define DEV_LS2K3000_DC 0x7a46
#define DEV_LS2K2000_DC 0x7a36
#define DEV_LS2K2000_GPU 0x7a25
#define DEV_LS2K3000_GPU 0x7a35
#define LS2K2000_DC_OFFSET 0x1240
#define LS2K3000_DC_OFFSET 0
#define LS2K2000_DC_CRTC_OFFSET 0x10
#define LS2K3000_DC_CRTC_OFFSET 0x400
#define LS2K_DC_OUTPUT_ENABLE 0x100
#define LS2K_DC_BAR_SIZE 0x10000
#define LS2K_DC_NUM_MAX 2

static u32 save_status[LS2K_DC_NUM_MAX] = { 0 };
static void loongson_dma_hangs_fixup(struct pci_dev *pdev, bool open)
{
	void __iomem *dc_reg, *base, *regbase;
	u32 val, count, i, crtc_offset, device;

	base = pdev->bus->ops->map_bus(pdev->bus, pdev->devfn + 1, 0);
	if (!base)
		return;
	device = readw(base + PCI_DEVICE_ID);

	switch (device) {
	case DEV_LS2K3000_DC:
		crtc_offset = LS2K3000_DC_CRTC_OFFSET;
		break;
	case DEV_LS2K2000_DC:
		crtc_offset = LS2K2000_DC_CRTC_OFFSET;
		break;
	default:
		return;
	}
	regbase = ioremap(readq(base + PCI_BASE_ADDRESS_0) & ~0xffull,
			  LS2K_DC_BAR_SIZE);
	if (!regbase) {
		pci_err(pdev, "Failed to ioremap\n");
		return;
	}

	dc_reg = regbase + ((device == DEV_LS2K2000_DC) ? LS2K2000_DC_OFFSET :
							  LS2K3000_DC_OFFSET);

	for (i = 0; i < LS2K_DC_NUM_MAX; i++, dc_reg += crtc_offset) {
		count = 0;

		val = readl(dc_reg);

		if (!open)
			save_status[i] = val;

		/* If the status is turned off at startup,
		 * there is no need to fixup.
		 */
		if (!(save_status[i] & LS2K_DC_OUTPUT_ENABLE)) {
			pci_info(pdev,
				 "dma hangs no fixup at reg[0x%llx] : 0x%x\n",
				 (u64)dc_reg & 0xffff, save_status[i]);
			continue;
		}

		if (open)
			val |= LS2K_DC_OUTPUT_ENABLE;
		else
			val &= ~LS2K_DC_OUTPUT_ENABLE;

		/* ensure value active */
		mb();
		writel(val, dc_reg);

		while (open ? (!(readl(dc_reg) & LS2K_DC_OUTPUT_ENABLE)) :
			      (readl(dc_reg) & LS2K_DC_OUTPUT_ENABLE)) {
			if (count++ > 50)
				break;
			udelay(1000);
		}

		pci_info(pdev, "dma hangs fixup at reg[0x%llx] : 0x%x\n",
			 (u64)dc_reg & 0xffff, val);
	}

	iounmap(regbase);
}

static void loongson_dma_hangs_early_quirk(struct pci_dev *pdev)
{
	loongson_dma_hangs_fixup(pdev, false);
}

static void loongson_dma_hangs_final_quirk(struct pci_dev *pdev)
{
	loongson_dma_hangs_fixup(pdev, true);
}

DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_LOONGSON, DEV_LS2K2000_GPU,
			loongson_dma_hangs_early_quirk);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_LOONGSON, DEV_LS2K3000_GPU,
			loongson_dma_hangs_early_quirk);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_LOONGSON, DEV_LS2K2000_GPU,
			loongson_dma_hangs_final_quirk);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_LOONGSON, DEV_LS2K3000_GPU,
			loongson_dma_hangs_final_quirk);


static void loongson_display_quirk(struct pci_dev *dev)
{
	u32 val;
	u64 mask, size;
	u64 max_size = 0;
	int i, num = 0;
	struct pci_bus *bus = dev->bus;

	/* return if HT not exist */
	if (cpu_pabits < 47)
		return;

	if (!dev->bus->number) {
		if (!(dev->vendor == PCI_VENDOR_ID_LOONGSON &&
		      (dev->device == 0x7a15 || dev->device == 0x7a25)))
			return;
	} else {
		if (!bus->parent)
			return;
		while (!pci_is_root_bus(bus->parent))
			bus = bus->parent;

		/* ensure slot is 7a2000 */
		if (!bus->self ||
		    bus->self->vendor != PCI_VENDOR_ID_LOONGSON ||
		    bus->self->device < 0x7a39)
			return;
	}

	max_size = 0;
	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		if (dev->resource[i].flags & IORESOURCE_MEM) {
			size = dev->resource[i].end - dev->resource[i].start;
			if (size > max_size) {
				max_size = size;
				num = i;
			}
		}
	}

	mask = ~(dev->resource[num].end - dev->resource[num].start);
	val = (dev->resource[num].start >> (24 - 16)) |
	      ((mask >> 24) & 0xffff);
	writel(val, (void *)TO_UNCACHE(0xefdfb000174));
	writel(0x80000000, (void *)TO_UNCACHE(0xefdfb000170));
}
DECLARE_PCI_FIXUP_CLASS_FINAL(PCI_ANY_ID, PCI_ANY_ID,
			      PCI_BASE_CLASS_DISPLAY, 16, loongson_display_quirk);
