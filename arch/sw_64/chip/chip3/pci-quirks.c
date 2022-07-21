// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/delay.h>

#include <asm/sw64io.h>

static int handshake(void __iomem *ptr, u32 mask, u32 done,
		int wait_usec, int delay_usec)
{
	u32 result;

	do {
		result = readl(ptr);
		result &= mask;
		if (result == done)
			return 0;
		udelay(delay_usec);
		wait_usec -= delay_usec;
	} while (wait_usec > 0);
	return -ETIMEDOUT;
}

#define XHCI_HCC_EXT_CAPS(p)	(((p) >> 16) & 0xffff)
#define XHCI_EXT_CAPS_ID(p)	(((p) >> 0) & 0xff)
#define XHCI_EXT_CAPS_NEXT(p)	(((p) >> 8) & 0xff)
#define XHCI_HC_LENGTH(p)	(((p) >> 0) & 0x00ff)
#define XHCI_CMD_OFFSET		(0x00)
#define XHCI_STS_OFFSET		(0x04)
#define XHCI_EXT_CAPS_LEGACY	(1)
#define XHCI_HCC_PARAMS_OFFSET	(0x10)
#define XHCI_LEGACY_CONTROL_OFFSET	(0x04)
#define XHCI_LEGACY_DISABLE_SMI		((0x7 << 1) + (0xff << 5) + (0x7 << 17))
#define XHCI_LEGACY_SMI_EVENTS		(0x7 << 29)
#define XHCI_HC_BIOS_OWNED	(1 << 16)
#define XHCI_HC_OS_OWNED	(1 << 24)
#define XHCI_CMD_RUN		(1 << 0)
#define XHCI_STS_HALT		(1 << 0)
#define XHCI_MAX_HALT_USEC	(16 * 1000)
#define XHCI_CMD_EIE		(1 << 2)
#define XHCI_CMD_HSEIE		(1 << 3)
#define XHCI_CMD_EWE		(1 << 10)
#define XHCI_IRQS		(XHCI_CMD_EIE | XHCI_CMD_HSEIE | XHCI_CMD_EWE)
#define XHCI_STS_CNR		(1 << 11)
#define STS_FATAL		(1 << 2)
#define STS_EINT		(1 << 3)
#define STS_PORT		(1 << 4)
#define STS_SRE			(1 << 10)
#define STS_RW1C_BITS		(STS_FATAL | STS_EINT | STS_PORT | STS_SRE)

static inline int xhci_find_next_ext_cap(void __iomem *base, u32 start, int id)
{
	u32 val;
	u32 next;
	u32 offset;

	offset = start;
	if (!start || start == XHCI_HCC_PARAMS_OFFSET) {
		val = readl(base + XHCI_HCC_PARAMS_OFFSET);
		if (val == ~0)
			return 0;
		offset = XHCI_HCC_EXT_CAPS(val) << 2;
		if (!offset)
			return 0;
	}
	do {
		val = readl(base + offset);
		if (val == ~0)
			return 0;
		if (offset != start && (id == 0 || XHCI_EXT_CAPS_ID(val) == id))
			return offset;

		next = XHCI_EXT_CAPS_NEXT(val);
		offset += next << 2;
	} while (next);

	return 0;
}

extern void usb_enable_intel_xhci_ports(struct pci_dev *xhci_pdev);

static void
fixup_usb_xhci_reset(struct pci_dev *dev)
{
	void __iomem *op_reg_base;
	int timeout;
	u32 xhci_command;
	u32 tmp, val;
	void __iomem *base;
	struct pci_controller *hose = dev->sysdata;
	unsigned long offset;
	int ext_cap_offset;
	int retries = 3;

	pci_read_config_dword(dev, PCI_COMMAND, &tmp);
	tmp |= (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	pci_write_config_dword(dev, PCI_COMMAND, tmp);

	pci_read_config_dword(dev, PCI_BASE_ADDRESS_0, &tmp);
	if (tmp & PCI_BASE_ADDRESS_MEM_TYPE_MASK) {
		pci_read_config_dword(dev, PCI_BASE_ADDRESS_1, &val);
		offset = (unsigned long)(val) << 32 | (tmp & (~0xf));
	} else
		offset = (unsigned long)(tmp & (~0xf));

	if (offset == 0)
		return;

	base = (void *)__va(SW64_PCI_IO_BASE(hose->node, hose->index) | offset);

	ext_cap_offset = xhci_find_next_ext_cap(base, 0, XHCI_EXT_CAPS_LEGACY);
	if (!ext_cap_offset)
		goto hc_init;

	val = readl(base + ext_cap_offset);

	if ((dev->vendor == PCI_VENDOR_ID_TI && dev->device == 0x8241) ||
			(dev->vendor == PCI_VENDOR_ID_RENESAS
			 && dev->device == 0x0014)) {
		val = (val | XHCI_HC_OS_OWNED) & ~XHCI_HC_BIOS_OWNED;
		writel(val, base + ext_cap_offset);
	}

	if (val & XHCI_HC_BIOS_OWNED) {
		writel(val | XHCI_HC_OS_OWNED, base + ext_cap_offset);

		timeout = handshake(base + ext_cap_offset, XHCI_HC_BIOS_OWNED,
				0, 1000000, 10);
		if (timeout) {
			pr_err("xHCI BIOS handoff failed (BIOS bug ?) %08x\n", val);
			writel(val & ~XHCI_HC_BIOS_OWNED, base + ext_cap_offset);
		}
	}

	val = readl(base + ext_cap_offset + XHCI_LEGACY_CONTROL_OFFSET);
	val &= XHCI_LEGACY_DISABLE_SMI;
	val |= XHCI_LEGACY_SMI_EVENTS;
	writel(val, base + ext_cap_offset + XHCI_LEGACY_CONTROL_OFFSET);

hc_init:
	if (dev->vendor == PCI_VENDOR_ID_INTEL)
		usb_enable_intel_xhci_ports(dev);

	op_reg_base = base + XHCI_HC_LENGTH(readl(base));

	timeout = handshake(op_reg_base + XHCI_STS_OFFSET, XHCI_STS_CNR, 0,
			5000000, 10);
	if (timeout) {
		val = readl(op_reg_base + XHCI_STS_OFFSET);
		pr_err("xHCI HW not ready after 5 sec (HC bug?) status = 0x%x\n", val);
	}

	xhci_command = readl(op_reg_base + XHCI_CMD_OFFSET);
	xhci_command |= 0x2;
	writel(xhci_command, op_reg_base + XHCI_CMD_OFFSET);

	timeout = handshake(op_reg_base + XHCI_CMD_OFFSET,
			0x2, 0, 10 * 1000 * 1000, 125);
	if (timeout)
		pr_err("xHCI BIOS handoff time out\n");

retry:
	val = readl(op_reg_base + XHCI_STS_OFFSET);
	val |= STS_RW1C_BITS;
	writel(val, op_reg_base + XHCI_STS_OFFSET);
	val = readl(op_reg_base + XHCI_STS_OFFSET);

	if ((val & STS_RW1C_BITS) && retries--) {
		pr_err("clear USB Status Register (status = %#x) failed, retry\n", val);
		goto retry;
	}

	val = readl(op_reg_base + XHCI_CMD_OFFSET);
	val &= ~(XHCI_CMD_RUN | XHCI_IRQS);
	writel(val, op_reg_base + XHCI_CMD_OFFSET);
	timeout = handshake(op_reg_base + XHCI_STS_OFFSET, XHCI_STS_HALT, 1,
			XHCI_MAX_HALT_USEC, 125);
	if (timeout) {
		val = readl(op_reg_base + XHCI_STS_OFFSET);
		pr_err("xHCI HW did not halt within %d usec status = 0x%x\n",
				XHCI_MAX_HALT_USEC, val);
	}

	xhci_command = readl(op_reg_base + XHCI_CMD_OFFSET);
	xhci_command |= 0x2;
	writel(xhci_command, op_reg_base + XHCI_CMD_OFFSET);

	timeout = handshake(op_reg_base + XHCI_CMD_OFFSET,
			0x2, 0, 10 * 1000 * 1000, 125);
	if (timeout)
		pr_err("xHCI BIOS handoff time out\n");

	pci_read_config_dword(dev, PCI_COMMAND, &tmp);
	tmp &= ~(PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	pci_write_config_dword(dev, PCI_COMMAND, tmp);
}
DECLARE_PCI_FIXUP_CLASS_EARLY(PCI_ANY_ID, PCI_ANY_ID,
		PCI_CLASS_SERIAL_USB_XHCI, 0, fixup_usb_xhci_reset);

#ifdef CONFIG_DCA
static void enable_sw_dca(struct pci_dev *dev)
{
	struct pci_controller *hose = (struct pci_controller *)dev->sysdata;
	unsigned long node, rc_index, dca_ctl, dca_conf;
	int i;

	if (dev->class >> 8 != PCI_CLASS_NETWORK_ETHERNET)
		return;
	node = hose->node;
	rc_index = hose->index;
	for (i = 0; i < 256; i++) {
		dca_conf = read_piu_ior1(node, rc_index, DEVICEID0 + (i << 7));
		if (dca_conf >> 63)
			continue;
		else {
			dca_conf = (1UL << 63) | (dev->bus->number << 8) | dev->devfn;
			printk("dca device index %d, dca_conf = %#lx\n", i, dca_conf);
			write_piu_ior1(node, rc_index, DEVICEID0 + (i << 7), dca_conf);
			break;
		}
	}
	dca_ctl = read_piu_ior1(node, rc_index, DCACONTROL);
	if (dca_ctl & 0x1) {
		dca_ctl = 0x2;
		write_piu_ior1(node, rc_index, DCACONTROL, dca_ctl);
		printk("Node %ld RC %ld enable DCA 1.0\n", node, rc_index);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, PCI_ANY_ID, enable_sw_dca);
#endif

void __init reserve_mem_for_pci(void)
{
	int ret;
	unsigned long base = PCI_32BIT_MEMIO;

	ret = add_memmap_region(base, PCI_32BIT_MEMIO_SIZE, memmap_pci);
	if (ret) {
		pr_err("reserved pages for pcie memory space failed\n");
		return;
	}

	pr_info("reserved pages for pcie memory space %lx:%lx\n", base >> PAGE_SHIFT,
			(base + PCI_32BIT_MEMIO_SIZE) >> PAGE_SHIFT);
}
